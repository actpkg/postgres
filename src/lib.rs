use act_sdk::prelude::*;
use ciborium::value::Value as Cv;

pub mod classify;
pub mod convert;
pub mod creds;
pub mod mode;

mod conn;
use conn::{ConnTarget, ConnectError, SslMode, TargetArgs};

#[act_component]
mod component {
    use super::*;

    // A plain `static`, not `thread_local!`: under wasip3 every host fiber
    // gets its own TLS, so a `thread_local` registry would be repopulated
    // from scratch on every tool call and no session would survive between
    // them. See the `act_sdk::sessions` module docs.
    static SESSIONS: std::sync::LazyLock<SessionRegistry<SessionState>> =
        std::sync::LazyLock::new(|| SessionRegistry::new("postgres"));

    // Connections parked for teardown by `close`, drained by the next async
    // export (see `drain_zombies`). A plain `static` with a `Mutex` for the
    // same fiber reason as the registry above; the lock is uncontended in
    // practice because fibers only switch at `.await` and no drain holds it
    // across one.
    static ZOMBIES: std::sync::LazyLock<std::sync::Mutex<Vec<conn::Connection>>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

    /// Park a session's live connection for later teardown.
    ///
    /// `close-session` is a **synchronous** WIT export: it runs on a fiber
    /// that has never awaited, and tearing a tokio runtime down from such a
    /// fiber (cancel the driver task, whose drop path closes the TCP socket
    /// through wasi:sockets) trap-fails under wasip3 cooperative threading —
    /// observed as `std:internal` from `close-session` with a backtrace
    /// through `tcp_free`. So `close` parks into [`ZOMBIES`] instead, and the
    /// next **async** export drains the list via
    /// [`conn::Connection::shutdown`], which runs the whole teardown inside
    /// `block_on` on the connection's own runtime — the same context every
    /// connection was created in, and one wasi:sockets accepts.
    ///
    /// A session-bound agent calls a tool after opening and again before any
    /// further close, so in the common MCP flow a zombie lives for exactly
    /// one tool call. One that is never drained lingers until the host drops
    /// the instance; that socket is closed by the instance teardown rather
    /// than a fiber we control, and leaking one socket per abandoned close is
    /// the price of never trapping.
    fn park(id: &str) {
        if let Some(state) = SESSIONS.remove(id)
            && let Some(conn) = state.conn
        {
            ZOMBIES.lock().unwrap_or_else(|e| e.into_inner()).push(conn);
        }
    }

    /// Tear down every parked connection. Called at the top of async exports
    /// (currently `ensure_connection`); never from a sync export.
    fn drain_zombies() {
        let drained: Vec<_> = ZOMBIES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for conn in drained {
            conn.shutdown();
        }
    }

    // ── OpenArgs ──────────────────────────────────────────────────────────────

    /// Arguments accepted by `open-session`, and therefore the open-args schema
    /// an agent reads before opening one.
    ///
    /// **There is no password field, and there must never be one.** Everything
    /// sent to `open-session` is agent-visible plaintext: it sits in the
    /// agent's context, in the transcript, and in the host's session record.
    /// The credential is *named* here — `credential_key` — and fetched from the
    /// host credential store on the first tool call.
    ///
    /// That rule is why `connection_string` must be password-free rather than
    /// merely discouraged: a DSN is a session argument like any other, and
    /// `postgres://user:pass@host/db` is a password that does not look like
    /// one. See [`ConnTarget::prepare`] for what a DSN may and may not carry.
    #[derive(Deserialize, JsonSchema)]
    pub struct OpenArgs {
        /// Password-free DSN, e.g. `postgres://host:5432/db?sslmode=require`.
        /// A DSN carrying a password — as userinfo, `password=` or
        /// `?password=` — is refused; authenticate with `credential_key`
        /// instead. Mutually exclusive with `host`/`port`.
        #[serde(default)]
        pub connection_string: Option<String>,
        /// Server hostname or IP. Mutually exclusive with `connection_string`.
        #[serde(default)]
        pub host: Option<String>,
        /// Server port. Default 5432. Only with `host` — with a
        /// `connection_string` the port belongs to the DSN.
        #[serde(default)]
        pub port: Option<u16>,
        /// Login role. Overrides both the DSN's `user=` and the credential's
        /// `postgres:user` field. A role name is not a credential.
        #[serde(default)]
        pub user: Option<String>,
        /// Which credential in this component's profile to authenticate with.
        /// Its `postgres:password` field is the password; its optional
        /// `postgres:user` field names the role.
        #[serde(default = "default_credential_key")]
        pub credential_key: String,
        /// Database name. Overrides the DSN's `dbname=`.
        #[serde(default)]
        pub dbname: Option<String>,
        /// TLS mode: disable | prefer | require. Overrides the DSN's
        /// `sslmode=`; defaults to the DSN's, and to `prefer` when neither
        /// says.
        #[serde(default)]
        pub sslmode: Option<SslModeArg>,
        /// Capability tier for this session: read-only | read-write | ddl | full.
        /// Default read-only.
        #[serde(default)]
        pub mode: crate::mode::Mode,
        /// Default row cap for `query`. Default 1000.
        #[serde(default = "default_max_rows")]
        pub max_rows: u32,
        /// Optional server-side statement timeout in milliseconds.
        #[serde(default)]
        pub statement_timeout_ms: Option<u32>,
    }

    fn default_credential_key() -> String {
        creds::DEFAULT_CREDENTIAL_KEY.to_string()
    }
    fn default_max_rows() -> u32 {
        1000
    }

    /// TLS mode selector for session open arguments.
    #[derive(Deserialize, JsonSchema, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    pub enum SslModeArg {
        /// No TLS; plain TCP.
        Disable,
        /// Attempt TLS. v1: no plaintext fallback (same behaviour as require).
        Prefer,
        /// Require TLS; fail if the server does not support it.
        Require,
    }

    impl From<SslModeArg> for SslMode {
        fn from(arg: SslModeArg) -> SslMode {
            match arg {
                SslModeArg::Disable => SslMode::Disable,
                SslModeArg::Prefer => SslMode::Prefer,
                SslModeArg::Require => SslMode::Require,
            }
        }
    }

    // ── Tool metadata ─────────────────────────────────────────────────────────

    #[derive(Deserialize)]
    pub struct ToolMeta {
        #[serde(rename = "std:session-id")]
        session_id: Option<String>,
    }

    // ── Session state ─────────────────────────────────────────────────────────

    /// What a session knows. Everything but [`SessionState::conn`] is settled
    /// at open; the connection cannot be, because the credential it needs
    /// cannot be fetched until the session is live.
    pub struct SessionState {
        /// Where to connect. Validated at open and secret-free.
        pub target: ConnTarget,
        /// Which credential to authenticate with. Fixed at open, which is why
        /// a rejection below is worth remembering.
        pub credential_key: String,
        /// Capability tier for this session.
        pub mode: crate::mode::Mode,
        /// Default row cap for `query`.
        pub max_rows: usize,
        /// Filled on the first tool call, not at open: `get-secret` requires a
        /// session the host has already marked live, and the host does that
        /// only after `open-session` returns (ACT-AUTH §1.1.4).
        pub conn: Option<conn::Connection>,
        /// Set when the server answered the startup with SQLSTATE class 28 —
        /// a wrong password, or a role that does not exist.
        ///
        /// Without it, the next tool call repeats the whole sequence
        /// *including `get-secret`*, which can put a consent prompt in front
        /// of a human on every single call. An authentication failure is not
        /// transient: no retry inside this session can change the answer,
        /// because the credential key and the role are both fixed at open. So
        /// the session is poisoned rather than retried, while transport
        /// failures keep retrying — those do change on their own.
        pub credential_rejected: bool,
    }

    // ── Session lifecycle ─────────────────────────────────────────────────────

    /// Validate the args and remember the target. **Opens no socket.**
    ///
    /// This is the behaviour change the credential store forces, and it is
    /// worth stating plainly: this component used to connect here, so a bad
    /// password failed at `open_session`. It cannot any more — the password
    /// arrives on the first tool call — so a credential that the server
    /// refuses now surfaces on the first `query`, not at open. Everything that
    /// can still be decided from the arguments alone is decided here, so that
    /// an argument mistake is still reported where it was made.
    #[session_open]
    fn open(args: OpenArgs) -> ActResult<String> {
        creds::validate_credential_key(&args.credential_key)?;
        let target = ConnTarget::prepare(TargetArgs {
            connection_string: args.connection_string,
            host: args.host,
            port: args.port,
            user: args.user,
            dbname: args.dbname,
            sslmode: args.sslmode.map(SslMode::from),
            statement_timeout_ms: args.statement_timeout_ms,
        })
        .map_err(ActError::invalid_args)?;

        Ok(SESSIONS.insert(SessionState {
            target,
            credential_key: args.credential_key,
            mode: args.mode,
            max_rows: args.max_rows as usize,
            conn: None,
            credential_rejected: false,
        }))
    }

    #[session_close]
    fn close(session_id: String) {
        // Never tears down here: sync export, no async context (see `park`).
        park(&session_id);
    }

    fn unknown_session(id: &str) -> ActError {
        ActError::session_not_found(format!("Unknown session-id: {id}"))
    }

    fn require_session(ctx: &mut ActContext<ToolMeta>) -> ActResult<String> {
        ctx.metadata()
            .session_id
            .clone()
            .ok_or_else(|| ActError::session_not_found("Missing std:session-id metadata"))
    }

    /// Run `f` against the session's live connection.
    ///
    /// Every caller has already awaited [`ensure_connection`], so the absent
    /// case is a bug in this file rather than something a caller can provoke.
    fn with_conn<T>(
        id: &str,
        f: impl FnOnce(&SessionState, &conn::Connection) -> ActResult<T>,
    ) -> ActResult<T> {
        SESSIONS
            .with(id, |s| match s.conn.as_ref() {
                Some(c) => f(s, c),
                None => Err(ActError::internal(
                    "the session has no connection; this call reached the database \
                     layer without establishing one",
                )),
            })
            .ok_or_else(|| unknown_session(id))?
    }

    // ── Credential fetch + connect ────────────────────────────────────────────

    /// Fetch the credential and open the connection, once per session.
    ///
    /// Runs on the first tool call, never at `open-session`: `get-secret`
    /// requires a session id the host has already marked live, and the host
    /// does that only once `open-session` has returned, so a fetch from inside
    /// it names an id the host has never seen and is refused every time
    /// (ACT-AUTH §1.1.4). Idempotent: a session that already holds a
    /// connection returns without touching the store or the network.
    ///
    /// **Not de-duplicated across concurrent first calls.** Two tool calls
    /// that arrive before either has connected both see `conn: None` and both
    /// run the sequence; the second overwrites the first's connection with an
    /// equivalent one. The same applies to
    /// [`SessionState::credential_rejected`]: its promise is about the calls
    /// that *follow* a refusal, not about two that raced it. The fix would be
    /// a per-session in-flight latch, and the cost today is one extra
    /// connection on a race no MCP client in this workspace can produce, all
    /// of them being request/response.
    ///
    /// Depends on **field names only** — the two this component declares in
    /// its own `act.toml` and names in every error it prints. No name is
    /// well-known (`ACT-CONSTANTS.md` §8 registers types, not names), so the
    /// component that reads a field is the party that asked for it.
    async fn ensure_connection(session_id: &str) -> ActResult<()> {
        // An async export is the only place teardown is safe (see `park`);
        // the head of the first tool call of this run is where zombies get
        // their shutdown, before anything else in this call can fail.
        drain_zombies();
        if SESSIONS
            .with(session_id, |s| s.conn.is_some())
            .unwrap_or(false)
        {
            return Ok(());
        }
        // Before the store, not after: the whole point of the flag is that
        // `get-secret` is never reached a second time.
        if let Some(e) = poisoned(session_id) {
            return Err(e);
        }
        let (target, key) = SESSIONS
            .with(session_id, |s| (s.target.clone(), s.credential_key.clone()))
            .ok_or_else(|| unknown_session(session_id))?;

        let raw = match act::credentials::store::get_secret(
            session_id.to_string(),
            secret_request(&target, &key),
        )
        .await
        {
            Ok(raw) => raw,
            Err(e) => return Err(secret_error(e, &key).await),
        };
        // Values cross as CBOR; `from_wit` decodes the field map. Its error
        // names the field and never its bytes.
        let secret = act_sdk::credentials::Secret::from_wit(raw.kind, raw.fields)
            .map_err(|e| ActError::internal(format!("credential field decode failed: {e}")))?;
        let credentials = creds::from_secret(&secret, &key)?;
        let user = creds::resolve_user(target.user(), credentials.user.as_deref(), &key)?;

        match target.connect(&user, &credentials.password) {
            Ok(connection) => SESSIONS
                .with_mut(session_id, |s| s.conn = Some(connection))
                .ok_or_else(|| unknown_session(session_id)),
            Err(ConnectError::Authentication(detail)) => {
                SESSIONS.with_mut(session_id, |s| s.credential_rejected = true);
                Err(ActError::new(
                    creds::ERR_CREDENTIAL_REQUIRED,
                    format!("{detail}\n{}", creds::credential_rejected_message(&key)),
                ))
            }
            // Not poisoned: DNS, TCP, TLS and a server that is still starting
            // all change on their own, and a session that refused to retry
            // them would have to be reopened for a database that came back.
            Err(ConnectError::Other(detail)) => Err(ActError::internal(format!(
                "could not connect to PostgreSQL: {detail}. postgres connects on the first \
                 tool call rather than at open-session, because the credential cannot be \
                 fetched until the session is live — so a connection failure is reported \
                 here and not when the session was opened."
            ))),
        }
    }

    /// The refusal a poisoned session answers with, or `None` while it is
    /// still worth asking the store. See
    /// [`SessionState::credential_rejected`].
    ///
    /// A named function rather than an `if` inside [`ensure_connection`]
    /// because only one of its two answers is testable on the host target: the
    /// `Some` side is reachable through `ensure_connection` (a poisoned
    /// session awaits nothing), while the `None` side falls straight through
    /// to the credential store, which is a component import with no host
    /// implementation.
    fn poisoned(session_id: &str) -> Option<ActError> {
        SESSIONS
            .with(session_id, |s| {
                (s.credential_rejected, s.credential_key.clone())
            })
            .filter(|(rejected, _)| *rejected)
            .map(|(_, key)| {
                ActError::new(
                    creds::ERR_CREDENTIAL_REQUIRED,
                    creds::credential_rejected_message(&key),
                )
            })
    }

    /// What this component asks the credential store for.
    ///
    /// Every field is host-visible **by contract**: a host may show `resource`
    /// and `hint` to a human when it prompts, and may record the request in
    /// its audit trail. What goes in one is therefore a disclosure decision,
    /// which is why this is a function with a test rather than a struct
    /// literal inline in [`ensure_connection`].
    ///
    /// `resource` is rebuilt from the validated target rather than echoed from
    /// the caller's DSN — see [`ConnTarget::resource`]. `kind` is `None`
    /// because `secret-kind` names nothing under the current model and
    /// retrieval MUST NOT be filtered by shape (ACT-AUTH §1.1.6,
    /// `ACT-CONSTANTS.md` §8.2.1); this component reads its declared fields by
    /// name and decides for itself.
    fn secret_request(target: &ConnTarget, key: &str) -> act::credentials::types::SecretRequest {
        act::credentials::types::SecretRequest {
            key: key.to_string(),
            kind: None,
            resource: Some(target.resource()),
            scopes: vec![],
            hint: Some("PostgreSQL role password".into()),
        }
    }

    /// Map a store refusal onto the error the agent sees.
    ///
    /// `not-found` and `denied` collapse into one message on purpose: the host
    /// decides `denied` before it consults the store (ACT-AUTH §1.1.7), so
    /// distinguishing them here would invent a difference the host refuses to
    /// disclose — and would turn the pair into a way to probe a profile for
    /// keys. The other two variants are different failures with different
    /// fixes and keep their own diagnosis.
    async fn secret_error(e: act::credentials::types::SecretError, key: &str) -> ActError {
        use act::credentials::types::SecretError;
        match e {
            SecretError::NotFound | SecretError::Denied => credential_missing(key).await,
            SecretError::InvalidSession => ActError::session_not_found(
                "the credential store does not recognise this session; open a new one",
            ),
            // `msg` is host-authored, and ACT-AUTH §1.1.7 requires it to be
            // free of credential material — including material a backend
            // error quotes back — precisely so it can be passed on like this.
            SecretError::Unavailable(msg) => {
                ActError::internal(format!("the credential store is unavailable: {msg}"))
            }
        }
    }

    async fn credential_missing(key: &str) -> ActError {
        // Best-effort: a policy that denies the store denies the listing too,
        // and then the message simply carries no inventory. Keys are not
        // secret — `list-secrets` exists to hand them to the agent.
        let known: Vec<String> = act::credentials::store::list_secrets(None)
            .await
            .map(|v| v.into_iter().map(|i| i.key).collect())
            .unwrap_or_default();
        ActError::new(
            creds::ERR_CREDENTIAL_REQUIRED,
            creds::credential_missing_message(key, &known),
        )
    }

    // ── Tier gate helper ─────────────────────────────────────────────────────

    /// Check `sql` against the session's tier.
    ///
    /// Called **before** [`ensure_connection`] by every tool: a statement the
    /// session's mode forbids is refused without fetching a credential, which
    /// keeps a request the component was never going to be allowed to make
    /// from reaching a human as a consent prompt.
    fn gate(id: &str, sql: &str) -> ActResult<()> {
        let mode = SESSIONS
            .with(id, |s| s.mode)
            .ok_or_else(|| unknown_session(id))?;
        mode::require_tier(mode, sql)
            .map(|_| ())
            .map_err(|g: mode::GateError| ActError::capability_denied(g.summary))
    }

    // ── Tools ─────────────────────────────────────────────────────────────────

    #[act_tool(
        description = "Execute a read-only SQL query (SELECT/CTE) and return rows. \
                       Rejected if it is not read-only or exceeds the session mode.",
        read_only
    )]
    async fn query(
        /// A single read-only SQL statement.
        sql: String,
        /// Bind values for $1, $2, ... (optional).
        params: Option<Vec<convert::PgParam>>,
        /// Override the session's default row cap (optional).
        max_rows: Option<u32>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
        gate(&id, &sql)?;
        ensure_connection(&id).await?;
        with_conn(&id, |s, c| {
            let cap = max_rows.map(|n| n as usize).unwrap_or(s.max_rows);
            let (rows, truncated) = c
                .query_rows(&sql, params.as_deref().unwrap_or(&[]), cap)
                .map_err(ActError::internal)?;
            Ok(Cv::Map(vec![
                (Cv::Text("rows".into()), Cv::Array(rows)),
                (Cv::Text("truncated".into()), Cv::Bool(truncated)),
            ]))
        })
    }

    #[act_tool(
        description = "Execute a write/DDL SQL statement (INSERT/UPDATE/DELETE/CREATE/...). \
                       Each statement is classified and checked against the session mode."
    )]
    async fn execute(
        /// A single SQL statement.
        sql: String,
        /// Bind values for $1, $2, ... (optional).
        params: Option<Vec<convert::PgParam>>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
        gate(&id, &sql)?;
        ensure_connection(&id).await?;
        with_conn(&id, |_, c| {
            let affected = c
                .execute_sql(&sql, params.as_deref().unwrap_or(&[]))
                .map_err(ActError::internal)?;
            Ok(Cv::Map(vec![(
                Cv::Text("rows_affected".into()),
                Cv::from(affected as i64),
            )]))
        })
    }

    #[act_tool(description = "List non-system schemas in the database.", read_only)]
    async fn list_schemas(ctx: &mut ActContext<ToolMeta>) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        let sql = "SELECT schema_name FROM information_schema.schemata \
                   WHERE schema_name NOT IN ('pg_catalog','information_schema') \
                   AND schema_name NOT LIKE 'pg_toast%' AND schema_name NOT LIKE 'pg_temp%' \
                   ORDER BY schema_name";
        // Catalog reads are always db:read; gate for consistency with
        // query/execute (and so a future tightening of read access is
        // enforced here too).
        gate(&id, sql)?;
        ensure_connection(&id).await?;
        with_conn(&id, |_, c| {
            let (rows, _) = c
                .query_rows(sql, &[], usize::MAX)
                .map_err(ActError::internal)?;
            Ok(Cv::Array(rows))
        })
    }

    #[act_tool(
        description = "List tables and views in a schema (default 'public').",
        read_only
    )]
    async fn list_tables(
        /// Schema to inspect. Defaults to 'public'.
        schema: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        let sql = "SELECT table_name, table_type FROM information_schema.tables \
                   WHERE table_schema = $1 ORDER BY table_name";
        gate(&id, sql)?;
        ensure_connection(&id).await?;
        with_conn(&id, |_, c| {
            let s = schema.unwrap_or_else(|| "public".to_string());
            let (rows, _) = c
                .query_rows(sql, &[convert::PgParam(Cv::Text(s))], usize::MAX)
                .map_err(ActError::internal)?;
            Ok(Cv::Array(rows))
        })
    }

    #[act_tool(
        description = "Describe a table: columns, types, nullability, defaults.",
        read_only
    )]
    async fn describe_table(
        /// Table name.
        table: String,
        /// Schema. Defaults to 'public'.
        schema: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        let sql = "SELECT column_name, data_type, is_nullable, column_default \
                   FROM information_schema.columns \
                   WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position";
        gate(&id, sql)?;
        ensure_connection(&id).await?;
        with_conn(&id, |_, c| {
            let s = schema.unwrap_or_else(|| "public".to_string());
            let (rows, _) = c
                .query_rows(
                    sql,
                    &[
                        convert::PgParam(Cv::Text(s)),
                        convert::PgParam(Cv::Text(table.clone())),
                    ],
                    usize::MAX,
                )
                .map_err(ActError::internal)?;
            if rows.is_empty() {
                return Err(ActError::not_found(format!("Table not found: {table}")));
            }
            Ok(Cv::Map(vec![
                (Cv::Text("table".into()), Cv::Text(table)),
                (Cv::Text("columns".into()), Cv::Array(rows)),
            ]))
        })
    }

    #[act_tool(
        description = "Return the query plan via EXPLAIN. analyze=false (default) does \
                       NOT execute the query; analyze=true requires the statement's tier.",
        read_only
    )]
    async fn explain_query(
        /// SQL statement to explain.
        sql: String,
        /// Run EXPLAIN ANALYZE (executes the query). Default false.
        analyze: Option<bool>,
        /// Output format: text | json. Default text.
        format: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
        let analyze = analyze.unwrap_or(false);
        // analyze=true executes the statement, so it must clear the real tier gate.
        if analyze {
            gate(&id, &sql)?;
        }
        ensure_connection(&id).await?;
        with_conn(&id, |_, c| {
            let plan = c
                .explain(&sql, analyze, format.as_deref().unwrap_or("text"))
                .map_err(ActError::internal)?;
            Ok(Cv::Array(plan))
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(host: &str) -> OpenArgs {
            serde_json::from_value(serde_json::json!({ "host": host })).expect("deserializes")
        }

        /// Collect every property name in the schema, at any depth.
        fn property_names(node: &serde_json::Value, out: &mut Vec<String>) {
            match node {
                serde_json::Value::Object(map) => {
                    if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                        out.extend(props.keys().cloned());
                    }
                    for (_, v) in map {
                        property_names(v, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for v in items {
                        property_names(v, out);
                    }
                }
                _ => {}
            }
        }

        /// The security property the whole credential design exists to
        /// protect, asserted instead of eyeballed: a password must not be
        /// nameable in the open-args schema, because everything sent to
        /// `open-session` is agent-visible plaintext.
        ///
        /// The root fields are an **allowlist**, spelled out exactly. A
        /// denylist of secret-sounding words cannot do this job on its own —
        /// it would let `connection_string` straight through, which is the
        /// field this component's leak actually lived in. Having to edit this
        /// list when a field is added is the point: adding a field to the
        /// open-args schema is a decision about what an agent may hand over,
        /// and it should not be reviewable by accident.
        ///
        /// The word search still runs, over field names at any depth, for the
        /// two things the allowlist does not cover: a secret hidden inside a
        /// nested object or a `$defs` entry, and a failure message that says
        /// what is wrong rather than just what differs. It reads names, not
        /// the raw document, because the descriptions deliberately use the
        /// word "password" to tell the agent not to send one — searching the
        /// whole schema would fail on its own warning.
        #[test]
        fn the_open_args_schema_names_a_credential_but_never_carries_one() {
            let schema = schemars::schema_for!(OpenArgs);
            let json: serde_json::Value = serde_json::to_value(&schema).expect("serializes");

            let mut root: Vec<&str> = json["properties"]
                .as_object()
                .expect("an object schema")
                .keys()
                .map(String::as_str)
                .collect();
            root.sort_unstable();
            assert_eq!(
                root,
                [
                    "connection_string",
                    "credential_key",
                    "dbname",
                    "host",
                    "max_rows",
                    "mode",
                    "port",
                    "sslmode",
                    "statement_timeout_ms",
                    "user",
                ]
            );

            let mut names = Vec::new();
            property_names(&json, &mut names);
            assert!(names.iter().any(|n| n == "credential_key"), "got {names:?}");
            for secret in [
                "password", "passwd", "pwd", "secret", "token", "auth", "api_key",
            ] {
                assert!(
                    !names.iter().any(|n| n.to_lowercase().contains(secret)),
                    "open-args schema offers a place to put a {secret}: {names:?}"
                );
            }
        }

        /// `host` (or a DSN) is the one argument with no default; everything
        /// else has to survive being omitted, because these defaults are the
        /// contract an agent opening a session actually gets.
        #[test]
        fn every_argument_but_the_target_has_a_default() {
            let a = args("db.internal");
            assert_eq!(a.credential_key, creds::DEFAULT_CREDENTIAL_KEY);
            assert_eq!(a.max_rows, 1000);
            assert_eq!(a.mode, crate::mode::Mode::ReadOnly);
            assert!(a.port.is_none());
            assert!(a.user.is_none());
            assert!(a.sslmode.is_none());
        }

        #[test]
        fn open_allocates_a_prefixed_id_without_connecting() {
            let id = open(args("db.internal")).expect("opens");
            assert!(id.starts_with("postgres_"), "got {id}");
            // The session exists and holds no connection: the credential it
            // would need cannot be fetched from inside `open-session`.
            assert!(
                SESSIONS.with(&id, |s| s.conn.is_none()).unwrap(),
                "open must not connect"
            );
            close(id);
        }

        /// A password that arrives as part of a DSN is refused at open, where
        /// the caller can see which argument it made — not at the first query.
        #[test]
        fn open_refuses_a_connection_string_carrying_a_password() {
            let a: OpenArgs = serde_json::from_value(serde_json::json!({
                "connection_string": "postgres://alice:hunter2@db.internal/app"
            }))
            .expect("deserializes");
            let e = open(a).expect_err("refused");
            assert_eq!(e.kind, act_sdk::constants::ERR_INVALID_ARGS);
            assert!(!e.message.contains("hunter2"), "leaked: {}", e.message);
            assert!(e.message.contains("credential_key"), "got {}", e.message);
        }

        #[test]
        fn open_refuses_a_credential_key_that_is_not_a_bounded_name() {
            let a: OpenArgs = serde_json::from_value(serde_json::json!({
                "host": "db.internal",
                "credential_key": "default (approved by your administrator)"
            }))
            .expect("deserializes");
            let e = open(a).expect_err("refused");
            assert_eq!(e.kind, act_sdk::constants::ERR_INVALID_ARGS);
        }

        /// A poisoned session answers without reaching the store — the whole
        /// point of the flag. Reachable on the host target precisely because
        /// it returns before the first `await`.
        #[test]
        fn a_poisoned_session_refuses_before_it_asks_the_store_again() {
            let id = open(args("db.internal")).expect("opens");
            assert!(poisoned(&id).is_none(), "a fresh session is not poisoned");
            SESSIONS.with_mut(&id, |s| s.credential_rejected = true);
            let e = poisoned(&id).expect("poisoned");
            assert_eq!(e.kind, creds::ERR_CREDENTIAL_REQUIRED);
            assert!(e.message.contains("act secret set"), "got {}", e.message);
            close(id);
        }

        /// `secret-request` leaves the component for the host, which may show
        /// it to a human and record it. Nothing in it is caller-echoed.
        #[test]
        fn the_secret_request_names_the_key_and_describes_the_target_only() {
            let a: OpenArgs = serde_json::from_value(serde_json::json!({
                "connection_string": "postgres://db.internal:5433/app?user=alice",
                "credential_key": "reporting"
            }))
            .expect("deserializes");
            let id = open(a).expect("opens");
            let (target, key) = SESSIONS
                .with(&id, |s| (s.target.clone(), s.credential_key.clone()))
                .expect("live");
            let want = secret_request(&target, &key);
            assert_eq!(want.key, "reporting");
            assert_eq!(
                want.resource.as_deref(),
                Some("postgres://db.internal:5433/app")
            );
            // A shape filter would constrain what the store may return;
            // ACT-AUTH §1.1.6 says it must not.
            assert!(want.kind.is_none());
            close(id);
        }

        /// The tier gate runs before the credential fetch, so a statement the
        /// session was never going to be allowed to run cannot put a consent
        /// prompt in front of a human.
        #[test]
        fn the_tier_gate_refuses_without_reaching_the_credential_store() {
            let id = open(args("db.internal")).expect("opens");
            let e = gate(&id, "DROP TABLE users").expect_err("refused");
            assert_eq!(e.kind, act_sdk::constants::ERR_CAPABILITY_DENIED);
            assert!(gate(&id, "SELECT 1").is_ok());
            close(id);
        }
    }
}
