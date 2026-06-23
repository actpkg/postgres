use act_sdk::prelude::*;
use ciborium::value::Value as Cv;

pub mod classify;
pub mod convert;
pub mod mode;

mod conn;
use conn::{ConnConfig, Connection, SslMode};

#[act_component]
mod component {
    use super::*;

    thread_local! {
        static SESSIONS: SessionRegistry<Connection> = SessionRegistry::new("postgres");
    }

    // ── OpenArgs ──────────────────────────────────────────────────────────────

    #[derive(Deserialize, JsonSchema)]
    pub struct OpenArgs {
        /// Full DSN, e.g. `postgres://user:pass@host:5432/db?sslmode=require`.
        /// If set, the discrete fields below are ignored.
        #[serde(default)]
        pub connection_string: Option<String>,
        /// Server hostname or IP (when not using connection_string).
        #[serde(default)]
        pub host: Option<String>,
        /// Server port. Defaults to 5432.
        #[serde(default = "default_port")]
        pub port: u16,
        /// Login role.
        #[serde(default)]
        pub user: Option<String>,
        /// Password.
        #[serde(default)]
        pub password: Option<String>,
        /// Database name.
        #[serde(default)]
        pub dbname: Option<String>,
        /// TLS mode: disable | prefer | require. Default prefer.
        #[serde(default)]
        pub sslmode: SslModeArg,
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

    fn default_port() -> u16 {
        5432
    }
    fn default_max_rows() -> u32 {
        1000
    }

    /// TLS mode selector for session open arguments.
    #[derive(Deserialize, JsonSchema, Default, Clone, Copy)]
    #[serde(rename_all = "lowercase")]
    pub enum SslModeArg {
        /// No TLS; plain TCP.
        Disable,
        /// Attempt TLS. v1: no plaintext fallback (same behaviour as require).
        #[default]
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

    // ── Session lifecycle ─────────────────────────────────────────────────────

    #[session_open]
    fn open(args: OpenArgs) -> ActResult<String> {
        let conn = Connection::open(ConnConfig {
            connection_string: args.connection_string,
            host: args.host,
            port: args.port,
            user: args.user,
            password: args.password,
            dbname: args.dbname,
            sslmode: SslMode::from(args.sslmode),
            statement_timeout_ms: args.statement_timeout_ms,
            mode: args.mode,
            max_rows: args.max_rows as usize,
        })
        .map_err(ActError::internal)?;
        Ok(SESSIONS.with(|r| r.insert(conn)))
    }

    #[session_close]
    fn close(session_id: String) {
        SESSIONS.with(|r| {
            r.remove(&session_id);
        });
    }

    fn with_session<F, T>(id: &str, f: F) -> ActResult<T>
    where
        F: FnOnce(&Connection) -> ActResult<T>,
    {
        SESSIONS
            .with(|r| r.with(id, f))
            .ok_or_else(|| ActError::session_not_found(format!("Unknown session-id: {id}")))?
    }

    fn require_session(ctx: &mut ActContext<ToolMeta>) -> ActResult<String> {
        ctx.metadata()
            .session_id
            .clone()
            .ok_or_else(|| ActError::session_not_found("Missing std:session-id metadata"))
    }

    // ── Tools (Phase-0 placeholder; real tools wired in Task 8) ──────────────

    /// Phase-0 spike tool: runs a read-only query and returns CBOR rows.
    /// Replaced by the full tool suite in Task 8.
    #[act_tool(description = "Run a read-only SQL query", read_only)]
    fn query(
        /// SQL query to execute.
        sql: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Vec<Cv>> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            let (rows, _truncated) = c
                .query_rows(&sql, &[], c.default_max_rows())
                .map_err(ActError::internal)?;
            Ok(rows)
        })
    }
}
