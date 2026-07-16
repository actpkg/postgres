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

    // ── Tier gate helper ─────────────────────────────────────────────────────

    fn gate(conn: &Connection, sql: &str) -> ActResult<()> {
        mode::require_tier(conn.mode(), sql)
            .map(|_| ())
            .map_err(|g: mode::GateError| ActError::capability_denied(g.summary))
    }

    // ── Tools ─────────────────────────────────────────────────────────────────

    #[act_tool(
        description = "Execute a read-only SQL query (SELECT/CTE) and return rows. \
                       Rejected if it is not read-only or exceeds the session mode.",
        read_only
    )]
    fn query(
        /// A single read-only SQL statement.
        sql: String,
        /// Bind values for $1, $2, ... (optional).
        params: Option<Vec<convert::PgParam>>,
        /// Override the session's default row cap (optional).
        max_rows: Option<u32>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
            gate(c, &sql)?;
            let cap = max_rows.map(|n| n as usize).unwrap_or(c.default_max_rows());
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
    fn execute(
        /// A single SQL statement.
        sql: String,
        /// Bind values for $1, $2, ... (optional).
        params: Option<Vec<convert::PgParam>>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
            gate(c, &sql)?;
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
    fn list_schemas(ctx: &mut ActContext<ToolMeta>) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            let sql = "SELECT schema_name FROM information_schema.schemata \
                       WHERE schema_name NOT IN ('pg_catalog','information_schema') \
                       AND schema_name NOT LIKE 'pg_toast%' AND schema_name NOT LIKE 'pg_temp%' \
                       ORDER BY schema_name";
            // Catalog reads are always db:read; gate for consistency with query/execute
            // (and so a future tightening of read access is enforced here too).
            gate(c, sql)?;
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
    fn list_tables(
        /// Schema to inspect. Defaults to 'public'.
        schema: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            let s = schema.unwrap_or_else(|| "public".to_string());
            let sql = "SELECT table_name, table_type FROM information_schema.tables \
                       WHERE table_schema = $1 ORDER BY table_name";
            gate(c, sql)?;
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
    fn describe_table(
        /// Table name.
        table: String,
        /// Schema. Defaults to 'public'.
        schema: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            let s = schema.unwrap_or_else(|| "public".to_string());
            let sql = "SELECT column_name, data_type, is_nullable, column_default \
                       FROM information_schema.columns \
                       WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position";
            gate(c, sql)?;
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
    fn explain_query(
        /// SQL statement to explain.
        sql: String,
        /// Run EXPLAIN ANALYZE (executes the query). Default false.
        analyze: Option<bool>,
        /// Output format: text | json. Default text.
        format: Option<String>,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Cv> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            classify::assert_single_statement(&sql).map_err(ActError::invalid_args)?;
            let analyze = analyze.unwrap_or(false);
            // analyze=true executes the statement, so it must clear the real tier gate.
            if analyze {
                gate(c, &sql)?;
            }
            let plan = c
                .explain(&sql, analyze, format.as_deref().unwrap_or("text"))
                .map_err(ActError::internal)?;
            Ok(Cv::Array(plan))
        })
    }
}
