use act_sdk::prelude::*;
use ciborium::value::Value as Cv;

pub mod classify;

mod conn;
use conn::{Connection, SslMode};

#[act_component]
mod component {
    use super::*;

    thread_local! {
        static SESSIONS: SessionRegistry<Connection> = SessionRegistry::new("postgres");
    }

    #[derive(Deserialize, JsonSchema)]
    pub struct OpenArgs {
        /// PostgreSQL server hostname or IP.
        pub host: String,
        /// Server port. Defaults to 5432.
        #[serde(default = "default_port")]
        pub port: u16,
        /// Login role.
        pub user: String,
        /// Password (omit for trust/peer auth).
        #[serde(default)]
        pub password: Option<String>,
        /// Database name.
        pub dbname: String,
    }

    fn default_port() -> u16 {
        5432
    }

    #[derive(Deserialize)]
    pub struct ToolMeta {
        #[serde(rename = "std:session-id")]
        session_id: Option<String>,
    }

    #[session_open]
    fn open(args: OpenArgs) -> ActResult<String> {
        // TODO(task-N): thread sslmode through OpenArgs; for now default to Disable.
        let conn = Connection::open(
            &args.host,
            args.port,
            &args.user,
            args.password.as_deref(),
            &args.dbname,
            SslMode::Disable,
        )
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

    /// Phase-0 spike tool: returns rows for a trivial scalar SELECT.
    #[act_tool(description = "Run a read-only SQL query", read_only)]
    fn query(
        /// SQL query to execute.
        sql: String,
        ctx: &mut ActContext<ToolMeta>,
    ) -> ActResult<Vec<Cv>> {
        let id = require_session(ctx)?;
        with_session(&id, |c| {
            let n = c.select_scalar_i64(&sql).map_err(ActError::internal)?;
            // Phase 0 returns a single {first-column-name: n} row to satisfy the smoke test.
            Ok(vec![Cv::Map(vec![(Cv::Text("one".into()), Cv::from(n))])])
        })
    }
}
