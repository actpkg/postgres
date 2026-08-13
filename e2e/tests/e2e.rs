//! Drive the packed postgres component through `act run --mcp` with a real
//! MCP client.
//!
//! This replaces the python fastmcp/pytest suite that used to live in this
//! directory: the tests observe exactly what an agent observes, over the same
//! client stack (`rmcp`) the host bridge itself is built on.
//!
//! `postgres` is a session-provider whose credential is NOT a session
//! argument: the password is fetched from the host credential store on the
//! first tool call, because `get-secret` needs a session the host has already
//! marked live and it does that only after `open_session` returns (ACT-AUTH
//! §1.1.4). Two things follow for this suite, and both are load-bearing: the
//! host needs `--allow act:credentials` and a `--credentials-backend` (see
//! `credential_store`), and a connection failure now surfaces on the first
//! tool call rather than at `open_session`.
//!
//! This suite drives the MCP bridge's *virtual* `open_session` /
//! `close_session` tools during normal serving (ACT-MCP §4.1): the host binds
//! its listener with nothing pre-opened, and each test opens its own session
//! after the connection is already up. (The old suite pre-opened one session
//! per host process via `act run --session-args ...` — a pattern that hides
//! `open-session` stalls behind a listener that never comes up. Session-of-1
//! itself is covered by act-cli's own `session_of_1_mcp.rs`.)
//!
//! needs: PostgreSQL at 127.0.0.1:5434 (user `postgres`, db `postgres`, no
//!        TLS, password `postgres`) — the compose.yaml service; the
//!        justfile's `test` recipe brings it up (`docker compose up -d
//!        --wait`).
//!
//! Env: WASM — path to the packed component (default: the component's
//!      release build output);
//!      ACT  — the act invocation (default `act`; `npx @actcore/act`, the
//!             component justfile's default, also works — whitespace-split,
//!             like the shlex.split the python conftest did).

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use tokio::{io::AsyncWriteExt, sync::Mutex as AsyncMutex};

/// `().serve(transport)` hands back the client-role service running over the
/// child process: role first, the unit client handler second.
type Client = rmcp::service::RunningService<rmcp::service::RoleClient, ()>;
type JsonObject = serde_json::Map<String, Value>;

/// Matches compose.yaml: postgres:16, container port 5432 published on the
/// host as 5434 (the image's default user and database are both "postgres").
/// sslmode=disable: the container has no TLS certificate configured.
///
/// **No password.** These are session arguments, which are plaintext in the
/// agent's context and in the host's session record; the password lives in
/// the credential store `credential_store()` provisions, and the component
/// fetches it on its first tool call.
fn pg_conn() -> JsonObject {
    json!({
        "host": "127.0.0.1",
        "port": 5434,
        "user": "postgres",
        "dbname": "postgres",
        "sslmode": "disable",
    })
    .as_object()
    .expect("PG_CONN is an object")
    .clone()
}

/// What compose.yaml sets POSTGRES_PASSWORD to, and therefore what goes into
/// the store rather than into the session args.
const PG_PASSWORD: &str = "postgres";

/// Deliberately loose. `act run --mcp` instantiates the component before it
/// answers `initialize`, so "connect" includes that cost — seconds, and on a
/// loaded runner it varies. The bound sits well above the worst observed
/// cost and still well below a CI per-test timeout, keeping this the
/// diagnostic that fires first.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

fn wasm_path() -> PathBuf {
    PathBuf::from(std::env::var("WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/wasm32-wasip2/release/component_postgres.wasm"
        )
        .into()
    }))
}

/// The ACT invocation, honouring the same override the component justfile
/// uses. Its default there is `npx @actcore/act` — two words — which cannot
/// be `argv[0]` for a non-shell spawn, so the value is whitespace-split into
/// program + leading args. Quoted paths with spaces are not a form this
/// fleet passes through `ACT`; a full shlex is deliberately not pulled in.
fn act_argv() -> Vec<String> {
    std::env::var("ACT")
        .unwrap_or_else(|_| "act".into())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The python conftest's `postgres_up` fixture: confirm a real PostgreSQL is
/// reachable before any test runs. A probe, not provisioning — a fixture
/// that silently provisions the thing under test would make CI green
/// precisely when provisioning is broken. The justfile's `test` recipe runs
/// `docker compose up -d --wait` before the harness; if that didn't happen,
/// fail with a remedy message instead of a raw connection-refused buried
/// inside whichever test happens to open a session first.
async fn postgres_up() {
    match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", 5434)),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!(
            "PostgreSQL not reachable at 127.0.0.1:5434 ({e}) — run `docker compose up -d --wait` first"
        ),
        Err(_) => panic!(
            "PostgreSQL not reachable at 127.0.0.1:5434 (connect timed out) — run `docker compose up -d --wait` first"
        ),
    }
}

/// Session-scoped, like the python `credential_store` fixture: one store per
/// test process, provisioned on first use.
static CREDENTIAL_STORE: OnceCell<String> = OnceCell::const_new();

/// A `--credentials-backend` argument naming a store that holds the
/// container's password under the key the component looks for by default.
///
/// Naming the field is not optional: `act secret set` has no default field
/// set — a credential IS its named fields — which is what the component's
/// own error messages print.
async fn credential_store() -> &'static str {
    CREDENTIAL_STORE
        .get_or_init(|| async {
            // The python suite skipped here when `act secret` was absent —
            // the feature under test does not exist. This port fails instead:
            // the assertion must not silently turn green.
            let argv = act_argv();
            let probe = {
                let mut cmd = std::process::Command::new(&argv[0]);
                cmd.args(&argv[1..]);
                cmd.args(["secret", "--help"])
                    .output()
                    .expect("run `act secret --help`")
            };
            if !probe.status.success() {
                panic!("this `act` has no credential store (`act secret`); nothing to drive");
            }

            // tmp_path_factory.mktemp('credentials'): a directory unique to
            // this test process.
            let dir = std::env::temp_dir().join(format!(
                "act-postgres-e2e-credentials-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create the credentials dir");
            let backend = format!("file:{}", dir.display());

            let mut cmd = tokio::process::Command::new(&argv[0]);
            cmd.args(&argv[1..]);
            cmd.args(["secret", "set"])
                .arg(wasm_path())
                .args([
                    "--key",
                    "default",
                    "--field",
                    "postgres:password",
                    "--fields-stdin",
                    "--credentials-backend",
                ])
                .arg(&backend);
            let mut child = cmd
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn `act secret set`");
            child
                .stdin
                .as_mut()
                .expect("stdin was piped")
                .write_all(json!({"postgres:password": PG_PASSWORD}).to_string().as_bytes())
                .await
                .expect("write the credential fields");
            let written = child.wait_with_output().await.expect("`act secret set`");
            // Not a skip: the probe above proved the subcommand exists, so a
            // failure here is a store that broke rather than one that is
            // absent, and skipping would turn the whole suite green while
            // proving nothing.
            assert!(
                written.status.success(),
                "`act secret set` failed even though `act secret` exists, so the credential \
                 store is broken rather than missing:\n{}",
                String::from_utf8_lossy(&written.stderr)
            );
            backend
        })
        .await
}

/// An MCP client granted the component's full declared `wasi:sockets`
/// ceiling (act.toml allows any host on the standard PostgreSQL ports) and
/// its credential store, with no session pre-opened. Every test opens its
/// own session via the virtual `open_session` tool.
///
/// `--allow act:credentials` is mandatory, not tidiness: the default policy
/// is ask-by-default, a headless run degrades `ask` to deny, and a denied
/// store makes every tool call fail with `std:credential-required` on its
/// first attempt to connect.
///
/// Fresh process per test: the component holds live connections in a
/// per-process session registry, so sharing one process across tests would
/// let a session opened by one test leak into another.
async fn connect() -> Client {
    postgres_up().await;
    let backend = credential_store().await.to_string();

    let argv = act_argv();
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg("run").arg(wasm_path()).arg("--mcp");
    cmd.args(["--allow", "wasi:sockets", "--allow", "act:credentials"]);
    cmd.arg("--credentials-backend").arg(&backend);

    let transport =
        TokioChildProcess::new(cmd).expect("spawn act run --mcp");
    // Bound the connect, not the test body. A stalled handshake otherwise
    // consumes the whole runner timeout with no diagnostic at all — which is
    // precisely how the webdriver-bidi CI hang presented for hours.
    tokio::time::timeout(CONNECT_TIMEOUT, ().serve(transport))
        .await
        .expect(
            "MCP client did not connect within 120s; act's stderr, if it wrote any, is \
             interleaved above",
        )
        .expect("rmcp handshake with act run --mcp")
}

fn first_text_block(result: &rmcp::model::CallToolResult) -> &rmcp::model::TextContent {
    match result.content.first() {
        Some(rmcp::model::ContentBlock::Text(t)) => t,
        other => panic!("expected the first content block to be Text, got: {other:?}"),
    }
}

/// A successful tool call. Mirrors fastmcp's default raise-on-error, which
/// every plain `client.call_tool(...)` in the python suite relied on: an
/// `isError` result fails the test here, with the guest's own message.
async fn call(client: &Client, tool: &str, args: JsonObject) -> rmcp::model::CallToolResult {
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await
        .expect("call_tool");
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool} failed: {}",
        first_text_block(&result).text
    );
    result
}

/// The python conftest's `expect_error` fixture: assert a call fails with a
/// specific ACT error kind, and optionally a substring of the human-readable
/// error message.
///
/// Measured, not assumed. `call-tool` in `act:tools` returns a bare
/// `tool-result` with NO `result<>` wrapper — only `list-tools` has one — so
/// a guest reporting a failed tool call can only do it through
/// `tool-event::error`, which arrives as a result with `is_error` set and the
/// kind in `_meta`. **That is the path a tool test will take**, and on that
/// path the human message lands in `content[0].text`.
///
/// The JSON-RPC error path exists for failures that are not the guest's tool
/// body: `list-tools`, the session operations, a wasmtime trap, an
/// unreachable actor. No tool test in this suite is expected to reach it, but
/// both are handled here so callers need not care.
async fn expect_error(
    client: &Client,
    tool: &str,
    arguments: JsonObject,
    kind: &str,
    message_contains: Option<&str>,
) {
    match client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(arguments))
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => {
            let data_kind = e
                .data
                .as_ref()
                .and_then(|d| d.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str());
            assert_eq!(
                data_kind,
                Some(kind),
                "expected {kind} on the JSON-RPC error path, got {:?}",
                e.data
            );
            if let Some(needle) = message_contains {
                assert!(
                    e.message.contains(needle),
                    "expected message to contain {needle:?}, got {:?}",
                    e.message
                );
            }
        }
        Ok(result) => {
            assert_eq!(
                result.is_error,
                Some(true),
                "expected {tool} to fail, got {result:?}"
            );
            let meta_kind = result
                .meta
                .as_ref()
                .and_then(|m| m.0.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str());
            assert_eq!(
                meta_kind,
                Some(kind),
                "expected {kind} on the isError path, got {:?}",
                result.meta
            );
            if let Some(needle) = message_contains {
                let text = result
                    .content
                    .first()
                    .and_then(|b| match b {
                        rmcp::model::ContentBlock::Text(t) => Some(t.text.as_str()),
                        _ => None,
                    })
                    .unwrap_or("");
                assert!(
                    text.contains(needle),
                    "expected message to contain {needle:?}, got {text:?}"
                );
            }
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

/// The python test_credentials helper: call `tool`, assert it failed, and
/// return the human-readable message. Handles both failure paths so the
/// tests need not care which one a synthesized session tool takes:
/// `open_session` reports through the JSON-RPC error path, a real tool call
/// through `isError`.
async fn refusal_message(client: &Client, tool: &str, arguments: JsonObject) -> String {
    match client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(arguments))
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => e.message.to_string(),
        Ok(result) => {
            assert_eq!(
                result.is_error,
                Some(true),
                "expected {tool} to fail, got {result:?}"
            );
            result
                .content
                .first()
                .and_then(|b| match b {
                    rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .unwrap_or_default()
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

/// Call the virtual `open_session` tool: `pg_conn()` plus `extra`.
///
/// Its argument shape is the component's `get-open-session-args-schema`
/// directly — no wrapper key — and its result is a JSON object in
/// `content[0].text`, carrying `{"id": ..., "metadata": {...}}`
/// (ACT-MCP §4.1). This is NOT `structured_content`: the synthesized session
/// tools bypass the normal tool-result folding a real tool call goes through.
async fn open_session(client: &Client, extra: JsonObject) -> String {
    let mut args = pg_conn();
    args.extend(extra);
    let result = client
        .call_tool(CallToolRequestParams::new("open_session").with_arguments(args))
        .await
        .expect("call_tool open_session");
    assert_ne!(
        result.is_error,
        Some(true),
        "open_session failed: {}",
        first_text_block(&result).text
    );
    let opened: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("open_session reply is JSON");
    opened["id"]
        .as_str()
        .expect("open_session reply carries a string id")
        .to_string()
}

/// A session in `mode=full` — the capability tier most tests need.
async fn open_session_full(client: &Client) -> String {
    open_session(client, json!({"mode": "full"}).as_object().unwrap().clone()).await
}

/// A session in `mode=read-only` — used only by the tier-gate tests.
async fn open_session_readonly(client: &Client) -> String {
    open_session(client, json!({"mode": "read-only"}).as_object().unwrap().clone()).await
}

/// `close_session`'s one argument is `session_id` itself, a plain top-level
/// key — it is the object of the close, not contextual metadata, unlike
/// `std:session-id` on every other tool call.
async fn close_session(client: &Client, session_id: &str) {
    let args = json!({"session_id": session_id})
        .as_object()
        .unwrap()
        .clone();
    let result = client
        .call_tool(CallToolRequestParams::new("close_session").with_arguments(args))
        .await
        .expect("call_tool close_session");
    assert_ne!(
        result.is_error,
        Some(true),
        "close_session failed: {}",
        first_text_block(&result).text
    );
}

/// Merge a session id into a tool call's arguments via the argument
/// metadata channel: `{"_meta": {"std:session-id": sid}}` inside
/// `arguments`, keeping the `std:` spelling. That channel is ordinary JSON
/// inside `params.arguments` and is deliberately exempt from the
/// `dev.actcore/*` respelling transport-level metadata goes through.
fn with_session(session_id: &str, args: Value) -> JsonObject {
    let mut args = args
        .as_object()
        .expect("tool arguments are an object")
        .clone();
    args.insert("_meta".into(), json!({"std:session-id": session_id}));
    args
}

// ---------------------------------------------------------------------------
// test_list_tools.py
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_tools_includes_all_six() {
    let client = connect().await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    for n in [
        "query",
        "execute",
        "list_schemas",
        "list_tables",
        "describe_table",
        "explain_query",
    ] {
        assert!(
            tools.iter().any(|t| t.name == n),
            "{n} must be among the tools, got: {:?}",
            tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>()
        );
    }
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// test_query_execute.py
// ---------------------------------------------------------------------------

/// DDL + write + read round-trip (session runs in mode=full).
#[tokio::test]
async fn query_execute_round_trip() {
    let client = connect().await;
    let sid = open_session_full(&client).await;

    call(
        &client,
        "execute",
        with_session(&sid, json!({"sql": "DROP TABLE IF EXISTS act_e2e_users"})),
    )
    .await;
    call(
        &client,
        "execute",
        with_session(
            &sid,
            json!({"sql": "CREATE TABLE act_e2e_users (id serial primary key, name text not null, age int)"}),
        ),
    )
    .await;

    let result = call(
        &client,
        "execute",
        with_session(
            &sid,
            json!({
                "sql": "INSERT INTO act_e2e_users (name, age) VALUES ($1, $2)",
                "params": ["Alice", 30],
            }),
        ),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("execute returns an object, so it is structured");
    assert_eq!(structured["rows_affected"], json!(1), "{structured}");

    let result = call(
        &client,
        "query",
        with_session(&sid, json!({"sql": "SELECT name, age FROM act_e2e_users ORDER BY id"})),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("query returns an object, so it is structured");
    let rows = structured["rows"].as_array().expect("rows is an array");
    assert_eq!(rows[0]["name"], json!("Alice"), "{structured}");
    assert_eq!(rows[0]["age"], json!(30), "{structured}");
    assert_eq!(structured["truncated"], json!(false), "{structured}");

    // max_rows cap sets the truncated flag.
    let result = call(
        &client,
        "query",
        with_session(
            &sid,
            json!({
                "sql": "SELECT * FROM generate_series(1, 5) AS g(n)",
                "max_rows": 2,
            }),
        ),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("query returns an object, so it is structured");
    assert_eq!(
        structured["rows"].as_array().map(Vec::len),
        Some(2),
        "{structured}"
    );
    assert_eq!(structured["truncated"], json!(true), "{structured}");

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// test_readonly.py
// ---------------------------------------------------------------------------

#[tokio::test]
async fn readonly_session_gates_writes() {
    let client = connect().await;
    let sid = open_session_readonly(&client).await;

    // A SELECT is allowed in read-only mode.
    let result = call(
        &client,
        "query",
        with_session(&sid, json!({"sql": "SELECT 1 AS ok"})),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("query returns an object, so it is structured");
    assert_eq!(structured["rows"][0]["ok"], json!(1), "{structured}");

    // A DDL write is rejected by the tier gate (capability_denied), NOT executed.
    expect_error(
        &client,
        "execute",
        with_session(&sid, json!({"sql": "CREATE TABLE should_not_exist (id int)"})),
        "std:capability-denied",
        Some("db:ddl"),
    )
    .await;

    // Prove the rejected DDL had NO side effect: the table must not exist.
    // (BOOL expression, since regclass is not a decoded type.)
    let result = call(
        &client,
        "query",
        with_session(
            &sid,
            json!({"sql": "SELECT to_regclass('public.should_not_exist') IS NULL AS missing"}),
        ),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("query returns an object, so it is structured");
    assert_eq!(structured["rows"][0]["missing"], json!(true), "{structured}");

    // Statement-stacking is rejected (single-statement guard) on the read path.
    expect_error(
        &client,
        "query",
        with_session(&sid, json!({"sql": "SELECT 1; DROP TABLE act_e2e_users"})),
        "std:invalid-args",
        None,
    )
    .await;

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// test_introspection.py
// ---------------------------------------------------------------------------

/// Self-contained: create our own table so this test needs nothing any other
/// test set up.
#[tokio::test]
async fn introspection_lists_schema_table_and_columns() {
    let client = connect().await;
    let sid = open_session_full(&client).await;

    call(
        &client,
        "execute",
        with_session(
            &sid,
            json!({"sql": "CREATE TABLE IF NOT EXISTS act_e2e_intro (id serial primary key, name text not null, age int)"}),
        ),
    )
    .await;

    // list_schemas/list_tables return bare arrays — no structured_content.
    let result = call(&client, "list_schemas", with_session(&sid, json!({}))).await;
    assert!(
        result.structured_content.is_none(),
        "list_schemas returns a bare array, got structured_content: {:?}",
        result.structured_content
    );
    let schemas: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("schemas is a JSON array");
    assert!(
        schemas
            .as_array()
            .expect("schemas is a JSON array")
            .iter()
            .any(|s| s["schema_name"] == "public"),
        "the public schema must be listed: {schemas}"
    );

    let result = call(
        &client,
        "list_tables",
        with_session(&sid, json!({"schema": "public"})),
    )
    .await;
    assert!(
        result.structured_content.is_none(),
        "list_tables returns a bare array, got structured_content: {:?}",
        result.structured_content
    );
    let tables: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("tables is a JSON array");
    assert!(
        tables
            .as_array()
            .expect("tables is a JSON array")
            .iter()
            .any(|t| t["table_name"] == "act_e2e_intro"),
        "act_e2e_intro must be listed: {tables}"
    );

    // describe_table returns an object ({table, columns}), so this one *is*
    // structured.
    let result = call(
        &client,
        "describe_table",
        with_session(&sid, json!({"table": "act_e2e_intro"})),
    )
    .await;
    let structured = result
        .structured_content
        .as_ref()
        .expect("describe_table returns an object, so it is structured");
    assert!(
        structured["columns"]
            .as_array()
            .expect("columns is an array")
            .iter()
            .any(|c| c["column_name"] == "name"),
        "columns must include name: {structured}"
    );

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// test_explain.py
// ---------------------------------------------------------------------------

/// Self-contained: explain a table-less query so this test needs nothing any
/// other test set up.
#[tokio::test]
async fn explain_query_returns_plan() {
    let client = connect().await;
    let sid = open_session_full(&client).await;

    let result = call(
        &client,
        "explain_query",
        with_session(
            &sid,
            json!({
                "sql": "SELECT n FROM generate_series(1, 100) AS g(n) WHERE n > 18",
                "format": "text",
            }),
        ),
    )
    .await;
    // explain_query returns a bare array (the plan rows), so the SDK does not
    // populate structured_content for it — only object-shaped results get
    // that (measured, same rule as filesystem's list_directory).
    assert!(
        result.structured_content.is_none(),
        "explain_query returns a bare array, got structured_content: {:?}",
        result.structured_content
    );
    let plan: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("plan is a JSON array");
    let plan = plan.as_array().expect("plan is a JSON array");
    assert!(plan.len() >= 1, "expected at least one plan row: {plan:?}");
    assert!(
        plan[0]["QUERY PLAN"].is_string(),
        "plan[0][\"QUERY PLAN\"] must be a string: {}",
        plan[0]
    );

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// test_info.py
// ---------------------------------------------------------------------------

/// The manifest probe from the python test_info.py: the packed artifact must
/// declare its name and a version. Also the fast-fail the python `wasm_path`
/// fixture provided — an unpacked wasm (raw `cargo build` output, no
/// `act:component` section) declares no ceiling, every grant is refused as
/// "outside ceiling", and the failures point anywhere but at the missing
/// metadata. The justfile's `test: build` ordering exists so this test finds
/// a packed artifact.
#[test]
fn manifest_reports_name_and_version() {
    let output = {
        let argv = act_argv();
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.args(["inspect", "component-manifest"])
            .arg(wasm_path())
            .output()
            .expect("run act inspect component-manifest")
    };
    assert!(
        output.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_slice(&output.stdout).expect("manifest is JSON");
    assert_eq!(
        manifest["std"]["name"], "postgres",
        "packed manifest must carry the component name"
    );
    assert!(
        manifest["std"]["version"].is_string(),
        "packed manifest must carry a version, got: {}",
        manifest["std"]["version"]
    );
}

// ---------------------------------------------------------------------------
// test_credentials.py
// ---------------------------------------------------------------------------

/// The security property the design exists to protect. `open_session`'s
/// schema is the component's `get-open-session-args-schema` verbatim, so
/// this is the same document an agent reads before deciding what to send.
#[tokio::test]
async fn open_session_schema_has_no_place_to_put_a_password() {
    let client = connect().await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let open_session = tools
        .iter()
        .find(|t| t.name == "open_session")
        .expect("open_session must be listed");
    let props = open_session
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("the schema has a properties object");

    for forbidden in ["password", "passwd", "pwd", "secret", "token", "auth", "api_key"] {
        assert!(
            !props.keys().any(|name| name.to_lowercase().contains(forbidden)),
            "open_session offers a place to put a {forbidden}: {:?}",
            props.keys().collect::<Vec<_>>()
        );
    }
    // The credential is named rather than carried.
    assert!(
        props.contains_key("credential_key"),
        "open_session must name the credential: {:?}",
        props.keys().collect::<Vec<_>>()
    );
    client.cancel().await.ok();
}

/// `credential_key` is the one name allowed to mention a credential, and
/// only because it names one instead of carrying it.
#[tokio::test]
async fn no_tool_takes_a_password() {
    let client = connect().await;
    for tool in client.list_all_tools().await.expect("list_all_tools") {
        let props: Vec<&String> = tool
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|p| p.keys().filter(|n| *n != "credential_key").collect())
            .unwrap_or_default();
        for forbidden in ["password", "passwd", "pwd", "secret", "token", "credential"] {
            assert!(
                !props.iter().any(|name| name.to_lowercase().contains(forbidden)),
                "{} takes a {forbidden}: {:?}",
                tool.name,
                props
            );
        }
    }
    client.cancel().await.ok();
}

/// A DSN is the spelling that does not look like a credential, which is why
/// all three of its password forms are refused — and refused at open, where
/// the caller can still see which argument it made. (The python suite
/// parametrized this over the three DSNs; one process serving all three
/// keeps the same per-DSN assertions at a third of the handshakes.)
#[tokio::test]
async fn a_dsn_carrying_a_password_is_refused_at_open() {
    let client = connect().await;
    for dsn in [
        "postgres://alice:hunter2@127.0.0.1:5434/postgres",
        "postgres://127.0.0.1:5434/postgres?password=hunter2",
        "host=127.0.0.1 port=5434 dbname=postgres password=hunter2",
    ] {
        let text = refusal_message(
            &client,
            "open_session",
            json!({"connection_string": dsn}).as_object().unwrap().clone(),
        )
        .await;
        assert!(
            !text.contains("hunter2"),
            "the refusal echoed the password: {text}"
        );
        assert!(
            text.contains("credential_key") || text.contains("credential store"),
            "{text}"
        );
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn a_host_carrying_userinfo_is_refused_at_open() {
    let client = connect().await;
    let mut args = pg_conn();
    args.insert("host".into(), json!("alice:hunter2@127.0.0.1"));
    let text = refusal_message(&client, "open_session", args).await;
    assert!(
        !text.contains("hunter2"),
        "the refusal echoed the password: {text}"
    );
    assert!(text.contains("userinfo"), "{text}");
    client.cancel().await.ok();
}

/// The positive half: the session args carry no password, the credential
/// store does, and the query runs. If the fetch path were broken this fails
/// with `std:credential-required` naming `act secret set`.
#[tokio::test]
async fn a_session_authenticates_from_the_store_without_ever_seeing_a_password() {
    let client = connect().await;
    let sid = open_session_readonly(&client).await;
    let result = call(
        &client,
        "query",
        with_session(&sid, json!({"sql": "SELECT current_user AS who"})),
    )
    .await;
    assert_ne!(
        result.is_error,
        Some(true),
        "{}",
        first_text_block(&result).text
    );
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

/// The behaviour change the credential store forces, asserted rather than
/// described: the role below does not exist, so the server answers SQLSTATE
/// 28000 — but only once something asks it, and nothing does until the first
/// tool call. `open_session` therefore succeeds.
///
/// The loop asserts the poison flag: the second call must be refused
/// *without* another `get-secret`, which on an interactive host would be
/// another consent prompt for a credential already known to be wrong.
#[tokio::test]
async fn a_credential_the_server_rejects_fails_on_the_first_call_not_at_open() {
    let client = connect().await;
    let mut args = pg_conn();
    args.insert("user".into(), json!("nobody_by_that_name"));
    args.insert("mode".into(), json!("read-only"));
    let sid = open_session(&client, args).await;

    for _ in 0..2 {
        expect_error(
            &client,
            "query",
            with_session(&sid, json!({"sql": "SELECT 1"})),
            "std:credential-required",
            Some("act secret set"),
        )
        .await;
    }

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

/// The tier gate runs first. A statement the session was never going to be
/// allowed to run must not reach the credential store, where on an
/// interactive host it would put a consent prompt in front of a human.
#[tokio::test]
async fn a_forbidden_statement_is_refused_before_any_credential_is_fetched() {
    let client = connect().await;
    let sid = open_session_readonly(&client).await;
    expect_error(
        &client,
        "execute",
        with_session(&sid, json!({"sql": "DROP TABLE anything"})),
        "std:capability-denied",
        None,
    )
    .await;
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}
