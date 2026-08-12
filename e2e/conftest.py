"""Shared fixtures for the MCP-driven e2e suite.

The suite drives the packed component through `act run --mcp` over stdio with
a real MCP client, so what the tests observe is what an agent observes.

`postgres` is a session-provider. The old suite pre-opened one session per
host process via `act run --session-args ...` — two processes, one per
capability tier (`mode=full` and `mode=read-only`). That pattern is what is
hanging this component's host today: opening the session happens *before*
the listener binds, so a stall inside `open-session` means the port never
comes up, and there is no diagnostic — just a dead port.

This suite instead drives the MCP bridge's *virtual* `open_session` /
`close_session` tools during normal serving (ACT-MCP §4.1): the host binds
its listener with nothing pre-opened, and each test opens its own session
after the connection is already up. That failure mode cannot happen here.
Session-of-1 itself (the `--session-args` path) is already covered by
act-cli's own `session_of_1_mcp.rs`, so nothing is lost by not re-testing it.
"""

import json
import os
import shlex
import socket
import subprocess
import pytest
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Measured in docs/specs/2026-08-08-e2e-harness-findings.md, question 1.
from mcp.shared.exceptions import McpError

WASM = "target/wasm32-wasip2/release/component_postgres.wasm"
COMPONENT_ROOT = Path(__file__).parent.parent

# ACT's audit trail writes to stderr unconditionally — it is not governed by
# RUST_LOG — so it is redirected to a file rather than left to flood pytest.
LOG_FILE = Path(".pytest-act-stderr.log")

# Matches compose.yaml: postgres:16, container port 5432 published on the
# host as 5434, POSTGRES_PASSWORD=postgres (the image's default user and
# database are both "postgres"). sslmode=disable: the container has no TLS
# certificate configured.
PG_CONN = {
    "host": "127.0.0.1",
    "port": 5434,
    "user": "postgres",
    "password": "postgres",
    "dbname": "postgres",
    "sslmode": "disable",
}


@pytest.fixture(scope="session", autouse=True)
def postgres_up():
    """Confirm a real PostgreSQL is reachable before any test runs.

    Mirrors `wasm_path`'s probe-and-fail shape rather than starting the
    database itself: a fixture that silently provisions the thing under test
    would make CI green precisely when provisioning is broken (the same
    reasoning that keeps `wasm_path` from running `just pack` on your
    behalf). The justfile's `test` recipe runs `docker compose up -d --wait`
    before pytest; if that didn't happen (or failed), fail here with a
    remedy message instead of a raw connection-refused buried inside
    whichever test happens to open a session first.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect((PG_CONN["host"], PG_CONN["port"]))
        except OSError as e:
            pytest.fail(
                f"PostgreSQL not reachable at {PG_CONN['host']}:{PG_CONN['port']} ({e}) "
                "— run `docker compose up -d --wait` first"
            )


@pytest.fixture(scope="session")
def act_command() -> list[str]:
    """The ACT invocation, honouring the same override the justfile uses.

    Parsed with shlex, not treated as a single path: the justfile's own
    default for its `act` variable is `npx @actcore/act` — two words — which
    cannot be `argv[0]` for a non-shell `subprocess.run`/`StdioTransport`
    call. A bare `os.environ.get("ACT", "act")` string breaks that default;
    splitting it is what makes both forms ("act" on PATH, and the npx
    two-word default) actually spawn.
    """
    return shlex.split(os.environ.get("ACT", "act"))


@pytest.fixture(scope="session")
def wasm_path(act_command: list[str]) -> Path:
    """The packed component.

    Existence is not enough and neither is a fresh mtime: `cargo build`
    produces a wasm with no `act:component` custom section, and an unpacked
    artifact declares no capability ceiling, so every grant is refused as
    "outside ceiling" and the failures point anywhere but here. This has
    already bitten repeatedly in this workspace, so the fixture checks the
    section rather than the file.
    """
    path = Path(WASM)
    if not path.exists():
        pytest.fail(f"{path} is missing — run `just build` first")
    probe = subprocess.run(
        [*act_command, "inspect", "component-manifest", str(path)],
        capture_output=True, text=True,
    )
    name = json.loads(probe.stdout or "{}").get("std", {}).get("name", "unknown")
    if name in ("", "unknown"):
        pytest.fail(f"{path} is built but not packed — run `just pack`")
    return path


@pytest.fixture
async def client(act_command: list[str], wasm_path: Path):
    """An MCP client granted the component's full declared `wasi:sockets`
    ceiling (act.toml allows any host on the standard PostgreSQL ports), with
    no session pre-opened — see the module docstring for why. Every test
    that needs a session opens its own via the virtual `open_session` tool,
    through the `session_id`/`readonly_session_id` fixtures below.

    Function-scoped, fresh process per test: the component holds live
    connections in a per-process session registry, so sharing one process
    across tests would let a session opened by one test leak into another.
    """
    transport = StdioTransport(
        command=act_command[0],
        args=[*act_command[1:], "run", str(wasm_path), "--mcp", "--allow", "wasi:sockets"],
        keep_alive=False,
        log_file=LOG_FILE,
    )
    async with Client(transport) as connected:
        yield connected


async def _open_session(client, mode: str) -> str:
    """Call the virtual `open_session` tool.

    Its argument shape is the component's `get-open-session-args-schema`
    directly — no wrapper key — and its result is a JSON object in
    `content[0].text`, carrying `{"id": ..., "metadata": {...}}`
    (ACT-MCP §4.1). This is NOT `structured_content`: the synthesized
    session tools bypass the normal tool-result folding a real tool call
    goes through.
    """
    result = await client.call_tool("open_session", {**PG_CONN, "mode": mode})
    return json.loads(result.content[0].text)["id"]


async def _close_session(client, session_id: str):
    # `close_session`'s one argument is `session_id` itself, a plain
    # top-level key — it is the object of the close, not contextual
    # metadata, unlike `std:session-id` on every other tool call.
    await client.call_tool("close_session", {"session_id": session_id})


@pytest.fixture
async def session_id(client):
    """A session in `mode=full` — the capability tier most tests need.
    Matches the old justfile's first `--session-args` host.
    """
    sid = await _open_session(client, "full")
    yield sid
    await _close_session(client, sid)


@pytest.fixture
async def readonly_session_id(client):
    """A session in `mode=read-only`, matching the old justfile's second
    `--session-args` host — used only by the tier-gate test.
    """
    sid = await _open_session(client, "read-only")
    yield sid
    await _close_session(client, sid)


@pytest.fixture
def with_session():
    """Merge a session id into a tool call's arguments via the argument
    metadata channel: `{"_meta": {"std:session-id": sid}}` inside
    `arguments`, keeping the `std:` spelling. That channel is ordinary JSON
    inside `params.arguments` and is deliberately exempt from the
    `dev.actcore/*` respelling transport-level metadata goes through.
    """

    def _with(session_id: str, **kwargs) -> dict:
        return {**kwargs, "_meta": {"std:session-id": session_id}}

    return _with


@pytest.fixture
def expect_error():
    """Assert a call fails with a specific ACT error kind, and optionally a
    substring of the human-readable error message.

    Exposed as a fixture rather than a plain function so tests never have to
    import from `conftest` — that import only resolves when the test
    directory happens to be on `sys.path`, which is not something to rely on.

    Measured, not assumed. `call-tool` in `act:tools` returns a bare
    `tool-result` with NO `result<>` wrapper — only `list-tools` has one — so
    a guest reporting a failed tool call can only do it through
    `tool-event::error`, which arrives as a result with `is_error` set and the
    kind in `_meta`. **That is the path a tool test will take**, and on that
    path the human message lands in `content[0].text`.

    The JSON-RPC error path exists for failures that are not the guest's tool
    body: `list-tools`, the session operations, a wasmtime trap, an
    unreachable actor. It raises `mcp.shared.exceptions.McpError` with the
    payload at `exc.error.data` and the message at `exc.error.message`. No
    tool test in this suite is expected to reach it, but both are handled
    here so callers need not care.
    """

    async def _expect(client, tool: str, arguments: dict, kind: str, *, message_contains: str | None = None):
        try:
            result = await client.call_tool(tool, arguments, raise_on_error=False)
        except McpError as exc:
            data = getattr(getattr(exc, "error", None), "data", None) or {}
            assert data.get("dev.actcore/error-kind") == kind, (
                f"expected {kind} on the JSON-RPC error path, got {data!r}"
            )
            if message_contains is not None:
                message = getattr(exc.error, "message", "") or ""
                assert message_contains in message, (
                    f"expected message to contain {message_contains!r}, got {message!r}"
                )
            return

        assert result.is_error, f"expected {tool} to fail, got {result!r}"
        meta = result.meta or {}
        assert meta.get("dev.actcore/error-kind") == kind, (
            f"expected {kind} on the isError path, got {meta!r}"
        )
        if message_contains is not None:
            text = result.content[0].text if result.content else ""
            assert message_contains in text, (
                f"expected message to contain {message_contains!r}, got {text!r}"
            )

    return _expect
