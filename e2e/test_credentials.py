"""The password is not an argument — not a tool one, not a session one.

Everything here is observed through the MCP surface an agent actually sees:
the published schemas, and the component's own refusals. The one test that
reaches the database does so to prove the *positive* half — that a session
opened with no password still authenticates — which is the whole point of
moving the credential into the host store.
"""

import json

import pytest
from mcp.shared.exceptions import McpError


async def refusal_message(client, tool: str, arguments: dict) -> str:
    """Call `tool`, assert it failed, and return the human-readable message.

    Handles both failure paths so the tests need not care which one a
    synthesized session tool takes: `open_session` reports through the
    JSON-RPC error path, a real tool call through `isError`.
    """
    try:
        result = await client.call_tool(tool, arguments, raise_on_error=False)
    except McpError as exc:
        return getattr(exc.error, "message", "") or ""
    assert result.is_error, f"expected {tool} to fail, got {result!r}"
    return result.content[0].text if result.content else ""


async def test_open_session_schema_has_no_place_to_put_a_password(client):
    """The security property the design exists to protect. `open_session`'s
    schema is the component's `get-open-session-args-schema` verbatim, so
    this is the same document an agent reads before deciding what to send.
    """
    tools = await client.list_tools()
    open_session = next(t for t in tools if t.name == "open_session")
    props = open_session.inputSchema.get("properties", {})

    for forbidden in ("password", "passwd", "pwd", "secret", "token", "auth", "api_key"):
        assert not any(forbidden in name.lower() for name in props), (
            f"open_session offers a place to put a {forbidden}: {sorted(props)}"
        )
    # The credential is named rather than carried.
    assert "credential_key" in props


async def test_no_tool_takes_a_password(client):
    """`credential_key` is the one name allowed to mention a credential, and
    only because it names one instead of carrying it.
    """
    for tool in await client.list_tools():
        props = [n for n in tool.inputSchema.get("properties", {}) if n != "credential_key"]
        for forbidden in ("password", "passwd", "pwd", "secret", "token", "credential"):
            assert not any(forbidden in name.lower() for name in props), (
                f"{tool.name} takes a {forbidden}: {sorted(props)}"
            )


@pytest.mark.parametrize(
    "dsn",
    [
        "postgres://alice:hunter2@127.0.0.1:5434/postgres",
        "postgres://127.0.0.1:5434/postgres?password=hunter2",
        "host=127.0.0.1 port=5434 dbname=postgres password=hunter2",
    ],
)
async def test_a_dsn_carrying_a_password_is_refused_at_open(client, dsn):
    """A DSN is the spelling that does not look like a credential, which is
    why all three of its password forms are refused — and refused at open,
    where the caller can still see which argument it made.
    """
    text = await refusal_message(client, "open_session", {"connection_string": dsn})
    assert "hunter2" not in text, f"the refusal echoed the password: {text}"
    assert "credential_key" in text or "credential store" in text, text


async def test_a_host_carrying_userinfo_is_refused_at_open(client, pg_conn):
    text = await refusal_message(
        client, "open_session", {**pg_conn, "host": "alice:hunter2@127.0.0.1"}
    )
    assert "hunter2" not in text, f"the refusal echoed the password: {text}"
    assert "userinfo" in text, text


async def test_a_session_authenticates_from_the_store_without_ever_seeing_a_password(
    client, with_session, pg_conn
):
    """The positive half: `PG_CONN` carries no password, the credential store
    does, and the query runs. If the fetch path were broken this fails with
    `std:credential-required` naming `act secret set`.
    """
    opened = await client.call_tool("open_session", {**pg_conn, "mode": "read-only"})
    sid = json.loads(opened.content[0].text)["id"]
    try:
        result = await client.call_tool(
            "query", with_session(sid, sql="SELECT current_user AS who")
        )
        assert not result.is_error, result.content[0].text
    finally:
        await client.call_tool("close_session", {"session_id": sid})


async def test_a_credential_the_server_rejects_fails_on_the_first_call_not_at_open(
    client, with_session, expect_error, pg_conn
):
    """The behaviour change the credential store forces, asserted rather than
    described: the role below does not exist, so the server answers SQLSTATE
    28000 — but only once something asks it, and nothing does until the first
    tool call. `open_session` therefore succeeds.

    The second call asserts the poison flag: it must be refused *without*
    another `get-secret`, which on an interactive host would be another
    consent prompt for a credential already known to be wrong.
    """
    opened = await client.call_tool(
        "open_session", {**pg_conn, "user": "nobody_by_that_name", "mode": "read-only"}
    )
    sid = json.loads(opened.content[0].text)["id"]
    try:
        for _ in range(2):
            await expect_error(
                client,
                "query",
                with_session(sid, sql="SELECT 1"),
                "std:credential-required",
                message_contains="act secret set",
            )
    finally:
        await client.call_tool("close_session", {"session_id": sid})


async def test_a_forbidden_statement_is_refused_before_any_credential_is_fetched(
    client, readonly_session_id, with_session, expect_error
):
    """The tier gate runs first. A statement the session was never going to be
    allowed to run must not reach the credential store, where on an
    interactive host it would put a consent prompt in front of a human.
    """
    await expect_error(
        client,
        "execute",
        with_session(readonly_session_id, sql="DROP TABLE anything"),
        "std:capability-denied",
    )
