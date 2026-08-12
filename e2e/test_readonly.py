async def test_readonly_session_gates_writes(client, readonly_session_id, with_session, expect_error):
    # A SELECT is allowed in read-only mode.
    result = await client.call_tool("query", with_session(readonly_session_id, sql="SELECT 1 AS ok"))
    assert result.structured_content["rows"][0]["ok"] == 1

    # A DDL write is rejected by the tier gate (capability_denied), NOT executed.
    await expect_error(
        client, "execute",
        with_session(readonly_session_id, sql="CREATE TABLE should_not_exist (id int)"),
        "std:capability-denied",
        message_contains="db:ddl",
    )

    # Prove the rejected DDL had NO side effect: the table must not exist.
    # (BOOL expression, since regclass is not a decoded type.)
    result = await client.call_tool(
        "query",
        with_session(readonly_session_id, sql="SELECT to_regclass('public.should_not_exist') IS NULL AS missing"),
    )
    assert result.structured_content["rows"][0]["missing"] is True

    # Statement-stacking is rejected (single-statement guard) on the read path.
    await expect_error(
        client, "query",
        with_session(readonly_session_id, sql="SELECT 1; DROP TABLE act_e2e_users"),
        "std:invalid-args",
    )
