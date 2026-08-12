async def test_query_execute_round_trip(client, session_id, with_session):
    # DDL + write + read round-trip (session runs in mode=full).
    await client.call_tool("execute", with_session(session_id, sql="DROP TABLE IF EXISTS act_e2e_users"))
    await client.call_tool(
        "execute",
        with_session(session_id, sql="CREATE TABLE act_e2e_users (id serial primary key, name text not null, age int)"),
    )

    result = await client.call_tool(
        "execute",
        with_session(session_id, sql="INSERT INTO act_e2e_users (name, age) VALUES ($1, $2)", params=["Alice", 30]),
    )
    assert result.structured_content["rows_affected"] == 1

    result = await client.call_tool(
        "query", with_session(session_id, sql="SELECT name, age FROM act_e2e_users ORDER BY id")
    )
    rows = result.structured_content["rows"]
    assert rows[0]["name"] == "Alice"
    assert rows[0]["age"] == 30
    assert result.structured_content["truncated"] is False

    # max_rows cap sets the truncated flag.
    result = await client.call_tool(
        "query", with_session(session_id, sql="SELECT * FROM generate_series(1, 5) AS g(n)", max_rows=2)
    )
    assert len(result.structured_content["rows"]) == 2
    assert result.structured_content["truncated"] is True
