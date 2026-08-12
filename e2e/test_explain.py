import json


async def test_explain_query_returns_plan(client, session_id, with_session):
    # Self-contained: explain a table-less query so this test needs nothing
    # any other test set up.
    result = await client.call_tool(
        "explain_query",
        with_session(session_id, sql="SELECT n FROM generate_series(1, 100) AS g(n) WHERE n > 18", format="text"),
    )
    # explain_query returns a bare array (the plan rows), so the SDK does not
    # populate structured_content for it — only object-shaped results get
    # that (measured, same rule as filesystem's list_directory).
    assert result.structured_content is None
    plan = json.loads(result.content[0].text)
    assert len(plan) >= 1
    assert isinstance(plan[0]["QUERY PLAN"], str)
