import json


async def test_introspection_lists_schema_table_and_columns(client, session_id, with_session):
    # Self-contained: create our own table so this test needs nothing any
    # other test set up.
    await client.call_tool(
        "execute",
        with_session(
            session_id,
            sql="CREATE TABLE IF NOT EXISTS act_e2e_intro (id serial primary key, name text not null, age int)",
        ),
    )

    result = await client.call_tool("list_schemas", with_session(session_id))
    # list_schemas/list_tables return bare arrays — no structured_content.
    assert result.structured_content is None
    schemas = json.loads(result.content[0].text)
    assert "public" in [s["schema_name"] for s in schemas]

    result = await client.call_tool("list_tables", with_session(session_id, schema="public"))
    assert result.structured_content is None
    tables = json.loads(result.content[0].text)
    assert "act_e2e_intro" in [t["table_name"] for t in tables]

    # describe_table returns an object ({table, columns}), so this one *is*
    # structured.
    result = await client.call_tool("describe_table", with_session(session_id, table="act_e2e_intro"))
    columns = result.structured_content["columns"]
    assert "name" in [c["column_name"] for c in columns]
