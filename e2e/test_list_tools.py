async def test_list_tools_includes_all_six(client):
    tools = await client.list_tools()
    names = [t.name for t in tools]
    for n in ["query", "execute", "list_schemas", "list_tables", "describe_table", "explain_query"]:
        assert n in names
