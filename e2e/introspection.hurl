# Self-contained: create our own table so this file is independent of other
# e2e files (hurl runs --test files in parallel by default).
POST {{baseurl}}/tools/execute
{"arguments": {"sql": "CREATE TABLE IF NOT EXISTS act_e2e_intro (id serial primary key, name text not null, age int)"}}
HTTP 200

POST {{baseurl}}/tools/list_schemas
{"arguments": {}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data[*].schema_name" contains "public"

POST {{baseurl}}/tools/list_tables
{"arguments": {"schema": "public"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data[*].table_name" contains "act_e2e_intro"

POST {{baseurl}}/tools/describe_table
{"arguments": {"table": "act_e2e_intro"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.columns[*].column_name" contains "name"
