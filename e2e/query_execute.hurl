# DDL + write + read round-trip (server runs in mode=full).
POST {{baseurl}}/tools/execute
{"arguments": {"sql": "DROP TABLE IF EXISTS act_e2e_users"}}
HTTP 200

POST {{baseurl}}/tools/execute
{"arguments": {"sql": "CREATE TABLE act_e2e_users (id serial primary key, name text not null, age int)"}}
HTTP 200

POST {{baseurl}}/tools/execute
{"arguments": {"sql": "INSERT INTO act_e2e_users (name, age) VALUES ($1, $2)", "params": ["Alice", 30]}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.rows_affected" == 1

POST {{baseurl}}/tools/query
{"arguments": {"sql": "SELECT name, age FROM act_e2e_users ORDER BY id"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.rows[0].name" == "Alice"
jsonpath "$.content[0].data.rows[0].age" == 30
jsonpath "$.content[0].data.truncated" == false

# max_rows cap sets the truncated flag.
POST {{baseurl}}/tools/query
{"arguments": {"sql": "SELECT * FROM generate_series(1, 5) AS g(n)", "max_rows": 2}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.rows" count == 2
jsonpath "$.content[0].data.truncated" == true
