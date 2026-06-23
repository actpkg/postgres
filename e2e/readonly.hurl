# A SELECT is allowed in read-only mode.
POST {{baseurl}}/tools/query
{"arguments": {"sql": "SELECT 1 AS ok"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.rows[0].ok" == 1

# A DDL write is rejected by the tier gate (capability_denied), NOT executed.
# ACT-HTTP maps capability_denied -> HTTP 403.
POST {{baseurl}}/tools/execute
{"arguments": {"sql": "CREATE TABLE should_not_exist (id int)"}}
HTTP 403
[Asserts]
jsonpath "$.error.kind" == "std:capability-denied"
jsonpath "$.error.message" contains "db:ddl"

# Statement-stacking is rejected (single-statement guard) on the read path.
# ACT-HTTP maps invalid-args -> HTTP 422.
POST {{baseurl}}/tools/query
{"arguments": {"sql": "SELECT 1; DROP TABLE act_e2e_users"}}
HTTP 422
[Asserts]
jsonpath "$.error.kind" == "std:invalid-args"
