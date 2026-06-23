# Phase 0 smoke: a trivial SELECT runs end-to-end (session-of-1, mode=full).
POST {{baseurl}}/tools/query
{
  "arguments": {"sql": "SELECT 1 AS one"}
}
HTTP 200
[Asserts]
jsonpath "$.content[0].data[0].one" == 1
