# Self-contained: explain a table-less query so this file is independent of
# other e2e files (hurl runs --test files in parallel by default).
POST {{baseurl}}/tools/explain_query
{"arguments": {"sql": "SELECT n FROM generate_series(1, 100) AS g(n) WHERE n > 18", "format": "text"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" count >= 1
jsonpath "$.content[0].data[0]['QUERY PLAN']" isString
