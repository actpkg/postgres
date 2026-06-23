GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$.std.name" == "postgres"
jsonpath "$.std.version" isString
