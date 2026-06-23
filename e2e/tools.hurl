POST {{baseurl}}/tools
HTTP 200
[Asserts]
jsonpath "$.tools" count >= 1
