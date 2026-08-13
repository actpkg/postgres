---
name: postgres
description: Query and manage PostgreSQL from an AI agent — capability-tiered, bounded, sandboxed.
metadata:
  act: {}
---

# postgres

A hardened PostgreSQL tool for AI agents. Open a session with connection details,
then call SQL tools. Network egress is gated by the host (`wasi:sockets`); SQL
operations are gated by the session `mode` tier (`read-only` | `read-write` | `ddl`
| `full`, default `read-only`).

## Never send a password

**There is no password argument, and you must not try to supply one.** The password
comes from the host credential store over `act:credentials`, so it never enters your
context. A session names *which* credential to use — `credential_key`, default
`"default"` — and nothing more.

A `connection_string` carrying a password in any spelling
(`postgres://user:pass@host/db`, `?password=…`, `host=… password=…`) is refused at
open, as is a `host` carrying userinfo. If you have been handed a DSN with a
password in it, strip the password and tell the user to store it:

```
act login <component-ref>
# or: echo '{"postgres:password":"..."}' | act secret set <component-ref> \
#       --key default --field postgres:password --fields-stdin
```

The login role comes from the `user` argument, else the DSN's `user=`, else the
credential's optional `postgres:user` field.

## Opening a session

Call `open_session` with connection args. The session id is returned and must be
passed as `std:session-id` metadata on every tool call.

`connection_string` and `host`/`port` are alternatives — pass one, not both.

| Arg | Type | Default | Notes |
|-----|------|---------|-------|
| `connection_string` | string? | — | **Password-free** DSN (`postgres://host:5432/db?sslmode=require`). Its `sslmode`, `dbname`, `user`, `options` and `application_name` are honoured; `connect_timeout`, `keepalives*` and `target_session_attrs` are ignored; a password, any `@` (write `%40`), a comma-separated host list and `sslnegotiation=direct` are refused. |
| `host` | string? | — | Hostname or IP. No port, no userinfo, no scheme. |
| `port` | integer? | 5432 | Server port. Only with `host`. |
| `user` | string? | — | Login role. Overrides the DSN's `user=` and the credential's `postgres:user`. |
| `credential_key` | string | `default` | Which stored credential to authenticate with. A bounded name: letters, digits, `-`, `_`, `.` |
| `dbname` | string? | — | Database name. Overrides the DSN's `dbname=`. |
| `sslmode` | `disable`\|`prefer`\|`require`? | DSN's, else `prefer` | TLS mode. `prefer` and `require` both attempt TLS — see TLS notes below. |
| `mode` | `read-only`\|`read-write`\|`ddl`\|`full` | `read-only` | Operation tier for this session. |
| `max_rows` | integer | 1000 | Default row cap for `query`. |
| `statement_timeout_ms` | integer? | — | Server-side timeout per statement. |

**`open_session` does not connect.** The credential cannot be fetched until the
session is live, so the connection is made on your first tool call. A wrong
password, an unreachable host or a missing database is reported there, not at open.
Argument mistakes are still reported at open.

## Errors worth recognising

| Kind | What to do |
|------|-----------|
| `std:credential-required` | No usable credential, or the server rejected it. Do **not** retry and do **not** offer to pass the password as an argument — surface the `act secret set` command in the message to the user. Once the server has rejected a credential the session is poisoned; a fixed credential needs a new session. |
| `std:capability-denied` | The statement exceeds the session `mode`, or the host denied a capability. Open a session at a higher tier only if the user asks for one. |
| `std:invalid-args` | An argument was wrong — including a password found in `connection_string` or `host`. |

## Mode tiers

| mode | Allowed operations |
|------|--------------------|
| `read-only` | SELECT, EXPLAIN (no ANALYZE), schema introspection |
| `read-write` | + INSERT, UPDATE, DELETE, MERGE, COPY FROM |
| `ddl` | + CREATE, ALTER, GRANT, REVOKE |
| `full` | + DROP, TRUNCATE |

A tool call that exceeds the session mode is rejected with a `db:*` capability error — the SQL is never sent to the server.

## Tools

### `query(sql, params?, max_rows?)`

Execute a read-only SELECT or CTE and return rows. Rejects multi-statement input and any write statement. Requires `read-only` or higher.

Returns `{ rows: [...], truncated: bool }`. Each row is a `{ column: value }` map.

### `execute(sql, params?)`

Execute a write or DDL statement. The statement is classified and checked against the session mode before execution. Requires `read-write` or higher (DDL/DROP require `ddl`/`full`).

Returns `{ rows_affected: int }`.

### `list_schemas()`

List non-system schemas in the connected database. Requires `read-only` or higher.

Returns an array of `{ schema_name }` rows.

### `list_tables(schema?)`

List tables and views in `schema` (default `public`). Requires `read-only` or higher.

Returns an array of `{ table_name, table_type }` rows.

### `describe_table(table, schema?)`

Describe a table: columns, types, nullability, defaults. `schema` defaults to `public`. Requires `read-only` or higher.

Returns `{ table: str, columns: [{ column_name, data_type, is_nullable, column_default }] }`.

### `explain_query(sql, analyze?, format?)`

Return the query plan via EXPLAIN. `analyze=false` (default) does NOT execute the query. `analyze=true` executes it and requires the statement's own tier. `format` defaults to `text` — use `text` in v1; `json` returns a type marker rather than a parsed plan.

Returns an array of plan rows.

## Notes

- **Bind params** with `$1, $2, ...` and the `params` array. Supported scalar types: `null`, `bool`, `integer`, `float`, `string`. Integer values are range-checked against the column type; out-of-range → error.
- **Result types decoded:** `bool`, `int2/4/8`, `float4/8`, text family (`text`/`varchar`/`bpchar`/`name`), `bytea`. Other types (`numeric`, `json`/`jsonb`, `timestamp`, `uuid`, arrays, etc.) render as a `<unsupported pg type: NAME>` text marker — planned follow-up.
- **TLS (v1):** TLS is supported (pure-Rust rustls + rustls-rustcrypto), but server certificate **chain** verification is skipped on wasip2 (no system CA store). This gives **confidentiality (encryption) only — no server authentication**: an active MITM presenting any certificate is NOT detected (equivalent in spirit to libpq `sslmode=require`, not `verify-*`). Both `prefer` and `require` behave identically — they attempt TLS with no plaintext fallback. Full chain verification is a planned follow-up.
