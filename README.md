# postgres

A hardened PostgreSQL tool for AI agents — capability-gated, SQL-tier-enforced, and
bounded by design. Runs as a wasip2 WebAssembly component inside the
[ACT](https://actcore.dev) host.

## Positioning

`postgres` is not a thin SQL passthrough. Every tool call is subject to two independent
security layers:

1. **Host capability gate (`wasi:sockets`)** — the ACT host controls whether the
   component can open any TCP connection at all. Deny `wasi:sockets` and no network
   egress occurs, regardless of what the agent asks.
2. **SQL-tier gate (self-enforced, consent-WIT swap-point)** — the session `mode` arg
   sets a read/write/DDL/DROP ceiling. Each tool call classifies the incoming SQL and
   rejects it before the wire if it exceeds the ceiling. These tiers are declared in
   `act.toml` as `db:read` / `db:write` / `db:ddl` / `db:drop` capabilities so
   future `--deny db:drop` host enforcement is a config change, not a code change
   (swap-point for `act:consent` WIT once it lands).

## Capability declarations

`act.toml` declares:

| Capability | Meaning |
|------------|---------|
| `wasi:sockets` | TCP egress to any host / any port — host-gated |
| `db:read` | SELECT, EXPLAIN, schema introspection — self-enforced |
| `db:write` | INSERT, UPDATE, DELETE, MERGE, COPY FROM — self-enforced |
| `db:ddl` | CREATE, ALTER, GRANT, REVOKE — self-enforced |
| `db:drop` | DROP, TRUNCATE — self-enforced |

## Quick start

### One-shot call

```bash
# Open a session-of-1 and run a single query.
act call postgres.wasm query \
  --session-args '{"host":"localhost","user":"postgres","password":"secret","dbname":"mydb"}' \
  --allow wasi:sockets \
  --args '{"sql":"SELECT version()"}'
```

### MCP server (agent-facing)

```bash
# Serve over MCP stdio — agents open/close sessions themselves.
act run postgres.wasm --mcp --allow wasi:sockets
```

### HTTP server

```bash
act run postgres.wasm --http -l [::1]:3000 --allow wasi:sockets
```

### Scoped grant (restrict to one host)

```bash
act run postgres.wasm --mcp \
  --grant '{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"db.internal","protocols":["tcp"]}]}}'
```

### Restrict to read-only (default, but explicit)

Pass `mode: "read-only"` (the default) in `open_session` args. Any write attempt is
rejected before reaching the server:

```json
{ "host": "db.example.com", "user": "ro_user", "dbname": "prod", "mode": "read-only" }
```

## Session open args

| Arg | Type | Default | Notes |
|-----|------|---------|-------|
| `connection_string` | string? | — | Full DSN (`postgres://user:pass@host:5432/db`). When set, discrete fields are ignored. |
| `host` | string? | — | Hostname or IP. |
| `port` | integer | 5432 | Server port. |
| `user` | string? | — | Login role. |
| `password` | string? | — | Password. |
| `dbname` | string? | — | Database name. |
| `sslmode` | `disable`\|`prefer`\|`require` | `prefer` | TLS mode — see TLS section below. |
| `mode` | `read-only`\|`read-write`\|`ddl`\|`full` | `read-only` | SQL operation ceiling. |
| `max_rows` | integer | 1000 | Default row cap for `query`. |
| `statement_timeout_ms` | integer? | — | Server-side statement timeout. |

## Mode tiers

| mode | Permitted SQL |
|------|--------------|
| `read-only` | SELECT, WITH (CTE), EXPLAIN (no ANALYZE), schema catalog reads |
| `read-write` | + INSERT, UPDATE, DELETE, MERGE, COPY FROM |
| `ddl` | + CREATE, ALTER, GRANT, REVOKE |
| `full` | + DROP, TRUNCATE |

A tool call that exceeds the session mode is rejected with a `db:*` capability error.
The SQL is never sent to the server.

## Tools

### `query(sql, params?, max_rows?)`

Execute a single read-only SELECT or CTE. Multi-statement input and any write
statement are rejected. Requires `read-only` or higher.

Returns `{ rows: [...], truncated: bool }`. Each row is a `{ column: value }` map.
`truncated` is `true` when the result was capped at `max_rows`.

```bash
act call postgres.wasm query --session-args '...' --allow wasi:sockets \
  --args '{"sql":"SELECT id, name FROM users WHERE active = $1","params":[true]}'
```

### `execute(sql, params?)`

Execute a single write or DDL statement. The statement is classified and checked
against the session mode. Requires `read-write` or higher (DDL/DROP require
`ddl`/`full`).

Returns `{ rows_affected: int }`.

### `list_schemas()`

List non-system schemas. Requires `read-only` or higher.

### `list_tables(schema?)`

List tables and views in `schema` (default `public`). Requires `read-only` or higher.

### `describe_table(table, schema?)`

Describe a table: column names, types, nullability, defaults. `schema` defaults to
`public`. Requires `read-only` or higher. Returns an error if the table is not found.

### `explain_query(sql, analyze?, format?)`

Return the query plan. `analyze=false` (default) does not execute the query.
`analyze=true` executes it and requires the statement's tier.

`format` defaults to `text`. Use `text` in v1 — `json` returns a type marker
(see Result types below) rather than a parsed plan.

## Parameters

Bind values with `$1, $2, ...` positional placeholders and the `params` array.

Supported scalar types:

| JSON/CBOR type | Postgres bind |
|----------------|---------------|
| `null` | NULL |
| `bool` | BOOL |
| integer | INT2 / INT4 / INT8 (range-checked; out-of-range → error, no silent truncation) |
| float | FLOAT4 / FLOAT8 |
| string | TEXT / VARCHAR / any string column |

## Result types

The following Postgres types are decoded to native values:

| Postgres type | Decoded as |
|---------------|-----------|
| `bool` | boolean |
| `int2`, `int4`, `int8` | integer |
| `float4`, `float8` | float |
| `text`, `varchar`, `bpchar`, `name` | string |
| `bytea` | bytes |

All other types (`numeric`, `json`, `jsonb`, `timestamp`, `timestamptz`, `uuid`,
`regclass`, arrays, composite, etc.) currently render as a text marker:

```
<unsupported pg type: numeric>
```

Type coverage is incremental. These markers are stable output — callers can detect
and surface them. `json`/`jsonb` decoding is a planned follow-up.

Consequence: **`explain_query` should use `format=text`** (the default). With
`format=json`, the EXPLAIN output column is typed `json`, which renders as the
marker above instead of the plan.

## TLS

TLS is implemented with pure-Rust cryptography (rustls + rustls-rustcrypto) — no
system OpenSSL dependency, works on wasip2.

**v1 limitation — encryption without authentication:** TLS handshake signatures are
verified, but server certificate **chain** verification is skipped because wasip2
provides no system CA store. Both `sslmode=prefer` and `sslmode=require` attempt TLS
but cannot verify that the server certificate is trusted by a known CA. This is
similar in spirit to PostgreSQL's own `sslmode=require` (weaker than `verify-ca` or
`verify-full`) — you get encryption, but no protection against a MITM that presents
any certificate. Full chain verification is a planned follow-up.

Additional v1 TLS notes:

- `sslmode=prefer` and `sslmode=require` behave identically — both attempt TLS with
  no plaintext fallback.
- `sslmode=disable` skips TLS entirely (plain TCP).
- When `connection_string` is used, any `?sslmode=...` inside the DSN is ignored;
  the top-level `sslmode` arg (default `prefer`) controls transport.

## Development

```bash
just init   # first time: fetch WIT deps
just build  # build wasm component
just pack   # embed act:component metadata
just test   # run e2e tests (requires Docker for postgres:16)
```

The e2e suite starts a `postgres:16` container via Docker Compose, runs hurl tests
against an HTTP server, and tears down automatically.

Use the locally-rebuilt binaries when repacking (the released `act-build` does not
yet support the any-port sockets ceiling declaration):

```bash
ACT_BUILD=/path/to/act-cli/target/debug/act-build just pack
ACT=/path/to/act-cli/target/debug/act ACT_BUILD=... just test
```

## Publishing

Pushing to `main` publishes a signed component to `actpkg.dev/<owner>/postgres`
(owner derived from the git remote; override with `OCI_REGISTRY`). CI signs
keylessly with [cosign](https://docs.sigstore.dev/) via GitHub OIDC.

One-time setup: create a Personal Access Token at [actpkg.dev](https://actpkg.dev)
and add it as a repository secret named `ACTPKG_TOKEN`.

```bash
just publish   # local publish (unsigned); CI signs on push to main
```

## License

MIT OR Apache-2.0
