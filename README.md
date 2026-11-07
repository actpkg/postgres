# postgres

A hardened PostgreSQL tool for AI agents — capability-gated, SQL-tier-enforced, and
bounded by design. Runs as a wasip3 WebAssembly component inside the
[ACT](https://actcore.dev) host.

## Positioning

`postgres` is not a thin SQL passthrough. Every tool call is subject to two independent
security layers:

1. **Host capability gate (`wasi:sockets`, `act:credentials`)** — the ACT host
   controls whether the component can open any TCP connection at all, and whether it
   may read a credential. Deny `wasi:sockets` and no network egress occurs,
   regardless of what the agent asks.
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
| `wasi:sockets` | TCP egress to any host on the standard PostgreSQL ports — host-gated |
| `act:credentials` | Read the password from the host credential store — host-gated |
| `db:read` | SELECT, EXPLAIN, schema introspection — self-enforced |
| `db:write` | INSERT, UPDATE, DELETE, MERGE, COPY FROM — self-enforced |
| `db:ddl` | CREATE, ALTER, GRANT, REVOKE — self-enforced |
| `db:drop` | DROP, TRUNCATE — self-enforced |

## The password is not an argument

**postgres never accepts a password in its session arguments.** Everything sent to
`open_session` is plaintext in the agent's context, in the transcript, and in the
host's session record. The password lives in the host credential store instead, and
the component fetches it over `act:credentials` — so it never passes through the
agent at all.

Provision it once:

```bash
# Prompts for the declared fields with no further arguments.
act login postgres.wasm

# Or non-interactively:
echo '{"postgres:password":"..."}' | act secret set postgres.wasm \
  --key default --field postgres:password --fields-stdin
```

| Field | Required | Meaning |
|-------|----------|---------|
| `postgres:password` | yes | The role's password. |
| `postgres:user` | no | The role it belongs to — stored beside it so the pair rotates together. |

The session names which credential to use with `credential_key` (default
`"default"`), so one deployment can hold several: a read-only reporting role and a
migration role, say.

**Login role precedence:** the `user` session argument wins, then the DSN's `user=`,
then the credential's `postgres:user`. The pairing is not checked and cannot be —
only the server knows whether a role and a password go together — so a mismatch
surfaces as an authentication failure on the first tool call.

### What changed for `connection_string`

A DSN mixes secret and non-secret in one opaque string, which makes it the nastier
of the two leaks this component used to have: `password` at least looked like a
credential, while `postgres://user:pass@host/db` reads as an address. So the DSN
stays — it is how connection details are actually recorded — but **it must be
password-free**, in every spelling:

| Rejected | Why |
|----------|-----|
| `postgres://user:pass@host/db` | userinfo; refused whole, not just the `:pass` half |
| `postgres://host/db?password=…` | same password, different slot |
| `host=… password=…` | same again, keyword/value form |
| any `@` in a URL-form DSN | tokio-postgres reads everything before the first `@` as userinfo, so `?application_name=job@1` would silently connect to host `1`. Write `%40`. |
| a comma-separated host list | failover is not implemented, and connecting to the first host silently is worse than saying so |
| `sslnegotiation=direct` | needs an ALPN protocol this build does not set |

What a DSN *may* carry, and what happens to it:

| Parameter | Fate |
|-----------|------|
| `host`, `port` | honoured (exactly one host, TCP only) |
| `dbname`, `user` | honoured, and overridden by the `dbname` / `user` session args |
| `sslmode` | honoured, and overridden by the `sslmode` session arg |
| `options`, `application_name`, `channel_binding` | honoured, sent at startup |
| `connect_timeout`, `keepalives*`, `tcp_user_timeout`, `target_session_attrs`, `load_balance_hosts`, `hostaddr` | ignored — they belong to tokio-postgres's `runtime` connector, which does not build for wasm32-wasip3 |

Anything else is a parse error rather than a silent drop — including
`sslmode=verify-full`, which tokio-postgres does not know (and see the TLS section
for why there is no chain verification to ask for yet).

`connection_string` and `host`/`port` are alternatives: pass one, not both.

### The connection now opens on the first tool call

`get-secret` requires a session the host has already marked live, and the host does
that only after `open-session` returns (ACT-AUTH §1.1.4) — so the credential cannot
be fetched at open, and neither can the connection be made there. **A bad password,
an unreachable server or a missing database therefore surfaces on the first tool
call, not at `open_session`.** Everything decidable from the arguments alone is
still decided at open, so an argument mistake is still reported where it was made.

An authentication failure (SQLSTATE class 28) poisons the session: subsequent calls
are refused without asking the store again, which on an interactive host would mean
another consent prompt for a credential already known to be wrong. Transport
failures are retried, because those change on their own.

## Quick start

### One-shot call

```bash
# Open a session-of-1 and run a single query. No password anywhere: it comes
# from the credential store provisioned above.
act call postgres.wasm query \
  --session-args '{"host":"localhost","user":"postgres","dbname":"mydb"}' \
  --allow wasi:sockets --allow act:credentials \
  --args '{"sql":"SELECT version()"}'
```

### MCP server (agent-facing)

```bash
# Serve over MCP stdio — agents open/close sessions themselves.
act run postgres.wasm --mcp --allow wasi:sockets --allow act:credentials
```

### MCP over Streamable HTTP

```bash
act run postgres.wasm --mcp --http -l [::1]:3000 \
  --allow wasi:sockets --allow act:credentials
```

### Scoped grant (restrict to one host)

Worth doing whenever the credential store is granted: `--allow wasi:sockets` opens
the component's whole declared ceiling, which is every host on the standard
PostgreSQL ports — so an allowlist is the only bound you have chosen yourself on
where a credential could be sent. The host warns about exactly this combination.

```bash
act run postgres.wasm --mcp --allow act:credentials \
  --grant '{"wasi:sockets":{"mode":"allowlist","allow":[{"host":"db.internal","ports":[5432],"protocols":["tcp"]}]}}'
```

### Restrict to read-only (default, but explicit)

Pass `mode: "read-only"` (the default) in `open_session` args. Any write attempt is
rejected before reaching the server:

```json
{ "host": "db.example.com", "user": "ro_user", "dbname": "prod", "mode": "read-only" }
```

(Still no password — `credential_key` defaults to `"default"`.)

## Session open args

There is no `password`, and there never will be — see "The password is not an
argument" above.

| Arg | Type | Default | Notes |
|-----|------|---------|-------|
| `connection_string` | string? | — | **Password-free** DSN (`postgres://host:5432/db?…`). Alternative to `host`/`port`. |
| `host` | string? | — | Hostname or IP. Alternative to `connection_string`. |
| `port` | integer? | 5432 | Server port. Only with `host`. |
| `user` | string? | — | Login role. Overrides the DSN's `user=` and the credential's `postgres:user`. |
| `credential_key` | string | `default` | Which credential in this component's profile to authenticate with. |
| `dbname` | string? | — | Database name. Overrides the DSN's `dbname=`. |
| `sslmode` | `disable`\|`prefer`\|`require`? | DSN's, else `prefer` | TLS mode — see TLS section below. |
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
system OpenSSL dependency, works on wasip3.

**v1 limitation — encryption without authentication:** TLS handshake signatures are
verified, but server certificate **chain** verification is skipped because wasip3
provides no system CA store. Both `sslmode=prefer` and `sslmode=require` attempt TLS
but cannot verify that the server certificate is trusted by a known CA. This is
similar in spirit to PostgreSQL's own `sslmode=require` (weaker than `verify-ca` or
`verify-full`) — you get encryption, but no protection against a MITM that presents
any certificate. Full chain verification is a planned follow-up.

Additional v1 TLS notes:

- `sslmode=prefer` and `sslmode=require` behave identically — both attempt TLS with
  no plaintext fallback.
- `sslmode=disable` skips TLS entirely (plain TCP).
- A DSN's `?sslmode=...` **is** honoured, and the `sslmode` session arg overrides it.
  (It used to be parsed and then ignored, which meant a DSN saying `sslmode=disable`
  connected in the clear even when the session arg said `require` — `connect_raw`
  reads `ssl_mode` itself and returns a plaintext stream for `disable` whatever
  connector it is handed.)

## Development

```bash
just init   # first time: fetch WIT deps
just build  # build wasm component
just pack   # embed act:component metadata
just test   # run e2e tests (requires Docker for postgres:16)
```

The e2e suite starts a `postgres:16` container via Docker Compose, drives the packed
component through `act run --mcp` with a real MCP client, and tears down
automatically. It provisions the container's password into a temporary file-backed
credential store (`act secret set --credentials-backend file:…`) and grants the host
`--allow act:credentials`, because a headless run degrades ask-by-default to deny.

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
