# Changelog

All notable changes to this component are documented here.

## [0.2.0] - 2026-08-30

### Changed

- **BREAKING: the password is no longer a session argument.** `password` is gone
  from `open-session`, and the password is fetched from the host credential store
  over `act:credentials` — field `postgres:password`, with an optional
  `postgres:user` beside it — so it never passes through the agent's context.
  Sessions name a credential with the new `credential_key` argument (default
  `"default"`), and the component declares both fields in `act.toml`, so
  `act login <ref>` prompts for them with no arguments. Hosts must grant
  `--allow act:credentials`.
- **BREAKING: `connection_string` must be password-free.** A DSN carrying a
  password — as userinfo, `password=` or `?password=` — is refused at open, as is
  any `@` in a URL-form DSN (tokio-postgres reads everything before the first one
  as userinfo), a comma-separated host list, and `sslnegotiation=direct`. A `host`
  argument carrying userinfo is refused for the same reason.
  `connection_string` and `host`/`port` are now alternatives rather than one
  silently overriding the other.
- **BREAKING: `open-session` no longer connects.** A credential cannot be fetched
  from inside `open-session` (ACT-AUTH §1.1.4), so the connection is established
  lazily on the first tool call and cached for the session. A wrong password, an
  unreachable server or a missing database now surfaces there rather than at open;
  argument mistakes are still refused at open. An authentication failure (SQLSTATE
  class 28) poisons the session so the credential is not re-fetched on every call.

### Fixed

- A DSN's `sslmode` is now honoured, and overridden by the `sslmode` session arg.
  It used to be parsed and then ignored, so `connection_string` with
  `sslmode=disable` connected in the clear even when the session arg said
  `require` — `Config::connect_raw` consults `ssl_mode` itself and returns a
  plaintext stream for `disable` whatever connector it is handed.
- `DROP FUNCTION`, `DROP PROCEDURE`, `DROP TRIGGER`, `DROP POLICY` and
  `DROP SECRET` now require `db:drop`. sqlparser parses them into variants of
  their own, which fell through to `db:ddl`. The same applies to
  `DROP EXTENSION`, `DROP DOMAIN` and `DROP OPERATOR [CLASS|FAMILY]`, which
  sqlparser 0.63 now parses (0.52 refused them as syntax errors).

### Dependencies

- sqlparser 0.52 → 0.63, tokio 1.51 → 1.53, act-sdk 0.14.1 → 0.14.2.

## [0.1.3] - 2026-08-11

### Changed

- Drop the `wit-bindgen` dependency. `act-sdk` 0.14 generates the WIT bindings
  through its own copy of the runtime, so the component only depends on
  `act-sdk`. No behaviour change; the compiled wasm moves to wit-bindgen 0.60.

## [0.1.0] - 2026-06-24

Initial release. A hardened PostgreSQL tool component for ACT: connects to a
PostgreSQL server over `wasi:sockets` (host-gated egress) and exposes a small,
capability-tiered SQL surface.

### Added

- Session-provider connection model (`tokio-postgres` over a `wasi:sockets` TCP
  stream, driven by a per-session current-thread tokio runtime). Open-session
  args: `connection_string` (DSN) or discrete `host`/`port`/`user`/`password`/
  `dbname`, plus `sslmode`, `mode`, `max_rows`, `statement_timeout_ms`.
- Six tools: `query` (read-only, single-statement, `max_rows`-capped, returns
  `{rows, truncated}`), `execute` (write/DDL), `list_schemas`, `list_tables`,
  `describe_table`, `explain_query`.
- Capability tiering: every statement is classified (`sqlparser`) into
  `db:read`/`db:write`/`db:ddl`/`db:drop` and checked against the session `mode`
  (`read-only` default), with a `TODO(act-consent)` swap-point for future
  host-enforced consent. Reads run inside a `SET TRANSACTION READ ONLY` txn and
  statement-stacking is rejected.
- Bound parameters (`$1, $2, …` via `params`), with range-checked integer binds.
- TLS via pure-Rust `rustls` + `rustls-rustcrypto`.

### Known limitations (v1)

- TLS skips server **certificate-chain** verification on wasip2 (no system CA
  store): all `sslmode` values, including `require`, give encryption without
  MITM protection. `prefer` behaves like `require` (no plaintext fallback). A
  DSN's embedded `?sslmode=` is ignored; the discrete `sslmode` arg governs.
- Result decoding covers bool, int2/4/8, float4/8, text family, and bytea;
  other types (numeric, json/jsonb, timestamp, uuid, regclass, arrays) render as
  a `<unsupported pg type: …>` marker. Use `explain_query` with `format=text`.
