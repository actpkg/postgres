# Changelog

All notable changes to this component are documented here.

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
