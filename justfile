wasm := "target/wasm32-wasip2/release/component_postgres.wasm"
# OCI reference to publish to (registry/namespace/name, no tag). Override with OCI_REF.
component_ref := env("OCI_REF", "actpkg.dev/library/postgres")

act := env("ACT", "npx @actcore/act")
actbuild := env("ACT_BUILD", "npx @actcore/act-build")
hurl := env("HURL", "hurl")
# Random port for the e2e server, in a safe range: above the well-known/common
# dev ports and below the Linux outbound ephemeral range (32768+).
port := `shuf -i 10000-29999 -n 1`
addr := "[::1]:" + port
baseurl := "http://" + addr
# Second server port for the read-only enforcement test.
port2 := `shuf -i 10000-29999 -n 1`
addr2 := "[::1]:" + port2
baseurl2 := "http://" + addr2

# Fetch WIT deps from the registry (ghcr.io/actcore) into wit/deps/.
# wkg-registry.toml maps the act namespace -> actcore.dev (well-known -> ghcr.io/actcore).
init:
    WKG_CONFIG_FILE=wkg-registry.toml wkg wit fetch --type wit

setup: init
    prek install

build:
    cargo build --release

# Embed act:component metadata and act:skill into the wasm.
pack: build
    {{actbuild}} pack {{wasm}}

test: pack
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose up -d --wait
    SA_FULL='{"host":"127.0.0.1","port":5434,"user":"postgres","password":"postgres","dbname":"postgres","sslmode":"disable","mode":"full"}'
    SA_RO='{"host":"127.0.0.1","port":5434,"user":"postgres","password":"postgres","dbname":"postgres","sslmode":"disable","mode":"read-only"}'
    {{act}} run {{wasm}} --http --listen "{{addr}}" --allow wasi:sockets --session-args "$SA_FULL" &
    PID=$!
    {{act}} run {{wasm}} --http --listen "{{addr2}}" --allow wasi:sockets --session-args "$SA_RO" &
    PID2=$!
    trap "kill $PID $PID2 2>/dev/null || true; docker compose down -v" EXIT
    curl --retry 60 --retry-connrefused --retry-delay 1 -fsS -o /dev/null {{baseurl}}/info
    curl --retry 60 --retry-connrefused --retry-delay 1 -fsS -o /dev/null {{baseurl2}}/info
    # hurl --test sorts files alphabetically; create test schema before the run
    # so introspection/explain (e,i) can find act_e2e_users created in query_execute (q).
    curl -fsS -X POST "{{baseurl}}/tools/execute" \
      -H "Content-Type: application/json" \
      -d '{"arguments":{"sql":"DROP TABLE IF EXISTS act_e2e_users"}}' -o /dev/null
    curl -fsS -X POST "{{baseurl}}/tools/execute" \
      -H "Content-Type: application/json" \
      -d '{"arguments":{"sql":"CREATE TABLE act_e2e_users (id serial primary key, name text not null, age int)"}}' -o /dev/null
    {{hurl}} --test --variable "baseurl={{baseurl}}" e2e/info.hurl e2e/list_tools.hurl e2e/query_execute.hurl e2e/introspection.hurl e2e/explain.hurl
    {{hurl}} --test --variable "baseurl={{baseurl2}}" e2e/readonly.hurl

publish: pack
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} inspect component-manifest {{wasm}})
    VERSION=$(echo "$INFO" | jq -r .std.version)
    OUTPUT=$({{actbuild}} push {{wasm}} "{{component_ref}}:$VERSION" \
      --skip-if-exists \
      --also-tag latest 2>&1) || { echo "$OUTPUT" >&2; exit 1; }
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}' || true)
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{component_ref}}" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi

