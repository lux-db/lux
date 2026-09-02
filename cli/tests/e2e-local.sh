#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE_BIN="${LUX_E2E_ENGINE_BIN:-$REPO_ROOT/target/debug/lux}"
CLI_BIN="${LUX_E2E_CLI_BIN:-$REPO_ROOT/cli/target/debug/lux}"
mkdir -p "$REPO_ROOT/.scratch"
TEST_ROOT="$(mktemp -d "$REPO_ROOT/.scratch/cli-e2e.XXXXXX")"
ENGINE_PID=""
RESP_PORT="${LUX_E2E_RESP_PORT:-16379}"
HTTP_PORT="${LUX_E2E_HTTP_PORT:-15890}"
OPERATOR_KEY="lux-cli-e2e-operator"

cleanup() {
  if [[ -n "$ENGINE_PID" ]]; then
    kill "$ENGINE_PID" 2>/dev/null || true
    wait "$ENGINE_PID" 2>/dev/null || true
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/project/lux/migrations" "$TEST_ROOT/data"
cat >"$TEST_ROOT/project/lux/.lux-local.json" <<JSON
{
  "password": "$OPERATOR_KEY",
  "publishable_key": "lux-cli-e2e-public",
  "secret_key": "$OPERATOR_KEY",
  "http_port": $HTTP_PORT,
  "resp_port": $RESP_PORT,
  "container": "unused-e2e-container",
  "volume": "unused-e2e-volume",
  "image": "ghcr.io/lux-db/lux:latest",
  "studio_port": 15891,
  "studio_container": "unused-e2e-studio"
}
JSON

env \
  LUX_PORT="$RESP_PORT" \
  LUX_HTTP_PORT="$HTTP_PORT" \
  LUX_BIND_HOST=127.0.0.1 \
  LUX_DATA_DIR="$TEST_ROOT/data" \
  LUX_STORAGE_MODE=tiered \
  LUX_STORAGE_DIR="$TEST_ROOT/data/storage" \
  LUX_AUTH_ENABLED=1 \
  LUX_PASSWORD="$OPERATOR_KEY" \
  LUX_ENC_AUTO_INIT=1 \
  "$ENGINE_BIN" >"$TEST_ROOT/engine.log" 2>&1 &
ENGINE_PID=$!

for _ in $(seq 1 80); do
  if curl -fsS \
    -H "Authorization: Bearer $OPERATOR_KEY" \
    "http://127.0.0.1:$HTTP_PORT/v1/version" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  "http://127.0.0.1:$HTTP_PORT/v1/version" >/dev/null

cd "$TEST_ROOT/project"
cat >lux/migrations/001_create.lux <<'LUX'
TCREATE cli_e2e id INT;
LUX

"$CLI_BIN" migrate plan --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY"
"$CLI_BIN" migrate run --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY"
"$CLI_BIN" migrate status --check --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY"

cat >lux/migrations/002_partial.lux <<'LUX'
TINSERT cli_e2e id 1;
NOT_A_COMMAND;
LUX
if "$CLI_BIN" migrate run --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY"; then
  echo "expected partial migration to fail" >&2
  exit 1
fi
"$CLI_BIN" migrate status --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY" \
  | grep -q "1/2 commands"
"$CLI_BIN" migrate repair 002_partial.lux abandon \
  --host 127.0.0.1 --port "$RESP_PORT" --password "$OPERATOR_KEY"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out AuthKey_TEST.p8 2>/dev/null
"$CLI_BIN" push status --check --output json
"$CLI_BIN" push apns set \
  --team-id TEAM123 \
  --key-id KEY123 \
  --topic dev.lux.e2e \
  --environment sandbox \
  --p8-file AuthKey_TEST.p8
"$CLI_BIN" push apns set \
  --team-id TEAM123 \
  --key-id KEY123 \
  --topic dev.lux.e2e \
  --environment production

"$CLI_BIN" push vapid enable --subject mailto:e2e@luxdb.dev
FIRST_VAPID="$("$CLI_BIN" push status --output json | sed -n 's/.*"public_key": "\(.*\)",/\1/p')"
"$CLI_BIN" push vapid enable --subject mailto:e2e@luxdb.dev
SECOND_VAPID="$("$CLI_BIN" push status --output json | sed -n 's/.*"public_key": "\(.*\)",/\1/p')"
test -n "$FIRST_VAPID"
test "$FIRST_VAPID" = "$SECOND_VAPID"

if "$CLI_BIN" push vapid rotate --subject mailto:e2e@luxdb.dev; then
  echo "expected VAPID rotation without --yes to fail" >&2
  exit 1
fi
"$CLI_BIN" push vapid rotate --subject mailto:e2e@luxdb.dev --yes
ROTATED_VAPID="$("$CLI_BIN" push status --output json | sed -n 's/.*"public_key": "\(.*\)",/\1/p')"
test -n "$ROTATED_VAPID"
test "$FIRST_VAPID" != "$ROTATED_VAPID"

"$CLI_BIN" push vapid disable --yes
"$CLI_BIN" push apns clear --yes
FINAL_STATUS="$("$CLI_BIN" push status --check --output json)"
grep -q '"configured": false' <<<"$FINAL_STATUS"
if grep -q "dGVzdC1vbmx5" <<<"$FINAL_STATUS"; then
  echo "push status exposed private key material" >&2
  exit 1
fi

echo "CLI local migration and push E2E passed"
