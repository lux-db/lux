#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLIENT_DIR="$ROOT/tests/client-compat"
PORT="${LUX_COMPAT_PORT:-26379}"
REFERENCE_PORT="${LUX_COMPAT_REFERENCE_PORT:-26380}"
PASSWORD="${LUX_COMPAT_PASSWORD:-lux-client-compat}"
VALKEY_IMAGE="valkey/valkey:8.1.9-alpine@sha256:4934d214fd7e091d4ee77b398945b3fd62c6dd0ac71d8b79e2e3cbad8364f3b1"
REDIS_IMAGE="redis:7.2.4-alpine@sha256:c8bb255c3559b3e458766db810aa7b3c7af1235b204cfdb304e79ff388fe1a5a"
GO_IMAGE="golang:1.24.4-alpine@sha256:68932fa6d4d4059845c8f40ad7e654e626f3ebd3706eef7846f319293ab5cb7a"
CONTAINER="lux-client-compat-$$"
DATA_DIR="$ROOT/.scratch/client-compat-$$"
BUN_TMP="$ROOT/.scratch/bun-tmp"
BUN_CACHE="$ROOT/.scratch/bun-cache"
LUX_PID=""

cleanup() {
  if [ -n "$LUX_PID" ] && kill -0 "$LUX_PID" 2>/dev/null; then
    kill -TERM "$LUX_PID" 2>/dev/null || true
    wait "$LUX_PID" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf -- "$DATA_DIR"
}
trap cleanup EXIT INT TERM

for tool in cargo bun docker; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$DATA_DIR" "$BUN_TMP" "$BUN_CACHE"
cd "$ROOT"
cargo build --locked --bin lux
(cd "$CLIENT_DIR" && TMPDIR="$BUN_TMP" BUN_INSTALL_CACHE_DIR="$BUN_CACHE" bun install --frozen-lockfile)

docker run --detach --rm \
  --name "$CONTAINER" \
  --publish "127.0.0.1:${REFERENCE_PORT}:6379" \
  "$VALKEY_IMAGE" \
  valkey-server --save "" --appendonly no --requirepass "$PASSWORD" >/dev/null

LUX_PORT="$PORT" \
LUX_HTTP_PORT=0 \
LUX_BIND_HOST=0.0.0.0 \
LUX_PASSWORD="$PASSWORD" \
LUX_DATA_DIR="$DATA_DIR" \
LUX_DURABILITY=ephemeral \
LUX_SAVE_INTERVAL=0 \
  "$ROOT/target/debug/lux" >"$DATA_DIR/lux.log" 2>&1 &
LUX_PID=$!

for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" valkey-cli --no-auth-warning -a "$PASSWORD" PING >/dev/null 2>&1 && \
    docker run --rm --add-host host.docker.internal:host-gateway "$REDIS_IMAGE" \
      redis-cli --no-auth-warning -h host.docker.internal -p "$PORT" -a "$PASSWORD" PING >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

docker exec "$CONTAINER" valkey-cli --no-auth-warning -a "$PASSWORD" PING >/dev/null
docker run --rm --add-host host.docker.internal:host-gateway "$REDIS_IMAGE" \
  redis-cli --no-auth-warning -h host.docker.internal -p "$PORT" -a "$PASSWORD" PING >/dev/null

export LUX_COMPAT_PORT="$PORT"
export LUX_COMPAT_REFERENCE_PORT="$REFERENCE_PORT"
export LUX_COMPAT_PASSWORD="$PASSWORD"

bun run "$CLIENT_DIR/matrix.ts"
bun run "$CLIENT_DIR/bullmq.ts"
docker run --rm --add-host host.docker.internal:host-gateway \
  --env LUX_COMPAT_HOST=host.docker.internal \
  --env LUX_COMPAT_PORT="$PORT" \
  --env LUX_COMPAT_PASSWORD="$PASSWORD" \
  --volume "$CLIENT_DIR/go:/src:ro" \
  --workdir /src \
  "$GO_IMAGE" go run -mod=readonly .

docker run --rm --add-host host.docker.internal:host-gateway \
  --volume "$CLIENT_DIR/redis-cli.sh:/compat/redis-cli.sh:ro" \
  "$REDIS_IMAGE" sh /compat/redis-cli.sh host.docker.internal "$PORT" "$PASSWORD"

kill -TERM "$LUX_PID"
wait "$LUX_PID"
LUX_PID=""
printf 'shutdown: clean SIGTERM\n'
