#!/bin/bash
set -euo pipefail

BENCH_PORT=${BENCH_PORT:-6391}
PG_PORT=15432
PG_CONTAINER="lux_bench_pg"

BOLD='\033[1m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LUX_BIN="$SCRIPT_DIR/target/release/lux"
REDIS_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/lux-bench"
REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"
LUX_TMPDIR=""
LUX_PID=""

cleanup() {
    [ -n "${LUX_PID:-}" ] && kill "$LUX_PID" 2>/dev/null || true
    [ -n "${LUX_TMPDIR:-}" ] && rm -rf "$LUX_TMPDIR"
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    wait 2>/dev/null || true
} 2>/dev/null
trap cleanup EXIT

if [ ! -f "$LUX_BIN" ]; then
    echo -e "${YELLOW}Building Lux (release)...${NC}"
    cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"
fi

echo -e "${YELLOW}Starting Postgres container...${NC}"
docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=bench -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=bench \
    -p "${PG_PORT}:5432" \
    postgres:16-alpine \
    postgres -c fsync=off -c synchronous_commit=off -c full_page_writes=off \
             -c shared_buffers=256MB -c work_mem=64MB >/dev/null

for i in $(seq 1 60); do
    PGPASSWORD=bench psql -h 127.0.0.1 -p "$PG_PORT" -U bench -d bench \
        -c "SELECT 1" >/dev/null 2>&1 && break || sleep 0.5
done

LUX_TMPDIR=$(mktemp -d)
LUX_PORT=$BENCH_PORT LUX_SAVE_INTERVAL=0 LUX_DATA_DIR="$LUX_TMPDIR" "$LUX_BIN" >/dev/null 2>&1 &
LUX_PID=$!
for i in $(seq 1 60); do
    "$REDIS_CLI" -p "$BENCH_PORT" PING >/dev/null 2>&1 && break || sleep 0.1
done

BENCH_PORT=$BENCH_PORT python3 /tmp/bench_pg.py

echo -e "${GREEN}Done. Container removed.${NC}"
