#!/bin/bash
set -euo pipefail

BENCH_PORT=${BENCH_PORT:-6390}
REQUESTS=${BENCH_REQUESTS:-1000000}
CLIENTS=${BENCH_CLIENTS:-50}
GEO_MEMBERS=${GEO_MEMBERS:-1000}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "${TMPDIR_LUX:-}" ] && rm -rf "$TMPDIR_LUX"
    wait 2>/dev/null
} 2>/dev/null
trap cleanup EXIT

wait_for_port() {
    local port=$1
    local name=$2
    for i in $(seq 1 20); do
        if "$REDIS_CLI" -p "$port" PING >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo -e "${RED}$name failed to start on port $port${NC}"
    exit 1
}

kill_port() {
    local port=$1
    lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 0.2
}

fmt_rps() {
    local n=${1:-0}
    awk "BEGIN {
        n = $n + 0
        if (n >= 1000000) printf \"%.2fM\", n/1000000
        else if (n >= 1000) printf \"%.0fK\", n/1000
        else printf \"%.0f\", n
    }"
}

ratio_rps() {
    local l=${1:-0} r=${2:-0}
    awk "BEGIN {
        if ($r > 0) printf \"%.2fx\", $l/$r
        else printf \"N/A\"
    }"
}

REDIS_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/lux-bench"

ensure_latest_redis() {
    local latest
    latest=$(curl -sL "https://api.github.com/repos/redis/redis/releases?per_page=1" \
        | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o '[0-9][0-9.]*' || echo "")
    if [ -z "$latest" ]; then
        echo -e "${YELLOW}Could not fetch latest Redis version from GitHub${NC}"
        if [ -x "$REDIS_CACHE_DIR/redis-server" ]; then
            echo -e "${YELLOW}Using cached Redis build${NC}"
            return 0
        fi
        echo -e "${RED}No cached Redis and cannot fetch latest version. Need internet.${NC}"
        exit 1
    fi

    local marker="$REDIS_CACHE_DIR/.version"
    if [ -x "$REDIS_CACHE_DIR/redis-server" ] && [ -f "$marker" ] && [ "$(cat "$marker")" = "$latest" ]; then
        return 0
    fi

    echo -e "${YELLOW}Building Redis $latest from source...${NC}"
    local tmpdir
    tmpdir=$(mktemp -d)
    curl -sL "https://github.com/redis/redis/archive/refs/tags/${latest}.tar.gz" | tar xz -C "$tmpdir"
    make -C "$tmpdir/redis-${latest}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null 2>&1
    mkdir -p "$REDIS_CACHE_DIR"
    cp "$tmpdir/redis-${latest}/src/redis-server" "$REDIS_CACHE_DIR/"
    cp "$tmpdir/redis-${latest}/src/redis-benchmark" "$REDIS_CACHE_DIR/"
    cp "$tmpdir/redis-${latest}/src/redis-cli" "$REDIS_CACHE_DIR/"
    echo "$latest" > "$marker"
    rm -rf "$tmpdir"
    echo -e "${GREEN}Redis $latest built and cached at $REDIS_CACHE_DIR${NC}"
}

ensure_latest_redis

REDIS_SERVER="$REDIS_CACHE_DIR/redis-server"
REDIS_BENCH="$REDIS_CACHE_DIR/redis-benchmark"
REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LUX_BIN="$SCRIPT_DIR/target/release/lux"

if [ ! -f "$LUX_BIN" ]; then
    echo -e "${YELLOW}Building Lux (release)...${NC}"
    cd "$SCRIPT_DIR"
    cargo build --release
fi

REDIS_VER=$("$REDIS_SERVER" --version 2>&1 | head -1 | grep -oE 'v=[0-9]+\.[0-9]+\.[0-9]+' | cut -d= -f2)
LUX_VER=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

echo -e "${BOLD}=== Lux Benchmark ===${NC}"
echo "    redis-benchmark: $("$REDIS_BENCH" --version 2>&1 | head -1)"
echo "    redis-server:    $("$REDIS_SERVER" --version 2>&1 | head -1)"
echo "    lux:             v${LUX_VER}"
echo "    requests:        $REQUESTS"
echo "    clients:         $CLIENTS"
echo "    mode:            sequential (one server at a time)"
echo ""

kill_port "$BENCH_PORT"

run_bench() {
    local port=$1
    local pipeline=$2
    local tmpfile=$(mktemp)
    "$REDIS_BENCH" -p "$port" -t SET -n "$REQUESTS" -c "$CLIENTS" -P "$pipeline" -q >"$tmpfile" 2>/dev/null
    local rps=$(tr '\r' '\n' < "$tmpfile" | grep "requests per second" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    rm -f "$tmpfile"
    echo "${rps:-0}"
}

run_geo_bench() {
    local port=$1
    local pipeline=$2
    local n=$3
    shift 3
    local tmpfile=$(mktemp)
    "$REDIS_BENCH" -p "$port" -n "$n" -c "$CLIENTS" -P "$pipeline" -q "$@" >"$tmpfile" 2>/dev/null
    local rps=$(tr '\r' '\n' < "$tmpfile" | grep "requests per second" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    rm -f "$tmpfile"
    echo "${rps:-0}"
}

seed_geo() {
    local port=$1
    local i=0
    while [ $i -lt "$GEO_MEMBERS" ]; do
        local batch_end=$((i + 50))
        [ $batch_end -gt "$GEO_MEMBERS" ] && batch_end=$GEO_MEMBERS
        local args=""
        local j=$i
        while [ $j -lt $batch_end ]; do
            local lon=$(awk "BEGIN { printf \"%.6f\", -180 + $j * (360.0 / $GEO_MEMBERS) }")
            local lat=$(awk "BEGIN { v = -80 + $j * (170.0 / $GEO_MEMBERS); if (v > 85) v = 85; if (v < -85) v = -85; printf \"%.6f\", v }")
            args="$args $lon $lat place:$j"
            j=$((j + 1))
        done
        "$REDIS_CLI" -p "$port" GEOADD mygeo $args >/dev/null 2>&1
        i=$batch_end
    done
}

declare -a LUX_RESULTS
declare -a REDIS_RESULTS
PIPELINES=(1 16 64 128 256 512)

echo -e "${BOLD}--- SET benchmark ---${NC}"
echo -e "${BOLD}Benchmarking Lux...${NC}"
TMPDIR_LUX=$(mktemp -d)
LUX_PORT=$BENCH_PORT LUX_SAVE_INTERVAL=0 LUX_DATA_DIR="$TMPDIR_LUX" "$LUX_BIN" >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Lux"

for i in "${!PIPELINES[@]}"; do
    P=${PIPELINES[$i]}
    LUX_RESULTS[$i]=$(run_bench "$BENCH_PORT" "$P")
    echo "  pipeline $P: ${LUX_RESULTS[$i]}"
done

kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null || true
rm -rf "$TMPDIR_LUX"
TMPDIR_LUX=""
sleep 1

echo -e "${BOLD}Benchmarking Redis...${NC}"
kill_port "$BENCH_PORT"
"$REDIS_SERVER" --port "$BENCH_PORT" --save "" --appendonly no --daemonize no --loglevel warning >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Redis"

for i in "${!PIPELINES[@]}"; do
    P=${PIPELINES[$i]}
    REDIS_RESULTS[$i]=$(run_bench "$BENCH_PORT" "$P")
    echo "  pipeline $P: ${REDIS_RESULTS[$i]}"
done

kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo ""
echo -e "${BOLD}| Pipeline |                  |         Lux |   Redis ${REDIS_VER} | Lux/Redis |${NC}"
echo "|----------|------------------|------------:|------------:|----------:|"

for i in "${!PIPELINES[@]}"; do
    P=${PIPELINES[$i]}
    lux_fmt=$(fmt_rps "${LUX_RESULTS[$i]:-0}")
    red_fmt=$(fmt_rps "${REDIS_RESULTS[$i]:-0}")
    ratio=$(ratio_rps "${LUX_RESULTS[$i]:-0}" "${REDIS_RESULTS[$i]:-0}")
    printf "| %8s | %-16s | %11s | %11s | %9s |\n" "$P" "SET" "$lux_fmt" "$red_fmt" "$ratio"
done

echo ""
echo ""
echo -e "${BOLD}--- GEO benchmark ($GEO_MEMBERS members) ---${NC}"

GEO_REQ=200000
GEO_PIPELINES=(1 16 64 128 256 512)
GEO_CMDS=(
    "GEOPOS mygeo place:500"
    "GEODIST mygeo place:100 place:500 km"
    "GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 500 km ASC COUNT 10"
    "GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 5000 km ASC COUNT 100"
)
GEO_LABELS=("GEOPOS" "GEODIST" "GEOSEARCH 500km" "GEOSEARCH 5000km")
GEO_CMD_COUNT=${#GEO_CMDS[@]}

run_geo_suite() {
    local port=$1
    local all_results=""
    for pi in "${!GEO_PIPELINES[@]}"; do
        local P=${GEO_PIPELINES[$pi]}
        echo "  pipeline $P:" >&2
        for ci in $(seq 0 $((GEO_CMD_COUNT - 1))); do
            local rps
            rps=$(run_geo_bench "$port" "$P" "$GEO_REQ" ${GEO_CMDS[$ci]})
            echo "    ${GEO_LABELS[$ci]}: $rps" >&2
            all_results="$all_results $rps"
        done
    done
    echo "$all_results"
}

echo -e "${BOLD}Benchmarking Lux GEO...${NC}"
kill_port "$BENCH_PORT"
TMPDIR_LUX=$(mktemp -d)
LUX_PORT=$BENCH_PORT LUX_SAVE_INTERVAL=0 LUX_DATA_DIR="$TMPDIR_LUX" "$LUX_BIN" >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Lux"
seed_geo "$BENCH_PORT"
GEO_LUX_RAW=$(run_geo_suite "$BENCH_PORT")

kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null || true
rm -rf "$TMPDIR_LUX"
TMPDIR_LUX=""
sleep 1

echo -e "${BOLD}Benchmarking Redis GEO...${NC}"
kill_port "$BENCH_PORT"
"$REDIS_SERVER" --port "$BENCH_PORT" --save "" --appendonly no --daemonize no --loglevel warning >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Redis"
seed_geo "$BENCH_PORT"
GEO_REDIS_RAW=$(run_geo_suite "$BENCH_PORT")

kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

read -r -a GEO_LUX_ARR <<< "$GEO_LUX_RAW"
read -r -a GEO_REDIS_ARR <<< "$GEO_REDIS_RAW"

GEO_P_COUNT=${#GEO_PIPELINES[@]}

for ci in $(seq 0 $((GEO_CMD_COUNT - 1))); do
    echo ""
    echo -e "${BOLD}${GEO_LABELS[$ci]}${NC}"
    echo -e "${BOLD}| Pipeline |         Lux |   Redis ${REDIS_VER} | Lux/Redis |${NC}"
    echo "|----------|------------:|------------:|----------:|"
    for pi in "${!GEO_PIPELINES[@]}"; do
        P=${GEO_PIPELINES[$pi]}
        idx=$((pi * GEO_CMD_COUNT + ci))
        lux_fmt=$(fmt_rps "${GEO_LUX_ARR[$idx]:-0}")
        red_fmt=$(fmt_rps "${GEO_REDIS_ARR[$idx]:-0}")
        ratio=$(ratio_rps "${GEO_LUX_ARR[$idx]:-0}" "${GEO_REDIS_ARR[$idx]:-0}")
        printf "| %8s | %11s | %11s | %9s |\n" "$P" "$lux_fmt" "$red_fmt" "$ratio"
    done
done

echo ""
echo -e "${GREEN}Done.${NC}"
