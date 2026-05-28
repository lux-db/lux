#!/bin/bash
set -euo pipefail

BENCH_PORT=${BENCH_PORT:-6390}
REQUESTS=${BENCH_REQUESTS:-1000000}
CLIENTS=${BENCH_CLIENTS:-50}
PIPELINE=${BENCH_PIPELINE:-64}
GEO_MEMBERS=${GEO_MEMBERS:-1000}
EMBEDDED_DISCARD_WRITES=${EMBEDDED_DISCARD_WRITES:-0}
BENCH_DURATION_SECONDS=${BENCH_DURATION_SECONDS:-${BENCH_MIN_SECONDS:-1}}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'


normalize_duration_seconds() {
    python3 - "$1" <<'PYDURATION'
import math
import sys

raw = sys.argv[1].strip()
try:
    value = float(raw)
except ValueError:
    print(f"BENCH_DURATION_SECONDS must be a positive number, got {raw!r}", file=sys.stderr)
    sys.exit(2)

if not math.isfinite(value) or value <= 0:
    print(f"BENCH_DURATION_SECONDS must be greater than 0, got {raw!r}", file=sys.stderr)
    sys.exit(2)

print(f"{value:.9f}")
PYDURATION
}

BENCH_DURATION_SECONDS=$(normalize_duration_seconds "$BENCH_DURATION_SECONDS")

cleanup() {
    [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "${TMPDIR_LUX:-}" ] && rm -rf "$TMPDIR_LUX"
    wait 2>/dev/null || true
} 2>/dev/null
trap cleanup EXIT

wait_for_port() {
    local port=$1
    local name=$2
    for _ in $(seq 1 30); do
        if "$REDIS_CLI" -p "$port" PING >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    echo -e "${RED}$name failed to start on port $port${NC}" >&2
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
    local lhs=${1:-0}
    local rhs=${2:-0}
    awk "BEGIN {
        if ($rhs > 0) printf \"%.2fx\", $lhs/$rhs
        else printf \"N/A\"
    }"
}

now_seconds() {
    python3 -c 'import time; print(f"{time.perf_counter():.9f}")'
}

elapsed_seconds() {
    local start=$1
    local end=$2
    awk "BEGIN { printf \"%.9f\", $end - $start }"
}

less_than_duration() {
    local elapsed=$1
    awk "BEGIN { exit !($elapsed < $BENCH_DURATION_SECONDS) }"
}

REDIS_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/lux-bench"

ensure_latest_redis() {
    local latest
    latest=$(curl -sL "https://api.github.com/repos/redis/redis/releases?per_page=1" \
        | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o '[0-9][0-9.]*' || echo "")
    if [ -z "$latest" ]; then
        if [ -x "$REDIS_CACHE_DIR/redis-server" ]; then
            echo -e "${YELLOW}Using cached Redis build${NC}" >&2
            return 0
        fi
        echo -e "${RED}No cached Redis and cannot fetch latest version. Need internet.${NC}" >&2
        exit 1
    fi

    local marker="$REDIS_CACHE_DIR/.version"
    if [ -x "$REDIS_CACHE_DIR/redis-server" ] && [ -f "$marker" ] && [ "$(cat "$marker")" = "$latest" ]; then
        return 0
    fi

    echo -e "${YELLOW}Building Redis $latest from source...${NC}" >&2
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
}

ensure_latest_redis

REDIS_SERVER="$REDIS_CACHE_DIR/redis-server"
REDIS_BENCH="$REDIS_CACHE_DIR/redis-benchmark"
REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LUX_BIN="$SCRIPT_DIR/target/release/lux"
LUX_EMBEDDED_BENCH="$SCRIPT_DIR/target/release/examples/embedded_bench"

if [ ! -f "$LUX_BIN" ]; then
    echo -e "${YELLOW}Building Lux (release)...${NC}" >&2
    (cd "$SCRIPT_DIR" && cargo build --release)
fi

if [ ! -f "$LUX_EMBEDDED_BENCH" ]; then
    echo -e "${YELLOW}Building Lux embedded benchmark (release)...${NC}" >&2
    (cd "$SCRIPT_DIR" && cargo build --release --example embedded_bench)
fi

REDIS_VER=$("$REDIS_SERVER" --version 2>&1 | head -1 | grep -oE 'v=[0-9]+\.[0-9]+\.[0-9]+' | cut -d= -f2)
LUX_VER=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

COMMANDS=(
    "SET|SET __lux_bench_key __lux_bench_value"
    "GET|GET __lux_bench_key"
    "INCR|INCR __lux_bench_counter"
    "LPUSH|LPUSH __lux_bench_list __lux_bench_value"
    "RPUSH|RPUSH __lux_bench_list __lux_bench_value"
    "LPOP|LPOP __lux_bench_list"
    "RPOP|RPOP __lux_bench_list"
    "SADD|SADD __lux_bench_set __lux_bench_member"
    "HSET|HSET __lux_bench_hash __lux_bench_field __lux_bench_value"
    "SPOP|SPOP __lux_bench_set"
    "ZADD|ZADD __lux_bench_zset 1 __lux_bench_member"
    "ZPOPMIN|ZPOPMIN __lux_bench_zset"
    "GEOPOS|GEOPOS mygeo place:500"
    "GEODIST|GEODIST mygeo place:100 place:500 km"
    "GEOSEARCH (500km)|GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 500 km ASC COUNT 10"
    "GEOSEARCH (5000km)|GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 5000 km ASC COUNT 100"
)

is_geo_label() {
    [[ "$1" == GEO* ]]
}

seed_geo() {
    local port=$1
    local i=0
    while [ "$i" -lt "$GEO_MEMBERS" ]; do
        local batch_end=$((i + 50))
        [ "$batch_end" -gt "$GEO_MEMBERS" ] && batch_end=$GEO_MEMBERS
        local args=""
        local j=$i
        while [ "$j" -lt "$batch_end" ]; do
            local lon
            local lat
            lon=$(awk "BEGIN { printf \"%.6f\", -180 + $j * (360.0 / $GEO_MEMBERS) }")
            lat=$(awk "BEGIN { v = -80 + $j * (170.0 / $GEO_MEMBERS); if (v > 85) v = 85; if (v < -85) v = -85; printf \"%.6f\", v }")
            args="$args $lon $lat place:$j"
            j=$((j + 1))
        done
        "$REDIS_CLI" -p "$port" GEOADD mygeo $args >/dev/null 2>&1
        i=$batch_end
    done
}

seed_unique_set() {
    local port=$1
    local key=$2
    awk -v n="$REQUESTS" -v key="$key" 'BEGIN {
        for (i = 0; i < n; i++) {
            member = "member:" i
            printf "*3\r\n$4\r\nSADD\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", length(key), key, length(member), member
        }
    }' | "$REDIS_CLI" -p "$port" --pipe >/dev/null 2>&1
}

seed_unique_zset() {
    local port=$1
    local key=$2
    awk -v n="$REQUESTS" -v key="$key" 'BEGIN {
        for (i = 0; i < n; i++) {
            score = "" i
            member = "member:" i
            printf "*4\r\n$4\r\nZADD\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", length(key), key, length(score), score, length(member), member
        }
    }' | "$REDIS_CLI" -p "$port" --pipe >/dev/null 2>&1
}

seed_resp_command() {
    local port=$1
    local label=$2
    "$REDIS_CLI" -p "$port" FLUSHDB >/dev/null 2>&1
    if [ "$label" = "GET" ]; then
        "$REDIS_CLI" -p "$port" SET __lux_bench_key __lux_bench_value >/dev/null 2>&1
    elif [ "$label" = "LPOP" ] || [ "$label" = "RPOP" ]; then
        "$REDIS_BENCH" -p "$port" -n "$REQUESTS" -c "$CLIENTS" -P "$PIPELINE" -q \
            RPUSH __lux_bench_list __lux_bench_value >/dev/null 2>&1
    elif [ "$label" = "SPOP" ]; then
        seed_unique_set "$port" "__lux_bench_set"
    elif [ "$label" = "ZPOPMIN" ]; then
        seed_unique_zset "$port" "__lux_bench_zset"
    elif is_geo_label "$label"; then
        seed_geo "$port"
    fi
}

reseed_each_trial() {
    case "$1" in
        LPOP|RPOP|SPOP|ZPOPMIN|APPEND|"PERSIST (ttl)") return 0 ;;
        *) return 1 ;;
    esac
}

run_resp_command() {
    local port=$1
    local label=$2
    local cmdline=$3
    local argv
    read -r -a argv <<< "$cmdline"
    local tmpfile
    local total_elapsed=0
    local total_requests=0
    if ! reseed_each_trial "$label"; then
        seed_resp_command "$port" "$label"
    fi
    while less_than_duration "$total_elapsed"; do
        tmpfile=$(mktemp)
        if reseed_each_trial "$label"; then
            seed_resp_command "$port" "$label"
        fi
        local started
        local ended
        started=$(now_seconds)
        "$REDIS_BENCH" -p "$port" -n "$REQUESTS" -c "$CLIENTS" -P "$PIPELINE" -q "${argv[@]}" >"$tmpfile" 2>/dev/null
        ended=$(now_seconds)
        rm -f "$tmpfile"
        local elapsed
        elapsed=$(elapsed_seconds "$started" "$ended")
        total_elapsed=$(awk "BEGIN { printf \"%.9f\", $total_elapsed + $elapsed }")
        total_requests=$((total_requests + REQUESTS))
    done
    awk "BEGIN { if ($total_elapsed > 0) printf \"%.2f\\n\", $total_requests / $total_elapsed; else print 0 }"
}

run_embedded_command() {
    local cmdline=$1
    local argv
    read -r -a argv <<< "$cmdline"
    BENCH_REQUESTS="$REQUESTS" \
        BENCH_CLIENTS="$CLIENTS" \
        BENCH_PIPELINE="$PIPELINE" \
        BENCH_MIN_SECONDS="$BENCH_DURATION_SECONDS" \
        GEO_MEMBERS="$GEO_MEMBERS" \
        EMBEDDED_DISCARD_WRITES="$EMBEDDED_DISCARD_WRITES" \
        "$LUX_EMBEDDED_BENCH" cmd "${argv[@]}"
}

run_embedded_suite() {
    for item in "${COMMANDS[@]}"; do
        IFS='|' read -r label cmdline <<< "$item"
        echo -e "  ${label}" >&2
        local rps
        rps=$(run_embedded_command "$cmdline")
        echo -e "    ${label}: $(fmt_rps "$rps")" >&2
        echo "$rps"
    done
}

run_resp_suite() {
    local port=$1
    for item in "${COMMANDS[@]}"; do
        IFS='|' read -r label cmdline <<< "$item"
        echo -e "  ${label}" >&2
        local rps
        rps=$(run_resp_command "$port" "$label" "$cmdline")
        echo -e "    ${label}: $(fmt_rps "$rps")" >&2
        echo "$rps"
    done
}

echo -e "${BOLD}=== Lux Command Table Benchmark ===${NC}" >&2
echo "    lux:                  v${LUX_VER}" >&2
echo "    redis-server:         $("$REDIS_SERVER" --version 2>&1 | head -1)" >&2
echo "    redis-benchmark:      $("$REDIS_BENCH" --version 2>&1 | head -1)" >&2
echo "    requests:             $REQUESTS" >&2
echo "    clients:              $CLIENTS" >&2
echo "    pipeline:             $PIPELINE" >&2
echo "    geo members:          $GEO_MEMBERS" >&2
echo "    embedded discard:     $EMBEDDED_DISCARD_WRITES" >&2
echo "    duration seconds:     $BENCH_DURATION_SECONDS" >&2
echo "" >&2

echo -e "${BOLD}Benchmarking Embedded Lux...${NC}" >&2
EMBEDDED_RAW=$(run_embedded_suite)
EMBEDDED_RESULTS=()
while IFS= read -r line; do
    EMBEDDED_RESULTS+=("$line")
done <<< "$EMBEDDED_RAW"

echo -e "${BOLD}Benchmarking Lux RESP...${NC}" >&2
kill_port "$BENCH_PORT"
TMPDIR_LUX=$(mktemp -d)
LUX_PORT=$BENCH_PORT LUX_SAVE_INTERVAL=0 LUX_DATA_DIR="$TMPDIR_LUX" "$LUX_BIN" >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Lux"
LUX_RAW=$(run_resp_suite "$BENCH_PORT")
LUX_RESULTS=()
while IFS= read -r line; do
    LUX_RESULTS+=("$line")
done <<< "$LUX_RAW"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
rm -rf "$TMPDIR_LUX"
TMPDIR_LUX=""

echo -e "${BOLD}Benchmarking Redis RESP...${NC}" >&2
kill_port "$BENCH_PORT"
"$REDIS_SERVER" --port "$BENCH_PORT" --save "" --appendonly no --daemonize no --loglevel warning >/dev/null 2>&1 &
SERVER_PID=$!
wait_for_port "$BENCH_PORT" "Redis"
REDIS_RAW=$(run_resp_suite "$BENCH_PORT")
REDIS_RESULTS=()
while IFS= read -r line; do
    REDIS_RESULTS+=("$line")
done <<< "$REDIS_RAW"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo "| Command | Embedded Lux | Lux RESP | Redis RESP ${REDIS_VER} | Embedded/Lux | Lux/Redis |"
echo "|---------|-------------:|---------:|-------------------:|-------------:|----------:|"
for i in "${!COMMANDS[@]}"; do
    IFS='|' read -r label _ <<< "${COMMANDS[$i]}"
    embedded=${EMBEDDED_RESULTS[$i]:-0}
    lux=${LUX_RESULTS[$i]:-0}
    redis=${REDIS_RESULTS[$i]:-0}
    printf "| %s | %s | %s | %s | **%s** | **%s** |\n" \
        "$label" \
        "$(fmt_rps "$embedded")" \
        "$(fmt_rps "$lux")" \
        "$(fmt_rps "$redis")" \
        "$(ratio_rps "$embedded" "$lux")" \
        "$(ratio_rps "$lux" "$redis")"
done

echo -e "${GREEN}Done.${NC}" >&2
