#!/bin/bash
set -euo pipefail
set -f

BENCH_PORT=${BENCH_PORT:-6390}
REQUESTS=${BENCH_REQUESTS:-100000}
CLIENTS=${BENCH_CLIENTS:-10}
PIPELINE=${BENCH_PIPELINE:-32}
SEED_ITEMS=${BENCH_SEED_ITEMS:-32}
GEO_MEMBERS=${GEO_MEMBERS:-100}
KEYSPACE=${BENCH_KEYSPACE:-1024}
EMBEDDED_DISCARD_WRITES=${EMBEDDED_DISCARD_WRITES:-0}
BENCH_DURATION_SECONDS=${BENCH_DURATION_SECONDS:-${BENCH_MIN_SECONDS:-0.5}}
EMBEDDED_TRIALS=${EMBEDDED_TRIALS:-1}
BENCH_BUILD_MISSING_BINARIES=${BENCH_BUILD_MISSING_BINARIES:-0}
BENCH_VALIDATE=${BENCH_VALIDATE:-1}
BENCH_VALIDATE_ONLY=${BENCH_VALIDATE_ONLY:-0}
BENCH_VALIDATE_REQUESTS=${BENCH_VALIDATE_REQUESTS:-1}
BENCH_ALLOW_DISCARD_WRITES=${BENCH_ALLOW_DISCARD_WRITES:-0}
BENCH_KEY_PREFIX=${BENCH_KEY_PREFIX:-__lux_bench_$(date +%s%N)_$$}
BENCH_GEO_KEY=${BENCH_GEO_KEY:-${BENCH_KEY_PREFIX}_geo}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --validate-only)
            BENCH_VALIDATE_ONLY=1
            shift
            ;;
        --no-validate)
            BENCH_VALIDATE=0
            shift
            ;;
        *)
            echo "usage: $0 [--validate-only] [--no-validate]" >&2
            exit 2
            ;;
    esac
done

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
    [ -n "${VALIDATE_LUX_PID:-}" ] && kill "$VALIDATE_LUX_PID" 2>/dev/null || true
    [ -n "${VALIDATE_REDIS_PID:-}" ] && kill "$VALIDATE_REDIS_PID" 2>/dev/null || true
    [ -n "${TMPDIR_LUX:-}" ] && rm -rf "$TMPDIR_LUX"
    [ -n "${TMP_RESULTS_DIR:-}" ] && rm -rf "$TMP_RESULTS_DIR"
    [ -n "${VALIDATE_LUX_TMPDIR:-}" ] && rm -rf "$VALIDATE_LUX_TMPDIR"
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

less_than_duration() {
    local elapsed=$1
    awk "BEGIN { exit !($elapsed < $BENCH_DURATION_SECONDS) }"
}

now_seconds() {
    python3 -c 'import time; print(f"{time.perf_counter():.9f}")'
}

elapsed_seconds() {
    local start=$1
    local end=$2
    awk "BEGIN { printf \"%.9f\", $end - $start }"
}

parse_redis_benchmark_rps() {
    local file=$1
    local rps
    rps=$(awk -F',' 'NR > 1 {
        gsub(/"/, "", $2)
        if ($2 ~ /^[0-9]+([.][0-9]+)?$/ && $2 + 0 > 0) {
            print $2
            exit
        }
    }' "$file")
    if [ -z "$rps" ]; then
        rps=$(sed -nE 's/.* ([0-9]+([.][0-9]+)?) requests per second.*/\1/p' "$file" | tail -1)
    fi
    if [ -z "$rps" ]; then
        echo -e "${RED}Could not parse redis-benchmark throughput from:${NC}" >&2
        sed -n '1,20p' "$file" >&2
        return 1
    fi
    echo "$rps"
}

REDIS_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/lux-bench"
BENCH_FETCH_LATEST_REDIS=${BENCH_FETCH_LATEST_REDIS:-0}

ensure_latest_redis() {
    if [ -n "${REDIS_SERVER:-}" ] && [ -n "${REDIS_BENCH:-}" ] && [ -n "${REDIS_CLI:-}" ]; then
        if [ -x "$REDIS_SERVER" ] && [ -x "$REDIS_BENCH" ] && [ -x "$REDIS_CLI" ]; then
            return 0
        fi
        echo -e "${RED}REDIS_SERVER/REDIS_BENCH/REDIS_CLI must all point to executables.${NC}" >&2
        exit 1
    fi

    if [ "$BENCH_FETCH_LATEST_REDIS" != "1" ]; then
        if command -v redis-server >/dev/null 2>&1 && command -v redis-benchmark >/dev/null 2>&1 && command -v redis-cli >/dev/null 2>&1; then
            REDIS_SERVER="$(command -v redis-server)"
            REDIS_BENCH="$(command -v redis-benchmark)"
            REDIS_CLI="$(command -v redis-cli)"
            return 0
        fi
        if [ -x "$REDIS_CACHE_DIR/redis-server" ] && [ -x "$REDIS_CACHE_DIR/redis-benchmark" ] && [ -x "$REDIS_CACHE_DIR/redis-cli" ]; then
            REDIS_SERVER="$REDIS_CACHE_DIR/redis-server"
            REDIS_BENCH="$REDIS_CACHE_DIR/redis-benchmark"
            REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"
            return 0
        fi
        echo -e "${RED}Redis tools not found locally. Set BENCH_FETCH_LATEST_REDIS=1 to fetch/build.${NC}" >&2
        exit 1
    fi

    local latest
    latest=$(curl -sL "https://api.github.com/repos/redis/redis/releases?per_page=1" \
        | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o '[0-9][0-9.]*' || echo "")
    if [ -z "$latest" ]; then
        if [ -x "$REDIS_CACHE_DIR/redis-server" ]; then
            echo -e "${YELLOW}Using cached Redis build${NC}" >&2
            REDIS_SERVER="$REDIS_CACHE_DIR/redis-server"
            REDIS_BENCH="$REDIS_CACHE_DIR/redis-benchmark"
            REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"
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
    REDIS_SERVER="$REDIS_CACHE_DIR/redis-server"
    REDIS_BENCH="$REDIS_CACHE_DIR/redis-benchmark"
    REDIS_CLI="$REDIS_CACHE_DIR/redis-cli"
}

ensure_latest_redis

is_wrapper_executable() {
    local path=$1
    [ -f "$path" ] || return 1
    LC_ALL=C head -c 512 "$path" 2>/dev/null | grep -Eq 'wrapper|\.real'
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LUX_BIN_OVERRIDE=${LUX_BIN:-}
LUX_EMBEDDED_BENCH_OVERRIDE=${LUX_EMBEDDED_BENCH:-}

if [ -n "$LUX_BIN_OVERRIDE" ]; then
    LUX_BIN="$LUX_BIN_OVERRIDE"
else
    LUX_BIN="$SCRIPT_DIR/target/release/lux"
    if [ -x "$SCRIPT_DIR/target/release/lux.real" ] && is_wrapper_executable "$LUX_BIN"; then
        LUX_BIN="$SCRIPT_DIR/target/release/lux.real"
    fi
fi

if [ -n "$LUX_EMBEDDED_BENCH_OVERRIDE" ]; then
    LUX_EMBEDDED_BENCH="$LUX_EMBEDDED_BENCH_OVERRIDE"
else
    LUX_EMBEDDED_BENCH="$SCRIPT_DIR/target/release/examples/embedded_bench"
    if [ -x "$SCRIPT_DIR/target/release/examples/embedded_bench.real" ] && is_wrapper_executable "$LUX_EMBEDDED_BENCH"; then
        LUX_EMBEDDED_BENCH="$SCRIPT_DIR/target/release/examples/embedded_bench.real"
    fi
fi

if [ ! -x "$LUX_BIN" ] && [ "$BENCH_BUILD_MISSING_BINARIES" = "1" ]; then
    echo -e "${YELLOW}Building Lux (release)...${NC}" >&2
    (cd "$SCRIPT_DIR" && cargo build --release)
fi

if [ ! -x "$LUX_EMBEDDED_BENCH" ] && [ "$BENCH_BUILD_MISSING_BINARIES" = "1" ]; then
    echo -e "${YELLOW}Building Lux embedded benchmark (release)...${NC}" >&2
    (cd "$SCRIPT_DIR" && cargo build --release --example embedded_bench)
fi

if [ ! -x "$LUX_BIN" ]; then
    echo -e "${RED}Lux RESP binary missing/non-executable: $LUX_BIN${NC}" >&2
    exit 1
fi
if [ ! -x "$LUX_EMBEDDED_BENCH" ]; then
    echo -e "${RED}Embedded benchmark binary missing/non-executable: $LUX_EMBEDDED_BENCH${NC}" >&2
    exit 1
fi

REDIS_VER=$("$REDIS_SERVER" --version 2>&1 | head -1 | grep -oE 'v=[0-9]+\.[0-9]+\.[0-9]+' | cut -d= -f2)
LUX_VER=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

if [ "$GEO_MEMBERS" -lt 1 ]; then
    echo -e "${RED}GEO_MEMBERS must be at least 1.${NC}" >&2
    exit 2
fi
if [ "$KEYSPACE" -lt 1 ]; then
    echo -e "${RED}BENCH_KEYSPACE must be at least 1.${NC}" >&2
    exit 2
fi
GEO_MEMBER_A="place:0"
GEO_MEMBER_B="place:$((GEO_MEMBERS / 2))"

COMMANDS=(
    "PING|PING"
    "SET|SET __lux_bench_key __lux_bench_value"
    "GET|GET __lux_bench_key"
    "MSET|MSET __lux_bench_key1 one __lux_bench_key2 two __lux_bench_key3 three"
    "MGET|MGET __lux_bench_key1 __lux_bench_key2 __lux_bench_key3"
    "GETSET|GETSET __lux_bench_key __lux_bench_new_value"
    "SETNX (existing)|SETNX __lux_bench_key __lux_bench_value"
    "SETEX|SETEX __lux_bench_key 3600 __lux_bench_value"
    "PSETEX|PSETEX __lux_bench_key 3600000 __lux_bench_value"
    "APPEND|APPEND __lux_bench_key x"
    "STRLEN|STRLEN __lux_bench_strlen:__rand_int__"
    "INCR|INCR __lux_bench_counter"
    "DECR|DECR __lux_bench_counter"
    "INCRBY|INCRBY __lux_bench_counter 10"
    "DECRBY|DECRBY __lux_bench_counter 10"
    "EXISTS|EXISTS __lux_bench_exists1 __lux_bench_exists2 __lux_bench_exists3 __lux_bench_exists4"
    "EXPIRE|EXPIRE __lux_bench_key 3600"
    "TTL|TTL __lux_bench_key"
    "PTTL|PTTL __lux_bench_key"
    "PERSIST (ttl)|PERSIST __lux_bench_key"
    "TYPE|TYPE __lux_bench_key"
    "DBSIZE|DBSIZE"
    "LPUSH|LPUSH __lux_bench_list __lux_bench_value"
    "RPUSH|RPUSH __lux_bench_list __lux_bench_value"
    "LLEN|LLEN __lux_bench_list"
    "LINDEX|LINDEX __lux_bench_list 10"
    "LRANGE (10)|LRANGE __lux_bench_list 0 9"
    "LPOP|LPOP __lux_bench_list"
    "RPOP|RPOP __lux_bench_list"
    "HSET|HSET __lux_bench_hash field:1 __lux_bench_value"
    "HGET|HGET __lux_bench_hash field:1"
    "HMGET|HMGET __lux_bench_hash field:1 field:2 field:3"
    "HINCRBY|HINCRBY __lux_bench_hash counter 1"
    "HEXISTS|HEXISTS __lux_bench_hash field:1"
    "HLEN|HLEN __lux_bench_hash"
    "HGETALL|HGETALL __lux_bench_hash"
    "SADD|SADD __lux_bench_set member:1"
    "SISMEMBER|SISMEMBER __lux_bench_set member:1"
    "SCARD|SCARD __lux_bench_set"
    "SMEMBERS|SMEMBERS __lux_bench_set"
    "SRANDMEMBER|SRANDMEMBER __lux_bench_set"
    "SPOP|SPOP __lux_bench_set"
    "SUNION|SUNION __lux_bench_set1 __lux_bench_set2"
    "SINTER|SINTER __lux_bench_set1 __lux_bench_set2"
    "SDIFF|SDIFF __lux_bench_set1 __lux_bench_set2"
    "ZADD|ZADD __lux_bench_zset 1 member:1"
    "ZSCORE|ZSCORE __lux_bench_zset member:1"
    "ZCARD|ZCARD __lux_bench_zset"
    "ZCOUNT|ZCOUNT __lux_bench_zset -inf +inf"
    "ZRANGE (10)|ZRANGE __lux_bench_zset 0 9"
    "ZRANGE WITHSCORES (10)|ZRANGE __lux_bench_zset 0 9 WITHSCORES"
    "ZINCRBY|ZINCRBY __lux_bench_zset 1 member:1"
    "ZPOPMIN|ZPOPMIN __lux_bench_zset"
    "ZPOPMAX|ZPOPMAX __lux_bench_zset"
    "GEOADD (update)|GEOADD mygeo 0 0 $GEO_MEMBER_B"
    "GEOPOS|GEOPOS mygeo $GEO_MEMBER_B"
    "GEODIST|GEODIST mygeo $GEO_MEMBER_A $GEO_MEMBER_B km"
    "GEOSEARCH (500km)|GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 500 km ASC COUNT 10"
    "GEOSEARCH (5000km)|GEOSEARCH mygeo FROMLONLAT 0 0 BYRADIUS 5000 km ASC COUNT 100"
    "XADD|XADD __lux_bench_stream * field value"
    "XLEN|XLEN __lux_bench_stream"
    "XRANGE (10)|XRANGE __lux_bench_stream - + COUNT 10"
    "PUBLISH (no subscribers)|PUBLISH __lux_bench_channel __lux_bench_message"
)

is_geo_label() {
    [[ "$1" == GEO* ]]
}

resolve_cmdline() {
    local cmdline=$1
    cmdline=${cmdline//__lux_bench/$BENCH_KEY_PREFIX}
    cmdline=${cmdline//mygeo/$BENCH_GEO_KEY}
    printf "%s\n" "$cmdline"
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
        "$REDIS_CLI" -p "$port" GEOADD "$BENCH_GEO_KEY" $args >/dev/null 2>&1
        i=$batch_end
    done
}

seed_string() {
    local port=$1
    local key=$2
    "$REDIS_CLI" -p "$port" SET "$key" __lux_bench_value >/dev/null 2>&1
}

seed_string_keyspace() {
    local port=$1
    local template=$2
    local count=$3
    awk -v n="$count" -v template="$template" 'BEGIN {
        for (i = 0; i < n; i++) {
            key = template
            token = sprintf("%012d", i)
            gsub(/__rand_int__/, token, key)
            value = "__lux_bench_value"
            printf "*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", length(key), key, length(value), value
        }
    }' | "$REDIS_CLI" -p "$port" --pipe >/dev/null 2>&1
}

seed_expiring_string() {
    local port=$1
    local key=$2
    seed_string "$port" "$key"
    "$REDIS_CLI" -p "$port" EXPIRE "$key" 3600 >/dev/null 2>&1
}

seed_list() {
    local port=$1
    local key=$2
    local count=$3
    awk -v n="$count" -v key="$key" 'BEGIN {
        for (i = 0; i < n; i++) {
            value = "__lux_bench_value"
            printf "*3\r\n$5\r\nRPUSH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", length(key), key, length(value), value
        }
    }' | "$REDIS_CLI" -p "$port" --pipe >/dev/null 2>&1
}

seed_hash() {
    local port=$1
    local key=$2
    local count=${3:-$SEED_ITEMS}
    local i=0
    while [ "$i" -lt "$count" ]; do
        local batch_end=$((i + 200))
        [ "$batch_end" -gt "$count" ] && batch_end=$count
        local args=()
        while [ "$i" -lt "$batch_end" ]; do
            args+=("field:$i" "value:$i")
            i=$((i + 1))
        done
        "$REDIS_CLI" -p "$port" HSET "$key" "${args[@]}" >/dev/null 2>&1
    done
    "$REDIS_CLI" -p "$port" HSET "$key" counter 0 >/dev/null 2>&1
}

seed_set() {
    local port=$1
    local key=$2
    local count=$3
    local i=0
    while [ "$i" -lt "$count" ]; do
        local batch_end=$((i + 500))
        [ "$batch_end" -gt "$count" ] && batch_end=$count
        local args=()
        while [ "$i" -lt "$batch_end" ]; do
            args+=("member:$i")
            i=$((i + 1))
        done
        "$REDIS_CLI" -p "$port" SADD "$key" "${args[@]}" >/dev/null 2>&1
    done
}

seed_zset() {
    local port=$1
    local key=$2
    local count=$3
    local i=0
    while [ "$i" -lt "$count" ]; do
        local batch_end=$((i + 250))
        [ "$batch_end" -gt "$count" ] && batch_end=$count
        local args=()
        while [ "$i" -lt "$batch_end" ]; do
            args+=("$i" "member:$i")
            i=$((i + 1))
        done
        "$REDIS_CLI" -p "$port" ZADD "$key" "${args[@]}" >/dev/null 2>&1
    done
}

seed_stream() {
    local port=$1
    local key=$2
    local i=0
    while [ "$i" -lt "$SEED_ITEMS" ]; do
        "$REDIS_CLI" -p "$port" XADD "$key" "$((i + 1))-0" field "value:$i" >/dev/null 2>&1
        i=$((i + 1))
    done
}

seed_keys_after_command() {
    local port=$1
    shift
    shift
    for key in "$@"; do
        seed_string "$port" "$key"
    done
}

seed_resp_command() {
    local port=$1
    local label=$2
    local cmdline=$3
    "$REDIS_CLI" -p "$port" FLUSHDB >/dev/null 2>&1

    read -r -a argv <<< "$cmdline"
    local cmd=${argv[0]^^}
    case "$cmd" in
        STRLEN)
            if [[ "${argv[1]}" == *__rand_int__* ]]; then
                seed_string_keyspace "$port" "${argv[1]}" "$KEYSPACE"
            else
                seed_string "$port" "${argv[1]}"
            fi
            ;;
        GET|GETSET|SETNX|APPEND|EXPIRE|TYPE)
            seed_string "$port" "${argv[1]}"
            ;;
        TTL|PTTL|PERSIST)
            seed_expiring_string "$port" "${argv[1]}"
            ;;
        MGET|EXISTS)
            seed_keys_after_command "$port" "${argv[@]}"
            ;;
        DBSIZE)
            seed_string "$port" "${BENCH_KEY_PREFIX}_key"
            ;;
        LLEN|LINDEX|LRANGE)
            seed_list "$port" "${argv[1]}" "$SEED_ITEMS"
            ;;
        LPOP|RPOP)
            seed_list "$port" "${argv[1]}" "$REQUESTS"
            ;;
        HGET|HMGET|HINCRBY|HEXISTS|HLEN)
            seed_hash "$port" "${argv[1]}" 4
            ;;
        HGETALL)
            seed_hash "$port" "${argv[1]}" "$SEED_ITEMS"
            ;;
        SISMEMBER|SCARD|SMEMBERS|SRANDMEMBER)
            seed_set "$port" "${argv[1]}" "$SEED_ITEMS"
            ;;
        SPOP)
            seed_set "$port" "${argv[1]}" "$REQUESTS"
            ;;
        SUNION|SINTER|SDIFF)
            seed_set "$port" "${argv[1]}" "$SEED_ITEMS"
            seed_set "$port" "${argv[2]}" "$SEED_ITEMS"
            ;;
        ZSCORE|ZCARD|ZCOUNT|ZRANGE|ZINCRBY)
            seed_zset "$port" "${argv[1]}" "$SEED_ITEMS"
            ;;
        ZPOPMIN|ZPOPMAX)
            seed_zset "$port" "${argv[1]}" "$REQUESTS"
            ;;
        XLEN|XRANGE)
            seed_stream "$port" "${argv[1]}"
            ;;
    esac

    if is_geo_label "$label"; then
        seed_geo "$port"
    fi
}

reseed_each_trial() {
    case "$1" in
        LPOP|RPOP|SPOP|ZPOPMIN|ZPOPMAX|APPEND|"PERSIST (ttl)") return 0 ;;
        *) return 1 ;;
    esac
}

run_resp_command() {
    local port=$1
    local label=$2
    local cmdline=$3
    local argv
    read -r -a argv <<< "$cmdline"
    local measured_elapsed=0
    local wall_elapsed=0
    local total_requests=0
    if ! reseed_each_trial "$label"; then
        seed_resp_command "$port" "$label" "$cmdline"
    fi
    while less_than_duration "$wall_elapsed"; do
        local trial_requests
        trial_requests=$(requests_for_label "$label")
        local tmpfile
        tmpfile=$(mktemp)
        if reseed_each_trial "$label"; then
            seed_resp_command "$port" "$label" "$cmdline"
        fi
        local started
        local ended
        started=$(now_seconds)
        local status=0
        if [[ "$cmdline" == *__rand_int__* ]]; then
            "$REDIS_BENCH" -p "$port" -r "$KEYSPACE" -n "$trial_requests" -c "$CLIENTS" -P "$PIPELINE" --csv "${argv[@]}" >"$tmpfile" 2>&1 || status=$?
        else
            "$REDIS_BENCH" -p "$port" -n "$trial_requests" -c "$CLIENTS" -P "$PIPELINE" --csv "${argv[@]}" >"$tmpfile" 2>&1 || status=$?
        fi
        if [ "$status" -ne 0 ]; then
            echo -e "${RED}redis-benchmark failed for ${label}:${NC}" >&2
            sed -n '1,20p' "$tmpfile" >&2
            rm -f "$tmpfile"
            return 1
        fi
        ended=$(now_seconds)
        local trial_rps
        if ! trial_rps=$(parse_redis_benchmark_rps "$tmpfile"); then
            rm -f "$tmpfile"
            return 1
        fi
        rm -f "$tmpfile"
        local elapsed
        elapsed=$(elapsed_seconds "$started" "$ended")
        wall_elapsed=$(awk -v total="$wall_elapsed" -v elapsed="$elapsed" 'BEGIN { printf "%.9f", total + elapsed }')
        measured_elapsed=$(awk -v total="$measured_elapsed" -v requests="$trial_requests" -v rps="$trial_rps" 'BEGIN {
            if (rps <= 0) exit 1
            printf "%.9f", total + (requests / rps)
        }')
        total_requests=$((total_requests + trial_requests))
    done
    awk -v elapsed="$measured_elapsed" -v requests="$total_requests" 'BEGIN {
        if (elapsed > 0) printf "%.2f\n", requests / elapsed
        else print 0
    }'
}

json_array() {
    local primary=$1
    local post=${2:-}
    PRIMARY_JSON="$primary" POST_JSON="$post" python3 - <<'PYJSON'
import json
import os

primary = json.loads(os.environ["PRIMARY_JSON"])
post = os.environ.get("POST_JSON", "")
values = [primary]
if post:
    values.append(json.loads(post))
print(json.dumps(values, separators=(",", ":")))
PYJSON
}

run_resp_json_command() {
    local port=$1
    local cmdline=$2
    local argv
    read -r -a argv <<< "$cmdline"
    "$REDIS_CLI" -p "$port" --json "${argv[@]}" | tr -d '\r'
}

run_resp_validation() {
    local port=$1
    local label=$2
    local cmdline=$3
    local postcheck=${4:-}
    local saved_requests=$REQUESTS
    REQUESTS=$BENCH_VALIDATE_REQUESTS
    seed_resp_command "$port" "$label" "$cmdline"
    REQUESTS=$saved_requests

    local primary
    primary=$(run_resp_json_command "$port" "$cmdline")
    if [ -n "$postcheck" ]; then
        local post
        post=$(run_resp_json_command "$port" "$postcheck")
        json_array "$primary" "$post"
    else
        json_array "$primary"
    fi
}

requests_for_label() {
    local label=$1
    local requested
    case "$label" in
        "GEOSEARCH (5000km)") requested=1000 ;;
        "GEOSEARCH (500km)") requested=2000 ;;
        "SMEMBERS"|"SUNION"|"SINTER"|"SDIFF"|"HGETALL"|"XRANGE (10)") requested=3000 ;;
        "ZRANGE WITHSCORES (10)"|"ZRANGE (10)"|"LRANGE (10)"|"MGET"|"HMGET") requested=5000 ;;
        *) requested=$REQUESTS ;;
    esac
    if [ "$REQUESTS" -lt "$requested" ]; then
        echo "$REQUESTS"
    else
        echo "$requested"
    fi
}

postcheck_for_label() {
    local label=$1
    local cmdline=$2
    local argv
    read -r -a argv <<< "$cmdline"
    local cmd=${argv[0]^^}
    case "$cmd" in
        SET|SETEX|PSETEX|GETSET|SETNX|APPEND)
            echo "GET ${argv[1]}"
            ;;
        MSET)
            local out=("MGET")
            local i
            for ((i = 1; i < ${#argv[@]}; i += 2)); do
                out+=("${argv[$i]}")
            done
            printf "%s " "${out[@]}" | sed 's/ $//'
            echo
            ;;
        INCR|DECR|INCRBY|DECRBY)
            echo "GET ${argv[1]}"
            ;;
        EXPIRE|PERSIST)
            echo "TTL ${argv[1]}"
            ;;
        LPUSH|RPUSH|LPOP|RPOP)
            echo "LLEN ${argv[1]}"
            ;;
        HSET|HINCRBY)
            echo "HGET ${argv[1]} ${argv[2]}"
            ;;
        SADD)
            echo "SISMEMBER ${argv[1]} ${argv[2]}"
            ;;
        SPOP)
            echo "SCARD ${argv[1]}"
            ;;
        ZADD)
            echo "ZSCORE ${argv[1]} ${argv[3]}"
            ;;
        ZINCRBY)
            echo "ZSCORE ${argv[1]} ${argv[3]}"
            ;;
        ZPOPMIN|ZPOPMAX)
            echo "ZCARD ${argv[1]}"
            ;;
        GEOADD)
            echo "GEOPOS ${argv[1]} ${argv[4]}"
            ;;
        XADD)
            echo "XLEN ${argv[1]}"
            ;;
        *)
            echo ""
            ;;
    esac
}

seed_count_for_label() {
    local label=$1
    case "$label" in
        LPOP|RPOP|SPOP|ZPOPMIN|ZPOPMAX) requests_for_label "$label" ;;
        *) echo "$REQUESTS" ;;
    esac
}

should_validate_label() {
    case "$1" in
        PING|SET|GET|MSET|LPOP|HINCRBY|HGETALL|SPOP|ZINCRBY|ZPOPMIN|GEOPOS|"GEOSEARCH (500km)"|XADD|"PUBLISH (no subscribers)")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

run_embedded_command() {
    local cmdline=$1
    local argv
    read -r -a argv <<< "$cmdline"
    BENCH_REQUESTS="$REQUESTS" \
        BENCH_CLIENTS="$CLIENTS" \
        BENCH_PIPELINE="$PIPELINE" \
        BENCH_MIN_SECONDS="$BENCH_DURATION_SECONDS" \
        BENCH_SEED_ITEMS="$SEED_ITEMS" \
        BENCH_KEYSPACE="$KEYSPACE" \
        GEO_MEMBERS="$GEO_MEMBERS" \
        EMBEDDED_DISCARD_WRITES="$EMBEDDED_DISCARD_WRITES" \
        "$LUX_EMBEDDED_BENCH" cmd "${argv[@]}"
}


validate_outputs() {
    local label=$1
    local embedded=$2
    local lux=$3
    local redis=$4
    LABEL="$label" EMBEDDED_JSON="$embedded" LUX_JSON="$lux" REDIS_JSON="$redis" python3 - <<'PYVALIDATE'
import json
import math
import os
import re
import sys

label = os.environ["LABEL"]
raw = {
    "Embedded Lux": os.environ["EMBEDDED_JSON"],
    "Lux RESP": os.environ["LUX_JSON"],
    "Redis RESP": os.environ["REDIS_JSON"],
}

def parse(name, text):
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"{name} produced invalid JSON for {label}: {text!r}: {exc}", file=sys.stderr)
        sys.exit(1)

def numeric(value):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None

def rounded_number(value, places=3):
    n = numeric(value)
    if n is None or not math.isfinite(n):
        return value
    return round(n, places)

def normalize_geo(value):
    if isinstance(value, list):
        return [normalize_geo(item) for item in value]
    return rounded_number(value, 3)

def normalize_hgetall(value):
    if isinstance(value, dict):
        return sorted(
            [[key, item] for key, item in value.items()],
            key=lambda item: json.dumps(item, sort_keys=True),
        )
    if not isinstance(value, list):
        return value
    pairs = []
    for idx in range(0, len(value), 2):
        pairs.append(value[idx:idx + 2])
    return sorted(pairs, key=lambda item: json.dumps(item, sort_keys=True))

def normalize_unordered(value):
    if not isinstance(value, list):
        return value
    return sorted(value, key=lambda item: json.dumps(item, sort_keys=True))

def normalize_slot(value, slot):
    if slot == 0 and label == "XADD":
        if isinstance(value, str) and re.match(r"^[0-9]+-[0-9]+$", value):
            return "<stream-id>"
        return value
    if slot == 0 and label in {"SPOP", "SRANDMEMBER"}:
        return "<bulk>" if isinstance(value, str) and value else value
    if label in {"TTL", "PTTL"} and slot == 0:
        n = numeric(value)
        return "<positive-int>" if n is not None and n > 0 else value
    if label in {"EXPIRE"} and slot == 1:
        n = numeric(value)
        return "<positive-int>" if n is not None and n > 0 else value
    if label in {"GEOPOS", "GEODIST"}:
        return normalize_geo(value)
    if label == "ZINCRBY":
        return rounded_number(value, 3)
    if label in {"ZPOPMIN", "ZPOPMAX"}:
        return normalize_geo(value)
    if label.startswith("GEOSEARCH") and isinstance(value, list):
        return normalize_unordered(value)
    if slot == 0 and label in {"SMEMBERS", "SUNION", "SINTER", "SDIFF"}:
        return normalize_unordered(value)
    if slot == 0 and label == "HGETALL":
        return normalize_hgetall(value)
    return value

def normalize(reply):
    if not isinstance(reply, list):
        print(f"{label} validation reply must be a JSON array, got {reply!r}", file=sys.stderr)
        sys.exit(1)
    return [normalize_slot(value, idx) for idx, value in enumerate(reply)]

values = {name: normalize(parse(name, text)) for name, text in raw.items()}
expected = values["Redis RESP"]
for name, value in values.items():
    if value != expected:
        print(f"Validation failed for {label}", file=sys.stderr)
        for item_name, item_value in values.items():
            print(f"  {item_name}: {json.dumps(item_value, sort_keys=True)}", file=sys.stderr)
        sys.exit(1)
PYVALIDATE
}

run_embedded_command_best() {
    local cmdline=$1
    local best=0
    local i=0
    while [ "$i" -lt "$EMBEDDED_TRIALS" ]; do
        local rps
        rps=$(run_embedded_command "$cmdline")
        best=$(awk "BEGIN { a=$best+0; b=$rps+0; print (b>a)?b:a }")
        i=$((i + 1))
    done
    printf "%.2f\n" "$best"
}

run_embedded_suite() {
    for i in "${!COMMANDS[@]}"; do
        local item=${COMMANDS[$i]}
        IFS='|' read -r label cmdline <<< "$item"
        cmdline=$(resolve_cmdline "$cmdline")
        echo -e "  ${label}" >&2
        local rps
        rps=$(run_embedded_command_best "$cmdline")
        echo -e "    ${label}: $(fmt_rps "$rps")" >&2
        echo "$rps"
    done
}

run_resp_suite() {
    local port=$1
    for i in "${!COMMANDS[@]}"; do
        local item=${COMMANDS[$i]}
        IFS='|' read -r label cmdline <<< "$item"
        cmdline=$(resolve_cmdline "$cmdline")
        echo -e "  ${label}" >&2
        local rps
        if ! rps=$(run_resp_command "$port" "$label" "$cmdline"); then
            return 1
        fi
        echo -e "    ${label}: $(fmt_rps "$rps")" >&2
        echo "$rps"
    done
}

run_embedded_suite_to_file() {
    local out=$1
    run_embedded_suite >"$out"
}

run_lux_suite_to_file() {
    local port=$1
    local out=$2
    local tmpdir
    local pid
    local status=0

    kill_port "$port"
    tmpdir=$(mktemp -d)
    LUX_PORT=$port LUX_SAVE_INTERVAL=0 LUX_DATA_DIR="$tmpdir" "$LUX_BIN" >/dev/null 2>&1 &
    pid=$!
    if wait_for_port "$port" "Lux"; then
        run_resp_suite "$port" >"$out" || status=$?
    else
        status=$?
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$tmpdir"
    return "$status"
}

run_redis_suite_to_file() {
    local port=$1
    local out=$2
    local pid
    local status=0

    kill_port "$port"
    "$REDIS_SERVER" --port "$port" --save "" --appendonly no --daemonize no --loglevel warning >/dev/null 2>&1 &
    pid=$!
    if wait_for_port "$port" "Redis"; then
        run_resp_suite "$port" >"$out" || status=$?
    else
        status=$?
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return "$status"
}

load_results() {
    local suite_name=$1
    local raw=$2
    local results_name=$3
    local expected=${#COMMANDS[@]}
    local count=0

    eval "$results_name=()"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        if ! [[ "$line" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            echo -e "${RED}${suite_name} produced a non-numeric result: ${line}${NC}" >&2
            exit 1
        fi
        eval "$results_name+=(\"\$line\")"
        count=$((count + 1))
    done <<< "$raw"

    if [ "$count" -ne "$expected" ]; then
        echo -e "${RED}${suite_name} produced ${count} result(s), expected ${expected}.${NC}" >&2
        exit 1
    fi
}

assert_loaded_results() {
    local suite_name=$1
    local results_name=$2
    local actual
    local expected=${#COMMANDS[@]}

    eval "actual=\${#$results_name[@]}"
    if [ "$actual" -ne "$expected" ]; then
        echo -e "${RED}${suite_name} loaded ${actual} result(s), expected ${expected}.${NC}" >&2
        echo -e "${RED}The benchmark output is incomplete; refusing to render a misleading table.${NC}" >&2
        exit 1
    fi
}

echo -e "${BOLD}=== Lux Full Command Table Benchmark ===${NC}" >&2
echo "    lux:                  v${LUX_VER}" >&2
echo "    redis-server:         $("$REDIS_SERVER" --version 2>&1 | head -1)" >&2
echo "    redis-benchmark:      $("$REDIS_BENCH" --version 2>&1 | head -1)" >&2
echo "    requests:             $REQUESTS" >&2
echo "    clients:              $CLIENTS" >&2
echo "    pipeline:             $PIPELINE" >&2
echo "    seed items:           $SEED_ITEMS" >&2
echo "    geo members:          $GEO_MEMBERS" >&2
echo "    keyspace:             $KEYSPACE" >&2
echo "    embedded discard:     $EMBEDDED_DISCARD_WRITES" >&2
echo "    embedded trials:      $EMBEDDED_TRIALS" >&2
echo "    spot checks:          $BENCH_VALIDATE" >&2
echo "    validate only:        $BENCH_VALIDATE_ONLY" >&2
echo "    key prefix:           $BENCH_KEY_PREFIX" >&2
echo "    geo key:              $BENCH_GEO_KEY" >&2
echo "    duration seconds:     $BENCH_DURATION_SECONDS" >&2
echo "" >&2

TMP_RESULTS_DIR=$(mktemp -d)
EMBEDDED_OUT="$TMP_RESULTS_DIR/embedded.out"
LUX_OUT="$TMP_RESULTS_DIR/lux.out"
REDIS_OUT="$TMP_RESULTS_DIR/redis.out"
LUX_BENCH_PORT=$BENCH_PORT
REDIS_BENCH_PORT=$((BENCH_PORT + 1))

echo -e "${BOLD}Benchmarking Lux Embedded...${NC}" >&2
run_embedded_suite_to_file "$EMBEDDED_OUT"

echo -e "${BOLD}Benchmarking Lux RESP...${NC}" >&2
run_lux_suite_to_file "$LUX_BENCH_PORT" "$LUX_OUT"

echo -e "${BOLD}Benchmarking Redis RESP...${NC}" >&2
run_redis_suite_to_file "$REDIS_BENCH_PORT" "$REDIS_OUT"

EMBEDDED_RAW=$(cat "$EMBEDDED_OUT")
EMBEDDED_RESULTS=()
load_results "Embedded Lux" "$EMBEDDED_RAW" EMBEDDED_RESULTS

LUX_RAW=$(cat "$LUX_OUT")
LUX_RESULTS=()
load_results "Lux RESP" "$LUX_RAW" LUX_RESULTS

REDIS_RAW=$(cat "$REDIS_OUT")
REDIS_RESULTS=()
load_results "Redis RESP" "$REDIS_RAW" REDIS_RESULTS

assert_loaded_results "Lux Embedded" EMBEDDED_RESULTS
assert_loaded_results "Lux RESP" LUX_RESULTS
assert_loaded_results "Redis RESP" REDIS_RESULTS

echo "| Command | Lux Embedded | Lux RESP | Redis RESP ${REDIS_VER} | Embedded/Lux | Lux/Redis |"
echo "|---------|-------------:|---------:|-------------------:|-------------:|----------:|"
for i in "${!COMMANDS[@]}"; do
    IFS='|' read -r label _ <<< "${COMMANDS[$i]}"
    embedded=${EMBEDDED_RESULTS[$i]:-}
    lux=${LUX_RESULTS[$i]:-}
    redis=${REDIS_RESULTS[$i]:-}
    if [ -z "$embedded" ] || [ -z "$lux" ] || [ -z "$redis" ]; then
        echo -e "${RED}Missing benchmark result for ${label}; refusing to render a partial row.${NC}" >&2
        exit 1
    fi
    printf "| %s | %s | %s | %s | **%s** | **%s** |\n" \
        "$label" \
        "$(fmt_rps "$embedded")" \
        "$(fmt_rps "$lux")" \
        "$(fmt_rps "$redis")" \
        "$(ratio_rps "$embedded" "$lux")" \
        "$(ratio_rps "$lux" "$redis")"
done

echo -e "${GREEN}Done.${NC}" >&2
