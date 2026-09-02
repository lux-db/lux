#!/bin/bash
set -e
ulimit -n 65536 2>/dev/null || true

PORT=6399
HOST=127.0.0.1
LUX_BIN="./target/release/lux"
STORAGE_DIR="/tmp/lux-tiered-bench"
MAXMEMORY="50mb"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cleanup() { lsof -i :$PORT -t 2>/dev/null | xargs kill -9 2>/dev/null || true; sleep 1; }
now_ms() { date +%s%3N; }
section() { echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}"; }
result() { echo -e "  ${GREEN}$1${NC}"; }
warn() { echo -e "  ${YELLOW}$1${NC}"; }

start_server() {
    cleanup
    LUX_MAXMEMORY=$MAXMEMORY LUX_MAXMEMORY_POLICY=allkeys-lru \
    LUX_STORAGE_MODE=tiered LUX_STORAGE_DIR="$STORAGE_DIR/storage" \
    LUX_DATA_DIR="$STORAGE_DIR" LUX_PORT=$PORT LUX_SAVE_INTERVAL=60 \
    $LUX_BIN &
    sleep 2
    redis-cli -h $HOST -p $PORT PING > /dev/null 2>&1 || { echo "Server failed"; exit 1; }
}

gen_resp_set() {
    local count="$1" valsize="$2"
    local val=$(head -c $valsize /dev/urandom | base64 | head -c $valsize)
    for i in $(seq 1 $count); do
        local key="str:${i}"
        printf "*3\r\n\$3\r\nSET\r\n\$%d\r\n%s\r\n\$%d\r\n%s\r\n" ${#key} "$key" ${#val} "$val"
    done
}

gen_resp_hset() {
    local count="$1"
    for i in $(seq 1 $count); do
        local key="hash:${i}"
        local v1="val1-$i" v2="val2-$i" v3="val3-$i" v4="val4-$i" v5="val5-$i"
        printf "*12\r\n\$4\r\nHSET\r\n\$%d\r\n%s\r\n" ${#key} "$key"
        printf "\$2\r\nf1\r\n\$%d\r\n%s\r\n" ${#v1} "$v1"
        printf "\$2\r\nf2\r\n\$%d\r\n%s\r\n" ${#v2} "$v2"
        printf "\$2\r\nf3\r\n\$%d\r\n%s\r\n" ${#v3} "$v3"
        printf "\$2\r\nf4\r\n\$%d\r\n%s\r\n" ${#v4} "$v4"
        printf "\$2\r\nf5\r\n\$%d\r\n%s\r\n" ${#v5} "$v5"
    done
}

echo -e "${BOLD}Lux Tiered Storage Benchmark${NC}"
echo "Memory limit: $MAXMEMORY"

section "Starting server"
rm -rf "$STORAGE_DIR" && mkdir -p "$STORAGE_DIR"
start_server
result "Server running"

section "Phase 1: Load 50K strings (512B values)"
START=$(now_ms)
gen_resp_set 50000 512 | redis-cli -h $HOST -p $PORT --pipe 2>&1 | grep -o 'replies: [0-9]*'
END=$(now_ms)
result "Time: $(( (END - START) / 1000 ))s"

section "Phase 2: Load 10K hashes (5 fields each)"
START=$(now_ms)
gen_resp_hset 10000 | redis-cli -h $HOST -p $PORT --pipe 2>&1 | grep -o 'replies: [0-9]*'
END=$(now_ms)
result "Time: $(( (END - START) / 1000 ))s"

section "Phase 3: Create table + 10K rows"
redis-cli -h $HOST -p $PORT TCREATE users name:str email:str age:int score:float > /dev/null 2>&1 || true
START=$(now_ms)
for i in $(seq 1 10000); do
    redis-cli -h $HOST -p $PORT TINSERT users name "user-$i" email "u${i}@t.co" age $((20 + i % 50)) score "$((i % 100)).$((i % 10))" > /dev/null 2>&1
done
END=$(now_ms)
result "Time: $(( (END - START) / 1000 ))s"

MEM=$(redis-cli -h $HOST -p $PORT INFO memory 2>/dev/null | grep used_memory_bytes | tr -d '\r' | cut -d: -f2)
DISK=$(du -sb "$STORAGE_DIR/storage/" 2>/dev/null | cut -f1 || echo 0)
DBSIZE=$(redis-cli -h $HOST -p $PORT DBSIZE 2>/dev/null | tr -d '\r')

section "Data loaded"
result "DBSIZE: $DBSIZE"
result "Memory: $(( ${MEM:-0} / 1024 / 1024 ))MB / $MAXMEMORY"
result "Disk: $(( ${DISK:-0} / 1024 / 1024 ))MB"

section "Phase 4: Read throughput (mixed hot + cold)"
echo "  GET random keys across full keyspace (some hot, some cold):"
redis-benchmark -h $HOST -p $PORT -n 50000 -c 50 -q -r 50000 GET "str:__rand_int__" 2>&1 | grep 'requests per second' | while read line; do result "GET: $line"; done
redis-benchmark -h $HOST -p $PORT -n 20000 -c 50 -q -r 10000 HGETALL "hash:__rand_int__" 2>&1 | grep 'requests per second' | while read line; do result "HGETALL: $line"; done
redis-benchmark -h $HOST -p $PORT -n 20000 -c 50 -q -r 50000 EXISTS "str:__rand_int__" 2>&1 | grep 'requests per second' | while read line; do result "EXISTS: $line"; done
redis-benchmark -h $HOST -p $PORT -n 10000 -c 50 -q DBSIZE 2>&1 | grep 'requests per second' | while read line; do result "DBSIZE: $line"; done

section "Phase 5: Cold read latency (oldest keys, guaranteed cold)"
START=$(now_ms)
COLD_OK=0
for i in $(seq 1 500); do
    VAL=$(redis-cli -h $HOST -p $PORT GET "str:$i" 2>/dev/null)
    if [ -n "$VAL" ]; then COLD_OK=$((COLD_OK + 1)); fi
done
END=$(now_ms)
ELAPSED=$(( END - START ))
result "500 cold GETs: ${ELAPSED}ms (avg $(( ELAPSED / 500 ))ms/op, $COLD_OK/500 returned data)"

section "Phase 6: Table queries"
START=$(now_ms)
for i in $(seq 1 50); do
    redis-cli -h $HOST -p $PORT TSELECT "*" FROM users WHERE age \> 40 LIMIT 10 > /dev/null 2>&1
done
END=$(now_ms)
result "50x TQUERY (WHERE age > 40 LIMIT 10): $(( END - START ))ms total, $(( (END - START) / 50 ))ms avg"

START=$(now_ms)
for i in $(seq 1 50); do
    redis-cli -h $HOST -p $PORT TSELECT "*" FROM users WHERE name = "user-$((RANDOM % 10000 + 1))" LIMIT 1 > /dev/null 2>&1
done
END=$(now_ms)
result "50x TQUERY (WHERE name = random LIMIT 1): $(( END - START ))ms total, $(( (END - START) / 50 ))ms avg"

section "Phase 7: Data integrity"
echo "  Verifying random samples across all types..."
FAIL=0
for i in 1 100 500 5000 25000 50000; do
    VAL=$(redis-cli -h $HOST -p $PORT GET "str:$i" 2>/dev/null)
    if [ -z "$VAL" ]; then warn "str:$i MISSING"; FAIL=$((FAIL+1)); else echo -e "  str:$i ${GREEN}OK${NC}"; fi
done
for i in 1 500 5000 10000; do
    F=$(redis-cli -h $HOST -p $PORT HGETALL "hash:$i" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$F" -eq 10 ]; then echo -e "  hash:$i ${GREEN}OK${NC} (10 fields)"; else warn "hash:$i FAIL ($F fields)"; FAIL=$((FAIL+1)); fi
done
result "Failures: $FAIL"

section "Phase 8: Crash recovery"
echo "  Triggering BGSAVE..."
redis-cli -h $HOST -p $PORT BGSAVE > /dev/null 2>&1
sleep 3
PRE_DBSIZE=$(redis-cli -h $HOST -p $PORT DBSIZE 2>/dev/null | tr -d '\r')
result "Pre-crash DBSIZE: $PRE_DBSIZE"
echo "  Writing 100 keys AFTER snapshot (these rely on WAL)..."
for i in $(seq 1 100); do
    redis-cli -h $HOST -p $PORT SET "post-snap:$i" "wal-test-$i" > /dev/null
done
echo "  Killing (SIGKILL)..."
lsof -i :$PORT -t | xargs kill -9 2>/dev/null
sleep 2

echo "  Restarting..."
START=$(now_ms)
start_server
END=$(now_ms)
result "Restart time: $(( END - START ))ms"

POST_DBSIZE=$(redis-cli -h $HOST -p $PORT DBSIZE 2>/dev/null | tr -d '\r')
result "Post-crash DBSIZE: $POST_DBSIZE"

echo "  Checking post-snapshot WAL keys..."
WAL_OK=0
for i in $(seq 1 100); do
    V=$(redis-cli -h $HOST -p $PORT GET "post-snap:$i" 2>/dev/null)
    if [ "$V" = "wal-test-$i" ]; then WAL_OK=$((WAL_OK+1)); fi
done
result "WAL-recovered keys: $WAL_OK/100"

echo "  Checking pre-existing data..."
RECOVER_FAIL=0
for i in 1 1000 10000; do
    F=$(redis-cli -h $HOST -p $PORT HGETALL "hash:$i" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$F" -ne 10 ]; then warn "hash:$i FAIL ($F fields)"; RECOVER_FAIL=$((RECOVER_FAIL+1)); fi
done
for i in 1 5000 25000; do
    V=$(redis-cli -h $HOST -p $PORT GET "str:$i" 2>/dev/null)
    if [ -z "$V" ]; then warn "str:$i FAIL"; RECOVER_FAIL=$((RECOVER_FAIL+1)); fi
done
if [ $RECOVER_FAIL -eq 0 ]; then
    result "PASS: All recovery checks passed"
else
    warn "$RECOVER_FAIL recovery checks failed"
fi

section "Final"
MEM=$(redis-cli -h $HOST -p $PORT INFO memory 2>/dev/null | grep used_memory_bytes | tr -d '\r' | cut -d: -f2)
DISK=$(du -sb "$STORAGE_DIR/storage/" 2>/dev/null | cut -f1 || echo 0)
result "Memory: $(( ${MEM:-0} / 1024 / 1024 ))MB"
result "Disk: $(( ${DISK:-0} / 1024 / 1024 ))MB"
result "Keys: $(redis-cli -h $HOST -p $PORT DBSIZE 2>/dev/null | tr -d '\r')"

cleanup
rm -rf "$STORAGE_DIR"
echo -e "\n${BOLD}Done.${NC}"
