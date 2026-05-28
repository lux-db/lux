#!/bin/bash
set -euo pipefail

LUX_DIR="/Users/mattyhogan/Desktop/Lux/lux"
LUX_BIN="$LUX_DIR/target/release/lux"
REDIS_CLI="${XDG_CACHE_HOME:-$HOME/.cache}/lux-bench/redis-cli"
LUX_PORT=6395
LUX_HTTP=8095
PG_PORT=15433
PGRST_PORT=3001
ROWS=${BENCH_ROWS:-100000}
JOIN_ROWS=${JOIN_ROWS:-50000}
ITERS=20

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
LUX_TMPDIR=""; LUX_PID=""

cleanup() {
    [ -n "${LUX_PID:-}" ] && kill "$LUX_PID" 2>/dev/null || true
    [ -n "${LUX_TMPDIR:-}" ] && rm -rf "$LUX_TMPDIR"
    docker rm -f lux_bench_pg2 lux_bench_pgrst 2>/dev/null || true
    wait 2>/dev/null || true
} 2>/dev/null
trap cleanup EXIT

now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time()*1000'; }
fmt_rps() { awk "BEGIN{n=$1+0;if(n>=1e6)printf \"%.2fM/s\",n/1e6;else if(n>=1e3)printf \"%.1fK/s\",n/1e3;else printf \"%.0f/s\",n}"; }
ratio_ms() { awk "BEGIN{if($1==0){print \"N/A\";exit}x=$2/$1;if(x>=1)printf \"%.2fx faster\",x;else printf \"%.2fx slower\",1/x}"; }
ratio_rps() { awk "BEGIN{if($2==0){print \"N/A\";exit}x=$1/$2;if(x>=1)printf \"%.2fx faster\",x;else printf \"%.2fx slower\",1/x}"; }

# curl median: run ITERS times, return median ms
curl_bench() {
    local iters=$1 url=$2
    local all=()
    for i in $(seq 1 $iters); do
        ms=$(curl -s -o /dev/null -w "%{time_total}" "$url" | awk '{printf "%.1f",$1*1000}')
        all+=("$ms")
    done
    printf '%s\n' "${all[@]}" | sort -n | awk "NR==int($iters/2)+1"
}

# Build
[ ! -f "$LUX_BIN" ] && cargo build --release --manifest-path "$LUX_DIR/Cargo.toml"

# Start Postgres
echo -e "${YELLOW}Starting Postgres + PostgREST...${NC}"
docker rm -f lux_bench_pg2 lux_bench_pgrst 2>/dev/null || true
docker run -d --name lux_bench_pg2 \
    -e POSTGRES_USER=bench -e POSTGRES_PASSWORD=bench -e POSTGRES_DB=bench \
    -p "${PG_PORT}:5432" postgres:16-alpine \
    postgres -c fsync=off -c synchronous_commit=off -c full_page_writes=off \
             -c shared_buffers=256MB -c work_mem=64MB >/dev/null
for i in $(seq 1 60); do
    PGPASSWORD=bench psql -h 127.0.0.1 -p "$PG_PORT" -U bench -d bench \
        -c "SELECT 1" >/dev/null 2>&1 && break || sleep 0.5
done

PGPASSWORD=bench psql -h 127.0.0.1 -p "$PG_PORT" -U bench -d bench -q << 'SQL'
CREATE TABLE users(id BIGINT PRIMARY KEY, name TEXT, email TEXT UNIQUE NOT NULL, age INT, active BOOLEAN);
CREATE TABLE orders(id BIGINT PRIMARY KEY, user_id BIGINT, amount FLOAT, status TEXT);
CREATE ROLE anon NOLOGIN;
GRANT USAGE ON SCHEMA public TO anon;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
SQL

docker run -d --name lux_bench_pgrst --network host \
    -e PGRST_DB_URI="postgres://bench:bench@127.0.0.1:${PG_PORT}/bench" \
    -e PGRST_DB_SCHEMA=public -e PGRST_DB_ANON_ROLE=anon \
    -e PGRST_SERVER_PORT="$PGRST_PORT" \
    -e PGRST_DB_MAX_ROWS=1000000 \
    postgrest/postgrest:latest >/dev/null
for i in $(seq 1 30); do
    curl -s "http://127.0.0.1:${PGRST_PORT}/users?limit=1" >/dev/null 2>&1 && break || sleep 0.5
done

# Start Lux
LUX_TMPDIR=$(mktemp -d)
LUX_PORT=$LUX_PORT LUX_HTTP_PORT=$LUX_HTTP LUX_SAVE_INTERVAL=0 \
    LUX_DATA_DIR="$LUX_TMPDIR" "$LUX_BIN" >/dev/null 2>&1 &
LUX_PID=$!
for i in $(seq 1 60); do "$REDIS_CLI" -p "$LUX_PORT" PING >/dev/null 2>&1 && break || sleep 0.1; done

"$REDIS_CLI" -p "$LUX_PORT" TCREATE users \
    id INT PRIMARY KEY , name STR , email STR UNIQUE NOT NULL , age INT , active BOOL >/dev/null
"$REDIS_CLI" -p "$LUX_PORT" TCREATE orders \
    id INT PRIMARY KEY , user_id INT , amount FLOAT , status STR >/dev/null

echo ""
echo -e "${BOLD}=== HTTP/JSON Benchmark: Lux v0.11.3 vs PostgreSQL 16 + PostgREST ===${NC}"
echo "    ${ROWS} users + ${JOIN_ROWS} orders | both return JSON over HTTP | ${ITERS} iters median"
echo -e "${YELLOW}    Lux: in-memory | Postgres: ACID fsync=off${NC}"
echo ""

# 1. INSERT
echo -e "${BOLD}[1/5] INSERT ${ROWS} rows${NC}"
echo "  Lux (HTTP POST pipelined)..."
t0=$(now_ms)
python3 - << PYEOF
import socket
s=socket.socket(); s.connect(("127.0.0.1",$LUX_HTTP))
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.settimeout(60)
buf=b""
def do(body):
    global buf
    r=f"POST /v1/tables/users HTTP/1.1\r\nHost:localhost\r\nContent-Type:application/json\r\nContent-Length:{len(body)}\r\n\r\n{body}"
    s.sendall(r.encode())
    while b"\r\n\r\n" not in buf: buf+=s.recv(65536)
    h,rest=buf.split(b"\r\n\r\n",1)
    cl=next((int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")),0)
    while len(rest)<cl: rest+=s.recv(65536)
    buf=rest[cl:]
for i in range(1,$ROWS+1):
    do('{"id":"%d","name":"User_%d","email":"u%d@b.com","age":"%d","active":"%s"}'%(i,i,i,(i%60)+18,"true"if i%2==0 else"false"))
s.close()
PYEOF
t1=$(now_ms)
LUX_INS_MS=$((t1-t0)); LUX_INS_RPS=$(awk "BEGIN{printf \"%.0f\",$ROWS/($LUX_INS_MS/1000.0)}")

echo "  Postgres (HTTP POST pipelined)..."
t0=$(now_ms)
python3 - << PYEOF
import socket
s=socket.socket(); s.connect(("127.0.0.1",$PGRST_PORT))
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.settimeout(120)
buf=b""
def do(body, path="/users"):
    global buf
    r=f"POST /v1/tables/users HTTP/1.1\r\nHost:localhost\r\nContent-Type:application/json\r\nContent-Length:{len(body)}\r\n\r\n{body}"
    # PostgREST uses different path
    r2=f"POST {path} HTTP/1.1\r\nHost:localhost\r\nContent-Type:application/json\r\nPrefer:return=minimal\r\nContent-Length:{len(body)}\r\n\r\n{body}"
    s.sendall(r2.encode())
    while b"\r\n\r\n" not in buf: buf+=s.recv(65536)
    h,rest=buf.split(b"\r\n\r\n",1)
    cl=next((int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")),0)
    while len(rest)<cl: rest+=s.recv(65536)
    buf=rest[cl:]
for i in range(1,$ROWS+1):
    do('{"id":"%d","name":"User_%d","email":"u%d@b.com","age":"%d","active":"%s"}'%(i,i,i,(i%60)+18,"true"if i%2==0 else"false"))
s.close()
PYEOF
t1=$(now_ms)
PG_INS_MS=$((t1-t0)); PG_INS_RPS=$(awk "BEGIN{printf \"%.0f\",$ROWS/($PG_INS_MS/1000.0)}")

printf "  %-14s  %10s  %6dms\n" "Lux"         "$(fmt_rps $LUX_INS_RPS)" $LUX_INS_MS
printf "  %-14s  %10s  %6dms\n" "PG+PostgREST" "$(fmt_rps $PG_INS_RPS)"  $PG_INS_MS
echo "  $(ratio_rps $LUX_INS_RPS $PG_INS_RPS)"

# 2. Point lookup by ID
echo ""; echo -e "${BOLD}[2/7] Point lookup (WHERE id = 50000)${NC}"
LUX_POINT=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users?where=id+%3D+50000")
PG_POINT=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/users?id=eq.50000")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_POINT"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_POINT"
echo "  $(ratio_ms $LUX_POINT $PG_POINT)"

# 3. Filtered query with small result set
echo ""; echo -e "${BOLD}[3/7] WHERE age > 40 LIMIT 100${NC}"
LUX_FILTER=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users?where=age+>+40&limit=100")
PG_FILTER=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/users?age=gt.40&limit=100")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_FILTER"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_FILTER"
echo "  $(ratio_ms $LUX_FILTER $PG_FILTER)"

# 4. SELECT * (full scan - noted as pathological case)
echo ""; echo -e "${BOLD}[4/7] GET all users (${ROWS} rows - full scan, no limit)${NC}"
echo -e "${YELLOW}  Note: Lux stores rows as individual hashes (needed for row-level pub/sub).${NC}"
echo -e "${YELLOW}  Full scans require N hash lookups vs Postgres sequential scan.${NC}"
LUX_SCAN=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users")
PG_SCAN=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/users?limit=${ROWS}")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_SCAN"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_SCAN"
echo "  $(ratio_ms $LUX_SCAN $PG_SCAN)"

# 5. WHERE no limit (large result)
echo ""; echo -e "${BOLD}[5/7] WHERE age > 40 (no limit, ~61k rows)${NC}"
LUX_WHERE=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users?where=age+>+40")
PG_WHERE=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/users?age=gt.40&limit=${ROWS}")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_WHERE"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_WHERE"
echo "  $(ratio_ms $LUX_WHERE $PG_WHERE)"

# 6. COUNT
echo ""; echo -e "${BOLD}[6/7] COUNT (aggregate)${NC}"
LUX_COUNT=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users/count")
PG_COUNT=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/users?select=count")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_COUNT"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_COUNT"
echo "  $(ratio_ms $LUX_COUNT $PG_COUNT)"

# 5. JOIN
echo ""; echo -e "${BOLD}[7/7] JOIN + LIMIT 1000${NC}"
echo "  Seeding ${JOIN_ROWS} orders..."
python3 - << PYEOF
import socket
s=socket.socket(); s.connect(("127.0.0.1",$LUX_HTTP))
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.settimeout(60)
buf=b""
def do(body):
    global buf
    r=f"POST /v1/tables/orders HTTP/1.1\r\nHost:localhost\r\nContent-Type:application/json\r\nContent-Length:{len(body)}\r\n\r\n{body}"
    s.sendall(r.encode())
    while b"\r\n\r\n" not in buf: buf+=s.recv(65536)
    h,rest=buf.split(b"\r\n\r\n",1)
    cl=next((int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")),0)
    while len(rest)<cl: rest+=s.recv(65536)
    buf=rest[cl:]
for i in range(1,$JOIN_ROWS+1):
    uid=(i%$ROWS)+1; amt=round(10+(i%990)+0.99,2); st="active"if i%2==0 else"pending"
    do('{"id":"%d","user_id":"%d","amount":"%.2f","status":"%s"}'%(i,uid,amt,st))
s.close()
PYEOF
perl -e "print join(\"\\n\",map{my \$u=(\$_%$ROWS)+1;sprintf(\"%d\\t%d\\t%.2f\\t%s\",\$_,\$u,10+(\$_%990)+0.99,\$_%2==0?\"active\":\"pending\")} 1..$JOIN_ROWS)" \
    | PGPASSWORD=bench psql -h 127.0.0.1 -p "$PG_PORT" -U bench -d bench -q \
        -c "\COPY orders(id,user_id,amount,status) FROM STDIN"

LUX_JOIN=$(curl_bench $ITERS "http://127.0.0.1:${LUX_HTTP}/v1/tables/users?join=user_id&limit=1000")
PG_JOIN=$(curl_bench  $ITERS "http://127.0.0.1:${PGRST_PORT}/orders?select=amount,users(name)&limit=1000")
printf "  %-14s  %8sms\n" "Lux"          "$LUX_JOIN"
printf "  %-14s  %8sms\n" "PG+PostgREST" "$PG_JOIN"
echo "  $(ratio_ms $LUX_JOIN $PG_JOIN)"

# Summary
echo ""
echo -e "${BOLD}=== Summary: Lux vs PostgreSQL 16 + PostgREST (HTTP/JSON) ===${NC}"
echo -e "${YELLOW}Same wire format (JSON over HTTP). Median of ${ITERS} curl requests.${NC}"
echo -e "${YELLOW}Postgres: ACID, fsync=off. Lux: in-memory.${NC}"
echo ""
echo -e "${BOLD}| Benchmark                  |       Lux | PG+PostgREST | Result              |${NC}"
echo "|---------------------------|-----------|--------------|---------------------|"
printf "| INSERT rows/s             | %7s | %8s     | %-19s |\n" \
    "$(fmt_rps $LUX_INS_RPS)" "$(fmt_rps $PG_INS_RPS)" "$(ratio_rps $LUX_INS_RPS $PG_INS_RPS)"
printf "| Point lookup (1 row)      | %6sms  | %8sms    | %-19s |\n" \
    "$LUX_POINT" "$PG_POINT" "$(ratio_ms $LUX_POINT $PG_POINT)"
printf "| WHERE+LIMIT 100           | %6sms  | %8sms    | %-19s |\n" \
    "$LUX_FILTER" "$PG_FILTER" "$(ratio_ms $LUX_FILTER $PG_FILTER)"
printf "| COUNT(*)                  | %6sms  | %8sms    | %-19s |\n" \
    "$LUX_COUNT" "$PG_COUNT" "$(ratio_ms $LUX_COUNT $PG_COUNT)"
printf "| JOIN LIMIT 1000           | %6sms  | %8sms    | %-19s |\n" \
    "$LUX_JOIN" "$PG_JOIN" "$(ratio_ms $LUX_JOIN $PG_JOIN)"
printf "| Full scan (100k rows)     | %6sms  | %8sms    | %-19s |\n" \
    "$LUX_SCAN" "$PG_SCAN" "$(ratio_ms $LUX_SCAN $PG_SCAN)"
printf "| WHERE no limit (~61k rows)| %6sms  | %8sms    | %-19s |\n" \
    "$LUX_WHERE" "$PG_WHERE" "$(ratio_ms $LUX_WHERE $PG_WHERE)"
echo ""
echo -e "${YELLOW}  * Full scan and large WHERE are pathological for Lux's hash-per-row storage model${NC}"
echo -e "${YELLOW}    (required for row-level pub/sub). Use LUX_MAX_ROWS to prevent in production.${NC}"
echo ""
echo -e "${GREEN}Done.${NC}"
