#!/usr/bin/env sh
set -eu

host="${1:?host required}"
port="${2:?port required}"
password="${3:?password required}"

redis() {
  redis-cli --no-auth-warning -h "$host" -p "$port" -a "$password" "$@"
}

[ "$(redis PING)" = "PONG" ]
[ "$(redis SET cli:key value)" = "OK" ]
[ "$(redis --raw GET cli:key)" = "value" ]
[ "$(printf '*3\r\n$3\r\nSET\r\n$8\r\ncli:pipe\r\n$1\r\n1\r\n*2\r\n$4\r\nINCR\r\n$8\r\ncli:pipe\r\n' | redis-cli --no-auth-warning -h "$host" -p "$port" -a "$password" --pipe | tail -1)" = "errors: 0, replies: 2" ]
printf 'client: %s\n' "$(redis-cli --version)"
