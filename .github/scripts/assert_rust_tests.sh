#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 MINIMUM cargo test ..." >&2
  exit 2
fi

minimum="$1"
shift
listing="$("$@" -- --list --format terse)"
count="$(grep -Ec ': test$' <<<"$listing" || true)"

if (( count < minimum )); then
  echo "test discovery failed: found $count Rust tests; expected at least $minimum" >&2
  exit 1
fi

echo "Discovered $count Rust tests (minimum $minimum)."
