#!/bin/bash
set -euo pipefail

# -----------------------------------------------------------------------------
# cmd-compare.sh
#
# Purpose
# - Convenience wrapper for running the RESP benchmark comparison runner:
#     target/release/examples/resp_bench
# - Builds `lux` + `resp_bench` in release mode by default, then executes the
#   benchmark runner.
#
# How it works
# 1) Resolve repo root (`SCRIPT_DIR`) from this script location.
# 2) Compute runner path:
#      $SCRIPT_DIR/target/release/examples/resp_bench
# 3) If BENCH_SKIP_BUILD != 1:
#      cargo build --release --bin lux --example resp_bench
# 4) If BENCH_SKIP_BUILD == 1:
#      require an already-built executable at the runner path.
# 5) `exec` the runner with any CLI args passed to this script.
#
# Environment variables
# - BENCH_SKIP_BUILD
#   - `0` (default): build before running.
#   - `1`: skip build; fail if runner binary does not exist.
#
# The following are consumed by `resp_bench` (passed through environment):
# - BENCH_TARGETS
#   - Comma-separated benchmark targets.
#   - Common values: `embedded,lux,redis` or `embedded,lux,main`.
# - BENCH_DURATION_SECONDS
#   - Per-command benchmark duration in seconds.
# - BENCH_CLIENTS
#   - Parallel client count for RESP targets.
#
# CLI arguments
# - Any args provided to this script are forwarded directly to `resp_bench`.
# - Run `target/release/examples/resp_bench --help` (or pass `--help` here) to
#   see supported flags in your current build.
#
# Examples
# - Default run (build + run with defaults):
#     ./benches/cmd-compare.sh
#
# - 1 second runs for embedded/lux/redis:
#     BENCH_DURATION_SECONDS=1 BENCH_TARGETS=embedded,lux,redis \
#       ./benches/cmd-compare.sh
#
# - 3 second runs with 16 RESP clients:
#     BENCH_DURATION_SECONDS=3 BENCH_CLIENTS=16 \
#     BENCH_TARGETS=embedded,lux,redis ./benches/cmd-compare.sh
#
# - Skip rebuild (requires existing release benchmark binary):
#     BENCH_SKIP_BUILD=1 BENCH_DURATION_SECONDS=3 \
#       ./benches/cmd-compare.sh
#
# BENCH_LOOPS=3 BENCH_DURATION_SECONDS=2 BENCH_CLIENTS=32 BENCH_PIPELINE=16 \
#  BENCH_RESP_OUTSTANDING_PIPELINES=1 BENCH_TARGETS=embedded,lux,main,redis ./benches/cmd-compare.sh
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNNER="$SCRIPT_DIR/target/release/examples/resp_bench"

if [ "${BENCH_SKIP_BUILD:-0}" != "1" ]; then
    (cd "$SCRIPT_DIR" && cargo build --release --bin lux --example resp_bench)
elif [ ! -x "$RUNNER" ]; then
    echo "missing benchmark runner: $RUNNER" >&2
    echo "run without BENCH_SKIP_BUILD=1 to build it" >&2
    exit 1
fi

exec "$RUNNER" "$@"
