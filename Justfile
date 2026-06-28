#!/usr/bin/env just --justfile
# https://github.com/casey/just

export RUST_BACKTRACE := "1"

# List all available commands.
default:
    just --list

# Remove build artifacts.
clean:
    cargo clean

# Build in debug mode.
build:
    cargo build

# Build an optimised release binary.
release:
    cargo build --release

# Format and lint.
dev:
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

# Run lux (debug build).
run *ARGS:
    cargo run -- {{ARGS}}

# Run lux (release build).
run-release *ARGS:
    cargo run --release -- {{ARGS}}

# Generate docs.
doc:
    cargo doc --all-features --no-deps

# Run CI checks (fmt, clippy, tests).
check:
    cargo fmt -- --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-targets

# Run tests.
test:
    cargo test --all-targets

# Run selected Valkey Tcl compatibility suites against a running Lux RESP port.
# Example: LUX_PORT=6379 VALKEY_DIR=/tmp/valkey just valkey-compat
valkey-compat:
    #!/usr/bin/env sh
    set -eu
    cd "${VALKEY_DIR:-/tmp/valkey}"
    ./runtest \
        --host "${LUX_HOST:-127.0.0.1}" --port "${LUX_PORT:-6379}" \
        --timeout "${VALKEY_TIMEOUT:-60}" \
        --singledb --no-latency --ignore-encoding --durable \
        --skiptest '/.*replica.*' \
        --skiptest '/.*replication.*' \
        --skiptest '/.*propagate.*' \
        --skiptest '/.*Expiration time is expired.*' \
        --single unit/type/string --single unit/keyspace \
        --single unit/type/list --single unit/type/hash --single unit/type/set \
        --single unit/type/zset --single unit/type/stream \
        --single unit/scripting --single unit/multi

# Automatically fix lint issues.
fix:
    cargo fix --allow-staged --all-targets --all-features
    cargo clippy --fix --allow-staged --all-targets --all-features
    cargo fmt

# Upgrade Rust toolchain and dependencies.
upgrade:
    rustup upgrade
    cargo install cargo-edit
    cargo upgrade
