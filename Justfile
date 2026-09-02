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

# Run the pinned Valkey differential and third-party client compatibility gate.
client-compat:
    bash tests/client-compat/run.sh

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
