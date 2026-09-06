# Contributing to Lux

Thanks for your interest in contributing to Lux!

## Getting started

```bash
git clone https://github.com/lux-db/lux.git
cd lux
cargo build --release
```

Run the server:

```bash
cargo run --release
```

## Running tests

The pre-1.0 upgrade matrix uses real standalone binaries and Node.js 22 or
newer, without npm packages:

```bash
node tests/upgrade.mjs /path/to/lux-v0.37.0 /path/to/lux-candidate
```

Supply the published v0.37.0 binary for the host architecture; the test verifies
its release checksum before execution. It creates isolated loopback instances
and private fixtures under `.scratch/`, never an installed project. The JSON
report records both binary hashes, snapshot hashes, fixture location, and each
case's result. Fixtures are retained for inspection. The matrix checks snapshot
imports and backup-based rollback with Auth, encrypted values, core data types,
table indexes, migration history, queue consumer state, and cold tiered data.
It also checks expiry during downtime, row grants, reconnected live queries,
and repair after incomplete snapshot or encryption-state copies.
Rollback is checked without the old engine's memory-pressure eviction, whose
cold table scans are not a reliable logical-data oracle. This does not certify
in-place downgrade, every platform, or future release artifacts.

```bash
cargo test --all-targets
```

## Before you start

- **Open an issue first** for anything beyond small bug fixes. This saves everyone time if the approach needs discussion.
- Check the [open issues](https://github.com/lux-db/lux/issues) for things to work on. Issues labeled `good first issue` or `help wanted` are great starting points.

## Pull requests

- Keep PRs focused. One feature or fix per PR.
- Use [conventional commits](https://www.conventionalcommits.org/): `fix:`, `feat:`, `test:`, `docs:`, `refactor:`, `perf:`, `ci:`, `chore:`.
- Make sure `cargo clippy --all-targets --all-features -- -D warnings` passes.
- Make sure `cargo test` passes.
- Add tests for new commands when possible.

## Adding new Redis commands

1. Add the command handler under `src/cmd/`
2. Add the store operation under `src/store/`
3. Add snapshot serialization/deserialization in `src/snapshot.rs` if it involves a new data type
4. Update the command list in `README.md`

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Code of conduct

Be respectful. We're all here to build something useful.
