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

Automatic CLI upgrade tests use Node.js 22 or newer, Docker, a built CLI, and
preloaded old/candidate engine images. No registry push is performed:

```bash
node cli/tests/upgrade.mjs ./cli/target/debug/lux OLD_IMAGE CANDIDATE_IMAGE
```

Set `AUTO_TEST_MODE` to `snapshot-failure`, `stopped-snapshot-failure`,
`probe-failure`, `import-failure`, `verification-write`, `stopped`, `prepare-interruption`, or
`cutover-interruption` to exercise the corresponding failure boundary. The
default verifies a running upgrade with concurrent writes and an existing auth
session. Registry lookups use the preloaded images; container, volume, network,
snapshot, and recovery operations are real. Fixtures and their volume names are
retained under `.scratch/` for inspection.

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
