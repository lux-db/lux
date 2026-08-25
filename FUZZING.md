# Fuzzing

Lux fuzzes the untrusted-byte decoders listed below. A panic, abort, excessive
allocation, or hang found by these targets is a bug. Fuzzing explores this
failure surface; a bounded run does not prove that every possible input is
safe.

Covered decoders:

- Binary snapshot loader (`lux.dat`)
- RESP request parser
- Command dispatch / lowering
- TSELECT query + WHERE parser
- Lua MessagePack (`cmsgpack.unpack`)
- WAL replay + on-disk entry reader (`src/disk.rs`)

There are two complementary layers.

## Layer 1 — in-crate proptest (runs in CI, stable Rust)

Property tests feed random bytes to the decoders and assert that the tested
inputs do not panic. They run as ordinary unit tests in the main CI suite:

```sh
cargo test --release fuzz_
```

These are the `fuzz_*_no_panic` tests in `snapshot.rs`, `resp.rs`, `cmd/mod.rs`,
`tables/mod.rs`, `lua.rs`, and `disk.rs`. Regressions for specific bugs the
fuzzer has found live next to them (e.g. `malformed_snapshot_large_count_does_not_oom`,
`msgpack_map_with_nil_key_does_not_abort`).

## Layer 2 — coverage-guided cargo-fuzz (deeper, out-of-band)

libFuzzer targets in `fuzz/fuzz_targets/` drive snapshot, RESP, command,
table-query, and MessagePack decoding via the `fuzz_api` module (compiled only
under `--features fuzzing`). Disk and WAL decoding currently have in-crate
property tests but no cargo-fuzz target. Coverage-guided mutation uses execution
feedback to explore paths that random generation may miss.

Requires the nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run a target (builds with sanitizers the first time):

```sh
cargo +nightly fuzz run snapshot         # or: resp, command, table_query, msgpack
cargo +nightly fuzz run snapshot -- -max_total_time=60   # time-boxed
```

A crash writes the triggering input to `fuzz/artifacts/<target>/`; reproduce it
with `cargo +nightly fuzz run <target> <artifact-path>`.

## Corpus

`fuzz/corpus/<target>/` holds a small, curated set of readable valid and
malformed seeds. Named regression inputs such as `regression_oom_hash_count`
and `regression_oom_stream_groups` preserve fixed-bug coverage. libFuzzer's
hash-named working corpus, `fuzz/artifacts/`, and `fuzz/target/` are generated
locally and are not committed.

## Bugs found so far

- snapshot: a claimed collection count drove `Vec::with_capacity`/`reserve` into
  multi-GB allocations on a few bytes of input (hash pairs, stream groups) —
  pre-allocation is now bounded.
- msgpack: a map with a nil/NaN key was forwarded to Lua as `table[nil]=v`,
  aborting the process; invalid keys are skipped. Unbounded decode recursion
  could stack-overflow; nesting depth is capped.
