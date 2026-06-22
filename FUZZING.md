# Fuzzing

Lux fuzzes every decoder that turns untrusted bytes into structured data. The
contract for all of them is the same: **any input returns cleanly (Ok or Err)
and never panics, OOMs, aborts, or hangs.**

Covered decoders:

- Binary snapshot loader (`lux.dat`)
- RESP request parser
- Command dispatch / lowering
- TSELECT query + WHERE parser
- Lua MessagePack (`cmsgpack.unpack`)
- WAL replay + on-disk entry reader (`src/disk.rs`)

There are two layers, sharing the same targets.

## Layer 1 — in-crate proptest (runs in CI, stable Rust)

Property tests feed random bytes to each decoder and assert no panic. They run
as ordinary unit tests on every push:

```sh
cargo test --release fuzz_
```

These are the `fuzz_*_no_panic` tests in `snapshot.rs`, `resp.rs`, `cmd/mod.rs`,
`tables/mod.rs`, `lua.rs`, and `disk.rs`. Regressions for specific bugs the
fuzzer has found live next to them (e.g. `malformed_snapshot_large_count_does_not_oom`,
`msgpack_map_with_nil_key_does_not_abort`).

## Layer 2 — coverage-guided cargo-fuzz (deeper, out-of-band)

libfuzzer targets in `fuzz/fuzz_targets/` drive the same decoders via the
`fuzz_api` module (compiled only under `--features fuzzing`). Coverage-guided
mutation finds bugs random testing can't (it learns which bytes reach new code).

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

`fuzz/corpus/<target>/` holds seed inputs: valid samples plus every malformed
input a fuzzer has previously crashed on (e.g. `regression_oom_hash_count`,
`regression_oom_stream_groups`). Keep these checked in so the seeds, and the
fixed-bug coverage, persist. `fuzz/artifacts/` and `fuzz/target/` are not
committed.

## Bugs found so far

- snapshot: a claimed collection count drove `Vec::with_capacity`/`reserve` into
  multi-GB allocations on a few bytes of input (hash pairs, stream groups) —
  pre-allocation is now bounded.
- msgpack: a map with a nil/NaN key was forwarded to Lua as `table[nil]=v`,
  aborting the process; invalid keys are skipped. Unbounded decode recursion
  could stack-overflow; nesting depth is capped.
