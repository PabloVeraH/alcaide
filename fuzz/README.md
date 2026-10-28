# Fuzzing

Coverage-guided fuzz targets for `alcaide-core`, built with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). They check invariants, not only crashes:

| Target | Input | Checks |
|---|---|---|
| `evaluate` | arbitrary text, default rules | never panics; every span slices the input; each rule reported once; the verdict matches the documented policy (severity threshold, oversize floor, shadow mode); deterministic. Also runs with a 48-byte limit so the oversize path is exercised. |
| `normalize` | arbitrary text + obfuscation choices | every normalized span maps to a valid input span; decoded blobs are valid; folding is idempotent; obfuscating ASCII text (invisible characters, look-alikes, fullwidth forms, tag characters, odd whitespace) leaves its normalized form unchanged. |
| `rules_yaml` | arbitrary YAML, then `\0`, then text | loading never panics or hangs; an accepted rule set upholds every `evaluate` guarantee. |
| `rule_patterns` | arbitrary rule sets built in code | building never panics; `evaluate` guarantees hold; an accepted literal pattern always matches its own text. |

A panic inside `Detector::evaluate` is normally caught and turned into the `on_error` verdict. Under libFuzzer the panic hook aborts first, so the fuzzer still reports it as a crash.

## Running

Requires nightly and Linux or macOS (libFuzzer doesn't support the `windows-gnu` toolchain; on Windows, use WSL or Docker).

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run normalize fuzz/corpus/normalize fuzz/seeds/normalize -- -dict=fuzz/dict/text.dict
```

`rules_yaml` takes no dictionary. CI (`.github/workflows/fuzz.yml`) runs every target for 2 minutes on each change to the engine, and for 30 minutes weekly, keeping the grown corpus between runs.

## When it finds something

The failing input lands in `fuzz/artifacts/<target>/` (in CI, in the run's `fuzz-artifacts-<target>` artifact). Replay it with `cargo +nightly fuzz run <target> <file>`, then add the input as a regression test next to the code it broke. For an evasion, also add an entry to the labeled corpus (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
