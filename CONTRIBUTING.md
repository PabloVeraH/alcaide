# Contributing to Alcaide

Thanks for helping. Security vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues.

## Development

Requires Rust 1.89 or newer (the workspace's `rust-version`).

```sh
cargo test --workspace                                # unit, integration, corpus and property tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Python bindings (in `alcaide-py/`):

```sh
python -m venv .venv && source .venv/bin/activate
pip install maturin pytest && pip install .
pytest tests/
```

Changes to normalization, matching or rule loading should also survive a few minutes of fuzzing (nightly, Linux/macOS): see [fuzz/README.md](fuzz/README.md).

CI compares `alcaide-core`'s public API with its latest release on crates.io ([cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)). A breaking change, such as removing or renaming a public item, fails the check until the same pull request bumps the workspace version to the next minor (0.2.x to 0.3.0) and notes it in the CHANGELOG.

Every behavior change comes with a test that fails without it. For an evasion or a false positive, that means a regression test next to the code, and an entry in the labeled corpus below.

## Contributing rules

Rules live in [`alcaide-core/rules/default.yaml`](alcaide-core/rules/default.yaml). Each one must:

- **cite a public, verifiable source** for the attack it targets in its `notes`;
- come with **at least one malicious and one benign entry** in [`alcaide-core/tests/corpus/prompts.yaml`](alcaide-core/tests/corpus/prompts.yaml). The benign entry is a near miss that shows where the rule stops matching;
- document any known false positive in its `notes` instead of hiding it.

Write word boundaries as `(?-u:\b)`, not `\b`: a Unicode word boundary makes the regex engine fall back to a much slower path on non-ASCII text.

Matching is case-insensitive and runs on normalized text (whitespace collapsed, invisible characters removed, look-alike letters folded to Latin), plus decoded base64/hex and a deobfuscated copy (escapes decoded, emoji inside words removed, spaced-out letters joined, typos of attack words corrected), so a rule doesn't need to handle those variations itself. Typo correction only knows the words in `ATTACK_WORDS` (`alcaide-core/src/normalize.rs`): a rule built on a new word should add it there, with its inflections. `alcaide lint-rules <file>` validates a rule file without evaluating anything.

After changing rules or the corpus, re-run `alcaide bench` and update [BENCHMARKS.md](BENCHMARKS.md) with the new numbers, including the public datasets (`python benchmarks/fetch_public.py`). Their train splits may inform a rule; never read their test splits while writing one, or the held-out numbers stop meaning anything.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) (`fix: ...`, `feat: ...`, `docs: ...`), one logical change per commit, and add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for anything user-visible.
