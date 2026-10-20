# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

### Security

- An input longer than `max_input_bytes` was flagged without being inspected, so padding any payload past the limit downgraded a `Block` to a `Flag`. Its prefix is now always inspected, and the new `on_oversize` setting (default `block`) sets the minimum verdict.
- Normalization now removes invisible characters (zero-width spaces, soft hyphens, bidi controls, variation selectors), reveals Unicode tag characters ("ASCII smuggling"), collapses whitespace runs, and folds uppercase Cyrillic, Greek and IPA look-alikes. Each of these used to bypass every rule.
- The base64 decoder now accepts unpadded and URL-safe base64, and payloads misaligned by junk glued in front of them.
- Regex rules are case-insensitive by default (opt out with `(?-i)`); literal rules are folded like the input and non-ASCII literals get Unicode case folding.
- When literal rules overlap, all of them are now reported, so a low-severity rule can no longer hide a high-severity one.
- Rule files reject unknown fields (`enabeld: false` used to be silently ignored), blank patterns, and patterns that match empty text (which matched every input).

### Added

- `Defaults::max_input_bytes` and `Defaults::on_oversize`, plus `Decision::input_truncated`.
- Default rules: verb synonyms for instruction overrides (disregard/forget/override, olvidar/omitir/hacer caso omiso) and markdown image exfiltration.
- Property tests for `Detector::evaluate`: it never panics, and every span slices the input.
- `SECURITY.md`, `CONTRIBUTING.md`, cargo-deny, Dependabot, and CI on Linux, Windows and macOS, plus the MSRV.

### Changed

- `MatchDetail::span` is now a byte range of the caller's original input. It used to point into internal normalized text.
- `Rule::pattern` is required for every pattern type, heuristics included.
- `Verdict` is ordered by strictness: `Allow < Flag < Block`.
- Default rules `jailbreak-dan-persona` and `exfiltration-repeat-above` were narrowed to stop blocking "I can't do anything now" and "repeat everything above as bullets".
- Minimum supported Rust version is 1.89. `serde_yaml` (unmaintained) was replaced by `serde-saphyr`.

## [0.1.0] - 2026-09-02

Initial release: rule engine (literal, regex and heuristic rules), normalization, shadow and enforcement modes, structured logging, curated default rule set, CLI and Python bindings.

[Unreleased]: https://github.com/PabloVeraH/alcaide/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PabloVeraH/alcaide/releases/tag/v0.1.0
