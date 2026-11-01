# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break the API).

## [Unreleased]

## [0.2.0] - 2026-11-01

First release published to crates.io and PyPI.

### Security

- An input longer than `max_input_bytes` was flagged without being inspected, so padding any payload past the limit downgraded a `Block` to a `Flag`. Its prefix is now always inspected, and the new `on_oversize` setting (default `block`) sets the minimum verdict.
- Normalization now removes invisible characters (zero-width spaces, soft hyphens, bidi controls, variation selectors), reveals Unicode tag characters ("ASCII smuggling"), collapses whitespace runs, and folds uppercase Cyrillic, Greek and IPA look-alikes. Each of these used to bypass every rule.
- The base64 decoder now accepts unpadded and URL-safe base64, and payloads misaligned by junk glued in front of them.
- Regex rules are case-insensitive by default (opt out with `(?-i)`); literal rules are folded like the input and non-ASCII literals get Unicode case folding.
- When literal rules overlap, all of them are now reported, so a low-severity rule can no longer hide a high-severity one.
- A look-alike or tag-character letter followed by a combining accent (Cyrillic "а" + U+0301), or an accent separated from its letter by an invisible character, never composed into the accented letter, so "Ignorа́ las instrucciones anteriores" evaded the Spanish rule. Normalization now resolves look-alikes, tags and invisible characters before composing, which also folds accented look-alikes (Greek "ά"). Found by fuzzing.
- Rule files reject unknown fields (`enabeld: false` used to be silently ignored), blank patterns, and patterns that match empty text (which matched every input).

### Fixed

- In shadow mode, an internal pipeline failure returned `Block` to the caller; shadow mode now always returns `Allow`, as documented.
- A match reaching into decoded base64/hex content could report a reversed span, which panics when used to slice the input.
- The CLI exited with 2 on invalid arguments, the same code as a `Flag` verdict; usage errors now exit with 64.

### Added

- `Defaults::max_input_bytes` and `Defaults::on_oversize`, plus `Decision::input_truncated`.
- The default rule set is embedded in the crate: `DEFAULT_RULES_YAML` and `Detector::with_default_rules()`.
- `Detector::new(RuleSet)`, `Detector::from_yaml_str` and `Detector::rules()`. `Decision` implements `Serialize`.
- CLI: `--rules` is optional everywhere (defaults to the built-in rules); `check` reads standard input or `--file`, and shows the matched text; `bench --min-detection / --max-false-positive` gates (exit 1 on failure); `--version`.
- Python: `Detector.from_yaml_str`, `Detector.with_default_rules`, `rule_count()`, `Decision.input_truncated`, informative `repr`s, type stubs (`py.typed`). `evaluate` releases the GIL. A single abi3 wheel covers CPython 3.9+.
- Default rules: verb synonyms for instruction overrides (disregard/forget/override, olvidar/omitir/hacer caso omiso) and markdown image exfiltration.
- Default rules from published attacks: fake role markers (`[system](#additional_instructions)`), impersonated system error messages, chat-template control tokens (`<|im_start|>`, `[INST]`, `<<SYS>>`; medium severity), and fake completions ("Answer: task complete."). Two OWASP smoke-test strings that used to pass are now detected.
- Property tests for `Detector::evaluate`: it never panics, and every span slices the input.
- `benchmarks/fetch_public.py` and a held-out measurement against three public datasets (deepset/prompt-injections, Lakera/gandalf_ignore_instructions, jackhhao/jailbreak-classification) in BENCHMARKS.md: 0-36% of attacks detected, no false positive on 1,039 benign prompts.
- Default rules written from the public datasets' train splits: German instruction overrides, "new task" announcements (medium), prompt-dump requests, content-policy bypass and "any kind of content" jailbreak claims, "stay in character" (medium); the English override rule now covers "your instructions", prompts/rules/commands/orders, "everything you've been told" and the DAN opener. Held-out test splits: deepset 0 -> 7/60, Gandalf 40 -> 63/112, jailbreak-classification 39 -> 74/139 detected, still no false positive.
- Normalization appends a deobfuscated copy of the text when it has something to undo: URL, backslash and HTML escapes decoded, symbols and emoji between two letters removed ("i🔓gnore", which used to pass every rule), spaced-out letters joined ("i g n o r e"). Base64 inside base64 is decoded too.
- Typo correction in the deobfuscated copy: misspelled, scrambled and leetspeak forms of the words the default rules use ("ignroe", "promt", "1gn0r3 4ll") are corrected, so two of OWASP's three typoglycemia examples are now detected. Gandalf held-out test: 63 -> 64/112, still no false positive. `injection-ignore-instructions-en` accepts an optional "system" before the noun ("ignore all previous system instructions").
- Default rules `encoding-invisible-text` and `encoding-mixed-script` (medium), with heuristics `invisible_text` and `mixed_script`: they flag text hidden with invisible characters, bidi controls or tag characters, and words mixing Latin with look-alike letters, even when the hidden text matches no rule.
- Rule files can build on the default rules instead of copying them: `extends: default`, plus `disable: [ids]` to drop default rules (an unknown id is an error). Works everywhere a rule file loads: Rust, the CLI's `--rules`, and Python.
- Python: `Detector.with_default_rules(mode=Mode.Enforcement)` enforces the default rules without copying their YAML.
- Coverage-guided fuzzing (`fuzz/`, cargo-fuzz) of evaluation, normalization and rule loading, checking invariants rather than only crashes: verdict policy, valid spans, idempotent folding, and that obfuscating text never changes its normalized form. Runs on every engine change and weekly in CI.
- `SECURITY.md`, `CONTRIBUTING.md`, cargo-deny, Dependabot, and CI on Linux, Windows and macOS, plus the MSRV.

### Changed

- The decision log record is one `tracing` event with a field per entry (message `prompt evaluated`) instead of a JSON string inside the message, which a JSON subscriber encoded twice. `matched_rules` stays JSON text, since a list can't be a `tracing` field, and `input_snippet` is omitted rather than null when not logged.
- `max_input_bytes` defaults to 1,000,000 instead of 32,000. A retrieved document longer than 32 KB was blocked unread by default, and with `on_oversize: flag` a payload appended to it went undetected; a whole 1 MB document is now inspected in 20-80 ms.
- Default rules write word boundaries as ASCII `(?-u:\b)`: a Unicode `\b` made the regex engine leave its DFA on non-ASCII text, 10x slower at p99 on long prompts.
- `MatchDetail::span` is now a byte range of the caller's original input. It used to point into internal normalized text. In Python, `MatchDetail.span` is in characters, so `text[start:end]` works.
- `Decision`, `MatchDetail` and `ConfigError` are `#[non_exhaustive]`.
- CLI: `bench` takes the rule set as `--rules` (optional) instead of a positional argument; `--corpus` is unchanged. It now warms up before measuring, so its latency percentiles reflect steady state.
- Each rule is reported at most once per evaluation, at its first occurrence: a payload repeated many times no longer inflates `matched_rules` and every log record.
- The log record no longer has a `timestamp` field (the `tracing` subscriber stamps each event), which drops the `chrono` dependency.
- `Rule::pattern` is required for every pattern type, heuristics included.
- `Verdict` is ordered by strictness: `Allow < Flag < Block`.
- Default rules `jailbreak-dan-persona` and `exfiltration-repeat-above` were narrowed to stop blocking "I can't do anything now" and "repeat everything above as bullets".
- Minimum supported Rust version is 1.89. `serde_yaml` (unmaintained) was replaced by `serde-saphyr`.

### Performance

- 43–60% faster end to end (criterion, against 0.1.0 plus the security fixes above): the per-request log record is only built when a subscriber listens; non-whitespace ASCII runs skip per-character normalization; regex rules stop at their first match; matches refer to rules by index.

## [0.1.0] - 2026-09-02

Initial release: rule engine (literal, regex and heuristic rules), normalization, shadow and enforcement modes, structured logging, curated default rule set, CLI and Python bindings.

[Unreleased]: https://github.com/PabloVeraH/alcaide/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/PabloVeraH/alcaide/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PabloVeraH/alcaide/releases/tag/v0.1.0
