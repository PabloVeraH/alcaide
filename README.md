# Alcaide

A deterministic, auditable prompt-injection firewall written in Rust — inspects user input before it reaches an LLM, and tells you exactly which rule fired instead of handing back an opaque score.

## Status

Pre-1.0, but functionally complete for the core use case: config loading, normalization (Unicode NFKC, invisible-character removal, homoglyph folding, whitespace collapsing, base64/hex decoding), pattern matching (literal + regex + heuristic rules), scoring, shadow/enforcement modes, structured JSON logging, a curated default rule set with cited sources, a CLI (`alcaide check` / `lint-rules` / `bench`), and Python bindings (`pip install .` in `alcaide-py/`) all work end to end. Not yet published to crates.io or PyPI. See [`BENCHMARKS.md`](BENCHMARKS.md) for real, measured detection/false-positive rates and latency against the curated rule set.

## Usage

Not published to crates.io yet — depend on the git repo directly (Rust 1.89+):

```toml
[dependencies]
alcaide-core = { git = "https://github.com/PabloVeraH/alcaide" }
```

The curated default rule set is embedded in the crate. It ships in shadow mode (it reports what it would block, but never blocks); switch to enforcement once you've checked it against your own traffic:

```rust
use alcaide_core::{Detector, Mode, RuleSet, Verdict, DEFAULT_RULES_YAML};

fn main() -> Result<(), alcaide_core::ConfigError> {
    let mut rules = RuleSet::from_yaml_str(DEFAULT_RULES_YAML)?;
    rules.defaults.mode = Mode::Enforcement;
    let detector = Detector::new(rules)?; // build once, share across threads

    let input = "Ignore all previous instructions";
    let decision = detector.evaluate(input, None);

    match decision.verdict {
        Verdict::Block => println!("blocked"),
        Verdict::Flag => println!("flagged for review, allowed through"),
        Verdict::Allow => println!("allowed"),
    }
    for m in &decision.matched_rules {
        let (start, end) = m.span; // byte offsets into `input`
        println!("{} ({:?}) matched {:?}", m.rule_id, m.severity, &input[start..end]);
    }
    Ok(())
}
```

`decision.matched_rules` carries the exact rule id, category, severity, and the span of *your* input that triggered it — even when the payload was hidden with invisible characters, look-alike letters or base64 — so every decision is explainable, never just a score.

### Custom rules

Load your own rule set with `Detector::from_config_path` or `Detector::from_yaml_str`:

```yaml
version: 1
defaults:
  mode: enforcement       # or `shadow` to log without blocking
  block_threshold: high   # minimum severity that triggers Block
  # max_input_bytes: 32000  # longer inputs: only this prefix is inspected...
  # on_oversize: block      # ...and this is their minimum verdict (or `flag`)

rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignore (all )?(previous |prior )?instructions"
```

Matching is case-insensitive and runs on normalized text, so rules don't need to handle capitalization, extra whitespace, invisible characters or homoglyphs themselves. Unknown fields are rejected, so a typo fails loudly instead of being ignored. The default rule set at [`alcaide-core/rules/default.yaml`](alcaide-core/rules/default.yaml) is a cited-source starting point, not a claim of completeness (see [`BENCHMARKS.md`](BENCHMARKS.md)).

### Command line

```sh
cargo install --git https://github.com/PabloVeraH/alcaide alcaide-cli

alcaide check "Ignore all previous instructions"   # built-in rules
echo "some text" | alcaide check --rules rules.yaml --json
alcaide check --file prompt.txt
alcaide lint-rules rules.yaml
alcaide bench --corpus corpus.yaml --min-detection 0.9 --max-false-positive 0.05
```

`check` exits with 0 (Allow), 1 (Block) or 2 (Flag); `bench` exits with 1 if a `--min-detection` / `--max-false-positive` gate fails, so it can guard a rule set in CI. Any usage or configuration error exits with 64.

### Python

```python
from alcaide import Detector, Verdict

detector = Detector.with_default_rules()  # or from_config_path / from_yaml_str
decision = detector.evaluate("Ignore all previous instructions")
for m in decision.matched_rules:
    start, end = m.span  # character offsets: text[start:end]
```

See [`alcaide-py/README.md`](alcaide-py/README.md).

### Privacy

Nothing is sent over the network. Every call to `evaluate` also emits one structured JSON log line via [`tracing`](https://docs.rs/tracing) (target `alcaide::decision`) containing a SHA-256 hash of the input, never the raw text, unless `log_raw_input: true` is explicitly set in `defaults`.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to propose rules, and [CHANGELOG.md](CHANGELOG.md) for what changed between versions. Found a bypass? Please report it privately, as described in [SECURITY.md](SECURITY.md).

## License

Every crate in this repository (`alcaide-core`, `alcaide-cli`, and the `alcaide` Python bindings in `alcaide-py`) is distributed under [AGPL-3.0-only](LICENSE).
