# Alcaide

A deterministic, auditable prompt-injection firewall written in Rust — inspects user input before it reaches an LLM, and tells you exactly which rule fired instead of handing back an opaque score.

## Status

Pre-1.0, but functionally complete for the core use case: config loading, normalization (Unicode NFKC, invisible-character removal, homoglyph folding, whitespace collapsing, base64/hex decoding, a deobfuscated copy that undoes escapes, emoji inside words and spaced-out letters), pattern matching (literal + regex + heuristic rules), scoring, shadow/enforcement modes, structured JSON logging, a curated default rule set with cited sources, a CLI (`alcaide check` / `lint-rules` / `bench`), and Python bindings (`pip install alcaide`) all work end to end. See [`BENCHMARKS.md`](BENCHMARKS.md) for real, measured detection/false-positive rates and latency against the curated rule set.

## Usage

Add [`alcaide-core`](https://crates.io/crates/alcaide-core) to your project (Rust 1.89+):

```sh
cargo add alcaide-core
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
  # max_input_bytes: 1000000  # longer inputs: only this prefix is inspected...
  # on_oversize: block      # ...and this is their minimum verdict (or `flag`)

rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignore (all )?(previous |prior )?instructions"
```

To keep the default rules and add your own, extend them instead of copying the file, so you keep getting their updates:

```yaml
version: 1
extends: default
disable: [jailbreak-stay-in-character]  # default rules to drop, by id
defaults:
  mode: enforcement
  block_threshold: high
rules:
  - id: internal-codename
    category: exfiltration
    severity: high
    pattern_type: literal
    pattern: "project bluebird"
```

To change a default rule, disable it and redefine it under the same id. Disabling an id the default set doesn't have is an error, so a typo can't leave a rule running.

Matching is case-insensitive and runs on normalized text, so rules don't need to handle capitalization, extra whitespace, invisible characters or homoglyphs themselves. Unknown fields are rejected, so a typo fails loudly instead of being ignored. The default rule set at [`alcaide-core/rules/default.yaml`](alcaide-core/rules/default.yaml) is a cited-source starting point, not a claim of completeness (see [`BENCHMARKS.md`](BENCHMARKS.md)).

### Command line

```sh
cargo install alcaide-cli

alcaide check "Ignore all previous instructions"   # built-in rules
echo "some text" | alcaide check --rules rules.yaml --json
alcaide check --file prompt.txt
alcaide lint-rules rules.yaml
alcaide bench --corpus corpus.yaml --min-detection 0.9 --max-false-positive 0.05
```

`check` exits with 0 (Allow), 1 (Block) or 2 (Flag); `bench` exits with 1 if a `--min-detection` / `--max-false-positive` gate fails, so it can guard a rule set in CI. Any usage or configuration error exits with 64.

### Python

```python
from alcaide import Detector, Mode, Verdict

detector = Detector.with_default_rules(mode=Mode.Enforcement)  # or from_config_path / from_yaml_str
decision = detector.evaluate("Ignore all previous instructions")
for m in decision.matched_rules:
    start, end = m.span  # character offsets: text[start:end]
```

See [`alcaide-py/README.md`](alcaide-py/README.md).

### Privacy

Nothing is sent over the network. Every call to `evaluate` also emits one structured event via [`tracing`](https://docs.rs/tracing) (target `alcaide::decision`, one field per entry, so a JSON subscriber writes real JSON fields) containing a SHA-256 hash of the input, never the raw text, unless `log_raw_input: true` is explicitly set in `defaults`.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to propose rules, and [CHANGELOG.md](CHANGELOG.md) for what changed between versions. Found a bypass? Please report it privately, as described in [SECURITY.md](SECURITY.md).

## License

Every crate in this repository (`alcaide-core`, `alcaide-cli`, and the `alcaide` Python bindings in `alcaide-py`) is distributed under [AGPL-3.0-only](LICENSE).
