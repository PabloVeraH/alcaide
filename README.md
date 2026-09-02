# Alcaide

A deterministic, auditable prompt-injection firewall written in Rust — inspects user input before it reaches an LLM, and tells you exactly which rule fired instead of handing back an opaque score.

## Status

Early development. The rule engine (`alcaide-core`) is functional and tested: config loading, normalization (Unicode NFKC, homoglyph folding, base64/hex decoding), pattern matching (literal + regex + heuristic rules), scoring, shadow/enforcement modes, and structured JSON logging all work end to end. Not yet on crates.io. No CLI or Python bindings yet.

## Usage

Not published to crates.io yet — depend on the git repo directly:

```toml
[dependencies]
alcaide-core = { git = "https://github.com/PabloVeraH/alcaide" }
```

Define a rule set (`rules.yaml`):

```yaml
version: 1
defaults:
  mode: enforcement       # or `shadow` to log without blocking
  block_threshold: high   # minimum severity that triggers Block

rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignore (all )?(previous |prior )?instructions"
    enabled: true
```

Evaluate input before it reaches your LLM call:

```rust
use alcaide_core::{Detector, Verdict};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = Detector::from_config_path(Path::new("rules.yaml"))?;

    let decision = detector.evaluate("ignore all previous instructions", None);

    match decision.verdict {
        Verdict::Block => println!("blocked — see decision.matched_rules for why"),
        Verdict::Flag => println!("flagged for review, allowed through"),
        Verdict::Allow => println!("allowed"),
    }

    Ok(())
}
```

`decision.matched_rules` carries the exact rule id, category, severity, and text span that triggered — every decision is explainable, never just a score.

### Privacy

Nothing is sent over the network. Every call to `evaluate` also emits one structured JSON log line via [`tracing`](https://docs.rs/tracing) (target `alcaide::decision`) containing a SHA-256 hash of the input, never the raw text, unless `log_raw_input: true` is explicitly set in `defaults`.

## License

This crate (`alcaide-core` and `alcaide-cli`) is distributed under [AGPL-3.0-only](LICENSE).
