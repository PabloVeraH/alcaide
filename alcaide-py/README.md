# alcaide

Python bindings for [Alcaide](https://github.com/PabloVeraH/alcaide) — a deterministic, auditable prompt-injection firewall written in Rust. Inspects user input before it reaches an LLM, and tells you exactly which rule fired instead of handing back an opaque score.

## Install

```sh
pip install alcaide
```

## Usage

```python
from alcaide import Detector, Verdict

detector = Detector.from_config_path("rules.yaml")
decision = detector.evaluate("ignore all previous instructions")

if decision.verdict == Verdict.Block:
    print("blocked — see decision.matched_rules for why")
elif decision.verdict == Verdict.Flag:
    print("flagged for review, allowed through")
else:
    print("allowed")
```

A curated, cited-source default rule set ships in the main repository at [`alcaide-core/rules/default.yaml`](https://github.com/PabloVeraH/alcaide/blob/main/alcaide-core/rules/default.yaml) — see [`BENCHMARKS.md`](https://github.com/PabloVeraH/alcaide/blob/main/BENCHMARKS.md) for its measured detection/false-positive rates.

## License

AGPL-3.0-only. See [LICENSE](https://github.com/PabloVeraH/alcaide/blob/main/LICENSE).
