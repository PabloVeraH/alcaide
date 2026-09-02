//! `alcaide check` — evaluate a single input against a rule set.

use alcaide_core::{Detector, MatchDetail, Mode, Verdict};
use serde::Serialize;
use std::path::Path;

use crate::EXIT_USAGE_ERROR;

/// JSON shape for `--json`. Reuses the already-public, already-Serialize
/// types (`Verdict`, `Mode`, `MatchDetail`) rather than depending on
/// alcaide-core's internal log record format.
#[derive(Serialize)]
struct CheckOutput<'a> {
    verdict: Verdict,
    evaluated_verdict: Verdict,
    matched_rules: &'a [MatchDetail],
    latency_us: u128,
    mode: Mode,
}

pub fn run(text: &str, rules_path: &Path, json: bool) -> u8 {
    let detector = match Detector::from_config_path(rules_path) {
        Ok(detector) => detector,
        Err(error) => {
            eprintln!("Error loading {}: {error}", rules_path.display());
            return EXIT_USAGE_ERROR;
        }
    };

    // The exit code and display reflect the real result the rules
    // produced (`evaluated_verdict`), not the caller-facing `verdict` --
    // someone running `alcaide check` wants to know what actually matched,
    // not what a shadow-mode caller happens to receive.
    let decision = detector.evaluate(text, None);

    if json {
        let output = CheckOutput {
            verdict: decision.verdict,
            evaluated_verdict: decision.evaluated_verdict,
            matched_rules: &decision.matched_rules,
            latency_us: decision.latency.as_micros(),
            mode: decision.mode,
        };
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("Error serializing output: {error}");
                return EXIT_USAGE_ERROR;
            }
        }
    } else {
        println!("Verdict: {:?}", decision.evaluated_verdict);
        if decision.mode == Mode::Shadow && decision.verdict != decision.evaluated_verdict {
            println!("(shadow mode: a real caller would receive Allow instead)");
        }
        if decision.matched_rules.is_empty() {
            println!("No rules matched.");
        } else {
            println!("Matched rules:");
            for m in &decision.matched_rules {
                println!(
                    "  {} ({:?}, {:?}) at {:?}",
                    m.rule_id, m.category, m.severity, m.span
                );
            }
        }
        println!("Latency: {}us", decision.latency.as_micros());
    }

    match decision.evaluated_verdict {
        Verdict::Allow => 0,
        Verdict::Block => 1,
        Verdict::Flag => 2,
    }
}
