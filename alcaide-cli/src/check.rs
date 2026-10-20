//! `alcaide check` — evaluate a single input against a rule set.

use alcaide_core::{Mode, Verdict};
use std::io::Read;
use std::path::Path;

use crate::{load_detector, EXIT_USAGE_ERROR};

pub fn run(text: Option<&str>, file: Option<&Path>, rules: Option<&Path>, json: bool) -> u8 {
    let detector = match load_detector(rules) {
        Ok(detector) => detector,
        Err(code) => return code,
    };

    let input = match read_input(text, file) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("Error reading input: {error}");
            return EXIT_USAGE_ERROR;
        }
    };

    // The exit code and display reflect the real result the rules
    // produced (`evaluated_verdict`), not the caller-facing `verdict` --
    // someone running `alcaide check` wants to know what actually matched,
    // not what a shadow-mode caller happens to receive.
    let decision = detector.evaluate(&input, None);

    if json {
        match serde_json::to_string(&decision) {
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
        if decision.input_truncated {
            println!("(input exceeded max_input_bytes: only its beginning was inspected)");
        }
        if decision.matched_rules.is_empty() {
            println!("No rules matched.");
        } else {
            println!("Matched rules:");
            for m in &decision.matched_rules {
                let (start, end) = m.span;
                println!(
                    "  {} ({:?}, {:?}) at {start}..{end}: {:?}",
                    m.rule_id,
                    m.category,
                    m.severity,
                    &input[start..end]
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

/// The text to evaluate: `text` itself, the contents of `file`, or standard
/// input when neither is given (or `text` is "-").
fn read_input(text: Option<&str>, file: Option<&Path>) -> std::io::Result<String> {
    match (text, file) {
        (Some(text), _) if text != "-" => Ok(text.to_string()),
        (_, Some(file)) => std::fs::read_to_string(file),
        _ => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            Ok(input)
        }
    }
}
