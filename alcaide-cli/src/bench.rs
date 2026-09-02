//! `alcaide bench` — run a rule set against a labeled test corpus and
//! report measured detection/false-positive rates and latency.
//!
//! Corpus schema matches `alcaide-core/tests/corpus/prompts.yaml`
//! (milestone M6) -- this is deliberately a small, focused reimplementation
//! rather than a shared library dependency, since `tests/` files aren't
//! importable as a crate and the schema is only a few fields.

use alcaide_core::{Detector, Verdict};
use serde::Deserialize;
use std::path::Path;

use crate::EXIT_USAGE_ERROR;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    prompt: String,
    label: String,
    #[serde(default)]
    #[allow(dead_code)] // not asserted on here, just documentation
    expect_detected: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    source: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

pub fn run(rules_path: &Path, corpus_path: &Path) -> u8 {
    let detector = match Detector::from_config_path(rules_path) {
        Ok(detector) => detector,
        Err(error) => {
            eprintln!("Error loading {}: {error}", rules_path.display());
            return EXIT_USAGE_ERROR;
        }
    };

    let corpus_yaml = match std::fs::read_to_string(corpus_path) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Error reading {}: {error}", corpus_path.display());
            return EXIT_USAGE_ERROR;
        }
    };

    let corpus: Vec<CorpusEntry> = match serde_yaml::from_str(&corpus_yaml) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("Error parsing {}: {error}", corpus_path.display());
            return EXIT_USAGE_ERROR;
        }
    };

    if corpus.is_empty() {
        eprintln!("Error: corpus at {} is empty", corpus_path.display());
        return EXIT_USAGE_ERROR;
    }

    let mut latencies_us: Vec<u128> = Vec::with_capacity(corpus.len());
    let (mut malicious_total, mut malicious_detected) = (0u32, 0u32);
    let (mut benign_total, mut benign_false_positive) = (0u32, 0u32);

    for entry in &corpus {
        let decision = detector.evaluate(&entry.prompt, None);
        latencies_us.push(decision.latency.as_micros());
        let detected = decision.evaluated_verdict != Verdict::Allow;

        match entry.label.as_str() {
            "malicious" => {
                malicious_total += 1;
                if detected {
                    malicious_detected += 1;
                }
            }
            "benign" => {
                benign_total += 1;
                if detected {
                    benign_false_positive += 1;
                }
            }
            other => eprintln!("Warning: unrecognized label {other:?}, skipped in rate totals"),
        }
    }

    latencies_us.sort_unstable();
    let p50 = percentile(&latencies_us, 50);
    let p99 = percentile(&latencies_us, 99);

    println!(
        "Corpus:              {} ({} entries)",
        corpus_path.display(),
        corpus.len()
    );
    println!("Rules loaded:         {}", detector.rule_count());
    println!("Detection rate:       {malicious_detected}/{malicious_total} malicious detected");
    println!("False positive rate:  {benign_false_positive}/{benign_total} benign false-positived");
    println!("Latency p50:          {p50}us");
    println!("Latency p99:          {p99}us");

    0
}

/// Nearest-rank percentile over an already-sorted slice.
fn percentile(sorted: &[u128], pct: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}
