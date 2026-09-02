//! Regression test against the curated default rule set
//! (`rules/default.yaml`) and its labeled test corpus
//! (`tests/corpus/prompts.yaml`). See milestone M6.
//!
//! This is a small-scale preview of the full benchmark milestone M10 will
//! run against the complete curated set -- here we verify our own
//! measured PREDICTIONS (including documented gaps and documented false
//! positives, see `prompts.yaml`) match reality, not that detection is
//! perfect. If a prediction drifts, that's a real signal to investigate,
//! not something to silence by relaxing the assertion.

use alcaide_core::{Detector, Verdict};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    prompt: String,
    label: String,
    expect_detected: bool,
    source: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation for humans reading the corpus, not asserted on
    note: Option<String>,
}

fn load_corpus() -> Vec<CorpusEntry> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/prompts.yaml");
    let yaml = std::fs::read_to_string(path).expect("corpus file exists");
    serde_yaml::from_str(&yaml).expect("valid corpus YAML")
}

fn default_detector() -> Detector {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/rules/default.yaml");
    Detector::from_config_path(Path::new(path)).expect("default rule set loads and validates")
}

#[test]
fn default_rule_set_loads_and_validates() {
    // If this fails, rules/default.yaml itself is broken -- independent
    // of whether individual corpus predictions below hold.
    let _detector = default_detector();
}

#[test]
fn corpus_predictions_match_measured_reality() {
    let detector = default_detector();
    let corpus = load_corpus();
    assert!(!corpus.is_empty(), "corpus must not be empty");

    let mismatches: Vec<String> = corpus
        .iter()
        .filter_map(|entry| {
            let decision = detector.evaluate(&entry.prompt, None);
            let was_detected = decision.evaluated_verdict != Verdict::Allow;

            (was_detected != entry.expect_detected).then(|| {
                format!(
                    "prompt {:?} (label: {}, source: {}): expected detected={}, got \
                     detected={} (verdict={:?})",
                    entry.prompt,
                    entry.label,
                    entry.source,
                    entry.expect_detected,
                    was_detected,
                    decision.evaluated_verdict
                )
            })
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "corpus predictions drifted from measured reality -- update rules/default.yaml or \
         tests/corpus/prompts.yaml's expect_detected deliberately, don't silence this:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn reports_measured_detection_and_false_positive_rates() {
    // Not a pass/fail gate -- prints the honest numbers this milestone's
    // corpus was built to measure (PRD success metrics), the same way
    // M10 will report at full scale against the real, larger corpus.
    let detector = default_detector();
    let corpus = load_corpus();

    let malicious: Vec<&CorpusEntry> = corpus.iter().filter(|e| e.label == "malicious").collect();
    let benign: Vec<&CorpusEntry> = corpus.iter().filter(|e| e.label == "benign").collect();

    let detected_malicious = malicious
        .iter()
        .filter(|e| detector.evaluate(&e.prompt, None).evaluated_verdict != Verdict::Allow)
        .count();
    let false_positives = benign
        .iter()
        .filter(|e| detector.evaluate(&e.prompt, None).evaluated_verdict != Verdict::Allow)
        .count();

    println!(
        "corpus results: {}/{} malicious detected, {}/{} benign false-positived (run with \
         --nocapture to see this)",
        detected_malicious,
        malicious.len(),
        false_positives,
        benign.len()
    );
}
