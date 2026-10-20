//! `alcaide bench` — run a rule set against a labeled test corpus and
//! report measured detection/false-positive rates and latency, optionally
//! failing when they miss a target (for use as a CI gate).
//!
//! Corpus schema matches `alcaide-core/tests/corpus/prompts.yaml`
//! -- this is deliberately a small, focused reimplementation rather than a
//! shared library dependency, since `tests/` files aren't importable as a
//! crate and the schema is only a few fields.

use alcaide_core::{Detector, Verdict};
use serde::Deserialize;
use std::path::Path;

use crate::{load_detector, EXIT_USAGE_ERROR};

/// Exit code when the run succeeded but a requested gate failed.
const EXIT_GATE_FAILED: u8 = 1;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    prompt: String,
    label: Label,
    // Other corpus fields (expect_detected, source, note) document the
    // entry for humans; the benchmark doesn't need them.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Malicious,
    Benign,
}

/// Optional pass/fail thresholds, as fractions in `0.0..=1.0`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Gates {
    pub min_detection: Option<f64>,
    pub max_false_positive: Option<f64>,
}

/// Measured outcome of one corpus run.
#[derive(Debug, Default)]
struct Tally {
    malicious: u32,
    detected: u32,
    benign: u32,
    false_positives: u32,
    latencies_us: Vec<u128>,
}

impl Tally {
    fn record(&mut self, label: Label, detected: bool, latency_us: u128) {
        self.latencies_us.push(latency_us);
        match label {
            Label::Malicious => {
                self.malicious += 1;
                self.detected += u32::from(detected);
            }
            Label::Benign => {
                self.benign += 1;
                self.false_positives += u32::from(detected);
            }
        }
    }

    fn detection_rate(&self) -> f64 {
        ratio(self.detected, self.malicious)
    }

    fn false_positive_rate(&self) -> f64 {
        ratio(self.false_positives, self.benign)
    }

    /// A human-readable reason for every gate this run fails.
    fn gate_failures(&self, gates: Gates) -> Vec<String> {
        let mut failures = Vec::new();
        if let Some(min) = gates.min_detection {
            if self.detection_rate() < min {
                failures.push(format!(
                    "detection rate {:.1}% is below the required {:.1}%",
                    self.detection_rate() * 100.0,
                    min * 100.0
                ));
            }
        }
        if let Some(max) = gates.max_false_positive {
            if self.false_positive_rate() > max {
                failures.push(format!(
                    "false positive rate {:.1}% is above the allowed {:.1}%",
                    self.false_positive_rate() * 100.0,
                    max * 100.0
                ));
            }
        }
        failures
    }
}

pub fn run(corpus_path: &Path, rules_path: Option<&Path>, gates: Gates) -> u8 {
    let detector = match load_detector(rules_path) {
        Ok(detector) => detector,
        Err(code) => return code,
    };

    let corpus = match load_corpus(corpus_path) {
        Ok(corpus) => corpus,
        Err(error) => {
            eprintln!("Error in {}: {error}", corpus_path.display());
            return EXIT_USAGE_ERROR;
        }
    };

    let mut tally = measure(&detector, &corpus);
    tally.latencies_us.sort_unstable();

    println!(
        "Corpus:              {} ({} entries)",
        corpus_path.display(),
        corpus.len()
    );
    println!("Rules loaded:         {}", detector.rule_count());
    println!(
        "Detection rate:       {}/{} malicious detected ({:.1}%)",
        tally.detected,
        tally.malicious,
        tally.detection_rate() * 100.0
    );
    println!(
        "False positive rate:  {}/{} benign false-positived ({:.1}%)",
        tally.false_positives,
        tally.benign,
        tally.false_positive_rate() * 100.0
    );
    println!(
        "Latency p50:          {}us",
        percentile(&tally.latencies_us, 50)
    );
    println!(
        "Latency p99:          {}us",
        percentile(&tally.latencies_us, 99)
    );

    let failures = tally.gate_failures(gates);
    for failure in &failures {
        eprintln!("FAILED: {failure}");
    }
    if failures.is_empty() {
        0
    } else {
        EXIT_GATE_FAILED
    }
}

fn load_corpus(path: &Path) -> Result<Vec<CorpusEntry>, String> {
    let yaml = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let corpus: Vec<CorpusEntry> = serde_saphyr::from_str(&yaml).map_err(|e| e.to_string())?;
    if corpus.is_empty() {
        return Err("corpus is empty".to_string());
    }
    Ok(corpus)
}

fn measure(detector: &Detector, corpus: &[CorpusEntry]) -> Tally {
    let mut tally = Tally::default();
    for entry in corpus {
        let decision = detector.evaluate(&entry.prompt, None);
        let detected = decision.evaluated_verdict != Verdict::Allow;
        tally.record(entry.label, detected, decision.latency.as_micros());
    }
    tally
}

/// `part / whole`, or 0 for an empty `whole`.
fn ratio(part: u32, whole: u32) -> f64 {
    if whole == 0 {
        0.0
    } else {
        f64::from(part) / f64::from(whole)
    }
}

/// Nearest-rank percentile over an already-sorted slice.
fn percentile(sorted: &[u128], pct: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally(detected: u32, malicious: u32, false_positives: u32, benign: u32) -> Tally {
        Tally {
            malicious,
            detected,
            benign,
            false_positives,
            latencies_us: Vec::new(),
        }
    }

    #[test]
    fn records_detections_and_false_positives_by_label() {
        let mut t = Tally::default();
        t.record(Label::Malicious, true, 5);
        t.record(Label::Malicious, false, 7);
        t.record(Label::Benign, true, 3);

        assert_eq!((t.detected, t.malicious), (1, 2));
        assert_eq!((t.false_positives, t.benign), (1, 1));
        assert_eq!(t.latencies_us, [5, 7, 3]);
    }

    #[test]
    fn no_gates_never_fail() {
        assert!(tally(0, 10, 10, 10)
            .gate_failures(Gates::default())
            .is_empty());
    }

    #[test]
    fn detection_gate_fails_only_below_the_threshold() {
        let gates = Gates {
            min_detection: Some(0.9),
            ..Gates::default()
        };

        assert!(tally(9, 10, 0, 10).gate_failures(gates).is_empty());
        assert_eq!(tally(8, 10, 0, 10).gate_failures(gates).len(), 1);
    }

    #[test]
    fn false_positive_gate_fails_only_above_the_threshold() {
        let gates = Gates {
            max_false_positive: Some(0.1),
            ..Gates::default()
        };

        assert!(tally(0, 10, 1, 10).gate_failures(gates).is_empty());
        assert_eq!(tally(0, 10, 2, 10).gate_failures(gates).len(), 1);
    }

    #[test]
    fn rates_of_an_empty_class_are_zero() {
        let t = tally(0, 0, 0, 0);

        assert_eq!(t.detection_rate(), 0.0);
        assert_eq!(t.false_positive_rate(), 0.0);
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let sorted: Vec<u128> = (1..=100).collect();

        assert_eq!(percentile(&sorted, 50), 50);
        assert_eq!(percentile(&sorted, 99), 99);
        assert_eq!(percentile(&[7], 99), 7);
        assert_eq!(percentile(&[], 50), 0);
    }
}
