//! Structured JSON log record emitted per evaluation.
//!
//! Privacy-first by construction: the raw input is hashed (SHA-256) by
//! default and never logged verbatim unless `log_raw_input` is explicitly
//! enabled in the rule set's `defaults`.
//!
//! The record carries no timestamp of its own: the `tracing` subscriber
//! stamps every event it writes.

use crate::decision::{Decision, MatchDetail, Mode, Verdict};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// One structured log record per `Detector::evaluate` call. Borrows from
/// the `Decision` it describes; it only lives long enough to be
/// serialized.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord<'a> {
    pub request_id: Option<&'a str>,
    pub mode: Mode,
    /// The real evaluation result, even in `Shadow` mode -- see
    /// `Decision::evaluated_verdict`. This is the field to use to
    /// calibrate before switching to enforcement.
    pub verdict: Verdict,
    pub matched_rules: &'a [MatchDetail],
    pub latency_us: u128,
    pub input_truncated: bool,
    pub rule_set_version: u32,
    pub input_hash: String,
    /// `None` unless `log_raw_input` is explicitly enabled. Privacy
    /// guarantee -- do not change this default without a deliberate,
    /// reviewed decision.
    pub input_snippet: Option<&'a str>,
}

pub fn build_log_record<'a>(
    decision: &'a Decision,
    input: &'a str,
    request_id: Option<&'a str>,
    rule_set_version: u32,
    log_raw_input: bool,
) -> LogRecord<'a> {
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let input_snippet = log_raw_input.then_some(input);

    LogRecord {
        request_id,
        mode: decision.mode,
        verdict: decision.evaluated_verdict,
        matched_rules: &decision.matched_rules,
        latency_us: decision.latency.as_micros(),
        input_truncated: decision.input_truncated,
        rule_set_version,
        input_hash,
        input_snippet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_decision(verdict: Verdict, evaluated_verdict: Verdict) -> Decision {
        Decision {
            verdict,
            evaluated_verdict,
            matched_rules: Vec::new(),
            latency: Duration::from_micros(42),
            mode: Mode::Enforcement,
            input_truncated: false,
        }
    }

    #[test]
    fn input_snippet_is_null_by_default() {
        // Privacy guarantee (documented log schema) -- do not remove or
        // relax this test without a deliberate, reviewed decision. Raw
        // prompt content must never be logged unless explicitly opted in.
        let decision = sample_decision(Verdict::Allow, Verdict::Allow);
        let record = build_log_record(&decision, "sensitive user prompt", None, 1, false);

        assert!(record.input_snippet.is_none());

        let json = serde_json::to_string(&record).expect("serializes");
        assert!(json.contains("\"input_snippet\":null"));
        assert!(!json.contains("sensitive user prompt"));
    }

    #[test]
    fn input_snippet_appears_only_when_explicitly_enabled() {
        let decision = sample_decision(Verdict::Allow, Verdict::Allow);
        let record = build_log_record(&decision, "sensitive user prompt", None, 1, true);

        assert_eq!(record.input_snippet, Some("sensitive user prompt"));
    }

    #[test]
    fn input_hash_never_contains_the_raw_input() {
        let decision = sample_decision(Verdict::Allow, Verdict::Allow);
        let record = build_log_record(&decision, "sensitive user prompt", None, 1, false);

        assert_ne!(record.input_hash, "sensitive user prompt");
        assert_eq!(record.input_hash.len(), 64); // SHA-256 hex digest length
    }

    #[test]
    fn hash_is_deterministic_for_the_same_input() {
        let decision = sample_decision(Verdict::Allow, Verdict::Allow);
        let a = build_log_record(&decision, "same input", None, 1, false);
        let b = build_log_record(&decision, "same input", None, 1, false);

        assert_eq!(a.input_hash, b.input_hash);
    }

    #[test]
    fn logged_verdict_is_the_real_evaluated_verdict_not_the_caller_facing_one() {
        // Simulates shadow mode: caller-facing verdict is Allow, but the
        // rules really would have blocked -- the log must reflect that.
        let decision = sample_decision(Verdict::Allow, Verdict::Block);
        let record = build_log_record(&decision, "irrelevant", None, 1, false);

        assert_eq!(record.verdict, Verdict::Block);
    }

    #[test]
    fn request_id_is_carried_through_when_provided() {
        let decision = sample_decision(Verdict::Allow, Verdict::Allow);
        let record = build_log_record(&decision, "text", Some("req-123"), 1, false);

        assert_eq!(record.request_id, Some("req-123"));
    }
}
