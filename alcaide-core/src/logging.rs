//! Structured JSON log record emitted per evaluation.
//!
//! Privacy-first by construction: the raw input is hashed (SHA-256) by
//! default and never logged verbatim unless `log_raw_input` is explicitly
//! enabled in the rule set's `defaults`.

use crate::decision::{Decision, MatchDetail, Mode, Verdict};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// One structured log record per `Detector::evaluate` call.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    pub timestamp: String,
    pub request_id: Option<String>,
    pub mode: Mode,
    /// The real evaluation result, even in `Shadow` mode -- see
    /// `Decision::evaluated_verdict`. This is the field to use to
    /// calibrate before switching to enforcement.
    pub verdict: Verdict,
    pub matched_rules: Vec<MatchDetail>,
    pub latency_us: u128,
    pub rule_set_version: u32,
    pub input_hash: String,
    /// `None` unless `log_raw_input` is explicitly enabled. Privacy
    /// guarantee -- do not change this default without a deliberate,
    /// reviewed decision.
    pub input_snippet: Option<String>,
}

pub fn build_log_record(
    decision: &Decision,
    input: &str,
    request_id: Option<&str>,
    rule_set_version: u32,
    log_raw_input: bool,
) -> LogRecord {
    let input_hash = format!("{:x}", Sha256::digest(input.as_bytes()));
    let input_snippet = log_raw_input.then(|| input.to_string());

    LogRecord {
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        request_id: request_id.map(str::to_string),
        mode: decision.mode,
        verdict: decision.evaluated_verdict,
        matched_rules: decision.matched_rules.clone(),
        latency_us: decision.latency.as_micros(),
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

        assert_eq!(
            record.input_snippet.as_deref(),
            Some("sensitive user prompt")
        );
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

        assert_eq!(record.request_id.as_deref(), Some("req-123"));
    }
}
