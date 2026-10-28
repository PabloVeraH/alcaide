//! Checks shared by the fuzz targets.
//!
//! Every target runs with libfuzzer-sys's panic hook, which aborts the
//! process on any panic -- even one `Detector::evaluate` would catch and
//! turn into an `on_error` verdict. A pipeline panic is therefore always
//! reported as a crash, never masked by the fail-closed fallback.

use alcaide_core::{Decision, Detector, Mode, OnOversize, RuleSet, Verdict};

/// A span the caller can slice `input` with: ordered, in bounds, and on
/// character boundaries.
pub fn assert_valid_span(input: &str, (start, end): (usize, usize)) {
    assert!(start <= end, "span ({start}, {end}) is reversed");
    assert!(
        end <= input.len(),
        "span ({start}, {end}) exceeds input length {}",
        input.len()
    );
    assert!(
        input.is_char_boundary(start) && input.is_char_boundary(end),
        "span ({start}, {end}) splits a character"
    );
}

/// The guarantees `Detector::evaluate` documents for any input and any
/// valid rule set, checked on one `decision` for `input`.
pub fn assert_decision_invariants(rules: &RuleSet, input: &str, decision: &Decision) {
    let defaults = &rules.defaults;

    let mut seen = std::collections::HashSet::new();
    for matched in &decision.matched_rules {
        assert_valid_span(input, matched.span);
        assert!(
            seen.insert(matched.rule_id.as_str()),
            "rule {} reported more than once",
            matched.rule_id
        );
        let rule = rules
            .rules
            .iter()
            .find(|rule| rule.id == matched.rule_id)
            .expect("a match names a rule of the rule set");
        assert!(rule.enabled, "disabled rule {} matched", rule.id);
        assert_eq!(matched.severity, rule.severity);
        assert_eq!(matched.category, rule.category);
    }

    assert_eq!(
        decision.input_truncated,
        input.len() > defaults.max_input_bytes,
        "input_truncated disagrees with max_input_bytes"
    );
    // The documented policy, recomputed independently: the highest matched
    // severity decides, and an oversized input never gets less than its
    // on_oversize floor.
    let mut expected = match decision.matched_rules.iter().map(|m| m.severity).max() {
        Some(severity) if severity >= defaults.block_threshold => Verdict::Block,
        Some(_) => Verdict::Flag,
        None => Verdict::Allow,
    };
    if decision.input_truncated {
        expected = expected.max(match defaults.on_oversize {
            OnOversize::Block => Verdict::Block,
            OnOversize::Flag => Verdict::Flag,
        });
    }
    assert_eq!(
        decision.evaluated_verdict, expected,
        "verdict disagrees with policy"
    );

    match defaults.mode {
        Mode::Shadow => assert_eq!(decision.verdict, Verdict::Allow),
        Mode::Enforcement => assert_eq!(decision.verdict, decision.evaluated_verdict),
    }
}

/// Evaluates `input` and checks every invariant, plus determinism.
pub fn check_evaluate(detector: &Detector, input: &str) {
    let decision = detector.evaluate(input, None);
    assert_decision_invariants(detector.rules(), input, &decision);

    let again = detector.evaluate(input, None);
    assert_eq!(
        decision.evaluated_verdict, again.evaluated_verdict,
        "nondeterministic verdict"
    );
    assert_eq!(
        decision.matched_rules, again.matched_rules,
        "nondeterministic matches"
    );
}
