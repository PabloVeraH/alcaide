//! `Detector::evaluate` on arbitrary input, with the default rule set:
//! never panics, and every documented guarantee about the `Decision`
//! holds (see `alcaide_fuzz::assert_decision_invariants`).

#![no_main]

use alcaide_core::{Detector, Mode, OnOversize, RuleSet, DEFAULT_RULES_YAML};
use alcaide_fuzz::check_evaluate;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The default rules in enforcement mode, plus a copy with a tiny input
/// limit so short fuzz inputs also exercise the oversize path (with the
/// non-default `flag` floor, so both floors are covered).
fn detectors() -> &'static [Detector; 2] {
    static DETECTORS: OnceLock<[Detector; 2]> = OnceLock::new();
    DETECTORS.get_or_init(|| {
        let mut rules = RuleSet::from_yaml_str(DEFAULT_RULES_YAML).expect("default rules load");
        rules.defaults.mode = Mode::Enforcement;
        let mut small = rules.clone();
        small.defaults.max_input_bytes = 48;
        small.defaults.on_oversize = OnOversize::Flag;
        [
            Detector::new(rules).expect("valid"),
            Detector::new(small).expect("valid"),
        ]
    })
}

fuzz_target!(|input: &str| {
    for detector in detectors() {
        check_evaluate(detector, input);
    }
});
