//! Arbitrary rule sets built in code (so every case reaches the pattern
//! compiler, unlike raw YAML): building never panics, evaluation upholds
//! every guarantee, and an accepted literal pattern always matches its
//! own text.

#![no_main]

use alcaide_core::{
    Category, Defaults, Detector, Mode, OnError, OnOversize, PatternType, Rule, RuleSet, Severity,
};
use alcaide_fuzz::check_evaluate;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Case {
    rules: Vec<FuzzRule>,
    enforcement: bool,
    block_threshold: u8,
    oversize_flag: bool,
    max_input_bytes: u16,
    input: String,
}

#[derive(Debug, Arbitrary)]
struct FuzzRule {
    kind: u8,
    pattern: String,
    severity: u8,
    enabled: bool,
}

fn severity(n: u8) -> Severity {
    [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ][usize::from(n % 4)]
}

fuzz_target!(|case: Case| {
    let rules: Vec<Rule> = case
        .rules
        .into_iter()
        .take(16)
        .enumerate()
        .map(|(i, rule)| Rule {
            id: format!("r{i}"),
            category: Category::InjectionGeneric,
            severity: severity(rule.severity),
            pattern_type: match rule.kind % 8 {
                0..=3 => PatternType::Literal,
                4..=6 => PatternType::Regex,
                _ => PatternType::Heuristic,
            },
            pattern: rule.pattern,
            enabled: rule.enabled,
            notes: None,
        })
        .collect();
    let rule_set = RuleSet {
        version: alcaide_core::SUPPORTED_VERSION,
        defaults: Defaults {
            mode: if case.enforcement {
                Mode::Enforcement
            } else {
                Mode::Shadow
            },
            block_threshold: severity(case.block_threshold),
            on_error: OnError::Block,
            log_raw_input: false,
            max_input_bytes: usize::from(case.max_input_bytes),
            on_oversize: if case.oversize_flag {
                OnOversize::Flag
            } else {
                OnOversize::Block
            },
        },
        rules,
    };

    let Ok(detector) = Detector::new(rule_set) else {
        return;
    };
    check_evaluate(&detector, &case.input);

    // A literal rule must find its own pattern, alone or between spaces.
    let max = detector.rules().defaults.max_input_bytes;
    for rule in &detector.rules().rules {
        if rule.pattern_type != PatternType::Literal || !rule.enabled {
            continue;
        }
        for text in [rule.pattern.clone(), format!(" {} ", rule.pattern)] {
            if text.len() > max {
                continue;
            }
            let decision = detector.evaluate(&text, None);
            assert!(
                decision.matched_rules.iter().any(|m| m.rule_id == rule.id),
                "literal rule {} ({:?}) does not match its own text {text:?}",
                rule.id,
                rule.pattern
            );
        }
    }
});
