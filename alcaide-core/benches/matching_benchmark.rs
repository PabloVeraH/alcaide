//! Preliminary matching-engine benchmark (milestone M3).
//!
//! ~1000 synthetic literal rules, to sanity-check RNF1 (p99 < 5ms) before
//! investing in curating the real default rule set. This is NOT the final
//! verification: milestone M10 re-measures against the real, curated rule
//! set and publishes the results.

use alcaide_core::{
    Category, Defaults, Matcher, Mode, NormalizedInput, OnError, PatternType, Rule, RuleSet,
    Severity,
};
use criterion::{criterion_group, criterion_main, Criterion};

const SYNTHETIC_RULE_COUNT: usize = 1000;

fn synthetic_rule_set(count: usize) -> RuleSet {
    let rules = (0..count)
        .map(|i| Rule {
            id: format!("synthetic-rule-{i}"),
            category: Category::InjectionGeneric,
            severity: Severity::Medium,
            pattern_type: PatternType::Literal,
            pattern: Some(format!("synthetic-evasion-pattern-{i}")),
            enabled: true,
            notes: None,
        })
        .collect();

    RuleSet {
        version: 1,
        defaults: Defaults {
            mode: Mode::Shadow,
            block_threshold: Severity::High,
            on_error: OnError::Block,
            log_raw_input: false,
        },
        rules,
    }
}

fn bench_matching(c: &mut Criterion) {
    let rule_set = synthetic_rule_set(SYNTHETIC_RULE_COUNT);
    let matcher = Matcher::build(&rule_set).expect("synthetic rule set compiles");

    // Worst case for a pure literal scan: realistic-length prompt, no hits.
    let text = "Could you help me understand how transformer attention mechanisms work \
                in modern large language models, specifically regarding multi-head \
                attention and positional encoding schemes used in practice?";
    let normalized = NormalizedInput {
        original_len: text.len(),
        normalized_text: text.to_string(),
        decode_applied: Vec::new(),
    };

    c.bench_function("match_1000_synthetic_rules_no_hit", |b| {
        b.iter(|| matcher.find_matches(&normalized));
    });
}

criterion_group!(benches, bench_matching);
criterion_main!(benches);
