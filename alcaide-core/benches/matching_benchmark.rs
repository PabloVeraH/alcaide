//! Matching-engine scalability benchmark: ~1000 synthetic literal rules,
//! to check the matcher alone stays fast as a rule set grows. For the
//! end-to-end numbers against the real rule set, see
//! `real_rules_benchmark.rs`.

use alcaide_core::{normalize, Category, Defaults, Matcher, PatternType, Rule, RuleSet, Severity};
use criterion::{criterion_group, criterion_main, Criterion};

const SYNTHETIC_RULE_COUNT: usize = 1000;

fn synthetic_rule_set(count: usize) -> RuleSet {
    let rules = (0..count)
        .map(|i| Rule {
            id: format!("synthetic-rule-{i}"),
            category: Category::InjectionGeneric,
            severity: Severity::Medium,
            pattern_type: PatternType::Literal,
            pattern: format!("synthetic-evasion-pattern-{i}"),
            enabled: true,
            notes: None,
        })
        .collect();

    RuleSet {
        version: 1,
        defaults: Defaults::default(),
        rules,
    }
}

fn bench_matching(c: &mut Criterion) {
    let rule_set = synthetic_rule_set(SYNTHETIC_RULE_COUNT);
    let matcher = Matcher::build(&rule_set).expect("synthetic rule set compiles");

    // Worst case for a pure literal scan: realistic-length prompt, no hits.
    let normalized = normalize(
        "Could you help me understand how transformer attention mechanisms work \
         in modern large language models, specifically regarding multi-head \
         attention and positional encoding schemes used in practice?",
    );

    c.bench_function("match_1000_synthetic_rules_no_hit", |b| {
        b.iter(|| matcher.find_matches(&normalized));
    });
}

fn bench_normalization(c: &mut Criterion) {
    // The normalization stage alone, on ~30KB of mostly-ASCII prose: the
    // per-character work every evaluation pays before matching starts.
    let paragraph = "Résumé of the quarterly meeting: the team reviewed the roadmap, \
                     discussed latency budgets and agreed on next steps. ";
    let text = paragraph.repeat(31_000 / paragraph.len());

    c.bench_function("normalize_30kb", |b| {
        b.iter(|| normalize(&text));
    });
}

criterion_group!(benches, bench_matching, bench_normalization);
criterion_main!(benches);
