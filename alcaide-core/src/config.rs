//! Schema of the rule configuration file (`rules.yaml`).

use serde::{Deserialize, Serialize};

/// Root of the `rules.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSet {
    /// Schema version of this file, for future migrations.
    pub version: u32,
    /// Global settings applied to every evaluation using this rule set.
    pub defaults: Defaults,
    /// The rule catalog. Order does not affect evaluation.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Parses and semantically validates a `RuleSet` from a YAML string.
    /// Covers RF2 (the rule set is defined in an external, human-editable
    /// file, updatable without recompiling the binary).
    pub fn from_yaml_str(yaml: &str) -> Result<Self, crate::ConfigError> {
        let parsed: RuleSet = serde_yaml::from_str(yaml)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Semantic validation that can't be expressed through serde alone:
    /// rule ids must be unique, and a `pattern` is required unless
    /// `pattern_type` is `Heuristic`.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let mut seen_ids = std::collections::HashSet::with_capacity(self.rules.len());

        for rule in &self.rules {
            if !seen_ids.insert(rule.id.as_str()) {
                return Err(crate::ConfigError::DuplicateRuleId(rule.id.clone()));
            }

            if rule.pattern_type != PatternType::Heuristic && rule.pattern.is_none() {
                return Err(crate::ConfigError::MissingPattern {
                    id: rule.id.clone(),
                    pattern_type: rule.pattern_type,
                });
            }
        }

        Ok(())
    }
}

/// Global settings for a [`RuleSet`]: mode, blocking threshold, and error
/// behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Defaults {
    /// `shadow` logs the real verdict but always returns `Allow` to the
    /// caller; `enforcement` returns the real verdict.
    pub mode: crate::decision::Mode,
    /// Minimum matched severity that produces a `Block` verdict; matches
    /// below this threshold produce `Flag` instead.
    pub block_threshold: Severity,
    /// Verdict to return if the pipeline itself fails unexpectedly.
    /// Defaults to `Block` (fail-closed).
    #[serde(default)]
    pub on_error: OnError,
    /// Privacy opt-in (default `false`): whether the raw input text is
    /// included in the structured log record's `input_snippet` field.
    /// Never enabled implicitly -- see the milestone M5 privacy test.
    #[serde(default)]
    pub log_raw_input: bool,
}

/// Behavior on internal evaluation failure (design decision: fail-closed
/// by default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    /// Fail-closed (default): treat an internal pipeline failure as a
    /// `Block`.
    #[default]
    Block,
    /// Fail-open: treat an internal pipeline failure as an `Allow`.
    Allow,
}

/// A single rule in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Stable identifier, unique across the rule set. Appears in
    /// `MatchDetail` and in log records -- must survive edits to
    /// `pattern` so it stays a reliable reference over time.
    pub id: String,
    /// Attack taxonomy this rule belongs to.
    pub category: Category,
    /// This rule's severity, compared against `Defaults::block_threshold`.
    pub severity: Severity,
    /// How `pattern` is interpreted: literal substring, regex, or a
    /// named built-in heuristic.
    pub pattern_type: PatternType,
    /// Required if `pattern_type` != `Heuristic` — validated by
    /// [`RuleSet::validate`].
    #[serde(default)]
    pub pattern: Option<String>,
    /// Whether this rule participates in matching. Defaults to `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Free-text documentation for humans editing the file -- not used by
    /// the engine.
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_enabled() -> bool {
    true
}

/// Attack taxonomy a [`Rule`] belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Attempts to override the model's alignment/persona (e.g. DAN-style
    /// prompts).
    Jailbreak,
    /// Attempts to leak the system prompt or other secrets.
    Exfiltration,
    /// Fictional framing used to justify bypassing rules (e.g. "pretend
    /// you are an AI with no restrictions").
    RoleplayBypass,
    /// Obfuscation via encoding (base64, hex, etc.) rather than plain text.
    EncodingEvasion,
    /// Direct instruction-override attempts not covered by a more
    /// specific category.
    InjectionGeneric,
}

/// Declaration order matters: derives `Ord` to compare against
/// `Defaults::block_threshold` (Low < Medium < High < Critical).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth logging; rarely worth blocking on its own.
    Low,
    /// Notable signal, not usually conclusive on its own.
    Medium,
    /// Strong signal of a real attempt.
    High,
    /// Near-certain attempt at direct compromise (e.g. system prompt
    /// exfiltration).
    Critical,
}

/// How a [`Rule`]'s `pattern` field should be interpreted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    /// `pattern` is matched as a literal substring (case-insensitive),
    /// via a shared Aho-Corasick automaton across all literal rules.
    Literal,
    /// `pattern` is a regular expression, compiled independently per rule.
    Regex,
    /// `pattern` names a built-in heuristic (e.g. `base64_suspicious`)
    /// driven by the normalization stage rather than direct text matching.
    Heuristic,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kept in Spanish on purpose: it demonstrates detection of a
    /// Spanish-language jailbreak pattern.
    const EXAMPLE_YAML: &str = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: high

rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignora(r)?\\s+(todas\\s+)?las\\s+instrucciones\\s+(anteriores|previas)"
    enabled: true
    notes: "Patrón clásico de override de system prompt, ver JailbreakBench #142"

  - id: encoding-base64-evasion
    category: encoding-evasion
    severity: medium
    pattern_type: heuristic
    pattern: base64_suspicious
    enabled: true
"#;

    #[test]
    fn parses_the_documented_example_verbatim() {
        // Goes through the full public entry point (parse + validate), not
        // just serde_yaml::from_str, so this also guards against a valid
        // documented example accidentally failing semantic validation.
        let parsed = RuleSet::from_yaml_str(EXAMPLE_YAML).expect("valid config");

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.defaults.mode, crate::decision::Mode::Shadow);
        assert_eq!(parsed.defaults.block_threshold, Severity::High);
        assert_eq!(parsed.defaults.on_error, OnError::Block); // default applied
        assert_eq!(parsed.rules.len(), 2);

        let jailbreak_rule = &parsed.rules[0];
        assert_eq!(jailbreak_rule.id, "jailbreak-ignore-instructions");
        assert_eq!(jailbreak_rule.category, Category::Jailbreak);
        assert_eq!(jailbreak_rule.pattern_type, PatternType::Regex);
        assert!(jailbreak_rule.enabled);

        let encoding_rule = &parsed.rules[1];
        assert_eq!(encoding_rule.pattern_type, PatternType::Heuristic);
        assert_eq!(encoding_rule.pattern.as_deref(), Some("base64_suspicious"));
    }

    #[test]
    fn severity_ordering_matches_documented_scale() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn rejects_malformed_yaml_syntax() {
        let broken = "version: 1\ndefaults: [this is not a mapping";

        let result = RuleSet::from_yaml_str(broken);

        assert!(matches!(result, Err(crate::ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_unknown_severity_value() {
        let invalid = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: extreme
rules: []
"#;

        let result = RuleSet::from_yaml_str(invalid);

        // Invalid enum discriminants are caught by serde itself at parse
        // time, before our own semantic validation ever runs.
        assert!(matches!(result, Err(crate::ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let duplicated = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: high
rules:
  - id: same-id
    category: jailbreak
    severity: high
    pattern_type: literal
    pattern: "foo"
  - id: same-id
    category: jailbreak
    severity: low
    pattern_type: literal
    pattern: "bar"
"#;

        let result = RuleSet::from_yaml_str(duplicated);

        match result {
            Err(crate::ConfigError::DuplicateRuleId(id)) => assert_eq!(id, "same-id"),
            other => panic!("expected DuplicateRuleId, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_heuristic_rule_missing_pattern() {
        let missing_pattern = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: high
rules:
  - id: incomplete-rule
    category: jailbreak
    severity: high
    pattern_type: regex
"#;

        let result = RuleSet::from_yaml_str(missing_pattern);

        match result {
            Err(crate::ConfigError::MissingPattern { id, pattern_type }) => {
                assert_eq!(id, "incomplete-rule");
                assert_eq!(pattern_type, PatternType::Regex);
            }
            other => panic!("expected MissingPattern, got {other:?}"),
        }
    }

    #[test]
    fn allows_heuristic_rule_without_pattern() {
        let heuristic_only = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: high
rules:
  - id: heuristic-rule
    category: encoding-evasion
    severity: medium
    pattern_type: heuristic
"#;

        let result = RuleSet::from_yaml_str(heuristic_only);

        assert!(result.is_ok());
    }
}
