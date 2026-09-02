//! Schema of the rule configuration file (`rules.yaml`).

use serde::{Deserialize, Serialize};

/// Root of the `rules.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSet {
    pub version: u32,
    pub defaults: Defaults,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Defaults {
    pub mode: crate::decision::Mode,
    pub block_threshold: Severity,
    #[serde(default)]
    pub on_error: OnError,
}

/// Behavior on internal evaluation failure (design decision: fail-closed
/// by default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    #[default]
    Block,
    Allow,
}

/// A single rule in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern_type: PatternType,
    /// Required if `pattern_type` != `Heuristic` — not validated here yet
    /// (semantic validation is milestone M1's job).
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Jailbreak,
    Exfiltration,
    RoleplayBypass,
    EncodingEvasion,
    InjectionGeneric,
}

/// Declaration order matters: derives `Ord` to compare against
/// `Defaults::block_threshold` (Low < Medium < High < Critical).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    Literal,
    Regex,
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
        let parsed: RuleSet = serde_yaml::from_str(EXAMPLE_YAML).expect("valid YAML");

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
}
