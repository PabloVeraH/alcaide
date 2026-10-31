//! Schema of the rule configuration file (`rules.yaml`).

use serde::{Deserialize, Serialize};

/// The only `RuleSet::version` this release understands.
pub const SUPPORTED_VERSION: u32 = 1;

/// Root of the `rules.yaml` file.
///
/// Unknown fields are rejected everywhere in the file: in a security
/// config, a typo like `enabeld: false` or `on_eror: allow` must fail
/// loudly rather than be silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// Schema version of this file, for future migrations. Must equal
    /// [`SUPPORTED_VERSION`].
    pub version: u32,
    /// Global settings applied to every evaluation using this rule set.
    pub defaults: Defaults,
    /// The rule catalog. Order does not affect evaluation.
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Parses and semantically validates a `RuleSet` from a YAML string.
    ///
    /// A file with `extends: default` starts from the curated default rules
    /// ([`DEFAULT_RULES_YAML`](crate::DEFAULT_RULES_YAML)), drops the ids
    /// listed under `disable`, and adds its own `rules`; its `defaults`
    /// apply as written. The result holds the combined rules.
    ///
    /// This checks the file itself; patterns are compiled (and checked
    /// further) when a [`Detector`](crate::Detector) is built from it.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, crate::ConfigError> {
        let file: RuleFile = serde_saphyr::from_str(yaml)?;
        let parsed = file.resolve()?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Semantic validation that can't be expressed through serde alone:
    /// a supported `version`, a non-zero `max_input_bytes`, and non-empty,
    /// unique rule ids and non-blank patterns.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        use crate::ConfigError;

        if self.version != SUPPORTED_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.version,
                supported: SUPPORTED_VERSION,
            });
        }

        if self.defaults.max_input_bytes == 0 {
            // Would truncate every input to nothing: nothing inspected,
            // everything blocked (or flagged).
            return Err(ConfigError::ZeroMaxInputBytes);
        }

        let mut seen_ids = std::collections::HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err(ConfigError::EmptyRuleId);
            }
            if !seen_ids.insert(rule.id.as_str()) {
                return Err(ConfigError::DuplicateRuleId(rule.id.clone()));
            }
            if rule.pattern.trim().is_empty() {
                return Err(ConfigError::BlankPattern(rule.id.clone()));
            }
        }

        Ok(())
    }
}

/// A rule file as written: a [`RuleSet`] that may build on another rule
/// set instead of copying it, so it keeps receiving that set's updates.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    version: u32,
    #[serde(default)]
    extends: Option<BaseRuleSet>,
    #[serde(default)]
    disable: Vec<String>,
    defaults: Defaults,
    #[serde(default)]
    rules: Vec<Rule>,
}

/// A rule set a file can `extends`.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum BaseRuleSet {
    /// The curated default rule set.
    Default,
}

impl RuleFile {
    fn resolve(self) -> Result<RuleSet, crate::ConfigError> {
        use crate::ConfigError;

        let mut rules = match self.extends {
            None if !self.disable.is_empty() => return Err(ConfigError::DisableWithoutExtends),
            None => Vec::new(),
            Some(BaseRuleSet::Default) => {
                let mut base = RuleSet::from_yaml_str(crate::DEFAULT_RULES_YAML)?.rules;
                for id in &self.disable {
                    let before = base.len();
                    base.retain(|rule| &rule.id != id);
                    if base.len() == before {
                        return Err(ConfigError::UnknownDisabledRule(id.clone()));
                    }
                }
                base
            }
        };
        rules.extend(self.rules);

        Ok(RuleSet {
            version: self.version,
            defaults: self.defaults,
            rules,
        })
    }
}

/// Global settings for a [`RuleSet`]: mode, blocking threshold, and error
/// behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Never enabled implicitly -- see the logging module's privacy tests.
    #[serde(default)]
    pub log_raw_input: bool,
    /// Inputs longer than this many bytes are only inspected up to this
    /// length (bounding worst-case evaluation cost), and `on_oversize`
    /// decides the minimum verdict for them. Defaults to 1,000,000 (1 MB),
    /// which takes tens of milliseconds to inspect: a whole document fits.
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: usize,
    /// Minimum verdict for an input longer than `max_input_bytes`, whose
    /// tail could not be inspected. Defaults to `Block` (fail-closed).
    #[serde(default)]
    pub on_oversize: OnOversize,
}

impl Default for Defaults {
    /// The same values the shipped default rule set uses: shadow mode,
    /// block at `high`, fail-closed everywhere, raw input never logged.
    fn default() -> Self {
        Self {
            mode: crate::decision::Mode::Shadow,
            block_threshold: Severity::High,
            on_error: OnError::default(),
            log_raw_input: false,
            max_input_bytes: default_max_input_bytes(),
            on_oversize: OnOversize::default(),
        }
    }
}

fn default_max_input_bytes() -> usize {
    1_000_000
}

/// What to do with an input longer than `Defaults::max_input_bytes`.
///
/// Its first `max_input_bytes` are always inspected, and any match there
/// counts as usual; this policy is the *floor* applied on top, because an
/// attacker controls what sits in the uninspected tail.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnOversize {
    /// Fail-closed (default): an input that can't be fully inspected is
    /// blocked. Padding a payload past the limit can't sneak it through.
    #[default]
    Block,
    /// Flag it for review and let it through, unless the inspected part
    /// already warrants a block. Choose this only if long inputs are
    /// expected and a human reviews flags -- a payload placed past the
    /// limit is *not* detected.
    Flag,
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
#[serde(deny_unknown_fields)]
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
    /// The literal text, the regular expression, or the heuristic's name,
    /// depending on `pattern_type`. Required for every rule.
    pub pattern: String,
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
        // just serde_saphyr::from_str, so this also guards against a valid
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
        assert_eq!(encoding_rule.pattern, "base64_suspicious");
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

    /// A minimal valid file with `extra_defaults` spliced into `defaults`
    /// and a single rule made of `rule_body` (YAML mapping lines).
    fn yaml_with(extra_defaults: &str, rule_body: &str) -> String {
        format!(
            "version: 1\ndefaults:\n  mode: shadow\n  block_threshold: high\n{extra_defaults}\
             rules:\n  - id: rule-1\n    category: jailbreak\n    severity: high\n{rule_body}"
        )
    }

    const LITERAL_BODY: &str = "    pattern_type: literal\n    pattern: \"foo\"\n";

    #[test]
    fn the_test_template_is_itself_valid() {
        assert!(RuleSet::from_yaml_str(&yaml_with("", LITERAL_BODY)).is_ok());
    }

    #[test]
    fn rejects_a_rule_missing_its_pattern_whatever_its_type() {
        // Regression: a heuristic rule without a pattern passed validation
        // but then failed when the Detector was built -- now every rule
        // needs one, consistently, at parse time.
        for pattern_type in ["literal", "regex", "heuristic"] {
            let yaml = yaml_with("", &format!("    pattern_type: {pattern_type}\n"));

            let result = RuleSet::from_yaml_str(&yaml);

            assert!(
                matches!(result, Err(crate::ConfigError::Parse(_))),
                "{pattern_type}: expected a parse error, got {result:?}"
            );
        }
    }

    #[test]
    fn rejects_a_blank_pattern() {
        for blank in ["\"\"", "\"   \""] {
            let yaml = yaml_with(
                "",
                &format!("    pattern_type: literal\n    pattern: {blank}\n"),
            );

            let result = RuleSet::from_yaml_str(&yaml);

            assert!(
                matches!(&result, Err(crate::ConfigError::BlankPattern(id)) if id == "rule-1"),
                "pattern {blank}: got {result:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        // Regression: typos were silently ignored -- `enabeld: false` left
        // the rule enabled, `on_eror: allow` left fail-closed in place, and
        // nobody was told.
        let typo_in_rule = yaml_with("", &format!("{LITERAL_BODY}    enabeld: false\n"));
        let typo_in_defaults = yaml_with("  on_eror: allow\n", LITERAL_BODY);
        let typo_at_root = format!("{}extra_key: 1\n", yaml_with("", LITERAL_BODY));

        for yaml in [typo_in_rule, typo_in_defaults, typo_at_root] {
            let result = RuleSet::from_yaml_str(&yaml);

            match result {
                Err(crate::ConfigError::Parse(error)) => {
                    assert!(error.to_string().contains("unknown field"), "{error}");
                }
                other => panic!("expected an unknown-field error, got {other:?}"),
            }
        }
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let yaml = yaml_with("", LITERAL_BODY).replacen("version: 1", "version: 2", 1);

        let result = RuleSet::from_yaml_str(&yaml);

        assert!(matches!(
            result,
            Err(crate::ConfigError::UnsupportedVersion {
                found: 2,
                supported: SUPPORTED_VERSION
            })
        ));
    }

    #[test]
    fn rejects_zero_max_input_bytes() {
        let yaml = yaml_with("  max_input_bytes: 0\n", LITERAL_BODY);

        let result = RuleSet::from_yaml_str(&yaml);

        assert!(matches!(result, Err(crate::ConfigError::ZeroMaxInputBytes)));
    }

    #[test]
    fn rejects_an_empty_rule_id() {
        let yaml = yaml_with("", LITERAL_BODY).replacen("id: rule-1", "id: \"  \"", 1);

        let result = RuleSet::from_yaml_str(&yaml);

        assert!(matches!(result, Err(crate::ConfigError::EmptyRuleId)));
    }

    #[test]
    fn oversize_settings_parse_and_default_to_fail_closed() {
        let defaulted = RuleSet::from_yaml_str(&yaml_with("", LITERAL_BODY)).expect("valid");
        let explicit = RuleSet::from_yaml_str(&yaml_with(
            "  max_input_bytes: 1000\n  on_oversize: flag\n",
            LITERAL_BODY,
        ))
        .expect("valid");

        assert_eq!(defaulted.defaults.max_input_bytes, 1_000_000);
        assert_eq!(defaulted.defaults.on_oversize, OnOversize::Block);
        assert_eq!(explicit.defaults.max_input_bytes, 1000);
        assert_eq!(explicit.defaults.on_oversize, OnOversize::Flag);
    }

    // --- extends / disable ---

    fn default_rule_ids() -> Vec<String> {
        RuleSet::from_yaml_str(crate::DEFAULT_RULES_YAML)
            .expect("valid default rules")
            .rules
            .into_iter()
            .map(|rule| rule.id)
            .collect()
    }

    /// `yaml_with`'s single rule on top of the default rules.
    fn extending(extra: &str) -> String {
        yaml_with("", LITERAL_BODY).replacen(
            "version: 1\n",
            &format!("version: 1\nextends: default\n{extra}"),
            1,
        )
    }

    #[test]
    fn extends_default_adds_own_rules_and_settings_to_the_default_rules() {
        let yaml = extending("").replacen("mode: shadow", "mode: enforcement", 1);

        let parsed = RuleSet::from_yaml_str(&yaml).expect("valid");

        let mut expected = default_rule_ids();
        expected.push("rule-1".to_string());
        let ids: Vec<_> = parsed.rules.iter().map(|rule| rule.id.clone()).collect();
        assert_eq!(ids, expected);
        assert_eq!(parsed.defaults.mode, crate::decision::Mode::Enforcement);
    }

    #[test]
    fn disable_drops_default_rules_and_frees_their_id() {
        let dropped = &default_rule_ids()[0];
        // Redefining a disabled rule under its own id is how one is changed.
        let yaml = extending(&format!("disable: [{dropped}]\n")).replacen(
            "id: rule-1",
            &format!("id: {dropped}"),
            1,
        );

        let parsed = RuleSet::from_yaml_str(&yaml).expect("valid");

        assert_eq!(parsed.rules.len(), default_rule_ids().len());
        let redefined: Vec<_> = parsed.rules.iter().filter(|r| &r.id == dropped).collect();
        assert_eq!(redefined.len(), 1);
        assert_eq!(redefined[0].pattern, "foo");
    }

    #[test]
    fn disabling_an_unknown_rule_is_an_error() {
        // A typo must not leave the rule it meant to disable running.
        let yaml = extending("disable: [no-such-rule]\n");

        let result = RuleSet::from_yaml_str(&yaml);

        assert!(
            matches!(&result, Err(crate::ConfigError::UnknownDisabledRule(id)) if id == "no-such-rule"),
            "{result:?}"
        );
    }

    #[test]
    fn disable_without_extends_is_an_error() {
        let yaml = yaml_with("", LITERAL_BODY).replacen(
            "version: 1\n",
            "version: 1\ndisable: [rule-1]\n",
            1,
        );

        let result = RuleSet::from_yaml_str(&yaml);

        assert!(matches!(
            result,
            Err(crate::ConfigError::DisableWithoutExtends)
        ));
    }

    #[test]
    fn extends_only_accepts_a_known_rule_set() {
        let yaml = extending("").replacen("extends: default", "extends: ./other.yaml", 1);

        assert!(matches!(
            RuleSet::from_yaml_str(&yaml),
            Err(crate::ConfigError::Parse(_))
        ));
    }

    #[test]
    fn an_extending_file_needs_no_rules_of_its_own() {
        let yaml = "version: 1\nextends: default\ndefaults:\n  mode: enforcement\n  block_threshold: high\n";

        let parsed = RuleSet::from_yaml_str(yaml).expect("valid");

        assert_eq!(parsed.rules.len(), default_rule_ids().len());
    }
}
