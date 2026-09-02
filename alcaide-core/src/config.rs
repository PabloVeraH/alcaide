//! Esquema del archivo de configuración de reglas (`rules.yaml`).
//!
//! Espejo tipado de `docs/esquema-datos.md` sección 1 — cualquier cambio de
//! campo debe reflejarse en ambos lugares.

use serde::{Deserialize, Serialize};

/// Raíz del archivo `rules.yaml`. Ver `docs/esquema-datos.md` sección 1.
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

/// Comportamiento ante fallo interno de evaluación — ver `docs/TRD.md` sección 5
/// (decisión de diseño: fail-closed por defecto).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnError {
    #[default]
    Block,
    Allow,
}

/// Una regla individual del catálogo. Ver `docs/esquema-datos.md` sección 1
/// y `docs/ui-ux-brief.md` sección 2 para el formato editado por humanos.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub pattern_type: PatternType,
    /// Obligatorio si `pattern_type` != `Heuristic` — no se valida aquí todavía
    /// (validación semántica post-parsing es trabajo del hito M1).
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

/// El orden de declaración importa: deriva `Ord` para poder comparar contra
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

    /// Fixture tomado literalmente de `docs/ui-ux-brief.md` sección 2 — si este
    /// test falla, la documentación y el esquema real se desincronizaron.
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
        let parsed: RuleSet = serde_yaml::from_str(EXAMPLE_YAML).expect("YAML válido");

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.defaults.mode, crate::decision::Mode::Shadow);
        assert_eq!(parsed.defaults.block_threshold, Severity::High);
        assert_eq!(parsed.defaults.on_error, OnError::Block); // default aplicado
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
