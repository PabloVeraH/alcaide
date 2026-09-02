//! `alcaide-core` — deterministic rule engine for prompt-injection detection,
//! with no network dependencies (RNF2).
//!
//! See `docs/TRD.md` for the full detection pipeline architecture and
//! `docs/esquema-datos.md` for the exact schema of the public types.
#![forbid(unsafe_code)]

mod config;
mod decision;

pub use config::{Category, Defaults, OnError, PatternType, Rule, RuleSet, Severity};
pub use decision::{Decision, MatchDetail, Mode, Verdict};

use std::path::Path;

/// Main evaluation engine. See `docs/TRD.md` section 4 for the full public
/// API contract.
pub struct Detector {
    #[allow(dead_code)] // used starting at milestone M2 (docs/plan-implementacion.md)
    rules: RuleSet,
    #[allow(dead_code)]
    mode: Mode,
}

/// Error loading or validating a `RuleSet`. See `docs/ui-ux-brief.md`
/// section 2 for the expected message format (exact line/field).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration error: {0}")]
    Invalid(String),
}

impl Detector {
    /// Loads and validates a `RuleSet` from a YAML file.
    ///
    /// Placeholder — parsing and semantic validation are implemented in
    /// milestone M1 (`docs/plan-implementacion.md`).
    pub fn from_config_path(_path: &Path) -> Result<Self, ConfigError> {
        unimplemented!("M1: configuration parsing and semantic validation")
    }

    /// Evaluates an input against the loaded rules and returns an
    /// explainable `Decision`. Never panics on arbitrary input (see
    /// `docs/TRD.md` section 4).
    ///
    /// Placeholder — the normalization/matching/scoring pipeline is
    /// implemented in milestones M2-M4.
    pub fn evaluate(&self, _input: &str) -> Decision {
        unimplemented!("M2-M4: normalization, matching, and scoring pipeline")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_are_exported_and_usable() {
        // Smoke test: confirms the crate compiles and its public surface
        // (docs/TRD.md section 4) is accessible from outside the module.
        let mode = Mode::Shadow;
        assert_eq!(mode, Mode::Shadow);

        let verdict = Verdict::Block;
        assert_ne!(verdict, Verdict::Allow);
    }
}
