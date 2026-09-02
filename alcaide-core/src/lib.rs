//! `alcaide-core` — deterministic rule engine for prompt-injection detection,
//! with no network dependencies.
#![forbid(unsafe_code)]

mod config;
mod decision;

pub use config::{Category, Defaults, OnError, PatternType, Rule, RuleSet, Severity};
pub use decision::{Decision, MatchDetail, Mode, Verdict};

use std::path::Path;

/// Main evaluation engine.
pub struct Detector {
    #[allow(dead_code)] // used starting at milestone M2
    rules: RuleSet,
    #[allow(dead_code)]
    mode: Mode,
}

/// Error loading or validating a `RuleSet`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration error: {0}")]
    Invalid(String),
}

impl Detector {
    /// Loads and validates a `RuleSet` from a YAML file.
    ///
    /// Placeholder — parsing and semantic validation are implemented in
    /// milestone M1.
    pub fn from_config_path(_path: &Path) -> Result<Self, ConfigError> {
        unimplemented!("M1: configuration parsing and semantic validation")
    }

    /// Evaluates an input against the loaded rules and returns an
    /// explainable `Decision`. Never panics on arbitrary input.
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
        // is accessible from outside the module.
        let mode = Mode::Shadow;
        assert_eq!(mode, Mode::Shadow);

        let verdict = Verdict::Block;
        assert_ne!(verdict, Verdict::Allow);
    }
}
