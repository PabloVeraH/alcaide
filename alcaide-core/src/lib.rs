//! `alcaide-core` — deterministic rule engine for prompt-injection detection,
//! with no network dependencies.
#![forbid(unsafe_code)]

mod config;
mod decision;
mod normalize;

pub use config::{Category, Defaults, OnError, PatternType, Rule, RuleSet, Severity};
pub use decision::{Decision, MatchDetail, Mode, Verdict};

use std::path::{Path, PathBuf};

/// Main evaluation engine.
#[derive(Debug)]
pub struct Detector {
    #[allow(dead_code)] // used starting at milestone M2
    rules: RuleSet,
    #[allow(dead_code)]
    mode: Mode,
}

/// Error loading or validating a `RuleSet`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("duplicate rule id '{0}': rule ids must be unique across the rule set")]
    DuplicateRuleId(String),
    #[error(
        "rule '{id}': pattern_type is '{pattern_type:?}' but no pattern was provided \
         (required unless pattern_type is heuristic)"
    )]
    MissingPattern {
        id: String,
        pattern_type: PatternType,
    },
}

impl Detector {
    /// Loads and validates a `RuleSet` from a YAML file.
    pub fn from_config_path(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let rules = RuleSet::from_yaml_str(&contents)?;
        let mode = rules.defaults.mode;

        Ok(Self { rules, mode })
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
