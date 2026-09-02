//! Decision schema and JSON log record.
//!
//! Typed mirror of `docs/esquema-datos.md` section 2 and the runtime
//! decision flow described in `docs/flujo-app.md` (flow A).

use crate::config::{Category, Severity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Shadow,
    Enforcement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Block,
    Flag,
}

/// Result returned by `Detector::evaluate` — see `docs/TRD.md` section 4.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub matched_rules: Vec<MatchDetail>,
    pub latency: Duration,
    pub mode: Mode,
}

/// A single match within a `Decision` — corresponds to the `MatchDetail`
/// object in `docs/esquema-datos.md` section 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetail {
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    /// `(start, end)` offsets in the normalized text, not the raw input.
    pub span: (usize, usize),
}
