//! Decision schema and JSON log record.

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

/// Result returned by `Detector::evaluate`.
#[derive(Debug, Clone)]
pub struct Decision {
    /// The verdict actually enforced for the caller. In `Shadow` mode this
    /// is always `Allow`, regardless of what the rules found -- see
    /// `evaluated_verdict`.
    pub verdict: Verdict,
    /// What the rules determined, before any mode adjustment. Equals
    /// `verdict` in `Enforcement` mode; in `Shadow` mode this carries what
    /// enforcement *would have* done, while `verdict` itself stays `Allow`.
    /// This is the field a structured logger (milestone M5) should record
    /// to calibrate before switching to enforcement.
    pub evaluated_verdict: Verdict,
    pub matched_rules: Vec<MatchDetail>,
    pub latency: Duration,
    pub mode: Mode,
}

/// A single match within a `Decision`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetail {
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    /// `(start, end)` offsets in the normalized text, not the raw input.
    pub span: (usize, usize),
}
