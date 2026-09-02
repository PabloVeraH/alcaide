//! Decision schema and JSON log record.

use crate::config::{Category, Severity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Whether a [`Detector`](crate::Detector) actually blocks, or only
/// observes and logs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Always returns `Verdict::Allow` to the caller; the real result is
    /// still logged (`Decision::evaluated_verdict`), for calibrating a
    /// rule set before switching to `Enforcement`.
    Shadow,
    /// Returns the rules' real verdict to the caller.
    Enforcement,
}

/// The outcome of one evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No match at or above the configured block threshold.
    Allow,
    /// A match at or above the configured block threshold.
    Block,
    /// A match below the block threshold -- worth a human's attention,
    /// not severe enough to block on its own.
    Flag,
}

/// Result returned by [`Detector::evaluate`](crate::Detector::evaluate).
#[derive(Debug, Clone)]
pub struct Decision {
    /// The verdict actually enforced for the caller. In `Shadow` mode this
    /// is always `Allow`, regardless of what the rules found -- see
    /// `evaluated_verdict`.
    pub verdict: Verdict,
    /// What the rules determined, before any mode adjustment. Equals
    /// `verdict` in `Enforcement` mode; in `Shadow` mode this carries what
    /// enforcement *would have* done, while `verdict` itself stays `Allow`.
    /// This is the field the structured log record uses, so it reflects
    /// reality even in shadow mode.
    pub evaluated_verdict: Verdict,
    /// Every rule that matched, in no particular order. Empty for
    /// `Verdict::Allow` (except when the pipeline failed and fail-open
    /// was configured, in which case it's also empty).
    pub matched_rules: Vec<MatchDetail>,
    /// Wall-clock time spent evaluating, excluding log emission.
    pub latency: Duration,
    /// The mode this evaluation ran under.
    pub mode: Mode,
}

/// A single match within a [`Decision`], enriched with the matched rule's
/// own category and severity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetail {
    /// The id of the [`Rule`](crate::Rule) that matched.
    pub rule_id: String,
    /// Copied from the matched rule, so a log line is self-contained
    /// without cross-referencing the rule set.
    pub category: Category,
    /// Copied from the matched rule, so a log line is self-contained
    /// without cross-referencing the rule set.
    pub severity: Severity,
    /// `(start, end)` byte offsets in the normalized text, not the raw
    /// input.
    pub span: (usize, usize),
}
