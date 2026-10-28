//! Python bindings for Alcaide, mirroring the Rust API (`alcaide-core`):
//! `Detector`, `Decision`, `Verdict`, `Mode`, `MatchDetail`.
//!
//! Kept as a thin translation layer -- all real logic lives in
//! `alcaide-core`; this crate only converts between Rust and Python types
//! and maps errors to Python exceptions. The Python-facing signatures are
//! declared for type checkers in `alcaide.pyi`; keep both in sync.

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::path::Path;

#[pyclass(name = "Verdict", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
enum PyVerdict {
    Allow,
    Block,
    Flag,
}

impl From<alcaide_core::Verdict> for PyVerdict {
    fn from(v: alcaide_core::Verdict) -> Self {
        match v {
            alcaide_core::Verdict::Allow => Self::Allow,
            alcaide_core::Verdict::Block => Self::Block,
            alcaide_core::Verdict::Flag => Self::Flag,
        }
    }
}

#[pyclass(name = "Mode", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
enum PyMode {
    Shadow,
    Enforcement,
}

impl From<alcaide_core::Mode> for PyMode {
    fn from(m: alcaide_core::Mode) -> Self {
        match m {
            alcaide_core::Mode::Shadow => Self::Shadow,
            alcaide_core::Mode::Enforcement => Self::Enforcement,
        }
    }
}

#[pyclass(name = "Category", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
enum PyCategory {
    Jailbreak,
    Exfiltration,
    RoleplayBypass,
    EncodingEvasion,
    InjectionGeneric,
}

impl From<alcaide_core::Category> for PyCategory {
    fn from(c: alcaide_core::Category) -> Self {
        match c {
            alcaide_core::Category::Jailbreak => Self::Jailbreak,
            alcaide_core::Category::Exfiltration => Self::Exfiltration,
            alcaide_core::Category::RoleplayBypass => Self::RoleplayBypass,
            alcaide_core::Category::EncodingEvasion => Self::EncodingEvasion,
            alcaide_core::Category::InjectionGeneric => Self::InjectionGeneric,
        }
    }
}

#[pyclass(name = "Severity", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum PySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<alcaide_core::Severity> for PySeverity {
    fn from(s: alcaide_core::Severity) -> Self {
        match s {
            alcaide_core::Severity::Low => Self::Low,
            alcaide_core::Severity::Medium => Self::Medium,
            alcaide_core::Severity::High => Self::High,
            alcaide_core::Severity::Critical => Self::Critical,
        }
    }
}

/// One rule that matched, enriched with its category/severity.
#[pyclass(name = "MatchDetail", get_all, frozen)]
#[derive(Clone)]
struct PyMatchDetail {
    rule_id: String,
    category: PyCategory,
    severity: PySeverity,
    span: (usize, usize),
}

impl PyMatchDetail {
    /// Converts a core match, whose span is in UTF-8 bytes of `input`, to
    /// Python's view, where `input[start:end]` indexes characters.
    fn new(m: alcaide_core::MatchDetail, input: &str) -> Self {
        let chars_before = |byte: usize| input.get(..byte).map_or(0, |s| s.chars().count());
        Self {
            rule_id: m.rule_id,
            category: m.category.into(),
            severity: m.severity.into(),
            span: (chars_before(m.span.0), chars_before(m.span.1)),
        }
    }
}

#[pymethods]
impl PyMatchDetail {
    fn __repr__(&self) -> String {
        format!(
            "MatchDetail(rule_id={:?}, category=Category.{:?}, severity=Severity.{:?}, span={:?})",
            self.rule_id,
            alcaide_core::Category::from(self.category),
            alcaide_core::Severity::from(self.severity),
            self.span
        )
    }
}

/// Result of one `Detector.evaluate` call.
#[pyclass(name = "Decision", get_all, frozen)]
struct PyDecision {
    verdict: PyVerdict,
    evaluated_verdict: PyVerdict,
    matched_rules: Vec<PyMatchDetail>,
    latency_us: u64,
    mode: PyMode,
    input_truncated: bool,
}

impl PyDecision {
    fn new(d: alcaide_core::Decision, input: &str) -> Self {
        Self {
            verdict: d.verdict.into(),
            evaluated_verdict: d.evaluated_verdict.into(),
            matched_rules: d
                .matched_rules
                .into_iter()
                .map(|m| PyMatchDetail::new(m, input))
                .collect(),
            latency_us: u64::try_from(d.latency.as_micros()).unwrap_or(u64::MAX),
            mode: d.mode.into(),
            input_truncated: d.input_truncated,
        }
    }
}

#[pymethods]
impl PyDecision {
    fn __repr__(&self) -> String {
        format!(
            "Decision(verdict=Verdict.{:?}, evaluated_verdict=Verdict.{:?}, matched_rules={}, \
             mode=Mode.{:?}, input_truncated={}, latency_us={})",
            alcaide_core::Verdict::from(self.verdict),
            alcaide_core::Verdict::from(self.evaluated_verdict),
            self.matched_rules.len(),
            alcaide_core::Mode::from(self.mode),
            if self.input_truncated {
                "True"
            } else {
                "False"
            },
            self.latency_us
        )
    }
}

/// The rule engine. Build it once (it's immutable and thread-safe), then
/// call `evaluate` per input.
#[pyclass(name = "Detector", frozen)]
struct PyDetector(alcaide_core::Detector);

#[pymethods]
impl PyDetector {
    /// Loads a rule set from a YAML file. Raises `OSError` if the file
    /// can't be read, `ValueError` if the rule set is invalid.
    #[staticmethod]
    fn from_config_path(path: &str) -> PyResult<Self> {
        alcaide_core::Detector::from_config_path(Path::new(path))
            .map(Self)
            .map_err(to_py_error)
    }

    /// Loads a rule set from YAML text. Raises `ValueError` if the rule
    /// set is invalid.
    #[staticmethod]
    fn from_yaml_str(yaml: &str) -> PyResult<Self> {
        alcaide_core::Detector::from_yaml_str(yaml)
            .map(Self)
            .map_err(to_py_error)
    }

    /// The curated default rule set bundled with the package, as shipped:
    /// in shadow mode (reports what it would block, always allows).
    #[staticmethod]
    fn with_default_rules() -> Self {
        Self(alcaide_core::Detector::with_default_rules())
    }

    /// Total number of rules in the loaded rule set, enabled or not.
    fn rule_count(&self) -> usize {
        self.0.rule_count()
    }

    /// Evaluates `input` and returns a `Decision`. `request_id` is
    /// optional, used only for log correlation. Releases the GIL while
    /// evaluating, so other Python threads keep running.
    #[pyo3(signature = (input, request_id=None))]
    fn evaluate(&self, py: Python<'_>, input: String, request_id: Option<String>) -> PyDecision {
        py.detach(|| PyDecision::new(self.0.evaluate(&input, request_id.as_deref()), &input))
    }

    fn __repr__(&self) -> String {
        format!(
            "Detector(rules={}, mode=Mode.{:?})",
            self.0.rule_count(),
            self.0.rules().defaults.mode
        )
    }
}

fn to_py_error(error: alcaide_core::ConfigError) -> PyErr {
    match error {
        alcaide_core::ConfigError::Io { .. } => PyIOError::new_err(error.to_string()),
        _ => PyValueError::new_err(error.to_string()),
    }
}

// Reverse conversions, only for `__repr__`: reuses the core types' Debug
// names so the Python repr can't drift from the Rust variant names.

impl From<PyVerdict> for alcaide_core::Verdict {
    fn from(v: PyVerdict) -> Self {
        match v {
            PyVerdict::Allow => Self::Allow,
            PyVerdict::Block => Self::Block,
            PyVerdict::Flag => Self::Flag,
        }
    }
}

impl From<PyMode> for alcaide_core::Mode {
    fn from(m: PyMode) -> Self {
        match m {
            PyMode::Shadow => Self::Shadow,
            PyMode::Enforcement => Self::Enforcement,
        }
    }
}

impl From<PyCategory> for alcaide_core::Category {
    fn from(c: PyCategory) -> Self {
        match c {
            PyCategory::Jailbreak => Self::Jailbreak,
            PyCategory::Exfiltration => Self::Exfiltration,
            PyCategory::RoleplayBypass => Self::RoleplayBypass,
            PyCategory::EncodingEvasion => Self::EncodingEvasion,
            PyCategory::InjectionGeneric => Self::InjectionGeneric,
        }
    }
}

impl From<PySeverity> for alcaide_core::Severity {
    fn from(s: PySeverity) -> Self {
        match s {
            PySeverity::Low => Self::Low,
            PySeverity::Medium => Self::Medium,
            PySeverity::High => Self::High,
            PySeverity::Critical => Self::Critical,
        }
    }
}

/// Alcaide: a deterministic, auditable prompt-injection firewall.
#[pymodule]
fn alcaide(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyDetector>()?;
    m.add_class::<PyDecision>()?;
    m.add_class::<PyMatchDetail>()?;
    m.add_class::<PyVerdict>()?;
    m.add_class::<PyMode>()?;
    m.add_class::<PyCategory>()?;
    m.add_class::<PySeverity>()?;
    Ok(())
}
