//! Python bindings for Alcaide, mirroring the Rust API (`alcaide-core`,
//! TRD §4): `Detector`, `Decision`, `Verdict`, `Mode`, `MatchDetail`.
//!
//! Kept as a thin translation layer -- all real logic lives in
//! `alcaide-core`; this crate only converts between Rust and Python types
//! and maps errors to Python exceptions.

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::path::Path;

#[pyclass(name = "Verdict", eq, eq_int, skip_from_py_object)]
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

#[pyclass(name = "Mode", eq, eq_int, skip_from_py_object)]
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

#[pyclass(name = "Category", eq, eq_int, skip_from_py_object)]
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

#[pyclass(name = "Severity", eq, eq_int, skip_from_py_object)]
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
#[pyclass(name = "MatchDetail", get_all, skip_from_py_object)]
#[derive(Clone)]
struct PyMatchDetail {
    rule_id: String,
    category: PyCategory,
    severity: PySeverity,
    span: (usize, usize),
}

impl From<alcaide_core::MatchDetail> for PyMatchDetail {
    fn from(m: alcaide_core::MatchDetail) -> Self {
        Self {
            rule_id: m.rule_id,
            category: m.category.into(),
            severity: m.severity.into(),
            span: m.span,
        }
    }
}

/// Result of one `Detector.evaluate` call.
#[pyclass(name = "Decision", get_all)]
struct PyDecision {
    verdict: PyVerdict,
    evaluated_verdict: PyVerdict,
    matched_rules: Vec<PyMatchDetail>,
    latency_us: u64,
    mode: PyMode,
}

impl From<alcaide_core::Decision> for PyDecision {
    fn from(d: alcaide_core::Decision) -> Self {
        Self {
            verdict: d.verdict.into(),
            evaluated_verdict: d.evaluated_verdict.into(),
            matched_rules: d.matched_rules.into_iter().map(Into::into).collect(),
            latency_us: d.latency.as_micros().min(u64::MAX as u128) as u64,
            mode: d.mode.into(),
        }
    }
}

/// The rule engine. Load with `Detector.from_config_path`, then call
/// `evaluate` per input.
#[pyclass(name = "Detector")]
struct PyDetector(alcaide_core::Detector);

#[pymethods]
impl PyDetector {
    /// Loads and validates a rule set from a YAML file, compiling its
    /// matching engine. Raises `ValueError` if the config is invalid, or
    /// `OSError` if the file can't be read.
    #[staticmethod]
    fn from_config_path(path: &str) -> PyResult<Self> {
        alcaide_core::Detector::from_config_path(Path::new(path))
            .map(Self)
            .map_err(|error| match &error {
                alcaide_core::ConfigError::Io { .. } => PyIOError::new_err(error.to_string()),
                _ => PyValueError::new_err(error.to_string()),
            })
    }

    /// Evaluates `input` and returns a `Decision`. `request_id` is
    /// optional, used only for log correlation.
    #[pyo3(signature = (input, request_id=None))]
    fn evaluate(&self, input: &str, request_id: Option<&str>) -> PyDecision {
        self.0.evaluate(input, request_id).into()
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
