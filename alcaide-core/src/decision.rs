//! Esquema de decisión y del registro de log JSON.
//!
//! Espejo tipado de `docs/esquema-datos.md` sección 2 y del flujo de
//! decisión en tiempo de ejecución descrito en `docs/flujo-app.md` (flujo A).

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

/// Resultado devuelto por `Detector::evaluate` — ver `docs/TRD.md` sección 4.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub matched_rules: Vec<MatchDetail>,
    pub latency: Duration,
    pub mode: Mode,
}

/// Una coincidencia individual dentro de una `Decision` — corresponde al
/// objeto `MatchDetail` de `docs/esquema-datos.md` sección 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchDetail {
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    /// Offsets `(start, end)` en el texto normalizado, no en el input crudo.
    pub span: (usize, usize),
}
