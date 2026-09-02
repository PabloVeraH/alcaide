//! `alcaide-core` — motor de reglas deterministas para detección de inyección
//! de prompts, sin dependencias de red (RNF2).
//!
//! Ver `docs/TRD.md` para la arquitectura completa del pipeline de detección
//! y `docs/esquema-datos.md` para el esquema exacto de los tipos públicos.
#![forbid(unsafe_code)]

mod config;
mod decision;

pub use config::{Category, Defaults, OnError, PatternType, Rule, RuleSet, Severity};
pub use decision::{Decision, MatchDetail, Mode, Verdict};

use std::path::Path;

/// Motor de evaluación principal. Ver `docs/TRD.md` sección 4 para el
/// contrato completo de la API pública.
pub struct Detector {
    #[allow(dead_code)] // se usa a partir del hito M2 (docs/plan-implementacion.md)
    rules: RuleSet,
    #[allow(dead_code)]
    mode: Mode,
}

/// Error de carga o validación de un `RuleSet`. Ver `docs/ui-ux-brief.md`
/// sección 2 para el formato de mensaje esperado (línea/campo exactos).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("error de configuración: {0}")]
    Invalid(String),
}

impl Detector {
    /// Carga y valida un `RuleSet` desde un archivo YAML.
    ///
    /// Placeholder — el parsing y la validación semántica se implementan en
    /// el hito M1 (`docs/plan-implementacion.md`).
    pub fn from_config_path(_path: &Path) -> Result<Self, ConfigError> {
        unimplemented!("M1: parsing y validación semántica de configuración")
    }

    /// Evalúa un input contra las reglas cargadas y retorna una `Decision`
    /// explicable. Nunca hace panic sobre input arbitrario (ver `docs/TRD.md`
    /// sección 4).
    ///
    /// Placeholder — el pipeline de normalización/matching/scoring se
    /// implementa en los hitos M2-M4.
    pub fn evaluate(&self, _input: &str) -> Decision {
        unimplemented!("M2-M4: pipeline de normalización, matching y scoring")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_are_exported_and_usable() {
        // Test de humo: confirma que el crate compila y su superficie
        // pública (docs/TRD.md sección 4) es accesible desde fuera del módulo.
        let mode = Mode::Shadow;
        assert_eq!(mode, Mode::Shadow);

        let verdict = Verdict::Block;
        assert_ne!(verdict, Verdict::Allow);
    }
}
