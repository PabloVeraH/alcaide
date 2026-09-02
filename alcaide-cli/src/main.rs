//! Binario `alcaide` — comandos `check`, `lint-rules`, `bench`, `contribute`.
//!
//! Placeholder de estructura (hito M0). El parseo de argumentos y los
//! comandos reales se implementan en el hito M9 — ver
//! `docs/ui-ux-brief.md` sección 3 y `docs/plan-implementacion.md`.

fn main() {
    // Prueba de enlace: confirma que alcaide-cli puede consumir los tipos
    // públicos de alcaide-core (docs/TRD.md sección 1: arquitectura de workspace).
    let mode = alcaide_core::Mode::Shadow;
    println!("alcaide-cli: esqueleto de M0 — modo por defecto: {mode:?}");
    println!("Comandos reales (check/lint-rules/bench/contribute) pendientes del hito M9.");
}
