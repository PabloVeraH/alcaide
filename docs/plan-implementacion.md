# Plan de implementación — Alcaide (Fase 1: motor de reglas)

**Estado:** Borrador v0.1 — 30 ago 2026
**Traza a:** `TRD.md` (arquitectura) y `PRD.md` sección 11 (Fase 1 del roadmap).
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`TRD.md`](./TRD.md) · [`PRD.md`](./PRD.md)
**Nota sobre estimaciones:** se usa tamaño relativo (S/M/L) en vez de fechas de calendario, porque el tiempo disponible real no se ha definido todavía. S ≈ una sesión de trabajo enfocada, M ≈ varias sesiones, L ≈ una semana de trabajo dedicado o más.

## Orden de dependencias (vista rápida)

```
M0 (setup)
 └─▶ M1 (data model + config)
      └─▶ M2 (normalización) ─┐
      └─▶ M3 (matching)       ├─▶ M4 (scoring/decisión) ─▶ M5 (logging)
                               ┘                              │
                                                                ▼
M6 (curación de reglas, en paralelo desde M1) ────────▶ M7 (API pública)
                                                                │
                                                                ├─▶ M8 (bindings Python)
                                                                └─▶ M9 (CLI)
                                                                       │
                                                                       ▼
                                                          M10 (testing/benchmarks)
                                                                       │
                                                                       ▼
                                                          M11 (documentación/release)
```

## M0 — Setup del proyecto (S)

- Crear workspace de Cargo con la estructura de `TRD.md` §1 (`alcaide-core`, `alcaide-py`, `alcaide-cli`).
- Configurar CI: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`.
- ~~Definir licencia (dual MIT/Apache-2.0)~~ **Completado:** AGPLv3 para el Core, licencia comercial separada para la capa paga — ver `ADR-004-licenciamiento-dual-agpl-comercial.md`. Texto oficial de AGPLv3 descargado en `LICENSE`.
- `#![forbid(unsafe_code)]` en `alcaide-core` desde el commit inicial.

**Definition of Done:** `cargo build` y `cargo test` pasan en CI sobre un crate vacío con la estructura correcta.

## M1 — Modelo de datos y parsing de configuración (M)

- Implementar structs `RuleSet`, `Rule` según `esquema-datos.md` §1.
- Parsing con `serde_yaml`, con mensajes de error que incluyan línea/campo (`ui-ux-brief.md` §2).
- Validación semántica post-parsing (ids únicos, `pattern` presente si `pattern_type` ≠ `heuristic`, enums válidos).
- Tests unitarios: config válida, config con cada tipo de error esperado.

**Definition of Done:** cubre RF2 del PRD. `cargo test` incluye al menos un caso por tipo de error de validación documentado en el brief de UX.

## M2 — Pipeline de normalización (M)

- NFKC vía `unicode-normalization`.
- Tabla de homoglifos comunes (set inicial curado manualmente, no exhaustivo).
- Heurística de detección/decodificación de base64/hex evidente.
- Tests de regresión con los casos de evasión documentados en `TRD.md` §7, incluyendo los marcados como "limitación conocida".

**Definition of Done:** función `normalize(&str) -> NormalizedInput` con cobertura de tests ≥ 80% (RNF4), y el `Vec<DecodeStep>` de trazabilidad queda poblado correctamente para debug.

## M3 — Motor de coincidencia (M)

- Integración de `aho-corasick` para patrones `literal`.
- Integración de `regex` para patrones `pattern_type: regex`.
- Benchmark inicial con `criterion` sobre un set sintético de ~1000 reglas para validar que el enfoque escala antes de invertir en curar el set real.

**Definition of Done:** cumple el objetivo preliminar de RNF1 (p99 < 5ms) en el benchmark sintético — la verificación final con reglas reales ocurre en M10.

## M4 — Agregación, scoring y resolución de modo (S)

- Lógica de severidad agregada → `Verdict`.
- Manejo de `shadow` vs `enforcement` según `flujo-app.md` (flujo A).
- Manejo de `on_error` (fail-closed por defecto, TRD §5).

**Definition of Done:** tests que cubren las cuatro combinaciones relevantes (shadow/enforcement × supera/no supera umbral) más el caso de error interno simulado.

## M5 — Logging estructurado (S)

- Emisión de línea JSON según `esquema-datos.md` §2, vía `tracing`.
- `input_hash` por defecto (SHA-256), `input_snippet` solo si `log_raw_input: true`.

**Definition of Done:** cumple RF5. Test que verifica que `input_snippet` es `null` por defecto y solo aparece con el flag explícito activado — este test no debe poder eliminarse sin revisión (es una garantía de privacidad, no solo una feature).

## M6 — Curación del set de reglas por defecto (L, en paralelo desde M1)

- Recolectar patrones desde corpus públicos (JailbreakBench y equivalentes citados en la investigación de mercado de este proyecto).
- Curar `rules.yaml` por defecto con categorías del esquema (`jailbreak`, `exfiltration`, `roleplay-bypass`, `encoding-evasion`, `injection-generic`).
- Armar corpus de prueba propio en `tests/corpus/` con casos etiquetados (malicioso/benigno) para medir falsos positivos — necesario para la métrica de éxito del PRD (sección 9).

**Definition of Done:** `rules.yaml` por defecto cargado y validado por M1; corpus de prueba con al menos casos positivos, negativos y de evasión conocida, cada uno con la fuente citada (para trazabilidad y para poder actualizar si la fuente cambia).

## M7 — API pública de Rust (S)

- Pulir `Detector`, `Decision`, tipos de error según `TRD.md` §4.
- Doc comments completos, `cargo doc` sin warnings.

**Definition of Done:** ejemplo de uso en `examples/` que corre de punta a punta contra el `rules.yaml` por defecto.

## M8 — Bindings Python (M)

- `alcaide-py` vía PyO3, empaquetado con `maturin`.
- Espejar la forma de la API de Rust (`ui-ux-brief.md` §4).
- Suite básica de `pytest` (no necesita duplicar toda la cobertura de Rust, solo verificar que el binding expone correctamente el contrato).

**Definition of Done:** `pip install .` local funciona, ejemplo Python equivalente al de M7 corre sin errores.

## M9 — CLI (S)

- Comandos `check`, `lint-rules`, `bench` según `ui-ux-brief.md` §3.
- Exit codes según convención documentada.
- Modo `--json` en `check`.

**Definition of Done:** los tres comandos documentados funcionan contra el `rules.yaml` por defecto y contra una config inválida (para verificar los mensajes de error).

## M10 — Testing de aceptación y benchmarks públicos (M)

- Correr el motor completo (reglas reales de M6) contra el benchmark público de jailbreaks y el corpus de prompts benignos.
- Medir y documentar: tasa de detección, tasa de falsos positivos, latencia p50/p99 reales (no sintéticos).
- Confirmar cumplimiento de RNF1 con reglas reales, no solo el benchmark sintético de M3.

**Definition of Done:** resultados de este benchmark quedan en un documento público (`BENCHMARKS.md`, fuera del alcance de este plan pero mencionado como entregable) — es la base del diferenciador de "benchmarks honestos" del PRD, sección 5.

## M11 — Documentación y release (S)

- README con quick-start (<5 minutos, objetivo de `ui-ux-brief.md` §1).
- `CONTRIBUTING.md`, licencia confirmada.
- Publicar `alcaide-core`/`alcaide-cli` en crates.io, `alcaide` en PyPI.
- Tag `v0.1.0`.

**Definition of Done:** un desarrollador externo puede instalar, correr `alcaide check` con la config por defecto, y entender el resultado sin leer el código fuente.

## Fuera de alcance de este plan

- Fase 2 (clasificador ML embebido) y Fase 3 (filtro WASM) no tienen hitos aquí — se planifican por separado cuando el PRD confirme avanzar a esas fases, previa validación con usuarios reales (riesgo identificado en PRD sección 10).
