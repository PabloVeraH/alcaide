# Technical Requirement Document (TRD) — Alcaide

**Estado:** Borrador v0.1 — 30 ago 2026
**Alcance:** Fase 1 del roadmap del PRD (motor de reglas). Fases 2 (clasificador ML) y 3 (filtro WASM) se mencionan solo como restricciones de diseño a no bloquear, no se especifican en detalle aquí.
**Traza a:** `PRD.md` — secciones 6, 7 y 8.
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`PRD.md`](./PRD.md) (requisitos de origen) · [`ADR-001-eleccion-lenguaje-rust.md`](./ADR-001-eleccion-lenguaje-rust.md) (justificación de las decisiones de stack de la sección 2) · [`modelo-de-reglas.md`](./modelo-de-reglas.md) (extiende el pipeline de la sección 3 al caso multi-empresa) · [`esquema-datos.md`](./esquema-datos.md) (detalle de los esquemas referidos en la sección 4) · [`plan-implementacion.md`](./plan-implementacion.md) (cómo se ejecuta esta especificación)

## 1. Visión técnica general

Alcaide es un **workspace de Cargo** con tres crates:

```
alcaide/                  (workspace root)
├── alcaide-core/          → librería principal (motor de reglas), sin dependencias de red ni de I/O bloqueante
├── alcaide-py/             → bindings Python vía PyO3, empaquetados con maturin
└── alcaide-cli/            → binario CLI, consume alcaide-core
```

`alcaide-core` es el único crate con lógica de detección. Los demás son wrappers de distribución. Esto evita duplicar lógica entre bindings y garantiza que cualquier fix de detección beneficie a todos los consumidores por igual.

## 2. Stack tecnológico y decisiones

| Área | Elección | Razón |
|---|---|---|
| Lenguaje núcleo | Rust (edition 2021) | Definido en el PRD (RNF3, memory-safe) |
| Matching multi-patrón | `aho-corasick` | Estándar de facto en Rust para búsqueda simultánea de miles de patrones literales en tiempo lineal |
| Regex secundaria | `regex` (crate oficial) | Para patrones estructurales que un diccionario literal no cubre (ej. `ignora (todas )?las instrucciones (anteriores|previas)`) |
| Normalización Unicode | `unicode-normalization` | NFKC para neutralizar homoglifos y formas de compatibilidad Unicode usadas para evasión |
| Formato de config de reglas | **YAML** | Elegido sobre TOML/JSON: es el estándar de facto en herramientas de reglas de seguridad comparables (Semgrep, Sigma, YARA-adyacentes), soporta comentarios y listas anidadas legibles — importante porque el archivo de reglas lo edita un humano, no solo una máquina |
| Serialización | `serde` + `serde_yaml` | Estándar Rust para (de)serializar la config y los registros de decisión |
| Logging estructurado | `tracing` + `tracing-subscriber` (formatter JSON) | Cumple RF5 sin reinventar un logger propio |
| Bindings Python | `PyO3` + `maturin` | Estándar de facto para exponer crates Rust como paquetes pip nativos |
| Benchmarking | `criterion` | Necesario para verificar RNF1 (p99 < 5ms) de forma reproducible en CI |
| Testing de regresión | `insta` (snapshot testing) + corpus propio en `tests/corpus/` | Los casos de evasión conocidos (ver §7) deben quedar como regresión permanente, no solo como benchmark puntual |

## 3. Arquitectura del pipeline de detección

```
Input (&str)
   │
   ▼
[1] Validación de entrada        → tamaño máx, validez UTF-8
   │
   ▼
[2] Normalización                → NFKC, mapa de homoglifos, heurística de
   │                                 decodificación base64/hex evidente
   ▼
[3] Motor de coincidencia        → Aho-Corasick (patrones literales)
   │                                 + regex (patrones estructurales)
   ▼
[4] Agregación y scoring         → severidad por categoría, umbrales configurables
   │
   ▼
[5] Resolución de modo           → shadow (loguea, no bloquea) vs enforcement
   │
   ▼
[6] Emisión de Decision + log    → RF1, RF5
```

Cada etapa es una función pura sobre el `NormalizedInput`, sin estado mutable compartido — esto es lo que permite paralelizar llamadas concurrentes sin locks (relevante para RNF1 bajo carga).

## 4. Contrato de interfaz (Rust API)

```rust
pub struct Detector {
    rules: RuleSet,
    mode: Mode, // Shadow | Enforcement
}

impl Detector {
    pub fn from_config_path(path: &Path) -> Result<Self, ConfigError>;
    pub fn evaluate(&self, input: &str) -> Decision;
}

pub struct Decision {
    pub verdict: Verdict,           // Allow | Block | Flag
    pub matched_rules: Vec<MatchDetail>,
    pub latency: Duration,
    pub mode: Mode,
}

pub enum Verdict { Allow, Block, Flag }
```

`evaluate` **nunca** hace panic sobre input arbitrario (incluyendo bytes inválidos UTF-8 que Rust ya impide a nivel de tipo `&str`, e inputs vacíos o extremadamente largos — estos se manejan como `Verdict::Flag` con razón `input_too_large`, no como error).

### Bindings Python (mismo contrato, forma idiomática)

```python
from alcaide import Detector

detector = Detector.from_config("rules.yaml")
decision = detector.evaluate(user_input)
# decision.verdict, decision.matched_rules, decision.latency_ms
```

## 5. Manejo de errores

| Situación | Comportamiento |
|---|---|
| Config YAML inválida al cargar | `Result::Err(ConfigError)` con línea/campo del error — falla rápido al iniciar, no en runtime |
| Input excede tamaño máximo configurado | `Verdict::Flag` (no `Block` automático — evita que un ataque de "input gigante" se use para generar ruido de bloqueos; queda registrado para que el operador decida) |
| Fallo interno inesperado durante evaluación (no debería ocurrir dado que no hay I/O) | **Fail-closed por defecto**: `Verdict::Block` con razón `internal_error`, configurable a fail-open explícitamente. Se documenta esta decisión abajo. |

**Decisión de diseño — fail-closed por defecto:** para una herramienta de seguridad, un fallo interno silencioso que deja pasar todo (fail-open) es más peligroso que un falso positivo ocasional. Se deja como opción configurable (`on_error: allow`) para equipos que priorizan disponibilidad sobre seguridad estricta, pero el default de la librería es bloquear ante error interno.

## 6. Requisitos no funcionales — verificación

| RNF (PRD) | Cómo se verifica en este TRD |
|---|---|
| RNF1: p99 < 5ms modo reglas | Suite `criterion` en CI, corre en cada PR contra hardware de referencia documentado (GitHub Actions runner estándar), falla el build si regresiona >10% |
| RNF2: sin red en modo librería | `alcaide-core` declara explícitamente cero dependencias de crates con I/O de red (verificado con `cargo tree` en CI). **Excepción puntual documentada:** el comando `alcaide contribute` de la CLI (`ADR-003-mecanismo-de-contribucion-de-reglas.md`) es la única vía de red del proyecto, y solo se activa por invocación explícita del usuario — nunca como efecto secundario de `Detector::evaluate()` ni de ningún flujo automático. |
| RNF3: memory-safe, sin `unsafe` | `#![forbid(unsafe_code)]` a nivel de crate en `alcaide-core`; cualquier excepción requiere PR separado con justificación documentada |
| RNF4: cobertura ≥ 80% | `cargo llvm-cov` en CI con umbral duro |

## 7. Casos de evasión a cubrir como regresión (no como promesa de detección perfecta)

Basado en la literatura revisada (arXiv 2504.11168), el corpus de tests de regresión debe incluir explícitamente, con expectativa documentada de qué SÍ y qué NO se espera que el motor de reglas detecte en Fase 1:

- Character injection básico (espaciado anómalo, eliminación de puntuación) — el motor de reglas debe normalizar y detectar variantes simples.
- Emoji smuggling y texto bidireccional — **documentado como limitación conocida de la Fase 1** (requiere la capa ML de Fase 2); el test de regresión verifica que como mínimo no genere un falso ALLOW silencioso sin quedar registrado como "no evaluado con confianza".
- Evasión por encoding (base64/hex simple) — cubierto por la heurística de normalización (§3, etapa 2).

Este listado se actualiza en cada release; es parte del changelog público, no solo de tests internos — coherente con el diferenciador de "benchmarks honestos" del PRD.

## 8. Fuera de alcance de este TRD

- Arquitectura del clasificador ML embebido (Fase 2).
- Especificación del filtro WASM para Envoy/Istio (Fase 3).
- Cualquier componente de red, servicio hosted, o base de datos — no existen en Fase 1.
