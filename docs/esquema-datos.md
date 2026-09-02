# Esquema de datos internos — Alcaide

**Estado:** Borrador v0.1 — 30 ago 2026
**Alcance:** esquemas de datos internos del MVP (config de reglas + log de decisión). No hay base de datos ni servicio backend en Fase 1 — Alcaide es una librería embebida sin persistencia propia (RNF2 del PRD). Un eventual esquema de base de datos para un control-plane centralizado queda fuera de alcance y se documentaría por separado si esa fase se aborda.
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`TRD.md`](./TRD.md) (pipeline que consume estos esquemas) · [`ui-ux-brief.md`](./ui-ux-brief.md) (cómo se presenta este esquema al desarrollador) · [`modelo-de-reglas.md`](./modelo-de-reglas.md) (extiende este esquema al caso de múltiples capas de reglas — Core/Sector/Custom, pendiente de incorporar formalmente aquí)

## 1. Esquema — archivo de configuración de reglas (`rules.yaml`)

| Campo | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `version` | integer | Sí | Versión del esquema del archivo. Permite migraciones futuras sin romper archivos existentes. |
| `defaults.mode` | enum: `shadow` \| `enforcement` | Sí | Modo global por defecto (puede sobreescribirse en runtime vía la API). |
| `defaults.block_threshold` | enum: `low` \| `medium` \| `high` \| `critical` | Sí | Severidad mínima que gatilla `Block` en modo enforcement. |
| `defaults.on_error` | enum: `block` \| `allow` | No (default: `block`) | Comportamiento ante fallo interno — ver decisión de fail-closed en el TRD. |
| `rules[]` | lista de objetos `Rule` | Sí | Ver tabla siguiente. |

### Objeto `Rule`

| Campo | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `id` | string (kebab-case, único) | Sí | Identificador estable de la regla — aparece en los logs de decisión, debe sobrevivir ediciones del `pattern`. |
| `category` | enum: `jailbreak` \| `exfiltration` \| `roleplay-bypass` \| `encoding-evasion` \| `injection-generic` | Sí | Taxonomía usada tanto para reporting como para umbrales por categoría en fases futuras. |
| `severity` | enum: `low` \| `medium` \| `high` \| `critical` | Sí | Severidad individual de la regla. |
| `pattern_type` | enum: `literal` \| `regex` \| `heuristic` | Sí | `literal`/`regex` van al motor Aho-Corasick/regex; `heuristic` referencia una función interna (ej. `base64_suspicious`), no un patrón de texto libre. |
| `pattern` | string | Sí si `pattern_type` ≠ `heuristic` | El patrón literal o expresión regular. |
| `enabled` | boolean | No (default: `true`) | Permite desactivar sin borrar la definición. |
| `notes` | string | No | Documentación humana, no funcional (ver `ui-ux-brief.md`, sección 2). |

## 2. Esquema — registro de decisión (log JSON estructurado)

Este es el esquema que RF5 del PRD exige. Se emite **una línea JSON por evaluación**.

| Campo | Tipo | Descripción |
|---|---|---|
| `timestamp` | string (ISO 8601, UTC) | Momento de la evaluación. |
| `request_id` | string \| null | Opcional, provisto por el caller para correlacionar con sus propios logs. Alcaide no genera IDs propios. |
| `mode` | enum: `shadow` \| `enforcement` | Modo activo al momento de la evaluación. |
| `verdict` | enum: `allow` \| `block` \| `flag` | Resultado final devuelto al caller. En modo `shadow`, este campo refleja el veredicto *real* aunque el caller siempre reciba `allow` — es la fuente de verdad para calibrar antes de pasar a enforcement. |
| `matched_rules[]` | lista de `MatchDetail` | Ver tabla siguiente. Vacía si no hubo coincidencias. |
| `latency_us` | integer | Latencia de la evaluación completa, en microsegundos — insumo directo para verificar RNF1. |
| `rule_set_version` | integer | Copia de `version` del `rules.yaml` cargado, para poder correlacionar cambios de comportamiento con cambios de config en auditorías. |
| `input_hash` | string (SHA-256, hex) | **Por defecto se loguea el hash, no el texto crudo del prompt** — decisión de privacidad: el log no debe convertirse en un repositorio de datos sensibles de usuarios finales por defecto. |
| `input_snippet` | string \| null | Fragmento del input **solo si** se habilita explícitamente `log_raw_input: true` en la config — opt-in, nunca default, y debe documentarse como una decisión consciente de trade-off privacidad/depurabilidad. |

### Objeto `MatchDetail`

| Campo | Tipo | Descripción |
|---|---|---|
| `rule_id` | string | Referencia al `id` de la regla en `rules.yaml`. |
| `category` | string | Copiado de la regla, para poder filtrar logs por categoría sin tener que cruzar con el archivo de config. |
| `severity` | string | Copiado de la regla, mismo motivo. |
| `span` | `[start, end]` (offsets en el texto normalizado) | Dónde ocurrió la coincidencia — necesario para que la explicación sea verificable, no solo un score. |

### Ejemplo de línea de log

```json
{"timestamp":"2026-08-30T21:14:02Z","request_id":"req-8841","mode":"shadow","verdict":"block","matched_rules":[{"rule_id":"jailbreak-ignore-instructions","category":"jailbreak","severity":"high","span":[12,58]}],"latency_us":312,"rule_set_version":1,"input_hash":"a1b2c3...","input_snippet":null}
```

## 3. Tipos internos en memoria (Rust)

Estos no son persistidos — existen solo durante la evaluación, pero se documentan aquí porque son el contrato entre las etapas del pipeline descrito en `TRD.md` sección 3.

```rust
struct NormalizedInput {
    original_len: usize,
    normalized_text: String,   // tras NFKC + homoglifos + decode heurístico
    decode_applied: Vec<DecodeStep>, // trazabilidad de qué transformación se aplicó, para debug
}

struct Match {
    rule_id: String,
    span: (usize, usize),
}

struct Decision {
    verdict: Verdict,
    matched_rules: Vec<Match>,
    latency: std::time::Duration,
    mode: Mode,
}
```

## 4. Fuera de alcance de este documento

- Esquema de base de datos relacional/documental — no aplica, no hay persistencia en Fase 1.
- Esquema de un control-plane centralizado (gestión de reglas entre equipos, agregación de logs multi-servicio) — quedaría para una fase futura fuera del alcance actual del PRD.
