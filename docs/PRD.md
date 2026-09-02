# PRD — Alcaide (Filtro de Inyección de Prompts en Rust)

**Nombre:** Alcaide — confirmado el 1 sept 2026
**Estado:** Borrador v0.1 — 30 ago 2026
**Origen:** idea #29 de `Ideas_Rust.md`, desarrollada tras investigación de mercado
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`ADR-001-eleccion-lenguaje-rust.md`](./ADR-001-eleccion-lenguaje-rust.md) (por qué Rust) · [`TRD.md`](./TRD.md) (especificación técnica derivada de este PRD)

## 1. Resumen ejecutivo

Herramienta open source en Rust que actúa como capa de inspección de prompts antes de que lleguen a un LLM, combinando un motor de reglas determinista y auditable con un clasificador ML embebido liviano (fase posterior), distribuida como librería embebible (crate/bindings) y, más adelante, como filtro WASM para proxies de infraestructura (Envoy/Istio). Se diferencia de las alternativas existentes por ofrecer explicabilidad de primera clase (no solo un score de caja negra) y por publicar benchmarks honestos de robustez contra técnicas de evasión conocidas.

## 2. Problema y motivación

- Cada llamada a un LLM con un prompt malicioso no bloqueado cuesta dinero real en tokens, incluso si el modelo termina rechazando la solicitud.
- Rebuff, la alternativa open source más citada históricamente, está archivada desde el 16 de mayo de 2025.
- Lakera Guard, el líder comercial, fue adquirido por Check Point (sept. 2025, ~US$300M) y su acceso ahora pasa por procurement enterprise — deja un vacío para equipos que buscan algo self-hosted, económico y rápido de adoptar.
- Las soluciones activas (LLM Guard, NeMo Guardrails) son Python-first, con el costo de latencia/footprint que eso implica en el hot path de cada request.
- JailGuard (Rust) ya cubre "rápido + embebible + alternativa a Rebuff/Lakera", pero es un clasificador ML de caja negra sin capa de reglas explicable, y no se distribuye como filtro de infraestructura (WASM/Envoy).

## 3. Usuarios objetivo y casos de uso

- **Equipos de plataforma/infraestructura** que exponen un LLM a usuarios externos (chatbots públicos, agentes con herramientas) y ya operan un service mesh (Envoy/Istio) — quieren el filtro en el proxy, no reescribir cada app.
- **Equipos de compliance en industrias reguladas** (banca, salud, gobierno) que necesitan poder explicar y auditar por qué una solicitud fue bloqueada, no solo un score de confianza.
- **Desarrolladores individuales / startups** que integran un LLM en su producto y quieren una librería liviana embebible sin llamar a un servicio externo (sin exponer los prompts de sus usuarios a un tercero).

## 4. Panorama competitivo (resumen)

| Producto | Tipo | Estado (ago 2026) |
|---|---|---|
| Lakera Guard | SaaS propietario | Adquirida por Check Point, ventas enterprise |
| Rebuff | Open source | Archivado (mayo 2025) |
| LLM Guard (Protect AI) | Open source, Python | Activo |
| NeMo Guardrails (NVIDIA) | Open source, Python | Activo |
| Bedrock Guardrails (AWS) | Managed | Activo, solo AWS |
| Meta PromptGuard-86M | Modelo open-weight | Activo, bypasseable documentado |
| JailGuard | Open source, Rust | Activo, muy temprano (10 stars) |
| Tirith | Crate Rust | Nicho adyacente (config de agentes, no runtime) |

Detalle completo y fuentes en el análisis de mercado de esta sesión (no incluido en este documento para mantenerlo enfocado en producto, no en investigación).

## 5. Propuesta de valor / diferenciador

1. **Motor de reglas determinista y auditable** como ciudadano de primera clase — no solo ML de caja negra. Cada bloqueo es explicable con la regla/patrón exacto que lo disparó.
2. **Distribución como filtro WASM para Envoy/Istio**, además de crate/bindings nativos — encaja con equipos que ya operan infraestructura de proxy, algo que ningún competidor de la tabla ofrece hoy.
3. **Benchmarks públicos de robustez contra ataques de evasión conocidos** (character injection, emoji smuggling, adversarial ML) — honestidad sobre límites en vez de marketing de "100% de detección".

## 6. Alcance v1 (MVP)

**Dentro de alcance:**
- Motor de reglas deterministas (Aho-Corasick + normalización Unicode/encoding) sobre un set curado de patrones de jailbreak conocidos.
- Modo shadow (solo logging, sin bloqueo) y modo enforcement (bloqueo activo).
- Librería Rust (crate) + bindings a Python.
- Reporte de decisión explicable (qué regla disparó, con qué confianza).

**Fuera de alcance para v1 (fases posteriores):**
- Clasificador ML embebido (fase 2).
- Filtro WASM para Envoy/Istio (fase 3).
- Canary tokens / verificación de output.
- Bindings a Node/Go/Elixir.
- Dashboard o UI de administración.

## 7. Requisitos funcionales

- **RF1:** dado un string de input, el sistema retorna ALLOW/BLOCK/FLAG junto con la regla o razón que motivó la decisión.
- **RF2:** el set de reglas debe ser actualizable sin recompilar el binario (archivo de configuración externo).
- **RF3:** soporte de normalización previa a la detección (decodificación de base64 evidente, normalización Unicode NFKC, detección de homoglifos comunes).
- **RF4:** modo shadow configurable por request o global.
- **RF5:** logging estructurado (JSON) de cada decisión para auditoría.

## 8. Requisitos no funcionales

- **RNF1:** latencia añadida p99 < 5ms en modo solo-reglas, medida en hardware de referencia (ej. instancia cloud estándar de 2 vCPU).
- **RNF2:** sin dependencias de red en el modo librería (nada de llamadas salientes).
- **RNF3:** memory-safe (Rust, sin `unsafe` salvo justificación documentada).
- **RNF4:** cobertura de tests ≥ 80% sobre el motor de reglas, incluyendo casos de evasión conocidos como regresión.

## 9. Métricas de éxito

- Tasa de detección sobre un benchmark público de jailbreaks conocidos (ej. JailbreakBench) ≥ X% (definir umbral tras primera medición).
- Tasa de falsos positivos sobre un corpus de prompts benignos ≤ Y%.
- Latencia p99 documentada y reproducible públicamente.
- Adopción: señal temprana de validación (estrellas/descargas en los primeros 3 meses), no meta de negocio.

## 10. Riesgos y supuestos

- **Riesgo de mercado:** el nicho "Rust + embebible + alternativa a Rebuff/Lakera" ya lo ocupa JailGuard, aunque en etapa temprana — hay que ejecutar rápido en el diferenciador (reglas explicables + WASM) antes de que lo cubran ellos u otro actor.
- **Riesgo técnico:** ningún filtro de este tipo es robusto de forma determinista contra atacantes dedicados (evidencia académica de evasión hasta 100% contra sistemas comerciales como Azure Prompt Shield y Meta Prompt Guard). El mensaje de producto debe ser honesto sobre esto, no prometer detección perfecta.
- **Supuesto a validar:** existe demanda real de equipos que prefieren self-hosted/on-prem sobre SaaS (Lakera/Bedrock) por costo o soberanía de datos — validar con conversaciones reales antes de invertir en fase 3 (WASM).

## 11. Roadmap de alto nivel

- **Fase 1 — Motor de reglas (MVP):** validar la demanda y la calidad de detección determinista sola.
- **Fase 2 — Clasificador ML embebido:** cerrar la brecha de detección semántica que las reglas no cubren.
- **Fase 3 — Distribución como filtro WASM (Envoy/Istio) + benchmarks públicos de evasión.**

El detalle de implementación de cada fase (crates, estructura de módulos, datasets, CI) corresponde al plan técnico de MVP, no a este documento.

## 12. Preguntas abiertas

- ~~¿Nombre definitivo del proyecto y licencia?~~ **Resuelto:** nombre confirmado como **Alcaide** (1 sept 2026; verificado libre en crates.io y sin colisión de producto de software detectada en una revisión liviana — pendiente aún la búsqueda formal de marca registrada, ver `informe-legal-patentes.md`). Licencia: AGPLv3 (Core) + licencia comercial separada (capa paga) — ver [`ADR-004-licenciamiento-dual-agpl-comercial.md`](./ADR-004-licenciamiento-dual-agpl-comercial.md).
- ~~¿Se persigue esto como proyecto open source de portafolio, o con intención de monetización?~~ **Resuelto:** hay intención de venta confirmada. Modelo final: open core con licenciamiento dual AGPL/comercial — ver `ADR-004-licenciamiento-dual-agpl-comercial.md` (reemplaza al `ADR-002` original). Sigue abierto: modalidad exacta de venta (suscripción vs. plataforma vs. ambas).
- ¿Validación con usuarios reales antes de fase 2/3, o se construye especulativamente?
