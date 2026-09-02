# ADR-002 — Estrategia de propiedad intelectual y modelo "open core"

**Estado:** ~~Aceptado~~ **Superado el 1 sept 2026** — ver nota abajo
**Fecha:** 31 ago 2026

> **Nota de actualización (1 sept 2026):** tras varias iteraciones, la decisión final quedó en [`ADR-004-licenciamiento-dual-agpl-comercial.md`](./ADR-004-licenciamiento-dual-agpl-comercial.md): open core con licenciamiento dual (AGPLv3 para la capa Core, licencia comercial separada para la capa paga) — no el modelo Apache-2.0/MIT descrito originalmente en este documento, ni el modelo completamente cerrado de la nota anterior. Se conserva este documento porque su sección "Mecanismos de protección de IP evaluados" sigue siendo válida y fue la base del análisis que llevó a la decisión final.
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`PRD.md`](./PRD.md) (resuelve la pregunta abierta de monetización, sección 12) · [`informe-legal-patentes.md`](./informe-legal-patentes.md) (evalúa qué protege cada mecanismo legal disponible) · [`modelo-de-reglas.md`](./modelo-de-reglas.md) (el modelo de capas Core/Sector/Custom es la base técnica de esta estrategia)

## Contexto

Se confirma intención de venta del proyecto (modalidad exacta —suscripción, plataforma, o ambas— aún sin decidir). Pregunta que motiva este ADR: cómo proteger el proyecto para que no sea fácil de copiar, y qué mecanismos legales de propiedad intelectual aplican.

## Corrección de premisa

Las patentes no protegen "ideas" — protegen un método técnico específico y no obvio, tras un trámite público de años. Dado el volumen de arte previo ya identificado en `informe-legal-patentes.md` (patentes de Preamble y HiddenLayer, proyectos open source existentes, papers académicos), una patente amplia sobre el concepto general de "detectar y bloquear prompt injection" no es una vía viable.

## Mecanismos de protección de IP evaluados

| Mecanismo | Qué protege | Aplicabilidad a este proyecto |
|---|---|---|
| Patente | Método técnico específico, tras trámite de 2-3 años y costo de varios miles de USD | Débil para algo amplio (prior art); posible solo para una combinación muy específica y novedosa |
| Copyright | Expresión literal del código (automático) | Solo detiene copia literal; no detiene reimplementación funcional equivalente |
| Secreto comercial (trade secret) | Cualquier información mantenida confidencial que dé ventaja competitiva | Protección fuerte, pero mutuamente excluyente con publicar el código — se pierde en el momento de la publicación |
| Marca comercial (trademark) | Nombre/marca del producto | No protege funcionalidad, solo el nombre |
| Contratos (ToS/EULA/NDA) | Obligaciones de quien firmó | Sin efecto sobre terceros independientes sin relación contractual |

## La tensión a resolver

El posicionamiento ya definido en `PRD.md` y `ADR-001-eleccion-lenguaje-rust.md` depende de ser open source (transparencia, self-hosted, benchmarks públicos como diferenciador de mercado). Esto es incompatible, sobre el mismo componente, con protección por secreto comercial — no se puede tener ambas cosas sobre lo mismo.

## Decisión: modelo "open core"

Se adopta un modelo de negocio de núcleo abierto, mapeado directamente sobre el modelo de capas ya definido en `modelo-de-reglas.md`:

- **Capa Core (motor de reglas + set genérico de reglas):** permanece open source (licencia Apache-2.0/MIT, `ADR-001-eleccion-lenguaje-rust.md`). No se persigue protección legal sobre esta capa — dado que no es patentable (prior art) y ya estaba destinada a publicarse (por lo tanto tampoco protegible como secreto comercial), se usa deliberadamente como motor de adopción y confianza en vez de como activo a proteger.
- **Capa Sector (packs por industria) y futura plataforma hosted/dashboard:** permanecen propietarias y cerradas. Aquí sí aplica protección real por secreto comercial (contenido curado de reglas, datos de ajuste acumulados de clientes, metodología de benchmarks internos) más contratos comerciales (ToS/EULA) para clientes y NDA para colaboradores con acceso previo. Es la capa candidata para monetización vía suscripción y/o plataforma.

## Consecuencias

**Positivas:**
- Aprovecha como ventaja de adopción una capa que de todas formas no se podía proteger legalmente.
- Concentra el esfuerzo de protección legal donde sí es efectivo (secreto comercial sobre contenido nunca publicado).
- No obliga a decidir todavía entre suscripción y plataforma como modelo de venta — ambos son compatibles con esta estructura.

**Negativas / trade-offs aceptados:**
- La capa Core queda expuesta a que un competidor la tome como base de un fork — se acepta conscientemente, dado que no había protección legal real disponible para ella de todas formas.
- Requiere disciplina operativa desde ya: marcar contenido de la capa Sector como confidencial internamente, y usar NDA con cualquier colaborador que la vea antes de ser pública — el estatus de secreto comercial exige poder demostrar esfuerzos razonables de confidencialidad, no basta con simplemente no publicar por omisión.

## Próximos pasos

- Confirmar modalidad de venta (suscripción vs. plataforma vs. ambas) — no se resuelve en este ADR.
- Registrar marca comercial en EE.UU. una vez definido el nombre final (`PRD.md`, sección 12).
- Encargar el análisis de libertad de operación (FTO) profesional descrito en `informe-legal-patentes.md` — pasa de recomendación condicional a prioridad, dado que ahora hay intención comercial confirmada.
- Redactar ToS/EULA con un abogado para la capa comercial antes de la primera venta.
