# ADR-004 — Licenciamiento dual: AGPLv3 (Core) + licencia comercial (capa paga)

**Estado:** Aceptado — decisión final, reemplaza a `ADR-002-estrategia-propiedad-intelectual.md` y a su nota de actualización que había marcado el proyecto como completamente cerrado
**Fecha:** 1 sept 2026
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`PRD.md`](./PRD.md) (actualiza sección 12) · [`ADR-001-eleccion-lenguaje-rust.md`](./ADR-001-eleccion-lenguaje-rust.md) (Rust como lenguaje no cambia) · [`ADR-002-estrategia-propiedad-intelectual.md`](./ADR-002-estrategia-propiedad-intelectual.md) (superado por este documento) · [`ADR-003-mecanismo-de-contribucion-de-reglas.md`](./ADR-003-mecanismo-de-contribucion-de-reglas.md) (vía principal para lograr el objetivo de compartir reglas, dado lo explicado abajo) · [`modelo-de-reglas.md`](./modelo-de-reglas.md) (el modelo de capas Core/Sector/Custom es la base técnica de este licenciamiento)

## Contexto

Decisión final tras varias iteraciones: la capa Core vuelve a ser open source, ahora bajo **AGPLv3**, con la capa de pago (Sector + plataforma) bajo una **licencia comercial separada** — modelo de licenciamiento dual, igual al usado por MinIO (y usado antes por MongoDB y Sentry en sus inicios). El objetivo declarado del solicitante: que quien use la versión open source tenga la obligación, en espíritu open source, de compartir las reglas que va generando, para ir mejorando la herramienta; la versión paga no tendría esa obligación.

## Corrección legal: qué puede y qué no puede exigir AGPL

AGPL es una licencia de copyright sobre **el código del programa**. Su obligación distintiva frente a la GPL normal: si se toma el programa, se modifica, y se ofrece como servicio de red a terceros, se debe publicar el código fuente de esas modificaciones **al programa**.

Esa obligación no se extiende a los datos que un usuario crea mientras usa el programa. El archivo `rules.yaml` que un cliente escribe con sus propias reglas no es una modificación del código fuente del motor — es un archivo de datos que el programa simplemente lee, de la misma forma en que un `nginx.conf` no es una modificación del código fuente de Nginx aunque Nginx lo use para funcionar. **AGPL no puede usarse legalmente para obligar a compartir reglas custom** — eso no es lo que el copyleft regula.

## Decisión

1. **Doble licenciamiento del núcleo (capa Core):**
   - Publicado bajo **AGPLv3** para cualquiera que lo use gratis, sujeto a las obligaciones normales de esa licencia.
   - Licencia comercial separada, sin esas obligaciones, ofrecida para la capa de pago — mecanismo estándar para monetizar código AGPL (patrón MinIO). Es la vía natural para vender la capa Sector/plataforma sin dependencia de AGPL en absoluto.
2. **El objetivo de "compartir reglas en espíritu open source" no se logra vía el texto de la licencia AGPL** (no puede, legalmente, por lo explicado arriba) — se logra mediante el mecanismo ya diseñado en `ADR-003-mecanismo-de-contribucion-de-reglas.md`: contribución voluntaria y explícita (`alcaide contribute`), presentada como norma cultural de la comunidad open source, no como obligación legal exigible.
3. Para preservar la capacidad de licenciar comercialmente el código a futuro, cualquier contribución externa de **código** (no de reglas) al Core requerirá firmar un **Acuerdo de Licencia de Contribuyente (CLA)** que otorgue el derecho de relicenciar esa contribución también bajo la licencia comercial — sin esto, contribuciones de terceros podrían bloquear la venta de licencias comerciales sobre esas partes del código.

## Consecuencias

**Positivas:**
- Logra la estructura pedida: Core gratis y abierto, capa paga sin las obligaciones de AGPL, coexistiendo legalmente vía licenciamiento dual — patrón probado comercialmente.
- AGPL sí protege contra el riesgo que motivó originalmente la pregunta de licencias en esta conversación: que un actor como AWS tome el motor, lo modifique, y lo ofrezca como servicio competidor sin devolver nada — ese es exactamente el caso de uso para el que se diseñó AGPL.
- Recupera el argumento de confianza para el segmento de cliente regulado (banca/salud/gobierno, `PRD.md` sección 3): pueden auditar el código Core antes de desplegarlo.

**Negativas / trade-offs aceptados:**
- El objetivo de "obligar a compartir las reglas" no se logra de forma legalmente exigible — solo de forma voluntaria/cultural vía `ADR-003`. Se evaluó y **se descartó explícitamente** una variante más fuerte (gatear la descarga oficial detrás de un acuerdo de Términos de Uso separado de la licencia del código): es incompatible con publicar el Core en GitHub/crates.io bajo AGPL — la licencia ya otorga a cualquiera el derecho de clonar/hacer fork libremente, por lo que cualquier gate en un canal oficial no ata a quien obtenga el código por otra vía, y una sola persona que republique sin el gate lo neutraliza de forma permanente. No es una opción viable dada la decisión de publicar en GitHub bajo AGPL, no solo una opción subóptima.
- Requiere gestionar CLA para cualquier contribuidor externo de código desde el momento en que se acepten contribuciones.

## Próximos pasos

- Redactar el texto de la licencia comercial (distinta de AGPL) con apoyo de un abogado antes de la primera venta.
- Preparar plantilla de CLA antes de aceptar la primera contribución externa de código.
