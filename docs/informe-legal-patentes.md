# Informe legal — Panorama de patentes en Estados Unidos

**Estado:** Investigación informativa v0.1 — 31 ago 2026
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`ADR-001-eleccion-lenguaje-rust.md`](./ADR-001-eleccion-lenguaje-rust.md) (licencia Apache-2.0 candidata, relevante para la sección 5) · [`PRD.md`](./PRD.md) (pregunta abierta de monetización, sección 12, relevante para la sección 3) · [`TRD.md`](./TRD.md) (arquitectura de Fase 1 evaluada contra las patentes de la sección 2)

> **Aviso:** este documento es investigación informativa, no asesoría legal. Las conclusiones sobre infracción de patente requieren la lectura del texto completo de las reivindicaciones por un abogado de patentes habilitado en EE.UU. Este informe es un punto de partida para esa consulta, no un reemplazo.

## 1. Resumen ejecutivo

- Existen patentes concedidas y vigentes en EE.UU. que cubren específicamente mecanismos de mitigación de prompt injection — el espacio no está legalmente vacío, a diferencia de lo que sugería el panorama de productos comerciales revisado en `PRD.md`.
- Los mecanismos técnicos cubiertos por las cuatro patentes identificadas (aprendizaje por refuerzo con tagging de tokens, entrenamiento de clasificador ML, análisis de activaciones internas del LLM) son distintos, en una primera lectura, del motor de reglas deterministas externo planificado para la Fase 1 de este proyecto.
- El riesgo de licenciamiento aumenta si se avanza a la Fase 2 del roadmap (clasificador ML embebido) — ahí el solapamiento con al menos una de las patentes identificadas sería más directo.
- Patentar nuestro propio enfoque de forma amplia probablemente no sea viable dado el volumen de arte previo (prior art) ya público. Una combinación específica y novedosa podría tener una oportunidad más real, pero no se recomienda invertir en esto sin intención de negocio confirmada.

## 2. Patentes activas identificadas

| Patente | Titular | Concedida | Presentada | Mecanismo cubierto (reivindicación principal) |
|---|---|---|---|---|
| [US12118471B2](https://patents.google.com/patent/US12118471B2/en) | Preamble Inc. | 15 oct 2024 | 4 may 2023 | Modelo de IA + procesador que usa **reinforcement learning** para etiquetar tokens como confiables/no confiables (usando conjuntos de tokens incompatibles) y remueve contenido no confiable antes de la ejecución del modelo. |
| [US12130917B1](https://patents.google.com/patent/US12130917B1/en) | HiddenLayer Inc. | 29 oct 2024 | 28 may 2024 | Método de **entrenamiento de un clasificador ML** de prompt injection usando datasets sintéticos generados con plantillas de ataque ("skeleton attacks") y LLMs deliberadamente desalineados. |
| US12137118B1 / US12107885 | HiddenLayer Inc. (mismo dominio) | oct–nov 2024 | — | Clasificación de prompt injection mediante **análisis de patrones de activación internos** del LLM (acceso white-box a capas del transformer). |

**Sobre Preamble Inc.:** startup de Pittsburgh enfocada en seguridad de IA. Comunicó públicamente que la concesión de esta patente les da "derechos exclusivos para realizar (o licenciar su sistema de) mitigación de prompt injection en modelos de IA capaces de aceptar texto" — lenguaje de comunicado de prensa deliberadamente amplio; el alcance legal real lo define el texto de las reivindicaciones, no el comunicado.

**Sobre HiddenLayer Inc.:** empresa de seguridad de ML/IA con financiamiento significativo, con múltiples patentes en esta familia — indica una estrategia activa de protección de propiedad intelectual en este espacio específico.

No se encontró evidencia pública de litigios o acciones de enforcement activas de ninguna de las dos empresas contra terceros a la fecha de esta investigación.

## 3. Evaluación preliminar contra el diseño de Fase 1

El diseño de Fase 1 (`TRD.md`) es un motor de reglas deterministas externo (Aho-Corasick + regex) que corre **antes** de cualquier llamada al LLM, sin acceso a los tokens internos del modelo, sin aprendizaje por refuerzo, y sin entrenar ningún clasificador.

En una lectura de las reivindicaciones principales resumidas arriba, **ninguna de las cuatro patentes parece cubrir literalmente este mecanismo**:
- US12118471B2 exige específicamente reinforcement learning operando sobre el espacio de tokens del propio modelo.
- Las patentes de HiddenLayer exigen entrenamiento de un clasificador ML o acceso a activaciones internas del transformer.

**Esto no constituye un análisis de libertad de operación (Freedom to Operate / FTO) válido.** Un FTO profesional cubre: texto completo de todas las reivindicaciones (no solo la independiente principal), reivindicaciones dependientes, solicitudes pendientes de publicación (no solo patentes ya concedidas), y jurisdicciones adicionales si se opera fuera de EE.UU.

**Dónde el riesgo aumenta:** la Fase 2 del roadmap (clasificador ML embebido, ver `PRD.md` sección 11) se acerca mucho más al mecanismo cubierto por la patente de HiddenLayer (US12130917B1) si el enfoque de entrenamiento resulta similar (datasets sintéticos con plantillas de ataque). Se recomienda encargar un FTO profesional **antes** de iniciar esa fase, no después.

## 4. ¿Se necesitaría pagar una licencia?

Con la información disponible, no hay señal clara de que el diseño de Fase 1 requiera licenciar algo de Preamble o HiddenLayer. Sin embargo, el riesgo práctico de que una patente se haga cumplir es proporcional a la exposición comercial del proyecto: litigar una patente en EE.UU. es costoso, por lo que rara vez se persigue a proyectos open source sin ingresos. Este cálculo cambia si el proyecto pasa a tener intención de negocio real con clientes pagando (pregunta abierta en `PRD.md`, sección 12) — en ese escenario, encargar el FTO deja de ser opcional.

## 5. ¿Se podría patentar nuestro propio enfoque?

En EE.UU., desde *Alice Corp. v. CLS Bank International* (2014), una idea abstracta implementada en una computadora genérica no es patentable — se requiere una mejora técnica concreta y no obvia.

Dado el volumen de arte previo ya público antes de cualquier presentación nuestra — las cuatro patentes de esta investigación, más JailGuard, Rebuff, LLM Guard, y los papers académicos citados en la investigación de mercado (`PRD.md`) — una reivindicación amplia tipo "detectar prompt injection y bloquear antes de gastar tokens" muy probablemente sería rechazada por falta de novedad, o de concederse, sería vulnerable a invalidación usando esa misma evidencia.

Una combinación específica y novedosa —por ejemplo, el modelo de capas Core/Sector/Custom con su mecanismo de `overrides` (`modelo-de-reglas.md`) combinado con la distribución como filtro WASM— tendría en teoría más chance de pasar el estándar de novedad. No se recomienda invertir en esto sin intención de negocio confirmada, dado el costo de tramitación de una patente de utilidad en EE.UU. (típicamente varios miles de dólares con un abogado especializado). Existe la práctica legítima de "patentamiento defensivo" combinado con licencia open source (patentar y de todas formas liberar bajo Apache-2.0), pero es una decisión a revisar solo si el camino de monetización se confirma.

## 6. Nota — la licencia Apache-2.0 no cubre este riesgo

La licencia Apache-2.0, candidata en `ADR-001-eleccion-lenguaje-rust.md`, incluye una cláusula de concesión de patente: protege a quien use el proyecto de reclamos de patente hechos por **quienes contribuyen código al propio proyecto**. No ofrece ninguna protección frente a patentes de terceros no relacionados, como las de Preamble o HiddenLayer identificadas en este informe — son dos categorías de riesgo distintas y no deben confundirse.

## 7. Nota aparte — marca comercial (trademark)

Fuera del alcance de este informe (que se centra en patentes, según lo solicitado), pero vale la pena dejarlo anotado: si el proyecto se lanza públicamente con un nombre definitivo (pendiente en `PRD.md`, sección 12), conviene una búsqueda de marca registrada en EE.UU. por separado — es un trámite y un riesgo legal distinto al de patentes.

## 8. Recomendación

- No se identificó un bloqueo legal para continuar el desarrollo de la Fase 1 tal como está especificada en `TRD.md`.
- **Actualización:** se confirmó intención de venta (`ADR-002-estrategia-propiedad-intelectual.md`) — el análisis de libertad de operación (FTO) profesional deja de ser condicional y pasa a ser prioridad antes de cualquier lanzamiento comercial o levantamiento de capital.
- Encargar ese FTO específicamente **antes** de iniciar la Fase 2 (clasificador ML embebido), dado el mayor solapamiento potencial con la patente de HiddenLayer — esto es aún más relevante ahora que hay intención comercial confirmada.
- La opción de patentamiento defensivo propio se evalúa en `ADR-002-estrategia-propiedad-intelectual.md`: se descartó como prioridad frente al modelo "open core" adoptado, que protege la capa comercial (Sector/plataforma) vía secreto comercial en vez de patente.

## Fuentes

- [US12118471B2 — Google Patents](https://patents.google.com/patent/US12118471B2/en)
- [US12130917B1 — Google Patents](https://patents.google.com/patent/US12130917B1/en)
- [US12137118B1 — Google Patents](https://patents.google.com/patent/US12137118B1/en)
- [Patent 12,107,885 — Justia Patents](https://patents.justia.com/patent/12107885)
- [Preamble — anuncio de concesión de patente (X/Twitter)](https://x.com/PreambleAI/status/1846251599213310385)
- [Preamble Secures Comprehensive Patent — Pittsburgh Technology Council](https://www.pghtech.org/news-and-publications/preamble_aipatent)
- [Can You Patent AI? What the USPTO Actually Grants in 2026 — Rapacke Law Group](https://arapackelaw.com/patents/can-you-patent-ai/)
- [USPTO MPEP 2106 — Patent Subject Matter Eligibility](https://www.uspto.gov/web/offices/pac/mpep/s2106.html)
