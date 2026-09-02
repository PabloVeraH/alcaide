# ADR-003 — Mecanismo de contribución de reglas (opt-in, no automático)

**Estado:** Aceptado
**Fecha:** 1 sept 2026
**Documentos relacionados:** [`README.md`](./README.md) (índice) · [`TRD.md`](./TRD.md) (excepción puntual a RNF2) · [`modelo-de-reglas.md`](./modelo-de-reglas.md) (extiende el ciclo de vida de la regla custom, sección 6) · [`ADR-004-licenciamiento-dual-agpl-comercial.md`](./ADR-004-licenciamiento-dual-agpl-comercial.md) (decisión de licenciamiento final: este mecanismo voluntario es, legalmente, la única vía para lograr el objetivo de "compartir reglas" — AGPL no puede exigirlo)

## Contexto

Se evaluó incluir en el contrato comercial una obligación de que los clientes compartan de vuelta las reglas que escriben en su capa Custom (`modelo-de-reglas.md`, sección 4.3), con el objetivo de mejorar continuamente el set de reglas del producto.

## Por qué se descarta la obligación automática/contractual

Las reglas de la capa Custom son, por diseño, información sensible del cliente (nombres de productos internos, jerga de negocio). Una obligación de compartirlas automáticamente:

- Contradice directamente RNF2 del `TRD.md` ("sin dependencias de red en el modo librería"), que es la base técnica del diferenciador de soberanía de datos del `PRD.md`.
- Es probablemente inaceptable para el segmento de cliente objetivo (banca, salud, gobierno) independientemente de lo que diga el contrato — en muchos casos su propio marco regulatorio no les permite aceptar esa cláusula, sin importar el consentimiento contractual.
- Debilita el argumento de venta central usado contra los competidores SaaS (Lakera, Bedrock) en `PRD.md` sección 5.

## Decisión

Se adopta un mecanismo de contribución **explícito y opt-in**, sin ninguna obligación contractual de compartir, siguiendo el mismo patrón usado por comunidades de inteligencia de amenazas ya establecidas (envío voluntario de muestras a VirusTotal, reglas YARA, plataformas MISP):

1. **Comando explícito `alcaide contribute`**: única vía de salida de red relacionada a reglas, y solo se ejecuta cuando el cliente lo invoca a propósito, con confirmación explícita de qué contenido se envía. Nunca ocurre como efecto secundario de `Detector::evaluate()` ni de ningún otro comando.
2. **Telemetría agregada opcional (opt-in, separada del punto 1)**: limitada estrictamente a `rule_id` (solo de la capa Core, nunca Sector ni Custom) + conteo de activaciones. Nunca incluye contenido de reglas Custom, texto de reglas Sector, ni el prompt evaluado.
3. Ambos mecanismos quedan deshabilitados por defecto — el cliente los activa explícitamente si lo desea.

## Consecuencias

**Positivas:**
- Preserva intacto RNF2 y el argumento de soberanía de datos para el segmento de cliente objetivo.
- Mantiene compatibilidad legal con clientes que no podrían aceptar una obligación de compartir datos, sin excluirlos de la venta.

**Negativas / trade-offs aceptados:**
- Menor volumen de datos de mejora que una obligación automática habría dado — se acepta como costo necesario de no comprometer la venta al segmento principal.
- Requiere construir el flujo de confirmación explícita del comando `contribute` (no está en el alcance de la Fase 1 actual del `plan-implementacion.md` — queda como extensión futura a incorporar en un hito posterior).

## Pendiente

- Revisión de un abogado especializado en privacidad de datos antes de implementar cualquiera de los dos mecanismos (punto 1 o 2), incluso en su forma opt-in — el diseño del flujo de consentimiento importa legalmente, especialmente dado el perfil regulado del cliente objetivo.
- Incorporar el hito técnico correspondiente al `plan-implementacion.md` cuando se decida construir esta función — no se modificó ese documento en este ADR para no adelantar trabajo de planificación sin confirmarlo contigo primero.
