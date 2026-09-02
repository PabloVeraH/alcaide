# ADR-001 — Elección de Rust como lenguaje de implementación

**Estado:** Aceptado
**Fecha:** 31 ago 2026
**Documentos relacionados:** [`PRD.md`](./PRD.md) (contexto de negocio y diferenciador) · [`TRD.md`](./TRD.md) (consecuencia técnica de esta decisión) · [`README.md`](./README.md) (índice general)

## Contexto

Durante la investigación de mercado de este proyecto (resumida en `PRD.md`, sección 4) se identificaron cuatro áreas donde ningún competidor activo tiene una posición fuerte hoy:

| # | Diferenciador | ¿Depende del lenguaje de implementación? |
|---|---|---|
| 1 | Motor de reglas deterministas y explicable (vs. clasificadores ML de caja negra) | **No** — es una decisión de arquitectura/diseño, replicable en cualquier lenguaje |
| 2 | Distribución como filtro WASM para proxies de infraestructura (Envoy/Istio) | **Sí** — requiere compilar a WebAssembly de forma madura y eficiente; Python no tiene hoy un camino de producción viable para esto |
| 3 | Benchmarks públicos y honestos de robustez contra evasión conocida | **No** — es una decisión de transparencia/marketing, no de lenguaje |
| 4 | Embebible on-prem en runtimes no-Python (Go, Elixir, edge/IoT), sin salida de datos | **Sí** — requiere compilar a binario nativo sin runtime interpretado |

Esta tabla corrige una simplificación inicial de la conversación de origen: no es solo el punto 4 el que depende de no ser Python — el punto 2 también. De los cuatro diferenciadores, dos son alcanzables en cualquier lenguaje y dos requieren un lenguaje compilado tipo sistemas (Rust, C++, o similar).

La pregunta que motiva este ADR: **dado que los puntos 1 y 3 se podrían lograr igual en Python (lenguaje con ecosistema más maduro y comunidad más grande), ¿vale la pena la fricción adicional de Rust solo por los puntos 2 y 4, o hay razones técnicas adicionales?**

## Decisión

Se elige **Rust** como lenguaje de implementación del núcleo del proyecto (`alcaide-core`), manteniendo bindings a Python como capa de distribución adicional, no como reemplazo del núcleo.

## Alternativas consideradas

### Opción A — Python puro (con `re` estándar)

Rechazada rápidamente: el módulo `re` de Python usa backtracking, lo que lo hace vulnerable a ReDoS (ver justificación abajo) — inaceptable para un componente cuyo trabajo es procesar input adversarial por diseño.

### Opción B — Python + extensiones en C (`pyahocorasick`, `google-re2`)

Cierra buena parte de la brecha de velocidad de matching puro y de la vulnerabilidad ReDoS (si se usa `re2` en vez de `re`). Es una alternativa viable y honesta. Se descartó como elección principal porque:
- No resuelve los puntos 2 y 4 del diferenciador (WASM, embebible sin runtime).
- Sigue dependiendo de un runtime Python instalado en el destino, y de que la lógica de orquestación alrededor del matching (normalización, scoring) corra en el intérprete de Python, con su recolector de basura y su GIL.

### Opción C — Rust (elegida)

## Justificación técnica adicional (más allá de los puntos 2 y 4 del diferenciador)

1. **Resistencia estructural a ReDoS.** El crate `regex` de Rust garantiza tiempo lineal de ejecución por diseño (sin backtracking catastrófico). Esto no es una optimización de rendimiento — es una propiedad de seguridad relevante específicamente porque este componente procesa texto que un atacante diseñó a propósito para romperlo. Un motor de matching vulnerable a ReDoS es, en sí mismo, un vector de ataque contra el propio filtro.
2. **Sin pausas de recolector de basura.** Relevante para cumplir RNF1 del PRD (p99 < 5ms) de forma predecible bajo carga, incluyendo picos de tráfico que podrían coincidir con un intento de ataque real.
3. **Distribución sin dependencia de runtime.** Un binario Rust no requiere que la máquina destino tenga un intérprete instalado con la versión correcta — relevante tanto para la CLI como para el embebido en otros sistemas (más allá del caso edge/IoT del punto 4).

## Consecuencias

**Positivas:**
- Habilita los puntos 2 y 4 del diferenciador de mercado, inalcanzables en Python.
- Resistencia estructural a ReDoS y latencia más predecible bajo carga.
- Un solo núcleo (`alcaide-core`) sirve a todos los bindings sin duplicar lógica de detección.

**Negativas / trade-offs aceptados conscientemente:**
- Curva de aprendizaje más alta y prototipado más lento que en Python — la fase de curación del set de reglas (`plan-implementacion.md`, hito M6) será más lenta de iterar.
- Comunidad de contribuidores potencialmente más chica para un proyecto open source, comparado con publicar en Python.
- Se renuncia a la velocidad de "shippear algo funcional ya" que permitiría un prototipo en Python para validar demanda antes de invertir en Rust.

## Cuándo revisitar esta decisión

- Si tras publicar la Fase 1 no se logra tracción de contribuidores externos y se atribuye razonablemente a la barrera de entrada de Rust.
- Si la validación con usuarios reales (riesgo abierto en `PRD.md`, sección 10) muestra que nadie pide de verdad el filtro WASM ni el despliegue embebido no-Python — en ese caso, los puntos 2 y 4 dejan de justificar la fricción de Rust y esta decisión debería reabrirse.
