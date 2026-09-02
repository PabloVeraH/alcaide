# Alcaide

Filtro de inyección de prompts en Rust: motor de reglas deterministas y auditables que inspecciona el input de un usuario antes de que llegue a un LLM.

**Estado del proyecto: en desarrollo temprano (hito M0 del roadmap).** La API pública todavía no está implementada — ver [`docs/plan-implementacion.md`](docs/plan-implementacion.md) para el estado real de cada componente. Todavía no es utilizable en producción.

## Documentación

Toda la documentación de producto, arquitectura y decisiones de diseño vive en [`docs/`](docs/) — empieza por [`docs/README.md`](docs/README.md) para el índice completo.

## Licencia

Este crate (`alcaide-core` y `alcaide-cli`) se distribuye bajo [AGPL-3.0-only](LICENSE). Ver [`docs/ADR-004-licenciamiento-dual-agpl-comercial.md`](docs/ADR-004-licenciamiento-dual-agpl-comercial.md) para el detalle del modelo de licenciamiento dual del proyecto.
