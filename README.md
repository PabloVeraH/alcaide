# Alcaide

A deterministic, auditable prompt-injection firewall written in Rust — inspects user input before it reaches an LLM.

**Project status: early development (roadmap milestone M0).** The public API is not implemented yet — see [`docs/plan-implementacion.md`](docs/plan-implementacion.md) for the real status of each component. Not production-ready.

## Documentation

All product, architecture, and design-decision documentation lives in [`docs/`](docs/) — start at [`docs/README.md`](docs/README.md) for the full index. (Note: the planning documentation is written in Spanish, the maintainer's working language; the code and this README are in English.)

## License

This crate (`alcaide-core` and `alcaide-cli`) is distributed under [AGPL-3.0-only](LICENSE). See [`docs/ADR-004-licenciamiento-dual-agpl-comercial.md`](docs/ADR-004-licenciamiento-dual-agpl-comercial.md) for the project's dual-licensing model.
