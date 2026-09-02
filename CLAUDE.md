# Alcaide — Project Conventions

## Language

- **README.md** (repository root): English.
- **Code comments, doc comments (`///`, `//!`), and user-facing strings in source code** (error messages, CLI output): English.
- **Planning and decision documentation** (`docs/` folder — PRD, TRD, ADRs, etc.): Spanish, as originally authored. Not to be translated unless explicitly requested.
- **Chat with the maintainer**: Chilean Spanish, regardless of the language used in code, comments, or docs.

Rationale: the project targets a primarily English-speaking Rust/open-source audience (crates.io, GitHub), while the internal planning documentation and the maintainer's working language remain Spanish. These are independent axes — don't conflate them.

Exception: test fixtures that intentionally exercise Spanish-language detection patterns (e.g. example rules copied verbatim from `docs/`) stay in Spanish — translating them would defeat their purpose.
