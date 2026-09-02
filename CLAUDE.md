# Alcaide — Project Conventions

## Language

- **README.md** and all other repo-facing content: English.
- **Code comments, doc comments (`///`, `//!`), and user-facing strings in source code** (error messages, CLI output): English.
- **Chat with the maintainer**: Chilean Spanish, regardless of the language used in code or repo content.

Rationale: the project targets a primarily English-speaking Rust/open-source audience (crates.io, GitHub).

Exception: test fixtures that intentionally exercise Spanish-language detection patterns (e.g. example rules) stay in Spanish — translating them would defeat their purpose.

## Repository scope

Product and business planning documentation (requirements, architecture decisions, legal/licensing analysis) is maintained privately and is intentionally not part of this public repository.
