# Alcaide — Project Conventions

## Language

- **README.md** and all other repo-facing content: English.
- **Code comments, doc comments (`///`, `//!`), and user-facing strings in source code** (error messages, CLI output): English.
- **Chat with the maintainer**: Chilean Spanish, regardless of the language used in code or repo content.

Rationale: the project targets a primarily English-speaking Rust/open-source audience (crates.io, GitHub).

Exception: test fixtures that intentionally exercise Spanish-language detection patterns (e.g. example rules) stay in Spanish — translating them would defeat their purpose.

## Repository scope

Product and business planning documentation (requirements, architecture decisions, legal/licensing analysis) is maintained privately and is intentionally not part of this public repository.

## Git commits

- No external attribution of any kind: no `Co-Authored-By` trailers, no AI-tooling/session metadata (e.g. session links), no footers referencing the tool used to write the code.
- Author and committer must be the maintainer's own configured git identity only — nothing else.
- Commit messages otherwise follow Conventional Commits (`type: description`).
