# Security Policy

Alcaide is a security control: a bypass of its detection is a security issue, and so is anything that lets crafted input crash, hang, or slow down the host process.

## Supported versions

Alcaide is pre-1.0. Only the latest release receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Report it privately through GitHub's [private vulnerability reporting](https://github.com/PabloVeraH/alcaide/security/advisories/new) instead.

Include what you can of:

- the input (or a description of how to build it) and the rule set used;
- the verdict you got and the one you expected;
- the version or commit you tested.

You can expect an acknowledgement within 7 days. Once a fix is released, the advisory is published and you are credited, unless you prefer otherwise.

## What counts

In scope:

- **Detection bypasses of the normalization stage**: an encoding, Unicode trick, or formatting change that hides a payload the default rules otherwise catch (e.g. a new invisible character, a homoglyph, an encoding the decoder misses).
- **Panics, hangs or super-linear slowdowns** of `Detector::evaluate` on any input.
- **Privacy leaks**: raw input reaching the logs while `log_raw_input` is `false`.
- **Fail-open behavior** contrary to the configuration (e.g. an oversized input or internal error that is allowed despite `on_oversize: block` / `on_error: block`).

Out of scope (open a regular issue or pull request instead):

- Phrasings the default rule set doesn't cover yet: new rules are welcome as contributions (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- The documented, acknowledged limits in [BENCHMARKS.md](BENCHMARKS.md), such as typoglycemia (scrambled letters).
