//! `alcaide` binary — `check`, `lint-rules`, `bench`, `contribute` commands.
//!
//! Structural placeholder (milestone M0). Argument parsing and the real
//! commands are implemented in milestone M9.

fn main() {
    // Link test: confirms alcaide-cli can consume alcaide-core's public types.
    let mode = alcaide_core::Mode::Shadow;
    println!("alcaide-cli: M0 scaffold — default mode: {mode:?}");
    println!("Real commands (check/lint-rules/bench/contribute) pending milestone M9.");
}
