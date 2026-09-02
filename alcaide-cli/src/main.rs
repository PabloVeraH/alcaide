//! `alcaide` binary — `check`, `lint-rules`, `bench` commands.
//!
//! Exit code convention (documented, applies to `check`; `lint-rules` and
//! `bench` only ever use 0 or 64, since neither produces a verdict):
//! 0 = Allow, 1 = Block, 2 = Flag, 64 = usage/config error.

mod bench;
mod check;
mod lint_rules;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

const EXIT_USAGE_ERROR: u8 = 64;

#[derive(Parser)]
#[command(
    name = "alcaide",
    about = "A deterministic, auditable prompt-injection firewall"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a single input against a rule set.
    Check {
        /// The text to evaluate.
        text: String,
        /// Path to the rule set YAML file.
        #[arg(long, default_value = "rules.yaml")]
        rules: PathBuf,
        /// Print machine-readable JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Validate a rule set file without evaluating anything.
    LintRules {
        /// Path to the rule set YAML file.
        rules: PathBuf,
    },
    /// Run a rule set against a labeled test corpus and report measured
    /// detection/false-positive rates and latency.
    Bench {
        /// Path to the rule set YAML file.
        rules: PathBuf,
        /// Path to a labeled corpus YAML file (see
        /// `alcaide-core/tests/corpus/prompts.yaml` for the schema).
        #[arg(long)]
        corpus: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Command::Check { text, rules, json } => check::run(&text, &rules, json),
        Command::LintRules { rules } => lint_rules::run(&rules),
        Command::Bench { rules, corpus } => bench::run(&rules, &corpus),
    };

    ExitCode::from(exit_code)
}
