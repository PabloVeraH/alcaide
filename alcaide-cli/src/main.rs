//! `alcaide` binary — `check`, `lint-rules`, `bench` commands.
//!
//! Exit codes:
//! - `check`: 0 = Allow, 1 = Block, 2 = Flag.
//! - `bench`: 0 = every requested gate passed, 1 = a gate failed.
//! - `lint-rules`: 0 = valid.
//! - Any command: 64 = usage or configuration error (including invalid
//!   command-line arguments, which clap would otherwise report as 2 --
//!   indistinguishable from a Flag).

mod bench;
mod check;
mod lint_rules;

use alcaide_core::Detector;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_USAGE_ERROR: u8 = 64;

#[derive(Parser)]
#[command(
    name = "alcaide",
    version,
    about = "A deterministic, auditable prompt-injection firewall"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate one input against a rule set.
    ///
    /// The input is TEXT, the contents of --file, or standard input (when
    /// neither is given, or TEXT is "-").
    Check {
        /// The text to evaluate; "-" or omitted reads standard input.
        #[arg(conflicts_with = "file")]
        text: Option<String>,
        /// Read the text to evaluate from this file.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        /// Rule set YAML file [default: the built-in curated rule set].
        #[arg(long, value_name = "PATH")]
        rules: Option<PathBuf>,
        /// Print machine-readable JSON instead of a human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Validate a rule set file without evaluating anything.
    LintRules {
        /// Path to the rule set YAML file.
        rules: PathBuf,
    },
    /// Run a rule set against a labeled corpus and report measured
    /// detection/false-positive rates and latency.
    Bench {
        /// Labeled corpus YAML file (see
        /// `alcaide-core/tests/corpus/prompts.yaml` for the schema).
        #[arg(long, value_name = "PATH")]
        corpus: PathBuf,
        /// Rule set YAML file [default: the built-in curated rule set].
        #[arg(long, value_name = "PATH")]
        rules: Option<PathBuf>,
        /// Fail (exit 1) if fewer than this fraction of malicious prompts
        /// are detected, e.g. 0.9.
        #[arg(long, value_name = "RATE", value_parser = parse_rate)]
        min_detection: Option<f64>,
        /// Fail (exit 1) if more than this fraction of benign prompts are
        /// false-positived, e.g. 0.05.
        #[arg(long, value_name = "RATE", value_parser = parse_rate)]
        max_false_positive: Option<f64>,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // --help and --version are "errors" to clap but succeed.
            let code = if error.use_stderr() {
                EXIT_USAGE_ERROR
            } else {
                0
            };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    let exit_code = match cli.command {
        Command::Check {
            text,
            file,
            rules,
            json,
        } => check::run(text.as_deref(), file.as_deref(), rules.as_deref(), json),
        Command::LintRules { rules } => lint_rules::run(&rules),
        Command::Bench {
            corpus,
            rules,
            min_detection,
            max_false_positive,
        } => bench::run(
            &corpus,
            rules.as_deref(),
            bench::Gates {
                min_detection,
                max_false_positive,
            },
        ),
    };

    ExitCode::from(exit_code)
}

/// Loads the rule set at `path`, or the built-in one when `None`. Reports
/// a load error on stderr and returns the usage-error exit code.
fn load_detector(path: Option<&Path>) -> Result<Detector, u8> {
    match path {
        None => Ok(Detector::with_default_rules()),
        Some(path) => Detector::from_config_path(path).map_err(|error| {
            eprintln!("Error loading {}: {error}", path.display());
            EXIT_USAGE_ERROR
        }),
    }
}

/// Parses a rate: a number between 0 and 1 inclusive.
fn parse_rate(value: &str) -> Result<f64, String> {
    match value.parse::<f64>() {
        Ok(rate) if (0.0..=1.0).contains(&rate) => Ok(rate),
        _ => Err(format!("{value:?} is not a rate between 0 and 1")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_must_be_between_zero_and_one() {
        assert_eq!(parse_rate("0"), Ok(0.0));
        assert_eq!(parse_rate("0.95"), Ok(0.95));
        assert_eq!(parse_rate("1"), Ok(1.0));
        assert!(parse_rate("1.5").is_err());
        assert!(parse_rate("-0.1").is_err());
        assert!(parse_rate("NaN").is_err());
        assert!(parse_rate("ninety").is_err());
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
