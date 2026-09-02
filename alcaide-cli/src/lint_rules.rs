//! `alcaide lint-rules` — validate a rule set file without evaluating
//! anything.

use alcaide_core::Detector;
use std::path::Path;

use crate::EXIT_USAGE_ERROR;

pub fn run(rules_path: &Path) -> u8 {
    // Goes through the full pipeline (parse, semantic validation, matcher
    // compilation) via Detector::from_config_path, not just YAML parsing
    // -- a malformed regex should be caught here too, not silently at
    // first use.
    match Detector::from_config_path(rules_path) {
        Ok(detector) => {
            println!("OK, {} rules loaded", detector.rule_count());
            0
        }
        Err(error) => {
            eprintln!("Error in {}: {error}", rules_path.display());
            EXIT_USAGE_ERROR
        }
    }
}
