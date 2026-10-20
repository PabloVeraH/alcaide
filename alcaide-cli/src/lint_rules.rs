//! `alcaide lint-rules` — validate a rule set file without evaluating
//! anything.

use std::path::Path;

use crate::load_detector;

pub fn run(rules_path: &Path) -> u8 {
    // Goes through the full pipeline (parse, semantic validation, matcher
    // compilation, disabled rules included) -- a malformed regex should be
    // caught here too, not silently at first use.
    match load_detector(Some(rules_path)) {
        Ok(detector) => {
            println!("OK, {} rules loaded", detector.rule_count());
            0
        }
        Err(code) => code,
    }
}
