//! Integration tests for `Detector::from_config_path` — exercises real
//! file I/O, as opposed to the in-memory YAML-string tests in
//! `src/config.rs` (which cover parsing/validation logic in isolation).

use alcaide_core::{ConfigError, Detector};
use std::io::Write;

const VALID_YAML: &str = r#"
version: 1
defaults:
  mode: shadow
  block_threshold: high
rules:
  - id: jailbreak-ignore-instructions
    category: jailbreak
    severity: high
    pattern_type: regex
    pattern: "ignore all previous instructions"
    enabled: true
"#;

#[test]
fn loads_a_valid_config_file() {
    let mut file = tempfile::NamedTempFile::new().expect("create temp file");
    write!(file, "{VALID_YAML}").expect("write temp file");

    let result = Detector::from_config_path(file.path());

    assert!(result.is_ok());
}

#[test]
fn reports_io_error_for_missing_file() {
    let missing_path = std::path::Path::new("/nonexistent/path/rules.yaml");

    let result = Detector::from_config_path(missing_path);

    match result {
        Err(ConfigError::Io { path, .. }) => assert_eq!(path, missing_path),
        other => panic!("expected ConfigError::Io, got {other:?}"),
    }
}
