//! Loading a rule file from arbitrary YAML: never panics, never hangs.
//! When the file is accepted, the resulting detector must uphold every
//! evaluation guarantee on the text that follows the first NUL byte.

#![no_main]

use alcaide_core::Detector;
use alcaide_fuzz::check_evaluate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (yaml, text) = match data.iter().position(|&b| b == 0) {
        Some(nul) => (&data[..nul], &data[nul + 1..]),
        None => (data, &[][..]),
    };
    let Ok(yaml) = std::str::from_utf8(yaml) else {
        return;
    };
    let Ok(detector) = Detector::from_yaml_str(yaml) else {
        return;
    };
    check_evaluate(&detector, &String::from_utf8_lossy(text));
});
