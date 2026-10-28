//! The normalization stage on its own:
//!
//! - every span of the normalized text maps to a valid span of the input;
//! - decoded blobs point at real text;
//! - folding is idempotent (a rule pattern is folded once, the input once:
//!   they only agree if folding a folded text changes nothing);
//! - obfuscating ASCII text with the tricks normalization exists to undo
//!   (invisible characters, look-alike letters, fullwidth forms, tag
//!   characters, odd whitespace) yields exactly the same normalized text.

#![no_main]

use alcaide_core::normalize;
use alcaide_fuzz::assert_valid_span;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Case {
    text: String,
    /// One obfuscation choice per character of `text`, cycled.
    ops: Vec<u8>,
}

/// Characters that render as nothing and must be dropped.
const INVISIBLE: [char; 6] = [
    '\u{200B}', '\u{200D}', '\u{00AD}', '\u{2060}', '\u{FEFF}', '\u{FE0F}',
];

/// Whitespace that must collapse into one ASCII space.
const SPACES: [char; 6] = [' ', '\t', '\n', '\u{00A0}', '\u{2003}', '\u{3000}'];

/// Non-Latin letters that normalization must read as `c`.
fn lookalikes(c: char) -> &'static [char] {
    match c {
        'A' => &['А', 'Α'],
        'B' => &['В', 'Β'],
        'C' => &['С'],
        'E' => &['Е', 'Ε'],
        'H' => &['Н', 'Η'],
        'I' => &['І', 'Ι'],
        'J' => &['Ј'],
        'K' => &['К', 'Κ'],
        'M' => &['М', 'Μ'],
        'N' => &['Ν'],
        'O' => &['О', 'Ο'],
        'P' => &['Р', 'Ρ'],
        'Q' => &['Ԛ'],
        'S' => &['Ѕ'],
        'T' => &['Т', 'Τ'],
        'W' => &['Ԝ'],
        'X' => &['Х', 'Χ'],
        'Y' => &['У', 'Υ'],
        'Z' => &['Ζ'],
        'a' => &['а', 'α', 'ɑ'],
        'c' => &['с'],
        'd' => &['ԁ'],
        'e' => &['е'],
        'g' => &['ɡ'],
        'h' => &['һ'],
        'i' => &['і', 'ι', 'ı'],
        'j' => &['ј'],
        'k' => &['κ'],
        'l' => &['ӏ'],
        'o' => &['о', 'ο', 'օ'],
        'p' => &['р', 'ρ'],
        'q' => &['ԛ'],
        's' => &['ѕ'],
        'u' => &['υ', 'ս'],
        'v' => &['ν'],
        'w' => &['ԝ'],
        'x' => &['х', 'χ'],
        'y' => &['у'],
        _ => &[],
    }
}

/// Rewrites ASCII `text` with evasion tricks chosen by `ops`; normalizing
/// the result must give the same text as normalizing the original.
fn obfuscate(text: &str, ops: &[u8]) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        let op = ops[i % ops.len()];
        let pick = usize::from(op / 8);
        match op % 8 {
            1 => {
                out.push(INVISIBLE[pick % INVISIBLE.len()]);
                out.push(c);
            }
            2 if !lookalikes(c).is_empty() => {
                let options = lookalikes(c);
                out.push(options[pick % options.len()]);
            }
            // Fullwidth forms U+FF01..U+FF5E are NFKC-equivalent to ASCII
            // U+0021..U+007E.
            3 if ('!'..='~').contains(&c) => {
                out.push(char::from_u32(u32::from(c) - 0x21 + 0xFF01).expect("valid"));
            }
            // Tag characters mirror printable ASCII at U+E0020..U+E007E.
            4 if (' '..='~').contains(&c) => {
                out.push(char::from_u32(u32::from(c) + 0xE0000).expect("valid"));
            }
            5 if c.is_whitespace() => {
                for j in 0..=pick % 3 {
                    out.push(SPACES[(pick + j) % SPACES.len()]);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fuzz_target!(|case: Case| {
    let input = case.text.as_str();
    let normalized = normalize(input);
    let text = &normalized.normalized_text;

    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain([text.len()])
        .collect();
    for &b in &boundaries {
        assert_valid_span(input, normalized.original_span((b, b)));
        assert_valid_span(input, normalized.original_span((0, b)));
        assert_valid_span(input, normalized.original_span((b, text.len())));
    }
    for blob in &normalized.decoded {
        assert_valid_span(text, blob.span);
        assert!(blob.span.0 < blob.span.1, "empty decoded blob");
    }

    if normalized.decoded.is_empty() {
        assert_eq!(
            &normalize(text).normalized_text,
            text,
            "folding is not idempotent for {input:?}"
        );
    }

    if input.is_ascii() && !case.ops.is_empty() {
        let obfuscated = obfuscate(input, &case.ops);
        assert_eq!(
            &normalize(&obfuscated).normalized_text,
            text,
            "obfuscation survived normalization: {obfuscated:?} vs {input:?}"
        );
    }
});
