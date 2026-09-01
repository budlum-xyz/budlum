//! The record format: JSONL (serde_json).
//!
//! The production format is JSON Lines; the chat template is kept separately
//! in the `template` module. Deepening (2026-08-13): the dependency-free
//! placeholder format was removed, so records are real JSON now.
//!
//! Turkish text stays in the tests on purpose: the round trip has to carry
//! multi-byte UTF-8, and that is what those fixtures measure.

use serde::{Deserialize, Serialize};

/// An SFT record: the system (optional) / user / assistant triple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub user: String,
    pub assistant: String,
}

/// Encode the record into a single line of JSON.
///
/// The documentation used to say "production uses a wrapper that returns a
/// `Result`". No such wrapper existed: this function was the only path and it
/// panicked, and it was called only from the tests. The claim was removed, and
/// so was the panic.
///
/// Serialisation does not fail here in practice (three `String` fields), but
/// "does not" and "cannot" are not the same thing, and the release profile
/// uses `panic = "abort"`. On an error the caller decides.
///
/// # Errors
///
/// Returns an error when `serde_json` cannot serialise the record.
pub fn encode(rec: &InstructionRecord) -> Result<String, String> {
    serde_json::to_string(rec).map_err(|e| format!("the JSONL record could not be encoded: {e}"))
}

/// Decode a record from a JSONL line.
///
/// # Errors
///
/// When the line is not valid JSON or fields are missing.
pub fn decode(line: &str) -> Result<InstructionRecord, String> {
    serde_json::from_str(line).map_err(|e| format!("the JSONL record could not be decoded: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_plain() {
        let rec = InstructionRecord {
            system: None,
            user: "Başkent neresi?".to_string(),
            assistant: "Ankara.".to_string(),
        };
        assert_eq!(decode(&encode(&rec).unwrap()).unwrap(), rec);
    }

    #[test]
    fn roundtrip_with_special_characters() {
        let rec = InstructionRecord {
            system: Some("a|b\\c \"d\"".to_string()),
            user: "x|y\nz".to_string(),
            assistant: "ş ğ ü ö ç".to_string(),
        };
        assert_eq!(decode(&encode(&rec).unwrap()).unwrap(), rec);
    }

    #[test]
    fn system_field_is_optional_in_json() {
        let line = r#"{"user":"question","assistant":"answer"}"#;
        let rec = decode(line).unwrap();
        assert_eq!(rec.system, None);
    }

    #[test]
    fn malformed_json_is_error() {
        assert!(decode("single-field").is_err());
        assert!(decode(r#"{"user":1}"#).is_err());
    }
}
