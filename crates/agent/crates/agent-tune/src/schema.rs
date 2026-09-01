//! SFT data set schema validation.
//!
//! Every record is inspected BEFORE the training run: field presence,
//! whitespace rules, byte limits. The goal is to refuse a corrupt example
//! before the run starts, rather than letting it into the training mixture (a
//! data quality gate).
//!
//! The rule (research sections 3 and 4): 100 perfect examples beat 10,000
//! mediocre ones.
//!
//! Turkish text remains in this file on purpose: `tr_ratio_estimate` detects
//! the Turkish character signature, and both the marker list and the test
//! fixture that exercises it have to carry those characters.

use agent_data::jsonl::InstructionRecord;

/// Schema errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// `user` or `assistant` is empty.
    EmptyField { line: usize, field: &'static str },
    /// The record exceeds the byte limit (a single example ballooned).
    TooLarge {
        line: usize,
        bytes: usize,
        max: usize,
    },
    /// The JSONL line could not be decoded (a jsonl::decode error).
    Unparsable { line: usize, detail: String },
}

/// The byte ceiling for a single example (a raw check before truncation; the
/// real truncation happens in the tokenizer through `cutoff_len`).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Validate the record list. It returns the first error and names the line it
/// came from.
///
/// # Errors
///
/// The first of the [`SchemaError`] variants.
pub fn validate_records(lines: &[String]) -> Result<Vec<InstructionRecord>, SchemaError> {
    let mut out = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let line_no = i + 1;
        if line.len() > MAX_RECORD_BYTES {
            return Err(SchemaError::TooLarge {
                line: line_no,
                bytes: line.len(),
                max: MAX_RECORD_BYTES,
            });
        }
        let rec = agent_data::jsonl::decode(line).map_err(|e| SchemaError::Unparsable {
            line: line_no,
            detail: e,
        })?;
        if rec.user.trim().is_empty() {
            return Err(SchemaError::EmptyField {
                line: line_no,
                field: "user",
            });
        }
        if rec.assistant.trim().is_empty() {
            return Err(SchemaError::EmptyField {
                line: line_no,
                field: "assistant",
            });
        }
        out.push(rec);
    }
    Ok(out)
}

/// The mixture report: a simple count for the TR/EN ratio target. `tr_ratio`
/// is the fraction of examples carrying the Turkish character signature
/// (0.0..=1.0). It is not exact language detection, only a health signal
/// before the run.
#[must_use]
pub fn tr_ratio_estimate(records: &[InstructionRecord]) -> f64 {
    if records.is_empty() {
        return 0.0;
    }
    let tr_markers = ['ğ', 'Ğ', 'ü', 'Ü', 'ş', 'Ş', 'ı', 'İ', 'ö', 'Ö', 'ç', 'Ç'];
    let mut tr = 0usize;
    for r in records {
        let text: String = format!("{} {}", r.user, r.assistant);
        if text.chars().any(|c| tr_markers.contains(&c)) {
            tr += 1;
        }
    }
    tr as f64 / records.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_string()
    }

    #[test]
    fn valid_records_pass() {
        let lines = vec![
            s(r#"{"user":"Başkent neresi?","assistant":"Ankara."}"#),
            s(r#"{"user":"What is 2+2?","assistant":"4"}"#),
        ];
        let recs = validate_records(&lines).unwrap();
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn empty_assistant_is_rejected_with_line_number() {
        let lines = vec![
            s(r#"{"user":"soru","assistant":"cevap"}"#),
            s(r#"{"user":"soru2","assistant":"   "}"#),
        ];
        assert_eq!(
            validate_records(&lines),
            Err(SchemaError::EmptyField {
                line: 2,
                field: "assistant"
            })
        );
    }

    #[test]
    fn unparsable_line_is_rejected() {
        let lines = vec![s("this is not json")];
        assert!(matches!(
            validate_records(&lines),
            Err(SchemaError::Unparsable { line: 1, .. })
        ));
    }

    #[test]
    fn turkish_ratio_detects_markers() {
        let recs = vec![
            InstructionRecord {
                system: None,
                user: "şeker nedir?".to_string(),
                assistant: "tatlı bir maddedir.".to_string(),
            },
            InstructionRecord {
                system: None,
                user: "What is salt?".to_string(),
                assistant: "A mineral.".to_string(),
            },
        ];
        let ratio = tr_ratio_estimate(&recs);
        assert!((ratio - 0.5).abs() < f64::EPSILON);
    }
}
