//! SFT veri seti şema doğrulaması.
//!
//! Eğitim koşusundan ÖNCE her kayıt denetlenir: alan varlığı, boşluk
//! kuralları, bayt sınırları. Amaç: bozuk bir örneğin eğitim karışımına
//! girmesini koşuya başlamadan reddetmek (veri kalitesi kapısı).
//!
//! Kural (araştırma §3/§4): 100 mükemmel örnek > 10.000 vasat örnek.

use lubot_data::jsonl::InstructionRecord;

/// Şema hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// `user` veya `assistant` boş.
    EmptyField { line: usize, field: &'static str },
    /// Kayıt bayt sınırını aşıyor (tek örnek şişmesi).
    TooLarge { line: usize, bytes: usize, max: usize },
    /// JSONL satırı çözülemedi (jsonl::decode hatası).
    Unparsable { line: usize, detail: String },
}

/// Tek örnek için bayt tavanı (kesme öncesi ham denetim; gerçek kesme
/// tokenizer'da `cutoff_len` ile yapılır).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Kayıt listesini doğrula. İlk hata döner; hangi satır olduğu söylenir.
///
/// # Errors
///
/// [`SchemaError`] varyantlarından ilki.
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
        let rec = lubot_data::jsonl::decode(line).map_err(|e| SchemaError::Unparsable {
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

/// Karışım raporu: TR/EN oranı hedefi için basit sayım. `tr_ratio` =
/// Türkçe karakter imzası taşıyan örneklerin oranı (0.0..=1.0). Kesin
/// dil tespiti değildir; koşu öncesi sağlık sinyalidir.
#[must_use]
pub fn tr_ratio_estimate(records: &[InstructionRecord]) -> f64 {
    if records.is_empty() {
        return 0.0;
    }
    let tr_markers = [
        'ğ', 'Ğ', 'ü', 'Ü', 'ş', 'Ş', 'ı', 'İ', 'ö', 'Ö', 'ç', 'Ç',
    ];
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
        let lines = vec![s("bu json degil")];
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
