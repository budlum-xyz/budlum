//! Kayıt formatı: JSONL (serde_json).
//!
//! Üretim formatı JSON Lines'tır; chat şablonu ayrıca `template` modülünde
//! tutulur. Derinleştirme (2026-08-13): bağımlılıksız yer tutucu format
//! kaldırıldı; kayıtlar artık gerçek JSON'dur.

use serde::{Deserialize, Serialize};

/// SFT kaydı: system (opsiyonel) / user / assistant üçlüsü.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub user: String,
    pub assistant: String,
}

/// Kaydı tek satırlık JSON'a kodla.
///
/// # Panics
///
/// Yalnızca serileştirme hatalarında (String alanlar için pratikte imkânsız);
/// üretimde `Result` dönen sarmalayıcı kullanılır.
#[must_use]
pub fn encode(rec: &InstructionRecord) -> String {
    serde_json::to_string(rec).expect("InstructionRecord serileştirilemeli")
}

/// JSONL satırından kayıt çöz.
///
/// # Errors
///
/// Satır geçerli JSON değilse veya alanlar eksikse.
pub fn decode(line: &str) -> Result<InstructionRecord, String> {
    serde_json::from_str(line).map_err(|e| format!("JSONL kaydı çözülemedi: {e}"))
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
        assert_eq!(decode(&encode(&rec)).unwrap(), rec);
    }

    #[test]
    fn roundtrip_with_special_characters() {
        let rec = InstructionRecord {
            system: Some("a|b\\c \"d\"".to_string()),
            user: "x|y\nz".to_string(),
            assistant: "ş ğ ü ö ç".to_string(),
        };
        assert_eq!(decode(&encode(&rec)).unwrap(), rec);
    }

    #[test]
    fn system_field_is_optional_in_json() {
        let line = r#"{"user":"soru","assistant":"cevap"}"#;
        let rec = decode(line).unwrap();
        assert_eq!(rec.system, None);
    }

    #[test]
    fn malformed_json_is_error() {
        assert!(decode("tek-alan").is_err());
        assert!(decode(r#"{"user":1}"#).is_err());
    }
}
