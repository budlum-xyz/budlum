//! İçerik doğrulaması - gerçek SHA-256.
//!
//! Üretim yolunun ilk adımı: iskelet artık fail-closed "uygulanmadı"
//! hatası döndürmez; içerik hash'i gerçek SHA-256 ile doğrulanır.
//! Doğrulama başarısızsa `HashMismatch` - veri akmaz.

use lubot_core::model::Hash32;
use sha2::{Digest, Sha256};

use crate::source::DataError;

/// İçeriği beklenen hex SHA-256 ile doğrula.
///
/// # Errors
///
/// - Hex çözülemezse `HashMismatch` (boş/yanlış biçim).
/// - Digest uyuşmuyorsa `HashMismatch`.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<(), DataError> {
    let expected: Vec<u8> = hex_bytes(expected_hex)
        .ok_or_else(|| DataError::HashMismatch {
            detail: format!("beklenen hex çözülemedi: {expected_hex}"),
        })?;
    if expected.len() != 32 {
        return Err(DataError::HashMismatch {
            detail: format!("SHA-256 32 bayttır; {expected_hex} farklı uzunlukta"),
        });
    }
    let actual = Sha256::digest(data);
    if actual.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(DataError::HashMismatch {
            detail: format!("beklenen: {expected_hex}, gerçek: {}", hex_of(actual.as_slice())),
        })
    }
}

/// İçerikten content_id türet - SHA-256 (üretim biçimi).
#[must_use]
pub fn content_id_of(data: &[u8]) -> Hash32 {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_hash_passes() {
        let hex = hex_of(&content_id_of(b"lubot"));
        assert_eq!(verify_sha256(b"lubot", &hex), Ok(()));
    }

    #[test]
    fn tampered_data_is_rejected() {
        let hex = hex_of(&content_id_of(b"lubot"));
        assert!(matches!(
            verify_sha256(b"lobot", &hex),
            Err(DataError::HashMismatch { .. })
        ));
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(matches!(
            verify_sha256(b"x", "zz"),
            Err(DataError::HashMismatch { .. })
        ));
        assert!(matches!(
            verify_sha256(b"x", "abcd"),
            Err(DataError::HashMismatch { .. })
        ));
    }

    #[test]
    fn content_id_is_deterministic_and_32_bytes() {
        assert_eq!(content_id_of(b"lubot"), content_id_of(b"lubot"));
        assert_eq!(content_id_of(b"lubot").len(), 32);
    }
}
