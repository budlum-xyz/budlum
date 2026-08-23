//! Kapalı-devre kaynak denetimi.
//!
//! İlke: Lubot'un okuyabildiği kaynak türleri kapalı bir kümedir
//! (Pollen grant / B.U.D. StorageDeal / SocialFi). İzin **kuralları**
//! zincirden sorgulanır - burada kopyalanmaz (K3 kararı; budlum'daki
//! "ikinci kopya en kötü kopyadır" ilkesi).

use lubot_core::dataset::{SourceKind, SourceRef};

/// Veri katmanı hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataError {
    /// Kapalı-devre dışı kaynak türü (bilinmeyen bayt değeri).
    NotClosedLoop { found: u8 },
    /// Kaynak kapalı-devre ama beklenen tür değil.
    UnexpectedSource {
        expected: SourceKind,
        got: SourceKind,
    },
    /// SHA-256 doğrulaması başarısız - veri akmaz.
    HashMismatch { detail: String },
}

/// Kaynağın kapalı-devre üç kanaldan biri olduğunu doğrula.
///
/// # Errors
///
/// Kaynak türü üç kanaldan biri değilse `NotClosedLoop`.
pub fn assert_closed_loop(source: &SourceRef) -> Result<(), DataError> {
    match source.kind {
        SourceKind::PollenGrant | SourceKind::StorageDeal | SourceKind::SocialRef => Ok(()),
    }
}

/// Ham (bayt) kaynak türünü yorumla; bilinmeyen değerleri reddet.
///
/// # Errors
///
/// `raw_kind` 0..=2 dışındaysa `NotClosedLoop`.
pub fn reject_unknown_source(raw_kind: u8) -> Result<SourceKind, DataError> {
    match raw_kind {
        0 => Ok(SourceKind::PollenGrant),
        1 => Ok(SourceKind::StorageDeal),
        2 => Ok(SourceKind::SocialRef),
        other => Err(DataError::NotClosedLoop { found: other }),
    }
}

/// Kaynağın belirli bir kapalı-devre türde olmasını iste (ör. eğitim
/// planı yalnızca `StorageDeal` kaynaklı setleri kabul edebilir).
///
/// # Errors
///
/// Tür uyuşmuyorsa `UnexpectedSource`.
pub fn require_source(source: &SourceRef, expected: SourceKind) -> Result<(), DataError> {
    assert_closed_loop(source)?;
    if source.kind == expected {
        Ok(())
    } else {
        Err(DataError::UnexpectedSource {
            expected,
            got: source.kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_closed_loop_kinds_pass() {
        assert!(assert_closed_loop(&SourceRef::pollen_grant([1; 32], 2)).is_ok());
        assert!(assert_closed_loop(&SourceRef::storage_deal([1; 32])).is_ok());
        assert!(assert_closed_loop(&SourceRef::social([1; 32])).is_ok());
    }

    #[test]
    fn unknown_raw_source_is_rejected() {
        assert_eq!(reject_unknown_source(0), Ok(SourceKind::PollenGrant));
        assert_eq!(
            reject_unknown_source(3),
            Err(DataError::NotClosedLoop { found: 3 })
        );
        assert_eq!(
            reject_unknown_source(255),
            Err(DataError::NotClosedLoop { found: 255 })
        );
    }

    #[test]
    fn require_source_enforces_exact_kind() {
        let grant = SourceRef::pollen_grant([1; 32], 1);
        assert!(require_source(&grant, SourceKind::PollenGrant).is_ok());
        assert_eq!(
            require_source(&grant, SourceKind::StorageDeal),
            Err(DataError::UnexpectedSource {
                expected: SourceKind::StorageDeal,
                got: SourceKind::PollenGrant
            })
        );
    }
}
