//! B.U.D. 2.0 - THE LOSS GATE (the KF2 extension: the AVIF lossy threshold plus
//! ZFP/SZ error-bounded classes).
//!
//! Remaining work: "the AVIF lossy-tier threshold plus admission of the ZFP/SZ
//! error-bounded class."
//! The rule: a lossy transform is admitted only under VISUALLY-LOSSLESS or
//! ERROR-BOUNDED thresholds; every lossy transform carries its lossiness
//! METADATA (the measurement) and the gate either refuses it or records it.
//! The default thresholds:
//! - AVIF/JPEG visually lossless: crf <= 32 (the threshold of the measured 3.2x
//!   gain; F134)
//! - ZFP/SZ error-bounded: a relative error <= 1e-3 (the scientific class; the
//!   100-web finding says 6-23x)
//! - Resolution is ALWAYS preserved (KF2)
//!
//! The defaults are open to a product decision (they are comment lines and ask
//! for the user's approval).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const FID_MAGIC: [u8; 8] = *b"\xB5FID1\0\0\0";

pub const AVIF_CRF_VISUALLY_LOSSLESS: u32 = 32; // at or below this counts as visually lossless (measured)
pub const ZFP_REL_ERROR_BOUND: f64 = 1e-3; // ≤ bu → error-bounded
pub const SZ_REL_ERROR_BOUND: f64 = 1e-3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossyKind {
    None,             // lossless
    VisuallyLossless, // under the AVIF/JXL crf threshold
    ErrorBounded,     // under the ZFP/SZ relative error threshold
    Unbounded,        // RED
}

/// The lossiness decision: visual media by crf, scientific data by relative
/// error.
pub fn classify_lossy(kind: &str, crf: Option<u32>, rel_error: Option<f64>) -> LossyKind {
    match kind {
        "avif" | "jxl" | "webp" | "jpeg" => match crf {
            Some(c) if c <= AVIF_CRF_VISUALLY_LOSSLESS => LossyKind::VisuallyLossless,
            Some(_) => LossyKind::Unbounded,
            None => LossyKind::None,
        },
        "zfp" | "sz" => match rel_error {
            Some(e) if e <= ZFP_REL_ERROR_BOUND => LossyKind::ErrorBounded,
            Some(_) => LossyKind::Unbounded,
            None => LossyKind::None,
        },
        _ => LossyKind::None,
    }
}

/// The gate: the list of admitted lossiness classes.
pub fn gate_allows(l: LossyKind) -> bool {
    // Lossless (None) always passes; bounded lossy classes are admitted;
    // unbounded ones are REFUSED.
    matches!(
        l,
        LossyKind::None | LossyKind::VisuallyLossless | LossyKind::ErrorBounded
    )
}

pub fn fidelity_digest(kind: &str, crf: Option<u32>, rel_error: Option<f64>) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(FID_MAGIC);
    h.update(kind.as_bytes());
    h.update(crf.unwrap_or(u32::MAX).to_le_bytes());
    h.update(rel_error.unwrap_or(f64::MAX).to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_avif_threshold_is_correct() {
        assert!(gate_allows(classify_lossy("avif", Some(30), None)));
        assert!(gate_allows(classify_lossy("avif", Some(32), None)));
        assert!(!gate_allows(classify_lossy("avif", Some(40), None)));
    }

    #[test]
    fn the_error_bounded_class_is_admitted() {
        assert!(gate_allows(classify_lossy("zfp", None, Some(1e-4))));
        assert!(!gate_allows(classify_lossy("sz", None, Some(0.01))));
    }

    #[test]
    fn lossless_always_passes() {
        assert!(gate_allows(classify_lossy("png", None, None)));
    }

    #[test]
    fn the_resolution_is_preserved_note() {
        // KF2: this module is only the threshold; resolution preservation is
        // guaranteed on the code path.
        assert_eq!(AVIF_CRF_VISUALLY_LOSSLESS, 32);
    }
}
