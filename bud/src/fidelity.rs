//! The fidelity core - whatever the resolution is, it is preserved; the format
//! is free to change.
//! ContentId = SHA3-256(domain-tag || length || kanonik baytlar) - kriptografik (K3 fix)
//! Render deterministik, float yok, IHDR boyut birebir

use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FidelityError {
    ResolutionMismatch {
        expected: (u32, u32),
        got: (u32, u32),
    },
    HashMismatch,
    FloatForbidden,
}

impl std::fmt::Display for FidelityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FidelityError::ResolutionMismatch { expected, got } => write!(
                f,
                "resolution mismatch expected {:?} got {:?}",
                expected, got
            ),
            FidelityError::HashMismatch => write!(f, "hash mismatch - byte changed, fidelity lost"),
            FidelityError::FloatForbidden => write!(f, "float forbidden in render - determinism"),
        }
    }
}
impl std::error::Error for FidelityError {}

/// ContentId - independent of G2, a pure hash. In reality the blake3 crate is
/// used; the skeleton carries no dependency and uses a deterministic hash
/// instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentId([u8; 32]);

impl ContentId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        // K3 fix (2026-08-16): DefaultHasher and SipHash are NOT cryptographic (a collision can be forged
        // forged). The real cryptographic hash: SHA3-256, domain-tagged + length-prefixed
        // (budlum src/storage/content_id.rs deseniyle ayni: BDLM_CONTENT_V1).
        let mut h = Sha3_256::new();
        h.update(b"BDLM_CONTENT_V1");
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
        ContentId(h.finalize().into())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderFormat {
    Original,
    AvifSameRes,
    WebPLossless,
    Av1SameRes,
    Thumbnail { w: u32, h: u32 }, // derived; cannot stand in for the original
}

#[derive(Debug, Clone)]
pub struct FidelityCore {
    pub canonical: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub content_id: ContentId,
}

impl FidelityCore {
    pub fn new(bytes: Vec<u8>, width: u32, height: u32) -> Self {
        let cid = ContentId::from_bytes(&bytes);
        FidelityCore {
            canonical: bytes,
            width,
            height,
            content_id: cid,
        }
    }

    /// Render - deterministik, float yok
    /// The KF2 gate: the rendered result has to carry the same resolution.
    pub fn render(&self, fmt: &RenderFormat) -> Result<(Vec<u8>, (u32, u32)), FidelityError> {
        match fmt {
            RenderFormat::Original => Ok((self.canonical.clone(), (self.width, self.height))),
            RenderFormat::AvifSameRes | RenderFormat::WebPLossless | RenderFormat::Av1SameRes => {
                // The format may change but the resolution is preserved.
                // Iskelette ayni bayt donduruluyor, gercekte transcode
                Ok((self.canonical.clone(), (self.width, self.height)))
            }
            RenderFormat::Thumbnail { w, h } => {
                // Derived - a separate ContentId; cannot stand in for the original
                // Deterministik nearest-neighbor (float yok)
                Ok((self.canonical.clone(), (*w, *h)))
            }
        }
    }

    pub fn verify_fidelity(
        &self,
        rendered_bytes: &[u8],
        rendered_res: (u32, u32),
    ) -> Result<(), FidelityError> {
        if rendered_res != (self.width, self.height) {
            return Err(FidelityError::ResolutionMismatch {
                expected: (self.width, self.height),
                got: rendered_res,
            });
        }
        let got_id = ContentId::from_bytes(rendered_bytes);
        // For an original the hash has to match; for a derivative it need not - this function is only the original path.
        if got_id != self.content_id {
            return Err(FidelityError::HashMismatch);
        }
        Ok(())
    }

    /// A separate check for a derivative: the resolution is preserved but the
    /// hash may differ, because the format changed.
    pub fn verify_derived_resolution(&self, derived_res: (u32, u32)) -> Result<(), FidelityError> {
        if derived_res != (self.width, self.height) {
            return Err(FidelityError::ResolutionMismatch {
                expected: (self.width, self.height),
                got: derived_res,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_fidelity_ok() {
        let core = FidelityCore::new(vec![1, 2, 3, 4], 1920, 1080);
        let (bytes, res) = core.render(&RenderFormat::Original).unwrap();
        assert!(core.verify_fidelity(&bytes, res).is_ok());
    }
    #[test]
    fn resolution_mismatch_detected() {
        let core = FidelityCore::new(vec![1, 2, 3], 1920, 1080);
        let err = core.verify_fidelity(&[1, 2, 3], (1280, 720)).unwrap_err();
        assert!(matches!(err, FidelityError::ResolutionMismatch { .. }));
    }
    #[test]
    fn hash_mismatch_detected() {
        let core = FidelityCore::new(vec![1, 2, 3], 100, 100);
        let err = core.verify_fidelity(&[4, 5, 6], (100, 100)).unwrap_err();
        assert_eq!(err, FidelityError::HashMismatch);
    }
}
