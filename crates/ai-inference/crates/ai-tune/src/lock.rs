//! The output hash lock: a training output is bound to its manifest digest.
//!
//! The on-chain `register_ai_model(model_hash)` record has to match this
//! digest: an output not derived from the same digest is not accepted.

use ai_core::manifest::LoRaManifest;
use ai_core::model::{Hash32, ModelId};

/// The lock placed on a training output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLock {
    pub manifest_digest: Hash32,
    pub model_id: ModelId,
}

/// Produces an output lock from a manifest.
#[must_use]
pub fn lock_output(manifest: &LoRaManifest) -> OutputLock {
    OutputLock {
        manifest_digest: manifest.digest(),
        model_id: manifest.base_model,
    }
}

/// Verifies that the lock and the manifest match.
///
/// # Errors
///
/// If the digest or the model_id does not match.
pub fn verify_lock(lock: &OutputLock, manifest: &LoRaManifest) -> Result<(), String> {
    if lock.model_id == ModelId([0u8; 32]) || lock.manifest_digest == [0u8; 32] {
        return Err("output lock carries a zero model_id or manifest_digest".to_string());
    }
    if lock.manifest_digest != manifest.digest() {
        return Err("the output lock does not match the manifest digest".to_string());
    }
    if lock.model_id != manifest.base_model {
        return Err("the output lock does not match the base model".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_matches_its_manifest() {
        let m = LoRaManifest::new(ModelId([4; 32]), 16, 32);
        let lock = lock_output(&m);
        assert!(verify_lock(&lock, &m).is_ok());
    }

    #[test]
    fn tampered_manifest_breaks_lock() {
        let m = LoRaManifest::new(ModelId([4; 32]), 16, 32);
        let lock = lock_output(&m);

        let mut tampered = m.clone();
        tampered.rank = 64;
        assert!(verify_lock(&lock, &tampered).is_err());
    }

    /// Swapping the adapter hash or dtype after locking is caught.
    #[test]
    fn swapped_adapter_or_dtype_breaks_lock() {
        let mut m = LoRaManifest::new(ModelId([4; 32]), 16, 32);
        m.adapter_sha256 = Some("ab".repeat(32));
        let lock = lock_output(&m);
        assert!(verify_lock(&lock, &m).is_ok());

        let mut swapped = m.clone();
        swapped.adapter_sha256 = Some("cd".repeat(32));
        assert!(verify_lock(&lock, &swapped).is_err());

        let mut other_dtype = m.clone();
        other_dtype.dtype = ai_core::manifest::AdapterDtype::Fp16;
        assert!(verify_lock(&lock, &other_dtype).is_err());

        let zero_manifest = LoRaManifest::new(ModelId([0u8; 32]), 16, 32);
        let zero_lock = lock_output(&zero_manifest);
        assert!(
            verify_lock(&zero_lock, &zero_manifest).is_err(),
            "zero base_model OutputLock must be refused"
        );
    }
}
