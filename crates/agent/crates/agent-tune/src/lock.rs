//! The output hash lock: a training output is bound to its manifest digest.
//!
//! The on-chain `register_agent_model(model_hash)` record has to match this
//! digest: an output not derived from the same digest is not accepted.

use agent_core::manifest::LoRaManifest;
use agent_core::model::{Hash32, ModelId};

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
}
