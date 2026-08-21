//! Çıktı hash kilidi: eğitim çıktısı manifest digest'ine bağlanır.
//!
//! Zincir üstü `register_lubot_model(model_hash)` kaydı bu digest ile
//! eşleşmelidir - aynı digest'ten türetilmemiş bir çıktı kabul edilmez.

use lubot_core::manifest::LoRaManifest;
use lubot_core::model::{Hash32, ModelId};

/// Eğitim çıktısına vurulan kilit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputLock {
    pub manifest_digest: Hash32,
    pub model_id: ModelId,
}

/// Manifest'ten çıktı kilidi üret.
#[must_use]
pub fn lock_output(manifest: &LoRaManifest) -> OutputLock {
    OutputLock {
        manifest_digest: manifest.digest(),
        model_id: manifest.base_model,
    }
}

/// Kilit-manifest eşleşmesini doğrula.
///
/// # Errors
///
/// Digest veya model_id uyuşmuyorsa.
pub fn verify_lock(lock: &OutputLock, manifest: &LoRaManifest) -> Result<(), String> {
    if lock.manifest_digest != manifest.digest() {
        return Err("çıktı kilidi manifest digest'iyle eşleşmiyor".to_string());
    }
    if lock.model_id != manifest.base_model {
        return Err("çıktı kilidi taban modelle eşleşmiyor".to_string());
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
