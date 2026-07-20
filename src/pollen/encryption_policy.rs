//! P12-4: Encryption DAO — DAO yönetimli Pollen şifreleme politikası.
//!
//! EncryptionPolicy, Pollen data asset'lerinin şifreleme gereksinimlerini
//! DAO (merkeziyetsiz otonom organizasyon) tarafından yönetilen parametreler
//! olarak tanımlar. Bu, ağın şifreleme standartlarını merkezi bir otorite
//! olmadan güncelleyebilmesini sağlar.
//!
//! # DAO Yönetim Modeli
//!
//! ```text
//! GovernanceProposal → Vote → Execute → EncryptionPolicy güncellemesi
//! ```
//!
//! Şifreleme parametreleri normal governance sürecinden daha yüksek bir
//! eşikle değiştirilir (güvenlik kritik).

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::pollen::AssetId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Şifreleme algoritması.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (standart).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (hafif cihazlar için).
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305 (nonce collision direnci yüksek).
    XChaCha20Poly1305,
    /// Şifreleme yok (public data).
    None,
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithm::Aes256Gcm => write!(f, "aes-256-gcm"),
            EncryptionAlgorithm::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            EncryptionAlgorithm::XChaCha20Poly1305 => write!(f, "xchacha20-poly1305"),
            EncryptionAlgorithm::None => write!(f, "none"),
        }
    }
}

/// Anahtar türetme fonksiyonu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDerivationFunction {
    /// HKDF-SHA256.
    HkdfSha256,
    /// Argon2id (memory-hard, password-based).
    Argon2Id,
    /// PBKDF2-SHA256.
    Pbkdf2Sha256,
}

/// DAO yönetimli şifreleme politikası.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPolicy {
    /// Politika versiyonu (her güncellemede artar).
    pub version: u64,
    /// Varsayılan şifreleme algoritması.
    pub default_algorithm: EncryptionAlgorithm,
    /// İzin verilen algoritmalar.
    pub allowed_algorithms: Vec<EncryptionAlgorithm>,
    /// Anahtar türetme fonksiyonu.
    pub kdf: KeyDerivationFunction,
    /// Minimum anahtar uzunluğu (bit).
    pub min_key_length_bits: u32,
    /// Anahtar rotasyon periyodu (epoch).
    pub key_rotation_epochs: u64,
    /// Maksimum şifreli veri boyutu (bayt).
    pub max_encrypted_data_size: u64,
    /// Nonce boyutu (bayt).
    pub nonce_size_bytes: u32,
    /// Asset bazlı özel politikalar.
    pub asset_policies: BTreeMap<AssetId, AssetEncryptionPolicy>,
    /// Politika güncelleme eşiği (fixed-point, 800_000 = %80).
    pub update_threshold: u64,
    /// Son güncelleme epoch'u.
    pub last_updated_epoch: u64,
    /// Güncelleyen governance proposal ID.
    pub last_update_proposal_id: Option<u64>,
}

/// Asset bazlı özel şifreleme politikası.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEncryptionPolicy {
    /// Asset ID.
    pub asset_id: AssetId,
    /// Bu asset için zorunlu algoritma.
    pub required_algorithm: EncryptionAlgorithm,
    /// Özel anahtar rotasyon periyodu (0 = global varsayılan).
    pub custom_rotation_epochs: u64,
    /// Ek şifreleme katmanı gerekli mi?
    pub double_encryption: bool,
    /// Erişim loglama zorunlu mu?
    pub access_logging_required: bool,
}

/// Şifreleme politikası güncelleme sonucu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdateResult {
    /// Eski versiyon.
    pub from_version: u64,
    /// Yeni versiyon.
    pub to_version: u64,
    /// Değişen alanlar.
    pub changed_fields: Vec<String>,
    /// Güncelleme epoch'u.
    pub epoch: u64,
    /// Governance proposal ID.
    pub proposal_id: u64,
}

impl Default for EncryptionPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            default_algorithm: EncryptionAlgorithm::Aes256Gcm,
            allowed_algorithms: vec![
                EncryptionAlgorithm::Aes256Gcm,
                EncryptionAlgorithm::ChaCha20Poly1305,
                EncryptionAlgorithm::XChaCha20Poly1305,
            ],
            kdf: KeyDerivationFunction::HkdfSha256,
            min_key_length_bits: 256,
            key_rotation_epochs: 10080, // 7 gün
            max_encrypted_data_size: 1_073_741_824, // 1 GB
            nonce_size_bytes: 12,
            asset_policies: BTreeMap::new(),
            update_threshold: 800_000, // 80% DAO onayı
            last_updated_epoch: 0,
            last_update_proposal_id: None,
        }
    }
}

impl EncryptionPolicy {
    /// Yeni varsayılan politika oluşturur.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bir algoritmanın izin verilenler listesinde olup olmadığını kontrol eder.
    pub fn is_algorithm_allowed(&self, algo: EncryptionAlgorithm) -> bool {
        if algo == EncryptionAlgorithm::None {
            // Şifreleme yok sadece asset policy ile izin verilebilir
            return false;
        }
        self.allowed_algorithms.contains(&algo)
    }

    /// Bir asset'in şifreleme gereksinimlerini döndürür.
    pub fn asset_requirement(&self, asset_id: &AssetId) -> AssetEncryptionRequirement {
        if let Some(asset_policy) = self.asset_policies.get(asset_id) {
            AssetEncryptionRequirement {
                algorithm: asset_policy.required_algorithm,
                rotation_epochs: if asset_policy.custom_rotation_epochs > 0 {
                    asset_policy.custom_rotation_epochs
                } else {
                    self.key_rotation_epochs
                },
                double_encryption: asset_policy.double_encryption,
                access_logging: asset_policy.access_logging_required,
            }
        } else {
            AssetEncryptionRequirement {
                algorithm: self.default_algorithm,
                rotation_epochs: self.key_rotation_epochs,
                double_encryption: false,
                access_logging: false,
            }
        }
    }

    /// DAO governance kararıyla politikayı günceller.
    pub fn apply_dao_update(
        &mut self,
        update: EncryptionPolicyUpdate,
        epoch: u64,
        proposal_id: u64,
        vote_ratio: u64,
    ) -> Result<PolicyUpdateResult, EncryptionPolicyError> {
        // Oy eşiği kontrolü
        if vote_ratio < self.update_threshold {
            return Err(EncryptionPolicyError::InsufficientVotes {
                required: self.update_threshold,
                actual: vote_ratio,
            });
        }

        let from_version = self.version;
        let mut changed_fields = Vec::new();

        if let Some(algo) = update.default_algorithm {
            // V207 (ARENAS): EncryptionAlgorithm::None must never be set as
            // default — even if someone adds it to allowed_algorithms, the
            // default must require encryption.
            if algo == EncryptionAlgorithm::None {
                return Err(EncryptionPolicyError::AlgorithmNotAllowed {
                    algorithm: algo,
                });
            }
            if !self.allowed_algorithms.contains(&algo) {
                return Err(EncryptionPolicyError::AlgorithmNotAllowed {
                    algorithm: algo,
                });
            }
            self.default_algorithm = algo;
            changed_fields.push("default_algorithm".to_string());
        }

        if let Some(kdf) = update.kdf {
            self.kdf = kdf;
            changed_fields.push("kdf".to_string());
        }

        if let Some(key_length) = update.min_key_length_bits {
            if key_length < 128 {
                return Err(EncryptionPolicyError::KeyTooShort { bits: key_length });
            }
            self.min_key_length_bits = key_length;
            changed_fields.push("min_key_length_bits".to_string());
        }

        if let Some(rotation) = update.key_rotation_epochs {
            if rotation == 0 {
                return Err(EncryptionPolicyError::InvalidRotationPeriod);
            }
            self.key_rotation_epochs = rotation;
            changed_fields.push("key_rotation_epochs".to_string());
        }

        if let Some(max_size) = update.max_encrypted_data_size {
            self.max_encrypted_data_size = max_size;
            changed_fields.push("max_encrypted_data_size".to_string());
        }

        // V205 (ARENAS): Use checked_add for version increment
        self.version = self.version.checked_add(1).unwrap_or_else(|| {
            tracing::error!("ENCRYPTION POLICY VERSION OVERFLOW: clamping to u64::MAX");
            u64::MAX
        });
        self.last_updated_epoch = epoch;
        self.last_update_proposal_id = Some(proposal_id);

        Ok(PolicyUpdateResult {
            from_version,
            to_version: self.version,
            changed_fields,
            epoch,
            proposal_id,
        })
    }

    /// Asset bazlı özel politika ekler.
    pub fn set_asset_policy(&mut self, policy: AssetEncryptionPolicy) {
        self.asset_policies.insert(policy.asset_id, policy);
    }

    /// Asset bazlı özel politikayı kaldırır.
    pub fn remove_asset_policy(&mut self, asset_id: &AssetId) -> bool {
        self.asset_policies.remove(asset_id).is_some()
    }

    /// V204 (ARENAS): Prune unbounded asset_policies growth. Without this,
    /// the BTreeMap grows indefinitely as DAO adds per-asset policies.
    pub fn prune_asset_policies(&mut self, max_policies: usize) -> usize {
        if self.asset_policies.len() <= max_policies {
            return 0;
        }
        let to_remove = self.asset_policies.len() - max_policies;
        let keys: Vec<AssetId> = self.asset_policies.keys().take(to_remove).copied().collect();
        for key in keys {
            self.asset_policies.remove(&key);
        }
        to_remove
    }
}

/// Asset şifreleme gereksinimi (sorgu sonucu).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEncryptionRequirement {
    /// Zorunlu algoritma.
    pub algorithm: EncryptionAlgorithm,
    /// Anahtar rotasyon periyodu (epoch).
    pub rotation_epochs: u64,
    /// Çift şifreleme gerekli mi?
    pub double_encryption: bool,
    /// Erişim loglama gerekli mi?
    pub access_logging: bool,
}

/// DAO güncelleme parametreleri (governance proposal'dan).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EncryptionPolicyUpdate {
    /// Yeni varsayılan algoritma.
    pub default_algorithm: Option<EncryptionAlgorithm>,
    /// Yeni KDF.
    pub kdf: Option<KeyDerivationFunction>,
    /// Yeni minimum anahtar uzunluğu.
    pub min_key_length_bits: Option<u32>,
    /// Yeni anahtar rotasyon periyodu.
    pub key_rotation_epochs: Option<u64>,
    /// Yeni maksimum veri boyutu.
    pub max_encrypted_data_size: Option<u64>,
}

/// Şifreleme politikası hataları.
#[derive(Debug)]
pub enum EncryptionPolicyError {
    /// Yetersiz oy.
    InsufficientVotes { required: u64, actual: u64 },
    /// Algoritma izin verilenler listesinde değil.
    AlgorithmNotAllowed { algorithm: EncryptionAlgorithm },
    /// Anahtar çok kısa.
    KeyTooShort { bits: u32 },
    /// Geçersiz rotasyon periyodu.
    InvalidRotationPeriod,
}

impl std::fmt::Display for EncryptionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionPolicyError::InsufficientVotes { required, actual } => {
                write!(
                    f,
                    "Insufficient votes: {}/1M (required: {}/1M)",
                    actual, required
                )
            }
            EncryptionPolicyError::AlgorithmNotAllowed { algorithm } => {
                write!(f, "Algorithm {} not in allowed list", algorithm)
            }
            EncryptionPolicyError::KeyTooShort { bits } => {
                write!(f, "Key length {} bits is below minimum 128", bits)
            }
            EncryptionPolicyError::InvalidRotationPeriod => {
                write!(f, "Key rotation period must be > 0")
            }
        }
    }
}

impl std::error::Error for EncryptionPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows_standard_algorithms() {
        let policy = EncryptionPolicy::new();
        assert!(policy.is_algorithm_allowed(EncryptionAlgorithm::Aes256Gcm));
        assert!(policy.is_algorithm_allowed(EncryptionAlgorithm::ChaCha20Poly1305));
        assert!(!policy.is_algorithm_allowed(EncryptionAlgorithm::None));
    }

    #[test]
    fn asset_requirement_uses_default_without_custom_policy() {
        let policy = EncryptionPolicy::new();
        let req = policy.asset_requirement(&AssetId::from([1u8; 32]));
        assert_eq!(req.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert!(!req.double_encryption);
    }

    #[test]
    fn asset_requirement_uses_custom_policy_when_set() {
        let mut policy = EncryptionPolicy::new();
        let asset_id = AssetId::from([5u8; 32]);
        policy.set_asset_policy(AssetEncryptionPolicy {
            asset_id,
            required_algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
            custom_rotation_epochs: 720,
            double_encryption: true,
            access_logging_required: true,
        });

        let req = policy.asset_requirement(&asset_id);
        assert_eq!(req.algorithm, EncryptionAlgorithm::XChaCha20Poly1305);
        assert_eq!(req.rotation_epochs, 720);
        assert!(req.double_encryption);
        assert!(req.access_logging);
    }

    #[test]
    fn dao_update_requires_threshold_votes() {
        let mut policy = EncryptionPolicy::new();
        let update = EncryptionPolicyUpdate {
            key_rotation_epochs: Some(5000),
            ..Default::default()
        };
        // 50% < 80% threshold
        let result = policy.apply_dao_update(update, 100, 1, 500_000);
        assert!(matches!(result, Err(EncryptionPolicyError::InsufficientVotes { .. })));
    }

    #[test]
    fn dao_update_succeeds_with_enough_votes() {
        let mut policy = EncryptionPolicy::new();
        let update = EncryptionPolicyUpdate {
            key_rotation_epochs: Some(5000),
            ..Default::default()
        };
        let result = policy.apply_dao_update(update, 100, 1, 850_000);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.from_version, 1);
        assert_eq!(res.to_version, 2);
        assert_eq!(policy.key_rotation_epochs, 5000);
    }

    #[test]
    fn dao_update_rejects_short_key() {
        let mut policy = EncryptionPolicy::new();
        let update = EncryptionPolicyUpdate {
            min_key_length_bits: Some(64),
            ..Default::default()
        };
        let result = policy.apply_dao_update(update, 100, 1, 900_000);
        assert!(matches!(result, Err(EncryptionPolicyError::KeyTooShort { .. })));
    }

    #[test]
    fn dao_update_rejects_zero_rotation() {
        let mut policy = EncryptionPolicy::new();
        let update = EncryptionPolicyUpdate {
            key_rotation_epochs: Some(0),
            ..Default::default()
        };
        let result = policy.apply_dao_update(update, 100, 1, 900_000);
        assert!(matches!(result, Err(EncryptionPolicyError::InvalidRotationPeriod)));
    }

    #[test]
    fn remove_asset_policy() {
        let mut policy = EncryptionPolicy::new();
        let asset_id = AssetId::from([5u8; 32]);
        policy.set_asset_policy(AssetEncryptionPolicy {
            asset_id,
            required_algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            custom_rotation_epochs: 0,
            double_encryption: false,
            access_logging_required: false,
        });
        assert!(policy.asset_policies.contains_key(&asset_id));
        assert!(policy.remove_asset_policy(&asset_id));
        assert!(!policy.asset_policies.contains_key(&asset_id));
    }

    #[test]
    fn policy_version_increments() {
        let mut policy = EncryptionPolicy::new();
        assert_eq!(policy.version, 1);
        policy
            .apply_dao_update(
                EncryptionPolicyUpdate {
                    key_rotation_epochs: Some(720),
                    ..Default::default()
                },
                100,
                1,
                900_000,
            )
            .unwrap();
        assert_eq!(policy.version, 2);
        policy
            .apply_dao_update(
                EncryptionPolicyUpdate {
                    key_rotation_epochs: Some(1440),
                    ..Default::default()
                },
                200,
                2,
                900_000,
            )
            .unwrap();
        assert_eq!(policy.version, 3);
    }

    #[test]
    fn encryption_algorithm_display() {
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.to_string(), "aes-256-gcm");
        assert_eq!(EncryptionAlgorithm::None.to_string(), "none");
    }
}
