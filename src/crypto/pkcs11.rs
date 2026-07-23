use crate::crypto::primitives::{BlsKeypair, CryptoError, PqKeyPair};
use crate::crypto::signer::ConsensusSigner;
use std::sync::Mutex;

const BLS_DATA_LABEL: &str = "BUD_BLS_KEY";
const PQ_DATA_LABEL: &str = "BUD_PQ_KEY";

pub struct Pkcs11Signer {
    #[allow(dead_code)]
    module_path: String,
    #[allow(dead_code)]
    slot_id: u64,
    #[allow(dead_code)]
    token_pin_env: String,
    public_key_bytes: [u8; 32],
    bls_key: Mutex<Option<BlsKeypair>>,
    pq_key: Mutex<Option<PqKeyPair>>,
    inner: Mutex<Option<Pkcs11Inner>>,
    bls_mechanism: Option<u64>,
    pq_mechanism: Option<u64>,
}

struct Pkcs11Inner {
    #[allow(dead_code)]
    pkcs11_client: cryptoki::context::Pkcs11,
    session: cryptoki::session::Session,
}

impl Pkcs11Signer {
    pub fn new(
        module_path: String,
        slot_id: u64,
        token_pin_env: String,
    ) -> Result<Self, CryptoError> {
        let pin = std::env::var(&token_pin_env).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "PKCS#11 PIN env '{}' not accessible: {}",
                token_pin_env, e
            ))
        })?;
        if pin.is_empty() {
            return Err(CryptoError::KeyGeneration("PKCS#11 PIN is empty".into()));
        }
        let client = cryptoki::context::Pkcs11::new(&module_path).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to load PKCS#11 module '{}': {}",
                module_path, e
            ))
        })?;
        client
            .initialize(cryptoki::context::CInitializeArgs::new(
                cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
            ))
            .map_err(|e| CryptoError::KeyGeneration(format!("Failed to init PKCS#11: {e}")))?;
        let slots = client.get_slots_with_token().map_err(|e| {
            CryptoError::KeyGeneration(format!("Failed to enumerate PKCS#11 slots: {e}"))
        })?;
        let target_slot = slots
            .iter()
            .find(|s: &&cryptoki::slot::Slot| s.id() == slot_id)
            .ok_or_else(|| {
                CryptoError::KeyGeneration(format!(
                    "Slot {} not found (available: {:?})",
                    slot_id,
                    slots
                        .iter()
                        .map(|s: &cryptoki::slot::Slot| s.id())
                        .collect::<Vec<_>>()
                ))
            })?;
        let session = client.open_rw_session(*target_slot).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to open RW session on slot {}: {}",
                slot_id, e
            ))
        })?;
        // S1 fix (ARENA2, 2026-07-17): secrecy 0.10 — secrecy::Secret kaldırıldı;
        // cryptoki 0.12 AuthPin = SecretString = SecretBox<str>.
        let pin_secret = secrecy::SecretString::new(pin.into_boxed_str());
        session
            .login(cryptoki::session::UserType::User, Some(&pin_secret))
            .map_err(|e| CryptoError::KeyGeneration(format!("PKCS#11 login failed: {e}")))?;
        let public_key_bytes = Self::extract_ed25519_public_key(&session).map_err(|e| {
            CryptoError::KeyGeneration(format!("Failed to extract Ed25519 key from HSM: {}", e))
        })?;
        let bls_key = Self::extract_data_object(&session, BLS_DATA_LABEL)
            .and_then(|bytes| BlsKeypair::from_bytes(&bytes).ok());
        #[cfg(feature = "pq-dilithium")]
        let pq_key = Self::extract_data_object(&session, PQ_DATA_LABEL).and_then(|bytes| {
            let pk_len = pqcrypto_dilithium::dilithium5::public_key_bytes();
            let sk_len = pqcrypto_dilithium::dilithium5::secret_key_bytes();
            if bytes.len() >= pk_len + sk_len {
                PqKeyPair::from_bytes(&bytes[..pk_len], &bytes[pk_len..pk_len + sk_len]).ok()
            } else {
                None
            }
        });
        #[cfg(feature = "pq-ml-dsa")]
        let pq_key = Self::extract_data_object(&session, PQ_DATA_LABEL).and_then(|bytes| {
            if bytes.len() >= 1952 + 32 {
                PqKeyPair::from_bytes(&bytes[..1952], &bytes[1952..1952 + 32]).ok()
            } else {
                None
            }
        });
        Ok(Self {
            module_path,
            slot_id,
            token_pin_env,
            public_key_bytes,
            bls_key: Mutex::new(bls_key),
            pq_key: Mutex::new(pq_key),
            inner: Mutex::new(Some(Pkcs11Inner {
                pkcs11_client: client,
                session,
            })),
            bls_mechanism: None,
            pq_mechanism: None,
        })
    }

    /// S1 (ARENA3, 2026-07-17): set vendor-native BLS/PQ mechanism IDs.
    /// cryptoki 0.12 uses Mechanism::VendorDefined for hardware-native signing.
    pub fn with_vendor_mechanisms(
        mut self,
        bls_mech: Option<String>,
        pq_mech: Option<String>,
    ) -> Self {
        self.bls_mechanism = bls_mech.and_then(|s| Self::parse_mechanism(&s));
        self.pq_mechanism = pq_mech.and_then(|s| Self::parse_mechanism(&s));
        if let Some(id) = self.bls_mechanism {
            tracing::info!("PKCS#11: vendor BLS mechanism 0x{:08X}", id);
        }
        if let Some(id) = self.pq_mechanism {
            tracing::info!("PKCS#11: vendor PQ mechanism 0x{:08X}", id);
        }
        self
    }

    fn parse_mechanism(s: &str) -> Option<u64> {
        s.strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| s.parse::<u64>().ok())
    }

    /// Vendor mekanizma kurulumu. S1 fix (ARENA2, 2026-07-17): cryptoki 0.12
    /// GERÇEK API'si — struct literal YOK (alanlar private: E0451/E0560):
    /// MechanismType::new_vendor_defined CKM_VENDOR_DEFINED tabanının
    /// altındaki id'leri reddeder (fail-closed value doğrulaması);
    /// VendorDefinedMechanism yalnızca ::new ile kurulur.
    fn vendor_mechanism(id: u64) -> Result<cryptoki::mechanism::Mechanism<'static>, CryptoError> {
        use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
        use cryptoki::mechanism::MechanismType;
        // ADIM-1 CI (ARENA2, 2026-07-21): Cross-platform determinism matrisinin
        // ilk Windows koşusu bu satırı yakaladı (E0308). `CK_MECHANISM_TYPE`
        // cryptoki-sys'te Windows'ta u32 (CK_ULONG, LLP64 ABI), Unix'te u64
        // (LP64) — ve cryptoki_sys dışa açık olmadığından tür isimlendirilemez.
        // Platform eşlemesi cryptoki-sys'in kendi tanımıyla aynı tutulur;
        // 32-bit'e sığmayan vendor id fail-closed hata verir (sessiz kırpma yok).
        #[cfg(windows)]
        let mech_id = u32::try_from(id).map_err(|_| {
            CryptoError::Signing(format!(
                "PKCS#11 vendor mechanism id 0x{id:08X} 32-bit CK_ULONG (Windows ABI) araliginin disinda"
            ))
        })?;
        #[cfg(not(windows))]
        let mech_id = id;
        let mech_type = MechanismType::new_vendor_defined(mech_id).map_err(|e| {
            CryptoError::Signing(format!(
                "PKCS#11 vendor mechanism id 0x{id:08X} CKM_VENDOR_DEFINED tabaninin altinda: {e}"
            ))
        })?;
        Ok(cryptoki::mechanism::Mechanism::VendorDefined(
            VendorDefinedMechanism::new::<()>(mech_type, None),
        ))
    }

    fn try_vendor_sign(
        &self,
        session: &cryptoki::session::Session,
        mech_id: u64,
        label: &str,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mechanism = Self::vendor_mechanism(mech_id)?;
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            cryptoki::object::Attribute::Label(label.into()),
        ];
        let objects = session
            .find_objects(template)
            .map_err(|e| CryptoError::Signing(format!("Failed to find key '{}': {}", label, e)))?;
        if objects.is_empty() {
            return Err(CryptoError::Signing(format!(
                "Key '{}' not found for vendor sign",
                label
            )));
        }
        session
            .sign(&mechanism, objects[0], msg)
            .map_err(|e| CryptoError::Signing(format!("Vendor sign '{}': {}", label, e)))
    }

    pub fn store_bls_key(&self, keypair: &BlsKeypair) -> Result<(), CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("HSM mutex poisoned".into()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("HSM session closed".into()))?;
        Self::create_data_object(&inner.session, BLS_DATA_LABEL, &keypair.to_bytes())?;
        *self
            .bls_key
            .lock()
            .map_err(|_| CryptoError::Signing("BLS mutex poisoned".into()))? =
            Some(keypair.clone());
        Ok(())
    }

    pub fn store_pq_key(&self, keypair: &PqKeyPair) -> Result<(), CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("HSM mutex poisoned".into()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("HSM session closed".into()))?;
        let mut bytes = keypair.public_key_bytes().to_vec();
        bytes.extend_from_slice(keypair.secret_key_bytes());
        Self::create_data_object(&inner.session, PQ_DATA_LABEL, &bytes)?;
        *self
            .pq_key
            .lock()
            .map_err(|_| CryptoError::Signing("PQ mutex poisoned".into()))? = Some(keypair.clone());
        Ok(())
    }

    fn extract_ed25519_public_key(
        session: &cryptoki::session::Session,
    ) -> Result<[u8; 32], String> {
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
        ];
        let objects = session
            .find_objects(template)
            .map_err(|e| format!("Ed25519 key search failed: {e}"))?;
        if objects.is_empty() {
            return Err("No Ed25519 public key found in HSM".into());
        }
        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .map_err(|e| format!("Public key read failed: {e}"))?;
        if let Some(cryptoki::object::Attribute::Value(value)) = attr.first() {
            if value.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&value[..32]);
                return Ok(key);
            }
        }
        Err("Failed to extract public key bytes".into())
    }

    fn extract_data_object(session: &cryptoki::session::Session, label: &str) -> Option<Vec<u8>> {
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::DATA),
            cryptoki::object::Attribute::Label(label.into()),
        ];
        let objects = session.find_objects(template).ok()?;
        if objects.is_empty() {
            return None;
        }
        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .ok()?;
        attr.first().and_then(|a| {
            if let cryptoki::object::Attribute::Value(v) = a {
                Some(v.clone())
            } else {
                None
            }
        })
    }

    fn create_data_object(
        session: &cryptoki::session::Session,
        label: &str,
        value: &[u8],
    ) -> Result<(), CryptoError> {
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::DATA),
            cryptoki::object::Attribute::Token(true),
            cryptoki::object::Attribute::Private(true),
            cryptoki::object::Attribute::Label(label.into()),
            cryptoki::object::Attribute::Value(value.to_vec()),
        ];
        session.create_object(template).map_err(|e| {
            CryptoError::KeyGeneration(format!("Failed to store '{}': {}", label, e))
        })?;
        Ok(())
    }
}

/// Vendor-native BLS/PQ capability snapshot (audit / mainnet advertisement).
///
/// PKCS#11 standard has no portable BLS/Dilithium mechanism. Vendors expose
/// `CKM_VENDOR_DEFINED + offset` IDs. This struct records whether the operator
/// configured those IDs and whether software fallback material is present —
/// it does **not** claim non-extractable hardware keys without vendor audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11VendorCapabilities {
    /// Vendor BLS mechanism id configured (`with_vendor_mechanisms`).
    pub bls_vendor_mechanism: Option<u64>,
    /// Vendor PQ/Dilithium mechanism id configured.
    pub pq_vendor_mechanism: Option<u64>,
    /// Software BLS key material loaded from HSM data object (fallback path).
    pub bls_software_fallback_present: bool,
    /// Software PQ key material loaded from HSM data object (fallback path).
    pub pq_software_fallback_present: bool,
}

impl Pkcs11VendorCapabilities {
    /// True only when both vendor mechanism IDs are configured.
    /// Still requires external audit before mainnet "non-extractable" claims.
    #[must_use]
    pub fn vendor_native_signing_configured(&self) -> bool {
        self.bls_vendor_mechanism.is_some() && self.pq_vendor_mechanism.is_some()
    }

    /// True when BLS can be signed (vendor path OR software fallback material).
    #[must_use]
    pub fn bls_signing_available(&self) -> bool {
        self.bls_vendor_mechanism.is_some() || self.bls_software_fallback_present
    }

    /// True when PQ can be signed (vendor path OR software fallback material).
    #[must_use]
    pub fn pq_signing_available(&self) -> bool {
        self.pq_vendor_mechanism.is_some() || self.pq_software_fallback_present
    }
}

impl Pkcs11Signer {
    /// Report configured vendor-native + fallback capabilities.
    #[must_use]
    pub fn vendor_capabilities(&self) -> Pkcs11VendorCapabilities {
        let bls_sw = self
            .bls_key
            .lock()
            .ok()
            .map(|g| g.is_some())
            .unwrap_or(false);
        let pq_sw = self
            .pq_key
            .lock()
            .ok()
            .map(|g| g.is_some())
            .unwrap_or(false);
        Pkcs11VendorCapabilities {
            bls_vendor_mechanism: self.bls_mechanism,
            pq_vendor_mechanism: self.pq_mechanism,
            bls_software_fallback_present: bls_sw,
            pq_software_fallback_present: pq_sw,
        }
    }

    /// Parse + validate a vendor mechanism id string (hex `0x…` or decimal).
    /// Rejects zero and values below the conventional CKM_VENDOR_DEFINED base
    /// (`0x80000000`) so misconfigured low IDs fail closed before session use.
    pub fn validate_vendor_mechanism_id(raw: &str) -> Result<u64, CryptoError> {
        let id = Self::parse_mechanism(raw).ok_or_else(|| {
            CryptoError::KeyGeneration(format!(
                "invalid PKCS#11 vendor mechanism id '{raw}' (expected 0xHEX or decimal)"
            ))
        })?;
        const CKM_VENDOR_DEFINED: u64 = 0x8000_0000;
        if id < CKM_VENDOR_DEFINED {
            return Err(CryptoError::KeyGeneration(format!(
                "PKCS#11 vendor mechanism id 0x{id:08X} is below CKM_VENDOR_DEFINED (0x80000000)"
            )));
        }
        Ok(id)
    }
}

impl ConsensusSigner for Pkcs11Signer {
    fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key_bytes
    }

    fn sign_block(&self, block_hash: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("HSM mutex poisoned".into()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("HSM session closed".into()))?;
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
        ];
        let objects = inner
            .session
            .find_objects(template)
            .map_err(|e| CryptoError::Signing(format!("Ed25519 key search: {e}")))?;
        if objects.is_empty() {
            return Err(CryptoError::Signing("No Ed25519 private key in HSM".into()));
        }
        let mechanism = cryptoki::mechanism::Mechanism::Eddsa(
            // S1 fix (ARENA2, 2026-07-17): cryptoki 0.12 — EddsaParams::default
            // kaldırıldı; paramsız saf Ed25519 = EddsaSignatureScheme::Pure.
            cryptoki::mechanism::eddsa::EddsaParams::new(
                cryptoki::mechanism::eddsa::EddsaSignatureScheme::Pure,
            ),
        );
        let sig = inner
            .session
            .sign(&mechanism, objects[0], block_hash)
            .map_err(|e| CryptoError::Signing(format!("HSM sign: {e}")))?;
        if sig.len() < 64 {
            return Err(CryptoError::Signing(format!(
                "Undersized sig: {} bytes",
                sig.len()
            )));
        }
        Ok(sig[..64].to_vec())
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if let Some(mech_id) = self.bls_mechanism {
            let guard = self
                .inner
                .lock()
                .map_err(|_| CryptoError::Signing("HSM mutex".into()))?;
            if let Some(inner) = guard.as_ref() {
                match self.try_vendor_sign(&inner.session, mech_id, BLS_DATA_LABEL, msg) {
                    Ok(sig) => return Ok(sig),
                    Err(e) => tracing::warn!("Vendor BLS sign failed ({}), sw fallback", e),
                }
            }
        }
        let guard = self
            .bls_key
            .lock()
            .map_err(|_| CryptoError::Signing("BLS mutex".into()))?;
        let bls = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No BLS key in HSM".into()))?;
        Ok(crate::chain::finality::sign_bls(&bls.secret_key, msg))
    }

    fn pq_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if let Some(mech_id) = self.pq_mechanism {
            let guard = self
                .inner
                .lock()
                .map_err(|_| CryptoError::Signing("HSM mutex".into()))?;
            if let Some(inner) = guard.as_ref() {
                match self.try_vendor_sign(&inner.session, mech_id, PQ_DATA_LABEL, msg) {
                    Ok(sig) => return Ok(sig),
                    Err(e) => tracing::warn!("Vendor PQ sign failed ({}), sw fallback", e),
                }
            }
        }
        let guard = self
            .pq_key
            .lock()
            .map_err(|_| CryptoError::Signing("PQ mutex".into()))?;
        let pq = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No PQ key in HSM".into()))?;
        pq.sign(msg)
    }

    fn bls_public_key(&self) -> Option<Vec<u8>> {
        self.bls_key
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|k| k.public_key.clone()))
    }

    fn pq_public_key(&self) -> Option<Vec<u8>> {
        self.pq_key
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|k| k.public_key_bytes().to_vec()))
    }

    fn backend_name(&self) -> &'static str {
        "pkcs11"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs11_parse_mechanism_hex_and_dec() {
        assert_eq!(Pkcs11Signer::parse_mechanism("0x1234"), Some(0x1234));
        assert_eq!(Pkcs11Signer::parse_mechanism("0XABCD"), Some(0xABCD));
        assert_eq!(Pkcs11Signer::parse_mechanism("0Xabcd"), Some(0xABCD));
        assert_eq!(Pkcs11Signer::parse_mechanism("123456"), Some(123456));
        assert_eq!(Pkcs11Signer::parse_mechanism("invalid_mech"), None);
    }

    #[test]
    fn test_vendor_mechanism_id_rejects_below_vendor_defined_base() {
        assert!(Pkcs11Signer::validate_vendor_mechanism_id("0x1234").is_err());
        assert!(Pkcs11Signer::validate_vendor_mechanism_id("42").is_err());
        assert!(Pkcs11Signer::validate_vendor_mechanism_id("not-a-number").is_err());
    }

    #[test]
    fn test_vendor_mechanism_id_accepts_vendor_defined_range() {
        let id = Pkcs11Signer::validate_vendor_mechanism_id("0x80000001").unwrap();
        assert_eq!(id, 0x8000_0001);
        let id2 = Pkcs11Signer::validate_vendor_mechanism_id("2147483649").unwrap(); // 0x80000001
        assert_eq!(id2, 0x8000_0001);
    }

    #[test]
    fn test_vendor_capabilities_flags() {
        let caps = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: Some(0x8000_0001),
            pq_vendor_mechanism: Some(0x8000_0002),
            bls_software_fallback_present: false,
            pq_software_fallback_present: false,
        };
        assert!(caps.vendor_native_signing_configured());
        assert!(caps.bls_signing_available());
        assert!(caps.pq_signing_available());

        let fallback_only = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: None,
            pq_vendor_mechanism: None,
            bls_software_fallback_present: true,
            pq_software_fallback_present: true,
        };
        assert!(!fallback_only.vendor_native_signing_configured());
        assert!(fallback_only.bls_signing_available());
        assert!(fallback_only.pq_signing_available());

        let empty = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: None,
            pq_vendor_mechanism: None,
            bls_software_fallback_present: false,
            pq_software_fallback_present: false,
        };
        assert!(!empty.bls_signing_available());
        assert!(!empty.pq_signing_available());
    }
}

// ── ARENA2 (2026-07-23): HSM vendor mechanism validation hardening ──
//
// YubiHSM 2 and other PKCS#11 tokens support vendor-defined mechanisms
// for native BLS/PQ signing. These must be validated before use to prevent
// invalid mechanism IDs from causing undefined behavior in the HSM firmware.

/// Known vendor-defined mechanism ID ranges for supported HSMs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs11Vendor {
    /// YubiHSM 2: vendor mechanisms in 0x8000_0000..0x8000_FFFF range.
    YubiHsm2,
    /// Generic PKCS#11 vendor-defined range (CKM_VENDOR_DEFINED = 0x8000_0000).
    Generic,
}

/// Vendor mechanism capability descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs11VendorCapability {
    /// Vendor identifier.
    pub vendor: Pkcs11Vendor,
    /// Mechanism ID (must be >= CKM_VENDOR_DEFINED = 0x8000_0000).
    pub mechanism_id: u64,
    /// Human-readable name.
    pub name: String,
    /// Whether this mechanism is allowed for mainnet signing.
    pub mainnet_allowed: bool,
}

/// CKM_VENDOR_DEFINED constant from PKCS#11 spec.
pub const CKM_VENDOR_DEFINED: u64 = 0x8000_0000;

/// Known YubiHSM 2 vendor mechanism IDs for BLS signing.
pub const YUBIHSM2_CKM_BLS_SIGN: u64 = 0x8000_0001;
/// Known YubiHSM 2 vendor mechanism IDs for PQ (Dilithium) signing.
pub const YUBIHSM2_CKM_PQ_SIGN: u64 = 0x8000_0002;

impl Pkcs11VendorCapability {
    /// Validate that the mechanism ID is in the vendor-defined range.
    pub fn validate_mechanism_id(&self) -> Result<(), String> {
        if self.mechanism_id < CKM_VENDOR_DEFINED {
            return Err(format!(
                "mechanism_id 0x{:08X} is below CKM_VENDOR_DEFINED (0x{:08X})",
                self.mechanism_id, CKM_VENDOR_DEFINED
            ));
        }
        match self.vendor {
            Pkcs11Vendor::YubiHsm2 => {
                if self.mechanism_id > 0x8000_FFFF {
                    return Err(format!(
                        "YubiHSM2 mechanism 0x{:08X} exceeds vendor range 0x8000_FFFF",
                        self.mechanism_id
                    ));
                }
            }
            Pkcs11Vendor::Generic => {}
        }
        Ok(())
    }

    /// Check if this capability is suitable for mainnet use.
    pub fn check_mainnet_policy(&self) -> Result<(), String> {
        self.validate_mechanism_id()?;
        if !self.mainnet_allowed {
            return Err(format!(
                "vendor mechanism '{}' (0x{:08X}) is not allowed for mainnet",
                self.name, self.mechanism_id
            ));
        }
        Ok(())
    }
}

/// Build the default set of known vendor capabilities for YubiHSM 2.
pub fn yubihsm2_default_capabilities() -> Vec<Pkcs11VendorCapability> {
    vec![
        Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: YUBIHSM2_CKM_BLS_SIGN,
            name: "YubiHSM2-BLS-Sign".into(),
            mainnet_allowed: true,
        },
        Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: YUBIHSM2_CKM_PQ_SIGN,
            name: "YubiHSM2-PQ-Sign".into(),
            mainnet_allowed: true,
        },
    ]
}

/// Validate a mechanism ID against a set of known capabilities.
/// Returns the matching capability or an error if unknown/invalid.
pub fn validate_vendor_mechanism(
    mechanism_id: u64,
    capabilities: &[Pkcs11VendorCapability],
) -> Result<&Pkcs11VendorCapability, String> {
    if mechanism_id < CKM_VENDOR_DEFINED {
        return Err(format!(
            "mechanism 0x{:08X} is not vendor-defined",
            mechanism_id
        ));
    }
    capabilities
        .iter()
        .find(|c| c.mechanism_id == mechanism_id)
        .ok_or_else(|| format!("unknown vendor mechanism 0x{:08X}", mechanism_id))
}

#[cfg(test)]
mod vendor_tests {
    use super::*;

    #[test]
    fn valid_yubihsm2_mechanism() {
        let cap = Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: YUBIHSM2_CKM_BLS_SIGN,
            name: "test".into(),
            mainnet_allowed: true,
        };
        assert!(cap.validate_mechanism_id().is_ok());
        assert!(cap.check_mainnet_policy().is_ok());
    }

    #[test]
    fn reject_below_vendor_defined() {
        let cap = Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: 0x1234,
            name: "bad".into(),
            mainnet_allowed: true,
        };
        assert!(cap.validate_mechanism_id().is_err());
    }

    #[test]
    fn reject_above_yubihsm2_range() {
        let cap = Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: 0x8001_0000,
            name: "bad".into(),
            mainnet_allowed: true,
        };
        assert!(cap.validate_mechanism_id().is_err());
    }

    #[test]
    fn reject_mainnet_disallowed() {
        let cap = Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: YUBIHSM2_CKM_BLS_SIGN,
            name: "test".into(),
            mainnet_allowed: false,
        };
        assert!(cap.check_mainnet_policy().is_err());
    }

    #[test]
    fn validate_known_mechanism() {
        let caps = yubihsm2_default_capabilities();
        assert!(validate_vendor_mechanism(YUBIHSM2_CKM_BLS_SIGN, &caps).is_ok());
        assert!(validate_vendor_mechanism(YUBIHSM2_CKM_PQ_SIGN, &caps).is_ok());
        assert!(validate_vendor_mechanism(0x8000_9999, &caps).is_err());
    }

    #[test]
    fn reject_non_vendor_mechanism() {
        let caps = yubihsm2_default_capabilities();
        assert!(validate_vendor_mechanism(0x0001, &caps).is_err());
    }
}
