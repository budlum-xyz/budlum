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
        let mech_type = MechanismType::new_vendor_defined(id).map_err(|e| {
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
