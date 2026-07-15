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
                "PKCS#11 PIN environment variable '{}' not accessible: {}",
                token_pin_env, e
            ))
        })?;
        if pin.is_empty() {
            return Err(CryptoError::KeyGeneration(
                "PKCS#11 PIN is empty".to_string(),
            ));
        }

        let pkcs11_client = cryptoki::context::Pkcs11::new(&module_path).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to load PKCS#11 module '{}': {}",
                module_path, e
            ))
        })?;

        pkcs11_client
            .initialize(cryptoki::context::CInitializeArgs::OsThreads)
            .map_err(|e| {
                CryptoError::KeyGeneration(format!("Failed to initialize PKCS#11: {}", e))
            })?;

        let slots = pkcs11_client.get_slots_with_token().map_err(|e| {
            CryptoError::KeyGeneration(format!("Failed to enumerate PKCS#11 slots: {}", e))
        })?;

        let target_slot = slots
            .iter()
            .find(|s: &&cryptoki::slot::Slot| s.id() == slot_id)
            .ok_or_else(|| {
                CryptoError::KeyGeneration(format!(
                    "Slot {} not found (available slots with tokens: {:?})",
                    slot_id,
                    slots
                        .iter()
                        .map(|s: &cryptoki::slot::Slot| s.id())
                        .collect::<Vec<_>>()
                ))
            })?;

        let session = pkcs11_client.open_rw_session(*target_slot).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to open RW session on slot {}: {}",
                slot_id, e
            ))
        })?;

        let pin_secret = secrecy::Secret::new(pin);
        session
            .login(cryptoki::session::UserType::User, Some(&pin_secret))
            .map_err(|e| CryptoError::KeyGeneration(format!("PKCS#11 login failed: {}", e)))?;

        let public_key_bytes = Self::extract_ed25519_public_key(&session).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to extract Ed25519 public key from HSM: {}",
                e
            ))
        })?;

        let bls_key = Self::extract_data_object(&session, BLS_DATA_LABEL)
            .and_then(|bytes| BlsKeypair::from_bytes(&bytes).ok());
        #[cfg(feature = "pq-dilithium")]
        let pq_key = Self::extract_data_object(&session, PQ_DATA_LABEL).and_then(|bytes| {
            if bytes.len()
                >= pqcrypto_dilithium::dilithium5::public_key_bytes()
                    + pqcrypto_dilithium::dilithium5::secret_key_bytes()
            {
                let pk_len = pqcrypto_dilithium::dilithium5::public_key_bytes();
                let sk_len = pqcrypto_dilithium::dilithium5::secret_key_bytes();
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
                pkcs11_client,
                session,
            })),
        })
    }

    /// Store a BLS keypair into the HSM as a data object.
    pub fn store_bls_key(&self, keypair: &BlsKeypair) -> Result<(), CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("PKCS#11 inner mutex poisoned".to_string()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("PKCS#11 session already closed".to_string()))?;

        let bytes = keypair.to_bytes();
        Self::create_data_object(&inner.session, BLS_DATA_LABEL, &bytes)?;
        *self.bls_key.lock().map_err(|_| {
            CryptoError::Signing("BLS key mutex poisoned during store".to_string())
        })? = Some(keypair.clone());
        Ok(())
    }

    /// Store a PQ keypair into the HSM as a data object.
    pub fn store_pq_key(&self, keypair: &PqKeyPair) -> Result<(), CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("PKCS#11 inner mutex poisoned".to_string()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("PKCS#11 session already closed".to_string()))?;

        let mut bytes = keypair.public_key_bytes().to_vec();
        bytes.extend_from_slice(keypair.secret_key_bytes());
        Self::create_data_object(&inner.session, PQ_DATA_LABEL, &bytes)?;
        *self.pq_key.lock().map_err(|_| {
            CryptoError::Signing("PQ key mutex poisoned during store".to_string())
        })? = Some(keypair.clone());
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
            .map_err(|e| format!("Failed to search for Ed25519 key: {}", e))?;
        if objects.is_empty() {
            return Err("No Ed25519 public key found in HSM slot".to_string());
        }
        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .map_err(|e| format!("Failed to read public key value: {}", e))?;
        if let Some(cryptoki::object::Attribute::Value(value)) = attr.first() {
            if value.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&value[..32]);
                return Ok(key);
            }
        }
        Err("Failed to extract public key bytes".to_string())
    }

    fn extract_data_object(session: &cryptoki::session::Session, label: &str) -> Option<Vec<u8>> {
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::DATA),
            cryptoki::object::Attribute::Label(label.to_string().into()),
        ];
        let objects = session.find_objects(template).ok()?;
        if objects.is_empty() {
            return None;
        }
        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .ok()?;
        if let Some(cryptoki::object::Attribute::Value(value)) = attr.first() {
            Some(value.clone())
        } else {
            None
        }
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
            cryptoki::object::Attribute::Label(label.to_string().into()),
            cryptoki::object::Attribute::Value(value.to_vec()),
        ];
        session
            .create_object(template)
            .map_err(|e| CryptoError::KeyGeneration(format!("Failed to store {}: {}", label, e)))?;
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
            .map_err(|_| CryptoError::Signing("PKCS#11 inner mutex poisoned".to_string()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("PKCS#11 session already closed".to_string()))?;

        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS),
        ];
        let objects = inner.session.find_objects(template).map_err(|e| {
            CryptoError::Signing(format!("Failed to find Ed25519 private key: {}", e))
        })?;
        if objects.is_empty() {
            return Err(CryptoError::Signing(
                "No Ed25519 private key found in HSM slot".to_string(),
            ));
        }
        let key_handle = objects[0];

        let mechanism = cryptoki::mechanism::Mechanism::Eddsa;
        let signature = inner
            .session
            .sign(&mechanism, key_handle, block_hash)
            .map_err(|e| CryptoError::Signing(format!("HSM sign operation failed: {}", e)))?;

        if signature.len() < 64 {
            return Err(CryptoError::Signing(format!(
                "HSM returned undersized signature: {} bytes",
                signature.len()
            )));
        }
        Ok(signature[..64].to_vec())
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let guard = self
            .bls_key
            .lock()
            .map_err(|_| CryptoError::Signing("BLS key mutex poisoned during sign".to_string()))?;
        let bls = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No BLS key stored in HSM".to_string()))?;
        Ok(crate::chain::finality::sign_bls(&bls.secret_key, msg))
    }

    fn pq_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let guard = self
            .pq_key
            .lock()
            .map_err(|_| CryptoError::Signing("PQ key mutex poisoned during sign".to_string()))?;
        let pq = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No PQ key stored in HSM".to_string()))?;
        pq.sign(msg)
    }

    fn bls_public_key(&self) -> Option<Vec<u8>> {
        self.bls_key
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|bls| bls.public_key.clone()))
    }

    fn pq_public_key(&self) -> Option<Vec<u8>> {
        self.pq_key
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|pq| pq.public_key_bytes().to_vec()))
    }

    fn backend_name(&self) -> &'static str {
        "pkcs11"
    }
}
