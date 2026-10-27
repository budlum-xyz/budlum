use crate::crypto::primitives::{BlsKeypair, CryptoError, PqKeyPair};
use crate::crypto::signer::ConsensusSigner;
use std::sync::Mutex;

const BLS_DATA_LABEL: &str = "BUD_BLS_KEY";
const PQ_DATA_LABEL: &str = "BUD_PQ_KEY";

/// The fixed test message used at startup to prove that the private key held in the
/// HSM belongs to the public key that was read.
const ED25519_BINDING_TEST_MESSAGE: &[u8] = b"BUDLUM_PKCS11_ED25519_BINDING_V1";

/// A post-quantum signing key that lives in an HSM and never leaves it
///. The anchor and Root Seal signers of `settlement::anchor_production`
/// sit on this trait; the PKCS#11 3.2 implementation is `Pkcs11PqKey`.
pub trait HsmPqKey: Send + Sync {
    /// The raw public key of the token object (ML-DSA-87 or
    /// SLH-DSA-SHAKE-256s, as the key was generated).
    fn public_key(&self) -> Vec<u8>;
    /// Sign `payload` inside the token under the FIPS 204/205 context `ctx`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Signing`] for any token refusal. Never substituted
    /// output.
    fn sign(&self, ctx: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub struct Pkcs11Signer {
    /// Read by [`Self::connection_info`] (F12): no dead-code allow here.
    module_path: String,
    /// Read by [`Self::connection_info`] (F12).
    slot_id: u64,
    /// Read by [`Self::connection_info`] (F12).
    token_pin_env: String,
    /// Label that picks the consensus key when the slot holds more than one Ed25519 pair.
    key_label: Option<String>,
    public_key_bytes: [u8; 32],
    bls_key: Mutex<Option<BlsKeypair>>,
    pq_key: Mutex<Option<PqKeyPair>>,
    inner: Mutex<Option<Pkcs11Inner>>,
    bls_mechanism: Option<u64>,
    pq_mechanism: Option<u64>,
    strict_vendor_native: bool,
    /// HSM-held BLS public key, read from the slot's PUBLIC_KEY object
    /// (P02-F01 decision A). `None` when the slot carries no such object.
    bls_public_key_bytes: Option<Vec<u8>>,
    /// HSM-held PQ public key, read the same way (P02-F01 decision A).
    pq_public_key_bytes: Option<Vec<u8>>,
    /// Operator-configured expectations (P02-F01 decision B). When set, the
    /// HSM-read key must equal it; a mismatch is a fail-closed startup error,
    /// and a slot with no readable key may be announced only through these.
    expected_bls_public_key: Option<Vec<u8>>,
    expected_pq_public_key: Option<Vec<u8>>,
    /// ML-DSA-65 validator key signing through the PKCS#11 3.2 standard
    /// mechanism. When present it is the PQ path and the vendor
    /// mechanism and the software fallback are not consulted.
    standard_pq_key: Option<Pkcs11PqKey>,
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
        key_label: Option<String>,
    ) -> Result<Self, CryptoError> {
        Self::connect(module_path, slot_id, token_pin_env, key_label)
    }

    /// Construct a PKCS#11 signer without loading extractable BLS/PQ secret
    /// material into process memory. Mainnet vendor-native validators must use
    /// this path: BLS/PQ signing is served only through configured vendor
    /// mechanisms and any vendor failure is fail-closed by
    /// [`Self::require_vendor_native_signing`].
    ///
    /// F12: there is no software fallback left to load, so this is the same
    /// extractable-free session as [`Self::new`]; the two names are kept
    /// because callers use both and the semantics each name promises.
    pub fn new_without_software_fallback(
        module_path: String,
        slot_id: u64,
        token_pin_env: String,
        key_label: Option<String>,
    ) -> Result<Self, CryptoError> {
        Self::connect(module_path, slot_id, token_pin_env, key_label)
    }

    /// The HSM connection identity this signer is bound to (F12). Logged at
    /// startup so an operator can confirm which module and slot answered.
    pub fn connection_info(&self) -> String {
        format!(
            "PKCS#11 module '{}' slot {} pin-env '{}'",
            self.module_path, self.slot_id, self.token_pin_env
        )
    }

    fn connect(
        module_path: String,
        slot_id: u64,
        token_pin_env: String,
        key_label: Option<String>,
    ) -> Result<Self, CryptoError> {
        let pin = std::env::var(&token_pin_env).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "PKCS#11 PIN env '{token_pin_env}' not accessible: {e}"
            ))
        })?;
        if pin.is_empty() {
            return Err(CryptoError::KeyGeneration("PKCS#11 PIN is empty".into()));
        }
        let client = cryptoki::context::Pkcs11::new(&module_path).map_err(|e| {
            CryptoError::KeyGeneration(format!(
                "Failed to load PKCS#11 module '{module_path}': {e}"
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
            CryptoError::KeyGeneration(format!("Failed to open RW session on slot {slot_id}: {e}"))
        })?;
        // Secrecy 0.10 removed secrecy::Secret; in Cryptoki 0.12 an AuthPin is
        // a SecretString, which is a SecretBox<str>.
        let pin_secret = secrecy::SecretString::new(pin.into_boxed_str());
        session
            .login(cryptoki::session::UserType::User, Some(&pin_secret))
            .map_err(|e| CryptoError::KeyGeneration(format!("PKCS#11 login failed: {e}")))?;
        let public_key_bytes = Self::extract_ed25519_public_key(&session, key_label.as_deref())
            .map_err(|e| {
                CryptoError::KeyGeneration(format!("Failed to extract Ed25519 key from HSM: {e}"))
            })?;
        // Prove up front, with a test signature, that the public key read here and the
        // private key that will do the signing belong to the same pair.
        Self::verify_key_binding(&session, key_label.as_deref(), &public_key_bytes)
            .map_err(CryptoError::KeyGeneration)?;
        let bls_key = None;
        let pq_key = None;
        // P02-F01 decision A: the consensus public halves live in the slot as
        // PUBLIC_KEY objects. They used to be hard-coded `None` here, so a
        // mainnet HSM validator could never register its BLS or PQ key.
        let bls_public_key_bytes = Self::extract_public_key_by_label(&session, BLS_DATA_LABEL);
        let pq_public_key_bytes = Self::extract_public_key_by_label(&session, PQ_DATA_LABEL);

        Ok(Self {
            module_path,
            slot_id,
            token_pin_env,
            key_label,
            public_key_bytes,
            bls_key: Mutex::new(bls_key),
            pq_key: Mutex::new(pq_key),
            inner: Mutex::new(Some(Pkcs11Inner {
                pkcs11_client: client,
                session,
            })),
            bls_mechanism: None,
            pq_mechanism: None,
            strict_vendor_native: false,
            bls_public_key_bytes,
            pq_public_key_bytes,
            expected_bls_public_key: None,
            expected_pq_public_key: None,
            standard_pq_key: None,
        })
    }

    /// Read the PUBLIC_KEY object carrying `label`, exactly one (P02-F01).
    ///
    /// Zero objects is `None` - the slot may legitimately hold only the Ed25519
    /// identity. More than one is refused: announcing one consensus key while
    /// signing with another is a consensus fault, the same rule the Ed25519
    /// extractor follows.
    fn extract_public_key_by_label(
        session: &cryptoki::session::Session,
        label: &str,
    ) -> Option<Vec<u8>> {
        let template = vec![
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
            cryptoki::object::Attribute::Label(label.into()),
        ];
        let objects = match session.find_objects(&template) {
            Ok(objects) => objects,
            Err(e) => {
                tracing::warn!("PKCS#11: public key search for label {label} failed: {e}");
                return None;
            }
        };
        if objects.is_empty() {
            return None;
        }
        if objects.len() > 1 {
            tracing::warn!(
                "PKCS#11: {} PUBLIC_KEY objects carry label {label}; refusing to guess",
                objects.len()
            );
            return None;
        }
        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .ok()?;
        match attr.first() {
            Some(cryptoki::object::Attribute::Value(value)) => Some(value.clone()),
            _ => None,
        }
    }

    /// Operator-configured expectations, cross-checked against the slot
    /// (P02-F01 decision B).
    ///
    /// With both sides present they must match byte for byte; with only the
    /// expectation present it becomes the announced key and the vendor
    /// binding test in [`Self::with_vendor_mechanisms`] proves the pairing.
    pub fn with_expected_consensus_public_keys(
        mut self,
        bls_public_key: Option<Vec<u8>>,
        pq_public_key: Option<Vec<u8>>,
    ) -> Result<Self, CryptoError> {
        if let Some(expected) = &bls_public_key {
            if let Some(read) = &self.bls_public_key_bytes {
                if read != expected {
                    return Err(CryptoError::KeyGeneration(
                        "HSM BLS public key does not match the operator-configured key".into(),
                    ));
                }
            }
        }
        if let Some(expected) = &pq_public_key {
            if let Some(read) = &self.pq_public_key_bytes {
                if read != expected {
                    return Err(CryptoError::KeyGeneration(
                        "HSM PQ public key does not match the operator-configured key".into(),
                    ));
                }
            }
        }
        self.expected_bls_public_key = bls_public_key;
        self.expected_pq_public_key = pq_public_key;
        Ok(self)
    }

    /// Bind the validator ML-DSA-65 key stored under `label` and sign with it
    /// through the PKCS#11 3.2 standard mechanism (: the first path; a
    /// vendor mechanism is for tokens without 3.2). The key is opened with the
    /// pairing proof of [`Pkcs11PqToken::open_key`] and, when the operator
    /// configured an expected public key, must equal it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] when the token has no such key pair, the
    /// pairing proof fails or the key is not the configured one.
    pub fn with_standard_pq_key(mut self, label: &str) -> Result<Self, CryptoError> {
        let token = Pkcs11PqToken::open(&self.module_path, self.slot_id, &self.token_pin_env)?;
        let key = token.open_key(label, HsmPqAlgorithm::MlDsa65)?;
        if let Some(expected) = &self.expected_pq_public_key {
            if key.public_key() != *expected {
                return Err(CryptoError::KeyGeneration(
                    "HSM PQ public key does not match the operator-configured key".into(),
                ));
            }
        }
        self.standard_pq_key = Some(key);
        Ok(self)
    }

    /// Set vendor-native BLS/PQ mechanism IDs.
    /// Cryptoki 0.12 uses Mechanism::VendorDefined for hardware-native signing.
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

    /// The consensus public half this signer announces (P02-F01).
    ///
    /// Operator expectation (decision B) wins as the announced identity; the
    /// HSM-read object (decision A) is the fallback. Both were cross-checked
    /// for equality at build time when both existed.
    fn announced_bls_public_key(&self) -> Option<Vec<u8>> {
        self.expected_bls_public_key
            .clone()
            .or_else(|| self.bls_public_key_bytes.clone())
    }

    /// The PQ counterpart of [`Self::announced_bls_public_key`].
    fn announced_pq_public_key(&self) -> Option<Vec<u8>> {
        self.expected_pq_public_key
            .clone()
            .or_else(|| self.standard_pq_key.as_ref().map(HsmPqKey::public_key))
            .or_else(|| self.pq_public_key_bytes.clone())
    }

    /// Startup binding test (P02-F01 decision B): the announced consensus
    /// public keys must pair with the keys the HSM actually signs with.
    ///
    /// Announcing one BLS key and signing with another is a consensus fault
    /// with no recovery, so the pairing is proven once at startup against a
    /// fixed message instead of at the first checkpoint.
    pub fn verify_consensus_key_bindings(&self) -> Result<(), CryptoError> {
        const BINDING_MSG: &[u8] = b"BUDLUM_HSM_CONSENSUS_KEY_BINDING_V1";
        if self.bls_mechanism.is_some() {
            let pk = Self::binding_key("BLS", self.announced_bls_public_key())
                .map_err(CryptoError::KeyGeneration)?;
            let sig = self.bls_sign(BINDING_MSG)?;
            crate::chain::finality::verify_bls_sig(&pk, BINDING_MSG, &sig).map_err(|e| {
                CryptoError::KeyGeneration(format!("HSM BLS key binding test failed: {e}"))
            })?;
        }
        if self.pq_mechanism.is_some() || self.standard_pq_key.is_some() {
            let pk = Self::binding_key("PQ", self.announced_pq_public_key())
                .map_err(CryptoError::KeyGeneration)?;
            let ctx = crate::crypto::ctx::KEY_BINDING_V1;
            let sig = self.pq_sign(ctx, BINDING_MSG)?;
            crate::crypto::primitives::PqKeyPair::verify(&pk, ctx, BINDING_MSG, &sig).map_err(
                |e| CryptoError::KeyGeneration(format!("HSM PQ key binding test failed: {e}")),
            )?;
        }
        Ok(())
    }

    /// A configured vendor mechanism needs a public key to bind against.
    /// Without one the binding test would pass by doing nothing.
    fn binding_key(which: &str, announced: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
        announced.ok_or_else(|| {
            format!("{which} vendor mechanism is configured but no {which} public key is known to bind it against")
        })
    }

    /// Require vendor-native BLS/PQ signing and fail closed on any fallback.
    #[must_use]
    pub fn require_vendor_native_signing(mut self) -> Self {
        self.strict_vendor_native = true;
        self
    }

    fn parse_mechanism(s: &str) -> Option<u64> {
        s.strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| s.parse::<u64>().ok())
    }

    /// Builds a vendor mechanism. S1 fix (2026-07-17): this is the REAL
    /// cryptoki 0.12 API - there is NO struct literal, because the fields are
    /// private (E0451/E0560). `MechanismType::new_vendor_defined` refuses ids
    /// below the `CKM_VENDOR_DEFINED` base, which is a fail-closed value
    /// check, and a `VendorDefinedMechanism` is only built through `::new`.
    fn vendor_mechanism(id: u64) -> Result<cryptoki::mechanism::Mechanism<'static>, CryptoError> {
        use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
        use cryptoki::mechanism::MechanismType;
        // CI (2026-07-21): the first Windows run of the cross-platform
        // determinism matrix caught this line (E0308). In cryptoki-sys,
        // `CK_MECHANISM_TYPE` is u32 on Windows (CK_ULONG under the LLP64 ABI)
        // and u64 on Unix (LP64) - and since cryptoki_sys is not re-exported,
        // the type cannot be named here. The platform mapping is kept identical
        // to cryptoki-sys's own definition, and a vendor id that does not fit
        // in 32 bits fails closed with an error, never a silent truncation.
        #[cfg(windows)]
        let mech_id = u32::try_from(id).map_err(|_| {
            CryptoError::Signing(format!(
                "PKCS#11 vendor mechanism id 0x{id:08X} is outside the range of a 32-bit CK_ULONG (Windows ABI)"
            ))
        })?;
        #[cfg(not(windows))]
        let mech_id = id;
        let mech_type = MechanismType::new_vendor_defined(mech_id).map_err(|e| {
            CryptoError::Signing(format!(
                "PKCS#11 vendor mechanism id 0x{id:08X} is below the CKM_VENDOR_DEFINED base: {e}"
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
        check_signature: fn(&[u8]) -> Result<(), String>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mechanism = Self::vendor_mechanism(mech_id)?;
        let template = &[
            cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            cryptoki::object::Attribute::Label(label.into()),
        ];
        let objects = session
            .find_objects(template)
            .map_err(|e| CryptoError::Signing(format!("Failed to find key '{label}': {e}")))?;
        Self::require_single_vendor_object(label, objects.len()).map_err(CryptoError::Signing)?;
        let sig = session
            .sign(&mechanism, objects[0], msg)
            .map_err(|e| CryptoError::Signing(format!("Vendor sign '{label}': {e}")))?;
        check_signature(&sig)
            .map_err(|e| CryptoError::Signing(format!("Vendor sign '{label}': {e}")))?;
        Ok(sig)
    }

    /// A vendor label must name exactly one private key. Taking the first of several
    /// objects could sign with a key other than the one the node announced.
    fn require_single_vendor_object(label: &str, count: usize) -> Result<(), String> {
        match count {
            0 => Err(format!("Key '{label}' not found for vendor sign")),
            1 => Ok(()),
            n => Err(format!(
                "{n} private keys carry the label '{label}'; refusing to guess"
            )),
        }
    }

    /// A vendor BLS signature is a compressed G1 point (48 bytes), as the software path
    /// produces. Any other length is a scheme mismatch and must not be voted.
    fn check_bls_signature_len(sig: &[u8]) -> Result<(), String> {
        const BLS_SIGNATURE_LEN: usize = 48;
        if sig.len() == BLS_SIGNATURE_LEN {
            Ok(())
        } else {
            Err(format!(
                "BLS signature length {} is not {BLS_SIGNATURE_LEN}",
                sig.len()
            ))
        }
    }

    /// A vendor PQ signature must have the length of the validator PQ scheme.
    ///
    /// The scheme is fixed by configuration (ML-DSA-65, suite 0x0002) and named
    /// here; the length is checked against that scheme only, never used to
    /// decide which scheme the bytes are (INV-03).
    fn check_pq_signature_len(sig: &[u8]) -> Result<(), String> {
        let expected = crate::crypto::pq::signature_len(crate::crypto::scheme::SchemeId::ML_DSA_65)
            .map_err(|e| e.to_string())?;
        if sig.len() == expected {
            Ok(())
        } else {
            Err(format!(
                "PQ signature length {} is not the validator scheme length {expected}",
                sig.len()
            ))
        }
    }

    pub fn store_bls_key(&self, _keypair: &BlsKeypair) -> Result<(), CryptoError> {
        // HIGH (CWE-922, 2026-08-17): storing a plaintext BLS key in a
        // DATA object is refused in EVERY mode. Hardware custody means
        // vendor-managed objects; a DATA object is readable from software
        // (fallback loaders rehydrate it through CKA_VALUE), so the
        // "hardware-only custody" claim would have been broken. Nothing was
        // calling store_*, so the door was shut completely.
        Err(CryptoError::Signing(
            "BLS key storage refused: DATA objects are not hardware custody; use vendor-native key objects"
                .into(),
        ))
    }

    pub fn store_pq_key(&self, _keypair: &PqKeyPair) -> Result<(), CryptoError> {
        // HIGH (CWE-922, 2026-08-17): the same reasoning - a PQ secret
        // cannot be stored as a DATA object; hardware custody is
        // vendor-managed.
        Err(CryptoError::Signing(
            "PQ key storage refused: DATA objects are not hardware custody; use vendor-native key objects"
                .into(),
        ))
    }

    fn extract_ed25519_public_key(
        session: &cryptoki::session::Session,
        key_label: Option<&str>,
    ) -> Result<[u8; 32], String> {
        let class = cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY);
        let key_type = cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS);
        let label = key_label.map(|l| cryptoki::object::Attribute::Label(l.into()));

        let template: Vec<cryptoki::object::Attribute> = match &label {
            Some(label) => vec![class, key_type, label.clone()],
            None => vec![class, key_type],
        };

        let objects = session
            .find_objects(&template)
            .map_err(|e| format!("Ed25519 key search failed: {e}"))?;

        // More than one key is never guessed: announcing one identity and signing with a
        // different key is a consensus fault.
        Self::require_single_key("public", objects.len())?;

        let attr = session
            .get_attributes(objects[0], &[cryptoki::object::AttributeType::Value])
            .map_err(|e| format!("Public key read failed: {e}"))?;
        if let Some(cryptoki::object::Attribute::Value(value)) = attr.first() {
            // P02-F14: the exact length, not a silent cut. A 33-byte read
            // truncated to 32 announced a key the HSM never held.
            if value.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(value);
                return Ok(key);
            }
            return Err(format!(
                "Ed25519 public key has unexpected length {} (want 32)",
                value.len()
            ));
        }
        Err("Failed to extract public key bytes".into())
    }

    /// The slot must hold exactly one Ed25519 key. The older behaviour guessed with
    /// `objects[0]`, so with several keys the identity a node announced and the key it
    /// signed with could differ.
    fn require_single_key(kind: &str, count: usize) -> Result<(), String> {
        match count {
            0 => Err(format!("No Ed25519 {kind} key found in HSM")),
            1 => Ok(()),
            n => Err(format!(
                "{n} Ed25519 {kind} keys found in HSM slot; refusing to guess, set an explicit key label"
            )),
        }
    }

    fn private_key_handle(
        session: &cryptoki::session::Session,
        key_label: Option<&str>,
    ) -> Result<cryptoki::object::ObjectHandle, String> {
        let class = cryptoki::object::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY);
        let key_type = cryptoki::object::Attribute::KeyType(cryptoki::object::KeyType::EC_EDWARDS);
        let label = key_label.map(|l| cryptoki::object::Attribute::Label(l.into()));

        let template: Vec<cryptoki::object::Attribute> = match &label {
            Some(label) => vec![class, key_type, label.clone()],
            None => vec![class, key_type],
        };

        let objects = session
            .find_objects(&template)
            .map_err(|e| format!("Ed25519 key search: {e}"))?;

        Self::require_single_key("private", objects.len())?;
        Ok(objects[0])
    }

    fn ed25519_mechanism() -> cryptoki::mechanism::Mechanism<'static> {
        // Cryptoki 0.12 removed EddsaParams::default; parameterless pure
        // Ed25519 is EddsaSignatureScheme::Pure.
        cryptoki::mechanism::Mechanism::Eddsa(cryptoki::mechanism::eddsa::EddsaParams::new(
            cryptoki::mechanism::eddsa::EddsaSignatureScheme::Pure,
        ))
    }

    fn sign_ed25519(
        session: &cryptoki::session::Session,
        key_label: Option<&str>,
        msg: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key_handle = Self::private_key_handle(session, key_label)?;
        let sig = session
            .sign(&Self::ed25519_mechanism(), key_handle, msg)
            .map_err(|e| format!("HSM sign: {e}"))?;
        // P02-F14: the exact length, not a silent cut. A vendor signature
        // longer than 64 bytes is a different encoding, not a longer Ed25519
        // signature; truncating it verified nothing.
        if sig.len() != 64 {
            return Err(format!(
                "HSM returned a signature of {} bytes (want 64)",
                sig.len()
            ));
        }
        Ok(sig)
    }

    /// Checks the read public key against the private key that will sign in the slot, over
    /// a fixed test message. On a mismatch the node does not start: a wrong pairing
    /// produces an invalid signature on every block.
    fn verify_key_binding(
        session: &cryptoki::session::Session,
        key_label: Option<&str>,
        public_key_bytes: &[u8; 32],
    ) -> Result<(), String> {
        let signature = Self::sign_ed25519(session, key_label, ED25519_BINDING_TEST_MESSAGE)?;
        let signature_bytes: [u8; 64] = signature[..64]
            .try_into()
            .map_err(|_| "HSM returned an unexpected signature length".to_string())?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| format!("HSM public key is not a valid Ed25519 verifying key: {e}"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify_strict(ED25519_BINDING_TEST_MESSAGE, &signature)
            .map_err(|_| {
                "HSM private key does not match the Ed25519 public key read from the slot"
                    .to_string()
            })
    }
}

/// Vendor-native BLS/PQ capability snapshot (audit / mainnet advertisement).
///
/// PKCS#11 standard has no portable BLS/Dilithium mechanism. Vendors expose
/// `CKM_VENDOR_DEFINED + offset` IDs. This struct records whether the operator
/// Configured those IDs and whether software fallback material is present -
/// It does **not** claim non-extractable hardware keys without vendor audit.
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
    /// The validator PQ key signs through the PKCS#11 3.2 standard mechanism.
    pub pq_standard_mechanism: bool,
}

impl Pkcs11VendorCapabilities {
    /// True only when the BLS vendor mechanism is configured and the PQ key
    /// signs in the token, through the PKCS#11 3.2 standard mechanism or a
    /// vendor mechanism. Still requires external audit before mainnet
    /// "non-extractable" claims.
    #[must_use]
    pub fn vendor_native_signing_configured(&self) -> bool {
        self.bls_vendor_mechanism.is_some()
            && (self.pq_vendor_mechanism.is_some() || self.pq_standard_mechanism)
    }

    /// True when BLS can be signed (vendor path OR software fallback material).
    #[must_use]
    pub fn bls_signing_available(&self) -> bool {
        self.bls_vendor_mechanism.is_some() || self.bls_software_fallback_present
    }

    /// True when PQ can be signed (vendor path OR software fallback material).
    #[must_use]
    pub fn pq_signing_available(&self) -> bool {
        self.pq_vendor_mechanism.is_some()
            || self.pq_standard_mechanism
            || self.pq_software_fallback_present
    }
}

impl Pkcs11Signer {
    /// Report configured vendor-native + fallback capabilities.
    #[must_use]
    pub fn vendor_capabilities(&self) -> Pkcs11VendorCapabilities {
        let bls_sw = self.bls_key.lock().ok().is_some_and(|g| g.is_some());
        let pq_sw = self.pq_key.lock().ok().is_some_and(|g| g.is_some());
        Pkcs11VendorCapabilities {
            bls_vendor_mechanism: self.bls_mechanism,
            pq_vendor_mechanism: self.pq_mechanism,
            bls_software_fallback_present: bls_sw,
            pq_software_fallback_present: pq_sw,
            pq_standard_mechanism: self.standard_pq_key.is_some(),
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

        Self::sign_ed25519(&inner.session, self.key_label.as_deref(), block_hash)
            .map_err(CryptoError::Signing)
    }

    fn ed25519_sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::Signing("HSM mutex poisoned".into()))?;
        let inner = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("HSM session closed".into()))?;
        Self::sign_ed25519(&inner.session, self.key_label.as_deref(), msg)
            .map_err(CryptoError::Signing)
    }

    fn bls_sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Strict mode is a fail-CLOSED policy, so it has to be decided before
        // any path that could reach the in-process fallback key. The previous
        // shape only consulted `strict_vendor_native` inside the error arm of
        // an attempted vendor sign, so two configurations silently downgraded
        // to software signing: no vendor mechanism id, and a closed session.
        // Neither of those is a vendor-native signature, and both were
        // reported as success.
        if self.strict_vendor_native && self.bls_mechanism.is_none() {
            return Err(CryptoError::Signing(
                "vendor-native BLS signing required, but no vendor BLS mechanism is configured"
                    .into(),
            ));
        }
        if let Some(mech_id) = self.bls_mechanism {
            let guard = self
                .inner
                .lock()
                .map_err(|_| CryptoError::Signing("HSM mutex".into()))?;
            if let Some(inner) = guard.as_ref() {
                let check = Self::check_bls_signature_len;
                match self.try_vendor_sign(&inner.session, mech_id, BLS_DATA_LABEL, msg, check) {
                    Ok(sig) => return Ok(sig),
                    Err(e) => {
                        if self.strict_vendor_native {
                            return Err(CryptoError::Signing(format!(
                                "vendor-native BLS signing required, fallback forbidden: {e}"
                            )));
                        }
                        tracing::warn!("Vendor BLS sign failed ({e}), sw fallback")
                    }
                }
            } else if self.strict_vendor_native {
                return Err(CryptoError::Signing(
                    "vendor-native BLS signing required, but the HSM session is closed".into(),
                ));
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

    fn pq_sign(&self, ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // The PKCS#11 3.2 standard mechanism carries the FIPS 204 context and
        // the key never leaves the token: no vendor mechanism, no software
        // fallback.
        if let Some(key) = &self.standard_pq_key {
            let sig = key.sign(ctx, msg)?;
            Self::check_pq_signature_len(&sig).map_err(CryptoError::Signing)?;
            return Ok(sig);
        }
        // Same fail-closed ordering as `bls_sign`; the two must stay identical
        // or a strict-mode validator gets one guarantee for its BLS key and a
        // different one for its PQ key.
        if self.strict_vendor_native && self.pq_mechanism.is_none() {
            return Err(CryptoError::Signing(
                "vendor-native PQ signing required, but no vendor PQ mechanism is configured"
                    .into(),
            ));
        }
        if self.pq_mechanism.is_some() {
            // A vendor-defined mechanism signs the raw message and takes no
            // FIPS 204 context, so its signature cannot carry the context
            // string every PQ signature must bind. Signing without a
            // context is refused, not emulated: the standard PKCS#11 3.2
            // ML-DSA mechanisms take a context parameter (`with_standard_pq_key`).
            if self.strict_vendor_native {
                return Err(CryptoError::Signing(
                    "vendor-native PQ signing required, but vendor mechanisms carry no FIPS 204 context (use the PKCS#11 3.2 standard key, `with_standard_pq_key`)"
                        .into(),
                ));
            }
            tracing::warn!(
                "Vendor PQ mechanism cannot carry a FIPS 204 context; using the software key"
            );
        }
        let guard = self
            .pq_key
            .lock()
            .map_err(|_| CryptoError::Signing("PQ mutex".into()))?;
        let pq = guard
            .as_ref()
            .ok_or_else(|| CryptoError::Signing("No PQ key in HSM".into()))?;
        let sig = pq.sign(ctx, msg)?;
        Self::check_pq_signature_len(&sig).map_err(CryptoError::Signing)?;
        Ok(sig)
    }

    fn bls_public_key(&self) -> Option<Vec<u8>> {
        self.announced_bls_public_key().or_else(|| {
            self.bls_key
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|k| k.public_key.clone()))
        })
    }

    fn pq_public_key(&self) -> Option<Vec<u8>> {
        self.announced_pq_public_key().or_else(|| {
            self.pq_key
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|k| k.public_key_bytes().to_vec()))
        })
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
            pq_standard_mechanism: false,
        };
        assert!(caps.vendor_native_signing_configured());
        assert!(caps.bls_signing_available());
        assert!(caps.pq_signing_available());

        let fallback_only = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: None,
            pq_vendor_mechanism: None,
            bls_software_fallback_present: true,
            pq_software_fallback_present: true,
            pq_standard_mechanism: false,
        };
        assert!(!fallback_only.vendor_native_signing_configured());
        assert!(fallback_only.bls_signing_available());
        assert!(fallback_only.pq_signing_available());

        let empty = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: None,
            pq_vendor_mechanism: None,
            bls_software_fallback_present: false,
            pq_software_fallback_present: false,
            pq_standard_mechanism: false,
        };
        assert!(!empty.bls_signing_available());
        assert!(!empty.pq_signing_available());

        let standard = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: Some(0x8000_0001),
            pq_vendor_mechanism: None,
            bls_software_fallback_present: false,
            pq_software_fallback_present: false,
            pq_standard_mechanism: true,
        };
        assert!(standard.vendor_native_signing_configured());
        assert!(standard.pq_signing_available());
        let no_bls = Pkcs11VendorCapabilities {
            bls_vendor_mechanism: None,
            ..standard
        };
        assert!(!no_bls.vendor_native_signing_configured());
    }
}

// ── (2026-07-23): HSM vendor mechanism validation hardening ──
//
// YubiHSM 2 and other PKCS#11 tokens support vendor-defined mechanisms
// For native BLS/PQ signing. These must be validated before use to prevent
// Invalid mechanism IDs from causing undefined behavior in the HSM firmware.

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

/// Decide whether a configured mechanism id may sign on mainnet.
///
/// Two functions existed for this and neither had a caller.
/// `validate_vendor_mechanism` matched an id against a capability table, and
/// `Pkcs11VendorCapability::check_mainnet_policy` refused a capability whose
/// `mainnet_allowed` was false. `main.rs` checked only that the id parsed and
/// sat at or above `CKM_VENDOR_DEFINED`, so a mechanism the table explicitly
/// marks as not-for-mainnet was accepted, and so was one outside the vendor's
/// own documented range: `validate_mechanism_id` refuses a YubiHSM2 id above
/// `0x8000_FFFF` and nothing asked it.
///
/// The rule, as decided: an id the table knows is governed by the table's
/// answer. An id the table does not know is admitted as `Generic` and put
/// through the same policy, rather than refused outright, because a hard
/// allow-list would exclude every HSM vendor nobody has enumerated yet, and
/// that is a reason to add an entry, not a reason to refuse the operator's
/// hardware.
///
/// What the fallback does not do is weaken the floor. A `Generic` capability
/// still has to clear `CKM_VENDOR_DEFINED`, which is the one bound that holds
/// for any PKCS#11 token: below it, the id belongs to a standard mechanism
/// that means something else entirely, and asking a token to BLS-sign with
/// the id of, say, `CKM_SHA256` is undefined behaviour in the firmware.
///
/// # Errors
///
/// The reason the mechanism may not sign here, naming the id.
pub fn check_mechanism_admissible_for_mainnet(
    mechanism_id: u64,
    capabilities: &[Pkcs11VendorCapability],
) -> Result<(), String> {
    match validate_vendor_mechanism(mechanism_id, capabilities) {
        Ok(known) => known.check_mainnet_policy(),
        Err(_) => {
            // Unknown to the table. Admitted as Generic and held to the same
            // policy rather than waved through: `validate_mechanism_id` still
            // applies the `CKM_VENDOR_DEFINED` floor.
            let assumed = Pkcs11VendorCapability {
                vendor: Pkcs11Vendor::Generic,
                mechanism_id,
                name: format!("unlisted vendor mechanism 0x{mechanism_id:08X}"),
                // An unlisted mechanism is not thereby forbidden; it is
                // unaudited. Saying otherwise here would make the fallback a
                // refusal wearing a different name.
                mainnet_allowed: true,
            };
            assumed.check_mainnet_policy()
        }
    }
}

/// Validate a mechanism ID against a set of known capabilities.
/// Returns the matching capability or an error if unknown/invalid.
pub fn validate_vendor_mechanism(
    mechanism_id: u64,
    capabilities: &[Pkcs11VendorCapability],
) -> Result<&Pkcs11VendorCapability, String> {
    if mechanism_id < CKM_VENDOR_DEFINED {
        return Err(format!(
            "mechanism 0x{mechanism_id:08X} is not vendor-defined"
        ));
    }
    capabilities
        .iter()
        .find(|c| c.mechanism_id == mechanism_id)
        .ok_or_else(|| format!("unknown vendor mechanism 0x{mechanism_id:08X}"))
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

    /// A mechanism the table forbids on mainnet is refused.
    ///
    /// `check_mainnet_policy` was written for exactly this and had no caller.
    /// `main.rs` checked that the id parsed and cleared `CKM_VENDOR_DEFINED`,
    /// so a capability the table explicitly marks `mainnet_allowed: false`
    /// was accepted by a mainnet validator.
    #[test]
    fn a_mechanism_marked_not_for_mainnet_is_refused() {
        let caps = vec![Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: YUBIHSM2_CKM_BLS_SIGN,
            name: "deprecated-bls".into(),
            mainnet_allowed: false,
        }];

        let err = check_mechanism_admissible_for_mainnet(YUBIHSM2_CKM_BLS_SIGN, &caps)
            .expect_err("the table says this one may not sign on mainnet");
        assert!(
            err.contains("not allowed for mainnet"),
            "the refusal must say the table forbade it, got: {err}"
        );
    }

    /// A mechanism outside the vendor's documented range is refused.
    ///
    /// `validate_mechanism_id` refuses a YubiHSM2 id above `0x8000_FFFF` and
    /// nothing asked it. Above that range the id is not a YubiHSM2 mechanism
    /// at all, so what the token does with it is undefined.
    #[test]
    fn a_mechanism_outside_the_vendor_range_is_refused() {
        let caps = vec![Pkcs11VendorCapability {
            vendor: Pkcs11Vendor::YubiHsm2,
            mechanism_id: 0x8001_0000,
            name: "out-of-range".into(),
            mainnet_allowed: true,
        }];

        assert!(
            check_mechanism_admissible_for_mainnet(0x8001_0000, &caps).is_err(),
            "an id above the vendor's own documented range must be refused \
             even when the entry says mainnet is allowed"
        );
    }

    /// An id the table does not list is admitted, and still held to the floor.
    ///
    /// The decision recorded for this: a hard allow-list would exclude every
    /// HSM vendor nobody has enumerated yet, which is a reason to add an
    /// entry rather than to refuse the operator's hardware. What the fallback
    /// must not do is drop the one bound that holds for any PKCS#11 token.
    #[test]
    fn an_unlisted_mechanism_is_admitted_but_still_floored() {
        let caps = yubihsm2_default_capabilities();

        // Unlisted and above CKM_VENDOR_DEFINED: admitted as Generic.
        check_mechanism_admissible_for_mainnet(0x8000_9999, &caps)
            .expect("an unlisted vendor-defined mechanism is unaudited, not forbidden");

        // Unlisted and below the floor: refused. Below `CKM_VENDOR_DEFINED`
        // the id names a standard mechanism that means something else, and
        // asking a token to BLS-sign with it is undefined in the firmware.
        let err = check_mechanism_admissible_for_mainnet(0x1234, &caps)
            .expect_err("an id below CKM_VENDOR_DEFINED is not a vendor mechanism");
        assert!(
            err.contains("CKM_VENDOR_DEFINED"),
            "the refusal must name the floor it failed, got: {err}"
        );
    }

    /// The known-good pair still passes, or this is a ban on HSMs.
    #[test]
    fn the_documented_yubihsm2_mechanisms_are_admissible() {
        let caps = yubihsm2_default_capabilities();
        for id in [YUBIHSM2_CKM_BLS_SIGN, YUBIHSM2_CKM_PQ_SIGN] {
            check_mechanism_admissible_for_mainnet(id, &caps)
                .expect("the vendor's own documented signing mechanisms must pass");
        }
    }

    #[test]
    fn binding_test_refuses_a_mechanism_without_a_public_key() {
        let missing = Pkcs11Signer::binding_key("BLS", None).unwrap_err();
        assert!(missing.contains("no BLS public key"), "{missing}");
        assert_eq!(
            Pkcs11Signer::binding_key("PQ", Some(vec![1, 2])).unwrap(),
            vec![1, 2]
        );
    }

    #[test]
    fn vendor_sign_refuses_zero_or_several_objects() {
        assert!(Pkcs11Signer::require_single_vendor_object("L", 1).is_ok());
        let none = Pkcs11Signer::require_single_vendor_object("L", 0).unwrap_err();
        assert!(none.contains("not found"), "{none}");
        let many = Pkcs11Signer::require_single_vendor_object("L", 2).unwrap_err();
        assert!(many.contains("refusing to guess"), "{many}");
    }

    #[test]
    fn vendor_signature_length_is_checked() {
        assert!(Pkcs11Signer::check_bls_signature_len(&[0u8; 48]).is_ok());
        assert!(Pkcs11Signer::check_bls_signature_len(&[0u8; 47]).is_err());
        assert!(Pkcs11Signer::check_bls_signature_len(&[0u8; 96]).is_err());
        assert!(Pkcs11Signer::check_pq_signature_len(&[]).is_err());
        assert!(Pkcs11Signer::check_pq_signature_len(&[0u8; 64]).is_err());
        let ok = vec![0u8; crate::crypto::primitives::PQ_ML_DSA_65_SIGNATURE_LEN];
        assert!(Pkcs11Signer::check_pq_signature_len(&ok).is_ok());
    }

    #[test]
    fn a_single_ed25519_key_is_accepted() {
        assert!(Pkcs11Signer::require_single_key("private", 1).is_ok());
    }

    #[test]
    fn a_missing_ed25519_key_is_rejected() {
        let err = Pkcs11Signer::require_single_key("private", 0).unwrap_err();
        assert!(err.contains("No Ed25519 private key"), "{err}");
    }

    /// The older behaviour guessed with `objects[0]`: with more than one key the
    /// announced identity and the signing key could differ.
    #[test]
    fn an_ambiguous_ed25519_key_selection_is_refused() {
        let err = Pkcs11Signer::require_single_key("public", 2).unwrap_err();
        assert!(err.contains("refusing to guess"), "{err}");
    }
}

// ──: post-quantum keys through the PKCS#11 3.2 standard
// mechanisms. cryptoki 0.12 carries CKM_ML_DSA, CKM_SLH_DSA and their key
// pair generation mechanisms, so no vendor mechanism and no raw call is
// involved. A vendor-specific mechanism stays the fallback for tokens that
// lack 3.2 (`Pkcs11Signer::with_vendor_mechanisms`).

use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlDsaParameterSetType, ObjectClass, ObjectHandle,
    ParameterSetType, SlhDsaParameterSetType,
};
use std::sync::Arc;

use crate::crypto::scheme::SchemeId;

/// The post-quantum families a token key can belong to. Only the three the
/// needs for signing: ML-DSA-65 (validator), ML-DSA-87 (anchor) and
/// SLH-DSA-SHAKE-256s (Root Seal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmPqAlgorithm {
    /// CKK_ML_DSA with CKP_ML_DSA_65: the validator key.
    MlDsa65,
    /// CKK_ML_DSA with CKP_ML_DSA_87.
    MlDsa87,
    /// CKK_SLH_DSA with CKP_SLH_DSA_SHAKE_256S.
    SlhDsaShake256s,
}

impl HsmPqAlgorithm {
    fn scheme(self) -> SchemeId {
        match self {
            Self::MlDsa65 => SchemeId::ML_DSA_65,
            Self::MlDsa87 => SchemeId::ML_DSA_87,
            Self::SlhDsaShake256s => SchemeId::SLH_DSA_SHAKE_256S,
        }
    }

    fn key_type(self) -> KeyType {
        match self {
            Self::MlDsa65 | Self::MlDsa87 => KeyType::ML_DSA,
            Self::SlhDsaShake256s => KeyType::SLH_DSA,
        }
    }

    fn parameter_set(self) -> ParameterSetType {
        match self {
            Self::MlDsa65 => MlDsaParameterSetType::ML_DSA_65.into(),
            Self::MlDsa87 => MlDsaParameterSetType::ML_DSA_87.into(),
            Self::SlhDsaShake256s => SlhDsaParameterSetType::SHAKE_256S.into(),
        }
    }

    fn keygen_mechanism(self) -> Mechanism<'static> {
        match self {
            Self::MlDsa65 | Self::MlDsa87 => Mechanism::MlDsaKeyPairGen,
            Self::SlhDsaShake256s => Mechanism::SlhDsaKeyPairGen,
        }
    }

    /// The signing mechanism carrying the FIPS 204/205 context string. The
    /// hedge variant is the token's choice (hedged when it can).
    fn sign_mechanism(self, ctx: &[u8]) -> Mechanism<'_> {
        let params = SignAdditionalContext::new(HedgeType::Preferred, Some(ctx));
        match self {
            Self::MlDsa65 | Self::MlDsa87 => Mechanism::MlDsa(params),
            Self::SlhDsaShake256s => Mechanism::SlhDsa(params),
        }
    }
}

fn pq_err(what: &str, e: impl std::fmt::Display) -> CryptoError {
    CryptoError::KeyGeneration(format!("PKCS#11 3.2 {what}: {e}"))
}

/// A logged-in session on one token, shared by the post-quantum keys that
/// live on it. A session is not `Sync`, so every operation takes the lock.
pub struct Pkcs11PqToken {
    inner: Mutex<Pkcs11Inner>,
}

impl Pkcs11PqToken {
    /// Load the module, open a read-write session on `slot_id` and log in as
    /// the user with the PIN read from the environment variable.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] for a missing or empty PIN, a module
    /// that does not load, a slot that is absent or a failed login.
    pub fn open(
        module_path: &str,
        slot_id: u64,
        token_pin_env: &str,
    ) -> Result<Arc<Self>, CryptoError> {
        let pin = std::env::var(token_pin_env)
            .map_err(|e| pq_err("PIN env not accessible", format!("{token_pin_env}: {e}")))?;
        if pin.is_empty() {
            return Err(pq_err("PIN", "empty"));
        }
        let client = cryptoki::context::Pkcs11::new(module_path)
            .map_err(|e| pq_err("module load", format!("{module_path}: {e}")))?;
        match client.initialize(cryptoki::context::CInitializeArgs::new(
            cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
        )) {
            Ok(()) => {}
            // The validator signer of the same node already initialised the
            // module in this process.
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::CryptokiAlreadyInitialized,
                _,
            )) => {}
            Err(e) => return Err(pq_err("initialize", e)),
        }
        let slots = client
            .get_slots_with_token()
            .map_err(|e| pq_err("slot enumeration", e))?;
        let slot = slots
            .iter()
            .find(|s| s.id() == slot_id)
            .copied()
            .ok_or_else(|| pq_err("slot", format!("{slot_id} not found")))?;
        let session = client
            .open_rw_session(slot)
            .map_err(|e| pq_err("session", e))?;
        let pin_secret = secrecy::SecretString::new(pin.into_boxed_str());
        session
            .login(cryptoki::session::UserType::User, Some(&pin_secret))
            .map_err(|e| pq_err("login", e))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(Pkcs11Inner {
                pkcs11_client: client,
                session,
            }),
        }))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Pkcs11Inner>, CryptoError> {
        self.inner
            .lock()
            .map_err(|_| pq_err("session", "lock poisoned"))
    }

    /// Generate a key pair inside the token under `label`. The private key is
    /// a token object, sensitive and not extractable; the public key is read
    /// back and length checked.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] when the token lacks the 3.2 mechanism,
    /// refuses the template, or returns a public key of the wrong length.
    pub fn generate_key(
        self: &Arc<Self>,
        label: &str,
        algorithm: HsmPqAlgorithm,
    ) -> Result<Pkcs11PqKey, CryptoError> {
        {
            let guard = self.lock()?;
            let public_template = [
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::Label(label.into()),
                Attribute::ParameterSet(algorithm.parameter_set()),
            ];
            let private_template = [
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(label.into()),
            ];
            guard
                .session
                .generate_key_pair(
                    &algorithm.keygen_mechanism(),
                    &public_template,
                    &private_template,
                )
                .map_err(|e| pq_err("key pair generation", e))?;
        }
        self.open_key(label, algorithm)
    }

    /// Bind to the key pair stored under `label`. Exactly one private and one
    /// public object must carry the label; the public key must have the
    /// length and parameter set of `algorithm`; and a probe signature made by
    /// the token must verify under that public key, which proves the two
    /// objects are one pair.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] naming the check that failed.
    pub fn open_key(
        self: &Arc<Self>,
        label: &str,
        algorithm: HsmPqAlgorithm,
    ) -> Result<Pkcs11PqKey, CryptoError> {
        let (private_key, public_key) = {
            let guard = self.lock()?;
            let find_one = |class: ObjectClass| -> Result<ObjectHandle, CryptoError> {
                let template = [
                    Attribute::Class(class),
                    Attribute::KeyType(algorithm.key_type()),
                    Attribute::Label(label.into()),
                ];
                let found = guard
                    .session
                    .find_objects(&template)
                    .map_err(|e| pq_err("object search", e))?;
                match found.as_slice() {
                    [one] => Ok(*one),
                    [] => Err(pq_err("key", format!("no {class} object labelled {label}"))),
                    many => Err(pq_err(
                        "key",
                        format!("{} objects labelled {label}, refusing to guess", many.len()),
                    )),
                }
            };
            let private_key = find_one(ObjectClass::PRIVATE_KEY)?;
            let public_handle = find_one(ObjectClass::PUBLIC_KEY)?;
            let attributes = guard
                .session
                .get_attributes(
                    public_handle,
                    &[AttributeType::Value, AttributeType::ParameterSet],
                )
                .map_err(|e| pq_err("public key attributes", e))?;
            let mut value = None;
            for attribute in attributes {
                match attribute {
                    Attribute::Value(bytes) => value = Some(bytes),
                    Attribute::ParameterSet(set) if set != algorithm.parameter_set() => {
                        return Err(pq_err("key", "parameter set is not the expected one"));
                    }
                    _ => {}
                }
            }
            (
                private_key,
                value.ok_or_else(|| pq_err("key", "public key has no value"))?,
            )
        };
        let expected = crate::crypto::pq::public_key_len(algorithm.scheme())
            .map_err(|e| pq_err("public key length", format!("{e:?}")))?;
        if public_key.len() != expected {
            return Err(pq_err(
                "key",
                format!(
                    "public key is {} bytes, expected {expected}",
                    public_key.len()
                ),
            ));
        }
        let key = Pkcs11PqKey {
            algorithm,
            public_key,
            private_key,
            token: Arc::clone(self),
        };
        // The pairing proof: a probe signed in the token verifies under the
        // public key that was read.
        let probe = b"BDLM_PKCS11_PQ_BINDING_V1";
        key.sign(crate::crypto::ctx::ANCHOR_V2, probe)?;
        Ok(key)
    }
}

/// A post-quantum signing key held in a PKCS#11 3.2 token. The private key
/// never leaves the token; the signature is checked against the public key
/// before it is returned.
pub struct Pkcs11PqKey {
    algorithm: HsmPqAlgorithm,
    public_key: Vec<u8>,
    private_key: ObjectHandle,
    token: Arc<Pkcs11PqToken>,
}

impl HsmPqKey for Pkcs11PqKey {
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn sign(&self, ctx: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = {
            let guard = self.token.lock()?;
            guard
                .session
                .sign(
                    &self.algorithm.sign_mechanism(ctx),
                    self.private_key,
                    payload,
                )
                .map_err(|e| CryptoError::Signing(format!("PKCS#11 3.2 sign: {e}")))?
        };
        // A token that returns a signature its own public key does not accept
        // is faulty or lying; nothing downstream sees that signature.
        crate::crypto::pq::verify(
            self.algorithm.scheme(),
            &self.public_key,
            payload,
            ctx,
            &signature,
        )
        .map_err(|e| {
            CryptoError::Signing(format!("PKCS#11 3.2 token signature rejected: {e:?}"))
        })?;
        Ok(signature)
    }
}

#[cfg(test)]
mod pkcs11_pq_tests {
    use super::*;

    /// The environment of the software token CI job (kryoptic built with the
    /// `pqc` feature). Without it the test has nothing to talk to and reports
    /// that it did not run; CI sets it and fails the job when it is missing.
    const MODULE_ENV: &str = "BUDLUM_PKCS11_32_MODULE";
    const PIN_ENV: &str = "BUDLUM_PKCS11_32_PIN";
    const SO_PIN: &str = "so-pin-for-tests";
    const USER_PIN: &str = "user-pin-for-tests";

    fn initialise_token(module: &str) -> u64 {
        let client = cryptoki::context::Pkcs11::new(module).expect("module loads");
        client
            .initialize(cryptoki::context::CInitializeArgs::new(
                cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
            ))
            .expect("initialize");
        let slot = *client
            .get_slots_with_token()
            .expect("slots")
            .first()
            .expect("a slot");
        let so = secrecy::SecretString::new(SO_PIN.to_string().into_boxed_str());
        client
            .init_token(slot, &so, "budlum-pq")
            .expect("init token");
        let session = client.open_rw_session(slot).expect("so session");
        session
            .login(cryptoki::session::UserType::So, Some(&so))
            .expect("so login");
        let user = secrecy::SecretString::new(USER_PIN.to_string().into_boxed_str());
        session.init_pin(&user).expect("init user pin");
        session.logout().expect("logout");
        slot.id()
    }

    #[test]
    fn a_pkcs11_3_2_token_signs_ml_dsa_87_and_slh_dsa_with_the_fips_context() {
        let Ok(module) = std::env::var(MODULE_ENV) else {
            eprintln!("{MODULE_ENV} is not set: the PKCS#11 3.2 token test did not run");
            return;
        };
        let slot = initialise_token(&module);
        std::env::set_var(PIN_ENV, USER_PIN);
        let token = Pkcs11PqToken::open(&module, slot, PIN_ENV).expect("token opens");

        for (label, algorithm, scheme, ctx) in [
            (
                "validator-0",
                HsmPqAlgorithm::MlDsa65,
                SchemeId::ML_DSA_65,
                crate::crypto::ctx::KEY_BINDING_V1,
            ),
            (
                "anchor-0",
                HsmPqAlgorithm::MlDsa87,
                SchemeId::ML_DSA_87,
                crate::crypto::ctx::ANCHOR_V2,
            ),
            (
                "seal-0",
                HsmPqAlgorithm::SlhDsaShake256s,
                SchemeId::SLH_DSA_SHAKE_256S,
                crate::crypto::ctx::SEAL_V1,
            ),
        ] {
            let key = token
                .generate_key(label, algorithm)
                .expect("generate in token");
            let payload = b"payload signed inside the token";
            let signature = key.sign(ctx, payload).expect("token signs");
            crate::crypto::pq::verify(scheme, &key.public_key(), payload, ctx, &signature)
                .expect("the signature verifies through the dual verifier facade");
            // The FIPS context is bound: another context does not verify.
            assert!(crate::crypto::pq::verify(
                scheme,
                &key.public_key(),
                payload,
                crate::crypto::ctx::COLD_V1,
                &signature
            )
            .is_err());
            // The private key is not extractable.
            {
                let guard = token.lock().expect("lock");
                let value = guard
                    .session
                    .get_attributes(key.private_key, &[AttributeType::Value]);
                assert!(
                    value.map_or(true, |attrs| attrs.is_empty()),
                    "the private key value must not be readable"
                );
            }
            // A second handle binds to the same pair and a missing label fails.
            let again = token.open_key(label, algorithm).expect("reopen");
            assert_eq!(again.public_key(), key.public_key());
            assert!(token.open_key("no-such-label", algorithm).is_err());
        }
    }
}
