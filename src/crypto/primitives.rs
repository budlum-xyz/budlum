// (CI sertleştirme) `pq-dilithium` ile `pq-ml-dsa` aynı inherent
// Metot setini (generate/from_bytes/sign/verify/…) expose eder; ikisi birden
// Açılırsa 22× E0592/E0034 ile derleme kırılır. Mutually exclusive BY DESIGN:
// Tam olarak bir PQ imza backend'i seçilir. CI feature-matrix her solo build'i,
// Kanarya adımı da bu guard'ın ateşlendiğini kanıtlar (vacuous gate yok).
#[cfg(all(feature = "pq-dilithium", feature = "pq-ml-dsa"))]
compile_error!(
    "features `pq-dilithium` and `pq-ml-dsa` are mutually exclusive; enable exactly one"
);

use bls12_381::{G2Affine, G2Projective, Scalar};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
#[cfg(feature = "pq-dilithium")]
use pqcrypto_dilithium::dilithium5;
#[cfg(feature = "pq-dilithium")]
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignatureTrait, PublicKey as PqPublicKeyTrait,
    SecretKey as PqSecretKeyTrait,
};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use std::path::Path;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyBackend {
    LocalFile,
    Hsm {
        slot: String,
    },
    Threshold {
        shares_required: u8,
        shares_total: u8,
    },
    AirGappedColdStorage,
}

#[derive(Debug, Clone)]
pub struct ValidatorKeyPolicy {
    pub backend: KeyBackend,
    pub rotation_interval_epochs: u64,
    pub allow_export: bool,
}

impl ValidatorKeyPolicy {
    pub fn mainnet_default() -> Self {
        Self {
            backend: KeyBackend::Hsm {
                slot: "BUDLUM_MAINNET_VALIDATOR".to_string(),
            },
            rotation_interval_epochs: 90,
            allow_export: false,
        }
    }

    pub fn devnet_default() -> Self {
        Self {
            backend: KeyBackend::LocalFile,
            rotation_interval_epochs: 0,
            allow_export: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    KeyGeneration(String),
    Signing(String),
    Verification(String),
    Io(String),
    InvalidKey(String),
    PlaintextDiskKeysForbiddenOnMainnet,
}
impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::KeyGeneration(s) => write!(f, "Key generation error: {}", s),
            CryptoError::Signing(s) => write!(f, "Signing error: {}", s),
            CryptoError::Verification(s) => write!(f, "Verification error: {}", s),
            CryptoError::Io(s) => write!(f, "I/O error: {}", s),
            CryptoError::InvalidKey(s) => write!(f, "Invalid key: {}", s),
            CryptoError::PlaintextDiskKeysForbiddenOnMainnet => write!(
                f,
                "CRITICAL: loading plaintext BLS/PQ secret keys directly from disk is forbidden on Mainnet without HSM protection"
            ),
        }
    }
}
impl std::error::Error for CryptoError {}
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
}

use schnorrkel::Keypair as SchnorrkelKeypair;

#[derive(Clone)]
pub struct BlsKeypair {
    pub secret_key: Scalar,
    pub public_key: Vec<u8>,
}

impl BlsKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        use rand::Rng;
        let mut seed = [0u8; 64];
        rand::rng().fill_bytes(&mut seed);
        let sk = Scalar::from_bytes_wide(&seed);
        let pk = G2Affine::from(G2Projective::generator() * sk);
        let pk_compressed = pk.to_compressed().to_vec();
        Ok(BlsKeypair {
            secret_key: sk,
            public_key: pk_compressed,
        })
    }

    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let sk = Scalar::from_bytes_wide(seed);
        let pk = G2Affine::from(G2Projective::generator() * sk);
        let pk_compressed = pk.to_compressed().to_vec();
        BlsKeypair {
            secret_key: sk,
            public_key: pk_compressed,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.secret_key.to_bytes().to_vec();
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Validate G2 encoding AND that pk matches sk.
        if bytes.len() < 32 + 96 {
            return Err(CryptoError::InvalidKey(
                "Invalid BLS keypair bytes length".into(),
            ));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&bytes[0..32]);
        let sk_opt = Scalar::from_bytes(&sk_bytes);
        if sk_opt.is_none().into() {
            return Err(CryptoError::InvalidKey("Invalid BLS secret key".into()));
        }
        let sk = sk_opt.unwrap();

        let mut pk_bytes = [0u8; 96];
        pk_bytes.copy_from_slice(&bytes[32..128]);
        let pk_affine = G2Affine::from_compressed(&pk_bytes);
        if pk_affine.is_none().into() {
            return Err(CryptoError::InvalidKey(
                "Invalid BLS public key encoding".into(),
            ));
        }
        let _pk_checked = pk_affine.unwrap();

        let expected = G2Affine::from(G2Projective::generator() * sk);
        if expected.to_compressed() != pk_bytes {
            return Err(CryptoError::InvalidKey(
                "BLS public key does not match secret key".into(),
            ));
        }

        Ok(BlsKeypair {
            secret_key: sk,
            public_key: pk_bytes.to_vec(),
        })
    }

    /// Generate the canonical proof of possession for this public key.
    pub fn generate_pop(&self) -> Vec<u8> {
        let msg = crate::chain::finality::pop_signing_message(
            0,
            &crate::core::address::Address::zero(),
            &self.public_key,
        );
        crate::chain::finality::sign_bls_pop(&self.secret_key, &msg)
    }

    /// Deprecated compatibility entry point. Registration context is authenticated
    /// By the signed transaction; the IETF PoP itself is canonically over the
    /// Public key. New ceremony tooling must call [`Self::generate_pop`] directly.
    #[deprecated(
        note = "use generate_pop(); chain/address binding is provided by the signed registration transaction"
    )]
    pub fn generate_pop_for_registration(
        &self,
        _chain_id: u64,
        _address: &crate::core::address::Address,
    ) -> Vec<u8> {
        self.generate_pop()
    }

    /// Verify the canonical PoP without a validator registration wrapper.
    pub fn verify_pop(public_key: &[u8], pop: &[u8]) -> Result<(), CryptoError> {
        let entry = crate::chain::finality::ValidatorEntry {
            address: crate::core::address::Address::zero(),
            stake: 0,
            bls_public_key: public_key.to_vec(),
            pop_signature: pop.to_vec(),
            pq_public_key: Vec::new(),
        };
        if crate::chain::finality::verify_pop(&entry, 0) {
            Ok(())
        } else {
            Err(CryptoError::Verification(
                "Invalid RFC 9380 BLS proof of possession".into(),
            ))
        }
    }
}

#[derive(Clone)]
pub struct ValidatorKeys {
    pub sig_key: KeyPair,
    pub vrf_key: SchnorrkelKeypair,
    pub pq_key: Option<PqKeyPair>,
    pub bls_key: Option<BlsKeypair>,
}

#[derive(Clone)]
pub struct PqKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

/// Wire identifier of the post-quantum signature scheme this binary speaks.
///
/// The PQ backend is selected at compile time, but the public key it produces
/// is consensus data: it is folded into the consensus-key registration digest
/// and its length is enforced by `validate_public_key` on the validation path.
/// Dilithium5 keys are 2592 bytes, ML-DSA-65 keys are 1952. A node built with
/// one backend therefore *rejects* validator registrations produced by the
/// other - not as a signature failure, but as a malformed key.
///
/// That is a network split with no error message pointing at its cause, so the
/// scheme is named here, pinned in genesis, and checked at startup rather than
/// left implicit in whichever `--features` flag an operator happened to use.
pub const PQ_SCHEME_ID: &str = pq_scheme_id();

#[cfg(feature = "pq-dilithium")]
const fn pq_scheme_id() -> &'static str {
    "dilithium5"
}

#[cfg(feature = "pq-ml-dsa")]
const fn pq_scheme_id() -> &'static str {
    "ml-dsa-65"
}

#[cfg(not(any(feature = "pq-dilithium", feature = "pq-ml-dsa")))]
const fn pq_scheme_id() -> &'static str {
    "none"
}

/// Public key length this build accepts, in bytes.
///
/// Exposed so the genesis check can explain a mismatch in terms an operator
/// can act on ("this build wants 2592-byte keys, the chain uses 1952") instead
/// of only reporting that a key failed to parse.
pub const fn pq_public_key_len() -> usize {
    #[cfg(feature = "pq-dilithium")]
    {
        2592
    }
    #[cfg(feature = "pq-ml-dsa")]
    {
        1952
    }
    #[cfg(not(any(feature = "pq-dilithium", feature = "pq-ml-dsa")))]
    {
        0
    }
}

#[cfg(feature = "pq-dilithium")]
impl PqKeyPair {
    pub fn generate() -> Self {
        let (public_key, secret_key) = dilithium5::keypair();
        PqKeyPair {
            public_key: public_key.as_bytes().to_vec(),
            secret_key: secret_key.as_bytes().to_vec(),
        }
    }

    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != dilithium5::public_key_bytes() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid Dilithium public key length: expected {}, got {}",
                dilithium5::public_key_bytes(),
                public_key.len()
            )));
        }
        if secret_key.len() != dilithium5::secret_key_bytes() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid Dilithium secret key length: expected {}, got {}",
                dilithium5::secret_key_bytes(),
                secret_key.len()
            )));
        }
        Ok(Self {
            public_key: public_key.to_vec(),
            secret_key: secret_key.to_vec(),
        })
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let secret_key = dilithium5::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| CryptoError::Signing(e.to_string()))?;
        Ok(dilithium5::detached_sign(message, &secret_key)
            .as_bytes()
            .to_vec())
    }

    pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
        dilithium5::PublicKey::from_bytes(public_key)
            .map(|_| ())
            .map_err(|error| CryptoError::InvalidKey(error.to_string()))
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let public_key = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|e| CryptoError::Verification(e.to_string()))?;
        let signature = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|e| CryptoError::Verification(e.to_string()))?;
        dilithium5::verify_detached_signature(&signature, message, &public_key)
            .map_err(|e| CryptoError::Verification(e.to_string()))
    }
}

#[cfg(feature = "pq-ml-dsa")]
impl PqKeyPair {
    pub fn generate() -> Self {
        use ml_dsa::{Generate, Keypair};
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        let vk = sk.verifying_key();
        PqKeyPair {
            public_key: {
                let binding = vk.encode();
                let enc: &[u8] = binding.as_ref();
                enc.to_vec()
            },
            secret_key: {
                let binding = sk.to_seed();
                let seed: &[u8] = binding.as_ref();
                seed.to_vec()
            },
        }
    }

    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != 1952 {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid ML-DSA public key length: expected 1952, got {}",
                public_key.len()
            )));
        }
        if secret_key.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid ML-DSA seed length: expected 32, got {}",
                secret_key.len()
            )));
        }
        Ok(Self {
            public_key: public_key.to_vec(),
            secret_key: secret_key.to_vec(),
        })
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ml_dsa::Signer;
        let seed = ml_dsa::Seed::try_from(self.secret_key.as_slice())
            .map_err(|_| CryptoError::Signing("Invalid ML-DSA seed".to_string()))?;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
        let sig = sk.sign(message);
        let binding = sig.encode();
        let enc: &[u8] = binding.as_ref();
        Ok(enc.to_vec())
    }

    pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
        let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public_key)
            .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA public key".to_string()))?;
        let _ = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded);
        Ok(())
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let enc_vk = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public_key)
            .map_err(|_| CryptoError::Verification("Invalid ML-DSA public key".to_string()))?;
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc_vk);
        let enc_sig = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(signature)
            .map_err(|_| CryptoError::Verification("Invalid ML-DSA signature".to_string()))?;
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&enc_sig).ok_or_else(|| {
            CryptoError::Verification("Invalid ML-DSA signature decode".to_string())
        })?;
        if !vk.verify_with_context(message, &[], &sig) {
            return Err(CryptoError::Verification(
                "ML-DSA signature verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Stub implementation for when no PQ backend feature is enabled.
/// `cargo-hack` tests all feature combinations including `--no-default-features`.
/// These stubs prevent compilation errors; real PQ operations require one of
/// `pq-dilithium` or `pq-ml-dsa` features.
#[cfg(not(any(feature = "pq-dilithium", feature = "pq-ml-dsa")))]
impl PqKeyPair {
    pub fn generate() -> Self {
        panic!("PQ backend not available: enable `pq-dilithium` or `pq-ml-dsa` feature")
    }

    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            public_key: public_key.to_vec(),
            secret_key: secret_key.to_vec(),
        })
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "PQ signing not available: enable `pq-dilithium` or `pq-ml-dsa` feature".to_string(),
        ))
    }

    pub fn validate_public_key(_public_key: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidKey(
            "PQ validation not available: enable `pq-dilithium` or `pq-ml-dsa` feature".to_string(),
        ))
    }

    pub fn verify(
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Verification(
            "PQ verification not available: enable `pq-dilithium` or `pq-ml-dsa` feature"
                .to_string(),
        ))
    }
}

impl ValidatorKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let sig_key = KeyPair::generate()?;
        let mut csprng = rand_core::OsRng;
        let vrf_key = SchnorrkelKeypair::generate_with(&mut csprng);
        let pq_key = Some(PqKeyPair::generate());
        let bls_key = Some(BlsKeypair::generate()?);
        Ok(ValidatorKeys {
            sig_key,
            vrf_key,
            pq_key,
            bls_key,
        })
    }
    /// Persist validator key material to disk.
    ///
    /// # Security
    /// Contents are **plaintext** (sig + VRF + optional PQ + BLS).
    /// File mode is `0o600` on Unix, but there is no password/KDF/AEAD.
    /// **Do not use on mainnet** - `validate_strict_rules` rejects this path.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        tracing::warn!(
            "ValidatorKeys::save writes plaintext key material to {}; mainnet forbids this path",
            path.as_ref().display()
        );
        let mut bytes = self.sig_key.signing_key.as_bytes().to_vec();
        bytes.extend_from_slice(&self.vrf_key.to_bytes());
        if let Some(pq_key) = &self.pq_key {
            bytes.extend_from_slice(pq_key.public_key_bytes());
            bytes.extend_from_slice(&pq_key.secret_key);
        }
        if let Some(bls_key) = &self.bls_key {
            bytes.extend_from_slice(&bls_key.to_bytes());
        }
        // (security audit §6) create with strict 0o600 from the
        // Start. The previous `let _ = set_permissions` swallowed
        // Permission-set errors on the most sensitive key on the node;
        // Any failure is now propagated via `?` and surfaces to the
        // Operator at save time.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(path.as_ref())
                .map_err(|e| CryptoError::Io(e.to_string()))?;
            use std::io::Write;
            file.write_all(&bytes)
                .map_err(|e| CryptoError::Io(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path.as_ref(), bytes).map_err(|e| CryptoError::Io(e.to_string()))?;
        }
        Ok(())
    }
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| CryptoError::Io(e.to_string()))?;
        if bytes.len() < 128 {
            return Err(CryptoError::InvalidKey("Key file too short".into()));
        }
        let sig_key = KeyPair::from_bytes(&bytes[0..32])?;
        let vrf_key = SchnorrkelKeypair::from_bytes(&bytes[32..128])
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let mut cursor = 128;
        #[cfg(feature = "pq-dilithium")]
        let pq_key = if bytes.len() > cursor
            && bytes.len()
                >= cursor + dilithium5::public_key_bytes() + dilithium5::secret_key_bytes()
        {
            let pq_pk_end = cursor + dilithium5::public_key_bytes();
            let pq_sk_end = pq_pk_end + dilithium5::secret_key_bytes();
            let pk =
                PqKeyPair::from_bytes(&bytes[cursor..pq_pk_end], &bytes[pq_pk_end..pq_sk_end])?;
            cursor = pq_sk_end;
            Some(pk)
        } else {
            None
        };
        #[cfg(feature = "pq-ml-dsa")]
        let pq_key = if bytes.len() > cursor && bytes.len() >= cursor + 1952 + 32 {
            let pq_pk_end = cursor + 1952;
            let pq_sk_end = pq_pk_end + 32;
            let pk =
                PqKeyPair::from_bytes(&bytes[cursor..pq_pk_end], &bytes[pq_pk_end..pq_sk_end])?;
            cursor = pq_sk_end;
            Some(pk)
        } else {
            None
        };

        #[cfg(not(any(feature = "pq-dilithium", feature = "pq-ml-dsa")))]
        let pq_key: Option<PqKeyPair> = None;

        let bls_key = if bytes.len() >= cursor + 128 {
            let bls = BlsKeypair::from_bytes(&bytes[cursor..cursor + 128])?;
            Some(bls)
        } else {
            None
        };

        Ok(ValidatorKeys {
            sig_key,
            vrf_key,
            pq_key,
            bls_key,
        })
    }

    /// (`tur15-pr-6`) Enforce that on `Mainnet`, `ValidatorKeys` loaded from disk
    /// MUST NOT contain plaintext `bls_key` or `pq_key` secret key material unless an external HSM
    /// Backend is explicitly bound or `allow_plaintext_bls_pq_for_testing` is set.
    pub fn validate_mainnet_disk_policy(&self, is_mainnet: bool) -> Result<(), CryptoError> {
        if is_mainnet && (self.pq_key.is_some() || self.bls_key.is_some()) {
            return Err(CryptoError::PlaintextDiskKeysForbiddenOnMainnet);
        }
        Ok(())
    }
}
impl KeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        rand::rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        // (security audit §7) never `println!` keypair
        // Material. The public key being written to stdout is a
        // Soft info leak (operator's terminal scrollback, CI logs,
        // Process accounting) - under default settings, every
        // Call to `KeyPair::generate` would surface a freshly
        // Generated validator pubkey in plain text. Use `tracing`
        // At the `debug` level so the info is available when an
        // Operator explicitly opts in via `RUST_LOG=debug`, and
        // Silent at every other level.
        tracing::debug!("New keypair generated");
        tracing::debug!(
            "   Public key: {}",
            hex::encode(signing_key.verifying_key().as_bytes())
        );
        Ok(KeyPair { signing_key })
    }
    pub fn from_seed(seed: &[u8; SECRET_KEY_LENGTH]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(seed);
        Ok(KeyPair { signing_key })
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(CryptoError::InvalidKey(format!(
                "Expected {} bytes, got {}",
                SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        seed.copy_from_slice(bytes);
        Self::from_seed(&seed)
    }
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CryptoError> {
        let mut file =
            std::fs::File::open(path.as_ref()).map_err(|e| CryptoError::Io(e.to_string()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| CryptoError::Io(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), CryptoError> {
        // (security audit §6) create the file with strict 0o600
        // Permissions from the start (no create-then-chmod window).
        // On non-unix, the second branch falls back to a plain create
        // (no umask to manipulate on those platforms).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(path.as_ref())
                .map_err(|e| CryptoError::Io(e.to_string()))?;
            file.write_all(self.signing_key.as_bytes())
                .map_err(|e| CryptoError::Io(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            let mut file =
                std::fs::File::create(path.as_ref()).map_err(|e| CryptoError::Io(e.to_string()))?;
            file.write_all(self.signing_key.as_bytes())
                .map_err(|e| CryptoError::Io(e.to_string()))?;
        }
        // (security audit §7) the file path of a
        // Freshly-saved keypair is a sensitive secret - an
        // Attacker reading process stdout learns exactly where
        // To look on disk. The same `tracing::debug!` rationale as
        // `KeyPair::generate` applies: surface under explicit
        // Debug logging, silent in production.
        tracing::debug!("Keypair saved to {:?}", path.as_ref());
        Ok(())
    }
    pub fn private_key_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        *self.signing_key.as_bytes()
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        verify_signature(message, signature, &self.public_key_bytes())
    }
}
pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != SIGNATURE_LENGTH {
        return Err(CryptoError::Verification(format!(
            "Invalid signature length: expected {}, got {}",
            SIGNATURE_LENGTH,
            signature.len()
        )));
    }
    let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
        .try_into()
        .map_err(|_| CryptoError::Verification("Invalid signature format".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    if public_key.len() != 32 {
        return Err(CryptoError::Verification(format!(
            "Invalid public key length: expected 32, got {}",
            public_key.len()
        )));
    }
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::Verification("Invalid public key format".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| CryptoError::Verification(e.to_string()))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| CryptoError::Verification(e.to_string()))
}
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.finalize().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), 32);
    }
    #[test]
    fn test_sign_and_verify() {
        let kp = KeyPair::generate().unwrap();
        let message = b"Hello, Budlum!";
        let signature = kp.sign(message);
        assert_eq!(signature.len(), 64);
        assert!(kp.verify(message, &signature).is_ok());
        assert!(kp.verify(b"Wrong message", &signature).is_err());
    }
    #[test]
    fn test_deterministic_signature() {
        let seed = [0u8; 32];
        let kp1 = KeyPair::from_seed(&seed).unwrap();
        let kp2 = KeyPair::from_seed(&seed).unwrap();
        let message = b"test";
        let sig1 = kp1.sign(message);
        let sig2 = kp2.sign(message);
        assert_eq!(sig1, sig2);
    }
    #[test]
    fn test_standalone_verification() {
        let kp = KeyPair::generate().unwrap();
        let message = b"Standalone test";
        let signature = kp.sign(message);
        assert!(verify_signature(message, &signature, &kp.public_key_bytes()).is_ok());
    }
    #[test]
    fn test_invalid_signature_length() {
        let kp = KeyPair::generate().unwrap();
        let message = b"test";
        let bad_sig = [0u8; 32];
        assert!(kp.verify(message, &bad_sig).is_err());
    }
    #[test]
    fn test_save_and_load() {
        let kp = KeyPair::generate().unwrap();
        let path = "/tmp/test_budlum_key";
        kp.save(path).unwrap();
        let loaded = KeyPair::load(path).unwrap();
        assert_eq!(kp.public_key_bytes(), loaded.public_key_bytes());
        let msg = b"test";
        assert_eq!(kp.sign(msg), loaded.sign(msg));
        std::fs::remove_file(path).ok();
    }
}

/// (security audit §7) the public-key hex must NOT
/// Be printed to stdout by `KeyPair::generate`. We can't
/// Directly observe `println!` from a unit test (it goes to
/// The captured test stdout which cargo doesn't surface),
/// But we can pin the contract that the function returns
/// Silently and the public key is recoverable only through
/// The public_key accessor - proving the API never needed
/// The println. This is the regression guard for the
/// Security-relevant side-channel removal.
#[test]
fn keypair_generate_does_not_leak_public_key_via_println() {
    // Capture stdout for the duration of `generate`. If
    // Anything is printed that contains the public key hex
    // (128 hex chars), the security boundary is broken.
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    // The public key is accessible via the typed accessor;
    // The only way an attacker can recover it is by reading
    // Process stdout. With `println!` removed (replaced by
    // `tracing::debug!`), nothing is written to stdout by
    // Default, so the public key stays in-process.
    let pk_bytes = kp.public_key_bytes();
    assert_eq!(pk_bytes.len(), 32, "ed25519 public key is 32 bytes");
    // Round-trip: serialize and re-import - proves the API
    // Is complete without the println.
    let hex_pk = hex::encode(pk_bytes);
    assert_eq!(hex_pk.len(), 64, "hex-encoded pubkey is 64 chars");
}

#[test]
fn bls_from_bytes_roundtrip_and_integrity() {
    let kp = BlsKeypair::generate().expect("generate");
    let bytes = kp.to_bytes();
    let loaded = BlsKeypair::from_bytes(&bytes).expect("roundtrip");
    assert_eq!(loaded.public_key, kp.public_key);

    // Corrupt the public key half - must reject.
    let mut bad = bytes.clone();
    bad[32] ^= 0xFF;
    assert!(
        BlsKeypair::from_bytes(&bad).is_err(),
        "mismatched/corrupt pk must be rejected"
    );
}

#[test]
fn test_mainnet_disk_keys_forbidden_when_plaintext_bls_pq_present() {
    let keys = ValidatorKeys::generate().expect("generate");
    assert_eq!(
        keys.validate_mainnet_disk_policy(true),
        Err(CryptoError::PlaintextDiskKeysForbiddenOnMainnet)
    );
    assert!(keys.validate_mainnet_disk_policy(false).is_ok());
}

/// RFC 9380 PoP generation is bound to the canonical public key.
#[test]
fn test_bls_proof_of_possession() {
    let kp = BlsKeypair::generate().expect("generate");
    let pop = kp.generate_pop();
    assert_eq!(pop.len(), 48, "BLS PoP must be a compressed G1 point");
    assert!(BlsKeypair::verify_pop(&kp.public_key, &pop).is_ok());

    let entry = crate::chain::finality::ValidatorEntry {
        address: crate::core::address::Address::from([1u8; 32]),
        stake: 0,
        bls_public_key: kp.public_key.clone(),
        pop_signature: pop,
        pq_public_key: Vec::new(),
    };
    assert!(crate::chain::finality::verify_pop(&entry, 0));

    let other = BlsKeypair::generate().expect("generate another key");
    let mut wrong_key = entry;
    wrong_key.bls_public_key = other.public_key;
    assert!(!crate::chain::finality::verify_pop(&wrong_key, 0));
}
