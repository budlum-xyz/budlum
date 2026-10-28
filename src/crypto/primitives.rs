#[cfg(feature = "pq-ml-dsa")]
use super::ctx;
#[cfg(any(feature = "pq-ml-dsa", feature = "wallet-ml-dsa"))]
use super::{pq, scheme::SchemeId};
use bls12_381::{G2Affine, G2Projective, Scalar};
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;
/// Write secret key bytes so that a crash never leaves a short or empty key file.
///
/// The bytes go to a new sibling file made with `create_new` and mode `0o600`, are
/// flushed to disk, and then replace the target with an atomic rename. The mode of a
/// file that already existed is therefore never kept: the new file always has `0o600`.
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    let io_err = |e: std::io::Error| CryptoError::Io(e.to_string());
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| CryptoError::Io("key path has no file name".into()))?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options
        .open(&tmp_path)
        .map_err(io_err)
        .and_then(|mut file| {
            file.write_all(bytes).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
            std::fs::rename(&tmp_path, path).map_err(io_err)
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

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
            CryptoError::KeyGeneration(s) => write!(f, "Key generation error: {s}"),
            CryptoError::Signing(s) => write!(f, "Signing error: {s}"),
            CryptoError::Verification(s) => write!(f, "Verification error: {s}"),
            CryptoError::Io(s) => write!(f, "I/O error: {s}"),
            CryptoError::InvalidKey(s) => write!(f, "Invalid key: {s}"),
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

/// F11: zero the secret scalar when the pair is dropped.
impl Drop for BlsKeypair {
    fn drop(&mut self) {
        self.secret_key = Scalar::zero();
    }
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
        // Validate G2 encoding AND that pk matches sk. F10: the length is
        // exact - trailing garbage is not silently ignored - and the zero
        // scalar is refused (its public key is the identity point).
        if bytes.len() != 32 + 96 {
            return Err(CryptoError::InvalidKey(
                "Invalid BLS keypair bytes length".into(),
            ));
        }
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&bytes[0..32]);
        if sk_bytes == [0u8; 32] {
            return Err(CryptoError::InvalidKey(
                "Refusing a zero BLS secret key".into(),
            ));
        }
        let sk_opt = Scalar::from_bytes(&sk_bytes);
        // `Option::from` consumes the `CtOption` once; the previous form
        // branched on `is_none()` and then called `unwrap()`, which reads the
        // choice a second time and panics if the two ever disagree.
        let sk: Scalar = Option::from(sk_opt)
            .ok_or_else(|| CryptoError::InvalidKey("Invalid BLS secret key".into()))?;

        let mut pk_bytes = [0u8; 96];
        pk_bytes.copy_from_slice(&bytes[32..128]);
        let pk_affine = G2Affine::from_compressed(&pk_bytes);
        let _pk_checked: G2Affine = Option::from(pk_affine)
            .ok_or_else(|| CryptoError::InvalidKey("Invalid BLS public key encoding".into()))?;

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

    /// Generate the canonical proof of possession for this public key,
    /// bound to the chain id and account address it will be registered
    /// under (R11: a PoP over only the key replays across chains).
    pub fn generate_pop(&self, chain_id: u64, address: &crate::core::address::Address) -> Vec<u8> {
        let msg = crate::chain::finality::pop_signing_message(chain_id, address, &self.public_key);
        crate::chain::finality::sign_bls_pop(&self.secret_key, &msg)
    }

    /// Verify the canonical PoP without a validator registration wrapper.
    /// The PoP must be bound to the given chain id and address (R11): a
    /// PoP produced for another chain or account is rejected.
    pub fn verify_pop(
        public_key: &[u8],
        pop: &[u8],
        chain_id: u64,
        address: &crate::core::address::Address,
    ) -> Result<(), CryptoError> {
        let entry = crate::chain::finality::ValidatorEntry {
            address: *address,
            stake: 0,
            bls_public_key: public_key.to_vec(),
            pop_signature: pop.to_vec(),
            pq_public_key: Vec::new(),
        };
        if crate::chain::finality::verify_pop(&entry, chain_id) {
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

/// The validator ML-DSA-65 key pair (suite 0x0002 post-quantum half).
///
/// The secret is the 32-byte FIPS 204 seed and it is wiped on drop.
#[derive(Clone)]
pub struct PqKeyPair {
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

// The secret half is `Zeroizing`, so dropping the key pair wipes the seed.
impl zeroize::ZeroizeOnDrop for PqKeyPair {}

/// Wire identifier of the post-quantum signature scheme this binary speaks.
///
/// The public key it produces is consensus data: it is folded into the
/// consensus-key registration digest and its length is enforced by
/// `validate_public_key` on the validation path. The name is derived from the
/// scheme registry, not typed here, and genesis pins
/// it and checks it at startup so a mismatch is an explained refusal rather
/// than a network split with no error message pointing at its cause.
pub const PQ_SCHEME_ID: &str = super::scheme::PQ_SCHEME_NAME;

/// Public key length this build accepts, in bytes, read from the registry.
///
/// Exposed so the genesis check can explain a mismatch in terms an operator
/// can act on ("this build wants 1952-byte keys, the chain uses 2592") instead
/// of only reporting that a key failed to parse.
pub const fn pq_public_key_len() -> usize {
    match super::scheme::SchemeId::ML_DSA_65.info() {
        Some(info) => match info.public_key_len {
            Some(len) => len,
            None => 0,
        },
        None => 0,
    }
}

#[cfg(feature = "pq-ml-dsa")]
impl PqKeyPair {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; pq::ML_DSA_SEED_LEN]);
        rand::rng().fill_bytes(seed.as_mut_slice());
        // A fixed-length seed and a listed scheme: the derivation cannot fail.
        let public_key = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).unwrap_or_default();
        PqKeyPair {
            public_key,
            secret_key: Zeroizing::new(seed.to_vec()),
        }
    }

    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != pq_public_key_len() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid ML-DSA public key length: expected {}, got {}",
                pq_public_key_len(),
                public_key.len()
            )));
        }
        if secret_key.len() != pq::ML_DSA_SEED_LEN {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid ML-DSA seed length: expected {}, got {}",
                pq::ML_DSA_SEED_LEN,
                secret_key.len()
            )));
        }
        let kp = Self {
            public_key: public_key.to_vec(),
            secret_key: Zeroizing::new(secret_key.to_vec()),
        };
        // F10: the halves must pair. A probe signature under the key file
        // context must verify against the announced public key.
        const PAIRING_PROBE: &[u8] = b"BUDLUM_KEYFILE_PAIRING_PROBE_V1";
        let probe = kp
            .sign(ctx::KEY_BINDING_V1, PAIRING_PROBE)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Self::verify(public_key, ctx::KEY_BINDING_V1, PAIRING_PROBE, &probe).map_err(|_| {
            CryptoError::InvalidKey("PQ public and secret halves do not match".into())
        })?;
        Ok(kp)
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `message` under the FIPS 204 context `ctx`.
    pub fn sign(&self, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let seed: &[u8; pq::ML_DSA_SEED_LEN] = self
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Signing("Invalid ML-DSA seed".to_string()))?;
        // FIPS 204 3.6.1 hedged variant: a fresh `rnd` per signature keeps
        // repeated signatures of one message from repeating intermediate
        // values (fault-injection and side-channel defence). Verifiers
        // accept hedged and deterministic signatures alike, so the wire and
        // every read path stay unchanged.
        let mut rnd = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(rnd.as_mut_slice());
        pq::ml_dsa_sign(SchemeId::ML_DSA_65, seed, message, ctx, &rnd)
            .map_err(|e| CryptoError::Signing(e.to_string()))
    }

    pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
        pq::validate_public_key(SchemeId::ML_DSA_65, public_key)
            .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA public key".to_string()))
    }

    /// Verify through the dual-verifier facade under the
    /// statuses of a fresh genesis. A chain reads its own registry through
    /// [`Self::verify_in`].
    pub fn verify(
        public_key: &[u8],
        ctx: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        Self::verify_in(
            &super::scheme::SchemeStatusRegistry::genesis(),
            public_key,
            ctx,
            message,
            signature,
        )
    }

    /// Verify through the dual-verifier facade under the scheme statuses of a
    /// chain: a family the registry deprecated past use or disabled
    /// stops verifying here in the same block on every node.
    pub fn verify_in(
        registry: &super::scheme::SchemeStatusRegistry,
        public_key: &[u8],
        ctx: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        pq::verify_in(
            registry,
            SchemeId::ML_DSA_65,
            public_key,
            message,
            ctx,
            signature,
        )
        .map_err(|e| CryptoError::Verification(format!("ML-DSA-65: {e}")))
    }
}

/// Stub implementation for when the `pq-ml-dsa` feature is off.
/// `cargo-hack` tests all feature combinations including `--no-default-features`.
/// These stubs prevent compilation errors; real validator PQ operations
/// require the `pq-ml-dsa` feature.
#[cfg(not(feature = "pq-ml-dsa"))]
impl PqKeyPair {
    pub fn generate() -> Self {
        panic!("PQ backend not available: enable the `pq-ml-dsa` feature")
    }

    pub fn from_bytes(_public_key: &[u8], _secret_key: &[u8]) -> Result<Self, CryptoError> {
        // Fail closed, like every other method on this stub. Returning `Ok`
        // here used to hand back a `PqKeyPair` whose bytes had never been
        // checked against any scheme, so a caller compiled without a PQ
        // backend could hold what looks like a validated PQ key and only
        // discover otherwise when it tried to sign or verify.
        Err(CryptoError::InvalidKey(
            "PQ key loading not available: enable the `pq-ml-dsa` feature".to_string(),
        ))
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn sign(&self, _ctx: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Signing(
            "PQ signing not available: enable the `pq-ml-dsa` feature".to_string(),
        ))
    }

    pub fn validate_public_key(_public_key: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidKey(
            "PQ validation not available: enable the `pq-ml-dsa` feature".to_string(),
        ))
    }

    pub fn verify(
        _public_key: &[u8],
        _ctx: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Verification(
            "PQ verification not available: enable the `pq-ml-dsa` feature".to_string(),
        ))
    }

    /// The registry-aware verifier the consensus paths call. Present here for
    /// the same reason the others are: `cargo-hack` builds every feature
    /// combination, and a chain path that compiles with the feature on must
    /// still compile - and fail closed - with it off.
    pub fn verify_in(
        _registry: &super::scheme::SchemeStatusRegistry,
        _public_key: &[u8],
        _ctx: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Verification(
            "PQ verification not available: enable the `pq-ml-dsa` feature".to_string(),
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
    /// The validator's account address, derived from its signing key.
    #[must_use]
    pub fn address(&self) -> crate::core::address::Address {
        crate::core::address::Address::from(self.sig_key.public_key_bytes())
    }

    /// The validator suite (`0x0002`) composite key of this key set: its
    /// ML-DSA-65 seed and its Ed25519 signing seed. It signs V7
    /// validator transactions, whose sender stays the Ed25519 address.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] when the key set holds no PQ key.
    pub fn composite_keypair(
        &self,
    ) -> Result<crate::crypto::composite::CompositeKeypair, CryptoError> {
        let pq = self
            .pq_key
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("the key set holds no PQ key".into()))?;
        crate::crypto::composite::CompositeKeypair::from_seeds(
            super::scheme::SuiteId::VALIDATOR,
            &pq.secret_key,
            self.sig_key.signing_key.as_bytes(),
        )
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    /// The public consensus-key registration of these keys on `chain_id`:
    /// the VRF key, the BLS key with its proof of possession bound to the
    /// chain and the validator's address, and the PQ key. It is what an
    /// operator hands the genesis ceremony and what `RegisterConsensusKeys`
    /// carries; it holds no secret.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] when the key set has no BLS or no PQ key.
    pub fn consensus_key_registration(
        &self,
        chain_id: u64,
    ) -> Result<crate::core::transaction::ConsensusKeyRegistration, CryptoError> {
        let bls = self
            .bls_key
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("the key set holds no BLS key".into()))?;
        let pq = self
            .pq_key
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidKey("the key set holds no PQ key".into()))?;
        let address = self.address();
        Ok(crate::core::transaction::ConsensusKeyRegistration {
            scheme_id: crate::chain::finality::BLS_SCHEME_RFC9380_V1.to_string(),
            vrf_public_key: self.vrf_key.public.to_bytes().to_vec(),
            bls_public_key: bls.public_key.clone(),
            pop_signature: bls.generate_pop(chain_id, &address),
            pq_public_key: pq.public_key_bytes().to_vec(),
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
        write_key_file(path.as_ref(), &bytes)?;
        // F11: the plaintext key buffer does not outlive the write.
        bytes.fill(0);
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

        // `cursor` is only advanced by the PQ branch below; with the PQ
        // feature off nothing writes to it, so the `mut` is conditional too.
        #[cfg(feature = "pq-ml-dsa")]
        let mut cursor = 128;
        #[cfg(not(feature = "pq-ml-dsa"))]
        let cursor = 128;
        #[cfg(feature = "pq-ml-dsa")]
        let pq_key = {
            let pq_pk_len = pq_public_key_len();
            let pq_sk_len = pq::ML_DSA_SEED_LEN;
            if bytes.len() > cursor && bytes.len() >= cursor + pq_pk_len + pq_sk_len {
                let pq_pk_end = cursor + pq_pk_len;
                let pq_sk_end = pq_pk_end + pq_sk_len;
                let pk =
                    PqKeyPair::from_bytes(&bytes[cursor..pq_pk_end], &bytes[pq_pk_end..pq_sk_end])?;
                cursor = pq_sk_end;
                Some(pk)
            } else {
                None
            }
        };

        #[cfg(not(feature = "pq-ml-dsa"))]
        let pq_key: Option<PqKeyPair> = None;

        // F10: the tail after the optional PQ block is either absent or
        // exactly one BLS keypair. A 1..127-byte tail used to be dropped
        // silently, losing the BLS key; extra bytes were ignored.
        let bls_key = match bytes.len().saturating_sub(cursor) {
            0 => None,
            128 => Some(BlsKeypair::from_bytes(&bytes[cursor..cursor + 128])?),
            _ => {
                return Err(CryptoError::InvalidKey(
                    "Key file has a partial or trailing BLS tail".into(),
                ))
            }
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
    ///
    /// # Errors
    ///
    /// [`CryptoError::PlaintextDiskKeysForbiddenOnMainnet`] when mainnet keys
    /// carry BLS or post-quantum secrets in the clear.
    /// F18: the engine enforces mainnet policy through
    /// [`crate::crypto::mainnet_policy::check_mainnet_validator_key_policy`];
    /// this hook exists for the test suite that proves the rule.
    #[cfg(test)]
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
        write_key_file(path.as_ref(), self.signing_key.as_bytes())?;
        // (security audit §7) the file path of a
        // Freshly-saved keypair is a sensitive secret, an
        // Attacker reading process stdout learns exactly where
        // To look on disk. The same `tracing::debug!` rationale as
        // `KeyPair::generate` applies: surface under explicit
        // Debug logging, silent in production.
        tracing::debug!("Keypair saved to {:?}", path.as_ref());
        Ok(())
    }
    /// Test-only: production code must not read the raw ed25519 seed
    /// (F18 keeps the surface minimal; tests use it for round-trips).
    #[cfg(test)]
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
    // `verify_strict` (ed25519-dalek) rejects weak public keys (low-order
    // points). A weak key can produce a signature valid for almost every
    // message; `verify()` accepts it, `verify_strict()` denies it. Every
    // consensus-relevant signature (transaction, block, snapshot, evidence)
    // funnels through this one function, so the strict check applies to all
    // of them (hardening research #44).
    verifying_key
        .verify_strict(message, &sig)
        .map_err(|e| CryptoError::Verification(e.to_string()))
}
/// FIPS 204 ML-DSA-87 public key length (wallet/user signatures).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// FIPS 204 ML-DSA-87 signature length (wallet/user signatures).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

/// Dilithium5 signature length in bytes (CRYSTALS-Dilithium round-3 set,
/// the validator PQ backend behind the `pq-dilithium` feature).
pub const PQ_DILITHIUM5_SIGNATURE_LEN: usize = 4595;
/// FIPS 204 ML-DSA-65 signature length in bytes (validator PQ backend behind
/// the `pq-ml-dsa` feature).
pub const PQ_ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// The PQ signature scheme a signature length identifies.
///
/// The three accepted signature lengths (Dilithium5, ML-DSA-65, ML-DSA-87)
/// are pairwise distinct, so a single length classifies a PQ signature
/// unambiguously. This is the bounded logic around signature verification
/// that the Kani mirror in `kani/src/lib.rs` model-checks
/// (`pq_signature_classification_round_trips`,
/// `pq_signature_acceptability_agrees_with_classification`); the raw
/// signature arithmetic stays behind the PQ backend crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub enum PqSignatureClass {
    Dilithium5,
    MlDsa65,
    MlDsa87,
    Unknown,
}

/// Classify a PQ signature length. Total: every length maps to a variant,
/// never a panic. When a scheme is named, the length is exactly that scheme's
/// constant (proved by the Kani round-trip harness).
#[must_use]
/// exposed for: the crypto/key registry's public labels and shapes - production readers land with the anchor-ceremony and key-config doors (wiring pending).
pub fn classify_pq_signature_len(len: usize) -> PqSignatureClass {
    if len == PQ_DILITHIUM5_SIGNATURE_LEN {
        PqSignatureClass::Dilithium5
    } else if len == PQ_ML_DSA_65_SIGNATURE_LEN {
        PqSignatureClass::MlDsa65
    } else if len == ML_DSA_87_SIGNATURE_LEN {
        PqSignatureClass::MlDsa87
    } else {
        PqSignatureClass::Unknown
    }
}

/// Whether a signature length is acceptable for an expected scheme.
///
/// `Unknown` accepts nothing. The Kani harness
/// `pq_signature_acceptability_agrees_with_classification` proves this never
/// disagrees with [`classify_pq_signature_len`].
#[must_use]
#[cfg(test)]
pub fn pq_signature_len_acceptable(len: usize, expected: PqSignatureClass) -> bool {
    match expected {
        PqSignatureClass::Dilithium5 => len == PQ_DILITHIUM5_SIGNATURE_LEN,
        PqSignatureClass::MlDsa65 => len == PQ_ML_DSA_65_SIGNATURE_LEN,
        PqSignatureClass::MlDsa87 => len == ML_DSA_87_SIGNATURE_LEN,
        PqSignatureClass::Unknown => false,
    }
}

/// V5 user keypair backed by FIPS 204 ML-DSA-87.
///
/// This type is for user-visible transaction signing. It is intentionally
/// separate from validator [`KeyPair`]: validators use ML-DSA-65, while user
/// wallets are pinned to ML-DSA-87 (NIST Category 5).
#[cfg(feature = "wallet-ml-dsa")]
#[derive(Clone)]
pub struct WalletKeyPair {
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa87>,
}

// The drop below replaces the key, and the inner `ml_dsa::SigningKey` wipes
// itself on drop (the `zeroize` feature of `ml-dsa`).
#[cfg(feature = "wallet-ml-dsa")]
impl zeroize::ZeroizeOnDrop for WalletKeyPair {}

/// F11: overwrite the wallet signing key when the pair is dropped.
#[cfg(feature = "wallet-ml-dsa")]
impl Drop for WalletKeyPair {
    fn drop(&mut self) {
        self.signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&[0u8; 32]).into());
    }
}

#[cfg(feature = "wallet-ml-dsa")]
impl WalletKeyPair {
    pub fn generate() -> Self {
        use ml_dsa::signature::Keypair;
        // FIPS 204 uses 32 bytes of seed xi as input to KeyGen_internal. The
        // seed buffer is wiped on drop.
        let mut seed = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut_slice());
        let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed((&*seed).into());
        let _ = signing_key.verifying_key();
        Self { signing_key }
    }

    /// Rebuild the keypair from its 32-byte FIPS 204 seed (`xi`), the form a
    /// key file holds. The same seed always yields the same key, so a
    /// service that signs with a long-lived address (the testnet faucet)
    /// reloads it from disk instead of keeping key material in memory
    /// between runs.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(seed.into());
        Self { signing_key }
    }

    pub fn public_key_bytes(&self) -> [u8; ML_DSA_87_PUBLIC_KEY_LEN] {
        use ml_dsa::signature::Keypair;
        let vk = self.signing_key.verifying_key();
        let enc = vk.encode();
        let mut out = [0u8; ML_DSA_87_PUBLIC_KEY_LEN];
        out.copy_from_slice(enc.as_ref());
        out
    }

    /// # Panics
    /// Only if the derived address is invalid, which cannot happen: the
    /// public key comes from a generated ML-DSA-87 keypair, and address
    /// derivation only rejects malformed keys. The panic is allowed here
    /// deliberately rather than by the workspace default: a silent
    /// zero-address fallback would let a malformed key spend as
    /// `[0u8; 32]`.
    #[allow(clippy::expect_used)]
    pub fn address(&self) -> crate::core::address::Address {
        wallet_address_from_ml_dsa_87_public_key(&self.public_key_bytes())
            .expect("Valid ML-DSA-87 public key must yield a valid address")
    }

    /// Sign `message` under the FIPS 204 context `ctx`.
    ///
    /// Hedged per FIPS 204 3.6.1: fresh randomness per signature keeps repeated
    /// signatures of one message from repeating intermediate values
    /// (fault-injection and side-channel defence). A dead OS rng must not
    /// strand a transaction mid-flight, so the deterministic variant (also
    /// FIPS 204 approved) takes over, and losing the hedge is an incident, not
    /// a quiet detail: it is logged at error level (P02-F20).
    ///
    /// The one other failure is an unusable context (empty or longer than 255
    /// bytes), a programming error at the call site since every context is a
    /// constant from `crypto::ctx`. It is never papered over with a
    /// context-free signature: the result is an all-zero array, which no
    /// verifier accepts, and the error is logged.
    pub fn sign(&self, ctx: &[u8], message: &[u8]) -> [u8; ML_DSA_87_SIGNATURE_LEN] {
        let mut rnd = Zeroizing::new([0u8; 32]);
        if rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, rnd.as_mut_slice()).is_err() {
            tracing::error!(
                "Wallet ML-DSA randomized signing failed (OS rng unavailable); fell back to deterministic signing"
            );
            rnd.fill(0);
        }
        let seed_slice: &[u8] = self.signing_key.as_seed().as_ref();
        let signed = <&[u8; pq::ML_DSA_SEED_LEN]>::try_from(seed_slice)
            .map_err(|_| pq::PqError::Signing)
            .and_then(|seed| pq::ml_dsa_sign(SchemeId::ML_DSA_87, seed, message, ctx, &rnd));
        let mut out = [0u8; ML_DSA_87_SIGNATURE_LEN];
        match signed {
            Ok(sig) if sig.len() == out.len() => out.copy_from_slice(&sig),
            Ok(_) => tracing::error!("Wallet ML-DSA-87 signature has an unexpected length"),
            Err(e) => tracing::error!("Wallet ML-DSA-87 signing refused: {e}"),
        }
        out
    }

    /// Reads the statuses of a fresh genesis. A chain reads its own registry
    /// through [`Self::verify_in`].
    pub fn verify(
        public_key: &[u8],
        ctx: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_ml_dsa_87_signature(ctx, message, signature, public_key)
    }

    /// Verify under the scheme statuses of a chain.
    pub fn verify_in(
        registry: &super::scheme::SchemeStatusRegistry,
        public_key: &[u8],
        ctx: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_ml_dsa_87_signature_in(registry, ctx, message, signature, public_key)
    }
}

#[cfg(feature = "wallet-ml-dsa")]
/// Compute the 32-byte user address from an ML-DSA-87 public key.
///
/// This must match `budlum_wallet_core::Wallet::address_from_public_key`:
/// `SHA3-256("BUDLUM_ADDRESS_V2" || public_key)`.
pub fn wallet_address_from_ml_dsa_87_public_key(
    public_key: &[u8],
) -> Result<crate::core::address::Address, CryptoError> {
    if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
        return Err(CryptoError::Verification(format!(
            "invalid ML-DSA-87 public key length: expected {ML_DSA_87_PUBLIC_KEY_LEN}, got {}",
            public_key.len()
        )));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b"BUDLUM_ADDRESS_V2");
    hasher.update(public_key);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(crate::core::address::Address::from(digest))
}

#[cfg(feature = "wallet-ml-dsa")]
/// Verify an ML-DSA-87 signature under the FIPS 204 context `ctx`.
///
/// The signature must be exactly 4627 bytes and the public key exactly 2592
/// bytes. The check runs through the dual-verifier facade (`crypto::pq`,
///): RustCrypto `ml-dsa` and `libcrux-ml-dsa` must both accept. This path
/// is intentionally separate from validator PQ signatures (ML-DSA-65): user
/// wallets are pinned to ML-DSA-87 for Category 5 security.
///
/// This form reads the statuses of a fresh genesis: every path that decides on
/// behalf of a chain calls [`verify_ml_dsa_87_signature_in`] with the
/// chain-state registry.
pub fn verify_ml_dsa_87_signature(
    ctx: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    verify_ml_dsa_87_signature_in(
        &super::scheme::SchemeStatusRegistry::genesis(),
        ctx,
        message,
        signature,
        public_key,
    )
}

#[cfg(feature = "wallet-ml-dsa")]
/// [`verify_ml_dsa_87_signature`] under the scheme statuses of a chain
///. A family the registry marks
/// `Disabled` or not yet `Active` is refused before any key is decoded.
pub fn verify_ml_dsa_87_signature_in(
    registry: &super::scheme::SchemeStatusRegistry,
    ctx: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    pq::verify_in(
        registry,
        SchemeId::ML_DSA_87,
        public_key,
        message,
        ctx,
        signature,
    )
    .map_err(|e| CryptoError::Verification(format!("ML-DSA-87: {e}")))
}

pub fn hash_message(message: &[u8]) -> [u8; 32] {
    // A distinct hasher name keeps this single-field digest visibly separate
    // from the address derivation above: the preimages share no chain.
    let mut digest = Sha3_256::new();
    digest.update(message);
    digest.finalize().into()
}

#[cfg(not(feature = "wallet-ml-dsa"))]
pub fn wallet_address_from_ml_dsa_87_public_key(
    _public_key: &[u8],
) -> Result<crate::core::address::Address, CryptoError> {
    Err(CryptoError::Verification(
        "wallet ML-DSA-87 support is not compiled in (enable wallet-ml-dsa)".into(),
    ))
}

#[cfg(not(feature = "wallet-ml-dsa"))]
pub fn verify_ml_dsa_87_signature_in(
    _registry: &super::scheme::SchemeStatusRegistry,
    _ctx: &[u8],
    _message: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<(), CryptoError> {
    Err(CryptoError::Verification(
        "wallet ML-DSA-87 support is not compiled in (enable wallet-ml-dsa)".into(),
    ))
}

#[cfg(not(feature = "wallet-ml-dsa"))]
pub fn verify_ml_dsa_87_signature(
    _ctx: &[u8],
    _message: &[u8],
    _signature: &[u8],
    _public_key: &[u8],
) -> Result<(), CryptoError> {
    Err(CryptoError::Verification(
        "wallet ML-DSA-87 support is not compiled in (enable wallet-ml-dsa)".into(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    // ---- BLG-0046 (F10): key-file parsing is exact. ----

    #[test]
    fn bls_from_bytes_refuses_a_zero_scalar() {
        let zeros = vec![0u8; 128];
        assert!(BlsKeypair::from_bytes(&zeros).is_err());
    }

    #[test]
    fn bls_from_bytes_demands_exact_length() {
        let good = BlsKeypair::generate().unwrap().to_bytes();
        assert_eq!(good.len(), 128);
        assert!(BlsKeypair::from_bytes(&good).is_ok());
        let mut long = good;
        long.push(0);
        assert!(BlsKeypair::from_bytes(&long).is_err());
        let short = vec![0u8; 127];
        assert!(BlsKeypair::from_bytes(&short).is_err());
    }

    #[test]
    fn validator_key_file_partial_bls_tail_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vk.bin");
        let keys = ValidatorKeys::generate().unwrap();
        keys.save(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(0x7f);
        std::fs::write(&path, &bytes).unwrap();
        assert!(ValidatorKeys::load(&path).is_err());
    }

    #[cfg(feature = "pq-ml-dsa")]
    #[test]
    fn pq_from_bytes_refuses_mismatched_halves() {
        let a = PqKeyPair::generate();
        let b = PqKeyPair::generate();
        assert!(PqKeyPair::from_bytes(a.public_key_bytes(), &b.secret_key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn save_over_a_wide_mode_file_resets_mode_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kp.bin");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let kp = KeyPair::generate().unwrap();
        kp.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            KeyPair::load(&path).unwrap().private_key_bytes(),
            kp.private_key_bytes()
        );
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file may remain");
    }

    #[test]
    fn a_stale_temp_file_does_not_block_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kp.bin");
        std::fs::write(dir.path().join("kp.bin.tmp"), b"stale").unwrap();
        let kp = KeyPair::generate().unwrap();
        kp.save(&path).unwrap();
        assert_eq!(
            KeyPair::load(&path).unwrap().private_key_bytes(),
            kp.private_key_bytes()
        );
    }
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
        // BLG-0053 (F17): a fixed /tmp path is shared between parallel test
        // processes; every run gets its own tempdir now.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_budlum_key");
        let kp = KeyPair::generate().unwrap();
        kp.save(&path).unwrap();
        let loaded = KeyPair::load(&path).unwrap();
        assert_eq!(kp.public_key_bytes(), loaded.public_key_bytes());
        let msg = b"test";
        assert_eq!(kp.sign(msg), loaded.sign(msg));
    }
}

/// Does the captured stdout contain a run of 64 hex characters?
#[cfg(test)]
fn stdout_has_64_hex_run(stdout: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stdout);
    let bytes = text.as_bytes();
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b.to_ascii_lowercase());
    let mut run = 0usize;
    for &b in bytes {
        if is_hex(b) {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// (security audit §7) the public-key hex must NOT be printed to stdout by
/// `KeyPair::generate`.
///
/// BLG-0053 (F17): the old test claimed to capture stdout but never did. The
/// check now runs `generate` inside a child process whose raw stdout is
/// fully captured, so any printed 64-hex public key is observable. A canary
/// test proves the detector itself works (red-green).
#[test]
#[cfg_attr(
    miri,
    ignore = "re-executes the test binary (process spawn) to capture stdout; Miri cannot spawn processes"
)]
fn keypair_generate_does_not_leak_public_key_via_println() {
    match std::env::var("BUDLUM_STDOUT_PROBE").as_deref() {
        Ok("child") => {
            let _kp = KeyPair::generate().expect("KeyPair::generate must succeed");
        }
        Ok("canary") => {
            let canary = std::env::var("BUDLUM_STDOUT_CANARY").expect("canary hex");
            println!("{canary}");
        }
        _ => {
            // Test-only re-exec of this test binary to capture its stdout; no
            // security decision depends on the path. The suppression carries
            // the rule id alone: a trailing " - reason" after the id is not
            // part of the recognised form in every semgrep version, and the
            // alert this line exists to silence came back on the PR when it
            // had one.
            // nosemgrep: rust.lang.security.current-exe.current-exe
            let exe = std::env::current_exe().expect("test binary path");
            // `--exact` matches the full test path, which includes the module
            // (without the crate name). A bare function name matches nothing,
            // and a probe that runs nothing prints nothing - the red-green
            // canary below is what notices that.
            let test_path = format!(
                "{}::keypair_generate_does_not_leak_public_key_via_println",
                module_path!().split_once("::").map_or("", |(_, rest)| rest)
            );
            let run_probe = |mode: &str| {
                std::process::Command::new(&exe)
                    .args([test_path.as_str(), "--exact", "--nocapture"])
                    .env("BUDLUM_STDOUT_PROBE", mode)
                    .output()
                    .expect("spawn probe")
            };
            let out = run_probe("child");
            assert!(
                !stdout_has_64_hex_run(&out.stdout),
                "KeyPair::generate printed a public key to stdout"
            );
            // Canary: the same detector must see hex that IS printed.
            let canary = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
            let out = std::process::Command::new(&exe)
                .args([test_path.as_str(), "--exact", "--nocapture"])
                .env("BUDLUM_STDOUT_PROBE", "canary")
                .env("BUDLUM_STDOUT_CANARY", canary)
                .output()
                .expect("spawn canary");
            assert!(
                stdout_has_64_hex_run(&out.stdout),
                "the stdout detector must see a printed public key (canary)"
            );
        }
    }
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

/// RFC 9380 PoP generation is bound to the canonical public key, the chain
/// id and the account address it is registered under (R11).
#[test]
fn test_bls_proof_of_possession() {
    use crate::core::address::Address;
    use crate::core::transaction::DEFAULT_CHAIN_ID;

    let kp = BlsKeypair::generate().expect("generate");
    let addr = Address::from([1u8; 32]);
    let pop = kp.generate_pop(DEFAULT_CHAIN_ID, &addr);
    assert_eq!(pop.len(), 48, "BLS PoP must be a compressed G1 point");
    assert!(BlsKeypair::verify_pop(&kp.public_key, &pop, DEFAULT_CHAIN_ID, &addr).is_ok());

    let entry = crate::chain::finality::ValidatorEntry {
        address: addr,
        stake: 0,
        bls_public_key: kp.public_key.clone(),
        pop_signature: pop,
        pq_public_key: Vec::new(),
    };
    assert!(crate::chain::finality::verify_pop(&entry, DEFAULT_CHAIN_ID));

    // R11: the same key must not satisfy a PoP for another chain or account.
    assert!(!crate::chain::finality::verify_pop(
        &entry,
        DEFAULT_CHAIN_ID + 1
    ));
    let mut other_account = entry.clone();
    other_account.address = Address::from([2u8; 32]);
    assert!(!crate::chain::finality::verify_pop(
        &other_account,
        DEFAULT_CHAIN_ID
    ));

    let other = BlsKeypair::generate().expect("generate another key");
    let mut wrong_key = entry;
    wrong_key.bls_public_key = other.public_key.clone();
    assert!(!crate::chain::finality::verify_pop(
        &wrong_key,
        DEFAULT_CHAIN_ID
    ));
}

/// The PQ length classification stays in step with the Kani mirror.
///
/// `kani/src/lib.rs` model-checks the classifier on the whole `usize` domain
/// (`pq_signature_classification_round_trips` and the acceptability
/// agreement). This test holds the constants this crate exports and the Kani
/// mirror's literal copy of them together, exactly like
/// `bond_arithmetic_matches_the_kani_mirror` holds `penalty_for` in step.
#[test]
fn pq_signature_classification_matches_the_kani_mirror() {
    use crate::crypto::primitives::{
        classify_pq_signature_len, pq_signature_len_acceptable, PqSignatureClass,
        ML_DSA_87_SIGNATURE_LEN, PQ_DILITHIUM5_SIGNATURE_LEN, PQ_ML_DSA_65_SIGNATURE_LEN,
    };

    // The Kani mirror constants, verbatim.
    const KANI_PQ_SIG_LEN_DILITHIUM5: usize = 4595;
    const KANI_PQ_SIG_LEN_ML_DSA_65: usize = 3309;
    const KANI_PQ_SIG_LEN_ML_DSA_87: usize = 4627;

    assert_eq!(PQ_DILITHIUM5_SIGNATURE_LEN, KANI_PQ_SIG_LEN_DILITHIUM5);
    assert_eq!(PQ_ML_DSA_65_SIGNATURE_LEN, KANI_PQ_SIG_LEN_ML_DSA_65);
    assert_eq!(ML_DSA_87_SIGNATURE_LEN, KANI_PQ_SIG_LEN_ML_DSA_87);

    // The Kani mirror classifier, verbatim.
    fn kani_classify(len: usize) -> PqSignatureClass {
        if len == KANI_PQ_SIG_LEN_DILITHIUM5 {
            PqSignatureClass::Dilithium5
        } else if len == KANI_PQ_SIG_LEN_ML_DSA_65 {
            PqSignatureClass::MlDsa65
        } else if len == KANI_PQ_SIG_LEN_ML_DSA_87 {
            PqSignatureClass::MlDsa87
        } else {
            PqSignatureClass::Unknown
        }
    }

    // Sweep a wide length range so the two classifiers cannot drift apart on
    // the lengths that matter (the Kani proof covers the rest symbolically).
    for len in 0..=5000usize {
        assert_eq!(
            classify_pq_signature_len(len),
            kani_classify(len),
            "classifier disagreement at length {len}"
        );
    }

    // The acceptance check agrees with the classifier at every length.
    for len in 0..=5000usize {
        for class in [
            PqSignatureClass::Dilithium5,
            PqSignatureClass::MlDsa65,
            PqSignatureClass::MlDsa87,
            PqSignatureClass::Unknown,
        ] {
            // `Unknown` accepts nothing, so acceptability implies the
            // classifier names the same (known) scheme; the reverse holds for
            // known schemes. This is exactly the one-way implication the Kani
            // harness `pq_signature_acceptability_agrees_with_classification`
            // proves, kept total here by the `Unknown` guard.
            let expected = class != PqSignatureClass::Unknown && kani_classify(len) == class;
            assert_eq!(
                pq_signature_len_acceptable(len, class),
                expected,
                "acceptability disagreement at length {len}, class {class:?}"
            );
        }
    }
}
