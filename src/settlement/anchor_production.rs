//! Anchor production: the pipeline that turns finality
//! checkpoints into anchors and Root Seals, and the three conditions that
//! open production mode.
//!
//! WIRING: wired - `Blockchain::emit_anchor_for` in `src/chain/blockchain.rs`
//! calls [`AnchorEmission::on_checkpoint`] on every committed global header;
//! the node builds the emission from its `[anchor]` configuration in
//! `src/main.rs` through [`AnchorEmission::devnet`] (devnet, software keys) or
//! [`AnchorEmission::production`] (HSM keys, a ceremony record, self-tests).
//! Rules are pinned by this file's tests.
//!
//! # Rollout
//!
//! Devnet first, then testnet, then mainnet. Devnet derives its public
//! development keys from the chain id and refuses any other network.
//! Testnet and mainnet load the ledger from the genesis file
//! (`anchor_ledger`) and run only in [`AnchorMode::ProductionApproved`].
//!
//! # The three conditions of production mode
//!
//! 1. **HSM backend.** Every signer reports [`SignerBackend::Hsm`] and its
//!    public key is the ledger key of its slot. The Root Seal signer is an HSM
//!    too.
//! 2. **Key ceremony record.** A [`CeremonyRecord`] binds the digest of the
//!    genesis ledger and is attested by the cold committee (3-of-6
//!    SLH-DSA-SHAKE-256s devices).
//! 3. **Tests.** A self-test signs a probe under every signer and verifies it
//!    against the ledger key before the first anchor is emitted.
//!
//! # VerifyMerkle
//!
//! The anchor signature covers a local SHA3 Merkle root, and the VerifyMerkle
//! opcode does not run on that path. Only an anchor that carries a
//! `stark_root` depends on the VerifyMerkle audit. Production mode therefore
//! emits aggregate-root anchors without it and refuses a `stark_root` until an
//! audit record is supplied ([`VerifyMerkleAudit`]).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[cfg(feature = "wallet-ml-dsa")]
use super::anchor_ledger::ANCHOR_KEY_COUNT;
use super::anchor_ledger::{AnchorKeyLedger, LedgerKey};
use super::cold_quorum::{verify_quorum, DeviceSignature};
use super::cold_wallet::ColdWalletState;
use super::pq_anchor::{
    anchor_due, append_anchor_log, build_anchor_for_height, verify_anchor_full, AnchorError,
    AnchorMode, AnchorSignature, AnchorSigner, EmissionRequest, PqAnchor, SignerBackend,
};
use super::root_seal::{
    build_root_seal, seal_due, RootSeal, RootSealLog, SealSigner, MAX_SEAL_ANCHORS,
    ROOT_SEAL_INTERVAL,
};
use crate::crypto::pkcs11::HsmPqKey;

/// What the cold committee attests when the anchor keys are generated: the
/// ledger the genesis file lists, for one chain and one key epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyRecord {
    /// The chain the ceremony was for.
    pub chain_id: u64,
    /// The key epoch of the generated keys.
    pub key_epoch: u32,
    /// The digest of the key ledger the ceremony produced.
    pub ledger_digest: [u8; 32],
    /// When the ceremony was held, milliseconds since the Unix epoch.
    pub held_at_ms: u64,
    /// The cold committee device signatures over [`ceremony_payload`].
    pub attestations: Vec<DeviceSignature>,
}

/// The bytes the cold committee devices sign for a ceremony.
#[must_use]
pub fn ceremony_payload(
    chain_id: u64,
    key_epoch: u32,
    ledger_digest: &[u8; 32],
    held_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 8 + 4 + 32 + 8);
    out.extend_from_slice(b"BDLM_ANCHOR_CEREMONY_V1");
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&key_epoch.to_le_bytes());
    out.extend_from_slice(ledger_digest);
    out.extend_from_slice(&held_at_ms.to_le_bytes());
    out
}

/// Check a ceremony record against the genesis ledger and the cold committee.
///
/// # Errors
///
/// [`AnchorError::ProductionBlocked`] naming what does not match, or
/// [`AnchorError::CommitteeQuorum`] when the attestations are not a quorum.
pub fn verify_ceremony(
    record: &CeremonyRecord,
    ledger: &AnchorKeyLedger,
    cold: &ColdWalletState,
) -> Result<(), AnchorError> {
    if record.chain_id != ledger.chain_id {
        return Err(AnchorError::ProductionBlocked {
            blocker: "ceremony-record-for-another-chain",
        });
    }
    if record.key_epoch != ledger.key_epoch {
        return Err(AnchorError::ProductionBlocked {
            blocker: "ceremony-record-for-another-key-epoch",
        });
    }
    if record.ledger_digest != ledger.digest() {
        return Err(AnchorError::ProductionBlocked {
            blocker: "ceremony-record-does-not-bind-this-ledger",
        });
    }
    if cold.policy.chain_id != record.chain_id {
        return Err(AnchorError::ProductionBlocked {
            blocker: "cold-committee-is-for-another-chain",
        });
    }
    let payload = ceremony_payload(
        record.chain_id,
        record.key_epoch,
        &record.ledger_digest,
        record.held_at_ms,
    );
    // The devices sign at the epoch of the cold committee; the ledger's own
    // key epoch is inside the payload.
    verify_quorum(
        &cold.policy,
        &cold.trusted_devices,
        &payload,
        cold.key_epoch,
        &record.attestations,
    )
    .map(|_| ())
    .map_err(AnchorError::CommitteeQuorum)
}

/// The record of a third-party VerifyMerkle opcode audit. Without one, an
/// anchor may not carry a `stark_root` in production.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyMerkleAudit {
    /// Who audited.
    pub auditor: String,
    /// SHA3-256 of the audit report.
    pub report_digest: [u8; 32],
}

/// The result of the signer self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestReport {
    /// How many signers were exercised.
    pub tested: usize,
    /// How many of them produced a signature the ledger key verifies.
    pub passed: usize,
}

fn self_test_probe(ledger: &AnchorKeyLedger, key_index: u8) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_ANCHOR_SELF_TEST_V1");
    hasher.update(ledger.digest());
    hasher.update([key_index]);
    hasher.finalize().to_vec()
}

/// Sign a probe with every signer and verify it under the ledger key of its
/// slot (condition 3 of production mode).
///
/// # Errors
///
/// [`AnchorError::UnknownKeyIndex`] when a signer names no ledger slot.
pub fn run_self_test(
    ledger: &AnchorKeyLedger,
    signers: &[&dyn AnchorSigner],
) -> Result<SelfTestReport, AnchorError> {
    let mut passed = 0usize;
    for signer in signers {
        let index = signer.key_index();
        let Some(public_key) = ledger.anchor_key(index) else {
            return Err(AnchorError::UnknownKeyIndex { index });
        };
        let probe = self_test_probe(ledger, index);
        let verified = signer.sign(&probe).and_then(|sig| {
            super::pq_anchor_verify::verify_one(public_key, &probe, &sig.signature)
        });
        if verified.is_ok() {
            passed += 1;
        }
    }
    Ok(SelfTestReport {
        tested: signers.len(),
        passed,
    })
}

/// Everything the production gate looks at.
pub struct ProductionInputs<'a> {
    /// The genesis key ledger.
    pub ledger: &'a AnchorKeyLedger,
    /// The anchor signers this node holds.
    pub signers: &'a [&'a dyn AnchorSigner],
    /// The Root Seal signer.
    pub seal_signer: &'a dyn SealSigner,
    /// The ceremony record.
    pub ceremony: Option<&'a CeremonyRecord>,
    /// The cold wallet whose committee attests the ceremony.
    pub cold: &'a ColdWalletState,
    /// The VerifyMerkle audit record, if any.
    pub verifymerkle_audit: Option<VerifyMerkleAudit>,
}

/// Proof that the three production conditions held. Only [`enforce_production`]
/// builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionGrant {
    ledger_digest: [u8; 32],
    stark_path_open: bool,
}

impl ProductionGrant {
    /// The digest of the ledger the grant was issued for.
    #[must_use]
    pub fn ledger_digest(&self) -> [u8; 32] {
        self.ledger_digest
    }

    /// Whether anchors may carry a `stark_root` (a VerifyMerkle audit is on
    /// record).
    #[must_use]
    pub fn stark_path_open(&self) -> bool {
        self.stark_path_open
    }
}

/// Check the three conditions of [`AnchorMode::ProductionApproved`].
///
/// # Errors
///
/// [`AnchorError::ProductionBlocked`] naming the first condition that fails,
/// or the ledger and quorum errors behind it.
pub fn enforce_production(inputs: &ProductionInputs<'_>) -> Result<ProductionGrant, AnchorError> {
    inputs.ledger.validate().map_err(AnchorError::from)?;
    // Condition 1: an HSM backend, and the key it holds is the ledger's key.
    if inputs.signers.is_empty() {
        return Err(AnchorError::ProductionBlocked {
            blocker: "no-anchor-signer-configured",
        });
    }
    for signer in inputs.signers {
        if signer.backend() != SignerBackend::Hsm {
            return Err(AnchorError::ProductionBlocked {
                blocker: "anchor-signer-is-not-an-hsm",
            });
        }
        match inputs.ledger.anchor_key(signer.key_index()) {
            Some(key) if key == signer.public_key().as_slice() => {}
            Some(_) => {
                return Err(AnchorError::ProductionBlocked {
                    blocker: "anchor-signer-key-is-not-the-ledger-key",
                })
            }
            None => {
                return Err(AnchorError::UnknownKeyIndex {
                    index: signer.key_index(),
                })
            }
        }
    }
    if inputs.seal_signer.backend() != SignerBackend::Hsm {
        return Err(AnchorError::ProductionBlocked {
            blocker: "seal-signer-is-not-an-hsm",
        });
    }
    // Condition 2: the key ceremony record.
    let Some(ceremony) = inputs.ceremony else {
        return Err(AnchorError::ProductionBlocked {
            blocker: "no-key-ceremony-record",
        });
    };
    verify_ceremony(ceremony, inputs.ledger, inputs.cold)?;
    // Condition 3: the self-test.
    let report = run_self_test(inputs.ledger, inputs.signers)?;
    if report.passed != report.tested {
        return Err(AnchorError::ProductionBlocked {
            blocker: "anchor-self-test-failed",
        });
    }
    // The seal key is the ledger's seal slot 0 and signs a verifiable probe.
    match inputs.ledger.seal_keys.first() {
        Some(key) if key.public_key == inputs.seal_signer.public_key() => {}
        _ => {
            return Err(AnchorError::ProductionBlocked {
                blocker: "seal-signer-key-is-not-the-ledger-key",
            })
        }
    }
    let seal_probe = self_test_probe(inputs.ledger, u8::MAX);
    let seal_verified = inputs.seal_signer.sign(&seal_probe).and_then(|sig| {
        super::pq_anchor_verify::verify_seal_signature(
            &inputs.seal_signer.public_key(),
            &seal_probe,
            &sig,
        )
    });
    if seal_verified.is_err() {
        return Err(AnchorError::ProductionBlocked {
            blocker: "seal-self-test-failed",
        });
    }
    Ok(ProductionGrant {
        ledger_digest: inputs.ledger.digest(),
        stark_path_open: inputs.verifymerkle_audit.is_some(),
    })
}

/// An anchor signer whose key lives in an HSM and signs through PKCS#11 3.2
/// (ML-DSA-87, `BDLM/ANCHOR/V2`).
pub struct HsmAnchorSigner {
    key_index: u8,
    key: Arc<dyn HsmPqKey>,
}

impl HsmAnchorSigner {
    /// Bind an HSM key to a ledger slot.
    #[must_use]
    pub fn new(key_index: u8, key: Arc<dyn HsmPqKey>) -> Self {
        Self { key_index, key }
    }
}

impl AnchorSigner for HsmAnchorSigner {
    fn key_index(&self) -> u8 {
        self.key_index
    }

    fn backend(&self) -> SignerBackend {
        SignerBackend::Hsm
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    fn sign(&self, payload: &[u8]) -> Result<AnchorSignature, AnchorError> {
        let signature = self
            .key
            .sign(crate::crypto::ctx::ANCHOR_V2, payload)
            .map_err(|_| AnchorError::SigningBackendUnavailable("pkcs11"))?;
        Ok(AnchorSignature {
            key_index: self.key_index,
            signature,
        })
    }
}

/// A Root Seal signer whose SLH-DSA-SHAKE-256s key lives in an HSM.
pub struct HsmSealSigner {
    key: Arc<dyn HsmPqKey>,
}

impl HsmSealSigner {
    /// Wrap an HSM key.
    #[must_use]
    pub fn new(key: Arc<dyn HsmPqKey>) -> Self {
        Self { key }
    }
}

impl SealSigner for HsmSealSigner {
    fn backend(&self) -> SignerBackend {
        SignerBackend::Hsm
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        self.key
            .sign(crate::crypto::ctx::SEAL_V1, payload)
            .map_err(|_| AnchorError::SigningBackendUnavailable("pkcs11"))
    }
}

/// Where the node's HSM keys are: one PKCS#11 3.2 token, the ledger slots
/// this node signs for, and the Root Seal key.
pub struct HsmCustody<'a> {
    /// The PKCS#11 module.
    pub module_path: &'a str,
    /// The token slot.
    pub slot_id: u64,
    /// The environment variable that holds the user PIN.
    pub token_pin_env: &'a str,
    /// `(ledger slot, key label)` of every anchor key this node holds.
    pub anchor_keys: &'a [(u8, String)],
    /// The label of the SLH-DSA-SHAKE-256s Root Seal key.
    pub seal_key_label: &'a str,
}

/// Build the production pipeline: open the HSM keys, check the three
/// conditions of [`AnchorMode::ProductionApproved`] and return the emission
/// that carries the grant.
///
/// # Errors
///
/// [`AnchorError::SigningBackendUnavailable`] when a token key cannot be
/// opened, or the refusal of [`enforce_production`].
pub fn production_emission(
    log_path: std::path::PathBuf,
    ledger: AnchorKeyLedger,
    custody: &HsmCustody<'_>,
    ceremony: &CeremonyRecord,
    cold: &ColdWalletState,
    verifymerkle_audit: Option<VerifyMerkleAudit>,
) -> Result<AnchorEmission, AnchorError> {
    use crate::crypto::pkcs11::{HsmPqAlgorithm, Pkcs11PqToken};
    let token = Pkcs11PqToken::open(custody.module_path, custody.slot_id, custody.token_pin_env)
        .map_err(|_| AnchorError::SigningBackendUnavailable("pkcs11"))?;
    let mut signers: Vec<Arc<dyn AnchorSigner + Send + Sync>> = Vec::new();
    for (slot, label) in custody.anchor_keys {
        let key = token
            .open_key(label, HsmPqAlgorithm::MlDsa87)
            .map_err(|_| AnchorError::SigningBackendUnavailable("pkcs11"))?;
        signers.push(Arc::new(HsmAnchorSigner::new(*slot, Arc::new(key))));
    }
    let seal_key = token
        .open_key(custody.seal_key_label, HsmPqAlgorithm::SlhDsaShake256s)
        .map_err(|_| AnchorError::SigningBackendUnavailable("pkcs11"))?;
    let seal_signer: Arc<dyn SealSigner + Send + Sync> =
        Arc::new(HsmSealSigner::new(Arc::new(seal_key)));
    let grant = {
        let mut refs: Vec<&dyn AnchorSigner> = Vec::new();
        for signer in &signers {
            refs.push(signer.as_ref());
        }
        enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &refs,
            seal_signer: seal_signer.as_ref(),
            ceremony: Some(ceremony),
            cold,
            verifymerkle_audit,
        })?
    };
    Ok(AnchorEmission::production(
        log_path,
        ledger,
        signers,
        seal_signer,
        grant,
    ))
}

/// What one checkpoint did to the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckpointOutcome {
    /// An anchor was built, verified and logged.
    pub anchored: bool,
    /// A Root Seal was built and accepted, at this height.
    pub sealed: Option<u64>,
}

/// Node-side anchor emission (BLG-0076 / P03-F19): where a sealed anchor is
/// written, under which mode, at which key epoch, with which keys, and the
/// Root Seal state that follows it.
///
/// The default is the GatedOff stub, so the trace takes the skipped arm and
/// nothing is written until a node configures its signers and a mode.
pub struct AnchorEmission {
    /// Node-local anchor log path. The seal log sits next to it.
    pub log_path: std::path::PathBuf,
    /// Enforcement mode (GatedOff skips; ProductionApproved needs its grant).
    pub mode: AnchorMode,
    /// The key epoch the emitted anchor is signed at.
    pub key_epoch: u32,
    /// The signers this node holds: all three software keys on devnet, the
    /// node's own HSM key in production.
    pub signers: Vec<Arc<dyn AnchorSigner + Send + Sync>>,
    /// The Root Seal signer.
    pub seal_signer: Option<Arc<dyn SealSigner + Send + Sync>>,
    /// The genesis key ledger, with the suspensions evidence has caused.
    pub ledger: Option<AnchorKeyLedger>,
    /// The grant production mode needs.
    pub production: Option<ProductionGrant>,
    /// The Root Seals this node has built and verified.
    pub seals: RootSealLog,
    /// The anchors of the open period, oldest first.
    pub pending: Vec<PqAnchor>,
    /// The anchor the last checkpoint built, verified and logged. The Root
    /// Seal consumes `pending` in the same call, so the node reads this one
    /// to feed `PqCanonicalSource`.
    pub last_anchor: Option<PqAnchor>,
}

impl Clone for AnchorEmission {
    fn clone(&self) -> Self {
        Self {
            log_path: self.log_path.clone(),
            mode: self.mode,
            key_epoch: self.key_epoch,
            signers: self.signers.clone(),
            seal_signer: self.seal_signer.clone(),
            ledger: self.ledger.clone(),
            production: self.production.clone(),
            seals: self.seals.clone(),
            pending: self.pending.clone(),
            last_anchor: self.last_anchor.clone(),
        }
    }
}

impl Default for AnchorEmission {
    fn default() -> Self {
        Self {
            log_path: std::path::PathBuf::from("data/anchors.jsonl"),
            mode: AnchorMode::GatedOff,
            key_epoch: 0,
            signers: Vec::new(),
            seal_signer: None,
            ledger: None,
            production: None,
            seals: RootSealLog::new(),
            pending: Vec::new(),
            last_anchor: None,
        }
    }
}

/// The path of the seal log next to an anchor log.
#[must_use]
pub fn seal_log_path(anchor_log: &std::path::Path) -> std::path::PathBuf {
    anchor_log.with_file_name("root-seals.jsonl")
}

/// The seed of the public development anchor key `index` of `chain_id`.
fn devnet_seed(chain_id: u64, index: u8) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_DEVNET_ANCHOR_KEY_V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update([index]);
    hasher.finalize().into()
}

/// The seed of the public development seal key of `chain_id`, 96 bytes.
fn devnet_seal_seed(chain_id: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    for block in 0u8..3 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_DEVNET_SEAL_KEY_V1");
        hasher.update(chain_id.to_le_bytes());
        hasher.update([block]);
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

impl AnchorEmission {
    /// The development pipeline: three software anchor keys and one software
    /// seal key derived from the chain id. The seeds are public, so the keys
    /// secure nothing; the constructor refuses any network but devnet.
    ///
    /// # Errors
    ///
    /// [`AnchorError::ProductionBlocked`] on a chain id that is not devnet's.
    #[cfg(feature = "wallet-ml-dsa")]
    pub fn devnet(chain_id: u64, log_path: std::path::PathBuf) -> Result<Self, AnchorError> {
        if crate::core::chain_config::Network::from_chain_id(chain_id)
            != Some(crate::core::chain_config::Network::Devnet)
        {
            return Err(AnchorError::ProductionBlocked {
                blocker: "development-anchor-keys-are-devnet-only",
            });
        }
        let seal = super::root_seal::SoftwareSealSigner::from_seed(&devnet_seal_seed(chain_id))?;
        let mut signers: Vec<Arc<dyn AnchorSigner + Send + Sync>> = Vec::new();
        let mut anchor_keys = Vec::new();
        for index in 0..u8::try_from(ANCHOR_KEY_COUNT).unwrap_or(3) {
            let signer = super::pq_anchor::SoftwareMlDsa87Signer::from_seed(
                index,
                &devnet_seed(chain_id, index),
            );
            anchor_keys.push(LedgerKey {
                index,
                vendor: if index == 1 { "devnet-b" } else { "devnet-a" }.to_string(),
                public_key: signer.public_key(),
            });
            signers.push(Arc::new(signer));
        }
        let ledger = AnchorKeyLedger {
            chain_id,
            key_epoch: 1,
            anchor_keys,
            seal_keys: vec![LedgerKey {
                index: 0,
                vendor: "devnet-c".to_string(),
                public_key: seal.public_key(),
            }],
            suspended: std::collections::BTreeSet::new(),
        };
        ledger.validate().map_err(AnchorError::from)?;
        Ok(Self {
            log_path,
            mode: AnchorMode::Devnet,
            key_epoch: ledger.key_epoch,
            signers,
            seal_signer: Some(Arc::new(seal)),
            ledger: Some(ledger),
            production: None,
            seals: RootSealLog::new(),
            pending: Vec::new(),
            last_anchor: None,
        })
    }

    /// The production pipeline. The grant comes from [`enforce_production`];
    /// without it the constructor does not exist.
    #[must_use]
    pub fn production(
        log_path: std::path::PathBuf,
        ledger: AnchorKeyLedger,
        signers: Vec<Arc<dyn AnchorSigner + Send + Sync>>,
        seal_signer: Arc<dyn SealSigner + Send + Sync>,
        grant: ProductionGrant,
    ) -> Self {
        Self {
            log_path,
            mode: AnchorMode::ProductionApproved,
            key_epoch: ledger.key_epoch,
            signers,
            seal_signer: Some(seal_signer),
            ledger: Some(ledger),
            production: Some(grant),
            seals: RootSealLog::new(),
            pending: Vec::new(),
            last_anchor: None,
        }
    }

    /// Seed the seal log from the node-local seal file after a restart: the
    /// last line is the latest seal this node built, so the next seal links to
    /// it. A missing file is a fresh log; an unreadable last line is an error,
    /// not a silent restart from the genesis link.
    ///
    /// # Errors
    ///
    /// [`AnchorError::EmissionIo`] when the file exists but cannot be read or
    /// its last line is not a Root Seal.
    pub fn resume_seal_log(&mut self) -> Result<(), AnchorError> {
        let path = seal_log_path(&self.log_path);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(AnchorError::EmissionIo("read seal log")),
        };
        let Some(line) = text.lines().rev().find(|l| !l.trim().is_empty()) else {
            return Ok(());
        };
        let seal: RootSeal =
            serde_json::from_str(line).map_err(|_| AnchorError::EmissionIo("seal log line"))?;
        self.seals.adopt(seal);
        Ok(())
    }

    /// Check the mode gate: devnet off mainnet, production only with a grant
    /// whose ledger is the loaded one.
    fn check_mode(&self, request: &EmissionRequest<'_>) -> Result<(), AnchorError> {
        match self.mode {
            AnchorMode::GatedOff => Ok(()),
            AnchorMode::Devnet => {
                //: development keys have public seeds and secure nothing.
                if crate::core::chain_config::Network::from_chain_id(request.chain_id)
                    == Some(crate::core::chain_config::Network::Mainnet)
                {
                    return Err(AnchorError::ProductionBlocked {
                        blocker: "development-mode-is-not-allowed-on-mainnet",
                    });
                }
                Ok(())
            }
            AnchorMode::ProductionApproved => {
                let Some(grant) = &self.production else {
                    return Err(AnchorError::ProductionBlocked {
                        blocker: "production-grant-missing",
                    });
                };
                let Some(ledger) = &self.ledger else {
                    return Err(AnchorError::ProductionBlocked {
                        blocker: "production-needs-the-genesis-ledger",
                    });
                };
                if grant.ledger_digest() != ledger.digest() {
                    return Err(AnchorError::ProductionBlocked {
                        blocker: "production-grant-is-for-another-ledger",
                    });
                }
                //: only the stark_root path depends on VerifyMerkle.
                if request.stark_root.is_some() && !grant.stark_path_open() {
                    return Err(AnchorError::ProductionBlocked {
                        blocker: "verifymerkle-audit-pending-for-the-stark-root-path",
                    });
                }
                Ok(())
            }
        }
    }

    /// Run the pipeline for one committed checkpoint.
    ///
    /// Every [`ANCHOR_INTERVAL`](super::pq_anchor::ANCHOR_INTERVAL) blocks the
    /// anchor is built, verified against the ledger and appended to the log;
    /// every [`ROOT_SEAL_INTERVAL`] blocks the Root Seal of the period follows.
    ///
    /// # Errors
    ///
    /// The mode gate, the anchor assembly and verification refusals, the
    /// seal refusals, or the log io.
    pub fn on_checkpoint(
        &mut self,
        request: &EmissionRequest<'_>,
    ) -> Result<CheckpointOutcome, AnchorError> {
        let mut outcome = CheckpointOutcome::default();
        if self.mode == AnchorMode::GatedOff || !anchor_due(request.height) {
            return Ok(outcome);
        }
        self.check_mode(request)?;
        let mut signers: Vec<&dyn AnchorSigner> = Vec::new();
        for signer in &self.signers {
            signers.push(signer.as_ref());
        }
        let request = EmissionRequest {
            key_epoch: self.ledger.as_ref().map_or(self.key_epoch, |l| l.key_epoch),
            ..*request
        };
        let anchor = build_anchor_for_height(&request, &signers)?;
        if let Some(ledger) = &self.ledger {
            // The node does not log an anchor its own ledger refuses.
            verify_anchor_full(&anchor, ledger)?;
        }
        append_anchor_log(&self.log_path, &anchor)?;
        self.last_anchor = Some(anchor.clone());
        self.pending.push(anchor);
        // A period holds ten anchors; a node without a seal signer must not
        // grow the list without bound.
        if self.pending.len() > MAX_SEAL_ANCHORS {
            let excess = self.pending.len() - MAX_SEAL_ANCHORS;
            self.pending.drain(..excess);
        }
        outcome.anchored = true;
        if seal_due(request.height) {
            outcome.sealed = self.seal_period(request.chain_id, request.height)?;
        }
        Ok(outcome)
    }

    /// Build, verify and log the Root Seal of the period ending at
    /// `seal_height`. `None` when no seal signer or ledger is configured.
    fn seal_period(&mut self, chain_id: u64, seal_height: u64) -> Result<Option<u64>, AnchorError> {
        let (Some(signer), Some(ledger)) = (self.seal_signer.clone(), self.ledger.as_ref()) else {
            return Ok(None);
        };
        let period_start = seal_height.saturating_sub(ROOT_SEAL_INTERVAL);
        let in_period: Vec<PqAnchor> = self
            .pending
            .iter()
            .filter(|a| a.height > period_start && a.height <= seal_height)
            .cloned()
            .collect();
        let key_epoch = ledger.key_epoch;
        let seal = build_root_seal(
            chain_id,
            seal_height,
            &in_period,
            self.seals.latest(),
            key_epoch,
            0,
            signer.as_ref(),
        )
        .map_err(|_| AnchorError::Ledger("root-seal-refused"))?;
        self.seals
            .accept(seal.clone(), chain_id, ledger, key_epoch, Some(&in_period))
            .map_err(|_| AnchorError::Ledger("root-seal-not-accepted"))?;
        append_seal_log(&seal_log_path(&self.log_path), &seal)?;
        self.pending.retain(|a| a.height > seal_height);
        Ok(Some(seal_height))
    }

    /// Apply two conflicting anchors as evidence: the keys that signed both
    /// are suspended for their key epoch. Returns the suspended slots.
    ///
    /// # Errors
    ///
    /// [`AnchorError::Ledger`] when no ledger is loaded or the pair is no
    /// evidence.
    pub fn report_equivocation(
        &mut self,
        first: &PqAnchor,
        second: &PqAnchor,
    ) -> Result<Vec<u8>, AnchorError> {
        let Some(ledger) = self.ledger.as_mut() else {
            return Err(AnchorError::Ledger("no-ledger-loaded"));
        };
        ledger
            .apply_equivocation(first, second)
            .map_err(AnchorError::from)
    }

    /// Install the keys of the next key epoch after a cold committee rotation.
    ///
    /// # Errors
    ///
    /// [`AnchorError::Ledger`] when no ledger is loaded or the keys are
    /// refused.
    pub fn install_rotated_keys(
        &mut self,
        key_epoch: u32,
        anchor_keys: Vec<LedgerKey>,
        seal_keys: Vec<LedgerKey>,
    ) -> Result<(), AnchorError> {
        let Some(ledger) = self.ledger.as_mut() else {
            return Err(AnchorError::Ledger("no-ledger-loaded"));
        };
        ledger
            .install_rotated_keys(key_epoch, anchor_keys, seal_keys)
            .map_err(AnchorError::from)?;
        self.key_epoch = key_epoch;
        // The grant was issued for the old ledger; production needs a new one.
        self.production = None;
        Ok(())
    }
}

/// Append one Root Seal to the node-local seal log.
///
/// # Errors
///
/// [`AnchorError::EmissionIo`] naming the stage that failed.
pub fn append_seal_log(log_path: &std::path::Path, seal: &RootSeal) -> Result<(), AnchorError> {
    let line =
        serde_json::to_string(seal).map_err(|_| AnchorError::EmissionIo("json serialize"))?;
    use std::io::Write as _;
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| AnchorError::EmissionIo("mkdir"))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|_| AnchorError::EmissionIo("open"))?;
    writeln!(file, "{line}").map_err(|_| AnchorError::EmissionIo("append"))
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::crypto::facts::QuantumClass;
    use crate::crypto::primitives::{CryptoError, WalletKeyPair};
    use crate::settlement::anchor_ledger::test_support::{
        anchor_seed, seal_signer, software_ledger,
    };
    use crate::settlement::cold_quorum::dev_fixture_device_signers;
    use crate::settlement::cold_wallet::ColdWalletPolicy;
    use crate::settlement::pq_anchor::{AnchorLeaf, SoftwareMlDsa87Signer};
    use crate::settlement::root_seal::{verify_root_seal, SoftwareSealSigner};

    const DEVNET: u64 = 45262;
    const HELD_AT: u64 = 1_700_000_000_000;

    /// A software key behind the HSM trait: the production code path sees an
    /// `HsmPqKey`, the token is the only thing replaced.
    struct TokenDouble {
        public: Vec<u8>,
        signer: Box<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, CryptoError> + Send + Sync>,
    }

    impl HsmPqKey for TokenDouble {
        fn public_key(&self) -> Vec<u8> {
            self.public.clone()
        }

        fn sign(&self, ctx: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
            (self.signer)(ctx, payload)
        }
    }

    fn hsm_anchor_signer(index: u8) -> HsmAnchorSigner {
        let pair = WalletKeyPair::from_seed(&anchor_seed(index));
        let public = pair.public_key_bytes().to_vec();
        HsmAnchorSigner::new(
            index,
            Arc::new(TokenDouble {
                public,
                signer: Box::new(move |ctx, payload| Ok(pair.sign(ctx, payload).to_vec())),
            }),
        )
    }

    fn hsm_seal_signer() -> HsmSealSigner {
        let software = seal_signer();
        let public = SealSigner::public_key(&software);
        HsmSealSigner::new(Arc::new(TokenDouble {
            public,
            signer: Box::new(move |_ctx, payload| {
                SealSigner::sign(&software, payload)
                    .map_err(|_| CryptoError::Signing("token refused".to_string()))
            }),
        }))
    }

    fn cold_committee() -> ColdWalletState {
        ColdWalletState::new(ColdWalletPolicy {
            chain_id: DEVNET,
            max_value_per_settlement_atoms: 1000,
            max_value_per_epoch_atoms: 3000,
            min_height_advance: 1,
            required_quorum: 3,
            device_count: 6,
            refusal_history_capacity: 8,
        })
        .with_trusted_devices(
            dev_fixture_device_signers()
                .iter()
                .map(|d| d.identity.clone())
                .collect(),
        )
    }

    fn ceremony(
        ledger: &AnchorKeyLedger,
        cold: &ColdWalletState,
        devices: usize,
    ) -> CeremonyRecord {
        let payload =
            ceremony_payload(ledger.chain_id, ledger.key_epoch, &ledger.digest(), HELD_AT);
        CeremonyRecord {
            chain_id: ledger.chain_id,
            key_epoch: ledger.key_epoch,
            ledger_digest: ledger.digest(),
            held_at_ms: HELD_AT,
            attestations: dev_fixture_device_signers()[..devices]
                .iter()
                .map(|d| d.sign_payload(&payload, cold.key_epoch))
                .collect(),
        }
    }

    fn leaf(n: u8) -> AnchorLeaf {
        AnchorLeaf {
            finality_digest: [n; 32],
            quantum_class: QuantumClass::Lattice,
        }
    }

    fn request<'a>(
        height: u64,
        window: &'a [AnchorLeaf],
        ledger: &AnchorKeyLedger,
    ) -> EmissionRequest<'a> {
        EmissionRequest {
            chain_id: ledger.chain_id,
            height,
            window_leaves: window,
            stark_root: None,
            crossdomain_root: None,
            key_epoch: ledger.key_epoch,
        }
    }

    fn temp_log(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "anchor-production-test-{name}-{}",
            std::process::id()
        ));
        let _unused = std::fs::remove_dir_all(&dir);
        dir.push("anchors.jsonl");
        dir
    }

    /// A pipeline over the fixture ledger: software signers in the
    /// development mode, so one test can look at emission without an HSM.
    fn fixture_emission(name: &str) -> AnchorEmission {
        let ledger = software_ledger(DEVNET, 1);
        let mut signers: Vec<Arc<dyn AnchorSigner + Send + Sync>> = Vec::new();
        for i in 0u8..3 {
            signers.push(Arc::new(SoftwareMlDsa87Signer::from_seed(
                i,
                &anchor_seed(i),
            )));
        }
        AnchorEmission {
            log_path: temp_log(name),
            mode: AnchorMode::Devnet,
            key_epoch: ledger.key_epoch,
            signers,
            seal_signer: Some(Arc::new(seal_signer())),
            ledger: Some(ledger),
            production: None,
            seals: RootSealLog::new(),
            pending: Vec::new(),
            last_anchor: None,
        }
    }

    fn cleanup(emission: &AnchorEmission) {
        if let Some(dir) = emission.log_path.parent() {
            let _unused = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn production_is_granted_with_hsm_signers_a_ceremony_and_a_passing_self_test() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let record = ceremony(&ledger, &cold, 3);
        let hsm: Vec<HsmAnchorSigner> = (0u8..3).map(hsm_anchor_signer).collect();
        let mut signers: Vec<&dyn AnchorSigner> = Vec::new();
        for signer in &hsm {
            signers.push(signer);
        }
        let seal = hsm_seal_signer();
        let grant = enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &signers,
            seal_signer: &seal,
            ceremony: Some(&record),
            cold: &cold,
            verifymerkle_audit: None,
        })
        .expect("three HSM signers, a ceremony and a self-test open production");
        assert_eq!(grant.ledger_digest(), ledger.digest());
        assert!(!grant.stark_path_open());
    }

    #[test]
    fn production_refuses_a_software_signer() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let record = ceremony(&ledger, &cold, 3);
        let software = SoftwareMlDsa87Signer::from_seed(0, &anchor_seed(0));
        let signers: Vec<&dyn AnchorSigner> = vec![&software];
        let seal = hsm_seal_signer();
        let err = enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &signers,
            seal_signer: &seal,
            ceremony: Some(&record),
            cold: &cold,
            verifymerkle_audit: None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            AnchorError::ProductionBlocked {
                blocker: "anchor-signer-is-not-an-hsm"
            }
        );
    }

    #[test]
    fn production_refuses_a_software_seal_signer() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let record = ceremony(&ledger, &cold, 3);
        let hsm = hsm_anchor_signer(0);
        let signers: Vec<&dyn AnchorSigner> = vec![&hsm];
        let seal = seal_signer();
        let err = enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &signers,
            seal_signer: &seal,
            ceremony: Some(&record),
            cold: &cold,
            verifymerkle_audit: None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            AnchorError::ProductionBlocked {
                blocker: "seal-signer-is-not-an-hsm"
            }
        );
    }

    #[test]
    fn production_refuses_a_seal_key_that_is_not_the_ledger_seal_key() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let record = ceremony(&ledger, &cold, 3);
        let hsm: Vec<HsmAnchorSigner> = (0u8..3).map(hsm_anchor_signer).collect();
        let mut signers: Vec<&dyn AnchorSigner> = Vec::new();
        for signer in &hsm {
            signers.push(signer);
        }
        // An HSM seal key other than the one the ledger lists.
        let other = SoftwareSealSigner::from_seed(&[0x11; 96]).expect("seed");
        let public = SealSigner::public_key(&other);
        let seal = HsmSealSigner::new(Arc::new(TokenDouble {
            public,
            signer: Box::new(move |_ctx, payload| {
                SealSigner::sign(&other, payload)
                    .map_err(|_| CryptoError::Signing("token refused".to_string()))
            }),
        }));
        let err = enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &signers,
            seal_signer: &seal,
            ceremony: Some(&record),
            cold: &cold,
            verifymerkle_audit: None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            AnchorError::ProductionBlocked {
                blocker: "seal-signer-key-is-not-the-ledger-key"
            }
        );
    }

    #[test]
    fn production_refuses_a_signer_whose_key_is_not_the_ledger_key() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let record = ceremony(&ledger, &cold, 3);
        // Slot 1 claims the key of slot 2.
        let pair = WalletKeyPair::from_seed(&anchor_seed(2));
        let public = pair.public_key_bytes().to_vec();
        let wrong = HsmAnchorSigner::new(
            1,
            Arc::new(TokenDouble {
                public,
                signer: Box::new(move |ctx, payload| Ok(pair.sign(ctx, payload).to_vec())),
            }),
        );
        let signers: Vec<&dyn AnchorSigner> = vec![&wrong];
        let seal = hsm_seal_signer();
        let err = enforce_production(&ProductionInputs {
            ledger: &ledger,
            signers: &signers,
            seal_signer: &seal,
            ceremony: Some(&record),
            cold: &cold,
            verifymerkle_audit: None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            AnchorError::ProductionBlocked {
                blocker: "anchor-signer-key-is-not-the-ledger-key"
            }
        );
    }

    #[test]
    fn production_needs_a_ceremony_that_binds_this_ledger_and_a_quorum() {
        let ledger = software_ledger(DEVNET, 1);
        let cold = cold_committee();
        let hsm = hsm_anchor_signer(0);
        let signers: Vec<&dyn AnchorSigner> = vec![&hsm];
        let seal = hsm_seal_signer();
        let run = |ceremony: Option<&CeremonyRecord>| {
            enforce_production(&ProductionInputs {
                ledger: &ledger,
                signers: &signers,
                seal_signer: &seal,
                ceremony,
                cold: &cold,
                verifymerkle_audit: None,
            })
        };
        assert_eq!(
            run(None).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "no-key-ceremony-record"
            }
        );
        // The ceremony of a different ledger.
        let other = software_ledger(DEVNET, 2);
        assert_eq!(
            run(Some(&ceremony(&other, &cold, 3))).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "ceremony-record-for-another-key-epoch"
            }
        );
        // Two of six devices are not the 3-of-6 quorum.
        assert!(matches!(
            run(Some(&ceremony(&ledger, &cold, 2))).unwrap_err(),
            AnchorError::CommitteeQuorum(_)
        ));
        // A record whose ledger digest was edited.
        let mut forged = ceremony(&ledger, &cold, 3);
        forged.ledger_digest = [0xEE; 32];
        assert_eq!(
            run(Some(&forged)).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "ceremony-record-does-not-bind-this-ledger"
            }
        );
        // A held_at edit invalidates the attestations.
        let mut moved = ceremony(&ledger, &cold, 3);
        moved.held_at_ms += 1;
        assert!(matches!(
            run(Some(&moved)).unwrap_err(),
            AnchorError::CommitteeQuorum(_)
        ));
    }

    #[test]
    fn the_self_test_catches_a_signer_that_signs_with_the_wrong_key() {
        let ledger = software_ledger(DEVNET, 1);
        // Slot 0 reports the ledger key but signs with another key.
        let ledger_key = WalletKeyPair::from_seed(&anchor_seed(0))
            .public_key_bytes()
            .to_vec();
        let other = WalletKeyPair::from_seed(&[0x77; 32]);
        let liar = HsmAnchorSigner::new(
            0,
            Arc::new(TokenDouble {
                public: ledger_key,
                signer: Box::new(move |ctx, payload| Ok(other.sign(ctx, payload).to_vec())),
            }),
        );
        let honest = hsm_anchor_signer(1);
        let signers: Vec<&dyn AnchorSigner> = vec![&liar, &honest];
        let report = run_self_test(&ledger, &signers).expect("both slots exist");
        assert_eq!(
            report,
            SelfTestReport {
                tested: 2,
                passed: 1
            }
        );
    }

    #[test]
    fn a_stark_root_needs_a_verifymerkle_audit_in_production_and_nothing_else_does() {
        let ledger = software_ledger(DEVNET, 1);
        let mut emission = fixture_emission("stark");
        emission.mode = AnchorMode::ProductionApproved;
        let window = [leaf(1)];
        let mut with_stark = request(360, &window, &ledger);
        with_stark.stark_root = Some([9u8; 32]);
        let plain = request(360, &window, &ledger);

        // Without a grant production refuses everything.
        assert_eq!(
            emission.check_mode(&plain).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "production-grant-missing"
            }
        );
        // A grant without an audit record: the aggregate-root anchor passes
        //, the stark_root fails.
        emission.production = Some(ProductionGrant {
            ledger_digest: ledger.digest(),
            stark_path_open: false,
        });
        assert!(emission.check_mode(&plain).is_ok());
        assert_eq!(
            emission.check_mode(&with_stark).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "verifymerkle-audit-pending-for-the-stark-root-path"
            }
        );
        emission.production = Some(ProductionGrant {
            ledger_digest: ledger.digest(),
            stark_path_open: true,
        });
        assert!(emission.check_mode(&with_stark).is_ok());
        // A grant for another ledger is no grant.
        emission.production = Some(ProductionGrant {
            ledger_digest: [1u8; 32],
            stark_path_open: true,
        });
        assert_eq!(
            emission.check_mode(&plain).unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "production-grant-is-for-another-ledger"
            }
        );
        cleanup(&emission);
    }

    #[test]
    fn development_mode_is_refused_on_mainnet() {
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let ledger = software_ledger(mainnet, 1);
        let emission = fixture_emission("mainnet");
        let window = [leaf(1)];
        assert_eq!(
            emission
                .check_mode(&request(360, &window, &ledger))
                .unwrap_err(),
            AnchorError::ProductionBlocked {
                blocker: "development-mode-is-not-allowed-on-mainnet"
            }
        );
        cleanup(&emission);
    }

    #[test]
    fn the_devnet_constructor_refuses_every_other_network() {
        let log = temp_log("ctor");
        for chain in [
            crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value(),
            crate::core::chain_config::Network::Testnet
                .chain_id()
                .value(),
        ] {
            assert!(matches!(
                AnchorEmission::devnet(chain, log.clone()),
                Err(AnchorError::ProductionBlocked { .. })
            ));
        }
    }

    #[test]
    fn a_default_emission_is_inert_and_off_boundary_heights_emit_nothing() {
        let ledger = software_ledger(DEVNET, 1);
        let window = [leaf(1)];
        let mut off = AnchorEmission::default();
        assert_eq!(
            off.on_checkpoint(&request(360, &window, &ledger)).unwrap(),
            CheckpointOutcome::default()
        );
        let mut emission = fixture_emission("off-boundary");
        for height in [1u64, 10, 359, 361, 719] {
            assert_eq!(
                emission
                    .on_checkpoint(&request(height, &window, &ledger))
                    .unwrap(),
                CheckpointOutcome::default()
            );
        }
        assert!(!emission.log_path.exists());
        cleanup(&emission);
    }

    #[test]
    fn the_360_block_anchor_is_built_verified_and_logged() {
        let ledger = software_ledger(DEVNET, 1);
        let mut emission = fixture_emission("anchor-360");
        let window = [leaf(1), leaf(2)];
        let outcome = emission
            .on_checkpoint(&request(360, &window, &ledger))
            .expect("the 360 block anchor is produced");
        assert_eq!(
            outcome,
            CheckpointOutcome {
                anchored: true,
                sealed: None
            }
        );
        let text = std::fs::read_to_string(&emission.log_path).expect("the anchor log exists");
        let logged: PqAnchor = serde_json::from_str(text.lines().next().expect("one line"))
            .expect("the line is an anchor");
        assert_eq!(logged.height, 360);
        assert_eq!(logged.signatures.len(), 3);
        verify_anchor_full(&logged, &ledger).expect("the logged anchor verifies");
        assert_eq!(emission.pending.len(), 1);
        cleanup(&emission);
    }

    #[test]
    fn the_hourly_root_seal_follows_the_anchor_and_links_by_digest() {
        let ledger = software_ledger(DEVNET, 1);
        let mut emission = fixture_emission("seal-3600");
        let window = [leaf(1)];
        let outcome = emission
            .on_checkpoint(&request(3_600, &window, &ledger))
            .expect("the 3,600 block checkpoint anchors and seals");
        assert_eq!(
            outcome,
            CheckpointOutcome {
                anchored: true,
                sealed: Some(3_600)
            }
        );
        let seal = emission
            .seals
            .latest()
            .expect("a seal was accepted")
            .clone();
        verify_root_seal(&seal, DEVNET, &ledger, ledger.key_epoch, None)
            .expect("the seal verifies under the ledger seal key");
        assert!(
            emission.pending.is_empty(),
            "the period's anchors are consumed"
        );
        // The seal reached the log next to the anchor log.
        let text = std::fs::read_to_string(seal_log_path(&emission.log_path))
            .expect("the seal log exists");
        assert_eq!(text.lines().count(), 1);

        // A restart resumes from the last logged seal.
        let mut restarted = fixture_emission("seal-3600");
        restarted.log_path = emission.log_path.clone();
        restarted
            .resume_seal_log()
            .expect("the seal log is readable");
        assert_eq!(restarted.seals.latest(), Some(&seal));
        cleanup(&emission);
    }

    #[test]
    fn an_unreadable_seal_log_stops_the_resume() {
        let mut emission = fixture_emission("bad-seal-log");
        let path = seal_log_path(&emission.log_path);
        std::fs::create_dir_all(path.parent().expect("dir")).expect("temp dir");
        std::fs::write(&path, "not a seal\n").expect("write");
        assert_eq!(
            emission.resume_seal_log().unwrap_err(),
            AnchorError::EmissionIo("seal log line")
        );
        cleanup(&emission);
    }

    #[test]
    fn a_rotation_drops_the_production_grant() {
        let mut emission = fixture_emission("rotation");
        let ledger = emission.ledger.clone().expect("fixture ledger");
        emission.production = Some(ProductionGrant {
            ledger_digest: ledger.digest(),
            stark_path_open: false,
        });
        emission
            .install_rotated_keys(2, ledger.anchor_keys.clone(), ledger.seal_keys.clone())
            .expect("epoch 2 follows epoch 1");
        assert!(emission.production.is_none());
        assert_eq!(emission.key_epoch, 2);
        cleanup(&emission);
    }

    #[test]
    fn the_devnet_pipeline_signs_a_verifiable_anchor() {
        let log = temp_log("devnet");
        let mut emission = AnchorEmission::devnet(DEVNET, log).expect("devnet chain id");
        let ledger = emission.ledger.clone().expect("devnet ledger");
        ledger.validate().expect("the devnet ledger is valid");
        let window = [leaf(3)];
        emission
            .on_checkpoint(&request(360, &window, &ledger))
            .expect("devnet anchor");
        let text = std::fs::read_to_string(&emission.log_path).expect("log");
        let anchor: PqAnchor =
            serde_json::from_str(text.lines().next().expect("line")).expect("json");
        verify_anchor_full(&anchor, &ledger).expect("verifies");
        cleanup(&emission);
    }

    fn chain_with(
        chain_id: u64,
        ledger: Option<AnchorKeyLedger>,
    ) -> crate::chain::blockchain::Blockchain {
        let mut genesis = crate::chain::genesis::GenesisConfig::new(chain_id);
        genesis.anchor_ledger = ledger;
        crate::chain::blockchain::Blockchain::new_with_genesis(
            Arc::new(crate::consensus::pow::PoWEngine::new(0)),
            None,
            chain_id,
            None,
            Some(genesis),
        )
    }

    #[test]
    fn the_chain_accepts_only_an_emission_that_matches_its_genesis_ledger() {
        // Genesis without a ledger: devnet derives its own, production cannot start.
        let mut bare = chain_with(DEVNET, None);
        let mut production = fixture_emission("chain-production");
        production.mode = AnchorMode::ProductionApproved;
        assert!(bare.configure_anchor_emission(production.clone()).is_err());
        let devnet = AnchorEmission::devnet(DEVNET, temp_log("chain-devnet")).expect("devnet");
        bare.configure_anchor_emission(devnet.clone())
            .expect("a genesis without a ledger takes the devnet pipeline");
        assert_eq!(bare.anchor_emission.mode, AnchorMode::Devnet);

        // Genesis with a ledger: the emission must carry the same one.
        let ledger = software_ledger(DEVNET, 1);
        let mut pinned = chain_with(DEVNET, Some(ledger.clone()));
        let err = pinned
            .configure_anchor_emission(devnet)
            .expect_err("the devnet ledger is not the genesis ledger");
        assert!(err.contains("not the ledger of the genesis file"));
        let mut matching = fixture_emission("chain-matching");
        matching.mode = AnchorMode::Devnet;
        pinned
            .configure_anchor_emission(matching.clone())
            .expect("the same ledger is accepted");
        cleanup(&matching);
        cleanup(&production);

        // Genesis with a ledger and an emission without one.
        let mut without = fixture_emission("chain-without");
        without.ledger = None;
        assert!(pinned.configure_anchor_emission(without.clone()).is_err());
        cleanup(&without);
    }

    #[test]
    fn software_seal_signer_reports_its_backend() {
        let signer: SoftwareSealSigner = seal_signer();
        assert_eq!(SealSigner::backend(&signer), SignerBackend::Software);
    }
}
