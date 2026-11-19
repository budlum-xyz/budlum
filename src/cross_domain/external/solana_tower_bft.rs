//! Solana Tower BFT (`TowerBFT`) external finality adapter.
//!
//! Solana orders transactions on a Proof-of-History (`PoH`) clock and votes
//! through a tower of exponentially-doubling lockouts (`2^n` slots). A block is
//! **rooted** (irreversibly finalized) once validators holding more than
//! two-thirds of the active stake have voted for it on their towers at the
//! root depth of 32 consecutive confirmations. Unlike Casper or Tendermint,
//! finality is therefore not a single BFT certificate: it is a stake-weighted
//! supermajority of `TowerVote`s, each carrying the voter's `confirmation_count`
//! (lockout level) and `last_voted_slot`.
//!
//! This adapter certifies a **Tower-rooted bank**: the canonical `Bank`
//! digest for `(epoch, slot, bank_hash)` signed by a strict stake supermajority.
//! Honest scope limits, stated plainly:
//!
//! 1. **Pinned epoch stake table**: a governance-pinned snapshot of the active
//!    stake distribution for one Solana epoch binds the evidence. The adapter
//!    never fetches the table; rotating epochs and stake drift are the caller's
//!    re-pinning responsibility. A vote from a validator absent from the pinned
//!    table is refused fail-closed, and a signer whose pinned stake is zero is
//!    refused.
//! 2. **Strict stake supermajority**: the stake of distinct signing vote
//!    accounts must satisfy `3 * signed_stake > 2 * total_stake` (strictly
//!    greater than two-thirds). Ties at exactly two-thirds are refused.
//! 3. **Tower discipline from evidence alone**: every vote must carry
//!    `confirmation_count >= 32` (root threshold, `2^31`-slot lockout) and
//!    `63 >= confirmation_count >= 32` to stop lockout-exponent abuse, and
//!    `last_voted_slot < slot`. Switching to a conflicting fork before lockout
//!    expiry is a slashable offense on Solana; that rule cannot be checked
//!    without history, so cross-fork contradiction detection is delegated to
//!    the `ExternalDomainRegistry` contradiction flow (two conflicting rooted
//!    certificates for the same `slot` mark the domain `Faulted` and slash the
//!    prover), never to silent acceptance of both.
//! 4. **Self-derived bank header**: `header_hash` commits
//!    `(network_id_hash, epoch, slot, parent_slot, bank_hash, parent_bank_hash,
//!    tx_root)`; the verifier re-derives it and refuses on any mismatch. Slots
//!    must fall inside the pinned epoch `[first_slot, last_slot]` and
//!    `parent_slot < slot`.
//! 5. **Hybrid post-quantum non-downgrade**: every validator with a registered
//!    ML-DSA-65 public key MUST attach a valid ML-DSA-65 co-signature under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`]. Ed25519 alone remains valid for
//!    pinned validators that carry no PQ key (Solana mainnet today), and the
//!    attestation reports exactly which combination was checked.
//! 6. **Honest economic disclosure**: Solana mainnet has no in-protocol
//!    slashing today, so `SecurityBacking::SignatureSet` reports
//!    `slashable: pinned.has_bonded_slash_escrow` (callers requiring slashable
//!    backing refuse bare mainnet votes automatically, while Budlum's bonded
//!    prover remains slashable on contradiction).
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! admission/submission/slashing; `AdapterSpec` tag append joins `intake.rs`
//! after concurrent intake hardening merges.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

const ADAPTER_NAME: &str = "solana-tower-bft-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
/// Root threshold: every attesting vote must be locked at this tower level.
const ROOT_CONFIRMATIONS: u8 = 32;
/// Attestation depth reported to consumers (root = 32 confirmations).
const SOL_TOWER_DEPTH: u64 = u64::from(ROOT_CONFIRMATIONS);
/// Lockout exponent ceiling (`2^63` slots) guarding exponent arithmetic.
const MAX_CONFIRMATIONS: u8 = 63;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMSOL1";
const MAX_SOL_PAYLOAD_BYTES: usize = 512 * 1024;
/// Bound on the pinned epoch roster so pinning and stake summation stay bounded.
const MAX_SOL_VALIDATORS: usize = 2048;

/// One vote-account participant of a pinned Solana epoch stake table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaValidator {
    /// Vote account address (32-byte compressed `ed25519` account id).
    pub vote_account: [u8; 32],
    /// Active stake in lamports for this epoch (`> 0`).
    pub stake_lamports: u64,
    /// Classical Ed25519 signing key for votes.
    pub ed25519_pubkey: [u8; 32],
    /// Optional ML-DSA-65 post-quantum key enforced on every vote from this
    /// validator.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned Solana epoch stake table and slot schedule binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSolEpoch {
    /// Canonical genesis hash (base58) the evidence is bound to, e.g. the
    /// mainnet-beta genesis hash. Hashed into every signing root.
    pub genesis_hash_hex: String,
    /// Epoch this stake table belongs to.
    pub epoch: u64,
    /// First slot of the pinned epoch (inclusive).
    pub first_slot: u64,
    /// Last slot of the pinned epoch (inclusive).
    pub last_slot: u64,
    /// True only when every validator is backed by an active external
    /// slashable bond escrow; `false` for bare Solana mainnet stake.
    pub has_bonded_slash_escrow: bool,
    /// Pinned active stake distribution (`1..=2048` vote accounts).
    pub validators: Vec<SolanaValidator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SolBankHeader {
    epoch: u64,
    slot: u64,
    parent_slot: u64,
    bank_hash: Hash32,
    parent_bank_hash: Hash32,
    tx_root: Hash32,
    header_hash: Hash32,
}

impl SolBankHeader {
    #[must_use]
    fn compute_hash(&self, network_id_hash: &Hash32) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SOL_BANK_V1",
            network_id_hash,
            &self.epoch.to_le_bytes(),
            &self.slot.to_le_bytes(),
            &self.parent_slot.to_le_bytes(),
            &self.bank_hash,
            &self.parent_bank_hash,
            &self.tx_root,
        ])
    }
}

/// A rooted `TowerVote` for the header bank. The voted bank is always the
/// header's bank: votes carry no independent bank fields, so a vote can never
/// reference anything other than the header being finalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TowerVoteCertificate {
    vote_account: [u8; 32],
    /// Lockout level on the voter's tower (`32..=63` for a rooted vote).
    confirmation_count: u8,
    /// The voter's last voted slot; must be strictly below `header.slot`.
    last_voted_slot: u64,
    ed25519_sig: Vec<u8>,
    #[serde(default)]
    pq_sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SolanaTowerEvidence {
    bank: SolBankHeader,
    votes: Vec<TowerVoteCertificate>,
}

#[must_use]
fn compute_solana_network_id_hash(network: &str, genesis_hash_hex: &str) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SOL_NET_V1",
        network.as_bytes(),
        genesis_hash_hex.as_bytes(),
    ])
}

#[must_use]
fn vote_sign_bytes(
    network_id_hash: &Hash32,
    epoch: u64,
    slot: u64,
    bank_hash: &Hash32,
    confirmation_count: u8,
    last_voted_slot: u64,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SOL_VOTE_V1",
        network_id_hash,
        &epoch.to_le_bytes(),
        &slot.to_le_bytes(),
        bank_hash,
        &[confirmation_count],
        &last_voted_slot.to_le_bytes(),
    ])
}

#[cfg(test)]
fn encode_sol_evidence(bundle: &SolanaTowerEvidence) -> Result<Vec<u8>, String> {
    let body =
        bincode::serialize(bundle).map_err(|e| format!("solana-tower encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_SOL_PAYLOAD_BYTES {
        return Err(format!(
            "solana-tower payload {total} exceeds ceiling {MAX_SOL_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_sol_evidence(payload: &[u8]) -> Result<SolanaTowerEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Solana Tower payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_SOL_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_SOL_PAYLOAD_BYTES,
            reason: format!("Solana Tower payload exceeds {MAX_SOL_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Solana Tower payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing Solana Tower payload body".into(),
    })?;
    let decoded =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_SOL_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid Solana Tower root evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical Solana Tower root evidence".into(),
        });
    }
    Ok(decoded)
}

/// External finality adapter for Solana Tower BFT rooted-bank finality.
pub struct SolanaTowerBftAdapter {
    network: String,
    pinned: Option<PinnedSolEpoch>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl SolanaTowerBftAdapter {
    /// Construct a `SolanaTowerBftAdapter` bound to `network` and its pinned
    /// epoch stake table.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedSolEpoch>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned.as_ref().map_or(0, |p| p.validators.len() as u64);
        let finality_kind = if pinned.as_ref().is_some_and(|p| p.has_bonded_slash_escrow) {
            FinalityKind::EconomicFinality
        } else {
            FinalityKind::ProtocolFinality
        };
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "solana-tower-bft".into(),
            finality_kind,
            required_depth: SOL_TOWER_DEPTH,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        Self {
            network,
            pinned,
            golden: None,
            descriptor,
        }
    }

    /// Attach a canonical golden sample for [`super::selftest::admit`].
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn validate_pinned(
        pinned: &PinnedSolEpoch,
    ) -> Result<(BTreeMap<[u8; 32], usize>, u128), AdapterError> {
        if pinned.genesis_hash_hex.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana genesis_hash_hex cannot be empty".into(),
            });
        }
        if pinned.first_slot > pinned.last_slot {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana pinned epoch slot range is inverted".into(),
            });
        }
        if pinned.validators.is_empty() || pinned.validators.len() > MAX_SOL_VALIDATORS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Solana pinned epoch roster size {} outside 1..={MAX_SOL_VALIDATORS}",
                    pinned.validators.len()
                ),
            });
        }
        let mut index = BTreeMap::new();
        let mut total_stake: u128 = 0;
        for (idx, validator) in pinned.validators.iter().enumerate() {
            if validator.vote_account == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana vote account cannot be all-zero".into(),
                });
            }
            if validator.stake_lamports == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana validator stake must be non-zero".into(),
                });
            }
            if validator.ed25519_pubkey == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana validator Ed25519 public key cannot be all-zero".into(),
                });
            }
            if !validator.pq_pubkey.is_empty() {
                crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &validator.pq_pubkey)
                    .map_err(|_| AdapterError::ConsensusRule {
                    rule: "invalid ML-DSA-65 public key in pinned Solana epoch".into(),
                })?;
            }
            if index.insert(validator.vote_account, idx).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate vote account in pinned Solana epoch".into(),
                });
            }
            total_stake += u128::from(validator.stake_lamports);
        }
        Ok((index, total_stake))
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Solana Tower network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned Solana epoch stake table configured".into(),
            });
        };
        if policy.require_slashable && !pinned.has_bonded_slash_escrow {
            return Err(AdapterError::ConsensusRule {
                rule: "caller policy requires slashable backing; bare Solana mainnet stake is non-slashable without bonded slash escrow".into(),
            });
        }
        let (index, total_stake) = Self::validate_pinned(pinned)?;

        let decoded = decode_sol_evidence(&evidence.payload)?;
        let bank = &decoded.bank;

        if bank.slot == 0
            || bank.bank_hash == [0u8; 32]
            || bank.tx_root == [0u8; 32]
            || bank.parent_slot >= bank.slot
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana slot, bank_hash, tx_root must be non-zero and parent_slot < slot"
                    .into(),
            });
        }
        if bank.epoch != pinned.epoch
            || bank.slot < pinned.first_slot
            || bank.slot > pinned.last_slot
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana bank slot falls outside the pinned epoch schedule".into(),
            });
        }

        if policy.require_declared_match {
            if evidence.declared_height != bank.slot {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&bank.bank_hash)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        let need_depth = policy.min_depth.max(SOL_TOWER_DEPTH);
        if SOL_TOWER_DEPTH < need_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: SOL_TOWER_DEPTH,
                required: need_depth,
            });
        }
        if policy.max_age > 0 && policy.now > bank.slot {
            let age = policy.now.saturating_sub(bank.slot);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let net_hash = compute_solana_network_id_hash(&self.network, &pinned.genesis_hash_hex);
        let expected_header_hash = bank.compute_hash(&net_hash);
        if !bool::from(bank.header_hash.ct_eq(&expected_header_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana bank header_hash does not match self-derived fields".into(),
            });
        }

        if decoded.votes.is_empty() || decoded.votes.len() > pinned.validators.len() {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Solana Tower vote count {} outside 1..={}",
                    decoded.votes.len(),
                    pinned.validators.len()
                ),
            });
        }

        let mut seen = BTreeSet::new();
        let mut signed_stake: u128 = 0;
        let mut all_pq = true;

        for vote in &decoded.votes {
            if !seen.insert(vote.vote_account) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate vote account in Solana Tower root bundle".into(),
                });
            }
            if vote.confirmation_count < ROOT_CONFIRMATIONS
                || vote.confirmation_count > MAX_CONFIRMATIONS
            {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "Solana Tower vote confirmation_count {} outside {ROOT_CONFIRMATIONS}..={MAX_CONFIRMATIONS}",
                        vote.confirmation_count
                    ),
                });
            }
            if vote.last_voted_slot >= bank.slot {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana Tower vote last_voted_slot must be strictly below header slot"
                        .into(),
                });
            }
            let Some(&idx) = index.get(&vote.vote_account) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana Tower vote signer is not in pinned epoch table".into(),
                });
            };
            let Some(validator) = pinned.validators.get(idx) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "Solana pinned epoch index out of bounds".into(),
                });
            };
            let msg = vote_sign_bytes(
                &net_hash,
                bank.epoch,
                bank.slot,
                &bank.bank_hash,
                vote.confirmation_count,
                vote.last_voted_slot,
            );
            crate::crypto::primitives::verify_signature(
                &msg,
                &vote.ed25519_sig,
                &validator.ed25519_pubkey,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid Ed25519 signature on Solana Tower vote".into(),
            })?;
            if validator.pq_pubkey.is_empty() {
                all_pq = false;
            } else {
                if vote.pq_sig.is_empty() {
                    return Err(AdapterError::Crypto {
                        what: "missing mandatory ML-DSA-65 co-signature on Solana Tower vote"
                            .into(),
                    });
                }
                crate::crypto::primitives::PqKeyPair::verify(
                    &validator.pq_pubkey,
                    crate::crypto::ctx::CROSS_DOMAIN_V1,
                    &msg,
                    &vote.pq_sig,
                )
                .map_err(|_| AdapterError::Crypto {
                    what: "invalid ML-DSA-65 co-signature on Solana Tower vote".into(),
                })?;
            }
            signed_stake += u128::from(validator.stake_lamports);
        }

        // Strict stake supermajority: signed > 2/3 of total pinned stake.
        if 3u128.saturating_mul(signed_stake) <= 2u128.saturating_mul(total_stake) {
            return Err(AdapterError::ConsensusRule {
                rule: "Solana Tower root requires a strict greater-than-two-thirds stake-weighted supermajority".into(),
            });
        }

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let required_stake = total_stake
            .saturating_mul(2)
            .checked_div(3)
            .unwrap_or(u128::MAX)
            .saturating_add(1);
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: bank.slot,
            state_root: bank.bank_hash,
            attested_block_hash: Some(bank.header_hash),
            attested_event_root: None,
            attested_tx_root: Some(bank.tx_root),
            finalized_at: bank.slot,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: u64::try_from(seen.len()).unwrap_or(u64::MAX),
                required: u64::try_from(required_stake).unwrap_or(u64::MAX),
                total_weight: total_stake,
                slashable: pinned.has_bonded_slash_escrow,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for SolanaTowerBftAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, all_pq) = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        vec![
            FaultProbe {
                name: "refuses unsupported Solana Tower evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 6 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign Solana Tower network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-other", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared Solana bank slot".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared Solana bank_hash".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Solana Tower payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x11, 0x22],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses tampered Solana bank slot breaking header hash".into(),
                patch: BytePatch::InPayload {
                    offset: 17,
                    bytes: vec![0xFF, 0x7F],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted Solana Tower vote signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xFE, 0xED, 0xFA, 0xCE],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated Solana Tower payload".into(),
                patch: BytePatch::TruncatePayload { keep: 4 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    const NETWORK: &str = "mainnet-beta";
    const GENESIS_HASH: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    const EPOCH: u64 = 770;
    const FIRST_SLOT: u64 = 332_800_000;
    const LAST_SLOT: u64 = 333_232_639;
    const SLOT: u64 = 333_000_000;

    struct StakeNode {
        ed: KeyPair,
        pq: PqKeyPair,
        vote_account: [u8; 32],
        stake: u64,
    }

    impl StakeNode {
        fn new(seed: u8, stake: u64) -> Self {
            let ed = KeyPair::from_seed(&[seed; 32]).unwrap();
            let mut vote_account = [0u8; 32];
            vote_account[0] = seed;
            vote_account[1] = 0x5A;
            Self {
                ed,
                pq: PqKeyPair::generate(),
                vote_account,
                stake,
            }
        }

        fn id(&self) -> [u8; 32] {
            self.ed.public_key_bytes()
        }

        fn sign_vote(
            &self,
            net_hash: &Hash32,
            slot: u64,
            bank_hash: &Hash32,
            confirmation_count: u8,
            last_voted_slot: u64,
        ) -> TowerVoteCertificate {
            let msg = vote_sign_bytes(
                net_hash,
                EPOCH,
                slot,
                bank_hash,
                confirmation_count,
                last_voted_slot,
            );
            TowerVoteCertificate {
                vote_account: self.vote_account,
                confirmation_count,
                last_voted_slot,
                ed25519_sig: self.ed.sign(&msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                    .unwrap(),
            }
        }
    }

    /// 5 validators with stake 40 / 30 / 15 / 10 / 5 (total 100 units).
    /// Top-3 signers control 85% of stake (strict supermajority); tail-2 hold 15%.
    fn build_tower_fixture(
        slash_escrow: bool,
    ) -> (
        PinnedSolEpoch,
        Vec<StakeNode>,
        SolanaTowerEvidence,
        RawConsensusEvidence,
    ) {
        let nodes: Vec<StakeNode> = vec![
            StakeNode::new(0x11, 40),
            StakeNode::new(0x22, 30),
            StakeNode::new(0x33, 15),
            StakeNode::new(0x44, 10),
            StakeNode::new(0x55, 5),
        ];
        let validators = nodes
            .iter()
            .map(|n| SolanaValidator {
                vote_account: n.vote_account,
                stake_lamports: n.stake,
                ed25519_pubkey: n.id(),
                pq_pubkey: n.pq.public_key_bytes().to_vec(),
            })
            .collect();
        let pinned = PinnedSolEpoch {
            genesis_hash_hex: GENESIS_HASH.into(),
            epoch: EPOCH,
            first_slot: FIRST_SLOT,
            last_slot: LAST_SLOT,
            has_bonded_slash_escrow: slash_escrow,
            validators,
        };

        let net_hash = compute_solana_network_id_hash(NETWORK, GENESIS_HASH);
        let mut bank = SolBankHeader {
            epoch: EPOCH,
            slot: SLOT,
            parent_slot: SLOT - 1,
            bank_hash: [0xB1; 32],
            parent_bank_hash: [0xA0; 32],
            tx_root: [0xC3; 32],
            header_hash: [0; 32],
        };
        bank.header_hash = bank.compute_hash(&net_hash);

        let votes: Vec<TowerVoteCertificate> = nodes[0..3]
            .iter()
            .map(|n| n.sign_vote(&net_hash, SLOT, &bank.bank_hash, 32, SLOT - 32))
            .collect();
        let evidence = SolanaTowerEvidence { bank, votes };
        let payload = encode_sol_evidence(&evidence).unwrap();
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NETWORK.into(),
            payload,
            declared_height: SLOT,
            declared_root: [0xB1; 32],
            submitter: Address::from([0x04; 32]),
        };
        (pinned, nodes, evidence, ev)
    }

    fn vote_at_lockout(
        node: &StakeNode,
        net_hash: &Hash32,
        confirmation_count: u8,
        last_voted_slot: u64,
        bundle: &mut SolanaTowerEvidence,
        ev: &mut RawConsensusEvidence,
    ) {
        bundle.votes = vec![node.sign_vote(
            net_hash,
            bundle.bank.slot,
            &bundle.bank.bank_hash,
            confirmation_count,
            last_voted_slot,
        )];
        ev.payload = encode_sol_evidence(bundle).unwrap();
    }

    #[test]
    fn tower_supermajority_root_attestation_and_selftest() {
        let (pinned, _, _, golden) = build_tower_fixture(false);
        let adapter = SolanaTowerBftAdapter::new(NETWORK, Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: SLOT,
            require_slashable: false,
        };

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, SLOT);
        assert_eq!(att.state_root, [0xB1; 32]);
        assert!(matches!(
            att.security,
            SecurityBacking::SignatureSet {
                signers: 3,
                required: 68,
                total_weight: 100,
                slashable: false,
                ..
            }
        ));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        // Honest disclosure: bare mainnet stake fails require_slashable.
        let mut slash_req = policy.clone();
        slash_req.require_slashable = true;
        assert!(matches!(
            adapter.verify(&golden, &slash_req),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("non-slashable")
        ));

        let report = admit(&adapter, &policy);
        assert!(
            report.admitted,
            "Solana Tower BFT selftest failed: {:?}",
            report.probes
        );
    }

    #[test]
    fn insufficient_stake_and_registry_contradiction_slash_lifecycle() {
        use crate::cross_domain::external::{
            ChallengeReward, DomainEconomics, DomainState, ExternalDomainRegistry, VersionPolicy,
        };

        let (pinned, nodes, bundle_a, ev_a) = build_tower_fixture(true);
        let net_hash = compute_solana_network_id_hash(NETWORK, GENESIS_HASH);
        let adapter = SolanaTowerBftAdapter::new(NETWORK, Some(pinned.clone()));
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: SLOT,
            require_slashable: true,
        };

        // Tail validators (10 + 5 = 15% stake) cannot reach supermajority.
        let mut weak = bundle_a.clone();
        weak.votes = nodes[3..5]
            .iter()
            .map(|n| n.sign_vote(&net_hash, SLOT, &weak.bank.bank_hash, 32, SLOT - 32))
            .collect();
        let mut weak_ev = ev_a.clone();
        weak_ev.payload = encode_sol_evidence(&weak).unwrap();
        assert!(matches!(
            adapter.verify(&weak_ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("supermajority")
        ));

        // Registry lifecycle: submit rooted certificate, contradiction submit
        // must fail, mark_faulted freezes, slash pays challenger.
        let prover = ev_a.submitter;
        let challenger = Address::from([0x94; 32]);
        let mut bundle_b = bundle_a.clone();
        bundle_b.bank.bank_hash = [0x99; 32];
        bundle_b.bank.header_hash = bundle_b.bank.compute_hash(&net_hash);
        bundle_b.votes = nodes[0..3]
            .iter()
            .map(|n| n.sign_vote(&net_hash, SLOT, &bundle_b.bank.bank_hash, 32, SLOT - 32))
            .collect();
        let mut ev_b = ev_a.clone();
        ev_b.declared_root = [0x99; 32];
        ev_b.submitter = challenger;
        ev_b.payload = encode_sol_evidence(&bundle_b).unwrap();

        let adapter = SolanaTowerBftAdapter::new(NETWORK, Some(pinned)).with_golden(ev_a.clone());
        let admission = admit(&adapter, &policy);
        assert!(admission.admitted);

        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            challenge: ChallengeReward {
                bps_of_slash: 1_000,
                floor_atoms: 0,
            },
            ..DomainEconomics::default()
        };
        let req_bond = econ.required_bond_atoms();
        let mut registry = ExternalDomainRegistry::new();
        let domain = registry
            .register(
                NETWORK,
                adapter.descriptor(),
                econ,
                VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0),
                &admission,
                req_bond,
                prover,
            )
            .unwrap();
        registry.bond_prover(&domain, challenger, req_bond).unwrap();

        let att = registry.submit(&adapter, &ev_a, &policy).unwrap();
        assert_eq!(
            registry
                .domain(&domain)
                .unwrap()
                .record
                .crypto_facts
                .count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
            1
        );

        let conflict = adapter.verify(&ev_b, &policy).unwrap();
        assert_eq!(conflict.height, att.height);
        assert_ne!(conflict.state_root, att.state_root);
        assert!(registry.submit(&adapter, &ev_b, &policy).is_err());
        registry
            .mark_faulted(&domain, "Solana Tower double-rooted conflicting banks")
            .unwrap();
        assert_eq!(
            registry.domain(&domain).unwrap().record.state,
            DomainState::Faulted
        );
        let (slashed, reward) = registry
            .slash(
                &domain,
                prover,
                att.evidence_digest,
                econ.routing_ceiling_atoms,
                challenger,
            )
            .unwrap();
        assert!(slashed > 0 && reward > 0 && reward <= slashed);
        assert!(!registry
            .domain(&domain)
            .unwrap()
            .attestations
            .contains_key(&(att.height, EVIDENCE_VERSION)));
    }

    #[test]
    fn tower_lockout_ordering_and_epoch_schedule_fail_closed() {
        let (pinned, nodes, mut bundle, mut ev) = build_tower_fixture(false);
        let net_hash = compute_solana_network_id_hash(NETWORK, GENESIS_HASH);
        let adapter = SolanaTowerBftAdapter::new(NETWORK, Some(pinned.clone()));
        let policy = VerificationPolicy {
            min_depth: 1,
            require_declared_match: true,
            max_age: 1_000,
            now: SLOT,
            require_slashable: false,
        };
        assert!(adapter.verify(&ev, &policy).is_ok());

        // 1. Lockout level below the 32-confirmation root threshold is refused.
        vote_at_lockout(&nodes[0], &net_hash, 31, SLOT - 31, &mut bundle, &mut ev);
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("confirmation_count")
        ));
        // Restore valid evidence.
        bundle.votes =
            vec![nodes[0].sign_vote(&net_hash, SLOT, &bundle.bank.bank_hash, 32, SLOT - 32)];
        ev.payload = encode_sol_evidence(&bundle).unwrap();

        // 2. Voter claiming last_voted_slot >= header slot is refused.
        vote_at_lockout(&nodes[0], &net_hash, 32, SLOT, &mut bundle, &mut ev);
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("last_voted_slot")
        ));
        bundle.votes =
            vec![nodes[0].sign_vote(&net_hash, SLOT, &bundle.bank.bank_hash, 32, SLOT - 32)];
        ev.payload = encode_sol_evidence(&bundle).unwrap();

        // 3. Duplicate vote account in the bundle is refused.
        bundle.votes = vec![
            nodes[0].sign_vote(&net_hash, SLOT, &bundle.bank.bank_hash, 32, SLOT - 32),
            nodes[0].sign_vote(&net_hash, SLOT, &bundle.bank.bank_hash, 32, SLOT - 32),
        ];
        ev.payload = encode_sol_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("duplicate vote account")
        ));

        // 4. Bank slot outside the pinned epoch schedule is refused.
        bundle.bank.slot = FIRST_SLOT - 1;
        bundle.bank.header_hash = bundle.bank.compute_hash(&net_hash);
        ev.declared_height = bundle.bank.slot;
        ev.payload = encode_sol_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("pinned epoch")
        ));
    }
}
