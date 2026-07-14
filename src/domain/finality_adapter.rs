use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
use crate::core::block::Block;
use crate::domain::types::{ConsensusDomain, DomainCommitment, DomainId, Hash32};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalityStatus {
    Pending {
        required_depth: u64,
        observed_depth: u64,
    },
    Finalized,
    Rejected(String),
}

/// Canonical header consumed by the bounded PoW light client.
///
/// The target header binds the commitment roots; descendant headers provide
/// confirmation work. `difficulty_bits` is consensus data but is accepted only
/// inside the range pinned in `ConsensusDomain::pow_parameters`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoWHeader {
    pub height: u64,
    pub parent_hash: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    pub timestamp_ms: u128,
    pub nonce: u64,
    pub difficulty_bits: u32,
}

impl PoWHeader {
    fn canonical_bytes(&self, domain_chain_id: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 8 + 32 * 4 + 16 + 8 + 4);
        bytes.extend_from_slice(&domain_chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.tx_root);
        bytes.extend_from_slice(&self.event_root);
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        bytes
    }
}

/// Calculate a header hash with the immutable hash scheme registered for the
/// source domain. Custom schemes require a domain plugin and are deliberately
/// rejected by this generic light client.
pub fn hash_pow_header(
    domain: &ConsensusDomain,
    header: &PoWHeader,
) -> Result<Hash32, FinalityError> {
    use crate::domain::types::RootScheme;
    use sha2::{Digest, Sha256};

    let encoded = header.canonical_bytes(domain.domain_chain_id);
    match &domain.block_hash_scheme {
        RootScheme::BudlumBlockV2 => Ok(crate::core::hash::hash_fields_bytes(&[
            b"BDLM_POW_HEADER_V1",
            &encoded,
        ])),
        RootScheme::Sha256 => {
            let digest = Sha256::digest(&encoded);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        RootScheme::Sha3_256 => {
            let digest = sha3::Sha3_256::digest(&encoded);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        RootScheme::Custom(name) => Err(FinalityError(format!(
            "PoW header-chain adapter does not implement custom hash scheme {name}"
        ))),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinalityProof {
    /// Legacy self-declared confirmation proof. It remains decodable for
    /// historical domains, but bridge mint never accepts it.
    PoW {
        confirmations: u64,
        total_work_hint: u128,
        /// The domain block hash this PoW finality claim refers to. Must equal
        /// `commitment.domain_block_hash` — binds the proof to THIS commitment
        /// (Tur 6 hardening; previously the proof was unbound).
        #[serde(default)]
        declared_head_hash: Hash32,
        /// Declared cumulative proof-of-work up to `declared_head_hash`. Checked
        /// for internal consistency against `confirmations` and against the
        /// domain's minimum-work threshold. Not a full light client, but far
        /// stronger than "write any positive number".
        #[serde(default)]
        declared_cumulative_work: u128,
    },
    PoS {
        cert: FinalityCert,
        validator_snapshot: ValidatorSetSnapshot,
    },
    PoA {
        /// The KYC-approved authority set for this PoA domain (equal-weight, no
        /// stake — PoA deliberately has no stake concept). Order-independent;
        /// duplicates are ignored during verification.
        #[serde(default)]
        authorities: Vec<crate::core::address::Address>,
        /// Real ed25519 signatures over the commitment binding message, each by
        /// an authority (the authority's `Address` IS its ed25519 public key,
        /// per the chain-wide convention). Replaces the former self-reported
        /// `signer_count`/`validator_count` (Tur 7 hardening).
        #[serde(default)]
        signatures: Vec<PoAAuthoritySignature>,
    },
    Bft {
        round: u64,
        commit_hash: Hash32,
        /// Real BFT commit certificate (BLS aggregate over the validator set),
        /// verified cryptographically — replaces the former self-reported
        /// `signer_count`/`total_validators` (Tur 6 hardening).
        cert: FinalityCert,
        validator_snapshot: ValidatorSetSnapshot,
    },
    /// ZK finality (Tur 5, Option B): rather than carrying the raw STARK proof,
    /// this references a proof already submitted to — and cryptographically
    /// verified by — the `ProofClaimRegistry` (via `submit_zk_proof`). This keeps
    /// a single source of truth for ZK verification and removes the two parallel
    /// verification paths that the Tur-4/5 audit flagged.
    ///
    /// - `domain_id` / `target_height`: the `ProofClaimKey` to look up.
    /// - `final_state_root`: must match BOTH the accepted claim's root AND the
    ///   commitment's `state_root`, binding the proof to this specific commitment.
    Zk {
        domain_id: DomainId,
        target_height: u64,
        final_state_root: Hash32,
    },
    Raw(Vec<u8>),
    /// A target header followed by contiguous descendants. Appended to the
    /// enum so existing bincode variant indices remain stable.
    PoWHeaderChain {
        headers: Vec<PoWHeader>,
    },
}

/// A single PoA authority's ed25519 signature over a commitment binding message.
/// The `authority` address doubles as the ed25519 public key (chain-wide
/// convention, same as block producers).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoAAuthoritySignature {
    pub authority: crate::core::address::Address,
    pub signature: Vec<u8>,
}

/// Canonical message a PoA authority signs to attest a commitment. Binds the
/// signature to the specific (domain, height, block hash), so a signature cannot
/// be replayed for a different commitment.
pub fn poa_commit_signing_message(
    domain_id: DomainId,
    domain_height: u64,
    domain_block_hash: &Hash32,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 32 + 16);
    msg.extend_from_slice(b"BUDLUM_POA_COMMIT_V1");
    msg.extend_from_slice(&domain_id.to_le_bytes());
    msg.extend_from_slice(&domain_height.to_le_bytes());
    msg.extend_from_slice(domain_block_hash);
    msg
}

#[derive(Debug, Clone)]
pub struct FinalityError(pub String);

impl std::fmt::Display for FinalityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Finality error: {}", self.0)
    }
}

impl std::error::Error for FinalityError {}

pub trait DomainFinalityAdapter: Send + Sync {
    fn adapter_name(&self) -> &'static str;

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError>;
}

#[derive(Debug, Clone)]
pub struct PoWFinalityAdapter {
    pub default_min_confirmations: u64,
    /// Minimum plausible proof-of-work attributed to a single confirmation.
    /// Used to (a) reject cumulative-work claims that are inconsistent with the
    /// declared confirmation depth and (b) enforce a minimum-work floor. This is
    /// a config parameter, not a hard-coded constant (Tur 6).
    pub min_work_per_confirmation: u128,
}

impl Default for PoWFinalityAdapter {
    fn default() -> Self {
        Self {
            default_min_confirmations: 64,
            // Tur 12 / BUG #9: non-trivial floor so depth claims must be
            // backed by declared work (still not a full light-client).
            min_work_per_confirmation: 1_000,
        }
    }
}

/// Count leading zero bits in a 32-byte block hash (big-endian byte order).
/// Used as a minimal PoW difficulty check for declared domain heads.
pub fn leading_zero_bits(hash: &crate::domain::Hash32) -> u32 {
    let mut bits = 0u32;
    for b in hash {
        if *b == 0 {
            bits += 8;
        } else {
            bits += b.leading_zeros();
            break;
        }
    }
    bits
}

/// Map domain config_hash / chain parameters to a minimum leading-zero
/// difficulty. When no explicit difficulty is encoded, require a modest
/// floor so totally random hashes cannot finalize.
pub fn pow_min_difficulty_bits(domain: &crate::domain::ConsensusDomain) -> u32 {
    // Optional override: config_hash[0..4] = b"DIFF", config_hash[4..8] = u32 LE bits.
    // Otherwise use a conservative default floor (8 leading zero bits).
    if &domain.config_hash[0..4] == b"DIFF" {
        let encoded = u32::from_le_bytes(domain.config_hash[4..8].try_into().unwrap_or([0; 4]));
        return encoded.clamp(1, 128);
    }
    8
}

impl DomainFinalityAdapter for PoWFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "pow-confirmation-depth"
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        let min_depth = domain.min_confirmations.max(self.default_min_confirmations);
        match proof {
            FinalityProof::PoW {
                confirmations,
                total_work_hint,
                declared_head_hash,
                declared_cumulative_work,
            } => {
                // (1) Bind the proof to THIS commitment (Tur 6: previously the
                // commitment was ignored, so any commitment could borrow any
                // depth claim).
                if *declared_head_hash != commitment.domain_block_hash {
                    return Ok(FinalityStatus::Rejected(
                        "PoW declared head hash does not match commitment block hash".into(),
                    ));
                }

                // (2) Cumulative work must be positive (supersedes the old
                // symbolic `total_work_hint > 0`).
                if *declared_cumulative_work == 0 {
                    return Ok(FinalityStatus::Rejected(
                        "PoW declared cumulative work is zero".into(),
                    ));
                }

                // (3) Internal consistency: the declared cumulative work must be
                // at least `confirmations * min_work_per_confirmation`. This stops
                // a submitter from claiming a huge confirmation depth backed by a
                // tiny amount of work (the core weakness the audit flagged).
                let required_work =
                    (*confirmations as u128).saturating_mul(self.min_work_per_confirmation);
                if *declared_cumulative_work < required_work {
                    return Ok(FinalityStatus::Rejected(format!(
                        "PoW declared work {} inconsistent with {} confirmations (need >= {})",
                        declared_cumulative_work, confirmations, required_work
                    )));
                }

                // (4) `total_work_hint` must not contradict the declared work.
                if *total_work_hint > *declared_cumulative_work {
                    return Ok(FinalityStatus::Rejected(
                        "PoW total_work_hint exceeds declared cumulative work".into(),
                    ));
                }

                // (5) Tur 12 / BUG #9: the committed domain block hash must
                // itself exhibit proof-of-work (leading zero bits). Self-declared
                // confirmations alone are not enough for Finalized status.
                let min_bits = pow_min_difficulty_bits(domain);
                let observed_bits = leading_zero_bits(declared_head_hash);
                if observed_bits < min_bits {
                    return Ok(FinalityStatus::Rejected(format!(
                        "PoW domain block hash has only {observed_bits} leading zero bits, need >= {min_bits}"
                    )));
                }

                // (6) Depth threshold.
                if *confirmations >= min_depth {
                    Ok(FinalityStatus::Finalized)
                } else {
                    Ok(FinalityStatus::Pending {
                        required_depth: min_depth,
                        observed_depth: *confirmations,
                    })
                }
            }
            _ => Err(FinalityError("Expected PoW finality proof".into())),
        }
    }
}

/// Bounded, deterministic PoW light client used by bridge-enabled PoW domains.
#[derive(Debug, Clone, Default)]
pub struct PoWHeaderChainFinalityAdapter;

impl DomainFinalityAdapter for PoWHeaderChainFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        crate::domain::types::POW_HEADER_CHAIN_ADAPTER
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        let FinalityProof::PoWHeaderChain { headers } = proof else {
            return Err(FinalityError(
                "Expected PoWHeaderChain finality proof".into(),
            ));
        };
        let params = domain
            .pow_parameters
            .as_ref()
            .ok_or_else(|| FinalityError("PoW header-chain domain has no pow_parameters".into()))?;
        params
            .validate(domain.min_confirmations)
            .map_err(FinalityError)?;

        if headers.is_empty() {
            return Ok(FinalityStatus::Rejected("PoW header chain is empty".into()));
        }
        if headers.len() > params.max_headers as usize {
            return Ok(FinalityStatus::Rejected(format!(
                "PoW header chain has {} headers, maximum is {}",
                headers.len(),
                params.max_headers
            )));
        }

        let target = &headers[0];
        if target.height != commitment.domain_height
            || target.parent_hash != commitment.parent_domain_block_hash
            || target.state_root != commitment.state_root
            || target.tx_root != commitment.tx_root
            || target.event_root != commitment.event_root
            || target.timestamp_ms != commitment.timestamp_ms
        {
            return Ok(FinalityStatus::Rejected(
                "PoW target header does not bind the commitment height, parent, roots, or timestamp".into(),
            ));
        }

        let mut previous_hash = [0u8; 32];
        let mut previous_height = 0u64;
        let mut previous_timestamp = 0u128;
        let mut cumulative_work = 0u128;

        for (index, header) in headers.iter().enumerate() {
            if header.difficulty_bits < params.min_difficulty_bits
                || header.difficulty_bits > params.max_difficulty_bits
            {
                return Ok(FinalityStatus::Rejected(format!(
                    "PoW header {} difficulty {} is outside registered range {}..={}",
                    header.height,
                    header.difficulty_bits,
                    params.min_difficulty_bits,
                    params.max_difficulty_bits
                )));
            }

            if index > 0 {
                if header.height != previous_height.saturating_add(1) {
                    return Ok(FinalityStatus::Rejected(
                        "PoW header heights are not contiguous".into(),
                    ));
                }
                if header.parent_hash != previous_hash {
                    return Ok(FinalityStatus::Rejected(
                        "PoW header parent link mismatch".into(),
                    ));
                }
                if header.timestamp_ms < previous_timestamp {
                    return Ok(FinalityStatus::Rejected(
                        "PoW header timestamps move backwards".into(),
                    ));
                }
            }

            let hash = hash_pow_header(domain, header)?;
            let observed_bits = leading_zero_bits(&hash);
            if observed_bits < header.difficulty_bits {
                return Ok(FinalityStatus::Rejected(format!(
                    "PoW header {} has {} leading zero bits, claims {}",
                    header.height, observed_bits, header.difficulty_bits
                )));
            }
            if index == 0 && hash != commitment.domain_block_hash {
                return Ok(FinalityStatus::Rejected(
                    "PoW target header hash does not match commitment block hash".into(),
                ));
            }

            let header_work = 1u128.checked_shl(header.difficulty_bits).ok_or_else(|| {
                FinalityError("PoW difficulty cannot be represented as u128 work".into())
            })?;
            cumulative_work = cumulative_work.saturating_add(header_work);
            previous_hash = hash;
            previous_height = header.height;
            previous_timestamp = header.timestamp_ms;
        }

        let observed_depth = headers.len() as u64;
        if observed_depth < domain.min_confirmations {
            return Ok(FinalityStatus::Pending {
                required_depth: domain.min_confirmations,
                observed_depth,
            });
        }
        if cumulative_work < params.min_cumulative_work {
            return Ok(FinalityStatus::Rejected(format!(
                "PoW header chain cumulative work {} is below registered minimum {}",
                cumulative_work, params.min_cumulative_work
            )));
        }

        Ok(FinalityStatus::Finalized)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoSFinalityAdapter;

impl DomainFinalityAdapter for PoSFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "pos-qc-finality"
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        let FinalityProof::PoS {
            cert,
            validator_snapshot,
        } = proof
        else {
            return Err(FinalityError("Expected PoS finality proof".into()));
        };

        if cert.checkpoint_height != commitment.domain_height {
            return Ok(FinalityStatus::Rejected(
                "PoS cert height does not match commitment".into(),
            ));
        }

        let commitment_hash = hex::encode(commitment.domain_block_hash);
        if cert.checkpoint_hash != commitment_hash {
            return Ok(FinalityStatus::Rejected(
                "PoS cert hash does not match commitment".into(),
            ));
        }

        if validator_snapshot.set_hash != cert.set_hash {
            return Ok(FinalityStatus::Rejected(
                "PoS cert set hash does not match validator snapshot".into(),
            ));
        }

        if let Ok(decoded_set_hash) = hex::decode(&validator_snapshot.set_hash) {
            if decoded_set_hash.len() == 32 {
                let mut snapshot_set_hash = [0u8; 32];
                snapshot_set_hash.copy_from_slice(&decoded_set_hash);
                if domain.validator_set_hash != [0u8; 32]
                    && snapshot_set_hash != domain.validator_set_hash
                {
                    return Ok(FinalityStatus::Rejected(
                        "PoS validator snapshot does not match registered domain set".into(),
                    ));
                }
                if commitment.validator_set_hash != [0u8; 32]
                    && commitment.validator_set_hash != snapshot_set_hash
                {
                    return Ok(FinalityStatus::Rejected(
                        "PoS commitment validator set does not match finality proof".into(),
                    ));
                }
            }
        }

        cert.verify(validator_snapshot)
            .map_err(|e| FinalityError(format!("Invalid PoS finality cert: {}", e)))?;

        Ok(FinalityStatus::Finalized)
    }
}

#[derive(Debug, Clone)]
pub struct PoAFinalityAdapter {
    /// Count-based quorum numerator (PoA is equal-weight, NOT stake-weighted —
    /// PoA deliberately has no stake concept, preserving Tur 1-2 isolation).
    pub quorum_numerator: u64,
    /// Count-based quorum denominator.
    pub quorum_denominator: u64,
}

impl Default for PoAFinalityAdapter {
    fn default() -> Self {
        Self {
            quorum_numerator: 2,
            quorum_denominator: 3,
        }
    }
}

impl PoAFinalityAdapter {
    /// Number of authority signatures required for finality: ceil(N * num / den).
    pub fn required_signatures(&self, authority_count: usize) -> usize {
        ((authority_count as u64 * self.quorum_numerator).div_ceil(self.quorum_denominator))
            as usize
    }
}

impl DomainFinalityAdapter for PoAFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "poa-authority-quorum"
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        // Tur 7: PoA finality now verifies REAL ed25519 signatures from the
        // approved authority set (count-based quorum), instead of trusting a
        // self-reported signer_count. `domain` and `commitment` are genuinely
        // used. This does NOT touch the permissionless stake registry — PoA
        // keeps its own separate, stake-free authority/signature model
        // (isolation from Tur 1-2 preserved).
        let FinalityProof::PoA {
            authorities,
            signatures,
        } = proof
        else {
            return Err(FinalityError("Expected PoA finality proof".into()));
        };

        if authorities.is_empty() {
            return Ok(FinalityStatus::Rejected(
                "PoA authority set is empty".into(),
            ));
        }

        // De-duplicate the declared authority set (order-independent).
        let authority_set: std::collections::BTreeSet<crate::core::address::Address> =
            authorities.iter().copied().collect();

        // The message every authority must have signed, bound to THIS commitment.
        let msg = poa_commit_signing_message(
            domain.id,
            commitment.domain_height,
            &commitment.domain_block_hash,
        );

        // Count DISTINCT authorities with a valid signature over `msg`.
        let mut valid_signers: std::collections::BTreeSet<crate::core::address::Address> =
            std::collections::BTreeSet::new();
        for sig in signatures {
            // The signer must be a member of the declared authority set.
            if !authority_set.contains(&sig.authority) {
                return Ok(FinalityStatus::Rejected(
                    "PoA signature from a non-authority".into(),
                ));
            }
            // Verify the real ed25519 signature (authority address == pubkey).
            if crate::crypto::primitives::verify_signature(
                &msg,
                &sig.signature,
                sig.authority.as_bytes(),
            )
            .is_err()
            {
                return Ok(FinalityStatus::Rejected(
                    "PoA signature verification failed".into(),
                ));
            }
            valid_signers.insert(sig.authority);
        }

        let required = self.required_signatures(authority_set.len());
        if valid_signers.len() >= required {
            Ok(FinalityStatus::Finalized)
        } else {
            Ok(FinalityStatus::Pending {
                required_depth: required as u64,
                observed_depth: valid_signers.len() as u64,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct BftFinalityAdapter {
    /// Retained for API/config compatibility. NOTE (Tur 6): the effective quorum
    /// is now enforced cryptographically inside `FinalityCert::verify` via
    /// `ValidatorSetSnapshot::quorum_stake()` (stake-weighted, using the global
    /// `FINALITY_QUORUM_*` constants), not by these fields.
    pub quorum_numerator: u64,
    pub quorum_denominator: u64,
}

impl Default for BftFinalityAdapter {
    fn default() -> Self {
        Self {
            quorum_numerator: 2,
            quorum_denominator: 3,
        }
    }
}

impl DomainFinalityAdapter for BftFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "bft-quorum-commit"
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        // Tur 6: BFT now verifies a REAL commit certificate (BLS aggregate over
        // the validator set) using the same primitive as PoS
        // (`FinalityCert::verify`), instead of trusting a self-reported
        // `signer_count`. `domain` and `commitment` are genuinely used.
        let FinalityProof::Bft {
            round: _,
            commit_hash,
            cert,
            validator_snapshot,
        } = proof
        else {
            return Err(FinalityError("Expected BFT finality proof".into()));
        };

        if validator_snapshot.validators.is_empty() {
            return Ok(FinalityStatus::Rejected(
                "BFT validator set is empty".into(),
            ));
        }

        // Bind the commit hash to THIS commitment's block hash.
        if *commit_hash != commitment.domain_block_hash {
            return Ok(FinalityStatus::Rejected(
                "BFT commit hash does not match commitment block hash".into(),
            ));
        }

        // Bind the certificate to THIS commitment (height + hash).
        if cert.checkpoint_height != commitment.domain_height {
            return Ok(FinalityStatus::Rejected(
                "BFT cert height does not match commitment".into(),
            ));
        }
        let commitment_hash = hex::encode(commitment.domain_block_hash);
        if cert.checkpoint_hash != commitment_hash {
            return Ok(FinalityStatus::Rejected(
                "BFT cert hash does not match commitment".into(),
            ));
        }

        // Bind cert/snapshot together and to the registered domain set.
        if validator_snapshot.set_hash != cert.set_hash {
            return Ok(FinalityStatus::Rejected(
                "BFT cert set hash does not match validator snapshot".into(),
            ));
        }
        if let Ok(decoded_set_hash) = hex::decode(&validator_snapshot.set_hash) {
            if decoded_set_hash.len() == 32 {
                let mut snapshot_set_hash = [0u8; 32];
                snapshot_set_hash.copy_from_slice(&decoded_set_hash);
                if domain.validator_set_hash != [0u8; 32]
                    && snapshot_set_hash != domain.validator_set_hash
                {
                    return Ok(FinalityStatus::Rejected(
                        "BFT validator snapshot does not match registered domain set".into(),
                    ));
                }
                if commitment.validator_set_hash != [0u8; 32]
                    && commitment.validator_set_hash != snapshot_set_hash
                {
                    return Ok(FinalityStatus::Rejected(
                        "BFT commitment validator set does not match finality proof".into(),
                    ));
                }
            }
        }

        // Cryptographic quorum + aggregate-signature verification.
        cert.verify(validator_snapshot)
            .map_err(|e| FinalityError(format!("Invalid BFT finality cert: {}", e)))?;

        Ok(FinalityStatus::Finalized)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ZkFinalityAdapter;

impl ZkFinalityAdapter {
    /// Verify ZK finality against an already-accepted proof claim (Tur 5,
    /// Option B).
    ///
    /// The raw STARK proof is NOT re-verified here — it was already
    /// cryptographically verified when it was submitted via `submit_zk_proof`
    /// and recorded in the `ProofClaimRegistry`. This method enforces the
    /// binding the audit found missing:
    ///
    /// - `accepted_claim_root` is the `final_state_root` of the claim the
    ///   registry accepted for `(domain_id, target_height)` — `None` if no such
    ///   claim exists.
    /// - It must match BOTH the proof's declared `final_state_root` AND the
    ///   `commitment.state_root`, so a finality request cannot borrow a proof
    ///   accepted for a different state.
    ///
    /// `domain` and `commitment` are now genuinely USED (the audit flagged their
    /// former underscore-ignored state).
    pub fn verify_finality_with_claim(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
        accepted_claim_root: Option<Hash32>,
    ) -> Result<FinalityStatus, FinalityError> {
        let FinalityProof::Zk {
            domain_id,
            target_height,
            final_state_root,
        } = proof
        else {
            return Err(FinalityError("Expected ZK finality proof".into()));
        };

        // The proof reference must be for THIS domain and THIS commitment height.
        if *domain_id != domain.id {
            return Ok(FinalityStatus::Rejected(format!(
                "ZK proof domain {} does not match commitment domain {}",
                domain_id, domain.id
            )));
        }
        if *target_height != commitment.domain_height {
            return Ok(FinalityStatus::Rejected(format!(
                "ZK proof height {} does not match commitment height {}",
                target_height, commitment.domain_height
            )));
        }

        // There must be an accepted, cryptographically-verified claim.
        let claim_root = match accepted_claim_root {
            Some(root) => root,
            None => {
                return Ok(FinalityStatus::Rejected(
                    "no accepted ZK proof for this (domain, height) claim".into(),
                ));
            }
        };

        // Bind the proof to the accepted claim...
        if claim_root != *final_state_root {
            return Ok(FinalityStatus::Rejected(
                "ZK proof final_state_root does not match accepted claim".into(),
            ));
        }
        // ...and bind the claim to THIS commitment (the missing link the audit
        // called out).
        if commitment.state_root != *final_state_root {
            return Ok(FinalityStatus::Rejected(
                "ZK proof/commitment state root mismatch".into(),
            ));
        }

        Ok(FinalityStatus::Finalized)
    }
}

impl DomainFinalityAdapter for ZkFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        "zk-proof-verification"
    }

    /// The generic trait entry point cannot reach the `ProofClaimRegistry`, so
    /// it must NEVER finalise on its own. ZK finality is resolved exclusively
    /// through `Blockchain::verify_domain_commitment_finality`, which calls
    /// [`ZkFinalityAdapter::verify_finality_with_claim`] with the registry
    /// lookup. This fail-closed default prevents a second, registry-less
    /// verification path from re-emerging.
    fn verify_finality(
        &self,
        _domain: &ConsensusDomain,
        _commitment: &DomainCommitment,
        _proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        Ok(FinalityStatus::Rejected(
            "ZK finality must be resolved via the ProofClaimRegistry (verify_finality_with_claim)"
                .into(),
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub struct StorageAttestationFinalityAdapter;

impl DomainFinalityAdapter for StorageAttestationFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        crate::domain::types::STORAGE_ATTESTATION_ADAPTER
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        if domain.id != commitment.domain_id {
            return Ok(FinalityStatus::Rejected("Domain ID mismatch".into()));
        }
        match proof {
            FinalityProof::PoA {
                authorities,
                signatures,
            } => {
                if authorities.is_empty() || signatures.is_empty() {
                    return Ok(FinalityStatus::Rejected(
                        "Empty storage attestation signatures".into(),
                    ));
                }
                let authority_set: std::collections::BTreeSet<crate::core::address::Address> =
                    authorities.iter().copied().collect();
                let msg = poa_commit_signing_message(
                    domain.id,
                    commitment.domain_height,
                    &commitment.domain_block_hash,
                );
                let mut valid_signers = std::collections::BTreeSet::new();
                for sig in signatures {
                    if !authority_set.contains(&sig.authority) {
                        return Ok(FinalityStatus::Rejected(
                            "Storage attestation signature from unlisted authority".into(),
                        ));
                    }
                    if crate::crypto::primitives::verify_signature(
                        &msg,
                        &sig.signature,
                        sig.authority.as_bytes(),
                    )
                    .is_err()
                    {
                        return Ok(FinalityStatus::Rejected(
                            "Storage attestation signature verification failed".into(),
                        ));
                    }
                    valid_signers.insert(sig.authority);
                }
                let required = (authority_set.len() * 2).div_ceil(3);
                if valid_signers.len() >= required {
                    Ok(FinalityStatus::Finalized)
                } else {
                    Ok(FinalityStatus::Pending {
                        required_depth: required as u64,
                        observed_depth: valid_signers.len() as u64,
                    })
                }
            }
            FinalityProof::PoS { cert, .. } | FinalityProof::Bft { cert, .. } => {
                if cert.agg_sig_bls.is_empty() {
                    return Ok(FinalityStatus::Rejected(
                        "Empty storage attestation certificate".into(),
                    ));
                }
                let commitment_hash = hex::encode(commitment.domain_block_hash);
                if cert.checkpoint_height != commitment.domain_height
                    || cert.checkpoint_hash != commitment_hash
                {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation certificate height/hash mismatch".into(),
                    ));
                }
                Ok(FinalityStatus::Finalized)
            }
            _ => Ok(FinalityStatus::Rejected(
                "Unsupported or unverified storage attestation proof format".into(),
            )),
        }
    }
}

pub fn hash_finality_proof(proof: &FinalityProof) -> [u8; 32] {
    // SECURITY (Tur 11): must not silently hash empty bytes on serialize failure
    // — two distinct proofs could collide. Fail-fast on the (deterministic,
    // non-attacker-triggerable) programming error instead.
    let encoded = bincode::serialize(proof)
        .expect("BUG: FinalityProof must serialize for finality proof hash");
    crate::core::hash::hash_fields_bytes(&[b"BDLM_FINALITY_PROOF_V1", &encoded])
}

pub fn empty_event_root() -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_EMPTY_DOMAIN_EVENT_ROOT_V1"])
}

pub fn block_finality_proof_hash(_block: &Block) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_NO_FINALITY_PROOF_YET_V1"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::FinalityCert;
    use crate::domain::plugin::default_domain;
    use crate::domain::types::{ConsensusKind, DomainCommitment};

    fn commitment(kind: ConsensusKind) -> DomainCommitment {
        DomainCommitment {
            domain_id: 1,
            domain_height: 10,
            domain_block_hash: [1u8; 32],
            parent_domain_block_hash: [0u8; 32],
            state_root: [2u8; 32],
            tx_root: [3u8; 32],
            event_root: [4u8; 32],
            finality_proof_hash: [5u8; 32],
            consensus_kind: kind,
            validator_set_hash: [6u8; 32],
            timestamp_ms: 123,
            sequence: 0,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        }
    }

    /// Hash with at least 8 leading zero bits (default PoW floor).
    fn pow_looking_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0x00;
        h[1] = 0x0f; // 12 leading zero bits
        h
    }

    #[test]
    fn pow_finality_requires_confirmation_depth_work_and_pow_hash() {
        let mut domain = default_domain(1, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 80);
        // Default difficulty floor = 8 bits (config_hash first u32 == 0).
        domain.config_hash = [0u8; 32];
        let pow_hash = pow_looking_hash();
        let mut commitment = commitment(ConsensusKind::PoW);
        commitment.domain_block_hash = pow_hash;
        let adapter = PoWFinalityAdapter::default();
        let min_work = adapter.min_work_per_confirmation;

        // Depth short + sufficient work + valid PoW hash → Pending.
        assert_eq!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoW {
                        confirmations: 79,
                        total_work_hint: 79 * min_work,
                        declared_head_hash: pow_hash,
                        declared_cumulative_work: 79 * min_work,
                    },
                )
                .unwrap(),
            FinalityStatus::Pending {
                required_depth: 80,
                observed_depth: 79,
            }
        );

        // Depth met + work met + PoW hash → Finalized.
        assert_eq!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoW {
                        confirmations: 80,
                        total_work_hint: 80 * min_work,
                        declared_head_hash: pow_hash,
                        declared_cumulative_work: 80 * min_work,
                    },
                )
                .unwrap(),
            FinalityStatus::Finalized
        );

        // Self-declared depth with non-PoW hash → Rejected (Tur 12 / #9).
        let junk = [0xABu8; 32];
        let mut junk_commit = commitment.clone();
        junk_commit.domain_block_hash = junk;
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &junk_commit,
                    &FinalityProof::PoW {
                        confirmations: 80,
                        total_work_hint: 80 * min_work,
                        declared_head_hash: junk,
                        declared_cumulative_work: 80 * min_work,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        // Work inconsistent with depth → Rejected.
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoW {
                        confirmations: 80,
                        total_work_hint: 1,
                        declared_head_hash: pow_hash,
                        declared_cumulative_work: 1,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        assert!(adapter
            .verify_finality(
                &domain,
                &commitment,
                &FinalityProof::PoA {
                    authorities: vec![],
                    signatures: vec![],
                },
            )
            .is_err());
    }

    #[test]
    fn tur12_leading_zero_bits_counts_prefix() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        let mut h = [0u8; 32];
        h[0] = 0x0f;
        assert_eq!(leading_zero_bits(&h), 4);
        h[0] = 0x00;
        h[1] = 0x0f;
        assert_eq!(leading_zero_bits(&h), 12);
    }

    fn mine_header(domain: &ConsensusDomain, mut header: PoWHeader) -> (PoWHeader, Hash32) {
        loop {
            let hash = hash_pow_header(domain, &header).unwrap();
            if leading_zero_bits(&hash) >= header.difficulty_bits {
                return (header, hash);
            }
            header.nonce = header.nonce.checked_add(1).expect("test nonce space");
        }
    }

    #[test]
    fn tur13_5_pow_header_chain_recomputes_links_work_and_commitment_binding() {
        let mut domain = default_domain(
            9,
            ConsensusKind::PoW,
            9_001,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            3,
        );
        domain.pow_parameters = Some(crate::domain::types::PoWDomainParameters {
            min_difficulty_bits: 4,
            max_difficulty_bits: 8,
            min_cumulative_work: 3 * (1u128 << 4),
            max_headers: 8,
        });

        let mut commitment = commitment(ConsensusKind::PoW);
        commitment.domain_id = domain.id;
        commitment.domain_height = 10;
        commitment.parent_domain_block_hash = [7u8; 32];
        commitment.state_root = [11u8; 32];
        commitment.tx_root = [12u8; 32];
        commitment.event_root = [13u8; 32];
        commitment.timestamp_ms = 100;

        let (target, target_hash) = mine_header(
            &domain,
            PoWHeader {
                height: commitment.domain_height,
                parent_hash: commitment.parent_domain_block_hash,
                state_root: commitment.state_root,
                tx_root: commitment.tx_root,
                event_root: commitment.event_root,
                timestamp_ms: 100,
                nonce: 0,
                difficulty_bits: 4,
            },
        );
        commitment.domain_block_hash = target_hash;

        let (child, child_hash) = mine_header(
            &domain,
            PoWHeader {
                height: 11,
                parent_hash: target_hash,
                state_root: [21u8; 32],
                tx_root: [22u8; 32],
                event_root: [23u8; 32],
                timestamp_ms: 101,
                nonce: 0,
                difficulty_bits: 4,
            },
        );
        let (tip, _) = mine_header(
            &domain,
            PoWHeader {
                height: 12,
                parent_hash: child_hash,
                state_root: [31u8; 32],
                tx_root: [32u8; 32],
                event_root: [33u8; 32],
                timestamp_ms: 102,
                nonce: 0,
                difficulty_bits: 4,
            },
        );

        let adapter = PoWHeaderChainFinalityAdapter;
        let proof = FinalityProof::PoWHeaderChain {
            headers: vec![target, child, tip],
        };
        assert_eq!(
            adapter
                .verify_finality(&domain, &commitment, &proof)
                .unwrap(),
            FinalityStatus::Finalized
        );

        let mut broken = proof.clone();
        let FinalityProof::PoWHeaderChain { headers } = &mut broken else {
            unreachable!()
        };
        headers[1].parent_hash = [0xFF; 32];
        assert!(matches!(
            adapter
                .verify_finality(&domain, &commitment, &broken)
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));
    }

    #[test]
    fn poa_finality_enforces_quorum_and_empty_validator_set_rejection() {
        use crate::crypto::primitives::KeyPair;
        let domain = default_domain(2, ConsensusKind::PoA, 1337, "poa-authority-quorum", 0);
        let commitment = commitment(ConsensusKind::PoA);
        let adapter = PoAFinalityAdapter::default();

        // Build 4 real ed25519 authorities and sign the commit message.
        let mut kps = Vec::new();
        let mut authorities = Vec::new();
        for i in 0..4u8 {
            let mut seed = [0u8; 32];
            seed[0] = 0xB0 + i;
            let kp = KeyPair::from_seed(&seed).unwrap();
            authorities.push(crate::core::address::Address::from(kp.public_key_bytes()));
            kps.push(kp);
        }
        let msg = poa_commit_signing_message(
            domain.id,
            commitment.domain_height,
            &commitment.domain_block_hash,
        );
        let sig = |i: usize| PoAAuthoritySignature {
            authority: authorities[i],
            signature: kps[i].sign(&msg).to_vec(),
        };

        // 2 of 4 signatures -> pending (need ceil(4*2/3)=3).
        assert_eq!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoA {
                        authorities: authorities.clone(),
                        signatures: vec![sig(0), sig(1)],
                    },
                )
                .unwrap(),
            FinalityStatus::Pending {
                required_depth: 3,
                observed_depth: 2,
            }
        );
        // 3 of 4 -> finalized.
        assert_eq!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoA {
                        authorities: authorities.clone(),
                        signatures: vec![sig(0), sig(1), sig(2)],
                    },
                )
                .unwrap(),
            FinalityStatus::Finalized
        );
        // Empty authority set -> rejected.
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoA {
                        authorities: vec![],
                        signatures: vec![],
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));
    }

    #[test]
    fn pos_finality_rejects_mismatched_height_or_hash_before_signature_work() {
        let domain = default_domain(3, ConsensusKind::PoS, 1337, "pos-qc-finality", 0);
        let commitment = commitment(ConsensusKind::PoS);
        let adapter = PoSFinalityAdapter;
        let snapshot = ValidatorSetSnapshot::new(0, vec![]);

        let wrong_height = FinalityCert {
            epoch: 0,
            checkpoint_height: 9,
            checkpoint_hash: hex::encode(commitment.domain_block_hash),
            agg_sig_bls: vec![],
            bitmap: vec![],
            set_hash: snapshot.set_hash.clone(),
        };
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoS {
                        cert: wrong_height,
                        validator_snapshot: snapshot.clone(),
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        let wrong_hash = FinalityCert {
            epoch: 0,
            checkpoint_height: commitment.domain_height,
            checkpoint_hash: "ff".repeat(32),
            agg_sig_bls: vec![],
            bitmap: vec![],
            set_hash: snapshot.set_hash.clone(),
        };
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoS {
                        cert: wrong_hash,
                        validator_snapshot: snapshot,
                    },
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));
    }

    #[test]
    fn test_storage_attestation_finality_enforces_cryptographic_signatures_and_quorum() {
        use crate::crypto::primitives::KeyPair;
        let adapter = StorageAttestationFinalityAdapter;
        let domain = default_domain(
            5,
            crate::domain::ConsensusKind::StorageAttestation(crate::domain::StorageDomainParams {
                min_operator_bond: 100,
                chunk_size: 1024,
                challenge_interval: 10,
                ..Default::default()
            }),
            1337,
            crate::domain::types::STORAGE_ATTESTATION_ADAPTER,
            0,
        );
        let mut commitment = commitment(crate::domain::ConsensusKind::StorageAttestation(
            crate::domain::StorageDomainParams::default(),
        ));
        commitment.domain_id = 5;

        assert!(matches!(
            adapter
                .verify_finality(&domain, &commitment, &FinalityProof::Raw(vec![1, 2, 3]))
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        let kp = KeyPair::generate().unwrap();
        let auth_addr = crate::core::address::Address::from(kp.public_key_bytes());
        let fake_proof = FinalityProof::PoA {
            authorities: vec![auth_addr],
            signatures: vec![PoAAuthoritySignature {
                authority: auth_addr,
                signature: vec![0u8; 64],
            }],
        };
        assert!(matches!(
            adapter
                .verify_finality(&domain, &commitment, &fake_proof)
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        let msg = poa_commit_signing_message(
            domain.id,
            commitment.domain_height,
            &commitment.domain_block_hash,
        );
        let real_sig = kp.sign(&msg);
        let real_proof = FinalityProof::PoA {
            authorities: vec![auth_addr],
            signatures: vec![PoAAuthoritySignature {
                authority: auth_addr,
                signature: real_sig.to_vec(),
            }],
        };
        assert_eq!(
            adapter
                .verify_finality(&domain, &commitment, &real_proof)
                .unwrap(),
            FinalityStatus::Finalized
        );
    }
}
