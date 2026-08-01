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
/// Confirmation work. `difficulty_bits` is consensus data but is accepted only
/// Inside the range pinned in `ConsensusDomain::pow_parameters`.
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
/// Source domain. Custom schemes require a domain plugin and are deliberately
/// Rejected by this generic light client.
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
    PoS {
        cert: FinalityCert,
        validator_snapshot: ValidatorSetSnapshot,
    },
    PoA {
        /// The KYC-approved authority set for this PoA domain (equal-weight, no
        /// Stake - PoA deliberately has no stake concept). Order-independent;
        /// Duplicates are ignored during verification.
        #[serde(default)]
        authorities: Vec<crate::core::address::Address>,
        /// Real ed25519 signatures over the commitment binding message, each by
        /// An authority (the authority's `Address` IS its ed25519 public key,
        /// Per the chain-wide convention). Replaces the former self-reported
        /// `signer_count`/`validator_count` (hardening).
        #[serde(default)]
        signatures: Vec<PoAAuthoritySignature>,
    },
    Bft {
        round: u64,
        commit_hash: Hash32,
        /// Real BFT commit certificate (BLS aggregate over the validator set),
        /// Verified cryptographically - replaces the former self-reported
        /// `signer_count`/`total_validators` (hardening).
        cert: FinalityCert,
        validator_snapshot: ValidatorSetSnapshot,
    },
    /// ZK finality: rather than carrying the raw STARK proof,
    /// This references a proof already submitted to - and cryptographically
    /// Verified by - the `ProofClaimRegistry` (via `submit_zk_proof`). This keeps
    /// A single source of truth for ZK verification and removes the two parallel
    /// Verification paths that audit flagged.
    ///
    /// - `domain_id` / `target_height`: the `ProofClaimKey` to look up.
    /// - `final_state_root`: must match BOTH the accepted claim's root AND the
    ///   Commitment's `state_root`, binding the proof to this specific commitment.
    Zk {
        domain_id: DomainId,
        target_height: u64,
        final_state_root: Hash32,
    },
    Raw(Vec<u8>),
    /// A target header followed by contiguous descendants. Appended to the
    /// Enum so existing bincode variant indices remain stable.
    PoWHeaderChain {
        headers: Vec<PoWHeader>,
    },
}

/// A single PoA authority's ed25519 signature over a commitment binding message.
/// The `authority` address doubles as the ed25519 public key (chain-wide
/// Convention, same as block producers).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoAAuthoritySignature {
    pub authority: crate::core::address::Address,
    pub signature: Vec<u8>,
}

/// Canonical message a PoA authority signs to attest a commitment. Binds the
/// Signature to the specific (domain, height, block hash), so a signature cannot
/// Be replayed for a different commitment.
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
/// Difficulty. When no explicit difficulty is encoded, require a modest
/// Floor so totally random hashes cannot finalize.
pub fn pow_min_difficulty_bits(domain: &crate::domain::ConsensusDomain) -> u32 {
    // Optional override: config_hash[0..4] = b"DIFF", config_hash[4..8] = u32 LE bits.
    // Otherwise use a conservative default floor (8 leading zero bits).
    if &domain.config_hash[0..4] == b"DIFF" {
        let encoded = u32::from_le_bytes(domain.config_hash[4..8].try_into().unwrap_or([0; 4]));
        return encoded.clamp(1, 128);
    }
    8
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
            .map_err(|e| FinalityError(format!("Invalid PoS finality cert: {e}")))?;

        Ok(FinalityStatus::Finalized)
    }
}

#[derive(Debug, Clone)]
pub struct PoAFinalityAdapter {
    /// Count-based quorum numerator (PoA is equal-weight, NOT stake-weighted -
    /// PoA deliberately has no stake concept, preserving-2 isolation).
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

/// Re-derive the `validator_set_hash` a PoA domain would have been registered
/// with, from an authority list carried inside a finality proof.
///
/// A PoA domain records its authority set as a `validator_set_hash` at
/// registration: `genesis.rs` builds one `ValidatorEntry` per authority with
/// `stake: 1` (PoA is equal-weight and has no stake concept), hashes them with
/// `ValidatorSetSnapshot::compute_hash`, and normalises the result. This
/// reproduces that derivation so an adapter can check a proof's claimed
/// authorities against the registered commitment instead of trusting them.
///
/// `compute_hash` sorts by address, so the ordering of `authorities` does not
/// matter, and duplicates must be removed by the caller before hashing -
/// otherwise a proof could pad its list to change the digest.
pub fn poa_authority_set_hash(
    domain: &ConsensusDomain,
    authorities: &[crate::core::address::Address],
) -> Result<Hash32, FinalityError> {
    use crate::chain::finality::ValidatorEntry;

    let entries: Vec<ValidatorEntry> = authorities
        .iter()
        .map(|address| ValidatorEntry {
            address: *address,
            stake: 1,
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: Vec::new(),
        })
        .collect();

    Ok(crate::domain::types::validator_set_commitment(
        b"bootstrap_validator_set_hash",
        domain.id,
        &crate::domain::types::RootScheme::Sha3_256,
        ValidatorSetSnapshot::compute_hash(&entries).as_bytes(),
    ))
}

/// Check a proof's authority set against the one the domain was registered
/// with, returning a rejection reason when they disagree.
///
/// Without this the authority set is whatever the proof says it is: an
/// attacker supplies three keys it controls, signs with two of them, and
/// `ceil(3 * 2 / 3) = 2` is met, so the commitment finalizes. Every
/// stake-weighted adapter here already binds its validator set to
/// `domain.validator_set_hash` (`PoSFinalityAdapter`, `BftFinalityAdapter`,
/// and both certificate branches of `StorageAttestationFinalityAdapter`); the
/// two count-weighted PoA branches were the ones that did not.
///
/// A domain with a zero `validator_set_hash` has no registered set to compare
/// against - the same convention the stake-weighted adapters use - and is left
/// to the quorum check alone.
fn reject_unregistered_poa_authorities(
    domain: &ConsensusDomain,
    authority_set: &std::collections::BTreeSet<crate::core::address::Address>,
    label: &str,
) -> Result<Option<FinalityStatus>, FinalityError> {
    if domain.validator_set_hash == [0u8; 32] {
        return Ok(None);
    }
    let declared: Vec<crate::core::address::Address> = authority_set.iter().copied().collect();
    let derived = poa_authority_set_hash(domain, &declared)?;
    if derived != domain.validator_set_hash {
        return Ok(Some(FinalityStatus::Rejected(format!(
            "{label} authority set does not match the set registered for domain {}",
            domain.id
        ))));
    }
    Ok(None)
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
        // PoA finality now verifies REAL ed25519 signatures from the
        // Approved authority set (count-based quorum), instead of trusting a
        // Self-reported signer_count. `domain` and `commitment` are genuinely
        // Used. This does NOT touch the permissionless stake registry - PoA
        // Keeps its own separate, stake-free authority/signature model
        // (isolation preserved).
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

        // The authority set arrives inside the proof, and the quorum is a
        // fraction of its size, so an unbound set lets a proof choose its own
        // denominator. Bind it to the set the domain registered.
        if let Some(rejected) = reject_unregistered_poa_authorities(domain, &authority_set, "PoA")?
        {
            return Ok(rejected);
        }

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
    /// Retained for API/config compatibility. NOTE: the effective quorum
    /// Is now enforced cryptographically inside `FinalityCert::verify` via
    /// `ValidatorSetSnapshot::quorum_stake` (stake-weighted, using the global
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
        // BFT now verifies a REAL commit certificate (BLS aggregate over
        // The validator set) using the same primitive as PoS
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
            .map_err(|e| FinalityError(format!("Invalid BFT finality cert: {e}")))?;

        Ok(FinalityStatus::Finalized)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ZkFinalityAdapter;

impl ZkFinalityAdapter {
    /// Verify ZK finality against an already-accepted proof claim (
    /// Option B).
    ///
    /// The raw STARK proof is NOT re-verified here - it was already
    /// Cryptographically verified when it was submitted via `submit_zk_proof`
    /// And recorded in the `ProofClaimRegistry`. This method enforces the
    /// Binding the audit found missing:
    ///
    /// - `accepted_claim_root` is the `final_state_root` of the claim the
    ///   Registry accepted for `(domain_id, target_height)` - `None` if no such
    ///   Claim exists.
    /// - It must match BOTH the proof's declared `final_state_root` AND the
    ///   `commitment.state_root`, so a finality request cannot borrow a proof
    ///   Accepted for a different state.
    ///
    /// `domain` and `commitment` are now genuinely USED (the audit flagged their
    /// Former underscore-ignored state).
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
        // Called out).
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
    /// It must NEVER finalise on its own. ZK finality is resolved exclusively
    /// Through `Blockchain::verify_domain_commitment_finality`, which calls
    /// [`ZkFinalityAdapter::verify_finality_with_claim`] with the registry
    /// Lookup. This fail-closed default prevents a second, registry-less
    /// Verification path from re-emerging.
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
                // Same binding as the plain PoA adapter: the attesting set has
                // to be the one the domain registered, not the one the proof
                // nominates for itself.
                if let Some(rejected) = reject_unregistered_poa_authorities(
                    domain,
                    &authority_set,
                    "Storage attestation",
                )? {
                    return Ok(rejected);
                }
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
            FinalityProof::PoS {
                cert,
                validator_snapshot,
            } => {
                // Real PoS verification - same checks as
                // PosFinalityAdapter (lines 470-525). Previously this branch only
                // Checked agg_sig_bls.is_empty and height/hash match, which
                // Allowed a fake agg_sig_bls to pass if height/hash matched.
                if validator_snapshot.validators.is_empty() {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation PoS validator set is empty".into(),
                    ));
                }
                if cert.checkpoint_height != commitment.domain_height {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation PoS cert height mismatch".into(),
                    ));
                }
                let commitment_hash = hex::encode(commitment.domain_block_hash);
                if cert.checkpoint_hash != commitment_hash {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation PoS cert hash mismatch".into(),
                    ));
                }
                if validator_snapshot.set_hash != cert.set_hash {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation PoS cert set hash does not match validator snapshot"
                            .into(),
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
                                "Storage attestation PoS validator snapshot does not match registered domain set".into(),
                            ));
                        }
                        if commitment.validator_set_hash != [0u8; 32]
                            && commitment.validator_set_hash != snapshot_set_hash
                        {
                            return Ok(FinalityStatus::Rejected(
                                "Storage attestation PoS commitment validator set does not match finality proof".into(),
                            ));
                        }
                    }
                }
                cert.verify(validator_snapshot).map_err(|e| {
                    FinalityError(format!(
                        "Invalid storage attestation PoS finality cert: {e}"
                    ))
                })?;
                Ok(FinalityStatus::Finalized)
            }
            FinalityProof::Bft {
                round: _,
                commit_hash,
                cert,
                validator_snapshot,
            } => {
                // Real BFT verification - same checks as
                // BftFinalityAdapter (lines 665-730). Previously this branch only
                // Checked agg_sig_bls.is_empty and height/hash match.
                if validator_snapshot.validators.is_empty() {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation BFT validator set is empty".into(),
                    ));
                }
                if *commit_hash != commitment.domain_block_hash {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation BFT commit hash does not match commitment".into(),
                    ));
                }
                if cert.checkpoint_height != commitment.domain_height {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation BFT cert height mismatch".into(),
                    ));
                }
                let commitment_hash = hex::encode(commitment.domain_block_hash);
                if cert.checkpoint_hash != commitment_hash {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation BFT cert hash mismatch".into(),
                    ));
                }
                if validator_snapshot.set_hash != cert.set_hash {
                    return Ok(FinalityStatus::Rejected(
                        "Storage attestation BFT cert set hash does not match validator snapshot"
                            .into(),
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
                                "Storage attestation BFT validator snapshot does not match registered domain set".into(),
                            ));
                        }
                        if commitment.validator_set_hash != [0u8; 32]
                            && commitment.validator_set_hash != snapshot_set_hash
                        {
                            return Ok(FinalityStatus::Rejected(
                                "Storage attestation BFT commitment validator set does not match finality proof".into(),
                            ));
                        }
                    }
                }
                cert.verify(validator_snapshot).map_err(|e| {
                    FinalityError(format!(
                        "Invalid storage attestation BFT finality cert: {e}"
                    ))
                })?;
                Ok(FinalityStatus::Finalized)
            }
            _ => Ok(FinalityStatus::Rejected(
                "Unsupported or unverified storage attestation proof format".into(),
            )),
        }
    }
}

/// Finality for the AI inference attestation domain.
///
/// AI verifiers stake and attest to inference results; agreement at the
/// domain's threshold produces an `AiInferenceOutcome` that reaches the
/// settlement layer through `GlobalBlockHeader::ai_root`. At this layer the
/// question is the same one every other attestation domain answers: did
/// enough registered attesters sign *this* commitment.
///
/// This exists as its own type rather than reusing
/// [`StorageAttestationFinalityAdapter`] because of the name. Registration
/// requires `finality_adapter == "ai-inference-threshold"`
/// (`blockchain.rs`), and the runtime path re-checks the selected adapter's
/// `adapter_name()` against that same field. Pointing the `AiInference` arm at
/// the storage adapter meant comparing `"ai-inference-threshold"` against
/// `"storage-attestation-v1"`, which never matches - so an `AiInference`
/// domain could be registered but not one of its commitments could ever
/// finalize. Measured across all seven kinds, it was the only disagreeing
/// pair:
///
/// ```text
/// PoW                kayit=pow-header-chain-v1    runtime=pow-header-chain-v1    OK
/// PoS                kayit=pos-qc-finality        runtime=pos-qc-finality        OK
/// PoA                kayit=poa-authority-quorum   runtime=poa-authority-quorum   OK
/// Bft                kayit=bft-quorum-commit      runtime=bft-quorum-commit      OK
/// Zk                 kayit=zk-proof-verification  runtime=zk-proof-verification  OK
/// StorageAttestation kayit=storage-attestation-v1 runtime=storage-attestation-v1 OK
/// AiInference        kayit=ai-inference-threshold runtime=storage-attestation-v1 CELISKI
/// ```
///
/// The same class of dead wiring was already found and fixed once in the `Zk`
/// arm, which used to call a trait method that always rejected.
#[derive(Debug, Clone, Default)]
pub struct AiInferenceFinalityAdapter;

impl DomainFinalityAdapter for AiInferenceFinalityAdapter {
    fn adapter_name(&self) -> &'static str {
        crate::domain::types::AI_INFERENCE_ADAPTER
    }

    fn verify_finality(
        &self,
        domain: &ConsensusDomain,
        commitment: &DomainCommitment,
        proof: &FinalityProof,
    ) -> Result<FinalityStatus, FinalityError> {
        // Attestation shape is identical to storage: a set of registered
        // signers over the commitment binding message, at a count quorum. The
        // AI-specific agreement threshold is enforced where the outcome is
        // produced (`AiRegistry`); this layer checks that the commitment
        // carrying it is attested by the domain's registered set.
        StorageAttestationFinalityAdapter.verify_finality(domain, commitment, proof)
    }
}

pub fn hash_finality_proof(proof: &FinalityProof) -> [u8; 32] {
    // SECURITY: must not silently hash empty bytes on serialize failure
    // Two distinct proofs could collide. Fail-fast on the (deterministic,
    // Non-attacker-triggerable) programming error instead.
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

    #[test]
    fn pow_header_chain_rejects_empty_or_short_chain_d3() {
        // The ONLY PoW finality path left is the bounded
        // PoWHeaderChain. The legacy self-declared `FinalityProof::PoW` variant
        // Was removed from the production ISA - a PoW domain finalizes solely
        // Via `PoWHeaderChainFinalityAdapter`.
        let mut domain = default_domain(
            1,
            ConsensusKind::PoW,
            45262,
            crate::domain::types::POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        domain.config_hash = [0u8; 32];
        domain.pow_parameters = Some(crate::domain::types::PoWDomainParameters {
            min_difficulty_bits: 4,
            max_difficulty_bits: 8,
            min_cumulative_work: 1,
            max_headers: 8,
        });
        let commitment = commitment(ConsensusKind::PoW);
        let adapter = PoWHeaderChainFinalityAdapter;

        // Empty header chain must be rejected (bounded, not self-declared).
        assert!(matches!(
            adapter
                .verify_finality(
                    &domain,
                    &commitment,
                    &FinalityProof::PoWHeaderChain { headers: vec![] }
                )
                .unwrap(),
            FinalityStatus::Rejected(_)
        ));

        // A non-PoW proof type is rejected by the PoW adapter. The adapter
        // Returns Err for an unexpected proof variant, so accept both
        // Err (rejection) and Ok(FinalityStatus::Rejected(_)).
        let non_pow = adapter.verify_finality(
            &domain,
            &commitment,
            &FinalityProof::PoA {
                authorities: vec![],
                signatures: vec![],
            },
        );
        assert!(
            matches!(non_pow, Err(_) | Ok(FinalityStatus::Rejected(_))),
            "non-PoW proof must be rejected, got: {:?}",
            non_pow
        );
    }

    #[test]
    fn leading_zero_bits_counts_prefix() {
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
    fn pow_header_chain_recomputes_links_work_and_commitment_binding() {
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
        let domain = default_domain(2, ConsensusKind::PoA, 45262, "poa-authority-quorum", 0);
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
        let domain = default_domain(3, ConsensusKind::PoS, 45262, "pos-qc-finality", 0);
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
            45262,
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
