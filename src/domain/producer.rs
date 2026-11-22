//! Producer kits for `PoW`, BFT and `PoA` domains.
//!
//! BFT and `PoA` kits sign with keys the caller loads: a BFT validator's BLS key
//! (and its ML-DSA-65 key for the QC half), a `PoA` authority's composite key.
//! The kits never read a key from disk themselves.
//!
//! A `PoW` domain finalizes on Budlum only through the bounded header-chain
//! light client (`PoWHeaderChainFinalityAdapter`): a target header that binds
//! the commitment, followed by enough contiguous descendants to reach the
//! domain's confirmation depth and registered work. This module builds that
//! proof and the commitment it binds, so a producer submits exactly what the
//! block will verify. It writes no state; the block verifies the proof again.

use crate::core::address::Address;
use crate::domain::finality_adapter::{
    decode_compact_bits, hash_finality_proof, hash_pow_header, leading_zero_bits,
    target_leading_zero_bits, BitcoinHeader, FinalityProof, PoWHeader,
};
use crate::domain::types::{ConsensusDomain, DomainCommitment, Hash32, VerifiedDomainCommitment};
use serde::{Deserialize, Serialize};

/// The content of one domain block: what its header commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// WIRING: domain surface - the producer/registry doors that read it land with their wiring.
pub struct PowBlockContent {
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    pub timestamp_ms: u128,
}

/// What a producer needs to build one `PoW` commitment: the registered domain,
/// the parent of the target block, the target height, and the target block
/// followed by its descendants (the confirmation headers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowChainSpec {
    pub domain: ConsensusDomain,
    pub parent_hash: Hash32,
    pub height: u64,
    pub difficulty_bits: u32,
    pub sequence: u64,
    pub producer: Option<Address>,
    pub blocks: Vec<PowBlockContent>,
}

/// The nonce search bound: past it the difficulty is not one a producer can
/// meet, and the search refuses instead of spinning.
/// WIRING: domain surface - the producer/registry doors that read it land with their wiring.
pub const MAX_NONCE_ATTEMPTS: u64 = 1 << 32;

/// Mine `header` until its hash meets its own `difficulty_bits` under the
/// domain's hash scheme. Returns the header with its nonce and its hash.
///
/// # Errors
///
/// The domain's hash scheme is not one the light client implements, or no
/// nonce within [`MAX_NONCE_ATTEMPTS`] meets the difficulty.
/// WIRING: domain surface - the producer/registry doors that read it land with their wiring.
pub fn mine_pow_header(
    domain: &ConsensusDomain,
    mut header: PoWHeader,
) -> Result<(PoWHeader, Hash32), String> {
    for _ in 0..MAX_NONCE_ATTEMPTS {
        let hash = hash_pow_header(domain, &header).map_err(|e| e.to_string())?;
        if leading_zero_bits(&hash) >= header.difficulty_bits {
            return Ok((header, hash));
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| "PoW nonce space exhausted".to_string())?;
    }
    Err(format!(
        "no nonce within {MAX_NONCE_ATTEMPTS} attempts meets {} difficulty bits",
        header.difficulty_bits
    ))
}

/// Build the commitment and its header-chain proof from a [`PowChainSpec`].
///
/// # Errors
///
/// An empty block list, a difficulty outside the domain's registered range,
/// a domain without `PoW` parameters, or a header that cannot be mined.
pub fn build_pow_commitment(spec: &PowChainSpec) -> Result<VerifiedDomainCommitment, String> {
    let params = spec
        .domain
        .pow_parameters
        .as_ref()
        .ok_or_else(|| "the domain has no pow_parameters".to_string())?;
    if spec.difficulty_bits < params.min_difficulty_bits
        || spec.difficulty_bits > params.max_difficulty_bits
    {
        return Err(format!(
            "difficulty {} is outside the registered range {}..={}",
            spec.difficulty_bits, params.min_difficulty_bits, params.max_difficulty_bits
        ));
    }
    let target = spec
        .blocks
        .first()
        .ok_or_else(|| "a PoW commitment needs at least its target block".to_string())?;

    let mut headers = Vec::with_capacity(spec.blocks.len());
    let mut target_hash = [0u8; 32];
    let mut parent = spec.parent_hash;
    let mut height = spec.height;
    for (index, block) in spec.blocks.iter().enumerate() {
        let (header, hash) = mine_pow_header(
            &spec.domain,
            PoWHeader {
                height,
                parent_hash: parent,
                state_root: block.state_root,
                tx_root: block.tx_root,
                event_root: block.event_root,
                timestamp_ms: block.timestamp_ms,
                nonce: 0,
                difficulty_bits: spec.difficulty_bits,
            },
        )?;
        if index == 0 {
            target_hash = hash;
        }
        headers.push(header);
        parent = hash;
        height = height
            .checked_add(1)
            .ok_or_else(|| "PoW header height overflows".to_string())?;
    }

    let proof = FinalityProof::PoWHeaderChain { headers };
    let finality_proof_hash = hash_finality_proof(&proof).map_err(|e| e.to_string())?;
    let commitment = DomainCommitment {
        domain_id: spec.domain.id,
        domain_height: spec.height,
        domain_block_hash: target_hash,
        parent_domain_block_hash: spec.parent_hash,
        state_root: target.state_root,
        tx_root: target.tx_root,
        event_root: target.event_root,
        finality_proof_hash,
        consensus_kind: spec.domain.kind.clone(),
        validator_set_hash: spec.domain.validator_set_hash,
        timestamp_ms: target.timestamp_ms,
        sequence: spec.sequence,
        producer: spec.producer,
        state_updates: std::collections::BTreeMap::new(),
    };
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// Content fields a single Bitcoin header commits to (`merkle_root`, timestamp, version, bits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinBlockContent {
    pub version: i32,
    pub merkle_root: Hash32,
    pub timestamp: u32,
    pub bits: u32,
}

/// Producer input for building a contiguous Bitcoin SPV commitment and header window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinSpvChainSpec {
    pub domain: ConsensusDomain,
    pub parent_hash: Hash32,
    pub height: u64,
    pub sequence: u64,
    pub producer: Option<Address>,
    pub blocks: Vec<BitcoinBlockContent>,
}

/// Mine a [`BitcoinHeader`] until its little-endian `SHA256d` hash meets its compact `bits` target.
fn mine_bitcoin_header(mut header: BitcoinHeader) -> Result<(BitcoinHeader, Hash32), String> {
    let (target, _) = decode_compact_bits(header.bits)
        .ok_or_else(|| format!("malformed compact bits {:#010x}", header.bits))?;
    loop {
        let hash = header.block_hash();
        let mut be = hash;
        be.reverse();
        if be.as_slice() <= target.as_slice() {
            return Ok((header, hash));
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| "Bitcoin nonce space exhausted".to_string())?;
    }
}

/// Build a `bitcoin-spv-v1` [`VerifiedDomainCommitment`] from a [`BitcoinSpvChainSpec`].
///
/// # Errors
///
/// Returns an error if the domain is not `bitcoin-spv-v1`, lacks valid `pow_parameters`,
/// has an empty block window, has out-of-range header difficulty, or cannot mine a block.
pub fn build_bitcoin_spv_commitment(
    spec: &BitcoinSpvChainSpec,
) -> Result<VerifiedDomainCommitment, String> {
    if spec.domain.finality_adapter != crate::domain::types::BITCOIN_SPV_ADAPTER {
        return Err(format!(
            "domain {} uses adapter {}, expected {}",
            spec.domain.id,
            spec.domain.finality_adapter,
            crate::domain::types::BITCOIN_SPV_ADAPTER
        ));
    }
    let params = spec
        .domain
        .pow_parameters
        .as_ref()
        .ok_or_else(|| "the domain has no pow_parameters".to_string())?;
    let target_block = spec
        .blocks
        .first()
        .ok_or_else(|| "a Bitcoin SPV commitment needs at least its target block".to_string())?;
    let mut headers = Vec::with_capacity(spec.blocks.len());
    let mut target_hash = [0u8; 32];
    let mut parent = spec.parent_hash;
    let mut height = spec.height;
    let mut prev_timestamp = 0u32;
    for (index, block) in spec.blocks.iter().enumerate() {
        let (decoded_target, _) = decode_compact_bits(block.bits)
            .ok_or_else(|| format!("malformed compact bits {:#010x}", block.bits))?;
        let required_leading = target_leading_zero_bits(&decoded_target);
        if required_leading < params.min_difficulty_bits
            || required_leading > params.max_difficulty_bits
        {
            return Err(format!(
                "difficulty {} is outside the registered range {}..={}",
                required_leading, params.min_difficulty_bits, params.max_difficulty_bits
            ));
        }
        if index > 0 && block.timestamp < prev_timestamp {
            return Err("Bitcoin header timestamps move backwards".to_string());
        }
        let (header, hash) = mine_bitcoin_header(BitcoinHeader {
            version: block.version,
            prev_hash: parent,
            merkle_root: block.merkle_root,
            timestamp: block.timestamp,
            bits: block.bits,
            nonce: 0,
            height,
        })?;
        if index == 0 {
            target_hash = hash;
        }
        headers.push(header);
        parent = hash;
        height = height
            .checked_add(1)
            .ok_or_else(|| "Bitcoin header height overflows".to_string())?;
        prev_timestamp = block.timestamp;
    }
    let proof = FinalityProof::BitcoinSpv { headers };
    let finality_proof_hash = hash_finality_proof(&proof).map_err(|e| e.to_string())?;
    let commitment = DomainCommitment {
        domain_id: spec.domain.id,
        domain_height: spec.height,
        domain_block_hash: target_hash,
        parent_domain_block_hash: spec.parent_hash,
        state_root: [0u8; 32],
        tx_root: target_block.merkle_root,
        event_root: [0u8; 32],
        finality_proof_hash,
        consensus_kind: spec.domain.kind.clone(),
        validator_set_hash: spec.domain.validator_set_hash,
        timestamp_ms: u128::from(target_block.timestamp) * 1000,
        sequence: spec.sequence,
        producer: spec.producer,
        state_updates: std::collections::BTreeMap::new(),
    };
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// The block a BFT or `PoA` domain finalized, as its producer states it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumBlockSpec {
    pub domain: ConsensusDomain,
    pub height: u64,
    pub block_hash: Hash32,
    pub parent_hash: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    pub timestamp_ms: u128,
    pub sequence: u64,
    pub producer: Option<Address>,
}

/// One BFT validator a producer signs for: its snapshot entry, its BLS key
/// and, for the post-quantum half, its ML-DSA-65 key.
pub struct BftMember {
    pub entry: crate::chain::finality::ValidatorEntry,
    pub bls: crate::crypto::primitives::BlsKeypair,
    pub pq: Option<crate::crypto::primitives::PqKeyPair>,
}

fn commitment_for(
    spec: &QuorumBlockSpec,
    proof: &FinalityProof,
    validator_set_hash: Hash32,
) -> Result<DomainCommitment, String> {
    Ok(DomainCommitment {
        domain_id: spec.domain.id,
        domain_height: spec.height,
        domain_block_hash: spec.block_hash,
        parent_domain_block_hash: spec.parent_hash,
        state_root: spec.state_root,
        tx_root: spec.tx_root,
        event_root: spec.event_root,
        finality_proof_hash: hash_finality_proof(proof).map_err(|e| e.to_string())?,
        consensus_kind: spec.domain.kind.clone(),
        validator_set_hash,
        timestamp_ms: spec.timestamp_ms,
        sequence: spec.sequence,
        producer: spec.producer,
        state_updates: std::collections::BTreeMap::new(),
    })
}

/// Build a BFT commitment: the BLS certificate of `signers` (indices into
/// `members`) over the checkpoint `(chain_id, epoch, height, hash)`, and,
/// when every signer holds an ML-DSA-65 key, their QC over the same
/// checkpoint (`FinalityProof::BftPq`, the form mainnet requires).
///
/// # Errors
///
/// No signer, an index out of range, a malformed BLS signature, or a PQ
/// signing failure.
pub fn build_bft_commitment(
    spec: &QuorumBlockSpec,
    chain_id: u64,
    epoch: u64,
    round: u64,
    members: &[BftMember],
    signers: &[usize],
) -> Result<VerifiedDomainCommitment, String> {
    use bls12_381::{G1Affine, G1Projective};
    if signers.is_empty() {
        return Err("a BFT certificate needs at least one signer".into());
    }
    let snapshot = crate::chain::finality::ValidatorSetSnapshot::new(
        epoch,
        members.iter().map(|m| m.entry.clone()).collect(),
    );
    let checkpoint_hash = hex::encode(spec.block_hash);
    let message = crate::chain::finality::checkpoint_signing_message(
        chain_id,
        epoch,
        spec.height,
        &checkpoint_hash,
    );
    let mut aggregate = G1Projective::identity();
    let mut bitmap = vec![0u8; members.len().div_ceil(8)];
    let mut entries = Vec::new();
    for &index in signers {
        let member = members
            .get(index)
            .ok_or_else(|| format!("signer index {index} is out of range"))?;
        let signature = crate::chain::finality::sign_bls(&member.bls.secret_key, &message);
        let bytes: [u8; 48] = signature
            .as_slice()
            .try_into()
            .map_err(|_| "a BLS signature is not 48 bytes".to_string())?;
        let point = Option::<G1Affine>::from(G1Affine::from_compressed(&bytes))
            .ok_or_else(|| "a BLS signature does not decode".to_string())?;
        aggregate += G1Projective::from(point);
        bitmap[index / 8] |= 1 << (index % 8);
        if let Some(pq) = &member.pq {
            // The domain validator's own PQ signing path: its key, the QC
            // message of this checkpoint, the QC context.
            let validator_index =
                u32::try_from(index).map_err(|_| "signer index too large".to_string())?;
            let message = crate::consensus::qc::pq_signing_message(
                epoch,
                spec.height,
                &checkpoint_hash,
                validator_index,
            );
            let pq_signature = pq
                .sign(crate::crypto::ctx::QC_V2, &message)
                .map_err(|e| format!("PQ sign failed: {e}"))?;
            entries.push(crate::consensus::qc::PqSignatureEntry {
                validator_index,
                validator_address: member.entry.address.to_string(),
                pq_signature,
            });
        }
    }
    let cert = crate::chain::finality::FinalityCert {
        epoch,
        checkpoint_height: spec.height,
        checkpoint_hash: checkpoint_hash.clone(),
        chain_id,
        agg_sig_bls: G1Affine::from(aggregate).to_compressed().to_vec(),
        bitmap,
        set_hash: snapshot.set_hash.clone(),
        seat_table_version: 0,
    };
    let set_hash: Hash32 = hex::decode(&snapshot.set_hash)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "the snapshot set hash is not 32 bytes".to_string())?;
    let proof = if entries.len() == signers.len() {
        FinalityProof::BftPq {
            round,
            commit_hash: spec.block_hash,
            cert,
            validator_snapshot: snapshot,
            qc: crate::consensus::qc::QcBlob::new(epoch, spec.height, checkpoint_hash, entries),
        }
    } else {
        FinalityProof::Bft {
            round,
            commit_hash: spec.block_hash,
            cert,
            validator_snapshot: snapshot,
        }
    };
    let commitment = commitment_for(spec, &proof, set_hash)?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// Build a `PoA` commitment with composite authority signatures
///. `authorities` is the whole registered
/// set; `signers` are the key pairs that sign (each must be in the set).
///
/// # Errors
///
/// A signer outside the set, or a key that cannot sign.
fn unsigned_commitment_for(
    spec: &QuorumBlockSpec,
    consensus_kind: crate::domain::ConsensusKind,
) -> DomainCommitment {
    // The producer signs the same state-updates map the verifier will fold in.
    // A commitment built here carries none: the writes it would attest are the
    // relayer's claim and belong to the settlement door, not to this builder.
    DomainCommitment {
        domain_id: spec.domain.id,
        domain_height: spec.height,
        domain_block_hash: spec.block_hash,
        parent_domain_block_hash: spec.parent_hash,
        state_root: spec.state_root,
        tx_root: spec.tx_root,
        event_root: spec.event_root,
        finality_proof_hash: [0u8; 32],
        consensus_kind,
        validator_set_hash: [0u8; 32],
        timestamp_ms: spec.timestamp_ms,
        sequence: spec.sequence,
        producer: spec.producer,
        state_updates: std::collections::BTreeMap::new(),
    }
}

/// Maximum challenge-search attempts when `mine_pospace_block_hash` searches for
/// a block hash whose derived `PoSpace` challenge meets `DAG_FAMILY_QUALITY_BITS`.
const MAX_POSPACE_CHALLENGE_ATTEMPTS: u64 = 1_048_576;

fn validate_composite_authority_set(
    domain: &ConsensusDomain,
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
) -> Result<Hash32, String> {
    use crate::domain::finality_adapter::{poa_pq_authority_set_hash, DAG_FAMILY_MAX_AUTHORITIES};

    if authorities.is_empty() {
        return Err("composite authority set cannot be empty".into());
    }
    if authorities.len() > DAG_FAMILY_MAX_AUTHORITIES {
        return Err(format!(
            "composite authority set size {} exceeds maximum {DAG_FAMILY_MAX_AUTHORITIES}",
            authorities.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in authorities {
        if !seen.insert(entry.authority) {
            return Err(format!(
                "duplicate authority {} in composite authority set",
                entry.authority
            ));
        }
    }
    let set_hash = poa_pq_authority_set_hash(domain, authorities).map_err(|e| e.to_string())?;
    if domain.validator_set_hash != [0u8; 32] && domain.validator_set_hash != set_hash {
        return Err(format!(
            "composite authority set hash {} does not match registered domain validator_set_hash {}",
            hex::encode(set_hash),
            hex::encode(domain.validator_set_hash)
        ));
    }
    Ok(set_hash)
}

fn sign_composite_quorum(
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
    signers: &[crate::crypto::composite::CompositeKeypair],
    digest: &[u8; 32],
) -> Result<Vec<crate::domain::finality_adapter::PoAAuthoritySignature>, String> {
    if signers.is_empty() {
        return Err("at least one composite signing authority is required".into());
    }
    let mut authority_keys = std::collections::BTreeMap::new();
    for entry in authorities {
        authority_keys.insert(entry.authority, entry.public_key.as_slice());
    }
    let mut seen_signers = std::collections::BTreeSet::new();
    let mut signatures = Vec::with_capacity(signers.len());
    for keypair in signers {
        let public = keypair.public_key().map_err(|e| e.to_string())?;
        let authority = Address::from(public.ed);
        let Some(expected_pk) = authority_keys.get(&authority) else {
            return Err(format!("{authority} is not in the authority set"));
        };
        if public.encode().as_slice() != *expected_pk {
            return Err(format!(
                "composite public key for {authority} disagrees with declared authority entry"
            ));
        }
        if !seen_signers.insert(authority) {
            return Err(format!("duplicate composite signing key for {authority}"));
        }
        let mut rnd = [0u8; 32];
        {
            use rand::Rng;
            rand::rng().fill_bytes(&mut rnd);
        }
        let signature = crate::consensus::block_signature::sign_poa(keypair, digest, &rnd)
            .map_err(|e| e.to_string())?;
        signatures.push(crate::domain::finality_adapter::PoAAuthoritySignature {
            authority,
            signature,
        });
    }
    Ok(signatures)
}

pub fn build_poa_commitment(
    spec: &QuorumBlockSpec,
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
    signers: &[crate::crypto::composite::CompositeKeypair],
) -> Result<VerifiedDomainCommitment, String> {
    if spec.domain.kind != crate::domain::ConsensusKind::PoA {
        return Err(format!(
            "PoA commitment requires ConsensusKind::PoA, found {:?}",
            spec.domain.kind
        ));
    }
    let set_hash = validate_composite_authority_set(&spec.domain, authorities)?;
    let unsigned_commitment = unsigned_commitment_for(spec, crate::domain::ConsensusKind::PoA);
    let digest = crate::domain::finality_adapter::poa_commit_digest(
        spec.domain.domain_chain_id,
        spec.domain.id,
        &unsigned_commitment,
    );
    let signatures = sign_composite_quorum(authorities, signers, &digest)?;
    let proof = FinalityProof::PoAPq {
        authorities: authorities.to_vec(),
        signatures,
    };
    let commitment = commitment_for(spec, &proof, set_hash)?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// Build a post-quantum DAG structural finality commitment (`FinalityProof::DagPq`):
/// derives the causal anchor from `(chain_id, domain_id, round, parent_hash, block_hash)`
/// and collects composite (`Ed25519 + ML-DSA-65`) authority signatures over the
/// domain-separated DAG PQ commit digest.
///
/// # Errors
///
/// Wrong domain kind, invalid authority/signer set, a self-referential anchor,
/// or a signing/hashing failure.
pub fn build_dag_commitment(
    spec: &QuorumBlockSpec,
    round: u64,
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
    signers: &[crate::crypto::composite::CompositeKeypair],
) -> Result<VerifiedDomainCommitment, String> {
    if spec.domain.kind != crate::domain::ConsensusKind::Dag {
        return Err(format!(
            "DAG commitment requires ConsensusKind::Dag, found {:?}",
            spec.domain.kind
        ));
    }
    let set_hash = validate_composite_authority_set(&spec.domain, authorities)?;
    let unsigned_commitment = unsigned_commitment_for(spec, crate::domain::ConsensusKind::Dag);
    let parent_anchor = spec.parent_hash;
    let anchor = crate::domain::finality_adapter::dag_anchor_hash(
        spec.domain.domain_chain_id,
        spec.domain.id,
        round,
        parent_anchor,
        spec.block_hash,
    );
    if parent_anchor == anchor {
        return Err("DAG anchor collides with parent anchor".to_string());
    }
    let digest = crate::domain::finality_adapter::dag_pq_commit_digest(
        spec.domain.domain_chain_id,
        spec.domain.id,
        round,
        anchor,
        parent_anchor,
        &unsigned_commitment,
    );
    let signatures = sign_composite_quorum(authorities, signers, &digest)?;
    let proof = FinalityProof::DagPq {
        round,
        anchor,
        parent_anchor,
        authorities: authorities.to_vec(),
        signatures,
    };
    let commitment = commitment_for(spec, &proof, set_hash)?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// Build a post-quantum `PoH` structural finality commitment (`FinalityProof::PohPq`):
/// computes the sequential hash ladder starting from `spec.parent_hash` (when
/// `spec.height > 1`) or `seed_tick` (at height 0/1) for `tick_count` entries and
/// collects composite (`Ed25519 + ML-DSA-65`) authority signatures over the ladder root.
///
/// # Errors
///
/// Wrong domain kind, `tick_count` outside `2..=DAG_FAMILY_MAX_POH_TICKS`,
/// invalid authority/signer set, or a signing/hashing failure.
pub fn build_poh_commitment(
    spec: &QuorumBlockSpec,
    seed_tick: Hash32,
    tick_count: usize,
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
    signers: &[crate::crypto::composite::CompositeKeypair],
) -> Result<VerifiedDomainCommitment, String> {
    if spec.domain.kind != crate::domain::ConsensusKind::Poh {
        return Err(format!(
            "PoH commitment requires ConsensusKind::Poh, found {:?}",
            spec.domain.kind
        ));
    }
    let max_ticks = crate::domain::finality_adapter::DAG_FAMILY_MAX_POH_TICKS;
    if tick_count < 2 || tick_count > max_ticks {
        return Err(format!(
            "PoH tick_count {tick_count} must be in 2..={max_ticks}"
        ));
    }
    let set_hash = validate_composite_authority_set(&spec.domain, authorities)?;
    let unsigned_commitment = unsigned_commitment_for(spec, crate::domain::ConsensusKind::Poh);
    let seed = if spec.height > 1 {
        spec.parent_hash
    } else {
        seed_tick
    };
    let mut chain = Vec::with_capacity(tick_count);
    let mut current = seed;
    chain.push(current);
    for _ in 1..tick_count {
        current = crate::domain::finality_adapter::poh_next_tick(&current);
        chain.push(current);
    }
    let first = chain
        .first()
        .copied()
        .ok_or_else(|| "PoH ladder is empty".to_string())?;
    let last = chain
        .last()
        .copied()
        .ok_or_else(|| "PoH ladder is empty".to_string())?;
    let tick_len_u64 =
        u64::try_from(chain.len()).map_err(|_| "PoH ladder length overflows u64".to_string())?;
    let root = crate::domain::finality_adapter::poh_ladder_root(
        spec.domain.domain_chain_id,
        spec.domain.id,
        spec.block_hash,
        last,
        tick_len_u64,
    );
    let digest = crate::domain::finality_adapter::poh_pq_commit_digest(
        spec.domain.domain_chain_id,
        spec.domain.id,
        root,
        first,
        &unsigned_commitment,
    );
    let signatures = sign_composite_quorum(authorities, signers, &digest)?;
    let proof = FinalityProof::PohPq {
        chain,
        authorities: authorities.to_vec(),
        signatures,
    };
    let commitment = commitment_for(spec, &proof, set_hash)?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

/// Deterministically search for a `block_hash` derived from `spec.block_hash`
/// whose `PoSpace` plot challenge reaches `DAG_FAMILY_QUALITY_BITS`.
///
/// If the initial `spec.block_hash` already satisfies the quality floor, it is
/// preserved unchanged.
///
/// # Errors
///
/// Wrong domain kind or exhausted `MAX_POSPACE_CHALLENGE_ATTEMPTS` search window.
pub fn mine_pospace_block_hash(
    spec: &mut QuorumBlockSpec,
    prover: &Address,
) -> Result<u32, String> {
    use crate::domain::finality_adapter::{
        pospace_challenge, pospace_plot_id, pospace_quality, DAG_FAMILY_QUALITY_BITS,
    };
    use sha2::{Digest as _, Sha256};

    if spec.domain.kind != crate::domain::ConsensusKind::Pospace {
        return Err(format!(
            "PoSpace mining requires ConsensusKind::Pospace, found {:?}",
            spec.domain.kind
        ));
    }
    let plot_id = pospace_plot_id(prover, &spec.domain.config_hash);
    let seed_hash = spec.block_hash;
    for attempt in 0..MAX_POSPACE_CHALLENGE_ATTEMPTS {
        let candidate_hash = if attempt == 0 {
            seed_hash
        } else {
            let mut hasher = Sha256::new();
            hasher.update(seed_hash);
            hasher.update(attempt.to_le_bytes());
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            out
        };
        spec.block_hash = candidate_hash;
        let candidate = unsigned_commitment_for(spec, crate::domain::ConsensusKind::Pospace);
        let challenge = pospace_challenge(&spec.domain, &candidate);
        let quality = pospace_quality(&plot_id, &challenge);
        let observed = leading_zero_bits(&quality);
        if observed >= DAG_FAMILY_QUALITY_BITS {
            return Ok(observed);
        }
    }
    spec.block_hash = seed_hash;
    Err(format!(
        "no PoSpace block hash within {MAX_POSPACE_CHALLENGE_ATTEMPTS} attempts met {DAG_FAMILY_QUALITY_BITS} quality bits"
    ))
}

/// Build a post-quantum `PoSpace` structural finality commitment (`FinalityProof::PospacePq`):
/// derives the prover's plot id from `(prover, domain.config_hash)`, checks that the
/// plot quality for the commitment challenge meets `DAG_FAMILY_QUALITY_BITS`, signs
/// the digest with the prover's composite key and the authority quorum.
///
/// # Errors
///
/// Wrong domain kind, `prover_index` out of range, the prover outside `authorities`,
/// plot quality below `DAG_FAMILY_QUALITY_BITS`, or a signing/hashing failure.
pub fn build_pospace_commitment(
    spec: &QuorumBlockSpec,
    prover_index: usize,
    authorities: &[crate::domain::finality_adapter::PoAAuthorityKey],
    signers: &[crate::crypto::composite::CompositeKeypair],
) -> Result<VerifiedDomainCommitment, String> {
    if spec.domain.kind != crate::domain::ConsensusKind::Pospace {
        return Err(format!(
            "PoSpace commitment requires ConsensusKind::Pospace, found {:?}",
            spec.domain.kind
        ));
    }
    let set_hash = validate_composite_authority_set(&spec.domain, authorities)?;
    let prover_keypair = signers.get(prover_index).ok_or_else(|| {
        format!(
            "PoSpace prover_index {prover_index} is out of range for {} signers",
            signers.len()
        )
    })?;
    let prover_public = prover_keypair.public_key().map_err(|e| e.to_string())?;
    let prover = Address::from(prover_public.ed);
    let Some(prover_entry) = authorities.iter().find(|a| a.authority == prover) else {
        return Err(format!(
            "PoSpace prover {prover} is not in the authority set"
        ));
    };
    if prover_public.encode() != prover_entry.public_key {
        return Err(format!(
            "PoSpace prover {prover} composite public key disagrees with authority entry"
        ));
    }
    let unsigned_commitment = unsigned_commitment_for(spec, crate::domain::ConsensusKind::Pospace);
    let plot_id =
        crate::domain::finality_adapter::pospace_plot_id(&prover, &spec.domain.config_hash);
    let challenge =
        crate::domain::finality_adapter::pospace_challenge(&spec.domain, &unsigned_commitment);
    let quality = crate::domain::finality_adapter::pospace_quality(&plot_id, &challenge);
    let quality_bits = leading_zero_bits(&quality);
    let required = crate::domain::finality_adapter::DAG_FAMILY_QUALITY_BITS;
    if quality_bits < required {
        return Err(format!(
            "PoSpace plot quality {quality_bits} bits is below required {required} bits"
        ));
    }
    let digest = crate::domain::finality_adapter::pospace_pq_commit_digest(
        spec.domain.domain_chain_id,
        spec.domain.id,
        &prover,
        plot_id,
        quality_bits,
        &unsigned_commitment,
    );
    let mut prover_rnd = [0u8; 32];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut prover_rnd);
    }
    let prover_signature =
        crate::consensus::block_signature::sign_poa(prover_keypair, &digest, &prover_rnd)
            .map_err(|e| e.to_string())?;
    let signatures = sign_composite_quorum(authorities, signers, &digest)?;
    let proof = FinalityProof::PospacePq {
        prover,
        plot_id,
        quality_bits,
        prover_signature,
        authorities: authorities.to_vec(),
        signatures,
    };
    let commitment = commitment_for(spec, &proof, set_hash)?;
    Ok(VerifiedDomainCommitment { commitment, proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::finality_adapter::FinalityStatus;
    use crate::domain::finality_adapter::{DomainFinalityAdapter, PoWHeaderChainFinalityAdapter};
    use crate::domain::types::PoWDomainParameters;

    fn spec(blocks: usize) -> PowChainSpec {
        let mut domain = crate::domain::plugin::default_domain(
            7,
            crate::domain::ConsensusKind::PoW,
            45_262,
            crate::domain::POW_HEADER_CHAIN_ADAPTER,
            2,
        );
        domain.pow_parameters = Some(PoWDomainParameters {
            min_difficulty_bits: 4,
            max_difficulty_bits: 8,
            min_cumulative_work: 2 * (1u128 << 4),
            max_headers: 8,
        });
        PowChainSpec {
            domain,
            parent_hash: [1; 32],
            height: 10,
            difficulty_bits: 4,
            sequence: 1,
            producer: None,
            blocks: (0..blocks)
                .map(|i| {
                    let seed = u8::try_from(i).unwrap_or(u8::MAX).saturating_add(2);
                    PowBlockContent {
                        state_root: [seed; 32],
                        tx_root: [seed; 32],
                        event_root: [seed; 32],
                        timestamp_ms: 1_000 + u128::from(seed),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn a_built_pow_commitment_finalizes_under_the_light_client() {
        let spec = spec(2);
        let built = build_pow_commitment(&spec).expect("the chain is mined");
        let status = PoWHeaderChainFinalityAdapter
            .verify_finality(&spec.domain, &built.commitment, &built.proof)
            .expect("the adapter runs");
        assert!(matches!(status, FinalityStatus::Finalized), "{status:?}");
        assert_eq!(
            built.commitment.finality_proof_hash,
            hash_finality_proof(&built.proof).expect("the proof hashes")
        );
    }

    #[test]
    fn a_chain_short_of_the_confirmation_depth_stays_pending() {
        let spec = spec(1);
        let built = build_pow_commitment(&spec).expect("the chain is mined");
        let status = PoWHeaderChainFinalityAdapter
            .verify_finality(&spec.domain, &built.commitment, &built.proof)
            .expect("the adapter runs");
        assert!(
            matches!(status, FinalityStatus::Pending { .. }),
            "{status:?}"
        );
    }

    #[test]
    fn a_difficulty_outside_the_registered_range_is_refused() {
        let mut spec = spec(2);
        spec.difficulty_bits = 9;
        assert!(build_pow_commitment(&spec).is_err());
        spec.difficulty_bits = 4;
        spec.blocks.clear();
        assert!(build_pow_commitment(&spec).is_err());
    }

    fn quorum_spec(kind: crate::domain::ConsensusKind, adapter: &str) -> QuorumBlockSpec {
        QuorumBlockSpec {
            domain: crate::domain::plugin::default_domain(8, kind, 45_262, adapter, 0),
            height: 12,
            block_hash: [0x21; 32],
            parent_hash: [0x20; 32],
            state_root: [0x22; 32],
            tx_root: [0x23; 32],
            event_root: [0x24; 32],
            timestamp_ms: 5_000,
            sequence: 1,
            producer: None,
        }
    }

    fn bft_members(n: u8) -> Vec<BftMember> {
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 64];
                seed[0] = i + 1;
                let bls = crate::crypto::primitives::BlsKeypair::from_seed(&seed)
                    .expect("a non-zero test seed");
                let pq = crate::crypto::primitives::PqKeyPair::generate();
                let address = Address::from([i + 1; 32]);
                let pop = crate::chain::finality::sign_bls_pop(
                    &bls.secret_key,
                    &crate::chain::finality::pop_signing_message(45_262, &address, &bls.public_key),
                );
                BftMember {
                    entry: crate::chain::finality::ValidatorEntry {
                        address,
                        stake: 100,
                        bls_public_key: bls.public_key.clone(),
                        pop_signature: pop,
                        pq_public_key: pq.public_key_bytes().to_vec(),
                    },
                    bls,
                    pq: Some(pq),
                }
            })
            .collect()
    }

    #[test]
    fn a_built_bft_commitment_carries_both_halves_and_finalizes() {
        let mut spec = quorum_spec(crate::domain::ConsensusKind::Bft, "bft-quorum-commit");
        let members = bft_members(4);
        let snapshot = crate::chain::finality::ValidatorSetSnapshot::new(
            1,
            members.iter().map(|m| m.entry.clone()).collect(),
        );
        spec.domain.validator_set_hash = hex::decode(&snapshot.set_hash)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let built =
            build_bft_commitment(&spec, 45_262, 1, 0, &members, &[0, 1, 2]).expect("builds");
        assert!(matches!(built.proof, FinalityProof::BftPq { .. }));
        let status = crate::domain::finality_adapter::BftFinalityAdapter::default()
            .verify_finality(&spec.domain, &built.commitment, &built.proof)
            .expect("the adapter runs");
        assert_eq!(status, FinalityStatus::Finalized);
    }

    #[test]
    fn a_built_poa_commitment_with_composite_signatures_finalizes() {
        let mut spec = quorum_spec(crate::domain::ConsensusKind::PoA, "poa-authority-quorum");
        let keypairs: Vec<crate::crypto::composite::CompositeKeypair> = (0..3u8)
            .map(|i| {
                crate::crypto::composite::CompositeKeypair::from_seeds(
                    crate::crypto::scheme::SuiteId::VALIDATOR,
                    &[i + 1; crate::crypto::pq::ML_DSA_SEED_LEN],
                    &[i + 9; 32],
                )
                .expect("seeds")
            })
            .collect();
        let authorities: Vec<crate::domain::finality_adapter::PoAAuthorityKey> = keypairs
            .iter()
            .map(|kp| {
                let public = kp.public_key().expect("public");
                crate::domain::finality_adapter::PoAAuthorityKey {
                    authority: Address::from(public.ed),
                    public_key: public.encode(),
                }
            })
            .collect();
        spec.domain.validator_set_hash =
            crate::domain::finality_adapter::poa_pq_authority_set_hash(&spec.domain, &authorities)
                .expect("hash");
        let built = build_poa_commitment(&spec, &authorities, &keypairs[..2]).expect("builds");
        let status = crate::domain::finality_adapter::PoAFinalityAdapter::default()
            .verify_finality(&spec.domain, &built.commitment, &built.proof)
            .expect("the adapter runs");
        assert_eq!(status, FinalityStatus::Finalized);
        let one = build_poa_commitment(&spec, &authorities, &keypairs[..1]).expect("builds");
        let status = crate::domain::finality_adapter::PoAFinalityAdapter::default()
            .verify_finality(&spec.domain, &one.commitment, &one.proof)
            .expect("the adapter runs");
        assert!(
            matches!(status, FinalityStatus::Pending { .. }),
            "{status:?}"
        );
    }

    #[test]
    fn a_built_bitcoin_spv_commitment_finalizes() {
        let mut domain = crate::domain::plugin::default_domain(
            3,
            crate::domain::ConsensusKind::PoW,
            0,
            crate::domain::types::BITCOIN_SPV_ADAPTER,
            2,
        );
        domain.pow_parameters = Some(crate::domain::types::PoWDomainParameters {
            min_difficulty_bits: 1,
            max_difficulty_bits: 16,
            min_cumulative_work: 4,
            max_headers: 8,
        });
        let spec = BitcoinSpvChainSpec {
            domain: domain.clone(),
            parent_hash: [0x11; 32],
            height: 1,
            sequence: 0,
            producer: None,
            blocks: vec![
                BitcoinBlockContent {
                    version: 1,
                    merkle_root: [0x22; 32],
                    timestamp: 1_700_000_000,
                    bits: 0x207f_ffff,
                },
                BitcoinBlockContent {
                    version: 1,
                    merkle_root: [0x33; 32],
                    timestamp: 1_700_000_600,
                    bits: 0x207f_ffff,
                },
            ],
        };
        let built = build_bitcoin_spv_commitment(&spec).expect("bitcoin spv commitment builds");
        assert!(matches!(
            built.proof,
            FinalityProof::BitcoinSpv { ref headers } if headers.len() == 2
        ));
        let status = crate::domain::finality_adapter::BitcoinSpvFinalityAdapter
            .verify_finality(&domain, &built.commitment, &built.proof)
            .expect("adapter runs");
        assert_eq!(status, FinalityStatus::Finalized);
    }

    /// Signer `i`'s composite key pair, re-derived from the fixed seeds
    /// [`composite_quorum`] uses. Key material is deliberately not `Clone`
    /// (wiped on drop), so a repeated signer is re-derived from its seeds
    /// instead of copied.
    fn composite_keypair_at(i: u8) -> crate::crypto::composite::CompositeKeypair {
        crate::crypto::composite::CompositeKeypair::from_seeds(
            crate::crypto::scheme::SuiteId::VALIDATOR,
            &[i + 11; crate::crypto::pq::ML_DSA_SEED_LEN],
            &[i + 29; 32],
        )
        .expect("seeds")
    }

    fn composite_quorum(
        count: u8,
    ) -> (
        Vec<crate::crypto::composite::CompositeKeypair>,
        Vec<crate::domain::finality_adapter::PoAAuthorityKey>,
    ) {
        let keypairs: Vec<crate::crypto::composite::CompositeKeypair> =
            (0..count).map(composite_keypair_at).collect();
        let authorities: Vec<crate::domain::finality_adapter::PoAAuthorityKey> = keypairs
            .iter()
            .map(|kp| {
                let public = kp.public_key().expect("public");
                crate::domain::finality_adapter::PoAAuthorityKey {
                    authority: Address::from(public.ed),
                    public_key: public.encode(),
                }
            })
            .collect();
        (keypairs, authorities)
    }

    #[test]
    fn dag_poh_and_pospace_commitments_finalize_under_their_native_adapters() {
        let (keypairs, authorities) = composite_quorum(3);
        let quorum = keypairs.get(..2).expect("two signers");

        // 1. DAG PQ commitment + fail-closed rejections
        let mut dag_spec = quorum_spec(crate::domain::ConsensusKind::Dag, "dag-tip-vote-v1");
        dag_spec.domain.validator_set_hash =
            crate::domain::finality_adapter::poa_pq_authority_set_hash(
                &dag_spec.domain,
                &authorities,
            )
            .expect("dag set hash");
        let dag_built = build_dag_commitment(&dag_spec, 7, &authorities, quorum).expect("dag");
        assert!(matches!(dag_built.proof, FinalityProof::DagPq { .. }));
        let dag_status = crate::domain::finality_adapter::DagFinalityAdapter
            .verify_finality(&dag_spec.domain, &dag_built.commitment, &dag_built.proof)
            .expect("dag adapter");
        assert_eq!(dag_status, FinalityStatus::Finalized);
        assert!(build_dag_commitment(&dag_spec, 7, &authorities, &[]).is_err());
        // The same signer twice: signer 0 is re-derived from its seeds, so the
        // two key pairs hold identical public keys and the builder's
        // duplicate-signer rejection is exactly what this exercises.
        let dup_signers = [composite_keypair_at(0), composite_keypair_at(0)];
        assert!(build_dag_commitment(&dag_spec, 7, &authorities, &dup_signers).is_err());

        // 2. PoH PQ commitment + fail-closed rejections
        let mut poh_spec = quorum_spec(crate::domain::ConsensusKind::Poh, "poh-hash-chain-v1");
        poh_spec.domain.validator_set_hash =
            crate::domain::finality_adapter::poa_pq_authority_set_hash(
                &poh_spec.domain,
                &authorities,
            )
            .expect("poh set hash");
        let poh_built =
            build_poh_commitment(&poh_spec, [0x42; 32], 8, &authorities, quorum).expect("poh");
        assert!(matches!(poh_built.proof, FinalityProof::PohPq { .. }));
        let poh_status = crate::domain::finality_adapter::PohFinalityAdapter
            .verify_finality(&poh_spec.domain, &poh_built.commitment, &poh_built.proof)
            .expect("poh adapter");
        assert_eq!(poh_status, FinalityStatus::Finalized);
        assert!(build_poh_commitment(&poh_spec, [0x42; 32], 1, &authorities, quorum).is_err());

        // 3. PoSpace PQ commitment via `mine_pospace_block_hash`
        let mut pospace_spec =
            quorum_spec(crate::domain::ConsensusKind::Pospace, "pospace-plot-v1");
        pospace_spec.domain.validator_set_hash =
            crate::domain::finality_adapter::poa_pq_authority_set_hash(
                &pospace_spec.domain,
                &authorities,
            )
            .expect("pospace set hash");
        let prover_addr = authorities.first().expect("prover").authority;
        let mined_bits =
            mine_pospace_block_hash(&mut pospace_spec, &prover_addr).expect("mines challenge");
        assert!(mined_bits >= crate::domain::finality_adapter::DAG_FAMILY_QUALITY_BITS);
        let pospace_built =
            build_pospace_commitment(&pospace_spec, 0, &authorities, quorum).expect("pospace");
        assert!(matches!(
            pospace_built.proof,
            FinalityProof::PospacePq { .. }
        ));
        let pospace_status = crate::domain::finality_adapter::PospaceFinalityAdapter
            .verify_finality(
                &pospace_spec.domain,
                &pospace_built.commitment,
                &pospace_built.proof,
            )
            .expect("pospace adapter");
        assert_eq!(pospace_status, FinalityStatus::Finalized);
    }
}
