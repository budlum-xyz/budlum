//! F10.3 Ethereum PoS sync committee light client, Altair-and-later finality.
//!
//! **BLS variant.** This module follows the Altair *structure* - 512 keys,
//! sync periods, two-thirds threshold, fork-domain signing root - with
//! Ethereum mainnet's BLS instantiation, the minimal-pubkey-size variant:
//! public keys are compressed G1 points (48 bytes), signatures are
//! compressed G2 points (96 bytes), and messages are hashed with the G2
//! suite `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. This is exactly
//! what Ethereum's sync committees produce, so a genuine mainnet
//! `SyncCommitteeState` or sync aggregate verifies here. The module
//! previously ran an internal minimal-signature-size variant (G2 keys,
//! G1 signatures) that no Ethereum aggregate could satisfy; the groups
//! were swapped under the approved work package ARGE-SYNC-ETH-INTEROP
//! (workspace AR-GE queue, P1, approved 2026-09-07).
//!
//! **Serialization note.** `SyncCommitteeState` key material is now 48
//! bytes per key instead of 96; any persisted copy written by the old
//! variant is from before mainnet launch and is discarded, not migrated.
//!
//! This strengthens N-confirmation finality: the sync committee, 512 validators
//! over a period of about 27 hours, gives real PoS finality through a BLS12-381
//! aggregate signature. N-confirmation remains as the fallback, for when there
//! is no sync committee or the period rotation fails.
//!
//! # The model, Ethereum Altair `BeaconSyncCommittee`
//!
//! - **The sync period** is about 256 epochs, roughly 27 hours. Each period
//!   rotates in a new committee of 512 validators, selected at random.
//! - **The sync aggregate**, `SyncAggregate`, holds
//!   `sync_committee_bits: Bitvector<512>` and
//!   `sync_committee_signature: BLSSignature`, a signature over the Altair
//!   header. Participation at or above two thirds, about 342 of 512, counts as
//!   finalized.
//! - **The light client state** holds `finalized_header`,
//!   `next_sync_committee` with its 512 public keys, and `current_period`. On
//!   every finalized header, `next_sync_committee` is updated.
//!
//! # Security
//!
//! - **Deterministic and network-free.** The relayer produces the sync
//!   aggregate and the header; Budlum performs the BLS aggregate verification.
//!   That is Q1, relayer-produces.
//! - **One aggregate verification**, Ethereum's `FastAggregateVerify`: the
//!   participating public keys are summed in G1, each decoded and
//!   subgroup-checked on its own first, and a single pairing checks the
//!   G2 aggregate signature over the signing root; see
//!   [`verify_execution_block_finality`].
//! - **Threshold participation**: below two thirds is REFUSED, meaning no
//!   finality.
//! - **The message is derived, not supplied.** A committee signs the SSZ
//!   root of a beacon header under the fork domain. The verifier rebuilds
//!   that root from the header fields the relayer names and the adapter's
//!   chain parameters, and only after the header's body has been shown to
//!   commit to the execution block the deposit proof is about.

use crate::chain::finality::hash_to_g2;
use bls12_381::{G1Affine, G1Projective, G2Affine};
use sha2::{Digest, Sha256};

/// A sync committee error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncCommitteeError {
    /// An invalid public key size or encoding.
    InvalidPubkey,
    /// An invalid signature size or encoding.
    InvalidSignature,
    /// Participation is below the threshold, under two thirds of the committee.
    InsufficientParticipation {
        participating: usize,
        threshold: usize,
    },
    /// The BLS aggregate verification failed.
    SignatureVerificationFailed,
    /// Inconsistent with the light client state: the wrong period or the wrong
    /// `next_sync_committee`.
    StateMismatch,
    /// The header does not match the sync committee state.
    HeaderMismatch,
    /// The beacon header the committee signed does not commit to the
    /// execution block the deposit proof is about: the Merkle branch from
    /// the execution block hash does not reach the beacon body root.
    ExecutionBlockNotInBeaconBody,
    /// The beacon header's slot falls outside the period the committee
    /// state is for, so the 512 keys are not the ones that signed it.
    PeriodMismatch { slot_period: u64, state_period: u64 },
}

impl std::fmt::Display for SyncCommitteeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncCommitteeError::InvalidPubkey => write!(f, "sync: invalid pubkey"),
            SyncCommitteeError::InvalidSignature => write!(f, "sync: invalid signature"),
            SyncCommitteeError::InsufficientParticipation {
                participating,
                threshold,
            } => write!(
                f,
                "sync: participation {participating} < threshold {threshold} (2/3)"
            ),
            SyncCommitteeError::SignatureVerificationFailed => {
                write!(f, "sync: BLS signature verification failed")
            }
            SyncCommitteeError::StateMismatch => write!(f, "sync: light-client state mismatch"),
            SyncCommitteeError::HeaderMismatch => write!(f, "sync: header mismatch"),
            SyncCommitteeError::ExecutionBlockNotInBeaconBody => write!(
                f,
                "sync: the signed beacon header does not commit to the execution block"
            ),
            SyncCommitteeError::PeriodMismatch {
                slot_period,
                state_period,
            } => write!(
                f,
                "sync: beacon slot is in period {slot_period}, committee state is for period {state_period}"
            ),
        }
    }
}

impl std::error::Error for SyncCommitteeError {}

/// The sync committee size, an Altair constant.
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// The participation threshold, two thirds, for Altair finality:
/// 512 * 2 / 3 = 341.33, rounded up to 342.
pub const PARTICIPATION_THRESHOLD: usize = (SYNC_COMMITTEE_SIZE * 2) / 3 + 1;

/// The BLS public key size, G1 compressed on BLS12-381. Ethereum mainnet's
/// minimal-pubkey-size variant puts public keys in G1 (a compressed G1
/// point is 48 bytes).
pub const BLS_PUBKEY_LEN: usize = 48;

/// The BLS signature size, G2 compressed. Ethereum mainnet puts signatures
/// in G2 (a compressed G2 point is 96 bytes).
pub const BLS_SIGNATURE_LEN: usize = 96;

/// The Ethereum sync committee light client state, for a single period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommitteeState {
    /// The period of the finalized header.
    pub current_period: u64,
    /// The current sync committee: 512 public keys, each 48 bytes, G1
    /// compressed.
    pub current_sync_committee: [[u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
    /// The next sync committee, for the period rotation.
    pub next_sync_committee: [[u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
}

/// An Altair sync aggregate: the signature over the header plus the
/// participation bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// The 512-bit participation bitmap, where a 1 means the member signed.
    pub sync_committee_bits: [u8; SYNC_COMMITTEE_SIZE / 8],
    /// The aggregated BLS signature, G2 compressed, 96 bytes.
    pub sync_committee_signature: [u8; BLS_SIGNATURE_LEN],
}

impl SyncAggregate {
    /// The participation count, the number of set bits in the bitmap.
    pub fn participation_count(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Did the sync committee member at `index` sign?
    pub fn signed(&self, index: usize) -> bool {
        if index >= SYNC_COMMITTEE_SIZE {
            return false;
        }
        let byte = index / 8;
        let bit = index % 8;
        (self.sync_committee_bits[byte] >> bit) & 1 == 1
    }
}

/// Verifies a sync committee aggregate signature: Altair's
/// `FastAggregateVerify`.
///
/// An Altair `sync_committee_signature` is one G2 point, the sum of the
/// participating members' signatures over the same message. It verifies
/// against the sum of the participating public keys, once:
/// `e(sum(pk_i), H(msg)) == e(g1_gen, sig)`. Two earlier versions of this
/// function got that wrong in opposite directions. The first returned `Ok`
/// on the first member whose key verified the signature, so one valid
/// signature stood in for finality. The second verified the aggregate
/// against every participating key separately and counted the successes,
/// which no genuine aggregate over two or more distinct keys can pass, so
/// every real attestation was refused as `InsufficientParticipation`. A
/// control that refuses everything is not a control.
///
/// Order of checks: participation first, because it is a bit count and an
/// aggregate short of 342 signers is refused before any curve arithmetic;
/// then every participating key is decoded and subgroup-checked, because a
/// small-subgroup or identity key inside a sum would let the sum be steered;
/// then the single pairing.
///
/// `signing_message` is the Altair signing root. It is derived by
/// [`verify_execution_block_finality`], which is the only caller: a
/// signature check over caller-chosen bytes proves that the relayer can
/// sign its own message, not that the committee finalized a block.
fn verify_sync_aggregate(
    state: &SyncCommitteeState,
    aggregate: &SyncAggregate,
    signing_message: &[u8],
) -> Result<(), SyncCommitteeError> {
    // 1. Participation threshold.
    let participating = aggregate.participation_count();
    if participating < PARTICIPATION_THRESHOLD {
        return Err(SyncCommitteeError::InsufficientParticipation {
            participating,
            threshold: PARTICIPATION_THRESHOLD,
        });
    }

    // 2. Sum the participating public keys in G1. Every one of them is
    //    decoded and checked on its own: the sum of valid points is valid,
    //    but a single small-subgroup point in it would not be caught by a
    //    check on the sum alone.
    let mut agg_pk = G1Projective::identity();
    for (i, pk) in state.current_sync_committee.iter().enumerate() {
        if !aggregate.signed(i) {
            continue;
        }
        let pk_affine = G1Affine::from_compressed(pk)
            .into_option()
            .ok_or(SyncCommitteeError::InvalidPubkey)?;
        if !bool::from(pk_affine.is_torsion_free()) || bool::from(pk_affine.is_identity()) {
            return Err(SyncCommitteeError::InvalidPubkey);
        }
        agg_pk += G1Projective::from(pk_affine);
    }
    let agg_pk_affine = G1Affine::from(agg_pk);
    if bool::from(agg_pk_affine.is_identity()) {
        return Err(SyncCommitteeError::InvalidPubkey);
    }

    // 3. Decode the aggregate signature in G2 with the same subgroup
    //    discipline.
    let sig_affine = G2Affine::from_compressed(&aggregate.sync_committee_signature)
        .into_option()
        .ok_or(SyncCommitteeError::InvalidSignature)?;
    if !bool::from(sig_affine.is_torsion_free()) || bool::from(sig_affine.is_identity()) {
        return Err(SyncCommitteeError::InvalidSignature);
    }

    // 4. One pairing: e(agg_pk, H(msg)) * e(-g1_gen, sig) == 1, the
    //    FastAggregateVerify check e(sum(pk_i), H(m)) == e(g1_gen, sig)
    //    moved to one side.
    let h_msg = hash_to_g2(signing_message);
    let g1_gen_neg = -G1Affine::generator();
    let pairing_result = bls12_381::multi_miller_loop(&[
        (&agg_pk_affine, &h_msg.into()),
        (&g1_gen_neg, &sig_affine.into()),
    ])
    .final_exponentiation();
    if pairing_result != bls12_381::Gt::identity() {
        return Err(SyncCommitteeError::SignatureVerificationFailed);
    }
    Ok(())
}

/// Slots per sync-committee period: `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`
/// (256) times `SLOTS_PER_EPOCH` (32).
const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256 * 32;

/// `DOMAIN_SYNC_COMMITTEE`, the four-byte domain type Altair sync
/// committees sign under.
const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

/// Generalized index of `BeaconBlockBody.execution_payload.block_hash`
/// from the Deneb fork on: `execution_payload` is body field 9 (of 16 in a
/// 12-field container padded to depth 4, gindex 25) and `block_hash` is
/// payload field 12 (of 17 fields padded to 32, gindex 44), so the combined
/// index is `25 * 32 + 12 = 812`, nine levels below the body root.
const EXECUTION_BLOCK_HASH_GINDEX: u64 = 812;

/// The chain parameters an Altair signing root depends on. Both are fixed
/// per network and fork; neither is something a proof may name for itself,
/// which is why they sit on the adapter's configuration rather than in the
/// [`BeaconBinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconChainParams {
    /// The fork version in force at the signed slot (`0x04000000` for
    /// mainnet Deneb, `0x05000000` for Electra).
    pub fork_version: [u8; 4],
    /// `genesis_validators_root` of the beacon chain.
    pub genesis_validators_root: [u8; 32],
}

/// What ties a sync-committee signature to one execution block.
///
/// A sync committee never signs an execution header. It signs the SSZ root of
/// a `BeaconBlockHeader`, mixed with the fork domain. The execution block is
/// reachable from that header only through `body_root`, so proving the
/// attestation is about the deposit's block means: rebuild the beacon header
/// root, rebuild the signing root from it and the domain, and walk a Merkle
/// branch from the execution block hash up to `body_root`. Every field here
/// is the relayer's, and every one of them is checked against either the
/// target header (the block hash), the committee state (the slot's period)
/// or the pairing (the signing root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconBinding {
    /// `BeaconBlockHeader.slot`.
    pub slot: u64,
    /// `BeaconBlockHeader.proposer_index`.
    pub proposer_index: u64,
    /// `BeaconBlockHeader.parent_root`.
    pub parent_root: [u8; 32],
    /// `BeaconBlockHeader.state_root`.
    pub state_root: [u8; 32],
    /// `BeaconBlockHeader.body_root`.
    pub body_root: [u8; 32],
    /// The SSZ Merkle branch from `execution_payload.block_hash` up to
    /// `body_root`, leaf's sibling first: nine nodes, for generalized
    /// index 812 (Deneb and later).
    pub execution_block_hash_branch: Vec<[u8; 32]>,
}

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn u64_chunk(value: u64) -> [u8; 32] {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&value.to_le_bytes());
    chunk
}

/// SSZ `hash_tree_root` of a fixed list of 32-byte chunks, padded with zero
/// chunks to the next power of two.
fn merkleize_chunks(chunks: &[[u8; 32]]) -> [u8; 32] {
    let mut width = 1usize;
    while width < chunks.len() {
        width *= 2;
    }
    let mut layer: Vec<[u8; 32]> = chunks.to_vec();
    layer.resize(width, [0u8; 32]);
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| sha256_pair(&pair[0], &pair[1]))
            .collect();
    }
    layer.first().copied().unwrap_or([0u8; 32])
}

impl BeaconBinding {
    /// The sync-committee period the signed slot belongs to.
    fn period(&self) -> u64 {
        self.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
    }

    /// `hash_tree_root(BeaconBlockHeader)`: five fields, padded to eight.
    fn beacon_header_root(&self) -> [u8; 32] {
        merkleize_chunks(&[
            u64_chunk(self.slot),
            u64_chunk(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }

    /// `compute_signing_root(header, compute_domain(DOMAIN_SYNC_COMMITTEE,
    /// fork_version, genesis_validators_root))`.
    fn signing_root(&self, params: &BeaconChainParams) -> [u8; 32] {
        // ForkData is a two-field container (current_version,
        // genesis_validators_root) in the current consensus spec, so its
        // hash tree root is one level: sha256 of the version padded to 32
        // bytes paired with the genesis validators root. The mainnet
        // known-answer test below locks this derivation against a genuine
        // 510-of-512 sync aggregate.
        let mut fork_version_chunk = [0u8; 32];
        fork_version_chunk[..4].copy_from_slice(&params.fork_version);
        let fork_data_root = sha256_pair(&fork_version_chunk, &params.genesis_validators_root);
        let mut domain = [0u8; 32];
        domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
        domain[4..].copy_from_slice(&fork_data_root[..28]);
        sha256_pair(&self.beacon_header_root(), &domain)
    }

    /// Does `body_root` commit to `execution_block_hash` at the
    /// execution-payload block-hash index? A branch of the wrong length is
    /// a refusal, not a shorter walk.
    fn commits_to_execution_block(&self, execution_block_hash: &[u8; 32]) -> bool {
        let depth = EXECUTION_BLOCK_HASH_GINDEX.ilog2() as usize;
        if self.execution_block_hash_branch.len() != depth {
            return false;
        }
        let index = EXECUTION_BLOCK_HASH_GINDEX - (1u64 << depth);
        let mut node = *execution_block_hash;
        for (level, sibling) in self.execution_block_hash_branch.iter().enumerate() {
            node = if (index >> level) & 1 == 1 {
                sha256_pair(sibling, &node)
            } else {
                sha256_pair(&node, sibling)
            };
        }
        node == self.body_root
    }
}

/// Verify that a sync-committee aggregate finalizes one execution block.
///
/// This is the entry point a deposit proof uses; `verify_sync_aggregate`
/// alone checks a signature over whatever bytes it is handed, and a caller
/// that hands it the relayer's bytes has verified that the relayer can sign
/// its own message. Here the message is derived: the beacon header root is
/// rebuilt from the binding's fields, the domain from the adapter's chain
/// parameters, and before any curve arithmetic the binding must place
/// `execution_block_hash` inside the header's body and the header's slot
/// inside the committee state's period.
pub fn verify_execution_block_finality(
    state: &SyncCommitteeState,
    aggregate: &SyncAggregate,
    binding: &BeaconBinding,
    params: &BeaconChainParams,
    execution_block_hash: &[u8; 32],
) -> Result<(), SyncCommitteeError> {
    if !binding.commits_to_execution_block(execution_block_hash) {
        return Err(SyncCommitteeError::ExecutionBlockNotInBeaconBody);
    }
    let slot_period = binding.period();
    if slot_period != state.current_period {
        return Err(SyncCommitteeError::PeriodMismatch {
            slot_period,
            state_period: state.current_period,
        });
    }
    let signing_root = binding.signing_root(params);
    verify_sync_aggregate(state, aggregate, &signing_root)
}

/// The period rotation: on a finalized header, `next_sync_committee` becomes
/// the current one.
pub fn rotate_period(state: &mut SyncCommitteeState) {
    state.current_sync_committee = state.next_sync_committee;
    state.current_period = state.current_period.saturating_add(1);
}

/// Test-only builders shared with `verify.rs`.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{sha256_pair, BeaconBinding, EXECUTION_BLOCK_HASH_GINDEX};

    /// A header whose body root is whatever the branch yields for the given
    /// execution block hash at the execution-payload block-hash index.
    pub(crate) fn binding_committing_to(
        execution_block_hash: [u8; 32],
        slot: u64,
    ) -> BeaconBinding {
        let branch: Vec<[u8; 32]> = (1u8..=9).map(|i| [i; 32]).collect();
        let depth = EXECUTION_BLOCK_HASH_GINDEX.ilog2() as usize;
        let index = EXECUTION_BLOCK_HASH_GINDEX - (1u64 << depth);
        let mut node = execution_block_hash;
        for (level, sibling) in branch.iter().enumerate() {
            node = if (index >> level) & 1 == 1 {
                sha256_pair(sibling, &node)
            } else {
                sha256_pair(&node, sibling)
            };
        }
        BeaconBinding {
            slot,
            proposer_index: 1,
            parent_root: [0xA0; 32],
            state_root: [0xA1; 32],
            body_root: node,
            execution_block_hash_branch: branch,
        }
    }

    /// The first slot of a sync-committee period.
    pub(crate) fn first_slot_of_period(period: u64) -> u64 {
        period * super::SLOTS_PER_SYNC_COMMITTEE_PERIOD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_state() -> SyncCommitteeState {
        SyncCommitteeState {
            current_period: 0,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        }
    }

    fn full_participation_aggregate() -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: [0xFFu8; SYNC_COMMITTEE_SIZE / 8],
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    fn zero_participation_aggregate() -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: [0u8; SYNC_COMMITTEE_SIZE / 8],
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    #[test]
    fn participation_count_full() {
        let agg = full_participation_aggregate();
        assert_eq!(agg.participation_count(), SYNC_COMMITTEE_SIZE);
    }

    #[test]
    fn participation_count_zero() {
        let agg = zero_participation_aggregate();
        assert_eq!(agg.participation_count(), 0);
    }

    #[test]
    fn participation_threshold_is_two_thirds() {
        // 512 * 2/3 = 341.33, rounded up to 342.
        assert_eq!(PARTICIPATION_THRESHOLD, 342);
    }

    #[test]
    fn signed_bit_lookup() {
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        bits[0] = 0b00000010; // bit 1 set
        let agg = SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        };
        assert!(!agg.signed(0));
        assert!(agg.signed(1));
        assert!(!agg.signed(2));
        assert!(!agg.signed(511)); // out of range edge
    }

    #[test]
    fn zero_participation_rejected_below_threshold() {
        let state = dummy_state();
        let agg = zero_participation_aggregate();
        let err = verify_sync_aggregate(&state, &agg, b"msg").unwrap_err();
        assert_eq!(
            err,
            SyncCommitteeError::InsufficientParticipation {
                participating: 0,
                threshold: 342
            }
        );
    }

    #[test]
    fn rotate_period_advances() {
        let mut state = dummy_state();
        state.next_sync_committee[0] = [0xAA; BLS_PUBKEY_LEN];
        let original_period = state.current_period;
        rotate_period(&mut state);
        assert_eq!(state.current_period, original_period + 1);
        assert_eq!(state.current_sync_committee[0], [0xAA; BLS_PUBKEY_LEN]);
    }

    #[test]
    fn full_participation_all_zero_pubkeys_fails_signature() {
        // Zero bytes are not a G1 point, so the first participating key
        // refuses to decode and the aggregate is rejected as InvalidPubkey
        // before any pairing runs.
        let state = dummy_state();
        let agg = full_participation_aggregate();
        let err = verify_sync_aggregate(&state, &agg, b"msg").unwrap_err();
        assert_eq!(err, SyncCommitteeError::InvalidPubkey);
    }

    /// A committee with real keys and a signing set: `n` members, keys
    /// derived from a seed, so a test can build a genuine Altair-shaped
    /// aggregate (sum of signatures, sum of keys) and check it verifies.
    fn signing_committee(signers: usize) -> (SyncCommitteeState, Vec<bls12_381::Scalar>) {
        use bls12_381::{G1Affine, G1Projective, Scalar};
        let mut state = dummy_state();
        let mut secrets = Vec::with_capacity(signers);
        for i in 0..SYNC_COMMITTEE_SIZE {
            let mut wide = [0u8; 64];
            wide[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            wide[8] = 0x5A;
            let sk = Scalar::from_bytes_wide(&wide);
            let pk = G1Affine::from(G1Projective::generator() * sk);
            state.current_sync_committee[i] = pk.to_compressed();
            if i < signers {
                secrets.push(sk);
            }
        }
        (state, secrets)
    }

    fn aggregate_over(secrets: &[bls12_381::Scalar], msg: &[u8]) -> SyncAggregate {
        use bls12_381::{G2Affine, G2Projective};
        let h = G2Projective::from(hash_to_g2(msg));
        let mut sig = G2Projective::identity();
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        for (i, sk) in secrets.iter().enumerate() {
            sig += h * sk;
            bits[i / 8] |= 1 << (i % 8);
        }
        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: G2Affine::from(sig).to_compressed(),
        }
    }

    /// Known answer: a genuine aggregate of exactly the threshold count
    /// verifies. This is the case both earlier versions of the function
    /// got wrong, and it is the case that makes F10.3 a control at all.
    #[test]
    fn a_genuine_aggregate_at_the_threshold_verifies() {
        let msg = b"altair-signing-root";
        let (state, secrets) = signing_committee(PARTICIPATION_THRESHOLD);
        let agg = aggregate_over(&secrets, msg);
        assert_eq!(agg.participation_count(), PARTICIPATION_THRESHOLD);
        verify_sync_aggregate(&state, &agg, msg).expect("a real aggregate verifies");
    }

    /// The aggregate binds the message: the same signatures over another
    /// signing root are refused by the pairing, not by the bit count.
    #[test]
    fn a_genuine_aggregate_over_another_message_is_rejected() {
        let (state, secrets) = signing_committee(PARTICIPATION_THRESHOLD);
        let agg = aggregate_over(&secrets, b"altair-signing-root");
        let err = verify_sync_aggregate(&state, &agg, b"another-root").unwrap_err();
        assert_eq!(err, SyncCommitteeError::SignatureVerificationFailed);
    }

    /// The bitmap is bound to the signature: claiming one more signer than
    /// actually signed changes the summed key and the pairing fails. This is
    /// the forgery a bitmap-only check would let through.
    #[test]
    fn a_bitmap_claiming_a_member_who_did_not_sign_is_rejected() {
        let msg = b"altair-signing-root";
        let (state, secrets) = signing_committee(PARTICIPATION_THRESHOLD);
        let mut agg = aggregate_over(&secrets[..PARTICIPATION_THRESHOLD - 1], msg);
        // 341 signed; claim the 342nd as well to pass the bit count.
        let i = PARTICIPATION_THRESHOLD - 1;
        agg.sync_committee_bits[i / 8] |= 1 << (i % 8);
        assert_eq!(agg.participation_count(), PARTICIPATION_THRESHOLD);
        let err = verify_sync_aggregate(&state, &agg, msg).unwrap_err();
        assert_eq!(err, SyncCommitteeError::SignatureVerificationFailed);
    }

    /// One participating key that is not a valid curve point poisons the
    /// sum, so it is refused before the pairing regardless of the others.
    #[test]
    fn a_malformed_participating_key_is_rejected() {
        let msg = b"altair-signing-root";
        let (mut state, secrets) = signing_committee(PARTICIPATION_THRESHOLD);
        let agg = aggregate_over(&secrets, msg);
        state.current_sync_committee[3] = [0xFF; BLS_PUBKEY_LEN];
        let err = verify_sync_aggregate(&state, &agg, msg).unwrap_err();
        assert_eq!(err, SyncCommitteeError::InvalidPubkey);
    }

    /// The header, domain and signing-root construction against values
    /// computed independently (Python `hashlib`, SSZ by hand): mainnet
    /// Deneb fork version and genesis validators root, slot 8_800_000
    /// (period 1074), proposer 12345, parent `0x33..`, state `0x44..`, and
    /// a body root produced by walking a nine-node branch from leaf
    /// `0x11..` at gindex 812 with siblings `0x01..` to `0x09..`.
    #[test]
    fn beacon_signing_root_matches_an_independent_ssz_computation() {
        let branch: Vec<[u8; 32]> = (1u8..=9).map(|i| [i; 32]).collect();
        let mut binding = BeaconBinding {
            slot: 8_800_000,
            proposer_index: 12345,
            parent_root: [0x33; 32],
            state_root: [0x44; 32],
            body_root: [0u8; 32],
            execution_block_hash_branch: branch,
        };
        // The body root the branch produces for leaf 0x11.. at index 812.
        let expected_body =
            hex_32("f517b586495fd5e4dc1e4ef58195d08ffcd61071596fe3de8b8886bb33b76fe4");
        binding.body_root = expected_body;
        assert!(binding.commits_to_execution_block(&[0x11; 32]));
        assert!(!binding.commits_to_execution_block(&[0x12; 32]));

        assert_eq!(binding.period(), 1074);
        assert_eq!(
            binding.beacon_header_root(),
            hex_32("6ac884771826592816b794628de0ae509bd4070e443d2b8cb3a6bd8de3aa94bb")
        );
        let mainnet_deneb = BeaconChainParams {
            fork_version: [0x04, 0, 0, 0],
            genesis_validators_root: hex_32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
        };
        assert_eq!(
            binding.signing_root(&mainnet_deneb),
            hex_32("4dfbef8950e107772429da3b8938027adc36d81b414ee2481837493536e5732d")
        );

        // A branch of the wrong length is a refusal, not a shorter walk.
        binding.execution_block_hash_branch.pop();
        assert!(!binding.commits_to_execution_block(&[0x11; 32]));
    }

    fn hex_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).expect("test constant is hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// End to end: a genuine committee signs the derived signing root of a
    /// header that commits to the execution block, and the block finalizes.
    /// The same committee's signature over a header for another block does
    /// not carry over, and neither does a state for another period.
    #[test]
    fn a_genuine_attestation_finalizes_only_the_block_the_header_commits_to() {
        let params = BeaconChainParams {
            fork_version: [0x04, 0, 0, 0],
            genesis_validators_root: [0x42; 32],
        };
        let execution_block = [0xE1; 32];
        let (state, secrets) = signing_committee(PARTICIPATION_THRESHOLD);

        let bound = binding_committing_to(execution_block, 5);
        let agg = aggregate_over(&secrets, &bound.signing_root(&params));
        verify_execution_block_finality(&state, &agg, &bound, &params, &execution_block)
            .expect("a genuine attestation over the block finalizes it");

        // The very same aggregate does not finalize another execution block.
        assert_eq!(
            verify_execution_block_finality(&state, &agg, &bound, &params, &[0xE2; 32]),
            Err(SyncCommitteeError::ExecutionBlockNotInBeaconBody)
        );

        // A header for another block, signed by the same committee, is a
        // valid signature over a different message: the branch refuses it
        // before the pairing would.
        let other = binding_committing_to([0xE2; 32], 5);
        let other_agg = aggregate_over(&secrets, &other.signing_root(&params));
        assert_eq!(
            verify_execution_block_finality(&state, &other_agg, &other, &params, &execution_block),
            Err(SyncCommitteeError::ExecutionBlockNotInBeaconBody)
        );

        // The domain is the adapter's: the same header under another fork
        // version is another signing root, and the pairing says so.
        let other_fork = BeaconChainParams {
            fork_version: [0x05, 0, 0, 0],
            ..params
        };
        assert_eq!(
            verify_execution_block_finality(&state, &agg, &bound, &other_fork, &execution_block),
            Err(SyncCommitteeError::SignatureVerificationFailed)
        );

        // A state for another period holds other keys; refused before any
        // curve arithmetic.
        let mut later = state.clone();
        later.current_period = 9;
        assert_eq!(
            verify_execution_block_finality(&later, &agg, &bound, &params, &execution_block),
            Err(SyncCommitteeError::PeriodMismatch {
                slot_period: 0,
                state_period: 9,
            })
        );
    }

    use super::fixtures::binding_committing_to;

    #[test]
    fn garbage_aggregate_does_not_panic() {
        // DoS safety: random bytes give an Err and NO panic.
        let state = dummy_state();
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        bits[0] = 0xFF; // 8 participating, below the threshold
        let agg = SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: [0xFFu8; BLS_SIGNATURE_LEN],
        };
        let _ = verify_sync_aggregate(&state, &agg, b"garbage"); // an Err is expected, and NO panic
    }

    #[test]
    fn sync_committee_size_constant_correct() {
        assert_eq!(SYNC_COMMITTEE_SIZE, 512);
        assert_eq!(SYNC_COMMITTEE_SIZE / 8, 64); // 512-bit bitmap = 64 bytes
    }

    // ===== Known-answer test against a genuine Ethereum mainnet aggregate =====
    //
    // Source: Ethereum mainnet, captured 2026-09-07 from the Chainsafe
    // Lodestar public API (lodestar-mainnet.chainsafe.io). Block at slot
    // 15_165_712 (root 0xf923838bed7a11f04ffc05577b4a67f438ebb4200f7f8764218ea6c7d158fe2b)
    // carries a sync aggregate with participation 510/512 over the parent
    // header at slot 15_165_711 (root 0xf10f3e2e0aebc44260d3ac39ea684ec18a6fcaa7de9347e03656c3c10a8d7dca).
    // The committee comes from the light-client bootstrap at that parent
    // root (period 1851). The signing fork is the one active at epoch
    // 473928 (fork version 0x06000000). This locks hash_to_g2, the group
    // assignment, the SSZ header root and the fork-data derivation against
    // real Ethereum material; it was pre-verified with py_ecc before merge.

    const MAINNET_KAT_KEYS_HEX: &str = concat!(
    "8da49a2000438f173f937d9b4ac62edb4a9aaa181ffb4266315367574466fea01f0f6dd236a8c4a1d369a0b5b27d0cbb",
    "b65682d98404a0fa97a6ad767aa573379de19b8e659fb518f5d99369f93836750de555e1dc982e90f0ce714f57a03957",
    "b22d458c157d4a53ed7a8b500fb517d87506b7945763a8ba7aaec6cd8bd8184bd84be31073c347ca9e1e720d9165ce93",
    "8b4c2750ab685b36bb948b8f01bd203a822a40c9dc5ed77bf2de9011e18adc46eaf74c4f48fd459a90aaa471a0838330",
    "b4dae7c8e2ebd3af4876145ef0d9cb3ce6b8bc3ac96a94d308e3daa7c8b657bd2c790e061ec1b49a3c931d9d5a79bbe5",
    "91b26e7d4dad1131774c7de462560a70d4b559ae8dc701856b472f8a1ac3fe543f8e5f860289b12d81d539c46d7e7a1a",
    "934b6621d02f612144ecebf02d51f5b8d20029c4b56cf41fe07ed336773d2fb3a6de82f191186cdfb5cc25d6755f9e44",
    "b8763b017d2a4056da365f1c74cd6dfdf298210f88466f0371daeccdfb5e47a6722dc6141f6fd419579073ca4086e9a5",
    "86702782a3f73d7d806c9037ed143b1bd175601d46476416d86a43672e792674570d29380828fe4c70534247ecc4af58",
    "89a9b8fa99c1fab3cb3ea29ece4d5df4074bcc0509a5f82577bf4ce86f24b93537540f8fdef6d9cf05006a09c9afcfbb",
    "a0aa710b12af7249ec9c114b5f2de7015fdb1941075c714f7712870b1a2b9933d879fd40681614d95d60b4d4286d0b17",
    "82393ea92a4ab7a1335c521ac8083a9dd76ebb3abc3e2d9274285dc1909db3e419b27324570a7fbbf3329c863adc9f31",
    "b965c66a333cc973f586123c9fb94227a4487fdebd7731f59610857c5d3e2622e341618e4318674c138f6b9cebc3dfc0",
    "af869229773ce8ed411274088ee30d280896070082843e7eb54ff8788e346b174a3cd780a88f96733b97e1ab461311fe",
    "a27c5370c27ed79b01ed4ac66e70cfb3fef028bab6b861255b92338654363014960ef75bce40ebc546c6c2c0963888ab",
    "8ae5dfcf6b23de0af24b057236c95cccee0119bccd8e5170946a86157e04a5ade90f76e2954f9b5ea8ae904567419bc9",
    "aa6bd30678d3bc3992ab639ac8086e893eac99c8fd5b701468172f98ea63e804cc218b56e570bff9917bd27733790a1a",
    "88390a4e0697b8d35a57a7e56d0b9954dfd66cddb94bbbe1022d3acdb250bcd1e90a1ba99df287047da4152af6ba7e1b",
    "a5b05b3b6ce4a99b449b095865edaf0135d73a2db66b725bbcf8c784642b970df201c670421defa014d23d1b4c05dfdf",
    "a91c9f8f35c8a57c7873fb47d5474b5ab40f90ebdb207959555a7e2846e0b42a989a8ce1c63d9f81a2e7eae47add799f",
    "aa11540460443283a260c1207415d0b2776f9fb3ff0de30946a24ec073c8694434bed74e1d9793a64080b257a0d6cf80",
    "a8e4fd41932a214cc532bd15854710ea3f0cb494c9e2f5c1d9ba6410f8e391da5eb1b0dec674920d6ea371892ed4ca49",
    "9190a02baf3939ea895014d87771e4cb4598cd27ec554426ae944335cec0969ddb0510ebe722c2d7d93704713ba9f76f",
    "86474184ef40f9c0024cb682704e847e8170403faf5dfcc99882ddd37ad50eab78698358246b72fd9dd68cb46bf6110b",
    "84c99a7469a567403fae43fd1570957e398c9668b5b42ca100be367bd8f1e343e33bc60a2a1f0148661b7df71e81f070",
    "924f40ff6d31d47f4001c57910172be331ea399a1bb2e861fc0863cca96db21df85ace33ca7fad08b27d7e281634b49a",
    "8367c47355fb313e3777d173f838f41b901164e86093e29fb662d93bf4f7db5341a989edea4d203153be52126aedd46a",
    "89ac1cb98963036983c59483451b2f55072aa608d0b0c30478a43ef2641ce4fdd7208880fbf9884c2ade4768db19d2c0",
    "b45fe5394b439f3b60c1b0c1ac52bf0a3e7e7ddf8701164329c6ec4a2f7d9f957498fea8ac2ac22ad77a0f1783e5f829",
    "972f685c5646139afb3de00cd05def80ce1c59281ea35a14479d565c3a305e12f775725de16f47987a599a2f62efb3d5",
    "8433d830652e8d1375bad0589a715c7479c02b60d88efab136a6a8cc13bd2be4e1ca5b10988a3be72838466035ff77b8",
    "a6aa107bca6815f7e716933c5fc8b9b01d2e9480b86801229298aef9b586d1a270c72ca8edfd9c520066f60c56e3666e",
    "ab0ec69f055a7bf91b07b5be69d5136caaf85c0d49888b19ca883604b2dddb443e737b76edb5e38ec1c39bc7f2ac3476",
    "8ff7b2ca989a4c21fe9d2f0e9b4e3960934b13cac5d7b658d1466ef461f62403ba61dd1573948fc8692c593447028bbe",
    "8364f23831ab330e375c959848f625073f2bab80332de357f4da1172795c944015f1e8354fdee19953a7a5e0665bf066",
    "a4d3e253371c97a853aa276bbaa771e0eb235e1e6b8ae870e7eed9cc00c2db177527749d43f8725c2ca87a150043e5c6",
    "961e52467b2b2ac9e26a99f4f3a798a055ebb82f048beffcad573c0e734b0fdf2fd993939cb4cf294e9e6b928b02b231",
    "99727ebbaf50f61ddf30177d1bd20f72eb18cbe9b0e033d37284fe1df2dc12f730a6b706a1f67ff54ea495b5bf07fb2e",
    "8fe9eaa915bfb10073ded3ff4c4fcb4b60e3e49847a6486fc7a65838e37295f1b715800391bfff69729a91cbd97efe85",
    "b88130ab469796e532f7f74b088c7f1e9cc56e4ba7ea9d3dbaf684db858cffbdd8590e99079fc4feab3f1941b50ee57b",
    "92ec6eeff6f526027569e8f252be72998aa784bc7ce6fc0c3b9dab8a3a9440c91b8a1246c973c346ccfe8cb8a08401ea",
    "ae97d2f2a92b56ab841c025bea19868f114f784fa672dbbf91b0e80d526d967732feda7090e67771e028c324057f5427",
    "9116801e52e477cd5231b57472c11abac1bb2329c96e9357f2dd154f2223525cf22126e0e64f4a860391933aca3d3304",
    "8eb4801bab4bbaa8edf32b2577983276596b24b45bd1da0f8f085b6a887d86013024affa6b8bac80d92dfc2d51ecd708",
    "8a5025021bcbd4fbc9633554d825ee10ba8a78818c798a1de1d6104c36ee5d724db2a63467b6055646927419d21da0b7",
    "b80302ee593f210e740b94969c8801de497411203da288d97a6cfa4f5574c3ecbcd9ad168970140d38fff4813cad890a",
    "ab401806b0da80f00dccc19ee77386e062b8a5306e4136dd1d6e082fdf35e98b992fa51478f753acd25785290cf00788",
    "a713b4b941d1405243d6d9955509accdbb2cbe7b92957b5737bbb208a5660a0fc748fbb01bdb328419e2ee56b90952e8",
    "926d84aa36d4110ef0f996e9d5c56d880c458e49ca4379cdae1e191fa132fdbc703f265f7bed82168cb890ebb3b87a09",
    "86aa72ec278e2e7a07830e210cef5037f56c147c47471ca0df208cede98d789c1e62131615a812ed01d74ff5731b9ccc",
    "b5a19588874a30973a545cdb60f3f47f9603e01778f6ec8c8936c2aa3de17e085d70525cb6faa84406c95eecc91501a7",
    "981473fd8cbdd4bf73c94bd79fb622bc0de3d602f859819cf8a9fb8416ee8bc448127b7e8f5d3cdb82accc45cac3d9d5",
    "8134cb9c4610b073222b92c70325c7640f108524277ccc8a443fa48f44d2a27943b713789bb640012715775b6fad5bc5",
    "90736ef7cf9a75730a3f3ebc6ce691e67bc4c31e97444cd6cb18bcb3912a07a6fdb5136b0f2cf78d8b9225fc3b777848",
    "b5593625615df1711bead395bcce05068e943bb0eb3f00c4312532431fc8cbd099da482549b0ca1d60932ddc082be142",
    "b9df126372f7bef72a823fa8c097ea7dbd6c2c680fce81d6e9f7ec96f6b971df3e36dfa74c61729b2d5853afa05bd66a",
    "a8522fc6c0ee1d35b521eeb3ec398028c2c08b602eb279b514754bad581be82bf27de1201e565e1fadc58c73daf0c7bd",
    "b05ae5e245881711f856767823c128bb6b505880805d6af49177ce8d396dc6741d817e6c9225c84e88af925f6c1759d6",
    "928063ee117d0c3962b13aa0acd5242ec4b1f82deccdf0df894b85c3c8e08d32c6da6a1a71e27320e2b0e3d41b974d1c",
    "ac440b211a9a2ad923b9a42b25ceef378aa0a7b0446607f9855ce8219ee847b5e953d38e7a65b94a5d7975556a570551",
    "b7d6b7d6c156efcebca54a24aabb6dea76daa25b9448ef6fa381dfac463cd1044813d4687ac1e13b04952cc82103cdf3",
    "b89c7f27017ee3966fa97135b6357faea6b411973fdfe61d6032e1e9668e219184e188fd2e2edf60527ec48bee757972",
    "ad44fb6fd2b6b7a4143fd45a2124a34be84ec6eb5d785ffc5bdf90890ccd863f7c624772b970a052c793281b4ed896b1",
    "ae496d0ab55a8519130bdfbdeae621b3c106942148f5c41628f11d7b8f734cb9034093d396686737869dd573525b65cb",
    "8315cd56a9f1f203c30b2feed0842b21cff22068efc85b6821652194c9181dbd607644d55b1449846a6804e073a0fa0c",
    "b22f27eda364853fdb9adb0d2bf306e80228df09502b921642429ba37eb84916bae142f3cd3522c20ca846911e72da25",
    "8c2a4c66186fc37f50c878c6a9b26d783dccc13c50063b1ec6989f82e52d241c468a80c844da66b9bd593ddab11e4a92",
    "812aecd38990594520f474ac98980745adf7631a1b303938a43e3831a90b2d8e8e8aa496445fab722dd87d906654a5d1",
    "a7a4521e18ad5be65f1a2d492690df72d520ad01bb60a29d97cd13808366c8b7ef24e75e1409079eb670f08236fa9eb0",
    "a48e5d8f80248b0eae4bc0eda36c742d3763c0256b2747455da7c0e5108cb79871a0745956251bc81b23ed460351bc4c",
    "83c600d6b7e3e61a133b8d92be002b6e97015e2f2c38e07065ea4349297afc3f14462f7797db68ef54b243eb1a6123ca",
    "8abf33cb3a326e2f451541b4201d372fa1aa48a2f2ab63c7c51970d117d196357708b9546d43f0badfa53a1529d3aa86",
    "a8ac85125602697ccd49d1b503cc2a5cecc3bcee87b61a2731c6cc2d39ad76dfb1f6e2572da71cff9a744ad22c9f8597",
    "804cde2da6f8621aee1f0594ff892f45b250d862db40405b15335c8801ca2df4cae98b31451c6943131d721ff0f08ddd",
    "a8dca6e97b85e943425e80a77c8be7820d840161e3e5faa52d1d9e4c187f8a8066b9125f77895a2dca4bf0650186199a",
    "a27169ef0c2f19c968360b7745f9200de7085399fc8f147760c84734fb153d2d4ad71432cebb7b054d63245ee70f71a4",
    "95c78e0bbeddfd51cf1fe32cf6db535f6c13c841881597e2e94db3a04bb98407d7a003100368a162aa6d2f3d12e5b15b",
    "894f6efa334702fc19b16300114c6b560cbe085a15ec3309d01fe25929a143dfe3291123f2e2905bb94a7fcdc11ff050",
    "946da7166bc7e161e8a48cbfcd5e05ec31288f41de3d082349e8426414d6f99668e3856f489b1fe48c3065188e318273",
    "8c175c5005a85c2fa37746c588b2ab6cbcb68e375064be1addc2910ebd4955f0e2d5c5952b1cb57b62d388207801f0b5",
    "ae7b2d87763c6d0dbdd8f3b8fffd9c8fc24f7610344e5e5f1eed0a812c1aba1c39b1fa04395c5562ded49799e1a0c41e",
    "b9e10476162b28f7ccbc309ada44590766b0780664853b20df2cf9dfdb4df213ae022997987905bb4db7ebff6b29e5c2",
    "aac0e76ad58ff3cc06f3f79c805db4038eab420658a53961625889c2325e5cae9f4b236e4a454ca032a1819ea9e3202f",
    "a20ecce40505b0e56c9dd4aba8158346c7afc9691ccc9288646d25abc8dd2430a6e4437eaaf7c8bd0fa3094d0a7bf12e",
    "8eba254086252040c6203ce1abaa7283e82db5b115451ac4556ee36cb48eb68160e7685a1bdc4f5181c47019d1a24f16",
    "9688a755d8c2788da4f50344656cee300a5faeda8242c792e067c9800f49af3a5f85c714eec78b7e320a9de1889f3861",
    "a79e55fb7e94bc135b5a29c9219e3a3338e81816ce130a8da4663ccde1e81e8f595e12e04467ac579465121e501aadc1",
    "a6e6144ae059c9f3111569ae0274d75f086bce6ccf3bc725a1a812263eea2e3c3e598dc081cf667166c8fadf4f134f7c",
    "a0755d820386fb4573e4a45d182e157f39db4be32dfdcb49c76bd8e6bb9ebdf6a87bbda5cac9cc0f45942da1c35159d8",
    "a8c054b52bd9e88f279f7b292de5cab532a327947ab8af8ecb28d8453187c9197c095c27dcbcdd66d311b3b7d03a0d1c",
    "b6427724f1989620e80ac9c1527312736153cdf4af6c70c6c2f767b4446014a2d74a7333e4cecedbf073e171422fcbcf",
    "a77e142ac39e2a4c6b9dcc656c71f5d6b8161f4eb26d5053c44d032dfc1c123d4759e2ecbb2c4c3bdcae008cb1e00d2e",
    "a8083066122cc8400ba700899e72e8e92e02fb7cdabac6a7cf7b1b42d26c6e404173857a6861ea7fd65131083a1efb50",
    "858df4d60c55982627bde5c99597323d6a3990dcecd4c0df6553324f58f7087414db07f02a0ccbdb5dbf62d9542b242d",
    "8b1cf5a635402e876693105650b6c3c1f2fe740d32eef1a45a53bf24fc1ec0a562c2c79bb9c0e5257dfb02c6ce4b10d3",
    "80cb47988c154cdb06b841da509b65ec0eed9374e826a9dbd0b914485ab3074a9a51aad54baa05a838ba9adacb731fba",
    "86fe221ce1624c5c5d5599d8157da25f210baaa37742d00b6c914941dfb7c23bc91a9e2b999791f5856fba74e74d81d9",
    "806e6e46fa45fa28e4d0c6a6b2f1857fbd5a0d0d1a4d41d553e63e38caab7f2f71db752bff8c7fd332c29b59e9845332",
    "a11b29bb8d63612c41a97c5eca0c6f820ca691d073751744e69fc58bbb5a7e43438da188b95259b2cba2ce1705ef5abc",
    "b0bdc8c76c325f002f563893b1375dc49f02e1112a82658026884b393aae1b46f6b95e622625af2656c0e38831bffa6c",
    "91a25d6450a6df3e244aabc1433d0be093a5e716847a79b40f3048ed44fa30e885d442a047f42650addd15b5a7be47d6",
    "922d88c8cd67ef234f55f3a3cbfafaf4c3e92b71df4165904d0cea39ae0df2e60aff79c9316c152a4211add92487f081",
    "908fe4ecf69a6a8d970e81ffee64bf71f9195aa8ca8d76842654274358cf5f812ea5ff67e35b460716e67d9ab620b220",
    "aa3a54eac13a4b3b64e37730d56491d690166971ba9bc92ef2f02aeec55481f79bc2f21d04f8409fdcad69e95eb618aa",
    "8f7fff982f8b40b754c595011c48c95f48769e11361beeb4ee9d9d3f81ec1bd1402cfc865a61fd692e9040ed679b6585",
    "80d770ad3699c4e0946999213f7394dca8ba5dddac29c52d7f6c90b0b040ddf6cb9d952b438be59d5fd4eac8579b23b1",
    "a72e5c7b0875ee0d3797dd44fe867562bad1c0915b1bdbfb0c78cb55f33b049342da32bd5a9e6396bbf8dcf105061cd3",
    "84a155e4b63c383d9b2a7857c728bb0cdbc02aaf95ad7149fdefa23fc5ea014e413fad9344d4f7be1eeca012f84f603b",
    "868286ab32e72de2cc34848fc4f2b124b62c391cddab39e0a88a7ef19ca10338ebb5d4aa6325a1b5332310b3f7e0b44a",
    "91edb1a61105ec4c011357f92b14d8313f9bedc97f81be4682fe986f7261c395853d2e91c4d11cd60e567525e6c55455",
    "85cdcd1ef661cad1458630a818f6d4c445f7217af061b021e5390a085f466395babe3e10b5cc9cac5abd1c0483b7e230",
    "a0a4eee9949676786e67ff2c0b0d01b64ba4cbf39e486e43dc6b5c73168defc5bff5aeb8e1eb42bda8768c98a2ce6da5",
    "87ec49229774c17335c6905a351d37ea2ec13cd1cbf4f0b656ffbd994f560b21f0824190a6508275741739b14d498293",
    "b0c33ec6129450121af2c4f405f4ef98b720873ba286916bbe8238d1b62a2830f9f20313b61063652881f3dd5949d822",
    "98f9c0a0915815c6b8b4236243155df772520ddc328c2e7e6d11dc621d6aa03744aa91ccbe0e9585702c9913d829baf9",
    "8ac836ef58304f3ec1cf8f4fd00d599018688c13cf524d54dd47aabc28d23d84931424f6a64c511def5fd30307c1837d",
    "b4f42d2b7e123f160a3411dc40111c45b710f0a2586fd47594cdc96131bc12a0c8ddca3b4130687f23743549eb57be91",
    "a472c844ea1a4b95bc0a4d17e6dcda0703657e3eb93477aa527560aee6bbdec2301eb5b0c6c83192cad63fb496247d29",
    "a2fe217e03f2adbd1206afe840615c083f5e9d85a8a86817120fa0c3794eaa07ea283cb3d849dc65c99729561d6a722a",
    "a33cce34a8ef573b5356e1d668611d484baff0924e0210628862e545bcf03abbc8a06f9cdff9e53d62e8d07d0a59f70c",
    "8d60fc928466eb3e7a95c84a4fc7c59f36bc3bc8dc4d295f6adbb24fd5ca1b1cf0f88fd588bbab8259d0da7a15834979",
    "b2a9b2ca583d4af0aa03ae88f73d38d0c5ec3dbc4a75cda4a01b7d9b5a70ec6b91623050a6707dffc5fc8a65ab5534fb",
    "89589df8dfe8564e6bcca34006d6440ddb61e15231d2d459bac49508c7eb26d1cddc3091576181c52e3d9fb515aae247",
    "a179f7e98824482d6eaa89637fbe4fd976339ee04fdd336dfe3b47fb31ce609811836a57119cf0db581bf09ed94b5909",
    "80c0eef2d71698ed0d308ad3e130fb3d67943514fc1b444b2b0608e845a691d01d076acd693367fca8d63dd02c98d021",
    "a194dea5129d80bc436e2172db1d76e783dc79a121a21df48ad3b48abf265eba9001c0d8c9db99e2b68f9788a24032c7",
    "af06583baa296596d8b2fb433abea0eff3ffaffc854b0aeafb1e1921d2f098bbee0823299d9623c9f2797620b786c425",
    "95036c4634ab5bcf0422eeb78177584f798e041fbe63747976ee13ba7bf7a8d0e24d1bcd6c8869bf0c671069226ea111",
    "895345cb1c60b261778dc0daaf136308d5fdc33a84120c8319c814d0efb64ddc23882b6a46bbd1ef560ffd6e5f5d1e33",
    "a765b05bd64c8d6578483976db60764842a41e3f146f53574c79c87010cd100a8e4e418f7f1b93915f878c3506d5395f",
    "b93181bc3300258ff8e78ff4c820f92ab4b52cdcdec24ab57af6317a44f76b51edf92a05db6eef7e5b345ccc460976be",
    "b16c600c9c0c9e066849653e6152932a8e643b94e9d9b6a0448867c06b321567ea7a3df63c76ae73c178837db90eb751",
    "888740fb2444ebe0e1347117ffed721a1f9b25e5476b61dbe3cf5c72a0c6d0ba420bd38401aaa7f868e4e7d95ceb4285",
    "a36948c78ba766b23dfa538357605df3c0df8161913f32b6c6fccf9a19ef0ff4d0f9e75f07fac4f29c965a1493557a55",
    "ae25afdb691eb4b1e06979c6148a687c00136df5d08f15d5afc69fc4e7c9b50e840e1059e005a6dd038c6391ed6af3c2",
    "827a38431e9a8d38dc29edc18173ccf482319706e6d9677b06cafd51ed3f41c0415c7422e6c4a96a9c8a2025b88bcdf1",
    "a5ac1199d12a5be5e0fb1b8adfa6fcd55ba2395acaea5dc174e14290e52750c51205d97c35729eb5f3484d28ccdda6a1",
    "a4790fa36240b41632e79efbc76bdcd9f15520118f09b95331ea0c717f49424f963474a989d9387deb0488e9be78e69d",
    "91e3a534d370c94e2acf339380dedd94cf015f8d5b25214cbfafe2f31173dd51a7dc8b847e551c5ee8368e3868a8d648",
    "a1a7d4c21b4c44b9f27cdb46434de6dad199295210f16b9b830ede3fe6f9ba8e29842128eefe7c1b46390ce710309d0f",
    "b3a5515529930af56765b3ad7d9519be378b602f877861974e8ce8b5c44479791fbbd18b85b982bbce16e0584821bddd",
    "948e23a6ca3bfb0d80f11d081fa8e9df5179e9de75c2048bd020ff0fb0bc21d87c48e95cbb7312674f5c9f559fc96d23",
    "8bc64fba9c5e8515e20171c023a88d3a3a6614614ce2de9b397b0e00acbf37d04b0b09dcebe034fe0dfcf3a3a640cf34",
    "938ea39c3adf8339c69b9e48709808bff6aa86579b3349250f8f0463ee64655da727088c756313d61963b6738d0d4834",
    "a40ba120d789994e701e0a627caedde9a562e4735aca4e9d63f3779fa1952e99032bad9183eb49a54de24216e12f252a",
    "b1eeb3502873b20fdb1d7f65b890bbe438ddf616f7d6dcc10410eb44f216b9600295c55e1ed6186d6db6ca134fa91371",
    "a6f39e1e3831b7cccd459c6e221dae750f729074d0cbd8aaa89a84b73069601a6a4846f6279c0f6ae292495eded39563",
    "af3f5d9671821e30f575cee176411af31cf829a722e24b98f294e7d403fa0f11771fd9c2ea686e6b32eab4aad78cff41",
    "b2ab741f42af8b8f76ae1274b07c7362329d74d56577cf47ee476b616331195a1d76c5ded7c7b6b76e70e99611baef92",
    "98b7ad408c4e405432e8a2b54e804e48b011a5544fb768f2afda05f54759c9302f56f5f30d530f272ae244fcd57d63e4",
    "b456823a282d3cd4688a5645bf54a0c7a761fc3faafd8fc2a76371fcdb069b8f03313e522905b6f80b1bcfa12b9648e3",
    "a8750ec5beea2e5caa89f09ed49be6a509c578cbc02f168373af26bdce281fb1249c544262171d693067f9f4dd6470c9",
    "8bc622414f4c33c64df30e04d740b94eda46aa8840ef058fac6fb5a97907433a75b80cd91de5d1a5bf2e6b42e357c085",
    "b0b53580f5bac1a93f3b365d701c84afe69501c312f43f4a226f9097bb076997fa6000f4255027416243f34a888d0288",
    "91576032bf1b723f278018723ec3f450ef8bc0703ec4be8e5e297f925832c68a05eb77cfb1ee363055ce57ecfeb5adb2",
    "836f89b4935131a30c554aa529609d38ceec136a751e90c3fe1d5dfdf851d9c33335823518bf6ce9f1d28dddfe4b6140",
    "aafd8984593d816df1c4534ce230bf5afd758f712e614ec698298466f646d7c382dc49d56227cb04ede4e0f5826e4148",
    "ac2c81cde4ebcde07d2beff4d1eb8f89c78099133338bfb0e06b22ee404a05e6d8487a9c71b984bab838c48f58a25566",
    "b74ccc81d81cd73b9d949705fdd9d65103a82a6a1a15ce06523bcf62ce08301c4a15fcfe69f7ad06515f5589d69baa39",
    "ab24f9f78ef93123fae1242cdf7ad0fe525ef86f8947b9610b501083a184caee499dcf35fa29aed5183f9af2b0149291",
    "9494d7de06ce200b8ab2a5aa786758856dd3b45ff6e3a2eb8c99053ffb380ecaa3b9a19c45ec246adb4de47fd2f72834",
    "99f831bf34248ef1d01a6db314390b83dbaa7a7394a7d99b9dad955c63c515ce30c529c160abfc0033609892efd7a4aa",
    "874782c338367d04158ba967db303b967ef20784f002158c4435bdf2fb927d287dd232214f3078f219b1723682c4ab5f",
    "a2ecd64f366adf26a682b513c89e4f0d86da45378d47e2e62d39b8286d1358ff46c3b15d57e9883ff4ff19062a718fd2",
    "81f75db46c6a4318b81d29bf70688583bcad3ce2f65d6e28ebc5bd551fed40935d0ca4ca7bc7309136dac3f849aaa407",
    "8c2378a14f90d84e073d63c3e1a2157f54f35a28210c0ae56c90fa8b70e56a6ff0e9c2db72add307e779791fcb5cd8ff",
    "8a8df88d063d40346b245c4c3e63e345ccdc4e380e6ee5b5a25129b6c40a4bd2e7c66e745c3c84576f7076a520618554",
    "b35884c2970006869712e6bbea15f3f891e336bc807a2736111ca96a03506eb17f10e7ec7590e77446313d02aa333d9d",
    "8c30f9203a058f99c3595b3554ff9e0d4ea7b00754164edd3c57baba54cffb5e1cdd57523b2dee07f7910b925a1ede6e",
    "8cd3f722faf81dc3a98e39cc2e775d15c7f8b86d9e7943a902134c87292bfdd80f67896181df978b211089d1794ad6a6",
    "b14ab5e8d084de81a31feb7281801d9cd759e767693f7cfea6202fd16dd7edeb60c4b526b6d4020eb1883e6dbd9b7984",
    "83648c600e3cc74c88646a7d5961a97eeb3fc0e828421e5f30818d2e500245f0997d175d9c7f1dcdda0256a41b43f808",
    "b006f59ab209704a5de863ce4857fbcbaa399f907ae39f50a1200bcaefc2ce3ea66cf7939b63f91607e37763059ec3f2",
    "ab2a35cbc96f6bd2842364a423ba69e27e507f049961630fc61bf43ce4fba941febe13068668a534b603fa925705f78b",
    "98958b4d374e9d7aaeb7ac9f8a91e8c6e7a114523acdaaeb61dd9401dd0b534e33b9c732956a45664deba8ed7ec73e1f",
    "8eea41281b51b70b5cb2f6f80ce55ac626606989357ba080980c9c2235640203a7668b8e53bbf0889164677a0344243a",
    "a4eabe4ae489a00064359278c5cefa7c6a0a1ba722a01ec0faf88858eb12329e1ed66a0ceb1df2c900143fdba5634838",
    "8a4824893b256844a9bcb66c82a24a6e6f192b1de32a824f3d557a8316be90d6ce625e17f893b32e54c910034e38c1b1",
    "acfc0d3244e93203d9c2426e57cbc30a3295b7dfe6dff2bb0555807cb7e5c7cc7de2984907222ea3dab39e18ffa5f169",
    "a41de4c2b3297429dadf3ab6c9643141c6d9671158d7ad3f175fd66fce8589e9a0acbab6300678ffc19b826bbfa40f93",
    "a5ffad7692cdb55ad880ab95d4246bf62f27a98fed6cca74d2910f2063e3e101f38d852c6f73625b525eb0a35d128071",
    "b5884f6292fc6333a8452d8386f1c3f494d7ba49f1015791ea50a2a0862325af7b15d2ddb100a7f83be0e04a29b6d72e",
    "8a96495a59f0ee62de10ceadcef31a1f83f2722b61ca11f012c863e57166ebb420ea1096f10b5baee987d6b4614c9cf4",
    "a6b51f984f470bf940dcc075d625c5ccd04f873cdb638d85d4329e7c5faaecc37b45ef38a176a18043658c7054a4a651",
    "95729a629ac15e08fbf57179103f029e517e4eb157f27f3f7063d3aa369712951ba67b27618fdbd8f1d3c4dbf5784bd7",
    "91872363200e69d920ffdbf63c27738e7152920f86b3c19825b25fd304cebaf4600448802a8644a2dde2639633f18907",
    "ab8999469c10141bf502c01c34f09a8824cc160cfbc3d516f5ba9ff9035b94036b16d99fa4521866373ff0406c4ed7fc",
    "96aca7c120ccb62b0427d7a7a7d8b45187cb36c17c8968e7af0e09758c6d3911ea570810aa7d746065eed9f9a91bec3a",
    "b05ea8a83ba06210e0bb180c9f8cd73b3bac21bc5f541af27867a388de3f334db344d597998fc6e03256c56d8a68ddb0",
    "aa3918f5b2f9ee75a61320467abb4d50ac217a318785058d8734b7d0d204ac1e88117e95beb5e14405fd836c11b8bec1",
    "b7ee6a2ac10e69961e1c028961e04f2d19d03e4c8b6f57c26f30b70d348461717a3676ebe9668031b9b365fb2669373c",
    "91445a29c5cbc4864f78714208da289de2523b084942c76833b0c0e8448640013fc20ba19774dbcd4d5564c55394fcce",
    "926c071f497d0fc54d43ce05edf45d3901862f5d0f697e715f7b82c8460f61179062b67d6c1bdca1af4cf9f880b6121c",
    "a50bd5eea4fa33d4af7252d8884ee1175c9a48f5ff2a6609a810069b56a019d48a5eb75e024364c7d73db105534f6b93",
    "b493af2fdd304d163eec97acd5e19d289ec5c690001cdfa3ef2d9b70d667d48696520497f41e8c7e325f694f3c4b01c8",
    "a31914b66a5d02b31a23672e888f890625459bd08ef4cc4e893f14f05159a3e426194d7177599a190497f67e9dcdcd09",
    "a3d58a16c35f962e7cf861d0c71bb8c2a3227555f2a087bc17467f841e4c32c7e872114a1429fffbf2b2b1c82bbfa3aa",
    "97ee202091a6c7e3f072c72aa45d7feeccc1450d2273b2b279041e2e90de6ef08e6a7bf343f3d34e9cfc1889b5d1c264",
    "b8d0bba1274e3676a73c471f5fcdef20009a63715e0118729d370bee38e1e5c603780caca1152297c8fca40c63dba100",
    "b4a7f407d26bdab8e5bebdc21d191f3eaab3d161034d7fbac9f2c5448192b7bbee515324be65006ab8f29c0d137d2580",
    "84c54a02a30fd2c08839a0d18e9e6f179278cb0dde689607c5e0a3f8a1abd39498a882034ad54d78548fabc0e878e21e",
    "b254c1fb4f5fd6193018b2ce5bfafac9347aa6aa5e603064c171f0c8e9b302580701fb135054146862fb1c432c04920b",
    "b36e5caf36399bbe3900b71ee3c1552988be0b3a6499765ad67ca7c117efaeb7796fd374581abbec5cf695a1fa448078",
    "ad6841cd591503cf111b7f4223bf6a7392bfbd959b6b3f904d60dbd68207328c0bf6598a882d9d4278793050573aea6f",
    "9410d2c11abf288930dcf24376e9e9ae6d6147a27e6cd284fa2164f7ccd34719143ba7f6da53ee3f0bccb9a85fbb3fd1",
    "8f98d4610624095cb677b6108e6e5dcd4ac1af5d7a5f88d33be775b52ceecddfff20655c1a613d854978e48e8f11e2fe",
    "8b9e59b2437dc808cd74083f08d4569f15e96d42da0fe78e3a86266ef81863b79de5c6e322e5bd992eda0c8c140aee15",
    "92a3bbe7d2302e44b8fffea7f1d248474263ddb0c7beeb002122279685c7730730c8284c77c1056224b8816a6ea5362b",
    "9143d3590b519ed63a49fbdd41bc6de5afc98e2c4bccbf270ff8393ea51e6deffe0fe686aa784865b751d95bbe10298d",
    "8e512c5974b7ffa430fe98952127de967135c6ae502ec8152c873184211e5248941b7d1672591a6fa6b80b99bca72879",
    "b887c7dc7581734afa98b03ba8357eb83721476415f8d67e168e344dc06541ea759dec0108b4c3dca790c5275bcf59b7",
    "a2d4ed22ff60a5aa28bf1f60c3844ddb301a4ac5ebece4a8eada485b11bbd256a64bd543177829f6d4f41e8375dd860f",
    "a8c1081c04eb5f9f792bf0a9252aaae55c39f3d8da2ec520110815e6638ac9303b18457853a4ec1ef859217e93c03438",
    "a671cd8aaf7ad90ed00f423351868ca9d2dd2857eb91f4d6459ff49b9318b817e86f5affd81eccb5cdef11cc20fdce52",
    "b0389bbc9cb329a65fb4e2e8a3e89d3952243fa358fd3c5f45ee8f1c8374f35ccf3b2efcdbd96eef8dcd58e700ca16ed",
    "904e47d57d759ddc0ed0b87b7ebae7bafec78a4ab73e7bb9a1be629602bf4b5a6780ce8e1906b6ec33729ff7b377cb39",
    "87b949b73dbf45155068f05d2f59600f7b6445a6017ed287687e1ce35e0554295785712fd5619f99d77c2695d0c02a7a",
    "adafb5d7e35b2c62731be591996b208d2f54831baac113dbfeba334bf7de96ab5409e68b1c699a6524bcabb3c70142a6",
    "91d6086d3ad1fb06b9da0aa3b96755bdf57af3d3b91c8de8d5c13be72a4759040041d7d6cef888c5d496461631b4884c",
    "8b1efdc49cbaf9630341b86551b42b77fd83d20580cc72aa78b67bf4995bbefedee84bac4ef0c920c606afe177fee7d4",
    "88c1f208fd69b343cdea97d6be630a5048a6dc633be0031156e4d89418eee8e7dc041cdf1a0aa945321efbe795529ecc",
    "b6b22714479f40a8c2abf6a6e2a6643eacc79da34f058636ce52c4c326457327fd6d5480d7acea376782d42cf2d829d5",
    "84d093c07bce63dc0a42e7312024c28aefadc801192ed4decb309cbe11a5dcb79f3bc8ee899ad15c1aeb436dea45d9d6",
    "846bf35700d5d60a2e4df693c0fbd9cb1a8f2dc696e83318aac23b615ff85dd2e08532f191a677f83020037928c678ad",
    "965eabe3b9bfb2ee0da71e84794d3e6e3788ceacb070af5ed28201e832403b649a06e7ff45876cc16a35081d2229791a",
    "932e435ce44549719c8d38c439abfe728c889852e7f9b624f8cbd11329c8d8722698ccc8a558fddcb58f06d84605eda5",
    "8539809d3d9128db942e439868456db70d9d2c40025e3c689bd8bf3299ad8cea67c2c39c8dc32b37e871e357f510a7c8",
    "988bb8b43f2cc1ac9bb56261f56c6d6c023eff54614dc41952b7de155433021f9f9e8d6dfd7d05e842ff3528630f3c68",
    "a79b03d93f1d0ed04ed42c6ae5180d4ad0f91fe1819e7fdc130a92cd17ad8aba64bf80a481b7bab367c6e94df6409b3c",
    "80b15db14e62c864fcdd041f4b8407a4a8f8f329db331b262923d4c8b09a045c49cce715e87220b3c82825dd4a33c226",
    "861dd6abff5cc84d122be1c3ff269d30b2774ef413417732ddb8e5732bde2b3159955acb68a9fa698bec59038e327afc",
    "8563d76026044eeb4aca05d3760c03824a9688026f30fd2b948c8db9d3ed7b4db730246797159d407b1266e290bff975",
    "b82b072fd23222fa9dc8977dfb0c293ec35eeaafc8fd387f9e40e60979cd0bafa928730b1cfe1bc2f395b5a0b96deac7",
    "a25c9634b03edb08e0ba17b64fc1aadcaa4b40fb7305f1aba578fa1e5b1a2d3639c15f3f37c48102870ce3ef8ae3fe9f",
    "96ac6b64f85e1d7e48f76166a70d90089def68b042b38bddf4db33298646ad66d6c517aae38575b2bc26146123b3daf3",
    "8513fedb23a5c2f7b144ae3d314045fe1d84cfe52e8d5baf61fe3d79f6090d27a2aca850e8f954c5f3ff813aeff5394c",
    "99725cb26e8e608ca8219e1b42fee1b64ecab5447f6d05b6136dec6e31a5fb9eb1a1bf2d15e8ae2c0a1d67fed16db6a7",
    "8672e0190db8fbaa1a89f0a7bb29762634e9c6cdbfc8e1740c858ef8ee11bbad24c901918623686c32d124db2d32d5a1",
    "b262a26133d2ac5a6842be34742aa23042ab990146c0bd41aa9b9361ee94511da1caf7017d6f713f98165f5105cbfcaa",
    "85c87784ab7cc51e82125b90941304069bbf7251ecadf0ceeca7bacdacd363fcba64c0d4c9ecbb4c01fc72d6944dedd2",
    "a60204a91bc8c6f4542cc1e8f817f48e28d2a70a3e9e5fed7d1bfe41057047672936f559fa366e10309fff1cce30e621",
    "97089cb60d7e7a5fd05c1ee44c77dbf6be099cbbed9d53ebd2a163680b9980e4786516785878bfcbe22851faa937870f",
    "b08b4d5a72a4d71839298aff3b91ec1f6ad0f31e9bf8f595e15ecd268b8159400175c1c5048eb6911f7bfeffd3bad898",
    "994ed0142381f665653cdcdacae47b4907a2f3d584c96ecd97c1b85bc84b6a75c4a1d95e229145f2095ce1d3e280e143",
    "8a8bf099a24b8c8e0016fe8eaad91367bd742c55c018af8a35db16d10d6943254d1f2cdd49e28f2a93d1c55628de5705",
    "920bd911be8e17efeb55886093eada234c245a0878de7273244db7ef506a93f7557d51a3e4ef4779af94c7d3a74e793a",
    "81dfbb4664fc5eaa99a87c112442f0dcb17880a1ce00fd4d64efa8a4fbe882b87f47f102f1ab7a26e41897fb1fbd747c",
    "8a5e61a8cf038be6e889eda47db07dd3231d3f9fbb2acdac28da95b4feaa4445a41c655a4a0367c40f68e9a8b30994aa",
    "8b7382eca3e6f1528b043eb4802c688b6dffd3b9132f538aa702484efb55e8fd3ed1b4fa1bcdcc3c67547d5dfb249288",
    "96a91c26b1356a6212aae15563e468efeb80c49e4f825a28fcef30fca3cfac61f43328e3660624155c4681fcc037a4a2",
    "b8780164640e4acf295d83b4fd09b432ce6c7d546f3be417f94068d8651df9db0591e24e87415d36bee2609939252535",
    "819a9660aebfbac93af79665a2101781cf66f902b6203deba6441d5fdc5de06be00dc4f88a4067b5ca35f20fdfa39db3",
    "a8fe2f76b3195f9a09b11e93aaeca5c561f755b110d0e947737db63d2e37bbb6316b61845acbbbccbd5a6d28ce73be09",
    "816bde1ac228af0a70c5e0ca889ac86d7576c0bda3c0278d21813400144abfaf70206860b9165f89945058cc3bc98e97",
    "993ae3e83460db4a55ee7c5daa1b6ac3051698254f75dd666b347cde9ec1a315ec3449ef733775771ba68a7f7af81942",
    "a6afcdb438b792d42d5958e2bf41a49f70c7950efe4b4ae521cff7875b3aa1144565f54f5047fe5c3c7a99dd5be1c077",
    "8d163d828e7c687efcfbee3995609814db1b0c1d3e3889c327d9466a16086099af1cc994ba795a0788bafa37a92839cc",
    "b5d298d00141a2a8a05cf6ca91ad71879f9b75805ca41e564207976c95a09671c0823b315c71c6b4ace6f728e73c109b",
    "943ce5945884af53b206ae8592876cc55f856db407c0eab4345fd4b56a32e616e651abd9af63b43f3b2c8ce54fdc51da",
    "a57a75f63f522eff6434dfb8115109b5a96198714555ecd0399920c2b8f9da31fb6c052ffc246342cde57289681c22a1",
    "b64e5c5f6857d1f075e4bcd06cb1f0dd22d1d7d5ecfeccc2caa4adc7029ad6b419e4f72a6153232ff2ecba6655dcb00a",
    "ab97d75850ecfbb4ea571aeedc0beeecbb10ec438cb35a1ccb4ac5657dbf826612f40eea6d4922b72c147b53b10b6e4a",
    "890f710778d3ba410d9bcdf10f604c8b3a9e75eefe28420938ea2c0844d91e88b5aea3a8836a263bcca50a6a20b98d9b",
    "a2aecced143e4d71fdc60166748985700635b1253a7c7c634371b95223b8c7c8f7e9b44cccdd76160599d5b9c842eca1",
    "a4b32c8aa8ae54c5f761eb2304e416e1c7438ae40db4437d7395d9eb603317d03385f92fee099709eb4b26087912cb0a",
    "97e5baab32366902e7d75974d1263ca11f6df21e1118affa8adb3632bc98d517100d0678a19191ce09cdcc60c4c48b6c",
    "9095aa24a2ad8b0758898fd92e0abc507059197671bf2cfbf64d29d67736660fb8c5b4360727046f66b6e926b4e32e48",
    "b11e83ec7e804cb4519759f1bcddc4c27a0b22edb138fdb7399b6ed5d3db5d49f97957aee4b659a7668413024b354bc1",
    "88ce54ab5f6019ab339c1111c76a240ce881f6da374c040d2ff1f8cb6b28842e5898d85b89b737c43be166cbb276d151",
    "a9d83959a0dc003c11770843dc1d312f02cd4e93c79107442e42f67e94142b430b5157fc1441c13f97edfc8d38e2a258",
    "ae519ff3930a5e53c6bc502312d6af591a834cc044a6491d9b91c257f04d97329bea2d07578a49d97a0963417d603bc6",
    "b79d60f4451edcbd6e1698a96e8a8b78676ec0a8632517caf75707706345cad1c00a76613f67225d911df2cd78acd183",
    "90c4b8990f9b59d3b482ce0d0cbf1d907523f515298bc2456d6eff5d8428b09bbf8bf5a18cf8b96fae130c409c1dc763",
    "a4751c7cd0fbf4f7bebcdc5c3c04f9ce281da6a10037d5fef1133ca28a0ec39fe6f2fb3505cbd860f7066c06172eaf61",
    "8ba8c35d24bd01a70df2eef1b2abcf96fa6692cb524d2ebffb31de2b369e188296536f30b9ea43ad53f8eb848fe3ce87",
    "b487b5c81b039c1b212c44d2592bd8f2fbee6ded217eff0710e71881908dead36f5b8adf53733969b8c9db31da1aa07e",
    "b225a0c8f254568ac9f8c6ece62a30f4d06813498c0191fc172649d5e6da597d9162154042725faa4f82b7cb18060e55",
    "8e9c8a7f0ea4f5363d29dd17dbee93e39bf08b63950d5614ce610e35f24d33f5f4a5f2065b369acfb46b2070fe827d6f",
    "ab8430ec4c6a5463b1eed7ebed9d7edabdb8cfaa7254cf25d2366db231ed94faddae910f1b7171a0e2dd254a59ffe000",
    "aeb9e259dc07c5473d1846bbee75ce81ec642dc0af0de3c7c2ff772d9b1f3965fda05c271bd8ef895b269bd3a5ba0fdd",
    "82410b3550b9515b656c50f519a594cb26eee38bd855797d7e7715ce4dca72e65690c8d5d0e397d61ed53f2c24c9de6f",
    "826b329af878feb804431adc127a34df4781fec311133af61cd96801b1a0519504cc72675a90b76b9b35dc8bff8c4d22",
    "b19b64787985fb9d43f106f9243acc236e7c29615626b9bd67c261c9f85a7aa260c74741281ca9d502b85df73d2f8efa",
    "942831ef608c1d3d1522e545233f1bc03290ac8191dfda05debc71fe00b49c589ce3a8f5f1aabb657014bcf434e96348",
    "b3a9edbdee74d5443a9604d48b4d3c2de38e7193482ea163fbf879f3df7805dacd1da67f7887811dceebac6bce0fdfcf",
    "b1336aed6f3e762665af9b664eaa476b1ddc29c5ebfa257279a7602abbec8cd9ecd128cb2d613530a6adff7be0795a3e",
    "8123c9851a959c7af045965756be1c4dace0de74fde6bb6ae901eb8d42dfe302e6b649c7a016dc2e8c2cdb9c038b4032",
    "a5e998371acd15fbac39362306304f72cc39867b15417574ef22d800ee2cb9a37f20a50fb7c5b79b6716640cb94b45dd",
    "a2481ea165051396b245d6b99c68e1472ae16adbeecfc7267de7309a358e381b7de482bc143dc5536a28832cba8986a6",
    "b35e7a80cdeb49dbb81514596279852d765d73643739bac618c3fc564ac37b2f9b43e45377cdfc4b32bf42401f6c219c",
    "875ff0ee1840143262bf3608c8f6b57c6252c8bd82723b5ec77ef1f59a9d86bad3a850a74f3d126585b81e3289cafb0d",
    "8314f011500c2df975b1cfcf6f19da34b5b11882060123d86051d97b2966bd98126e71c5fe8df1aa0d129140ba925104",
    "8fb5fa28951f360273dc2a3ebd43b492fe03174516b25ce220a13ff63250d0c0bb5f455433525cf0c51508ad48f4b194",
    "999fd64092a0444ee2eb81fd9eae09e98220353b5cc6e003738a96f9c1a3993a3030b42a16d2580b55d01b44bf9d9f5a",
    "958756c6cdf2bdf18b12bebe45ae12303c5d2c55da48937666207b812465c39ed086ed468bc353c630b3df371e0786a3",
    "82e27383833be22dc5416b7cefc7f65550c2bfbc6527463b369d662e86a653b501c2a40f15cd81675013f97da844c4dd",
    "a76f7d13828c3f0afd2ed43703b996d02fb814ed6a72e87319952460978773e410a8858684cecb6b2e58b7fa0d67ef5d",
    "b098a636dbc07341ba0015e3b40f5e41f86cae8ab9f020f9d008df9ad600d6712ef828ca63c994037f39e66e1dbe7b20",
    "a0d96ac82075eec8034ec2f0dbae4e766d7fcf739ceeeb3ba25fff0467c066488a63c8ea485d9658b5f13b40e8e3b5f4",
    "983fda82678b934c455fe695a601ab44a13dcd52e2cf9abdac0db52f63c6880a160f5a45b45ca3a7e9e8e3751c562352",
    "845305e11baf48a5d0ab14f32b009da4ef9e3062bd6fe78b8aa7a0ee8f0f80b20f9b80f1b2c6458a0608209774f65bf9",
    "94c262724a6ea120fa2cba29cf95cdbf9ca322214dde06fdd72f0c5658209837e9acf8f4a0f18be5e0d2619c425de949",
    "813be53a379ff46f0918e22e171152dc38a41b7937cd292c52a5c41ded5ad7510bb79765f2bc9169ea0ce37de3a62e72",
    "8c2830ef8cf3e876f8c5e396d19d1087ce697bbbbaba9a89e0e136160e5de126a474b4e872de6468e5ba52d5ce12d826",
    "b7ae576eea8e8c200cbbdbd1e893e2a7d6fb531c1e372748cd6efe5fe97da0984de5c89d447ea411a0540195262d4a30",
    "a90cf5fe9b4a78f3d2d85659f6ca30080da766d46e355eca4ea7cd0edc3a8e0a5196380ae43688302ea3cbc325b92040",
    "94190eb35518898e94aa86893b35eef058598ff36856247023ffa9c63973bc4a9e431dfd31355583d4962bf5b6d3a315",
    "ade51a72f0894e5b9604e868ba79bf8de097d09ca79e844842ed9cd27d6996ed01c2c4cf32aecf2217a5db06bae111e1",
    "9743d18b422b18d5753cf0b9105ef465df99c194b39a6f868241d7561b85c2284d6acc88055809417f380f20c9bf0a8b",
    "80b339047cb37b28db60fcc6b25e07451376d6e5e10e4cf28bf0adcd36f07baac9f11956e4e8f701a7fc994639a24b04",
    "946884bc89a4256b7868a95555b54050ae6a64f86df362beeb56ee2d92e6b30dcd25dc913f57420934e685b753d4181f",
    "b96872cda61581a74cd774262b481b154a0492fa5cdae9f2b90db96e2356e7cff8567896c8d84bdfb7302c5b389dbd19",
    "b9fc9c1178bd14a67f0acde11c1c9c5ba7421604e0e264f0b73a2ca36b591af0acaf8962f4b5c4b11424f8a20f674e1f",
    "a9ed16ccccb1442d019107bc0b1d4d5b5550635a5d017e7054220e35098136b9a98dbad50e5b7b06709b8ee8174f2dc7",
    "a1a6212382bb9abf0f94fa266f3a443dab33208af4ccfdc08a8d93baca62cc0ac28e986fce54f06aeafc7a3cb1ec19eb",
    "a7e6c74d5491b6bb17ba18c8e404edfa93bdf292ebeade255c130c2b5c760d02823c80772f4e9a7dcf3c7502597a6c43",
    "b3ff348c02bc784fd204464b5c4eba89a5d598bd41eb6db71fab38e6b0841f549e17d220ac18a0c7931baab1b3be82b5",
    "85bdeef3a2b995a04e7ef304ec74757b35781a7bf1e78443d9cd0284f242039a282b14a735ccacb497768bf9c84ba254",
    "81fab1957de5a41c632e007deaa165f75bcd5b640f32c387fdc710b6547d8a526ba089fa8e010504a06c1014ca3cd342",
    "98afe49ce5a4ca3f379f349ee72cb6f2ac474646ceca53cfe16344daa5ac0af74fac7fa6eab0bee92cba6e0fe5d45e98",
    "95c72e89b1e5862fe36711725c49c9e0ec493d45ff17800eecd22ee36845e25c09adb2737ce7a1bf6f067978149124a0",
    "9817ac7bfaf2aeae88332f04ddc7d0cf2f3c4eb25879c172fa879545f11bf9ef44bb4678f5f66a3474ebb547d060178f",
    "871f24fce25199a202c22e2bfa9d5127877bf4a37c2b41193ca2d1b557a1ccafabd6c51e89f5fd90f64c2a6c97d58f5b",
    "ae5590262f60932f7dff23d3ec3094ad65c3d5511b8a1aa5f35d86738b66282aa05f075017a1588f13e66706a9730dc3",
    "aef681b7a17a80a74e8d91b338fa961ce0aefec79365d9d6c2bb81ca00766f3f092fb8e100a774936d70a6085ebc6873",
    "a888485f28603e52c9997d04359ff3d40e505410c008631a779ca5842f52799682c9ae373a72a3ecdaf7eb15d837bc65",
    "936757a11a74857edd4b43653f61c561ff7b68cfdaf5a6f15259dac4dbc8d5b88947a4efc3dd0402b7776af345c0205a",
    "add87c2315ba76d35adbcf309ccf46f849c65a3b55ee0930407c116730784ba9d4dc7d0ac72855492d807aba2803b3a2",
    "8d0cbb9ae0a019b00b84e0a6f0c4dfae17e7e435cf9c23b33d1c1c212282fa8a7db457a318135374b109f8b192a4a7fe",
    "ac0373986d575f57c924fe1b35362d3c8209285c2b5cdbb7837a472da402c52bf1d6a188b8e5da2a581554534eb67ad1",
    "98115bd917b3241d5eeb4625860981fc7a4b0d750df82a5d906b7744df8447026861518dae18a1bde5a5dd38f679d3f0",
    "96cf7a1784f452806f376b1afe17cc77ad7498c311c7f96b322409cd2c27c9b72ed5f90f61ac4f0085e5305467bf48c9",
    "b07a67bc936cdb9ecd5df78e23dc7bb4bc9561c66626551995efc99a9e25def5e3b591e01251367571806fb477eaf573",
    "a374ba7c8ba6379eeb25d8d2d25b565215f383f17d25845ffee9473e5579ff8ead4b4d4c3d8ecc65f6c5f553e828fedd",
    "b1ddb779bd482db15c6fd0ff2f15de952d45d7761807e72b253a8f9994a2d2c8b6363784c66ee844843cff1a41d1888b",
    "aff5386f0267340c3c6c994f136f462c5b6d658e02ff00e7fba773cefccf7755945f812b99e99187fee66aef8fde2340",
    "9311313d5d6a2bb6b14f207ecc33791ceee90cf803cd92199d22a1db31d0b964e2d13a1752e56f69517bed00a89fddc0",
    "afd8d5cb18d4a1c1b41d20083b611e06db7691f8cb0464b0a292acdf3a9f6fdcdbc7f77b143d1de00d8433b9a719f2b8",
    "b469975f0dd3cc5b78c11a8c03104ab0a8694ab1ea3e2d19f2d86f2bec62ed8b476f7746a5612f81a4b1a5f6fdd83c57",
    "a09185e88e3cec1d5e1aeeb472de4a3fe71054b9a0bdd825b94edfbbcbc0f3f89c7a0ad896b62fad22508efae4b76ebf",
    "b392afeee01b6764338eafa013e0a6b3f9a0ca7e2fb8490ed9d92217285bb3ee9c4437542e8f4c264da8124b04f86d63",
    "84ef16102df4efb7f4dc22595d35fdd3b3a2f2e553795b8413e93dfdbd779e9e82271397bcdd467b0f0ebf4befeb9ee2",
    "b007dbae84ed6757ac92d1f846549a558676d9e106ac95bb786dc91d7a62d169610de9a71a697a70b4c6367ae294cec8",
    "81978d97afab321c9dbcd717255e3ba278ed8cb54fb002dfc38a0b867bc50a45a5f240b1e397fdf395e93e8bfda30c56",
    "86f2c9fe9a6e3a3aec8a1665b5d8fe3494876228cd6c0de59a501b12d7b68dfa8d16d634c05b696a30d278dc2ff6927c",
    "85a39745aa0a11d8a81e1dd430d13e52b27690d9be8150a9972dce4f4b6d6c0e2b82021fa741adb1b8998e596101a1d3",
    "ac4f6ea5b3ab00075ede852cb555d5ddc5453a6a78207bbea0fd6dec0045a4c9449e9a9504671911c1070e9fa6a26c10",
    "89885398d46ebf3fcd32cce2f542112c2b0bfa2ad0e1e34f147141b50e42c148720c0e9b17857c8825a478d4e141295a",
    "b84e6d6a2f1890c227acc80e862dd845309305fcb5f28ace87bf170bcd9474eb2406faa99e54ceedef90c2213ed7253a",
    "a94fb87cecbfa8def44887acf851f397fbed991f9fd6c29bfc34747a3f2940af34294d692ae078b0c5d9220da1568bec",
    "886c414bc2a41b17e3f13d7e21b4bcdaa6ec57b69eff00d9b3d5291639d307c2643cabb0511b4bfcbe8d51e53246d757",
    "aa688c1f9aefd6a1b52b7a9cfa9423f6c6b9dcb601db1485e870827910cb3a1ee44399dbfc6ee380e1899627948f7a45",
    "adda46a913f97a3a21bfdad49cb80da02937106e04e6f1538898cfadc1554c7dbffcb8895242287c06404e93d241611e",
    "a299852963a249ee61348fda75256502b487a2fb6dc509e58ca03d5707c3bb4d313a5655ace2e3697870dc428f493b92",
    "86127da3e169282271c210a03e21287c4616d8790c2e7a07de4ee1aeb077e420ee17e7dd90aed9c5963005fd921bbfd3",
    "ac337226624080ff5d699cb515ec47ec91443f784f2c0e2ef1ef5090bed2b682cb804444bf9d2e250d29ab0c3aa4393e",
    "b638bdded8daadf9482757ee3bab65183bdfeaf313be87c35b97fed1513cdf06aa575b2c14e98d3ccd9d5255fcb288fe",
    "b1f2285e4ec866d798f50316c81d9744331f6d3a11dd795da38135273bbe5dd1aaea96678d80f5f5baf97b2ee519392d",
    "a32afeb9cc898a8c857f1b120da447ca971eab3b63bf8a4fdcdcc689ec2fb6f65d09a344e9463a5542434f52898eaed9",
    "a1d8fd7a7fa132b9c288fb9aea1109f88a3871adea5ba5250df7c5815a8fde7b31e8ce252fa2895122b913fc295f442a",
    "844330a48df5ac3b094d6aa71db616fe67dc08ea7e83e291f9ea20f83556cdfe4b91705eecc4cc3ac5ac8819ce5234a4",
    "93dcd3ea750c2257beec1910734fe138ed1a589ad22f80cc5cdb951754cd29dae57b3b56bf586684cf7e35f1ba98457a",
    "94972dcef9ecdb7bc4cdc9bcc7800a4388b42163080a536cac823ae6cf187d7df0dc8a62b8244eae808edede6d032341",
    "ae9d3f2fcc3cb198e80503fb30123b7bf6e5d67f0406169e2d2f5fb6855b55ca92edd1a2e0ffb472a74ac1485a68b6f5",
    "b59af1c6c5cc43dd761605240ba959c6605e9bb056f4ed9e0c9e95c4bf01efbfc4a03bfd05100b975636cc25bd3c0108",
    "a21210cb111f113079c900ac969e7be7394bfb4f0d3473594b0d43bc0cd2f85f7f34b92b2077f7f949aaa603074864be",
    "ad212eebe07f0b6f4a44df5e93f2b4be4b630e9ebca8a97f11ece309e84a0f5cf7d6583aa211491a184a251cba31c110",
    "8643815a6ac8a639a0bca4ce858eb8bd022bbaa9683ce7fb500a4542172b25e213bc4f5b5e1fe4abd914342531a3c5a4",
    "8a4f706f1d01fba2fe2494e4d588e743b144552116f3ab381374797d47b30ec114ebd61c7c580a7d6c982adcd4856121",
    "8e8f9eda41e43960c34a19296fe7bdbadc1f9a9de5cd14dd8d17a3880c0da57d7808b24a96647bd243b46b112b5466f2",
    "aae5d0b98e9b80119ff03f9fa5d7110d95f6fb9ba644289d48dc6bded408127473217fb25b8b39d2cabd91277224b20b",
    "897fe1b942d6d6f3729f44d162c85a4783053f3afd3e944957d28a76d78aefca1e9cfcf9ede01ab55897d39fe393239d",
    "ae89947bdda9b0ab8a7d0640b69c849c2ddeaacc7967f0a148a990f7f34fb46a1ba4b567388ddb56247a7cf6b29de048",
    "a3e3e80715c39005b369a56a15b8ecc9abf3b3009270a0f40c487d9e007d9fedcb24e3b8d5b17580787d39a9fa3ce90b",
    "9648627a1c168671984ea7e2690f37999a7475524bb1a7cfd077c1a19d28e76b7a1db03b55e5b94eaf630b6248d5892b",
    "b73cdc8dd1e5de013db3f89897c56a8b31c8c0bab89a23beae248f2495ea3fe0000d6c27f9350fecb0262b2f56daea49",
    "90e7aa6f7c34feae86e225ab54bf88023be75446409ef435cbd01c134a4f26fea4f820182cdc09e4c41cf1405687ca18",
    "ac8dc5111bfa8f60f9bb9c597cc82e92bb21fdd75bbfb4b30d0052ced475a3256fbffdcdcefb8dbdfda37450150a502c",
    "892332bd21654ac35a20207d8be49be88b970dd5f8078de21775dd665865a6a87c259cfec54727e4ebd3c736cee6a23f",
    "b7c87721a79577643b38e4e63a2d59b497f2eba34f98dd7f2eeaa9354ac89bd3171a581a24062283aa9e757a41ad0c1b",
    "b6b091022c4540c990c5cff64754b1e704c15f1279e93d1876c5a1f001615620e58d40b29db3f93445ef07e141c93e38",
    "979e1b889ce486b159b61f01db39aa3df5c4b3e0017bb49e881a815bdfa56ebd0bbcb92449373f81b57f554507f95a61",
    "b522ee7876eacf53c9ad882a7fcf0bf95bfe155af24a615b7fd3c57b2ab14641e350a4b8bb26b395cd9b38c9b3fb6bea",
    "97d2e9c21c3424edcede68cce4b590826fbe4df8d9be419f376b90b0a6d332b1d502ccd113189a5beefbc1d477f80b4f",
    "af49720370c9d741d87927343484d7e781439a275eeab300688d9251ae6841eb27fe26cb7d10375986c83d1411d4617b",
    "847654c6b3f23762eb180de0275fe911069bfafbd4f511ff3ebc9f204ab3b60910a66d9bb8e3e2349480e656ddde1adf",
    "894e143c7bd736ae6bd8c79c1f287d8013c29f48034711460a0f2c1f964fddba5af0ec370f964cf4ce8a6fc7735e4ed1",
    "80a4c4b31ea92b582415d64ae651ff4fb5463274a853bcf1849c049f8df977988874c428f5f37f9b98b6d85fa0da1fe6",
    "a637bf7d36e3f2c28c33b6f724eb56b3b626d575d45f5314ec5f6ff17f4db0bba06de4212118e435c0c34257c88a3923",
    "a912f019d787b6d5c64e9ff51a710f7d3dd987982775549f6ea319628d074854fa79c33c4d18ec4923af5c820bb14c01",
    "aa32d6571340d8795670e6968092bf95f7228b48c6708da31114a74d97dc6a9b1d50f54e3a48bcdb93176a05dee05fcb",
    "a4ed365863a26e2f2d83dbed95f7dcfb6b86ad9f14f32942d7e613ffcb850ceaec005038d71d779c1b448fc286e7b060",
    "89c80f34d2cce21e2668a9637b0b67a54085a63c7592ba3fbc21c93fef37d8d147e6dc35926191d373ef187eb8eac26d",
    "86eac8b58c51ad59be2ef099f75f47325ce754ef0b6f305150991160e1cd8a39e351370d9f18d0694ba7d7883d89f7e2",
    "848f926b81984ec78fff193f6e5a0b82d48897ad317daaa48fca4621cb2cf1783578f6ae5aad32ac229947c78cd107e2",
    "84910301164fb6523e3cac42a0a5c1ecbd05cd5b95b832341ddf435e7b025d5591ea429ef739fdb4e7042c0951c4bdeb",
    "9390b5a1bd28415342f9c155319b8bf6be9faf753b3efca7dafce8eeb7355d7c2405df9b6bd5c8e702bebfc5bdc8f57b",
    "8c751e088846a5882799f67eaf7f7dc3d2ae96106b534cf10316d380757089061e64503a7e978f384906ac9309231701",
    "8fcd882c54c6b0b2b234e3137c9a801124d08dcd483a88626470c6b10b3ae0c611feba9001f76bab510940deeacc31f7",
    "8bfb174e6a5fb0666ecaaea8019827726e1e6d768a8097b5ff467b0c6fc64fcba84db9569c08527ca515392c1fbd717f",
    "83ae69feaa60b325c6f002d389d8b80f2d4a3383578cb7253365c525fdc1a32dd3cdc0f2bb01ba7fc8b26be9a20d8d00",
    "af28faa3b40826d50a204db58f3fdedf7ed6b240e66f543506a8330e637e0d465fe521c2f2899d103faa2ffc15ec42e8",
    "a0d6026d8e79987c514b2eddea0e55705f64381dbcddea3b5ee381e4751f0cef18fe2d5b398b222e3e3b6bc2cf736897",
    "aead8e4f4c0138c2ceada482487f11697bf3c7d290d2b3c205bb537889ebffdedd3a5b3f019922e2fb96cb2e8bd65c5b",
    "8dc059856631a225f663b86a6040bafe3c7140f2e10ed6e08dc083be07b81244c3f0f0e94697133c804839b25ee1df47",
    "b6ac71b0b770dba4db32dd5794db51d7dc9efd46b3528bfa5d1e828e110229dbfb3e3b5137c2cd8a08766fd7b7a53b99",
    "b18f06f3fcd088d7d553c7cf8ad7bc268eba28ee2ee9377e227f55400d1c47fc3f825022ea8dac2910245847b51d33fe",
    "8e86d7e5af25f769e53de840fa2ac9793795228a6779cffcfa4575f7a5b02decaa1076a701b846958645bdea7da7d88e",
    "8e901ab6b2e4a9db21cf298463072e6cad2a26b684fb0b5813e26cb1ff48876b802e6792a04861d670ed92c2f13dde8b",
    "8832f687c87e690ad6d2f893b8aecd6a0d69474b5591b47bdcb990753f03e3fc3db509dcdad986771cb52f9e80943c3f",
    "8dedf783b2fe9d6dbc964240c36dfbe1c4837c90b92fa15af00ef7d5d8784c2def361d141a20a763916c09492bd6be1b",
    "8dafafec6ab64a6b2697db45ccc6c923210452c6272567c58d921d35853ee4d830d8a29456a0dfff3e43d0147b7008b3",
    "b1f4e8bc45886e02e739179283befcdfc319b6e6f67234ff8ac0597e4c983efe6a89daef35ab72db2a4f8d0ff9729859",
    "b640956957ba8e18904cf350b0b0226113954173f090f68ace434ccb9edfb6a9ab1a4cf552caa2b7914e49b460e1c397",
    "b899fdfed3aa45e2cb4bb12bbd5fdf5b2dfe86e277c00a62fc95af0827251184495fbadf3fb94ec026c793f9f405ec98",
    "8768a915dabe958cf25ebc50092872645ee1a7e09a4c8571cff6c5368b2c27a27e85b2c80c5d73cc644b5641200e321a",
    "a7644f5f17e98139349de478dae1352026f49cb4525d691b9b7aa2b5fba156fed4cdcf3de03278c4cf3833a9e03ae37b",
    "8fd53dcf48660c9ea3561bd985996ed9805d3edae1c22ddfecd7dd9585b06dfbb60f7e05ce638bf1b28a80ffad69e624",
    "b0a867c89ae397efaa326d44ca964a0436caeda4a5831b7b67055627bb8d41669de81fcff50c5574d5c787eb12a4ce5d",
    "8d597289ba78d1c3f6adf0c17cef392762070bbb93ab04647a6eae6db9d0d3d841a82a7ca34d15ecdb539d255bf50b48",
    "972543da07e694e579503d75e1dfb36b90895a8a569c29ac5c6642e1616eeb14294b59bb6f6203d5fb6dfee9a67e9a8d",
    "af6a57db377efddf99c0692736c4a00c2f209d2b42f89f1f1be0d06e35afbed7500d117bd98180e71b11d2bcb7067502",
    "882d0359370f327f8dad98c4fce205180a2be89753181fb3a6cafe46324151e9437c962453766f0153270d1f16d0d82c",
    "b55412b2a4625c6b250ed875f452654b959a755fdb948dc18af971835ca8028633bba6decdfe905416d09056392b5230",
    "b62effc3cf464a69d7474bed8edd98aace39b2a67ece39a2f5f86e6bda55fd4ae0b605c6e5e15b854f5ddbd035e5c709",
    "a3e0f9fec5632c7908cec366970e568abe40586f7aa811a017f105d69c2c3213dcaa5220546b463000aa7f3291c2a4b4",
    "8040f11fbd05412fccc16a9310ea738ee9c59d7ecddd6458ba2b154d163857c435569721e23aba348007497c57fa4e1c",
    "8512df491fbfcbea31cf5739c22a3144c63e02a1a0bdd7aae09646b6a44d728005a32d46d2ae190c2a74f5f1dc7f9aba",
    "ade475e959f6598d1d7f768e0fbffe5bb5c18995ce17178dd5309fe29cb87a0be3c4e1de0c3d53ab2b0074c9f8bdba45",
    "b7c749d36dc582a00a7a7383f9b396c0ca4941832b006748dc9daacf495b6760e77709889f5b33ad5717d450234b666f",
    "857c44c851999bedf13b195169458713fa1d68a80ad68d2c48692982ab2d9333e10bfb07d401be4007875eb42c1672c9",
    "97d78bedfbe84b6b4b527d87b98fe7d6aadab6ff79bd2f5a3f90825fca4d2c46e1b8e86868f4037c99eab737b6c74b39",
    "894c18a6f3391f1a9bac54618ddbb0e8cb11d77e9378ae0ac639d000c6d00a5dd8ddb2040a7161a524cad891c70b3201",
    "b52f9c59e0ddf09cb18a9469ad7ac9089dcf044f4475b9bef3a31fd18accb16862c02d19343137ecd893fc651694d596",
    "8cbbeb3b39e5d35b36f9a3b9c0888157fcf7f1ad6ddb5ac9f6f4d3e0e4b570e797951551b7bb35c47961d0e7d8e6107e",
    "b0bb4c1f2676e8362a4dbb2c81fec8d7c0746b143e4dd69bd38ca63d837055a27689a700d038fc44752fe4fa31bdabb3",
    "954f21c1e1e21a0991b3551c764ff20fa2c2de8f02ea002bf0d932aa8ffb899fa984d1fda01bd386e13e1fbf3a1196ce",
    "b642be6a9e92e6dcad1bd74d6e2141a17e8474a0b408147d026f5b0b11c097f83a4a26bb02013e4fe4c886445c1e1382",
    "ac25606fdf14ba2687d4bff8082e6610a256f164e6081785b96d8fd944b797c4718a242dfe523edc22a9e108cc8c3641",
    "b923234eaa9630ee210d0b40dcab6c14109b7f4ebc2f92f4d316455436d6047bf7587d03a8e72771fb5530068d1dacf9",
    "92fc39097350fc1b1cc740e9728232f95dad8b315fc0f16285130d3c5ae501d0191438b10052db1fe295a7a953fac0cb",
    "8efa81a7ea78be091e13feacfe62f664a18afe6b74e66657edc7564dc31b8ed0bd00808cb49a2b4f7df381ffe6c6cb57",
    "84bbf6eb7e5b0562944ac55e7176b7fda282da42c48859b413a130323c87bde46d19f6461a5580e9f5d24f3915df86f9",
    "8496caafed8ee89cc83d681c2f0ec08645cc49aaaf124f916f4bf77002f16a03fa64a7533441495acf409018abfc31a6",
    "b1d9863fff6e5edbbb482fc53665b8b2c9131817417a3f062a3b429569a9c3f465b2aec765e80a683cef6cfcd80a7362",
    "9422a4072b393cd806803369957f992d5770787023d51fef19051175b3efba66900128af86c2307bd9db9d2f545b1766",
    "80b73a14820b2fbf73b1e107ee0666256109bfee04fa8bd3eadfd9a6b5c1d084d07fec9618ff4584ea4a4c002e184db9",
    "b2aa763146b7bcc1a1d1c11fd4b4470c9d0421af1dcf27866713fa3a70643a91cfa7bcc5860056852bbb5fa060dcdecc",
    "906190239613ae98913cb7545a538c2553816d9634c806968fd6d11cd9b78aa68021e6b3cd435673d0e2d4ae27ea128b",
    "9252595641c2bababf19d2a05ea3f45fef73092b79c0305a1018a8cd7c323133b89e1bd9791152544b258d8f2a6d09a8",
    "86b0617f7939b31338911b6008db58ace63c1435e8e8b464a51d230c1c03a58838af8c5749c152585f1dcbd32f517109",
    "a885010d8165946c8a6f5b83ad6007a8fe8285089bd9923f84a70e6bece6302aa41aa729542bace612441e1ee99583b6",
    "92aeec455478edd6a8a36291a39ac5aa8c27ac665fd909a0db1946f6b16bfd76e7ce1aa14ca84f9e734b86c953ac7ea3",
    "879e319031920f716698ba89d9e433addd63a5db116f0ec8b554c409d7b30b20fa850a309d9cdc6bb08700ea3dc39f0c",
    "a109cdfb3f3e077336887e1726d9069d8101a60c38ab21703616e8d5f3c0c913ab0ea02fe224cf9e5980623903c9d91e",
    "97ba00ebec3b796169f15121783651590e40eea97bf1f947c80643bf1a190283c6d910a81650af19bfa7bcf215d642e4",
    "86e0507a1ead3a5473f2ff8bd4623162421b339a1b45b3399369ad430fa61fec55803e1bdb20f81304923bc8d072035c",
    "9793070828840d5a8715aa6c8e2869c1e02d82fcf436847fbe31f667f029d0c4bcb7951c1cca82f801c3cc6963725768",
    "b582de97fe68936710a844d3e0ecfea6bfb712bf0c4201ec8269221aa0f10ea063e6210058a9a39d67c2861f8626ef78",
    "a7284177b1f8a0ecf6b26788cd75015486b67422317e907a7fab422cca3ea9cc12f2fda4610831912cbe88e81ac780a0",
    "8362d50145aa48ec89a17f7090d3585aa99cb73db6437dbbef01d4fe0572193586177720c413f94681c612b7b96fda35",
    "b18d5cdd320067b4352361dacfdce6ddcf3f59c0b04c8f07095d2395891d6dde564e8a384c1a18b71af658e0bfa8488c",
    "9637d6b9e949a27ce35399572b701faa49052776dd8892a236cee0678c2e4eab2692553b9ca4e63126a4b64d717be58a",
    "92a4430987608b7430229ca5a2b680198c84a37f7bba26891f7347bfddb37fea1df02365287ef986851a449bde96fc96",
    "89584605fcff51b004c864c80d92109bc3c5cec1d1e57f13984b88ab2b7a3ca25a8fdd92d8354d02fb792156ea0b03eb",
    "8655a8241118d963eaa2c7ab720a8ae270dc5ee51f35cfc190b08aa707623af7317243503dc1d20322dd8c9b0de69497",
    "ada98730bcae4ee4dce00abf2d5a12d340e95659cd1ac81598ada2786e57b0013bb93f012c25eb2ea05993c21b9085e3",
    "abe691af582e6b95a1e50e1a75ad7b5ae01e683fac787cbdaf21f9e8a0c7a7fae4710ce540145e32a318fd9be0c2670e",
    "aa17a06eb321227b2e2ece4130a97e4acf9656c8d458540c81eaececf48774e5f159b50f5ea9634e8768715b8e56ddb3",
    "89148932b3399ecc30d66590810073fbc601d05f48e64740713a02a7b03a6374c1bc95484ef17cc130acf1dd45a6ef5b",
    "a26b20d3ebc0730606223a81a05477072fe1d543f82653d91223e4d2de8a31e61e2685c1d625b9fc61d4c70d47ba6829",
    "8834a851eeb7218653d4127310c54e97a2f6398803f311701abe63eda862b6be2686709dfdd4a439e13a6a7bf533f285",
    "82fcb18eab1756c6f1721fa7372f73eca8825cace88968239ffa06a3461f1e9763fef7c59a0bfa1444bf6cfdf3937470",
    "835755c4ef6807b83363a77723db2984e37b9f6297ce97a13cac69fd14c2c120f092d4c61bddf9c42811ba7fa21a32ef",
    "80f80545d8c7e10db0a68a07f3639e1724b451e3d8a1c748af74fa73b5c2494f74d7b187caaef426393bf8ec79630b9f",
    "898b930630962db8359bff75402dd7bbc7de875e6f513e7bad533eb3b61930d53896e9f9d4bf1709f899f4a8fd6d17de",
    "afa645b29e984235641fd2c74873dc206b0a29dbf601b2d0c483d3e120edf9a7b431f4e473c7ca2a76f172909a05e4c7",
    "8720752bee97abbe6d39faa231e3308615053410156dddc883410e617a563139f4566687655807a4f0fe9051f959cfc0",
    "8dfb845e0cb124eb4561cfc7808059d53fbb310f67cea8af855920e2105782418e3a059206e7d430785684e18a05c133",
    "ac8094ce76d5a8057d12655357f8063c475f9a9dd64f93a6e9e35c3cc479b86e0b8998f3f00da49d864547a70a5fc0c9",
    "aebbcec9719f850cd04871a448ead579720a53a6aa998ec5f86abeaff59007b4faa5ffd69e86eb89f960f9b85ff99515",
    "a526da8681178fbd735756168c0d62bb5e7634e49c23373d0a6b5ed96bb1417decbcb10a2b3b30256753f0fcfc897989",
    "a02447894b631671b42637ecb41a9355fe24b813e55aa6feb220fde12cead22c945b9eb8b356be31b0dad10fe07cf7e8",
    "b8681979357bdef23bbdb5694c79f02206a9cd2640c33e4aad77aea4f4558c002a8db573ffb9c36248a001d57ebf07e7",
    "a35eb9cf48cc28056f0ca3d7db8e778ddbda5ba08448ee664385279cd9103badbf579627a47a9cf6c3e59fcfed0cbade",
    "b91c7740f72a422a55951d56db05404cddae039f670763c3ccaf3464fd00d7339bf55c95c9cfebb28a7aa42a36b4b6f1",
    "a1c36b74e15b2a1881e0efb5bf1116bea68338ace70468be8596bd7a294c0d50e7158fa937d095ec686f1d56caf0a978",
    "b77da185448b80c25e7855d8479f05d219f9a004a46a528dab24c01c0a2979c706bfef985d424051a729dd4e22b88875",
    "88185a236ecbbb6a3a910b092e0ed471d3f31447fadc1bc3c511a41dfea485ce173264506201a5aba24a7b500d44b969",
    "96770485b7a42df8e78c20c66e9bc0c5e8d8797dde64ed7e02b729832aa03bb226d908bfa857f692f05808b090e639c9",
    "97cfc55b970b0765121333cab52f6f60e39f8eda60722d1e3cc8f3b17d2aa8567661fc8cbfc7947b029af5db7c4303f1",
    "922e477f0d5a36c5c1d23b79a4299e7020ed248ff14d651264ebe76cf86cfc624c9b63e86c74f0661aa1d304f95cc2a1",
    "94bcb8a20f749376b8f6e4a1b7012c7c55b02d5b1772751ba395a22ee08d08617ef28b57704799a8fdeb2877f367af20",
    "89769afc525933c612f9ffeba3fc68bb7c608af154457c7b27d736da4e3b10f5010141dfa5a742226a3372738964852d",
    "8423cf50c6cc0d70713d8ebbd332196a02b34bdc76f1eadbb24101fcce9774d93d95553cc9b97e6715f6d6c899658eb4",
    "b8a2d570ad7483c866d535a8ed2b86234b51abaf47e4e7e5e50a03749fb5b489263d1aae026236bdceb2fb3056a56374",
    "a413ce8c2f0669ca3c9fefa26ac01fa28878a02d69850e81bd7903c1a81118f33eae27891b77c6963d7799e4872bba11",
    "a490f25b0144b0fa9180b9bd2595cffdf075adb4e525865466a1183fce981c718931cdd4bf9b462c827b59f2146e9da4",
    "821af74b6ad84d96d4315afddc6b82faf30d44cf8bbf652534d87d4baddd89e59c56e304d84308bf3c93da9715b08581",
    "82b2b7512af2c315407e0535a4777be88a223be0537f0c375e95b8ba207142ceb9998e84ac38ec662db4392a78457690",
    "8e148677c84f2e99d55424f477c33b9d5183fce2d4b2b71b77953667043955fce36f7d7df392246ed5382534fb51578a",
    "895059e883b98873a78f3aac8ff82e7da6bbeda03999225eab4b41870cc2955471b995a5868bfbfb275d81f9c5360c8d",
    "b467582e6de87f862c7379b77955ff6d7f49c9f9ce20b81515f2b4922d5ae0f7cb57e7465e68a2939d462022a688f822",
    "a287b034486947659653e0d9ebf902a4a7a155fe3d667191280898a405984adc38f1ac890855551e78fe7903505a866b",
    "806e411d2a0a5474a1c873282c3e48f50039aacb38d6e5d4b27c16359838950622b8dc1a8a8c949b1002ce1a25e65818",
    "93edc3d3b1414e0ce7702af45bc8b8fffd997127deca08ceeeef939aac73668b067a21db9ee41b8251b9abd7a19c0267",
    "aea712633682ecf2798bc0f185808de0101506964e895a783ccf505a2aa06b69bef98d54ada343b33636467ccf48dba1",
    "b5d025243a972b389c6c0dd9203f58394cf238bbbf8e0d0846bf95b2f6f742fdd4cec20d44204b85e1193bf0e13cc578",
    "90f86db1f6a7e9d609cd792a12ca27248980084d92dc75eeefe29db6760abf80d6db4f8ba1e4feb3e0019ae394331d0c",
    "a9773af6fc896184ada021a01480637bfd50daf2e3b490101cdef1ff0a075d8cad96dd6c20e39bde016bb7e503e1a39f",
    "8b4b99112f7c7791ec31ab29c1b6dfa934b0d31e69369066b3cfb0913785bd7a5ad7f3604100d0ed66a78b57854a6ead",
    "a55aa7c9fba937bb7a4914f90ad6bca854193dc8673333d980ef2ec60f42f13eedfb773def18e038911df8b755e7d6a4",
);
    const MAINNET_KAT_BITS_HEX: &str = concat!(
    "ffffffffffffffffffffffffffffffffffffffffbfffffdfffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffff",
);
    const MAINNET_KAT_SIGNATURE_HEX: &str = concat!(
    "8c84407168151ef8d350d01c9927c9ec9c78d8c8bcd728527faf76339c2130f3b70942ee58c76f5210f8617351eda2fb",
    "00279945b1213c04dc4a58251c74404abddaae84cf2bd648f5ce3e1d71fd146182e8183ea6807d96b08a139fed8c85f8",
);

    fn hex_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).expect("test constant is hex")
    }

    fn mainnet_kat_state() -> SyncCommitteeState {
        let raw = hex_bytes(MAINNET_KAT_KEYS_HEX);
        assert_eq!(raw.len(), SYNC_COMMITTEE_SIZE * BLS_PUBKEY_LEN);
        let mut state = SyncCommitteeState {
            current_period: 1851,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        };
        for (i, chunk) in raw.chunks(BLS_PUBKEY_LEN).enumerate() {
            state.current_sync_committee[i].copy_from_slice(chunk);
        }
        state
    }

    fn mainnet_kat_binding_and_params() -> (BeaconBinding, BeaconChainParams) {
        let binding = BeaconBinding {
            slot: 15_165_711,
            proposer_index: 1_954_820,
            parent_root: hex_32("104a7edc1fd17cc7ca4a87351ed5eeda763fbd7888eb0d08b735c0198e850f53"),
            state_root: hex_32("d50cf14e2fc7320371db4e9a01222ea38ab848325fc8f99b9d19a2dca240c91b"),
            body_root: hex_32("bdf85b1308913e29cb4a9d3241a69ebdd7a379e7f55dceb75e9d6e3048579303"),
            execution_block_hash_branch: Vec::new(), // signing root only; no branch walk here
        };
        // Header root check: the rebuilt root must equal the block root the
        // beacon API reports for slot 15_165_711.
        assert_eq!(
            binding.beacon_header_root(),
            hex_32("f10f3e2e0aebc44260d3ac39ea684ec18a6fcaa7de9347e03656c3c10a8d7dca")
        );
        let params = BeaconChainParams {
            fork_version: [0x06, 0, 0, 0],
            genesis_validators_root: hex_32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
        };
        (binding, params)
    }

    fn mainnet_kat_aggregate() -> SyncAggregate {
        let bits_raw = hex_bytes(MAINNET_KAT_BITS_HEX);
        let sig_raw = hex_bytes(MAINNET_KAT_SIGNATURE_HEX);
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        bits.copy_from_slice(&bits_raw);
        let mut signature = [0u8; BLS_SIGNATURE_LEN];
        signature.copy_from_slice(&sig_raw);
        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: signature,
        }
    }

    /// The real thing: a genuine 510-of-512 mainnet sync aggregate
    /// verifies against the rebuilt signing root.
    #[test]
    fn mainnet_sync_aggregate_known_answer() {
        let state = mainnet_kat_state();
        let agg = mainnet_kat_aggregate();
        let (binding, params) = mainnet_kat_binding_and_params();
        assert_eq!(agg.participation_count(), 510);
        verify_sync_aggregate(&state, &agg, &binding.signing_root(&params))
            .expect("the genuine mainnet aggregate verifies");
    }

    /// The same aggregate with one signer removed from the bitmap changes
    /// the summed key and is refused by the pairing, not the bit count.
    #[test]
    fn mainnet_sync_aggregate_rejects_a_dropped_signer() {
        let state = mainnet_kat_state();
        let mut agg = mainnet_kat_aggregate();
        // Index 0 participated; unsetting it keeps participation at 509.
        agg.sync_committee_bits[0] &= !1u8;
        let (binding, params) = mainnet_kat_binding_and_params();
        assert_eq!(agg.participation_count(), 509);
        let err = verify_sync_aggregate(&state, &agg, &binding.signing_root(&params))
            .expect_err("a bitmap that drops a real signer must not verify");
        assert_eq!(err, SyncCommitteeError::SignatureVerificationFailed);
    }
}
