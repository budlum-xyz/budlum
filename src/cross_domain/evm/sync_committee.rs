//! F10.3 Ethereum PoS sync committee light client, Altair-and-later finality.
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
//!   participating public keys are summed in G2, each decoded and
//!   subgroup-checked on its own first, and a single pairing checks the
//!   aggregate signature over the signing root; see
//!   [`verify_execution_block_finality`].
//! - **Threshold participation**: below two thirds is REFUSED, meaning no
//!   finality.
//! - **The message is derived, not supplied.** A committee signs the SSZ
//!   root of a beacon header under the fork domain. The verifier rebuilds
//!   that root from the header fields the relayer names and the adapter's
//!   chain parameters, and only after the header's body has been shown to
//!   commit to the execution block the deposit proof is about.

use crate::chain::finality::hash_to_g1;
use bls12_381::{G1Affine, G2Affine, G2Projective};
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

/// The BLS public key size, G2 compressed on BLS12-381.
pub const BLS_PUBKEY_LEN: usize = 96;

/// The BLS signature size, G1 compressed. Ethereum's minimal-pubkey-size
/// scheme puts signatures in G1, and a compressed G1 point is 48 bytes; the
/// earlier value of 96 could not have been decoded by any verifier.
pub const BLS_SIGNATURE_LEN: usize = 48;

/// The Ethereum sync committee light client state, for a single period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommitteeState {
    /// The period of the finalized header.
    pub current_period: u64,
    /// The current sync committee: 512 public keys, each 96 bytes, G2
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
    /// The aggregated BLS signature, G1 compressed, 48 bytes.
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
/// An Altair `sync_committee_signature` is one G1 point, the sum of the
/// participating members' signatures over the same message. It verifies
/// against the sum of the participating public keys, once:
/// `e(sig, g2) == e(H(msg), sum(pk_i))`. Two earlier versions of this
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

    // 2. Sum the participating public keys. Every one of them is decoded
    //    and checked on its own: the sum of valid points is valid, but a
    //    single small-subgroup point in it would not be caught by a check
    //    on the sum alone.
    let mut agg_pk = G2Projective::identity();
    for (i, pk) in state.current_sync_committee.iter().enumerate() {
        if !aggregate.signed(i) {
            continue;
        }
        let pk_affine = G2Affine::from_compressed(pk)
            .into_option()
            .ok_or(SyncCommitteeError::InvalidPubkey)?;
        if !bool::from(pk_affine.is_torsion_free()) || bool::from(pk_affine.is_identity()) {
            return Err(SyncCommitteeError::InvalidPubkey);
        }
        agg_pk += G2Projective::from(pk_affine);
    }
    let agg_pk_affine = G2Affine::from(agg_pk);
    if bool::from(agg_pk_affine.is_identity()) {
        return Err(SyncCommitteeError::InvalidPubkey);
    }

    // 3. Decode the aggregate signature with the same subgroup discipline.
    let sig_affine = G1Affine::from_compressed(&aggregate.sync_committee_signature)
        .into_option()
        .ok_or(SyncCommitteeError::InvalidSignature)?;
    if !bool::from(sig_affine.is_torsion_free()) || bool::from(sig_affine.is_identity()) {
        return Err(SyncCommitteeError::InvalidSignature);
    }

    // 4. One pairing: e(sig, -g2) * e(H(msg), agg_pk) == 1.
    let h_msg = hash_to_g1(signing_message);
    let g2_gen_neg = -G2Affine::generator();
    let pairing_result = bls12_381::multi_miller_loop(&[
        (&sig_affine, &g2_gen_neg.into()),
        (&h_msg, &agg_pk_affine.into()),
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
        // Zero bytes are not a G2 point, so the first participating key
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
        use bls12_381::{G2Affine, G2Projective, Scalar};
        let mut state = dummy_state();
        let mut secrets = Vec::with_capacity(signers);
        for i in 0..SYNC_COMMITTEE_SIZE {
            let mut wide = [0u8; 64];
            wide[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            wide[8] = 0x5A;
            let sk = Scalar::from_bytes_wide(&wide);
            let pk = G2Affine::from(G2Projective::generator() * sk);
            state.current_sync_committee[i] = pk.to_compressed();
            if i < signers {
                secrets.push(sk);
            }
        }
        (state, secrets)
    }

    fn aggregate_over(secrets: &[bls12_381::Scalar], msg: &[u8]) -> SyncAggregate {
        use bls12_381::{G1Affine, G1Projective};
        let h = G1Projective::from(hash_to_g1(msg));
        let mut sig = G1Projective::identity();
        let mut bits = [0u8; SYNC_COMMITTEE_SIZE / 8];
        for (i, sk) in secrets.iter().enumerate() {
            sig += h * sk;
            bits[i / 8] |= 1 << (i % 8);
        }
        SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: G1Affine::from(sig).to_compressed(),
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
}
