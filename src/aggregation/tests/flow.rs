//! Tests of the flow: admission, the tick, merging, the block rules and the
//! fees, with the native backend.

use std::collections::{BTreeMap, BTreeSet};

use super::support::Signer;
use crate::aggregation::aggregator::Aggregator;
use crate::aggregation::backend::{AggBackend, AggError, TickCtx};
use crate::aggregation::block::{check_block_claims, BlockClaimError, TxClaims};
use crate::aggregation::claim::Claim;
use crate::aggregation::envelope::{Envelope, ObjectKind};
use crate::aggregation::fees::{claim_fee, settle, split_segment_fees};
use crate::aggregation::frame::{
    frame_hash, ClaimFrame, FrameError, FrameLimits, SHAPE_MERGE, SHAPE_TICK,
};
use crate::aggregation::native::NativeBackend;
use crate::aggregation::object::{derive_claim, ObjectError};
use crate::aggregation::params::{AggMode, AggParams};
use crate::aggregation::pool::{Admission, ObjectPool, PoolItem, Rejection, TxFacts, TxLookup};
use crate::aggregation::schemes::{agg_scheme, AGG_SCHEMES};
use crate::core::address::Address;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::Hash32;

const DOMAIN: u32 = 7;
/// The parameter set of the native backend under test.
const SET: u32 = 1;

/// The mempool the pool admits against.
#[derive(Default)]
struct Txs(BTreeMap<Hash32, TxFacts>);

impl TxLookup for Txs {
    fn tx_facts(&self, tx_hash: &Hash32) -> Option<TxFacts> {
        self.0.get(tx_hash).copied()
    }
}

impl Txs {
    fn add(&mut self, tx_hash: Hash32, from: Address, fee: u64) {
        self.0.insert(tx_hash, TxFacts { from, fee });
    }
}

/// Devnet parameters: the mode is on, and the proof limit has room for the
/// objects themselves, which is what a native proof is.
fn params() -> AggParams {
    AggParams {
        mode: AggMode::On,
        max_proof_bytes: 16 * 1024 * 1024,
        ..AggParams::default()
    }
}

fn registry() -> SchemeStatusRegistry {
    SchemeStatusRegistry::genesis()
}

fn backend() -> NativeBackend {
    NativeBackend::new(registry(), FrameLimits::from(&params()), SET)
}

fn ctx(aggregator: u8) -> TickCtx {
    TickCtx::from_seed(DOMAIN, zeroize::Zeroizing::new([aggregator; 32])).expect("valid seed")
}

fn tx_hash(n: u16) -> Hash32 {
    let mut hash = [0xA0; 32];
    if let Some(head) = hash.first_chunk_mut::<2>() {
        *head = n.to_be_bytes();
    }
    hash
}

const FEE: u64 = 1_000_000;

/// A signer, its `n`-th transaction registered in the mempool, and the
/// envelope of the signature over it.
fn signed(txs: &mut Txs, signer: &Signer, n: u16) -> Envelope {
    let hash = tx_hash(n);
    txs.add(hash, signer.address(), FEE);
    signer.envelope(DOMAIN, hash)
}

fn claim_of(signer: &Signer, n: u16) -> Claim {
    Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: signer.address(),
        msg_hash: tx_hash(n),
    }
}

// ---- scheme registry --------------------------------------------------------

#[test]
fn the_scheme_registry_names_ml_dsa_87_with_its_object_size() {
    let scheme = agg_scheme(SchemeId::ML_DSA_87).expect("registered");
    assert_eq!(scheme.name, "ml-dsa-87-fips204-v1");
    assert_eq!(
        (scheme.public_key_bytes, scheme.signature_bytes),
        (2592, 4627)
    );
    assert_eq!(scheme.max_object_bytes(), 7219);
    assert!(agg_scheme(SchemeId::ED25519).is_none());
    assert_eq!(AGG_SCHEMES.len(), 1);
}

/// The object of a claimed transaction is the witness an inline V5
/// transaction carries: the same key and the same signature, over the hash
/// that is also the transaction id. A wallet signs once for both paths.
#[test]
fn the_witness_of_a_signed_v5_transaction_is_the_object_of_its_claim() {
    use crate::core::transaction::Transaction;
    let keypair = crate::crypto::primitives::WalletKeyPair::from_seed(&[7; 32]);
    let mut tx = Transaction::new_with_fee(
        keypair.address(),
        Address::from([2; 32]),
        10,
        FEE,
        0,
        Vec::new(),
    );
    tx.sign_v5(&keypair);
    assert!(tx.verify_in(&registry()));
    let signing_hash = tx.signing_hash();
    assert_eq!(tx.hash, hex::encode(signing_hash));

    let mut payload = tx.signer_public_key.clone();
    payload.extend_from_slice(tx.signature.as_deref().expect("signed"));
    let envelope = Envelope {
        kind: ObjectKind::Signature,
        scheme: SchemeId::ML_DSA_87,
        payload,
        tx_hash: signing_hash,
        domain: DOMAIN,
    };
    assert_eq!(
        derive_claim(&registry(), &envelope),
        Ok(Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: tx.from,
            msg_hash: signing_hash,
        })
    );
    // The claim is 67 bytes; the witness it replaces is 7219.
    assert_eq!(envelope.payload.len(), 7219);
}

// ---- admission --------------------------------------------------------------

#[test]
fn a_valid_signature_object_is_admitted_with_the_account_rule_claim() {
    let (mut txs, signer) = (Txs::default(), Signer::new(1));
    let envelope = signed(&mut txs, &signer, 1);
    assert_eq!(
        derive_claim(&registry(), &envelope),
        Ok(claim_of(&signer, 1))
    );
    let mut pool = ObjectPool::new(params(), DOMAIN);
    let id = envelope.object_id();
    assert_eq!(
        pool.admit(envelope.clone(), &txs, &registry()),
        Ok(Admission::Accepted(id))
    );
    assert_eq!(pool.ready_len(), 1);
    assert_eq!(pool.bytes(), envelope.encode().len());
    assert_eq!(
        pool.next_items(),
        vec![PoolItem {
            envelope,
            claim: claim_of(&signer, 1)
        }]
    );
}

/// Section 11: wrong signature, wrong message, wrong scheme, wrong address.
#[test]
fn a_wrong_signature_message_scheme_or_address_is_refused_and_blames_the_peer() {
    let (mut txs, signer, other) = (Txs::default(), Signer::new(1), Signer::new(2));
    let good = signed(&mut txs, &signer, 1);
    let mut pool = ObjectPool::new(params(), DOMAIN);

    // Wrong signature: one bit of the signature half is flipped.
    let mut wrong_signature = good.clone();
    let at = 2592 + 5;
    wrong_signature.payload[at] ^= 1;
    // Wrong message: a valid signature, but over another transaction.
    let mut wrong_message = good.clone();
    wrong_message.tx_hash = tx_hash(2);
    txs.add(tx_hash(2), signer.address(), FEE);
    for bad in [wrong_signature, wrong_message] {
        assert_eq!(derive_claim(&registry(), &bad), Err(ObjectError::Invalid));
        let refused = pool.admit(bad, &txs, &registry()).expect_err("refused");
        assert_eq!(refused, Rejection::Object(ObjectError::Invalid));
        assert!(refused.blames_peer());
    }

    // Wrong scheme: the same bytes under a scheme that cannot be claimed.
    let mut wrong_scheme = good.clone();
    wrong_scheme.scheme = SchemeId::ED25519;
    let refused = pool
        .admit(wrong_scheme, &txs, &registry())
        .expect_err("refused");
    assert_eq!(refused, Rejection::Object(ObjectError::UnknownScheme(1)));
    assert!(refused.blames_peer());

    // Wrong address: a valid signature of another account over this transaction.
    let wrong_address = other.envelope(DOMAIN, tx_hash(1));
    let refused = pool
        .admit(wrong_address, &txs, &registry())
        .expect_err("refused");
    assert_eq!(refused, Rejection::NotTheSender);
    assert!(refused.blames_peer());

    // A wrong public key is a wrong address too: the claim names the account
    // the key controls, and that is not the sender.
    let mut wrong_key = good.clone();
    wrong_key.payload[0] ^= 1;
    assert_eq!(
        derive_claim(&registry(), &wrong_key),
        Err(ObjectError::Invalid)
    );

    assert_eq!((pool.ready_len(), pool.bytes()), (0, 0));
    // The good object still enters: nothing above poisoned its claim.
    assert!(pool.admit(good, &txs, &registry()).is_ok());
}

#[test]
fn size_domain_kind_and_duplicates_are_refused() {
    let (mut txs, signer) = (Txs::default(), Signer::new(1));
    let good = signed(&mut txs, &signer, 1);
    let mut pool = ObjectPool::new(params(), DOMAIN);

    let mut long = good.clone();
    long.payload.push(0);
    assert_eq!(
        pool.admit(long, &txs, &registry()),
        Err(Rejection::Object(ObjectError::PayloadTooLarge(7220)))
    );
    let mut short = good.clone();
    short.payload.pop();
    assert_eq!(
        pool.admit(short, &txs, &registry()),
        Err(Rejection::Object(ObjectError::Invalid))
    );
    let mut elsewhere = good.clone();
    elsewhere.domain = DOMAIN + 1;
    assert_eq!(
        pool.admit(elsewhere, &txs, &registry()),
        Err(Rejection::WrongDomain)
    );
    let mut stark = good.clone();
    stark.kind = ObjectKind::StarkProof;
    stark.scheme = SchemeId(0);
    assert_eq!(
        pool.admit(stark, &txs, &registry()),
        Err(Rejection::Object(ObjectError::Invalid))
    );
    let mut pcs = good.clone();
    pcs.kind = ObjectKind::PcsOpening;
    pcs.scheme = SchemeId(0);
    assert_eq!(
        pool.admit(pcs, &txs, &registry()),
        Err(Rejection::Object(ObjectError::Invalid))
    );

    assert!(pool.admit(good.clone(), &txs, &registry()).is_ok());
    assert_eq!(
        pool.admit(good.clone(), &txs, &registry()),
        Err(Rejection::Duplicate)
    );
    // A second, different object for the same claim (another valid signature
    // of the same message) is not a second claim.
    let again = signer.envelope_again(DOMAIN, tx_hash(1));
    assert_ne!(again.object_id(), good.object_id());
    assert_eq!(
        derive_claim(&registry(), &again),
        derive_claim(&registry(), &good)
    );
    assert_eq!(
        pool.admit(again, &txs, &registry()),
        Err(Rejection::ClaimKnown)
    );
    assert_eq!(pool.ready_len(), 1);
}

#[test]
fn the_fee_must_cover_the_claim_and_the_sender_limit_resets_each_tick() {
    let (mut txs, signer) = (Txs::default(), Signer::new(1));
    let mut pool = ObjectPool::new(params(), DOMAIN);
    let fee = claim_fee(&params(), &claim_of(&signer, 0));
    assert_eq!(fee, 64 * 67);

    txs.add(tx_hash(100), signer.address(), fee - 1);
    let underpaid = signer.envelope(DOMAIN, tx_hash(100));
    assert_eq!(
        pool.admit(underpaid.clone(), &txs, &registry()),
        Err(Rejection::FeeTooLow)
    );
    // The same object is admitted once the transaction pays enough: a
    // refusal for the fee is not remembered.
    txs.add(tx_hash(100), signer.address(), fee);
    assert!(pool.admit(underpaid, &txs, &registry()).is_ok());

    // The limit is 8 objects per sender and tick; one is used.
    for n in 1..8 {
        let envelope = signed(&mut txs, &signer, n);
        assert!(pool.admit(envelope, &txs, &registry()).is_ok(), "{n}");
    }
    let ninth = signed(&mut txs, &signer, 8);
    assert_eq!(
        pool.admit(ninth.clone(), &txs, &registry()),
        Err(Rejection::SenderLimit)
    );
    assert!(!Rejection::SenderLimit.blames_peer());
    // Another sender is not affected.
    let other = Signer::new(2);
    let envelope = signed(&mut txs, &other, 50);
    assert!(pool.admit(envelope, &txs, &registry()).is_ok());
    // The next tick gives the limit back.
    pool.begin_tick(&txs, &registry());
    assert!(pool.admit(ninth, &txs, &registry()).is_ok());
    assert_eq!(pool.ready_len(), 10);
}

#[test]
fn a_full_pool_drops_the_object_that_pays_the_least_per_byte() {
    let mut txs = Txs::default();
    let signers: Vec<Signer> = (1..=4).map(Signer::new).collect();
    let envelopes: Vec<Envelope> = signers
        .iter()
        .zip([300_000u64, 100_000, 200_000, 50_000])
        .zip(0u16..)
        .map(|((signer, fee), n)| {
            txs.add(tx_hash(n), signer.address(), fee);
            signer.envelope(DOMAIN, tx_hash(n))
        })
        .collect();
    let one = envelopes[0].encode().len();
    // Room for two objects.
    let small = AggParams {
        pool_max_bytes: 2 * one,
        ..params()
    };
    let mut pool = ObjectPool::new(small, DOMAIN);
    assert!(pool.admit(envelopes[0].clone(), &txs, &registry()).is_ok());
    assert!(pool.admit(envelopes[1].clone(), &txs, &registry()).is_ok());
    // The third pays more than the second: the second is dropped.
    assert_eq!(
        pool.admit(envelopes[2].clone(), &txs, &registry()),
        Ok(Admission::Accepted(envelopes[2].object_id()))
    );
    assert_eq!((pool.ready_len(), pool.bytes()), (2, 2 * one));
    let kept: BTreeSet<Hash32> = pool
        .next_items()
        .iter()
        .map(|item| item.envelope.tx_hash)
        .collect();
    assert_eq!(kept, BTreeSet::from([tx_hash(0), tx_hash(2)]));
    // The fourth pays the least of all: it is the one refused.
    assert_eq!(
        pool.admit(envelopes[3].clone(), &txs, &registry()),
        Err(Rejection::PoolFull)
    );
    assert_eq!((pool.ready_len(), pool.bytes()), (2, 2 * one));
    // The dropped object may come back when there is room: its claim is free.
    pool.mark_proven(&pool.next_items());
    assert_eq!(pool.bytes(), 0);
    assert!(pool.admit(envelopes[1].clone(), &txs, &registry()).is_ok());
}

#[test]
fn an_object_waits_two_ticks_for_its_transaction() {
    let (mut txs, signer) = (Txs::default(), Signer::new(1));
    let mut pool = ObjectPool::new(params(), DOMAIN);

    // The transaction arrives during the wait: the object is admitted.
    let early = signer.envelope(DOMAIN, tx_hash(1));
    let id = early.object_id();
    assert_eq!(
        pool.admit(early.clone(), &txs, &registry()),
        Ok(Admission::Waiting(id))
    );
    assert_eq!(
        pool.admit(early, &txs, &registry()),
        Err(Rejection::Duplicate)
    );
    assert_eq!((pool.waiting_len(), pool.ready_len()), (1, 0));
    pool.begin_tick(&txs, &registry());
    assert_eq!((pool.waiting_len(), pool.ready_len()), (1, 0));
    txs.add(tx_hash(1), signer.address(), FEE);
    pool.begin_tick(&txs, &registry());
    assert_eq!((pool.waiting_len(), pool.ready_len()), (0, 1));

    // The transaction never arrives: the object is gone after two ticks.
    let orphan = signer.envelope(DOMAIN, tx_hash(2));
    assert!(pool.admit(orphan, &txs, &registry()).is_ok());
    let held = pool.bytes();
    pool.begin_tick(&txs, &registry());
    assert_eq!(pool.waiting_len(), 1);
    pool.begin_tick(&txs, &registry());
    assert_eq!(pool.waiting_len(), 0);
    assert!(pool.bytes() < held);

    // A waiting object is not verified until its transaction is known, and
    // an invalid one is dropped at that point.
    let mut forged = signer.envelope(DOMAIN, tx_hash(3));
    forged.payload[2592 + 1] ^= 1;
    assert!(matches!(
        pool.admit(forged, &txs, &registry()),
        Ok(Admission::Waiting(_))
    ));
    txs.add(tx_hash(3), signer.address(), FEE);
    pool.begin_tick(&txs, &registry());
    assert_eq!((pool.waiting_len(), pool.ready_len()), (0, 1));
}

// ---- the tick ---------------------------------------------------------------

#[test]
fn a_tick_proves_the_pool_deletes_the_payloads_and_does_not_prove_twice() {
    let mut txs = Txs::default();
    let mut aggregator = Aggregator::new(backend(), ctx(0xA1), params());
    let signers: Vec<Signer> = (1..=5).map(Signer::new).collect();
    let mut envelopes = Vec::new();
    for (signer, n) in signers.iter().zip(0u16..) {
        let envelope = signed(&mut txs, signer, n);
        envelopes.push(envelope.clone());
        assert!(aggregator.on_object(envelope, &txs, &registry()).is_ok());
    }
    assert!(aggregator.pool().bytes() > 5 * 7219);

    let outcome = aggregator.on_tick(&txs, &registry());
    assert_eq!(outcome.error, None);
    assert_eq!(outcome.publish.len(), 1);
    let frame = &outcome.publish[0];
    assert_eq!(frame.claims.len(), 5);
    assert_eq!(frame.shape, vec![SHAPE_TICK]);
    assert_eq!(frame.segments[0].aggregator, ctx(0xA1).aggregator);
    assert_eq!(backend().verify(frame, DOMAIN), Ok(()));
    // Claims are sorted by digest.
    let digests: Vec<Hash32> = frame.claims.iter().map(|c| c.digest(DOMAIN)).collect();
    assert!(digests.windows(2).all(|pair| pair[0] < pair[1]));
    // Section 8: the payload bytes are gone from the pool.
    assert_eq!(
        (aggregator.pool().bytes(), aggregator.pool().ready_len()),
        (0, 0)
    );

    // The next tick has nothing to prove and publishes nothing.
    let outcome = aggregator.on_tick(&txs, &registry());
    assert_eq!((outcome.publish.len(), outcome.error), (0, None));
    // A proven object, or another object for a proven claim, is not admitted again.
    assert_eq!(
        aggregator.on_object(envelopes[0].clone(), &txs, &registry()),
        Err(Rejection::Duplicate)
    );
    let again = signers[0].envelope_again(DOMAIN, tx_hash(0));
    assert_eq!(
        aggregator.on_object(again, &txs, &registry()),
        Err(Rejection::ClaimKnown)
    );
}

/// A backend that cannot prove.
struct Broken;

impl AggBackend for Broken {
    fn prove_tick(&self, _: &TickCtx, _: &[PoolItem]) -> Result<ClaimFrame, AggError> {
        Err(AggError::MalformedProof)
    }
    fn prove_merge(&self, _: &ClaimFrame, _: &ClaimFrame) -> Result<Vec<u8>, AggError> {
        Err(AggError::MalformedProof)
    }
    fn verify(&self, _: &ClaimFrame, _: u32) -> Result<(), AggError> {
        Err(AggError::MalformedProof)
    }
}

#[test]
fn a_failed_tick_is_skipped_and_an_object_that_fails_twice_is_dropped() {
    let (mut txs, signer) = (Txs::default(), Signer::new(1));
    let mut aggregator = Aggregator::new(Broken, ctx(0xA1), params());
    let envelope = signed(&mut txs, &signer, 1);
    assert!(aggregator.on_object(envelope, &txs, &registry()).is_ok());

    let outcome = aggregator.on_tick(&txs, &registry());
    assert_eq!(outcome.error, Some(AggError::MalformedProof));
    assert!(outcome.publish.is_empty());
    assert_eq!(aggregator.pool().ready_len(), 1);

    let outcome = aggregator.on_tick(&txs, &registry());
    assert_eq!(outcome.error, Some(AggError::MalformedProof));
    assert_eq!(
        (aggregator.pool().ready_len(), aggregator.pool().bytes()),
        (0, 0)
    );

    let outcome = aggregator.on_tick(&txs, &registry());
    assert_eq!(outcome.error, None);
}

#[test]
fn a_tick_that_would_not_fit_the_proof_limit_proves_fewer_objects() {
    let mut txs = Txs::default();
    // Room for the proof of two signature objects, not three.
    let tight = AggParams {
        max_proof_bytes: 2 * 7262 + 64,
        ..params()
    };
    let backend = NativeBackend::new(registry(), FrameLimits::from(&tight), SET);
    let mut aggregator = Aggregator::new(backend, ctx(0xA1), tight);
    for n in 0..5u16 {
        let signer = Signer::new(u8::try_from(n).expect("small"));
        let envelope = signed(&mut txs, &signer, n);
        assert!(aggregator.on_object(envelope, &txs, &registry()).is_ok());
    }

    // No tick fails and no object is lost: every frame fits the limit, and
    // after a few ticks every claim is in one.
    let mut proven = BTreeSet::new();
    for _ in 0..4 {
        let outcome = aggregator.on_tick(&txs, &registry());
        assert_eq!(outcome.error, None);
        for frame in &outcome.publish {
            assert!(frame.proof.len() <= tight.max_proof_bytes);
            assert!(frame.claims.len() <= 2);
            proven.extend(frame.claims.iter().map(|claim| claim.digest(DOMAIN)));
        }
    }
    assert_eq!(proven.len(), 5);
    assert_eq!(aggregator.pool().ready_len(), 0);
}

// ---- merging ----------------------------------------------------------------

/// One aggregator with `count` proven objects of its own signers.
fn ticked(
    txs: &mut Txs,
    aggregator: u8,
    first_tx: u16,
    count: u16,
) -> (Aggregator<NativeBackend>, ClaimFrame) {
    let mut agg = Aggregator::new(backend(), ctx(aggregator), params());
    for n in first_tx..first_tx + count {
        let signer = Signer::new(u8::try_from(n % 251).expect("small"));
        let envelope = signed(txs, &signer, n);
        assert!(agg.on_object(envelope, txs, &registry()).is_ok());
    }
    let outcome = agg.on_tick(txs, &registry());
    assert_eq!(outcome.error, None);
    let frame = outcome.publish.first().expect("tick frame").clone();
    (agg, frame)
}

#[test]
fn frames_of_two_aggregators_merge_into_one_valid_frame() {
    let mut txs = Txs::default();
    let (mut first, frame_a) = ticked(&mut txs, 0xA1, 0, 3);
    let (_, frame_b) = ticked(&mut txs, 0xA2, 10, 2);

    assert_eq!(first.on_frame(frame_b.clone(), &registry()), Ok(true));
    assert_eq!(first.on_frame(frame_b, &registry()), Ok(false));
    let outcome = first.on_tick(&txs, &registry());
    assert_eq!(outcome.publish.len(), 1);
    let merged = &outcome.publish[0];
    assert_eq!(merged.claims.len(), 5);
    assert_eq!(merged.segments.len(), 2);
    assert_eq!(merged.shape, vec![SHAPE_TICK, SHAPE_TICK, SHAPE_MERGE]);
    assert_eq!(backend().verify(merged, DOMAIN), Ok(()));
    // The parts stay next to the merged frame.
    assert_eq!(first.frame_count(), 3);
    // Both aggregators keep their segment, so both are paid.
    let owners: BTreeSet<Address> = merged.segments.iter().map(|s| s.aggregator).collect();
    assert_eq!(
        owners,
        BTreeSet::from([ctx(0xA1).aggregator, ctx(0xA2).aggregator])
    );
    // Frames that share a claim do not merge, and nothing is merged twice.
    assert_eq!(first.on_frame(frame_a, &registry()), Ok(false));
    let outcome = first.on_tick(&txs, &registry());
    assert!(outcome.publish.is_empty());
    assert_eq!(first.frame_count(), 3);
}

#[test]
fn a_block_that_carries_one_part_leaves_the_other_part_usable() {
    let mut txs = Txs::default();
    let (mut first, frame_a) = ticked(&mut txs, 0xA1, 0, 3);
    let (_, frame_b) = ticked(&mut txs, 0xA2, 10, 2);
    assert_eq!(first.on_frame(frame_b.clone(), &registry()), Ok(true));
    assert_eq!(first.on_tick(&txs, &registry()).publish.len(), 1);

    // A producer that only knew the first three transactions carried the
    // first part. The merged frame shares its claims and goes with it; the
    // claims of the second part have no object left to prove them again,
    // so the part itself must still be there.
    first.on_final(&frame_a);
    assert_eq!(first.frame_count(), 1);
    let usable: BTreeSet<Hash32> = frame_b.claims.iter().map(|c| c.digest(DOMAIN)).collect();
    assert_eq!(first.block_frame(&usable), Some(frame_b));
}

#[test]
fn an_invalid_frame_from_the_network_is_dropped() {
    let mut txs = Txs::default();
    let (mut first, _) = ticked(&mut txs, 0xA1, 0, 2);
    let (_, frame) = ticked(&mut txs, 0xA2, 10, 2);

    let mut truncated = frame.clone();
    truncated.proof.truncate(truncated.proof.len() - 1);
    assert_eq!(
        first.on_frame(truncated, &registry()),
        Err(AggError::MalformedProof)
    );

    let mut forged = frame.clone();
    let last = forged.proof.len() - 1;
    forged.proof[last] ^= 0x40;
    assert_eq!(
        first.on_frame(forged, &registry()),
        Err(AggError::Object(ObjectError::Invalid))
    );

    let mut reordered = frame;
    reordered.claims.swap(0, 1);
    assert_eq!(
        first.on_frame(reordered, &registry()),
        Err(AggError::Frame(FrameError::ClaimsRootMismatch(0)))
    );
    assert_eq!(first.frame_count(), 1);
}

#[test]
fn duplicate_claim_sets_collapse_and_peer_frames_cannot_evict_local_ticks() {
    let mut txs = Txs::default();
    // Prove a local 1-claim frame on `local_agg`.
    let (mut local_agg, local_tick) = ticked(&mut txs, 0xA1, 0, 1);
    let local_bytes = local_tick.encode().len();

    // Same signer cannot re-submit an already-known claim, so build an identical-claim
    // tick frame from another aggregator over the same claim (e.g. a peer racing on the same tx).
    let signer0 = Signer::new(0);
    let env0 = signer0.envelope(DOMAIN, tx_hash(0));
    let item0 = PoolItem {
        claim: claim_of(&signer0, 0),
        envelope: env0,
    };
    let peer_same_claims = backend()
        .prove_tick(&ctx(0xA2), &[item0])
        .expect("peer frame over same claim");
    assert_eq!(peer_same_claims.claims, local_tick.claims);

    // Peer frame covering the exact same claim set collapses against the existing local frame
    // and never displaces it (`Ok(false)`).
    assert_eq!(local_agg.on_frame(peer_same_claims, &registry()), Ok(false));
    assert_eq!(local_agg.frame_count(), 1);
    assert_eq!(
        local_agg
            .block_frame(&BTreeSet::from([local_tick.claims[0].digest(DOMAIN)]))
            .map(|f| f.segments[0].aggregator),
        Some(ctx(0xA1).aggregator)
    );

    // Now tighten frame store limits to fit just 1 frame (`local_bytes`), and verify a
    // larger peer frame over distinct claims (2 claims) CANNOT evict the local 1-claim tick.
    let mut bounded =
        Aggregator::new(backend(), ctx(0xB1), params()).with_frame_limits(1, local_bytes * 2);
    let e_local = signed(&mut txs, &Signer::new(9), 90);
    assert!(bounded.on_object(e_local, &txs, &registry()).is_ok());
    let local_out = bounded.on_tick(&txs, &registry());
    assert_eq!(local_out.publish.len(), 1);
    let local_digest = local_out.publish[0].claims[0].digest(DOMAIN);

    let (_, peer_2_claims) = ticked(&mut txs, 0xA3, 100, 2);
    assert_eq!(bounded.on_frame(peer_2_claims, &registry()), Ok(false));
    assert_eq!(bounded.frame_count(), 1);
    assert!(bounded.tracks_claim(&local_digest));
}

// ---- the block rules --------------------------------------------------------

/// A block: a frame over the claims of `count` transactions, each authorized
/// by its claim, and the frame hash of the header.
struct Block {
    frame: ClaimFrame,
    header: Hash32,
    /// Per transaction: the digest it claims.
    claimed: Vec<Hash32>,
}

impl Block {
    fn new() -> Self {
        let mut txs = Txs::default();
        let (mut first, _) = ticked(&mut txs, 0xA1, 0, 3);
        let (_, other) = ticked(&mut txs, 0xA2, 10, 2);
        assert_eq!(first.on_frame(other, &registry()), Ok(true));
        let frame = first.on_tick(&txs, &registry()).publish.remove(0);
        let header = frame.hash(DOMAIN).expect("hash");
        // Transactions in another order than the claims.
        let mut claimed: Vec<Hash32> = frame.claims.iter().map(|c| c.digest(DOMAIN)).collect();
        claimed.reverse();
        Self {
            frame,
            header,
            claimed,
        }
    }

    fn txs(&self) -> Vec<TxClaims<'static>> {
        self.claimed
            .iter()
            .map(|digest| TxClaims {
                claimed: Some(*digest),
                account_claim: Some(*digest),
                quantum_safe: true,
                claim_refs: &[],
            })
            .collect()
    }

    /// Recompute the header for a frame that was changed on purpose, so the
    /// rule under test is the one that catches it and not rule 10.
    fn reseal(&mut self) {
        self.header = self.frame.hash(DOMAIN).expect("hash");
    }

    fn check(&self) -> Result<Vec<usize>, BlockClaimError> {
        self.check_with(&params(), &self.txs())
    }

    fn check_with(
        &self,
        params: &AggParams,
        txs: &[TxClaims<'_>],
    ) -> Result<Vec<usize>, BlockClaimError> {
        check_block_claims(
            params,
            DOMAIN,
            Some(&self.header),
            Some(&self.frame),
            txs,
            &registry(),
            &backend(),
        )
        .map(|claims| claims.payers)
    }
}

#[test]
fn a_block_whose_transactions_and_frame_agree_is_valid() {
    let block = Block::new();
    // Claim i is paid by the transaction that claims it: the order is reversed.
    assert_eq!(block.check(), Ok(vec![4, 3, 2, 1, 0]));
    // A block that uses no claim at all carries no frame.
    let plain = [TxClaims {
        claimed: None,
        account_claim: None,
        quantum_safe: false,
        claim_refs: &[],
    }];
    assert!(check_block_claims(
        &params(),
        DOMAIN,
        None,
        None,
        &plain,
        &registry(),
        &backend()
    )
    .is_ok());
}

#[test]
fn a_block_may_not_use_the_layer_unless_the_mode_is_on() {
    let block = Block::new();
    for mode in [AggMode::Off, AggMode::Shadow] {
        let off = AggParams { mode, ..params() };
        assert_eq!(
            block.check_with(&off, &block.txs()),
            Err(BlockClaimError::AggregationOff)
        );
        // A claimed transaction alone, with no frame, is refused too: nobody
        // verified it.
        assert_eq!(
            check_block_claims(
                &off,
                DOMAIN,
                None,
                None,
                &block.txs(),
                &registry(),
                &backend()
            ),
            Err(BlockClaimError::AggregationOff)
        );
        let refs = [[9u8; 32]];
        let with_refs = [TxClaims {
            claimed: None,
            account_claim: None,
            quantum_safe: false,
            claim_refs: &refs,
        }];
        assert_eq!(
            check_block_claims(
                &off,
                DOMAIN,
                None,
                None,
                &with_refs,
                &registry(),
                &backend()
            ),
            Err(BlockClaimError::AggregationOff)
        );
        // An inline quantum-safe transaction is the normal case here.
        let inline = [TxClaims {
            claimed: None,
            account_claim: None,
            quantum_safe: true,
            claim_refs: &[],
        }];
        assert!(
            check_block_claims(&off, DOMAIN, None, None, &inline, &registry(), &backend()).is_ok()
        );
    }
}

#[test]
fn a_quantum_safe_transaction_must_be_claimed_when_the_mode_is_on() {
    let block = Block::new();
    let mut txs = block.txs();
    txs[2].claimed = None;
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::InlineQuantumSafe(2))
    );
}

/// Section 11: a claim without a transaction, a claimed transaction without
/// a claim, and rule 6.
#[test]
fn transactions_and_claims_must_refer_to_each_other() {
    let block = Block::new();

    // Rule 6: the claimed digest is not the one the account rule asks for.
    let mut txs = block.txs();
    txs[1].claimed = Some([0xEE; 32]);
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::WrongAuthClaim(1))
    );
    // Rule 6 again: an account that cannot be claimed for.
    let mut txs = block.txs();
    txs[1].account_claim = None;
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::WrongAuthClaim(1))
    );

    // Rule 7: a claimed transaction whose claim is not in the frame.
    let stray = [0xEE; 32];
    let mut txs = block.txs();
    txs.push(TxClaims {
        claimed: Some(stray),
        account_claim: Some(stray),
        quantum_safe: true,
        claim_refs: &[],
    });
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::MissingClaim(5))
    );
    // Rule 7 through claim_refs.
    let refs = [stray];
    let mut txs = block.txs();
    txs[0].claim_refs = &refs;
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::MissingClaim(0))
    );
    // Rule 7 with no frame at all.
    assert_eq!(
        check_block_claims(
            &params(),
            DOMAIN,
            None,
            None,
            &block.txs(),
            &registry(),
            &backend()
        ),
        Err(BlockClaimError::MissingClaim(0))
    );

    // Rule 8: the frame carries a claim no transaction refers to.
    let mut txs = block.txs();
    let dropped = txs.pop().expect("five");
    assert_eq!(
        block.check_with(&params(), &txs),
        Err(BlockClaimError::UnusedClaim(0))
    );
    // A reference through claim_refs counts, and the first referrer pays.
    let refs = [dropped.claimed.expect("claimed")];
    txs[0].claim_refs = &refs;
    assert_eq!(block.check_with(&params(), &txs), Ok(vec![0, 3, 2, 1, 0]));
}

#[test]
fn the_header_must_carry_the_hash_of_the_frame() {
    let block = Block::new();
    assert_eq!(
        check_block_claims(
            &params(),
            DOMAIN,
            None,
            Some(&block.frame),
            &block.txs(),
            &registry(),
            &backend()
        ),
        Err(BlockClaimError::FramePresence)
    );
    assert_eq!(
        check_block_claims(
            &params(),
            DOMAIN,
            Some(&block.header),
            None,
            &block.txs(),
            &registry(),
            &backend()
        ),
        Err(BlockClaimError::FramePresence)
    );
    let mut wrong = Block::new();
    wrong.header[0] ^= 1;
    assert_eq!(wrong.check(), Err(BlockClaimError::FrameHashMismatch));
    // Rule 10 covers the proof bytes too.
    let mut padded = Block::new();
    padded.frame.proof.push(0);
    assert_eq!(padded.check(), Err(BlockClaimError::FrameHashMismatch));
}

/// Section 11: duplicate and reordered claims; changed `count`,
/// `claims_root`, `aggregator` and `shape`; swapped segments; the claims of
/// another domain. Each makes the block invalid, with the header left alone
/// and with the header recomputed by the attacker.
#[test]
fn every_mutation_of_the_frame_makes_the_block_invalid() {
    type Mutation = fn(&mut ClaimFrame);
    let structural: [(Mutation, FrameError); 7] = [
        (
            |f| {
                f.claims.push(f.claims[0].clone());
                f.segments[1].count += 1;
            },
            FrameError::DuplicateClaim,
        ),
        (|f| f.claims.swap(0, 1), FrameError::ClaimsRootMismatch(0)),
        (|f| f.segments[0].count += 1, FrameError::CountMismatch),
        (
            |f| f.segments[1].claims_root[7] ^= 1,
            FrameError::ClaimsRootMismatch(1),
        ),
        (|f| f.shape.push(SHAPE_MERGE), FrameError::BadShape),
        (|f| f.shape.swap(1, 2), FrameError::BadShape),
        (|f| f.segments.swap(0, 1), FrameError::ClaimsRootMismatch(0)),
    ];
    for (at, (mutate, expected)) in structural.into_iter().enumerate() {
        let mut block = Block::new();
        mutate(&mut block.frame);
        assert_eq!(
            block.check(),
            Err(BlockClaimError::Frame(expected)),
            "mutation {at}, header kept"
        );
        // An attacker who also controls the header gains nothing. A frame
        // whose shape does not fold has no hash to put there.
        if let Ok(header) = block.frame.hash(DOMAIN) {
            block.header = header;
            assert_eq!(
                block.check(),
                Err(BlockClaimError::Frame(expected)),
                "mutation {at}, header recomputed"
            );
        }
    }

    // A changed aggregator leaves the structure intact and moves the public
    // input, so the hash of the header no longer matches.
    let mut block = Block::new();
    block.frame.segments[0].aggregator = Address::from([0x99; 32]);
    assert_eq!(block.check(), Err(BlockClaimError::FrameHashMismatch));

    // The claims of another domain: the same block read under another domain.
    let block = Block::new();
    assert_eq!(
        check_block_claims(
            &params(),
            DOMAIN + 1,
            Some(&block.header),
            Some(&block.frame),
            &block.txs(),
            &registry(),
            &backend()
        ),
        Err(BlockClaimError::Frame(FrameError::ClaimsRootMismatch(0)))
    );
}

/// Segment ownership attestations bind every `tick_pi` to its aggregator's
/// ML-DSA-87 keypair: mutating `segment.aggregator` or corrupting the
/// signature is refused by `NativeBackend::verify`, `Aggregator::on_frame`,
/// and `check_block_claims`, even if the attacker recomputes `frame_hash`.
#[test]
fn segment_attestations_bind_every_segment_to_its_aggregator() {
    let block = Block::new();
    let mut stolen = block.frame.clone();
    stolen.segments[0].aggregator = Address::from([0x99; 32]);
    assert_eq!(
        backend().verify(&stolen, DOMAIN),
        Err(AggError::InvalidSegmentAttestation(0))
    );
    assert_ne!(stolen.hash(DOMAIN), block.frame.hash(DOMAIN));

    let mut bad_sig = block.frame.clone();
    bad_sig.segments[1].attestation.signature[0] ^= 0x01;
    assert_eq!(
        backend().verify(&bad_sig, DOMAIN),
        Err(AggError::InvalidSegmentAttestation(1))
    );

    let mut resealed = Block::new();
    resealed.frame.segments[0].aggregator = Address::from([0x99; 32]);
    resealed.reseal();
    assert_eq!(
        resealed.check(),
        Err(BlockClaimError::Proof(AggError::InvalidSegmentAttestation(
            0
        )))
    );
}

/// Section 11: the proof of another parameter set, a truncated proof, an
/// oversized proof, and a proof whose objects are wrong.
#[test]
fn a_wrong_proof_makes_the_block_invalid() {
    // Another parameter set.
    let block = Block::new();
    let other_set = NativeBackend::new(registry(), FrameLimits::from(&params()), SET + 1);
    assert_eq!(
        check_block_claims(
            &params(),
            DOMAIN,
            Some(&block.header),
            Some(&block.frame),
            &block.txs(),
            &registry(),
            &other_set
        ),
        Err(BlockClaimError::Proof(AggError::WrongParameterSet))
    );

    // Truncated, by one byte and to nothing.
    for keep in [1usize, 0] {
        let mut block = Block::new();
        let len = block.frame.proof.len();
        block.frame.proof.truncate((len - 1) * keep);
        block.reseal();
        assert_eq!(
            block.check(),
            Err(BlockClaimError::Proof(AggError::MalformedProof))
        );
    }

    // Oversized: over the consensus limit (rule 9).
    let mut block = Block::new();
    let tight = AggParams {
        max_proof_bytes: block.frame.proof.len() - 1,
        ..params()
    };
    assert_eq!(
        block.check_with(&tight, &block.txs()),
        Err(BlockClaimError::Frame(FrameError::ProofTooLarge(
            block.frame.proof.len()
        )))
    );
    // Oversized by padding: bytes after the last object.
    block.frame.proof.push(0);
    block.reseal();
    assert_eq!(
        block.check(),
        Err(BlockClaimError::Proof(AggError::MalformedProof))
    );

    // A wrong signature inside the proof.
    let mut block = Block::new();
    let last = block.frame.proof.len() - 1;
    block.frame.proof[last] ^= 0x40;
    block.reseal();
    assert_eq!(
        block.check(),
        Err(BlockClaimError::Proof(AggError::Object(
            ObjectError::Invalid
        )))
    );

    // Too many claims (rule 9).
    let block = Block::new();
    let tight = AggParams {
        max_claims_per_block: 4,
        ..params()
    };
    assert_eq!(
        block.check_with(&tight, &block.txs()),
        Err(BlockClaimError::Frame(FrameError::TooManyClaims(5)))
    );
}

/// Section 11: a claim cannot be made for an object that stands for another
/// claim. The frame is built by hand: valid objects, and claims that name
/// another signer, message or scheme than the objects prove.
#[test]
fn a_frame_whose_claims_are_not_what_its_objects_prove_is_refused() {
    let mut txs = Txs::default();
    let signer = Signer::new(1);
    let envelope = signed(&mut txs, &signer, 1);
    let item = |claim: Claim| PoolItem {
        envelope: envelope.clone(),
        claim,
    };
    let honest = claim_of(&signer, 1);
    let lies = [
        Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: Signer::new(2).address(),
            msg_hash: tx_hash(1),
        },
        Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: signer.address(),
            msg_hash: tx_hash(2),
        },
        Claim::Sig {
            scheme: SchemeId::ED25519,
            signer: signer.address(),
            msg_hash: tx_hash(1),
        },
    ];
    let frame = backend()
        .prove_tick(&ctx(0xA1), &[item(honest)])
        .expect("honest tick");
    assert_eq!(backend().verify(&frame, DOMAIN), Ok(()));
    for lie in lies {
        let frame = backend()
            .prove_tick(&ctx(0xA1), &[item(lie)])
            .expect("the native prover does not check");
        assert_eq!(
            backend().verify(&frame, DOMAIN),
            Err(AggError::ProofMismatch)
        );
    }
}

/// The native proof must hold exactly the objects of the claims, each made
/// for the domain of the frame.
#[test]
fn a_native_proof_with_extra_objects_or_another_domain_is_refused() {
    let mut txs = Txs::default();
    let (_, frame) = ticked(&mut txs, 0xA1, 0, 2);
    let (_, other) = ticked(&mut txs, 0xA2, 10, 2);

    // More objects than claims.
    let mut padded = frame.clone();
    padded.proof = backend().prove_merge(&frame, &other).expect("merge");
    assert_eq!(
        backend().verify(&padded, DOMAIN),
        Err(AggError::ProofMismatch)
    );
    // Fewer objects than claims.
    let (_, single) = ticked(&mut txs, 0xA3, 20, 1);
    let mut starved = frame.clone();
    starved.proof = single.proof;
    assert_eq!(
        backend().verify(&starved, DOMAIN),
        Err(AggError::ProofMismatch)
    );

    // The first object says it was made for another domain. The domain sits
    // after the proof header (12 bytes), the object length (4) and the kind,
    // scheme and transaction hash of the envelope (35).
    let mut elsewhere = frame;
    elsewhere.proof[12 + 4 + 35 + 3] ^= 1;
    assert_eq!(
        backend().verify(&elsewhere, DOMAIN),
        Err(AggError::WrongDomain)
    );

    // The prover refuses an item of another domain and an item whose payload
    // is gone.
    let signer = Signer::new(9);
    let item = PoolItem {
        envelope: signer.envelope(DOMAIN + 1, tx_hash(900)),
        claim: claim_of(&signer, 900),
    };
    assert_eq!(
        backend().prove_tick(&ctx(0xA1), &[item]),
        Err(AggError::WrongDomain)
    );
    let mut pruned = PoolItem {
        envelope: signer.envelope(DOMAIN, tx_hash(900)),
        claim: claim_of(&signer, 900),
    };
    pruned.envelope.payload.clear();
    assert_eq!(
        backend().prove_tick(&ctx(0xA1), &[pruned]),
        Err(AggError::PayloadPruned)
    );
}

/// Section 11, differential test: native verification of an object and
/// verification of the proof made from it give the same answer.
#[test]
fn native_verification_and_proof_verification_agree() {
    let mut txs = Txs::default();
    let signer = Signer::new(1);
    let good = signed(&mut txs, &signer, 1);
    let mut cases = vec![good.clone()];
    for at in [0usize, 100, 2591, 2592, 4000, 7218] {
        let mut bad = good.clone();
        bad.payload[at] ^= 0x40;
        cases.push(bad);
    }
    let mut other_message = good;
    other_message.tx_hash = tx_hash(2);
    cases.push(other_message);
    let mut accepted = 0;
    for envelope in cases {
        let native = derive_claim(&registry(), &envelope);
        // The claim the sender wants: its own account over this transaction.
        let wanted = Claim::Sig {
            scheme: SchemeId::ML_DSA_87,
            signer: signer.address(),
            msg_hash: envelope.tx_hash,
        };
        let frame = backend()
            .prove_tick(
                &ctx(0xA1),
                &[PoolItem {
                    envelope,
                    claim: wanted.clone(),
                }],
            )
            .expect("tick");
        let proven = backend().verify(&frame, DOMAIN).is_ok();
        assert_eq!(native == Ok(wanted), proven);
        accepted += usize::from(proven);
    }
    assert_eq!(accepted, 1);
}

// ---- fees -------------------------------------------------------------------

#[test]
fn the_claim_fee_is_split_between_the_aggregators_and_the_producer() {
    let block = Block::new();
    let payers = block.check().expect("valid");
    let fee = 64 * 67;
    let tx_fees = vec![FEE; 5];
    let settled = settle(&params(), &block.frame, &payers, &tx_fees);
    assert_eq!(settled.charged, vec![fee; 5]);
    assert_eq!(settled.failed, vec![false; 5]);
    // Segment sizes follow the frame: one has 3 claims, the other 2.
    let by_owner: BTreeMap<Address, u64> = settled.payout.aggregators.iter().copied().collect();
    let counts: BTreeMap<Address, u64> = block
        .frame
        .segments
        .iter()
        .map(|s| (s.aggregator, u64::from(s.count)))
        .collect();
    for (owner, count) in &counts {
        assert_eq!(by_owner[owner], count * fee / 2);
    }
    assert_eq!(settled.payout.producer, 5 * fee / 2);
    let paid: u64 = settled.payout.aggregators.iter().map(|(_, a)| a).sum();
    assert_eq!(paid + settled.payout.producer, 5 * fee);
}

/// Section 11: a transaction that cannot pay the claim fee fails, and its
/// claim stays in the frame.
#[test]
fn a_transaction_that_cannot_pay_the_claim_fee_fails_and_its_claim_stays() {
    let block = Block::new();
    let payers = block.check().expect("valid");
    let fee = 64 * 67;
    let mut tx_fees = vec![FEE; 5];
    tx_fees[4] = fee - 1;
    let settled = settle(&params(), &block.frame, &payers, &tx_fees);
    assert_eq!(settled.failed, vec![false, false, false, false, true]);
    assert_eq!(settled.charged, vec![fee, fee, fee, fee, 0]);
    let paid: u64 = settled.payout.aggregators.iter().map(|(_, a)| a).sum();
    assert_eq!(paid + settled.payout.producer, 4 * fee);
    // The block stays valid: the claim is in the frame and is referred to.
    assert_eq!(block.frame.claims.len(), 5);
    assert!(block.check().is_ok());
}

#[test]
fn the_split_never_creates_or_loses_a_unit() {
    for bps in [0u16, 1, 3333, 5000, 9999, 10_000, u16::MAX] {
        let p = AggParams {
            agg_share_bps: bps,
            ..params()
        };
        for total in [0u64, 1, 2, 3, 4287, 4288, 10_001, u64::MAX] {
            let (aggregator, producer) = split_segment_fees(&p, total);
            assert_eq!(
                aggregator.checked_add(producer),
                Some(total),
                "{bps} {total}"
            );
        }
    }
    assert_eq!(split_segment_fees(&params(), 4288), (2144, 2144));
    assert_eq!(split_segment_fees(&params(), 3), (1, 2));
}

// ---- load -------------------------------------------------------------------

/// Section 11, load test, in one process: four aggregators each prove a tick
/// of 256 objects, a fifth node collects the four frames, merges them and
/// produces a block of 1024 claims that passes every block rule.
#[test]
fn four_aggregators_and_a_producer_carry_1024_claims_in_one_block() {
    let mut txs = Txs::default();
    let mut frames = Vec::new();
    for (aggregator, first_tx) in [(0xA1u8, 0u16), (0xA2, 1000), (0xA3, 2000), (0xA4, 3000)] {
        let (_, frame) = ticked(&mut txs, aggregator, first_tx, 256);
        assert_eq!(frame.claims.len(), 256);
        frames.push(frame);
    }
    let mut producer = Aggregator::new(backend(), ctx(0xB0), params());
    for frame in frames {
        assert_eq!(producer.on_frame(frame, &registry()), Ok(true));
    }
    let merged = producer.on_tick(&txs, &registry()).publish;
    assert_eq!(merged.len(), 3);

    // The transactions of the block: every transaction of the mempool.
    let wanted: Vec<Hash32> = txs
        .0
        .iter()
        .map(|(hash, facts)| {
            Claim::Sig {
                scheme: SchemeId::ML_DSA_87,
                signer: facts.from,
                msg_hash: *hash,
            }
            .digest(DOMAIN)
        })
        .collect();
    let usable: BTreeSet<Hash32> = wanted.iter().copied().collect();
    let frame = producer.block_frame(&usable).expect("a frame");
    assert_eq!(frame.claims.len(), 1024);
    assert_eq!(frame.segments.len(), 4);
    let header = frame_hash(
        &frame
            .check_structure(DOMAIN, &FrameLimits::from(&params()))
            .expect("valid")
            .master_pi,
        &frame.segments,
        &frame.proof,
    );
    let block_txs: Vec<TxClaims<'_>> = wanted
        .iter()
        .map(|digest| TxClaims {
            claimed: Some(*digest),
            account_claim: Some(*digest),
            quantum_safe: true,
            claim_refs: &[],
        })
        .collect();
    let claims = check_block_claims(
        &params(),
        DOMAIN,
        Some(&header),
        Some(&frame),
        &block_txs,
        &registry(),
        &backend(),
    )
    .expect("a valid block");
    assert_eq!(claims.payers.len(), 1024);
    // What the block carries per transaction instead of 7219 signature bytes.
    let per_claim = frame.claims[0].encoded_len();
    assert_eq!(per_claim, 67);

    // A frame is not usable when a transaction of its claims is missing;
    // the frames that do not need that transaction still are.
    let mut fewer = usable;
    fewer.remove(&wanted[0]);
    let partial = producer
        .block_frame(&fewer)
        .expect("the parts are still there");
    assert!(partial.claims.len() < 1024);
    assert!(partial
        .claims
        .iter()
        .all(|claim| fewer.contains(&claim.digest(DOMAIN))));

    // Once the block is final the frame leaves the aggregator.
    producer.on_final(&frame);
    assert_eq!(producer.frame_count(), 0);
}
