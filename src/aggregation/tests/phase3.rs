//! Phase 3 aggregation tests:
//! 1. `AggMerge` `BudVM` execution + program-hash allowlist enforcement.
//! 2. End-to-end `Plonky3Adapter` (`BudAir`) + `BoundKeccakAir` proof for `AggMerge`.
//! 3. `StarkBackend` recursive `MasterProof` (including 1,024 claims <= 262,144 B)
//!    and negative forgery/replay/wrong-domain/wrong-program/bit-flip checks.
//! 4. `ShadowAuditor` 10,000-block parity against native ML-DSA-87 verification.

use zeroize::Zeroizing;

use crate::aggregation::backend::{AggBackend, AggError, TickCtx};
use crate::aggregation::frame::{merge_pi, ClaimFrame, FrameError, FrameLimits};
use crate::aggregation::object::derive_claim;
use crate::aggregation::params::{AggMode, AggParams};
use crate::aggregation::pool::PoolItem;
use crate::aggregation::programs::agg_merge::{
    agg_merge, prove_agg_merge, published_writes_digest_many, run_agg_merge, verify_agg_merge,
    AggMergeError, AggMergeWitness,
};
use crate::aggregation::shadow::ShadowAuditor;
use crate::aggregation::stark::{
    agg_merge_program_hash, agg_tick_program_hash, is_allowed_agg_program, StarkBackend,
    STARK_PARAMETER_SET,
};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::WalletKeyPair;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::DomainId;

const DOMAIN: DomainId = 43;

fn make_signed_tx(seed_byte: u8, nonce: u64) -> Transaction {
    let wallet = WalletKeyPair::from_seed(&[seed_byte; 32]);
    let mut tx = Transaction::new_with_fee(
        wallet.address(),
        Address::from([0x22; 32]),
        10,
        100_000,
        nonce,
        Vec::new(),
    );
    tx.chain_id = u64::from(DOMAIN);
    tx.sign_v5(&wallet);
    tx
}

fn pool_item_from_tx(tx: &Transaction, registry: &SchemeStatusRegistry) -> PoolItem {
    let (_, envelope) = crate::aggregation::chain::claim_signature(tx).expect("signature object");
    let claim = derive_claim(registry, &envelope).expect("derive claim");
    PoolItem { envelope, claim }
}

#[test]
fn agg_merge_vm_executes_and_enforces_program_hash_allowlist() {
    let tick_hash = agg_tick_program_hash();
    let merge_prog = agg_merge(&tick_hash).expect("compile AggMerge");
    assert_eq!(merge_prog.self_program_hash, agg_merge_program_hash());
    assert!(is_allowed_agg_program(&tick_hash));
    assert!(is_allowed_agg_program(&merge_prog.self_program_hash));
    assert!(!is_allowed_agg_program(&[0x99; 32]));

    let left_pi = [0x11; 32];
    let right_pi = [0x22; 32];
    let expected = merge_pi(&left_pi, &right_pi);

    // Tick + Tick allowed.
    let run = run_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: tick_hash,
            left_pi,
            right_program_hash: tick_hash,
            right_pi,
        },
    )
    .expect("Tick + Tick executes");
    assert_eq!(run.merge_pi, expected);
    assert_eq!(
        run.state_writes_digest,
        published_writes_digest_many(&[&left_pi, &right_pi, &expected])
    );

    // Merge + Tick allowed.
    let run_mt = run_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: merge_prog.self_program_hash,
            left_pi,
            right_program_hash: tick_hash,
            right_pi,
        },
    )
    .expect("Merge + Tick executes");
    assert_eq!(run_mt.merge_pi, expected);

    // Unauthorized left child program hash refused by guest.
    let bad_left = run_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: [0xAB; 32],
            left_pi,
            right_program_hash: tick_hash,
            right_pi,
        },
    );
    assert_eq!(
        bad_left.err(),
        Some(AggMergeError::UnauthorizedChildProgram)
    );

    // Unauthorized right child program hash refused by guest.
    let bad_right = run_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: tick_hash,
            left_pi,
            right_program_hash: [0xCD; 32],
            right_pi,
        },
    );
    assert_eq!(
        bad_right.err(),
        Some(AggMergeError::UnauthorizedChildProgram)
    );
}

#[test]
fn agg_merge_proves_and_verifies_end_to_end_in_plonky3_adapter() {
    let tick_hash = agg_tick_program_hash();
    let merge_prog = agg_merge(&tick_hash).expect("compile AggMerge");
    let left_pi = [0x33; 32];
    let right_pi = [0x44; 32];
    let expected = merge_pi(&left_pi, &right_pi);

    let proof = prove_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: tick_hash,
            left_pi,
            right_program_hash: merge_prog.self_program_hash,
            right_pi,
        },
        u64::from(DOMAIN),
    )
    .expect("BudAir + BoundKeccakAir prove succeeds");
    assert!(proof.steps < 1024);

    verify_agg_merge(
        &merge_prog,
        &left_pi,
        &right_pi,
        &expected,
        u64::from(DOMAIN),
        &proof,
    )
    .expect("AggMerge proof verifies");

    // Wrong chain_id must be rejected.
    assert!(verify_agg_merge(
        &merge_prog,
        &left_pi,
        &right_pi,
        &expected,
        u64::from(DOMAIN) + 1,
        &proof,
    )
    .is_err());

    // Wrong expected merge_pi must be rejected.
    let mut wrong_pi = expected;
    wrong_pi[0] ^= 0xFF;
    assert!(verify_agg_merge(
        &merge_prog,
        &left_pi,
        &right_pi,
        &wrong_pi,
        u64::from(DOMAIN),
        &proof,
    )
    .is_err());

    // Swapped left/right order must be rejected (merge is non-commutative).
    let swapped = merge_pi(&right_pi, &left_pi);
    assert!(verify_agg_merge(
        &merge_prog,
        &right_pi,
        &left_pi,
        &swapped,
        u64::from(DOMAIN),
        &proof,
    )
    .is_err());
}

#[test]
fn stark_backend_proves_merges_and_rejects_forgery() {
    let registry = SchemeStatusRegistry::genesis();
    let default_params = AggParams::default();
    let limits = FrameLimits::from(&default_params);
    let backend = StarkBackend::new(registry.clone(), limits, STARK_PARAMETER_SET);

    let tx1 = make_signed_tx(1, 0);
    let tx2 = make_signed_tx(2, 0);
    let tx3 = make_signed_tx(3, 0);
    let tx4 = make_signed_tx(4, 0);

    let tick_left = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xAA; 32])).expect("tick_left ctx"),
            &[
                pool_item_from_tx(&tx1, &registry),
                pool_item_from_tx(&tx2, &registry),
            ],
        )
        .expect("tick_left proves");
    backend
        .verify(&tick_left, DOMAIN)
        .expect("tick_left verifies");

    let tick_right = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xBB; 32])).expect("tick_right ctx"),
            &[
                pool_item_from_tx(&tx3, &registry),
                pool_item_from_tx(&tx4, &registry),
            ],
        )
        .expect("tick_right proves");
    backend
        .verify(&tick_right, DOMAIN)
        .expect("tick_right verifies");

    let merge_proof = backend
        .prove_merge(&tick_left, &tick_right)
        .expect("prove_merge succeeds");
    let master = ClaimFrame::combine(&tick_left, &tick_right, merge_proof).expect("combine");
    assert!(
        master.proof.len() <= default_params.max_proof_bytes,
        "master proof {} exceeds default budget {}",
        master.proof.len(),
        default_params.max_proof_bytes
    );
    backend.verify(&master, DOMAIN).expect("master verifies");

    // Wrong domain must be refused.
    assert_eq!(
        backend.verify(&master, DOMAIN + 1),
        Err(AggError::Frame(FrameError::ClaimsRootMismatch(0)))
    );

    // Cross-domain merge must be refused.
    let mut tx_other = Transaction::new_with_fee(
        WalletKeyPair::from_seed(&[5; 32]).address(),
        Address::from([0x22; 32]),
        10,
        100_000,
        0,
        Vec::new(),
    );
    tx_other.chain_id = u64::from(DOMAIN + 1);
    tx_other.sign_v5(&WalletKeyPair::from_seed(&[5; 32]));
    let (_, env_other) = crate::aggregation::chain::claim_signature(&tx_other).expect("other env");
    let claim_other = derive_claim(&registry, &env_other).expect("other claim");
    let other_domain_tick = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN + 1, Zeroizing::new([0xCC; 32])).expect("other ctx"),
            &[PoolItem {
                envelope: env_other,
                claim: claim_other,
            }],
        )
        .expect("other domain tick");
    assert_eq!(
        backend.prove_merge(&tick_left, &other_domain_tick),
        Err(AggError::WrongDomain)
    );

    // Wrong parameter set must be refused.
    let other_backend = StarkBackend::new(registry.clone(), limits, STARK_PARAMETER_SET + 1);
    assert_eq!(
        other_backend.verify(&master, DOMAIN),
        Err(AggError::WrongParameterSet)
    );

    // Redirecting aggregator fee by changing segment.aggregator must be refused.
    let mut stolen_fee = master.clone();
    stolen_fee.segments[0].aggregator = Address::from([0xEE; 32]);
    assert!(backend.verify(&stolen_fee, DOMAIN).is_err());

    // Tampering program_hash header to an unauthorized program must be refused.
    let mut bad_program_frame = tick_left.clone();
    // Header layout: magic(4) + ver(1) + param(4) + domain(4) + program_hash(32)
    bad_program_frame.proof[13] ^= 0xFF;
    assert_eq!(
        backend.verify(&bad_program_frame, DOMAIN),
        Err(AggError::ProofMismatch)
    );
    assert_eq!(
        backend.prove_merge(&bad_program_frame, &tick_right),
        Err(AggError::ProofMismatch)
    );

    // Swapping a tick proof directly onto a merged frame must be refused.
    let fake_merge =
        ClaimFrame::combine(&tick_left, &tick_right, tick_left.proof.clone()).expect("combine");
    assert_eq!(
        backend.verify(&fake_merge, DOMAIN),
        Err(AggError::ProofMismatch)
    );

    // Flipping a bit inside the STARK proof bytes must be refused.
    let mut corrupted = master.clone();
    let last_idx = corrupted.proof.len() - 1;
    corrupted.proof[last_idx] ^= 0x01;
    assert!(backend.verify(&corrupted, DOMAIN).is_err());

    // 1024-claim block proof from 4 aggregators must fit strictly inside
    // `AggParams::default().max_proof_bytes` (262,144 bytes).
    let wallet = WalletKeyPair::from_seed(&[0x55; 32]);
    let mut agg_frames = Vec::with_capacity(4);
    for agg_idx in 0u8..4 {
        let mut items = Vec::with_capacity(256);
        for j in 0u64..256 {
            let mut tx = Transaction::new_with_fee(
                wallet.address(),
                Address::from([0x44; 32]),
                10,
                100_000,
                u64::from(agg_idx) * 256 + j,
                Vec::new(),
            );
            tx.chain_id = u64::from(DOMAIN);
            tx.sign_v5(&wallet);
            items.push(pool_item_from_tx(&tx, &registry));
        }
        let frame = backend
            .prove_tick(
                &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xA0 + agg_idx; 32])).expect("agg ctx"),
                &items,
            )
            .expect("256-claim tick proves");
        agg_frames.push(frame);
    }
    let m01_proof = backend
        .prove_merge(&agg_frames[0], &agg_frames[1])
        .expect("merge 0+1");
    let m01 = ClaimFrame::combine(&agg_frames[0], &agg_frames[1], m01_proof).expect("combine 0+1");
    let m23_proof = backend
        .prove_merge(&agg_frames[2], &agg_frames[3])
        .expect("merge 2+3");
    let m23 = ClaimFrame::combine(&agg_frames[2], &agg_frames[3], m23_proof).expect("combine 2+3");
    let master_1024_proof = backend.prove_merge(&m01, &m23).expect("master 1024 merge");
    let master_1024 = ClaimFrame::combine(&m01, &m23, master_1024_proof).expect("combine 1024");
    assert_eq!(master_1024.claims.len(), 1024);
    assert!(
        master_1024.proof.len() <= default_params.max_proof_bytes,
        "1024-claim MasterProof {} exceeds default max_proof_bytes {}",
        master_1024.proof.len(),
        default_params.max_proof_bytes
    );
    backend
        .verify(&master_1024, DOMAIN)
        .expect("1024-claim MasterProof verifies");
}

#[test]
fn shadow_auditor_matches_native_across_10000_blocks() {
    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams {
        mode: AggMode::Shadow,
        ..AggParams::default()
    };

    let valid_tx = make_signed_tx(7, 0);
    let mut bad_sig_tx = make_signed_tx(8, 0);
    if let Some(sig) = bad_sig_tx.signature.as_mut() {
        if let Some(last) = sig.last_mut() {
            *last ^= 0xFF;
        }
    }

    let mut auditor = ShadowAuditor::new(registry, params);
    let prev_hash = "00".repeat(32);
    for height in 1u64..=10_000 {
        let tx = if height.is_multiple_of(500) {
            bad_sig_tx.clone()
        } else {
            valid_tx.clone()
        };
        let block =
            Block::new_with_chain_id(height, prev_hash.clone(), vec![tx], u64::from(DOMAIN));
        let ok = auditor.audit_block(&block).expect("audit_block succeeds");
        assert!(ok, "shadow divergence at block {height}");
    }

    let report = auditor.report();
    assert_eq!(report.blocks_audited, 10_000);
    assert_eq!(report.txs_checked, 10_000);
    assert_eq!(report.matches, 10_000);
    assert_eq!(report.mismatches, 0);
}
