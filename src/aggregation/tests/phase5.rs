//! Phase 5 tests: split STARK verifier (`verify_pcs_openings` + `verify_algebra`),
//! `ObjectKind::PcsOpening -> Claim::Poly`, `TransactionType::VerifyStark`,
//! `AirRegistry` (built-in `BudAir`, `AggFoldAir`, and external non-`BudAir`
//! `FibonacciAir`), 10,000-case differential test, negative tests, prefix-free
//! domain tag test, and 4-aggregator 1,024-claim load test.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bincode::Options;
use bud_proof::chips::fib::{prove_fibonacci, verify_fibonacci};
use bud_proof::plonky3_prover::{
    chip_commitment_from_bytes, chip_commitment_to_bytes, extract_bud_envelope_pcs, Plonky3Adapter,
};
use bud_proof::ProverAdapter;
use zeroize::Zeroizing;

use crate::aggregation::air_registry::{
    agg_fold_air_id, bud_air_id, external_fib_air_id, AirRegistry, AirVerifyError,
    ExternalFibAirEvaluator,
};
use crate::aggregation::backend::{AggBackend, TickCtx};
use crate::aggregation::chain::{
    check_block_with_backend_and_airs, check_pool_transaction, claim_signature,
};
use crate::aggregation::claim::{Claim, Ext, GOLDILOCKS_MODULUS};
use crate::aggregation::domain_finality::{compile_domain_transition, prove_domain_transition};
use crate::aggregation::envelope::{Envelope, ObjectKind};
use crate::aggregation::frame::{ClaimFrame, FrameLimits};
use crate::aggregation::hash::{
    TAG_AGG_MERGE, TAG_AGG_TICK, TAG_AIR_ID, TAG_CLAIM, TAG_CLAIM_ROOT, TAG_FRAME, TAG_OBJECT,
    TAG_PCS_EVAL, TAG_PCS_POLY,
};
use crate::aggregation::object::{derive_claim, ObjectError};
use crate::aggregation::params::{AggMode, AggParams};
use crate::aggregation::pool::PoolItem;
use crate::aggregation::programs::pcs_claim::{
    verify_pcs_opening, BudAirAuxData, PcsOpeningObject, VerifyStarkTx,
};
use crate::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::chain_config::Network;
use crate::core::transaction::{Transaction, TransactionType};
use crate::crypto::primitives::WalletKeyPair;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainId, DomainStatus, Hash32, RootScheme,
};
use crate::network::proto_conversions::pb::ProtoTransaction;

fn phase5_params() -> AggParams {
    AggParams {
        mode: AggMode::On,
        max_stark_object_bytes: 1_048_576,
        max_pcs_object_bytes: 1_048_576,
        ..AggParams::default()
    }
}

fn stark_backend(params: &AggParams) -> StarkBackend {
    StarkBackend::new(
        SchemeStatusRegistry::genesis(),
        FrameLimits::from(params),
        STARK_PARAMETER_SET,
    )
}

fn domain_of(chain_id: u64) -> DomainId {
    u32::try_from(chain_id).expect("testnet chain id fits DomainId")
}

fn make_verify_stark_tx_and_envelopes(
    sender: &WalletKeyPair,
    chain_id: u64,
    nonce: u64,
    pcs_obj: &PcsOpeningObject,
    verify_stmt: VerifyStarkTx,
) -> (Transaction, Envelope, Envelope, Claim) {
    let domain = domain_of(chain_id);
    let pcs_payload = pcs_obj.encode().expect("encode pcs object");
    let poly_claim = verify_pcs_opening(pcs_obj).expect("verify pcs opening");
    let poly_digest = poly_claim.digest(domain);

    let mut raw_tx = Transaction::new(sender.address(), Address::zero(), 0, Vec::new());
    raw_tx.chain_id = chain_id;
    raw_tx.nonce = nonce;
    raw_tx.fee = 20_000;
    raw_tx.tx_type = TransactionType::VerifyStark(Box::new(verify_stmt));
    raw_tx.claim_refs.push(poly_digest);
    raw_tx.sign_v5(sender);

    let tx_hash = raw_tx.signing_hash();
    let (claimed_tx, sig_env) = claim_signature(&raw_tx).expect("claim signature");
    let pcs_env = Envelope {
        kind: ObjectKind::PcsOpening,
        scheme: SchemeId(0),
        payload: pcs_payload,
        tx_hash,
        domain,
    };
    (claimed_tx, sig_env, pcs_env, poly_claim)
}

fn build_block(chain_id: u64, txs: Vec<Transaction>, frame: ClaimFrame) -> Block {
    let domain = domain_of(chain_id);
    let mut block = Block::new_with_chain_id(1, "0".repeat(64), txs, chain_id);
    block.frame_hash = Some(frame.hash(domain).expect("frame hash"));
    block.claim_frame = Some(frame);
    block
}

fn prove_single_bud_domain_proof(
    chain_id: u64,
) -> (
    PcsOpeningObject,
    VerifyStarkTx,
    bud_proof::adapter::ProofEnvelope,
    Vec<u64>,
    bud_proof::adapter::ExecutionPublicInputs,
) {
    let domain = domain_of(chain_id);
    let compiled = compile_domain_transition(77, 42_161).expect("compile domain transition");
    let consensus_domain = ConsensusDomain {
        id: 77,
        kind: ConsensusKind::Zk,
        status: DomainStatus::Active,
        domain_chain_id: 42_161,
        operator: None,
        operator_bond: 0,
        config_hash: [0x55; 32],
        validator_set_hash: [0x66; 32],
        finality_adapter: "agg-claimed-program-finality".into(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha3_256,
        state_root_scheme: RootScheme::Sha3_256,
        tx_root_scheme: RootScheme::Sha3_256,
        last_committed_height: 10,
        last_committed_hash: [0x11; 32],
        pow_parameters: None,
        zk_program_allowlist: vec![compiled.program_hash],
        plugin_code_hash: None,
        genesis_state_root: [0x11; 32],
    };
    let prev_root = [0x11u8; 32];
    let batch_digest = [0xABu8; 32];
    let commitment = DomainCommitment {
        domain_id: 77,
        domain_height: 11,
        domain_block_hash: [0x44; 32],
        parent_domain_block_hash: [0x43; 32],
        state_root: [0x99; 32],
        tx_root: [0x22; 32],
        event_root: [0x33; 32],
        finality_proof_hash: [0x55; 32],
        consensus_kind: ConsensusKind::Zk,
        validator_set_hash: [0x66; 32],
        timestamp_ms: 1_750_000_000_000,
        sequence: 11,
        producer: None,
        state_updates: BTreeMap::new(),
    };
    let stark_obj = prove_domain_transition(
        &compiled,
        &consensus_domain,
        10,
        &prev_root,
        &commitment,
        &batch_digest,
        domain,
    )
    .expect("prove domain transition");

    let pcs_obj = PcsOpeningObject::from_bud_envelope(
        &stark_obj.proof_envelope,
        &stark_obj.program,
        &stark_obj.public_inputs,
    )
    .expect("build BudAir PcsOpeningObject");
    let aux = BudAirAuxData {
        program: stark_obj.program.clone(),
        expected_inputs: stark_obj.public_inputs.clone(),
    };
    let aux_bytes = bincode::DefaultOptions::new()
        .serialize(&aux)
        .expect("serialize BudAirAuxData");
    let verify_stmt = pcs_obj.to_verify_stark_tx(bud_air_id(), aux_bytes);
    (
        pcs_obj,
        verify_stmt,
        stark_obj.proof_envelope,
        stark_obj.program,
        stark_obj.public_inputs,
    )
}

#[test]
fn external_non_budzkvm_air_verifies_end_to_end_via_claim_poly_and_verify_stark() {
    let chain_id = Network::Testnet.chain_id().value();
    let domain = domain_of(chain_id);
    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let backend = stark_backend(&params);

    let mut air_registry = AirRegistry::with_builtins();
    air_registry
        .register(Arc::new(ExternalFibAirEvaluator))
        .expect("register external FibonacciAir");

    let (fib_proof, pvs, shape) = prove_fibonacci(6, 1, 1).expect("prove external FibonacciAir");
    assert!(verify_fibonacci(&fib_proof, &pvs).is_ok());

    let pcs_obj =
        PcsOpeningObject::from_chip_proof(&fib_proof, shape, &pvs, None).expect("build pcs obj");
    let verify_stmt = pcs_obj.to_verify_stark_tx(external_fib_air_id(), Vec::new());

    let sender = WalletKeyPair::generate();
    let (claimed_tx, sig_env, pcs_env, poly_claim) =
        make_verify_stark_tx_and_envelopes(&sender, chain_id, 0, &pcs_obj, verify_stmt.clone());

    // Protobuf wire roundtrip preserves VerifyStark payload and claim_refs identically.
    let proto = ProtoTransaction::from(&claimed_tx);
    let roundtrip = Transaction::try_from(proto).expect("proto roundtrip");
    assert_eq!(roundtrip.tx_type, claimed_tx.tx_type);
    assert_eq!(roundtrip.claim_refs, claimed_tx.claim_refs);

    let sig_claim = derive_claim(&registry, &sig_env).expect("derive sig claim");
    let derived_poly = derive_claim(&registry, &pcs_env).expect("derive poly claim");
    assert_eq!(derived_poly, poly_claim);

    let items = vec![
        PoolItem {
            envelope: sig_env,
            claim: sig_claim,
        },
        PoolItem {
            envelope: pcs_env,
            claim: derived_poly,
        },
    ];
    let ctx = TickCtx::from_seed(domain, Zeroizing::new([0x51u8; 32])).expect("tick ctx");
    let frame = backend.prove_tick(&ctx, &items).expect("prove tick");
    assert!(frame.proof.len() <= params.max_proof_bytes);

    let block = build_block(chain_id, vec![claimed_tx.clone()], frame.clone());
    let accounts = AccountState::new();
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&accounts),
        &air_registry,
        &block,
        &backend,
    )
    .expect("block with external FibonacciAir VerifyStark must pass");

    // Negative 1: unregistered AirRegistry rejects external FibonacciAir.
    let builtin_only = AirRegistry::with_builtins();
    let err = check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&accounts),
        &builtin_only,
        &block,
        &backend,
    )
    .expect_err("unregistered external AIR must be rejected");
    assert!(err.contains("not registered"));

    // Negative 2: tampered opened value fails verify_algebra or Claim::Poly binding.
    let mut forged_stmt = verify_stmt.clone();
    forged_stmt.opened_values.trace_local[0][0] =
        (forged_stmt.opened_values.trace_local[0][0] + 1) % GOLDILOCKS_MODULUS;
    let proven: BTreeSet<Hash32> = frame.claims.iter().map(|c| c.digest(domain)).collect();
    assert!(air_registry
        .verify_stark_tx(domain, &forged_stmt, &claimed_tx.claim_refs, &proven)
        .is_err());

    // Negative 3: tampered public_values changes re-derived zeta -> fails algebra & Poly.point check.
    let mut bad_pv_stmt = verify_stmt.clone();
    bad_pv_stmt.public_values[2] = (bad_pv_stmt.public_values[2] + 1) % GOLDILOCKS_MODULUS;
    assert!(air_registry
        .verify_stark_tx(domain, &bad_pv_stmt, &claimed_tx.claim_refs, &proven)
        .is_err());

    // Negative 4: missing Poly claim reference in tx.claim_refs is rejected.
    assert_eq!(
        air_registry.verify_stark_tx(domain, &verify_stmt, &[], &proven),
        Err(AirVerifyError::MissingPolyClaimRef)
    );

    // Negative 5: Poly claim absent from ClaimFrame proven set is rejected.
    assert_eq!(
        air_registry.verify_stark_tx(
            domain,
            &verify_stmt,
            &claimed_tx.claim_refs,
            &BTreeSet::new()
        ),
        Err(AirVerifyError::UnprovenPolyClaim)
    );

    // Negative 6: non-canonical Goldilocks limb in VerifyStark is rejected.
    let mut non_canon = verify_stmt;
    non_canon.opened_values.trace_local[0][0] = GOLDILOCKS_MODULUS;
    assert_eq!(
        air_registry.verify_stark_tx(domain, &non_canon, &claimed_tx.claim_refs, &proven),
        Err(AirVerifyError::InvalidFieldElement)
    );

    // Negative 7: VerifyStark is refused when AggMode::Off.
    let off_params = AggParams {
        mode: AggMode::Off,
        ..params
    };
    assert!(check_block_with_backend_and_airs(
        &off_params,
        &registry,
        Some(&accounts),
        &air_registry,
        &block,
        &backend,
    )
    .is_err());
}

#[test]
fn bud_air_split_stark_verifies_end_to_end_via_builtin_air_registry() {
    let chain_id = Network::Testnet.chain_id().value();
    let domain = domain_of(chain_id);
    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let backend = stark_backend(&params);
    let air_registry = AirRegistry::with_builtins();

    let (pcs_obj, verify_stmt, envelope, program, expected_inputs) =
        prove_single_bud_domain_proof(chain_id);
    assert!(Plonky3Adapter::verify(&envelope, &expected_inputs, &program).is_ok());

    let sender = WalletKeyPair::generate();
    let (claimed_tx, sig_env, pcs_env, poly_claim) =
        make_verify_stark_tx_and_envelopes(&sender, chain_id, 0, &pcs_obj, verify_stmt);

    let sig_claim = derive_claim(&registry, &sig_env).expect("derive sig claim");
    let derived_poly = derive_claim(&registry, &pcs_env).expect("derive BudAir poly claim");
    assert_eq!(derived_poly, poly_claim);

    let items = vec![
        PoolItem {
            envelope: sig_env,
            claim: sig_claim,
        },
        PoolItem {
            envelope: pcs_env,
            claim: derived_poly,
        },
    ];
    let ctx = TickCtx::from_seed(domain, Zeroizing::new([0x52u8; 32])).expect("tick ctx");
    let frame = backend.prove_tick(&ctx, &items).expect("prove tick");

    let block = build_block(chain_id, vec![claimed_tx], frame);
    let accounts = AccountState::new();
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&accounts),
        &air_registry,
        &block,
        &backend,
    )
    .expect("block with built-in BudAir VerifyStark must pass");
}

#[test]
fn differential_two_stage_matches_full_verifier_across_10000_cases() {
    let (base_fib, base_pvs, base_shape) = prove_fibonacci(4, 1, 1).expect("prove fib");
    let base_pcs =
        PcsOpeningObject::from_chip_proof(&base_fib, base_shape, &base_pvs, None).expect("pcs");
    let mut air_registry = AirRegistry::with_builtins();
    air_registry
        .register(Arc::new(ExternalFibAirEvaluator))
        .expect("register fib");

    let (alt_fib, alt_pvs, alt_shape) = prove_fibonacci(4, 7, 13).expect("prove fib alt");
    let alt_pcs =
        PcsOpeningObject::from_chip_proof(&alt_fib, alt_shape, &alt_pvs, None).expect("pcs alt");

    let (bud_pcs, bud_stmt, bud_env, bud_prog, bud_pi) =
        prove_single_bud_domain_proof(Network::Testnet.chain_id().value());
    let (bud_chip, _, _, _) =
        extract_bud_envelope_pcs(&bud_env, &bud_prog, &bud_pi).expect("extract bud");

    let mut state: u64 = 0x5EED_FACE_CAFE_BABEu64;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        state
    };

    let mut accepts = 0usize;
    let mut rejects = 0usize;
    let total_cases = 10_000usize;

    for case in 0..total_cases {
        if case % 500 == 0 {
            let mut pcs = bud_pcs.clone();
            let mut stmt = bud_stmt.clone();
            let mut full_env = bud_env.clone();
            let mut full_pi = bud_pi.clone();
            let mut chip = bud_chip.clone();

            match (case / 500) % 5 {
                0 => {}
                1 => {
                    pcs.commitments.trace[0] ^= 0x01;
                    stmt.commitments.trace[0] ^= 0x01;
                    chip.commitments.trace = chip_commitment_from_bytes(pcs.commitments.trace);
                    full_env.proof_bytes = postcard::to_allocvec(&chip).expect("ser");
                }
                2 => {
                    pcs.opened_values.trace_local[0][0] =
                        (pcs.opened_values.trace_local[0][0] + 1) % GOLDILOCKS_MODULUS;
                    stmt.opened_values.trace_local[0][0] = pcs.opened_values.trace_local[0][0];
                    chip.opened_values = pcs.opened_values.to_chip().expect("ov");
                    full_env.proof_bytes = postcard::to_allocvec(&chip).expect("ser");
                }
                3 => {
                    full_pi.gas_used = full_pi.gas_used.wrapping_add(1);
                    let pvs = bud_proof::plonky3_prover::bud_air_public_values_u64(&full_pi);
                    pcs.public_values.clone_from(&pvs);
                    stmt.public_values = pvs;
                    let aux = BudAirAuxData {
                        program: bud_prog.clone(),
                        expected_inputs: full_pi.clone(),
                    };
                    stmt.air_aux_data =
                        bincode::DefaultOptions::new().serialize(&aux).expect("aux");
                }
                _ => {
                    if let Some(first) = chip.opening_proof.commit_phase_commits.first_mut() {
                        let mut root = chip_commitment_to_bytes(first).expect("cap 1");
                        root[0] ^= 0x80;
                        *first = chip_commitment_from_bytes(root);
                        pcs.opening_proof_bytes =
                            postcard::to_allocvec(&chip.opening_proof).expect("ser");
                        full_env.proof_bytes = postcard::to_allocvec(&chip).expect("ser");
                    }
                }
            }

            let full_ok = Plonky3Adapter::verify(&full_env, &full_pi, &bud_prog).is_ok();
            let two_stage_ok = match verify_pcs_opening(&pcs) {
                Ok(Claim::Poly {
                    poly_hash,
                    point,
                    value,
                }) => {
                    let mut proven = BTreeSet::new();
                    let d = Claim::Poly {
                        poly_hash,
                        point,
                        value,
                    }
                    .digest(1);
                    proven.insert(d);
                    air_registry
                        .verify_stark_tx(1, &stmt, &[d], &proven)
                        .is_ok()
                }
                _ => false,
            };
            assert_eq!(
                full_ok, two_stage_ok,
                "BudAir differential mismatch at case {case}"
            );
            if full_ok {
                accepts += 1;
            } else {
                rejects += 1;
            }
            continue;
        }

        let use_alt = (case & 1) == 1;
        let mut proof = if use_alt {
            alt_fib.clone()
        } else {
            base_fib.clone()
        };
        let mut pvs = if use_alt {
            alt_pvs.to_vec()
        } else {
            base_pvs.to_vec()
        };
        let mut pcs = if use_alt {
            alt_pcs.clone()
        } else {
            base_pcs.clone()
        };

        let mode = case % 11;
        match mode {
            0 => {}
            1 => {
                let bi = usize::try_from(next_u64() % 32).unwrap_or(0);
                let mask = u8::try_from((next_u64() % 255) + 1).unwrap_or(1);
                pcs.commitments.trace[bi] ^= mask;
                proof.commitments.trace = chip_commitment_from_bytes(pcs.commitments.trace);
            }
            2 => {
                let bi = usize::try_from(next_u64() % 32).unwrap_or(0);
                let mask = u8::try_from((next_u64() % 255) + 1).unwrap_or(1);
                pcs.commitments.quotient_chunks[bi] ^= mask;
                proof.commitments.quotient_chunks =
                    chip_commitment_from_bytes(pcs.commitments.quotient_chunks);
            }
            3 => {
                let col = usize::try_from(next_u64() % 2).unwrap_or(0);
                let limb = usize::try_from(next_u64() % 3).unwrap_or(0);
                let delta = (next_u64() % 1_000_000) + 1;
                pcs.opened_values.trace_local[col][limb] =
                    (pcs.opened_values.trace_local[col][limb] + delta) % GOLDILOCKS_MODULUS;
                proof.opened_values = pcs.opened_values.to_chip().expect("ov");
            }
            4 => {
                let col = usize::try_from(next_u64() % 2).unwrap_or(0);
                let limb = usize::try_from(next_u64() % 3).unwrap_or(0);
                let delta = (next_u64() % 1_000_000) + 1;
                if let Some(tn) = pcs.opened_values.trace_next.as_mut() {
                    tn[col][limb] = (tn[col][limb] + delta) % GOLDILOCKS_MODULUS;
                }
                proof.opened_values = pcs.opened_values.to_chip().expect("ov");
            }
            5 => {
                let q =
                    usize::try_from(next_u64() % (pcs.opened_values.quotient_chunks.len() as u64))
                        .unwrap_or(0);
                let e = usize::try_from(next_u64() % 3).unwrap_or(0);
                let limb = usize::try_from(next_u64() % 3).unwrap_or(0);
                pcs.opened_values.quotient_chunks[q][e][limb] =
                    (pcs.opened_values.quotient_chunks[q][e][limb] + 1) % GOLDILOCKS_MODULUS;
                proof.opened_values = pcs.opened_values.to_chip().expect("ov");
            }
            6 => {
                let pi = usize::try_from(next_u64() % 3).unwrap_or(0);
                let delta = (next_u64() % 1000) + 1;
                pvs[pi] = (pvs[pi] + delta) % GOLDILOCKS_MODULUS;
                pcs.public_values.clone_from(&pvs);
            }
            7 => {
                let bad_deg: u8 = match next_u64() % 4 {
                    0 => 0,
                    1 => 5,
                    2 => 27,
                    _ => 255,
                };
                pcs.degree_bits = bad_deg;
                proof.degree_bits = usize::from(bad_deg);
            }
            8 => {
                pcs.opened_values.trace_next = None;
                proof.opened_values.trace_next = None;
            }
            9 => {
                pcs.opened_values.trace_local.pop();
                proof.opened_values.trace_local.pop();
            }
            _ => {
                if let Some(first) = proof.opening_proof.commit_phase_commits.first_mut() {
                    let mut root = chip_commitment_to_bytes(first).expect("cap 1");
                    let bi = usize::try_from(next_u64() % 32).unwrap_or(0);
                    root[bi] ^= 0x01;
                    *first = chip_commitment_from_bytes(root);
                    pcs.opening_proof_bytes =
                        postcard::to_allocvec(&proof.opening_proof).expect("ser");
                }
            }
        }

        let full_ok = verify_fibonacci(&proof, &pvs).is_ok();
        let stmt = pcs.to_verify_stark_tx(external_fib_air_id(), Vec::new());
        let two_stage_ok = match verify_pcs_opening(&pcs) {
            Ok(Claim::Poly {
                poly_hash,
                point,
                value,
            }) => {
                let mut proven = BTreeSet::new();
                let d = Claim::Poly {
                    poly_hash,
                    point,
                    value,
                }
                .digest(1);
                proven.insert(d);
                air_registry
                    .verify_stark_tx(1, &stmt, &[d], &proven)
                    .is_ok()
            }
            _ => false,
        };
        assert_eq!(
            full_ok, two_stage_ok,
            "FibonacciAir differential mismatch at case {case} (mode={mode})"
        );
        if full_ok {
            accepts += 1;
        } else {
            rejects += 1;
        }
    }

    assert_eq!(accepts + rejects, total_cases);
    assert!(accepts >= 800, "expected >= 800 valid cases, got {accepts}");
    assert!(
        rejects >= 8_500,
        "expected >= 8500 rejected cases, got {rejects}"
    );
}

#[test]
fn phase5_domain_tags_are_distinct_and_prefix_free() {
    let tags: &[&[u8]] = &[
        TAG_CLAIM,
        TAG_CLAIM_ROOT,
        TAG_AGG_TICK,
        TAG_AGG_MERGE,
        TAG_OBJECT,
        TAG_FRAME,
        TAG_PCS_POLY,
        TAG_PCS_EVAL,
        TAG_AIR_ID,
        b"BDLM_AUTH_OK_V1",
        b"BDLM_AUTH_PROG_V1",
        b"BDLM_DOM_TRANS_IN_V1",
        b"BDLM_DOM_TRANS_OUT_V1",
        b"BDLM_AGG_PARAMS_V1",
        b"BDLM_AGG_SEGMENT_AUTH_V1",
    ];
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_ne!(a, b, "duplicate tag at {i} and {j}");
            assert!(
                !b.starts_with(a),
                "tag {:?} is a prefix of {:?}",
                std::str::from_utf8(a),
                std::str::from_utf8(b)
            );
        }
    }
    assert_ne!(bud_air_id(), agg_fold_air_id());
    assert_ne!(bud_air_id(), external_fib_air_id());
    assert_ne!(agg_fold_air_id(), external_fib_air_id());
}

#[test]
fn pcs_object_decode_refuses_bad_magic_and_trailing_bytes() {
    assert_eq!(PcsOpeningObject::decode(&[]), Err(ObjectError::Invalid));
    assert_eq!(
        PcsOpeningObject::decode(b"BAD!1abc"),
        Err(ObjectError::Invalid)
    );
    assert_eq!(
        PcsOpeningObject::decode(b"BDP5\x02abc"),
        Err(ObjectError::Invalid)
    );
    let bad_ext = Ext::new([GOLDILOCKS_MODULUS, 0, 0]);
    assert!(bad_ext.is_err());
}

#[test]
fn load_test_4_aggregators_1_producer_1024_claims_in_single_block() {
    let chain_id = Network::Testnet.chain_id().value();
    let domain = domain_of(chain_id);
    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let backend = stark_backend(&params);

    let sender = WalletKeyPair::generate();
    let mut all_txs = Vec::with_capacity(1024);
    let mut agg_frames = Vec::with_capacity(4);

    for agg_idx in 0u8..4 {
        let mut items = Vec::with_capacity(256);
        for local_i in 0u64..256 {
            let nonce = u64::from(agg_idx) * 256 + local_i;
            let mut raw = Transaction::new(
                sender.address(),
                Address::from([agg_idx.wrapping_add(1); 32]),
                1,
                Vec::new(),
            );
            raw.chain_id = chain_id;
            raw.nonce = nonce;
            raw.fee = 10_000;
            raw.sign_v5(&sender);
            let (claimed, env) = claim_signature(&raw).expect("claim sig");
            let claim = derive_claim(&registry, &env).expect("derive sig");
            all_txs.push(claimed);
            items.push(PoolItem {
                envelope: env,
                claim,
            });
        }
        let ctx = TickCtx::from_seed(domain, Zeroizing::new([0x60 + agg_idx; 32])).expect("ctx");
        let tick = backend
            .prove_tick(&ctx, &items)
            .expect("prove 256-claim tick");
        agg_frames.push(tick);
    }

    let left_proof = backend
        .prove_merge(&agg_frames[0], &agg_frames[1])
        .expect("merge 0+1");
    let left =
        ClaimFrame::combine(&agg_frames[0], &agg_frames[1], left_proof).expect("combine 0+1");
    let right_proof = backend
        .prove_merge(&agg_frames[2], &agg_frames[3])
        .expect("merge 2+3");
    let right =
        ClaimFrame::combine(&agg_frames[2], &agg_frames[3], right_proof).expect("combine 2+3");
    let master_proof = backend.prove_merge(&left, &right).expect("merge root");
    let master = ClaimFrame::combine(&left, &right, master_proof).expect("combine root");

    assert_eq!(master.claims.len(), 1024);
    assert_eq!(master.segments.len(), 4);
    assert!(
        master.proof.len() <= params.max_proof_bytes,
        "MasterProof {} B exceeds {} B cap",
        master.proof.len(),
        params.max_proof_bytes
    );

    let block = build_block(chain_id, all_txs, master);
    let accounts = AccountState::new();
    let air_registry = AirRegistry::with_builtins();
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&accounts),
        &air_registry,
        &block,
        &backend,
    )
    .expect("1,024-claim 4-aggregator block must verify cleanly");
}

#[test]
fn phase5_security_hardening_rejects_deflate_malleability_mainnet_mempool_and_oversized_bud_envelope(
) {
    let chain_id = Network::Testnet.chain_id().value();
    let (proof, pvs, shape) = prove_fibonacci(6, 1, 1).expect("prove fib");
    let pcs_obj = PcsOpeningObject::from_chip_proof(&proof, shape, &pvs, None).expect("pcs obj");
    let encoded = pcs_obj.encode().expect("encode BDP5");

    // 1. Trailing bytes appended after the deflate EOF stream must be rejected
    //    so distinct ObjectIds cannot alias the same PcsOpeningObject.
    let mut malleable = encoded;
    malleable.push(0xAA);
    assert_eq!(
        PcsOpeningObject::decode(&malleable),
        Err(ObjectError::Invalid)
    );

    // 2. Inconsistent preprocessed_width > 0 without preprocessed_commit must be rejected.
    let mut inconsistent = pcs_obj.clone();
    inconsistent.preprocessed_width = 4;
    inconsistent.preprocessed_commit = None;
    let inconsistent_bytes = inconsistent.encode().expect("encode inconsistent");
    assert_eq!(
        PcsOpeningObject::decode(&inconsistent_bytes),
        Err(ObjectError::Invalid)
    );

    // 3. TransactionType::VerifyStark with empty claim_refs must be rejected by
    //    check_pool_transaction on BOTH Mainnet (AggMode::Off) and Testnet (AggMode::On).
    let stmt = pcs_obj.to_verify_stark_tx(external_fib_air_id(), Vec::new());
    let mut raw_tx = Transaction::new(
        Address::from([0x11; 32]),
        Address::from([0x11; 32]),
        0,
        Vec::new(),
    );
    raw_tx.chain_id = chain_id;
    raw_tx.tx_type = TransactionType::VerifyStark(Box::new(stmt));
    assert!(check_pool_transaction(
        &AggParams {
            mode: AggMode::Off,
            ..phase5_params()
        },
        &raw_tx
    )
    .is_err());
    assert!(check_pool_transaction(&phase5_params(), &raw_tx).is_err());

    // 4. Oversized ProofEnvelope (> MAX_ENVELOPE_PROOF_BYTES) and oversized BudVM
    //    program (> 65_536 words) must be rejected without truncation or OOM.
    let dummy_inputs = bud_proof::adapter::ExecutionPublicInputs {
        chain_id,
        program_hash: [0u8; 32],
        initial_state_root: [0u8; 32],
        final_state_root: [0u8; 32],
        sender: 0,
        nonce: 0,
        block_height: 1,
        gas_limit: 1000,
        gas_used: 10,
        exit_code: 0,
        trace_len: 4,
        event_digest: [0u8; 32],
        state_writes_digest: [0u8; 32],
    };
    let oversized_env = bud_proof::adapter::ProofEnvelope {
        proof_format_version: bud_proof::adapter::PROOF_FORMAT_VERSION,
        backend: String::from("plonky3"),
        p3_version: String::from("0.8.0"),
        fri_params_id: String::from("budlum-goldilocks-keccak-v1"),
        public_inputs_hash: dummy_inputs.hash(),
        proof_bytes: vec![0u8; bud_proof::adapter::MAX_ENVELOPE_PROOF_BYTES + 1],
        degree_bits: 4,
    };
    assert!(extract_bud_envelope_pcs(&oversized_env, &[0u64], &dummy_inputs).is_err());

    let huge_program = vec![0u64; 65_537];
    let tiny_env = bud_proof::adapter::ProofEnvelope {
        proof_bytes: vec![0u8; 16],
        ..oversized_env
    };
    assert!(extract_bud_envelope_pcs(&tiny_env, &huge_program, &dummy_inputs).is_err());
}
