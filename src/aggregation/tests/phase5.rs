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
use crate::aggregation::domain_finality::{
    compile_domain_transition, derive_transition_state_root, prove_domain_transition,
};
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
        state_root: derive_transition_state_root(
            consensus_domain.id,
            consensus_domain.domain_chain_id,
            10,
            11,
            &prev_root,
            &batch_digest,
        ),
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

fn bonded_accounts_for_frame(chain_id: u64, frame: &ClaimFrame) -> AccountState {
    let mut accounts = AccountState::new();
    let floor = accounts.validator_stake_floor(chain_id);
    for seg in &frame.segments {
        accounts.add_validator_with_floor(seg.aggregator, floor, floor);
    }
    accounts
}

#[test]
fn external_non_budzkvm_air_verifies_end_to_end_via_claim_poly_and_verify_stark() {
    let chain_id = Network::Devnet.chain_id().value();
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
    let accounts = bonded_accounts_for_frame(chain_id, &frame);
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
    let chain_id = Network::Devnet.chain_id().value();
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

    let accounts = bonded_accounts_for_frame(chain_id, &frame);
    let block = build_block(chain_id, vec![claimed_tx], frame);
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
        b"BDLM_DOM_TRANS_STEP_V1",
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
    let chain_id = Network::Devnet.chain_id().value();
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

    let accounts = bonded_accounts_for_frame(chain_id, &master);
    let block = build_block(chain_id, all_txs, master);
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

#[test]
fn blocks_testnet_refuses_unbonded_aggregators_and_slashes_unbacked_or_conflicting_segments() {
    use crate::aggregation::chain::validate_params;
    use crate::aggregation::fraud::{
        is_authorized_segment_aggregator, required_challenger_bond, sign_backing_response,
        slash_conflicting_segment_attestation, slash_unbacked_segment, verify_segment_backing,
        ChallengeOutcome, ContradictingSegmentEvidence, RespondChallengeRequest,
        SegmentChallengeBook, SegmentChallengeRequest, SegmentFraudReason,
        UnbackedSegmentChallenge, SEGMENT_CHALLENGE_WINDOW_BLOCKS,
    };
    use crate::aggregation::merkle::prove_claim_inclusion;

    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let backend = stark_backend(&params);
    let air_registry = AirRegistry::with_builtins();

    // 1. Mainnet (45260) and public Testnet (45261) reject AggMode::On in both
    //    startup validation and consensus block checks.
    let mainnet_id = Network::Mainnet.chain_id().value();
    let testnet_id = Network::Testnet.chain_id().value();
    let devnet_id = Network::Devnet.chain_id().value();
    assert!(validate_params(&params, mainnet_id).is_err());
    assert!(validate_params(&params, testnet_id).is_err());
    assert!(validate_params(&params, devnet_id).is_ok());
    assert!(validate_params(
        &AggParams {
            mode: AggMode::Shadow,
            ..params
        },
        testnet_id
    )
    .is_ok());

    let empty_testnet_block = Block::new_with_chain_id(1, "0".repeat(64), Vec::new(), testnet_id);
    assert!(check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&AccountState::new()),
        &air_registry,
        &empty_testnet_block,
        &backend,
    )
    .is_err());

    // 2. Build a real StarkBackend frame on Devnet: unbonded, missing-state,
    //    under-floor, jailed, and slashed aggregators MUST all be refused.
    let domain = domain_of(devnet_id);
    let sender = WalletKeyPair::generate();
    let mut raw = Transaction::new(sender.address(), Address::from([0x33; 32]), 10, Vec::new());
    raw.chain_id = devnet_id;
    raw.nonce = 0;
    raw.fee = 20_000;
    raw.sign_v5(&sender);
    let (claimed, sig_env) = claim_signature(&raw).expect("claim signature");
    let sig_claim = derive_claim(&registry, &sig_env).expect("derive claim");

    let agg_seed = Zeroizing::new([0x91u8; 32]);
    let ctx = TickCtx::from_seed(domain, agg_seed.clone()).expect("agg ctx");
    let frame = backend
        .prove_tick(
            &ctx,
            &[PoolItem {
                envelope: sig_env.clone(),
                claim: sig_claim,
            }],
        )
        .expect("honest tick");
    let block = build_block(devnet_id, vec![claimed.clone()], frame.clone());

    // Missing AccountState -> rejected.
    assert!(check_block_with_backend_and_airs(
        &params,
        &registry,
        None,
        &air_registry,
        &block,
        &backend,
    )
    .is_err());
    // Unbonded fresh ML-DSA-87 seed -> rejected (`UnauthorizedSegmentAggregator`).
    let unbonded_err = check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&AccountState::new()),
        &air_registry,
        &block,
        &backend,
    )
    .expect_err("unbonded segment aggregator must be rejected");
    assert!(
        unbonded_err.contains("unbonded or unauthorized"),
        "{unbonded_err}"
    );

    // Under-floor bond -> rejected.
    let mut state = AccountState::new();
    let floor = state.validator_stake_floor(devnet_id);
    state.add_validator_with_floor(ctx.aggregator, floor - 1, floor);
    assert!(!is_authorized_segment_aggregator(
        &state,
        devnet_id,
        &ctx.aggregator
    ));
    assert!(check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&state),
        &air_registry,
        &block,
        &backend,
    )
    .is_err());

    // Full floor bond -> accepted, and honest backing cannot be falsely slashed.
    state.add_validator_with_floor(ctx.aggregator, floor, floor);
    assert!(is_authorized_segment_aggregator(
        &state,
        devnet_id,
        &ctx.aggregator
    ));
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&state),
        &air_registry,
        &block,
        &backend,
    )
    .expect("bonded honest validator passes consensus frame check");
    assert_eq!(
        verify_segment_backing(&registry, domain, &frame, 0, std::slice::from_ref(&sig_env)),
        Ok(Ok(()))
    );
    let watcher = Address::from([0x77; 32]);
    let honest_seg = frame.segments.first().expect("segment 0");
    let honest_resp_sig = sign_backing_response(
        &agg_seed,
        domain,
        honest_seg,
        std::slice::from_ref(&sig_env),
    )
    .expect("sign honest backing response");
    assert!(slash_unbacked_segment(
        &mut state,
        &registry,
        &UnbackedSegmentChallenge {
            chain_id: devnet_id,
            domain,
            frame: &frame,
            segment_index: 0,
            backing_envelopes: std::slice::from_ref(&sig_env),
            aggregator_response_sig: &honest_resp_sig,
            whistleblower: watcher,
        },
    )
    .is_err());
    // Regression: a griefing challenger CANNOT frame an honest aggregator
    // by passing `&[]` with a stranger's signature or reusing the honest signature.
    let attacker_seed = Zeroizing::new([0xA8u8; 32]);
    let forged_empty_sig =
        sign_backing_response(&attacker_seed, domain, honest_seg, &[]).expect("attacker sig");
    assert!(slash_unbacked_segment(
        &mut state,
        &registry,
        &UnbackedSegmentChallenge {
            chain_id: devnet_id,
            domain,
            frame: &frame,
            segment_index: 0,
            backing_envelopes: &[],
            aggregator_response_sig: &forged_empty_sig,
            whistleblower: watcher,
        },
    )
    .is_err());
    assert!(slash_unbacked_segment(
        &mut state,
        &registry,
        &UnbackedSegmentChallenge {
            chain_id: devnet_id,
            domain,
            frame: &frame,
            segment_index: 0,
            backing_envelopes: &[],
            aggregator_response_sig: &honest_resp_sig,
            whistleblower: watcher,
        },
    )
    .is_err());

    // 3. Byzantine bonded aggregator signs an invalid backing response for a
    //    forged `Claim::Sig` AND holds queued unbonding stake: 100% of
    //    both active stake and queued unbonding is swept, validator is jailed,
    //    and `total_bud_committed + burned_total` is conserved to the exact atom.
    state
        .unbonding_queue
        .push(crate::core::account::UnbondingEntry {
            address: ctx.aggregator,
            amount: 50_000,
            release_epoch: 999,
        });
    let accounting_before = state
        .total_bud_committed()
        .saturating_add(u128::from(state.burned_total));

    let victim = Address::from([0xDE; 32]);
    let forged_claim = Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: victim,
        msg_hash: [0xEE; 32],
    };
    let forged_frame = ClaimFrame::tick(domain, &agg_seed, vec![forged_claim.clone()], Vec::new())
        .expect("attested tick");
    let forged_seg = forged_frame.segments.first().expect("forged seg");
    let bad_resp_sig =
        sign_backing_response(&agg_seed, domain, forged_seg, &[]).expect("agg empty response sig");
    // Self-challenge is refused.
    assert!(slash_unbacked_segment(
        &mut state,
        &registry,
        &UnbackedSegmentChallenge {
            chain_id: devnet_id,
            domain,
            frame: &forged_frame,
            segment_index: 0,
            backing_envelopes: &[],
            aggregator_response_sig: &bad_resp_sig,
            whistleblower: ctx.aggregator,
        },
    )
    .is_err());
    // Wrong envelope (backing a different signer) is caught as DerivedClaimMismatch.
    assert_eq!(
        verify_segment_backing(
            &registry,
            domain,
            &forged_frame,
            0,
            std::slice::from_ref(&sig_env)
        ),
        Ok(Err((0, SegmentFraudReason::DerivedClaimMismatch)))
    );
    let report = slash_unbacked_segment(
        &mut state,
        &registry,
        &UnbackedSegmentChallenge {
            chain_id: devnet_id,
            domain,
            frame: &forged_frame,
            segment_index: 0,
            backing_envelopes: &[],
            aggregator_response_sig: &bad_resp_sig,
            whistleblower: watcher,
        },
    )
    .expect("unbacked attested segment slashes Byzantine aggregator");
    let expected_total_slashed = floor + 50_000;
    assert_eq!(report.aggregator, ctx.aggregator);
    assert_eq!(report.reason, SegmentFraudReason::MissingBackingEnvelope);
    assert_eq!(report.slashed_atoms, expected_total_slashed);
    assert_eq!(
        report.whistleblower_reward_atoms + report.burned_atoms,
        report.slashed_atoms
    );
    assert_eq!(
        state.spendable_balance(&watcher),
        expected_total_slashed / 10
    );
    assert!(
        state.unbonding_queue.is_empty(),
        "queued unbonding atoms must be confiscated on segment fraud slash"
    );
    assert!(state.get_validator(&ctx.aggregator).unwrap().jailed);
    let accounting_after = state
        .total_bud_committed()
        .saturating_add(u128::from(state.burned_total));
    assert_eq!(
        accounting_after, accounting_before,
        "total_bud_committed + burned_total must stay bit-for-bit invariant"
    );
    assert!(!is_authorized_segment_aggregator(
        &state,
        devnet_id,
        &ctx.aggregator
    ));
    // Subsequent blocks attested by the slashed aggregator are immediately rejected.
    assert!(check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&state),
        &air_registry,
        &block,
        &backend,
    )
    .is_err());

    // 4. disjoint honest back-to-back single-claim ticks with equal `count`
    //    are NEVER slashed, while contradictory `Claim::Prog` outputs for the
    //    exact same `(program_hash, input_hash)` slash 100% via Merkle opening.
    let eq_seed = Zeroizing::new([0x92u8; 32]);
    let eq_ctx = TickCtx::from_seed(domain, eq_seed.clone()).expect("eq ctx");
    state.add_validator_with_floor(eq_ctx.aggregator, floor, floor);
    let disjoint_a = Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: victim,
        msg_hash: [0x01; 32],
    };
    let disjoint_b = Claim::Sig {
        scheme: SchemeId::ML_DSA_87,
        signer: victim,
        msg_hash: [0x02; 32],
    };
    let d1 = ClaimFrame::tick(domain, &eq_seed, vec![disjoint_a.clone()], Vec::new()).expect("d1");
    let d2 = ClaimFrame::tick(domain, &eq_seed, vec![disjoint_b.clone()], Vec::new()).expect("d2");
    let dp1 = prove_claim_inclusion(&[disjoint_a.digest(domain)], 0).unwrap();
    let dp2 = prove_claim_inclusion(&[disjoint_b.digest(domain)], 0).unwrap();
    assert!(
        slash_conflicting_segment_attestation(
            &mut state,
            &registry,
            devnet_id,
            domain,
            &ContradictingSegmentEvidence {
                first_segment: d1.segments.first().unwrap(),
                first_claim: &disjoint_a,
                first_proof: &dp1,
                second_segment: d2.segments.first().unwrap(),
                second_claim: &disjoint_b,
                second_proof: &dp2,
            },
            watcher,
        )
        .is_err(),
        "honest disjoint ticks with identical count must NEVER be slashed"
    );

    let contra_a = Claim::Prog {
        program_hash: [0x55; 32],
        input_hash: [0x66; 32],
        output_hash: [0x01; 32],
    };
    let contra_b = Claim::Prog {
        program_hash: [0x55; 32],
        input_hash: [0x66; 32],
        output_hash: [0x02; 32],
    };
    let f1 = ClaimFrame::tick(domain, &eq_seed, vec![contra_a.clone()], Vec::new()).expect("f1");
    let f2 = ClaimFrame::tick(domain, &eq_seed, vec![contra_b.clone()], Vec::new()).expect("f2");
    let p1 = prove_claim_inclusion(&[contra_a.digest(domain)], 0).unwrap();
    let p2 = prove_claim_inclusion(&[contra_b.digest(domain)], 0).unwrap();
    // Identical claim pair is refused.
    assert!(slash_conflicting_segment_attestation(
        &mut state,
        &registry,
        devnet_id,
        domain,
        &ContradictingSegmentEvidence {
            first_segment: f1.segments.first().unwrap(),
            first_claim: &contra_a,
            first_proof: &p1,
            second_segment: f1.segments.first().unwrap(),
            second_claim: &contra_a,
            second_proof: &p1,
        },
        watcher,
    )
    .is_err());
    let eq_report = slash_conflicting_segment_attestation(
        &mut state,
        &registry,
        devnet_id,
        domain,
        &ContradictingSegmentEvidence {
            first_segment: f1.segments.first().unwrap(),
            first_claim: &contra_a,
            first_proof: &p1,
            second_segment: f2.segments.first().unwrap(),
            second_claim: &contra_b,
            second_proof: &p2,
        },
        watcher,
    )
    .expect("contradicting Claim::Prog segment attestations slash aggregator");
    assert_eq!(
        eq_report.reason,
        SegmentFraudReason::ConflictingSegmentAttestation
    );
    assert_eq!(eq_report.slashed_atoms, floor);
    assert!(!is_authorized_segment_aggregator(
        &state,
        devnet_id,
        &eq_ctx.aggregator
    ));

    // 5. Bonded `SegmentChallengeBook`: honest defense burns/rewards
    //    frivolous challenger bond; silent timeout slashes Byzantine aggregator.
    let def_seed = Zeroizing::new([0x93u8; 32]);
    let def_ctx = TickCtx::from_seed(domain, def_seed.clone()).expect("def ctx");
    state.add_validator_with_floor(def_ctx.aggregator, floor, floor);
    let def_frame = backend
        .prove_tick(
            &def_ctx,
            &[PoolItem {
                envelope: sig_env.clone(),
                claim: derive_claim(&registry, &sig_env).unwrap(),
            }],
        )
        .expect("def tick");
    let griefer = Address::from([0x88; 32]);
    let bond = required_challenger_bond(&state, devnet_id, &def_ctx.aggregator);
    state.add_balance(&griefer, bond * 2);
    let mut book = SegmentChallengeBook::new();
    let total_pre = state
        .total_bud_committed()
        .saturating_add(u128::from(state.burned_total));
    let cid = book
        .open_challenge(
            &mut state,
            &registry,
            &SegmentChallengeRequest {
                chain_id: devnet_id,
                domain,
                frame: &def_frame,
                segment_index: 0,
                challenger: griefer,
                opened_height: 100,
            },
        )
        .expect("open bonded challenge");
    // Premature timeout settlement refused.
    assert!(book
        .expire_challenge(&mut state, &cid, 100 + SEGMENT_CHALLENGE_WINDOW_BLOCKS)
        .is_err());
    let def_sig = sign_backing_response(
        &def_seed,
        domain,
        def_frame.segments.first().unwrap(),
        std::slice::from_ref(&sig_env),
    )
    .unwrap();
    let outcome = book
        .respond_challenge(
            &mut state,
            &registry,
            &RespondChallengeRequest {
                challenge_id: cid,
                current_height: 110,
                backing_envelopes: std::slice::from_ref(&sig_env),
                response_signature: &def_sig,
            },
        )
        .expect("honest defender responds in time");
    assert!(matches!(outcome, ChallengeOutcome::Defended { .. }));
    assert!(is_authorized_segment_aggregator(
        &state,
        devnet_id,
        &def_ctx.aggregator
    ));
    assert_eq!(
        state
            .total_bud_committed()
            .saturating_add(u128::from(state.burned_total)),
        total_pre
    );

    // Silent Byzantine aggregator misses challenge window -> 100% slash + bond refund.
    let silent_seed = Zeroizing::new([0x94u8; 32]);
    let silent_ctx = TickCtx::from_seed(domain, silent_seed.clone()).expect("silent ctx");
    state.add_validator_with_floor(silent_ctx.aggregator, floor, floor);
    let silent_frame =
        ClaimFrame::tick(domain, &silent_seed, vec![forged_claim], Vec::new()).unwrap();
    let total_pre_timeout = state
        .total_bud_committed()
        .saturating_add(u128::from(state.burned_total));
    let silent_cid = book
        .open_challenge(
            &mut state,
            &registry,
            &SegmentChallengeRequest {
                chain_id: devnet_id,
                domain,
                frame: &silent_frame,
                segment_index: 0,
                challenger: griefer,
                opened_height: 200,
            },
        )
        .expect("open silent challenge");
    let timeout_out = book
        .expire_challenge(
            &mut state,
            &silent_cid,
            200 + SEGMENT_CHALLENGE_WINDOW_BLOCKS + 1,
        )
        .expect("expired unbacked challenge slashes silent aggregator");
    assert!(matches!(
        timeout_out,
        ChallengeOutcome::Slashed(ref r)
            if r.reason == SegmentFraudReason::ChallengeResponseTimeout && r.slashed_atoms == floor
    ));
    assert_eq!(
        state
            .total_bud_committed()
            .saturating_add(u128::from(state.burned_total)),
        total_pre_timeout
    );
}

#[test]
fn hardens_bud_air_aux_preallocation_and_executor_verify_stark_bounds() {
    use crate::aggregation::air_registry::{
        validate_verify_stark_envelope, AirAlgebraEvaluator, BudAirEvaluator,
    };
    use crate::execution::executor::Executor;

    let (fib_proof, pvs, shape) = prove_fibonacci(4, 1, 1).expect("prove fib");
    let pcs_obj = PcsOpeningObject::from_chip_proof(&fib_proof, shape, &pvs, None).expect("pcs");

    // 1. Short `air_aux_data` carrying a varint `program.len() = u64::MAX / 2`
    //    must fail fast under the raw-length-clamped deserializer without OOM.
    let mut bomb = vec![253u8]; // bincode varint u64 tag
    bomb.extend_from_slice(&130_000u64.to_le_bytes());
    let bomb_stmt = pcs_obj.to_verify_stark_tx(bud_air_id(), bomb);
    assert_eq!(
        BudAirEvaluator.verify_algebra_statement(&bomb_stmt),
        Err(AirVerifyError::InvalidAuxData)
    );

    // 2. Empty `BudAirAuxData::program` is rejected before touching BudAir setup.
    let empty_aux = BudAirAuxData {
        program: Vec::new(),
        expected_inputs: bud_proof::adapter::ExecutionPublicInputs {
            chain_id: Network::Devnet.chain_id().value(),
            program_hash: [0u8; 32],
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 100,
            gas_used: 0,
            exit_code: 0,
            trace_len: 1,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        },
    };
    let empty_bytes = bincode::DefaultOptions::new()
        .serialize(&empty_aux)
        .expect("encode empty aux");
    let empty_stmt = pcs_obj.to_verify_stark_tx(bud_air_id(), empty_bytes);
    assert_eq!(
        BudAirEvaluator.verify_algebra_statement(&empty_stmt),
        Err(AirVerifyError::InvalidAuxData)
    );

    // 3. Direct Executor execution rejects VerifyStark on Testnet AND rejects
    //    excessive `degree_bits` / non-canonical Goldilocks elements on Devnet.
    let valid_stmt = pcs_obj.to_verify_stark_tx(external_fib_air_id(), Vec::new());
    assert!(validate_verify_stark_envelope(&valid_stmt).is_ok());

    let sender = Address::from([0x45; 32]);
    let mut state = AccountState::new();
    state.add_balance(&sender, 1_000_000);

    let mut testnet_tx = Transaction::new_with_chain_id(
        sender,
        Address::zero(),
        0,
        1_000,
        0,
        Vec::new(),
        Network::Testnet.chain_id().value(),
        TransactionType::VerifyStark(Box::new(valid_stmt.clone())),
    );
    testnet_tx.claim_refs.push([0xAA; 32]);
    assert!(Executor::apply_transaction_checked(&mut state, &testnet_tx).is_err());

    let mut bad_deg = valid_stmt.clone();
    bad_deg.degree_bits = 31;
    let mut devnet_bad_tx = Transaction::new_with_chain_id(
        sender,
        Address::zero(),
        0,
        1_000,
        0,
        Vec::new(),
        Network::Devnet.chain_id().value(),
        TransactionType::VerifyStark(Box::new(bad_deg)),
    );
    devnet_bad_tx.claim_refs.push([0xAA; 32]);
    assert!(Executor::apply_transaction_checked(&mut state, &devnet_bad_tx).is_err());

    let mut devnet_ok_tx = devnet_bad_tx;
    devnet_ok_tx.tx_type = TransactionType::VerifyStark(Box::new(valid_stmt));
    Executor::apply_transaction_checked(&mut state, &devnet_ok_tx)
        .expect("bounded Devnet VerifyStark passes executor check");
}

#[test]
fn node_claim_refs_and_program_auth_reject_uninvited_and_build_atomic_block() {
    use crate::aggregation::air_registry::external_fib_air_id;
    use crate::aggregation::chain::claim_program_auth;
    use crate::aggregation::node::{AggNode, ObjectRefusal};
    use crate::aggregation::pool::Rejection;
    use crate::aggregation::programs::hidden_multisig::{
        prove_hidden_multisig_auth, HiddenMultisigPolicy,
    };

    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let chain_id = Network::Devnet.chain_id().value();
    let domain = domain_of(chain_id);
    let agg_seed = Zeroizing::new([0xA1u8; 32]);
    let mut node =
        AggNode::new(&params, chain_id, agg_seed, &registry).expect("AggNode initializes");

    let mut state = AccountState::new();
    let floor = state.validator_stake_floor(chain_id);
    state.add_validator_with_floor(node.aggregator_address(), floor, floor);

    // 1. Standard V5 tx declaring one Phase 5 `Claim::Poly` in `tx.claim_refs`.
    let sender = WalletKeyPair::generate();
    let (fib_proof, pvs, shape) = prove_fibonacci(4, 1, 1).expect("prove fib");
    let pcs_obj = PcsOpeningObject::from_chip_proof(&fib_proof, shape, &pvs, None).expect("pcs");
    let verify_stmt = pcs_obj.to_verify_stark_tx(external_fib_air_id(), Vec::new());
    let (claimed_tx, sig_env, pcs_env, _poly_claim) =
        make_verify_stark_tx_and_envelopes(&sender, chain_id, 0, &pcs_obj, verify_stmt);

    assert!(node
        .admit(sig_env, claimed_tx.clone(), &registry)
        .expect("admit claimed VerifyStark tx"));

    // Uninvited `PcsOpening` (distinct Fibonacci instance not in `tx.claim_refs`) is refused!
    let (other_proof, other_pvs, other_shape) = prove_fibonacci(4, 2, 3).expect("prove other fib");
    let other_pcs =
        PcsOpeningObject::from_chip_proof(&other_proof, other_shape, &other_pvs, None).unwrap();
    let uninvited_env = Envelope {
        domain,
        tx_hash: claimed_tx.signing_hash(),
        kind: ObjectKind::PcsOpening,
        scheme: SchemeId(0),
        payload: other_pcs.encode().unwrap(),
    };
    assert_eq!(
        node.attach_claim_ref(uninvited_env, &registry),
        Err(ObjectRefusal::Pool(Rejection::NotTheSender)),
        "uninvited companion PcsOpening must be rejected before entering pool"
    );

    // Before `pcs_env` arrives, ticking proves only `auth_claim`; `block_input` MUST
    // withhold the transaction so block Rules 7/8 cannot fail on missing `claim_refs`.
    let _ = node.on_tick(&registry);
    assert!(
        node.block_input().is_none(),
        "partial transaction missing proven claim_refs must not enter block_input"
    );

    // Attach the authorized companion `PcsOpening`, tick, and build a valid block!
    assert!(node
        .attach_claim_ref(pcs_env, &registry)
        .expect("invited claim_ref attaches cleanly"));
    let _ = node.on_tick(&registry);
    let (frame, selected_txs) = node
        .block_input()
        .expect("full (auth_claim + claim_refs) set produces atomic block_input");
    assert_eq!(selected_txs.len(), 1);
    assert_eq!(frame.claims.len(), 2);

    let block = build_block(chain_id, selected_txs, frame);
    let backend = crate::aggregation::chain::ChainBackend::new(&params, &registry);
    let mut air_registry = AirRegistry::with_builtins();
    air_registry
        .register(std::sync::Arc::new(ExternalFibAirEvaluator))
        .unwrap();
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&state),
        &air_registry,
        &block,
        &backend,
    )
    .expect("atomic AggNode Phase 5 block passes full consensus verification");

    // 2. Phase 4 `BudZKVM` program-authorized account admission via `admit_with_auth`.
    let policy = HiddenMultisigPolicy::new(1, vec![101, 202], 777).unwrap();
    let compiled = policy.compile().expect("compile hidden multisig policy");
    let prog_sender = Address::from([0xB4; 32]);
    let mut raw_prog_tx = Transaction::new(prog_sender, Address::from([0xB5; 32]), 250, Vec::new());
    raw_prog_tx.chain_id = chain_id;
    raw_prog_tx.nonce = 0;
    raw_prog_tx.fee = 20_000;
    let tx_hash = raw_prog_tx.signing_hash();
    let (_, stark_obj) =
        prove_hidden_multisig_auth(&policy, &[0], tx_hash, domain).expect("prove hidden 1-of-2");
    let (prog_tx, prog_env) =
        claim_program_auth(&raw_prog_tx, compiled.program_hash, &stark_obj).expect("claim prog");
    assert!(node
        .admit_with_auth(prog_env, prog_tx, Some(compiled.program_hash), &registry)
        .expect("program-authorized account admits cleanly via admit_with_auth"));
}

#[test]
fn shadow_auditor_parity_and_10k_block_zero_silent_drop_campaign() {
    use crate::aggregation::shadow::ShadowAuditor;

    let registry = SchemeStatusRegistry::genesis();
    let shadow_params = AggParams {
        mode: AggMode::Shadow,
        ..AggParams::default()
    };
    let devnet_id = Network::Devnet.chain_id().value();
    let testnet_id = Network::Testnet.chain_id().value();

    let alice = WalletKeyPair::generate();
    let bob = Address::from([0xC2; 32]);

    // Valid native V5 tx on matching chain_id matches cleanly.
    let mut valid_tx = Transaction::new(alice.address(), bob, 50, Vec::new());
    valid_tx.chain_id = devnet_id;
    valid_tx.nonce = 0;
    valid_tx.fee = 5_000;
    valid_tx.sign_v5(&alice);

    // Foreign chain_id tx signed by Alice (valid raw signature over its own hash,
    // invalid for `devnet_id` block): both native + aggregation reject consistently.
    let mut foreign_tx = Transaction::new(alice.address(), bob, 50, Vec::new());
    foreign_tx.chain_id = testnet_id;
    foreign_tx.nonce = 1;
    foreign_tx.fee = 5_000;
    foreign_tx.sign_v5(&alice);

    // Corrupted signature tx: both native + aggregation reject consistently.
    let mut corrupted_tx = valid_tx.clone();
    if let Some(sig) = corrupted_tx.signature.as_mut() {
        if let Some(first) = sig.first_mut() {
            *first ^= 0xFF;
        }
    }

    // Spoofed `from` address (Alice's key & sig, foreign `from`): both reject consistently.
    let mut spoofed_from = valid_tx.clone();
    spoofed_from.from = Address::from([0xEE; 32]);

    let mut auditor = ShadowAuditor::new(registry, shadow_params);
    let probe_block = Block::new_with_chain_id(
        1,
        "0".repeat(64),
        vec![valid_tx.clone(), foreign_tx, corrupted_tx, spoofed_from],
        devnet_id,
    );
    assert!(
        auditor
            .audit_block(&probe_block)
            .expect("audit probe block"),
        "native verification and aggregation claim parity must agree on every case"
    );
    assert_eq!(auditor.report().txs_checked, 4);
    assert_eq!(auditor.report().matches, 4);
    assert_eq!(auditor.report().mismatches, 0);

    // Full 10,000-block ShadowAuditor replay campaign (zero silent drops, zero divergences).
    let empty_prev = "0".repeat(64);
    for height in 2u64..=10_000 {
        let txs = if height % 250 == 0 {
            vec![valid_tx.clone()]
        } else {
            Vec::new()
        };
        let blk = Block::new_with_chain_id(height, empty_prev.clone(), txs, devnet_id);
        assert!(auditor.audit_block(&blk).expect("shadow audit block"));
    }
    let rep = auditor.report();
    assert_eq!(rep.blocks_audited, 10_000);
    assert_eq!(rep.mismatches, 0);
    assert_eq!(rep.matches, rep.txs_checked);
    println!(
        "AGG_METRIC shadow_campaign blocks_audited={} txs_checked={} matches={} mismatches={}",
        rep.blocks_audited, rep.txs_checked, rep.matches, rep.mismatches
    );
}

#[test]
fn stark_tick_master_scaling_and_10k_split_stark_differential_campaign() {
    use std::time::Instant;

    use crate::aggregation::air_registry::external_fib_air_id;
    use crate::crypto::primitives::ML_DSA_87_SIGNATURE_LEN;

    let params = phase5_params();
    let registry = SchemeStatusRegistry::genesis();
    let backend = stark_backend(&params);
    let chain_id = Network::Devnet.chain_id().value();
    let domain = domain_of(chain_id);
    let agg_seed = Zeroizing::new([0xD1u8; 32]);
    let ctx = TickCtx::from_seed(domain, agg_seed).expect("ctx");

    // Pre-generate 256 real ML-DSA-87 signed envelopes from a deterministic pool of keys
    // so we benchmark StarkBackend TickProof at N = 16, 64, 256 and binary-tree MasterProof
    // across 4 disjoint 256-claim ticks (N = 1,024 total ML-DSA-87 claims!).
    let signers: Vec<WalletKeyPair> = (0..16).map(|_| WalletKeyPair::generate()).collect();
    let build_batch = |batch_idx: u64, count: usize| -> Vec<PoolItem> {
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let signer = signers.get(i % signers.len()).unwrap();
            let mut tx = Transaction::new(
                signer.address(),
                Address::from([0xE1; 32]),
                1 + i as u64,
                Vec::new(),
            );
            tx.chain_id = chain_id;
            tx.nonce = batch_idx * 10_000 + i as u64;
            tx.fee = 5_000;
            tx.sign_v5(signer);
            let (_, env) = claim_signature(&tx).unwrap();
            let claim = derive_claim(&registry, &env).unwrap();
            out.push(PoolItem {
                envelope: env,
                claim,
            });
        }
        out
    };

    let first_256 = build_batch(0, 256);
    for n in [16usize, 64, 256] {
        let slice = first_256.get(..n).unwrap();
        let t_prove = Instant::now();
        let frame = backend.prove_tick(&ctx, slice).expect("prove_tick");
        let prove_ms = t_prove.elapsed().as_millis();
        let t_ver = Instant::now();
        backend.verify(&frame, domain).expect("verify tick");
        let verify_us = t_ver.elapsed().as_micros();
        let proof_bytes = frame.proof.len();
        let frame_bytes = frame.encode().len();
        let native_sig_bytes = n * ML_DSA_87_SIGNATURE_LEN;
        let compression_x100 = (native_sig_bytes * 100) / proof_bytes.max(1);
        println!(
            "AGG_METRIC kind=TickProof n={n} prove_ms={prove_ms} verify_us={verify_us} proof_bytes={proof_bytes} frame_bytes={frame_bytes} native_sig_bytes={native_sig_bytes} proof_compression_x100={compression_x100}"
        );
    }

    // Binary-tree merge of 4 disjoint 256-claim ticks -> single MasterProof over N = 1,024 claims!
    let t0 = backend.prove_tick(&ctx, &first_256).expect("tick 0");
    let t1 = backend
        .prove_tick(&ctx, &build_batch(1, 256))
        .expect("tick 1");
    let t2 = backend
        .prove_tick(&ctx, &build_batch(2, 256))
        .expect("tick 2");
    let t3 = backend
        .prove_tick(&ctx, &build_batch(3, 256))
        .expect("tick 3");
    let t_merge = Instant::now();
    let p01 = backend.prove_merge(&t0, &t1).expect("prove merge 01");
    let m01 = ClaimFrame::combine(&t0, &t1, p01).expect("combine 01");
    let p23 = backend.prove_merge(&t2, &t3).expect("prove merge 23");
    let m23 = ClaimFrame::combine(&t2, &t3, p23).expect("combine 23");
    let p_master = backend.prove_merge(&m01, &m23).expect("prove master 1024");
    let master = ClaimFrame::combine(&m01, &m23, p_master).expect("combine master 1024");
    let merge_ms = t_merge.elapsed().as_millis();
    let t_mver = Instant::now();
    backend
        .verify(&master, domain)
        .expect("verify 1024 MasterProof");
    let master_verify_us = t_mver.elapsed().as_micros();
    let master_proof_bytes = master.proof.len();
    let master_frame_bytes = master.encode().len();
    let native_1024_bytes = 1_024 * ML_DSA_87_SIGNATURE_LEN;
    let master_comp_x100 = (native_1024_bytes * 100) / master_proof_bytes.max(1);
    assert_eq!(master.claims.len(), 1_024);
    println!(
        "AGG_METRIC kind=MasterProof n=1024 merge_ms={merge_ms} verify_us={master_verify_us} proof_bytes={master_proof_bytes} frame_bytes={master_frame_bytes} native_sig_bytes={native_1024_bytes} proof_compression_x100={master_comp_x100}"
    );

    // 10,000-vector deterministic Phase 5 split-STARK differential mutation campaign:
    // every honest statement passes and matches the golden Claim::Poly; every mutated
    // public input, trace/quotient commitment, degree_bits, air_id, opened limb, or
    // claim_ref is rejected with 0 false accepts and 0 false rejects.
    let (fib_proof, pvs, shape) = prove_fibonacci(4, 1, 1).expect("fib");
    let pcs = PcsOpeningObject::from_chip_proof(&fib_proof, shape, &pvs, None).expect("pcs");
    let golden_poly = verify_pcs_opening(&pcs).expect("golden poly");
    let golden_digest = golden_poly.digest(domain);
    let golden_stmt = pcs.to_verify_stark_tx(external_fib_air_id(), Vec::new());
    let mut airs = AirRegistry::with_builtins();
    airs.register(std::sync::Arc::new(ExternalFibAirEvaluator))
        .unwrap();
    let mut proven = BTreeSet::new();
    proven.insert(golden_digest);

    let mut state_rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next_u64 = || -> u64 {
        state_rng ^= state_rng << 13;
        state_rng ^= state_rng >> 7;
        state_rng ^= state_rng << 17;
        state_rng
    };
    let mut false_accepts = 0usize;
    let mut false_rejects = 0usize;
    for case in 0..10_000usize {
        let r = next_u64();
        if case % 20 == 0 {
            match airs.verify_stark_tx(domain, &golden_stmt, &[golden_digest], &proven) {
                Ok(c) if c == golden_poly => {}
                _ => false_rejects += 1,
            }
            continue;
        }
        let mut mutated = golden_stmt.clone();
        let mut refs = [golden_digest];
        match case % 6 {
            0 => {
                if let Some(pv) = mutated.public_values.get_mut((r as usize) % pvs.len()) {
                    *pv = pv.wrapping_add(1 + (r % 1_000));
                }
            }
            1 => {
                let idx = (r as usize) % 32;
                mutated.commitments.trace[idx] ^= ((r & 0xFE) as u8) | 1;
            }
            2 => {
                let idx = (r as usize) % 32;
                mutated.commitments.quotient_chunks[idx] ^= ((r & 0xFE) as u8) | 1;
            }
            3 => {
                if let Some(row) = mutated.opened_values.trace_local.first_mut() {
                    row[(r as usize) % 3] = row[(r as usize) % 3].wrapping_add(1 + (r % 997));
                }
            }
            4 => {
                mutated.degree_bits = mutated.degree_bits.wrapping_add(1 + ((r % 7) as u8));
            }
            _ => {
                let idx = (r as usize) % 32;
                refs[0][idx] ^= ((r & 0xFE) as u8) | 1;
            }
        }
        if airs
            .verify_stark_tx(domain, &mutated, &refs, &proven)
            .is_ok()
        {
            false_accepts += 1;
        }
    }
    assert_eq!(false_rejects, 0);
    assert_eq!(false_accepts, 0);
    println!(
        "AGG_METRIC split_stark_differential vectors=10000 false_accepts={false_accepts} false_rejects={false_rejects}"
    );
}

/// A `PcsOpeningObject` arrives from an untrusted peer, so its declared
/// `log_num_quotient_chunks` is a free one-byte claim while the chunk openings
/// it carries cost real bytes. `decode` admitted any `u8` value and
/// `verify_pcs_opening` never compared the declaration against the carried
/// data, so a peer could park objects in the pool whose shape the Stage 2
/// verifier is guaranteed to refuse (`1 << 255` chunk fan-out declared against
/// two carried chunks). Admission must fail closed on both the declaration
/// ceiling and the declaration/carry consistency.
#[test]
fn pcs_opening_refuses_inflated_quotient_chunk_declaration_and_inconsistent_carry() {
    let (proof, pvs, shape) = prove_fibonacci(6, 1, 1).expect("prove fib");
    let honest = PcsOpeningObject::from_chip_proof(&proof, shape, &pvs, None).expect("pcs obj");

    // The honest object is fully self-consistent: this must keep working.
    assert_eq!(verify_pcs_opening(&honest), verify_pcs_opening(&honest));
    assert!(verify_pcs_opening(&honest).is_ok());
    let roundtrip = PcsOpeningObject::decode(&honest.encode().expect("encode honest"))
        .expect("honest object must decode");
    assert_eq!(roundtrip, honest);

    // (1) A declared chunk count above the Stage 2 ceiling is refused at
    //     admission, before it can ever reach a shift or a subdomain expansion.
    let ceiling = u8::try_from(bud_proof::bud_stark::MAX_LOG_QUOTIENT_CHUNKS).expect("fits u8");
    let mut inflated = honest.clone();
    inflated.log_num_quotient_chunks = ceiling.saturating_add(1);
    assert_eq!(
        PcsOpeningObject::decode(&inflated.encode().expect("encode inflated")),
        Err(ObjectError::Invalid),
        "declared log_num_quotient_chunks above the ceiling must be refused at decode"
    );

    // (2) The same refusal must hold on the Stage 1 path without a round trip,
    //     because `shape()` is public and is the only shape the verifier sees.
    assert_eq!(
        verify_pcs_opening(&inflated),
        Err(ObjectError::Invalid),
        "inflated declaration must be refused by verify_pcs_opening"
    );

    // (3) The declaration must equal the number of chunk openings carried, in
    //     both directions: over-declaring and under-carrying are refused.
    let mut over_declared = honest.clone();
    over_declared.log_num_quotient_chunks = honest.log_num_quotient_chunks.saturating_add(1);
    assert_eq!(
        PcsOpeningObject::decode(&over_declared.encode().expect("encode over-declared")),
        Err(ObjectError::Invalid),
        "a declaration above the carried chunk openings must be refused at decode"
    );
    assert_eq!(
        verify_pcs_opening(&over_declared),
        Err(ObjectError::Invalid),
        "a declaration above the carried chunk openings must be refused at Stage 1"
    );

    let mut under_carried = honest.clone();
    assert!(
        under_carried.opened_values.quotient_chunks.pop().is_some(),
        "the honest fixture must carry a chunk to drop"
    );
    assert_eq!(
        PcsOpeningObject::decode(&under_carried.encode().expect("encode under-carried")),
        Err(ObjectError::Invalid),
        "a declaration with a missing carried chunk opening must be refused at decode"
    );
    assert_eq!(
        verify_pcs_opening(&under_carried),
        Err(ObjectError::Invalid),
        "a declaration with a missing carried chunk opening must be refused at Stage 1"
    );

    // (4) The prover-side constructor refuses the same over-claim, so an
    //     honest producer fails closed instead of publishing an object that
    //     every verifier will reject.
    let over_claimed = bud_proof::bud_stark::PcsOpeningShape {
        log_num_quotient_chunks: usize::from(ceiling) + 1,
        ..shape
    };
    assert_eq!(
        PcsOpeningObject::from_chip_proof(&proof, over_claimed, &pvs, None),
        Err(ObjectError::Invalid),
        "from_chip_proof must refuse a shape above the chunk ceiling"
    );
}
