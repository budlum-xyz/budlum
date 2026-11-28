//! Phase 5 benchmark & verification report (`benches/agg_phase5_pcs.rs`).
//!
//! Measures and compares:
//! 1. On-chain Stage 2 (`verify_algebra`) verification cost & byte size vs
//!    full monolithic STARK verification (`verify_with_preprocessed`) across:
//!    - `BudAir` (built-in VM AIR, 1,073 columns)
//!    - External `FibonacciAir` (non-`BudAir` 2-column AIR at 2^8 and 2^10 rows)
//!    - `AggFoldAir` (23-column recursive fold AIR at 2^4 rows)
//! 2. 10,000-case differential test (`verify_pcs_openings + verify_algebra` vs
//!    full verification across valid and corrupted proofs).
//! 3. End-to-end 4-aggregator + 1-producer load test (1,024 claims in 1 block).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use bud_proof::chips::fib::{prove_fibonacci, verify_fibonacci};
use bud_proof::chips::fold::{
    agg_fold_pcs_metadata, prove_agg_fold, verify_agg_fold, AggFoldPublic, AggFoldStep,
};
use bud_proof::plonky3_prover::{
    chip_commitment_from_bytes, chip_commitment_to_bytes, extract_bud_envelope_pcs, Plonky3Adapter,
};
use bud_proof::ProverAdapter;
use budlum_core::aggregation::air_registry::{
    agg_fold_air_id, bud_air_id, external_fib_air_id, AirRegistry, ExternalFibAirEvaluator,
};
use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::chain::{check_block_with_backend_and_airs, claim_signature};
use budlum_core::aggregation::claim::{Claim, GOLDILOCKS_MODULUS};
use budlum_core::aggregation::domain_finality::{
    compile_domain_transition, prove_domain_transition,
};
use budlum_core::aggregation::envelope::{Envelope, ObjectKind};
use budlum_core::aggregation::frame::{ClaimFrame, FrameLimits};
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::aggregation::pool::PoolItem;
use budlum_core::aggregation::programs::pcs_claim::{
    verify_pcs_opening, BudAirAuxData, PcsOpeningObject,
};
use budlum_core::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainId, DomainStatus, RootScheme,
};
use zeroize::Zeroizing;

fn sample_bud_domain_proof(
    domain: DomainId,
) -> Result<budlum_core::aggregation::programs::prog_claim::StarkProofObject, String> {
    let dom_prog =
        compile_domain_transition(77, 42_161).map_err(|e| format!("compile dom: {e}"))?;
    let ext_domain = ConsensusDomain {
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
        zk_program_allowlist: vec![dom_prog.program_hash],
        plugin_code_hash: None,
        genesis_state_root: [0x11; 32],
    };
    let prev_root = [0x11; 32];
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
    let batch_digest = [0xAB; 32];
    prove_domain_transition(
        &dom_prog,
        &ext_domain,
        10,
        &prev_root,
        &commitment,
        &batch_digest,
        domain,
    )
    .map_err(|e| format!("dom prove: {e}"))
}

fn measure_bud_air(
    domain: DomainId,
    air_registry: &AirRegistry,
) -> Result<(usize, usize, f64, f64, f64), String> {
    let stark_obj = sample_bud_domain_proof(domain)?;
    let pcs_obj = PcsOpeningObject::from_bud_envelope(
        &stark_obj.proof_envelope,
        &stark_obj.program,
        &stark_obj.public_inputs,
    )
    .map_err(|e| e.to_string())?;
    let aux = BudAirAuxData {
        program: stark_obj.program.clone(),
        expected_inputs: stark_obj.public_inputs.clone(),
    };
    let aux_bytes = bincode::DefaultOptions::new()
        .serialize(&aux)
        .map_err(|e| e.to_string())?;
    let verify_tx = pcs_obj.to_verify_stark_tx(bud_air_id(), aux_bytes);
    let tx_bytes = bincode::DefaultOptions::new()
        .serialize(&verify_tx)
        .map_err(|e| e.to_string())?
        .len();
    let full_bytes = stark_obj.proof_envelope.proof_bytes.len();

    let t_full = Instant::now();
    for _ in 0..5 {
        Plonky3Adapter::verify(
            &stark_obj.proof_envelope,
            &stark_obj.public_inputs,
            &stark_obj.program,
        )
        .map_err(|e| format!("{e:?}"))?;
    }
    let full_ms = t_full.elapsed().as_secs_f64() * 1000.0 / 5.0;

    let t_pcs = Instant::now();
    let poly_claim = verify_pcs_opening(&pcs_obj).map_err(|e| e.to_string())?;
    let pcs_ms = t_pcs.elapsed().as_secs_f64() * 1000.0;
    let d = poly_claim.digest(domain);
    let mut proven = BTreeSet::new();
    proven.insert(d);

    let t_alg = Instant::now();
    for _ in 0..5 {
        air_registry
            .verify_stark_tx(domain, &verify_tx, &[d], &proven)
            .map_err(|e| e.to_string())?;
    }
    let alg_ms = t_alg.elapsed().as_secs_f64() * 1000.0 / 5.0;
    Ok((full_bytes, tx_bytes, full_ms, pcs_ms, alg_ms))
}

fn measure_fib_air(
    domain: DomainId,
    degree_bits: usize,
    air_registry: &AirRegistry,
) -> Result<(usize, usize, f64, f64, f64), String> {
    let (proof, pvs, shape) = prove_fibonacci(degree_bits, 1, 1)?;
    let full_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| e.to_string())?
        .len();
    let pcs_obj =
        PcsOpeningObject::from_chip_proof(&proof, shape, &pvs, None).map_err(|e| e.to_string())?;
    let verify_tx = pcs_obj.to_verify_stark_tx(external_fib_air_id(), Vec::new());
    let tx_bytes = bincode::DefaultOptions::new()
        .serialize(&verify_tx)
        .map_err(|e| e.to_string())?
        .len();

    let iters = 20u32;
    let t_full = Instant::now();
    for _ in 0..iters {
        verify_fibonacci(&proof, &pvs)?;
    }
    let full_ms = t_full.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);

    let t_pcs = Instant::now();
    let mut poly_claim = verify_pcs_opening(&pcs_obj).map_err(|e| e.to_string())?;
    for _ in 1..iters {
        poly_claim = verify_pcs_opening(&pcs_obj).map_err(|e| e.to_string())?;
    }
    let pcs_ms = t_pcs.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);

    let d = poly_claim.digest(domain);
    let mut proven = BTreeSet::new();
    proven.insert(d);

    let alg_iters = 200u32;
    let t_alg = Instant::now();
    for _ in 0..alg_iters {
        air_registry
            .verify_stark_tx(domain, &verify_tx, &[d], &proven)
            .map_err(|e| e.to_string())?;
    }
    let alg_ms = t_alg.elapsed().as_secs_f64() * 1000.0 / f64::from(alg_iters);
    Ok((full_bytes, tx_bytes, full_ms, pcs_ms, alg_ms))
}

fn measure_fold_air(
    domain: DomainId,
    air_registry: &AirRegistry,
) -> Result<(usize, usize, f64, f64, f64), String> {
    let tick_hash = [0x11u8; 32];
    let merge_hash = [0x22u8; 32];
    let steps = vec![
        AggFoldStep {
            is_merge: false,
            left_is_merge: false,
            right_is_merge: false,
            program_hash: tick_hash,
            node_pi: [0xA1; 32],
        },
        AggFoldStep {
            is_merge: false,
            left_is_merge: false,
            right_is_merge: false,
            program_hash: tick_hash,
            node_pi: [0xA2; 32],
        },
        AggFoldStep {
            is_merge: true,
            left_is_merge: false,
            right_is_merge: false,
            program_hash: merge_hash,
            node_pi: [0xB1; 32],
        },
    ];
    let pub_stmt = AggFoldPublic {
        parameter_set: STARK_PARAMETER_SET,
        domain,
        tick_program_hash: tick_hash,
        merge_program_hash: merge_hash,
        shape_digest: [0xCC; 32],
        final_program_hash: merge_hash,
        master_pi: [0xB1; 32],
        step_count: 3,
    };
    let fold_proof = prove_agg_fold(&steps, &pub_stmt).map_err(|e| format!("{e:?}"))?;
    let full_bytes = postcard::to_allocvec(&fold_proof.proof)
        .map_err(|e| e.to_string())?
        .len();
    let (pvs, shape) = agg_fold_pcs_metadata(&steps, &pub_stmt, fold_proof.proof.degree_bits)
        .map_err(|e| format!("{e:?}"))?;
    let pcs_obj = PcsOpeningObject::from_chip_proof(&fold_proof.proof, shape, &pvs, None)
        .map_err(|e| e.to_string())?;
    let verify_tx = pcs_obj.to_verify_stark_tx(agg_fold_air_id(), Vec::new());
    let tx_bytes = bincode::DefaultOptions::new()
        .serialize(&verify_tx)
        .map_err(|e| e.to_string())?
        .len();

    let iters = 20u32;
    let t_full = Instant::now();
    for _ in 0..iters {
        verify_agg_fold(&steps, &pub_stmt, &fold_proof).map_err(|e| format!("{e:?}"))?;
    }
    let full_ms = t_full.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);

    let t_pcs = Instant::now();
    let mut poly_claim = verify_pcs_opening(&pcs_obj).map_err(|e| e.to_string())?;
    for _ in 1..iters {
        poly_claim = verify_pcs_opening(&pcs_obj).map_err(|e| e.to_string())?;
    }
    let pcs_ms = t_pcs.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);

    let d = poly_claim.digest(domain);
    let mut proven = BTreeSet::new();
    proven.insert(d);

    let alg_iters = 200u32;
    let t_alg = Instant::now();
    for _ in 0..alg_iters {
        air_registry
            .verify_stark_tx(domain, &verify_tx, &[d], &proven)
            .map_err(|e| e.to_string())?;
    }
    let alg_ms = t_alg.elapsed().as_secs_f64() * 1000.0 / f64::from(alg_iters);
    Ok((full_bytes, tx_bytes, full_ms, pcs_ms, alg_ms))
}

fn run_10000_differential(
    domain: DomainId,
    air_registry: &AirRegistry,
) -> Result<(usize, usize, f64), String> {
    let t0 = Instant::now();
    let (base_fib, base_pvs, base_shape) = prove_fibonacci(4, 1, 1)?;
    let base_pcs = PcsOpeningObject::from_chip_proof(&base_fib, base_shape, &base_pvs, None)
        .map_err(|e| e.to_string())?;

    let bud_obj = sample_bud_domain_proof(domain)?;
    let bud_pcs = PcsOpeningObject::from_bud_envelope(
        &bud_obj.proof_envelope,
        &bud_obj.program,
        &bud_obj.public_inputs,
    )
    .map_err(|e| e.to_string())?;
    let (bud_chip, _, _, _) = extract_bud_envelope_pcs(
        &bud_obj.proof_envelope,
        &bud_obj.program,
        &bud_obj.public_inputs,
    )?;
    let bud_aux_bytes = bincode::DefaultOptions::new()
        .serialize(&BudAirAuxData {
            program: bud_obj.program.clone(),
            expected_inputs: bud_obj.public_inputs.clone(),
        })
        .map_err(|e| e.to_string())?;
    let bud_stmt = bud_pcs.to_verify_stark_tx(bud_air_id(), bud_aux_bytes);

    let mut rng: u64 = 0xD1FF_5000_2026_1117u64;
    let mut next_u64 = || -> u64 {
        rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        rng
    };

    let mut accepts = 0usize;
    let mut rejects = 0usize;

    for case in 0..10_000usize {
        if case % 500 == 0 {
            let mut pcs = bud_pcs.clone();
            let mut stmt = bud_stmt.clone();
            let mut env = bud_obj.proof_envelope.clone();
            let mut chip = bud_chip.clone();
            if (case / 500) % 2 == 1 {
                pcs.commitments.trace[0] ^= 0x01;
                stmt.commitments.trace[0] ^= 0x01;
                chip.commitments.trace = chip_commitment_from_bytes(pcs.commitments.trace);
                env.proof_bytes = postcard::to_allocvec(&chip).map_err(|e| e.to_string())?;
            }
            let full_ok =
                Plonky3Adapter::verify(&env, &bud_obj.public_inputs, &bud_obj.program).is_ok();
            let split_ok = match verify_pcs_opening(&pcs) {
                Ok(Claim::Poly {
                    poly_hash,
                    point,
                    value,
                }) => {
                    let d = Claim::Poly {
                        poly_hash,
                        point,
                        value,
                    }
                    .digest(domain);
                    let mut proven = BTreeSet::new();
                    proven.insert(d);
                    air_registry
                        .verify_stark_tx(domain, &stmt, &[d], &proven)
                        .is_ok()
                }
                _ => false,
            };
            if full_ok != split_ok {
                return Err(format!("BudAir differential divergence at case {case}"));
            }
            if full_ok {
                accepts += 1;
            } else {
                rejects += 1;
            }
            continue;
        }

        let mut proof = base_fib.clone();
        let mut pvs = base_pvs.to_vec();
        let mut pcs = base_pcs.clone();
        match case % 10 {
            0 => {}
            1 => {
                let bi = usize::try_from(next_u64() % 32).unwrap_or(0);
                pcs.commitments.trace[bi] ^= 0x01;
                proof.commitments.trace = chip_commitment_from_bytes(pcs.commitments.trace);
            }
            2 => {
                let bi = usize::try_from(next_u64() % 32).unwrap_or(0);
                pcs.commitments.quotient_chunks[bi] ^= 0x01;
                proof.commitments.quotient_chunks =
                    chip_commitment_from_bytes(pcs.commitments.quotient_chunks);
            }
            3 => {
                pcs.opened_values.trace_local[0][0] =
                    (pcs.opened_values.trace_local[0][0] + 1) % GOLDILOCKS_MODULUS;
                proof.opened_values = pcs.opened_values.to_chip().map_err(|e| e.to_string())?;
            }
            4 => {
                if let Some(tn) = pcs.opened_values.trace_next.as_mut() {
                    tn[1][0] = (tn[1][0] + 1) % GOLDILOCKS_MODULUS;
                }
                proof.opened_values = pcs.opened_values.to_chip().map_err(|e| e.to_string())?;
            }
            5 => {
                pcs.opened_values.quotient_chunks[0][0][0] =
                    (pcs.opened_values.quotient_chunks[0][0][0] + 1) % GOLDILOCKS_MODULUS;
                proof.opened_values = pcs.opened_values.to_chip().map_err(|e| e.to_string())?;
            }
            6 => {
                pvs[2] = (pvs[2] + 1) % GOLDILOCKS_MODULUS;
                pcs.public_values.clone_from(&pvs);
            }
            7 => {
                pcs.degree_bits = 5;
                proof.degree_bits = 5;
            }
            8 => {
                pcs.opened_values.trace_next = None;
                proof.opened_values.trace_next = None;
            }
            _ => {
                if let Some(first) = proof.opening_proof.commit_phase_commits.first_mut() {
                    let mut root = chip_commitment_to_bytes(first)
                        .ok_or_else(|| "cap height != 0".to_string())?;
                    root[0] ^= 0x01;
                    *first = chip_commitment_from_bytes(root);
                    pcs.opening_proof_bytes =
                        postcard::to_allocvec(&proof.opening_proof).map_err(|e| e.to_string())?;
                }
            }
        }
        let full_ok = verify_fibonacci(&proof, &pvs).is_ok();
        let stmt = pcs.to_verify_stark_tx(external_fib_air_id(), Vec::new());
        let split_ok = match verify_pcs_opening(&pcs) {
            Ok(Claim::Poly {
                poly_hash,
                point,
                value,
            }) => {
                let d = Claim::Poly {
                    poly_hash,
                    point,
                    value,
                }
                .digest(domain);
                let mut proven = BTreeSet::new();
                proven.insert(d);
                air_registry
                    .verify_stark_tx(domain, &stmt, &[d], &proven)
                    .is_ok()
            }
            _ => false,
        };
        if full_ok != split_ok {
            return Err(format!(
                "FibonacciAir differential divergence at case {case}"
            ));
        }
        if full_ok {
            accepts += 1;
        } else {
            rejects += 1;
        }
    }
    Ok((accepts, rejects, t0.elapsed().as_secs_f64() * 1000.0))
}

fn run_load_test(chain_id: u64, air_registry: &AirRegistry) -> Result<(usize, f64, f64), String> {
    let domain = u32::try_from(chain_id).map_err(|_| "domain overflow".to_string())?;
    let params = AggParams {
        mode: AggMode::On,
        max_stark_object_bytes: 1_048_576,
        max_pcs_object_bytes: 1_048_576,
        ..AggParams::default()
    };
    let registry = SchemeStatusRegistry::genesis();
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&params),
        STARK_PARAMETER_SET,
    );
    let sender = WalletKeyPair::generate();

    // Include an external FibonacciAir VerifyStark tx + 1,022 ML-DSA-87 transfers = 1,024 claims!
    let (fib_proof, fib_pvs, fib_shape) = prove_fibonacci(6, 1, 1)?;
    let fib_pcs = PcsOpeningObject::from_chip_proof(&fib_proof, fib_shape, &fib_pvs, None)
        .map_err(|e| e.to_string())?;
    let fib_claim = verify_pcs_opening(&fib_pcs).map_err(|e| e.to_string())?;
    let fib_digest = fib_claim.digest(domain);
    let fib_stmt = fib_pcs.to_verify_stark_tx(external_fib_air_id(), Vec::new());

    let mut verify_tx_raw = Transaction::new(sender.address(), Address::zero(), 0, Vec::new());
    verify_tx_raw.chain_id = chain_id;
    verify_tx_raw.nonce = 0;
    verify_tx_raw.fee = 20_000;
    verify_tx_raw.tx_type = TransactionType::VerifyStark(Box::new(fib_stmt));
    verify_tx_raw.claim_refs.push(fib_digest);
    verify_tx_raw.sign_v5(&sender);
    let verify_hash = verify_tx_raw.signing_hash();
    let (claimed_verify_tx, verify_sig_env) =
        claim_signature(&verify_tx_raw).ok_or_else(|| "claim sig failed".to_string())?;
    let verify_pcs_env = Envelope {
        kind: ObjectKind::PcsOpening,
        scheme: SchemeId(0),
        payload: fib_pcs.encode().map_err(|e| e.to_string())?,
        tx_hash: verify_hash,
        domain,
    };

    let t_prove = Instant::now();
    let mut all_txs = Vec::with_capacity(1023);
    let mut frames = Vec::with_capacity(4);
    for agg_idx in 0u8..4 {
        let mut items = Vec::with_capacity(256);
        let start = if agg_idx == 0 {
            let sig_claim = derive_claim(&registry, &verify_sig_env).map_err(|e| e.to_string())?;
            let poly_claim = derive_claim(&registry, &verify_pcs_env).map_err(|e| e.to_string())?;
            all_txs.push(claimed_verify_tx.clone());
            items.push(PoolItem {
                envelope: verify_sig_env.clone(),
                claim: sig_claim,
            });
            items.push(PoolItem {
                envelope: verify_pcs_env.clone(),
                claim: poly_claim,
            });
            2u64
        } else {
            0u64
        };
        for local in start..256 {
            let nonce = u64::from(agg_idx) * 256 + local;
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
            let (claimed, env) =
                claim_signature(&raw).ok_or_else(|| "claim sig failed".to_string())?;
            let claim = derive_claim(&registry, &env).map_err(|e| e.to_string())?;
            all_txs.push(claimed);
            items.push(PoolItem {
                envelope: env,
                claim,
            });
        }
        let ctx = TickCtx::from_seed(domain, Zeroizing::new([0x70 + agg_idx; 32]))
            .map_err(|e| e.to_string())?;
        frames.push(
            backend
                .prove_tick(&ctx, &items)
                .map_err(|e| e.to_string())?,
        );
    }
    let lp = backend
        .prove_merge(&frames[0], &frames[1])
        .map_err(|e| e.to_string())?;
    let left = ClaimFrame::combine(&frames[0], &frames[1], lp).map_err(|e| e.to_string())?;
    let rp = backend
        .prove_merge(&frames[2], &frames[3])
        .map_err(|e| e.to_string())?;
    let right = ClaimFrame::combine(&frames[2], &frames[3], rp).map_err(|e| e.to_string())?;
    let mp = backend
        .prove_merge(&left, &right)
        .map_err(|e| e.to_string())?;
    let master = ClaimFrame::combine(&left, &right, mp).map_err(|e| e.to_string())?;
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = master.proof.len();

    let mut accounts = AccountState::new();
    let agg_floor = Network::Devnet
        .min_stake()
        .max(accounts.registry.params().min_stake)
        .max(1);
    for seg in &master.segments {
        accounts.add_validator_with_floor(seg.aggregator, agg_floor, agg_floor);
    }
    let mut block = Block::new_with_chain_id(1, "0".repeat(64), all_txs, chain_id);
    block.frame_hash = Some(master.hash(domain).map_err(|e| e.to_string())?);
    block.claim_frame = Some(master);

    let t_ver = Instant::now();
    check_block_with_backend_and_airs(
        &params,
        &registry,
        Some(&accounts),
        air_registry,
        &block,
        &backend,
    )?;
    let verify_ms = t_ver.elapsed().as_secs_f64() * 1000.0;
    Ok((proof_bytes, prove_ms, verify_ms))
}

fn main() -> Result<(), String> {
    let chain_id = Network::Devnet.chain_id().value();
    let domain = u32::try_from(chain_id).map_err(|_| "domain overflow".to_string())?;
    let mut air_registry = AirRegistry::with_builtins();
    air_registry
        .register(Arc::new(ExternalFibAirEvaluator))
        .map_err(|e| e.to_string())?;

    println!("=== Phase 5 PCS Claims & Split-STARK Cost Comparison ===");
    let (b_full_b, b_tx_b, b_full_ms, b_pcs_ms, b_alg_ms) = measure_bud_air(domain, &air_registry)?;
    println!(
        "BudAir (1073 cols, 2^9 rows)      : full_proof={b_full_b} B, verify_stark_tx={b_tx_b} B ({:.1}x smaller) | full_verify={b_full_ms:.2} ms, stage1_pcs={b_pcs_ms:.2} ms, chain_algebra={b_alg_ms:.3} ms ({:.1}x faster)",
        b_full_b as f64 / b_tx_b as f64,
        b_full_ms / b_alg_ms.max(0.0001)
    );

    let (f8_full_b, f8_tx_b, f8_full_ms, f8_pcs_ms, f8_alg_ms) =
        measure_fib_air(domain, 8, &air_registry)?;
    println!(
        "ExternalFibAir (2 cols, 2^8 rows) : full_proof={f8_full_b} B, verify_stark_tx={f8_tx_b} B ({:.1}x smaller) | full_verify={f8_full_ms:.2} ms, stage1_pcs={f8_pcs_ms:.2} ms, chain_algebra={f8_alg_ms:.3} ms ({:.1}x faster)",
        f8_full_b as f64 / f8_tx_b as f64,
        f8_full_ms / f8_alg_ms.max(0.0001)
    );

    let (f10_full_b, f10_tx_b, f10_full_ms, f10_pcs_ms, f10_alg_ms) =
        measure_fib_air(domain, 10, &air_registry)?;
    println!(
        "ExternalFibAir (2 cols, 2^10 rows): full_proof={f10_full_b} B, verify_stark_tx={f10_tx_b} B ({:.1}x smaller) | full_verify={f10_full_ms:.2} ms, stage1_pcs={f10_pcs_ms:.2} ms, chain_algebra={f10_alg_ms:.3} ms ({:.1}x faster)",
        f10_full_b as f64 / f10_tx_b as f64,
        f10_full_ms / f10_alg_ms.max(0.0001)
    );

    let (af_full_b, af_tx_b, af_full_ms, af_pcs_ms, af_alg_ms) =
        measure_fold_air(domain, &air_registry)?;
    println!(
        "AggFoldAir (23 cols, 2^4 rows)    : full_proof={af_full_b} B, verify_stark_tx={af_tx_b} B ({:.1}x smaller) | full_verify={af_full_ms:.2} ms, stage1_pcs={af_pcs_ms:.2} ms, chain_algebra={af_alg_ms:.3} ms ({:.1}x faster)",
        af_full_b as f64 / af_tx_b as f64,
        af_full_ms / af_alg_ms.max(0.0001)
    );

    let (diff_acc, diff_rej, diff_ms) = run_10000_differential(domain, &air_registry)?;
    println!(
        "Differential (10,000 cases)       : accepts={diff_acc}, rejects={diff_rej}, divergences=0, elapsed={diff_ms:.1} ms"
    );

    let (load_proof_b, load_prove_ms, load_ver_ms) = run_load_test(chain_id, &air_registry)?;
    println!(
        "Load Test (4 aggs, 1024 claims)   : master_proof={load_proof_b} B, prove_and_merge={load_prove_ms:.1} ms, block_verify={load_ver_ms:.2} ms"
    );
    Ok(())
}
