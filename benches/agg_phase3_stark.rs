//! Phase 3 STARK recursion, MasterProof size/speed, and 10,000-block Shadow
//! parity measurement harness.
//!
//! Run with: `cargo bench --bench agg_phase3_stark`

use std::time::Instant;

use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::frame::{merge_pi, ClaimFrame, FrameLimits};
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::aggregation::pool::PoolItem;
use budlum_core::aggregation::programs::agg_merge::{
    agg_merge, prove_agg_merge, verify_agg_merge, AggMergeWitness,
};
use budlum_core::aggregation::shadow::ShadowAuditor;
use budlum_core::aggregation::stark::{agg_tick_program_hash, StarkBackend, STARK_PARAMETER_SET};
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::domain::types::DomainId;

const DOMAIN: DomainId = 43;

fn build_pool_items(
    count: usize,
    registry: &SchemeStatusRegistry,
) -> Result<Vec<PoolItem>, String> {
    let wallet = WalletKeyPair::from_seed(&[0x42; 32]);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut tx = Transaction::new_with_fee(
            wallet.address(),
            Address::from([0x11; 32]),
            10,
            100_000,
            i as u64,
            Vec::new(),
        );
        tx.chain_id = u64::from(DOMAIN);
        tx.sign_v5(&wallet);
        let (_, env) = budlum_core::aggregation::chain::claim_signature(&tx)
            .ok_or_else(|| "claim_signature failed".to_string())?;
        let claim = derive_claim(registry, &env).map_err(|e| format!("derive claim: {e:?}"))?;
        out.push(PoolItem {
            envelope: env,
            claim,
        });
    }
    Ok(out)
}

fn main() -> Result<(), String> {
    let registry = SchemeStatusRegistry::genesis();

    // 1. Measure real AggMerge BudAir + BoundKeccakAir proof.
    println!("### 1. AggMerge BudZKVM (`Plonky3Adapter` / `BudAir`) Proof");
    println!("| Program | VM steps | Trace rows | VM proof bytes | Prove ms | Verify ms |");
    println!("|---|---:|---:|---:|---:|---:|");
    let tick_hash = agg_tick_program_hash();
    let merge_prog = agg_merge(&tick_hash).map_err(|e| format!("compile AggMerge: {e:?}"))?;
    let left_pi = [0x11; 32];
    let right_pi = [0x22; 32];
    let expected = merge_pi(&left_pi, &right_pi);
    let t0 = Instant::now();
    let vm_proof = prove_agg_merge(
        &merge_prog,
        &AggMergeWitness {
            left_program_hash: tick_hash,
            left_pi,
            right_program_hash: merge_prog.self_program_hash,
            right_pi,
        },
        u64::from(DOMAIN),
    )
    .map_err(|e| format!("prove AggMerge: {e:?}"))?;
    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;
    let t1 = Instant::now();
    verify_agg_merge(
        &merge_prog,
        &left_pi,
        &right_pi,
        &expected,
        u64::from(DOMAIN),
        &vm_proof,
    )
    .map_err(|e| format!("verify AggMerge: {e:?}"))?;
    let verify_ms = t1.elapsed().as_secs_f64() * 1e3;
    println!(
        "| AggMerge (BudAir + BoundKeccakAir) | {} | {} | {} | {:.1} | {:.1} |",
        vm_proof.steps,
        vm_proof.trace_rows,
        vm_proof.vm_proof.proof_bytes.len(),
        prove_ms,
        verify_ms
    );

    // 2. Measure StarkBackend recursive MasterProofs (16 / 64 / 256 / 1024 claims).
    println!();
    println!("### 2. StarkBackend Recursive MasterProof (16 / 64 / 256 / 1024 Claims)");
    println!("| Total claims | Ticks | Proof bytes | Master prove ms | Master verify ms |");
    println!("|---:|---:|---:|---:|---:|");

    let default_params = AggParams::default();
    let limits = FrameLimits::from(&default_params);
    let backend = StarkBackend::new(registry.clone(), limits, STARK_PARAMETER_SET);

    let pool_1024 = build_pool_items(1024, &registry)?;
    for &(total, ticks) in &[(16usize, 1usize), (64, 2), (256, 2), (1024, 4)] {
        let per_tick = total / ticks;
        let t_start = Instant::now();
        let mut frames = Vec::with_capacity(ticks);
        for t in 0..ticks {
            let slice = &pool_1024[t * per_tick..(t + 1) * per_tick];
            let frame = backend
                .prove_tick(
                    &TickCtx {
                        domain: DOMAIN,
                        aggregator: Address::from([0xA0 + t as u8; 32]),
                    },
                    slice,
                )
                .map_err(|e| format!("prove_tick: {e:?}"))?;
            frames.push(frame);
        }
        while frames.len() > 1 {
            let mut next = Vec::with_capacity(frames.len() / 2);
            let mut iter = frames.into_iter();
            while let Some(left) = iter.next() {
                if let Some(right) = iter.next() {
                    let proof = backend
                        .prove_merge(&left, &right)
                        .map_err(|e| format!("prove_merge: {e:?}"))?;
                    let combined = ClaimFrame::combine(&left, &right, proof)
                        .map_err(|e| format!("combine: {e:?}"))?;
                    next.push(combined);
                } else {
                    next.push(left);
                }
            }
            frames = next;
        }
        let master = frames
            .pop()
            .ok_or_else(|| "missing master frame".to_string())?;
        let total_prove_ms = t_start.elapsed().as_secs_f64() * 1e3;

        let t_ver = Instant::now();
        backend
            .verify(&master, DOMAIN)
            .map_err(|e| format!("verify master: {e:?}"))?;
        let total_verify_ms = t_ver.elapsed().as_secs_f64() * 1e3;

        println!(
            "| {} | {} | {} | {:.1} | {:.1} |",
            total,
            ticks,
            master.proof.len(),
            total_prove_ms,
            total_verify_ms
        );
    }

    // 3. Measure 10,000-block ShadowAuditor parity.
    println!();
    println!("### 3. Shadow Mode 10,000-Block Parity Audit");
    println!("| Blocks | Txs checked | Matches | Mismatches | Total ms |");
    println!("|---:|---:|---:|---:|---:|");
    let wallet = WalletKeyPair::from_seed(&[0x77; 32]);
    let mut tx = Transaction::new_with_fee(
        wallet.address(),
        Address::from([0x22; 32]),
        10,
        100_000,
        0,
        Vec::new(),
    );
    tx.chain_id = u64::from(DOMAIN);
    tx.sign_v5(&wallet);
    let prev_hash = "00".repeat(32);
    let mut auditor = ShadowAuditor::new(
        registry,
        AggParams {
            mode: AggMode::Shadow,
            ..AggParams::default()
        },
    );
    let t_shadow = Instant::now();
    for height in 1u64..=10_000 {
        let block = Block::new_with_chain_id(
            height,
            prev_hash.clone(),
            vec![tx.clone()],
            u64::from(DOMAIN),
        );
        let matched = auditor.audit_block(&block)?;
        if !matched {
            return Err(format!("shadow mismatch at height {height}"));
        }
    }
    let shadow_ms = t_shadow.elapsed().as_secs_f64() * 1e3;
    let r = auditor.report();
    println!(
        "| {} | {} | {} | {} | {:.1} |",
        r.blocks_audited, r.txs_checked, r.matches, r.mismatches, shadow_ms
    );
    Ok(())
}
