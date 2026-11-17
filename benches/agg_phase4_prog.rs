//! Phase 4 benchmark: hidden m-of-n multisig `Claim::Prog`, domain
//! state-transition `Claim::Prog`, and heterogeneous `MasterProof` finality.
//!
//! Run with:
//! `cargo bench --bench agg_phase4_prog`

use std::time::Instant;
use zeroize::Zeroizing;

use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::chain::{
    check_block_with_backend, claim_program_auth, claim_signature, settlement_of_with_accounts,
};
use budlum_core::aggregation::domain_finality::{
    compile_domain_transition, prove_domain_transition, ClaimedDomainFinalityAdapter,
};
use budlum_core::aggregation::frame::{ClaimFrame, FrameLimits};
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::aggregation::pool::PoolItem;
use budlum_core::aggregation::programs::hidden_multisig::{
    prove_hidden_multisig_auth, HiddenMultisigPolicy,
};
use budlum_core::aggregation::programs::prog_claim::verify_vm_proof;
use budlum_core::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use budlum_core::core::account::{Account, AccountState};
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::domain::finality_adapter::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainId, DomainStatus, RootScheme,
};

const DOMAIN: DomainId = 45262;
const CHAIN_ID: u64 = 45262;

fn main() -> Result<(), String> {
    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    };
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&params),
        STARK_PARAMETER_SET,
    );

    println!("=== Phase 4: Program Claims Benchmark ===");

    // 1. Domain state-transition BudVM + BudAir STARK proof
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
    let prev_height = 10u64;
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
        state_updates: std::collections::BTreeMap::new(),
    };
    let batch_digest = [0xAB; 32];

    let t2 = Instant::now();
    let dom_obj = prove_domain_transition(
        &dom_prog,
        &ext_domain,
        prev_height,
        &prev_root,
        &commitment,
        &batch_digest,
        DOMAIN,
    )
    .map_err(|e| format!("dom prove: {e}"))?;
    let dom_prove_ms = t2.elapsed().as_secs_f64() * 1000.0;

    let dom_encoded = dom_obj.encode().map_err(|e| format!("dom encode: {e}"))?;
    let t3 = Instant::now();
    let dom_claim = verify_vm_proof(DOMAIN, &dom_obj).map_err(|e| format!("dom verify: {e}"))?;
    let dom_verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
    let dom_claim_digest = dom_claim.digest(DOMAIN);

    println!(
        "Domain Transition (BudAir): steps={} raw_proof={} B compressed_obj={} B claim={} B prove={:.1} ms verify={:.1} ms",
        dom_obj.public_inputs.trace_len,
        dom_obj.proof_envelope.proof_bytes.len(),
        dom_encoded.len(),
        dom_claim.encode().len(),
        dom_prove_ms,
        dom_verify_ms
    );

    // 2. Hidden 2-of-3 multisig BudVM + BudAir STARK proof (authorizing a tx
    //    that also references the domain transition claim in claim_refs).
    let policy = HiddenMultisigPolicy::new(2, vec![101_001, 202_002, 303_003], 777_777)
        .map_err(|e| format!("policy: {e}"))?;
    let prog_addr = Address::from([0x77; 32]);
    let recipient = Address::from([0x88; 32]);
    let mut raw_tx = Transaction::new(prog_addr, recipient, 5_000, Vec::new());
    raw_tx.fee = 100_000;
    raw_tx.nonce = 0;
    raw_tx.chain_id = CHAIN_ID;
    raw_tx.claim_refs.push(dom_claim_digest);
    let msg_hash = raw_tx.signing_hash();

    let t0 = Instant::now();
    let (msig_prog, msig_obj) = prove_hidden_multisig_auth(&policy, &[0, 2], msg_hash, DOMAIN)
        .map_err(|e| format!("msig prove: {e}"))?;
    let msig_prove_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let msig_encoded = msig_obj.encode().map_err(|e| format!("msig encode: {e}"))?;
    let t1 = Instant::now();
    let msig_claim = verify_vm_proof(DOMAIN, &msig_obj).map_err(|e| format!("msig verify: {e}"))?;
    let msig_verify_ms = t1.elapsed().as_secs_f64() * 1000.0;

    println!(
        "Hidden 2-of-3 Multisig (BudAir): steps={} raw_proof={} B compressed_obj={} B claim={} B prove={:.1} ms verify={:.1} ms",
        msig_obj.public_inputs.trace_len,
        msig_obj.proof_envelope.proof_bytes.len(),
        msig_encoded.len(),
        msig_claim.encode().len(),
        msig_prove_ms,
        msig_verify_ms
    );

    // 3. Combined heterogeneous MasterProof: Hidden Multisig Prog + Domain Transition Prog + ML-DSA-87 Sig
    let (claimed_msig_tx, msig_env) =
        claim_program_auth(&raw_tx, msig_prog.program_hash, &msig_obj)
            .ok_or_else(|| "claim_program_auth returned None".to_string())?;
    let dom_env = dom_obj
        .to_envelope(DOMAIN, claimed_msig_tx.signing_hash())
        .map_err(|e| format!("dom env: {e}"))?;

    let kp = WalletKeyPair::generate();
    let mut sig_tx = Transaction::new(kp.address(), recipient, 1_000, Vec::new());
    sig_tx.fee = 100_000;
    sig_tx.nonce = 0;
    sig_tx.chain_id = CHAIN_ID;
    sig_tx.sign_v5(&kp);
    let (claimed_sig_tx, sig_env) =
        claim_signature(&sig_tx).ok_or_else(|| "claim_signature returned None".to_string())?;
    let sig_claim = derive_claim(&registry, &sig_env).map_err(|e| format!("sig claim: {e}"))?;

    let t4 = Instant::now();
    let tick_prog = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xA1; 32]))
                .map_err(|e| format!("ctx1: {e}"))?,
            &[
                PoolItem {
                    envelope: msig_env,
                    claim: msig_claim,
                },
                PoolItem {
                    envelope: dom_env,
                    claim: dom_claim,
                },
            ],
        )
        .map_err(|e| format!("tick_prog: {e}"))?;
    let tick_sig = backend
        .prove_tick(
            &TickCtx::from_seed(DOMAIN, Zeroizing::new([0xA2; 32]))
                .map_err(|e| format!("ctx2: {e}"))?,
            &[PoolItem {
                envelope: sig_env,
                claim: sig_claim,
            }],
        )
        .map_err(|e| format!("tick_sig: {e}"))?;
    let merged_proof = backend
        .prove_merge(&tick_prog, &tick_sig)
        .map_err(|e| format!("merge: {e}"))?;
    let master = ClaimFrame::combine(&tick_prog, &tick_sig, merged_proof)
        .map_err(|e| format!("frame combine: {e}"))?;
    let master_prove_ms = t4.elapsed().as_secs_f64() * 1000.0;

    let mut state = AccountState::new();
    state.accounts.insert(
        prog_addr,
        Account::with_auth_program(prog_addr, 10_000_000, msig_prog.program_hash),
    );
    let mut block = Block::new_with_chain_id(
        1,
        "0".repeat(64),
        vec![claimed_msig_tx, claimed_sig_tx],
        CHAIN_ID,
    );
    block.frame_hash = Some(master.hash(DOMAIN).map_err(|e| format!("hash: {e}"))?);
    block.claim_frame = Some(master.clone());

    let t5 = Instant::now();
    check_block_with_backend(&params, &registry, Some(&state), &block, &backend)?;
    let block_verify_ms = t5.elapsed().as_secs_f64() * 1000.0;
    let settlement = settlement_of_with_accounts(&params, Some(&state), &block)?;
    if settlement.failed.contains(&true) {
        return Err("unexpected claim fee failure".into());
    }

    let mut adapter = ClaimedDomainFinalityAdapter::new(DOMAIN);
    adapter.register_domain_program(ext_domain.id, dom_prog.program_hash);
    adapter
        .admit_verified_frame(&backend, &master)
        .map_err(|e| format!("admit frame: {e}"))?;
    let fin_proof = FinalityProof::AggregatedProg {
        program_hash: dom_prog.program_hash,
        prev_height,
        prev_state_root: prev_root,
        claim_digest: dom_claim_digest,
    };
    let t6 = Instant::now();
    let status = adapter
        .verify_finality(&ext_domain, &commitment, &fin_proof)
        .map_err(|e| format!("finality: {e}"))?;
    let finality_us = t6.elapsed().as_secs_f64() * 1_000_000.0;
    if status != FinalityStatus::Finalized {
        return Err(format!("expected Finalized, got {status:?}"));
    }

    println!(
        "Heterogeneous MasterProof (2 Prog + 1 Sig): proof={} B (budget={} B) agg_prove={:.1} ms block_verify={:.1} ms adapter_finality={:.1} us",
        master.proof.len(),
        params.max_proof_bytes,
        master_prove_ms,
        block_verify_ms,
        finality_us
    );
    Ok(())
}
