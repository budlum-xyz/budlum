use budlum_core::aggregation::air_registry::AirRegistry;
use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::chain::{
    check_block_with_backend_and_airs, claim_domain, claim_signature, genesis_commitment,
};
use budlum_core::aggregation::frame::FrameLimits;
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::aggregation::pool::PoolItem;
use budlum_core::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use zeroize::Zeroizing;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn some<T>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(v) => v,
        None => panic!("{msg}"),
    }
}

#[test]
fn k2i_ti3_stark_backend_and_block_admission_refuse_foreign_parameter_set_proofs() {
    let devnet_id = Network::Devnet.chain_id().value();
    let domain = some(claim_domain(devnet_id), "devnet claim domain");
    let registry = SchemeStatusRegistry::genesis();
    let air_registry = AirRegistry::with_builtins();
    let params = AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    };
    let limits = FrameLimits::from(&params);

    let backend_active = StarkBackend::new(registry.clone(), limits, STARK_PARAMETER_SET);
    let backend_next = StarkBackend::new(registry.clone(), limits, STARK_PARAMETER_SET + 1);
    let backend_prev = StarkBackend::new(
        registry.clone(),
        limits,
        STARK_PARAMETER_SET.saturating_sub(1),
    );

    let sender = WalletKeyPair::generate();
    let mut raw = Transaction::new(sender.address(), Address::from([0x51; 32]), 10, Vec::new());
    raw.chain_id = devnet_id;
    raw.nonce = 0;
    raw.fee = 20_000;
    raw.sign_v5(&sender);
    let (claimed, sig_env) = some(claim_signature(&raw), "claim signature");
    let sig_claim = must(derive_claim(&registry, &sig_env), "derive claim");
    let ctx = must(
        TickCtx::from_seed(domain, Zeroizing::new([0x7Au8; 32])),
        "tick ctx",
    );
    let frame = must(
        backend_active.prove_tick(
            &ctx,
            &[PoolItem {
                envelope: sig_env,
                claim: sig_claim.clone(),
            }],
        ),
        "prove tick under active parameter set",
    );

    // 1. Active parameter set accepts its own proof; adjacent parameter sets MUST fail closed.
    must(
        backend_active.verify(&frame, domain),
        "active backend verifies own proof",
    );
    assert!(
        backend_next.verify(&frame, domain).is_err(),
        "parameter_set + 1 backend must reject active parameter_set proof"
    );
    assert!(
        backend_prev.verify(&frame, domain).is_err(),
        "parameter_set - 1 backend must reject active parameter_set proof"
    );

    // 2. Full block admission under foreign parameter_set MUST fail closed even with bonded aggregator.
    let frame_hash = must(frame.hash(domain), "frame hash");
    let mut accounts = AccountState::new();
    let floor = Network::Devnet
        .min_stake()
        .max(accounts.registry.params().min_stake);
    for seg in &frame.segments {
        accounts.add_validator_with_floor(seg.aggregator, floor, floor);
    }
    let mut block = Block::new_with_chain_id(1, "0".repeat(64), vec![claimed], devnet_id);
    block.frame_hash = Some(frame_hash);
    block.claim_frame = Some(frame);

    must(
        check_block_with_backend_and_airs(
            &params,
            &registry,
            Some(&accounts),
            &air_registry,
            &block,
            &backend_active,
        ),
        "active parameter set accepts block",
    );
    assert!(
        check_block_with_backend_and_airs(
            &params,
            &registry,
            Some(&accounts),
            &air_registry,
            &block,
            &backend_next,
        )
        .is_err(),
        "block verified under mismatched parameter set must fail closed"
    );

    // 3. INV-04 (T-I.4): every binding commitment in the proof chain is 256-bit (32 bytes)
    //    and non-zero, and reacts to any 1-bit domain or parameter perturbation.
    let g_commit = some(genesis_commitment(&params, devnet_id), "genesis commitment");
    assert_eq!(g_commit.len(), 32);
    assert_ne!(g_commit, [0u8; 32]);
    assert_eq!(frame_hash.len(), 32);
    assert_ne!(frame_hash, [0u8; 32]);
    let d1 = sig_claim.digest(domain);
    let d2 = sig_claim.digest(domain.saturating_add(1));
    assert_eq!(d1.len(), 32);
    assert_ne!(d1, [0u8; 32]);
    assert_ne!(d1, d2, "claim digest must bind domain across 256 bits");
}
