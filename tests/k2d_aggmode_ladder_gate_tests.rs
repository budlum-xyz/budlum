use budlum_core::aggregation::air_registry::AirRegistry;
use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::chain::{
    check_block_with_backend_and_airs, claim_domain, claim_signature, genesis_commitment,
    validate_params,
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
fn k2d_td1_testnet_and_mainnet_refuse_agg_mode_on_when_ladder_conditions_not_met() {
    let mainnet_id = Network::Mainnet.chain_id().value();
    let testnet_id = Network::Testnet.chain_id().value();
    let registry = SchemeStatusRegistry::genesis();
    let air_registry = AirRegistry::with_builtins();

    // 1. Default AggMode::On (activation_height=None, require_proven_ticks=false) fails closed.
    let unconfigured = AggParams {
        mode: AggMode::On,
        ..AggParams::default()
    };
    assert!(validate_params(&unconfigured, testnet_id).is_err());
    assert!(validate_params(&unconfigured, mainnet_id).is_err());

    // 2. activation_height=Some(0) or require_proven_ticks=false still fails closed on Testnet.
    let zero_height = AggParams {
        mode: AggMode::On,
        activation_height: Some(0),
        require_proven_ticks: true,
        ..AggParams::default()
    };
    assert!(validate_params(&zero_height, testnet_id).is_err());

    let no_proven_ticks = AggParams {
        mode: AggMode::On,
        activation_height: Some(100),
        require_proven_ticks: false,
        ..AggParams::default()
    };
    assert!(validate_params(&no_proven_ticks, testnet_id).is_err());

    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&no_proven_ticks),
        STARK_PARAMETER_SET,
    );
    let block = Block::new_with_chain_id(150, "0".repeat(64), Vec::new(), testnet_id);
    assert!(check_block_with_backend_and_airs(
        &no_proven_ticks,
        &registry,
        Some(&AccountState::new()),
        &air_registry,
        &block,
        &backend,
    )
    .is_err());

    // 3. Mainnet remains closed even when Rung-4 Testnet flags are set.
    let rung4 = AggParams {
        mode: AggMode::On,
        activation_height: Some(100),
        require_proven_ticks: true,
        ..AggParams::default()
    };
    assert!(validate_params(&rung4, mainnet_id).is_err());
    let mainnet_block = Block::new_with_chain_id(150, "0".repeat(64), Vec::new(), mainnet_id);
    assert!(check_block_with_backend_and_airs(
        &rung4,
        &registry,
        Some(&AccountState::new()),
        &air_registry,
        &mainnet_block,
        &backend,
    )
    .is_err());
}

#[test]
fn k2d_td1_testnet_accepts_agg_mode_on_at_activation_height_when_rung4_conditions_hold() {
    let testnet_id = Network::Testnet.chain_id().value();
    let domain = some(claim_domain(testnet_id), "testnet claim domain");
    let registry = SchemeStatusRegistry::genesis();
    let air_registry = AirRegistry::with_builtins();

    let rung4_h100 = AggParams {
        mode: AggMode::On,
        activation_height: Some(100),
        require_proven_ticks: true,
        ..AggParams::default()
    };
    let rung4_h200 = AggParams {
        activation_height: Some(200),
        ..rung4_h100
    };

    // 1. validate_params accepts Rung-4 Testnet params and genesis commitment binds activation_height.
    must(
        validate_params(&rung4_h100, testnet_id),
        "rung-4 testnet params accepted",
    );
    let c100 = some(genesis_commitment(&rung4_h100, testnet_id), "commit h100");
    let c200 = some(genesis_commitment(&rung4_h200, testnet_id), "commit h200");
    assert_ne!(c100, c200, "genesis commitment must bind activation_height");

    // 2. Build a real StarkBackend frame on Testnet domain.
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&rung4_h100),
        STARK_PARAMETER_SET,
    );
    let sender = WalletKeyPair::generate();
    let mut raw = Transaction::new(sender.address(), Address::from([0x33; 32]), 10, Vec::new());
    raw.chain_id = testnet_id;
    raw.nonce = 0;
    raw.fee = 20_000;
    raw.sign_v5(&sender);
    let (claimed, sig_env) = some(claim_signature(&raw), "claim signature");
    let sig_claim = must(derive_claim(&registry, &sig_env), "derive claim");
    let ctx = must(
        TickCtx::from_seed(domain, Zeroizing::new([0x91u8; 32])),
        "tick ctx",
    );
    let frame = must(
        backend.prove_tick(
            &ctx,
            &[PoolItem {
                envelope: sig_env,
                claim: sig_claim,
            }],
        ),
        "prove tick",
    );
    let frame_hash = must(frame.hash(domain), "frame hash");

    let mut accounts = AccountState::new();
    let floor = Network::Testnet
        .min_stake()
        .max(accounts.registry.params().min_stake);
    for seg in &frame.segments {
        accounts.add_validator_with_floor(seg.aggregator, floor, floor);
    }

    // 3. Pre-activation (height 99 < 100): ordinary empty block succeeds,
    //    but a block carrying a claim_frame BEFORE activation_height MUST fail closed.
    let pre_clean = Block::new_with_chain_id(99, "0".repeat(64), Vec::new(), testnet_id);
    must(
        check_block_with_backend_and_airs(
            &rung4_h100,
            &registry,
            Some(&accounts),
            &air_registry,
            &pre_clean,
            &backend,
        ),
        "clean pre-activation block accepted",
    );
    let mut pre_claimed =
        Block::new_with_chain_id(99, "0".repeat(64), vec![claimed.clone()], testnet_id);
    pre_claimed.frame_hash = Some(frame_hash);
    pre_claimed.claim_frame = Some(frame.clone());
    assert!(
        check_block_with_backend_and_airs(
            &rung4_h100,
            &registry,
            Some(&accounts),
            &air_registry,
            &pre_claimed,
            &backend,
        )
        .is_err(),
        "claim_frame before activation_height must fail closed"
    );

    // 4. At activation_height (height 100 >= 100): unbonded aggregator fails closed,
    //    bonded aggregator + real StarkBackend MasterProof succeeds!
    let mut active_block = Block::new_with_chain_id(100, "0".repeat(64), vec![claimed], testnet_id);
    active_block.frame_hash = Some(frame_hash);
    active_block.claim_frame = Some(frame);
    assert!(
        check_block_with_backend_and_airs(
            &rung4_h100,
            &registry,
            Some(&AccountState::new()),
            &air_registry,
            &active_block,
            &backend,
        )
        .is_err(),
        "unbonded aggregator at activation_height must fail closed"
    );
    must(
        check_block_with_backend_and_airs(
            &rung4_h100,
            &registry,
            Some(&accounts),
            &air_registry,
            &active_block,
            &backend,
        ),
        "bonded aggregator + real StarkBackend MasterProof accepted on Testnet at activation_height",
    );
}
