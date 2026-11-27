//! End-to-end node shadow-mode hook tests (`AggMode::Shadow`).
//!
//! Verifies that committing blocks through `Blockchain` (`produce_block`,
//! `validate_and_add_block`, and `try_reorg`) drives `ShadowAuditor::audit_block_in`
//! against the live `SchemeStatusRegistry`, exports the four `budlum_agg_shadow_*`
//! Prometheus metrics without mutating consensus state, and keeps `AggMode::Off`
//! chains inactive with zeroed shadow gauges.

use std::sync::Arc;

use budlum_core::aggregation::params::{AggMode, AggParams};
use budlum_core::aggregation::shadow::ShadowAuditor;
use budlum_core::chain::blockchain::Blockchain;
use budlum_core::chain::genesis::GenesisConfig;
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::chain_config::Network;
use budlum_core::core::metrics::Metrics;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::SchemeStatusRegistry;

const DEVNET_CHAIN_ID: u64 = 45_262;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn must_some<T>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(v) => v,
        None => panic!("{msg}: None"),
    }
}

fn genesis_with_mode(chain_id: u64, mode: AggMode, funded: &[(Address, u64)]) -> GenesisConfig {
    let mut cfg = GenesisConfig::new(chain_id);
    cfg.aggregation = Some(AggParams {
        mode,
        ..AggParams::default()
    });
    for (addr, amount) in funded {
        cfg = cfg.with_allocation(*addr, *amount);
    }
    cfg
}

fn signed_v5_transfer(
    wallet: &WalletKeyPair,
    to: Address,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let mut tx = Transaction::new_with_chain_id(
        wallet.address(),
        to,
        1_000,
        100_000,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Transfer,
    );
    tx.sign_v5(wallet);
    tx
}

#[test]
fn shadow_mode_blockchain_audits_produced_and_validated_blocks_and_exports_metrics() {
    let sender = WalletKeyPair::from_seed(&[0x31; 32]);
    let recipient = Address::from([0x44; 32]);
    let miner = Address::from([0x55; 32]);

    let shadow_genesis = genesis_with_mode(
        DEVNET_CHAIN_ID,
        AggMode::Shadow,
        &[(sender.address(), 10_000_000)],
    );
    let off_genesis = genesis_with_mode(
        DEVNET_CHAIN_ID,
        AggMode::Off,
        &[(sender.address(), 10_000_000)],
    );

    let producer_metrics = Arc::new(must(Metrics::new(), "metrics build"));
    let validator_metrics = Arc::new(must(Metrics::new(), "metrics build"));

    let mut producer = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(shadow_genesis.clone()),
    )
    .with_metrics(Arc::clone(&producer_metrics));

    let mut validator = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(shadow_genesis),
    )
    .with_metrics(Arc::clone(&validator_metrics));

    let mut off_chain = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(off_genesis),
    );

    let tx = signed_v5_transfer(&sender, recipient, 0, DEVNET_CHAIN_ID);
    must(
        producer.add_transaction(tx.clone()),
        "shadow producer admits inline PQ tx",
    );
    must(
        off_chain.add_transaction(tx),
        "off chain admits identical inline PQ tx",
    );

    let (block, _) = must_some(producer.produce_block(miner), "shadow block produced");
    let (off_block, _) = must_some(off_chain.produce_block(miner), "off block produced");

    assert!(
        block.claim_frame.is_none(),
        "shadow mode must never publish an aggregation frame"
    );
    assert_eq!(
        block.state_root, off_block.state_root,
        "shadow mode must be consensus-identical to AggMode::Off"
    );

    must(
        validator.validate_and_add_block(block),
        "shadow validator commits produced block",
    );

    for (label, m) in [
        ("producer", Arc::clone(&producer_metrics)),
        ("validator", Arc::clone(&validator_metrics)),
    ] {
        assert_eq!(m.agg_shadow_blocks_audited.get(), 1, "{label}");
        assert_eq!(m.agg_shadow_txs_checked.get(), 1, "{label}");
        assert_eq!(m.agg_shadow_matches.get(), 1, "{label}");
        assert_eq!(m.agg_shadow_mismatches.get(), 0, "{label}");
        let scrape = m.encode();
        for expected_line in [
            "budlum_agg_shadow_blocks_audited 1",
            "budlum_agg_shadow_txs_checked 1",
            "budlum_agg_shadow_matches 1",
            "budlum_agg_shadow_mismatches 0",
        ] {
            assert!(
                scrape.contains(expected_line),
                "{label} scrape missing '{expected_line}'; scrape head: {}",
                scrape.chars().take(400).collect::<String>()
            );
        }
    }
}

#[test]
fn off_mode_blockchain_refuses_shadow_report_and_keeps_shadow_metrics_zero() {
    let sender = WalletKeyPair::from_seed(&[0x32; 32]);
    let miner = Address::from([0x56; 32]);
    let off_genesis = genesis_with_mode(
        DEVNET_CHAIN_ID,
        AggMode::Off,
        &[(sender.address(), 10_000_000)],
    );
    let metrics = Arc::new(must(Metrics::new(), "metrics build"));

    let mut bc = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(off_genesis),
    )
    .with_metrics(Arc::clone(&metrics));

    assert_eq!(metrics.agg_shadow_blocks_audited.get(), 0);
    let _ = must_some(bc.produce_block(miner), "off block produced");
    assert_eq!(
        metrics.agg_shadow_blocks_audited.get(),
        0,
        "producing a block in AggMode::Off must keep shadow blocks audited at 0"
    );

    let scrape = metrics.encode();
    for expected_line in [
        "budlum_agg_shadow_blocks_audited 0",
        "budlum_agg_shadow_txs_checked 0",
        "budlum_agg_shadow_matches 0",
        "budlum_agg_shadow_mismatches 0",
    ] {
        assert!(scrape.contains(expected_line), "missing '{expected_line}'");
    }
    assert_ne!(metrics.blocks_produced.get(), 0);
}

#[test]
fn shadow_mode_blockchain_reorg_audits_new_branch_blocks() {
    let sender = WalletKeyPair::from_seed(&[0x33; 32]);
    let recipient = Address::from([0x47; 32]);
    let miner_a = Address::from([0x57; 32]);
    let miner_b = Address::from([0x58; 32]);

    let shadow_genesis = genesis_with_mode(
        DEVNET_CHAIN_ID,
        AggMode::Shadow,
        &[(sender.address(), 20_000_000)],
    );
    let metrics_a = Arc::new(must(Metrics::new(), "metrics build"));

    let mut chain_a = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(shadow_genesis.clone()),
    )
    .with_metrics(Arc::clone(&metrics_a));
    let mut chain_b = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        DEVNET_CHAIN_ID,
        None,
        Some(shadow_genesis),
    );

    let _ = must_some(chain_a.produce_block(miner_a), "a1");

    let tx_b = signed_v5_transfer(&sender, recipient, 0, DEVNET_CHAIN_ID);
    must(chain_b.add_transaction(tx_b), "b admits tx");
    let _ = must_some(chain_b.produce_block(miner_b), "b1");
    let _ = must_some(chain_b.produce_block(miner_b), "b2");

    let candidate = chain_b.chain.clone();
    let switched = must(chain_a.try_reorg(candidate), "reorg succeeds");
    assert!(switched, "heavier chain_b must win reorg");

    assert!(
        metrics_a.agg_shadow_blocks_audited.get() >= 3,
        "initial block + 2 reorg blocks should be audited: {}",
        metrics_a.agg_shadow_blocks_audited.get()
    );
    assert_eq!(metrics_a.agg_shadow_txs_checked.get(), 1);
    assert_eq!(metrics_a.agg_shadow_matches.get(), 1);
    assert_eq!(metrics_a.agg_shadow_mismatches.get(), 0);

    let scrape = metrics_a.encode();
    assert!(scrape.contains("budlum_agg_shadow_txs_checked 1"));
    assert!(scrape.contains("budlum_agg_shadow_matches 1"));
    assert!(scrape.contains("budlum_agg_shadow_mismatches 0"));
}

#[test]
fn shadow_auditor_rejects_divergence_and_honors_live_scheme_registry() {
    let mainnet_id = Network::Mainnet.chain_id().value();
    let wallet = WalletKeyPair::from_seed(&[0x34; 32]);
    let tx_mainnet_v5 = signed_v5_transfer(&wallet, Address::from([0x49; 32]), 0, mainnet_id);

    let shadow_params = AggParams {
        mode: AggMode::Shadow,
        ..AggParams::default()
    };
    let mut auditor = ShadowAuditor::new(SchemeStatusRegistry::genesis(), shadow_params);

    // Inline V5 is refused natively on mainnet while ML-DSA-87 claim derivation succeeds:
    // audit_block_in must report Ok(false) and count 1 mismatch.
    let mismatch_block =
        Block::new_with_chain_id(1, "00".repeat(32), vec![tx_mainnet_v5], mainnet_id);
    let live_registry = SchemeStatusRegistry::genesis();
    let res = must(
        auditor.audit_block_in(&mismatch_block, &live_registry),
        "mainnet domain fits DomainId",
    );
    assert!(!res, "diverging V5 policy must return Ok(false)");
    assert_eq!(auditor.report().blocks_audited, 1);
    assert_eq!(auditor.report().txs_checked, 1);
    assert_eq!(auditor.report().matches, 0);
    assert_eq!(auditor.report().mismatches, 1);

    // Out-of-range chain_id fails closed with Err.
    let mut bad_chain_block = Block::new_with_chain_id(1, "00".repeat(32), vec![], u64::MAX);
    bad_chain_block.chain_id = u64::MAX;
    match auditor.audit_block_in(&bad_chain_block, &live_registry) {
        Err(err) => assert!(err.contains("DomainId"), "unexpected error: {err}"),
        Ok(v) => panic!("u64::MAX does not fit DomainId and must fail closed, got Ok({v})"),
    }
}
