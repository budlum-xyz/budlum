//! Task 9 audit autopsy (2026-07-18, ARENA3):
//! This file previously claimed "100+ unique tests" with 140 functions.
//! Body-hash analysis showed only 6 unique behaviors: 80 literal
//! `assert!(true);` calls, plus 5 behaviors copied 10-20 times with only
//! magic constants changed (nft/bns/market/relay/state). The 134 padding
//! copies were removed with zero behavior loss and consolidated into the
//! table-driven tests below (6 behaviors preserved, 1 negative added).
//!
//! Union rule (docs/STATUS_ONLINE.md): a test count is only reportable
//! from a CI summary line (libtest "test result:" / nextest "Summary"),
//! never from hand counts, file greps, or chat claims.

use crate::bns::{BnsError, BnsRegistry};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::cross_domain::relayer::{RelayerConfig, UniversalRelayer};
use crate::pollen::MarketplaceRegistry;
use crate::socialfi::NftRegistry;
use crate::storage::content_id::ContentId;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn cid(b: u8) -> ContentId {
    ContentId([b; 32])
}

/// Ten distinct mints must yield ten distinct, retrievable token ids
/// (consolidates the former nft_test_val_1..10 copies).
#[test]
fn nft_mint_table_distinct_ids() {
    let mut r = NftRegistry::new();
    let mut ids = Vec::new();
    for i in 1..=10u8 {
        let id = r.mint(addr(i), cid(i), i as u64, None);
        ids.push(id);
    }
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "mint must never reuse a token id");
    for id in &ids {
        assert!(
            r.get_nft(*id).is_some(),
            "minted token {id} must be retrievable"
        );
    }
}

/// Ten distinct names register and resolve back to their owners
/// (consolidates the former bns_test_val_1..10 copies).
#[test]
fn bns_register_table_resolves_owners() {
    let mut r = BnsRegistry::new();
    for i in 1..=10u8 {
        let name = format!("{i}.bud");
        r.register(name.clone(), addr(i), 0, 1000).unwrap();
        assert_eq!(r.resolve(&name, 0), Some(addr(i)), "{name} owner mismatch");
    }
}

/// Registering the same live name twice is rejected (new negative case).
#[test]
fn bns_register_duplicate_live_name_rejected() {
    let mut r = BnsRegistry::new();
    r.register("arena.bud".into(), addr(1), 0, 1000).unwrap();
    assert!(matches!(
        r.register("arena.bud".into(), addr(2), 0, 1000),
        Err(BnsError::NameTaken)
    ));
}

/// Ten distinct offers are created and retrievable by id
/// (consolidates the former market_test_val_1..10 copies).
#[test]
fn market_create_offer_table() {
    let mut r = MarketplaceRegistry::new();
    for i in 1..=10u8 {
        let id = r.create_offer(addr(i), cid(i), i as u64).unwrap();
        assert!(r.get_offer(id).is_some(), "created offer {id} missing");
    }
}

/// A fresh relayer has no pending relays
/// (consolidates the former relay_test_val_1..10 copies).
#[test]
fn relayer_starts_empty() {
    let r = UniversalRelayer::new(RelayerConfig::default());
    assert_eq!(r.pending_count(), 0);
}

/// A fresh account state starts at epoch 0
/// (consolidates the former state_test_val_1..20 copies).
#[test]
fn account_state_genesis_defaults() {
    let s = AccountState::new();
    assert_eq!(s.epoch_index, 0);
}
