//! Expanded BNS Registry tests coverage.

use crate::bns::types::BnsError;
use crate::bns::BnsRegistry;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

#[test]
fn test_bns_cost_scaling() {
    let reg = BnsRegistry::new();

    // 3-char label (excluding `.bud`) pays 100x base cost
    let cost_short = reg.calculate_cost("abc.bud", 1); // 100 * 100 * 1 = 10,000

    // 4..=6-char label pays 10x base cost
    let cost_med = reg.calculate_cost("abcde.bud", 1); // 100 * 10 * 1 = 1,000

    // 7..=32-char label pays 1x base cost
    let cost_long = reg.calculate_cost("abcdefgh.bud", 1); // 100 * 1 * 1 = 100

    assert_eq!(cost_short, 100 * cost_long);
    assert_eq!(cost_med, 10 * cost_long);
    assert!(cost_short > cost_med);
    assert!(cost_med > cost_long);
}

#[test]
fn test_bns_renewal() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("test.bud".to_string(), alice, 0, 100).unwrap();
    assert_eq!(reg.resolve("test.bud", 50), Some(alice));

    // Only the current owner may renew.
    assert!(matches!(
        reg.renew("test.bud", &bob, 50, 200),
        Err(BnsError::NotOwner)
    ));

    // Renewal extends from the current expiry (100 + 200 = 300).
    reg.renew("test.bud", &alice, 50, 200).unwrap();
    assert_eq!(reg.resolve("test.bud", 150), Some(alice));
    assert_eq!(reg.resolve("test.bud", 250), Some(alice));
    assert_eq!(reg.resolve("test.bud", 350), None);

    // Expired names cannot be renewed; they become re-registerable.
    assert!(matches!(
        reg.renew("test.bud", &alice, 400, 100),
        Err(BnsError::Expired)
    ));
    // F14: grace-period - expire (350) + GRACE_PERIOD (3000)
    // no third party can squat inside it. epoch 400 < 3350, so bob is REFUSED.
    assert!(matches!(
        reg.register("test.bud".to_string(), bob, 400, 100),
        Err(BnsError::NameTaken)
    ));
    // After the grace period (epoch 3360 > 3350) bob may register.
    reg.register("test.bud".to_string(), bob, 3360, 100)
        .unwrap();
    assert_eq!(reg.resolve("test.bud", 3370), Some(bob));
}

#[test]
fn test_bns_subdomains_owner_only() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("alice.bud".to_string(), alice, 0, 1000)
        .unwrap();

    // Alice can create subdomain
    reg.register_subdomain("alice.bud", "app".to_string(), bob, &alice, 0)
        .unwrap();

    assert_eq!(reg.resolve_subdomain("alice.bud", "app", 100), Some(bob));

    // Bob (not owner of parent) cannot create subdomain under alice.bud
    let res = reg.register_subdomain("alice.bud", "malicious".to_string(), bob, &bob, 0);
    assert!(res.is_err());
}

#[test]
fn test_bns_invalid_names() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);

    // Empty name
    assert_eq!(
        reg.register(String::new(), alice, 0, 100),
        Err(BnsError::InvalidName)
    );

    // Suffixless label `bids` is rejected; `bids.bud` is accepted; `ab.bud` (< 3 label chars) is rejected.
    assert_eq!(
        reg.register("bids".to_string(), alice, 0, 100),
        Err(BnsError::InvalidName)
    );
    assert_eq!(
        reg.register("ab.bud".to_string(), alice, 0, 100),
        Err(BnsError::InvalidName)
    );
    reg.register("bids.bud".to_string(), alice, 0, 100).unwrap();

    // Label length excludes `.bud`: 32-char label passes, 33-char label fails.
    reg.register(format!("{}.bud", "a".repeat(32)), alice, 0, 100)
        .unwrap();
    assert_eq!(
        reg.register(format!("{}.bud", "a".repeat(33)), alice, 0, 100),
        Err(BnsError::InvalidName)
    );
}

#[test]
fn test_bns_transfer() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    reg.register("transfer.bud".to_string(), alice, 0, 1000)
        .unwrap();

    // A live name cannot be re-registered by anyone (NameTaken guard is the
    // Anti-hijack invariant).
    assert!(matches!(
        reg.register("transfer.bud".to_string(), bob, 10, 1000),
        Err(BnsError::NameTaken)
    ));

    // Only the current owner may transfer.
    assert!(matches!(
        reg.transfer("transfer.bud", &bob, bob, 10),
        Err(BnsError::NotOwner)
    ));

    // Ownership moves to Bob: resolution follows the new owner and the
    // Previous owner loses control over the record (e.g. subdomains).
    reg.transfer("transfer.bud", &alice, bob, 10).unwrap();
    assert_eq!(reg.resolve("transfer.bud", 100), Some(bob));
    assert!(matches!(
        reg.register_subdomain("transfer.bud", "ghost".to_string(), alice, &alice, 10),
        Err(BnsError::NotOwner)
    ));
    reg.register_subdomain("transfer.bud", "app".to_string(), alice, &bob, 10)
        .unwrap();
    assert_eq!(
        reg.resolve_subdomain("transfer.bud", "app", 100),
        Some(alice)
    );
}

#[test]
fn test_bns_full_resolve_with_storage() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let cid = [7u8; 32];

    reg.register("storage.bud".to_string(), alice, 0, 1000)
        .unwrap();
    reg.set_storage("storage.bud", alice, cid, 1, 10).unwrap();

    let resolved = reg.resolve_full("storage.bud", 10).unwrap();
    assert_eq!(resolved.owner, alice);
    assert_eq!(resolved.storage_root, Some(cid));
    assert_eq!(resolved.storage_domain_id, Some(1));
}

#[test]
fn bns_lifecycle_doors_reject_zero_duration_and_zero_owner() {
    let alice = Address::from([1u8; 32]);
    let mut reg = BnsRegistry::new();
    reg.register("term.bud".into(), alice, 0, 100).unwrap();

    assert_eq!(
        reg.renew("term.bud", &alice, 10, 0),
        Err(BnsError::InvalidDuration),
        "a renewal must extend the registration"
    );
    assert_eq!(
        reg.transfer("term.bud", &alice, Address::zero(), 10),
        Err(BnsError::InvalidName),
        "a transfer must not create a name owned by the zero address"
    );
}

#[test]
fn test_bns_transfer_clears_previous_owner_pointers() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    reg.register("pointers.bud".to_string(), alice, 0, 1000)
        .unwrap();
    reg.register_subdomain("pointers.bud", "app".to_string(), alice, &alice, 0)
        .unwrap();
    reg.set_content(
        "pointers.bud",
        &alice,
        crate::storage::content_id::ContentId([9u8; 32]),
        0,
    )
    .unwrap();

    reg.transfer("pointers.bud", &alice, bob, 10).unwrap();
    let resolved = reg.resolve_full("pointers.bud", 100).unwrap();
    assert_eq!(resolved.address, Some(bob));
    assert_eq!(resolved.content_id, None);
    assert_eq!(reg.resolve_subdomain("pointers.bud", "app", 100), None);
}

#[test]
fn test_bns_expired_name_refuses_writes() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    reg.register("stale.bud".to_string(), alice, 0, 100)
        .unwrap();
    assert!(matches!(
        reg.register_subdomain("stale.bud", "app".to_string(), alice, &alice, 100),
        Err(BnsError::Expired)
    ));
    assert!(matches!(
        reg.set_content(
            "stale.bud",
            &alice,
            crate::storage::content_id::ContentId([1u8; 32]),
            100
        ),
        Err(BnsError::Expired)
    ));
}

#[test]
fn test_bns_default_registry_matches_new() {
    let reg = BnsRegistry::default();
    assert_eq!(reg.base_cost, BnsRegistry::new().base_cost);
    assert!(reg.is_empty());
}

#[test]
fn test_bns_register_refuses_expiry_overflow() {
    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    assert!(reg
        .register("overflow.bud".to_string(), alice, 1, u64::MAX)
        .is_err());
    assert!(reg.is_empty());
}

fn lifecycle_tx(
    from: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    tx_type: TransactionType,
    data: Vec<u8>,
) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee,
        nonce,
        data,
        DEFAULT_CHAIN_ID,
        tx_type,
    )
}

#[test]
fn bns_renew_and_transfer_execute_through_consensus_doors() {
    let key = KeyPair::from_seed(&[1u8; 32]).unwrap();
    let alice = Address::from(key.public_key_bytes());
    let bob = addr(2);
    let name = "term.bud".to_string();
    let duration = 100;
    let mut state = AccountState::new();
    state.add_balance(&alice, 500_000);
    state
        .bns_registry
        .register(name.clone(), alice, 0, duration)
        .unwrap();

    let cost = state.bns_registry.calculate_cost(&name, duration);
    let mut renewal = lifecycle_tx(
        alice,
        cost,
        1,
        0,
        TransactionType::BnsRenew,
        bincode::serialize(&(name.clone(), duration)).unwrap(),
    );
    renewal.sign(&key);
    state.validate_transaction(&renewal).unwrap();
    Executor::apply_transaction_checked(&mut state, &renewal).unwrap();
    assert_eq!(
        state.bns_registry.names.get(&name).unwrap().expires_at,
        200,
        "renewal extends from the old expiry"
    );
    assert_eq!(state.get_balance(&alice), 500_000 - cost - 1);
    assert_eq!(state.get_nonce(&alice), 1);

    let mut transfer = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsTransfer,
        bincode::serialize(&(name.clone(), bob)).unwrap(),
    );
    transfer.sign(&key);
    state.validate_transaction(&transfer).unwrap();
    Executor::apply_transaction_checked(&mut state, &transfer).unwrap();
    assert_eq!(state.bns_registry.resolve(&name, 100), Some(bob));
    assert_eq!(state.get_nonce(&alice), 2);

    let mut unauthorized = lifecycle_tx(
        alice,
        0,
        1,
        2,
        TransactionType::BnsTransfer,
        bincode::serialize(&(name, alice)).unwrap(),
    );
    unauthorized.sign(&key);
    state.validate_transaction(&unauthorized).unwrap();
    let error = Executor::apply_transaction_checked(&mut state, &unauthorized).unwrap_err();
    assert_eq!(error.code(), "bns_transfer_failed");
    assert_eq!(
        state.get_nonce(&alice),
        2,
        "refused transfers do not advance nonce"
    );
}

#[test]
fn bns_marketplace_primary_resale_cancel_expiry_and_governance() {
    use crate::bns::{CreateNameOffer, OfferKind};
    use crate::core::account::AccountState;
    use crate::core::governance::{GovernanceAction, ProposalStatus, ProposalType};
    use crate::core::transaction::TransactionType;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let primary_kp = KeyPair::generate().unwrap();
    let primary_seller = Address::from(primary_kp.public_key_bytes());
    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob_kp = KeyPair::generate().unwrap();
    let bob = Address::from(bob_kp.public_key_bytes());
    let outsider_kp = KeyPair::generate().unwrap();
    let outsider = Address::from(outsider_kp.public_key_bytes());

    let mut state = AccountState::new();
    state.base_fee = 1;
    state.epoch_index = 5;
    state.add_balance(&primary_seller, 100_000);
    state.add_balance(&alice, 500_000);
    state.add_balance(&bob, 500_000);
    state.add_balance(&outsider, 100_000);

    // 1. Non-primary seller cannot open a Primary offer.
    let mut unauth_primary = lifecycle_tx(
        outsider,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market.bud".to_string(),
            price_atoms: 40_000,
            duration: 500,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    unauth_primary.sign(&outsider_kp);
    assert!(state.validate_transaction(&unauth_primary).is_err());
    let err = Executor::apply_transaction_checked(&mut state, &unauth_primary).unwrap_err();
    assert_eq!(err.code(), "bns_unauthorized_primary_seller");

    // 2. Governance updates BNS_PRIMARY_SELLERS via GovernanceAction::BnsSetPrimarySellers.
    let prop_id = state
        .governance
        .create_proposal(
            primary_seller,
            ProposalType::BnsSetPrimarySellers {
                sellers: vec![primary_seller],
            },
            state.epoch_index,
            10,
        )
        .unwrap();
    state.governance.find_proposal_mut(prop_id).unwrap().status = ProposalStatus::Passed;
    let actions = state.governance.execute_passed_proposals(u64::MAX);
    assert_eq!(
        actions,
        vec![GovernanceAction::BnsSetPrimarySellers {
            sellers: vec![primary_seller]
        }]
    );
    state
        .bns_registry
        .set_primary_sellers(vec![primary_seller])
        .unwrap();
    assert!(state.bns_registry.is_primary_seller(&primary_seller));

    // 3. Authorized primary seller opens Primary offer #0 and Alice buys it;
    //    seller receives price_atoms and burned_total does NOT increase.
    let burned_before = state.burned_total;
    let seller_bal_before = state.get_balance(&primary_seller);
    let root_before_offer = state.calculate_state_root();

    let mut create_primary = lifecycle_tx(
        primary_seller,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market.bud".to_string(),
            price_atoms: 40_000,
            duration: 500,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    create_primary.sign(&primary_kp);
    state.validate_transaction(&create_primary).unwrap();
    Executor::apply_transaction_checked(&mut state, &create_primary).unwrap();
    assert_ne!(
        root_before_offer,
        state.calculate_state_root(),
        "opening a NameOffer must change AccountState root"
    );

    let mut buy_primary = lifecycle_tx(
        alice,
        40_000,
        1,
        0,
        TransactionType::BnsBuyName,
        bincode::serialize(&0u64).unwrap(),
    );
    buy_primary.sign(&alice_kp);
    state.validate_transaction(&buy_primary).unwrap();
    Executor::apply_transaction_checked(&mut state, &buy_primary).unwrap();

    assert_eq!(state.bns_registry.resolve("market.bud", 5), Some(alice));
    assert_eq!(
        state.get_balance(&primary_seller),
        seller_bal_before - 1 + 40_000,
        "Primary sale pays seller instead of burning"
    );
    assert_eq!(
        state.burned_total, burned_before,
        "Primary sale must not burn"
    );
    assert!(!state.marketplace.get_name_offer(0).unwrap().active);

    // 4. Alice sets content + subdomain, then lists `market.bud` as Resale (#1);
    //    Bob buys it -> ownership moves to Bob, Alice is paid, pointers are cleared!
    state
        .bns_registry
        .set_content(
            "market.bud",
            &alice,
            crate::storage::content_id::ContentId([0xAB; 32]),
            5,
        )
        .unwrap();
    state
        .bns_registry
        .register_subdomain("market.bud", "blog".into(), alice, &alice, 5)
        .unwrap();

    let mut create_resale = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market.bud".to_string(),
            price_atoms: 75_000,
            duration: 0,
            kind: OfferKind::Resale,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    create_resale.sign(&alice_kp);
    state.validate_transaction(&create_resale).unwrap();
    Executor::apply_transaction_checked(&mut state, &create_resale).unwrap();

    let alice_before_resale = state.get_balance(&alice);
    let mut buy_resale = lifecycle_tx(
        bob,
        75_000,
        1,
        0,
        TransactionType::BnsBuyName,
        bincode::serialize(&1u64).unwrap(),
    );
    buy_resale.sign(&bob_kp);
    state.validate_transaction(&buy_resale).unwrap();
    Executor::apply_transaction_checked(&mut state, &buy_resale).unwrap();

    assert_eq!(state.bns_registry.resolve("market.bud", 5), Some(bob));
    assert_eq!(state.bns_registry.resolve_content("market.bud", 5), None);
    assert_eq!(
        state
            .bns_registry
            .resolve_subdomain("market.bud", "blog", 5),
        None
    );
    assert_eq!(state.get_balance(&alice), alice_before_resale + 75_000);
    assert_eq!(state.burned_total, burned_before, "Resale must not burn");

    // 5. Cancelled offer and expired offer and stale offer (sold/transferred away) all fail closed.
    let mut offer_to_cancel = lifecycle_tx(
        bob,
        0,
        1,
        1,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market.bud".to_string(),
            price_atoms: 10_000,
            duration: 0,
            kind: OfferKind::Resale,
            expires_at_epoch: 20,
        })
        .unwrap(),
    );
    offer_to_cancel.sign(&bob_kp);
    Executor::apply_transaction_checked(&mut state, &offer_to_cancel).unwrap(); // id = 2

    let mut cancel_tx = lifecycle_tx(
        bob,
        0,
        1,
        2,
        TransactionType::BnsCancelOffer,
        bincode::serialize(&2u64).unwrap(),
    );
    cancel_tx.sign(&bob_kp);
    state.validate_transaction(&cancel_tx).unwrap();
    Executor::apply_transaction_checked(&mut state, &cancel_tx).unwrap();

    let mut buy_cancelled = lifecycle_tx(
        alice,
        10_000,
        1,
        2,
        TransactionType::BnsBuyName,
        bincode::serialize(&2u64).unwrap(),
    );
    buy_cancelled.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &buy_cancelled)
            .unwrap_err()
            .code(),
        "bns_offer_inactive_or_expired"
    );

    // Stale resale offer: Bob opens offer #3, transfers `market.bud` directly to outsider,
    // and Alice tries to buy offer #3 -> fails with `bns_resale_stale`!
    let mut offer_stale = lifecycle_tx(
        bob,
        0,
        1,
        3,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market.bud".to_string(),
            price_atoms: 10_000,
            duration: 0,
            kind: OfferKind::Resale,
            expires_at_epoch: 80,
        })
        .unwrap(),
    );
    offer_stale.sign(&bob_kp);
    Executor::apply_transaction_checked(&mut state, &offer_stale).unwrap(); // id = 3

    let mut direct_transfer = lifecycle_tx(
        bob,
        0,
        1,
        4,
        TransactionType::BnsTransfer,
        bincode::serialize(&("market.bud".to_string(), outsider)).unwrap(),
    );
    direct_transfer.sign(&bob_kp);
    Executor::apply_transaction_checked(&mut state, &direct_transfer).unwrap();

    let mut buy_stale = lifecycle_tx(
        alice,
        10_000,
        1,
        2,
        TransactionType::BnsBuyName,
        bincode::serialize(&3u64).unwrap(),
    );
    buy_stale.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &buy_stale)
            .unwrap_err()
            .code(),
        "bns_resale_stale"
    );

    // Expired offer: primary_seller opens offer #4 expiring at epoch 10, advance epoch to 10 -> rejected!
    let mut offer_expiring = lifecycle_tx(
        primary_seller,
        0,
        1,
        1,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "expiring.bud".to_string(),
            price_atoms: 10_000,
            duration: 100,
            kind: OfferKind::Primary,
            expires_at_epoch: 10,
        })
        .unwrap(),
    );
    offer_expiring.sign(&primary_kp);
    Executor::apply_transaction_checked(&mut state, &offer_expiring).unwrap(); // id = 4
    state.epoch_index = 10;

    let mut buy_expired = lifecycle_tx(
        alice,
        10_000,
        1,
        2,
        TransactionType::BnsBuyName,
        bincode::serialize(&4u64).unwrap(),
    );
    buy_expired.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &buy_expired)
            .unwrap_err()
            .code(),
        "bns_offer_inactive_or_expired"
    );
}

#[test]
fn bns_reserved_labels_rejected_unless_primary_seller_settles() {
    use crate::bns::{CreateNameOffer, OfferKind, RESERVED_LABELS};
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    for label in [
        "bud",
        "www",
        "app",
        "api",
        "rpc",
        "docs",
        "mail",
        "explorer",
        "faucet",
        "status",
        "testnet",
        "mainnet",
        "devnet",
        "seed",
        "seed-1",
        "root",
        "admin",
        "bns",
        "budlum",
        "validator",
        "node",
        "gateway",
    ] {
        assert!(
            RESERVED_LABELS.contains(&label),
            "RESERVED_LABELS must contain `{label}`"
        );
        assert_eq!(
            reg.register(format!("{label}.bud"), alice, 1, 100),
            Err(BnsError::ReservedName),
            "normal register must reject reserved `{label}.bud`"
        );
    }

    // Primary seller can list and settle a reserved label (`rpc.bud`) via marketplace,
    // whereas a non-primary seller is rejected on CreateOffer.
    let primary_kp = KeyPair::generate().unwrap();
    let primary_seller = Address::from(primary_kp.public_key_bytes());
    let outsider_kp = KeyPair::generate().unwrap();
    let outsider = Address::from(outsider_kp.public_key_bytes());
    let buyer_kp = KeyPair::generate().unwrap();
    let buyer = Address::from(buyer_kp.public_key_bytes());

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state
        .bns_registry
        .set_primary_sellers([primary_seller])
        .unwrap();
    state.add_balance(&primary_seller, 1_000_000);
    state.add_balance(&outsider, 1_000_000);
    state.add_balance(&buyer, 1_000_000);

    let mut bad_offer = lifecycle_tx(
        outsider,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "rpc.bud".to_string(),
            price_atoms: 50_000,
            duration: 100,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    bad_offer.sign(&outsider_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &bad_offer)
            .unwrap_err()
            .code(),
        "bns_reserved_name"
    );

    let mut ok_offer = lifecycle_tx(
        primary_seller,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "rpc.bud".to_string(),
            price_atoms: 50_000,
            duration: 100,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    ok_offer.sign(&primary_kp);
    Executor::apply_transaction_checked(&mut state, &ok_offer).unwrap();

    let mut buy_reserved = lifecycle_tx(
        buyer,
        50_000,
        1,
        0,
        TransactionType::BnsBuyName,
        bincode::serialize(&0u64).unwrap(),
    );
    buy_reserved.sign(&buyer_kp);
    Executor::apply_transaction_checked(&mut state, &buy_reserved).unwrap();
    assert_eq!(state.bns_registry.names["rpc.bud"].owner, buyer);
}

#[test]
fn bns_duration_and_owner_name_limits_enforced() {
    use crate::bns::{CreateNameOffer, OfferKind, MAX_DURATION, MAX_NAMES_PER_OWNER, MIN_DURATION};
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);

    // 1-epoch registration rejected (`MIN_DURATION = 10`).
    assert_eq!(
        reg.register("shortdur.bud".to_string(), alice, 1, 1),
        Err(BnsError::InvalidDuration)
    );
    assert_eq!(
        reg.register("shortdur.bud".to_string(), alice, 1, MIN_DURATION - 1),
        Err(BnsError::InvalidDuration)
    );
    // >10-year (`MAX_DURATION + 1`) registration rejected.
    assert_eq!(
        reg.register("longdur.bud".to_string(), alice, 1, MAX_DURATION + 1),
        Err(BnsError::InvalidDuration)
    );

    // Register at MAX_DURATION, advance 5 epochs, then renew by MIN_DURATION (10) ->
    // post-renewal remaining duration would be MAX_DURATION - 5 + 10 > MAX_DURATION -> rejected!
    reg.register("maxcap.bud".to_string(), alice, 1, MAX_DURATION)
        .unwrap();
    assert_eq!(
        reg.renew("maxcap.bud", &alice, 6, MIN_DURATION),
        Err(BnsError::InvalidDuration),
        "post-renewal remaining duration exceeding MAX_DURATION must be rejected"
    );
    // Advance 20 epochs so remaining is MAX_DURATION - 20 -> renewing by MIN_DURATION (10) succeeds!
    reg.renew("maxcap.bud", &alice, 21, MIN_DURATION).unwrap();

    // MAX_NAMES_PER_OWNER enforced on registration, marketplace purchase, and transfer!
    let primary_kp = KeyPair::generate().unwrap();
    let primary_seller = Address::from(primary_kp.public_key_bytes());
    let full_kp = KeyPair::generate().unwrap();
    let full_owner = Address::from(full_kp.public_key_bytes());
    let sender_kp = KeyPair::generate().unwrap();
    let sender = Address::from(sender_kp.public_key_bytes());

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state
        .bns_registry
        .set_primary_sellers([primary_seller])
        .unwrap();
    state.add_balance(&primary_seller, 10_000_000);
    state.add_balance(&full_owner, 10_000_000);
    state.add_balance(&sender, 10_000_000);

    for idx in 0..MAX_NAMES_PER_OWNER {
        state
            .bns_registry
            .register(format!("slot{idx:03}.bud"), full_owner, 1, 100)
            .unwrap();
    }
    assert_eq!(
        state
            .bns_registry
            .register("extra01.bud".to_string(), full_owner, 1, 100),
        Err(BnsError::OwnerNameLimitExceeded)
    );

    // Marketplace purchase by `full_owner` (already holding MAX_NAMES_PER_OWNER) is rejected.
    let mut offer_tx = lifecycle_tx(
        primary_seller,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "market65.bud".to_string(),
            price_atoms: 1_000,
            duration: 100,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    offer_tx.sign(&primary_kp);
    Executor::apply_transaction_checked(&mut state, &offer_tx).unwrap();

    let mut buy_over_cap = lifecycle_tx(
        full_owner,
        1_000,
        1,
        0,
        TransactionType::BnsBuyName,
        bincode::serialize(&0u64).unwrap(),
    );
    buy_over_cap.sign(&full_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &buy_over_cap)
            .unwrap_err()
            .code(),
        "bns_registration_failed"
    );

    // Direct transfer from `sender` to `full_owner` is also rejected!
    state
        .bns_registry
        .register("giftname.bud".to_string(), sender, 1, 100)
        .unwrap();
    let mut transfer_over_cap = lifecycle_tx(
        sender,
        0,
        1,
        0,
        TransactionType::BnsTransfer,
        bincode::serialize(&("giftname.bud".to_string(), full_owner)).unwrap(),
    );
    transfer_over_cap.sign(&sender_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &transfer_over_cap)
            .unwrap_err()
            .code(),
        "bns_transfer_failed"
    );
    let _ = bob;
}

#[test]
fn bns_forward_target_address_and_bidirectional_reverse_resolution() {
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let vault_kp = KeyPair::generate().unwrap();
    let vault = Address::from(vault_kp.public_key_bytes());
    let bob_kp = KeyPair::generate().unwrap();
    let bob = Address::from(bob_kp.public_key_bytes());

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 1_000_000);
    state.add_balance(&vault, 1_000_000);
    state.add_balance(&bob, 1_000_000);
    state
        .bns_registry
        .register("ayaz.bud".to_string(), alice, 1, 100)
        .unwrap();

    // Initially forward resolution returns `alice`, reverse resolution is None.
    assert_eq!(state.bns_registry.resolve("ayaz.bud", 2), Some(alice));
    assert_eq!(state.bns_registry.reverse_resolve(&alice, 2), None);

    // Outsider cannot claim `ayaz.bud` as primary name.
    let mut bob_claim = lifecycle_tx(
        bob,
        0,
        1,
        0,
        TransactionType::BnsSetPrimaryName,
        bincode::serialize(&Some("ayaz.bud".to_string())).unwrap(),
    );
    bob_claim.sign(&bob_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &bob_claim)
            .unwrap_err()
            .code(),
        "bns_set_primary_failed"
    );

    // Alice routes `ayaz.bud` -> `vault` (domain 2) and both Alice (owner) and
    // Vault (routed target) can set `ayaz.bud` as their verified primary name.
    let mut set_addr = lifecycle_tx(
        alice,
        0,
        1,
        0,
        TransactionType::BnsSetAddress,
        bincode::serialize(&("ayaz.bud".to_string(), Some(vault), Some(2u32))).unwrap(),
    );
    set_addr.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &set_addr).unwrap();
    assert_eq!(state.bns_registry.resolve("ayaz.bud", 2), Some(vault));
    assert_eq!(state.bns_registry.resolve_owner("ayaz.bud", 2), Some(alice));

    let mut vault_primary = lifecycle_tx(
        vault,
        0,
        1,
        0,
        TransactionType::BnsSetPrimaryName,
        bincode::serialize(&Some("ayaz.bud".to_string())).unwrap(),
    );
    vault_primary.sign(&vault_kp);
    Executor::apply_transaction_checked(&mut state, &vault_primary).unwrap();
    assert_eq!(
        state.bns_registry.reverse_resolve(&vault, 2).as_deref(),
        Some("ayaz.bud")
    );

    // Transferring `ayaz.bud` to `bob` clears `vault`'s stale primary-name mapping!
    let mut transfer_tx = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsTransfer,
        bincode::serialize(&("ayaz.bud".to_string(), bob)).unwrap(),
    );
    transfer_tx.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &transfer_tx).unwrap();
    assert_eq!(state.bns_registry.resolve("ayaz.bud", 2), Some(bob));
    assert_eq!(state.bns_registry.reverse_resolve(&vault, 2), None);
}

#[test]
fn bns_v3_text_and_multichain_records_commit_to_root_and_reject_unsafe_schemes() {
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;
    use std::collections::BTreeMap;

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = addr(9);

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 1_000_000);
    state
        .bns_registry
        .register("profile.bud".to_string(), alice, 1, 100)
        .unwrap();

    let root_before = state.bns_registry.root();
    let mut updates = BTreeMap::new();
    updates.insert(
        "avatar".to_string(),
        Some("https://budlum.xyz/avatar.png".to_string()),
    );
    updates.insert("com.github".to_string(), Some("budlum-xyz".to_string()));
    updates.insert(
        "addr.eth".to_string(),
        Some("0x1111111111111111111111111111111111111111".to_string()),
    );
    let mut set_tx = lifecycle_tx(
        alice,
        0,
        1,
        0,
        TransactionType::BnsSetRecords,
        bincode::serialize(&("profile.bud".to_string(), updates)).unwrap(),
    );
    set_tx.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &set_tx).unwrap();

    assert_ne!(state.bns_registry.root(), root_before);
    let records = state.bns_registry.get_records("profile.bud", 2).unwrap();
    assert_eq!(records["com.github"], "budlum-xyz");
    assert_eq!(
        records["addr.eth"],
        "0x1111111111111111111111111111111111111111"
    );

    // Unsafe `javascript:` URI rejected without mutating existing records.
    let mut bad_updates = BTreeMap::new();
    bad_updates.insert("url".to_string(), Some("javascript:alert(1)".to_string()));
    let mut bad_tx = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsSetRecords,
        bincode::serialize(&("profile.bud".to_string(), bad_updates)).unwrap(),
    );
    bad_tx.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &bad_tx)
            .unwrap_err()
            .code(),
        "bns_set_records_failed"
    );

    // Transfer clears all text/multi-chain records.
    state
        .bns_registry
        .transfer("profile.bud", &alice, bob, 2)
        .unwrap();
    assert!(state
        .bns_registry
        .get_records("profile.bud", 2)
        .unwrap()
        .is_empty());
}
