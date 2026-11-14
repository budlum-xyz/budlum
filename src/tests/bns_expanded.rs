//! Expanded BNS Registry tests coverage.

use crate::bns::types::BnsError;
use crate::bns::BnsRegistry;
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;
use proptest::{prop_assert_eq, proptest};

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

    // F14 + B8: inside GRACE_PERIOD (epoch 400 <= 300 + 3000), resolution fails closed
    // and third parties (`bob`) are refused on both `renew` and `register`, while the
    // owner (`alice`) may rescue the name (`new_expires_at = max(300, 400) + 100 = 500`).
    assert!(matches!(
        reg.renew("test.bud", &bob, 400, 100),
        Err(BnsError::NotOwner)
    ));
    assert!(matches!(
        reg.register("test.bud".to_string(), bob, 400, 100),
        Err(BnsError::NameTaken)
    ));
    reg.renew("test.bud", &alice, 400, 100).unwrap();
    assert_eq!(reg.resolve("test.bud", 450), Some(alice));
    assert_eq!(reg.resolve("test.bud", 550), None);

    // Past GRACE_PERIOD (epoch 3600 > 500 + 3000), owner renewal is refused (`Expired`)
    // and `bob` may register the released name.
    assert!(matches!(
        reg.renew("test.bud", &alice, 3600, 100),
        Err(BnsError::Expired)
    ));
    reg.register("test.bud".to_string(), bob, 3600, 100)
        .unwrap();
    assert_eq!(reg.resolve("test.bud", 3610), Some(bob));
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

    assert_eq!(
        reg.transfer("missing.bud", &alice, bob, 10),
        Err(BnsError::InvalidName),
        "transfer of an absent name must return a refusal"
    );
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
        "bns_offer_inactive_or_expired"
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

#[test]
fn bns_subdomains_resolve_fqdn_remove_cleanly_and_expire_with_parent() {
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let vault = addr(11);
    let api = addr(12);

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 1_000_000);
    state
        .bns_registry
        .register("studio.bud".to_string(), alice, 1, 20)
        .unwrap();

    // Register `pay.studio.bud` (3-char sub-label) and `v1.studio.bud` (2-char sub-label).
    let mut reg_pay = lifecycle_tx(
        alice,
        0,
        1,
        0,
        TransactionType::BnsRegisterSubdomain,
        bincode::serialize(&("studio.bud".to_string(), "pay".to_string(), vault)).unwrap(),
    );
    reg_pay.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &reg_pay).unwrap();

    let mut reg_v1 = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsRegisterSubdomain,
        bincode::serialize(&("studio.bud".to_string(), "v1".to_string(), api)).unwrap(),
    );
    reg_v1.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &reg_v1).unwrap();

    // Direct FQDN resolution works for `<sub_label>.<label>.bud`, refuses 3+ levels.
    assert_eq!(state.bns_registry.resolve("pay.studio.bud", 5), Some(vault));
    assert_eq!(state.bns_registry.resolve("v1.studio.bud", 5), Some(api));
    assert_eq!(state.bns_registry.resolve("a.pay.studio.bud", 5), None);

    // Non-zero header amount is rejected on consensus subdomain doors.
    let mut bad_amt = lifecycle_tx(
        alice,
        50,
        1,
        2,
        TransactionType::BnsRemoveSubdomain,
        bincode::serialize(&("studio.bud".to_string(), "v1".to_string())).unwrap(),
    );
    bad_amt.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &bad_amt)
            .unwrap_err()
            .code(),
        "bns_invalid_remove_subdomain"
    );

    // Removing `v1` clears `v1.studio.bud` while keeping `pay.studio.bud`.
    let mut rm_v1 = lifecycle_tx(
        alice,
        0,
        1,
        2,
        TransactionType::BnsRemoveSubdomain,
        bincode::serialize(&("studio.bud".to_string(), "v1".to_string())).unwrap(),
    );
    rm_v1.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &rm_v1).unwrap();
    assert_eq!(state.bns_registry.resolve("v1.studio.bud", 5), None);
    assert_eq!(state.bns_registry.resolve("pay.studio.bud", 5), Some(vault));

    // When `studio.bud` expires at epoch 21, `pay.studio.bud` fails closed automatically.
    assert_eq!(state.bns_registry.resolve("pay.studio.bud", 21), None);
    assert!(state
        .bns_registry
        .list_subdomains("studio.bud", 21)
        .is_none());
}

#[test]
fn bns_consensus_bud3_content_ref_validates_against_bud3_registry_and_serves_view() {
    use crate::bns::bud3::{BnsViewAccess, Bud3BnsResolver};
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;
    use crate::storage::bud3::content_ref::ContentRef;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};
    use crate::storage::bud3::view::MemorySymbolNetwork;

    const PROFILE: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = addr(21);

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 1_000_000);
    state
        .bns_registry
        .register("site.bud".to_string(), alice, 1, 50)
        .unwrap();

    let html = b"<html><body>On-chain B.U.D. 3.0 site</body></html>".repeat(6);
    let up = prepare_public_upload(&html, &PROFILE, &Bud3Limits::default(), 8).unwrap();
    let obj_key = up.record.commitment;
    let cid = up.record.content_id;
    let holder = [7u8; 32];

    let mut net = MemorySymbolNetwork::default();
    for (seg_idx, syms) in up.segments.iter().enumerate() {
        net.store_holder_share(holder, obj_key, seg_idx as u64, syms.clone());
    }

    // Before registering the object in `bud3_registry`, `BnsSetBud3Content` fails closed!
    let cref = ContentRef::new(cid, obj_key, None).unwrap();
    let mut premature_tx = lifecycle_tx(
        alice,
        0,
        1,
        0,
        TransactionType::BnsSetBud3Content,
        bincode::serialize(&("site.bud".to_string(), Some(cref))).unwrap(),
    );
    premature_tx.sign(&alice_kp);
    assert_eq!(
        Executor::apply_transaction_checked(&mut state, &premature_tx)
            .unwrap_err()
            .code(),
        "bns_set_bud3_content_failed"
    );

    // Register object in `state.bud3_registry`, then execute `BnsSetBud3Content`.
    state
        .bud3_registry
        .register_object(
            alice.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: holder,
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            50,
        )
        .unwrap();

    let root_before = state.bns_registry.root();
    Executor::apply_transaction_checked(&mut state, &premature_tx).unwrap();
    assert_ne!(state.bns_registry.root(), root_before);
    assert_eq!(
        state.bns_registry.resolve_bud3_content("site.bud", 2),
        Some(cref)
    );

    // `Bud3BnsResolver` reconstructs the exact payload directly from on-chain `NameRecord::bud3_content`!
    let resolver = Bud3BnsResolver::new();
    let reconstructed = resolver
        .resolve_via_bud3_view(
            &state.bns_registry,
            &state.bud3_registry,
            &net,
            "site.bud",
            2,
            &BnsViewAccess::default(),
        )
        .unwrap();
    assert_eq!(reconstructed, html);

    // Ownership transfer clears `bud3_content`.
    state
        .bns_registry
        .transfer("site.bud", &alice, bob, 3)
        .unwrap();
    assert_eq!(state.bns_registry.resolve_bud3_content("site.bud", 3), None);
}

#[test]
fn bns_grace_period_owner_rescue_resale_invalidation_and_owner_listing() {
    use crate::bns::{CreateNameOffer, NameStatus, OfferKind};
    use crate::core::account::AccountState;
    use crate::crypto::primitives::KeyPair;
    use crate::execution::executor::Executor;

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob_kp = KeyPair::generate().unwrap();
    let bob = Address::from(bob_kp.public_key_bytes());

    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 5_000_000);
    state.add_balance(&bob, 5_000_000);

    state
        .bns_registry
        .register("rescue.bud".to_string(), alice, 1, 20)
        .unwrap();
    state
        .bns_registry
        .register("listed.bud".to_string(), alice, 1, 200)
        .unwrap();

    // Alice opens a Resale offer on `listed.bud`, then transfers `listed.bud` directly to Bob:
    // the stale Resale offer is automatically invalidated!
    let mut offer_tx = lifecycle_tx(
        alice,
        0,
        1,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "listed.bud".to_string(),
            price_atoms: 10_000,
            duration: 0,
            kind: OfferKind::Resale,
            expires_at_epoch: 100,
        })
        .unwrap(),
    );
    offer_tx.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &offer_tx).unwrap();
    assert_eq!(
        state
            .marketplace
            .list_active_name_offers(1, Some(OfferKind::Resale))
            .len(),
        1
    );

    let mut xfer_tx = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsTransfer,
        bincode::serialize(&("listed.bud".to_string(), bob)).unwrap(),
    );
    xfer_tx.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &xfer_tx).unwrap();
    assert!(state
        .marketplace
        .list_active_name_offers(1, Some(OfferKind::Resale))
        .is_empty());

    // Advance into grace for `rescue.bud` (`expires_at == 21`, `epoch_index = 50 <= 3021`).
    state.epoch_index = 50;
    assert_eq!(state.bns_registry.resolve("rescue.bud", 50), None);
    let alice_names = state.bns_registry.list_names_by_owner(&alice, 50);
    assert_eq!(alice_names.len(), 1);
    assert_eq!(alice_names[0].name, "rescue.bud");
    assert_eq!(alice_names[0].status, NameStatus::Grace);

    // Alice rescues `rescue.bud` via `BnsRenew` in grace (`new_expires_at = 50 + 30 = 80`).
    let cost = state.bns_registry.calculate_cost("rescue.bud", 30);
    let mut renew_tx = lifecycle_tx(
        alice,
        cost,
        1,
        2,
        TransactionType::BnsRenew,
        bincode::serialize(&("rescue.bud".to_string(), 30u64)).unwrap(),
    );
    renew_tx.sign(&alice_kp);
    Executor::apply_transaction_checked(&mut state, &renew_tx).unwrap();

    assert_eq!(state.bns_registry.resolve("rescue.bud", 50), Some(alice));
    let alice_names_after = state.bns_registry.list_names_by_owner(&alice, 50);
    assert_eq!(alice_names_after[0].status, NameStatus::Active);
    assert_eq!(alice_names_after[0].expires_at, 80);
}

#[test]
fn bns_per_name_merkle_proofs_verify_inclusion_absence_tampering_and_expiry() {
    use crate::storage::ContentId;

    let mut reg = BnsRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    let carol = addr(3);

    reg.register("alpha.bud".to_string(), alice, 1, 50).unwrap();
    reg.register("gamma.bud".to_string(), bob, 1, 50).unwrap();
    reg.register("omega.bud".to_string(), carol, 1, 10).unwrap();
    reg.set_content("gamma.bud", &bob, ContentId([0xAB; 32]), 2)
        .unwrap();

    let expected_root = reg.root();

    // 1. Inclusion proof for `gamma.bud` verifies at live epoch 5.
    let inc = reg.prove_name("gamma.bud", 5);
    assert!(inc.included);
    let verified = BnsRegistry::verify_state_proof(&inc, &expected_root, 5)
        .unwrap()
        .unwrap();
    assert_eq!(verified.owner, bob);
    assert_eq!(verified.content_id, Some(ContentId([0xAB; 32])));
    assert_eq!(verified.siblings.len(), 2);

    // 2. Tampering with owner or root fails closed!
    let mut forged = inc.clone();
    forged.entry.as_mut().unwrap().owner = alice;
    assert!(BnsRegistry::verify_state_proof(&forged, &expected_root, 5).is_err());

    // 3. Expired proven entry (`omega.bud` expires at 11) is refused at epoch 15!
    let expired_proof = reg.prove_name("omega.bud", 15);
    assert!(BnsRegistry::verify_state_proof(&expired_proof, &expected_root, 15).is_err());

    // 4. Non-existence proof for `beta.bud` (between `alpha.bud` and `gamma.bud`) verifies!
    let abs = reg.prove_name("beta.bud", 5);
    assert!(!abs.included);
    assert_eq!(abs.predecessor.as_ref().unwrap().name, "alpha.bud");
    assert_eq!(abs.successor.as_ref().unwrap().name, "gamma.bud");
    assert!(BnsRegistry::verify_state_proof(&abs, &expected_root, 5)
        .unwrap()
        .is_none());
}

/// An absence proof must place its boundaries, not merely spell them.
///
/// Order alone proves nothing: every branch in the tree sorts next to some
/// target, and `names_count` is a claimed field that no leaf commits to. Before
/// the boundary rule, the honest inclusion branch of a live owned name could be
/// relabelled as the predecessor of a nearby target and served as proof that
/// the target is free, so a lying node could talk a wallet into treating a
/// taken name as unclaimed. The positions are the part a prover cannot invent
/// without opening a branch that says otherwise.
#[test]
fn bns_absence_proof_boundaries_must_be_adjacent_positions() {
    let mut reg = BnsRegistry::new();
    let alice = Address::from([0xA1; 32]);
    let bob = Address::from([0xB1; 32]);
    let t0 = 100u64;
    reg.register("alpha.bud".to_string(), alice, 10, t0)
        .unwrap();
    reg.register("gamma.bud".to_string(), bob, 10, t0).unwrap();
    reg.register("omega.bud".to_string(), bob, 10, t0 + 1)
        .unwrap();
    let root = reg.root();

    // The honest proof verifies, and it carries the positions it depends on.
    let honest = reg.prove_name("beta.bud", 5);
    assert!(!honest.included);
    assert!(BnsRegistry::verify_state_proof(&honest, &root, 5).is_ok());
    let pred = honest.predecessor.clone().unwrap();
    assert_eq!(pred.leaf_index, Some(0));
    assert_eq!(pred.tree_size, Some(3));

    // The attack: hide `gamma.bud` by dropping the successor and relabelling
    // the live `alpha.bud` branch as a lone predecessor. It still opens to the
    // header root, so only the position can refuse it.
    let mut spliced = honest.clone();
    spliced.successor = None;
    assert!(
        BnsRegistry::verify_state_proof(&spliced, &root, 5).is_err(),
        "a predecessor-only absence proof must be the end of the tree"
    );

    // A prover that reaches for the right names but the wrong positions: an
    // adjacent-looking pair taken from different indices of the same tree.
    let mut misplaced = honest.clone();
    misplaced.successor.as_mut().unwrap().leaf_index = Some(2);
    assert!(
        BnsRegistry::verify_state_proof(&misplaced, &root, 5).is_err(),
        "non-adjacent boundaries leave room for a live name in between"
    );

    // A branch from a different-sized tree cannot be spliced onto this one.
    let mut stitched = honest.clone();
    stitched.successor.as_mut().unwrap().tree_size = Some(4);
    assert!(
        BnsRegistry::verify_state_proof(&stitched, &root, 5).is_err(),
        "both boundaries must come from the list the root commits to"
    );

    // A branch that carries no position at all is usable for inclusion only.
    let mut unpositioned = honest.clone();
    unpositioned.predecessor.as_mut().unwrap().leaf_index = None;
    assert!(BnsRegistry::verify_state_proof(&unpositioned, &root, 5).is_err());

    // The two open ends of the tree remain provable with one boundary.
    let first = reg.prove_name("aardvark.bud", 5);
    assert!(first.predecessor.is_none());
    assert_eq!(first.successor.as_ref().unwrap().leaf_index, Some(0));
    assert!(BnsRegistry::verify_state_proof(&first, &root, 5).is_ok());

    let last = reg.prove_name("zeta.bud", 5);
    assert!(last.successor.is_none());
    assert_eq!(last.predecessor.as_ref().unwrap().leaf_index, Some(2));
    assert!(BnsRegistry::verify_state_proof(&last, &root, 5).is_ok());

    // And the boundary count is not a free variable: a proof that claims a
    // smaller list than the branch was built from is refused.
    let mut shrunk = honest.clone();
    shrunk.names_count = 2;
    assert!(BnsRegistry::verify_state_proof(&shrunk, &root, 5).is_err());
}

// ---------------------------------------------------------------------------
// B12: governance price door
// ---------------------------------------------------------------------------

/// B12: the absolute bounds are a property of the value, and the step bound is
/// a property of the move. Both are enforced, and neither clamps.
#[test]
fn bns_base_cost_bounds_and_tenfold_step_are_enforced() {
    use crate::bns::{MAX_BNS_BASE_COST, MIN_BNS_BASE_COST};
    use crate::registry::params::BNS_BASE_COST_MAX_STEP_FACTOR;

    let mut reg = BnsRegistry::new();
    let genesis_cost = reg.base_cost;
    assert_eq!(genesis_cost, 100, "the genesis price this test moves from");

    // Absolute floor and ceiling: rejected on their own, with no state change.
    assert!(BnsRegistry::check_base_cost_bounds(0).is_err());
    assert!(BnsRegistry::check_base_cost_bounds(MIN_BNS_BASE_COST - 1).is_err());
    assert!(BnsRegistry::check_base_cost_bounds(MAX_BNS_BASE_COST + 1).is_err());
    assert!(BnsRegistry::check_base_cost_bounds(u64::MAX).is_err());
    assert!(BnsRegistry::check_base_cost_bounds(MIN_BNS_BASE_COST).is_ok());
    assert!(BnsRegistry::check_base_cost_bounds(MAX_BNS_BASE_COST).is_ok());

    // The step bound is exactly tenfold in each direction: 10x passes, 11x fails.
    assert!(reg
        .set_base_cost(genesis_cost * BNS_BASE_COST_MAX_STEP_FACTOR)
        .is_ok());
    assert_eq!(reg.base_cost, genesis_cost * BNS_BASE_COST_MAX_STEP_FACTOR);

    let raised = reg.base_cost;
    assert!(
        reg.set_base_cost(genesis_cost).is_ok(),
        "10x down is allowed"
    );
    assert_eq!(reg.base_cost, genesis_cost);

    // 11x up is refused and leaves the price alone.
    assert!(reg
        .set_base_cost(genesis_cost * (BNS_BASE_COST_MAX_STEP_FACTOR + 1))
        .is_err());
    assert_eq!(
        reg.base_cost, genesis_cost,
        "a refused step does not move the price"
    );
    // 11x down is refused too: the bound is symmetric.
    assert!(reg
        .set_base_cost(genesis_cost / (BNS_BASE_COST_MAX_STEP_FACTOR + 1))
        .is_err());
    assert_eq!(reg.base_cost, genesis_cost);
    assert!(raised > genesis_cost);
}

/// B12: the price moves and nothing else does. A registered name keeps the term
/// it paid for, and the next renewal is charged at the new base.
#[test]
fn bns_base_cost_change_does_not_touch_existing_registrations() {
    use crate::bns::{CreateNameOffer, OfferKind};

    let mut state = AccountState::new();
    let owner = addr(0x51);
    let seller = addr(0x52);
    state
        .bns_registry
        .set_primary_sellers(vec![seller])
        .unwrap();

    let duration = crate::bns::MIN_DURATION;
    state.add_balance(&seller, 1_000_000);
    state.add_balance(&owner, 1_000_000);

    let offer_id = state
        .marketplace
        .create_name_offer(
            seller,
            CreateNameOffer {
                name: "priced.bud".to_string(),
                price_atoms: 1_000,
                duration,
                kind: OfferKind::Primary,
                expires_at_epoch: state.epoch_index + 100,
            },
            state.epoch_index,
        )
        .expect("the authorized seller lists an unregistered name");

    // The Primary sale path is the only registration door (B2).
    state
        .bns_registry
        .register_primary_sale(
            &seller,
            "priced.bud".to_string(),
            owner,
            state.epoch_index,
            duration,
        )
        .expect("the primary sale registers the name for the buyer");

    let before = state.bns_registry.names.get("priced.bud").cloned().unwrap();
    let root_before = state.bns_registry.root();
    let old_cost = state.bns_registry.calculate_cost("priced.bud", duration);

    state
        .bns_registry
        .set_base_cost(1_000)
        .expect("10x up from the genesis 100");

    let after = state.bns_registry.names.get("priced.bud").cloned().unwrap();
    assert_eq!(
        before, after,
        "no field of a registration moves with the price"
    );
    assert_ne!(
        root_before,
        state.bns_registry.root(),
        "the price is committed"
    );
    assert_eq!(
        state.bns_registry.calculate_cost("priced.bud", duration),
        old_cost * crate::registry::params::BNS_BASE_COST_MAX_STEP_FACTOR,
        "the new base is charged on the next renewal"
    );
    assert!(
        state.marketplace.get_name_offer(offer_id).is_some(),
        "the offer table is untouched by a price change"
    );
    assert_eq!(after.owner, owner);
}

// ---------------------------------------------------------------------------
// B13: capacity parameter and the expiry index
// ---------------------------------------------------------------------------

/// B13: the ceiling is a stored parameter, and the reclaim path reads the index
/// instead of scanning the registry.
#[test]
fn bns_expiry_index_reclaims_the_earliest_expired_name_without_a_scan() {
    use crate::bns::{BnsRegistry, MAX_DURATION};

    let mut reg = BnsRegistry::new();
    let seller = addr(0x61);
    let buyer = |i: u8| addr(0x60 + i);
    reg.set_primary_sellers(vec![seller]).unwrap();

    // A small ceiling makes the reclaim path reachable in a test.
    reg.max_names = 2;
    assert_eq!(reg.max_names, 2, "the ceiling is a field, not the constant");

    let duration = crate::bns::MIN_DURATION;
    reg.register_primary_sale(&seller, "aaa.bud".into(), buyer(1), 0, duration)
        .unwrap();
    reg.register_primary_sale(&seller, "bbb.bud".into(), buyer(2), 0, duration + 100)
        .unwrap();
    assert_eq!(reg.names.len(), 2);
    assert_eq!(
        reg.expired_by_grace_end.len(),
        2,
        "every live record is indexed"
    );

    // At the ceiling with nothing expired: refused, fail-closed.
    assert_eq!(
        reg.register_primary_sale(&seller, "ccc.bud".into(), buyer(3), 0, duration),
        Err(crate::bns::BnsError::NameTaken)
    );

    // Both names are expired but `aaa.bud` has the earlier grace end. The
    // reclaim must take that one, and only that one.
    let later = duration + 100 + crate::bns::GRACE_PERIOD;
    reg.register_primary_sale(&seller, "ccc.bud".into(), buyer(3), later, duration)
        .unwrap();
    assert!(
        !reg.names.contains_key("aaa.bud"),
        "the earliest grace end is reclaimed"
    );
    assert!(
        reg.names.contains_key("bbb.bud"),
        "a later grace end is not"
    );
    assert!(reg.names.contains_key("ccc.bud"));
    assert_eq!(reg.names.len(), 2);
    assert_eq!(
        reg.expired_by_grace_end.len(),
        2,
        "the reclaimed name left no index row behind"
    );
    assert!(MAX_DURATION > duration);
}

/// B13: renewal, transfer and prune all keep the index in step with `names`.
#[test]
fn bns_expiry_index_tracks_renewal_prune_and_rebuild() {
    use crate::bns::{BnsRegistry, MAX_DURATION};

    let mut reg = BnsRegistry::new();
    let seller = addr(0x71);
    let owner = addr(0x72);
    reg.set_primary_sellers(vec![seller]).unwrap();
    let duration = crate::bns::MIN_DURATION;
    reg.register_primary_sale(&seller, "keep.bud".into(), owner, 0, duration)
        .unwrap();

    let grace_end_before = reg.names["keep.bud"].expires_at + crate::bns::GRACE_PERIOD;
    assert!(reg
        .expired_by_grace_end
        .contains(&(grace_end_before, "keep.bud".to_string())));

    // Renewal moves the row.
    reg.renew("keep.bud", &owner, 0, duration).unwrap();
    let grace_end_after = reg.names["keep.bud"].expires_at + crate::bns::GRACE_PERIOD;
    assert!(grace_end_after > grace_end_before);
    assert!(
        !reg.expired_by_grace_end
            .contains(&(grace_end_before, "keep.bud".to_string())),
        "the stale row is gone"
    );
    assert_eq!(reg.expired_by_grace_end.len(), 1, "one name, one row");

    // Prune at an epoch inside grace deletes nothing.
    assert_eq!(reg.prune_expired(grace_end_after - 1), 0);
    assert!(reg.names.contains_key("keep.bud"));

    // Prune at the grace end deletes the name and its row together.
    assert_eq!(reg.prune_expired(grace_end_after), 1);
    assert!(!reg.names.contains_key("keep.bud"));
    assert!(reg.expired_by_grace_end.is_empty());

    // A registry restored from a snapshot has an empty index until rebuilt,
    // and the derived rebuild is idempotent.
    reg.register_primary_sale(&seller, "again.bud".into(), owner, 0, duration)
        .unwrap();
    reg.expired_by_grace_end.clear();
    assert!(reg.expired_by_grace_end.is_empty());
    reg.rebuild_expiry_index();
    assert_eq!(reg.expired_by_grace_end.len(), 1);
    reg.rebuild_expiry_index();
    assert_eq!(reg.expired_by_grace_end.len(), 1);
    assert!(MAX_DURATION > duration);
}

/// B13: the index is derived state, so it does not move the state root.
#[test]
fn bns_expiry_index_is_not_committed_to_the_root() {
    use crate::bns::BnsRegistry;

    let mut reg = BnsRegistry::new();
    let seller = addr(0x81);
    let owner = addr(0x82);
    reg.set_primary_sellers(vec![seller]).unwrap();
    reg.register_primary_sale(
        &seller,
        "rooted.bud".into(),
        owner,
        0,
        crate::bns::MIN_DURATION,
    )
    .unwrap();

    let root_with_index = reg.root();
    reg.expired_by_grace_end.clear();
    assert_eq!(
        reg.root(),
        root_with_index,
        "the index is a view; a snapshot without it must produce the same root"
    );
    reg.rebuild_expiry_index();
    assert_eq!(reg.root(), root_with_index);
}

// ---------------------------------------------------------------------------
// B16: the root is order-independent (property test)
// ---------------------------------------------------------------------------

// B16: the same set of records produces the same root in every insertion
// order, for randomly generated label sets.
//
// The root is a Merkle tree over an ordered map, so this is the property the
// tree shape depends on: if insertion order could reach the root, two nodes
// that applied the same block in the same order would still agree, but a
// snapshot restore that re-inserted rows would not. Proptest searches for a
// counterexample instead of trusting three hand-written permutations.
proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    #[test]
    fn bns_root_is_independent_of_insertion_order(
        order in proptest::collection::vec(0u8..12, 1..12)
    ) {
        fn registry_over(order: &[u8]) -> BnsRegistry {
            let mut reg = BnsRegistry::new();
            let seller = addr(0x95);
            reg.set_primary_sellers(vec![seller]).unwrap();
            for &i in order {
                let name = format!("order{i:02}.bud");
                reg.names.insert(
                    name.clone(),
                    crate::bns::NameRecord::try_new(
                        name,
                        addr(0xA0 ^ i),
                        0,
                        crate::bns::MIN_DURATION,
                    )
                    .unwrap(),
                );
            }
            reg.rebuild_expiry_index();
            reg
        }

        let mut reversed = order.clone();
        reversed.reverse();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        prop_assert_eq!(registry_over(&order).root(), registry_over(&reversed).root());
        prop_assert_eq!(registry_over(&order).root(), registry_over(&sorted).root());
    }
}

// A name may only point at content the chain has a row for.
#[test]
fn bns_set_content_refuses_unknown_content_and_binds_a_registered_object() {
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};

    const PROFILE: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    let key = KeyPair::from_seed(&[7u8; 32]).unwrap();
    let alice = Address::from(key.public_key_bytes());
    let name = "pages.bud".to_string();
    let mut state = AccountState::new();
    state.epoch_index = 1;
    state.add_balance(&alice, 10_000);
    state
        .bns_registry
        .register(name.clone(), alice, 1, 50)
        .unwrap();

    let body = b"<html><body>a small site</body></html>".repeat(6);
    let up = prepare_public_upload(&body, &PROFILE, &Bud3Limits::default(), 8).unwrap();
    let object = up.record.commitment;
    let known = crate::storage::content_id::ContentId(up.record.content_id.digest);
    let holder = [7u8; 32];

    let set_content = |cid: crate::storage::content_id::ContentId| {
        let mut tx = lifecycle_tx(
            alice,
            0,
            1,
            0,
            TransactionType::BnsSetContent,
            bincode::serialize(&(name.clone(), cid)).unwrap(),
        );
        tx.sign(&key);
        tx
    };

    // Nothing is registered yet, so the id names nothing.
    let err = Executor::apply_transaction_checked(&mut state, &set_content(known)).unwrap_err();
    assert_eq!(err.code(), "bns_content_unknown");
    assert_eq!(state.bns_registry.resolve_content(&name, 2), None);
    assert_eq!(state.get_nonce(&alice), 0);
    assert_eq!(state.get_balance(&alice), 10_000);

    state
        .bud3_registry
        .register_object(
            alice.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: holder,
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            50,
        )
        .unwrap();
    // Registered but not yet held: still not content a name can point at.
    let err = Executor::apply_transaction_checked(&mut state, &set_content(known)).unwrap_err();
    assert_eq!(err.code(), "bns_content_unknown");

    state.bud3_registry.ack(&object, &holder).unwrap();
    Executor::apply_transaction_checked(&mut state, &set_content(known)).unwrap();
    assert_eq!(state.bns_registry.resolve_content(&name, 2), Some(known));
    assert_eq!(state.get_nonce(&alice), 1);
    assert_eq!(state.get_balance(&alice), 9_999);

    // A different id is still refused once some content exists.
    let other = crate::storage::content_id::ContentId([0x5A; 32]);
    let mut tx = lifecycle_tx(
        alice,
        0,
        1,
        1,
        TransactionType::BnsSetContent,
        bincode::serialize(&(name.clone(), other)).unwrap(),
    );
    tx.sign(&key);
    let err = Executor::apply_transaction_checked(&mut state, &tx).unwrap_err();
    assert_eq!(err.code(), "bns_content_unknown");
    assert_eq!(state.bns_registry.resolve_content(&name, 2), Some(known));
}
