//! Acceptance cases of the name market and the grace window, at the door
//! a block uses.

use crate::bns::types::BnsError;
use crate::bns::{BnsRegistry, CreateNameOffer, OfferKind, GRACE_PERIOD, MIN_DURATION};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::crypto::primitives::KeyPair;
use crate::execution::executor::Executor;

const PRICE: u64 = 40_000;

fn tx(
    key: &KeyPair,
    amount: u64,
    nonce: u64,
    tx_type: TransactionType,
    data: Vec<u8>,
) -> Transaction {
    let mut tx = Transaction::new_with_chain_id(
        Address::from(key.public_key_bytes()),
        Address::zero(),
        amount,
        1,
        nonce,
        data,
        DEFAULT_CHAIN_ID,
        tx_type,
    );
    tx.sign(key);
    tx
}

/// A state with one primary seller and its open offer 0 for `sale.bud`.
fn market_with_one_offer() -> (AccountState, Address) {
    let seller_key = KeyPair::generate().unwrap();
    let seller = Address::from(seller_key.public_key_bytes());
    let mut state = AccountState::new();
    state.base_fee = 1;
    state.epoch_index = 5;
    state.add_balance(&seller, 1_000);
    state
        .bns_registry
        .set_primary_sellers(vec![seller])
        .unwrap();
    let offer = tx(
        &seller_key,
        0,
        0,
        TransactionType::BnsCreateOffer,
        bincode::serialize(&CreateNameOffer {
            name: "sale.bud".to_string(),
            price_atoms: PRICE,
            duration: 500,
            kind: OfferKind::Primary,
            expires_at_epoch: 50,
        })
        .unwrap(),
    );
    state.validate_transaction(&offer).unwrap();
    Executor::apply_transaction_checked(&mut state, &offer).unwrap();
    assert!(state.marketplace.get_name_offer(0).unwrap().active);
    (state, seller)
}

fn buy(key: &KeyPair) -> Transaction {
    tx(
        key,
        PRICE,
        0,
        TransactionType::BnsBuyName,
        bincode::serialize(&0u64).unwrap(),
    )
}

/// A buyer who cannot pay gets no name, the seller gets nothing, and the
/// offer stays open for a buyer who can.
#[test]
fn bns_buy_is_refused_when_the_buyer_cannot_pay_and_no_name_is_recorded() {
    let (mut state, seller) = market_with_one_offer();
    let poor_key = KeyPair::generate().unwrap();
    let poor = Address::from(poor_key.public_key_bytes());
    state.add_balance(&poor, PRICE - 1);

    let root_before = state.calculate_state_root();
    let seller_before = state.get_balance(&seller);
    let attempt = buy(&poor_key);
    assert!(state.validate_transaction(&attempt).is_err());
    assert!(Executor::apply_transaction_checked(&mut state, &attempt).is_err());

    assert_eq!(state.bns_registry.resolve("sale.bud", 5), None);
    assert!(!state.bns_registry.names().contains_key("sale.bud"));
    assert_eq!(state.get_balance(&poor), PRICE - 1);
    assert_eq!(state.get_balance(&seller), seller_before);
    assert!(state.marketplace.get_name_offer(0).unwrap().active);
    assert_eq!(state.calculate_state_root(), root_before);

    // The same offer still sells to a buyer who can pay.
    let rich_key = KeyPair::generate().unwrap();
    let rich = Address::from(rich_key.public_key_bytes());
    state.add_balance(&rich, PRICE + 10);
    let purchase = buy(&rich_key);
    state.validate_transaction(&purchase).unwrap();
    Executor::apply_transaction_checked(&mut state, &purchase).unwrap();
    assert_eq!(state.bns_registry.resolve("sale.bud", 5), Some(rich));
}

/// Two buyers send a purchase of the same offer. The first one in the block
/// gets the name. The second is refused and keeps its money.
#[test]
fn bns_two_buyers_of_one_offer_only_the_first_gets_the_name() {
    let (mut state, seller) = market_with_one_offer();
    let first_key = KeyPair::generate().unwrap();
    let first = Address::from(first_key.public_key_bytes());
    let second_key = KeyPair::generate().unwrap();
    let second = Address::from(second_key.public_key_bytes());
    state.add_balance(&first, PRICE + 10);
    state.add_balance(&second, PRICE + 10);

    // Both are valid against the state before either is applied.
    let first_buy = buy(&first_key);
    let second_buy = buy(&second_key);
    state.validate_transaction(&first_buy).unwrap();
    state.validate_transaction(&second_buy).unwrap();

    let seller_before = state.get_balance(&seller);
    Executor::apply_transaction_checked(&mut state, &first_buy).unwrap();
    assert_eq!(state.bns_registry.resolve("sale.bud", 5), Some(first));
    assert!(!state.marketplace.get_name_offer(0).unwrap().active);

    let second_before = state.get_balance(&second);
    assert!(state.validate_transaction(&second_buy).is_err());
    assert!(Executor::apply_transaction_checked(&mut state, &second_buy).is_err());
    assert_eq!(state.bns_registry.resolve("sale.bud", 5), Some(first));
    assert_eq!(state.get_balance(&second), second_before);
    assert_eq!(state.get_balance(&seller), seller_before + PRICE);
}

/// Both sides of the grace boundary. Until the last epoch of the window the
/// name belongs to nobody else: a stranger cannot take it and cannot renew
/// it, and the owner can still renew. From the first epoch after the window
/// the old owner has lost it and anyone can register it.
#[test]
fn bns_grace_window_holds_until_its_last_epoch_and_ends_on_the_next() {
    let owner = Address::from([0x61; 32]);
    let stranger = Address::from([0x62; 32]);
    let fresh = || {
        let mut reg = BnsRegistry::new();
        reg.register("edge.bud".to_string(), owner, 10, MIN_DURATION)
            .unwrap();
        reg
    };
    let expires_at = 10 + MIN_DURATION;
    let last_in_grace = expires_at + GRACE_PERIOD - 1;
    let first_after = expires_at + GRACE_PERIOD;

    // Expired, in grace: it resolves to nothing but it is not free.
    let mut reg = fresh();
    assert_eq!(reg.resolve("edge.bud", expires_at), None);
    for epoch in [expires_at, last_in_grace] {
        assert_eq!(
            reg.register("edge.bud".to_string(), stranger, epoch, MIN_DURATION),
            Err(BnsError::NameTaken),
            "a stranger took the name at epoch {epoch}"
        );
        assert!(reg
            .renew("edge.bud", &stranger, epoch, MIN_DURATION)
            .is_err());
    }

    // The owner renews on the last epoch of the window. The new end counts
    // from that epoch, and the record is kept.
    reg.renew("edge.bud", &owner, last_in_grace, MIN_DURATION)
        .unwrap();
    assert_eq!(
        reg.names()["edge.bud"].expires_at,
        last_in_grace + MIN_DURATION
    );
    assert_eq!(reg.resolve("edge.bud", last_in_grace), Some(owner));

    // One epoch later the window is over.
    let mut reg = fresh();
    assert!(reg
        .renew("edge.bud", &owner, first_after, MIN_DURATION)
        .is_err());
    reg.register("edge.bud".to_string(), stranger, first_after, MIN_DURATION)
        .unwrap();
    assert_eq!(reg.resolve("edge.bud", first_after), Some(stranger));
    assert_eq!(reg.names()["edge.bud"].owner, stranger);
}

/// Every name transaction type has a shape rule at admission. A transaction
/// that carries an amount where none belongs, or data that does not decode,
/// is named by the precheck and refused by the pool validation, so it never
/// waits in the mempool for a block to refuse it.
#[test]
fn bns_every_type_has_a_shape_check_at_admission() {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::pow::PoWEngine;
    use std::sync::Arc;

    let chain = Blockchain::new(Arc::new(PoWEngine::new(0)), None, DEFAULT_CHAIN_ID, None);
    let key = KeyPair::generate().unwrap();
    let types = [
        TransactionType::BnsCreateOffer,
        TransactionType::BnsCancelOffer,
        TransactionType::BnsBuyName,
        TransactionType::BnsRenew,
        TransactionType::BnsTransfer,
        TransactionType::BnsSetAddress,
        TransactionType::BnsSetPrimary,
        TransactionType::BnsSetRecords,
        TransactionType::BnsSetContent,
        TransactionType::BnsRegisterSubdomain,
        TransactionType::BnsRemoveSubdomain,
        TransactionType::BnsSetSubdomainContent,
        TransactionType::BnsSetStorage,
    ];
    for tx_type in types {
        let label = format!("{tx_type:?}");
        // Data no type decodes, and an amount only a purchase may carry.
        let bent = tx(&key, 7, 0, tx_type, vec![0xFF]);
        let answer = chain.tx_precheck(&bent);
        let reasons: Vec<String> = answer["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|reason| reason.as_str().map(str::to_string))
            .collect();
        assert!(
            reasons.iter().any(|reason| reason.contains("bns")),
            "{label} has no shape reason at admission: {reasons:?}"
        );
        assert!(
            chain.state.validate_transaction(&bent).is_err(),
            "{label} with bent data passed the pool validation"
        );
    }
}
