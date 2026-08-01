//! Locks for the mempool's asymmetric-DoS defences.
//!
//! The ADAMS family of attacks (DETER, `MemPurge`, and the variants catalogued
//! in the 2024 USENIX mempool study) all rest on the same footing: a mempool
//! that admits transactions it cannot charge for. The classic shape is the
//! *future* transaction - nonce well above the account's next - which can
//! never be mined from the pool it occupies, so the attacker pays nothing
//! while evicting transactions that would have paid. Geth carried this until
//! v1.11.4.
//!
//! This chain does not admit them: `validate_pool_transaction` runs before
//! `Mempool::add_transaction` and rejects any nonce that is not exactly the
//! projected next one, with the projection walking the sender's pending
//! transactions and debiting each cost as it goes.
//!
//! None of that was pinned. The mempool itself has no view of account state -
//! `Mempool::add_transaction` checks the signature, the fee floor, the
//! per-sender cap and RBF, and nothing else - so the entire defence is one
//! call in `Blockchain::add_transaction`. Removing it leaves every mempool
//! unit test green.

use crate::chain::blockchain::Blockchain;
use crate::chain::genesis::GenesisConfig;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use std::sync::Arc;

const CHAIN_ID: u64 = 45262;

fn funded_chain(who: Address) -> Blockchain {
    let mut genesis = GenesisConfig::new(CHAIN_ID);
    genesis = genesis.with_allocation(who, 1_000_000);
    genesis.base_fee = 0;
    let mut bc = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        CHAIN_ID,
        None,
        Some(genesis),
    );
    bc.mempool.set_min_fee(0);
    bc
}

fn signed(kp: &KeyPair, to: Address, amount: u64, fee: u64, nonce: u64) -> Transaction {
    let from = Address::from(kp.public_key_bytes());
    let mut tx = Transaction::new_with_fee(from, to, amount, fee, nonce, vec![]);
    tx.chain_id = CHAIN_ID;
    tx.sign(kp);
    tx
}

/// A transaction whose nonce is ahead of the account must be refused.
///
/// This is the DETER primitive. Admitting it costs the attacker nothing -
/// the transaction cannot be included while the gap exists - but it occupies
/// a slot that a payable transaction would have used.
#[test]
fn a_future_nonce_is_refused_instead_of_parked() {
    let kp = KeyPair::generate().unwrap();
    let sender = Address::from(kp.public_key_bytes());
    let mut bc = funded_chain(sender);

    let far_future = signed(&kp, Address::from([0xBB; 32]), 1, 1, 500);
    let result = bc.add_transaction(far_future);

    assert!(
        result.is_err(),
        "a transaction 500 nonces ahead was admitted. It can never be mined \
         from the pool, so it occupies a slot for free - this is the DETER \
         primitive, fixed in Geth v1.11.4"
    );
    assert_eq!(
        bc.mempool.len(),
        0,
        "the pool must be empty after a refused future transaction"
    );
}

/// Even a gap of one is a gap: nonce N+1 with N absent is unminable.
#[test]
fn a_nonce_gap_of_one_is_still_refused() {
    let kp = KeyPair::generate().unwrap();
    let sender = Address::from(kp.public_key_bytes());
    let mut bc = funded_chain(sender);

    // Account is at nonce 0; submit 1 without 0.
    let gapped = signed(&kp, Address::from([0xBB; 32]), 1, 1, 1);
    assert!(
        bc.add_transaction(gapped).is_err(),
        "nonce 1 was admitted while nonce 0 is missing; the pool cannot mine \
         it and the sender is not chargeable for it"
    );
}

/// The projection must follow the sender's own pending transactions, or a
/// legitimate sequential batch would be rejected after the first.
///
/// Without this the previous two tests could be satisfied by a mempool that
/// simply refuses every nonce above the on-chain one, which would make the
/// pool useless.
#[test]
fn a_sequential_batch_from_one_sender_is_admitted() {
    let kp = KeyPair::generate().unwrap();
    let sender = Address::from(kp.public_key_bytes());
    let mut bc = funded_chain(sender);
    let to = Address::from([0xBB; 32]);

    for nonce in 0..3u64 {
        bc.add_transaction(signed(&kp, to, 10, 1, nonce))
            .unwrap_or_else(|e| {
                panic!(
                    "sequential nonce {nonce} was refused: {e}. The nonce \
                        projection must walk the sender's pending transactions"
                )
            });
    }
    assert_eq!(bc.mempool.len(), 3);
}

/// The projection debits each pending transaction's cost, so a sender cannot
/// queue a batch that only the first transaction can afford.
///
/// This is the `MemPurge` shape: overdraft transactions are admitted, then all
/// but the first turn out to be unpayable at mining time - again occupying
/// slots for free.
#[test]
fn a_batch_that_outruns_the_balance_is_refused_at_the_point_it_does() {
    let kp = KeyPair::generate().unwrap();
    let sender = Address::from(kp.public_key_bytes());

    let mut genesis = GenesisConfig::new(CHAIN_ID);
    // Enough for two transfers of 100 plus fees, not three.
    genesis = genesis.with_allocation(sender, 250);
    genesis.base_fee = 0;
    let mut bc = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        None,
        CHAIN_ID,
        None,
        Some(genesis),
    );
    bc.mempool.set_min_fee(0);
    let to = Address::from([0xBB; 32]);

    assert!(bc.add_transaction(signed(&kp, to, 100, 1, 0)).is_ok());
    assert!(bc.add_transaction(signed(&kp, to, 100, 1, 1)).is_ok());

    assert!(
        bc.add_transaction(signed(&kp, to, 100, 1, 2)).is_err(),
        "a third transfer was admitted although the two ahead of it already \
         commit the balance. Admitting it parks an unpayable transaction in a \
         slot, which is the MemPurge shape"
    );
}

/// The defence lives in `Blockchain::add_transaction`, not in the mempool.
///
/// `Mempool::add_transaction` has no access to account state at all, so
/// anything that reaches it directly bypasses every check above. This pins the
/// call so a refactor cannot quietly move submission past it.
#[test]
fn the_pool_admission_path_still_validates_before_inserting() {
    let src = include_str!("../chain/blockchain.rs");
    let at = src
        .find("pub fn add_transaction(&mut self, transaction: Transaction)")
        .expect("Blockchain::add_transaction was renamed; re-derive this lock");
    let body = &src[at..at + 400];

    let validate = body.find("validate_pool_transaction").expect(
        "Blockchain::add_transaction no longer validates before insertion - \
                 the mempool cannot see account state, so nothing else checks the nonce",
    );
    let insert = body
        .find("self.mempool")
        .expect("Blockchain::add_transaction no longer reaches the mempool");
    assert!(
        validate < insert,
        "validation now runs after insertion; a future or overdraft transaction \
         would occupy a slot before being rejected"
    );
}
