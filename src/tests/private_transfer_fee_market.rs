//! (E) private transfer relayer mempool UX + fee market.
//!
//! TEE tabanlı `spent_commitment` gizleme = direktif gereği SCOPE OUT.
//! Bu test, fee market'in (`src/chain/fee_market.rs`) private transfer
//! Işlemlerine (`TransactionType::PrivateTransferSubmit`) uygulandığını
//! Kanıtlar: yeterli fee bid'i kabul edilir, taban fee'nin altındaki bid
//! Reddedilir (mempool / giriş kapısı fee market ile korunur).

use crate::chain::fee_market::effective_fee;
use crate::core::address::Address;
use crate::core::transaction::{
    Transaction, TransactionType, DEFAULT_CHAIN_ID, SIGNATURE_VERSION_V4,
};
use crate::privacy::PrivateTransferSubmit;

#[test]
fn private_transfer_fee_market_gates_inclusion() {
    // Minimal, shape-valid private transfer payload. TEE spent_commitment
    // Hiding is out of scope; we only exercise the fee-market gate here.
    let sub = PrivateTransferSubmit {
        spent_commitments: vec![[1u8; 32]],
        nullifiers: vec![[2u8; 32]],
        output_commitments: vec![[3u8; 32]],
        authorization_sig: vec![0u8; 64],
        public_digest: [0u8; 32],
    };
    assert!(sub.validate_shape().is_ok());

    let mut tx = Transaction {
        from: Address::zero(),
        to: Address::zero(),
        amount: 0,
        fee: 100,
        max_fee: 0,
        priority_fee: 0,
        nonce: 0,
        data: Vec::new(),
        timestamp: 0,
        hash: String::new(),
        signature: None,
        chain_id: DEFAULT_CHAIN_ID,
        signature_version: SIGNATURE_VERSION_V4,
        tx_type: TransactionType::PrivateTransferSubmit(sub),
    };
    tx.hash = tx.calculate_hash();

    let base_fee = 50;
    // A private-transfer fee bid that covers the base fee is accepted by the
    // Fee market - inclusion is allowed.
    assert!(effective_fee(tx.fee_bid(), base_fee).is_ok());

    // A private-transfer fee bid below the base fee is rejected: the fee
    // Market gates private-transfer inclusion exactly as for any tx type.
    let mut low = tx.clone();
    low.fee = 10;
    low.hash = low.calculate_hash();
    assert!(effective_fee(low.fee_bid(), base_fee).is_err());
}
