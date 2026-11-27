//! Block budgets measured on the canonical binary protobuf encoding.
//!
//! The measure is the protobuf `encoded_len` of the body and of the witness section, never the
//! JSON length. The body budget is 1,000,000 bytes and the witness budget 2,000,000 bytes; the
//! per-transaction cap is 160 KiB across body plus witness bytes.

use std::fmt;

use prost::Message;

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::network::proto_conversions::pb;

/// The body budget in bytes (transactions, evidence, headers).
pub const BODY_BUDGET_BYTES: usize = 1_000_000;

/// The witness budget in bytes (composite signatures and their witnesses).
pub const WITNESS_BUDGET_BYTES: usize = 2_000_000;

/// The largest single transaction, in binary bytes.
pub const MAX_TX_BYTES: usize = 160 * 1024;

/// Which budget an item is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// The block body.
    Body,
    /// The witness section.
    Witness,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Body => f.write_str("body"),
            Self::Witness => f.write_str("witness"),
        }
    }
}

/// Why an item was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    /// One transaction is larger than [`MAX_TX_BYTES`].
    TxTooLarge(usize),
    /// The section would exceed its budget.
    OverBudget(Section),
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TxTooLarge(bytes) => write!(
                f,
                "transaction binary size {bytes} exceeds MAX_TX_BYTES ({MAX_TX_BYTES})"
            ),
            Self::OverBudget(Section::Body) => {
                write!(f, "body section exceeds budget ({BODY_BUDGET_BYTES} bytes)")
            }
            Self::OverBudget(Section::Witness) => write!(
                f,
                "witness section exceeds budget ({WITNESS_BUDGET_BYTES} bytes)"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

/// Running binary size of a block under construction or validation.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockBudget {
    body: usize,
    witness: usize,
}

impl BlockBudget {
    /// An empty budget.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes charged to `section` so far.
    #[must_use]
    pub const fn used(&self, section: Section) -> usize {
        match section {
            Section::Body => self.body,
            Section::Witness => self.witness,
        }
    }

    /// Charges `bytes` to `section`, refusing an item that does not fit. A refused item
    /// leaves the budget unchanged.
    ///
    /// # Errors
    ///
    /// [`BudgetError::OverBudget`] when the section would pass its budget.
    pub fn charge(&mut self, section: Section, bytes: usize) -> Result<(), BudgetError> {
        let (used, limit) = match section {
            Section::Body => (&mut self.body, BODY_BUDGET_BYTES),
            Section::Witness => (&mut self.witness, WITNESS_BUDGET_BYTES),
        };
        let next = used
            .checked_add(bytes)
            .ok_or(BudgetError::OverBudget(section))?;
        if next > limit {
            return Err(BudgetError::OverBudget(section));
        }
        *used = next;
        Ok(())
    }

    /// Charges one transaction: its body bytes to the body and its witness bytes to the
    /// witness, after the per-transaction bound.
    ///
    /// # Errors
    ///
    /// [`BudgetError::TxTooLarge`] or [`BudgetError::OverBudget`]; nothing is charged on error.
    pub fn charge_tx(
        &mut self,
        body_bytes: usize,
        witness_bytes: usize,
    ) -> Result<(), BudgetError> {
        let total = body_bytes.saturating_add(witness_bytes);
        if total > MAX_TX_BYTES {
            return Err(BudgetError::TxTooLarge(total));
        }
        let before = *self;
        let result = self
            .charge(Section::Body, body_bytes)
            .and_then(|()| self.charge(Section::Witness, witness_bytes));
        if result.is_err() {
            *self = before;
        }
        result
    }
}

/// Partition one transaction's canonical protobuf `encoded_len` into
/// `(body_bytes, witness_bytes)`.
///
/// The witness section consists of signature and signer/authorization proof
/// bytes (`signature`, `signer_public_key`, `authorization`, `auth_claim`);
/// all other transaction fields are charged to the body section.
#[must_use]
pub fn tx_section_bytes(tx: &Transaction) -> (usize, usize) {
    let mut proto = pb::ProtoTransaction::from(tx);
    let total = proto.encoded_len();
    proto.signature.clear();
    proto.signer_public_key.clear();
    proto.authorization = None;
    proto.auth_claim.clear();
    let body = proto.encoded_len();
    let witness = total.saturating_sub(body);
    (body, witness)
}

/// Partition a block's non-transaction envelope (header, slashing evidence, and
/// block-level witnesses) into `(body_bytes, witness_bytes)` using canonical
/// protobuf `encoded_len`.
#[must_use]
fn block_envelope_section_bytes(block: &Block) -> (usize, usize) {
    let mut proto = pb::ProtoBlock::from(block);
    proto.transactions.clear();
    let total = proto.encoded_len();
    proto.signature.clear();
    proto.producer_public_key.clear();
    proto.vrf_proof.clear();
    proto.claim_frame.clear();
    let body = proto.encoded_len();
    let witness = total.saturating_sub(body);
    (body, witness)
}

/// Validate a complete block against the canonical binary protobuf body,
/// witness, and per-transaction budgets.
///
/// # Errors
///
/// Returns [`BudgetError::TxTooLarge`] if any single transaction exceeds
/// [`MAX_TX_BYTES`], or [`BudgetError::OverBudget`] if the cumulative body or
/// witness section exceeds its budget.
pub fn validate_block_budget(block: &Block) -> Result<BlockBudget, BudgetError> {
    let mut budget = BlockBudget::new();
    let (header_body, header_witness) = block_envelope_section_bytes(block);
    budget.charge(Section::Body, header_body)?;
    budget.charge(Section::Witness, header_witness)?;
    for tx in &block.transactions {
        let (tx_body, tx_witness) = tx_section_bytes(tx);
        budget.charge_tx(tx_body, tx_witness)?;
    }
    Ok(budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::core::transaction::TransactionType;

    #[test]
    fn a_transaction_over_the_bound_is_refused_and_uncharged() {
        let mut b = BlockBudget::new();
        assert_eq!(
            b.charge_tx(MAX_TX_BYTES, 1),
            Err(BudgetError::TxTooLarge(MAX_TX_BYTES + 1))
        );
        assert_eq!(b.used(Section::Body), 0);
    }

    #[test]
    fn the_body_budget_is_exact() {
        let mut b = BlockBudget::new();
        b.charge(Section::Body, BODY_BUDGET_BYTES)
            .expect("fits exactly");
        assert_eq!(
            b.charge(Section::Body, 1),
            Err(BudgetError::OverBudget(Section::Body))
        );
    }

    #[test]
    fn a_failed_witness_charge_rolls_the_body_back() {
        let mut b = BlockBudget::new();
        b.charge(Section::Witness, WITNESS_BUDGET_BYTES - 10)
            .expect("fits");
        assert!(b.charge_tx(100, 100).is_err());
        assert_eq!(b.used(Section::Body), 0);
    }

    #[test]
    fn protobuf_section_split_accounts_for_witness_separately_from_body() {
        let mut tx = Transaction::new_with_chain_id(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            10,
            1,
            0,
            vec![0xAA; 1024],
            45262,
            TransactionType::Transfer,
        );
        tx.signature = Some(vec![0xBB; 3309]);
        tx.signer_public_key = vec![0xCC; 1952];
        let (body, witness) = tx_section_bytes(&tx);
        assert!(body >= 1024, "body must account for payload bytes");
        assert!(
            witness >= 3309 + 1952,
            "witness must account for PQ signature and public key bytes"
        );
        assert_eq!(
            body + witness,
            pb::ProtoTransaction::from(&tx).encoded_len()
        );
    }

    #[test]
    fn binary_block_budget_accepts_large_pq_witness_under_two_megabytes() {
        let mut block = Block::new(1, "0".repeat(64), Vec::new());
        block.signature = Some(vec![0x55; 1_500_000]);
        let used = validate_block_budget(&block)
            .expect("1.5 MB witness fits inside the 2 MB witness budget");
        assert!(used.used(Section::Witness) >= 1_500_000);
        assert!(used.used(Section::Body) < 10_000);
    }
}
