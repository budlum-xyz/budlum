//! Block budgets measured on the binary encoding.
//!
//! The measure is the protobuf `encoded_len` of the body and of the witness section, never the
//! JSON length. The body budget is 1,000,000 bytes and the witness budget 2,000,000 bytes; the
//! propagation measurement tunes the witness budget, so it is a constant here and not
//! a consensus fact before then.

/// The body budget in bytes (transactions, evidence, headers).
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const BODY_BUDGET_BYTES: usize = 1_000_000;

/// The witness budget in bytes (composite signatures and their witnesses).
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const WITNESS_BUDGET_BYTES: usize = 2_000_000;

/// The largest single transaction, in binary bytes.
pub const MAX_TX_BYTES: usize = 160 * 1024;

/// Which budget an item is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub enum Section {
    /// The block body.
    Body,
    /// The witness section.
    Witness,
}

/// Why an item was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub enum BudgetError {
    /// One transaction is larger than [`MAX_TX_BYTES`].
    TxTooLarge(usize),
    /// The section would exceed its budget.
    OverBudget(Section),
}

/// Running binary size of a block under construction or validation.
#[derive(Debug, Default, Clone, Copy)]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
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
    pub fn used(&self, section: Section) -> usize {
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
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
