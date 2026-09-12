//! The chain's money type.
//!
//! [`Bud`] is a quantity of BUD: a `u64` in the only unit a balance can
//! hold, wrapped so that reaching it from anything wider is a refusal and
//! reaching it from a raw integer is a named constructor. The audit trail
//! behind it: a `u128` bridge amount left the "fits a balance" invariant
//! entirely to callers and every settle path narrowed it back where nobody
//! re-checked (F-10); the fee legs of the split were narrowed with
//! `u64::try_from` calls that existed only to undo a widening nobody
//! needed (F-9); and an unlock path took the fee ceiling check its mint
//! sibling had (F-8). The type carries the invariant now.
//!
//! There is deliberately **no `From<u128>` and no `From<u64>`**: a cast
//! must never silently become money. A wider value arrives through
//! [`TryFrom`] (a refusal at the boundary), a raw `u64` arrives through
//! [`Bud::new`] (a greppable, named boundary), and money reaches a balance
//! through [`Bud::get`] in plain sight.

use serde::{Deserialize, Serialize};

/// A quantity of BUD, bounded to what a balance can hold.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Bud(u64);

impl Bud {
    /// Name the boundary: a raw `u64` becomes money here and only here.
    #[must_use]
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    /// The raw `u64` a balance, a hash preimage or a wire field needs.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Money is never zero on a bridge path: locks, burns and splits all
    /// refuse zero at their own doors, so a zero here is a lost check.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl TryFrom<u128> for Bud {
    /// A single-condition refusal, so the error is the condition stated in
    /// words, not a type built to carry it.
    type Error = &'static str;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        u64::try_from(value)
            .map(Self)
            .map_err(|_| "bud amount exceeds u64::MAX")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_accepts_the_whole_u64_range_and_refuses_one_more() {
        assert_eq!(Bud::try_from(0u128), Ok(Bud::new(0)));
        assert_eq!(Bud::try_from(u64::MAX as u128), Ok(Bud::new(u64::MAX)));
        assert_eq!(
            Bud::try_from(u128::from(u64::MAX) + 1),
            Err("bud amount exceeds u64::MAX"),
            "one unit above the widest balance must be refused, not narrowed"
        );
        assert_eq!(Bud::try_from(u128::MAX), Err("bud amount exceeds u64::MAX"));
    }

    /// The persisted row of a `Bud` field is the row a plain `u64` field
    /// produced: the newtype must not move a wire or disk format.
    #[test]
    fn the_encoding_is_indistinguishable_from_a_plain_u64() {
        let as_bud = bincode::serialize(&Bud::new(7)).expect("serializes");
        let as_u64 = bincode::serialize(&7u64).expect("serializes");
        assert_eq!(as_bud, as_u64);
        let reloaded: Bud = bincode::deserialize(&as_u64).expect("deserializes");
        assert_eq!(reloaded.get(), 7);
    }

    #[test]
    fn zero_and_ordering_behave_like_the_underlying_units() {
        assert!(Bud::new(0).is_zero());
        assert!(!Bud::new(1).is_zero());
        assert!(Bud::new(1) < Bud::new(2));
        assert_eq!(Bud::default(), Bud::new(0));
    }
}
