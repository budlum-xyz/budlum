//! The one policy every value-moving finality gate applies, in one place.
//!
//! Three questions decide whether a domain row may move value. They are
//! answered here, and nowhere else, so the answers can be read off one screen:
//!
//! 1. **Root** - the row must commit a non-zero `state_root`.
//! 2. **Binds** - the proof this row attests must bind every root the gate is
//!    about to read: `required ⊆ row.guarantee.attestation`. A proof that binds
//!    only the transaction root cannot license a read of the event tree.
//! 3. **Posture** - the quantum posture must satisfy the caller's policy.
//!
//! The gate in [`crate::settlement::finality_gate`] calls [`enforce_root`],
//! [`enforce_binds`], then [`enforce_quantum_posture`], in that order, so a
//! refusal always names the earliest failing condition a caller can act on.
//!
//! ```text
//! use budlum_core::crypto::facts::QuantumClass;
//! use budlum_core::settlement::finality_policy::{
//!     enforce_binds, enforce_quantum_posture, enforce_root, QuantumPosturePolicy,
//!     BINDS_EVENT_ROOT, BINDS_STATE_ROOT,
//! };
//! use budlum_core::settlement::CommitmentAttestation;
//!
//! let binds = CommitmentAttestation {
//!     state_root: true,
//!     tx_root: false,
//!     event_root: false,
//!     parent: true,
//! };
//! assert!(enforce_root([0x11; 32]).is_ok());
//! assert!(enforce_root([0u8; 32]).is_err());
//! // The row binds the state root, so a state-root read is licensed...
//! assert!(enforce_binds(&binds, BINDS_STATE_ROOT.union(BINDS_EVENT_ROOT)).is_err());
//! assert!(enforce_binds(&binds, BINDS_STATE_ROOT).is_ok());
//! assert!(enforce_binds(&binds, BINDS_EVENT_ROOT).is_err());
//! // A hash-only posture meets `AtLeast(Hash)` but not `AtLeast(Lattice)`.
//! assert!(enforce_quantum_posture(QuantumClass::Hash, QuantumPosturePolicy::AtLeast(QuantumClass::Hash)).is_ok());
//! assert!(enforce_quantum_posture(QuantumClass::Hash, QuantumPosturePolicy::AtLeast(QuantumClass::Lattice)).is_err());
//! ```

use crate::crypto::facts::QuantumClass;
use crate::settlement::domains::CommitmentAttestation;

/// The row commits `state_root`; the proof binds it.
pub const BINDS_STATE_ROOT: CommitmentAttestation = CommitmentAttestation {
    state_root: true,
    tx_root: false,
    event_root: false,
    parent: false,
};

/// The row commits `tx_root`; the proof binds it.
pub const BINDS_TX_ROOT: CommitmentAttestation = CommitmentAttestation {
    state_root: false,
    tx_root: true,
    event_root: false,
    parent: false,
};

/// The row commits `event_root`; the proof binds it.
pub const BINDS_EVENT_ROOT: CommitmentAttestation = CommitmentAttestation {
    state_root: false,
    tx_root: false,
    event_root: true,
    parent: false,
};

/// The row commits `parent_domain_block_hash`; the proof binds it.
pub const BINDS_PARENT: CommitmentAttestation = CommitmentAttestation {
    state_root: false,
    tx_root: false,
    event_root: false,
    parent: true,
};

/// Every root a cross-domain value route reads at once.
pub const BINDS_VALUE_ROUTE: CommitmentAttestation = BINDS_STATE_ROOT
    .union(BINDS_TX_ROOT)
    .union(BINDS_EVENT_ROOT)
    .union(BINDS_PARENT);

/// Which quantum posture a caller is willing to settle under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumPosturePolicy {
    /// Any of the three classes satisfies the policy.
    Any,
    /// The posture must be no weaker than the one named here.
    AtLeast(QuantumClass),
}

impl QuantumPosturePolicy {
    /// The relative strength order: `Classical < Lattice < Hash`.
    ///
    /// Lattice keys survive Shor's algorithm and hash preimages survive both
    /// Shor and Grover at the relevant sizes, so `Hash` is the strongest
    /// assumption, `Lattice` sits between, and `Classical` is broken by Shor.
    const fn rank(class: QuantumClass) -> u8 {
        match class {
            QuantumClass::Classical => 0,
            QuantumClass::Lattice => 1,
            QuantumClass::Hash => 2,
        }
    }

    /// Whether `class` satisfies this policy.
    #[must_use]
    pub const fn admits(self, class: QuantumClass) -> bool {
        match self {
            Self::Any => true,
            Self::AtLeast(required) => Self::rank(class) >= Self::rank(required),
        }
    }
}

/// Condition 1: the row must commit a non-zero `state_root`.
///
/// # Errors
///
/// Returns the all-zero root as the failing value, which is the only root a
/// registry row carries before a commitment has produced one.
pub fn enforce_root(state_root: [u8; 32]) -> Result<(), [u8; 32]> {
    if state_root == [0u8; 32] {
        return Err(state_root);
    }
    Ok(())
}

/// Condition 2: what the proof binds must cover every root the gate reads.
///
/// `covers` is a subset test, so a row that binds *more* passes, and a row
/// that binds *less* is refused. The order of the two arguments is the whole
/// contract: `attestation` is what the proof proves, `required` is what the
/// caller is about to read.
///
/// # Errors
///
/// Returns `required` unchanged: the caller already knows what it was about
/// to read, and the message must name that, not the row.
pub fn enforce_binds(
    attestation: &CommitmentAttestation,
    required: CommitmentAttestation,
) -> Result<(), CommitmentAttestation> {
    if attestation.covers(&required) {
        return Ok(());
    }
    Err(required)
}

/// Condition 3: the posture must satisfy the caller's policy.
///
/// # Errors
///
/// Returns the observed class so the refusal can name it.
pub fn enforce_quantum_posture(
    observed: QuantumClass,
    policy: QuantumPosturePolicy,
) -> Result<(), QuantumClass> {
    if policy.admits(observed) {
        return Ok(());
    }
    Err(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_masks_are_single_bit_and_union_is_the_whole_route() {
        let masks = [
            BINDS_STATE_ROOT,
            BINDS_TX_ROOT,
            BINDS_EVENT_ROOT,
            BINDS_PARENT,
        ];
        for (i, mask) in masks.iter().enumerate() {
            let bits = [
                u8::from(mask.state_root),
                u8::from(mask.tx_root),
                u8::from(mask.event_root),
                u8::from(mask.parent),
            ];
            assert_eq!(bits.iter().sum::<u8>(), 1, "mask {i} is not a single root");
        }
        assert_eq!(
            BINDS_VALUE_ROUTE,
            CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            }
        );
    }

    #[test]
    fn enforce_root_refuses_exactly_the_zero_root() {
        assert!(enforce_root([0u8; 32]).is_err());
        assert!(enforce_root([1u8; 32]).is_ok());
        let mut almost_zero = [0u8; 32];
        almost_zero[31] = 1;
        assert!(enforce_root(almost_zero).is_ok());
    }

    #[test]
    fn parent_only_proof_refuses_every_root_read() {
        // The mask exists so callers name a parent read explicitly; a row
        // that binds only the parent must be refused for each of the other
        // three roots, one by one - not just as a whole-route failure.
        let parent_only = BINDS_PARENT;
        for required in [BINDS_STATE_ROOT, BINDS_TX_ROOT, BINDS_EVENT_ROOT] {
            assert!(
                enforce_binds(&parent_only, required).is_err(),
                "parent-only proof must not satisfy {required:?}"
            );
        }
        assert!(enforce_binds(&parent_only, BINDS_PARENT).is_ok());
    }

    #[test]
    fn enforce_binds_is_a_subset_test_not_an_equality_test() {
        let narrow = CommitmentAttestation {
            state_root: true,
            tx_root: false,
            event_root: false,
            parent: true,
        };
        let wide = narrow.union(BINDS_EVENT_ROOT);
        // Wider binds pass a narrower requirement...
        assert!(enforce_binds(&wide, BINDS_STATE_ROOT).is_ok());
        assert!(enforce_binds(&wide, BINDS_EVENT_ROOT).is_ok());
        // ...but not the whole route until every root is bound.
        assert!(enforce_binds(&wide, BINDS_VALUE_ROUTE).is_err());
        let full = wide.union(BINDS_TX_ROOT);
        assert!(enforce_binds(&full, BINDS_VALUE_ROUTE).is_ok());
        // ...and narrower binds fail a wider one, naming what was required.
        assert_eq!(
            enforce_binds(&narrow, BINDS_VALUE_ROUTE),
            Err(BINDS_VALUE_ROUTE)
        );
        assert!(enforce_binds(&narrow, BINDS_EVENT_ROOT).is_err());
    }

    #[test]
    fn posture_policy_orders_classical_below_lattice_below_hash() {
        use QuantumPosturePolicy::{Any, AtLeast};
        assert!(Any.admits(QuantumClass::Classical));
        assert!(AtLeast(QuantumClass::Classical).admits(QuantumClass::Hash));
        assert!(AtLeast(QuantumClass::Hash).admits(QuantumClass::Hash));
        assert!(!AtLeast(QuantumClass::Hash).admits(QuantumClass::Lattice));
        assert!(!AtLeast(QuantumClass::Lattice).admits(QuantumClass::Classical));
        assert_eq!(
            enforce_quantum_posture(QuantumClass::Classical, AtLeast(QuantumClass::Lattice)),
            Err(QuantumClass::Classical)
        );
    }
}
