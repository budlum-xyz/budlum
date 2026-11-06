//! The foreign-envelope lane of the execution coordinator (directive 8.6.2).
//!
//! A foreign account keeps its own ecosystem's signature. It cannot touch a
//! quantum-safe holding (Y-7, K-3). Its envelope is admitted through one door,
//! checked once for replay, and then handed to the execution environment of
//! its family. Only the Aptos/Move family is wired here (WP-32, 2/N). The
//! ethereum, cosmos and solana modules are owned by WP-27, WP-29 and WP-31;
//! an integrator that merges those PRs appends their `pub mod` lines here
//! without changing this file's shape.

pub mod aptos;

pub use aptos::{
    move_alias, AptosEnvelope, AptosRefusal, BcsError, ForeignReplayCache, APTOS_CHAIN_ID,
    MOVE_ALIAS_SCHEME_BYTE,
};

/// A foreign transaction envelope, by the family that produced it.
///
/// `Foreign::Aptos` is the name directive 8.6.2 uses. Other variants are added
/// by the packages that own those families; adding one does not change this
/// variant's wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Foreign {
    /// An Aptos BCS transaction: chain id 205, sequence number and expiry.
    Aptos(AptosEnvelope),
}

impl Foreign {
    /// The envelope of this foreign transaction.
    #[must_use]
    pub const fn envelope(&self) -> &AptosEnvelope {
        match self {
            Self::Aptos(envelope) => envelope,
        }
    }

    /// The native door that refuses this envelope until the Move worker runs.
    #[must_use]
    pub const fn worker_door(&self) -> &'static str {
        aptos::MOVE_WORKER_DOOR
    }
}
