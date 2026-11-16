//! The proving backend: what produces and checks the proof of a frame.

use super::frame::{ClaimFrame, FrameError};
use super::object::ObjectError;
use super::pool::PoolItem;
use crate::core::address::Address;
use crate::domain::types::DomainId;

/// What a tick is proven for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickCtx {
    /// The domain of the claims.
    pub domain: DomainId,
    /// The aggregator that proves the tick and earns its share.
    pub aggregator: Address,
}

/// Why a backend refused to prove or to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggError {
    /// The frame breaks a structure rule.
    Frame(FrameError),
    /// An object does not stand for its claim.
    Object(ObjectError),
    /// An item belongs to another domain than the tick.
    WrongDomain,
    /// The payload of an item is gone: it was proven before.
    PayloadPruned,
    /// The proof bytes are malformed.
    MalformedProof,
    /// The proof was made under another parameter set.
    WrongParameterSet,
    /// The proof does not cover the claims of the frame.
    ProofMismatch,
    /// This build has no backend that could prove or check a frame.
    Unavailable,
}

impl std::fmt::Display for AggError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::Object(e) => write!(f, "object: {e}"),
            Self::WrongDomain => write!(f, "an item belongs to another domain"),
            Self::PayloadPruned => write!(f, "the payload of an item was pruned"),
            Self::MalformedProof => write!(f, "the proof bytes are malformed"),
            Self::WrongParameterSet => write!(f, "the proof belongs to another parameter set"),
            Self::ProofMismatch => write!(f, "the proof does not cover the claims"),
            Self::Unavailable => write!(f, "this build has no aggregation backend"),
        }
    }
}

impl std::error::Error for AggError {}

impl From<FrameError> for AggError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<ObjectError> for AggError {
    fn from(e: ObjectError) -> Self {
        Self::Object(e)
    }
}

/// A proving backend.
pub trait AggBackend {
    /// Prove one tick: the frame over the claims of `items`, sorted by digest.
    ///
    /// # Errors
    ///
    /// [`AggError`] when an item cannot be proven.
    fn prove_tick(&self, ctx: &TickCtx, items: &[PoolItem]) -> Result<ClaimFrame, AggError>;

    /// The proof of the merge of two verified frames.
    ///
    /// # Errors
    ///
    /// [`AggError`] when a proof cannot be merged.
    fn prove_merge(&self, left: &ClaimFrame, right: &ClaimFrame) -> Result<Vec<u8>, AggError>;

    /// Check the frame: its structure and its proof against the public input
    /// its segments and shape fold to.
    ///
    /// # Errors
    ///
    /// [`AggError`] when the frame is not valid.
    fn verify(&self, frame: &ClaimFrame, domain: DomainId) -> Result<(), AggError>;
}
