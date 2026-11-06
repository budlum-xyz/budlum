//! Ethereum JSON-RPC compatibility gateway (section 8.11.1, port 18547).
//!
//! # What this gateway is
//!
//! A client built for Ethereum - MetaMask, an ethers script, a Foundry test -
//! is pointed at this listener and speaks its own vocabulary. The gateway
//! answers in that vocabulary and, where it cannot answer honestly, says so in
//! the way that client already understands.
//!
//! # What it must not become
//!
//! A translation layer with opinions. Every answer here is a restatement of
//! something this chain already decided: a block, a receipt, an account's
//! balance. The place where Ethereum's vocabulary and this chain's semantics
//! cannot be reconciled is marked and refused rather than approximated -
//! `eth_getProof` is the first, and the reason it is refused instead of
//! emulated is written in [`methods`].
//!
//! # Ordering rules a compatibility gateway inherits
//!
//! * **Reads, submits, and node-local bookkeeping only.** There is no arm of
//!   [`methods::Effect`] that changes consensus state. A gateway that could
//!   would let a client move this chain's state outside a block, which is the
//!   one thing every other door in this tree was built to prevent.
//! * **The operator listener is a superset, never a different protocol.**
//!   Debug tracing is added there; the public answers do not change.
//! * **Bounded node-local state.** Filters and subscriptions are memory this
//!   node spends on behalf of one caller, so both are counted and capped
//!   ([`limits`]), and a client that opens them all is refused with the
//!   Ethereum code a client already retries on.
//!
//! The transport, the handlers and the block-and-receipt encoding land
//! incrementally; this module states the surface and the limits those handlers
//! are held to, and a handler that is absent refuses by name rather than
//! failing at the transport.

pub mod limits;
pub mod methods;

pub use limits::{FilterBudget, MAX_FILTERS_PER_PEER, MAX_FILTER_TTL_BLOCKS};
pub use methods::{is_served, lookup, render, Effect, Listener, Method, Refusal, METHODS};
