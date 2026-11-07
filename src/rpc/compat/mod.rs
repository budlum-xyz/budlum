//! Compatibility RPC gateways (directive Section 8.11).
//!
//! A gateway answers another ecosystem's client in that ecosystem's own
//! vocabulary. It is a translation layer over Budlum state, never a second
//! source of truth: an answer is read from the chain, and a call that would
//! need an execution environment this node does not run is refused by name
//! instead of answered with a guess.
//!
//! Every gateway keeps the `src/rpc/method_class.rs` pattern. One table
//! states, for each method, which listener serves it and what a successful
//! call does. The table is the review surface: a method that is not in it
//! cannot be served, and the gateway tests hold the table, the declarations
//! in `src/rpc/api.rs` and the rows in `src/rpc/method_class.rs` to the same
//! answer.
//!
//! # Gateways
//!
//! * [`aptos`]: the Aptos REST subset of Section 8.11.4, with shared
//!   admission and a dedicated loopback listener. Move-state routes refuse
//!   by name until the Move worker exists.
//! * [`solana`]: the Solana JSON-RPC subset of Section 8.11.3: the namespace,
//!   the class table, honest chain reads, named refusals, the chain-backed
//!   slot feed and a dedicated loopback HTTP/WebSocket listener. The SVM
//!   account model and its four state-dependent subscriptions wait for the
//!   SVM worker. `docs/SOLANA_RPC.md` records the boundary.

pub mod aptos;
pub mod solana;
