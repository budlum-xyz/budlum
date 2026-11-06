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
//! * [`solana`]: the Solana JSON-RPC subset of Section 8.11.3. This is
//!   delivery 1/N of WP-31: the namespace, the class table, the honest
//!   chain reads and the named refusals. `docs/SOLANA_RPC.md` records what is
//!   served and what waits for the SVM execution environment and the
//!   dedicated listener.

pub mod solana;
