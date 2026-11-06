//! Compatibility gateways: other chains' JSON-RPC, spoken by this node.
//!
//! Section 8.11.1 gives each gateway its own listener and its own port, and
//! section 8.11.1 states the rule that makes them safe to run at all: a
//! compatibility gateway **reads**, and hands a signed transaction to the
//! mempool. It never applies state. Anything a client sends that would change
//! state outside block execution has no class here, so a new method cannot be
//! classified and therefore cannot be served - the same shape as
//! [`crate::rpc::method_class`] for the native `bud_*` surface.
//!
//! | Gateway | Listener | Code |
//! |---|---|---|
//! | Ethereum JSON-RPC | `127.0.0.1:18547` | this tree |
//!
//! # Why the port is bound to loopback
//!
//! A compatibility gateway answers in another chain's vocabulary, including
//! answers that are wrong for this chain (`eth_getProof`, for one: no MPT
//! exists to prove against). Section 8.11.1 puts the public name in front of
//! it through a TLS terminator that routes by path, so the loopback bind is
//! not an accident of defaults that a config file can widen; the operator
//! listens on the public name, and the gateway keeps speaking to `127.0.0.1`.

pub mod ethereum;
