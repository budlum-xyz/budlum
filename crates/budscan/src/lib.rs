// Unsafe lock: this crate is at 0 unsafe today. The moment an `unsafe` block
// enters, compilation FAILS (a regression gate). The same policy as the main
// crate.

//! Budscan: Budlum's decentralised browser core.
//!
//! # What the browser does
//!
//! The user types `ayaz.bud` into the address bar. The browser then:
//!
//! 1. Classifies what was typed ([`query`]): a name, an address, an NFT or a
//!    scheme.
//! 2. Runs it through the name rule ([`name_rule`]).
//! 3. Resolves the name: from BNS for `.bud` ([`bns_proof`]), from ENS for
//!    `.eth` ([`ens`]).
//! 4. Fetches the content ([`fetch`]).
//! 5. **Verifies that the bytes it fetched are the bytes that were asked
//!    for.**
//! 6. Hands the verified bytes to Gecko as a page ([`resolve`]).
//!
//! The fifth step is why this browser exists. On today's web a browser does
//! not know that the bytes the server sent are the right bytes; TLS only says
//! who the counterparty is, not what the content is. On a content-addressed
//! network this is different: `manifest_id` is the hash of the bytes, so
//! verification is a comparison.
//!
//! # The engine is not written, it is patched
//!
//! A browser engine is three things: an HTML/CSS layout engine, a JavaScript
//! engine and a sandbox. All three are decades of work and all three are the
//! entire attack surface. A web3 browser that writes its own engine adds a
//! browser-security problem next to the problem it set out to solve.
//!
//! Budscan writes no engine: it patches Gecko. This crate is the **decision
//! authority behind those patches**; the patch layer under `browser/` adds the
//! `bud://` protocol handler and the address-bar indicator, and refers every
//! decision back here.
//!
//! # No shell
//!
//! Nothing is a shell, the patch tooling included. The reason was measured
//! twice in the past: a misspelled variable is not an error in a shell but an
//! empty string, so a check can inspect nothing and still say OK. The patch
//! tooling lives inside [`patchset`], written in Rust.
//!
//! # What is not verified is written down too
//!
//! Part of this crate is a record of **what cannot be done**:
//!
//! * BNS resolution cannot be proven per name today, because
//!   `BnsRegistry::root()` writes the whole ledger into a single SHA-256
//!   stream ([`bns_proof`]).
//! * Ethereum has several light-client formats and none of them were
//!   implemented on the client side ([`light_client`]).
//! * IPFS `dag-pb` multi-block content is not verified ([`cid`]).
//! * There is no fetcher for IPNS or Swarm ([`resolve`]).
//!
//! None of these is silently labelled `verified`; each falls to a lower
//! strength through [`evidence::Strength`].

pub mod arweave;
pub mod bns_proof;
pub mod cid;
pub mod content_id;
pub mod ens;
pub mod evidence;
pub mod evm_audit;
pub mod fetch;
pub mod light_client;
pub mod name_rule;
pub mod patchset;
pub mod punycode;
pub mod query;
pub mod resolve;
pub mod search;

pub use content_id::ContentId;
pub use evidence::{Claim, Evidence, Strength};
pub use name_rule::{check_name, NameRejection};
pub use query::{classify, Query};
pub use resolve::Page;

/// This crate's version; used in badges and patch headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
