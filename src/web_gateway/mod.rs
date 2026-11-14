//! WIRING: wired - `src/bin/budlum-gateway.rs` mounts every layer here on a
//! socket. The binary holds no rules of its own: it parses the configuration,
//! reads the RPC answers into the proof type, and hands each decision to the
//! function in this module that has a test.
//!
//! Still absent, and named so they are not mistaken for done: the B.U.D. 3.0
//! content source (the binary uses a directory source today and refuses to
//! start without one), the light client that would fill `PinnedHeaderRoots`
//! with verified roots and epochs, the sealed-content symbol-bundle path, TLS
//! termination and `ops/gateway/`. A gateway whose pinned header set is empty
//! answers 502 to every request, which is the honest state until the light
//! client is wired.
//!
//! The `budlum.xyz` network gateway (B14).
//!
//! A `.bud` name resolves to a site through the chain, not through DNS. The
//! gateway turns an incoming `Host` header into a registry name and a
//! subdomain label, resolves that name against a proof the light client has
//! already verified, and serves the content the record points at.
//!
//! # Why it is a separate crate-level module and not part of consensus
//!
//! The gateway is not part of the chain. It holds no keys, writes no
//! transactions except the paid-view receipt it pays for its own cache fills,
//! and its answer is never authoritative: every response is derived from a
//! header the caller can check. A gateway that lied would be caught by the
//! same proof a browser extension checks locally. The domain name, the DNS
//! records and the IP address are all things that can be blocked, and the
//! extension path exists so that blocking them costs the reader nothing.
//!
//! # Layering
//!
//! - [`host`] is pure: a `Host` header in, a [`host::Target`] out. No I/O, so
//!   every ambiguity in the rule is a unit test rather than a live incident.
//! - [`manifest`] is pure: a site manifest in, a resolved route out. The
//!   traversal rule lives here and nowhere else.
//! - [`policy`] is pure: the response headers, the rate limiter and the block
//!   list. A block list affects this gateway only; it never touches a chain
//!   record.
//! - [`resolve`] is the trust boundary. It holds [`resolve::resolve_verified`],
//!   the one place where a root, a proof and a record meet, and it is written
//!   against two small traits so the trust argument is testable without a
//!   node, a socket or a certificate. The HTTP client and the process entry
//!   point are the parts that need a live chain, and they hold no rules.
//!
//! # What is not here yet
//!
//! The server process (`src/bin/budlum-gateway.rs`), the TLS terminator, the
//! symbol-bundle path for sealed content and the deployment units are not in
//! this change. They are the parts that need a live certificate, a DNS provider
//! and a host, and none of them changes an answer below: a gateway that mounts
//! these modules cannot serve a byte that did not fold to a verified root.

pub mod host;
pub mod manifest;
pub mod policy;
pub mod resolve;
