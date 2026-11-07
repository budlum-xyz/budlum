//! B.U.D. 3.0 storage layer - temporary interface (IP-07).
//!
//! Until IP-18..IP-21 land, B.U.D. 3.0 is not ready. This module provides the
//! minimal temporary reference type so dependent crates can compile while the
//! storage door stays fail-closed (`Bud3NotReady`).

pub mod content_ref;

pub use content_ref::ContentRef;
