//! The execution-environment interface as the node sees it (directive 8.3).
//!
//! WIRING: unwired - the Execution Coordinator (work package WP-26) is the first
//! consumer of [`abi::transport::EeClient`]; this module is where it attaches. The
//! ABI itself is covered by the crate's own tests (`crates/uel-abi/tests`), which run
//! the mock environment over a real socket.

pub use budlum_uel_abi as abi;
