//! The execution coordinator. A later step builds the coordinator
//! itself; this module holds the parts that already stand on their own.
//!
//! WIRING: the block executor reaches the scheduler once the coordinator
//! runs blocks through it; until then it is exercised by its
//! equality tests against sequential execution. The foreign-envelope lane
//! (WP-32, 2/N) is wired to the Aptos REST refusal surface through
//! `src/rpc/compat/aptos/move_worker.rs`.

pub mod foreign;
pub mod scheduler;
