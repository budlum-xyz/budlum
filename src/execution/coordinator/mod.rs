//! The execution coordinator. A later step builds the coordinator
//! itself; this module holds the parts that already stand on their own.
//!
//! WIRING: the block executor reaches the scheduler once the coordinator
//! runs blocks through it; until then it is exercised by its
//! equality tests against sequential execution.

pub mod migration;
pub mod scheduler;
pub mod foreign;
