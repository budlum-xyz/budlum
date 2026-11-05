//! The execution coordinator (directive 8.3). WP-26 builds the coordinator
//! itself; this module holds the parts that already stand on their own.
//!
//! WIRING: the block executor reaches the scheduler once the coordinator
//! (WP-26) runs blocks through it; until then it is exercised by its
//! equality tests against sequential execution.

pub mod scheduler;
