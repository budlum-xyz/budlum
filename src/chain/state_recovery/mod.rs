//! Node state recovery: the recovery ledger, the health assessment and the
//! mempool of pending recoveries. The node reproduces its canonical state by
//! re-execution; this is node maintenance, never content storage.

pub mod regen_health;
pub mod regen_health_tick;
pub mod regen_mempool;
pub mod regeneration_stage;
