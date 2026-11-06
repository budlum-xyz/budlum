//! Node state recovery: the stage ledger, the health assessment, the
//! recovery mempool and the node runtime tick that drives them.
//!
//! A node whose local view diverges from the sealed canonical view does
//! not split the network and does not guess: it reverts to a sealed stage
//! through the ledger, keeps the transactions the reversion gave up, and
//! grows back along the canonical chain. This tree is that machinery. It
//! is not content storage and it is not a domain: it repairs the node's
//! own state.
//!
//! | Module | Content |
//! |---|---|
//! | [`regeneration_stage`] | The recovery ledger and its stages, reversions and audit trail |
//! | [`regen_health`] | The health assessment over sealed stage snapshots |
//! | [`regen_mempool`] | Transactions a reversion gave up, kept for re-offer |
//! | [`regen_health_tick`] | The node runtime tick: assess, revert or repair, grow back |

pub mod regen_health;
pub mod regen_mempool;
pub mod regen_health_tick;
pub mod regeneration_stage;
pub mod tick;

pub use health::{assess, AlarmReason, HealthPolicy, HealthVerdict};
pub use mempool::RecoveryMempool;
pub use stage::RecoveryLedger;
