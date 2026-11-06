//! Execution-environment ABI and worker client surface (`BLG-250`).
//!
//! WIRING: consumed by [`crate::execution::coordinator::worker_manager`], which
//! supervises out-of-process `budlum-ee-*` workers over [`abi::transport::EeClient`].

pub use budlum_uel_abi as abi;
pub use crate::execution::coordinator::worker_manager::{
    CoordinatorBlockError, ExecutionCoordinator, UelCallReceipt, WorkerPool,
    MAX_BLOCK_WORKER_ATTEMPTS, WORKER_RLIMIT_AS_BYTES, WORKER_WATCHDOG,
};
