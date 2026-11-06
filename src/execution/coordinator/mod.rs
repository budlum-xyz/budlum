//! The execution coordinator and deterministic parallel block scheduler.
//!
//! WIRING: `scheduler::execute_block_checked` executes blocks wave-by-wave
//! with multithreaded worker waves and deterministic sequential fallback,
//! guaranteed byte-identical to `Executor::apply_block_checked`.

pub mod scheduler;
pub use scheduler::{execute_block_checked, ParallelExecutionConfig, ScheduleReport};
