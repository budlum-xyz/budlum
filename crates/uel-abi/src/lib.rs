//! Universal Execution Layer ABI.
//!
//! The contract between the Execution Coordinator in the node process and the
//! execution-environment workers (`budlum-ee-*`), one binary per environment:
//!
//! - [`host`]: the `ExecutionEnvironment`, `HostApi` and `HostRead` traits;
//! - [`types`]: the values they exchange, each with its bound;
//! - [`pb`] and [`wire`]: the protobuf messages and the validating conversions;
//! - [`frame`]: the `u32`-length framing, the 16 MiB bound and the ABI version
//!   check;
//! - [`transport`]: the Unix-socket client and server, request ids, the 2 second
//!   watchdog and reconnection;
//! - [`mock`]: a deterministic mock environment and an in-memory host.

/// The protobuf messages generated from `proto/budlum/execution/v1/ee.proto`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/budlum.execution.v1.rs"));
}

pub mod frame;
pub mod host;
pub mod mock;
pub mod transport;
pub mod types;
mod wire;

pub use frame::{ABI_VERSION, MAX_FRAME_BYTES};
pub use host::{panic_digest, panic_message, ExecutionEnvironment, HostApi, HostRead};
pub use types::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, HostError, Namespace, OutOfGas, OutcomeStatus, RefusalCode,
    UniversalCall, UniversalResult, WireError,
};
