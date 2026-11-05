//! Universal Execution Layer ABI (directive section 8.3).

/// The protobuf messages generated from `proto/budlum/execution/v1/ee.proto`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/budlum.execution.v1.rs"));
}

pub mod frame;
