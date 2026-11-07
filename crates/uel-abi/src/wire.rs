//! Conversions between the crate's types and the protobuf messages.
//!
//! Building a type from the wire is the validation point: every bound in
//! `types.rs` is checked here, so code past this module holds only values that
//! satisfy their type.

use crate::pb;
use crate::types::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog,
    EeOutcome, EeQuery, EeRefusal, HostError, OutcomeStatus, RefusalCode, UniversalCall,
    UniversalResult, WireError, MAX_IDENTITY_BYTES, MAX_LOG_TOPICS, MAX_TOPIC_BYTES,
};

fn ee_id(value: u32) -> Result<EeId, WireError> {
    u8::try_from(value)
        .map(EeId)
        .map_err(|_| WireError::BadEeId)
}

fn fixed32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], WireError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| WireError::BadLength { field })
}

fn need<T>(value: Option<T>, field: &'static str) -> Result<T, WireError> {
    value.ok_or(WireError::Missing { field })
}

impl From<&EeIdentity> for pb::Identity {
    fn from(value: &EeIdentity) -> Self {
        Self {
            ee: u32::from(value.ee.0),
            id: value.id.clone(),
        }
    }
}

impl TryFrom<pb::Identity> for EeIdentity {
    type Error = WireError;
    fn try_from(value: pb::Identity) -> Result<Self, WireError> {
        if value.id.len() > MAX_IDENTITY_BYTES {
            return Err(WireError::TooLong { field: "identity" });
        }
        Ok(Self {
            ee: ee_id(value.ee)?,
            id: value.id,
        })
    }
}

impl From<BudAmount> for pb::Amount {
    fn from(value: BudAmount) -> Self {
        Self {
            hi: u64::try_from(value.0 >> 64).unwrap_or(u64::MAX),
            lo: u64::try_from(value.0 & u128::from(u64::MAX)).unwrap_or(u64::MAX),
        }
    }
}

impl From<pb::Amount> for BudAmount {
    fn from(value: pb::Amount) -> Self {
        Self((u128::from(value.hi) << 64) | u128::from(value.lo))
    }
}

impl From<&BlockContext> for pb::BlockContext {
    fn from(value: &BlockContext) -> Self {
        Self {
            chain_id: value.chain_id,
            height: value.height,
            timestamp_ms: value.timestamp_ms,
        }
    }
}

impl From<pb::BlockContext> for BlockContext {
    fn from(value: pb::BlockContext) -> Self {
        Self {
            chain_id: value.chain_id,
            height: value.height,
            timestamp_ms: value.timestamp_ms,
        }
    }
}

impl From<&EeCall> for pb::Call {
    fn from(value: &EeCall) -> Self {
        Self {
            kind: match value.kind {
                EeCallKind::Call => pb::CallKind::Call,
                EeCallKind::Deploy => pb::CallKind::Deploy,
            } as i32,
            caller: Some((&value.caller).into()),
            target: Some((&value.target).into()),
            value: Some(value.value.into()),
            input: value.input.clone(),
            gas_limit: value.gas_limit,
            depth: value.depth,
            tx_hash: value.tx_hash.to_vec(),
        }
    }
}

impl TryFrom<pb::Call> for EeCall {
    type Error = WireError;
    fn try_from(value: pb::Call) -> Result<Self, WireError> {
        let kind = match pb::CallKind::try_from(value.kind) {
            Ok(pb::CallKind::Call) => EeCallKind::Call,
            Ok(pb::CallKind::Deploy) => EeCallKind::Deploy,
            _ => return Err(WireError::BadEnum { field: "call.kind" }),
        };
        Ok(Self {
            kind,
            caller: need(value.caller, "call.caller")?.try_into()?,
            target: need(value.target, "call.target")?.try_into()?,
            value: need(value.value, "call.value")?.into(),
            input: value.input,
            gas_limit: value.gas_limit,
            depth: value.depth,
            tx_hash: fixed32(&value.tx_hash, "call.tx_hash")?,
        })
    }
}

impl From<&EeOutcome> for pb::Outcome {
    fn from(value: &EeOutcome) -> Self {
        Self {
            status: match value.status {
                OutcomeStatus::Success => pb::OutcomeStatus::Success,
                OutcomeStatus::Revert => pb::OutcomeStatus::Revert,
                OutcomeStatus::OutOfGas => pb::OutcomeStatus::OutOfGas,
                OutcomeStatus::InvalidCode => pb::OutcomeStatus::InvalidCode,
            } as i32,
            output: value.output.clone(),
            gas_used: value.gas_used,
        }
    }
}

impl TryFrom<pb::Outcome> for EeOutcome {
    type Error = WireError;
    fn try_from(value: pb::Outcome) -> Result<Self, WireError> {
        let status = match pb::OutcomeStatus::try_from(value.status) {
            Ok(pb::OutcomeStatus::Success) => OutcomeStatus::Success,
            Ok(pb::OutcomeStatus::Revert) => OutcomeStatus::Revert,
            Ok(pb::OutcomeStatus::OutOfGas) => OutcomeStatus::OutOfGas,
            Ok(pb::OutcomeStatus::InvalidCode) => OutcomeStatus::InvalidCode,
            _ => {
                return Err(WireError::BadEnum {
                    field: "outcome.status",
                })
            }
        };
        Ok(Self {
            status,
            output: value.output,
            gas_used: value.gas_used,
        })
    }
}

impl From<&EeFault> for pb::Fault {
    fn from(value: &EeFault) -> Self {
        Self {
            ee: u32::from(value.ee.0),
            panic_digest: value.panic_digest.to_vec(),
        }
    }
}

impl TryFrom<pb::Fault> for EeFault {
    type Error = WireError;
    fn try_from(value: pb::Fault) -> Result<Self, WireError> {
        Ok(Self {
            ee: ee_id(value.ee)?,
            panic_digest: fixed32(&value.panic_digest, "fault.panic_digest")?,
        })
    }
}

impl From<&EeRefusal> for pb::Refusal {
    fn from(value: &EeRefusal) -> Self {
        Self {
            code: match value.code {
                RefusalCode::InvalidCode => pb::RefusalCode::InvalidCode,
                RefusalCode::Unsupported => pb::RefusalCode::Unsupported,
                RefusalCode::TooLarge => pb::RefusalCode::TooLarge,
                RefusalCode::Denied => pb::RefusalCode::Denied,
            } as i32,
            message: value.message.clone(),
        }
    }
}

impl TryFrom<pb::Refusal> for EeRefusal {
    type Error = WireError;
    fn try_from(value: pb::Refusal) -> Result<Self, WireError> {
        let code = match pb::RefusalCode::try_from(value.code) {
            Ok(pb::RefusalCode::InvalidCode) => RefusalCode::InvalidCode,
            Ok(pb::RefusalCode::Unsupported) => RefusalCode::Unsupported,
            Ok(pb::RefusalCode::TooLarge) => RefusalCode::TooLarge,
            Ok(pb::RefusalCode::Denied) => RefusalCode::Denied,
            _ => {
                return Err(WireError::BadEnum {
                    field: "refusal.code",
                })
            }
        };
        Ok(Self {
            code,
            message: value.message,
        })
    }
}

impl From<&CodeInfo> for pb::CodeInfo {
    fn from(value: &CodeInfo) -> Self {
        Self {
            code_hash: value.code_hash.to_vec(),
            abi_tag: value.abi_tag.clone(),
        }
    }
}

impl TryFrom<pb::CodeInfo> for CodeInfo {
    type Error = WireError;
    fn try_from(value: pb::CodeInfo) -> Result<Self, WireError> {
        Ok(Self {
            code_hash: fixed32(&value.code_hash, "code_info.code_hash")?,
            abi_tag: value.abi_tag,
        })
    }
}

impl From<&EeLog> for pb::Log {
    fn from(value: &EeLog) -> Self {
        Self {
            emitter: Some((&value.emitter).into()),
            topics: value.topics.clone(),
            data: value.data.clone(),
        }
    }
}

impl TryFrom<pb::Log> for EeLog {
    type Error = WireError;
    fn try_from(value: pb::Log) -> Result<Self, WireError> {
        if value.topics.len() > MAX_LOG_TOPICS
            || value.topics.iter().any(|t| t.len() > MAX_TOPIC_BYTES)
        {
            return Err(WireError::TooLong {
                field: "log.topics",
            });
        }
        Ok(Self {
            emitter: need(value.emitter, "log.emitter")?.try_into()?,
            topics: value.topics,
            data: value.data,
        })
    }
}

impl From<&UniversalCall> for pb::UniversalCall {
    fn from(value: &UniversalCall) -> Self {
        Self {
            to_ee: u32::from(value.to_ee.0),
            from: Some((&value.from).into()),
            target: Some((&value.target).into()),
            value: Some(value.value.into()),
            input: value.input.clone(),
            gas_limit: value.gas_limit,
            is_static: value.is_static,
        }
    }
}

impl TryFrom<pb::UniversalCall> for UniversalCall {
    type Error = WireError;
    fn try_from(value: pb::UniversalCall) -> Result<Self, WireError> {
        Ok(Self {
            from: need(value.from, "universal_call.from")?.try_into()?,
            to_ee: ee_id(value.to_ee)?,
            target: need(value.target, "universal_call.target")?.try_into()?,
            value: need(value.value, "universal_call.value")?.into(),
            input: value.input,
            gas_limit: value.gas_limit,
            is_static: value.is_static,
        })
    }
}

impl From<&UniversalResult> for pb::UniversalResult {
    fn from(value: &UniversalResult) -> Self {
        Self {
            success: value.success,
            output: value.output.clone(),
            gas_used: value.gas_used,
        }
    }
}

impl From<pb::UniversalResult> for UniversalResult {
    fn from(value: pb::UniversalResult) -> Self {
        Self {
            success: value.success,
            output: value.output,
            gas_used: value.gas_used,
        }
    }
}

impl From<&EeQuery> for pb::QueryRequest {
    fn from(value: &EeQuery) -> Self {
        Self {
            ctx: None,
            target: Some((&value.target).into()),
            input: value.input.clone(),
        }
    }
}

impl From<&HostError> for pb::HostError {
    fn from(value: &HostError) -> Self {
        let (code, message) = match value {
            HostError::OutOfGas => (pb::HostErrorCode::OutOfGas, String::new()),
            HostError::Denied(m) => (pb::HostErrorCode::Denied, m.clone()),
            HostError::NotFound(m) => (pb::HostErrorCode::NotFound, m.clone()),
            HostError::Invalid(m) => (pb::HostErrorCode::Invalid, m.clone()),
            HostError::Insufficient(m) => (pb::HostErrorCode::Insufficient, m.clone()),
            HostError::DepthExceeded => (pb::HostErrorCode::DepthExceeded, String::new()),
        };
        Self {
            code: code as i32,
            message,
        }
    }
}

impl TryFrom<pb::HostError> for HostError {
    type Error = WireError;
    fn try_from(value: pb::HostError) -> Result<Self, WireError> {
        Ok(match pb::HostErrorCode::try_from(value.code) {
            Ok(pb::HostErrorCode::OutOfGas) => Self::OutOfGas,
            Ok(pb::HostErrorCode::Denied) => Self::Denied(value.message),
            Ok(pb::HostErrorCode::NotFound) => Self::NotFound(value.message),
            Ok(pb::HostErrorCode::Invalid) => Self::Invalid(value.message),
            Ok(pb::HostErrorCode::Insufficient) => Self::Insufficient(value.message),
            Ok(pb::HostErrorCode::DepthExceeded) => Self::DepthExceeded,
            _ => {
                return Err(WireError::BadEnum {
                    field: "host_error.code",
                })
            }
        })
    }
}
