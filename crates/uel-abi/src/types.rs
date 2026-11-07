//! The types the coordinator and a worker exchange.
//!
//! Every type that crosses the socket has a bound here and is checked when it
//! is built from the wire (see `wire.rs`): an identity is at most
//! [`MAX_IDENTITY_BYTES`], a namespace [`MAX_NAMESPACE_BYTES`], a log carries at
//! most [`MAX_LOG_TOPICS`] topics. Payloads (keys, values, call input) are
//! bounded by the 16 MiB frame alone.
//! Convenience: public UEL wire and ABI types shared across budlum-core and out-of-process EE workers.

use std::fmt;

/// The longest account identity an environment may name, in bytes.
pub const MAX_IDENTITY_BYTES: usize = 64;
/// The longest namespace name, in bytes.
pub const MAX_NAMESPACE_BYTES: usize = 64;
/// The most topics one log may carry.
pub const MAX_LOG_TOPICS: usize = 8;
/// The longest log topic, in bytes.
pub const MAX_TOPIC_BYTES: usize = 64;

/// An execution environment: the catalog id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EeId(pub u8);

impl EeId {
    /// BudZero.
    pub const BUDZERO: Self = Self(0x00);
    /// EVM.
    pub const EVM: Self = Self(0x01);
    /// WASM (CosmWasm ABI).
    pub const WASM: Self = Self(0x02);
    /// SVM.
    pub const SVM: Self = Self(0x03);
    /// Move (Aptos dialect).
    pub const MOVE: Self = Self(0x04);
}

/// A state namespace the coordinator keeps for a worker, such as `uel/alias`.
/// Lowercase ASCII letters, digits and `_ - . /`, 1 to 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Namespace(String);

impl Namespace {
    /// Builds a namespace.
    ///
    /// # Errors
    ///
    /// [`WireError::BadNamespace`] when the name is empty, too long, or holds a
    /// character outside the allowed set.
    pub fn new(name: &str) -> Result<Self, WireError> {
        let ok = !name.is_empty()
            && name.len() <= MAX_NAMESPACE_BYTES
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-./".contains(&b));
        if ok {
            Ok(Self(name.to_string()))
        } else {
            Err(WireError::BadNamespace)
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An account as one environment sees it: its native address bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EeIdentity {
    /// The environment whose address format `id` is in.
    pub ee: EeId,
    /// The native address.
    pub id: Vec<u8>,
}

impl EeIdentity {
    /// Builds an identity.
    ///
    /// # Errors
    ///
    /// [`WireError::TooLong`] when `id` exceeds [`MAX_IDENTITY_BYTES`].
    pub fn new(ee: EeId, id: Vec<u8>) -> Result<Self, WireError> {
        if id.len() > MAX_IDENTITY_BYTES {
            return Err(WireError::TooLong { field: "identity" });
        }
        Ok(Self { ee, id })
    }
}

/// An amount of BUD in attoBUD (10^-18 BUD): `balance * 10^12 + frac_attos`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BudAmount(pub u128);

/// What an environment may read of the block it runs in. No wall clock: the
/// timestamp is the block's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// The chain id.
    pub chain_id: u64,
    /// The block height.
    pub height: u64,
    /// The block timestamp in milliseconds.
    pub timestamp_ms: u64,
}

/// What a call asks of the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EeCallKind {
    /// Call deployed code.
    Call,
    /// Deploy code and run its constructor.
    Deploy,
}

/// One call into an environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EeCall {
    /// Call or deploy.
    pub kind: EeCallKind,
    /// Who calls.
    pub caller: EeIdentity,
    /// The callee (the contract, or the address a deploy creates).
    pub target: EeIdentity,
    /// BUD sent with the call.
    pub value: BudAmount,
    /// Call data, or the code of a deploy.
    pub input: Vec<u8>,
    /// The gas the call may use, in BGU (the universal gas unit).
    pub gas_limit: u64,
    /// Nesting depth of universal calls; 0 for a transaction's first call.
    pub depth: u32,
    /// The transaction this call belongs to.
    pub tx_hash: [u8; 32],
}

/// A deterministic result of a call. Revert and out-of-gas are normal failed
/// receipts: the fee is taken, nothing else is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeStatus {
    /// The call succeeded.
    Success,
    /// The code reverted.
    Revert,
    /// The gas ran out.
    OutOfGas,
    /// The bytecode is not valid for this environment.
    InvalidCode,
}

/// The deterministic result of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EeOutcome {
    /// How it ended.
    pub status: OutcomeStatus,
    /// Return or revert data.
    pub output: Vec<u8>,
    /// BGU used.
    pub gas_used: u64,
}

/// A deterministic panic caught inside the engine. It is a
/// receipt, not a node failure: the worker restarts and the block continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EeFault {
    /// The environment that panicked.
    pub ee: EeId,
    /// SHA-256 over a domain tag, the environment id and the panic message.
    pub panic_digest: [u8; 32],
}

impl fmt::Display for EeFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "environment {} panicked (digest ", self.ee.0)?;
        for byte in &self.panic_digest[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

impl std::error::Error for EeFault {}

/// Why a deploy validation or a query was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The code is not valid for the environment.
    InvalidCode,
    /// The request names something the environment does not support.
    Unsupported,
    /// The code or input is above a limit.
    TooLarge,
    /// A policy refused it.
    Denied,
}

/// A deterministic refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EeRefusal {
    /// The class.
    pub code: RefusalCode,
    /// A human-readable reason.
    pub message: String,
}

impl fmt::Display for EeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for EeRefusal {}

/// What validating a deploy learned about the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeInfo {
    /// SHA-256 of the code.
    pub code_hash: [u8; 32],
    /// The environment's own ABI tag for the code.
    pub abi_tag: String,
}

/// A read-only call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EeQuery {
    /// The contract queried.
    pub target: EeIdentity,
    /// The query data.
    pub input: Vec<u8>,
}

/// A log an environment emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EeLog {
    /// The emitting account.
    pub emitter: EeIdentity,
    /// Indexed topics, at most [`MAX_LOG_TOPICS`] of at most [`MAX_TOPIC_BYTES`].
    pub topics: Vec<Vec<u8>>,
    /// The log data.
    pub data: Vec<u8>,
}

/// A call from one environment into another (Universal Call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalCall {
    /// The calling account, in the caller's environment.
    pub from: EeIdentity,
    /// The environment that runs the callee.
    pub to_ee: EeId,
    /// The callee, in the callee's environment.
    pub target: EeIdentity,
    /// BUD sent.
    pub value: BudAmount,
    /// Call data.
    pub input: Vec<u8>,
    /// The gas the callee may use.
    pub gas_limit: u64,
}

/// What a Universal Call returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalResult {
    /// Whether the callee succeeded.
    pub success: bool,
    /// Return data.
    pub output: Vec<u8>,
    /// BGU the callee used.
    pub gas_used: u64,
}

/// The gas budget is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfGas;

impl fmt::Display for OutOfGas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "out of gas")
    }
}

impl std::error::Error for OutOfGas {}

/// A refusal from the host (the coordinator) to a worker's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The gas budget is spent.
    OutOfGas,
    /// A policy refused the operation.
    Denied(String),
    /// The thing asked for does not exist.
    NotFound(String),
    /// The request is malformed.
    Invalid(String),
    /// A balance is too small.
    Insufficient(String),
    /// The Universal Call stack is at its limit.
    DepthExceeded,
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfGas => write!(f, "out of gas"),
            Self::Denied(m) => write!(f, "denied: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::Insufficient(m) => write!(f, "insufficient: {m}"),
            Self::DepthExceeded => write!(f, "universal call depth exceeded"),
        }
    }
}

impl std::error::Error for HostError {}

impl From<OutOfGas> for HostError {
    fn from(_: OutOfGas) -> Self {
        Self::OutOfGas
    }
}

/// A wire value that does not satisfy the type it is meant to become.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A required field is absent.
    Missing {
        /// The field.
        field: &'static str,
    },
    /// A field is above its bound.
    TooLong {
        /// The field.
        field: &'static str,
    },
    /// A field has the wrong fixed length.
    BadLength {
        /// The field.
        field: &'static str,
    },
    /// An enum field holds a value this ABI does not define.
    BadEnum {
        /// The field.
        field: &'static str,
    },
    /// A namespace name is outside the allowed set.
    BadNamespace,
    /// An environment id does not fit a byte.
    BadEeId,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { field } => write!(f, "missing field {field}"),
            Self::TooLong { field } => write!(f, "field {field} is above its bound"),
            Self::BadLength { field } => write!(f, "field {field} has the wrong length"),
            Self::BadEnum { field } => write!(f, "field {field} holds an undefined value"),
            Self::BadNamespace => write!(f, "namespace name is not allowed"),
            Self::BadEeId => write!(f, "environment id does not fit a byte"),
        }
    }
}

impl std::error::Error for WireError {}
