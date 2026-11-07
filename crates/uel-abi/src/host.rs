//! The two traits of the contract.
//!
//! Two deliberate refinements of the conceptual design. First,
//! `bud_balance` is a read, so it lives on [`HostRead`]: a `query` runs with a
//! `&dyn HostRead` and a read-only call has to see balances. Second,
//! `HostApi::write` takes a [`Namespace`] and `Option<&[u8]>`, where `None`
//! deletes the key.

use crate::types::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, HostError, Namespace, OutOfGas, UniversalCall, UniversalResult,
};

use sha2::{Digest, Sha256};

/// The digest an environment reports for a caught panic.
#[must_use]
pub fn panic_digest(ee: EeId, message: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_UEL_PANIC_V1");
    hasher.update([ee.0]);
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

/// Extracts a deterministic message from a caught panic payload.
#[must_use]
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic".to_string()
    }
}

/// The read side of the coordinator, available to `query` and `execute`.
pub trait HostRead {
    /// Reads one key; `None` when it is absent.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the coordinator refuses the read.
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError>;

    /// The BUD balance of `who`.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the identity cannot be resolved.
    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError>;
}

/// The write side of the coordinator, available to `execute`. A worker keeps no
/// state: every effect goes through here, into the coordinator's overlay.
pub trait HostApi: HostRead {
    /// Writes (`Some`) or deletes (`None`) one key.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the coordinator refuses the write.
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError>;

    /// Calls into another environment; the coordinator opens a frame, runs the
    /// callee, and merges or discards the frame.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the call cannot be made (depth, policy, gas).
    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError>;

    /// Emits a log.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when the log is refused.
    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError>;

    /// Charges `bgu` of gas.
    ///
    /// # Errors
    ///
    /// [`OutOfGas`] when the budget cannot cover it.
    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas>;

    /// Moves `attos` attoBUD between two accounts.
    ///
    /// # Errors
    ///
    /// A [`HostError`] when a balance is short or the unit does not divide.
    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError>;
}

/// An execution environment, served by a worker process.
pub trait ExecutionEnvironment {
    /// The catalog id.
    fn id(&self) -> EeId;

    /// Checks code before a deploy.
    ///
    /// # Errors
    ///
    /// An [`EeRefusal`] for code the environment will not accept.
    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal>;

    /// Runs one call. A deterministic failure (revert, out of gas, bad code) is
    /// an `Ok` outcome with that status; `Err` is a caught engine panic.
    ///
    /// # Errors
    ///
    /// An [`EeFault`] for a deterministic panic.
    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault>;

    /// Runs a read-only call.
    ///
    /// # Errors
    ///
    /// An [`EeRefusal`] when the query is not allowed or fails.
    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal>;
}
