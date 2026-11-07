//! A mock environment and an in-memory host, for the coordinator's tests
//! .
//!
//! [`MockEe`] is driven by the first byte of the call input, so a test states
//! the behaviour it wants in the call itself; faults and panics are injected
//! deterministically by call number.

use crate::host::{ExecutionEnvironment, HostApi, HostRead};
use crate::host::panic_digest;
use crate::types::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, HostError, Namespace, OutOfGas, OutcomeStatus, RefusalCode, UniversalCall,
    UniversalResult,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The namespace the mock writes to.
pub const MOCK_NAMESPACE: &str = "mock/state";
/// The largest code the mock accepts in a deploy.
pub const MOCK_MAX_CODE_BYTES: usize = 24_576;
/// The gas the mock charges for every call before it does anything else.
pub const MOCK_BASE_GAS: u64 = 100;

/// Input opcodes (the first byte of `EeCall::input`).
pub mod op {
    /// Echo the rest of the input.
    pub const ECHO: u8 = 0x00;
    /// Write key `[1]`..: `input[1]` is the key byte, `input[2..]` the value.
    pub const WRITE: u8 = 0x01;
    /// Revert with the rest of the input as output.
    pub const REVERT: u8 = 0x02;
    /// Panic inside the engine.
    pub const PANIC: u8 = 0x03;
    /// Charge `u64::from_be_bytes(input[1..9])` gas.
    pub const CHARGE: u8 = 0x04;
    /// Universal call: `input[1]` is the target environment, the rest the data.
    pub const UNIVERSAL: u8 = 0x05;
    /// Emit a log with topic `[input[1]]` and the rest as data.
    pub const LOG: u8 = 0x06;
    /// Transfer `call.value` from the caller to the target.
    pub const TRANSFER: u8 = 0x07;
    /// Read key byte `input[1]` and return the value (empty when absent).
    pub const READ: u8 = 0x08;
}

/// A mock environment.
pub struct MockEe {
    id: EeId,
    calls: u64,
    panic_on_call: BTreeSet<u64>,
    fault_on_call: BTreeSet<u64>,
}

impl MockEe {
    /// A mock serving environment `id`.
    #[must_use]
    pub fn new(id: EeId) -> Self {
        Self {
            id,
            calls: 0,
            panic_on_call: BTreeSet::new(),
            fault_on_call: BTreeSet::new(),
        }
    }

    /// Panics on the `n`th call to `execute` (counted from 1).
    #[must_use]
    pub fn with_panic_on_call(mut self, n: u64) -> Self {
        self.panic_on_call.insert(n);
        self
    }

    /// Returns an [`EeFault`] on the `n`th call to `execute` (counted from 1).
    #[must_use]
    pub fn with_fault_on_call(mut self, n: u64) -> Self {
        self.fault_on_call.insert(n);
        self
    }

    fn namespace() -> Result<Namespace, HostError> {
        Namespace::new(MOCK_NAMESPACE).map_err(|e| HostError::Invalid(e.to_string()))
    }

    fn run(&self, call: &EeCall, host: &mut dyn HostApi) -> Result<EeOutcome, HostError> {
        let input = call.input.as_slice();
        let (opcode, rest) = input
            .split_first()
            .map_or((op::ECHO, &[][..]), |(o, r)| (*o, r));
        let mut gas_used = MOCK_BASE_GAS;
        let ok = |output: Vec<u8>, gas_used: u64| EeOutcome {
            status: OutcomeStatus::Success,
            output,
            gas_used,
        };
        match opcode {
            op::ECHO => Ok(ok(rest.to_vec(), gas_used)),
            op::WRITE => {
                let (key, value) = rest
                    .split_first()
                    .ok_or_else(|| HostError::Invalid("no key".into()))?;
                host.write(&Self::namespace()?, &[*key], Some(value))?;
                Ok(ok(Vec::new(), gas_used))
            }
            op::REVERT => Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: rest.to_vec(),
                gas_used,
            }),
            op::PANIC => panic!("mock environment injected panic"),
            op::CHARGE => {
                let bytes: [u8; 8] = rest
                    .get(..8)
                    .and_then(|s| <[u8; 8]>::try_from(s).ok())
                    .ok_or_else(|| HostError::Invalid("charge needs 8 bytes".into()))?;
                let amount = u64::from_be_bytes(bytes);
                gas_used = gas_used.saturating_add(amount);
                host.charge(amount)?;
                Ok(ok(Vec::new(), gas_used))
            }
            op::UNIVERSAL => {
                let (to, data) = rest
                    .split_first()
                    .ok_or_else(|| HostError::Invalid("no target".into()))?;
                let result = host.universal_call(UniversalCall {
                    from: call.target.clone(),
                    to_ee: EeId(*to),
                    target: call.target.clone(),
                    value: BudAmount(0),
                    input: data.to_vec(),
                    gas_limit: call.gas_limit,
                    is_static: false,
                })?;
                Ok(EeOutcome {
                    status: if result.success {
                        OutcomeStatus::Success
                    } else {
                        OutcomeStatus::Revert
                    },
                    output: result.output,
                    gas_used: gas_used.saturating_add(result.gas_used),
                })
            }
            op::LOG => {
                let (topic, data) = rest
                    .split_first()
                    .ok_or_else(|| HostError::Invalid("no topic".into()))?;
                host.emit_log(EeLog {
                    emitter: call.target.clone(),
                    topics: vec![vec![*topic]],
                    data: data.to_vec(),
                })?;
                Ok(ok(Vec::new(), gas_used))
            }
            op::TRANSFER => {
                host.bud_transfer(&call.caller, &call.target, call.value.0)?;
                Ok(ok(Vec::new(), gas_used))
            }
            op::READ => {
                let key = rest
                    .first()
                    .ok_or_else(|| HostError::Invalid("no key".into()))?;
                let value = host.read(&Self::namespace()?, &[*key])?;
                Ok(ok(value.unwrap_or_default(), gas_used))
            }
            _ => Ok(EeOutcome {
                status: OutcomeStatus::InvalidCode,
                output: Vec::new(),
                gas_used,
            }),
        }
    }
}

impl ExecutionEnvironment for MockEe {
    fn id(&self) -> EeId {
        self.id
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "empty code".into(),
            });
        }
        if code.len() > MOCK_MAX_CODE_BYTES {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: format!(
                    "code is {} bytes, the limit is {MOCK_MAX_CODE_BYTES}",
                    code.len()
                ),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: "mock/1".into(),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        self.calls += 1;
        let fault = || EeFault {
            ee: self.id,
            panic_digest: panic_digest(self.id, "mock environment injected fault"),
        };
        if self.fault_on_call.contains(&self.calls) {
            return Err(fault());
        }
        if self.panic_on_call.contains(&self.calls) {
            panic!("mock environment injected panic");
        }
        match self.run(call, host) {
            Ok(outcome) => Ok(outcome),
            Err(HostError::OutOfGas) => Ok(EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            }),
            // A refused host operation is a deterministic revert of the call.
            Err(error) => Ok(EeOutcome {
                status: OutcomeStatus::Revert,
                output: error.to_string().into_bytes(),
                gas_used: MOCK_BASE_GAS,
            }),
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let Some(key) = q.input.first() else {
            return Err(EeRefusal {
                code: RefusalCode::Unsupported,
                message: "empty query".into(),
            });
        };
        let ns = Self::namespace().map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: e.to_string(),
        })?;
        host.read(&ns, &[*key])
            .map(Option::unwrap_or_default)
            .map_err(|e| EeRefusal {
                code: RefusalCode::Denied,
                message: e.to_string(),
            })
    }
}

/// What a [`MemoryHost`] does with a Universal Call.
pub type UniversalHandler = Box<dyn FnMut(UniversalCall) -> Result<UniversalResult, HostError>>;

/// An in-memory host: state, balances, logs and a gas budget. Enough to test a
/// coordinator-side flow and a worker round trip without the real overlay.
pub struct MemoryHost {
    /// Namespaced state.
    pub state: BTreeMap<(String, Vec<u8>), Vec<u8>>,
    /// Balances in attoBUD.
    pub balances: BTreeMap<EeIdentity, u128>,
    /// Logs emitted so far.
    pub logs: Vec<EeLog>,
    /// Gas still available.
    pub gas_left: u64,
    /// Gas charged so far.
    pub gas_charged: u64,
    /// Universal calls received.
    pub universal_calls: Vec<UniversalCall>,
    handler: Option<UniversalHandler>,
}

impl MemoryHost {
    /// A host with `gas` available and nothing stored.
    #[must_use]
    pub fn new(gas: u64) -> Self {
        Self {
            state: BTreeMap::new(),
            balances: BTreeMap::new(),
            logs: Vec::new(),
            gas_left: gas,
            gas_charged: 0,
            universal_calls: Vec::new(),
            handler: None,
        }
    }

    /// Answers Universal Calls with `handler` instead of the default echo.
    #[must_use]
    pub fn with_universal_handler(mut self, handler: UniversalHandler) -> Self {
        self.handler = Some(handler);
        self
    }
}

impl HostRead for MemoryHost {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        Ok(self
            .state
            .get(&(ns.as_str().to_string(), key.to_vec()))
            .cloned())
    }

    fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
        Ok(BudAmount(self.balances.get(who).copied().unwrap_or(0)))
    }
}

impl HostApi for MemoryHost {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        let slot = (ns.as_str().to_string(), key.to_vec());
        match value {
            Some(value) => {
                self.state.insert(slot, value.to_vec());
            }
            None => {
                self.state.remove(&slot);
            }
        }
        Ok(())
    }

    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        self.universal_calls.push(call.clone());
        match self.handler.as_mut() {
            Some(handler) => handler(call),
            None => Ok(UniversalResult {
                success: true,
                output: call.input,
                gas_used: 0,
            }),
        }
    }

    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        self.logs.push(log);
        Ok(())
    }

    fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
        if bgu > self.gas_left {
            self.gas_charged = self.gas_charged.saturating_add(self.gas_left);
            self.gas_left = 0;
            return Err(OutOfGas);
        }
        self.gas_left -= bgu;
        self.gas_charged = self.gas_charged.saturating_add(bgu);
        Ok(())
    }

    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        attos: u128,
    ) -> Result<(), HostError> {
        let have = self.balances.get(from).copied().unwrap_or(0);
        let left = have
            .checked_sub(attos)
            .ok_or_else(|| HostError::Insufficient("balance too small".into()))?;
        let target = self.balances.get(to).copied().unwrap_or(0);
        let gained = target
            .checked_add(attos)
            .ok_or_else(|| HostError::Invalid("balance overflow".into()))?;
        self.balances.insert(from.clone(), left);
        self.balances.insert(to.clone(), gained);
        Ok(())
    }
}
