//! Fail-closed host error propagation regression tests for `budlum-ee-polkavm`.

use budlum_ee_polkavm::{
    encode_polkavm_blob, PolkaVmDispatch, PolkaVmInsn, PolkaVmProgram, PolkaVmWorker,
    BUDLUM_TESTNET_CHAIN_ID,
};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeLog, ExecutionEnvironment,
    HostApi, HostError, HostRead, Namespace, OutOfGas, OutcomeStatus, UniversalCall,
    UniversalResult,
};

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_TESTNET_CHAIN_ID,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

struct FailHost {
    inner: MemoryHost,
    fail_owner_read: bool,
    fail_emit_log: bool,
}

impl HostRead for FailHost {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if self.fail_owner_read && key.starts_with(b"owner:") {
            return Err(HostError::OutOfGas);
        }
        self.inner.read(ns, key)
    }
    fn bud_balance(&self, id: &EeIdentity) -> Result<BudAmount, HostError> {
        self.inner.bud_balance(id)
    }
}

impl HostApi for FailHost {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        self.inner.write(ns, key, value)
    }
    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
        if self.fail_emit_log {
            return Err(HostError::OutOfGas);
        }
        self.inner.emit_log(log)
    }
    fn charge(&mut self, amount: u64) -> Result<(), OutOfGas> {
        self.inner.charge(amount)
    }
    fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        self.inner.universal_call(call)
    }
    fn bud_transfer(
        &mut self,
        from: &EeIdentity,
        to: &EeIdentity,
        amount: u128,
    ) -> Result<(), HostError> {
        self.inner.bud_transfer(from, to, amount)
    }
    fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
        self.inner.checkpoint_begin()
    }
    fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
        self.inner.checkpoint_commit(id)
    }
    fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
        self.inner.checkpoint_rollback(id)
    }
}

#[test]
fn polkavm_propagates_out_of_gas_from_require_owner_and_deposit_event() {
    let mut worker = PolkaVmWorker::with_activation_height(Some(0));
    let mut inner = MemoryHost::new(2_000_000);

    let prog = PolkaVmProgram {
        constructor: vec![],
        dispatches: vec![
            PolkaVmDispatch {
                selector: [1, 2, 3, 4],
                insns: vec![
                    PolkaVmInsn::RequireOwner,
                    PolkaVmInsn::SealReturnU32 { rs: 0 },
                ],
            },
            PolkaVmDispatch {
                selector: [5, 6, 7, 8],
                insns: vec![
                    PolkaVmInsn::LoadImm { rd: 1, imm: 42 },
                    PolkaVmInsn::SealDepositEvent {
                        topic: [0xEE; 32],
                        rs: 1,
                    },
                    PolkaVmInsn::SealReturnU32 { rs: 1 },
                ],
            },
        ],
    };
    let Ok(blob) = encode_polkavm_blob(&prog) else {
        panic!("encode");
    };
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::POLKAVM,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::POLKAVM,
            id: vec![0x00; 32],
        },
        value: BudAmount(0),
        input: blob,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(dep) = worker.execute(&ctx(), &deploy, &mut inner) else {
        panic!("deploy");
    };
    assert_eq!(dep.status, OutcomeStatus::Success);
    let addr = dep.output;

    let mut host_owner_oog = FailHost {
        inner,
        fail_owner_read: true,
        fail_emit_log: false,
    };
    let call_owner = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::POLKAVM,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::POLKAVM,
            id: addr.clone(),
        },
        value: BudAmount(0),
        input: vec![1, 2, 3, 4],
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x12; 32],
    };
    let Ok(res_owner) = worker.execute(&ctx(), &call_owner, &mut host_owner_oog) else {
        panic!("exec");
    };
    assert_eq!(
        res_owner.status,
        OutcomeStatus::OutOfGas,
        "RequireOwner must propagate HostError::OutOfGas"
    );

    host_owner_oog.fail_owner_read = false;
    host_owner_oog.fail_emit_log = true;
    let call_log = EeCall {
        input: vec![5, 6, 7, 8],
        tx_hash: [0x13; 32],
        ..call_owner
    };
    let Ok(res_log) = worker.execute(&ctx(), &call_log, &mut host_owner_oog) else {
        panic!("exec");
    };
    assert_eq!(
        res_log.status,
        OutcomeStatus::OutOfGas,
        "SealDepositEvent must fail closed on HostError::OutOfGas instead of ignoring emit_log"
    );
}
