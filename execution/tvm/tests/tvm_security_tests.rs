//! Stack-bound and fail-closed host-read regression tests for `budlum-ee-tvm`.

use budlum_ee_tvm::{
    encode_tvm_blob, TvmContract, TvmInsn, TvmInternalMsg, TvmMethod, TvmWorker,
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

struct FailOwnerReadHost {
    inner: MemoryHost,
}

impl HostRead for FailOwnerReadHost {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if key.starts_with(b"owner:") {
            return Err(HostError::OutOfGas);
        }
        self.inner.read(ns, key)
    }
    fn bud_balance(&self, id: &EeIdentity) -> Result<BudAmount, HostError> {
        self.inner.bud_balance(id)
    }
}

impl HostApi for FailOwnerReadHost {
    fn write(&mut self, ns: &Namespace, key: &[u8], value: Option<&[u8]>) -> Result<(), HostError> {
        self.inner.write(ns, key, value)
    }
    fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
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
fn tvm_enforces_stack_depth_bound_and_propagates_owner_read_out_of_gas() {
    let mut worker = TvmWorker::with_activation_height(Some(0));
    let mut inner = MemoryHost::new(5_000_000);

    let contract = TvmContract {
        init: vec![],
        handlers: vec![
            TvmMethod {
                op: 1,
                body: vec![TvmInsn::PushInt(1); 1_050],
            },
            TvmMethod {
                op: 2,
                body: vec![TvmInsn::ThrowUnlessOwner(401), TvmInsn::PushInt(7)],
            },
        ],
    };
    let Ok(boc) = encode_tvm_blob(&contract) else {
        panic!("encode");
    };
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::TVM,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::TVM,
            id: vec![0x00; 32],
        },
        value: BudAmount(0),
        input: boc,
        gas_limit: 2_000_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(dep) = worker.execute(&ctx(), &deploy, &mut inner) else {
        panic!("deploy");
    };
    assert_eq!(dep.status, OutcomeStatus::Success);
    let addr = dep.output;

    let Ok(bomb_input) = serde_json::to_vec(&TvmInternalMsg {
        op: 1,
        args: vec![],
    }) else {
        panic!("ser");
    };
    let call_bomb = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::TVM,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::TVM,
            id: addr,
        },
        value: BudAmount(0),
        input: bomb_input,
        gas_limit: 2_000_000,
        depth: 0,
        tx_hash: [0x12; 32],
    };
    let Ok(res_bomb) = worker.execute(&ctx(), &call_bomb, &mut inner) else {
        panic!("exec");
    };
    assert_eq!(
        res_bomb.status,
        OutcomeStatus::Revert,
        "TVM stack depth > 1,000 must fail closed"
    );

    let mut oom_host = FailOwnerReadHost { inner };
    let Ok(owner_input) = serde_json::to_vec(&TvmInternalMsg {
        op: 2,
        args: vec![],
    }) else {
        panic!("ser");
    };
    let call_owner = EeCall {
        input: owner_input,
        tx_hash: [0x13; 32],
        ..call_bomb
    };
    let Ok(res_owner) = worker.execute(&ctx(), &call_owner, &mut oom_host) else {
        panic!("exec");
    };
    assert_eq!(
        res_owner.status,
        OutcomeStatus::OutOfGas,
        "ThrowUnlessOwner must propagate HostError::OutOfGas"
    );
}
