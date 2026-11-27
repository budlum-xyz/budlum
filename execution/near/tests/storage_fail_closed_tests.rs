//! Fail-closed host-read and corrupt-storage regression tests for `budlum-ee-near`.

use budlum_ee_near::{
    encode_near_blob, NearContractProgram, NearFunctionCall, NearMethod, NearOp, NearWasmWorker,
    BUDLUM_TESTNET_CHAIN_ID,
};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeLog, ExecutionEnvironment,
    HostApi, HostError, HostRead, Namespace, OutOfGas, OutcomeStatus, UniversalCall,
    UniversalResult,
};
use std::collections::BTreeMap;

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_TESTNET_CHAIN_ID,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

struct FailDataReadHost {
    inner: MemoryHost,
    fail_with: HostError,
}

impl HostRead for FailDataReadHost {
    fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
        if key.starts_with(b"data:") {
            return Err(self.fail_with.clone());
        }
        self.inner.read(ns, key)
    }
    fn bud_balance(&self, id: &EeIdentity) -> Result<BudAmount, HostError> {
        self.inner.bud_balance(id)
    }
}

impl HostApi for FailDataReadHost {
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
fn near_storage_add_and_return_fail_closed_on_host_read_error_and_corrupt_bytes() {
    let mut worker = NearWasmWorker::with_activation_height(Some(0));
    let mut inner = MemoryHost::new(2_000_000);

    let prog = NearContractProgram {
        abi_version: "near-abi-v1".into(),
        init_ops: vec![],
        methods: vec![
            NearMethod {
                name: "inc".into(),
                is_view: false,
                ops: vec![NearOp::StorageAddU64 {
                    key: "bal".into(),
                    delta: 5,
                }],
            },
            NearMethod {
                name: "get".into(),
                is_view: true,
                ops: vec![NearOp::StorageReturn { key: "bal".into() }],
            },
            NearMethod {
                name: "corrupt".into(),
                is_view: false,
                ops: vec![NearOp::StorageWrite {
                    key: "bal".into(),
                    value: vec![1, 2, 3],
                }],
            },
        ],
    };
    let Ok(blob) = encode_near_blob(&prog) else {
        panic!("encode");
    };
    let deploy = EeCall {
        kind: EeCallKind::Deploy,
        caller: EeIdentity {
            ee: EeId::NEAR_WASM,
            id: vec![0xAA; 32],
        },
        target: EeIdentity {
            ee: EeId::NEAR_WASM,
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
    let contract_id = dep.output;

    let Ok(corrupt_input) = serde_json::to_vec(&NearFunctionCall {
        method_name: "corrupt".into(),
        args: BTreeMap::new(),
    }) else {
        panic!("ser");
    };
    let call_corrupt = EeCall {
        kind: EeCallKind::Call,
        caller: EeIdentity {
            ee: EeId::NEAR_WASM,
            id: vec![0xBB; 32],
        },
        target: EeIdentity {
            ee: EeId::NEAR_WASM,
            id: contract_id,
        },
        value: BudAmount(0),
        input: corrupt_input,
        gas_limit: 500_000,
        depth: 0,
        tx_hash: [0x12; 32],
    };
    assert_eq!(
        worker
            .execute(&ctx(), &call_corrupt, &mut inner)
            .ok()
            .map(|o| o.status),
        Some(OutcomeStatus::Success)
    );

    let Ok(inc_input) = serde_json::to_vec(&NearFunctionCall {
        method_name: "inc".into(),
        args: BTreeMap::new(),
    }) else {
        panic!("ser");
    };
    let call_inc = EeCall {
        input: inc_input,
        tx_hash: [0x13; 32],
        ..call_corrupt.clone()
    };
    let Ok(res_corrupt) = worker.execute(&ctx(), &call_inc, &mut inner) else {
        panic!("exec");
    };
    assert_eq!(
        res_corrupt.status,
        OutcomeStatus::Revert,
        "StorageAddU64 must revert on corrupt non-8-byte value instead of resetting to 0"
    );

    let mut oom_host = FailDataReadHost {
        inner,
        fail_with: HostError::OutOfGas,
    };
    let Ok(res_oog) = worker.execute(&ctx(), &call_inc, &mut oom_host) else {
        panic!("exec");
    };
    assert_eq!(
        res_oog.status,
        OutcomeStatus::OutOfGas,
        "StorageAddU64 must propagate HostError::OutOfGas"
    );

    let Ok(get_input) = serde_json::to_vec(&NearFunctionCall {
        method_name: "get".into(),
        args: BTreeMap::new(),
    }) else {
        panic!("ser");
    };
    let call_get = EeCall {
        input: get_input,
        tx_hash: [0x14; 32],
        ..call_corrupt
    };
    let Ok(res_get) = worker.execute(&ctx(), &call_get, &mut oom_host) else {
        panic!("exec");
    };
    assert_eq!(
        res_get.status,
        OutcomeStatus::OutOfGas,
        "StorageReturn must fail closed on HostError::OutOfGas"
    );
}
