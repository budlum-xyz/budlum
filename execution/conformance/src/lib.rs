//! UEL conformance suite runner, gas calibration verifier, and cross-architecture
//! deterministic `execution_root` harness (`WP-35`, Sections 8.9, 8.13, 8.15, 8.16).

#![forbid(unsafe_code)]

use std::time::Instant;

use bud_isa::{Instruction, Opcode};
use budlum_ee_budzero::BudZeroWorker;
use budlum_ee_evm::db::NS_EVM_STORAGE;
use budlum_ee_evm::EvmWorker;
use budlum_ee_move::framework::{
    encode_move_module, is_scheme_byte_unused_in_pinned_aptos, CompiledMoveModule, MoveFunctionDef,
    MoveOp, BUDLUM_MOVE_ALIAS_SCHEME_BYTE, FRAMEWORK_ADDRESS,
};
use budlum_ee_move::{MovePayload, MoveQuery, MoveWorker, APTOS_GAS_TO_BGU, NS_MOVE_STATE};
use budlum_ee_svm::programs::{
    SvmAccountMeta, SvmInstructionEnvelope, ATTOS_PER_LAMPORT, NS_SVM_ACCOUNT, STAKE_PROGRAM_ID,
    SYSTEM_PROGRAM_ID, VOTE_PROGRAM_ID,
};
use budlum_ee_svm::SvmWorker;
use budlum_ee_wasm::abi::WasmTxAction;
use budlum_ee_wasm::budlum_msg::{b64_encode, bud_addr_humanize};
use budlum_ee_wasm::{WasmWorker, NS_WASM_STORE};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeQuery, ExecutionEnvironment,
    OutcomeStatus,
};
use sha2::{Digest as _, Sha256};

/// Testnet block gas ceiling in BGU (`Section 8.9` item 2).
pub const BLOCK_GAS_LIMIT_BGU: u64 = 60_000_000;

/// Calibration target for `--release` runs (`Section 8.9` item 4: `1 BGU <= 16 ns`).
pub const MAX_NS_PER_BGU_RELEASE: u128 = 16;

/// Canonical initial conversion rates (`Section 8.9` item 3) in BGU per native gas unit.
pub const INITIAL_BGU_RATES: [(EeId, u64); 5] = [
    (EeId::BUDZERO, 1),
    (EeId::EVM, 1),
    (EeId::WASM, 1),
    (EeId::SVM, 1),
    (EeId::MOVE, APTOS_GAS_TO_BGU),
];

/// Compute a canonical, architecture-independent 32-byte commitment over every
/// `(namespace, key, value)` entry and `EeIdentity` balance in `host`.
#[must_use]
pub fn compute_conformance_execution_root(host: &MemoryHost) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_CONFORMANCE_ROOT_V1");
    h.update((host.state.len() as u64).to_le_bytes());
    for ((ns, key), val) in &host.state {
        h.update((ns.len() as u64).to_le_bytes());
        h.update(ns.as_bytes());
        h.update((key.len() as u64).to_le_bytes());
        h.update(key);
        h.update((val.len() as u64).to_le_bytes());
        h.update(val);
    }
    h.update((host.balances.len() as u64).to_le_bytes());
    for (who, bal) in &host.balances {
        h.update([who.ee.0]);
        h.update((who.id.len() as u64).to_le_bytes());
        h.update(&who.id);
        h.update(bal.to_le_bytes());
    }
    h.finalize().into()
}

/// Minimal EVM runtime contract storing `0x2A` at slot `0` and returning `0x2A` (`32` bytes).
#[must_use]
pub fn evm_sstore_initcode() -> Vec<u8> {
    // Runtime (13 bytes):
    // PUSH1 0x2a PUSH1 0x00 SSTORE PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    let runtime: [u8; 13] = [
        0x60, 0x2a, 0x60, 0x00, 0x55, 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00,
    ];
    let mut full_rt = Vec::with_capacity(14);
    full_rt.extend_from_slice(&runtime);
    full_rt.push(0xf3);
    // Initcode: PUSH1 14 DUP1 PUSH1 12 PUSH1 0 CODECOPY PUSH1 0 RETURN || runtime
    let mut init = vec![
        0x60,
        full_rt.len() as u8,
        0x80,
        0x60,
        0x0c,
        0x60,
        0x00,
        0x39,
        0x60,
        0x00,
        0xf3,
        0x00,
    ];
    // Adjust offset to 12 bytes (`init.len()` == 12 before extending).
    init.extend_from_slice(&full_rt);
    init
}

/// Minimal float-free CosmWasm `interface_version_8` contract writing `"42"` to `"count"`.
pub fn minimal_cosmwasm_module() -> Result<Vec<u8>, String> {
    let wat_src = r#"(module
(import "env" "db_read" (func $db_read (param i32) (result i32)))
(import "env" "db_write" (func $db_write (param i32 i32)))
(memory (export "memory") 2)
(global $bump (mut i32) (i32.const 4096))
(data (i32.const 128) "\a0\00\00\00\05\00\00\00\05\00\00\00")
(data (i32.const 160) "count")
(data (i32.const 224) "\00\01\00\00\3e\00\00\00\3e\00\00\00")
(data (i32.const 256) "{\"ok\":{\"messages\":[],\"attributes\":[],\"events\":[],\"data\":null}}")
(data (i32.const 480) "\00\02\00\00\0d\00\00\00\0d\00\00\00")
(data (i32.const 512) "{\"ok\":\"NDI=\"}")
(data (i32.const 600) "\6c\02\00\00\02\00\00\00\02\00\00\00")
(data (i32.const 620) "42")
(func (export "allocate") (param $size i32) (result i32)
    (local $hdr i32)
    (local $buf i32)
    (local.set $hdr (global.get $bump))
    (local.set $buf (i32.add (local.get $hdr) (i32.const 16)))
    (global.set $bump (i32.add (local.get $buf) (local.get $size)))
    (i32.store (local.get $hdr) (local.get $buf))
    (i32.store (i32.add (local.get $hdr) (i32.const 4)) (local.get $size))
    (i32.store (i32.add (local.get $hdr) (i32.const 8)) (i32.const 0))
    (local.get $hdr)
)
(func (export "deallocate") (param $ptr i32))
(func (export "instantiate") (param $e i32) (param $i i32) (param $m i32) (result i32)
    (call $db_write (i32.const 128) (i32.const 600))
    (i32.const 224)
)
(func (export "execute") (param $e i32) (param $i i32) (param $m i32) (result i32)
    (call $db_write (i32.const 128) (local.get $m))
    (i32.const 224)
)
(func (export "query") (param $e i32) (param $m i32) (result i32)
    (drop (call $db_read (i32.const 128)))
    (i32.const 480)
))"#;
    wat::parse_str(wat_src).map_err(|e| e.to_string())
}

/// Minimal verified sBPF V3 program (`r0 = 0; return`).
#[must_use]
pub fn minimal_sbpf_v3_program() -> Vec<u8> {
    vec![
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, 0
        0x9d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // return (SBPF V3)
    ]
}

/// Minimal stateful BudZero program writing `sender[0]` into storage slot `0` and halting.
#[must_use]
pub fn minimal_budzero_program() -> Vec<u8> {
    let ops = [
        Instruction {
            opcode: Opcode::Syscall,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 10, // sender word 0
        },
        Instruction {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: 0,
        },
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        },
    ];
    let mut out = Vec::with_capacity(ops.len() * 8);
    for ins in ops {
        out.extend_from_slice(&ins.encode().to_le_bytes());
    }
    out
}

/// Execute a deterministic multi-transaction block spanning all five UEL execution
/// environments (`BudZero`, `EVM`, `WASM`, `SVM`, `Move`) and return the final
/// [`MemoryHost`] plus its canonical 32-byte `execution_root`.
pub fn run_canonical_multi_ee_block_sequence() -> Result<(MemoryHost, [u8; 32]), String> {
    let wasm_bytes = minimal_cosmwasm_module()?;
    run_canonical_multi_ee_block_with_wasm(&wasm_bytes)
}

/// Execute the canonical 5-environment block sequence using pre-assembled `.wasm` bytes.
pub fn run_canonical_multi_ee_block_with_wasm(
    wasm_bytes: &[u8],
) -> Result<(MemoryHost, [u8; 32]), String> {
    let ctx = BlockContext {
        chain_id: 45_261,
        height: 1_024,
        timestamp_ms: 1_793_923_200_000,
    };
    let mut host = MemoryHost::new(BLOCK_GAS_LIMIT_BGU);

    // 1. BudZero (0x00): deploy + call logging sender word 0.
    let mut bz = BudZeroWorker;
    let bz_caller = EeIdentity::new(EeId::BUDZERO, vec![0x10; 32]).map_err(|e| e.to_string())?;
    let bz_prog = EeIdentity::new(EeId::BUDZERO, vec![0x20; 32]).map_err(|e| e.to_string())?;
    let bz_dep = bz
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: bz_caller.clone(),
                target: bz_prog.clone(),
                value: BudAmount(0),
                input: minimal_budzero_program(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x01; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if bz_dep.status != OutcomeStatus::Success {
        return Err("BudZero deploy failed".to_string());
    }
    let bz_run = bz
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: bz_caller,
                target: bz_prog,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x02; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if bz_run.status != OutcomeStatus::Success {
        return Err("BudZero call failed".to_string());
    }

    // 2. EVM (0x01): deploy contract + execute SSTORE(0, 0x2A).
    let mut evm = EvmWorker;
    let evm_caller = EeIdentity::new(EeId::EVM, vec![0x11; 20]).map_err(|e| e.to_string())?;
    let evm_target = EeIdentity::new(EeId::EVM, vec![0x22; 20]).map_err(|e| e.to_string())?;
    let evm_dep = evm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: evm_caller.clone(),
                target: evm_target,
                value: BudAmount(0),
                input: evm_sstore_initcode(),
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x03; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if evm_dep.status != OutcomeStatus::Success || evm_dep.output.len() != 20 {
        return Err(format!("EVM deploy failed: {:?}", evm_dep.status));
    }
    let deployed_evm = EeIdentity::new(EeId::EVM, evm_dep.output).map_err(|e| e.to_string())?;
    let evm_call = evm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: evm_caller,
                target: deployed_evm,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x04; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if evm_call.status != OutcomeStatus::Success {
        return Err("EVM SSTORE call failed".to_string());
    }

    // 3. WASM (0x02): store code + instantiate CosmWasm contract.
    let mut wasm = WasmWorker;
    let wasm_raw = vec![0x33u8; 20];
    let wasm_human = bud_addr_humanize(&wasm_raw)?;
    let wasm_caller =
        EeIdentity::new(EeId::WASM, wasm_human.into_bytes()).map_err(|e| e.to_string())?;
    let store_json = serde_json::to_vec(&WasmTxAction::StoreCode {
        wasm_b64: b64_encode(wasm_bytes),
    })
    .map_err(|e| e.to_string())?;
    let wasm_store = wasm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: wasm_caller.clone(),
                target: wasm_caller.clone(),
                value: BudAmount(0),
                input: store_json,
                gas_limit: 2_000_000,
                depth: 0,
                tx_hash: [0x05; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if wasm_store.status != OutcomeStatus::Success {
        return Err("WASM StoreCode failed".to_string());
    }
    let inst_json = serde_json::to_vec(&WasmTxAction::Instantiate {
        code_id: 1,
        admin: None,
        label: "conformance-cw".to_string(),
        msg_b64: b64_encode(b"{}"),
        funds_ubud: 0,
    })
    .map_err(|e| e.to_string())?;
    let wasm_inst = wasm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: wasm_caller.clone(),
                target: wasm_caller,
                value: BudAmount(0),
                input: inst_json,
                gas_limit: 2_000_000,
                depth: 0,
                tx_hash: [0x06; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if wasm_inst.status != OutcomeStatus::Success {
        return Err("WASM Instantiate failed".to_string());
    }

    // 4. SVM (0x03): deploy sBPF V3 program + execute System transfer.
    let mut svm = SvmWorker;
    let svm_payer = [0x44u8; 32];
    let svm_prog = [0x55u8; 32];
    let svm_rcpt = [0x66u8; 32];
    let svm_payer_id = EeIdentity::new(EeId::SVM, svm_payer.to_vec()).map_err(|e| e.to_string())?;
    let svm_prog_id = EeIdentity::new(EeId::SVM, svm_prog.to_vec()).map_err(|e| e.to_string())?;
    let svm_sys_id =
        EeIdentity::new(EeId::SVM, SYSTEM_PROGRAM_ID.to_vec()).map_err(|e| e.to_string())?;
    host.balances
        .insert(svm_payer_id.clone(), 1_000_000 * ATTOS_PER_LAMPORT);
    let svm_dep = svm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: svm_payer_id.clone(),
                target: svm_prog_id.clone(),
                value: BudAmount(0),
                input: minimal_sbpf_v3_program(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x07; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if svm_dep.status != OutcomeStatus::Success {
        return Err("SVM deploy failed".to_string());
    }
    let mut sys_transfer = vec![2, 0, 0, 0]; // SystemInstruction::Transfer = 2 (u32 LE)
    sys_transfer.extend_from_slice(&25_000u64.to_le_bytes());
    let svm_ix = serde_json::to_vec(&SvmInstructionEnvelope {
        accounts: vec![
            SvmAccountMeta {
                pubkey: svm_payer,
                is_signer: true,
                is_writable: true,
            },
            SvmAccountMeta {
                pubkey: svm_rcpt,
                is_signer: false,
                is_writable: true,
            },
        ],
        data: sys_transfer,
    })
    .map_err(|e| e.to_string())?;
    let svm_sys = svm
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: svm_payer_id,
                target: svm_sys_id,
                value: BudAmount(0),
                input: svm_ix,
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x08; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if svm_sys.status != OutcomeStatus::Success {
        return Err("SVM System transfer failed".to_string());
    }

    // 5. Move (0x04): publish Move module + execute entry function writing resource.
    let mut mv = MoveWorker::new();
    let mv_pub = [0x77u8; 32];
    let mv_id = EeIdentity::new(EeId::MOVE, mv_pub.to_vec()).map_err(|e| e.to_string())?;
    let mv_mod = CompiledMoveModule {
        address: mv_pub,
        name: "vault".to_string(),
        functions: vec![MoveFunctionDef {
            name: "deposit_tag".to_string(),
            is_entry: true,
            is_view: false,
            code: vec![MoveOp::WriteResource {
                resource_tag: "0x77::vault::State".to_string(),
                value: b"uel-ready".to_vec(),
            }],
        }],
    };
    let raw_mod = encode_move_module(&mv_mod)?;
    let pub_in = serde_json::to_vec(&MovePayload::PublishPackage {
        metadata_serialized: b"meta".to_vec(),
        modules: vec![raw_mod],
    })
    .map_err(|e| e.to_string())?;
    let mv_dep = mv
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: mv_id.clone(),
                target: mv_id.clone(),
                value: BudAmount(0),
                input: pub_in,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x09; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if mv_dep.status != OutcomeStatus::Success {
        return Err("Move PublishPackage failed".to_string());
    }
    let run_in = serde_json::to_vec(&MovePayload::EntryFunction {
        module_address: mv_pub,
        module_name: "vault".to_string(),
        function_name: "deposit_tag".to_string(),
        ty_args: Vec::new(),
        args: Vec::new(),
    })
    .map_err(|e| e.to_string())?;
    let mv_run = mv
        .execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller: mv_id.clone(),
                target: mv_id,
                value: BudAmount(0),
                input: run_in,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x0A; 32],
            },
            &mut host,
        )
        .map_err(|e| e.to_string())?;
    if mv_run.status != OutcomeStatus::Success {
        return Err("Move EntryFunction failed".to_string());
    }

    let root = compute_conformance_execution_root(&host);
    Ok((host, root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> BlockContext {
        BlockContext {
            chain_id: 45_261,
            height: 256,
            timestamp_ms: 1_793_923_200_000,
        }
    }

    /// Directive IP-35 suite gate for EVM (`0x01`).
    #[test]
    fn uel_conformance_evm() {
        let mut worker = EvmWorker;
        let initcode = evm_sstore_initcode();
        assert!(worker.validate_deploy(&initcode).is_ok());
        assert!(worker.validate_deploy(&[]).is_err());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::EVM, vec![0xAA; 20]) else {
            panic!("caller");
        };
        let Ok(target) = EeIdentity::new(EeId::EVM, vec![0xBB; 20]) else {
            panic!("target");
        };
        let Ok(dep) = worker.execute(
            &test_ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target,
                value: BudAmount(0),
                input: initcode,
                gas_limit: 1_000_000,
                depth: 0,
                tx_hash: [0x11; 32],
            },
            &mut host,
        ) else {
            panic!("evm deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(contract) = EeIdentity::new(EeId::EVM, dep.output) else {
            panic!("contract");
        };
        let Ok(call_out) = worker.execute(
            &test_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: contract,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x12; 32],
            },
            &mut host,
        ) else {
            panic!("evm call");
        };
        assert_eq!(call_out.status, OutcomeStatus::Success);
        assert_eq!(call_out.output.last().copied(), Some(0x2A));
        assert!(host.state.keys().any(|(ns, _)| ns == NS_EVM_STORAGE));
    }

    /// Directive IP-35 suite gate for WASM (`0x02`).
    #[test]
    fn uel_conformance_wasm() {
        let worker = WasmWorker;
        let Ok(good_wasm) = minimal_cosmwasm_module() else {
            panic!("wat");
        };
        assert!(worker.validate_deploy(&good_wasm).is_ok());

        // Floating-point Wasm module must be deterministically refused (Section 8.15).
        let Ok(float_wasm) = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "allocate") (param i32) (result i32) (i32.const 0))
                (func (export "deallocate") (param i32))
                (func (export "f") (param f64) (result f64) (f64.add (local.get 0) (local.get 0)))
            )"#,
        ) else {
            panic!("float wat");
        };
        assert!(worker.validate_deploy(&float_wasm).is_err());

        // IBC export must be deterministically refused (Section 8.15).
        let Ok(ibc_wasm) = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func (export "allocate") (param i32) (result i32) (i32.const 0))
                (func (export "deallocate") (param i32))
                (func (export "ibc_packet_receive") (param i32 i32) (result i32) (i32.const 0))
            )"#,
        ) else {
            panic!("ibc wat");
        };
        assert!(worker.validate_deploy(&ibc_wasm).is_err());

        let Ok((host, _)) = run_canonical_multi_ee_block_sequence() else {
            panic!("multi-ee sequence");
        };
        assert!(host.state.keys().any(|(ns, _)| ns == NS_WASM_STORE));
    }

    /// Directive IP-35 suite gate for SVM (`0x03`).
    #[test]
    fn uel_conformance_svm() {
        let mut worker = SvmWorker;
        let sbpf = minimal_sbpf_v3_program();
        assert!(worker.validate_deploy(&sbpf).is_ok());

        let mut host = MemoryHost::new(2_000_000);
        let Ok(caller) = EeIdentity::new(EeId::SVM, vec![0x01; 32]) else {
            panic!("caller");
        };
        // Solana Vote and Stake programs must be deterministically refused (Section 8.15).
        for forbidden in [VOTE_PROGRAM_ID, STAKE_PROGRAM_ID] {
            let Ok(target) = EeIdentity::new(EeId::SVM, forbidden.to_vec()) else {
                panic!("target");
            };
            let Ok(ix) = serde_json::to_vec(&SvmInstructionEnvelope {
                accounts: Vec::new(),
                data: Vec::new(),
            }) else {
                panic!("ix");
            };
            let Ok(out) = worker.execute(
                &test_ctx(),
                &EeCall {
                    kind: EeCallKind::Call,
                    caller: caller.clone(),
                    target,
                    value: BudAmount(0),
                    input: ix,
                    gas_limit: 200_000,
                    depth: 0,
                    tx_hash: [0x21; 32],
                },
                &mut host,
            ) else {
                panic!("svm exec");
            };
            assert_eq!(out.status, OutcomeStatus::Revert);
        }
        let Ok((full_host, _)) = run_canonical_multi_ee_block_sequence() else {
            panic!("multi-ee");
        };
        assert!(full_host.state.keys().any(|(ns, _)| ns == NS_SVM_ACCOUNT));
    }

    /// Directive IP-35 suite gate for Move (`0x04`).
    #[test]
    fn uel_conformance_move() {
        assert!(is_scheme_byte_unused_in_pinned_aptos(BUDLUM_MOVE_ALIAS_SCHEME_BYTE));
        let mut worker = MoveWorker::new();
        let mut host = MemoryHost::new(2_000_000);
        let Ok(caller) = EeIdentity::new(EeId::MOVE, vec![0x31; 32]) else {
            panic!("caller");
        };
        let Ok(fw) = EeIdentity::new(EeId::MOVE, FRAMEWORK_ADDRESS.to_vec()) else {
            panic!("fw");
        };
        let Ok(stake_in) = serde_json::to_vec(&MovePayload::EntryFunction {
            module_address: FRAMEWORK_ADDRESS,
            module_name: "stake".to_string(),
            function_name: "initialize".to_string(),
            ty_args: Vec::new(),
            args: Vec::new(),
        }) else {
            panic!("stake json");
        };
        let Ok(stake_out) = worker.execute(
            &test_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: fw,
                value: BudAmount(0),
                input: stake_in,
                gas_limit: 200_000,
                depth: 0,
                tx_hash: [0x31; 32],
            },
            &mut host,
        ) else {
            panic!("move exec");
        };
        assert_eq!(stake_out.status, OutcomeStatus::Revert);

        let Ok((full_host, _)) = run_canonical_multi_ee_block_sequence() else {
            panic!("multi-ee");
        };
        assert!(full_host.state.keys().any(|(ns, _)| ns == NS_MOVE_STATE));
        let Ok(view_in) = serde_json::to_vec(&MoveQuery::Resource {
            account: [0x77u8; 32],
            resource_tag: "0x77::vault::State".to_string(),
        }) else {
            panic!("view json");
        };
        let Ok(mv_target) = EeIdentity::new(EeId::MOVE, vec![0x77; 32]) else {
            panic!("mv target");
        };
        let Ok(val) = worker.query(
            &test_ctx(),
            &EeQuery {
                target: mv_target,
                input: view_in,
            },
            &full_host,
        ) else {
            panic!("move query");
        };
        assert_eq!(val, b"uel-ready");
    }

    /// Directive IP-35 suite gate for BudZero (`0x00`).
    #[test]
    fn uel_conformance_budzero() {
        let mut worker = BudZeroWorker;
        let code = minimal_budzero_program();
        assert!(worker.validate_deploy(&code).is_ok());

        // Testnet-closed opcodes must be refused at deploy validation (Section 10.1).
        for closed in [Opcode::VerifyMerkle, Opcode::VerifyInference] {
            let raw = Instruction {
                opcode: closed,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode()
            .to_le_bytes();
            assert!(worker.validate_deploy(&raw).is_err());
        }

        let mut host = MemoryHost::new(2_000_000);
        let Ok(caller) = EeIdentity::new(EeId::BUDZERO, vec![0x5A; 32]) else {
            panic!("caller");
        };
        let Ok(prog) = EeIdentity::new(EeId::BUDZERO, vec![0x6B; 32]) else {
            panic!("prog");
        };
        let Ok(dep) = worker.execute(
            &test_ctx(),
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: prog.clone(),
                value: BudAmount(0),
                input: code,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x41; 32],
            },
            &mut host,
        ) else {
            panic!("bz deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(run) = worker.execute(
            &test_ctx(),
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: prog,
                value: BudAmount(0),
                input: Vec::new(),
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x42; 32],
            },
            &mut host,
        ) else {
            panic!("bz run");
        };
        assert_eq!(run.status, OutcomeStatus::Success);
        assert_eq!(run.output, vec![0x5A; 8]);
    }

    /// Directive IP-35 item 2 gate: `uel_gas_calibration_bound` (`1 BGU <= 16 ns` p95).
    #[test]
    fn uel_gas_calibration_bound() {
        assert_eq!(BLOCK_GAS_LIMIT_BGU, 60_000_000);
        assert_eq!(
            INITIAL_BGU_RATES,
            [
                (EeId::BUDZERO, 1),
                (EeId::EVM, 1),
                (EeId::WASM, 1),
                (EeId::SVM, 1),
                (EeId::MOVE, 100),
            ]
        );

        // Warm up once with pre-compiled Wasm bytecode, then sample 40 full
        // 5-environment block sequences and evaluate the p95 ns/BGU.
        let Ok(wasm_bytes) = minimal_cosmwasm_module() else {
            panic!("wat assembly failed");
        };
        let Ok((warm_host, _)) = run_canonical_multi_ee_block_with_wasm(&wasm_bytes) else {
            panic!("warmup sequence failed");
        };
        assert!(warm_host.gas_charged > 0);

        let mut samples_ns_per_bgu = Vec::with_capacity(40);
        for _ in 0..40 {
            let start = Instant::now();
            let Ok((h, _)) = run_canonical_multi_ee_block_with_wasm(&wasm_bytes) else {
                panic!("sample sequence failed");
            };
            let elapsed_ns = start.elapsed().as_nanos();
            let charged = u128::from(h.gas_charged.max(1));
            samples_ns_per_bgu.push(elapsed_ns / charged);
        }
        samples_ns_per_bgu.sort_unstable();
        // p95 index in 40 sorted samples -> index 37 (0-based).
        let p95 = samples_ns_per_bgu.get(37).copied().unwrap_or(0);
        println!("UEL_CALIBRATION_P95_NS_PER_BGU={p95}");

        // In optimized `--release` builds (nightly calibration gate), enforce the exact
        // Section 8.9 item 4 bound (`1 BGU <= 16 ns`); in unoptimized debug builds, allow
        // debug-codegen headroom while verifying boundedness.
        let bound = if cfg!(debug_assertions) {
            500
        } else {
            MAX_NS_PER_BGU_RELEASE
        };
        assert!(
            p95 <= bound,
            "p95 calibration {p95} ns/BGU exceeded bound {bound} ns/BGU"
        );
    }

    /// Directive IP-35 item 3 & Section 8.16 gate: `uel_cross_arch_roots_equal`.
    #[test]
    fn uel_cross_arch_roots_equal() {
        let Ok((_, root_a)) = run_canonical_multi_ee_block_sequence() else {
            panic!("sequence A failed");
        };
        let Ok((_, root_b)) = run_canonical_multi_ee_block_sequence() else {
            panic!("sequence B failed");
        };
        assert_eq!(root_a, root_b);
        assert_ne!(root_a, [0u8; 32]);
        let hex_root = hex::encode(root_a);
        println!("UEL_EXECUTION_ROOT={hex_root}");
    }
}
