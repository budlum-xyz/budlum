use super::*;
use crate::core::account::{Account, ATTOS_PER_ATOM};
use crate::execution::coordinator::alias::derive_evm_alias;
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::state::ALL_NAMESPACES;
use bud_isa::{Instruction, Opcode};
use std::collections::BTreeSet;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static TEST_SOCK_SEQ: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
fn temp_socket_path(label: &str) -> std::path::PathBuf {
    let seq = TEST_SOCK_SEQ.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "budlum-uel-{label}-{}-{seq}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// Deterministic test environment operating on canonical UEL namespaces.
struct CanonicalTestEe {
    ee: EeId,
    ns: &'static str,
}

impl ExecutionEnvironment for CanonicalTestEe {
    fn id(&self) -> EeId {
        self.ee
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: String::from("empty code"),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: String::from("test-v1"),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(self.ns).expect("valid canonical namespace");
        if call.kind == EeCallKind::Deploy {
            let _ = host.charge(500);
            let _ = host.write(&ns, &call.target.id, Some(&call.input));
            return Ok(EeOutcome {
                status: OutcomeStatus::Success,
                output: call.target.id.clone(),
                gas_used: 500,
            });
        }
        let op = call.input.first().copied().unwrap_or(0);
        match op {
            0x00 => {
                let _ = host.charge(200);
                let key = call.input.get(1..5).unwrap_or(b"k000");
                let val = call.input.get(5..).unwrap_or(b"v");
                host.write(&ns, key, Some(val)).expect("write");
                Ok(EeOutcome {
                    status: OutcomeStatus::Success,
                    output: val.to_vec(),
                    gas_used: 200,
                })
            }
            0x01 => {
                let _ = host.charge(300);
                host.write(&ns, b"reverted-key", Some(b"dirty"))
                    .expect("staged write");
                Ok(EeOutcome {
                    status: OutcomeStatus::Revert,
                    output: b"revert".to_vec(),
                    gas_used: 300,
                })
            }
            0x02 => {
                panic!("injected-worker-panic");
            }
            0x03 => {
                let _ = host.charge(150);
                host.write(&ns, b"outer-key", Some(b"outer-val"))
                    .expect("outer write");
                let to_ee = EeId(call.input.get(1).copied().unwrap_or(EeId::WASM.0));
                let outer_reverts = call.input.get(2).copied() == Some(0xFF);
                let sub_input = call.input.get(3..).unwrap_or(&[]).to_vec();
                let target = EeIdentity::new(to_ee, vec![0xCC; 32]).expect("target");
                let ucall = UniversalCall {
                    from: call.target.clone(),
                    to_ee,
                    target,
                    value: BudAmount(u128::from(ATTOS_PER_ATOM)),
                    input: sub_input,
                    gas_limit: call.gas_limit.saturating_sub(150),
                };
                match host.universal_call(ucall) {
                    Ok(res) => {
                        if outer_reverts {
                            Ok(EeOutcome {
                                status: OutcomeStatus::Revert,
                                output: res.output,
                                gas_used: 150 + res.gas_used,
                            })
                        } else {
                            let tag = u8::from(res.success);
                            Ok(EeOutcome {
                                status: OutcomeStatus::Success,
                                output: vec![tag],
                                gas_used: 150 + res.gas_used,
                            })
                        }
                    }
                    Err(e) => Ok(EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: e.to_string().into_bytes(),
                        gas_used: 250,
                    }),
                }
            }
            _ => Ok(EeOutcome {
                status: OutcomeStatus::InvalidCode,
                output: Vec::new(),
                gas_used: 100,
            }),
        }
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        _q: &EeQuery,
        _host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        Ok(Vec::new())
    }
}

fn funded_state(addrs: &[Address]) -> AccountState {
    let mut state = AccountState::new();
    for a in addrs {
        state.accounts.insert(*a, Account::with_balance(*a, 1_000_000));
    }
    state.keys_dirty = true;
    state
}

fn sample_ctx() -> BlockContext {
    BlockContext {
        chain_id: 45261,
        height: 10,
        timestamp_ms: 1_762_000_000_000,
    }
}

fn make_call_tx(sender: Address, nonce: u64, ee: EeId, input: Vec<u8>) -> UelTx {
    let mut tx_hash = [0u8; 32];
    tx_hash[0] = ee.0;
    tx_hash[1..9].copy_from_slice(&nonce.to_le_bytes());
    UelTx {
        tx_hash,
        sender,
        nonce,
        ee,
        action: UelAction::Call {
            target: vec![0xAB; 32],
            input,
        },
        value_attos: 0,
        gas_limit_bgu: 50_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 100,
    }
}

#[test]
fn uel_worker_panic_yields_fault_receipt() {
    let sender = Address::from([0x11; 32]);
    let proposer = Address::from([0x99; 32]);
    let mut state = funded_state(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    #[cfg(unix)]
    let sock_path = {
        let path = temp_socket_path("panic");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind unix socket");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2).flatten() {
                let mut ee = CanonicalTestEe {
                    ee: EeId::EVM,
                    ns: "ee/evm/storage",
                };
                let _ = budlum_uel_abi::transport::serve_connection(stream, &mut ee);
            }
        });
        coord.register_worker(WorkerEndpoint::unix_socket(EeId::EVM, path.clone(), None));
        path
    };
    #[cfg(not(unix))]
    {
        coord.register_worker(WorkerEndpoint::in_process(|| {
            Box::new(CanonicalTestEe {
                ee: EeId::EVM,
                ns: "ee/evm/storage",
            })
        }));
    }

    let panic_tx = make_call_tx(sender, 0, EeId::EVM, vec![0x02]);
    let mut ok_input = vec![0x00];
    ok_input.extend_from_slice(b"slotok-after-panic");
    let next_tx = make_call_tx(sender, 1, EeId::EVM, ok_input);

    let receipts = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[panic_tx, next_tx])
        .expect("panic yields fault receipt without crashing block");
    assert_eq!(receipts.len(), 2);
    let expected_digest = budlum_uel_abi::panic_digest(EeId::EVM, "injected-worker-panic");
    assert_eq!(
        receipts[0].status,
        UelReceiptStatus::Fault {
            ee: EeId::EVM.0,
            panic_digest: expected_digest,
        }
    );
    assert_eq!(receipts[0].gas_used_bgu, 50_000);
    assert_eq!(coord.supervisor().fault_count(EeId::EVM), 1);
    assert_eq!(receipts[1].status, UelReceiptStatus::Success);
    assert_eq!(
        state
            .execution_state
            .read("ee/evm/storage", b"slot")
            .expect("read"),
        Some(b"ok-after-panic".to_vec())
    );
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(sock_path);
    }
}

#[test]
fn uel_worker_death_does_not_commit() {
    let sender = Address::from([0x21; 32]);
    let proposer = Address::from([0x22; 32]);
    let mut state = funded_state(&[sender, proposer]);
    let root_before = state.calculate_state_root();
    let exec_root_before = state.execution_state.execution_root();

    let mut coord_dead = ExecutionCoordinator::new();
    #[cfg(unix)]
    let dead_sock = {
        let path = temp_socket_path("dead");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind dead socket");
        std::thread::spawn(move || {
            for mut stream in listener.incoming().take(3).flatten() {
                let hello = budlum_uel_abi::frame::read_frame(&mut stream).expect("hello");
                let reply = budlum_uel_abi::pb::Envelope {
                    abi_version: budlum_uel_abi::ABI_VERSION,
                    request_id: hello.request_id,
                    body: Some(budlum_uel_abi::pb::envelope::Body::Hello(
                        budlum_uel_abi::pb::Hello {
                            ee: u32::from(EeId::EVM.0),
                        },
                    )),
                };
                budlum_uel_abi::frame::write_frame(&mut stream, &reply).expect("reply");
                let _ = budlum_uel_abi::frame::read_frame(&mut stream);
                drop(stream);
            }
        });
        coord_dead.register_worker(WorkerEndpoint::unix_socket(EeId::EVM, path.clone(), None));
        path
    };

    let mut input = vec![0x00];
    input.extend_from_slice(b"key1val1");
    let tx = make_call_tx(sender, 0, EeId::EVM, input);
    let err = state
        .execute_uel_block(&mut coord_dead, sample_ctx(), proposer, &[tx.clone()])
        .expect_err("persistent worker death must halt without committing");
    assert!(matches!(
        err,
        CoordinatorError::WorkerHalt { attempts: 3, .. }
    ));
    assert!(coord_dead.supervisor().halt_alarm().is_some());
    assert_eq!(state.calculate_state_root(), root_before);
    assert_eq!(state.execution_state.execution_root(), exec_root_before);
    assert_eq!(state.get_nonce(&sender), 0);

    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(dead_sock);
        let recover_sock = temp_socket_path("recover");
        let listener =
            std::os::unix::net::UnixListener::bind(&recover_sock).expect("bind recover socket");
        std::thread::spawn(move || {
            for (idx, mut stream) in listener.incoming().take(2).flatten().enumerate() {
                if idx == 0 {
                    let hello = budlum_uel_abi::frame::read_frame(&mut stream).expect("hello");
                    let reply = budlum_uel_abi::pb::Envelope {
                        abi_version: budlum_uel_abi::ABI_VERSION,
                        request_id: hello.request_id,
                        body: Some(budlum_uel_abi::pb::envelope::Body::Hello(
                            budlum_uel_abi::pb::Hello {
                                ee: u32::from(EeId::EVM.0),
                            },
                        )),
                    };
                    budlum_uel_abi::frame::write_frame(&mut stream, &reply).expect("reply");
                    let _ = budlum_uel_abi::frame::read_frame(&mut stream);
                    drop(stream);
                } else {
                    let mut ee = CanonicalTestEe {
                        ee: EeId::EVM,
                        ns: "ee/evm/storage",
                    };
                    let _ = budlum_uel_abi::transport::serve_connection(stream, &mut ee);
                }
            }
        });
        let mut coord_recover = ExecutionCoordinator::new();
        coord_recover.register_worker(WorkerEndpoint::unix_socket(
            EeId::EVM,
            recover_sock.clone(),
            None,
        ));
        let receipts = state
            .execute_uel_block(&mut coord_recover, sample_ctx(), proposer, &[tx])
            .expect("retry 2 recovers");
        assert_eq!(receipts[0].status, UelReceiptStatus::Success);
        let _ = std::fs::remove_file(recover_sock);
    }
}

#[test]
fn coordinator_overlay_rolls_back_frame() {
    let sender = Address::from([0x31; 32]);
    let evm_contract = Address::from([0xAB; 32]);
    let proposer = Address::from([0x32; 32]);
    let mut state = funded_state(&[sender, evm_contract, proposer]);
    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(|| {
        Box::new(CanonicalTestEe {
            ee: EeId::EVM,
            ns: "ee/evm/storage",
        })
    }));
    coord.register_worker(WorkerEndpoint::in_process(|| {
        Box::new(CanonicalTestEe {
            ee: EeId::WASM,
            ns: "ee/wasm/store",
        })
    }));

    let evm_bal_before = state.get_attos_balance(&evm_contract);
    let tx1 = make_call_tx(sender, 0, EeId::EVM, vec![0x03, EeId::WASM.0, 0x00, 0x01]);
    let r1 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx1])
        .expect("block 1");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    assert_eq!(r1[0].output, vec![0u8]);
    assert_eq!(
        state
            .execution_state
            .read("ee/evm/storage", b"outer-key")
            .expect("read"),
        Some(b"outer-val".to_vec())
    );
    assert_eq!(
        state
            .execution_state
            .read("ee/wasm/store", b"reverted-key")
            .expect("read"),
        None
    );
    assert_eq!(state.get_attos_balance(&evm_contract), evm_bal_before);

    let mut tx2_input = vec![0x03, EeId::WASM.0, 0xFF, 0x00];
    tx2_input.extend_from_slice(b"wkeywval");
    let tx2 = make_call_tx(sender, 1, EeId::EVM, tx2_input);
    let r2 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx2])
        .expect("block 2");
    assert_eq!(r2[0].status, UelReceiptStatus::Revert);
    assert_eq!(
        state
            .execution_state
            .read("ee/wasm/store", b"wkey")
            .expect("read"),
        None
    );
    assert_eq!(state.get_attos_balance(&evm_contract), evm_bal_before);
}

#[test]
fn uel_reentrancy_forbidden() {
    let sender = Address::from([0x41; 32]);
    let evm_contract = Address::from([0xAB; 32]);
    let wasm_contract = Address::from([0xCC; 32]);
    let proposer = Address::from([0x42; 32]);
    let mut state = funded_state(&[sender, evm_contract, wasm_contract, proposer]);
    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(|| {
        Box::new(CanonicalTestEe {
            ee: EeId::EVM,
            ns: "ee/evm/storage",
        })
    }));
    coord.register_worker(WorkerEndpoint::in_process(|| {
        Box::new(CanonicalTestEe {
            ee: EeId::WASM,
            ns: "ee/wasm/store",
        })
    }));

    let chain_input = vec![0x03, EeId::WASM.0, 0x00, 0x03, EeId::EVM.0, 0x00, 0x00];
    let tx = make_call_tx(sender, 0, EeId::EVM, chain_input);
    let receipts = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[tx])
        .expect("block");
    assert_eq!(receipts[0].status, UelReceiptStatus::Success);
    assert_eq!(receipts[0].output, vec![0u8], "nested EVM re-entry failed");
}

#[test]
fn uel_depth_limit() {
    let sender = Address::from([0x51; 32]);
    let mut state = funded_state(&[sender]);
    let mut overlay = TxOverlay::new(&state, EeId(0), 1_000_000);
    for d in 1u8..=8u8 {
        overlay
            .push_universal_frame(&state, EeId(d), false)
            .expect("frames 1..=8 allowed");
    }
    let ninth = overlay.push_universal_frame(&state, EeId(9), false);
    assert_eq!(ninth, Err(HostError::DepthExceeded));
    overlay.rollback_root(&mut state);
}

#[test]
fn execution_root_binds_every_namespace() {
    let mut base = state::ExecutionState::new();
    let empty_root = base.execution_root();
    let mut seen = BTreeSet::new();
    seen.insert(empty_root);

    for (idx, ns) in ALL_NAMESPACES.iter().enumerate() {
        base.write(ns, &[idx as u8, 0xAA], Some(&[0x55, idx as u8]))
            .expect("canonical namespace write");
        let next_root = base.execution_root();
        assert!(
            seen.insert(next_root),
            "namespace `{ns}` write failed to change execution_root uniquely"
        );
    }
    assert_eq!(seen.len(), ALL_NAMESPACES.len() + 1);
}

#[test]
fn uel_cross_arch_roots_equal() {
    let mut exec = state::ExecutionState::new();
    let mut evm_key = [0u8; 52];
    evm_key[..20].copy_from_slice(&[0x11; 20]);
    evm_key[20..].copy_from_slice(&[0x01; 32]);
    let mut evm_val = [0u8; 32];
    evm_val[31] = 0x2a;

    exec.write("ee/evm/storage", &evm_key, Some(&evm_val))
        .expect("evm");
    exec.write("ee/wasm/store", b"bud1contract:count", Some(b"42"))
        .expect("wasm");
    exec.write("ee/svm/account", &[0x33; 32], Some(b"svm-data"))
        .expect("svm");
    exec.write(
        "ee/move/state",
        b"0x1::coin::CoinStore",
        Some(&[1, 2, 3, 4]),
    )
    .expect("move");
    exec.write("ee/budzero/storage", &[0x55; 64], Some(b"stateful"))
        .expect("budzero");
    let mut alias_key = [0x77u8; 33];
    alias_key[32] = 1;
    exec.write("uel/alias", &alias_key, Some(&[0x88; 20]))
        .expect("alias");
    exec.write("uel/assets", &[0x99; 32], Some(b"erc20:BUD"))
        .expect("assets");

    assert_eq!(
        hex::encode(exec.execution_root()),
        "5598c6ef114629591641bdfea88d90fd92e2ac010be57bfecb4d9a63d0d47cb1"
    );
}

#[test]
fn ee_feature_flag_freezes_new_deploys() {
    let sender = Address::from([0x61; 32]);
    let proposer = Address::from([0x62; 32]);
    let mut state = funded_state(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(|| {
        Box::new(CanonicalTestEe {
            ee: EeId::EVM,
            ns: "ee/evm/storage",
        })
    }));

    let deploy1 = UelTx {
        tx_hash: [0xD1; 32],
        sender,
        nonce: 0,
        ee: EeId::EVM,
        action: UelAction::Deploy {
            code: vec![0x60, 0x00, 0x60, 0x00],
            salt: [1u8; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 50_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
    };
    let r1 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[deploy1])
        .expect("deploy 1");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    let deployed_addr = r1[0].contract_address.expect("contract address");

    state.execution_state.set_deploy_enabled(EeId::EVM, false);

    let deploy2 = UelTx {
        tx_hash: [0xD2; 32],
        sender,
        nonce: 1,
        ee: EeId::EVM,
        action: UelAction::Deploy {
            code: vec![0x60, 0x01],
            salt: [2u8; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 50_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
    };
    let mut call_input = vec![0x00];
    call_input.extend_from_slice(b"livekept");
    let existing_call = UelTx {
        tx_hash: [0xC1; 32],
        sender,
        nonce: 2,
        ee: EeId::EVM,
        action: UelAction::Call {
            target: deployed_addr.0.to_vec(),
            input: call_input,
        },
        value_attos: 0,
        gas_limit_bgu: 50_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
    };
    let r2 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[deploy2, existing_call])
        .expect("frozen block still executes");
    assert_eq!(r2[0].status, UelReceiptStatus::DeployFrozen);
    assert!(r2[0].contract_address.is_none());
    assert_eq!(r2[1].status, UelReceiptStatus::Success);
}

#[test]
fn uel_alias_collision_refused() {
    let native = Address::from([0x71; 32]);
    let mut exec = state::ExecutionState::new();
    let alias_bytes = exec
        .ensure_alias_registered(&native, EeId::EVM)
        .expect("register EVM alias");
    let expected = derive_evm_alias(&native);
    assert_eq!(alias_bytes.as_slice(), &expected);
    assert!(exec.check_evm_alias_collision(&expected).is_err());
    assert!(exec.check_evm_alias_collision(&[0xFE; 20]).is_ok());
}

#[test]
fn budzero_stateful_storage_persists_across_blocks() {
    let sender = Address::from([0x81; 32]);
    let proposer = Address::from([0x82; 32]);
    let mut state = funded_state(&[sender, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let program = [
        Instruction {
            opcode: Opcode::Load,
            rd: 1,
            rs1: 0,
            rs2: 0,
            imm: 7,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Log,
            rd: 0,
            rs1: 1,
            rs2: 0,
            imm: 0,
        }
        .encode(),
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        }
        .encode(),
    ];
    let code: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();

    let deploy = UelTx {
        tx_hash: [0xB1; 32],
        sender,
        nonce: 0,
        ee: EeId::BUDZERO,
        action: UelAction::Deploy {
            code,
            salt: [0xAA; 32],
        },
        value_attos: 0,
        gas_limit_bgu: 200_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
    };
    let r1 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[deploy])
        .expect("deploy budzero contract");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    let contract_addr = r1[0].contract_address.expect("budzero contract address");

    let slot = [0x44u8; 32];
    let mut call_data = slot.to_vec();
    call_data.extend_from_slice(b"persisted-budzero-state");
    let call_tx = UelTx {
        tx_hash: [0xB2; 32],
        sender,
        nonce: 1,
        ee: EeId::BUDZERO,
        action: UelAction::Call {
            target: contract_addr.0.to_vec(),
            input: call_data,
        },
        value_attos: 0,
        gas_limit_bgu: 500_000,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
        max_priority_fee_per_bgu_attos: 0,
    };
    let r2 = state
        .execute_uel_block(&mut coord, sample_ctx(), proposer, &[call_tx])
        .expect("call budzero contract");
    assert_eq!(r2[0].status, UelReceiptStatus::Success);
    assert_eq!(r2[0].output, 7u64.to_le_bytes().to_vec());

    let mut full_key = contract_addr.0.to_vec();
    full_key.extend_from_slice(&slot);
    assert_eq!(
        state
            .execution_state
            .read("ee/budzero/storage", &full_key)
            .expect("read budzero storage"),
        Some(b"persisted-budzero-state".to_vec())
    );
}
