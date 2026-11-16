use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::alias::{derive_svm_alias, is_ed25519_on_curve};
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::move_ee::{
    MoveCallEnvelope, MoveEe, MoveRuntimeConfig, MOVE_BINARY_MAGIC,
};
use crate::execution::coordinator::state::NS_WASM_STORE;
use crate::execution::coordinator::svm_ee::{
    derive_associated_token_address, derive_spl_mint_address, svm_universal_program_id, SvmEe,
    SvmInstructionEnvelope, SvmRuntimeConfig, FORBIDDEN_SVM_STAKE_PROGRAM_ID,
    FORBIDDEN_SVM_VOTE_PROGRAM_ID, SVM_SPL_TOKEN_PROGRAM_ID,
};
use crate::execution::coordinator::wasm_ee::build_valid_cosmwasm_module;
use crate::execution::coordinator::{ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx};
use budlum_uel_abi::{BlockContext, EeId, ExecutionEnvironment};

fn sample_ctx() -> BlockContext {
    BlockContext {
        height: 77,
        timestamp_ms: 1_700_000_077_000,
        chain_id: 45_261,
    }
}

fn funded(addrs: &[Address]) -> AccountState {
    let mut s = AccountState::new();
    for a in addrs {
        s.credit_account(a, 10_000);
    }
    s
}

#[test]
fn svm_jit_is_disabled() {
    let svm = SvmEe::new();
    assert!(!svm.config().jit_enabled, "SBPF JIT must default to false");

    let bad_cfg = SvmRuntimeConfig {
        jit_enabled: true,
        ..SvmRuntimeConfig::default()
    };
    let err = SvmEe::with_config(bad_cfg).expect_err("enabling SBPF JIT must be refused");
    assert!(err.contains("JIT"));

    // Verify ELF SBPF deploy validation succeeds in interpreter mode.
    let mut valid_elf = vec![0x7f, b'E', b'L', b'F'];
    valid_elf.extend_from_slice(&[0x02, 0x01, 0x01, 0x00]);
    svm.validate_deploy(&valid_elf).expect("valid ELF accepted");
    assert!(svm.validate_deploy(b"NOPE").is_err());
}

#[test]
fn svm_spl_token_and_vote_stake_refusal_and_universal_cpi() {
    let (alice_seed, alice) = super::test_uel_signer(0x71);
    let bob = Address::from([0x72; 32]);
    let proposer = Address::from([0x73; 32]);
    let mut state = funded(&[alice, bob, proposer]);
    let mut coord = ExecutionCoordinator::new();

    let (alice_svm, _) = derive_svm_alias(&alice).expect("alice off-curve svm alias");
    let (bob_svm, _) = derive_svm_alias(&bob).expect("bob off-curve svm alias");
    let mint_seed = [0x99u8; 32];
    let mint = derive_spl_mint_address(&alice_svm, &mint_seed).expect("mint address");
    let ata = derive_associated_token_address(&alice_svm, &mint).expect("ata");
    assert!(!is_ed25519_on_curve(&ata));

    // 1. Initialize SPL Mint, MintTo 500 to Alice, Transfer 200 to Bob.
    let init_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplInitializeMint {
        mint_seed,
        decimals: 6,
        mint_authority: alice_svm,
        is_token_2022: false,
    })
    .expect("json");
    let mint_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplMintTo {
        mint,
        dest_owner: alice_svm,
        amount: 500,
    })
    .expect("json");
    let xfer_ix = serde_json::to_vec(&SvmInstructionEnvelope::SplTransfer {
        mint,
        to_owner: bob_svm,
        amount: 200,
    })
    .expect("json");

    let recs = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x61; 32],
                    sender: alice,
                    nonce: 0,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: init_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed),
                UelTx {
                    tx_hash: [0x62; 32],
                    sender: alice,
                    nonce: 1,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: mint_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed),
                UelTx {
                    tx_hash: [0x63; 32],
                    sender: alice,
                    nonce: 2,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                        input: xfer_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed),
            ],
        )
        .expect("spl block");
    assert!(recs.iter().all(|r| r.status == UelReceiptStatus::Success));

    // 2. Vote and Stake programs MUST be refused (section 8.15).
    for (idx, forbidden_prog) in [
        FORBIDDEN_SVM_VOTE_PROGRAM_ID,
        FORBIDDEN_SVM_STAKE_PROGRAM_ID,
    ]
    .iter()
    .enumerate()
    {
        let r = state
            .execute_uel_block(
                &mut coord,
                sample_ctx(),
                proposer,
                &[UelTx {
                    tx_hash: [0x64 + idx as u8; 32],
                    sender: alice,
                    nonce: 3 + idx as u64,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: forbidden_prog.to_vec(),
                        input: b"{}".to_vec(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 100_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed)],
            )
            .expect("forbidden prog block");
        assert_eq!(r[0].status, UelReceiptStatus::Revert);
    }

    // 3. SVM Universal Call builtin CPI into WASM contract!
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x66; 32],
                sender: alice,
                nonce: 5,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x44; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
                auth: super::UelTxAuth::default(),
            }
            .signed(sample_ctx().chain_id, &alice_seed)],
        )
        .expect("deploy wasm");
    let wasm_contract = dep[0].output.clone();

    let auth_msg = serde_json::to_vec(&serde_json::json!({
        "execute": {
            "authorize_caller": {
                "caller": String::from_utf8_lossy(&svm_universal_program_id())
            }
        }
    }))
    .expect("json");
    let wasm_put = serde_json::to_vec(&serde_json::json!({
        "execute": { "put": { "key": "from_svm", "value": "ok" } }
    }))
    .expect("json");
    let cpi_ix = serde_json::to_vec(&SvmInstructionEnvelope::UniversalCpi {
        target_ee: EeId::WASM.0,
        target: wasm_contract.clone(),
        input: wasm_put,
        value_attos: 0,
        gas_limit_bgu: 150_000,
        is_static: false,
    })
    .expect("json");
    let cpi_rec = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                UelTx {
                    tx_hash: [0x66; 32],
                    sender: alice,
                    nonce: 6,
                    ee: EeId::WASM,
                    action: UelAction::Call {
                        target: wasm_contract.clone(),
                        input: auth_msg,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 150_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed),
                UelTx {
                    tx_hash: [0x67; 32],
                    sender: alice,
                    nonce: 7,
                    ee: EeId::SVM,
                    action: UelAction::Call {
                        target: svm_universal_program_id().to_vec(),
                        input: cpi_ix,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 300_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed),
            ],
        )
        .expect("svm universal cpi");
    assert_eq!(cpi_rec[0].status, UelReceiptStatus::Success);
    assert_eq!(cpi_rec[1].status, UelReceiptStatus::Success);

    let mut store_k = wasm_contract;
    store_k.extend_from_slice(b":kv:from_svm");
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &store_k)
            .expect("r"),
        Some(b"ok".to_vec())
    );
}

#[test]
fn move_sequential_randomness_staking_refusal_and_universal_call() {
    // Block-STM parallel execution must be refused.
    assert!(MoveEe::with_config(MoveRuntimeConfig {
        block_stm_parallel: true,
        max_value_nest_depth: 128,
    })
    .is_err());

    let (alice_seed, alice) = super::test_uel_signer(0x81);
    let proposer = Address::from([0x82; 32]);
    let mut state = funded(&[alice, proposer]);
    let mut coord = ExecutionCoordinator::new();

    // 1. Deploy valid Move binary module (`0xa11ceb0b` magic).
    let mut module_bytes = MOVE_BINARY_MAGIC.to_vec();
    module_bytes.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x70; 32],
                sender: alice,
                nonce: 0,
                ee: EeId::MOVE,
                action: UelAction::Deploy {
                    code: module_bytes,
                    salt: [0x55; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
                auth: super::UelTxAuth::default(),
            }
            .signed(sample_ctx().chain_id, &alice_seed)],
        )
        .expect("deploy move module");
    assert_eq!(dep[0].status, UelReceiptStatus::Success);

    // 2. Staking & Governance modules (`0x1::stake`, `0x1::aptos_governance`) are refused.
    for (i, mod_id) in ["0x1::stake", "0x1::aptos_governance"].iter().enumerate() {
        let payload = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
            module_id: String::from(*mod_id),
            function_name: String::from("initialize"),
            args: Vec::new(),
        })
        .expect("json");
        let rec = state
            .execute_uel_block(
                &mut coord,
                sample_ctx(),
                proposer,
                &[UelTx {
                    tx_hash: [0x71 + i as u8; 32],
                    sender: alice,
                    nonce: 1 + i as u64,
                    ee: EeId::MOVE,
                    action: UelAction::Call {
                        target: vec![0x01; 32],
                        input: payload,
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 100,
                    auth: super::UelTxAuth::default(),
                }
                .signed(sample_ctx().chain_id, &alice_seed)],
            )
            .expect("call forbidden move module");
        assert_eq!(rec[0].status, UelReceiptStatus::Revert);
    }

    // 3. `0x1::randomness` binds deterministically to `BlockContext.randao`.
    let rand_call = serde_json::to_vec(&MoveCallEnvelope::EntryFunction {
        module_id: String::from("0x1::randomness"),
        function_name: String::from("u256_integer"),
        args: Vec::new(),
    })
    .expect("json");
    let r1 = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x73; 32],
                sender: alice,
                nonce: 3,
                ee: EeId::MOVE,
                action: UelAction::Call {
                    target: vec![0x01; 32],
                    input: rand_call,
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
                auth: super::UelTxAuth::default(),
            }
            .signed(sample_ctx().chain_id, &alice_seed)],
        )
        .expect("randomness");
    assert_eq!(r1[0].status, UelReceiptStatus::Success);
    assert_eq!(r1[0].output.len(), 32);

    // 4. `0x1::budlum_universal::call` invokes WASM contract atomically!
    let cw_wasm = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[0x01]);
    let wdep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x74; 32],
                sender: alice,
                nonce: 4,
                ee: EeId::WASM,
                action: UelAction::Deploy {
                    code: cw_wasm,
                    salt: [0x66; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
                auth: super::UelTxAuth::default(),
            }
            .signed(sample_ctx().chain_id, &alice_seed)],
        )
        .expect("deploy wasm");
    let wasm_target = wdep[0].output.clone();

    let put_msg = serde_json::to_vec(&serde_json::json!({
        "execute": { "put": { "key": "from_move", "value": "aptos_ok" } }
    }))
    .expect("json");
    let ucall_env = serde_json::to_vec(&MoveCallEnvelope::BudlumUniversalCall {
        target_ee: EeId::WASM.0,
        target: wasm_target.clone(),
        input: put_msg,
        value_octas: 0,
        gas_bgu: 150_000,
        is_static: false,
    })
    .expect("json");
    let r_ucall = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[UelTx {
                tx_hash: [0x75; 32],
                sender: alice,
                nonce: 5,
                ee: EeId::MOVE,
                action: UelAction::Call {
                    target: vec![0x01; 32],
                    input: ucall_env,
                },
                value_attos: 0,
                gas_limit_bgu: 300_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
                auth: super::UelTxAuth::default(),
            }
            .signed(sample_ctx().chain_id, &alice_seed)],
        )
        .expect("move universal call");
    assert_eq!(r_ucall[0].status, UelReceiptStatus::Success);

    let mut store_k = wasm_target;
    store_k.extend_from_slice(b":kv:from_move");
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &store_k)
            .expect("r"),
        Some(b"aptos_ok".to_vec())
    );
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The same two vectors are pinned in the SVM worker: the home environment and the worker derive
/// one mint address for one `(caller, seed)` pair.
#[test]
fn the_spl_mint_address_matches_the_known_answers() {
    let caller = [0x11u8; 32];
    assert_eq!(
        derive_spl_mint_address(&caller, &[0x22; 32]).map(|a| hex32(&a)),
        Some(String::from(
            "1ae021a316289bcb841cd784d3ca1c8a7085beb18c93bca77ef7b3f79979d816"
        ))
    );
    // The first candidate for this seed is a curve point, so the search takes its retry path.
    assert_eq!(
        derive_spl_mint_address(&caller, &[0x25; 32]).map(|a| hex32(&a)),
        Some(String::from(
            "d316db7a76988d0f340d9014b3d0c9448e2240b9dcb7446ffc231081f7029217"
        ))
    );
    // The address belongs to the caller: the same seed names another mint for another caller.
    assert_ne!(
        derive_spl_mint_address(&[0x33; 32], &[0x22; 32]),
        derive_spl_mint_address(&caller, &[0x22; 32])
    );
}

/// A mint address is a global identity. An account used to be able to take any unclaimed address
/// first, block the real issuer for good and record a third party as an issuer.
#[test]
fn an_svm_mint_belongs_to_the_account_that_initializes_it() {
    let (alice_seed, alice) = super::test_uel_signer(0x71);
    let (mallory_seed, mallory) = super::test_uel_signer(0x74);
    let proposer = Address::from([0x73; 32]);
    let mut state = funded(&[alice, mallory, proposer]);
    let mut coord = ExecutionCoordinator::new();
    let (alice_svm, _) = derive_svm_alias(&alice).expect("alice svm alias");
    let (mallory_svm, _) = derive_svm_alias(&mallory).expect("mallory svm alias");
    let seed = [0x22u8; 32];
    let init = |seed: [u8; 32], authority: [u8; 32]| {
        serde_json::to_vec(&SvmInstructionEnvelope::SplInitializeMint {
            mint_seed: seed,
            decimals: 6,
            mint_authority: authority,
            is_token_2022: false,
        })
        .expect("json")
    };
    let tx = |hash: u8, sender: Address, signer_seed: &[u8; 32], nonce: u64, input: Vec<u8>| {
        UelTx {
            tx_hash: [hash; 32],
            sender,
            nonce,
            ee: EeId::SVM,
            action: UelAction::Call {
                target: SVM_SPL_TOKEN_PROGRAM_ID.to_vec(),
                input,
            },
            value_attos: 0,
            gas_limit_bgu: 200_000,
            max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
            max_priority_fee_per_bgu_attos: 100,
            auth: super::UelTxAuth::default(),
        }
        .signed(sample_ctx().chain_id, signer_seed)
    };

    // Mallory goes first with the seed Alice is about to use, and names Alice as an issuer.
    let recs = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[
                tx(0x81, mallory, &mallory_seed, 0, init(seed, mallory_svm)),
                tx(0x82, mallory, &mallory_seed, 1, init([0x23; 32], alice_svm)),
                tx(0x83, alice, &alice_seed, 0, init(seed, alice_svm)),
            ],
        )
        .expect("mint block");
    assert_eq!(recs[0].status, UelReceiptStatus::Success, "her own mint");
    assert_eq!(
        recs[1].status,
        UelReceiptStatus::Revert,
        "she cannot record Alice as the issuer of a mint Alice never asked for"
    );
    assert_eq!(
        recs[2].status,
        UelReceiptStatus::Success,
        "Alice is not blocked by Mallory taking the same seed"
    );
    assert_ne!(recs[0].output, recs[2].output);
    assert_eq!(
        Some(recs[2].output.clone()),
        derive_spl_mint_address(&alice_svm, &seed).map(|a| a.to_vec())
    );
    assert_eq!(
        Some(recs[0].output.clone()),
        derive_spl_mint_address(&mallory_svm, &seed).map(|a| a.to_vec())
    );

    // The same caller and seed name the same mint, so a second initialization is refused.
    let again = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(),
            proposer,
            &[tx(0x84, alice, &alice_seed, 1, init(seed, alice_svm))],
        )
        .expect("second block");
    assert_eq!(again[0].status, UelReceiptStatus::Revert);
}
