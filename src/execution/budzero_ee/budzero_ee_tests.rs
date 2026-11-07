use super::{
    decode_budzero_for_testnet, evaluate_optional_proof_job, evaluate_preprocessed_setup,
    BudZeroVmContext, MAX_SETUP_PREPROCESSED_BYTES,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use crate::execution::coordinator::state::{
    uel_proof_matches_root, ExecutionState, NS_BUDZERO_STORAGE, NS_EVM_STORAGE,
};
use crate::execution::coordinator::{
    ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
};
use crate::execution::proof_verifier::MAX_DEGREE_BITS;
use crate::execution::zkvm::{DEFAULT_CONTRACT_GAS_LIMIT, ZkVmExecutor};
use bud_isa::{Instruction, Opcode};
use budlum_uel_abi::{BlockContext, BudAmount, EeId};

fn encode_program(insts: &[Instruction]) -> Vec<u8> {
    insts
        .iter()
        .flat_map(|i| i.encode().to_le_bytes())
        .collect()
}

fn sample_ctx(height: u64) -> BlockContext {
    BlockContext {
        height,
        timestamp_ms: 1_700_000_000_000 + height * 3_000,
        chain_id: 45_261,
        randao: [0x77; 32],
        base_fee: BudAmount(MIN_UEL_BASE_FEE_ATTOS),
    }
}

#[test]
fn verify_merkle_is_closed_on_testnet() {
    let bytecode = encode_program(&[
        Instruction {
            opcode: Opcode::VerifyMerkle,
            rd: 0,
            rs1: 1,
            rs2: 2,
            imm: 0,
        },
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        },
    ]);
    assert!(
        decode_budzero_for_testnet(&bytecode).is_err(),
        "VerifyMerkle must be refused at BudZero EE deploy validation on testnet"
    );
    assert!(
        ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT).is_err(),
        "VerifyMerkle must be refused at BudZero VM execution on testnet"
    );
}

#[test]
fn verify_inference_is_closed_on_testnet() {
    let bytecode = encode_program(&[
        Instruction {
            opcode: Opcode::VerifyInference,
            rd: 0,
            rs1: 1,
            rs2: 2,
            imm: 3,
        },
        Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        },
    ]);
    assert!(
        decode_budzero_for_testnet(&bytecode).is_err(),
        "VerifyInference must be refused at BudZero EE deploy validation on testnet"
    );
    assert!(
        ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT).is_err(),
        "VerifyInference must be refused at BudZero VM execution on testnet"
    );
}

#[test]
fn budzero_sender_is_four_words() {
    // Two addresses identical in their low 8 bytes (`[0..8]`) and differing only
    // in the upper 192 bits (`[8..32]`) MUST produce distinct 4-word VM contexts ().
    let mut raw_a = [0x11u8; 32];
    let mut raw_b = [0x11u8; 32];
    raw_a[31] = 0xAA;
    raw_b[31] = 0xBB;
    let addr_a = Address::from(raw_a);
    let addr_b = Address::from(raw_b);

    let ctx_a = BudZeroVmContext::from_sender(&addr_a, 7, 100);
    let ctx_b = BudZeroVmContext::from_sender(&addr_b, 7, 100);
    assert_eq!(ctx_a.sender_words.len(), 4);
    assert_eq!(ctx_a.sender_words[0], ctx_b.sender_words[0]);
    assert_ne!(
        ctx_a.sender_words, ctx_b.sender_words,
        "4-word 256-bit sender context must preserve upper 192 bits ()"
    );
    assert_eq!(ctx_a.sender_address(), addr_a);
    assert_eq!(ctx_b.sender_address(), addr_b);
}

#[test]
fn budzero_ee_stateful_program_persists() {
    let sender = Address::from([0x91; 32]);
    let proposer = Address::from([0x92; 32]);
    let mut state = AccountState::new();
    state.credit_account(&sender, 20_000);
    state.credit_account(&proposer, 20_000);
    let mut coord = ExecutionCoordinator::new();

    let halt_prog = encode_program(&[Instruction {
        opcode: Opcode::Halt,
        rd: 0,
        rs1: 0,
        rs2: 0,
        imm: 0,
    }]);

    // Block 1: deploy BudZero program.
    let dep = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(1),
            proposer,
            &[UelTx {
                tx_hash: [0x81; 32],
                sender,
                nonce: 0,
                ee: EeId::BUDZERO,
                action: UelAction::Deploy {
                    code: halt_prog,
                    salt: [0x12; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("deploy budzero");
    assert_eq!(dep[0].status, UelReceiptStatus::Success);
    let contract_id = dep[0].output.clone();

    // Block 2: write persistent 32-byte slot (`[0xAB; 32] -> b"persisted"`).
    let slot32 = [0xABu8; 32];
    let mut put_input = slot32.to_vec();
    put_input.extend_from_slice(b"persisted");
    let put_rec = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(2),
            proposer,
            &[UelTx {
                tx_hash: [0x82; 32],
                sender,
                nonce: 1,
                ee: EeId::BUDZERO,
                action: UelAction::Call {
                    target: contract_id.clone(),
                    input: put_input,
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("put budzero");
    assert_eq!(put_rec[0].status, UelReceiptStatus::Success);

    // Block 3: call deployed program again and verify slot persists across blocks.
    let call_rec = state
        .execute_uel_block(
            &mut coord,
            sample_ctx(3),
            proposer,
            &[UelTx {
                tx_hash: [0x83; 32],
                sender,
                nonce: 2,
                ee: EeId::BUDZERO,
                action: UelAction::Call {
                    target: contract_id.clone(),
                    input: Vec::new(),
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 100,
            }],
        )
        .expect("call budzero");
    assert_eq!(call_rec[0].status, UelReceiptStatus::Success);

    let mut storage_key = contract_id;
    storage_key.extend_from_slice(&slot32);
    assert_eq!(
        state
            .execution_state
            .read(NS_BUDZERO_STORAGE, &storage_key)
            .expect("read"),
        Some(b"persisted".to_vec())
    );
}

#[test]
fn verifier_dos_bounds_and_optional_proof_market() {
    assert!(evaluate_preprocessed_setup(0, 64, 500_000).is_err());
    assert!(evaluate_preprocessed_setup(MAX_DEGREE_BITS + 1, 64, 500_000).is_err());
    assert!(
        evaluate_preprocessed_setup(16, MAX_SETUP_PREPROCESSED_BYTES + 1, 50_000_000).is_err()
    );
    assert!(evaluate_preprocessed_setup(16, 4_096, 1_000).is_err());

    let receipt =
        evaluate_optional_proof_job([0x55; 32], 14, 1_024, 500_000).expect("valid proof job");
    assert!(!receipt.alters_consensus_state);
    assert!(receipt.setup_gas > 0);
}

#[test]
fn uel_execution_proof_verifies_inclusion_and_absence() {
    let mut exec = ExecutionState::new();
    exec.write(NS_EVM_STORAGE, b"slot-a", Some(b"val-a"))
        .expect("w1");
    exec.write(NS_EVM_STORAGE, b"slot-b", Some(b"val-b"))
        .expect("w2");
    exec.write(NS_BUDZERO_STORAGE, b"bz-k", Some(b"bz-v"))
        .expect("w3");

    let root = exec.execution_root();

    // 1. Inclusion proof for `(NS_EVM_STORAGE, "slot-a")`.
    let inc = exec
        .build_execution_proof(NS_EVM_STORAGE, b"slot-a")
        .expect("proof");
    assert_eq!(inc.value.as_deref(), Some(b"val-a".as_slice()));
    assert!(uel_proof_matches_root(&inc, &root));

    // Tampering with value must fail verification!
    let mut forged = inc.clone();
    forged.value = Some(b"forged".to_vec());
    assert!(!uel_proof_matches_root(&forged, &root));

    // 2. Non-inclusion proof for an absent key `(NS_EVM_STORAGE, "missing")`.
    let abs = exec
        .build_execution_proof(NS_EVM_STORAGE, b"missing")
        .expect("absence proof");
    assert_eq!(abs.value, None);
    assert!(uel_proof_matches_root(&abs, &root));
}
