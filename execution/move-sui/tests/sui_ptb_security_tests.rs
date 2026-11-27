//! Security regression tests for `budlum-ee-move-sui`:
//! 1. `TransferObjects` refuses zero recipient (`[0u8; 32]`) and duplicate object IDs.
//! 2. `MoveCall` refuses duplicate `shared_inputs` and enforces the batch size cap.

use budlum_ee_move_sui::{
    MoveSuiWorker, SuiCompiledModule, SuiPtb, SuiPtbCommand, BUDLUM_TESTNET_CHAIN_ID,
};
use budlum_uel_abi::mock::MemoryHost;
use budlum_uel_abi::{
    BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, ExecutionEnvironment,
    OutcomeStatus,
};

fn ctx() -> BlockContext {
    BlockContext {
        chain_id: BUDLUM_TESTNET_CHAIN_ID,
        height: 10,
        timestamp_ms: 1_700_000_000_000,
    }
}

#[test]
fn sui_transfer_objects_refuses_zero_recipient_and_duplicate_ids_and_move_call_refuses_dup_shared()
{
    let mut worker = MoveSuiWorker::with_activation_height(Some(0));
    let mut host = MemoryHost::new(5_000_000);
    let sender = EeIdentity {
        ee: EeId::MOVE_SUI,
        id: vec![0xAA; 32],
    };
    host.balances
        .insert(sender.clone(), 10_000_000_000_000_000_000);

    // Publish package + mint an initial coin object.
    let pub_ptb = SuiPtb {
        commands: vec![SuiPtbCommand::PublishPackage {
            modules: vec![SuiCompiledModule {
                name: "vault".into(),
                bytecode: vec![0xa1, 0x1c, 0xeb, 0x0b],
                exported_functions: vec!["append".into()],
            }],
            initial_coin_mist: 500,
        }],
    };
    let Ok(pub_input) = serde_json::to_vec(&pub_ptb) else {
        panic!("ser");
    };
    let call_pub = EeCall {
        kind: EeCallKind::Call,
        caller: sender.clone(),
        target: EeIdentity {
            ee: EeId::MOVE_SUI,
            id: vec![0x00; 32],
        },
        value: BudAmount(0),
        input: pub_input,
        gas_limit: 2_000_000,
        depth: 0,
        tx_hash: [0x11; 32],
    };
    let Ok(dep) = worker.execute(&ctx(), &call_pub, &mut host) else {
        panic!("pub");
    };
    assert_eq!(dep.status, OutcomeStatus::Success);
    let Ok(created): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&dep.output) else {
        panic!("parse created ids");
    };
    let pkg_id = created[0];
    let coin_id = created[1];

    // 1. TransferObjects to zero address must revert (prevent burning owned objects).
    let zero_xfer = SuiPtb {
        commands: vec![SuiPtbCommand::TransferObjects {
            object_ids: vec![coin_id],
            recipient: [0u8; 32],
        }],
    };
    let Ok(zero_in) = serde_json::to_vec(&zero_xfer) else {
        panic!("ser");
    };
    let Ok(res_zero) = worker.execute(
        &ctx(),
        &EeCall {
            input: zero_in,
            tx_hash: [0x12; 32],
            ..call_pub.clone()
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(
        res_zero.status,
        OutcomeStatus::Revert,
        "TransferObjects to zero recipient must revert"
    );

    // 2. Duplicate object_id inside TransferObjects (even on self-transfer) must revert.
    let dup_xfer = SuiPtb {
        commands: vec![SuiPtbCommand::TransferObjects {
            object_ids: vec![coin_id, coin_id],
            recipient: [0xAA; 32],
        }],
    };
    let Ok(dup_in) = serde_json::to_vec(&dup_xfer) else {
        panic!("ser");
    };
    let Ok(res_dup) = worker.execute(
        &ctx(),
        &EeCall {
            input: dup_in,
            tx_hash: [0x13; 32],
            ..call_pub.clone()
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(
        res_dup.status,
        OutcomeStatus::Revert,
        "duplicate object_id in TransferObjects must revert"
    );

    // 3. Create a package-owned object via MoveCall, then pass it TWICE in shared_inputs -> MUST revert.
    let mk_obj = SuiPtb {
        commands: vec![SuiPtbCommand::MoveCall {
            package_id: pkg_id,
            module: "vault".into(),
            function: "append".into(),
            shared_inputs: vec![],
            arg_bytes: b"init".to_vec(),
        }],
    };
    let Ok(mk_in) = serde_json::to_vec(&mk_obj) else {
        panic!("ser");
    };
    let Ok(mk_out) = worker.execute(
        &ctx(),
        &EeCall {
            input: mk_in,
            tx_hash: [0x14; 32],
            ..call_pub.clone()
        },
        &mut host,
    ) else {
        panic!("mk");
    };
    assert_eq!(mk_out.status, OutcomeStatus::Success);
    let Ok(mk_ids): Result<Vec<[u8; 32]>, _> = serde_json::from_slice(&mk_out.output) else {
        panic!("parse");
    };
    let shared_obj = mk_ids[0];

    let dup_shared = SuiPtb {
        commands: vec![SuiPtbCommand::MoveCall {
            package_id: pkg_id,
            module: "vault".into(),
            function: "append".into(),
            shared_inputs: vec![shared_obj, shared_obj],
            arg_bytes: b"x".to_vec(),
        }],
    };
    let Ok(dup_sh_in) = serde_json::to_vec(&dup_shared) else {
        panic!("ser");
    };
    let Ok(res_dup_sh) = worker.execute(
        &ctx(),
        &EeCall {
            input: dup_sh_in,
            tx_hash: [0x15; 32],
            ..call_pub
        },
        &mut host,
    ) else {
        panic!("exec");
    };
    assert_eq!(
        res_dup_sh.status,
        OutcomeStatus::Revert,
        "duplicate shared_inputs in MoveCall must revert"
    );
}
