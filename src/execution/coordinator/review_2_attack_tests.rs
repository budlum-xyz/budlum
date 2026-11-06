use crate::core::account::{AccountState, ATTOS_PER_ATOM};
use crate::core::address::Address;
use crate::execution::coordinator::alias::{
    derive_evm_alias, derive_foreign_account, derive_foreign_cosmos_bech32, derive_svm_alias,
    ForeignScheme,
};
use crate::execution::coordinator::assets::{
    deploy_asset_pointer, register_asset_entry, AssetStandard,
};
use crate::execution::coordinator::foreign::aptos::{
    sign_aptos_ed25519_tx, AptosPayloadKind, BUDLUM_APTOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::cosmos::{
    sign_cosmos_tx_direct, BUDLUM_COSMOS_CHAIN_ID,
};
use crate::execution::coordinator::foreign::ethereum::{
    evm_address_from_secret_key, sign_eip1559_tx, BUDLUM_EVM_CHAIN_ID,
};
use crate::execution::coordinator::foreign::solana::{
    sign_solana_tx, SolanaCompiledInstruction, SolanaEnvelopeError, MAX_SOLANA_BLOCKHASH_WINDOW,
};
use crate::execution::coordinator::foreign::{
    adopt_signing_digest, AdoptForeignAccountTx, ClassicalAdoptProof, ForeignAdmissionError,
    ForeignTx, QuantumAlertLevel,
};
use crate::execution::coordinator::gas::{BlockBguMeter, MIN_UEL_BASE_FEE_ATTOS, SOFT_EE_BGU_CAP};
use crate::execution::coordinator::move_ee::MOVE_BINARY_MAGIC;
use crate::execution::coordinator::svm_ee::{SvmInstructionEnvelope, SVM_MEMO_PROGRAM_ID};
use crate::execution::coordinator::universal_call::{
    decode_precompile_calldata, encode_precompile_call, wrap_static_universal_input,
};
use crate::execution::coordinator::wasm_ee::build_valid_cosmwasm_module;
use crate::execution::coordinator::worker::WorkerEndpoint;
use crate::execution::coordinator::{
    ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
};
use crate::rpc::compat::{
    aptos::handle_aptos_rest, cosmos::handle_cosmos_rest, ethereum::handle_eth_jsonrpc,
    solana::handle_solana_jsonrpc,
};
use bud_isa::{encode_program, Instruction as BudInsn, Reg as BudReg};
use budlum_uel_abi::{
    BlockContext, EeCall, EeFault, EeId, ExecutionEnvironment, HostApi, OutcomeStatus,
    RefusalCode,
};
use k256::ecdsa::SigningKey as SecpSigningKey;

fn test_block_ctx(height: u64) -> BlockContext {
    BlockContext {
        height,
        timestamp_ms: 1_762_000_000_000 + height * 2_000,
        chain_id: BUDLUM_EVM_CHAIN_ID,
        prev_randao: [0x5Au8; 32],
        base_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS,
    }
}

fn total_supply_invariant_attos(state: &AccountState) -> u128 {
    state
        .total_bud_committed_attos()
        .saturating_add(u128::from(state.burned_total) * u128::from(ATTOS_PER_ATOM))
}

#[test]
fn review_2_refused_foreign_txs_never_mutate_state_blg_277() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let pq_dst = Address::from([0x44u8; 32]);
    let pq_evm = derive_evm_alias(&pq_dst);
    let now_secs = 1_762_000_000u64;

    let lane_before = state.execution_state.foreign_lane.clone();
    let root_before = state.execution_state.execution_root();

    // 1. Brand-new Ethereum sender with wrong initial nonce (7 != 0) is refused
    //    without inserting a phantom ForeignAccountRecord.
    let eth_sk = [0x11u8; 32];
    let bad_nonce_rlp = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        7,
        1_000,
        2_000,
        21_000,
        Some([0xAB; 20]),
        0,
        &[],
        &[],
    )
    .expect("sign eth wrong nonce");
    let err1 = coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: bad_nonce_rlp,
                direct_native_pq_recipient: None,
            },
            now_secs,
        )
        .expect_err("wrong initial nonce must fail");
    assert_eq!(
        err1,
        ForeignAdmissionError::NonceMismatch {
            expected: 0,
            got: 7
        }
    );
    assert_eq!(state.execution_state.foreign_lane, lane_before);

    // 2. Unfunded foreign sender attempting value transfer to PQ alias fails
    //    without bumping nonce or inserting an account record.
    let unfunded_rlp = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some(pq_evm),
        5 * u128::from(ATTOS_PER_ATOM),
        &[],
        &[],
    )
    .expect("sign unfunded transfer");
    assert!(coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: unfunded_rlp,
                direct_native_pq_recipient: Some(pq_dst),
            },
            now_secs,
        )
        .is_err());
    assert_eq!(state.execution_state.foreign_lane, lane_before);

    // 3. Brand-new Cosmos sender with wrong account_number (9 != 0) fails without
    //    bumping next_cosmos_account_number.
    let cosmos_sk = [0x22u8; 32];
    let bad_cosmos = sign_cosmos_tx_direct(
        &cosmos_sk,
        BUDLUM_COSMOS_CHAIN_ID,
        9,
        0,
        150_000,
        500,
        vec![(
            String::from("/cosmos.bank.v1beta1.MsgSend"),
            b"msg".to_vec(),
        )],
    )
    .expect("sign cosmos wrong account_number");
    let err3 = coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Cosmos {
                tx_raw_bytes: bad_cosmos,
                chain_id: String::from(BUDLUM_COSMOS_CHAIN_ID),
                account_number: 9,
                direct_native_pq_recipient: None,
            },
            now_secs,
        )
        .expect_err("wrong cosmos account_number must fail");
    assert_eq!(
        err3,
        ForeignAdmissionError::AccountNumberMismatch {
            expected: 0,
            got: 9
        }
    );
    assert_eq!(state.execution_state.foreign_lane, lane_before);
    assert_eq!(state.execution_state.execution_root(), root_before);
}

#[test]
fn review_2_quantum_alert_level2_spoofed_recipient_refused_blg_278() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let now_secs = 1_762_000_000u64;

    let pq_addr = Address::from([0x55u8; 32]);
    let pq_evm = derive_evm_alias(&pq_addr);
    let eth_sk = [0x33u8; 32];
    let eth_addr = evm_address_from_secret_key(&eth_sk).expect("evm addr");
    let eth_bud = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &eth_addr);

    let faucet = Address::from([0xFAu8; 32]);
    state.credit_account(&faucet, 50);
    state
        .transfer_attos_in_unit(
            &faucet,
            &eth_bud,
            10 * u128::from(ATTOS_PER_ATOM),
            crate::core::account::BudEnvUnit::EvmWei,
        )
        .expect("fund foreign account");

    // Register a second classical account to try classical-to-classical spoofing.
    let other_sk = [0x34u8; 32];
    let other_rlp = sign_eip1559_tx(
        &other_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some([0x01; 20]),
        0,
        &[],
        &[],
    )
    .expect("sign other");
    coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: other_rlp,
                direct_native_pq_recipient: None,
            },
            now_secs,
        )
        .expect("admit second classical account under Level 0");
    let other_addr = evm_address_from_secret_key(&other_sk).expect("other evm");
    let other_classical_bud =
        derive_foreign_account(ForeignScheme::EthereumSecp256k1, &other_addr);

    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level2Restricted;

    // Attack A: signed `to` is [0x99; 20], outer metadata claims `Some(pq_addr)`.
    let spoof_to = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some([0x99; 20]),
        u128::from(ATTOS_PER_ATOM),
        &[],
        &[],
    )
    .expect("sign spoof_to");
    assert!(matches!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: spoof_to,
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::InvalidDirectPqRecipient(_))
    ));

    // Attack B: signed `to` matches pq_evm, but non-empty calldata tries contract execution.
    let spoof_calldata = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        50_000,
        Some(pq_evm),
        0,
        &[0xca, 0xfe],
        &[],
    )
    .expect("sign spoof_calldata");
    assert!(matches!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: spoof_calldata,
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::InvalidDirectPqRecipient(_))
    ));

    // Attack C: target is another Classical account masquerading as PQ target.
    let spoof_classical = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some(derive_evm_alias(&other_classical_bud)),
        u128::from(ATTOS_PER_ATOM),
        &[],
        &[],
    )
    .expect("sign spoof_classical");
    assert!(matches!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: spoof_classical,
                direct_native_pq_recipient: Some(other_classical_bud),
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::InvalidDirectPqRecipient(_))
    ));

    // Legitimate empty-calldata transfer to `pq_evm` succeeds under Level 2.
    let valid_lvl2 = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some(pq_evm),
        2 * u128::from(ATTOS_PER_ATOM),
        &[],
        &[],
    )
    .expect("sign valid lvl2");
    coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: valid_lvl2,
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        )
        .expect("legitimate Level 2 transfer to PQ native account must succeed");
    assert_eq!(
        state.get_attos_balance(&pq_addr),
        2 * u128::from(ATTOS_PER_ATOM)
    );
}

#[test]
fn review_2_cross_ee_alias_collision_and_bounded_solana_window_blg_279() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let native_owner = Address::from([0x66u8; 32]);

    for ee in [EeId::EVM, EeId::WASM, EeId::SVM, EeId::MOVE] {
        let alias = state
            .execution_state
            .ensure_alias_registered(&native_owner, ee)
            .expect("register alias");
        assert!(state
            .execution_state
            .has_registered_alias_collision(ee, &alias));
        assert!(!state
            .execution_state
            .has_registered_alias_collision(ee, &[0xFFu8; 20]));
    }

    // Inject synthetic Cosmos bech32 alias collision and verify foreign Cosmos refuses it.
    let cosmos_sk = [0x41u8; 32];
    let vk = SecpSigningKey::from_bytes((&cosmos_sk).into())
        .expect("secp")
        .verifying_key()
        .to_encoded_point(true);
    let pk33: [u8; 33] = vk.as_bytes().try_into().expect("33");
    let addr20 =
        crate::execution::coordinator::foreign::cosmos::cosmos_addr20_from_compressed_pubkey(&pk33);
    let colliding_bech32 = derive_foreign_cosmos_bech32(&addr20);
    let alias_key = crate::execution::coordinator::alias::alias_storage_key(
        &Address::from([0x77u8; 32]),
        EeId::WASM,
    );
    state
        .execution_state
        .write(
            crate::execution::coordinator::alias::ALIAS_NAMESPACE,
            &alias_key,
            Some(colliding_bech32.as_bytes()),
        )
        .expect("seed colliding wasm alias");
    let cosmos_raw = sign_cosmos_tx_direct(
        &cosmos_sk,
        BUDLUM_COSMOS_CHAIN_ID,
        0,
        0,
        120_000,
        200,
        vec![(String::from("/cosmos.bank.v1beta1.MsgSend"), b"x".to_vec())],
    )
    .expect("sign cosmos");
    assert_eq!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Cosmos {
                tx_raw_bytes: cosmos_raw,
                chain_id: String::from(BUDLUM_COSMOS_CHAIN_ID),
                account_number: 0,
                direct_native_pq_recipient: None,
            },
            1_762_000_000,
        ),
        Err(ForeignAdmissionError::AliasCollision)
    );

    // Bounded Solana signature eviction across 150-blockhash window (R-12).
    let bh0 = [0xA0u8; 32];
    state.execution_state.foreign_lane.record_blockhash(bh0);
    let sol_seed = [0x51u8; 32];
    let sol_pk = ed25519_dalek::SigningKey::from_bytes(&sol_seed)
        .verifying_key()
        .to_bytes();
    let sol_raw = sign_solana_tx(
        &sol_seed,
        false,
        vec![sol_pk, SVM_MEMO_PROGRAM_ID],
        bh0,
        vec![SolanaCompiledInstruction {
            program_id_index: 1,
            accounts: vec![0],
            data: b"memo".to_vec(),
        }],
        Vec::new(),
    );
    coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Solana {
                raw_wire: sol_raw.clone(),
                direct_native_pq_recipient: None,
            },
            1_762_000_000,
        )
        .expect("admit solana tx");
    assert_eq!(
        state
            .execution_state
            .foreign_lane
            .seen_solana_signatures
            .len(),
        1
    );

    for step in 1..=MAX_SOLANA_BLOCKHASH_WINDOW {
        let mut bh = [0u8; 32];
        bh[0] = (step & 0xFF) as u8;
        bh[1] = 1;
        state.execution_state.foreign_lane.record_blockhash(bh);
    }
    assert!(
        state
            .execution_state
            .foreign_lane
            .seen_solana_signatures
            .is_empty(),
        "expired blockhash signatures must be evicted to bound memory (BLG-279 / R-12)"
    );
    assert_eq!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Solana {
                raw_wire: sol_raw,
                direct_native_pq_recipient: None,
            },
            1_762_000_000,
        ),
        Err(ForeignAdmissionError::Solana(
            SolanaEnvelopeError::UnknownOrExpiredBlockhash
        ))
    );
}

#[test]
fn review_2_static_prefix_spoofing_refused_blg_280() {
    let forged_input = wrap_static_universal_input(b"spoofed_mutating_payload");
    let calldata = encode_precompile_call(
        EeId::WASM,
        b"bud1target",
        &forged_input,
        1_000,
        100_000,
    );
    let err = decode_precompile_calldata(&calldata)
        .expect_err("non-static 0x...B001 call carrying STATIC_PREFIX must be refused");
    assert!(err.contains("BLG-280"));
}

#[test]
fn review_2_foreign_cross_scheme_signature_and_chain_id_confusion() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let now_secs = 1_762_000_000u64;

    // 1. Aptos wrong chain_id (1 != 205) refused.
    let aptos_seed = [0x61u8; 32];
    let bad_aptos = sign_aptos_ed25519_tx(
        &aptos_seed,
        0,
        1,
        now_secs + 60,
        AptosPayloadKind::EntryFunction,
        b"transfer",
    );
    assert!(coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Aptos {
                raw_bcs: bad_aptos,
                direct_native_pq_recipient: None,
            },
            now_secs,
        )
        .is_err());

    // 2. Adopt cross-scheme proof confusion: Ethereum scheme paired with Solana Ed25519 proof.
    let pq_seed = [0x62u8; 32];
    let pq_pk = crate::crypto::pq::ml_dsa_public_key(
        crate::crypto::scheme::SchemeId::ML_DSA_87,
        &pq_seed,
    )
    .expect("ml-dsa-87 pk");
    let pq_target =
        crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(&pq_pk)
            .expect("pq addr");
    let eth_local = [0xAAu8; 20];
    let digest = adopt_signing_digest(
        ForeignScheme::EthereumSecp256k1,
        &eth_local,
        &pq_target,
        BUDLUM_EVM_CHAIN_ID,
    );
    let pq_sig = crate::crypto::pq::ml_dsa_sign(
        crate::crypto::scheme::SchemeId::ML_DSA_87,
        &pq_seed,
        &digest,
        b"BDLM_ADOPT_FOREIGN_V1",
        &[0u8; 32],
    )
    .expect("ml-dsa-87 sig");

    let confused_adopt = ForeignTx::Adopt(AdoptForeignAccountTx {
        scheme: ForeignScheme::EthereumSecp256k1,
        local_id: eth_local.to_vec(),
        native_pq_target: pq_target,
        pq_public_key: pq_pk.clone(),
        pq_signature: pq_sig.clone(),
        classical_proof: ClassicalAdoptProof::SolanaEd25519 {
            signature64: vec![0u8; 64],
        },
        chain_id: BUDLUM_EVM_CHAIN_ID,
    });
    assert!(matches!(
        coord.process_foreign_envelope(&mut state, &confused_adopt, now_secs),
        Err(ForeignAdmissionError::InvalidAdoptProof(_))
    ));

    // 3. Adopt wrong chain_id (1 != 45261) refused.
    let wrong_chain_adopt = ForeignTx::Adopt(AdoptForeignAccountTx {
        scheme: ForeignScheme::EthereumSecp256k1,
        local_id: eth_local.to_vec(),
        native_pq_target: pq_target,
        pq_public_key: pq_pk,
        pq_signature: pq_sig,
        classical_proof: ClassicalAdoptProof::EthereumSecp256k1 {
            signature65: vec![0u8; 65],
        },
        chain_id: 1,
    });
    assert_eq!(
        coord.process_foreign_envelope(&mut state, &wrong_chain_adopt, now_secs),
        Err(ForeignAdmissionError::WrongAdoptChainId {
            expected: BUDLUM_EVM_CHAIN_ID,
            got: 1,
        })
    );
}

#[test]
fn review_2_random_cross_ee_bud_conservation_holds() {
    fn run_randomized_workload() -> ([u8; 32], u128) {
        let mut state = AccountState::new();
        let mut coord = ExecutionCoordinator::new();
        let proposer = Address::from([0xFEu8; 32]);
        let users = [
            Address::from([0x01u8; 32]),
            Address::from([0x02u8; 32]),
            Address::from([0x03u8; 32]),
            Address::from([0x04u8; 32]),
        ];
        for u in &users {
            state.credit_account(u, 1_000);
        }
        state.credit_account(&proposer, 100);
        let initial_supply = total_supply_invariant_attos(&state);

        // Deploy one valid contract in each of the 5 EEs.
        // 1. EVM simple storage contract (`PUSH1 0x2a PUSH0 SSTORE STOP`).
        let evm_init = vec![
            0x60, 0x05, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x05, 0x60, 0x00, 0xf3, 0x60, 0x2a,
            0x5f, 0x55, 0x00,
        ];
        let wasm_mod = build_valid_cosmwasm_module(false, 16, &[]);
        let mut move_mod = Vec::from(MOVE_BINARY_MAGIC);
        move_mod.extend_from_slice(b"review2_conservation_mod");
        let bz_prog = encode_program(&[
            BudInsn::AddImm {
                dst: BudReg::R0,
                src: BudReg::R0,
                imm: 1,
            },
            BudInsn::Halt,
        ]);

        let mut nonces = [0u64; 4];
        let deploys = [
            (0usize, EeId::EVM, evm_init, [0xA1u8; 32]),
            (1usize, EeId::WASM, wasm_mod, [0xA2u8; 32]),
            (2usize, EeId::MOVE, move_mod, [0xA3u8; 32]),
            (3usize, EeId::BUDZERO, bz_prog, [0xA4u8; 32]),
        ];
        let mut deployed_targets: Vec<(EeId, Vec<u8>)> = Vec::new();
        for (h, (u_idx, ee, code, salt)) in deploys.into_iter().enumerate() {
            let mut tx_hash = [0u8; 32];
            tx_hash[0] = (h + 1) as u8;
            let recs = state
                .execute_uel_block(
                    &mut coord,
                    test_block_ctx((h + 1) as u64),
                    proposer,
                    &[UelTx {
                        tx_hash,
                        sender: users[u_idx],
                        nonce: nonces[u_idx],
                        ee,
                        action: UelAction::Deploy { code, salt },
                        value_attos: 0,
                        gas_limit_bgu: 400_000,
                        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 4,
                        max_priority_fee_per_bgu_attos: 25,
                    }],
                )
                .expect("deploy block");
            nonces[u_idx] += 1;
            assert_eq!(recs[0].status, UelReceiptStatus::Success);
            assert_eq!(total_supply_invariant_attos(&state), initial_supply);
            deployed_targets.push((ee, recs[0].output.clone()));
        }

        // Verify Y-5 zero-balance pointer invariant alongside randomized cross-EE calls.
        let evm_home = deployed_targets[0].1.clone();
        let asset = register_asset_entry(
            &mut state,
            EeId::EVM,
            &evm_home,
            AssetStandard::Fungible,
            18,
            String::from("RV2"),
            String::from("Review2 Token"),
        )
        .expect("register asset");
        let wasm_ptr =
            deploy_asset_pointer(&mut state, &asset.asset_id, EeId::WASM).expect("wasm ptr");
        let ptr_bud = crate::execution::coordinator::alias::derive_contract_account(
            EeId::WASM,
            &wasm_ptr,
        );
        assert_eq!(state.get_attos_balance(&ptr_bud), 0);

        // Deterministic SplitMix64 PRNG over 48 mixed cross-EE txs (including OOG/reverts).
        let mut rng = 0xB0D1_0048_2026_1106u64;
        let mut next_u64 = || {
            rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };

        for step in 0..48u64 {
            let u_idx = (next_u64() as usize) % users.len();
            let selector = next_u64() % 5;
            let val_attos = (u128::from(next_u64() % 500_000)) * 1_000_000_000u128;
            // Deliberately inject occasional low gas limits to trigger deterministic OOG rollbacks.
            let gas_limit_bgu = if step % 9 == 7 {
                500
            } else {
                250_000
            };

            let (ee, target, input) = match selector {
                0 => (EeId::EVM, deployed_targets[0].1.clone(), Vec::new()),
                1 => (
                    EeId::WASM,
                    deployed_targets[1].1.clone(),
                    br#"{"set":{"key":"k","val":"v"}}"#.to_vec(),
                ),
                2 => {
                    let svm_env = SvmInstructionEnvelope {
                        program_id: SVM_MEMO_PROGRAM_ID,
                        accounts: Vec::new(),
                        data: b"bud-conservation".to_vec(),
                    };
                    (
                        EeId::SVM,
                        SVM_MEMO_PROGRAM_ID.to_vec(),
                        serde_json::to_vec(&svm_env).expect("svm env"),
                    )
                }
                3 => {
                    let mv =
                        crate::execution::coordinator::move_ee::MoveCallEnvelope::WriteResource {
                            resource_tag: String::from("0x1::Vault::State"),
                            payload: vec![step as u8],
                        };
                    (
                        EeId::MOVE,
                        deployed_targets[2].1.clone(),
                        serde_json::to_vec(&mv).expect("move env"),
                    )
                }
                _ => {
                    let mut slot_kv = vec![0u8; 36];
                    slot_kv[0] = (step & 0xFF) as u8;
                    slot_kv[32] = 0xAA;
                    (EeId::BUDZERO, deployed_targets[3].1.clone(), slot_kv)
                }
            };

            let mut tx_hash = [0u8; 32];
            tx_hash[0] = 0x80;
            tx_hash[1..9].copy_from_slice(&step.to_le_bytes());
            let _ = state.execute_uel_block(
                &mut coord,
                test_block_ctx(10 + step),
                proposer,
                &[UelTx {
                    tx_hash,
                    sender: users[u_idx],
                    nonce: nonces[u_idx],
                    ee,
                    action: UelAction::Call { target, input },
                    value_attos: val_attos,
                    gas_limit_bgu,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 8,
                    max_priority_fee_per_bgu_attos: 10,
                }],
            );
            nonces[u_idx] += 1;

            assert_eq!(
                total_supply_invariant_attos(&state),
                initial_supply,
                "BUD supply conservation violated at step {step}"
            );
            assert_eq!(
                state.get_attos_balance(&ptr_bud),
                0,
                "pointer contract must hold zero BUD balance (Y-5)"
            );
        }

        (state.execution_state.execution_root(), initial_supply)
    }

    let (root_a, supply_a) = run_randomized_workload();
    let (root_b, supply_b) = run_randomized_workload();
    assert_eq!(supply_a, supply_b);
    assert_eq!(
        root_a, root_b,
        "identical multi-EE workload must yield identical execution_root (G-2 / R-11)"
    );
}

struct FaultingWorkerEe;

impl ExecutionEnvironment for FaultingWorkerEe {
    fn id(&self) -> EeId {
        EeId::SVM
    }
    fn version(&self) -> u32 {
        1
    }
    fn execute(&mut self, _call: EeCall, _host: &mut dyn HostApi) -> budlum_uel_abi::EeOutcome {
        budlum_uel_abi::EeOutcome {
            status: OutcomeStatus::Fault(EeFault {
                message: String::from("simulated worker crash R-01"),
            }),
            gas_used: 5_000,
            output: Vec::new(),
            logs: Vec::new(),
        }
    }
    fn query(
        &self,
        _q: budlum_uel_abi::EeQuery,
        _h: &dyn budlum_uel_abi::HostRead,
    ) -> Result<Vec<u8>, budlum_uel_abi::EeRefusal> {
        Err(budlum_uel_abi::EeRefusal {
            code: RefusalCode::UnsupportedFeature,
            detail: String::from("faulting worker"),
        })
    }
    fn validate_code(
        &self,
        _code: &[u8],
    ) -> Result<budlum_uel_abi::CodeInfo, budlum_uel_abi::EeRefusal> {
        Err(budlum_uel_abi::EeRefusal {
            code: RefusalCode::InvalidCode,
            detail: String::from("faulting worker"),
        })
    }
}

#[test]
fn review_2_risk_matrix_r01_r08_r18_r21_and_rpc_isolation() {
    let mut state = AccountState::new();
    let sender = Address::from([0x91u8; 32]);
    let proposer = Address::from([0x92u8; 32]);
    state.credit_account(&sender, 500);
    let supply_before = total_supply_invariant_attos(&state);

    // R-01 / Y-6: Worker fault produces deterministic Fault receipt without halting node.
    let mut coord = ExecutionCoordinator::new();
    coord.register_worker(WorkerEndpoint::in_process(|| Box::new(FaultingWorkerEe)));
    let fault_recs = state
        .execute_uel_block(
            &mut coord,
            test_block_ctx(1),
            proposer,
            &[UelTx {
                tx_hash: [0xF1u8; 32],
                sender,
                nonce: 0,
                ee: EeId::SVM,
                action: UelAction::Call {
                    target: vec![0u8; 32],
                    input: vec![1, 2, 3],
                },
                value_attos: 1_000_000,
                gas_limit_bgu: 50_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 0,
            }],
        )
        .expect("faulting EE must not panic coordinator");
    assert!(matches!(
        fault_recs[0].status,
        UelReceiptStatus::Fault { .. }
    ));
    assert_eq!(total_supply_invariant_attos(&state), supply_before);

    // R-18: Per-EE soft BGU cap (`40_000_000 BGU`) refuses single-EE block monopolization.
    let mut meter = BlockBguMeter::new();
    assert!(meter.record_used(EeId::EVM, SOFT_EE_BGU_CAP).is_ok());
    assert!(meter.check_admissible(EeId::EVM, 1).is_err());
    assert!(meter.check_admissible(EeId::WASM, 10_000_000).is_ok());

    // R-21: Freezing deployments on one EE refuses new deploys while other EEs still deploy.
    let mut normal_coord = ExecutionCoordinator::new();
    state.execution_state.set_deploy_enabled(EeId::MOVE, false);
    let mut move_code = Vec::from(MOVE_BINARY_MAGIC);
    move_code.extend_from_slice(b"frozen_mod");
    let frozen_rec = state
        .execute_uel_block(
            &mut normal_coord,
            test_block_ctx(2),
            proposer,
            &[UelTx {
                tx_hash: [0xF2u8; 32],
                sender,
                nonce: 1,
                ee: EeId::MOVE,
                action: UelAction::Deploy {
                    code: move_code,
                    salt: [0x01u8; 32],
                },
                value_attos: 0,
                gas_limit_bgu: 200_000,
                max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                max_priority_fee_per_bgu_attos: 0,
            }],
        )
        .expect("frozen EE deploy returns deterministic refusal receipt");
    assert_eq!(frozen_rec[0].status, UelReceiptStatus::DeployFrozen);
    state.execution_state.set_deploy_enabled(EeId::MOVE, true);

    // R-08 / G-1: Compatibility RPC gateways accept `&AccountState` (cannot mutate state)
    // and bound oversized/malformed requests deterministically.
    let root_pre_rpc = state.execution_state.execution_root();
    let oversized = "x".repeat(300 * 1024);
    let eth_resp = handle_eth_jsonrpc(&state, &oversized);
    let sol_resp = handle_solana_jsonrpc(&state, &oversized);
    let (apt_code, _) = handle_aptos_rest(&state, "GET", "/v1", None);
    let (cos_code, _) = handle_cosmos_rest(
        &state,
        "GET",
        "/cosmos/base/tendermint/v1beta1/node_info",
        None,
    );
    assert!(eth_resp.contains("error"));
    assert!(sol_resp.contains("error"));
    assert_eq!(apt_code, 200);
    assert_eq!(cos_code, 200);
    assert_eq!(state.execution_state.execution_root(), root_pre_rpc);
}
