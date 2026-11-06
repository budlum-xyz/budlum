use super::aptos::{
    aptos_ed25519_address, move_alias_scheme_is_disjoint, sign_aptos_ed25519_tx, AptosPayloadKind,
    BUDLUM_APTOS_CHAIN_ID,
};
use super::cosmos::{
    ripemd160, sign_cosmos_tx_direct, CosmosEnvelopeError, BUDLUM_COSMOS_CHAIN_ID,
};
use super::ethereum::{
    decode_ethereum_tx, evm_address_from_secret_key, sign_eip1559_tx, EthereumEnvelopeError,
    BUDLUM_EVM_CHAIN_ID,
};
use super::solana::{sign_solana_tx, SolanaCompiledInstruction, SolanaEnvelopeError};
use super::{
    adopt_signing_digest, AdoptForeignAccountTx, ClassicalAdoptProof, ForeignAdmissionError,
    ForeignTx, QuantumAlertLevel, VerifiedForeignOutcome,
};
use crate::core::account::{AccountState, ATTOS_PER_ATOM};
use crate::core::address::Address;
use crate::crypto::pq::{self, SchemeId};
use crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key;
use crate::execution::coordinator::alias::{
    derive_foreign_account, AccountQuantumClass, ForeignScheme, MOVE_ALIAS_SCHEME_BYTE,
};
use crate::execution::coordinator::ExecutionCoordinator;
use budlum_uel_abi::EeId;
use k256::ecdsa::SigningKey as SecpSigningKey;

#[test]
fn evm_blob_tx_refused() {
    let blob_raw = vec![0x03, 0xc1, 0x80];
    let err = decode_ethereum_tx(&blob_raw, BUDLUM_EVM_CHAIN_ID)
        .expect_err("type-3 EIP-4844 blob transactions must be refused");
    assert_eq!(err, EthereumEnvelopeError::BlobTxUnsupported);

    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let res = coord.process_foreign_envelope(
        &mut state,
        &ForeignTx::Ethereum {
            raw_rlp: blob_raw,
            direct_native_pq_recipient: None,
        },
        1_700_000_000,
    );
    assert_eq!(
        res,
        Err(ForeignAdmissionError::Ethereum(
            EthereumEnvelopeError::BlobTxUnsupported
        ))
    );
}

#[test]
fn uel_foreign_tx_replay_refused() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let now_secs = 1_700_000_000u64;

    // 1. Ethereum leg: EIP-1559 succeeds once, replay and wrong chain_id fail.
    let eth_sk = [0x21u8; 32];
    let eth_raw = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000_000_000,
        2_000_000_000,
        21_000,
        Some([0xAB; 20]),
        0,
        &[],
        &[],
    )
    .expect("sign eip1559");
    let eth_env = ForeignTx::Ethereum {
        raw_rlp: eth_raw,
        direct_native_pq_recipient: None,
    };
    coord
        .process_foreign_envelope(&mut state, &eth_env, now_secs)
        .expect("first Ethereum tx admitted");
    let replay_eth = coord
        .process_foreign_envelope(&mut state, &eth_env, now_secs)
        .expect_err("replayed Ethereum tx must fail");
    assert_eq!(
        replay_eth,
        ForeignAdmissionError::NonceMismatch {
            expected: 1,
            got: 0
        }
    );

    let wrong_chain_eth = sign_eip1559_tx(
        &eth_sk,
        1,
        1,
        1_000_000_000,
        2_000_000_000,
        21_000,
        Some([0xAB; 20]),
        0,
        &[],
        &[],
    )
    .expect("sign mainnet tx");
    let bad_eth_res = coord.process_foreign_envelope(
        &mut state,
        &ForeignTx::Ethereum {
            raw_rlp: wrong_chain_eth,
            direct_native_pq_recipient: None,
        },
        now_secs,
    );
    assert_eq!(
        bad_eth_res,
        Err(ForeignAdmissionError::Ethereum(
            EthereumEnvelopeError::WrongChainId {
                expected: BUDLUM_EVM_CHAIN_ID,
                got: 1,
            }
        ))
    );

    // 2. Cosmos leg: SIGN_MODE_DIRECT succeeds once, replay and wrong chain_id fail.
    assert_eq!(
        hex::encode(ripemd160(b"")),
        "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    );
    let cosmos_sk = [0x31u8; 32];
    let cosmos_raw = sign_cosmos_tx_direct(
        &cosmos_sk,
        BUDLUM_COSMOS_CHAIN_ID,
        0,
        0,
        200_000,
        500,
        vec![(
            String::from("/cosmos.bank.v1beta1.MsgSend"),
            b"send-payload".to_vec(),
        )],
    )
    .expect("sign cosmos direct");
    let cosmos_env = ForeignTx::Cosmos {
        tx_raw_bytes: cosmos_raw.clone(),
        chain_id: String::from(BUDLUM_COSMOS_CHAIN_ID),
        account_number: 0,
        direct_native_pq_recipient: None,
    };
    coord
        .process_foreign_envelope(&mut state, &cosmos_env, now_secs)
        .expect("first Cosmos tx admitted");
    let replay_cosmos = coord
        .process_foreign_envelope(&mut state, &cosmos_env, now_secs)
        .expect_err("replayed Cosmos tx must fail");
    assert_eq!(
        replay_cosmos,
        ForeignAdmissionError::NonceMismatch {
            expected: 1,
            got: 0
        }
    );
    let wrong_cosmos = ForeignTx::Cosmos {
        tx_raw_bytes: cosmos_raw,
        chain_id: String::from("cosmoshub-4"),
        account_number: 0,
        direct_native_pq_recipient: None,
    };
    assert_eq!(
        coord.process_foreign_envelope(&mut state, &wrong_cosmos, now_secs),
        Err(ForeignAdmissionError::Cosmos(
            CosmosEnvelopeError::WrongChainId {
                expected: String::from(BUDLUM_COSMOS_CHAIN_ID),
                got: String::from("cosmoshub-4"),
            }
        ))
    );

    // 3. Solana leg: blockhash window + signature replay cache.
    let recent_bh = [0x77u8; 32];
    state.execution_state.foreign_lane.record_blockhash(recent_bh);
    let sol_seed = [0x41u8; 32];
    let sol_ix = vec![SolanaCompiledInstruction {
        program_id_index: 1,
        accounts: vec![0],
        data: vec![1, 2, 3],
    }];
    let sol_raw = sign_solana_tx(&sol_seed, true, recent_bh, &[[0x99u8; 32]], &sol_ix);
    let sol_env = ForeignTx::Solana {
        raw_wire: sol_raw,
        direct_native_pq_recipient: None,
    };
    coord
        .process_foreign_envelope(&mut state, &sol_env, now_secs)
        .expect("first Solana v0 tx admitted");
    assert_eq!(
        coord.process_foreign_envelope(&mut state, &sol_env, now_secs),
        Err(ForeignAdmissionError::Solana(
            SolanaEnvelopeError::ReplayedSignature
        ))
    );
    let expired_sol = sign_solana_tx(&sol_seed, false, [0xEEu8; 32], &[[0x99u8; 32]], &sol_ix);
    assert_eq!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Solana {
                raw_wire: expired_sol,
                direct_native_pq_recipient: None,
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::Solana(
            SolanaEnvelopeError::UnknownOrExpiredBlockhash
        ))
    );

    // 4. Aptos leg: chain_id 205 + sequence_number + expiration_timestamp_secs.
    let aptos_seed = [0x51u8; 32];
    let payload = AptosPayloadKind::EntryFunction {
        module_address: [0u8; 32],
        module_name: String::from("aptos_account"),
        function_name: String::from("transfer"),
        args_bcs: vec![1, 2, 3, 4],
    };
    let aptos_raw = sign_aptos_ed25519_tx(
        &aptos_seed,
        0,
        &payload,
        100_000,
        100,
        now_secs + 60,
        BUDLUM_APTOS_CHAIN_ID,
    );
    let aptos_env = ForeignTx::Aptos {
        raw_bcs: aptos_raw,
        direct_native_pq_recipient: None,
    };
    coord
        .process_foreign_envelope(&mut state, &aptos_env, now_secs)
        .expect("first Aptos tx admitted");
    assert_eq!(
        coord.process_foreign_envelope(&mut state, &aptos_env, now_secs),
        Err(ForeignAdmissionError::NonceMismatch {
            expected: 1,
            got: 0
        })
    );
    let wrong_aptos = sign_aptos_ed25519_tx(
        &aptos_seed,
        1,
        &payload,
        100_000,
        100,
        now_secs + 60,
        1,
    );
    assert!(matches!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Aptos {
                raw_bcs: wrong_aptos,
                direct_native_pq_recipient: None,
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::Aptos(_))
    ));
}

#[test]
fn uel_quantum_alert_closes_foreign_lane() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let now_secs = 1_700_000_000u64;

    let pq_seed = [0x12u8; 32];
    let pq_pk = pq::ml_dsa_public_key(SchemeId::ML_DSA_87, &pq_seed).expect("ml-dsa-87 pk");
    let pq_addr = wallet_address_from_ml_dsa_87_public_key(&pq_pk).expect("pq addr");

    let eth_sk = [0x62u8; 32];
    let eth_addr = evm_address_from_secret_key(&eth_sk).expect("evm addr");
    let foreign_bud_addr = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &eth_addr);
    state.credit_account(&foreign_bud_addr, 50);

    // Level 1 (Advisory): general contract call is admitted with advisory_warning = true.
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level1Advisory;
    let tx_lvl1 = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        50_000,
        Some([0xCC; 20]),
        0,
        &[0xaa, 0xbb],
        &[],
    )
    .expect("sign lvl1");
    let out1 = coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: tx_lvl1,
                direct_native_pq_recipient: None,
            },
            now_secs,
        )
        .expect("level 1 admits general tx");
    assert!(matches!(
        out1,
        VerifiedForeignOutcome::Ethereum {
            advisory_warning: true,
            ..
        }
    ));

    // Level 2 (Restricted): general contract call refused, direct transfer to PQ native allowed.
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level2Restricted;
    let tx_lvl2_call = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        1,
        1_000,
        2_000,
        50_000,
        Some([0xCC; 20]),
        0,
        &[0xde, 0xad],
        &[],
    )
    .expect("sign lvl2 call");
    assert_eq!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: tx_lvl2_call,
                direct_native_pq_recipient: None,
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::ClosedByQuantumAlert(
            QuantumAlertLevel::Level2Restricted
        ))
    );

    let pq_evm_alias: [u8; 20] = state
        .execution_state
        .ensure_alias_registered(&pq_addr, EeId::EVM)
        .expect("register pq alias")
        .try_into()
        .expect("20 bytes");
    let send_wei = 3 * u128::from(ATTOS_PER_ATOM);
    let tx_lvl2_to_pq = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        1,
        1_000,
        2_000,
        21_000,
        Some(pq_evm_alias),
        send_wei,
        &[],
        &[],
    )
    .expect("sign lvl2 transfer to pq");
    coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: tx_lvl2_to_pq,
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        )
        .expect("level 2 permits direct transfer to PQ native account");
    assert_eq!(state.get_attos_balance(&pq_addr), send_wei);

    // Level 3 (Isolated): even direct transfer to PQ native is refused; only Adopt is permitted.
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level3Isolated;
    let tx_lvl3_to_pq = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        2,
        1_000,
        2_000,
        21_000,
        Some(pq_evm_alias),
        u128::from(ATTOS_PER_ATOM),
        &[],
        &[],
    )
    .expect("sign lvl3 transfer");
    assert_eq!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: tx_lvl3_to_pq,
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::ClosedByQuantumAlert(
            QuantumAlertLevel::Level3Isolated
        ))
    );
}

#[test]
fn foreign_account_cannot_touch_pq_holdings() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    let pq_owner = Address::from([0x99u8; 32]);
    state.credit_account(&pq_owner, 100);

    let eth_sk = [0x71u8; 32];
    let eth_raw = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        1_000,
        2_000,
        21_000,
        Some([0x11; 20]),
        0,
        &[],
        &[],
    )
    .expect("sign eth");
    let out = coord
        .process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: eth_raw,
                direct_native_pq_recipient: None,
            },
            1_700_000_000,
        )
        .expect("admit foreign account");
    let VerifiedForeignOutcome::Ethereum { budlum_sender, .. } = out else {
        panic!("expected Ethereum outcome");
    };

    assert_eq!(
        state
            .execution_state
            .foreign_lane
            .quantum_class_of(&budlum_sender),
        AccountQuantumClass::Classical
    );
    assert_eq!(
        state
            .execution_state
            .foreign_lane
            .quantum_class_of(&pq_owner),
        AccountQuantumClass::PostQuantum
    );
    assert_eq!(
        state
            .execution_state
            .foreign_lane
            .authorize_holding_access(&budlum_sender, &pq_owner),
        Err(ForeignAdmissionError::PqHoldingsProtected)
    );
    assert!(state
        .execution_state
        .foreign_lane
        .authorize_holding_access(&budlum_sender, &budlum_sender)
        .is_ok());
}

#[test]
fn adopt_moves_holdings_once() {
    let mut state = AccountState::new();
    let mut coord = ExecutionCoordinator::new();
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level3Isolated;

    let eth_sk = [0x82u8; 32];
    let eth_addr = evm_address_from_secret_key(&eth_sk).expect("evm addr");
    let foreign_bud_addr = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &eth_addr);

    // Seed foreign account with 12 atoms + 345_678_901 attoBUD dust (via PQ faucet transfer).
    let faucet = Address::from([0xFAu8; 32]);
    state.credit_account(&faucet, 20);
    let exact_attos = 12 * u128::from(ATTOS_PER_ATOM) + 345_678_901u128;
    state
        .transfer_attos_in_unit(
            &faucet,
            &foreign_bud_addr,
            exact_attos,
            crate::core::account::BudEnvUnit::EvmWei,
        )
        .expect("fund foreign account with sub-atom precision");
    let supply_before = state.total_bud_committed_attos();

    let pq_seed = [0x33u8; 32];
    let pq_pk = pq::ml_dsa_public_key(SchemeId::ML_DSA_87, &pq_seed).expect("ml-dsa-87 pk");
    let pq_target = wallet_address_from_ml_dsa_87_public_key(&pq_pk).expect("pq target");

    let digest = adopt_signing_digest(
        ForeignScheme::EthereumSecp256k1,
        &eth_addr,
        &pq_target,
        BUDLUM_EVM_CHAIN_ID,
    );
    let pq_sig = pq::ml_dsa_sign(
        SchemeId::ML_DSA_87,
        &pq_seed,
        &digest,
        b"BDLM_ADOPT_FOREIGN_V1",
        &[0u8; 32],
    )
    .expect("ml-dsa-87 sign");

    let secp_key = SecpSigningKey::from_bytes((&eth_sk).into()).expect("secp key");
    let (sig, rec_id) = secp_key
        .sign_prehash_recoverable(&digest)
        .expect("recoverable secp sign");
    let mut sig65 = Vec::with_capacity(65);
    sig65.extend_from_slice(&sig.to_bytes());
    sig65.push(rec_id.to_byte());

    let adopt_tx = ForeignTx::Adopt(AdoptForeignAccountTx {
        scheme: ForeignScheme::EthereumSecp256k1,
        local_id: eth_addr.to_vec(),
        native_pq_target: pq_target,
        pq_public_key: pq_pk,
        pq_signature: pq_sig,
        classical_proof: ClassicalAdoptProof::EthereumSecp256k1 { signature65: sig65 },
        chain_id: BUDLUM_EVM_CHAIN_ID,
    });

    let outcome = coord
        .process_foreign_envelope(&mut state, &adopt_tx, 1_700_000_000)
        .expect("Adopt must succeed even under Level 3 Isolated");
    assert_eq!(
        outcome,
        VerifiedForeignOutcome::Adopted {
            foreign_address: foreign_bud_addr,
            native_pq_target: pq_target,
            moved_atoms: 12,
            moved_frac_attos: 345_678_901,
        }
    );
    assert_eq!(state.get_attos_balance(&foreign_bud_addr), 0);
    assert_eq!(state.get_attos_balance(&pq_target), exact_attos);
    assert_eq!(state.total_bud_committed_attos(), supply_before);

    // Second Adopt is refused: holdings move at most once.
    let second = coord
        .process_foreign_envelope(&mut state, &adopt_tx, 1_700_000_000)
        .expect_err("second Adopt must be refused");
    assert_eq!(
        second,
        ForeignAdmissionError::AccountAlreadyAdopted(pq_target)
    );
}

#[test]
fn move_alias_scheme_byte_is_unused() {
    assert_eq!(MOVE_ALIAS_SCHEME_BYTE, 0xBD);
    assert!(move_alias_scheme_is_disjoint());
    let sample_ed = aptos_ed25519_address(&[0x44u8; 32]);
    assert_ne!(sample_ed, [0u8; 32]);
}
