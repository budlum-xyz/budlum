use super::aptos::{
    aptos_ed25519_address, move_alias_scheme_is_disjoint, sign_aptos_ed25519_tx, AptosPayloadKind,
    BUDLUM_APTOS_CHAIN_ID, PINNED_APTOS_SCHEME_BYTES,
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
    ForeignLaneState, ForeignTx, QuantumAlertLevel, VerifiedForeignOutcome,
};
use crate::core::account::{AccountState, ATTOS_PER_ATOM};
use crate::core::address::Address;
use crate::crypto::pq;
use crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key;
use crate::crypto::scheme::SchemeId;
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
        (1_000_000_000, 2_000_000_000, 21_000),
        Some([0xAB; 20]),
        0,
        (&[], &[]),
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
        (1_000_000_000, 2_000_000_000, 21_000),
        Some([0xAB; 20]),
        0,
        (&[], &[]),
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
    state
        .execution_state
        .foreign_lane
        .record_blockhash(recent_bh);
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
    let wrong_aptos =
        sign_aptos_ed25519_tx(&aptos_seed, 1, &payload, 100_000, 100, now_secs + 60, 1);
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
        (1_000, 2_000, 50_000),
        Some([0xCC; 20]),
        0,
        (&[0xaa, 0xbb], &[]),
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
        (1_000, 2_000, 50_000),
        Some([0xCC; 20]),
        0,
        (&[0xde, 0xad], &[]),
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
        (1_000, 2_000, 21_000),
        Some(pq_evm_alias),
        send_wei,
        (&[], &[]),
    )
    .expect("sign lvl2 transfer to pq");
    // Unregistered recipient fails closed before native PQ registration (`1bd52750`).
    assert!(matches!(
        coord.process_foreign_envelope(
            &mut state,
            &ForeignTx::Ethereum {
                raw_rlp: tx_lvl2_to_pq.clone(),
                direct_native_pq_recipient: Some(pq_addr),
            },
            now_secs,
        ),
        Err(ForeignAdmissionError::InvalidDirectPqRecipient(_))
    ));
    state
        .execution_state
        .foreign_lane
        .register_native_pq_account(pq_addr);
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
        (1_000, 2_000, 21_000),
        Some(pq_evm_alias),
        u128::from(ATTOS_PER_ATOM),
        (&[], &[]),
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
    state
        .execution_state
        .foreign_lane
        .register_native_pq_account(pq_owner);

    let eth_sk = [0x71u8; 32];
    let eth_raw = sign_eip1559_tx(
        &eth_sk,
        BUDLUM_EVM_CHAIN_ID,
        0,
        (1_000, 2_000, 21_000),
        Some([0x11; 20]),
        0,
        (&[], &[]),
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
        crate::crypto::ctx::ADOPT_FOREIGN_V1,
        &[0u8; 32],
    )
    .expect("ml-dsa-87 sign");

    let secp_key = SecpSigningKey::from_bytes((&eth_sk).into()).expect("secp key");
    let (sig, rec_id) = secp_key.sign_prehash_recoverable(&digest);
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

    let pinned: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/aptos/pinned_scheme_ids.json"
    ))
    .expect("the pinned Aptos scheme vector is JSON");
    assert_eq!(
        pinned["commit"].as_str(),
        Some("81d89f428fe8e4b69d53b4916993e9a930afc37c"),
    );
    let expected: Vec<u8> = pinned["scheme_ids"]
        .as_array()
        .expect("scheme id list")
        .iter()
        .map(|id| u8::try_from(id.as_u64().expect("integer scheme id")).expect("u8 scheme id"))
        .collect();
    assert_eq!(PINNED_APTOS_SCHEME_BYTES, expected.as_slice());
    assert!(!expected.contains(&MOVE_ALIAS_SCHEME_BYTE));
    assert_eq!(pinned["reserved_byte_is_used"], serde_json::json!(false));
}

#[test]
fn unregistered_address_fails_closed_as_classical() {
    let lane = ForeignLaneState::new();
    let unknown = Address::from([0xAAu8; 32]);
    let target = Address::from([0xBBu8; 32]);
    assert_eq!(
        lane.quantum_class_of(&unknown),
        AccountQuantumClass::Classical
    );
    assert_eq!(
        lane.authorize_holding_access(&unknown, &target),
        Err(ForeignAdmissionError::PqHoldingsProtected)
    );
}

#[test]
fn uol_k1_home_key_stipend_all_four_chains_alert_and_pq_ceiling() {
    use super::{home_key_stipend_digest, MAX_HOME_KEY_STIPEND_PQ_CEILING_ATTOS};
    use crate::core::chain_config::Network;
    use crate::object_layer::charter::{CharterStatus, DataPolicy, DomainCharter};
    use crate::object_layer::family::{AssetKind, HomeVmFamily};
    use crate::object_layer::ids::{AssetClassId, HomeIdentity};
    use crate::object_layer::registry::{
        AssetClass, Call, ClassStatus, MAX_HOME_STIPEND_ATTOS,
    };
    use crate::object_layer::rule::{
        ClassRule, ClassSlice, Holder, TemplateId, TemplateParams, Verb,
    };
    use crate::object_layer::tx::{
        home_stipend_action_digest, HomeKeyScheme, HomeKeyStipendAuth, ObjectLayerTx,
    };
    use crate::settlement::domains::{
        execute_settlement_tx, SettlementTx, SettlementTxContext,
    };
    use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::Signature as SecpSig;

    let chain_id = Network::Testnet.chain_id().value();
    let domain = 77u32;
    let contract = b"uol-k1-token".to_vec();
    let class_id = AssetClassId::derive(domain, &contract);
    let recipient = Holder::Account(Address([0xDD; 32]));

    let mut state = AccountState::new();
    state.settlement.object_layer.charters.insert(
        domain,
        DomainCharter {
            vm_family: HomeVmFamily::Evm,
            chain_reference: String::from("eip155:1"),
            address_prefix: String::from("0x"),
            endpoint: vec![0xe0; 20],
            endpoint_code_hash: [0xc1; 32],
            verifier: vec![0xe2; 20],
            verifier_code_hash: [0xc2; 32],
            upgrade_notice: 100,
            silence_window: 1_000,
            data_policy: DataPolicy::Public,
            status: CharterStatus::Active,
        },
    );
    state.settlement.object_layer.classes.insert(
        class_id,
        AssetClass {
            id: class_id,
            home_domain: domain,
            kind: AssetKind::Fungible,
            contract,
            rule: ClassRule::Template {
                id: TemplateId::FungibleV1,
                params: TemplateParams::default(),
            },
            slice: ClassSlice::new(),
            upgrade_authority: None,
            status: ClassStatus::Active,
            registrant: Address([0x11; 32]),
            bond: 1_000_000,
            sample_commitment: [0u8; 32],
        },
    );

    let ctx = SettlementTxContext {
        sender: Address([0x99; 32]),
        chain_id,
        fee: 0,
        bls: || Box::new(crate::cross_domain::external::intake::PairingBls),
    };

    // 1. Ethereum secp256k1 home key stipend call (fee = 0).
    let eth_sk = [0x17u8; 32];
    let eth_addr = evm_address_from_secret_key(&eth_sk).expect("eth addr");
    let eth_home = HomeIdentity::derive(domain, &eth_addr);
    state
        .settlement
        .object_layer
        .balances
        .insert((class_id, Holder::Home(eth_home)), 100);
    let eth_action = ObjectLayerTx::Call {
        calls: vec![Call {
            class: class_id,
            native_id: Vec::new(),
            verb: Verb::Transfer {
                from: Holder::Home(eth_home),
                to: recipient,
                amount: 25,
            },
        }],
    };
    let eth_act_digest = home_stipend_action_digest(&eth_action).expect("digest");
    let eth_digest = home_key_stipend_digest(
        chain_id,
        domain,
        &eth_addr,
        0,
        MAX_HOME_STIPEND_ATTOS,
        &eth_act_digest,
    );
    let eth_key = SecpSigningKey::from_bytes((&eth_sk).into()).expect("secp key");
    let (eth_sig, eth_rec) = eth_key.sign_prehash_recoverable(&eth_digest);
    let mut eth_sig65 = Vec::with_capacity(65);
    eth_sig65.extend_from_slice(&eth_sig.to_bytes());
    eth_sig65.push(eth_rec.to_byte());
    let eth_tx = SettlementTx::ObjectLayer(Box::new(ObjectLayerTx::HomeStipendCall {
        domain,
        auth: HomeKeyStipendAuth {
            scheme: HomeKeyScheme::EthereumSecp256k1,
            home_address: eth_addr.to_vec(),
            signer_pubkey: Vec::new(),
            signature: eth_sig65,
            nonce: 0,
            requested_stipend_attos: MAX_HOME_STIPEND_ATTOS,
        },
        action: Box::new(eth_action.clone()),
    }));
    execute_settlement_tx(&mut state, &ctx, &eth_tx).expect("Ethereum UOL-K1 call succeeds");
    assert_eq!(state.settlement.object_layer.balance(&class_id, &recipient), 25);

    // 2. Solana Ed25519 home key stipend call (fee = 0).
    let sol_sk = EdSigningKey::from_bytes(&[0x27u8; 32]);
    let sol_addr = sol_sk.verifying_key().to_bytes();
    let sol_home = HomeIdentity::derive(domain, &sol_addr);
    state
        .settlement
        .object_layer
        .balances
        .insert((class_id, Holder::Home(sol_home)), 100);
    let sol_action = ObjectLayerTx::Call {
        calls: vec![Call {
            class: class_id,
            native_id: Vec::new(),
            verb: Verb::Transfer {
                from: Holder::Home(sol_home),
                to: recipient,
                amount: 15,
            },
        }],
    };
    let sol_act_digest = home_stipend_action_digest(&sol_action).expect("digest");
    let sol_digest = home_key_stipend_digest(
        chain_id,
        domain,
        &sol_addr,
        0,
        MAX_HOME_STIPEND_ATTOS,
        &sol_act_digest,
    );
    let sol_sig = sol_sk.sign(&sol_digest).to_bytes().to_vec();
    let sol_tx = SettlementTx::ObjectLayer(Box::new(ObjectLayerTx::HomeStipendCall {
        domain,
        auth: HomeKeyStipendAuth {
            scheme: HomeKeyScheme::SolanaEd25519,
            home_address: sol_addr.to_vec(),
            signer_pubkey: sol_addr.to_vec(),
            signature: sol_sig,
            nonce: 0,
            requested_stipend_attos: MAX_HOME_STIPEND_ATTOS,
        },
        action: Box::new(sol_action),
    }));
    execute_settlement_tx(&mut state, &ctx, &sol_tx).expect("Solana UOL-K1 call succeeds");
    assert_eq!(state.settlement.object_layer.balance(&class_id, &recipient), 40);

    // 3. Aptos Ed25519 home key stipend call (fee = 0).
    let apt_sk = EdSigningKey::from_bytes(&[0x37u8; 32]);
    let apt_pk = apt_sk.verifying_key().to_bytes();
    let apt_addr = aptos_ed25519_address(&apt_pk);
    let apt_home = HomeIdentity::derive(domain, &apt_addr);
    state
        .settlement
        .object_layer
        .balances
        .insert((class_id, Holder::Home(apt_home)), 100);
    let apt_action = ObjectLayerTx::Call {
        calls: vec![Call {
            class: class_id,
            native_id: Vec::new(),
            verb: Verb::Transfer {
                from: Holder::Home(apt_home),
                to: recipient,
                amount: 10,
            },
        }],
    };
    let apt_act_digest = home_stipend_action_digest(&apt_action).expect("digest");
    let apt_digest = home_key_stipend_digest(
        chain_id,
        domain,
        &apt_addr,
        0,
        MAX_HOME_STIPEND_ATTOS,
        &apt_act_digest,
    );
    let apt_sig = apt_sk.sign(&apt_digest).to_bytes().to_vec();
    let apt_tx = SettlementTx::ObjectLayer(Box::new(ObjectLayerTx::HomeStipendCall {
        domain,
        auth: HomeKeyStipendAuth {
            scheme: HomeKeyScheme::AptosEd25519,
            home_address: apt_addr.to_vec(),
            signer_pubkey: apt_pk.to_vec(),
            signature: apt_sig,
            nonce: 0,
            requested_stipend_attos: MAX_HOME_STIPEND_ATTOS,
        },
        action: Box::new(apt_action),
    }));
    execute_settlement_tx(&mut state, &ctx, &apt_tx).expect("Aptos UOL-K1 call succeeds");
    assert_eq!(state.settlement.object_layer.balance(&class_id, &recipient), 50);

    // 4. Cosmos secp256k1 home key stipend call (fee = 0).
    let cos_key = SecpSigningKey::from_bytes((&[0x47u8; 32]).into()).expect("cos key");
    let cos_pk = cos_key.verifying_key().to_encoded_point(true);
    let cos_pk_bytes = cos_pk.as_bytes().to_vec();
    let cos_addr = super::cosmos::cosmos_addr20_from_compressed_pubkey(
        cos_pk_bytes.as_slice().try_into().expect("33 bytes"),
    );
    let cos_home = HomeIdentity::derive(domain, &cos_addr);
    state
        .settlement
        .object_layer
        .balances
        .insert((class_id, Holder::Home(cos_home)), 100);
    let cos_action = ObjectLayerTx::Call {
        calls: vec![Call {
            class: class_id,
            native_id: Vec::new(),
            verb: Verb::Transfer {
                from: Holder::Home(cos_home),
                to: recipient,
                amount: 5,
            },
        }],
    };
    let cos_act_digest = home_stipend_action_digest(&cos_action).expect("digest");
    let cos_digest = home_key_stipend_digest(
        chain_id,
        domain,
        &cos_addr,
        0,
        MAX_HOME_STIPEND_ATTOS,
        &cos_act_digest,
    );
    let cos_sig_raw: SecpSig = cos_key.sign(&cos_digest);
    let cos_sig = cos_sig_raw.normalize_s().to_bytes().to_vec();
    let cos_tx = SettlementTx::ObjectLayer(Box::new(ObjectLayerTx::HomeStipendCall {
        domain,
        auth: HomeKeyStipendAuth {
            scheme: HomeKeyScheme::CosmosSecp256k1,
            home_address: cos_addr.to_vec(),
            signer_pubkey: cos_pk_bytes,
            signature: cos_sig,
            nonce: 0,
            requested_stipend_attos: MAX_HOME_STIPEND_ATTOS,
        },
        action: Box::new(cos_action),
    }));
    execute_settlement_tx(&mut state, &ctx, &cos_tx).expect("Cosmos UOL-K1 call succeeds");
    assert_eq!(state.settlement.object_layer.balance(&class_id, &recipient), 55);

    // 5. PQ holding ceiling enforcement (> 1 BUD refused).
    let eth_next_digest = home_key_stipend_digest(
        chain_id,
        domain,
        &eth_addr,
        1,
        MAX_HOME_STIPEND_ATTOS,
        &eth_act_digest,
    );
    let (eth_sig2, eth_rec2) = eth_key.sign_prehash_recoverable(&eth_next_digest);
    let mut eth_sig2_65 = Vec::with_capacity(65);
    eth_sig2_65.extend_from_slice(&eth_sig2.to_bytes());
    eth_sig2_65.push(eth_rec2.to_byte());
    let eth_tx2 = SettlementTx::ObjectLayer(Box::new(ObjectLayerTx::HomeStipendCall {
        domain,
        auth: HomeKeyStipendAuth {
            scheme: HomeKeyScheme::EthereumSecp256k1,
            home_address: eth_addr.to_vec(),
            signer_pubkey: Vec::new(),
            signature: eth_sig2_65,
            nonce: 1,
            requested_stipend_attos: MAX_HOME_STIPEND_ATTOS,
        },
        action: Box::new(eth_action),
    }));
    let derived_eth = derive_foreign_account(ForeignScheme::EthereumSecp256k1, &eth_addr);
    let over_ceiling_atoms =
        u64::try_from(MAX_HOME_KEY_STIPEND_PQ_CEILING_ATTOS / u128::from(ATTOS_PER_ATOM) + 2)
            .expect("fits u64");
    state.credit_account(&derived_eth, over_ceiling_atoms);
    assert!(
        execute_settlement_tx(&mut state, &ctx, &eth_tx2).is_err(),
        "classical stipend must refuse when PQ holding exceeds ceiling"
    );

    // 6. Quantum Alert Level 2 (and Level 3) closes UOL-K1 automatically.
    state.get_or_create(&derived_eth).balance = 0;
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level2Restricted;
    assert!(
        execute_settlement_tx(&mut state, &ctx, &eth_tx2).is_err(),
        "Quantum Alert Level 2 must close UOL-K1"
    );
    state.execution_state.foreign_lane.quantum_alert_level = QuantumAlertLevel::Level3Isolated;
    assert!(
        execute_settlement_tx(&mut state, &ctx, &eth_tx2).is_err(),
        "Quantum Alert Level 3 must close UOL-K1"
    );
}

#[test]
fn non_evm_migration_kit_8_12_3_wasm_svm_and_move() {
    use crate::core::chain_config::Network;
    use crate::execution::coordinator::migration::{
        compute_ics23_leaf_hash, fold_sha256_merkle, fold_sha3_merkle, move_migration_digest,
        move_state_leaf, svm_account_leaf, svm_migration_digest, wasm_migration_digest,
        Ics23ExistenceProof, Ics23InnerOp, ImportError, MigrationFeeSchedule,
        MoveMigrationEntryKind, MoveMigrationRequest, MoveStateProofEntry, MigrationTx,
        MigrationTxOutcome, SvmMigrationRequest, WasmMigrationRequest,
    };
    use crate::execution::coordinator::move_ee::{
        FORBIDDEN_MOVE_MODULES, MOVE_BINARY_MAGIC,
    };
    use crate::execution::coordinator::state::{
        NS_MOVE_STATE, NS_SVM_ACCOUNT, NS_WASM_CODE, NS_WASM_CONTRACT, NS_WASM_STORE,
    };
    use crate::execution::coordinator::svm_ee::{
        SvmAccountData, FORBIDDEN_SVM_STAKE_PROGRAM_ID,
    };
    use crate::execution::coordinator::wasm_ee::build_valid_cosmwasm_module;
    use crate::object_layer::family::encoding::bech32_encode;
    use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::Signature as SecpSig;
    use sha2::{Digest as _, Sha256};

    let chain_id = Network::Testnet.chain_id().value();
    let schedule = MigrationFeeSchedule::TESTNET_DEFAULT;
    let mut coord = ExecutionCoordinator::new();
    let mut state = AccountState::new();
    let migrator = Address([0xE1; 32]);
    state.credit_account(&migrator, 1_000_000_000);

    // 1. WASM (Cosmos) ICS-23 verified migration.
    let cos_sk = SecpSigningKey::from_bytes((&[0x61u8; 32]).into()).expect("secp key");
    let cos_pk = cos_sk.verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let creator_addr20 = super::cosmos::cosmos_addr20_from_compressed_pubkey(
        cos_pk.as_slice().try_into().expect("33B"),
    );
    let creator_bech32 = bech32_encode("cosmos", &creator_addr20);
    let contract_bech32 = bech32_encode("wasm", &[0x77u8; 32]);
    let wasm_code = build_valid_cosmwasm_module(&["instantiate", "execute", "query"], &[]);
    let code_hash: [u8; 32] = Sha256::digest(&wasm_code).into();
    let contract_info_bytes = serde_json::to_vec(&serde_json::json!({
        "code_hash": hex::encode(code_hash),
        "creator": creator_bech32,
    }))
    .expect("json");
    let store_key = b"config".to_vec();
    let store_val = br#"{"admin":"ok"}"#.to_vec();

    // Build a 2-leaf ICS-23 tree where `info_leaf` pairs with `store_leaf` under `app_hash`.
    let info_leaf = compute_ics23_leaf_hash(&[0x00], contract_bech32.as_bytes(), &contract_info_bytes);
    let store_leaf = compute_ics23_leaf_hash(&[0x00], &store_key, &store_val);
    let mut root_pre = vec![0x01u8];
    root_pre.extend_from_slice(&info_leaf);
    root_pre.extend_from_slice(&store_leaf);
    let wasm_root: [u8; 32] = Sha256::digest(&root_pre).into();

    let info_proof = Ics23ExistenceProof {
        key: contract_bech32.as_bytes().to_vec(),
        value: contract_info_bytes,
        leaf_prefix: vec![0x00],
        path: vec![Ics23InnerOp {
            prefix: vec![0x01],
            suffix: store_leaf.to_vec(),
        }],
    };
    let store_proof = Ics23ExistenceProof {
        key: store_key.clone(),
        value: store_val.clone(),
        leaf_prefix: vec![0x00],
        path: vec![Ics23InnerOp {
            prefix: [&[0x01][..], &info_leaf[..]].concat(),
            suffix: Vec::new(),
        }],
    };
    let wasm_digest = wasm_migration_digest(
        chain_id,
        11,
        500,
        &contract_bech32,
        &code_hash,
        &wasm_root,
    );
    let wasm_sig: SecpSig = cos_sk.sign(&wasm_digest);
    let wasm_req = WasmMigrationRequest {
        chain_id,
        budlum_chain_id: chain_id,
        source_domain_id: 11,
        source_block: 500,
        state_root: wasm_root,
        contract_address: contract_bech32.clone(),
        creator: creator_bech32.clone(),
        creator_pubkey33: cos_pk,
        creator_signature64: wasm_sig.normalize_s().to_bytes().to_vec(),
        label: String::from("migrated-cw20"),
        wasm_code: wasm_code.clone(),
        contract_info_proof: info_proof,
        storage_entries: vec![store_proof],
    };
    let wasm_out = coord
        .apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportWasmContract(Box::new(wasm_req.clone())),
            &schedule,
        )
        .expect("WASM ICS-23 migration succeeds");
    assert!(matches!(wasm_out, MigrationTxOutcome::WasmImported { keys: 1, .. }));
    assert_eq!(
        state.execution_state.read(NS_WASM_CODE, &code_hash).expect("read"),
        Some(wasm_code)
    );
    assert!(
        state
            .execution_state
            .read(NS_WASM_CONTRACT, contract_bech32.as_bytes())
            .expect("read")
            .is_some()
    );
    let expected_store_key = [contract_bech32.as_bytes(), b":", &store_key].concat();
    assert_eq!(
        state
            .execution_state
            .read(NS_WASM_STORE, &expected_store_key)
            .expect("read"),
        Some(store_val)
    );
    // Re-importing at the occupied CosmWasm contract address refuses.
    assert!(matches!(
        coord.apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportWasmContract(Box::new(wasm_req)),
            &schedule,
        ),
        Err(ImportError::AddressOccupied)
    ));

    // 2. SVM (Solana) verified account migration (`lamports` forced to `0`).
    let svm_sk = EdSigningKey::from_bytes(&[0x72u8; 32]);
    let svm_pk = svm_sk.verifying_key().to_bytes();
    let svm_owner = [0x06u8; 32];
    let svm_data = vec![0xAAu8; 64];
    let svm_leaf = svm_account_leaf(900, &svm_pk, 50_000_000, &svm_owner, false, 7, &svm_data);
    let svm_sib = [0x33u8; 32];
    let svm_root = fold_sha256_merkle(svm_leaf, 0, &[svm_sib]);
    let svm_digest = svm_migration_digest(chain_id, 12, 900, &svm_pk, &svm_root);
    let svm_sig = svm_sk.sign(&svm_digest).to_bytes().to_vec();
    let svm_req = SvmMigrationRequest {
        chain_id,
        budlum_chain_id: chain_id,
        source_domain_id: 12,
        source_slot: 900,
        accounts_root: svm_root,
        pubkey: svm_pk,
        owner: svm_owner,
        executable: false,
        rent_epoch: 7,
        data: svm_data.clone(),
        proven_lamports: 50_000_000,
        proof_index: 0,
        proof_siblings: vec![svm_sib],
        authority_pubkey: svm_pk,
        authority_signature64: svm_sig,
    };
    let svm_out = coord
        .apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportSvmAccount(Box::new(svm_req.clone())),
            &schedule,
        )
        .expect("SVM migration succeeds");
    assert!(matches!(svm_out, MigrationTxOutcome::SvmImported { data_len: 64, .. }));
    let raw_svm = state
        .execution_state
        .read(NS_SVM_ACCOUNT, &svm_pk)
        .expect("read")
        .expect("installed");
    let decoded_svm: SvmAccountData = serde_json::from_slice(&raw_svm).expect("svm json");
    assert_eq!(decoded_svm.lamports, 0, "native SOL must never mint on Budlum");
    assert_eq!(decoded_svm.data, svm_data);
    assert_eq!(decoded_svm.owner, svm_owner);
    assert!(matches!(
        coord.apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportSvmAccount(Box::new(svm_req.clone())),
            &schedule,
        ),
        Err(ImportError::AddressOccupied)
    ));
    let mut bad_svm = svm_req;
    bad_svm.owner = FORBIDDEN_SVM_STAKE_PROGRAM_ID;
    assert!(coord
        .apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportSvmAccount(Box::new(bad_svm)),
            &schedule,
        )
        .is_err());

    // 3. Move (Aptos) verified module + resource migration.
    let move_sk = EdSigningKey::from_bytes(&[0x83u8; 32]);
    let move_pk = move_sk.verifying_key().to_bytes();
    let move_addr = aptos_ed25519_address(&move_pk);
    let mut move_mod = MOVE_BINARY_MAGIC.to_vec();
    move_mod.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let mod_key = [b"mod:", &move_addr[..], b":my_token"].concat();
    let res_tag = "0x1::coin::CoinStore";
    let res_key = [b"res:", &move_addr[..], b":", res_tag.as_bytes()].concat();
    let res_val = vec![0x10, 0x20, 0x30];
    let mod_leaf = move_state_leaf(&mod_key, &move_mod);
    let res_leaf = move_state_leaf(&res_key, &res_val);
    let move_root = fold_sha3_merkle(mod_leaf, 0, &[res_leaf]);
    let move_digest = move_migration_digest(chain_id, 13, 42, &move_addr, &move_root);
    let move_sig = move_sk.sign(&move_digest).to_bytes().to_vec();
    let move_req = MoveMigrationRequest {
        chain_id,
        budlum_chain_id: chain_id,
        source_domain_id: 13,
        source_version: 42,
        state_root: move_root,
        account: move_addr,
        signer_pubkey: move_pk,
        signature64: move_sig,
        entries: vec![
            MoveStateProofEntry {
                kind: MoveMigrationEntryKind::Module(String::from("my_token")),
                bytes: move_mod.clone(),
                index: 0,
                siblings: vec![res_leaf],
            },
            MoveStateProofEntry {
                kind: MoveMigrationEntryKind::Resource(String::from(res_tag)),
                bytes: res_val.clone(),
                index: 1,
                siblings: vec![mod_leaf],
            },
        ],
    };
    let move_out = coord
        .apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportMoveResource(Box::new(move_req.clone())),
            &schedule,
        )
        .expect("Move migration succeeds");
    assert!(matches!(move_out, MigrationTxOutcome::MoveImported { entries: 2, .. }));
    assert_eq!(
        state.execution_state.read(NS_MOVE_STATE, &mod_key).expect("read"),
        Some(move_mod)
    );
    assert_eq!(
        state.execution_state.read(NS_MOVE_STATE, &res_key).expect("read"),
        Some(res_val)
    );
    let mut bad_move = move_req;
    bad_move.entries[0].kind =
        MoveMigrationEntryKind::Resource(format!("{}::StakePool", FORBIDDEN_MOVE_MODULES[0]));
    assert!(coord
        .apply_migration(
            &mut state,
            &migrator,
            MigrationTx::ImportMoveResource(Box::new(bad_move)),
            &schedule,
        )
        .is_err());
}
