use crate::ai::types::{AiInferenceRequest, AiModelId, AiModelSpec, BoundedBytes};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::pollen::{AccessGrant, AiDataInputRef, DataAsset, GrantId, Signature64};
use crate::storage::content_id::ContentId;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn model_spec(owner: Address) -> AiModelSpec {
    let model_hash = [0xA1; 32];
    let model_id = AiModelId::of(&owner, &model_hash, 1);
    AiModelSpec {
        model_id,
        model_hash,
        owner,
        min_verifier_count: 1,
        agreement_threshold: 1,
        max_input_ref_bytes: 1024,
        max_output_ref_bytes: 1024,
        request_deadline_blocks: 10,
        result_deadline_blocks: 10,
        version: 1,
        active: true,
    }
}

fn request(
    requester: Address,
    model_id: AiModelId,
    input_ref: Vec<u8>,
    seed: u8,
) -> AiInferenceRequest {
    let mut req = AiInferenceRequest {
        request_id: Default::default(),
        requester,
        model_id,
        input_commitment: [seed; 32],
        input_ref: BoundedBytes::try_new(input_ref).unwrap(),
        max_fee: 10,
        callback: None,
        submitted_at_block: 0,
        deadline_block: 10,
    };
    req.request_id = req.calculate_id();
    req
}

fn ai_request_tx(from: Address, req: AiInferenceRequest, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiInferenceRequest(req),
    )
}

fn signed_grant(asset: &DataAsset, grantee: Address, max_reads: u32) -> AccessGrant {
    let mut grant = AccessGrant::new_unsigned(
        asset.asset_id,
        asset.owner,
        grantee,
        grantee,
        42,
        0,
        10,
        max_reads,
        [0xD7; 32],
    );
    grant.owner_signature = Signature64::from([0x55; 64]);
    grant
}

#[test]
fn pollen_ai_data_ref_without_access_grant_is_rejected() {
    let requester = addr(2);
    let model_owner = addr(9);
    let mut state = AccountState::new();
    state.add_balance(&requester, 100);
    let spec = model_spec(model_owner);
    let model_id = spec.model_id;
    state.ai_registry.register_model(spec).unwrap();

    let asset = DataAsset::new(addr(1), ContentId::of(b"private data"), [0x11; 32], true);
    let asset_id = asset.asset_id;
    state.marketplace.register_data_asset(asset).unwrap();
    let input = AiDataInputRef {
        asset_id,
        grant_id: GrantId::from([0x44; 32]),
    }
    .encode();
    let req = request(requester, model_id, input, 1);
    let tx = ai_request_tx(requester, req, 0);

    let err = Executor::apply_transaction_checked(&mut state, &tx).unwrap_err();
    assert_eq!(err.code(), "ai_data_access_denied");
    assert_eq!(state.get_balance(&requester), 100);
}

#[test]
fn pollen_ai_data_ref_with_access_grant_is_consumed_once() {
    let requester = addr(2);
    let model_owner = addr(9);
    let mut state = AccountState::new();
    state.add_balance(&requester, 100);
    let spec = model_spec(model_owner);
    let model_id = spec.model_id;
    state.ai_registry.register_model(spec).unwrap();

    let asset = DataAsset::new(addr(1), ContentId::of(b"private data"), [0x22; 32], true);
    let asset_id = asset.asset_id;
    state
        .marketplace
        .register_data_asset(asset.clone())
        .unwrap();
    let grant_id = state
        .marketplace
        .create_access_grant(signed_grant(&asset, requester, 1))
        .unwrap();
    let input = AiDataInputRef { asset_id, grant_id }.encode();

    let first_req = request(requester, model_id, input.clone(), 1);
    let first_tx = ai_request_tx(requester, first_req, 0);
    Executor::apply_transaction_checked(&mut state, &first_tx).unwrap();
    assert_eq!(
        state
            .marketplace
            .access_grants
            .get(&grant_id)
            .unwrap()
            .reads_used,
        1
    );

    let second_req = request(requester, model_id, input, 2);
    let second_tx = ai_request_tx(requester, second_req, 1);
    let err = Executor::apply_transaction_checked(&mut state, &second_tx).unwrap_err();
    assert_eq!(err.code(), "ai_data_access_denied");
}

#[test]
fn non_pollen_ai_input_ref_still_uses_legacy_opaque_path() {
    let requester = addr(2);
    let model_owner = addr(9);
    let mut state = AccountState::new();
    state.add_balance(&requester, 100);
    let spec = model_spec(model_owner);
    let model_id = spec.model_id;
    state.ai_registry.register_model(spec).unwrap();

    let req = request(requester, model_id, b"plain prompt".to_vec(), 1);
    let tx = ai_request_tx(requester, req, 0);
    Executor::apply_transaction_checked(&mut state, &tx).unwrap();
}

fn signed_sale_authorization(asset: &DataAsset) -> crate::pollen::SaleAuthorization {
    let mut authorization = crate::pollen::SaleAuthorization::new_unsigned(
        asset.asset_id,
        asset.owner,
        42,
        0,
        10,
        2,
        [0xA4; 32],
    );
    authorization.seller_signature = Signature64::from([0x33; 64]);
    authorization
}

fn pollen_tx(from: Address, tx_type: TransactionType, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        tx_type,
    )
}

#[test]
fn tx_backed_pollen_asset_and_grant_unlock_ai_read() {
    let owner = addr(1);
    let requester = addr(2);
    let model_owner = addr(9);
    let mut state = AccountState::new();
    state.add_balance(&owner, 100);
    state.add_balance(&requester, 100);
    let spec = model_spec(model_owner);
    let model_id = spec.model_id;
    state.ai_registry.register_model(spec).unwrap();

    let asset = DataAsset::new(owner, ContentId::of(b"private data"), [0x44; 32], true);
    let asset_id = asset.asset_id;
    Executor::apply_transaction_checked(
        &mut state,
        &pollen_tx(
            owner,
            TransactionType::PollenRegisterDataAsset(asset.clone()),
            0,
        ),
    )
    .unwrap();

    let grant = signed_grant(&asset, requester, 1);
    let grant_id = grant.grant_id;
    Executor::apply_transaction_checked(
        &mut state,
        &pollen_tx(owner, TransactionType::PollenGrantAccess(grant), 1),
    )
    .unwrap();

    let input = AiDataInputRef { asset_id, grant_id }.encode();
    let req = request(requester, model_id, input, 1);
    Executor::apply_transaction_checked(&mut state, &ai_request_tx(requester, req, 0)).unwrap();
    assert_eq!(
        state
            .marketplace
            .access_grants
            .get(&grant_id)
            .unwrap()
            .reads_used,
        1
    );
}

#[test]
fn tx_backed_pollen_rejects_non_owner_grant_submission() {
    let owner = addr(1);
    let requester = addr(2);
    let mut state = AccountState::new();
    state.add_balance(&owner, 100);
    state.add_balance(&requester, 100);

    let asset = DataAsset::new(owner, ContentId::of(b"private data"), [0x55; 32], true);
    state
        .marketplace
        .register_data_asset(asset.clone())
        .unwrap();
    let grant = signed_grant(&asset, requester, 1);

    let err = Executor::apply_transaction_checked(
        &mut state,
        &pollen_tx(requester, TransactionType::PollenGrantAccess(grant), 0),
    )
    .unwrap_err();
    assert_eq!(err.code(), "pollen_grant_owner_mismatch");
}

#[test]
fn tx_backed_pollen_revoke_asset_blocks_ai_reads() {
    let owner = addr(1);
    let requester = addr(2);
    let mut state = AccountState::new();
    state.add_balance(&owner, 100);
    let asset = DataAsset::new(owner, ContentId::of(b"private data"), [0x66; 32], true);
    let asset_id = state
        .marketplace
        .register_data_asset(asset.clone())
        .unwrap();
    let grant_id = state
        .marketplace
        .create_access_grant(signed_grant(&asset, requester, 3))
        .unwrap();

    Executor::apply_transaction_checked(
        &mut state,
        &pollen_tx(owner, TransactionType::PollenRevokeDataAsset(asset_id), 0),
    )
    .unwrap();
    let reference = AiDataInputRef { asset_id, grant_id }.encode();
    assert!(state
        .marketplace
        .validate_ai_read_ref(&reference, &requester, 0)
        .is_err());
}

#[test]
fn tx_backed_pollen_sale_authorization_registers_and_roundtrips_proto() {
    let owner = addr(1);
    let asset = DataAsset::new(owner, ContentId::of(b"private data"), [0x77; 32], true);
    let authorization = signed_sale_authorization(&asset);
    let tx = pollen_tx(
        owner,
        TransactionType::PollenAuthorizeSale(authorization.clone()),
        0,
    );

    let proto = crate::network::proto_conversions::pb::ProtoTransaction::from(&tx);
    let back = Transaction::try_from(proto).unwrap();
    assert_eq!(back.tx_type, tx.tx_type);

    let mut state = AccountState::new();
    state.add_balance(&owner, 100);
    state.marketplace.register_data_asset(asset).unwrap();
    Executor::apply_transaction_checked(&mut state, &back).unwrap();
    assert!(state
        .marketplace
        .get_sale_authorization(&authorization.authorization_id)
        .is_some());
}
