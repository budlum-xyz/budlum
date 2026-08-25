use crate::ai::types::{
    AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId, BoundedBytes,
};
use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::registry::role::roles;

fn model_and_request(requester: Address) -> (AiModelSpec, AiInferenceRequest) {
    let model_hash = [0xA1; 32];
    let model_id = AiModelId::of(&requester, &model_hash, 1);
    let spec = AiModelSpec {
        model_id,
        model_hash,
        owner: requester,
        min_verifier_count: 3,
        agreement_threshold: 2,
        max_input_ref_bytes: 1_024,
        max_output_ref_bytes: 1_024,
        request_deadline_blocks: 100,
        result_deadline_blocks: 100,
        version: 1,
        active: true,
        require_execution_proof: false,
        execution_program_hash: None,
        execution_class: 0,
        execution_dims: None,
        execution_weights_digest: None,
        modalities: crate::lubot::perception::ModalitySet::text_only(),
    };
    let mut request = AiInferenceRequest {
        request_id: AiRequestId::default(),
        requester,
        model_id,
        input_commitment: crate::ai::types::canonical_input_commitment(&[]),
        input_ref: BoundedBytes::empty(),
        max_fee: 100,
        callback: None,
        submitted_at_block: 0,
        deadline_block: 100,
        effort: crate::lubot::effort::EffortTier::default(),
        perception: Some(crate::lubot::perception::PerceptionRequest {
            asset_id: crate::pollen::AssetId([0xAB; 32]),
            content_id: crate::storage::content_id::ContentId([0xBC; 32]),
            kind: crate::lubot::perception::PerceptionKind::Text,
            declared_units: 100,
        }),
    };
    request.request_id = request.calculate_id();
    (spec, request)
}

fn result_transaction(operator: Address, request_id: AiRequestId, fee: u64) -> Transaction {
    result_transaction_with_commitment(operator, request_id, fee, [0xC3; 32], 1, 1)
}

fn result_transaction_with_commitment(
    operator: Address,
    request_id: AiRequestId,
    fee: u64,
    output_commitment: [u8; 32],
    result_nonce: u64,
    tx_nonce: u64,
) -> Transaction {
    let result = AiInferenceResult {
        request_id,
        verifier: operator,
        output_commitment,
        output_ref: BoundedBytes::empty(),
        result_nonce,
        signature: vec![1],
        submitted_at_block: 0,
    };
    Transaction::new_with_chain_id(
        operator,
        Address::zero(),
        0,
        fee,
        tx_nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiInferenceResult(result),
    )
}

#[test]
fn signed_lubot_bond_debits_balance_and_registers_role8() {
    let mut state = AccountState::new();
    let operator = Address::from([0x11; 32]);
    let amount = state.registry.params().min_stake;
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, amount + fee);
    let committed_before = state.total_bud_committed();

    let tx = Transaction::new_lubot_operator_bond(operator, amount, fee, 0, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &tx).expect("valid Lubot bond must apply");

    let registration = state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .expect("RoleId(8) registration must exist");
    assert_eq!(registration.stake, amount);
    assert!(state.registry.is_active(&operator, roles::LUBOT_OPERATOR));
    assert_eq!(state.get_balance(&operator), 0);
    assert_eq!(state.accounts.get(&operator).expect("account").nonce, 1);
    assert_eq!(
        state.total_bud_committed(),
        committed_before - fee as u128,
        "bonded principal must remain in the committed-supply denominator"
    );
}

#[test]
fn lubot_bond_floor_matches_each_known_network_validator_floor() {
    let state = AccountState::new();
    assert_eq!(
        state.required_lubot_bond(
            crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value()
        ),
        crate::core::chain_config::Network::Mainnet.min_stake()
    );
    assert_eq!(
        state.required_lubot_bond(
            crate::core::chain_config::Network::Testnet
                .chain_id()
                .value()
        ),
        crate::core::chain_config::Network::Testnet.min_stake()
    );
    assert_eq!(
        state.required_lubot_bond(DEFAULT_CHAIN_ID),
        crate::core::chain_config::Network::Devnet.min_stake()
    );
}

#[test]
fn below_floor_lubot_bond_is_atomic() {
    let mut state = AccountState::new();
    let operator = Address::from([0x22; 32]);
    let floor = state.registry.params().min_stake;
    assert!(floor > 0);
    let amount = floor - 1;
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, amount + fee);
    let balance_before = state.get_balance(&operator);

    let tx = Transaction::new_lubot_operator_bond(operator, amount, fee, 0, DEFAULT_CHAIN_ID);
    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("below-floor Lubot bond must fail closed");

    assert!(err.contains("below network validator floor"));
    assert_eq!(state.get_balance(&operator), balance_before);
    assert!(state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .is_none());
    assert_eq!(state.accounts.get(&operator).expect("account").nonce, 0);
}

#[test]
fn mainnet_lubot_bond_rejects_devnet_sized_principal() {
    let mut state = AccountState::new();
    let operator = Address::from([0x23; 32]);
    let amount = crate::core::chain_config::Network::Devnet.min_stake();
    let required = crate::core::chain_config::Network::Mainnet.min_stake();
    let fee = state.base_fee.max(1);
    assert!(amount < required);
    state.add_balance(&operator, amount + fee);

    let tx = Transaction::new_lubot_operator_bond(
        operator,
        amount,
        fee,
        0,
        crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value(),
    );
    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("mainnet must reject a devnet-sized Lubot bond");

    assert!(err.contains("network validator floor"));
    assert_eq!(state.get_balance(&operator), amount + fee);
    assert!(state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .is_none());
}

#[test]
fn lubot_unbond_waits_seven_epochs_and_withdraws_principal() {
    let mut state = AccountState::new();
    let operator = Address::from([0x24; 32]);
    let bond_amount = state.required_lubot_bond(DEFAULT_CHAIN_ID);
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, bond_amount + fee * 3);

    let bond =
        Transaction::new_lubot_operator_bond(operator, bond_amount, fee, 0, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &bond).expect("bond");
    let unbond = Transaction::new_lubot_operator_unbond(operator, fee, 1, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &unbond).expect("begin unbond");

    let release_epoch = match state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .expect("registration")
        .status
    {
        crate::registry::MemberStatus::Unbonding { release_epoch } => release_epoch,
        other => panic!("expected unbonding, got {other:?}"),
    };
    assert_eq!(release_epoch, 7);
    assert!(!state.registry.is_active(&operator, roles::LUBOT_OPERATOR));

    let withdraw = Transaction::new_lubot_operator_withdraw(operator, fee, 2, DEFAULT_CHAIN_ID);
    let balance_before_early_withdraw = state.get_balance(&operator);
    let early_error = Executor::apply_transaction(&mut state, &withdraw)
        .expect_err("withdrawal before release epoch must fail");
    assert!(
        early_error.contains("still unbonding"),
        "got: {early_error}"
    );
    assert_eq!(state.get_balance(&operator), balance_before_early_withdraw);

    state.epoch_index = release_epoch;
    Executor::apply_transaction(&mut state, &withdraw).expect("mature withdrawal");
    assert!(state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .is_none());
    assert_eq!(state.get_balance(&operator), bond_amount);
    assert_eq!(state.accounts.get(&operator).expect("account").nonce, 3);
}

#[test]
fn unresolved_lubot_result_blocks_unbonding() {
    let mut state = AccountState::new();
    let operator = Address::from([0x25; 32]);
    let bond_amount = state.required_lubot_bond(DEFAULT_CHAIN_ID);
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, bond_amount + fee * 3);
    let bond =
        Transaction::new_lubot_operator_bond(operator, bond_amount, fee, 0, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &bond).expect("bond");

    let (spec, request) = model_and_request(operator);
    state.ai_registry.register_model(spec).expect("model");
    state
        .ai_registry
        .submit_request(request.clone(), 0)
        .expect("request");
    let result = result_transaction(operator, request.request_id, fee);
    Executor::apply_transaction(&mut state, &result).expect("result");

    let unbond = Transaction::new_lubot_operator_unbond(operator, fee, 2, DEFAULT_CHAIN_ID);
    let error = Executor::apply_transaction(&mut state, &unbond)
        .expect_err("open inference duty must block unbonding");
    assert!(error.contains("open inference or dispute obligations"));
    assert!(state.registry.is_active(&operator, roles::LUBOT_OPERATOR));

    state.current_block_height = crate::ai::registry::DISPUTE_WINDOW_BLOCKS + 1;
    Executor::apply_transaction(&mut state, &unbond)
        .expect("unbonding must open after task and dispute windows close");
    assert!(!state.registry.is_active(&operator, roles::LUBOT_OPERATOR));
}

#[test]
fn pos_validator_without_lubot_bond_cannot_submit_result() {
    let mut state = AccountState::new();
    let operator = Address::from([0x33; 32]);
    let fee = state.base_fee.max(1);
    let validator_stake = state.registry.params().min_stake;
    state.add_validator(operator, validator_stake);
    state.add_balance(&operator, fee);
    assert!(state.registry.is_active(&operator, roles::VALIDATOR));
    assert!(!state.registry.is_active(&operator, roles::LUBOT_OPERATOR));

    let (spec, request) = model_and_request(operator);
    state.ai_registry.register_model(spec).expect("model");
    state
        .ai_registry
        .submit_request(request.clone(), 0)
        .expect("request");
    let tx = result_transaction(operator, request.request_id, fee);

    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("PoS membership must not imply Lubot authorization");
    assert!(err.contains("active bonded LUBOT_OPERATOR"));
    assert!(!state.ai_registry.results.contains_key(&request.request_id));
    assert_eq!(state.get_balance(&operator), fee);
}

#[test]
fn bonded_lubot_operator_can_submit_result() {
    let mut state = AccountState::new();
    let operator = Address::from([0x44; 32]);
    let amount = state.registry.params().min_stake;
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, amount + fee + fee);

    let bond = Transaction::new_lubot_operator_bond(operator, amount, fee, 0, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &bond).expect("bond");

    let (spec, request) = model_and_request(operator);
    state.ai_registry.register_model(spec).expect("model");
    state
        .ai_registry
        .submit_request(request.clone(), 0)
        .expect("request");
    let result = result_transaction(operator, request.request_id, fee);
    Executor::apply_transaction(&mut state, &result).expect("bonded result must apply");

    let results = state
        .ai_registry
        .results
        .get(&request.request_id)
        .expect("result must be recorded");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].verifier, operator);
    assert!(state.ai_registry.get_outcome(&request.request_id).is_none());
    assert_eq!(state.accounts.get(&operator).expect("account").nonce, 2);
    assert_eq!(state.get_balance(&operator), 0);
}

#[test]
fn conflicting_signed_result_commits_evidence_and_burns_only_role8_bond() {
    let mut state = AccountState::new();
    let operator = Address::from([0x55; 32]);
    let reporter = Address::from([0x56; 32]);
    let bond_amount = state.required_lubot_bond(DEFAULT_CHAIN_ID);
    let fee = state.base_fee.max(1);
    state.add_balance(&operator, bond_amount + fee * 4);
    state.add_balance(&reporter, fee);

    let bond =
        Transaction::new_lubot_operator_bond(operator, bond_amount, fee, 0, DEFAULT_CHAIN_ID);
    Executor::apply_transaction(&mut state, &bond).expect("bond");

    let validator_stake = 2_000;
    state.add_validator(operator, validator_stake);
    let (spec, request) = model_and_request(operator);
    state.ai_registry.register_model(spec).expect("model");
    state
        .ai_registry
        .submit_request(request.clone(), 0)
        .expect("request");

    let first =
        result_transaction_with_commitment(operator, request.request_id, fee, [0xC3; 32], 1, 1);
    Executor::apply_transaction(&mut state, &first).expect("first result");
    let conflicting =
        result_transaction_with_commitment(operator, request.request_id, fee, [0xD4; 32], 2, 2);
    Executor::apply_transaction(&mut state, &conflicting)
        .expect("conflicting signed result must commit evidence");
    assert!(state
        .ai_registry
        .is_disputable(&request.request_id, &operator, 0));
    let unbond = Transaction::new_lubot_operator_unbond(operator, fee, 3, DEFAULT_CHAIN_ID);
    let unbond_error = Executor::apply_transaction(&mut state, &unbond)
        .expect_err("live dispute must block unbonding");
    assert!(unbond_error.contains("open inference or dispute obligations"));

    let committed_before_slash = state.total_bud_committed();
    let slash_tx = Transaction::new_with_chain_id(
        reporter,
        Address::zero(),
        0,
        fee,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiDisputeSlash {
            request_id: request.request_id,
            verifier: operator,
        },
    );
    Executor::apply_transaction(&mut state, &slash_tx).expect("equivocation slash");

    let registration = state
        .registry
        .get(&operator, roles::LUBOT_OPERATOR)
        .expect("slashed registration remains auditable");
    assert!(matches!(
        registration.status,
        crate::registry::MemberStatus::Slashed
    ));
    assert_eq!(registration.stake, 0);
    assert!(!state.registry.is_active(&operator, roles::LUBOT_OPERATOR));
    assert_eq!(
        state.validators.get(&operator).expect("validator").stake,
        validator_stake,
        "Lubot application evidence must not erase independent PoS stake"
    );
    assert_eq!(
        state.total_bud_committed(),
        committed_before_slash - bond_amount as u128 - fee as u128
    );
    assert!(!state
        .ai_registry
        .has_equivocated(&request.request_id, &operator));
}

/// The tier the requester signed is the tier the chain stores.
///
/// `AiInferenceRequest::effort` was added to `calculate_id` so an operator
/// cannot accept deep work and answer it shallow while claiming the deeper
/// fee. That only holds if the id really moves with the tier and the registry
/// really refuses a request whose id does not derive from its own fields. Both
/// halves are asserted here, because either one alone leaves the promise open.
#[test]
fn the_effort_tier_is_inside_the_request_identity() {
    use crate::lubot::effort::EffortTier;

    let requester = Address::from([0x51; 32]);
    let (_spec, baseline) = model_and_request(requester);

    let mut deep = baseline.clone();
    deep.effort = EffortTier::from_tenths(50).expect("5.0x is a valid tier");
    deep.request_id = deep.calculate_id();

    assert_ne!(
        baseline.request_id, deep.request_id,
        "a 1.0x request and a 5.0x request must not share an id"
    );
    assert!(baseline.verify_id() && deep.verify_id());
}

/// Rewriting the tier after the fact must invalidate the id.
///
/// This is the attack the field exists to stop: take a signed `5.0x` request,
/// change the tier to `0.5x`, do the cheap work, and claim the expensive fee.
/// The id no longer derives from the fields, so `verify_id` fails and
/// `submit_request` refuses.
#[test]
fn a_rewritten_effort_tier_is_rejected_by_the_registry() {
    use crate::lubot::effort::EffortTier;

    let requester = Address::from([0x52; 32]);
    let (spec, mut request) = model_and_request(requester);
    request.effort = EffortTier::from_tenths(50).expect("5.0x is a valid tier");
    request.request_id = request.calculate_id();

    let mut state = AccountState::new();
    state.ai_registry.register_model(spec).expect("model");

    // The operator downgrades the work it was asked for and keeps the id.
    let mut downgraded = request.clone();
    downgraded.effort = EffortTier::FASTEST;
    assert!(
        !downgraded.verify_id(),
        "a request whose tier was rewritten must not verify"
    );

    let err = state
        .ai_registry
        .submit_request(downgraded, 0)
        .expect_err("the registry must refuse a request whose id does not match its fields");
    assert!(
        err.contains("canonical preimage"),
        "unexpected refusal reason: {err}"
    );

    // The untouched request is still accepted, so the refusal above is about
    // the rewrite and not about the tier being present at all.
    state
        .ai_registry
        .submit_request(request.clone(), 0)
        .expect("the tier the requester signed must still be accepted");
    assert_eq!(
        state
            .ai_registry
            .requests
            .get(&request.request_id)
            .expect("stored")
            .effort,
        EffortTier::from_tenths(50).unwrap(),
        "the stored request must carry the tier that was signed"
    );
}

/// A request that predates the field reads as `1.0x`, not as zero.
///
/// `#[serde(default)]` and the wire-decode both map an absent tier to the
/// baseline. Zero is not a legal tier, so reading it literally would produce a
/// value `from_tenths` refuses, and a stored request would become unloadable.
#[test]
fn a_request_without_an_effort_field_reads_as_the_baseline() {
    use crate::lubot::effort::EffortTier;

    let requester = Address::from([0x53; 32]);
    let (_spec, request) = model_and_request(requester);
    let mut value = serde_json::to_value(&request).expect("serialize");
    value
        .as_object_mut()
        .expect("request serializes as an object")
        .remove("effort")
        .expect("the field is there to remove");

    let restored: AiInferenceRequest =
        serde_json::from_value(value).expect("a request written before the field must still load");
    assert_eq!(restored.effort, EffortTier::BASELINE);
    assert_eq!(
        restored.request_id, request.request_id,
        "the baseline default must reproduce the same id"
    );
}

/// The wire refuses a tier the type would refuse.
///
/// The proto field is a `uint32` and the Rust type is a bounded `u16`, so a
/// peer can put `20.0x`, or `u32::MAX`, on the wire. Decoding has to apply the
/// same range check the constructor does, otherwise the bound exists only for
/// callers that go through Rust.
#[test]
fn an_out_of_range_effort_tier_is_refused_on_the_wire() {
    use crate::lubot::effort::EffortTier;
    use crate::network::proto_conversions::pb;

    let requester = Address::from([0x54; 32]);
    let (_spec, mut request) = model_and_request(requester);
    request.effort = EffortTier::from_tenths(50).expect("5.0x");
    request.request_id = request.calculate_id();

    let tx = Transaction::new_with_chain_id(
        requester,
        Address::zero(),
        0,
        1,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiInferenceRequest(request),
    );
    let proto = pb::ProtoTransaction::from(&tx);

    // Round-tripping unchanged keeps the tier.
    let back = Transaction::try_from(proto.clone()).expect("valid tier round-trips");
    match back.tx_type {
        TransactionType::AiInferenceRequest(req) => {
            assert_eq!(req.effort, EffortTier::from_tenths(50).unwrap());
        }
        other => panic!("wrong transaction type: {other:?}"),
    }

    for smuggled in [200u32, 101, u32::from(u16::MAX) + 1, u32::MAX] {
        let mut tampered = proto.clone();
        match tampered.type_payload {
            Some(pb::proto_transaction::TypePayload::AiInferenceRequest(ref mut p)) => {
                p.effort_tenths = smuggled;
            }
            _ => panic!("expected an AiInferenceRequest payload"),
        }
        assert!(
            Transaction::try_from(tampered).is_err(),
            "effort_tenths {smuggled} is outside 0.5x..=10.0x and must be refused"
        );
    }
}

#[test]
fn finalized_lubot_output_is_bridged_to_socialfi_nft() {
    let mut state = AccountState::new();
    let requester = Address::from([0x51; 32]);
    let operator = Address::from([0x52; 32]);
    let fee = state.base_fee.max(1);

    let (spec, request) = model_and_request(requester);
    state.ai_registry.register_model(spec).expect("model");

    // The operators: a LUBOT_OPERATOR bond, granting the authority to sign
    // results. The registry accepts one result per verifier (anti-duplication and
    // anti-equivocation), so a threshold of 2 needs two SEPARATE operators.
    let operator2 = Address::from([0x53; 32]);
    let bond_amount = state.required_lubot_bond(DEFAULT_CHAIN_ID);
    for op in [operator, operator2] {
        state.add_balance(&op, bond_amount + fee * 2);
        let bond = Transaction::new_lubot_operator_bond(op, bond_amount, fee, 0, DEFAULT_CHAIN_ID);
        Executor::apply_transaction(&mut state, &bond).expect("bond");
    }

    // The request: the executor path, including the perception acceptance gate.
    state.add_balance(&requester, request.max_fee + fee);
    let req_tx = Transaction::new_with_chain_id(
        requester,
        Address::zero(),
        0,
        fee,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiInferenceRequest(request.clone()),
    );
    Executor::apply_transaction(&mut state, &req_tx).expect("request");

    // Two matching results (threshold=2, two separate operators) lead to
    // finalization and the NFT bridge.
    let output = b"lubot-finalized-output".to_vec();
    let commitment = [0xC3; 32];
    for (tx_nonce, op) in [(1u64, operator), (2u64, operator2)] {
        let res = AiInferenceResult {
            request_id: request.request_id,
            verifier: op,
            output_commitment: commitment,
            output_ref: BoundedBytes::try_new(output.clone()).unwrap(),
            result_nonce: 1,
            signature: vec![1],
            submitted_at_block: 0,
        };
        let tx = Transaction::new_with_chain_id(
            op,
            Address::zero(),
            0,
            fee,
            tx_nonce,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::AiInferenceResult(res),
        );
        Executor::apply_transaction(&mut state, &tx).expect("result");
    }

    // Proof of the bridge: the ContentId of the output is registered as an NFT
    // belonging to the requester (WIRING: wired).
    let cid = crate::storage::content_id::ContentId::of(&output);
    let bridged = state
        .nft_registry
        .nfts
        .values()
        .any(|n| n.content_id == cid && n.owner == requester);
    assert!(
        bridged,
        "finalized output must be bridged as a requester-owned NFT"
    );

    // Proof of the reverse direction (the Pollen bridge): the same output is
    // registered as a DataAsset, the manifest of its owner, readable through the
    // grant mechanism.
    let asset_id = crate::pollen::data_rights::DataAsset::derive_id(&requester, &cid, &commitment);
    assert!(
        state.marketplace.data_assets.contains_key(&asset_id),
        "finalized output must be registered as a Pollen DataAsset"
    );
}

#[test]
fn ai_model_register_charges_governance_fee_exactly() {
    let mut state = AccountState::new();
    let owner = Address::from([0x61; 32]);
    let fee = state.base_fee.max(1);
    let reg_fee = state.registry.params().ai_model_register_fee;
    assert!(reg_fee > 0, "the test assumes the fee is on by default");
    state.add_balance(&owner, reg_fee + fee);

    let (spec, _request) = model_and_request(owner);
    let tx = Transaction::new_with_chain_id(
        owner,
        Address::zero(),
        reg_fee, // exact cost: the full fee
        fee,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiModelRegister(spec.clone()),
    );
    Executor::apply_transaction(&mut state, &tx).expect("paid registration must apply");

    assert!(state.ai_registry.models.contains_key(&spec.model_id));
    // Exact cost: reg_fee plus tx.fee is deducted, and nothing else.
    assert_eq!(state.get_balance(&owner), 0);
}

#[test]
fn ai_model_register_below_fee_is_rejected_atomically() {
    let mut state = AccountState::new();
    let owner = Address::from([0x62; 32]);
    let fee = state.base_fee.max(1);
    let reg_fee = state.registry.params().ai_model_register_fee;
    assert!(reg_fee > 0);
    let balance = reg_fee + fee;
    state.add_balance(&owner, balance);

    let (spec, _request) = model_and_request(owner);
    let tx = Transaction::new_with_chain_id(
        owner,
        Address::zero(),
        reg_fee - 1, // below reg_fee; the balance suffices, so the specific gate fires
        fee,
        0,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::AiModelRegister(spec.clone()),
    );
    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("below-fee registration must fail closed");
    assert!(
        err.contains("AI model registration requires amount"),
        "got: {err}"
    );
    assert!(!state.ai_registry.models.contains_key(&spec.model_id));
    assert_eq!(
        state.get_balance(&owner),
        balance,
        "atomic: no deduction may happen"
    );
}

// -- effort.rs rule 2: the declared capacity governs what is servable --
//
// `tier_is_servable` had been written but was called from nowhere, because
// there was no place for an operator to declare its ceiling.
// `verifier_effort_ceilings` is that place; the tests below pin down both that
// the gate works and that it is not vacuous.

#[test]
fn tavan_ilan_edilmeden_varsayilan_baseline() {
    use crate::ai::registry::{AiRegistry, DEFAULT_OPERATOR_CEILING};
    use crate::lubot::effort::EffortTier;

    let reg = AiRegistry::new();
    let operator = Address::from([0x11; 32]);
    assert_eq!(reg.effort_ceiling(&operator), DEFAULT_OPERATOR_CEILING);
    assert_eq!(reg.effort_ceiling(&operator), EffortTier::BASELINE);
}

#[test]
fn stakesiz_operator_tavan_ilan_edemez() {
    use crate::ai::registry::AiRegistry;
    use crate::lubot::effort::EffortTier;

    let mut reg = AiRegistry::new();
    let operator = Address::from([0x12; 32]);
    // No stake means no authority, so the declaration has to be refused.
    assert!(reg
        .declare_effort_ceiling(&operator, EffortTier::DEEPEST)
        .is_err());
    assert_eq!(reg.effort_ceiling(&operator), EffortTier::BASELINE);
}

#[test]
fn a_request_above_the_ceiling_is_refused_fail_closed() {
    use crate::ai::registry::{AiRegistry, MIN_VERIFIER_STAKE};
    use crate::lubot::effort::EffortTier;

    let mut reg = AiRegistry::new();
    let operator = Address::from([0x13; 32]);
    reg.lock_verifier_stake(&operator, MIN_VERIFIER_STAKE)
        .unwrap();
    // The operator declares it can serve up to 2.0x.
    let ceiling = EffortTier::from_tenths(20).unwrap();
    reg.declare_effort_ceiling(&operator, ceiling).unwrap();

    // Below the ceiling and exactly at it are servable.
    assert!(reg.unservable_reason(EffortTier::BASELINE).is_none());
    assert!(reg.unservable_reason(ceiling).is_none());

    // Above the ceiling is fail-closed: it is not silently downgraded.
    let reason = reg
        .unservable_reason(EffortTier::DEEPEST)
        .expect("10.0x is above the 2.0x ceiling and should have been refused");
    assert!(
        reason.contains("exceeds every declared operator ceiling"),
        "{reason}"
    );
}

#[test]
fn a_request_above_the_ceiling_is_refused_by_submit_request() {
    use crate::ai::registry::{AiRegistry, MIN_VERIFIER_STAKE};
    use crate::lubot::effort::EffortTier;

    let requester = Address::from([0x14; 32]);
    let (spec, mut request) = model_and_request(requester);

    let mut reg = AiRegistry::new();
    reg.register_model(spec).unwrap();

    let operator = Address::from([0x15; 32]);
    reg.lock_verifier_stake(&operator, MIN_VERIFIER_STAKE)
        .unwrap();
    reg.declare_effort_ceiling(&operator, EffortTier::BASELINE)
        .unwrap();

    // The baseline request is accepted - the gate is not vacuous, so this side
    // has to pass.
    assert!(reg.submit_request(request.clone(), 0).is_ok());

    // The 10.0x request is refused.
    request.effort = EffortTier::DEEPEST;
    request.request_id = request.calculate_id();
    let err = reg
        .submit_request(request, 0)
        .expect_err("a request above the ceiling should have been refused at admission");
    assert!(err.contains("unservable"), "{err}");
}

#[test]
fn a_request_is_not_refused_when_no_operator_is_present() {
    use crate::ai::registry::AiRegistry;
    use crate::lubot::effort::EffortTier;

    // The absence of an operator is a liveness problem, not an admission one:
    // operators may join after the request.
    let reg = AiRegistry::new();
    assert!(reg.unservable_reason(EffortTier::DEEPEST).is_none());
}

#[test]
fn tavan_state_root_a_girer() {
    use crate::ai::registry::{AiRegistry, MIN_VERIFIER_STAKE};
    use crate::lubot::effort::EffortTier;

    let operator = Address::from([0x16; 32]);
    let mut a = AiRegistry::new();
    a.lock_verifier_stake(&operator, MIN_VERIFIER_STAKE)
        .unwrap();
    let mut b = a.clone();

    a.declare_effort_ceiling(&operator, EffortTier::BASELINE)
        .unwrap();
    b.declare_effort_ceiling(&operator, EffortTier::DEEPEST)
        .unwrap();

    // The ceiling changes the admission decision; if it does not enter the
    // state_root, two nodes resolve the same request differently and never notice.
    assert_ne!(a.state_root(), b.state_root());
}

#[test]
fn slash_tavani_da_kaldirir() {
    use crate::ai::registry::{AiRegistry, MIN_VERIFIER_STAKE};
    use crate::lubot::effort::EffortTier;

    let operator = Address::from([0x17; 32]);
    let mut reg = AiRegistry::new();
    reg.lock_verifier_stake(&operator, MIN_VERIFIER_STAKE)
        .unwrap();
    reg.declare_effort_ceiling(&operator, EffortTier::DEEPEST)
        .unwrap();
    assert_eq!(reg.effort_ceiling(&operator), EffortTier::DEEPEST);

    // Once the stake is fully withdrawn, the declaration falls with it.
    reg.withdraw_verifier_stake(&operator, MIN_VERIFIER_STAKE, 0)
        .unwrap();
    assert_eq!(reg.effort_ceiling(&operator), EffortTier::BASELINE);
}
