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
    };
    let mut request = AiInferenceRequest {
        request_id: AiRequestId::default(),
        requester,
        model_id,
        input_commitment: [0xB2; 32],
        input_ref: BoundedBytes::empty(),
        max_fee: 100,
        callback: None,
        submitted_at_block: 0,
        deadline_block: 100,
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
        state.required_lubot_bond(1),
        crate::core::chain_config::Network::Mainnet.min_stake()
    );
    assert_eq!(
        state.required_lubot_bond(42),
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

    let tx = Transaction::new_lubot_operator_bond(operator, amount, fee, 0, 1);
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
