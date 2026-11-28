use budlum_core::core::address::Address;
use budlum_core::registry::evidence::{
    DoubleSignKind, EvidenceError, SlashingProof, SlashingReport,
};
use budlum_core::registry::permissionless::{PermissionlessRegistry, RegistryError};
use budlum_core::registry::role::roles;

#[test]
fn permissionless_registry_refuses_zero_address_duplicate_deser_and_empty_double_sign_hashes() {
    let mut reg = PermissionlessRegistry::new();
    assert_eq!(
        reg.register(Address::zero(), roles::VALIDATOR, 10_000, 0),
        Err(RegistryError::ZeroAddress)
    );
    reg.upsert_stake(Address::zero(), roles::VALIDATOR, 10_000, 0);
    assert!(reg.get(&Address::zero(), roles::VALIDATOR).is_none());

    let member = Address::from([42u8; 32]);
    reg.register(member, roles::VALIDATOR, 10_000, 0).unwrap();
    let mut json: serde_json::Value = serde_json::to_value(&reg).unwrap();
    let first = json["registrations"][0].clone();
    json["registrations"].as_array_mut().unwrap().push(first);
    let dup: Result<PermissionlessRegistry, _> = serde_json::from_value(json);
    assert!(
        dup.is_err(),
        "duplicate (role, account) in serialized registrations must fail closed"
    );

    let empty_ds = SlashingReport::new(
        member,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            kind: DoubleSignKind::BlockHeader,
            height: 12,
            epoch: None,
            block_hash_1: "0x".into(),
            block_hash_2: "0xdeadbeef".into(),
            signature_1: vec![1; 64],
            signature_2: vec![2; 64],
        },
        None,
    );
    assert_eq!(
        empty_ds.validate_shape(),
        Err(EvidenceError::NonConflictingHashes)
    );

    let blank_tag = SlashingReport::new(
        member,
        roles::VALIDATOR,
        SlashingProof::Other {
            tag: "   ".into(),
            data: vec![1],
        },
        None,
    );
    assert_eq!(
        blank_tag.validate_shape(),
        Err(EvidenceError::EmptyProofTag)
    );
}

#[test]
fn ceremony_refuses_missing_pq_scheme_while_legacy_validate_pq_scheme_stays_compatible() {
    use budlum_core::chain::genesis::GenesisConfig;
    use budlum_core::core::chain_config::Network;

    // 1. Legacy configs without `pq_scheme` still pass bare `validate_pq_scheme()`.
    let mut cfg = GenesisConfig::for_network(Network::Testnet);
    cfg.pq_scheme = None;
    assert!(cfg.validate_pq_scheme().is_ok());

    // 2. Consensus ceremony validation fails closed immediately when `pq_scheme` is None or blank!
    let err_none = cfg
        .validate_consensus_ceremony(Network::Testnet)
        .expect_err("ceremony must refuse missing pq_scheme");
    assert!(
        err_none.contains("pq_scheme"),
        "ceremony refusal must name missing pq_scheme, got: {err_none}"
    );

    cfg.pq_scheme = Some("   ".to_string());
    let err_blank = cfg
        .validate_consensus_ceremony(Network::Testnet)
        .expect_err("ceremony must refuse blank pq_scheme");
    assert!(
        err_blank.contains("pq_scheme"),
        "ceremony refusal must name blank pq_scheme, got: {err_blank}"
    );
}

#[test]
fn previously_untested_six_fail_open_gates_enforce_fail_closed_boundaries() {
    use bud_isa::{Instruction, Opcode};
    use budlum_core::chain::genesis::GenesisConfig;
    use budlum_core::core::account::AccountState;
    use budlum_core::core::chain_config::Network;
    use budlum_core::cross_domain::economic_guard::{BridgeEconomicGuard, EconomicGuardError};
    use budlum_core::cross_domain::evm::sync_committee::{
        EthereumExecutionLightClient, ExecutionPayloadHeader, SyncCommitteeError,
        VerifiedExecutionPayload,
    };
    use budlum_core::domain::types::{ConsensusDomain, ConsensusKind, DomainStatus, RootScheme};
    use budlum_core::object_layer::rule::{verify_program_rule, ClassSlice, RuleRefusal};
    use budlum_core::settlement::domains::{
        enforce_relayer_route_finality_and_ceiling, SettlementTxError,
    };
    use budlum_core::settlement::liquidation_proof::{
        validate_liquidation_params, AmmReserveSnapshot, LiquidationError, LiquidationPosition,
    };
    use budlum_core::settlement::AnchorKeyLedger;
    use std::collections::BTreeSet;

    // Gate 1: `validate_anchor_ledger` - None passes ceremony pre-anchor, wrong chain_id or empty keys fail closed.
    let mut gen_cfg = GenesisConfig::for_network(Network::Testnet);
    gen_cfg.anchor_ledger = None;
    assert!(gen_cfg.validate_anchor_ledger().is_ok());

    gen_cfg.anchor_ledger = Some(AnchorKeyLedger {
        chain_id: gen_cfg.chain_id + 999,
        key_epoch: 0,
        anchor_keys: Vec::new(),
        seal_keys: Vec::new(),
        suspended: BTreeSet::new(),
        revoked_key_hashes: BTreeSet::new(),
    });
    assert!(gen_cfg
        .validate_anchor_ledger()
        .expect_err("wrong chain_id anchor_ledger must fail closed")
        .contains("Genesis anchor ledger is for chain"));

    gen_cfg.anchor_ledger = Some(AnchorKeyLedger {
        chain_id: gen_cfg.chain_id,
        key_epoch: 0,
        anchor_keys: Vec::new(),
        seal_keys: Vec::new(),
        suspended: BTreeSet::new(),
        revoked_key_hashes: BTreeSet::new(),
    });
    assert!(gen_cfg
        .validate_anchor_ledger()
        .expect_err("malformed empty-key anchor_ledger must fail closed")
        .contains("Genesis anchor ledger refused"));

    // Gate 2: `check_and_record_flow_inner` - production guard fails closed on unconfigured domains.
    let mut strict_guard = BridgeEconomicGuard::production();
    assert_eq!(
        strict_guard.check_and_record_flow_inner(77, 1_000, 10, false),
        Err(EconomicGuardError::UnknownDomain(77))
    );
    assert_eq!(
        strict_guard.check_and_record_flow_inner(77, 1_000, 10, true),
        Err(EconomicGuardError::UnknownDomain(77))
    );
    let mut dev_guard = BridgeEconomicGuard::new();
    assert!(dev_guard
        .check_and_record_flow_inner(77, 1_000, 10, false)
        .is_ok());

    // Gate 3: `check_monotonic_advance` - None passes bootstrap, regressed/conflicting beacon slots fail closed.
    let make_exec = |slot: u64, block_num: u64, ts: u64, block_byte: u8, parent_byte: u8| {
        VerifiedExecutionPayload {
            beacon_slot: slot,
            beacon_header_root: [block_byte; 32],
            beacon_state_root: [0x22; 32],
            beacon_body_root: [0x33; 32],
            execution_payload_root: [block_byte; 32],
            payload: ExecutionPayloadHeader {
                parent_hash: [parent_byte; 32],
                fee_recipient: [0x11; 20],
                state_root: [0x44; 32],
                receipts_root: [0x55; 32],
                logs_bloom: vec![0u8; 256],
                prev_randao: [0x66; 32],
                block_number: block_num,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: ts,
                extra_data: Vec::new(),
                base_fee_per_gas: [0u8; 32],
                block_hash: [block_byte; 32],
                transactions_root: [0x77; 32],
                withdrawals_root: [0x88; 32],
                blob_gas_used: 0,
                excess_blob_gas: 0,
            },
            signers: 512,
        }
    };
    let e0 = make_exec(100, 50, 1_700_000_000, 0xA1, 0xA0);
    let e_regressed = make_exec(99, 51, 1_700_000_012, 0xA2, 0xA1);
    let e_conflict = make_exec(100, 50, 1_700_000_000, 0xB9, 0xA0);
    let e_bad_parent = make_exec(101, 51, 1_700_000_012, 0xA2, 0xFF);
    let e_next = make_exec(101, 51, 1_700_000_012, 0xA2, 0xA1);

    assert!(EthereumExecutionLightClient::check_monotonic_advance(None, &e0).is_ok());
    assert!(matches!(
        EthereumExecutionLightClient::check_monotonic_advance(Some(&e0), &e_regressed),
        Err(SyncCommitteeError::NonMonotonicFinality(_))
    ));
    assert!(matches!(
        EthereumExecutionLightClient::check_monotonic_advance(Some(&e0), &e_conflict),
        Err(SyncCommitteeError::NonMonotonicFinality(_))
    ));
    assert!(matches!(
        EthereumExecutionLightClient::check_monotonic_advance(Some(&e0), &e_bad_parent),
        Err(SyncCommitteeError::NonMonotonicFinality(_))
    ));
    assert!(EthereumExecutionLightClient::check_monotonic_advance(Some(&e0), &e_next).is_ok());

    // Gate 4: `verify_program_rule` - empty slice passes, orphan proof / non-8B bytecode / failed VM fail closed.
    assert!(verify_program_rule(&ClassSlice::new()).is_ok());
    let mut orphan = ClassSlice::new();
    orphan.insert(String::from("program_proof"), vec![1, 2, 3]);
    assert_eq!(verify_program_rule(&orphan), Err(RuleRefusal::WrongShape));

    let mut bad_len = ClassSlice::new();
    bad_len.insert(String::from("program_bytecode"), vec![1, 2, 3]);
    assert_eq!(verify_program_rule(&bad_len), Err(RuleRefusal::WrongShape));

    let fail_word = Instruction {
        opcode: Opcode::Assert,
        rd: 0,
        rs1: 1,
        rs2: 0,
        imm: 0,
    }
    .encode()
    .to_le_bytes()
    .to_vec();
    let mut fail_prog = ClassSlice::new();
    fail_prog.insert(String::from("program_bytecode"), fail_word);
    assert_eq!(verify_program_rule(&fail_prog), Err(RuleRefusal::Paused));

    // Gate 5: `enforce_relayer_route_finality_and_ceiling` - Pending domain leg in certificate fails closed.
    let mut state = AccountState::new();
    state.current_block_height = 25;
    assert!(enforce_relayer_route_finality_and_ceiling(&state, 1, 9, 500).is_ok());

    state
        .settlement
        .domains
        .register(ConsensusDomain {
            id: 9,
            kind: ConsensusKind::Bft,
            status: DomainStatus::Active,
            domain_chain_id: 70_009,
            operator: Some(Address::from([0x10; 32])),
            operator_bond: budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
            config_hash: [0xA1; 32],
            validator_set_hash: [0xB1; 32],
            finality_adapter: "tendermint-v1".into(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: 0,
            last_committed_hash: [0u8; 32],
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
            genesis_state_root: [0x01; 32],
        })
        .expect("register pending domain");
    let route_err = enforce_relayer_route_finality_and_ceiling(&state, 1, 9, 500)
        .expect_err("Pending domain leg must fail closed");
    assert!(
        matches!(route_err, SettlementTxError::Refused(ref m) if m.contains("pending domain 9")),
        "unexpected error: {route_err:?}"
    );

    // Gate 6: `validate_liquidation_params` - empty positions pass, malformed observations or oversized batch fail closed.
    assert!(validate_liquidation_params(&[], &[]).is_ok());
    let pos = LiquidationPosition {
        position_id: 1,
        debt_x: 100,
        collateral_y: 50,
        maintenance_threshold_bps: 15_000,
    };
    assert!(validate_liquidation_params(&[], std::slice::from_ref(&pos)).is_err());
    let obs = [
        AmmReserveSnapshot {
            state_root: [1u8; 32],
            epoch: 1,
            reserve_x: 100,
            reserve_y: 200,
            proof: Vec::new(),
        },
        AmmReserveSnapshot {
            state_root: [2u8; 32],
            epoch: 2,
            reserve_x: 100,
            reserve_y: 200,
            proof: Vec::new(),
        },
        AmmReserveSnapshot {
            state_root: [3u8; 32],
            epoch: 3,
            reserve_x: 100,
            reserve_y: 200,
            proof: Vec::new(),
        },
    ];
    assert!(validate_liquidation_params(&obs, std::slice::from_ref(&pos)).is_ok());
    let oversized: Vec<LiquidationPosition> = (0..101)
        .map(|i| LiquidationPosition {
            position_id: i,
            debt_x: 100,
            collateral_y: 50,
            maintenance_threshold_bps: 15_000,
        })
        .collect();
    assert!(matches!(
        validate_liquidation_params(&obs, &oversized),
        Err(LiquidationError::BatchTooLarge { .. })
    ));
}
