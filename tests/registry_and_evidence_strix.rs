use budlum_core::core::address::Address;
use budlum_core::crypto::facts::QuantumClass;
use budlum_core::registry::evidence::{
    DoubleSignKind, EvidenceError, SlashingProof, SlashingReport,
};
use budlum_core::registry::permissionless::{PermissionlessRegistry, RegistryError};
use budlum_core::registry::role::roles;
use budlum_core::settlement::domains::CommitmentAttestation;
use budlum_core::settlement::finality_gate::{
    check_certificate_value_gate, check_certificate_value_gate_with_proof_level,
    enforce_domain_not_refuted, enforce_required_binds, ProofLivenessCheck, ProofRequirement,
    ValueGate, ValueGateRefusal,
};
use budlum_core::settlement::registries::SettlementRegistries;
use budlum_core::settlement::universal_finality::{
    compose, DomainFinalityEntry, FinalityBinds, FinalityGuarantee, FinalityPendingReason,
    FinalityReversibility, FinalityVerdict, FINALITY_BINDS_ALL,
};

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
fn finality_gate_enforces_event_root_floor_and_fail_closed_missing_domain_binds() {
    // 1. Standalone `enforce_required_binds` must fail closed (`DomainMissing`)
    // when a non-empty commitment binding is demanded for an absent domain,
    // while `enforce_domain_not_refuted` defers empty-registry preflight when
    // zero consensus domains exist (documented at `FAIL_OPEN_RATCETI.json`).
    let empty_regs = SettlementRegistries::new();
    enforce_domain_not_refuted(&empty_regs, 10, ValueGate::BridgeMint, 77)
        .expect("empty domain registry produces None certificate");

    let narrow_binds = FinalityBinds::STATE_ROOT
        .union(FinalityBinds::TX_ROOT)
        .union(FinalityBinds::PARENT);

    let cert = compose(&[
        DomainFinalityEntry {
            domain_id: 1,
            height: 51,
            checkpoint_height: 100,
            state_root: [1u8; 32],
            adapter_id: "pow-header-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x11; 32],
            guarantee_backing_hash: [0x22; 32],
            bond_atoms: 10_000_000,
            binds: FinalityBinds::ALL,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: 5_000,
            },
            verdict: FinalityVerdict::Established,
        },
        DomainFinalityEntry {
            domain_id: 2,
            height: 52,
            checkpoint_height: 100,
            state_root: [2u8; 32],
            adapter_id: "pow-header-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x33; 32],
            guarantee_backing_hash: [0x44; 32],
            bond_atoms: 10_000_000,
            // Pending row carrying narrow commitments (no EVENT_ROOT) so we can
            // verify both standalone `enforce_required_binds` bit-set checks and
            // verdict-before-binds ordering on `check_certificate_value_gate`.
            binds: narrow_binds,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation: CommitmentAttestation {
                    state_root: true,
                    tx_root: true,
                    event_root: false,
                    parent: true,
                },
                slashable_backing: true,
                fault_tolerance_bps: 5_000,
            },
            verdict: FinalityVerdict::Pending {
                reason: FinalityPendingReason::AttestationUnbound,
            },
        },
    ])
    .expect("compose certificate");

    // Absent domain fails closed with `DomainMissing` whenever required_binds is non-empty!
    assert_eq!(
        enforce_required_binds(&cert, 999, FinalityBinds::EVENT_ROOT),
        Err(ValueGateRefusal::DomainMissing { domain_id: 999 }),
        "enforce_required_binds must refuse missing domain instead of returning Ok(())"
    );
    enforce_required_binds(&cert, 999, FinalityBinds::NONE)
        .expect("empty demand imposes no binding requirement");

    // Narrow row lacking EVENT_ROOT is refused with both sets at `enforce_required_binds`.
    assert_eq!(
        enforce_required_binds(&cert, 2, FinalityBinds::EVENT_ROOT),
        Err(ValueGateRefusal::RequiredBindMissing {
            domain_id: 2,
            required_binds: FinalityBinds::EVENT_ROOT,
            present_binds: narrow_binds,
        })
    );
    let strengthened_demand = FinalityBinds::EVENT_ROOT.union(FinalityBinds::STATE_ROOT);
    assert_eq!(
        enforce_required_binds(&cert, 2, strengthened_demand),
        Err(ValueGateRefusal::RequiredBindMissing {
            domain_id: 2,
            required_binds: strengthened_demand,
            present_binds: narrow_binds,
        })
    );

    let sentry = budlum_core::cross_domain::external::sentry::ConsensusSentry::new();

    // Pending/Refuted/Missing checks precede binding checks for both source and target.
    for gate in [
        ValueGate::BridgeMint,
        ValueGate::BridgeUnlock,
        ValueGate::RelayerIntentSettle,
        ValueGate::AppBindingClaim,
        ValueGate::ObjectLayerArrive,
        ValueGate::UniversalPayment,
    ] {
        assert_eq!(
            check_certificate_value_gate(&cert, &sentry, gate, 2, None, FinalityBinds::NONE),
            Err(ValueGateRefusal::DomainPending {
                domain_id: 2,
                reason: FinalityPendingReason::AttestationUnbound,
            })
        );
        assert_eq!(
            check_certificate_value_gate(&cert, &sentry, gate, 1, Some(2), FinalityBinds::NONE),
            Err(ValueGateRefusal::DomainPending {
                domain_id: 2,
                reason: FinalityPendingReason::AttestationUnbound,
            })
        );
        assert_eq!(
            check_certificate_value_gate(&cert, &sentry, gate, 1, Some(999), FinalityBinds::NONE),
            Err(ValueGateRefusal::DomainMissing { domain_id: 999 })
        );
        let ok = check_certificate_value_gate_with_proof_level(
            &cert,
            &sentry,
            gate,
            1,
            None,
            FinalityBinds::STATE_ROOT,
            ProofLivenessCheck {
                block_height: 100,
                proven_height: 100,
                requirement: ProofRequirement::ProvenRequired,
            },
        )
        .expect("fully bound Established domain passes gate floor + caller demand");
        assert_eq!(ok.gate, gate);
    }
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

#[test]
fn enforce_domain_not_refuted_distinguishes_empty_registry_from_registered_refuted_and_pending_domains(
) {
    use budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
    use budlum_core::domain::types::{ConsensusDomain, ConsensusKind, DomainStatus, RootScheme};
    use budlum_core::settlement::universal_finality::FinalityPendingReason;

    let mut regs = SettlementRegistries::new();
    // 1. Empty registry (`domains.is_empty()`): passes preflight for local/dev flows.
    enforce_domain_not_refuted(&regs, 50, ValueGate::BridgeMint, 42)
        .expect("empty domain registry is allowed pre-ceremony");

    let mk_domain = |id: u32, status: DomainStatus, height: u64, hash: [u8; 32]| ConsensusDomain {
        id,
        kind: ConsensusKind::Bft,
        status,
        domain_chain_id: 90_000 + u64::from(id),
        operator: Some(Address::from([0x22; 32])),
        operator_bond: MIN_DOMAIN_OPERATOR_BOND,
        config_hash: [0xA2; 32],
        validator_set_hash: [0xB2; 32],
        finality_adapter: "tendermint-v1".into(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: height,
        last_committed_hash: hash,
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0x01; 32],
    };

    // 2. Registered domain claiming non-zero height without a bound commitment fails closed (`EvidenceMissing`).
    regs.domains
        .register(mk_domain(42, DomainStatus::Active, 7, [0xEE; 32]))
        .expect("register domain 42");
    assert_eq!(
        enforce_domain_not_refuted(&regs, 50, ValueGate::BridgeMint, 42),
        Err(ValueGateRefusal::DomainPending {
            domain_id: 42,
            reason: FinalityPendingReason::EvidenceMissing,
        })
    );

    // 3. Frozen domain in registry composes into `Refuted` bucket (`code: 1`) and fails closed (`DomainRefuted`).
    regs.domains
        .register(mk_domain(43, DomainStatus::Active, 0, [0u8; 32]))
        .expect("register domain 43");
    regs.domains
        .set_status(43, DomainStatus::Frozen)
        .expect("freeze domain 43");
    assert_eq!(
        enforce_domain_not_refuted(&regs, 50, ValueGate::BridgeUnlock, 43),
        Err(ValueGateRefusal::DomainRefuted {
            domain_id: 43,
            code: 1,
        })
    );
}
