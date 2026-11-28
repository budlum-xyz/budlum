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
