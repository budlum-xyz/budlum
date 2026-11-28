//! Regression integration tests for PR #215 (`testnet-50`) hardening fixes:
//! 1. `pollen::offers::MarketplaceRegistry::create_offer`: saturates at
//!    `u64::MAX` (`saturating_add(1)`), issues `u64::MAX` at most once, and
//!    preserves any sentinel `u64::MAX` listing across `MAX_OFFERS` retention
//!    so deactivation + eviction cannot re-issue `u64::MAX`.
//! 2. `cross_domain::economic_guard::BridgeEconomicGuard::queue_large_withdrawal`:
//!    fails closed when `next_withdrawal_nonce` reaches `u64::MAX` instead of
//!    saturating and overwriting queued withdrawals.
//! 3. `cross_domain::external::auxpow_pop::AuxPowPopAdapter`: enforces invalid
//!    compact target validation in `has_pinned_trust_anchor()` and exercises
//!    committee-less PoW-only `admit_observed` + `fault_probes()`.

use budlum_core::core::address::Address;
use budlum_core::cross_domain::economic_guard::{
    BridgeEconomicGuard, DomainCeilingPolicy, EconomicGuardError,
};
use budlum_core::cross_domain::external::auxpow_pop::{
    encode_auxpow_evidence, expand_compact_bits, expected_auxpow_slot, AuxBlockCommitment,
    AuxPowPopAdapter, AuxPowPopEvidence, PinnedAuxPowAnchor, AUXPOW_COINBASE_MAGIC,
};
use budlum_core::cross_domain::external::bitcoin_spv::sha256d;
use budlum_core::cross_domain::external::selftest::admit_observed;
use budlum_core::cross_domain::external::spec::{
    AdapterError, AdapterId, ExternalFinalityAdapter, RawConsensusEvidence, SecurityBacking,
    VerificationPolicy,
};
use budlum_core::crypto::facts::{CryptoFacts, ObservedScheme, QuantumClass};
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::pollen::offers::{DataOffer, MarketplaceRegistry, MAX_OFFERS};
use budlum_core::settlement::universal_finality::{
    compose, DomainFinalityEntry, FinalityBinds, FinalityGuarantee, FinalityReversibility,
    FinalityVerdict,
};
use budlum_core::storage::content_id::ContentId;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

const fn addr(b: u8) -> Address {
    Address([b; 32])
}

#[test]
fn offers_u64_max_is_issued_once_and_sentinel_preserved_across_retain() {
    let mut reg = MarketplaceRegistry::new();
    let seller = addr(1);
    let rival = addr(2);
    let cid = ContentId([0xEE; 32]);
    reg.next_offer_id = u64::MAX - 1;

    let id = must(
        reg.create_offer(seller, cid, 50, 7),
        "u64::MAX - 1 should still be issued cleanly",
    );
    assert_eq!(id, u64::MAX - 1);
    assert_eq!(reg.next_offer_id, u64::MAX);

    let last_id = must(
        reg.create_offer(seller, cid, 50, 7),
        "u64::MAX should be issued once before saturation blocks reuse",
    );
    assert_eq!(last_id, u64::MAX);
    assert_eq!(reg.next_offer_id, u64::MAX);
    assert!(
        reg.create_offer(rival, cid, 50, 7).is_err(),
        "saturated counter must refuse re-minting live u64::MAX"
    );

    if let Some(entry) = reg.offers.get_mut(&u64::MAX) {
        entry.active = false;
    }
    for i in 0..(MAX_OFFERS - 1) {
        let oid = must(u64::try_from(i), "index fits u64");
        reg.offers.insert(
            oid,
            DataOffer {
                id: oid,
                seller,
                cid,
                price: 10,
                active: false,
                created_at_block: 1,
            },
        );
    }
    assert!(
        reg.create_offer(rival, cid, 50, 8).is_err(),
        "deactivated u64::MAX offer must survive eviction so u64::MAX is never re-issued"
    );
    assert!(reg.offers.contains_key(&u64::MAX));
    assert_eq!(reg.offers.get(&u64::MAX).map(|o| o.seller), Some(seller));
}

#[test]
fn economic_guard_refuses_u64_max_withdrawal_nonce_saturation() {
    let mut guard = BridgeEconomicGuard::new();
    let policy = DomainCeilingPolicy {
        backing: SecurityBacking::SignatureSet {
            scheme: budlum_core::crypto::facts::ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 4,
            required: 3,
            total_weight: 100_000,
            slashable: true,
        },
        window_blocks: 100,
        ..DomainCeilingPolicy::default()
    };
    must(
        guard.configure_domain(42, policy, None),
        "configure domain 42",
    );

    let mut val = must(serde_json::to_value(&guard), "serialize guard");
    val["next_withdrawal_nonce"] = serde_json::json!(u64::MAX);
    let mut saturated: BridgeEconomicGuard = must(serde_json::from_value(val), "deserialize guard");
    let root_before = saturated.root();

    match saturated.queue_large_withdrawal(42, addr(0xAA), 1_000, 10) {
        Err(EconomicGuardError::InvalidPolicy(_)) => {}
        other => panic!("saturated withdrawal nonce must fail closed, got: {other:?}"),
    }
    assert_eq!(
        saturated.root(),
        root_before,
        "refusal must not mutate state"
    );
}

fn dsha_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256d(&buf)
}

fn mine_header(prev: [u8; 32], merkle_root: [u8; 32], ts: u32, bits: u32) -> (Vec<u8>, [u8; 32]) {
    let target = must(expand_compact_bits(bits), "valid bits");
    let mut hdr = vec![0u8; 80];
    hdr[0..4].copy_from_slice(&2i32.to_le_bytes());
    hdr[4..36].copy_from_slice(&prev);
    hdr[36..68].copy_from_slice(&merkle_root);
    hdr[68..72].copy_from_slice(&ts.to_le_bytes());
    hdr[72..76].copy_from_slice(&bits.to_le_bytes());
    for nonce in 0u32..=u32::MAX {
        hdr[76..80].copy_from_slice(&nonce.to_le_bytes());
        let raw_hash = sha256d(&hdr);
        let mut be_hash = raw_hash;
        be_hash.reverse();
        if be_hash <= target {
            return (hdr, raw_hash);
        }
    }
    panic!("easy target mines within a few attempts");
}

#[test]
fn auxpow_pop_committee_less_anchor_pin_and_fault_probes_hold() {
    const NET: &str = "doge-pop-mainnet";
    const EASY_BITS: u32 = 0x207f_ffff;
    const AUX_CHAIN_ID: u32 = 98;

    let mut aux_block = AuxBlockCommitment {
        aux_chain_id: AUX_CHAIN_ID,
        aux_height: 88_000,
        timestamp_secs: 1_750_100_000,
        state_root: [0x51; 32],
        tx_root: [0x52; 32],
        event_root: [0x53; 32],
        digest: [0u8; 32],
    };
    aux_block.digest = aux_block.compute_digest(NET);

    let tree_depth = 2u32;
    let tree_size = 1u32 << tree_depth;
    let merkle_nonce = 7u32;
    let slot = expected_auxpow_slot(AUX_CHAIN_ID, merkle_nonce, tree_depth);
    let mut leaves = [[0x10u8; 32], [0x20u8; 32], [0x30u8; 32], [0x40u8; 32]];
    leaves[slot as usize] = aux_block.digest;
    let sib0 = leaves[(slot ^ 1) as usize];
    let n01 = dsha_pair(&leaves[0], &leaves[1]);
    let n23 = dsha_pair(&leaves[2], &leaves[3]);
    let sib1 = if slot < 2 { n23 } else { n01 };
    let aux_merkle_root = dsha_pair(&n01, &n23);

    let mut coinbase_tx = Vec::new();
    coinbase_tx.extend_from_slice(b"\x01\x00\x00\x00coinbase-prefix:");
    coinbase_tx.extend_from_slice(&AUXPOW_COINBASE_MAGIC);
    coinbase_tx.extend_from_slice(&aux_merkle_root);
    coinbase_tx.extend_from_slice(&tree_size.to_le_bytes());
    coinbase_tx.extend_from_slice(&merkle_nonce.to_le_bytes());
    coinbase_tx.extend_from_slice(b":suffix");

    let cb_hash = sha256d(&coinbase_tx);
    let other_tx = [0x99u8; 32];
    let parent_merkle_root = dsha_pair(&cb_hash, &other_tx);

    let trusted_parent_hash = [0x07u8; 32];
    let mut parent_headers = Vec::new();
    let mut prev = trusted_parent_hash;
    for i in 0u8..6 {
        let mr = if i == 0 {
            parent_merkle_root
        } else {
            [0x60 + i; 32]
        };
        let (hdr, h) = mine_header(prev, mr, 1_750_100_000 + u32::from(i) * 60, EASY_BITS);
        parent_headers.push(hdr);
        prev = h;
    }

    let mut min_work = [0u8; 32];
    min_work[31] = 12;
    let pinned = PinnedAuxPowAnchor {
        aux_chain_id: AUX_CHAIN_ID,
        trusted_parent_hash,
        max_target_bits: EASY_BITS,
        min_cumulative_work: min_work,
        min_confirmations: 6,
        pop_signers: Vec::new(),
    };

    let mut bad_pinned = pinned.clone();
    bad_pinned.max_target_bits = 0;
    assert!(!AuxPowPopAdapter::new(NET, Some(bad_pinned)).has_pinned_trust_anchor());

    let bundle = AuxPowPopEvidence {
        aux_block: aux_block.clone(),
        parent_headers,
        coinbase_tx,
        coinbase_index: 0,
        coinbase_branch: vec![other_tx],
        aux_slot_index: slot,
        aux_branch: vec![sib0, sib1],
        pop_sigs: Vec::new(),
    };
    let payload = must(
        encode_auxpow_evidence(&bundle),
        "encode no-committee bundle",
    );
    let raw = RawConsensusEvidence {
        adapter: AdapterId::from_name("auxpow-pop-v1"),
        evidence_version: 1,
        network: NET.into(),
        declared_height: aux_block.aux_height,
        declared_root: aux_block.state_root,
        payload,
        submitter: addr(0x22),
    };
    let adapter = AuxPowPopAdapter::new(NET, Some(pinned)).with_golden(raw.clone());
    assert!(adapter.has_pinned_trust_anchor());

    let policy = VerificationPolicy {
        min_depth: 6,
        max_age: 1_000,
        now: 88_100,
        require_declared_match: true,
        require_slashable: false,
    };
    let (report, admit_facts) = admit_observed(&adapter, &policy);
    assert!(report.golden_verified);
    assert!(
        report.admitted,
        "committee-less auxpow-pop must admit and pass all fault probes; failing={:?}",
        report.failing_probe_names()
    );
    assert!(admit_facts.is_empty());

    let mut verify_facts = CryptoFacts::new();
    let att = must(
        adapter.verify_observed(&raw, &policy, &mut verify_facts),
        "committee-less auxpow-pop verifies under unslashable-allowed policy",
    );
    assert!(matches!(att.security, SecurityBacking::Work { .. }));
    assert!(verify_facts.is_empty());

    let mut slash_policy = policy;
    slash_policy.require_slashable = true;
    assert!(matches!(
        adapter.verify(&raw, &slash_policy),
        Err(AdapterError::UnslashableBacking)
    ));
}

#[test]
fn forged_global_finality_certificate_is_refused_without_state_change() {
    let mut guard = BridgeEconomicGuard::new();
    let domain_id = 409u32;
    let policy = DomainCeilingPolicy {
        backing: SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Secp256k1,
            signers: 4,
            required: 3,
            total_weight: 300_000,
            slashable: true,
        },
        stake_haircut_bps: 3_333,
        window_blocks: 100,
        ..DomainCeilingPolicy::default()
    };
    must(
        guard.configure_domain(domain_id, policy, None),
        "configure domain 409",
    );

    let cert = must(
        compose(&[DomainFinalityEntry {
            domain_id,
            height: 12,
            checkpoint_height: 50,
            state_root: [0x11; 32],
            adapter_id: "cometbft-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x22; 32],
            guarantee_backing_hash: [0x33; 32],
            bond_atoms: 300_000,
            binds: FinalityBinds::ALL,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: QuantumClass::Hash,
                attestation: budlum_core::settlement::universal_finality::FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: 3_333,
            },
            verdict: FinalityVerdict::Established,
        }]),
        "compose valid finality certificate",
    );

    let mut forged = cert.clone();
    forged.certificate_digest[0] ^= 0xFF;

    let root_before = guard.root();
    let res = guard.check_and_record_flow_with_certificate(domain_id, 1_000, 50, &forged);
    assert!(
        matches!(res, Err(EconomicGuardError::InvalidEvidence(_))),
        "forged certificate digest must fail closed with InvalidEvidence, got: {res:?}"
    );
    assert_eq!(
        guard.root(),
        root_before,
        "forged certificate must not mutate economic guard state"
    );
}

#[test]
fn verification_policy_require_slashable_refuses_unslashable_backing() {
    use budlum_core::cross_domain::external::spec::ProofSystem;

    let policy = VerificationPolicy {
        require_slashable: true,
        ..VerificationPolicy::strict(1_000)
    };
    let unslashable = [
        SecurityBacking::None,
        SecurityBacking::Authority { count: 4 },
        SecurityBacking::Work {
            difficulty_bits: 80,
        },
        SecurityBacking::Zk {
            system: ProofSystem::Stark,
            public_inputs_digest: [0x11; 32],
        },
        SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 4,
            required: 3,
            total_weight: 100_000,
            slashable: false,
        },
    ];
    for backing in unslashable {
        assert_eq!(
            policy.admits_backing(&backing),
            Err(AdapterError::UnslashableBacking),
            "require_slashable=true must refuse {backing:?}"
        );
    }
    let slashable = SecurityBacking::SignatureSet {
        scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
        signers: 4,
        required: 3,
        total_weight: 100_000,
        slashable: true,
    };
    assert_eq!(policy.admits_backing(&slashable), Ok(()));
}

#[test]
fn tendermint_misbehaviour_slash_refuses_forged_next_validators_hash_and_anchor_mismatch() {
    use budlum_core::core::chain_config::Network;
    use budlum_core::cross_domain::external::intake::{
        AdapterSpec, IntakeError, IntakeState, RegistrationRequest,
    };
    use budlum_core::cross_domain::external::registry::RegistryError;
    use budlum_core::cross_domain::external::spec::DomainKey;
    use budlum_core::cross_domain::external::tendermint::{
        validator_address_of, validator_set_commitment, validator_set_hash, vote_sign_bytes,
        PinnedTendermintAnchor, TendermintCommitEvidence, TendermintLightParams,
        TendermintMisbehaviour, TendermintSignature, TendermintValidator, TrustedTendermintState,
        EVIDENCE_VERSION,
    };
    use budlum_core::cross_domain::external::versioning::VersionPolicy;
    use budlum_core::crypto::primitives::KeyPair;
    use budlum_core::domain::plugin::default_domain;
    use budlum_core::domain::ConsensusKind;
    use budlum_core::settlement::domains::{
        register_domain, SettlementTxContext, SettlementTxError,
    };
    use budlum_core::settlement::shared_security::execute_tendermint_misbehaviour_slash;
    use budlum_core::AccountState;

    let keys: Vec<KeyPair> = (80u8..=83)
        .map(|s| must(KeyPair::from_seed(&[s; 32]), "tendermint key"))
        .collect();
    let tm_vals: Vec<TendermintValidator> = keys
        .iter()
        .map(|k| {
            let pk = k.public_key_bytes();
            TendermintValidator {
                address: validator_address_of(&pk),
                public_key: pk,
                voting_power: 100,
            }
        })
        .collect();
    let chain_id = "provider-ics-1";
    let network = "ics-provider";
    let set_hash = validator_set_hash(&tm_vals);
    let set_commitment = validator_set_commitment(&tm_vals);
    let ts = 1_790_000_600u64;
    let parts = [0x33u8; 32];

    let mk_commit =
        |height: u64, app_hash: [u8; 32], signers: &[usize]| -> TendermintCommitEvidence {
            let mut c = TendermintCommitEvidence {
                chain_id: chain_id.to_string(),
                height,
                round: 0,
                block_hash: [0u8; 32],
                parts_total: 1,
                parts_hash: parts,
                version_block: 11,
                last_block_hash: [0x11; 32],
                last_parts_total: 1,
                last_parts_hash: [0x22; 32],
                last_commit_hash: [0x33; 32],
                data_hash: [0x44; 32],
                validators_hash: set_hash,
                next_validators_hash: set_hash,
                consensus_hash: [0x66; 32],
                app_hash,
                last_results_hash: [0x88; 32],
                evidence_hash: [0xaa; 32],
                proposer_address: tm_vals[0].address,
                commit_time: ts,
                commit_time_nanos: 0,
                validators: tm_vals.clone(),
                signatures: Vec::new(),
            };
            c.block_hash = c.header_hash();
            c.signatures = signers
                .iter()
                .map(|&i| {
                    let msg = vote_sign_bytes(
                        chain_id,
                        height,
                        0,
                        &c.block_hash,
                        1,
                        &parts,
                        (i64::try_from(ts).expect("ts fits i64"), 0),
                    );
                    TendermintSignature {
                        address: tm_vals[i].address,
                        timestamp_seconds: i64::try_from(ts).expect("ts fits i64"),
                        timestamp_nanos: 0,
                        signature: keys[i].sign(&msg).to_vec(),
                    }
                })
                .collect();
            c
        };

    let golden_commit = mk_commit(900, [0x51; 32], &[0, 1, 2]);
    let spec = AdapterSpec::TendermintCommit {
        network: network.to_string(),
        chain_id: chain_id.to_string(),
        validator_set_hash: Some(set_commitment),
    };
    let adapter_id = AdapterId::from_name(&format!("tendermint-commit-{network}"));
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond_atoms = economics.required_bond_atoms();
    let payload = must(bincode::serialize(&golden_commit), "encode tm golden");
    let mut intake = IntakeState::new();
    intake.pin_tendermint_anchor(
        network,
        PinnedTendermintAnchor {
            chain_id: chain_id.to_string(),
            validator_set_hash: set_commitment,
        },
    );
    let key = must(
        intake.register_domain(
            RegistrationRequest {
                spec,
                policy: VerificationPolicy {
                    min_depth: 1,
                    max_age: 1_000,
                    now: ts + 10,
                    require_declared_match: true,
                    require_slashable: true,
                },
                economics,
                versions: VersionPolicy::single(adapter_id, EVIDENCE_VERSION, 0),
                bond_atoms,
                poster: addr(0x41),
                golden: RawConsensusEvidence {
                    adapter: adapter_id,
                    evidence_version: EVIDENCE_VERSION,
                    network: network.to_string(),
                    payload,
                    declared_height: 900,
                    declared_root: golden_commit.app_hash,
                    submitter: addr(0x42),
                },
            },
            None,
        ),
        "register pinned Tendermint domain",
    );

    let light_params = must(
        TendermintLightParams::standard_for_unbonding(1_814_400),
        "valid standard unbonding params",
    );
    let forged_trusted = TrustedTendermintState {
        chain_id: chain_id.to_string(),
        height: 900,
        time_secs: ts,
        trusting_period_secs: light_params.trusting_period_secs,
        validators: tm_vals.clone(),
        next_validators_hash: [0xEE; 32],
    };
    let honest_next = mk_commit(901, [0x52; 32], &[0, 1, 2]);
    let misbehaviour = TendermintMisbehaviour {
        header_1: honest_next.clone(),
        header_2: None,
    };
    let intake_res = intake.adjudicate_tendermint_misbehaviour(
        &key,
        &forged_trusted,
        &light_params,
        &misbehaviour,
        ts + 10,
    );
    assert!(
        matches!(
            intake_res,
            Err(IntakeError::Registry(RegistryError::Adapter(
                AdapterError::ConsensusRule { .. }
            )))
        ),
        "intake adjudicate_tendermint_misbehaviour must refuse forged next_validators_hash: {intake_res:?}"
    );

    // Also verify shared-security execution refuses a domain with an unpinned/mismatched
    // DomainKey in `domain.config_hash`.
    let dom_id = 778u32;
    let dom_op = addr(0x51);
    let mut state = AccountState::new();
    let mut domain = default_domain(
        dom_id,
        ConsensusKind::Custom("tendermint-bft".to_string()),
        778_001,
        budlum_core::cross_domain::external::EXTERNAL_DOMAIN_FINALITY_ADAPTER,
        1,
    );
    domain.operator = Some(dom_op);
    domain.plugin_code_hash = Some([0x77; 32]);
    domain.config_hash = DomainKey::from_parts(&adapter_id, "wrong-network").0;
    state.add_balance(&dom_op, domain.operator_bond.saturating_add(10));
    must(
        register_domain(&mut state, domain),
        "register mismatched domain",
    );
    state.settlement.external_intake.pin_tendermint_anchor(
        network,
        PinnedTendermintAnchor {
            chain_id: chain_id.to_string(),
            validator_set_hash: set_hash,
        },
    );
    let ctx = SettlementTxContext {
        sender: addr(0x52),
        chain_id: Network::Devnet.chain_id().value(),
        fee: 5,
        bls: IntakeState::production_bls,
    };
    let legitimate_trusted = TrustedTendermintState {
        next_validators_hash: set_commitment,
        ..forged_trusted
    };
    let ss_res = execute_tendermint_misbehaviour_slash(
        &mut state,
        &ctx,
        dom_id,
        &legitimate_trusted,
        &light_params,
        &TendermintMisbehaviour {
            header_1: honest_next,
            header_2: Some(mk_commit(901, [0x53; 32], &[1, 2, 3])),
        },
        ts + 10,
    );
    assert!(
        matches!(ss_res, Err(SettlementTxError::Refused(_))),
        "shared-security slash must refuse domain.config_hash anchor mismatch: {ss_res:?}"
    );
}
