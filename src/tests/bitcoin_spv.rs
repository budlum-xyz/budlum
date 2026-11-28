//! End-to-end tests for the Nakamoto (Bitcoin SPV) branch of the
//! consensus-of-consensuses: registration, admission, the external-domain
//! bridge, and the settlement commitment that feeds the global header.
//!
//! These tests use real Bitcoin mainnet headers 0..=6, pinned as hex. The
//! evidence carries headers 1..=6 on top of a pinned genesis checkpoint, so
//! the derived height is 6 and the accrued work is six real blocks.

use crate::core::address::Address;
use crate::cross_domain::external::bitcoin_spv::{
    sha256d, spv_evidence, BitcoinSpvAdapter, ChainWork256, PinnedBitcoinAnchor, HEADER_LEN,
};
use crate::cross_domain::external::spec::{
    ExternalFinalityAdapter, FinalityAttestation, RawConsensusEvidence, SecurityBacking,
    VerificationPolicy,
};
use crate::cross_domain::external::{
    admit, decode_external_evidence, encode_external_evidence, AdapterSpec as Spec,
    ExternalDomainFinalityBridge, IntakeError, IntakeState, RegistrationRequest, VersionPolicy,
    EXTERNAL_DOMAIN_FINALITY_ADAPTER,
};
use crate::domain::finality_adapter::{DomainFinalityAdapter, FinalityProof, FinalityStatus};
use crate::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
};

const MAINNET_HEADERS: [&str; 7] = [
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
    "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
    "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
    "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
    "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
    "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
];

fn headers() -> Vec<[u8; HEADER_LEN]> {
    MAINNET_HEADERS
        .iter()
        .map(|h| {
            let raw = hex::decode(h).expect("pinned header hex");
            let mut out = [0u8; HEADER_LEN];
            out.copy_from_slice(&raw);
            out
        })
        .collect()
}

fn anchor() -> PinnedBitcoinAnchor {
    PinnedBitcoinAnchor {
        height: 0,
        block_hash: sha256d(headers()[0].as_slice()),
        bits: 0x1d00_ffff,
    }
}

fn adapter() -> BitcoinSpvAdapter {
    BitcoinSpvAdapter::new("mainnet", Some(anchor()))
}

/// The policy clock is just after the last real header's timestamp. The
/// adapter has no clock of its own: `now` is supplied by the caller so the
/// same evidence verifies identically on every node.
fn policy() -> VerificationPolicy {
    VerificationPolicy {
        min_depth: 1,
        require_declared_match: true,
        max_age: 0,
        now: 1_231_500_000,
        require_slashable: false,
    }
}

fn golden() -> RawConsensusEvidence {
    let bytes = headers();
    let descendants: Vec<&[u8; HEADER_LEN]> = bytes.iter().skip(1).collect();
    spv_evidence(
        &adapter(),
        "mainnet",
        &descendants,
        Address::from([1u8; 32]),
    )
}

fn request(spec: Spec) -> RegistrationRequest {
    let adapter = spec.build(None, None);
    let economics = IntakeState::conservative_economics(1_000_000);
    RegistrationRequest {
        spec,
        policy: policy(),
        economics,
        versions: VersionPolicy::single(adapter.descriptor().id, 1, 0),
        bond_atoms: economics.required_bond_atoms(),
        poster: Address::from([9u8; 32]),
        golden: golden(),
    }
}

fn bitcoin_spec() -> Spec {
    Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: Some(anchor()),
    }
}

fn domain_and_commitment(
    evidence: &RawConsensusEvidence,
    proof: &FinalityProof,
) -> (ConsensusDomain, DomainCommitment) {
    let attestation: FinalityAttestation = adapter()
        .verify(evidence, &policy())
        .expect("golden evidence verifies");
    let domain = ConsensusDomain {
        id: 7,
        kind: ConsensusKind::Custom("nakamoto-pow".to_string()),
        status: DomainStatus::Active,
        domain_chain_id: 77,
        operator: Some(Address::from([4u8; 32])),
        operator_bond: 1_000_000,
        config_hash: [0; 32],
        validator_set_hash: [0; 32],
        finality_adapter: EXTERNAL_DOMAIN_FINALITY_ADAPTER.to_string(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 6,
        last_committed_hash: [6; 32],
        pow_parameters: None,
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0; 32],
    };
    let commitment = DomainCommitment {
        domain_id: 7,
        domain_height: attestation.height,
        domain_block_hash: attestation.state_root,
        parent_domain_block_hash: [4; 32],
        state_root: attestation.state_root,
        tx_root: attestation
            .attested_tx_root
            .expect("the adapter attests a tx root"),
        event_root: [0; 32],
        finality_proof_hash: crate::domain::hash_finality_proof(proof).expect("proof hashes"),
        consensus_kind: domain.kind.clone(),
        validator_set_hash: [0; 32],
        timestamp_ms: 0,
        sequence: 1,
        producer: None,
        state_updates: std::collections::BTreeMap::new(),
    };
    (domain, commitment)
}

/// RED before the adapter was wired: this variant did not exist. The test
/// pins the whole path from permissionless registration to a settlement
/// commitment that a `GlobalBlockHeader` can anchor.
#[test]
fn bitcoin_spv_domain_registers_and_passes_admission() {
    let mut state = IntakeState::new();
    // Self-supplied anchor before governance pinning must fail closed.
    let unpinned_err = state
        .register_domain(request(bitcoin_spec()), None)
        .expect_err("self-supplied unpinned Bitcoin checkpoint must be refused");
    assert_eq!(unpinned_err, IntakeError::CommitteeNotPinned);

    state.pin_bitcoin_anchor("mainnet", anchor());

    // A registrant supplying a forged regtest checkpoint on a pinned network
    // must also be refused.
    let forged_spec = Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: Some(PinnedBitcoinAnchor {
            height: 0,
            block_hash: [0xee; 32],
            bits: 0x207f_ffff,
        }),
    };
    let forged_err = state
        .register_domain(request(forged_spec), None)
        .expect_err("forged regtest checkpoint must be refused");
    assert_eq!(forged_err, IntakeError::CommitteeNotPinned);

    let key = state
        .register_domain(request(bitcoin_spec()), None)
        .expect("a pinned Bitcoin domain registers end to end");
    let entry = state.entries.get(&key).expect("entry is stored");
    assert!(entry.admission.admitted, "golden and all probes passed");
    assert!(entry.admission.golden_verified);

    // The stored spec rebuilds an adapter that still verifies the golden.
    let rebuilt = entry.spec.build(None, Some(entry.golden.clone()));
    assert!(rebuilt.verify(&entry.golden, &entry.policy).is_ok());
}

/// A domain with no pinned checkpoint must be refused at the door, not
/// admitted with a checkpoint the submitter can name later.
#[test]
fn an_unpinned_bitcoin_anchor_is_refused_at_registration() {
    let mut state = IntakeState::new();
    let spec = Spec::BitcoinSpv {
        network: "mainnet".to_string(),
        anchor: None,
    };
    assert!(matches!(
        state.register_domain(request(spec), None),
        Err(IntakeError::CommitteeNotPinned)
    ));
}

/// The admission suite is data, not code: every probe must refuse for the
/// exact reason it names, and the golden must verify. An adapter that
/// refuses everything cannot pass this test.
#[test]
fn every_bitcoin_fault_probe_refuses_for_its_named_rule() {
    let adapter = adapter().with_golden(golden());
    let report = admit(&adapter, &policy());
    assert!(report.golden_verified);
    assert!(report.admitted, "report: {report:?}");
    assert!(!report.probes.is_empty());
    for (name, outcome) in &report.probes {
        assert!(outcome.passed(), "probe {name} failed: {outcome:?}");
    }
}

/// The bridge is the seam into consensus. A real SPV proof finalizes a
/// commitment whose roots are exactly the ones the attestation binds.
#[test]
fn bridge_finalizes_a_bitcoin_commitment_end_to_end() {
    let evidence = golden();
    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let decoded = decode_external_evidence(&proof).expect("carrier round trips");
    assert_eq!(decoded, evidence);

    let (domain, commitment) = domain_and_commitment(&evidence, &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), policy());
    assert_eq!(
        bridge
            .verify_finality(&domain, &commitment, &proof)
            .expect("bridge verifies"),
        FinalityStatus::Finalized
    );
}

/// A corrupted header must not reach consensus: the bridge refuses rather
/// than finalizing a commitment built on a broken parent link.
#[test]
fn a_broken_parent_link_is_refused_by_the_bridge() {
    let mut evidence = golden();
    // The first evidence header's parent hash begins at payload offset 8.
    evidence.payload[8] ^= 0xff;
    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let (domain, commitment) = domain_and_commitment(&golden(), &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), policy());
    let result = bridge.verify_finality(&domain, &commitment, &proof);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| { format!("{error:?}").contains("does not link to its parent") }),
        "result: {result:?}"
    );
}

/// Work backing is the first producer of `SecurityBacking::Work`. The bridge
/// enforces a slashable-only policy at its own layer: accumulated work is a
/// different security class and must not be promoted to slashable, so a
/// slashability demand is not cleared by work backing.
#[test]
fn work_backing_does_not_clear_a_slashability_demand() {
    let mut strict = policy();
    strict.require_slashable = true;
    let evidence = golden();
    let attestation = adapter()
        .verify(&evidence, &strict)
        .expect("the adapter still emits work backing");
    assert!(matches!(attestation.security, SecurityBacking::Work { .. }));

    let proof = encode_external_evidence(&evidence).expect("evidence encodes");
    let (domain, commitment) = domain_and_commitment(&evidence, &proof);
    let bridge = ExternalDomainFinalityBridge::new(Box::new(adapter()), strict);
    let status = bridge
        .verify_finality(&domain, &commitment, &proof)
        .expect("the bridge answers");
    assert!(
        matches!(status, FinalityStatus::Rejected(ref message) if message.contains("slashable")),
        "work backing must not satisfy a slashable-only policy: {status:?}"
    );
}

/// STRX-194-01 regression lock: adding a consensus family must not shift the
/// bincode discriminants of the families already persisted in intake state.
/// The new variant is appended, never inserted.
#[test]
fn adapter_spec_variant_indices_stay_pinned() {
    let eth = Spec::EthereumSync {
        network: "testnet".to_string(),
        committee: None,
    };
    let zk = Spec::ZkVm {
        network: "testnet".to_string(),
        program_hash: None,
        chain_id: None,
    };
    let eth_bytes = bincode::serialize(&eth).expect("eth spec serializes");
    let zk_bytes = bincode::serialize(&zk).expect("zk spec serializes");
    let btc_bytes = bincode::serialize(&bitcoin_spec()).expect("btc spec serializes");
    assert_eq!(u32::from_le_bytes(eth_bytes[0..4].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(zk_bytes[0..4].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(btc_bytes[0..4].try_into().unwrap()), 2);
}

/// STRX-194-01 full-pin lock: every persisted adapter family's bincode
/// discriminant is pinned, not just tags 0, 1, 2. An insert or reorder
/// anywhere in `AdapterSpec` fails this test - inserting in the middle would
/// reinterpret every intake registration already persisted in consensus state.
/// New families are APPENDED with a new highest tag and this test is updated
/// in the same commit.
#[test]
fn adapter_spec_all_ten_indices_stay_pinned() {
    let cases: [(Spec, u32); 10] = [
        (
            Spec::EthereumSync {
                network: "n".to_string(),
                committee: None,
            },
            0,
        ),
        (
            Spec::ZkVm {
                network: "n".to_string(),
                program_hash: None,
                chain_id: None,
            },
            1,
        ),
        (
            Spec::BitcoinSpv {
                network: "n".to_string(),
                anchor: None,
            },
            2,
        ),
        (
            Spec::TendermintCommit {
                network: "n".to_string(),
                chain_id: "c".to_string(),
                validator_set_hash: None,
            },
            3,
        ),
        (
            Spec::DataAvailability {
                network: "n".to_string(),
                committee: None,
            },
            4,
        ),
        (
            Spec::HotStuffQc {
                network: "n".to_string(),
                committee: None,
            },
            5,
        ),
        (
            Spec::DagCertificate {
                network: "n".to_string(),
                committee: None,
            },
            6,
        ),
        (
            Spec::CasperFfg {
                network: "n".to_string(),
                committee: None,
            },
            7,
        ),
        (
            Spec::MysticetiDag {
                network: "n".to_string(),
                committee: None,
            },
            8,
        ),
        (
            Spec::BitVmCovenant {
                network: "n".to_string(),
                anchor: None,
            },
            9,
        ),
    ];
    for (spec, want) in cases {
        let bytes = bincode::serialize(&spec).expect("spec serializes");
        let got = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(
            got, want,
            "adapter family moved to bincode tag {got}: persisted intake registrations would be reinterpreted (STRX-194-01)"
        );
    }
}

/// The declared height and root are derived from the headers, not believed
/// from the envelope. This is the replay/index-drift rule made executable.
#[test]
fn declared_height_and_root_cannot_be_lied_about() {
    use crate::cross_domain::external::spec::AdapterError;

    let mut lying_height = golden();
    lying_height.declared_height += 1;
    assert!(matches!(
        adapter().verify(&lying_height, &policy()),
        Err(AdapterError::DeclarationMismatch { field: "height" })
    ));

    let mut lying_root = golden();
    lying_root.declared_root = [7; 32];
    assert!(matches!(
        adapter().verify(&lying_root, &policy()),
        Err(AdapterError::DeclarationMismatch { .. })
    ));
}

/// A short chain is pending by policy, not silently accepted.
#[test]
fn insufficient_spv_depth_is_refused() {
    use crate::cross_domain::external::spec::AdapterError;

    let mut evidence = golden();
    // Keep the count byte at six but remove the trailing header: the length
    // check refuses malformed truncation rather than reading a partial chain.
    evidence
        .payload
        .truncate(evidence.payload.len() - HEADER_LEN);
    assert!(matches!(
        adapter().verify(&evidence, &policy()),
        Err(AdapterError::Malformed { .. })
    ));
}

fn mine_regtest_header(
    parent_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u32,
    bits: u32,
) -> [u8; HEADER_LEN] {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    let mut target = [0u8; 32];
    let start = 32 - (exp - 3) - 3;
    target[start..start + 3].copy_from_slice(&mant.to_be_bytes()[1..4]);

    let mut raw = [0u8; HEADER_LEN];
    raw[0..4].copy_from_slice(&0x2000_0000i32.to_le_bytes());
    raw[4..36].copy_from_slice(&parent_hash);
    raw[36..68].copy_from_slice(&merkle_root);
    raw[68..72].copy_from_slice(&timestamp.to_le_bytes());
    raw[72..76].copy_from_slice(&bits.to_le_bytes());
    for nonce in 0..=u32::MAX {
        raw[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut h = sha256d(&raw);
        h.reverse();
        if h <= target {
            return raw;
        }
    }
    panic!("unreachable for regtest target {bits:08x}");
}

#[test]
fn exact_256_bit_chainwork_matches_bitcoin_core_and_defeats_longer_low_work_fork() {
    use crate::cross_domain::external::bitcoin_spv::{
        select_heaviest_bitcoin_chain, ChainWork256, REGTEST_POW_LIMIT_BITS,
    };

    // Bitcoin Core genesis block `0x1d00ffff`: exact GetBlockProof = 0x1_0001_0001 (4_295_032_833).
    let genesis_work = ChainWork256::from_bits(0x1d00_ffff).expect("genesis work");
    assert_eq!(genesis_work.to_le_words(), [0x0000_0001_0001_0001, 0, 0, 0]);
    assert!(!genesis_work.is_zero());
    assert_eq!(
        ChainWork256::from_be_bytes(genesis_work.to_be_bytes()),
        genesis_work
    );
    assert_eq!(genesis_work.log2_floor(), 32);

    // 6 real Satoshi mainnet blocks accumulate exact `6 * 0x1_0001_0001 = 0x6_0006_0006`.
    let verified_mainnet = adapter()
        .verify_chain(&golden(), &policy())
        .expect("mainnet chain verifies");
    assert_eq!(
        verified_mainnet.total_chainwork.to_le_words(),
        [6 * 0x0000_0001_0001_0001, 0, 0, 0]
    );

    // Fork choice: 6 blocks at 4x harder target (total work 24) beat 10 blocks at 1x target (work 20).
    let root_hash = sha256d(b"fork-root");
    let ts_open = 1_710_000_000u32;
    let base_anchor = PinnedBitcoinAnchor {
        height: 2_015,
        block_hash: root_hash,
        bits: REGTEST_POW_LIMIT_BITS,
    };
    let prior: [u32; 11] = std::array::from_fn(|i| ts_open + 300_000 + (i as u32) * 600);
    let fast_adapter = BitcoinSpvAdapter::new("regtest", Some(base_anchor.clone()))
        .with_epoch_start_timestamp(ts_open)
        .with_prior_timestamps(prior)
        .with_anchor_chainwork(ChainWork256::from_bits(REGTEST_POW_LIMIT_BITS).unwrap());
    let hard_bits =
        crate::cross_domain::external::bitcoin_spv::compute_next_work_required_with_limit(
            ts_open,
            prior[10],
            REGTEST_POW_LIMIT_BITS,
            REGTEST_POW_LIMIT_BITS,
        )
        .unwrap();

    // Shorter 6-block chain at 4x difficulty.
    let mut hard_headers = Vec::new();
    let mut prev = root_hash;
    for i in 0..6u32 {
        let h = mine_regtest_header(
            prev,
            sha256d(&[0xA0, i as u8]),
            prior[10] + 600 * (i + 1),
            hard_bits,
        );
        prev = sha256d(&h);
        hard_headers.push(h);
    }
    let hard_refs: Vec<&[u8; HEADER_LEN]> = hard_headers.iter().collect();
    let hard_ev = spv_evidence(&fast_adapter, "regtest", &hard_refs, Address::from([5; 32]));

    // Longer 10-block chain at 1x difficulty from the same anchor.
    let slow_prior: [u32; 11] =
        std::array::from_fn(|i| ts_open + 1_209_600 - (10 - i as u32) * 600);
    let slow_adapter = BitcoinSpvAdapter::new("regtest", Some(base_anchor))
        .with_epoch_start_timestamp(ts_open)
        .with_prior_timestamps(slow_prior)
        .with_anchor_chainwork(ChainWork256::from_bits(REGTEST_POW_LIMIT_BITS).unwrap());
    let mut easy_headers = Vec::new();
    let mut prev2 = root_hash;
    for i in 0..10u32 {
        let h = mine_regtest_header(
            prev2,
            sha256d(&[0xB0, i as u8]),
            slow_prior[10] + 600 * (i + 1),
            REGTEST_POW_LIMIT_BITS,
        );
        prev2 = sha256d(&h);
        easy_headers.push(h);
    }
    let easy_refs: Vec<&[u8; HEADER_LEN]> = easy_headers.iter().collect();
    let easy_ev = spv_evidence(&slow_adapter, "regtest", &easy_refs, Address::from([6; 32]));

    let pol = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: u64::from(slow_prior[10]) + 20_000,
        require_slashable: false,
    };
    let hard_chain = fast_adapter.verify_chain(&hard_ev, &pol).expect("hard");
    let easy_chain = slow_adapter.verify_chain(&easy_ev, &pol).expect("easy");
    assert!(hard_chain.headers.len() < easy_chain.headers.len());
    assert!(hard_chain.total_chainwork > easy_chain.total_chainwork);

    let candidates = [easy_chain, hard_chain.clone()];
    let winner = select_heaviest_bitcoin_chain(&candidates).expect("heaviest wins");
    assert_eq!(
        winner.attestation.state_root,
        hard_chain.attestation.state_root
    );
    assert_eq!(winner.attestation.height, 2_021);
}

#[test]
fn cross_epoch_retarget_and_prior_mtp11_enforce_exact_bitcoin_core_rules() {
    use crate::cross_domain::external::bitcoin_spv::{
        compute_next_work_required, compute_next_work_required_with_limit, median_time_past,
        DIFFICULTY_ADJUSTMENT_INTERVAL, MAINNET_POW_LIMIT_BITS, MAX_HEADERS, MTP_WINDOW_LEN,
        POW_TARGET_TIMESPAN_SECS, REGTEST_POW_LIMIT_BITS,
    };
    use crate::cross_domain::external::spec::AdapterError;

    assert!(MAX_HEADERS as u64 > DIFFICULTY_ADJUSTMENT_INTERVAL);
    assert_eq!(
        compute_next_work_required(
            1_712_000_000,
            1_712_000_000 + POW_TARGET_TIMESPAN_SECS,
            REGTEST_POW_LIMIT_BITS
        )
        .expect("mainnet clamp"),
        MAINNET_POW_LIMIT_BITS
    );

    // Mid-epoch anchor at 839_997 crossing 4th-halving retarget 840_000 at 2x speed.
    let prev_bits = 0x207f_fff0u32;
    let epoch_open_ts = 1_712_000_000u32;
    let block_839999_ts = epoch_open_ts + (POW_TARGET_TIMESPAN_SECS / 2);
    let expected_next_bits = compute_next_work_required_with_limit(
        epoch_open_ts,
        block_839999_ts,
        prev_bits,
        REGTEST_POW_LIMIT_BITS,
    )
    .expect("retarget");
    assert_ne!(expected_next_bits, prev_bits);

    let anchor_ts = block_839999_ts - 1_200;
    let prior: [u32; MTP_WINDOW_LEN] = std::array::from_fn(|i| anchor_ts - ((10 - i) as u32) * 600);
    let mtp_at_anchor = median_time_past(&prior).expect("mtp");
    let root_hash = sha256d(b"anchor-840669");
    let adp = BitcoinSpvAdapter::new(
        "regtest",
        Some(PinnedBitcoinAnchor {
            height: 840_669,
            block_hash: root_hash,
            bits: prev_bits,
        }),
    )
    .with_epoch_start_timestamp(epoch_open_ts)
    .with_prior_timestamps(prior);

    // Non-monotonic timestamp on block 839_998 (< anchor_ts) strictly ABOVE MTP-11 succeeds!
    let ts_list = [
        anchor_ts - 100, // < anchor_ts, > mtp_at_anchor (valid BIP-113!)
        block_839999_ts, // height 839_999 (closes epoch)
        block_839999_ts + 600,
        block_839999_ts + 1_200,
        block_839999_ts + 1_800,
        block_839999_ts + 2_400,
    ];
    assert!(ts_list[0] > mtp_at_anchor && ts_list[0] < anchor_ts);

    let mut chain = Vec::new();
    let mut prev = root_hash;
    for (i, &ts) in ts_list.iter().enumerate() {
        let h_bits = if i < 2 { prev_bits } else { expected_next_bits };
        let hdr = mine_regtest_header(prev, sha256d(&[0xC1, i as u8]), ts, h_bits);
        prev = sha256d(&hdr);
        chain.push(hdr);
    }
    let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
    let ev = spv_evidence(&adp, "regtest", &refs, Address::from([7; 32]));
    let pol = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: u64::from(block_839999_ts) + 3_000,
        require_slashable: false,
    };
    let ok = adp
        .verify_chain(&ev, &pol)
        .expect("840_672 retarget passes");
    assert_eq!(ok.attestation.height, 840_675);

    // Timestamp == MTP-11 on block 839_998 must fail closed (BIP-113 requires strict `>`).
    let mut mtp_fail = Vec::new();
    let mut p = root_hash;
    for (i, &ts) in ts_list.iter().enumerate() {
        let actual_ts = if i == 0 { mtp_at_anchor } else { ts };
        let h_bits = if i < 2 { prev_bits } else { expected_next_bits };
        let hdr = mine_regtest_header(p, sha256d(&[0xC2, i as u8]), actual_ts, h_bits);
        p = sha256d(&hdr);
        mtp_fail.push(hdr);
    }
    let mtp_refs: Vec<&[u8; HEADER_LEN]> = mtp_fail.iter().collect();
    let mtp_ev = spv_evidence(&adp, "regtest", &mtp_refs, Address::from([7; 32]));
    assert!(matches!(
        adp.verify(&mtp_ev, &pol),
        Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("BIP-113 MTP")
    ));

    // Wrong retarget bits on block 840_000 must fail closed.
    let wrong_bits = compute_next_work_required_with_limit(
        epoch_open_ts + 60_000,
        block_839999_ts,
        prev_bits,
        REGTEST_POW_LIMIT_BITS,
    )
    .unwrap();
    let mut bad_ret = Vec::new();
    let mut p2 = root_hash;
    for (i, &ts) in ts_list.iter().enumerate() {
        let h_bits = if i < 2 { prev_bits } else { wrong_bits };
        let hdr = mine_regtest_header(p2, sha256d(&[0xC3, i as u8]), ts, h_bits);
        p2 = sha256d(&hdr);
        bad_ret.push(hdr);
    }
    let bad_refs: Vec<&[u8; HEADER_LEN]> = bad_ret.iter().collect();
    let bad_ev = spv_evidence(&adp, "regtest", &bad_refs, Address::from([7; 32]));
    assert!(matches!(
        adp.verify(&bad_ev, &pol),
        Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("Bitcoin retarget")
    ));
}

#[test]
fn spv_raw_tx_refuses_cve_2017_12842_inner_node_and_underconfirmed_tip_tx() {
    use crate::cross_domain::external::bitcoin_spv::{
        verify_spv_raw_tx_inclusion, FORBIDDEN_INNER_NODE_TX_BYTES, MAX_STRIPPED_TX_BYTES,
        REGTEST_POW_LIMIT_BITS,
    };
    use crate::cross_domain::external::spec::AdapterError;

    assert_eq!(FORBIDDEN_INNER_NODE_TX_BYTES, 64);
    assert_eq!(MAX_STRIPPED_TX_BYTES, 1_000_000);

    let pair = |l: [u8; 32], r: [u8; 32]| {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&l);
        b[32..].copy_from_slice(&r);
        sha256d(&b)
    };
    let coinbase = [0x11u8; 100]; // valid non-64-byte stripped coinbase
    let payment_tx = [0x22u8; 192]; // valid non-64-byte stripped P2WPKH payment tx
    let tx2 = [0x33u8; 150];
    let tx3 = [0x44u8; 180];
    let id0 = sha256d(&coinbase);
    let id1 = sha256d(&payment_tx);
    let id2 = sha256d(&tx2);
    let id3 = sha256d(&tx3);
    let h01 = pair(id0, id1);
    let h23 = pair(id2, id3);
    let merkle_root = pair(h01, h23);

    // CVE-2017-12842 attack: submit the 64-byte internal concatenation `id2 || id3`
    // as a fake leaf transaction with 1-step branch `[h01]`. Without the 64-byte
    // guard its SHA256d equals `h23` and walks straight to `merkle_root`!
    let mut forged_64_byte_tx = [0u8; 64];
    forged_64_byte_tx[..32].copy_from_slice(&id2);
    forged_64_byte_tx[32..].copy_from_slice(&id3);
    let cve_err = verify_spv_raw_tx_inclusion(&forged_64_byte_tx, &merkle_root, 1, &[h01], false)
        .expect_err("64-byte CVE-2017-12842 inner-node payload must fail closed");
    assert!(matches!(
        cve_err,
        AdapterError::ConsensusRule { ref rule } if rule.contains("CVE-2017-12842")
    ));

    // Coinbase flag mismatch refused in both directions.
    assert!(verify_spv_raw_tx_inclusion(&coinbase, &merkle_root, 0, &[id1, h23], false).is_err());
    assert!(verify_spv_raw_tx_inclusion(&payment_tx, &merkle_root, 1, &[id0, h23], true).is_err());

    // Build a verified 6-block chain embedding `merkle_root` in block #1 (6 confs)
    // and another tx in block #6 (1 conf, below required 6 confirmations).
    let root_hash = sha256d(b"payment-anchor");
    let adp = BitcoinSpvAdapter::new(
        "regtest",
        Some(PinnedBitcoinAnchor {
            height: 500,
            block_hash: root_hash,
            bits: REGTEST_POW_LIMIT_BITS,
        }),
    );
    let tip_tx = [0x55u8; 120];
    let tip_merkle = sha256d(&tip_tx);
    let mut chain = Vec::new();
    let mut prev = root_hash;
    for i in 0..6u32 {
        let mr = if i == 0 {
            merkle_root
        } else if i == 5 {
            tip_merkle
        } else {
            sha256d(&[0xD0, i as u8])
        };
        let hdr = mine_regtest_header(prev, mr, 1_720_000_000 + i * 600, REGTEST_POW_LIMIT_BITS);
        prev = sha256d(&hdr);
        chain.push(hdr);
    }
    let b1_hash = sha256d(&chain[0]);
    let b6_hash = sha256d(&chain[5]);
    let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
    let ev = spv_evidence(&adp, "regtest", &refs, Address::from([8; 32]));
    let pol = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: 1_720_010_000,
        require_slashable: false,
    };
    let verified_chain = adp.verify_chain(&ev, &pol).expect("chain verifies");

    // Honest coinbase + payment at block 501 both verify with 6 confirmations!
    let cb_ok = verified_chain
        .verify_confirmed_payment(&b1_hash, &coinbase, 0, &[id1, h23], true, 6)
        .expect("coinbase 6 confs");
    assert!(cb_ok.is_coinbase && cb_ok.confirmations == 6 && cb_ok.txid == id0);

    let pay_ok = verified_chain
        .verify_confirmed_payment(&b1_hash, &payment_tx, 1, &[id0, h23], false, 6)
        .expect("payment 6 confs");
    assert!(!pay_ok.is_coinbase && pay_ok.confirmations == 6 && pay_ok.txid == id1);

    // Tip block 506 has only 1 confirmation -> refused when demanding 6!
    assert!(matches!(
        verified_chain.verify_confirmed_payment(&b6_hash, &tip_tx, 0, &[], true, 6),
        Err(AdapterError::InsufficientDepth {
            observed: 1,
            required: 6
        })
    ));
}

#[test]
fn real_mainnet_headers_prove_and_verify_plonky3_stark_prog_claim() {
    use crate::aggregation::claim::Claim;
    use crate::cross_domain::external::bitcoin_spv::{
        bitcoin_stark_input_hash, bitcoin_stark_output_hash, prove_bitcoin_header_chain_stark,
        verify_bitcoin_header_chain_stark, ChainWork256, MAX_STARK_BATCH_HEADERS,
    };

    const _: () = assert!(MAX_STARK_BATCH_HEADERS >= 6);
    let dom = 7u32;
    let adp = adapter();
    let ev = golden();
    let pol = policy();
    let pinned = anchor();

    // Generate a REAL 128-bit Plonky3 FRI-STARK BudAir proof over Satoshi's
    // real Bitcoin mainnet blocks 1..=6 anchored at Genesis block 0!
    let batch = prove_bitcoin_header_chain_stark(&adp, &ev, &pol, dom).expect("STARK batch proves");
    assert_eq!(batch.header_count, 6);
    assert_eq!(batch.tip_height, 6);
    assert_eq!(batch.tip_hash, ev.declared_root);
    assert_eq!(
        batch.total_chainwork.to_le_words(),
        [6 * 0x0000_0001_0001_0001, 0, 0, 0]
    );

    let claim =
        verify_bitcoin_header_chain_stark("mainnet", &pinned, ChainWork256::ZERO, dom, &batch)
            .expect("128-bit Plonky3 FRI-STARK Claim::Prog verifies");
    let expected_in = bitcoin_stark_input_hash(
        "mainnet",
        &pinned,
        ChainWork256::ZERO,
        6,
        batch.max_allowed_ts,
    );
    let expected_out = bitcoin_stark_output_hash(
        batch.tip_height,
        &batch.tip_hash,
        &batch.tip_merkle_root,
        batch.tip_timestamp,
        batch.tip_bits,
        batch.total_chainwork,
        batch.transcript_commitment,
    );
    assert_eq!(
        claim,
        Claim::Prog {
            program_hash: batch.program_hash,
            input_hash: expected_in,
            output_hash: expected_out,
        }
    );

    // 1. Cross-domain replay must fail closed.
    assert!(verify_bitcoin_header_chain_stark(
        "mainnet",
        &pinned,
        ChainWork256::ZERO,
        dom + 1,
        &batch
    )
    .is_err());

    // 2. Inflated cumulative chainwork forgery must fail closed.
    let mut forged_work = batch.clone();
    forged_work.total_chainwork = batch
        .total_chainwork
        .saturating_add(ChainWork256::from_bits(0x1d00_ffff).unwrap());
    assert!(verify_bitcoin_header_chain_stark(
        "mainnet",
        &pinned,
        ChainWork256::ZERO,
        dom,
        &forged_work
    )
    .is_err());

    // 3. Forged tip hash must fail closed.
    let mut forged_tip = batch.clone();
    forged_tip.tip_hash[0] ^= 0x01;
    assert!(verify_bitcoin_header_chain_stark(
        "mainnet",
        &pinned,
        ChainWork256::ZERO,
        dom,
        &forged_tip
    )
    .is_err());

    // 4. Forged pinned anchor must fail closed.
    let mut wrong_anchor = pinned;
    wrong_anchor.block_hash[0] ^= 0xff;
    assert!(verify_bitcoin_header_chain_stark(
        "mainnet",
        &wrong_anchor,
        ChainWork256::ZERO,
        dom,
        &batch
    )
    .is_err());

    spv_merkle_proof_verifies_every_leaf_of_odd_width_trees();
    spv_merkle_proof_index_is_canonical_even_with_duplicated_tail_nodes();
    spv_merkle_proof_refuses_a_duplicate_at_a_leftmost_or_right_child_position();
    spv_merkle_proof_verifies_every_transaction_of_real_odd_mainnet_blocks();
    spv_confirmed_payment_proves_the_tail_transaction_of_an_odd_block();
    spv_chain_with_a_backward_timestamp_step_verifies_when_median_time_past_holds();
    spv_chain_below_the_implied_median_time_past_floor_is_refused();
    an_equal_work_sibling_cannot_slash_the_carrier_of_a_bitcoin_attestation();
    a_sibling_pair_cannot_slash_the_carrier_of_a_bitcoin_attestation_by_ancestry();
    a_work_bucket_boundary_does_not_let_a_sibling_pair_slash_by_ancestry();
    unix_seconds_live_policy_clock_advances_from_accepted_attestation_timestamps();
}

/// Bitcoin's transaction Merkle tree: a level of odd width pairs its last node
/// with a copy of itself (the rule `ComputeMerkleRoot` applies in Bitcoin Core).
fn merkle_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().map_or(0, Vec::len) > 1 {
        let level = levels.last().expect("at least one level");
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(sha256d(&buf));
        }
        levels.push(next);
    }
    levels
}

fn merkle_branch(levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut idx = leaf_index;
    let mut branch = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in &levels[..levels.len() - 1] {
        branch.push(*level.get(idx ^ 1).unwrap_or(&level[idx]));
        idx >>= 1;
    }
    branch
}

fn synthetic_leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| sha256d(format!("leaf-{n}-{i}").as_bytes()))
        .collect()
}

fn spv_merkle_proof_verifies_every_leaf_of_odd_width_trees() {
    use crate::cross_domain::external::bitcoin_spv::verify_spv_tx_inclusion;

    for n in 1..=40usize {
        let leaves = synthetic_leaves(n);
        let levels = merkle_levels(&leaves);
        let root = levels.last().expect("levels")[0];
        for (i, leaf) in leaves.iter().enumerate() {
            let branch = merkle_branch(&levels, i);
            let index = u32::try_from(i).expect("small index");
            assert!(
                verify_spv_tx_inclusion(leaf, &root, index, &branch),
                "honest proof for leaf {i} of {n} was refused"
            );
        }
    }
}

fn spv_merkle_proof_index_is_canonical_even_with_duplicated_tail_nodes() {
    use crate::cross_domain::external::bitcoin_spv::verify_spv_tx_inclusion;

    for n in 1..=40usize {
        let leaves = synthetic_leaves(n);
        let levels = merkle_levels(&leaves);
        let root = levels.last().expect("levels")[0];
        let depth = levels.len() - 1;
        for (i, leaf) in leaves.iter().enumerate() {
            let branch = merkle_branch(&levels, i);
            for alias in 0..(1u32 << depth) {
                if usize::try_from(alias).expect("small index") == i {
                    continue;
                }
                assert!(
                    !verify_spv_tx_inclusion(leaf, &root, alias, &branch),
                    "leaf {i} of {n} also verified at index {alias}"
                );
            }
            let high_bit_alias = u32::try_from(i).expect("small index") | (1u32 << depth);
            assert!(
                !verify_spv_tx_inclusion(leaf, &root, high_bit_alias, &branch),
                "leaf {i} of {n} verified with a stray high index bit"
            );
        }
    }
}

fn spv_merkle_proof_refuses_a_duplicate_at_a_leftmost_or_right_child_position() {
    use crate::cross_domain::external::bitcoin_spv::verify_spv_tx_inclusion;

    let leaf = sha256d(b"duplicated");
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&leaf);
    buf[32..].copy_from_slice(&leaf);
    let doubled_root = sha256d(&buf);

    // `[x, x]` is the mutated form of a one-transaction block: a genuine
    // duplicate is only ever the last node of a wider odd level, never node 0
    // and never a right child.
    assert!(!verify_spv_tx_inclusion(&leaf, &doubled_root, 0, &[leaf]));
    assert!(!verify_spv_tx_inclusion(&leaf, &doubled_root, 1, &[leaf]));
}

/// Real mainnet blocks 100027 (3 transactions) and 100014 (7 transactions).
/// Each header's double-SHA256 equals the block hash and carries the Merkle
/// root below, so the transaction ids are pinned to proof-of-work.
const MAINNET_ODD_BLOCKS: [(&str, &[&str]); 2] = [
    (
        "7099d100635a0e5f62ef12a8420c99426a408951078f191a0f63ddedc4dcd198",
        &[
            "1a02db5db5a24c5edc5b653051d8aaaddec3f9abc30354f7df358c49fe40f735",
            "d3f3eb471e368a27f5320ff7a961bed748519139435cf8348e84ebd6225d7150",
            "7cbcf6b5378e3e43b39734baa578efa501d02abf90289547f0e6621ee959f0e3",
        ],
    ),
    (
        "8772d9d0fdf8c1303c7b1167e3c73b095fd970e33c799c6563d98b2e96c5167f",
        &[
            "147caa76786596590baa4e98f5d9f48b86c7765e489f7a6ff3360fe5c674360b",
            "0bcb16af267dee77ed8761662d31ee9d9a1bf1e4d268a9e7127407ebb3f9acfd",
            "48738657818e2628f216375a9d48d681e2b1b1390be1b7a028c7b810eaa3928a",
            "02981fa052f0481dbc5868f4fc2166035a10f27a03cfd2de67326471df5bc041",
            "652b0aa4cf4f17bdb31f7a1d308331bba91f3b3cbf8f39c9cb5e19d4015b9f01",
            "68d0685759c3d4f3f90a4f0e48d1b77641f06bb1f0b83a8841e8d71d5570ed41",
            "0a2a92f0bda4727d0a13eaddf4dd9ac6b5c61a1429e6b2b818f19b15df0ac154",
        ],
    ),
];

fn internal_order(display_hex: &str) -> [u8; 32] {
    let mut raw: [u8; 32] = hex::decode(display_hex)
        .expect("pinned hex")
        .try_into()
        .expect("32 bytes");
    raw.reverse();
    raw
}

fn spv_merkle_proof_verifies_every_transaction_of_real_odd_mainnet_blocks() {
    use crate::cross_domain::external::bitcoin_spv::verify_spv_tx_inclusion;

    for (root_hex, txids) in MAINNET_ODD_BLOCKS {
        let leaves: Vec<[u8; 32]> = txids.iter().map(|t| internal_order(t)).collect();
        let levels = merkle_levels(&leaves);
        let header_root = internal_order(root_hex);
        assert_eq!(levels.last().expect("levels")[0], header_root);
        for (i, leaf) in leaves.iter().enumerate() {
            let branch = merkle_branch(&levels, i);
            let index = u32::try_from(i).expect("small index");
            assert!(
                verify_spv_tx_inclusion(leaf, &header_root, index, &branch),
                "transaction {i} of {} in block {root_hex} was refused",
                leaves.len()
            );
            let mut forged = branch.clone();
            forged[0][0] ^= 1;
            assert!(!verify_spv_tx_inclusion(leaf, &header_root, index, &forged));
        }
    }
}

fn spv_confirmed_payment_proves_the_tail_transaction_of_an_odd_block() {
    use crate::cross_domain::external::bitcoin_spv::{
        verify_spv_raw_tx_inclusion, REGTEST_POW_LIMIT_BITS,
    };
    use crate::cross_domain::external::spec::AdapterError;

    let raw_txs: Vec<Vec<u8>> = (0u8..5)
        .map(|i| vec![0x70 + i; 120 + usize::from(i)])
        .collect();
    let leaves: Vec<[u8; 32]> = raw_txs.iter().map(|t| sha256d(t)).collect();
    let levels = merkle_levels(&leaves);
    let merkle_root = levels.last().expect("levels")[0];

    let anchor_hash = sha256d(b"odd-block-anchor");
    let adp = BitcoinSpvAdapter::new(
        "regtest",
        Some(PinnedBitcoinAnchor {
            height: 700,
            block_hash: anchor_hash,
            bits: REGTEST_POW_LIMIT_BITS,
        }),
    );
    let mut chain = Vec::new();
    let mut prev = anchor_hash;
    for i in 0..6u32 {
        let root = if i == 0 {
            merkle_root
        } else {
            sha256d(&[0xE0, u8::try_from(i).expect("small")])
        };
        let hdr = mine_regtest_header(prev, root, 1_730_000_000 + i * 600, REGTEST_POW_LIMIT_BITS);
        prev = sha256d(&hdr);
        chain.push(hdr);
    }
    let block_hash = sha256d(&chain[0]);
    let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
    let ev = spv_evidence(&adp, "regtest", &refs, Address::from([9; 32]));
    let pol = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: 1_730_010_000,
        require_slashable: false,
    };
    let verified_chain = adp.verify_chain(&ev, &pol).expect("chain verifies");

    for (i, raw_tx) in raw_txs.iter().enumerate() {
        let branch = merkle_branch(&levels, i);
        let index = u32::try_from(i).expect("small index");
        let proven = verified_chain
            .verify_confirmed_payment(&block_hash, raw_tx, index, &branch, i == 0, 6)
            .unwrap_or_else(|e| panic!("transaction {i} of 5 was refused: {e:?}"));
        assert_eq!(proven.txid, leaves[i]);
        assert_eq!(proven.tx_index, index);
        assert_eq!(proven.confirmations, 6);

        let standalone = verify_spv_raw_tx_inclusion(raw_tx, &merkle_root, index, &branch, i == 0)
            .expect("standalone proof");
        assert_eq!(standalone.txid, leaves[i]);
    }

    // The tail transaction cannot be claimed at the neighbouring index.
    let tail_branch = merkle_branch(&levels, 4);
    assert!(matches!(
        verified_chain.verify_confirmed_payment(&block_hash, &raw_txs[4], 5, &tail_branch, false, 6),
        Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("Merkle branch")
    ));
}

fn regtest_chain_with_timestamps(timestamps: &[u32]) -> (BitcoinSpvAdapter, RawConsensusEvidence) {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    let anchor_hash = sha256d(b"timestamp-rule-anchor");
    let adp = BitcoinSpvAdapter::new(
        "regtest",
        Some(PinnedBitcoinAnchor {
            height: 900,
            block_hash: anchor_hash,
            bits: REGTEST_POW_LIMIT_BITS,
        }),
    );
    let mut prev = anchor_hash;
    let mut chain = Vec::with_capacity(timestamps.len());
    for (i, ts) in timestamps.iter().enumerate() {
        let root = sha256d(&u32::try_from(i).expect("small index").to_le_bytes());
        let header = mine_regtest_header(prev, root, *ts, REGTEST_POW_LIMIT_BITS);
        prev = sha256d(&header);
        chain.push(header);
    }
    let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
    let evidence = spv_evidence(&adp, "regtest", &refs, Address::from([10; 32]));
    (adp, evidence)
}

fn timestamp_policy(latest: u32) -> VerificationPolicy {
    VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: u64::from(latest) + 1_000,
        require_slashable: false,
    }
}

fn spv_chain_with_a_backward_timestamp_step_verifies_when_median_time_past_holds() {
    // Bitcoin consensus only requires `timestamp > MTP-11`, so a header may
    // carry an earlier timestamp than its parent (3.4% of recent mainnet
    // parent links do). Without pinned prior timestamps the verifier cannot
    // evaluate the exact median, and must not invent a stricter rule.
    let base = 1_730_000_000u32;
    let mut timestamps: Vec<u32> = (1..=12u32).map(|i| base + i * 600).collect();
    timestamps[3] = timestamps[2] - 100;
    timestamps[8] = timestamps[7] - 100;
    let (adp, evidence) = regtest_chain_with_timestamps(&timestamps);
    let latest = *timestamps.iter().max().expect("non-empty");
    let attestation = adp
        .verify(&evidence, &timestamp_policy(latest))
        .expect("a consensus-valid chain with backward timestamp steps verifies");
    assert_eq!(attestation.height, 912);
}

fn spv_chain_below_the_implied_median_time_past_floor_is_refused() {
    use crate::cross_domain::external::spec::AdapterError;

    // With `k >= 6` known predecessors the true median is at least the
    // `(k - 5)`-th smallest of them whatever the unknown older blocks were, so
    // a header at or below that floor is invalid on every possible history.
    let base = 1_730_000_000u32;
    let rising: Vec<u32> = (1..=7u32).map(|i| base + i * 100).collect();

    // k = 6: the floor is the smallest known timestamp.
    let mut at_floor = rising[..6].to_vec();
    at_floor.push(rising[0]);
    let (adp, evidence) = regtest_chain_with_timestamps(&at_floor);
    assert!(matches!(
        adp.verify(&evidence, &timestamp_policy(base + 1_000)),
        Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("BIP-113")
    ));

    // k = 7: the floor is the second smallest. At the floor is refused, one
    // second above it is accepted even though it is below the parent.
    let mut seven = rising.clone();
    seven.push(rising[1]);
    let (adp, evidence) = regtest_chain_with_timestamps(&seven);
    assert!(matches!(
        adp.verify(&evidence, &timestamp_policy(base + 1_000)),
        Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("BIP-113")
    ));

    let mut above = rising;
    above.push(above[1] + 1);
    let (adp, evidence) = regtest_chain_with_timestamps(&above);
    adp.verify(&evidence, &timestamp_policy(base + 1_000))
        .expect("one second above the implied floor is consensus-valid");
}

const POW_DOOR_BASE_TS: u32 = 1_730_000_000;
const POW_DOOR_CARRIER: [u8; 32] = [9; 32];
const POW_DOOR_CHALLENGER: [u8; 32] = [77; 32];

fn pow_door_anchor() -> PinnedBitcoinAnchor {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    PinnedBitcoinAnchor {
        height: 900,
        block_hash: sha256d(b"pow-door-anchor"),
        bits: REGTEST_POW_LIMIT_BITS,
    }
}

fn pow_door_policy() -> VerificationPolicy {
    VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: u64::from(POW_DOOR_BASE_TS) + 10_000,
        require_slashable: false,
    }
}

/// Mines `len` regtest headers on top of `parent`, numbered from `first`. The
/// merkle roots come from `tag`, so two tags give two distinct valid branches
/// with the same heights, timestamps and work.
fn pow_door_branch(
    parent: [u8; 32],
    first: usize,
    len: usize,
    tag: &[u8],
) -> Vec<[u8; HEADER_LEN]> {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    let mut prev = parent;
    let mut branch = Vec::with_capacity(len);
    for index in first..first + len {
        let index = u32::try_from(index).expect("small index");
        let mut seed = tag.to_vec();
        seed.extend_from_slice(&index.to_le_bytes());
        let header = mine_regtest_header(
            prev,
            sha256d(&seed),
            POW_DOOR_BASE_TS + (index + 1) * 600,
            REGTEST_POW_LIMIT_BITS,
        );
        prev = sha256d(header.as_slice());
        branch.push(header);
    }
    branch
}

/// `common` headers every fork shares, then `tail` headers private to `tag`:
/// two tags with the same `common` are two forks off one block.
fn pow_door_fork(common: usize, tail: usize, tag: &[u8]) -> Vec<[u8; HEADER_LEN]> {
    let anchor_hash = pow_door_anchor().block_hash;
    let mut chain = pow_door_branch(anchor_hash, 0, common, b"shared");
    let parent = chain
        .last()
        .map_or(anchor_hash, |header| sha256d(header.as_slice()));
    chain.extend(pow_door_branch(parent, common, tail, tag));
    chain
}

fn pow_door_evidence(chain: &[[u8; HEADER_LEN]], submitter: [u8; 32]) -> RawConsensusEvidence {
    let adapter = BitcoinSpvAdapter::new("regtest", Some(pow_door_anchor()));
    let refs: Vec<&[u8; HEADER_LEN]> = chain.iter().collect();
    spv_evidence(&adapter, "regtest", &refs, Address::from(submitter))
}

fn pow_door_backing(chain: &[[u8; HEADER_LEN]]) -> SecurityBacking {
    BitcoinSpvAdapter::new("regtest", Some(pow_door_anchor()))
        .verify(
            &pow_door_evidence(chain, POW_DOOR_CHALLENGER),
            &pow_door_policy(),
        )
        .expect("the mined chain verifies")
        .security
}

/// A registered, bonded regtest Bitcoin domain whose carrier already has the
/// attestation for `accepted` in the book.
fn pow_door_book(
    accepted: &[[u8; HEADER_LEN]],
) -> (IntakeState, crate::cross_domain::external::spec::DomainKey) {
    let spec = Spec::BitcoinSpv {
        network: "regtest".to_string(),
        anchor: Some(pow_door_anchor()),
    };
    let economics = IntakeState::conservative_economics(1_000_000);
    let descriptor_id = spec.build(None, None).descriptor().id;
    let mut state = IntakeState::new();
    state.pin_bitcoin_anchor("regtest", pow_door_anchor());
    let key = state
        .register_domain(
            RegistrationRequest {
                spec,
                policy: pow_door_policy(),
                economics,
                versions: VersionPolicy::single(descriptor_id, 1, 0),
                bond_atoms: economics.required_bond_atoms(),
                poster: Address::from(POW_DOOR_CARRIER),
                golden: pow_door_evidence(&pow_door_fork(6, 0, b"golden"), POW_DOOR_CARRIER),
            },
            None,
        )
        .expect("a pinned regtest Bitcoin domain registers");
    state
        .submit_evidence(&pow_door_evidence(accepted, POW_DOOR_CARRIER), None)
        .expect("the carrier's attestation is accepted");
    (state, key)
}

fn assert_pow_door_book_untouched(
    state: &IntakeState,
    key: &crate::cross_domain::external::spec::DomainKey,
    digest_before: [u8; 32],
) {
    use crate::cross_domain::external::profile::DomainState;

    assert_eq!(
        state.state_digest().expect("digest"),
        digest_before,
        "a refused challenge must not move any state"
    );
    let registration = state.registry.domain(key).expect("domain stays registered");
    assert_eq!(registration.record.state, DomainState::Active);
    assert_eq!(
        registration.attestations.len(),
        1,
        "the carrier's attestation stays in the book"
    );
    let bond = registration
        .provers
        .get(&Address::from(POW_DOOR_CARRIER))
        .expect("the carrier's bond");
    assert_eq!(bond.slashed_atoms, 0);
    assert!(bond.slashings.is_empty());
}

fn an_equal_work_sibling_cannot_slash_the_carrier_of_a_bitcoin_attestation() {
    // Two forks off the fifth block reach the same height with the same work:
    // the external chain's own tie. Neither carrier is provably the liar, so
    // the contradiction door must refuse and leave every record where it was.
    let accepted = pow_door_fork(5, 1, b"carrier-tip");
    let rival = pow_door_fork(5, 1, b"rival-tip");
    assert_eq!(
        pow_door_backing(&accepted),
        pow_door_backing(&rival),
        "the forks carry exactly the same work"
    );
    let (mut state, key) = pow_door_book(&accepted);
    let digest_before = state.state_digest().expect("digest");

    let refusal = state
        .slash_on_contradiction(
            &pow_door_evidence(&rival, POW_DOOR_CHALLENGER),
            Address::from(POW_DOOR_CHALLENGER),
            None,
        )
        .expect_err("a tie slashes nobody");
    assert!(
        matches!(&refusal, IntakeError::InvalidContradiction { reason } if reason.contains("more than")),
        "unexpected refusal: {refusal:?}"
    );
    assert_pow_door_book_untouched(&state, &key, digest_before);
}

fn a_sibling_pair_cannot_slash_the_carrier_of_a_bitcoin_attestation_by_ancestry() {
    // The carrier attested a six-header chain. A rival fork off the fifth
    // block reaches height 7, so its header at height 6 is a sibling of the
    // carrier's tip. That is an ordinary one-block race, and it must not be
    // read as proof that the carrier lied.
    let accepted = pow_door_fork(5, 1, b"carrier-tip");
    let witness = pow_door_fork(5, 2, b"rival-tip");
    let (mut state, key) = pow_door_book(&accepted);
    let digest_before = state.state_digest().expect("digest");

    let refusal = state
        .adjudicate_ancestry(
            &pow_door_evidence(&witness, POW_DOOR_CHALLENGER),
            Address::from(POW_DOOR_CHALLENGER),
            None,
        )
        .expect_err("a one-block race refutes nothing");
    assert!(
        matches!(&refusal, IntakeError::InvalidContradiction { reason } if reason.contains("proof-of-work")),
        "unexpected refusal: {refusal:?}"
    );
    assert_pow_door_book_untouched(&state, &key, digest_before);
}

fn a_work_bucket_boundary_does_not_let_a_sibling_pair_slash_by_ancestry() {
    // The attested work is a power-of-two bucket. The witness is one block
    // longer by adjacency, so at a bucket edge its bucket is strictly higher
    // than the attested one even though it proves no reorg: a comparison of
    // the two buckets would let this pair slash an honest carrier.
    let accepted = pow_door_fork(6, 1, b"carrier-tip");
    let witness = pow_door_fork(6, 2, b"rival-tip");
    let (
        SecurityBacking::Work {
            difficulty_bits: attested_bits,
        },
        SecurityBacking::Work {
            difficulty_bits: witness_bits,
        },
    ) = (pow_door_backing(&accepted), pow_door_backing(&witness))
    else {
        panic!("a Bitcoin window is work backed");
    };
    assert!(
        witness_bits > attested_bits,
        "the fixture must sit on a bucket edge ({attested_bits} -> {witness_bits})"
    );
    let (mut state, key) = pow_door_book(&accepted);
    let digest_before = state.state_digest().expect("digest");

    let refusal = state
        .adjudicate_ancestry(
            &pow_door_evidence(&witness, POW_DOOR_CHALLENGER),
            Address::from(POW_DOOR_CHALLENGER),
            None,
        )
        .expect_err("a bucket edge is not a reorg");
    assert!(
        matches!(&refusal, IntakeError::InvalidContradiction { reason } if reason.contains("proof-of-work")),
        "unexpected refusal: {refusal:?}"
    );
    assert_pow_door_book_untouched(&state, &key, digest_before);
}

fn unix_seconds_live_policy_clock_advances_from_accepted_attestation_timestamps() {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    let anchor = PinnedBitcoinAnchor {
        height: 900,
        block_hash: sha256d(b"clock-unit-anchor"),
        bits: REGTEST_POW_LIMIT_BITS,
    };
    let anchor_hash = anchor.block_hash;
    let adapter = BitcoinSpvAdapter::new("regtest", Some(anchor.clone()));
    let mut prev = anchor_hash;
    let mut chain1 = Vec::new();
    for i in 0..6u32 {
        let hdr = mine_regtest_header(
            prev,
            sha256d(&i.to_le_bytes()),
            1_730_000_000 + (i + 1) * 1_000,
            REGTEST_POW_LIMIT_BITS,
        );
        prev = sha256d(&hdr);
        chain1.push(hdr);
    }
    let mut chain2 = chain1.clone();
    let hdr7 = mine_regtest_header(
        prev,
        sha256d(&7u32.to_le_bytes()),
        1_730_011_000,
        REGTEST_POW_LIMIT_BITS,
    );
    chain2.push(hdr7);

    let chain1_refs: Vec<&[u8; HEADER_LEN]> = chain1.iter().collect();
    let chain2_refs: Vec<&[u8; HEADER_LEN]> = chain2.iter().collect();
    let policy = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 3_600,
        now: 1_730_003_000,
        require_slashable: false,
    };
    let spec = Spec::BitcoinSpv {
        network: "regtest".to_string(),
        anchor: Some(anchor.clone()),
    };
    let economics = IntakeState::conservative_economics(1_000_000);
    let mut state = IntakeState::new();
    state.pin_bitcoin_anchor("regtest", anchor);
    state
        .register_domain(
            RegistrationRequest {
                spec,
                policy,
                economics,
                versions: VersionPolicy::single(adapter.descriptor().id, 1, 0),
                bond_atoms: economics.required_bond_atoms(),
                poster: Address::from(POW_DOOR_CARRIER),
                golden: spv_evidence(
                    &adapter,
                    "regtest",
                    &chain1_refs,
                    Address::from(POW_DOOR_CARRIER),
                ),
            },
            None,
        )
        .expect("domain registers");
    state
        .submit_evidence(
            &spv_evidence(
                &adapter,
                "regtest",
                &chain1_refs,
                Address::from(POW_DOOR_CARRIER),
            ),
            None,
        )
        .expect("first attestation accepted at UnixSeconds finalized_at 1_730_006_000");
    let second = state
        .submit_evidence(
            &spv_evidence(
                &adapter,
                "regtest",
                &chain2_refs,
                Address::from(POW_DOOR_CARRIER),
            ),
            None,
        )
        .expect(
            "UnixSeconds live_policy_clock advances to 1_730_006_000 and accepts 1_730_011_000",
        );
    assert_eq!(second.height, 907);
    assert_eq!(second.finalized_at, 1_730_011_000);
}

// ---------------------------------------------------------------------------
// B-10206: exact 256-bit chainwork must fail closed on overflow instead of
// saturating at `ChainWork256::MAX`. A saturated total makes every later
// `cumulative_work` compare equal, so the "strictly more work than the pinned
// anchor" invariant stops separating a real header batch from an empty one and
// the reported `difficulty_bits` freezes at the saturation point.
// ---------------------------------------------------------------------------

/// Six regtest headers mined on top of `anchor`, with the anchor's own accrued
/// work optionally pinned, so a test can drive the running total into the
/// 256-bit ceiling without mining 2^256 work.
fn regtest_six_headers(
    anchor: &PinnedBitcoinAnchor,
    anchor_chainwork: Option<ChainWork256>,
    tag: u8,
) -> (BitcoinSpvAdapter, Vec<[u8; HEADER_LEN]>, VerificationPolicy) {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    let ts_open = 1_712_000_000u32;
    let prior: [u32; 11] = std::array::from_fn(|i| ts_open + 300_000 + (i as u32) * 600);
    let mut adapter = BitcoinSpvAdapter::new("regtest", Some(anchor.clone()))
        .with_epoch_start_timestamp(ts_open)
        .with_prior_timestamps(prior);
    if let Some(work) = anchor_chainwork {
        adapter = adapter.with_anchor_chainwork(work);
    }
    let mut headers = Vec::new();
    let mut prev = anchor.block_hash;
    for i in 0..6u32 {
        let h = mine_regtest_header(
            prev,
            sha256d(&[tag, i as u8]),
            prior[10] + 600 * (i + 1),
            REGTEST_POW_LIMIT_BITS,
        );
        prev = sha256d(&h);
        headers.push(h);
    }
    let policy = VerificationPolicy {
        min_depth: 6,
        require_declared_match: true,
        max_age: 0,
        now: u64::from(prior[10]) + 20_000,
        require_slashable: false,
    };
    (adapter, headers, policy)
}

#[test]
fn anchor_chainwork_with_headroom_still_accretes_exactly() {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;

    let anchor = PinnedBitcoinAnchor {
        height: 1_000,
        block_hash: sha256d(b"regtest-room-anchor"),
        bits: REGTEST_POW_LIMIT_BITS,
    };
    let per_block = ChainWork256::from_bits(REGTEST_POW_LIMIT_BITS).expect("block work");
    let base = ChainWork256::from_bits(0x1d00_ffff).expect("genesis-sized base work");
    let (adapter, headers, policy) = regtest_six_headers(&anchor, Some(base), 0xC0);

    let refs: Vec<&[u8; HEADER_LEN]> = headers.iter().collect();
    let evidence = spv_evidence(&adapter, "regtest", &refs, Address::from([9u8; 32]));
    let chain = adapter
        .verify_chain(&evidence, &policy)
        .expect("a chain with headroom must verify");

    // Six exact additions on top of the pinned base, no saturation anywhere.
    let mut expected = base;
    for _ in 0..6 {
        expected = expected
            .checked_add(per_block)
            .expect("test headroom is exact");
    }
    assert_eq!(chain.total_chainwork, expected);
    assert_eq!(chain.headers.last().expect("tip").cumulative_work, expected);
    assert!(chain.total_chainwork > base);
}

#[test]
fn anchor_chainwork_overflow_is_refused_instead_of_saturating() {
    use crate::cross_domain::external::bitcoin_spv::REGTEST_POW_LIMIT_BITS;
    use crate::cross_domain::external::spec::AdapterError;

    let anchor = PinnedBitcoinAnchor {
        height: 1_000,
        block_hash: sha256d(b"regtest-overflow-anchor"),
        bits: REGTEST_POW_LIMIT_BITS,
    };
    // Five blocks of headroom for six blocks of work: the sixth addition leaves
    // the 256-bit range. Bitcoin's own `nChainWork` never wraps and never
    // clamps, so the only honest answers are "exact" or "refuse".
    let per_block = ChainWork256::from_bits(REGTEST_POW_LIMIT_BITS).expect("block work");
    // `ChainWork256` exposes no subtraction; build `MAX - 5*per_block` by
    // counting down from MAX through `to_be_bytes`/`from_be_bytes`, which are
    // both public.
    let mut raw = ChainWork256::MAX.to_be_bytes();
    for _ in 0..5 {
        raw = sub_be_bytes(raw, per_block.to_be_bytes());
    }
    let base = ChainWork256::from_be_bytes(raw);

    let (adapter, headers, policy) = regtest_six_headers(&anchor, Some(base), 0xD0);
    let refs: Vec<&[u8; HEADER_LEN]> = headers.iter().collect();
    let evidence = spv_evidence(&adapter, "regtest", &refs, Address::from([10u8; 32]));

    match adapter.verify_chain(&evidence, &policy) {
        Err(AdapterError::ConsensusRule { rule }) => {
            assert!(
                rule.to_lowercase().contains("chainwork"),
                "refusal must name chainwork, got: {rule}"
            );
        }
        Err(other) => panic!("expected a chainwork ConsensusRule refusal, got {other:?}"),
        Ok(chain) => panic!(
            "overflowing anchor chainwork must be refused, but the chain verified with total {:?}",
            chain.total_chainwork.to_le_words()
        ),
    }
}

/// Byte-wise big-endian subtraction, used only by the tests to build the
/// `MAX - k*work` anchor without adding a production subtraction helper for a
/// value the production path never sees.
fn sub_be_bytes(mut a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        if d < 0 {
            a[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            a[i] = d as u8;
            borrow = 0;
        }
    }
    a
}
