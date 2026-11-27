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
use budlum_core::crypto::facts::CryptoFacts;
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::pollen::offers::{DataOffer, MarketplaceRegistry, MAX_OFFERS};
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
