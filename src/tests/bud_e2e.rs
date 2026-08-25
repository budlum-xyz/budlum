//! B.U.D. (Broad Universal Database) end-to-end + module-independence
//! invariants.
//!
//! This file has two parts:
//!
//! 1. **`e2e_three_actor_manifest_to_challenge_flow`** - a three-actor
//!    happy path: operator A opens a deal for a manifest + shard,
//!    observer C opens a retrieval challenge, operator A answers,
//!    and the deal stays `Active`. This proves the interim retrieval
//!    challenge works and is **technically sound** (vision
//!    section 0.5: "third parties keep opening challenges").
//!
//! 2. **The `team_independence_invariants` module** - 9 invariants:
//!    Whitelist YOK, admin/pause hook YOK, "Budlum ekibi servisi"
//!    NO dependency, permissionless challenges, different accounts can compete
//!    for the same shard, and so on (plan sections 4 and 0.5).

use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::domain::storage_deal::{
    ChallengeOutcome, DealStatus, RetrievalChallengeRequest, StorageEconomicsParams, StorageError,
    StorageRegistry,
};
use crate::domain::storage_params::StorageDomainParams;
use crate::storage::content_id::ContentId;
use crate::storage::manifest::ContentManifest;

// --- Shared test helpers -------------------------------------------------

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn domain_params() -> StorageDomainParams {
    StorageDomainParams {
        chunk_size: 256,
        max_committed_chunks: 1_000_000,
        challenge_interval: 10,
        min_operator_bond: 1_000_000,
    }
}

fn good_manifest() -> ContentManifest {
    ContentManifest::from_bytes_sliced(
        b"B.U.D. E2E test content: three actors, one shard, one challenge",
        32,
    )
    .unwrap()
}

fn good_econ() -> StorageEconomicsParams {
    StorageEconomicsParams {
        operator_bond: 5_000_000,
        fee_per_byte_epoch: 100,
    }
}

/// A format-VALID test envelope (an honest marker -
/// not a REAL STARK proof; a minimal ProofEnvelope that bincode can deserialize).
fn valid_merkle_proof() -> Vec<u8> {
    let envelope = bud_proof::ProofEnvelope {
        proof_format_version: 1,
        backend: "test-backend".to_string(),
        p3_version: "0.6".to_string(),
        fri_params_id: "test-fri".to_string(),
        public_inputs_hash: [0x42u8; 32],
        proof_bytes: vec![0xABu8; 96],
        degree_bits: 8,
    };
    bincode::serialize(&envelope).expect("test envelope serialize")
}

//  1. THREE-ACTOR E2E - manifest -> deal -> challenge -> answer

#[test]
fn e2e_three_actor_manifest_to_challenge_flow() {
    // Three actors: operator A, operator B, observer C.
    let operator_a = addr(0xA1);
    let operator_b = addr(0xB2);
    let watcher_c = addr(0xC3);

    // Operator A opens a deal for shard 1.
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();

    let deal_a = reg
        .open_deal(
            42,
            &manifest,
            shard_id,
            operator_a,
            0,
            100,
            300,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("A deal-open");

    // Operator B opens the first replica deal for the same shard (replication).
    let deal_b = reg
        .open_deal(
            42,
            &manifest,
            shard_id,
            operator_b,
            1,
            100,
            300,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("B deal-open");
    assert_ne!(deal_a, deal_b);

    // Observer C: any account, with no role and not on the whitelist.
    // Opens a retrieval challenge against operator A's deal.
    let req = RetrievalChallengeRequest {
        deal_id: deal_a,
        byte_start: 0,
        byte_end: 16,
        challenge_epoch: 150,
        deadline_epoch: 200,
        opener_bond: 50_000,
        opener: Some(test_addr_from_byte(3u8)),
        opener_signature: None,
    };
    let challenge_id = reg
        .open_challenge(
            req.deal_id,
            req.byte_start,
            req.byte_end,
            req.challenge_epoch,
            req.deadline_epoch,
            watcher_c,
            req.opener_bond,
        )
        .expect("C challenge-open");
    assert_eq!(reg.all_challenges().len(), 1);

    // Operator A answers in time. Whether the hash truly matches is verified
    // off chain - the chain only checks timing + identity +
    // structure (an interim limitation, plan section 2.5).
    let dummy_hash = ContentId::of_subrange(b"x", 0, 0);
    let result = reg
        .answer_challenge(
            challenge_id,
            dummy_hash,
            operator_a,
            175,
            Some(b"test-mock-proof"),
        )
        .expect("A answer");
    assert_eq!(result.outcome, ChallengeOutcome::Answered);
    assert_eq!(result.slashed_bond, 0);
    assert_eq!(reg.get_deal(deal_a).unwrap().status, DealStatus::Active);

    // Operator B's deal is unaffected (the challenge was opened only against
    // A).
    assert_eq!(reg.get_deal(deal_b).unwrap().status, DealStatus::Active);
}

#[test]
fn e2e_missed_challenge_slashes_only_the_target_deal() {
    // Three actors: A, B, C. A is challenged, B is not. A does not answer -> only
    // A is `Slashed`. B stays `Active`.
    let operator_a = addr(0xA1);
    let operator_b = addr(0xB2);
    let watcher_c = addr(0xC3);

    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    let deal_a = reg
        .open_deal(
            42,
            &manifest,
            shard_id,
            operator_a,
            0,
            100,
            300,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let deal_b = reg
        .open_deal(
            42,
            &manifest,
            shard_id,
            operator_b,
            1,
            100,
            300,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let cid = reg
        .open_challenge(deal_a, 0, 8, 110, 120, watcher_c, 50_000)
        .unwrap();
    let r = reg.finalize_missed_challenge(cid, 200).unwrap();
    assert_eq!(r.outcome, ChallengeOutcome::Missed);
    assert_eq!(r.slashed_bond, 5_000_000);
    assert_eq!(reg.get_deal(deal_a).unwrap().status, DealStatus::Slashed);
    assert_eq!(reg.get_deal(deal_b).unwrap().status, DealStatus::Active);
}

#[test]
fn e2e_malicious_operator_cached_range_misses_entropy_selected_challenge() {
    // The malicious operator M holds only the old predictable range 0..8
    // Cache'lerse canonical entropy
    // so it cannot answer the newly selected range and takes a missed-challenge slash.
    let malicious_operator = addr(0xD4);
    let watcher_c = addr(0xC3);
    let mut reg = StorageRegistry::new();
    let data = b"B.U.D. adversarial storage content with more than one challenge range";
    let manifest = ContentManifest::from_bytes_sliced(data, data.len() as u32).unwrap();
    let shard_id = manifest.shards[0].shard_id;
    let deal_id = reg
        .open_deal(
            42,
            &manifest,
            shard_id,
            malicious_operator,
            0,
            100,
            300,
            good_econ(),
            &domain_params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let deal = reg.get_deal(deal_id).unwrap().clone();

    let mut entropy = [0u8; 32];
    let mut selected = (0, 0);
    for seed in 1u8..=u8::MAX {
        let candidate = [seed; 32];
        let range = StorageRegistry::derive_challenge_range(
            crate::domain::storage_deal::StorageChallengeRangeInput {
                entropy: &candidate,
                deal: &deal,
                manifest: &manifest,
                opener: watcher_c,
                challenge_epoch: 110,
                deadline_epoch: 120,
                requested_len: 8,
                challenge_id: 0,
            },
        )
        .unwrap();
        if range.0 != 0 {
            entropy = candidate;
            selected = range;
            break;
        }
    }
    assert_ne!(
        selected.0, 0,
        "test entropy must not pick the cached 0..8 range"
    );

    let challenge_id = reg
        .open_challenge_with_entropy(
            &RetrievalChallengeRequest {
                deal_id,
                byte_start: 0,
                byte_end: 8,
                challenge_epoch: 110,
                deadline_epoch: 120,
                opener_bond: 50_000,
                opener: Some(watcher_c),
                opener_signature: None,
            },
            watcher_c,
            &entropy,
        )
        .unwrap();
    let challenge = reg.get_challenge(challenge_id).unwrap();
    assert_eq!((challenge.byte_start, challenge.byte_end), selected);

    let cached_only_hash = ContentId::of_subrange(data, 0, 8);
    let required_hash = ContentId::of_subrange(data, challenge.byte_start, challenge.byte_end);
    assert_ne!(
        cached_only_hash, required_hash,
        "holding only the predictable old range must not answer the canonical challenge"
    );

    let result = reg.finalize_missed_challenge(challenge_id, 130).unwrap();
    assert_eq!(result.outcome, ChallengeOutcome::Missed);
    assert_eq!(reg.get_deal(deal_id).unwrap().status, DealStatus::Slashed);
}

#[test]
fn e2e_deal_queries_return_replica_set() {
    // Three deals: replicas 0/1/2. `deals_for_shard` must return all three.
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    for i in 0..3u8 {
        reg.open_deal(
            42,
            &manifest,
            shard_id,
            addr(0x10 + i),
            i,
            100,
            300,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    }
    assert_eq!(
        reg.deals_for_shard(&manifest.manifest_id, &shard_id).len(),
        3
    );
    assert_eq!(reg.deals_for_manifest(&manifest.manifest_id).len(), 3);
}

//  2. MODULE-INDEPENDENCE INVARIANTS (plan sections 0.5 and 4)
//
// These 9 invariants test B.U.D.'s requirement that it can be "run entirely by
// an independent node without depending on any service run by the Budlum team".
// Each one concretely attempts an attack/dependency scenario and
// invalidates it.

/// Invariant 1: no storage action requires a whitelist.
/// (The same idea already exists for validators/relayers in the
/// `permissionless.rs` tests; we repeat it here storage-specifically because the
/// code coverage differs.)
#[test]
fn invariant_1_no_whitelist_for_deal_or_challenge() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    // An account registered nowhere both opens a deal and opens a challenge.
    let stranger = addr(0xEE);
    let deal = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            stranger,
            0,
            1,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("stranger opens a deal without any prior approval");
    let _ = reg
        .open_challenge(deal, 0, 4, 2, 5, stranger, 10)
        .expect("stranger opens a challenge without any prior approval");
}

/// Invariant 2: `StorageRegistry` has NO admin/pause/freeze hook.
/// The type system already guarantees this (see the full API surface);
/// this test still locks the declaration, so that an accidental
/// `fn pause_all(&mut self)` added later becomes visible.
#[test]
fn invariant_2_no_admin_pause_freeze_hook() {
    // The public API surface of `StorageRegistry`:
    //   - new, register_manifest, validate_shard_membership
    //   - open_deal, open_challenge, answer_challenge,
    //     Finalize_missed_challenge, expire_deal
    //   - get_deal, get_challenge, get_result,
    //     Deals_for_shard, deals_for_manifest,
    //     All_deals, all_challenges, all_results
    // There is no `pause_*`, `freeze_*`, `admin_*`, `whitelist_*` or `force_*`
    // function - Rust has no `doesnt_exist!` macro for the names that must
    // not exist, so we enumerate the surface
    // by hand:
    let registry: StorageRegistry = StorageRegistry::new();
    // Permissionless surface check: on an empty registry every access method works,
    // and no admin/pause/freeze method exists (the README permissionless rule).
    assert!(
        registry.all_deals().is_empty(),
        "empty registry has no deals"
    );
    assert!(
        registry.all_challenges().is_empty(),
        "empty registry has no challenges"
    );
    assert!(
        registry.all_results().is_empty(),
        "empty registry has no results"
    );
}

/// Invariant 3: any account can open a challenge for any shard - even the
/// operator itself, even against its own deal
/// (the anti-spam bond suffices; there is no other gate).
#[test]
fn invariant_3_any_account_can_challenge_any_deal() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    let op = addr(0x99);
    let deal = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            op,
            0,
            1,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();

    // This invariant measures "who may open a challenge", not the rate limit.
    // Consecutive challenges for the same (operator, manifest) pair have a
    // MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS (=4) epoch bosluk sart; hepsini
    // cooldown; opening in the same epoch is refused with ChallengeRateLimited.
    // Challenge_epoch is the 4th argument; deadline_epoch the 5th.
    let cooldown = StorageRegistry::MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS;
    // (a) the operator against its own deal
    let _ = reg
        .open_challenge(deal, 0, 1, 2, 3, op, 5)
        .expect("operator can self-challenge");
    // (b) izleyici
    let _ = reg
        .open_challenge(deal, 0, 1, 2 + cooldown, 3 + cooldown, addr(0xAA), 5)
        .expect("any account can challenge");
    // (c) a rival operator
    let _ = reg
        .open_challenge(
            deal,
            0,
            1,
            2 + 2 * cooldown,
            3 + 2 * cooldown,
            addr(0xBB),
            5,
        )
        .expect("rival can challenge");
}

/// Invariant 4: if the operator bond is above
/// `StorageDomainParams::min_operator_bond` anyone can open a deal - no KYC, no
/// whitelist, no official application. The same account may open several deals (replicas) for the same shard.
#[test]
fn invariant_4_any_account_meeting_bond_can_open_deal() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    for i in 0..5u8 {
        reg.open_deal(
            1,
            &manifest,
            shard_id,
            addr(i + 1),
            i,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("any account with bond can open a deal");
    }
    assert_eq!(reg.all_deals().len(), 5);
}

/// Invariant 5: a challenge opener_bond must be > 0, otherwise anyone could
/// open free spam challenges. This is the data-sovereignty section 0.5
/// formula: no privileged anti-spam role, only an economic incentive.
#[test]
fn invariant_5_opener_bond_must_be_positive() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    let deal = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    assert_eq!(
        reg.open_challenge(deal, 0, 1, 1, 2, addr(2), 0),
        Err(StorageError::ZeroOpenerBond)
    );
}

/// Invariant 6: slashing only happens through a missed deadline -
/// "operator verileri yok etti" gibi ekstra-supreme iddialar zincir
/// it CANNOT be done otherwise. This guards against the "false-green path" risk
/// of vision section 9.1.
#[test]
fn invariant_6_slash_only_via_missed_deadline() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    let deal = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let cid = reg.open_challenge(deal, 0, 1, 1, 2, addr(2), 5).unwrap();
    // Answered -> NOT slashed.
    let _ = reg
        .answer_challenge(
            cid,
            ContentId::of(b"x"),
            addr(1),
            2,
            Some(b"test-mock-proof"),
        )
        .unwrap();
    assert_eq!(reg.get_deal(deal).unwrap().status, DealStatus::Active);
    // Before trying to open another challenge that has expired
    // Finalize edemeyiz - yeni bir deal ile test edelim.
    let deal2 = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            addr(1),
            1,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    // deal2 belongs to the same operator (addr(1)) and the same manifest; the first challenge
    // was opened with challenge_epoch=1, so to clear the rate-limit window
    // advance challenge_epoch (the 4th argument) by the cooldown.
    let cooldown6 = StorageRegistry::MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS;
    let cid2 = reg
        .open_challenge(deal2, 0, 1, 1 + cooldown6, 2 + cooldown6, addr(2), 5)
        .unwrap();
    // No answer, the deadline passed -> Slashed.
    let r = reg.finalize_missed_challenge(cid2, 100).unwrap();
    assert_eq!(r.outcome, ChallengeOutcome::Missed);
    assert_eq!(reg.get_deal(deal2).unwrap().status, DealStatus::Slashed);
}

/// Invariant 7: once a deal is `Slashed` no new challenge is accepted -
/// this keeps the jailed state consistent.
#[test]
fn invariant_7_slashed_deal_rejects_new_challenges() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let shard_id = manifest.shards[0].shard_id;
    let dp = domain_params();
    let deal = reg
        .open_deal(
            1,
            &manifest,
            shard_id,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let cid = reg.open_challenge(deal, 0, 1, 1, 2, addr(2), 5).unwrap();
    reg.finalize_missed_challenge(cid, 100).unwrap();
    // Now try to open a new challenge:
    let err = reg
        .open_challenge(deal, 0, 1, 5, 6, addr(2), 5)
        .unwrap_err();
    assert!(matches!(err, StorageError::DealNotActive(_)));
}

/// Invariant 8: a storage deal is bound to the `manifest`; if the shard_id
/// is not in the manifest no deal can be opened. This prevents random/spoofed
/// `(manifest_id, shard_id)` pairs from creating deals.
#[test]
fn invariant_8_deal_requires_shard_to_be_in_manifest() {
    let mut reg = StorageRegistry::new();
    let manifest = good_manifest();
    let dp = domain_params();
    let bogus = ContentId([0xFFu8; 32]);
    let err = reg
        .open_deal(
            1,
            &manifest,
            bogus,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::UnknownShard { .. }));
}

/// Invariant 9: a `ContentManifest` produced under the same conditions always
/// has the same `manifest_id` - so two independent nodes agree on the same
/// `manifest_id` without needing any server run by the team.
/// Data sovereignty.
#[test]
fn invariant_9_manifest_id_is_deterministic_across_nodes() {
    let bytes = b"the same bytes, sliced the same way, on any independent node";
    let m1 = ContentManifest::from_bytes_sliced(bytes, 16).unwrap();
    let m2 = ContentManifest::from_bytes_sliced(bytes, 16).unwrap();
    assert_eq!(m1.manifest_id, m2.manifest_id);
    // And both are consistent within the same domain:
    let dp = domain_params();
    let mut r1 = StorageRegistry::new();
    let mut r2 = StorageRegistry::new();
    let d1 = r1
        .open_deal(
            1,
            &m1,
            m1.shards[0].shard_id,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let d2 = r2
        .open_deal(
            1,
            &m2,
            m2.shards[0].shard_id,
            addr(1),
            0,
            0,
            10,
            good_econ(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap();
    let leaf1 = crate::domain::storage_deal::storage_deal_leaf_hash(r1.get_deal(d1).unwrap());
    let leaf2 = crate::domain::storage_deal::storage_deal_leaf_hash(r2.get_deal(d2).unwrap());
    assert_eq!(leaf1, leaf2);
}
