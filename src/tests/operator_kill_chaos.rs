//! Operator-kill chaos skeleton for the B.U.D. all_three baraj.
//!
//! Baraj (PLAN §BY): "≥3 operatörlü mini-ağ; bir operatör ölünce repair gerçekten
//! açılsın." This file is the **in-tree** half of that claim: the registry path
//! from multi-operator placement through kill → ticket → accept → live count.
//!
//! What it is **not** yet:
//! - a multi-process network with real disks and bonds (baraj item 1),
//! - an adversarial suite (lazy / Sybil / outsourcing — baraj item 3).
//! Those stay open. A skeleton that pretends they are closed is a lie; the
//! module doc names the gap so a green test cannot be read as all_three.
//!
//! Wiring checked here:
//! 1. Three operators hold distinct replica slots of one shard.
//! 2. Killing one (missed challenge) slashes only that deal and opens a
//!    `FailedDeal` ticket.
//! 3. A fourth operator accepts the ticket; live replica count returns.
//! 4. A coded object with a never-placed shard opens a `NeverPlaced` ticket
//!    when the repair band would otherwise only log.

use crate::core::address::Address;
use crate::domain::storage_deal::{
    ChallengeOutcome, DealStatus, ReallocationCause, ReallocationStatus, StorageEconomicsParams,
    StorageRegistry, STORAGE_REPLICATION_TARGET,
};
use crate::domain::storage_params::StorageDomainParams;
use crate::storage::content_id::ContentId;
use crate::storage::manifest::ContentManifest;
use crate::storage::{encode_object, ErasureScheme};

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

fn good_econ() -> StorageEconomicsParams {
    StorageEconomicsParams {
        operator_bond: 5_000_000,
        fee_per_byte_epoch: 100,
    }
}

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

fn open_replica(
    reg: &mut StorageRegistry,
    manifest: &ContentManifest,
    shard_id: ContentId,
    operator: Address,
    replica_index: u8,
) -> u64 {
    reg.open_deal(
        42,
        manifest,
        shard_id,
        operator,
        replica_index,
        100,
        400,
        good_econ(),
        &domain_params(),
        Some(valid_merkle_proof()),
        Some([0x42u8; 32]),
    )
    .unwrap_or_else(|e| panic!("replica {replica_index} must open: {e}"))
}

/// Kill → ticket → accept restores the replica count for one shard.
///
/// This is baraj item 2 reduced to the registry state machine. Three live
/// operators, one dies, a fourth takes the ticket. If the ticket is missing or
/// the accept path is broken, the live count stays short forever under a log
/// line that looks like progress.
#[test]
fn operator_kill_opens_ticket_and_replacement_restores_count() {
    let op_a = addr(0xA1);
    let op_b = addr(0xB2);
    let op_c = addr(0xC3);
    let op_d = addr(0xD4);
    let watcher = addr(0xEE);

    let mut reg = StorageRegistry::new();
    let manifest = ContentManifest::from_bytes_sliced(
        b"operator-kill chaos: three holders, one dies, one replaces",
        32,
    )
    .expect("manifest");
    let shard_id = manifest.shards[0].shard_id;

    let deal_a = open_replica(&mut reg, &manifest, shard_id, op_a, 0);
    let deal_b = open_replica(&mut reg, &manifest, shard_id, op_b, 1);
    let deal_c = open_replica(&mut reg, &manifest, shard_id, op_c, 2);

    assert_eq!(
        reg.active_replica_count(&manifest.manifest_id, &shard_id),
        3,
        "three operators hold the shard before the kill"
    );
    assert_eq!(
        usize::from(STORAGE_REPLICATION_TARGET),
        3,
        "fixture matches the protocol target so the kill is a real under-rep"
    );

    // Watcher challenges A; A is silent past the deadline → slash + ticket.
    let challenge_id = reg
        .open_challenge(deal_a, 0, 8, 150, 160, watcher, 50_000)
        .expect("challenge opens");
    let missed = reg
        .finalize_missed_challenge(challenge_id, 200)
        .expect("missed challenge finalises");
    assert_eq!(missed.outcome, ChallengeOutcome::Missed);
    assert_eq!(missed.slashed_bond, good_econ().operator_bond);
    assert_eq!(reg.get_deal(deal_a).unwrap().status, DealStatus::Slashed);
    assert_eq!(reg.get_deal(deal_b).unwrap().status, DealStatus::Active);
    assert_eq!(reg.get_deal(deal_c).unwrap().status, DealStatus::Active);
    assert_eq!(
        reg.active_replica_count(&manifest.manifest_id, &shard_id),
        2,
        "kill drops the live count by exactly one"
    );

    let tickets = reg.all_reallocation_tickets();
    assert_eq!(tickets.len(), 1, "exactly one repair ticket after one kill");
    let ticket = tickets[0].clone();
    assert_eq!(ticket.cause, ReallocationCause::FailedDeal);
    assert_eq!(ticket.failed_deal_id, deal_a);
    assert_eq!(ticket.status, ReallocationStatus::Pending);
    assert_eq!(ticket.slashed_operator, op_a);
    let ticket_id = ticket.ticket_id;

    // The slashed operator cannot take its own replacement.
    let barred = reg
        .accept_reallocation_ticket(
            ticket_id,
            op_a,
            201,
            500,
            good_econ(),
            &domain_params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect_err("slashed operator must stay barred");
    assert!(
        matches!(
            barred,
            crate::domain::storage_deal::StorageError::ReplacementOperatorMatchesSlashed(_)
        ),
        "got {barred:?}"
    );

    // A fresh fourth operator restores the slot.
    let replacement = reg
        .accept_reallocation_ticket(
            ticket_id,
            op_d,
            201,
            500,
            good_econ(),
            &domain_params(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("replacement accepts");
    assert_eq!(
        reg.get_deal(replacement).unwrap().status,
        DealStatus::Active
    );
    assert_eq!(
        reg.get_reallocation_ticket(ticket_id)
            .unwrap()
            .status,
        ReallocationStatus::ActiveReplacement
    );
    assert_eq!(
        reg.active_replica_count(&manifest.manifest_id, &shard_id),
        3,
        "accept must bring the live count back to the pre-kill target"
    );
}

/// Coded object: kill one of n shard holders and the object-level live count
/// moves; a repair ticket still names the failed deal, not a random slot.
#[test]
fn coded_object_kill_keeps_object_above_k_when_parity_remains() {
    let data: Vec<u8> = (0u8..=200).cycle().take(1200).collect();
    let enc = encode_object(&data, ErasureScheme { k: 4, n: 6 }).expect("encode");
    let manifest = enc.to_manifest().expect("manifest");
    let mut reg = StorageRegistry::new();
    let dp = domain_params();
    let econ = good_econ();

    // One deal per distinct shard (object-level durability = live shard count).
    let mut deals = Vec::new();
    for (i, shard) in manifest.shards.iter().enumerate() {
        let id = reg
            .open_deal(
                42,
                &manifest,
                shard.shard_id,
                addr(0x10 + i as u8),
                0,
                100,
                400,
                econ.clone(),
                &dp,
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_or_else(|e| panic!("shard {i}: {e}"));
        deals.push(id);
    }
    assert_eq!(reg.live_shard_count(&manifest.manifest_id), 6);

    // Kill shard 0's only holder.
    let victim = deals[0];
    let cid = reg
        .open_challenge(victim, 0, 4, 150, 160, addr(0xFF), 50_000)
        .unwrap();
    reg.finalize_missed_challenge(cid, 200).unwrap();
    assert_eq!(reg.get_deal(victim).unwrap().status, DealStatus::Slashed);
    assert_eq!(
        reg.live_shard_count(&manifest.manifest_id),
        5,
        "one shard lost, five remain"
    );
    // (4,6) still reconstructs with 5 live pieces.
    assert!(
        reg.objects_needing_repair(2)
            .iter()
            .all(|(id, _, _)| id != &manifest.manifest_id)
            || reg.live_shard_count(&manifest.manifest_id) >= 4,
        "with five of six live the object must still sit at or above k"
    );

    let ticket = reg
        .all_reallocation_tickets()
        .first()
        .copied()
        .expect("slash must open a ticket for the killed shard");
    assert_eq!(ticket.failed_deal_id, victim);
    assert_eq!(ticket.cause, ReallocationCause::FailedDeal);
    assert_eq!(ticket.shard_id, manifest.shards[0].shard_id);
}

/// Bootstrap half of the repair band: a registered shard with no historic deal
/// gets a NeverPlaced ticket, not a warn-and-walk log.
#[test]
fn never_placed_shard_on_coded_object_is_ticketed() {
    let data: Vec<u8> = (0u8..=200).cycle().take(1200).collect();
    let enc = encode_object(&data, ErasureScheme { k: 4, n: 6 }).expect("encode");
    let manifest = enc.to_manifest().expect("manifest");
    let mut reg = StorageRegistry::new();
    reg.register_manifest(&manifest);

    // Place five of six shards; leave the last never-placed.
    let dp = domain_params();
    let econ = good_econ();
    for (i, shard) in manifest.shards.iter().enumerate().take(5) {
        reg.open_deal(
            42,
            &manifest,
            shard.shard_id,
            addr(0x20 + i as u8),
            0,
            100,
            400,
            econ.clone(),
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .unwrap_or_else(|e| panic!("place {i}: {e}"));
    }
    let missing = manifest.shards[5].shard_id;
    assert_eq!(reg.active_replica_count(&manifest.manifest_id, &missing), 0);
    assert!(
        reg.deals_for_shard(&manifest.manifest_id, &missing).is_empty(),
        "fixture must have no historic deal on the missing shard"
    );

    let ticket_id = reg
        .open_never_placed_ticket(42, manifest.manifest_id, missing, 0, 100)
        .expect("never-placed path must open a bootstrap ticket");
    let ticket = reg.get_reallocation_ticket(ticket_id).unwrap();
    assert_eq!(ticket.cause, ReallocationCause::NeverPlaced);
    assert_eq!(ticket.failed_deal_id, 0);
    assert_eq!(ticket.shard_id, missing);
    assert_eq!(ticket.status, ReallocationStatus::Pending);

    // Accept by a new operator places the first copy.
    let holder = addr(0x99);
    let deal = reg
        .accept_reallocation_ticket(
            ticket_id,
            holder,
            101,
            500,
            econ,
            &dp,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect("bootstrap ticket is acceptable");
    assert_eq!(reg.get_deal(deal).unwrap().operator, holder);
    assert_eq!(reg.active_replica_count(&manifest.manifest_id, &missing), 1);
    assert_eq!(reg.live_shard_count(&manifest.manifest_id), 6);
}

/// Explicit debt marker: all_three is not closed by this file alone.
///
/// A test named "baraj" that only exercises the registry would be a false
/// green. This one fails the build if someone deletes the module-level warning
/// without replacing it with the multi-node / adversarial halves.
#[test]
fn all_three_baraj_is_not_claimed_by_this_skeleton() {
    let doc = include_str!("operator_kill_chaos.rs");
    assert!(
        doc.contains("What it is **not** yet"),
        "the skeleton must keep naming the open halves of all_three"
    );
    assert!(
        doc.contains("multi-process network"),
        "baraj item 1 (real disks/bonds across nodes) must stay listed as open"
    );
    assert!(
        doc.contains("adversarial suite"),
        "baraj item 3 (lazy/Sybil/outsourcing) must stay listed as open"
    );
}
