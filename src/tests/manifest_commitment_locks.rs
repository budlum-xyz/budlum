//! Locks on what a `ContentManifest` commits to and who is allowed to say so.
//!
//! Two findings closed alongside the Reed-Solomon coder, both of which were
//! invisible while replication was the only redundancy scheme:
//!
//! 1. `manifest_id` arrived from an RPC caller and nothing recomputed it, so a
//!    caller could register content under any id it chose.
//! 2. The commitment covered `(index, shard_id, size)` and not `kind` or
//!    `erasure`, so two manifests could share an id and disagree about how
//!    much redundancy the object has.
//!
//! Each test below fails if the corresponding check is removed.

use crate::domain::storage_deal::{StorageEconomicsParams, StorageError, StorageRegistry};
use crate::domain::storage_params::StorageDomainParams;
use crate::storage::content_id::ContentId;
use crate::storage::manifest::{
    manifest_id_from_parts, ContentManifest, ErasureScheme, ShardKind, ShardRef,
};
use crate::storage::{encode_object, reconstruct_object};

fn coded_manifest() -> ContentManifest {
    let data: Vec<u8> = (0..=180u8).cycle().take(900).collect();
    encode_object(&data, ErasureScheme { k: 4, n: 6 })
        .expect("a (4,6) code over 900 bytes encodes")
        .to_manifest()
        .expect("the encoding describes a manifest it can deliver")
}

#[test]
fn a_forged_manifest_id_is_refused() {
    let mut m = coded_manifest();
    assert!(m.verify_id().is_ok(), "an honest manifest verifies");

    m.manifest_id = ContentId([0xAA; 32]);
    let err = m
        .verify_id()
        .expect_err("an id that does not derive from the contents must be refused");
    assert!(
        err.contains("does not match"),
        "the error should name the mismatch, got: {err}"
    );
    assert!(
        m.validate_untrusted().is_err(),
        "the full untrusted check must refuse it too"
    );
}

/// A structurally valid proof envelope. Deal-open requires one before it
/// looks at anything else; this is the same shape the storage tests use.
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

#[test]
fn opening_a_deal_with_a_forged_manifest_is_refused() {
    // `open_deal` seeds the registry through `register_manifest`, which is
    // first-writer-wins. If it trusted the caller's id, the deal path would be
    // a second way to squat an entry even with the RPC path guarded.
    let mut reg = StorageRegistry::default();
    let mut m = coded_manifest();
    let shard_id = m.shards[0].shard_id;
    m.manifest_id = ContentId([0x11; 32]);

    let econ = StorageEconomicsParams {
        operator_bond: 1_000_000,
        fee_per_byte_epoch: 100,
    };
    let params = StorageDomainParams::default();
    let err = reg
        .open_deal(
            42,
            &m,
            shard_id,
            crate::core::address::Address([9u8; 32]),
            0,
            100,
            200,
            econ,
            &params,
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
        .expect_err("a deal must not register a manifest under a chosen id");
    assert!(
        matches!(err, StorageError::InvalidManifest { .. }),
        "expected InvalidManifest, got {err:?}"
    );
    assert!(
        reg.get_manifest(&ContentId([0x11; 32])).is_none(),
        "the forged id must not have been indexed"
    );
}

#[test]
fn relabelling_a_shard_changes_the_manifest_id() {
    // Measured before the fix: flipping Data -> Parity left the id unchanged.
    // `kind` decides which shards a reconstructor treats as content.
    let m = coded_manifest();
    let mut relabelled = m.shards.clone();
    relabelled[0].kind = ShardKind::Parity;

    assert_ne!(
        manifest_id_from_parts(&m.shards, &m.erasure),
        manifest_id_from_parts(&relabelled, &m.erasure),
        "a shard's kind must be inside the commitment"
    );
}

#[test]
fn understating_k_changes_the_manifest_id() {
    // `k` is what a repair trigger compares against. A manifest claiming
    // k = 1 for a 4-of-6 object reads as safe at one surviving shard, so
    // repair never fires and the object is lost quietly.
    let m = coded_manifest();
    let honest = ErasureScheme { k: 4, n: 6 };
    let understated = ErasureScheme { k: 1, n: 6 };

    assert_ne!(
        manifest_id_from_parts(&m.shards, &honest),
        manifest_id_from_parts(&m.shards, &understated),
        "the erasure scheme must be inside the commitment"
    );

    // And the claim cannot simply be swapped in, because the shard kinds no
    // longer match it.
    let swapped = m.clone();
    assert!(
        swapped.with_erasure(understated).is_err(),
        "a scheme the shard list cannot deliver must be refused"
    );
}

#[test]
fn content_size_is_the_object_not_the_stored_bytes() {
    // Under erasure coding the two differ by the parity shards and the padded
    // tail stripe. A reconstructor that used total_size would return padding.
    let data: Vec<u8> = (0..=99u8).cycle().take(1000).collect();
    let enc = encode_object(&data, ErasureScheme { k: 4, n: 6 }).unwrap();
    let m = enc.to_manifest().unwrap();

    assert_eq!(
        m.content_size(),
        1000,
        "content_size is the object's length"
    );
    assert!(
        m.total_size > m.content_size(),
        "stored bytes {} should exceed the {} byte object",
        m.total_size,
        m.content_size()
    );

    let present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
    let out = reconstruct_object(&m, &present).unwrap();
    assert_eq!(out.len(), 1000, "reconstruction must trim the padding");
    assert_eq!(out, data);
}

#[test]
fn a_content_size_larger_than_the_stored_bytes_is_refused() {
    // Otherwise a reconstructor reads past what it recovered.
    let m = coded_manifest();
    let stored = m.total_size;
    assert!(
        m.clone().with_content_size(stored + 1).is_err(),
        "an object cannot be larger than the shards holding it"
    );

    let mut lying = coded_manifest();
    lying.content_size = stored + 1;
    lying.manifest_id = manifest_id_from_parts(&lying.shards, &lying.erasure);
    assert!(
        lying.validate_untrusted().is_err(),
        "the untrusted check must catch it even with a consistent id"
    );
}

#[test]
fn a_legacy_replication_manifest_still_validates() {
    // Manifests built the old way carry no content_size and are pure
    // replication; the new checks must not reject them.
    let m = ContentManifest::from_bytes_sliced(b"hello world, stored twice", 8).unwrap();
    assert!(
        m.validate_untrusted().is_ok(),
        "a locally built replication manifest must pass"
    );
    assert_eq!(
        m.content_size(),
        m.total_size,
        "with no parity the two lengths agree"
    );
}

#[test]
fn shard_count_and_total_size_must_agree_with_the_shard_list() {
    // `validate_untrusted` is the only thing standing between an RPC caller
    // and the registry, so it has to check the scalars too, not just the id.
    let mut m = coded_manifest();
    m.shard_count = 99;
    assert!(
        m.validate_untrusted().is_err(),
        "a shard_count that contradicts the list must be refused"
    );

    let mut m = coded_manifest();
    m.total_size += 1;
    assert!(
        m.validate_untrusted().is_err(),
        "a total_size that contradicts the shard sizes must be refused"
    );
}

#[test]
fn duplicate_shard_indices_are_refused() {
    let mut m = coded_manifest();
    m.shards[1].index = m.shards[0].index;
    m.total_size = m.shards.iter().map(|s| s.size as u64).sum();
    m.manifest_id = manifest_id_from_parts(&m.shards, &m.erasure);
    assert!(
        m.validate_untrusted().is_err(),
        "two shards at the same index would make lookup ambiguous"
    );
}

#[test]
fn the_v2_commitment_differs_from_v1() {
    // If V2 hashed to the same value as V1 the new fields would be decorative.
    let shards = vec![
        ShardRef::from_bytes(0, b"first shard bytes"),
        ShardRef::from_bytes(1, b"second shard bytes"),
    ];
    let scheme = ErasureScheme::replication(2);
    assert_ne!(
        crate::storage::manifest::manifest_id_from_shards(&shards),
        manifest_id_from_parts(&shards, &scheme),
        "V2 must be domain-separated from V1"
    );
}

/// What an owner said about content they intend to self-host.
///
/// `MobileSelfContentPolicy` let an owner mark content critical and name how
/// many paid replicas it needs. The type was written, tested, and read by
/// nothing, so a phone could take the only copy of something its owner had
/// already declared too important for a phone.
mod self_host_policy {
    use super::*;
    use crate::domain::storage_deal::OperatorClass;
    use crate::storage::{MobileAvailabilityClass, MobileSelfContentPolicy, MobileSelfProfile};

    fn owner() -> crate::core::address::Address {
        crate::core::address::Address([3u8; 32])
    }

    fn profile() -> MobileSelfProfile {
        MobileSelfProfile {
            owner: owner(),
            device_commitment: [9u8; 32],
            availability: MobileAvailabilityClass::Opportunistic,
            max_storage_bytes: 1024,
            metered_network_ok: false,
            battery_saver_aware: true,
            last_seen_block: 10,
        }
    }

    fn policy(critical: bool, replicas: u16, allowed: bool) -> MobileSelfContentPolicy {
        MobileSelfContentPolicy {
            content_id: ContentId([5u8; 32]),
            owner: owner(),
            critical,
            required_paid_replicas: replicas,
            self_host_allowed: allowed,
        }
    }

    #[test]
    fn a_declaration_that_contradicts_itself_is_refused() {
        // Critical content with no paid replicas is the shape the type was
        // written to catch, and nothing was calling the check.
        let mut reg = StorageRegistry::new();
        let err = reg
            .declare_self_host_policy(policy(true, 0, true), &profile())
            .expect_err("critical content needs paid replicas");
        assert!(matches!(err, StorageError::SelfHostRefusedByPolicy { .. }));
    }

    #[test]
    fn a_declaration_for_someone_elses_content_is_refused() {
        let mut reg = StorageRegistry::new();
        let mut p = policy(false, 0, true);
        p.owner = crate::core::address::Address([99u8; 32]);
        assert!(reg.declare_self_host_policy(p, &profile()).is_err());
    }

    #[test]
    fn a_coherent_declaration_is_recorded() {
        // The inverse witness: the check must refuse contradictions and
        // nothing else, or every declaration would fail and the feature would
        // be off while looking enforced.
        let mut reg = StorageRegistry::new();
        assert!(reg
            .declare_self_host_policy(policy(true, 2, true), &profile())
            .is_ok());
    }

    #[test]
    fn content_nobody_declared_anything_about_is_allowed() {
        // Absence of a policy is not a restriction. Reading it as one would
        // turn a feature nobody opted into into a network-wide refusal.
        let reg = StorageRegistry::new();
        assert!(reg
            .check_self_host_allowed(&ContentId([1u8; 32]), &ContentId([2u8; 32]))
            .is_ok());
    }

    #[test]
    fn self_hosting_turned_off_is_refused() {
        let mut reg = StorageRegistry::new();
        reg.declare_self_host_policy(policy(false, 0, false), &profile())
            .expect("a non-critical declaration with no replicas is coherent");

        let err = reg
            .check_self_host_allowed(&ContentId([1u8; 32]), &ContentId([5u8; 32]))
            .expect_err("the owner turned self-hosting off");
        assert!(matches!(err, StorageError::SelfHostRefusedByPolicy { .. }));
    }

    #[test]
    fn critical_content_without_its_paid_replicas_is_refused() {
        // The finding, stated as a test: the owner asked for two paid
        // replicas before self-hosting, and none are open.
        let mut reg = StorageRegistry::new();
        reg.declare_self_host_policy(policy(true, 2, true), &profile())
            .expect("the declaration is coherent");

        let err = reg
            .check_self_host_allowed(&ContentId([1u8; 32]), &ContentId([5u8; 32]))
            .expect_err("no paid replicas are open");
        match err {
            StorageError::SelfHostRefusedByPolicy { reason, .. } => {
                assert!(
                    reason.contains("paid replica"),
                    "the reason should name what is missing, got: {reason}"
                );
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    /// Open a deal through the real path, so the test measures what a caller
    /// reaches rather than what the check does when called directly.
    ///
    /// Every earlier test in this module calls `check_self_host_allowed`
    /// itself, which proves the check is correct and proves nothing about
    /// whether anything runs it. That distinction is the finding: the check
    /// was correct and tested six ways for as long as no production path
    /// called it.
    fn open_for(
        reg: &mut StorageRegistry,
        manifest: &ContentManifest,
        shard_id: ContentId,
        operator: crate::core::address::Address,
        replica_index: u8,
    ) -> Result<u64, StorageError> {
        reg.open_deal(
            42,
            manifest,
            shard_id,
            operator,
            replica_index,
            100,
            200,
            StorageEconomicsParams {
                operator_bond: 1_000_000,
                fee_per_byte_epoch: 100,
            },
            &StorageDomainParams::default(),
            Some(valid_merkle_proof()),
            Some([0x42u8; 32]),
        )
    }

    /// The owner's declaration, keyed to a shard of a real manifest rather
    /// than the placeholder id the direct-call tests use.
    fn policy_for(shard_id: ContentId, critical: bool, replicas: u16) -> MobileSelfContentPolicy {
        let mut p = policy(critical, replicas, true);
        p.content_id = shard_id;
        p
    }

    #[test]
    fn a_phone_cannot_take_a_replica_the_owner_reserved_for_paid_operators() {
        // The finding, exercised where it bites: the owner marked this
        // content critical and asked for two paid replicas first, none are
        // open, and a phone offers to hold it. Before the check was wired,
        // this call returned a deal id.
        let manifest = coded_manifest();
        let shard_id = manifest.shards[1].shard_id;
        let phone = crate::core::address::Address([7u8; 32]);

        let mut reg = StorageRegistry::new();
        reg.set_operator_class(phone, OperatorClass::Mobile);
        reg.declare_self_host_policy(policy_for(shard_id, true, 2), &profile())
            .expect("two paid replicas for critical content is a coherent ask");

        let err = open_for(&mut reg, &manifest, shard_id, phone, 1)
            .expect_err("the owner's own policy has to refuse this placement");
        match err {
            StorageError::SelfHostRefusedByPolicy { reason, .. } => {
                assert!(
                    reason.contains("paid replica"),
                    "the refusal should name what is missing, got: {reason}"
                );
            }
            other => panic!("wrong error: {other:?}"),
        }

        // A refusal that already wrote something is not a refusal. `open_deal`
        // takes `&mut self`, so this is the half of the property a matching
        // error type does not cover.
        assert!(
            reg.deals_for_shard(&manifest.manifest_id, &shard_id)
                .is_empty(),
            "a refused deal must not be recorded"
        );
        assert!(
            reg.get_manifest(&manifest.manifest_id).is_none(),
            "a refused deal must not seed the manifest registry either"
        );
    }

    #[test]
    fn an_always_on_operator_is_not_asked_about_the_self_host_policy() {
        // First canary. The policy is about phones. Refusing an always-on
        // operator would block the very replicas the owner was asking for,
        // and the gate would be passing by rejecting everything.
        let manifest = coded_manifest();
        let shard_id = manifest.shards[1].shard_id;
        let server = crate::core::address::Address([8u8; 32]);

        let mut reg = StorageRegistry::new();
        reg.declare_self_host_policy(policy_for(shard_id, true, 2), &profile())
            .expect("the declaration is coherent");

        open_for(&mut reg, &manifest, shard_id, server, 1)
            .expect("an always-on operator is what the owner asked for");
    }

    #[test]
    fn a_phone_is_allowed_when_no_policy_names_the_content() {
        // Second canary. Content nobody restricted is not restricted content;
        // `check_self_host_allowed` returns `Ok(())` with no policy declared,
        // and wiring it must not turn that into a refusal.
        let manifest = coded_manifest();
        let shard_id = manifest.shards[1].shard_id;
        let phone = crate::core::address::Address([7u8; 32]);

        let mut reg = StorageRegistry::new();
        reg.set_operator_class(phone, OperatorClass::Mobile);

        open_for(&mut reg, &manifest, shard_id, phone, 1)
            .expect("no declaration means no restriction");
    }

    #[test]
    fn a_phone_is_allowed_once_the_paid_replicas_the_owner_asked_for_exist() {
        // Third canary, and the one that proves the check reads live state
        // rather than refusing every phone. Same policy, same phone, two paid
        // replicas now open: the condition the owner set is met, so the
        // placement goes through.
        let manifest = coded_manifest();
        let shard_id = manifest.shards[1].shard_id;
        let phone = crate::core::address::Address([7u8; 32]);

        let mut reg = StorageRegistry::new();
        reg.set_operator_class(phone, OperatorClass::Mobile);
        reg.declare_self_host_policy(policy_for(shard_id, true, 2), &profile())
            .expect("the declaration is coherent");

        open_for(
            &mut reg,
            &manifest,
            shard_id,
            crate::core::address::Address([1u8; 32]),
            0,
        )
        .expect("first paid replica");
        open_for(
            &mut reg,
            &manifest,
            shard_id,
            crate::core::address::Address([2u8; 32]),
            1,
        )
        .expect("second paid replica");
        assert_eq!(
            reg.active_replica_count(&manifest.manifest_id, &shard_id),
            2,
            "the two paid replicas the policy requires are open"
        );

        open_for(&mut reg, &manifest, shard_id, phone, 2)
            .expect("the owner's condition is met, so the phone may hold a copy");
    }

    #[test]
    fn a_phone_still_cannot_take_the_primary_even_with_the_policy_satisfied() {
        // The two mobile rules are independent and both have to hold. The
        // policy is the owner's choice about this content; the primary rule is
        // the protocol's, and satisfying the first does not buy the second.
        let manifest = coded_manifest();
        let shard_id = manifest.shards[1].shard_id;
        let phone = crate::core::address::Address([7u8; 32]);

        let mut reg = StorageRegistry::new();
        reg.set_operator_class(phone, OperatorClass::Mobile);

        let err = open_for(&mut reg, &manifest, shard_id, phone, 0)
            .expect_err("a phone cannot hold replica_index 0");
        assert!(
            matches!(err, StorageError::MobileOperatorCannotHoldPrimary(_)),
            "expected the primary refusal, got {err:?}"
        );
    }
}

/// Repair has to be decided per object, not per shard.
///
/// `under_replicated_shards` counts copies of each shard against a fixed
/// replication target. Under a `(k, n)` code the question is how many
/// *distinct* shards survive, compared against `k`. These lock the difference.
mod repair_band {
    use super::*;

    /// Retire every deal holding `shard_id`, so the shard counts as lost.
    ///
    /// Uses `expire_deal` rather than a test-only mutator: the point is that
    /// the repair band reacts to the same state transitions the chain makes.
    fn lose_shard(reg: &mut StorageRegistry, manifest_id: &ContentId, shard_id: &ContentId) {
        let deal_ids: Vec<u64> = reg
            .deals_for_shard(manifest_id, shard_id)
            .into_iter()
            .map(|d| d.deal_id)
            .collect();
        assert!(!deal_ids.is_empty(), "the shard should have had a deal");
        for deal_id in deal_ids {
            reg.expire_deal(deal_id, 200)
                .unwrap_or_else(|e| panic!("deal {deal_id} should expire at epoch 200: {e}"));
        }
    }

    /// Register a coded manifest and open one deal per shard.
    fn registry_with_object(k: u32, n: u32) -> (StorageRegistry, ContentId, Vec<ContentId>) {
        let data: Vec<u8> = (0..=200u8).cycle().take(1200).collect();
        let enc = encode_object(&data, ErasureScheme { k, n }).unwrap();
        let manifest = enc.to_manifest().unwrap();
        let shard_ids: Vec<ContentId> = manifest.shards.iter().map(|s| s.shard_id).collect();
        let manifest_id = manifest.manifest_id;

        let mut reg = StorageRegistry::default();
        let econ = StorageEconomicsParams {
            operator_bond: 1_000_000,
            fee_per_byte_epoch: 100,
        };
        let params = StorageDomainParams::default();
        for (i, shard_id) in shard_ids.iter().enumerate() {
            reg.open_deal(
                42,
                &manifest,
                *shard_id,
                crate::core::address::Address([(i as u8) + 1; 32]),
                0,
                100,
                200,
                econ.clone(),
                &params,
                Some(valid_merkle_proof()),
                Some([0x42u8; 32]),
            )
            .unwrap_or_else(|e| panic!("shard {i} deal should open: {e}"));
        }
        (reg, manifest_id, shard_ids)
    }

    #[test]
    fn a_fully_held_coded_object_needs_no_repair() {
        let (reg, manifest_id, _) = registry_with_object(4, 6);
        assert_eq!(reg.live_shard_count(&manifest_id), 6);
        assert!(
            reg.objects_needing_repair(2).is_empty(),
            "six of six shards live is not a repair case"
        );
        assert!(reg.unrecoverable_objects().is_empty());
    }

    #[test]
    fn shard_level_replication_disagrees_with_object_level_durability() {
        // Each shard is held exactly once, so every one of them is "under
        // replicated" against the target of 3 - while the object itself is
        // fully intact. Repair driven by the shard view would open six
        // pointless deals here.
        let (reg, manifest_id, _) = registry_with_object(4, 6);
        assert_eq!(
            reg.under_replicated_shards().len(),
            6,
            "the shard view flags every singly-held shard"
        );
        assert_eq!(
            reg.live_shard_count(&manifest_id),
            6,
            "all six distinct shards are held"
        );
        assert!(
            reg.objects_needing_repair(2).is_empty(),
            "the object view knows the object is whole"
        );
    }

    #[test]
    fn losing_into_the_margin_opens_the_repair_band() {
        let (mut reg, manifest_id, shard_ids) = registry_with_object(4, 6);
        // Lose one shard: 5 live, k = 4, margin 2 -> 4 <= 5 < 6, repair.
        lose_shard(&mut reg, &manifest_id, &shard_ids[0]);
        assert_eq!(reg.live_shard_count(&manifest_id), 5);

        let band = reg.objects_needing_repair(2);
        assert_eq!(band.len(), 1, "one object should be in the repair band");
        assert_eq!(band[0], (manifest_id, 5, 4));
        assert!(
            reg.unrecoverable_objects().is_empty(),
            "five of six is still recoverable"
        );
    }

    #[test]
    fn repair_fires_before_the_last_shard_of_headroom_is_gone() {
        // With margin 1 the band is only `live == k`, which is the edge case
        // the margin exists to avoid. Confirm the margin actually widens it.
        let (mut reg, manifest_id, shard_ids) = registry_with_object(4, 6);
        lose_shard(&mut reg, &manifest_id, &shard_ids[0]);

        assert!(
            reg.objects_needing_repair(1).is_empty(),
            "margin 1 only fires at the edge, which is too late"
        );
        assert_eq!(
            reg.objects_needing_repair(2).len(),
            1,
            "margin 2 fires with a shard of headroom left"
        );
    }

    #[test]
    fn an_unrecoverable_object_is_reported_separately_not_as_repairable() {
        // Below k there is nothing to reconstruct from; a repair deal opened
        // here would only burn an operator bond.
        let (mut reg, manifest_id, shard_ids) = registry_with_object(4, 6);
        for shard_id in shard_ids.iter().take(3) {
            lose_shard(&mut reg, &manifest_id, shard_id);
        }
        assert_eq!(reg.live_shard_count(&manifest_id), 3);

        assert!(
            reg.objects_needing_repair(2).is_empty(),
            "an unrecoverable object must not be queued for repair"
        );
        let lost = reg.unrecoverable_objects();
        assert_eq!(lost.len(), 1, "it must be reported as lost instead");
        assert_eq!(lost[0], (manifest_id, 3, 4));
    }

    #[test]
    fn replication_manifests_keep_their_old_meaning() {
        // k = n means every shard is needed, so the object has zero loss
        // tolerance and the next loss is fatal. The object view must not
        // quietly make legacy manifests look safer than they are.
        let (mut reg, manifest_id, shard_ids) = registry_with_object(3, 3);
        assert_eq!(reg.live_shard_count(&manifest_id), 3);
        assert!(
            reg.unrecoverable_objects().is_empty(),
            "all three shards held, so nothing is lost yet"
        );

        // Measured, and worth stating plainly: an intact k = n object still
        // reports as needing repair, because `live == k` is already the edge
        // the margin exists to warn about. There is no headroom to lose. That
        // is the honest answer for replication without parity, and it is the
        // signal that says "this object should be erasure coded".
        assert_eq!(
            reg.objects_needing_repair(1).len(),
            1,
            "a zero-tolerance object is permanently at the edge"
        );

        lose_shard(&mut reg, &manifest_id, &shard_ids[0]);
        assert_eq!(reg.live_shard_count(&manifest_id), 2);
        assert_eq!(
            reg.unrecoverable_objects().len(),
            1,
            "losing one of three when all three are needed loses the object"
        );
        assert!(
            reg.objects_needing_repair(1).is_empty(),
            "an already-lost object is not a repair candidate"
        );
    }

    #[test]
    fn a_coded_object_has_headroom_a_replicated_one_does_not() {
        // The contrast the coder exists for, on the same 1200 bytes.
        let (coded, coded_id, _) = registry_with_object(4, 6);
        let (replicated, replicated_id, _) = registry_with_object(3, 3);

        assert_eq!(coded.live_shard_count(&coded_id), 6);
        assert!(
            coded.objects_needing_repair(1).is_empty(),
            "a (4,6) object at full health has two shards of headroom"
        );
        assert_eq!(
            replicated.objects_needing_repair(1).len(),
            1,
            "a (3,3) object at full health has none"
        );
        assert_eq!(replicated.live_shard_count(&replicated_id), 3);
    }
}
