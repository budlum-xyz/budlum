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
    manifest_id_from_parts, ContentCipher, ContentEncryption, ContentManifest, ErasureScheme,
    ShardKind, ShardRef,
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
        manifest_id_from_parts(&m.shards, &m.erasure, &m.encryption),
        manifest_id_from_parts(&relabelled, &m.erasure, &m.encryption),
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
        manifest_id_from_parts(&m.shards, &honest, &m.encryption),
        manifest_id_from_parts(&m.shards, &understated, &m.encryption),
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
    lying.manifest_id = manifest_id_from_parts(&lying.shards, &lying.erasure, &lying.encryption);
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
    m.manifest_id = manifest_id_from_parts(&m.shards, &m.erasure, &m.encryption);
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
        manifest_id_from_parts(&shards, &scheme, &ContentEncryption::Plaintext),
        "V2 must be domain-separated from V1"
    );
}

/// What the chain records about how content was protected.
///
/// The chain holds no bytes, so it cannot encrypt and cannot verify that
/// anyone else did. What it can do is carry the uploader's statement inside
/// the commitment, so the statement cannot be rewritten under a stable id.
/// These lock that the statement is actually bound and actually checked as
/// far as it can be.
mod encryption_declaration {
    use super::*;

    #[test]
    fn declaring_client_side_encryption_changes_the_manifest_id() {
        // Measured before this field existed: the same shards uploaded as
        // ciphertext and as plaintext produced one id, so the privacy claim
        // was whatever the reader assumed.
        let m = coded_manifest();
        let plaintext = m.manifest_id;
        let encrypted = m
            .clone()
            .with_encryption(ContentEncryption::ClientSide(ContentCipher::Aes256Gcm));

        assert_ne!(
            plaintext, encrypted.manifest_id,
            "the encryption declaration must be inside the commitment"
        );
        assert!(
            encrypted.verify_id().is_ok(),
            "the recomputed id must verify against the declaration it covers"
        );
    }

    #[test]
    fn two_ciphers_are_two_different_objects() {
        // A tag shared between ciphers would let a manifest be reinterpreted
        // as naming a different construction at the same id.
        let m = coded_manifest();
        let gcm = m
            .clone()
            .with_encryption(ContentEncryption::ClientSide(ContentCipher::Aes256Gcm));
        let chacha = m.with_encryption(ContentEncryption::ClientSide(
            ContentCipher::ChaCha20Poly1305,
        ));

        assert_ne!(
            gcm.manifest_id, chacha.manifest_id,
            "each cipher must have its own commitment tag"
        );
    }

    #[test]
    fn rewriting_the_declaration_breaks_the_id() {
        // The attack the binding exists to stop: register as encrypted, then
        // serve a manifest reading plaintext at the same id, and a reader
        // concludes the bytes it pulled were never protected.
        let mut m = coded_manifest()
            .with_encryption(ContentEncryption::ClientSide(ContentCipher::Aes256Gcm));
        assert!(m.validate_untrusted().is_ok(), "the honest shape passes");

        m.encryption = ContentEncryption::Plaintext;
        let err = m
            .validate_untrusted()
            .expect_err("a rewritten declaration must not verify");
        assert!(
            err.contains("does not match"),
            "the error should name the id mismatch, got: {err}"
        );
    }

    #[test]
    fn a_manifest_written_before_this_field_reads_as_plaintext() {
        // Those manifests were written by a tree with no encryption in it.
        // Defaulting them to a privacy claim would invent one nobody made.
        let m = coded_manifest();
        assert_eq!(
            m.encryption,
            ContentEncryption::Plaintext,
            "the default must be the absence of a claim, not a claim"
        );
        assert!(!m.is_client_encrypted());
        assert_eq!(m.encryption.commitment_tag(), 0);
    }

    #[test]
    fn an_object_too_small_to_hold_an_auth_tag_cannot_claim_encryption() {
        // Every named cipher appends a 16-byte tag, so even a zero-length
        // plaintext encrypts to 16 bytes. Fewer than that was produced by
        // none of them. This catches the client that forgets to encrypt and
        // remembers to declare, which is the shape that ships.
        let tiny = ContentManifest::from_bytes_sliced(b"12345", 5)
            .expect("five bytes slice into one shard")
            .with_encryption(ContentEncryption::ClientSide(ContentCipher::Aes256Gcm));

        assert!(
            tiny.content_size() < crate::storage::MIN_AEAD_CIPHERTEXT_BYTES,
            "the fixture has to be below the tag length or it tests nothing"
        );
        let err = tiny
            .validate_untrusted()
            .expect_err("a 5-byte AEAD output does not exist");
        assert!(
            err.contains("authentication tag"),
            "the error should say why, got: {err}"
        );
    }

    #[test]
    fn an_object_at_the_tag_length_is_accepted() {
        // The inverse witness: the check must refuse impossible sizes and
        // nothing else. Sixteen bytes is exactly an empty plaintext sealed,
        // which is a real thing a client can upload.
        let exact = ContentManifest::from_bytes_sliced(&[7u8; 16], 16)
            .expect("sixteen bytes slice into one shard")
            .with_encryption(ContentEncryption::ClientSide(
                ContentCipher::XChaCha20Poly1305,
            ));

        assert_eq!(
            exact.content_size(),
            crate::storage::MIN_AEAD_CIPHERTEXT_BYTES
        );
        assert!(
            exact.validate_untrusted().is_ok(),
            "an object exactly the tag length is a sealed empty plaintext"
        );
        assert!(exact.is_client_encrypted());
    }

    #[test]
    fn a_small_plaintext_object_is_untouched_by_the_tag_check() {
        // The size floor applies to the claim, not to storage. A five-byte
        // plaintext object is ordinary and must stay registrable.
        let tiny = ContentManifest::from_bytes_sliced(b"12345", 5)
            .expect("five bytes slice into one shard");
        assert!(
            tiny.validate_untrusted().is_ok(),
            "the floor must not reach objects that claim nothing"
        );
    }

    #[test]
    fn the_declaration_carries_no_key_material() {
        // A key field in a public commitment is a key published on a public
        // chain. This locks the shape: the enum is two words wide at most,
        // which no wrapped key fits into.
        assert!(
            std::mem::size_of::<ContentEncryption>() <= 2,
            "ContentEncryption grew past a tag and a cipher byte; if a key, \
             key id, wrapped key or nonce was added, it is now on chain in \
             the clear"
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
