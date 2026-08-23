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
    manifest_id_from_parts_stored, ContentCipher, ContentEncryption, ContentManifest,
    ErasureScheme, ShardKind, ShardRef,
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
        manifest_id_from_parts_stored(
            &m.shards,
            &m.erasure,
            &m.encryption,
            m.content_size(),
            m.total_size
        ),
        manifest_id_from_parts_stored(
            &relabelled,
            &m.erasure,
            &m.encryption,
            m.content_size(),
            m.total_size
        ),
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
        manifest_id_from_parts_stored(
            &m.shards,
            &honest,
            &m.encryption,
            m.content_size(),
            m.total_size
        ),
        manifest_id_from_parts_stored(
            &m.shards,
            &understated,
            &m.encryption,
            m.content_size(),
            m.total_size
        ),
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
    lying.manifest_id = manifest_id_from_parts_stored(
        &lying.shards,
        &lying.erasure,
        &lying.encryption,
        lying.content_size(),
        lying.total_size,
    );
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
    m.manifest_id = manifest_id_from_parts_stored(
        &m.shards,
        &m.erasure,
        &m.encryption,
        m.content_size(),
        m.total_size,
    );
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
        manifest_id_from_parts_stored(
            &shards,
            &scheme,
            &ContentEncryption::Plaintext,
            shards.iter().map(|s| u64::from(s.size)).sum(),
            shards.iter().map(|s| u64::from(s.size)).sum(),
        ),
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

/// The coding audit: proving parity is parity without holding a shard.
///
/// A retrieval challenge asks whether the operator still has the bytes. It
/// cannot ask whether those bytes are *correct* parity, because the chain
/// never sees shard contents. An operator can therefore pass every retrieval
/// challenge while storing garbage under the parity shard's `ContentId`, and
/// the object is only discovered to be unrecoverable during the repair that
/// needed it.
mod coding_audit {
    use super::*;
    use crate::storage::{encode_object as enc_obj, ReedSolomon};

    /// Registry holding a coded object, plus the encoding, so a test can play
    /// both the chain and the operator.
    fn coded_registry() -> (
        StorageRegistry,
        crate::storage::EncodedObject,
        ContentManifest,
    ) {
        let data: Vec<u8> = (0..=199u8).cycle().take(800).collect();
        let encoded = enc_obj(&data, ErasureScheme { k: 4, n: 6 })
            .expect("a (4,6) code over 800 bytes encodes");
        let manifest = encoded
            .to_manifest()
            .expect("the encoding describes a manifest it can deliver");
        let mut reg = StorageRegistry::new();
        reg.register_manifest(&manifest);
        (reg, encoded, manifest)
    }

    /// Byte `column` of every data shard, in shard order.
    fn data_column(encoded: &crate::storage::EncodedObject, column: u64) -> Vec<u8> {
        (0..encoded.scheme.k as usize)
            .map(|j| encoded.shards[j][column as usize])
            .collect()
    }

    /// The coding audit is reachable from the chain, not only from these tests.
    ///
    /// `derive_coding_audit` and `verify_coding_audit` were complete and
    /// tested nine ways over, and unreachable: no `ChainCommand` opened an
    /// audit and no handler checked an answer. Everything above this line
    /// exercised them directly, which is precisely the shape that reads as
    /// finished work while nothing in production can invoke it.
    ///
    /// Measured against the source, because what was missing is an edge in
    /// the call graph and that is not observable from behaviour here.
    #[test]
    fn the_chain_can_open_and_answer_a_coding_audit() {
        let actor_src = include_str!("../chain/chain_actor.rs");

        for symbol in [
            "DeriveCodingAudit",
            "AnswerCodingAudit",
            "derive_coding_audit(",
            "verify_coding_audit(",
        ] {
            assert!(
                actor_src.contains(symbol),
                "{symbol} is missing from the chain actor; the audit is back to \
                 being a capability nothing can invoke"
            );
        }
    }

    /// The audited column comes from chain entropy, never from the caller.
    ///
    /// Both halves fail in opposite directions. An opener who picks the
    /// column picks one the operator is known to have, which makes the audit
    /// theatre. An operator who learns the column in advance stores that
    /// column and discards the rest, which is worse than storing nothing
    /// honestly, because it passes.
    #[test]
    fn the_audit_column_is_derived_from_chain_entropy() {
        let actor_src = include_str!("../chain/chain_actor.rs");
        // The match arm, not the enum variant and not the `ChainHandle`
        // method: all three spell `ChainCommand::DeriveCodingAudit {` or
        // something close to it, and `split_once` takes the first. Anchoring
        // on the arm's own first field is what distinguishes it. Measured:
        // CI failed on this, because the first match was the variant
        // declaration, whose body has no entropy in it at all.
        let handler = actor_src
            .split_once("ChainCommand::DeriveCodingAudit {\n                    manifest_id,")
            .map(|(_, after)| after)
            .expect("the DeriveCodingAudit match arm must exist");
        let handler = &handler[..handler.len().min(2000)];
        assert!(
            !handler.contains("challenge_id: u64,"),
            "the anchor matched the enum variant again, whose body carries no \
             entropy; the assertions below would be measuring a declaration"
        );

        assert!(
            handler.contains("last_block().hash.as_bytes()"),
            "the audit entropy must include the chain's own contribution, or \
             one party fixes the column alone"
        );
        assert!(
            handler.contains("chain_id.to_le_bytes()"),
            "the entropy must be chain-scoped, or an audit derived on one \
             chain is replayable on another"
        );
        assert!(
            !handler.contains("request.column"),
            "a caller-supplied column would let the opener choose what to test"
        );
    }

    /// The handler delegates rather than restating the relationship.
    ///
    /// A second copy of the generator check inside the actor would be the
    /// same defect as the executor's copied envelope bounds: correct on the
    /// day it was written and silently divergent afterwards.
    #[test]
    fn the_answer_handler_delegates_to_the_registry() {
        let actor_src = include_str!("../chain/chain_actor.rs");
        // Same anchoring as above, for the same reason.
        let handler = actor_src
            .split_once("ChainCommand::AnswerCodingAudit {\n                    audit,")
            .map(|(_, after)| after)
            .expect("the AnswerCodingAudit match arm must exist");
        let handler = &handler[..handler.len().min(1200)];

        assert!(
            handler.contains("verify_coding_audit("),
            "the handler must ask the registry, which owns the generator"
        );
        assert!(
            !handler.contains("ParityColumnMismatch"),
            "the handler is deciding the relationship itself; there must be \
             one definition of what a passing audit is"
        );
    }

    #[test]
    fn an_honest_operator_passes_the_audit() {
        let (reg, encoded, manifest) = coded_registry();
        let audit = StorageRegistry::derive_coding_audit(&[9u8; 32], &manifest, 1)
            .expect("a coded object has parity to audit");

        let column = data_column(&encoded, audit.column);
        let parity_byte = encoded.shards[encoded.scheme.k as usize + audit.parity_index as usize]
            [audit.column as usize];

        assert!(
            reg.verify_coding_audit(&audit, &column, parity_byte)
                .is_ok(),
            "an honestly encoded object must pass"
        );
    }

    #[test]
    fn an_operator_serving_garbage_parity_fails() {
        // The whole point: this operator holds bytes, so it answers every
        // retrieval challenge. The bytes are not parity.
        let (reg, encoded, manifest) = coded_registry();
        let audit = StorageRegistry::derive_coding_audit(&[9u8; 32], &manifest, 1).unwrap();
        let column = data_column(&encoded, audit.column);
        let honest = encoded.shards[encoded.scheme.k as usize + audit.parity_index as usize]
            [audit.column as usize];

        let err = reg
            .verify_coding_audit(&audit, &column, honest ^ 0xFF)
            .expect_err("parity that is not parity must be refused");
        assert!(
            matches!(err, StorageError::ParityColumnMismatch { .. }),
            "the error must name the mismatch, got: {err:?}"
        );
    }

    #[test]
    fn a_single_flipped_bit_is_caught() {
        let (reg, encoded, manifest) = coded_registry();
        let audit = StorageRegistry::derive_coding_audit(&[3u8; 32], &manifest, 7).unwrap();
        let column = data_column(&encoded, audit.column);
        let honest = encoded.shards[encoded.scheme.k as usize + audit.parity_index as usize]
            [audit.column as usize];

        assert!(reg.verify_coding_audit(&audit, &column, honest).is_ok());
        assert!(
            reg.verify_coding_audit(&audit, &column, honest ^ 1)
                .is_err(),
            "one bit is enough; the audit checks the relationship, not a checksum"
        );
    }

    #[test]
    fn a_replicated_object_has_nothing_to_audit() {
        // Refusing is the honest answer. Reporting a pass would report an
        // audit that never happened, on the objects that need one most:
        // replication has no redundancy to lose.
        let m = ContentManifest::from_bytes_sliced(b"three shards of plain replication", 12)
            .expect("the bytes slice into shards");
        assert_eq!(m.erasure.parity_count(), 0);

        let err = StorageRegistry::derive_coding_audit(&[1u8; 32], &m, 1)
            .expect_err("there is no coding relationship to sample");
        assert!(matches!(err, StorageError::NoParityToAudit { .. }));
    }

    #[test]
    fn the_selection_is_not_the_openers_to_make() {
        // If the opener chose the column it would choose one the operator
        // has, and an operator knowing the column in advance stores only that
        // column. Different entropy has to move the selection.
        let (_, _, manifest) = coded_registry();
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..40u8 {
            let a = StorageRegistry::derive_coding_audit(&[seed; 32], &manifest, 1).unwrap();
            seen.insert((a.parity_index, a.column));
        }
        assert!(
            seen.len() > 20,
            "40 seeds produced only {} distinct selections; the choice is \
             barely moving and an operator could store the few columns it hits",
            seen.len()
        );
    }

    #[test]
    fn the_same_entropy_selects_the_same_column() {
        // Every node verifying the audit has to recompute the same selection,
        // or they disagree about what was asked.
        let (_, _, manifest) = coded_registry();
        let a = StorageRegistry::derive_coding_audit(&[42u8; 32], &manifest, 5).unwrap();
        let b = StorageRegistry::derive_coding_audit(&[42u8; 32], &manifest, 5).unwrap();
        assert_eq!(a, b, "selection must be a function of its inputs alone");
    }

    #[test]
    fn the_selection_lands_inside_the_object() {
        // An out-of-range column is an audit no honest operator can answer,
        // which would slash the honest and let the dishonest through.
        let (_, encoded, manifest) = coded_registry();
        let stripe = encoded.shards[0].len() as u64;
        let parity_count = manifest.erasure.parity_count();

        for seed in 0..64u8 {
            let a = StorageRegistry::derive_coding_audit(&[seed; 32], &manifest, u64::from(seed))
                .unwrap();
            assert!(a.column < stripe, "column {} is past the shard", a.column);
            assert!(a.parity_index < parity_count);
        }
    }

    #[test]
    fn an_audit_costs_k_bytes_not_a_shard() {
        // The claim that makes sampling worth doing, measured rather than
        // described.
        let (_, encoded, manifest) = coded_registry();
        let audit = StorageRegistry::derive_coding_audit(&[11u8; 32], &manifest, 2).unwrap();
        let column = data_column(&encoded, audit.column);

        assert_eq!(column.len(), manifest.erasure.k as usize);
        assert!(
            column.len() + 1 < encoded.shards[0].len(),
            "the audit must read less than one shard, not more"
        );
    }

    #[test]
    fn the_coder_agrees_with_the_registry() {
        // Two paths reach the same relationship: the coder directly, and the
        // registry through the manifest it stored. They must not disagree,
        // because a repair uses one and the audit uses the other.
        let (reg, encoded, manifest) = coded_registry();
        let rs = ReedSolomon::for_scheme(&manifest.erasure).unwrap();
        let audit = StorageRegistry::derive_coding_audit(&[77u8; 32], &manifest, 3).unwrap();
        let column = data_column(&encoded, audit.column);
        let parity_byte = encoded.shards[manifest.erasure.k as usize + audit.parity_index as usize]
            [audit.column as usize];

        assert_eq!(
            rs.column_is_correctly_encoded(audit.parity_index as usize, &column, parity_byte),
            reg.verify_coding_audit(&audit, &column, parity_byte)
                .is_ok(),
        );
    }

    /// The answer picks the column the verifier checks.
    ///
    /// `derive_coding_audit` selects `(parity_index, column)` from chain
    /// entropy precisely so neither side chooses it, and the doc on
    /// `CodingAudit` says it is "deliberately not a stored type ... so there
    /// is no second copy of the selection that could drift".
    ///
    /// On the RPC path there is a second copy. `ChainCommand::AnswerCodingAudit`
    /// carries the whole `CodingAudit` struct up from the responder, and
    /// `verify_coding_audit` never recomputes it: it reads `parity_index` to
    /// pick the generator row and uses `column` only to fill in an error
    /// message. So the byte offset the verifier checks is the offset the
    /// answerer named.
    ///
    /// The consequence is narrow but it is the exact property entropy
    /// selection exists to provide. An operator holding valid parity at one
    /// column and garbage elsewhere can answer every audit at the column it
    /// kept, because nothing binds the answer to the column that was asked.
    /// The audit still proves the relationship holds somewhere; it stops
    /// proving it holds at a place the operator could not predict, and the
    /// `(1 - f)^rounds` argument in the module doc assumes exactly that
    /// unpredictability.
    ///
    /// Not fixed here: closing it means either recomputing the selection
    /// inside `verify_coding_audit` from the entropy and challenge id, or
    /// carrying those instead of the derived struct, and that changes the
    /// `ChainCommand` shape. Pinned so the gap is a decision rather than an
    /// oversight.
    #[test]
    fn a_coding_audit_answer_is_not_bound_to_the_column_that_was_asked() {
        let (reg, encoded, manifest) = coded_registry();
        let asked = StorageRegistry::derive_coding_audit(&[42u8; 32], &manifest, 9)
            .expect("a coded manifest has parity to audit");

        // A different column of the same code word. Entropy chose `asked`;
        // this is one the operator chose instead.
        let substituted = (asked.column + 1) % u64::from(manifest.shards[0].size);
        assert_ne!(substituted, asked.column, "the fixture needs two columns");

        let forged = crate::domain::storage_deal::CodingAudit {
            column: substituted,
            ..asked
        };
        let column = data_column(&encoded, substituted);
        let parity_byte = encoded.shards
            [manifest.erasure.k as usize + forged.parity_index as usize][substituted as usize];

        assert!(
            reg.verify_coding_audit(&forged, &column, parity_byte)
                .is_ok(),
            "an answer at a self-chosen column passes today; when this starts \
             failing the selection has been bound and this test should assert \
             the refusal instead"
        );
    }

    #[test]
    fn an_audit_against_an_unregistered_manifest_is_refused() {
        let (reg, _, _) = coded_registry();
        let audit = crate::domain::storage_deal::CodingAudit {
            manifest_id: ContentId([0xEE; 32]),
            parity_index: 0,
            column: 0,
        };
        assert!(matches!(
            reg.verify_coding_audit(&audit, &[0, 0, 0, 0], 0),
            Err(StorageError::UnknownManifest(_))
        ));
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
    /// Uses the slash path rather than expiry. Both retire a deal, but they
    /// answer different questions: expiry is a term ending, and the registry
    /// refuses one that would take an object below the replica count a decode
    /// needs, precisely so a lapsed term cannot lose content. These tests are
    /// about what the repair band reports once shards are gone regardless of
    /// how, and the ways content is actually lost are slashing and failure,
    /// so that is the transition to drive them with.
    fn lose_shard(reg: &mut StorageRegistry, manifest_id: &ContentId, shard_id: &ContentId) {
        let deal_ids: Vec<u64> = reg
            .deals_for_shard(manifest_id, shard_id)
            .into_iter()
            .map(|d| d.deal_id)
            .collect();
        assert!(!deal_ids.is_empty(), "the shard should have had a deal");
        for deal_id in deal_ids {
            let challenge_id = reg
                .open_challenge(deal_id, 0, 1, 110, 120, opener_address(), 100)
                .unwrap_or_else(|e| panic!("challenge on deal {deal_id} should open: {e}"));
            reg.finalize_missed_challenge(challenge_id, 150)
                .unwrap_or_else(|e| panic!("deal {deal_id} should slash at epoch 150: {e}"));
        }
    }

    /// A challenge opener distinct from every operator address the fixture
    /// hands out, which are `[1; 32]` upwards.
    fn opener_address() -> crate::core::address::Address {
        crate::core::address::Address([0xFE; 32])
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
            reg.under_replicated_shards(0).len(),
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

    // --- the repair margin, and the trigger that reads it -----------------

    #[test]
    fn the_repair_margin_scales_with_the_parity_budget() {
        use crate::storage::manifest::ErasureScheme;

        // A third of parity, rounded up, so a scheme with any parity at all
        // repairs before its last shard of headroom is gone.
        assert_eq!(ErasureScheme { k: 10, n: 16 }.repair_margin(), 2);
        assert_eq!(ErasureScheme { k: 20, n: 26 }.repair_margin(), 2);
        assert_eq!(ErasureScheme { k: 500, n: 535 }.repair_margin(), 12);
        assert_eq!(ErasureScheme { k: 2000, n: 2062 }.repair_margin(), 21);

        // Narrow schemes floor at 2 rather than at the 1 a third would give.
        // `needs_repair` fires on `k <= live < k + margin`, so a margin of 1
        // is a band of exactly `live == k`, which is where the next loss is
        // already fatal. A test caught this; the measured risk at that
        // setting is 9.6e-02 against 1.8e-05 at 2.
        assert_eq!(ErasureScheme { k: 4, n: 6 }.repair_margin(), 2);
        assert_eq!(ErasureScheme { k: 4, n: 7 }.repair_margin(), 2);

        // One parity shard gets 1, because that is all the scheme holds.
        // Asking for headroom it does not have would put it in the band
        // permanently.
        assert_eq!(ErasureScheme { k: 4, n: 5 }.repair_margin(), 1);

        // Replication has no parity to spend, so it asks for no headroom.
        // `needs_repair` still fires at `live == k`, which for replication is
        // every copy but one being gone.
        assert_eq!(ErasureScheme { k: 3, n: 3 }.repair_margin(), 0);
    }

    #[test]
    fn a_margin_can_never_exceed_the_parity_a_scheme_actually_has() {
        use crate::storage::manifest::ErasureScheme;

        // The property that makes the rule safe to apply blindly: asking for
        // more headroom than the scheme holds would put every object in the
        // band permanently, which is the failure mode of a fixed margin on a
        // narrow code.
        for k in 1..40u32 {
            for parity in 0..40u32 {
                let scheme = ErasureScheme { k, n: k + parity };
                let margin = scheme.repair_margin();
                assert!(
                    margin <= parity,
                    "k={k} parity={parity} asked for margin {margin}"
                );
                // And the band is never degenerate where the scheme can
                // afford otherwise: a margin of 1 with parity to spare means
                // the repair starts at `live == k`.
                if parity >= 2 {
                    assert!(
                        margin >= 2,
                        "k={k} parity={parity} left only {margin} of headroom"
                    );
                }
            }
        }
    }

    #[test]
    fn each_object_is_judged_against_its_own_scheme() {
        // The reason the sweep cannot take a single margin: two objects with
        // different schemes, both one shard down, disagree about whether that
        // is a repair case.
        let (mut wide, wide_id, wide_shards) = registry_with_object(4, 6);
        lose_shard(&mut wide, &wide_id, &wide_shards[0]);

        let band = wide.objects_below_own_repair_margin();
        assert_eq!(band.len(), 1, "(4,6) with 5 live is inside its own margin");
        assert_eq!(
            band[0],
            (wide_id, 5, 4, 2),
            "two parity shards floor the margin at 2, so the band is 4..6"
        );

        // A (3,3) object has no parity, so it asks for no headroom and
        // `k <= live < k + 0` is empty: replication never enters the band.
        // That is the honest answer rather than a convenient one. Repair
        // means rebuilding a lost shard from surviving ones, and replication
        // has nothing to rebuild from, only copies to make. Reporting it as
        // repairable would promise a mechanism that does not apply to it.
        let (mut replicated, replicated_id, replicated_shards) = registry_with_object(3, 3);
        assert!(
            replicated.objects_below_own_repair_margin().is_empty(),
            "replication has no parity budget, so it has no repair band"
        );

        // And the moment it loses anything it is unrecoverable, which is the
        // contrast: the coded object had headroom to spend, this one never
        // did.
        lose_shard(&mut replicated, &replicated_id, &replicated_shards[0]);
        assert!(replicated.objects_below_own_repair_margin().is_empty());
        assert_eq!(
            replicated.unrecoverable_objects().len(),
            1,
            "one lost copy of a (3,3) object is already past saving"
        );
    }

    #[test]
    fn an_unrecoverable_object_is_not_reported_as_repairable() {
        let (mut reg, manifest_id, shard_ids) = registry_with_object(4, 6);
        for shard_id in shard_ids.iter().take(3) {
            lose_shard(&mut reg, &manifest_id, shard_id);
        }
        assert_eq!(reg.live_shard_count(&manifest_id), 3, "below k = 4");

        assert!(
            reg.objects_below_own_repair_margin().is_empty(),
            "there is nothing to rebuild from, so this is not a repair case"
        );
        assert_eq!(
            reg.unrecoverable_objects().len(),
            1,
            "it belongs on the alarm path instead"
        );
    }

    // --- renewal, and the ticket a lapsed term now opens -------------------

    #[test]
    fn the_incumbent_may_renew_inside_the_window_and_not_before() {
        use crate::domain::storage_deal::RENEWAL_WINDOW_EPOCHS;

        let (mut reg, _, _) = registry_with_object(4, 6);
        let deal = reg.all_deals()[0].clone();
        let opens = deal.deal_end_epoch - RENEWAL_WINDOW_EPOCHS;

        // Too early: a renewal accepted before the window would let an
        // operator lock a price in ahead of the term it applies to.
        assert!(reg
            .renew_deal(deal.deal_id, deal.operator, opens - 1, 50)
            .is_err());

        // Inside the window the term extends, and the economics are the same
        // agreement running longer.
        let new_end = reg
            .renew_deal(deal.deal_id, deal.operator, opens, 50)
            .expect("the incumbent may renew inside the window");
        assert_eq!(new_end, deal.deal_end_epoch + 50);
        let after = reg.get_deal(deal.deal_id).unwrap();
        assert_eq!(after.economics, deal.economics, "renewal is not a reprice");
    }

    #[test]
    fn nobody_but_the_incumbent_can_renew() {
        use crate::domain::storage_deal::RENEWAL_WINDOW_EPOCHS;

        let (mut reg, _, _) = registry_with_object(4, 6);
        let deal = reg.all_deals()[0].clone();
        let opens = deal.deal_end_epoch - RENEWAL_WINDOW_EPOCHS;

        let stranger = crate::core::address::Address([0xAB; 32]);
        assert!(
            reg.renew_deal(deal.deal_id, stranger, opens, 50).is_err(),
            "renewal extends someone else's obligation, so only they may take it"
        );
    }

    #[test]
    fn a_deal_that_matures_unrenewed_opens_a_reallocation_ticket() {
        // The asymmetry this closes: the slash path always opened a ticket,
        // the expiry path did not, so an operator that served its whole term
        // and left honestly dropped a shard with nothing arranged.
        let (mut reg, _, _) = registry_with_object(4, 6);
        let deal_id = reg.all_deals()[0].deal_id;
        let before = reg.all_reallocation_tickets().len();

        reg.expire_deal(deal_id, 200).expect("the term is over");
        let ticket_id = reg
            .open_expiry_reallocation(deal_id, 200)
            .expect("an unheld shard needs a replacement");

        assert_eq!(reg.all_reallocation_tickets().len(), before + 1);
        let ticket = reg.get_reallocation_ticket(ticket_id).unwrap();
        assert_eq!(ticket.failed_deal_id, deal_id);
        assert_eq!(
            ticket.status,
            crate::domain::storage_deal::ReallocationStatus::Pending
        );
    }

    #[test]
    fn expiry_tickets_do_not_bar_the_operator_that_let_the_term_lapse() {
        // A slashed operator is barred from the replacement because it failed
        // a challenge. An operator whose term simply ran out failed nothing,
        // and it is the cheapest possible replacement: it still has the bytes.
        let (mut reg, _, _) = registry_with_object(4, 6);
        let deal_id = reg.all_deals()[0].deal_id;
        let incumbent = reg.get_deal(deal_id).unwrap().operator;

        reg.expire_deal(deal_id, 200).unwrap();
        let ticket_id = reg.open_expiry_reallocation(deal_id, 200).unwrap();
        let ticket = reg.get_reallocation_ticket(ticket_id).unwrap();

        assert_ne!(
            ticket.slashed_operator, incumbent,
            "letting a term lapse is not a slash, and must not be recorded as one"
        );
    }

    #[test]
    fn the_expiry_ticket_is_opened_once_however_often_the_sweep_runs() {
        // The sweep runs every block. A second ticket for the same deal would
        // have two operators paid to hold one shard.
        let (mut reg, _, _) = registry_with_object(4, 6);
        let deal_id = reg.all_deals()[0].deal_id;
        reg.expire_deal(deal_id, 200).unwrap();

        assert!(reg.open_expiry_reallocation(deal_id, 200).is_some());
        assert!(
            reg.open_expiry_reallocation(deal_id, 201).is_none(),
            "the second sweep must find the ticket already open"
        );
        assert!(
            reg.open_expiry_reallocation(deal_id, 500).is_none(),
            "and must keep finding it, however much later"
        );
    }

    #[test]
    fn a_deal_inside_its_renewal_window_is_offered_before_it_matures() {
        use crate::domain::storage_deal::RENEWAL_WINDOW_EPOCHS;

        let (reg, _, _) = registry_with_object(4, 6);
        let end = reg.all_deals()[0].deal_end_epoch;

        assert!(
            reg.deals_in_renewal_window(end - RENEWAL_WINDOW_EPOCHS - 1)
                .is_empty(),
            "before the window nothing is offered"
        );
        assert_eq!(
            reg.deals_in_renewal_window(end - 1).len(),
            6,
            "inside the window every live deal is offered its extension"
        );
        assert!(
            reg.deals_in_renewal_window(end).is_empty(),
            "at maturity the offer has expired and the ticket path takes over"
        );
    }
}
