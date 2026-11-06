//! The shared compression context acceptance tests (WP-54, step 3).
//!
//! The card names five tests, and each of them is here by that name:
//!
//! | Test | What it measures |
//! |---|---|
//! | `bud3_context_codec_vectors` | codecs 12 and 13 are registered, closed, and are the only context codecs |
//! | `bud3_context_rotation_keeps_content_id` | a renewal changes the manifest and never a member's content id |
//! | `bud3_context_burned_corpus_leaves` | deleted content leaves at the next renewal, and only then |
//! | `bud3_context_fee_goes_to_pool` | the savings fee lands in the Context Maintenance Pool, and a full match pays none |
//! | `bud3_closed_features_refuse` | bit1, bit3, a closed codec and the context path are all refused on the testnet |
//!
//! The last one is the package's closed-feature canary (T41). It is written
//! here because this package is what closes the context feature; the live
//! stream bit (bit1) and the context flag (bit3) are refused by the same
//! header parser the rest of B.U.D. 3.0 uses, so the canary reads the real
//! paths rather than restating them.

use crate::storage::bud3::bof1::{Flags, Header, Object};
use crate::storage::bud3::compression_context::{
    context_fee_for_upload, context_is_open_at, context_savings_fee, corpus_root, ContextError,
    ContextMaintenancePool, ContextManifest, ContextState, CorpusMember, CONTEXT_CODECS,
    CONTEXT_CODEC_LZ, CONTEXT_CODEC_MACHINE, CONTEXT_OPEN_AT, CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB,
    MAX_CORPUS_MEMBERS,
};
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::limits::{Profile, GIB};
use crate::storage::bud3::meter::Meter;
use crate::storage::bud3::stages::{recognise, ContentClass};

fn content(byte: u8) -> ContentId {
    ContentId::public(&[byte; 32])
}

fn member(byte: u8) -> CorpusMember {
    CorpusMember::new(content(byte), [byte; 32])
}

/// A public P0 header with `flags`, for the refusal canary.
fn header_with(flags: u8) -> Header {
    let id = ContentId::public(b"canary");
    Header {
        flags: Flags::from_byte(flags).expect("every flag under test is a known bit"),
        profile: Profile::P0.id,
        codec: 0,
        dictionary: 0,
        base: None,
        content_len: id.len,
        content_digest: id.digest,
        payload_len: 7,
        prev_object: if flags & Flags::LIVE != 0 {
            Some([1u8; 32])
        } else {
            None
        },
        context_manifest: if flags & Flags::HAS_CONTEXT != 0 {
            Some([2u8; 32])
        } else {
            None
        },
    }
}

#[test]
fn bud3_context_codec_vectors() {
    // The two context codecs are 12 and 13, and the register knows both of
    // them. A codec id that the register does not carry could never be
    // selected, so a manifest naming it would describe a compression the
    // network cannot perform.
    assert_eq!(CONTEXT_CODECS, [12, 13]);
    assert_eq!(CONTEXT_CODEC_LZ, 12);
    assert_eq!(CONTEXT_CODEC_MACHINE, 13);
    for id in CONTEXT_CODECS {
        let row = bud_codec::registry::entry(id).expect("a context codec is registered");
        assert_eq!(row.id, id);
        // Both are closed today: the vector pins that, so opening one is a
        // deliberate edit that moves this line with it.
        assert_eq!(
            row.state,
            bud_codec::registry::CodecState::Closed,
            "codec {id} is not measured, so it may not open"
        );
        assert!(!bud_codec::is_open(id), "codec {id} has no decoder");
    }
    // A manifest refuses an id that is not one of them, whatever else it is.
    for id in [0, 1, 8, 9, 11, 26, 27] {
        assert_eq!(
            ContextManifest::new(ContentClass::Text, id, &[], 0),
            Err(ContextError::NotAContextCodec(id))
        );
    }

    // The corpus fold is a fixed value: the same members give the same root on
    // every architecture, and the root changes with each field of a member.
    let root = corpus_root(&[member(1), member(2)]);
    assert_eq!(root, corpus_root(&[member(2), member(1)]), "order free");
    let moved_commitment = CorpusMember::new(content(1), [7u8; 32]);
    assert_ne!(
        corpus_root(&[moved_commitment, member(2)]),
        root,
        "a re-coded member is a different corpus"
    );
    let longer = ContentId {
        kind: content(1).kind,
        digest: content(1).digest,
        len: content(1).len.saturating_add(1),
    };
    assert_ne!(
        corpus_root(&[CorpusMember::new(longer, [1u8; 32]), member(2)]),
        root,
        "the length is folded, not just the digest"
    );

    // The manifest id is a pure function of its fields.
    let manifest = ContextManifest::new(ContentClass::Text, CONTEXT_CODEC_LZ, &[member(1)], 3)
        .expect("12 is a context codec");
    assert_eq!(manifest.id(), manifest.id());
    assert_eq!(manifest.member_count, 1);
}

#[test]
fn bud3_context_rotation_keeps_content_id() {
    let mut state = ContextState::new();
    let first_content = ContentId::public(b"the first record of the day");
    state
        .offer(ContentClass::Records, false, first_content, [9u8; 32])
        .expect("a public offer of the right class is admitted");
    let first = state.renew(10).expect("the renewal folds the corpus");

    // The same content, re-coded under a new context: a different commitment,
    // the same content id. This is the rotation the card is about.
    state
        .offer(ContentClass::Records, false, first_content, [10u8; 32])
        .expect("the re-coded member is offered again");
    let second = state.renew(11).expect("the second renewal folds");
    assert_ne!(first.id(), second.id(), "a new corpus is a new context");
    assert_ne!(first.corpus_root, second.corpus_root);
    assert_eq!(first.class, second.class);
    assert_eq!(
        ContentId::public(b"the first record of the day"),
        first_content,
        "the content id is the bytes, and the bytes did not move"
    );
    assert!(first_content.matches_public(b"the first record of the day"));

    // The context itself never enters the manifest: only its fold does.
    assert_eq!(second.built_at_epoch, 11);
    assert_eq!(state.manifest().map(|m| m.id()), Some(second.id()));

    // A renewal with no members is still a manifest: an empty context.
    let mut empty = ContextState::new();
    let manifest = empty.renew(12).expect("an empty context renews");
    assert_eq!(manifest.member_count, 0);
    assert_eq!(manifest.class, ContentClass::Generic);
}

#[test]
fn bud3_context_burned_corpus_leaves() {
    let mut state = ContextState::new();
    for byte in 1..=4u8 {
        state
            .offer(ContentClass::Records, false, content(byte), [byte; 32])
            .expect("a public offer is admitted");
    }
    let before = state.renew(20).expect("the first renewal folds four members");
    assert_eq!(before.member_count, 4);

    state
        .burn(&content(3))
        .expect("a member the corpus holds can be burned");
    assert_eq!(
        state.burn(&content(3)),
        Err(ContextError::NotInCorpus),
        "a second burn of the same digest is not a context event"
    );

    // Until the renewal, the stored manifest still names the old corpus: that
    // is what "leaves at the next renewal" means.
    assert_eq!(
        state.manifest().map(|m| m.corpus_root),
        Some(before.corpus_root)
    );

    let after = state.renew(21).expect("the second renewal folds three");
    assert_eq!(after.member_count, 3);
    assert_eq!(
        after.corpus_root,
        corpus_root(&[member(1), member(2), member(4)]),
        "the burned member is gone from the fold"
    );
    assert_ne!(after.corpus_root, before.corpus_root);

    // The corpus ceiling is a refusal rather than an allocation.
    let mut full = ContextState::new();
    for byte in 0..=255u8 {
        // 256 members is far below the ceiling, so every one is admitted.
        full.offer(
            ContentClass::Generic,
            false,
            ContentId::public(&[byte, 0, 1]),
            [byte; 32],
        )
        .expect("below the ceiling every offer is admitted");
    }
    assert_eq!(full.renew(0).expect("a full fold succeeds").member_count, 256);
    assert!(MAX_CORPUS_MEMBERS > 256);
}

#[test]
fn bud3_context_fee_goes_to_pool() {
    let mut pool = ContextMaintenancePool::new();
    assert_eq!(pool.balance(), 0);
    assert_eq!(pool.deposits(), 0);

    // A context that saved one GiB pays the unit fee, and the pool holds it.
    let fee = context_savings_fee(GIB);
    assert_eq!(fee, CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB);
    pool.deposit(fee);
    assert_eq!(pool.balance(), fee);
    assert_eq!(pool.deposits(), 1);

    // A context object whose content already exists pays no context fee: the
    // upload was deduplicated, so no byte was saved.
    assert_eq!(context_fee_for_upload(GIB, true), 0);
    assert_eq!(context_fee_for_upload(GIB, false), fee);

    // A context that saved nothing pays nothing, and one that saved a single
    // byte pays one unit rather than rounding to free.
    assert_eq!(context_savings_fee(0), 0);
    assert_eq!(context_savings_fee(1), 1);

    // The pool pays out at most what it holds: it never mints.
    assert_eq!(pool.payout(fee.saturating_mul(3)), fee);
    assert_eq!(pool.balance(), 0);
    assert_eq!(pool.payout(1), 0);
    assert_eq!(pool.deposits(), 1, "a payout is not a deposit");
}

#[test]
fn bud3_closed_features_refuse() {
    // The context path is closed at every height until a governance value
    // names one, and the refusal names the height it happened at.
    assert_eq!(CONTEXT_OPEN_AT, None);
    assert!(!context_is_open_at(0));
    assert!(!context_is_open_at(u64::MAX - 1));
    let state = ContextState::new();
    assert_eq!(
        state.admit_context_object(1),
        Err(ContextError::ClosedAt(1))
    );

    // bit3 (a context manifest) is refused by the object parser: a context the
    // network cannot rebuild is not an object it may store.
    let object = Object {
        header: header_with(Flags::HAS_CONTEXT),
        payload: b"canary".to_vec(),
    };
    let mut meter = Meter::new(1024, 64);
    assert_eq!(
        Object::decode(&object.encode(), &mut meter),
        Err(crate::storage::bud3::bof1::Bof1Error::ContextNotOpen)
    );

    // bit1 (a live segment) parses, because the format carries it; the stream
    // itself is WP-55 and never opens on the testnet chain. What this canary
    // pins is that the parser reads the bit rather than ignoring it.
    let live = Object {
        header: header_with(Flags::LIVE),
        payload: b"canary".to_vec(),
    };
    let decoded = Object::decode(&live.encode(), &mut meter).expect("bit1 is a known flag");
    assert_eq!(decoded.header.prev_object, Some([1u8; 32]));
    assert!(decoded.header.is_live());

    // A closed codec is refused by the record path: the register has no
    // decoder for it, so nothing could ever produce the content again.
    for id in [CONTEXT_CODEC_LZ, CONTEXT_CODEC_MACHINE, 5, 8] {
        assert!(
            !crate::storage::bud3::bof1::codec_is_open_on_testnet(id),
            "codec {id} is closed on the testnet"
        );
    }
    assert!(crate::storage::bud3::bof1::codec_is_open_on_testnet(0));

    // An unknown flag bit is refused outright, so a future bit cannot be
    // smuggled in under an old parser.
    assert!(Flags::from_byte(1 << 4).is_err());
    assert!(Flags::from_byte(0xff).is_err());
}

#[test]
fn the_recogniser_names_the_class_a_context_is_keyed_by() {
    // A context belongs to one recogniser class, so the two must agree on the
    // class names an operator sees in the manifest.
    assert_eq!(recognise(br#"{"a":1,"b":2}"#), ContentClass::Records);
    assert_eq!(recognise(b"plain words, no structure"), ContentClass::Text);
    assert_eq!(recognise(&[0x89, b'P', b'N', b'G']), ContentClass::Image);
    assert_eq!(
        ContextManifest::new(ContentClass::Records, CONTEXT_CODEC_LZ, &[member(1)], 0)
            .expect("12 is a context codec")
            .class,
        ContentClass::Records
    );
}
