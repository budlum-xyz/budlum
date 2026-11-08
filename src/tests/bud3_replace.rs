//! Object replacement (section 6.14): a second representation of the same
//! content.
//!
//! The content id never changes. The references move at the proposal, the old
//! shares stay until every new share is confirmed, a replacement that would
//! produce other content is refused, and the old commitment answers as a
//! redirect once the new object carries the content.
//!
//! The new records here are built by hand from a real upload: the registry
//! checks the record's shape (segments, roots, placement, codec, content id),
//! not the payload bytes, so a test can name a second representation without
//! coding one. The end-to-end door test does the same through the executor.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::storage::bud3::content_id::{ContentId, ContentKey};
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::pipeline::{prepare_public_upload, ObjectRecord};
use crate::storage::bud3::placement::{Class, Share};
use crate::storage::bud3::registry::{Bud3Query, Bud3Registry, ObjectKey, RegistryError};
use crate::storage::bud3::replace::{ReplaceAttestation, ReplaceError};
use crate::storage::bud3::tx::{apply, Applied, StorageTxV3};

const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 128,
    fps: 10,
    k_max: 16,
};

/// The uploader.
const OWNER: u8 = 1;
/// The three Full validators of the placement group.
const FULL_A: u8 = 10;
const FULL_B: u8 = 11;
const FULL_C: u8 = 12;
/// An address that is in no placement group.
const OUTSIDER: u8 = 99;

fn addr(b: u8) -> Address {
    [b; 32]
}

/// Three Full holders of four symbols each, on every segment.
fn placement(segments: u64) -> Vec<(u64, Share)> {
    (0..segments)
        .flat_map(|segment| {
            [FULL_A, FULL_B, FULL_C].into_iter().enumerate().map(move |(h, v)| {
                (
                    segment,
                    Share {
                        validator: [v; 32],
                        class: Class::Full,
                        first_esi: (h as u32) * 4,
                        symbols: 4,
                    },
                )
            })
        })
        .collect()
}

/// A real upload of `content`: its record and its placement.
fn upload(content: &[u8]) -> (ObjectRecord, Vec<(u64, Share)>) {
    let up = prepare_public_upload(content, &P, &Bud3Limits::default(), 12)
        .expect("the test content is inside every limit");
    let shares = placement(up.segments.len() as u64);
    (up.record, shares)
}

/// The same record as a second representation: another open codec, another
/// commitment and a payload of another length. The length stays inside one
/// segment, so the segment count and the roots stay valid.
fn recoded(old: &ObjectRecord, commitment: u8, extra: u64) -> ObjectRecord {
    let mut r = old.clone();
    r.codec = if old.codec == 0 { 1 } else { 0 };
    r.object_len = old.object_len + extra;
    r.commitment = [commitment; 32];
    r
}

/// Three distinct placement-group attestations over the old content id.
fn attestations(content: ContentId) -> Vec<ReplaceAttestation> {
    [FULL_A, FULL_B, FULL_C]
        .into_iter()
        .map(|validator| ReplaceAttestation {
            validator: addr(validator),
            verified_content_id: content,
        })
        .collect()
}

/// A registry holding one registered object.
fn registered(content: &[u8]) -> (Bud3Registry, ObjectKey, ObjectRecord, Vec<(u64, Share)>) {
    let (record, shares) = upload(content);
    let key = record.commitment;
    let mut r = Bud3Registry::default();
    assert!(matches!(
        apply(
            &mut r,
            addr(OWNER),
            StorageTxV3::RegisterObject {
                record: record.clone(),
                shares: shares.clone(),
                lifetime_epochs: 100,
            },
            0,
        ),
        Ok(Applied::Registered(_))
    ));
    (r, key, record, shares)
}

fn storage_tx(from: Address, nonce: u64, fee: u64, inner: StorageTxV3) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        fee,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::StorageV3(Box::new(inner)),
    )
}

/// T22, the acceptance the card names: one content id, two objects, both
/// sizes recorded and the references on the object that carries the content.
#[test]
fn bud3_object_replacement() {
    let (mut r, old, record, _) = registered(b"T22 object replacement");
    let root_before = r.state_root();
    let new_record = recoded(&record, 0x77, 40);
    let new = new_record.commitment;
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: new_record,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Ok(Applied::Replaced(new))
    );
    let replacement = r.replacement(&old).expect("the replacement is recorded");
    assert_eq!(replacement.content, record.content_id);
    assert_eq!(replacement.new, new);
    assert_eq!(replacement.old_object_len, record.object_len);
    assert_eq!(replacement.new_object_len, record.object_len + 40);
    assert_eq!(replacement.proposer, [FULL_A; 32]);
    assert_eq!(replacement.proposed_at, 1);
    assert!(!replacement.finalized);
    assert_ne!(r.state_root(), root_before, "the barrier is consensus state");
    let snapshot = serde_json::to_vec(&r).expect("serialize replacement barrier");
    let restored: Bud3Registry =
        serde_json::from_slice(&snapshot).expect("restore replacement barrier");
    assert_eq!(restored.state_root(), r.state_root());
    assert_eq!(restored.replacement(&old), r.replacement(&old));
    assert_eq!(
        r.object(&new).map(|o| o.record.content_id),
        Some(record.content_id)
    );
}

#[test]
fn bud3_object_replacement_keeps_the_content_id_and_moves_the_references() {
    let (mut r, old, record, _) = registered(b"a replacement keeps this content");
    let new_record = recoded(&record, 0xA5, 64);
    let new = new_record.commitment;
    let shares = placement(1);
    assert!(matches!(
        apply(
            &mut r,
            addr(OWNER),
            StorageTxV3::BindNft {
                nft: [7; 32],
                object: old,
            },
            0,
        ),
        Ok(Applied::Bound)
    ));
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: new_record,
                new_shares,
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Ok(Applied::Replaced(new))
    );
    let carried = r.object(&new).expect("the new object is live");
    assert_eq!(
        carried.record.content_id, record.content_id,
        "the content id never changes"
    );
    assert_eq!(carried.references.len(), 1, "the reference moved");
    assert_eq!(r.refcount(&old), 0, "the old object kept no reference");
    assert_eq!(
        r.query_json(&Bud3Query::Object(new))["content_digest"],
        r.query_json(&Bud3Query::Object(old))["content_digest"]
    );
}

#[test]
fn bud3_object_replacement_keeps_the_old_shares_until_the_new_ones_are_confirmed() {
    let (mut r, old, record, _) = registered(b"shares do not move before the ack");
    let new_record = recoded(&record, 0xB4, 32);
    let new = new_record.commitment;
    apply(
        &mut r,
        addr(FULL_A),
        StorageTxV3::ReplaceObject {
            old_object: old,
            new_record: new_record,
            new_shares: placement(1),
            attestations: attestations(record.content_id),
            proposer_stake: 100_000,
        },
        1,
    )
    .unwrap();
    let pending = "one holder confirmed, so the old shares stay";
    assert_eq!(
        apply(&mut r, addr(FULL_A), StorageTxV3::CustodyAck { object: new }, 2),
        Ok(Applied::Acked(1))
    );
    assert!(
        r.object(&old).is_some(),
        "{pending}: a partial confirmation releases nothing"
    );
    assert_eq!(r.replacement(&old).map(|x| x.finalized), Some(false));
    assert_eq!(
        apply(&mut r, addr(FULL_B), StorageTxV3::CustodyAck { object: new }, 2),
        Ok(Applied::Acked(1))
    );
    assert!(r.object(&old).is_some(), "one holder is still pending");
    assert_eq!(
        apply(&mut r, addr(FULL_C), StorageTxV3::CustodyAck { object: new }, 2),
        Ok(Applied::Acked(1))
    );
    assert!(
        r.object(&old).is_none(),
        "every new share is confirmed, so the old shares are released"
    );
    let redirect = r.replacement(&old).expect("the redirect stands");
    assert!(redirect.finalized);
    assert_eq!(redirect.new, new);
    assert_eq!(redirect.content, record.content_id);
    assert_eq!(redirect.old_object_len, record.object_len);
    assert_eq!(redirect.new_object_len, record.object_len + 32);
    let answer = r.query_json(&Bud3Query::Object(old));
    assert_eq!(answer["status"], "replaced");
    assert_eq!(
        answer["replaced_by"],
        serde_json::Value::String(hex::encode(new))
    );
}

#[test]
fn bud3_pending_replacement_expiry_does_not_release_old_shares() {
    let (mut r, old, record, _) = registered(b"expiry is not an acknowledgement");
    let new_record = recoded(&record, 0xB5, 24);
    let new = new_record.commitment;
    apply(
        &mut r,
        addr(FULL_A),
        StorageTxV3::ReplaceObject {
            old_object: old,
            new_record,
            new_shares: placement(1),
            attestations: attestations(record.content_id),
            proposer_stake: 100_000,
        },
        1,
    )
    .unwrap();
    r.renew(&new, 10).expect("keep the replacement live");

    let expired = r.expire(101);
    assert!(!expired.contains(&old), "a pending old object is not due alone");
    assert!(r.object(&old).is_some(), "expiry is not a share acknowledgement");
    assert_eq!(r.replacement(&old).map(|x| x.finalized), Some(false));

    for holder in [FULL_A, FULL_B, FULL_C] {
        apply(
            &mut r,
            addr(holder),
            StorageTxV3::CustodyAck { object: new },
            102,
        )
        .unwrap();
    }
    assert!(r.object(&old).is_none());
    assert_eq!(r.replacement(&old).map(|x| x.finalized), Some(true));
}

#[test]
fn bud3_object_replacement_refuses_different_content() {
    let (mut r, old, record, _) = registered(b"the replacement must carry the same bytes");
    let mut other = recoded(&record, 0xC3, 0);
    other.content_id = ContentId::public(b"some other content entirely");
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: other,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Err(RegistryError::BadReplacement(
            ReplaceError::ContentIdMismatch {
                proposer_slash_atoms: 1_000,
            }
        ))
    );
}

#[test]
fn bud3_object_replacement_needs_a_full_validator_of_the_group() {
    // The proposer's class is the class of its share in the old placement: a
    // Mobile holder of the same object may not propose.
    let (record, _) = upload(b"only the placement group proposes");
    let mut mobile_shares = placement(1);
    for (_, share) in &mut mobile_shares {
        if share.validator == [FULL_B; 32] {
            share.class = Class::Mobile;
        }
    }
    let mut r = Bud3Registry::default();
    apply(
        &mut r,
        addr(OWNER),
        StorageTxV3::RegisterObject {
            record: record.clone(),
            shares: mobile_shares,
            lifetime_epochs: 100,
        },
        0,
    )
    .unwrap();
    let old = record.commitment;
    let new_record = recoded(&record, 0xD2, 8);
    let root = r.state_root();
    for proposer in [OUTSIDER, FULL_B] {
        assert_eq!(
            apply(
                &mut r,
                addr(proposer),
                StorageTxV3::ReplaceObject {
                    old_object: old,
                    new_record: new_record.clone(),
                    new_shares: placement(1),
                    attestations: attestations(record.content_id),
                    proposer_stake: 100_000,
                },
                1,
            ),
            Err(RegistryError::NotAuthorized),
            "address {proposer} is not a Full validator of the group"
        );
    }
    assert_eq!(r.state_root(), root, "a refusal writes nothing");
}

#[test]
fn bud3_object_replacement_of_sealed_content_is_the_owners() {
    let key = ContentKey([3; 32]);
    let content = b"sealed content is re-coded only by its owner";
    let content_id = ContentId::sealed(&key, content);
    let mut record = upload(content).0;
    record.content_id = content_id;
    record.commitment = [0xE1; 32];
    let old = record.commitment;
    let mut r = Bud3Registry::default();
    apply(
        &mut r,
        addr(OWNER),
        StorageTxV3::RegisterObject {
            record: record.clone(),
            shares: placement(1),
            lifetime_epochs: 100,
        },
        0,
    )
    .unwrap();
    let mut new_record = recoded(&record, 0xE2, 16);
    new_record.content_id = content_id;
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: new_record.clone(),
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Err(RegistryError::NotAuthorized),
        "a validator cannot re-code sealed content"
    );
    assert!(matches!(
        apply(
            &mut r,
            addr(OWNER),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: new_record,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Ok(Applied::Replaced(_))
    ));
}

#[test]
fn bud3_object_replacement_refuses_a_second_proposal() {
    let (mut r, old, record, _) = registered(b"one replacement at a time");
    let first = recoded(&record, 0xF1, 8);
    apply(
        &mut r,
        addr(FULL_A),
        StorageTxV3::ReplaceObject {
            old_object: old,
            new_record: first,
            new_shares: placement(1),
            attestations: attestations(record.content_id),
            proposer_stake: 100_000,
        },
        1,
    )
    .unwrap();
    let second = recoded(&record, 0xF2, 16);
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: second,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            2,
        ),
        Err(RegistryError::BadReplacement(
            ReplaceError::ReplacementAlreadyPending
        ))
    );
}

#[test]
fn bud3_object_replacement_refuses_a_target_that_is_already_live() {
    // Dedup answers a public upload of held content with the live commitment,
    // so only sealed content can name a target that already exists. There the
    // content is already carried and a replacement would add nothing.
    let key = ContentKey([5; 32]);
    let content = b"a sealed object named twice";
    let content_id = ContentId::sealed(&key, content);
    let (mut r, old, record, shares) = {
        let mut record = upload(content).0;
        record.content_id = content_id;
        record.commitment = [0x31; 32];
        let mut r = Bud3Registry::default();
        apply(
            &mut r,
            addr(OWNER),
            StorageTxV3::RegisterObject {
                record: record.clone(),
                shares: placement(1),
                lifetime_epochs: 100,
            },
            0,
        )
        .unwrap();
        (r, record.commitment, record, placement(1))
    };
    let mut live = recoded(&record, 0x32, 8);
    live.content_id = content_id;
    apply(
        &mut r,
        addr(OWNER),
        StorageTxV3::RegisterObject {
            record: live.clone(),
            shares: shares.clone(),
            lifetime_epochs: 100,
        },
        0,
    )
    .unwrap();
    assert!(r.object(&live.commitment).is_some());
    assert_eq!(
        apply(
            &mut r,
            addr(OWNER),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: live,
                new_shares,
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Err(RegistryError::BadReplacement(
            ReplaceError::CommitmentAlreadyLive
        ))
    );
}

#[test]
fn bud3_object_replacement_refuses_a_closed_codec() {
    let (mut r, old, record, _) = registered(b"a closed codec cannot carry content");
    let mut closed = recoded(&record, 0x11, 0);
    closed.codec = 14; // defined, gated behind its own acceptance, closed here
    assert_eq!(
        apply(
            &mut r,
            addr(FULL_A),
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: closed,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
            1,
        ),
        Err(RegistryError::BadReplacement(ReplaceError::CodecNotOpen(14)))
    );
}

#[test]
fn bud3_object_replacement_round_trips_through_the_wire_codec() {
    let (_, _, record, shares) = registered(b"the variant has a wire form");
    let tx = StorageTxV3::ReplaceObject {
        old_object: [9; 32],
        new_record: recoded(&record, 0x1A, 8),
        new_shares,
        attestations: attestations(record.content_id),
        proposer_stake: 100_000,
    };
    let bytes = bincode::serialize(&tx).unwrap();
    assert_eq!(
        bincode::deserialize::<StorageTxV3>(&bytes).unwrap(),
        tx,
        "the new variant survives bincode"
    );
    let json = serde_json::to_string(&tx).unwrap();
    assert_eq!(
        serde_json::from_str::<StorageTxV3>(&json).unwrap(),
        tx,
        "the new variant survives JSON"
    );
    // The variant is appended after every earlier one, so no signed payload
    // of an earlier variant changes its bytes.
    let decline = bincode::serialize(&StorageTxV3::DeclineContent {
        content: ContentId::public(b"x"),
    })
    .unwrap();
    assert_ne!(decline, bytes);
}

#[test]
fn bud3_object_replacement_is_the_signed_door_path() {
    let owner = Address::from([OWNER; 32]);
    let proposer = Address::from([FULL_A; 32]);
    let mut state = AccountState::new();
    state.add_balance(&owner, 1_000);
    state.add_balance(&proposer, 1_000);
    let (record, shares) = upload(b"the door carries the replacement");
    let old = record.commitment;
    Executor::apply_transaction_checked(
        &mut state,
        &storage_tx(
            owner,
            0,
            1,
            StorageTxV3::RegisterObject {
                record: record.clone(),
                shares,
                lifetime_epochs: 100,
            },
        ),
    )
    .unwrap();
    let new_record = recoded(&record, 0x2B, 48);
    let new = new_record.commitment;
    Executor::apply_transaction_checked(
        &mut state,
        &storage_tx(
            proposer,
            0,
            1,
            StorageTxV3::ReplaceObject {
                old_object: old,
                new_record: new_record,
                new_shares: placement(1),
                attestations: attestations(record.content_id),
                proposer_stake: 100_000,
            },
        ),
    )
    .unwrap();
    assert!(state.bud3_registry.object(&new).is_some());
    assert_eq!(state.get_balance(&proposer), 999, "only the fee is charged");
}
