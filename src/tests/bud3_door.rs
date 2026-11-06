//! The B.U.D. 3.0 storage door end to end: the transaction envelope, the
//! wire codec, the executor and the state root.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::network::proto_conversions::pb;
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::pipeline::{prepare_public_upload, view_public};
use crate::storage::bud3::placement::{Class, Share};
use crate::storage::bud3::tx::StorageTxV3;

const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 128,
    fps: 10,
    k_max: 16,
};

fn storage_tx(from: Address, nonce: u64, fee: u64, amount: u64, inner: StorageTxV3) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::StorageV3(Box::new(inner)),
    )
}

fn apply(state: &mut AccountState, t: &Transaction) -> Result<(), String> {
    Executor::apply_transaction_checked(state, t).map_err(|e| e.code().to_string())
}

#[test]
fn register_bind_and_view_through_the_executor() {
    let uploader = Address::from([1u8; 32]);
    let holder = Address::from([10u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&uploader, 1_000);
    state.add_balance(&holder, 1_000);
    let empty_root = state.calculate_state_root();

    let content = b"stored on the testnet".repeat(20);
    let up = prepare_public_upload(&content, &P, &Bud3Limits::default(), 12).unwrap();
    let key = up.record.commitment;
    let shares = (0..up.segments.len() as u64)
        .flat_map(|seg| {
            (0..2u8).map(move |h| {
                (
                    seg,
                    Share {
                        validator: [10 + h; 32],
                        class: Class::Full,
                        first_esi: u32::from(h) * 6,
                        symbols: 6,
                    },
                )
            })
        })
        .collect();
    let register = storage_tx(
        uploader,
        0,
        1,
        0,
        StorageTxV3::RegisterObject {
            record: up.record.clone(),
            shares,
            lifetime_epochs: 100,
        },
    );

    // The transaction survives the wire codec unchanged.
    let wire = pb::ProtoTransaction::from(&register);
    assert_eq!(
        Transaction::try_from(wire).unwrap().tx_type,
        register.tx_type
    );

    apply(&mut state, &register).unwrap();
    assert!(state.bud3_registry.object(&key).is_some());
    assert_ne!(
        state.calculate_state_root(),
        empty_root,
        "the registry is rooted"
    );
    assert_eq!(state.get_balance(&uploader), 999, "only the fee is charged");

    apply(
        &mut state,
        &storage_tx(holder, 0, 1, 0, StorageTxV3::CustodyAck { object: key }),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            uploader,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft: [7; 32],
                object: key,
            },
        ),
    )
    .unwrap();
    assert_eq!(state.bud3_registry.refcount(&key), 1);

    // The RPC reads.
    use crate::storage::bud3::registry::Bud3Query;
    let obj = state.bud3_registry.query_json(&Bud3Query::Object(key));
    assert_eq!(obj["status"], "live");
    assert_eq!(obj["references"], 1);
    let custody = state
        .bud3_registry
        .query_json(&Bud3Query::Custody([10; 32]));
    assert_eq!(custody["shares"][0]["confirmed"], true);
    assert!(state
        .bud3_registry
        .query_json(&Bud3Query::Object([0; 32]))
        .is_null());

    // A viewer rebuilds the content from the holders' symbols.
    let symbols = up.segments.concat().into_iter().filter(|s| s.esi % 4 != 0);
    assert_eq!(view_public(&up.record, symbols).unwrap(), content);
}

#[test]
fn the_door_refuses_value_and_bad_steps_without_writing() {
    let from = Address::from([2u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&from, 1_000);
    let root = state.calculate_state_root();
    let burn = StorageTxV3::BurnReference { nft: [9; 32] };
    assert_eq!(
        apply(&mut state, &storage_tx(from, 0, 1, 5, burn.clone())),
        Err("storage_v3_amount_nonzero".to_string())
    );
    assert_eq!(
        apply(&mut state, &storage_tx(from, 0, 1, 0, burn)),
        Err("storage_v3_refused".to_string())
    );
    assert_eq!(state.calculate_state_root(), root);
    assert_eq!(state.get_balance(&from), 1_000);
}

#[test]
fn the_epoch_boundary_expires_and_audits() {
    let uploader = Address::from([3u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&uploader, 1_000);
    let up = prepare_public_upload(b"short lease", &P, &Bud3Limits::default(), 6).unwrap();
    let key = up.record.commitment;
    let shares = vec![(
        0,
        Share {
            validator: [11; 32],
            class: Class::Full,
            first_esi: 0,
            symbols: 6,
        },
    )];
    let t = storage_tx(
        uploader,
        0,
        1,
        0,
        StorageTxV3::RegisterObject {
            record: up.record,
            shares,
            lifetime_epochs: 2,
        },
    );
    apply(&mut state, &t).unwrap();
    let start = state.epoch_index;
    for _ in 0..3 {
        state.advance_epoch(0, DEFAULT_CHAIN_ID);
    }
    assert!(state.epoch_index > start + 2);
    assert!(
        state.bud3_registry.object(&key).is_none(),
        "the unpaid object expired"
    );
    assert!(state.bud3_registry.tombstone(&key).is_some());
}

#[test]
fn closed_codecs_refuse_on_testnet() {
    use crate::core::chain_config::Network;

    let uploader = Address::from([4u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&uploader, 1_000);
    let root = state.calculate_state_root();
    let content = b"closed codecs carry no content".repeat(20);
    let up = prepare_public_upload(&content, &P, &Bud3Limits::default(), 12).unwrap();
    let shares: Vec<(u64, Share)> = (0..up.segments.len() as u64)
        .flat_map(|seg| {
            (0..2u8).map(move |h| {
                (
                    seg,
                    Share {
                        validator: [10 + h; 32],
                        class: Class::Full,
                        first_esi: u32::from(h) * 6,
                        symbols: 6,
                    },
                )
            })
        })
        .collect();
    // Ids the codec register marks closed at testnet launch. The expansion
    // work may open some of them later; until a decoder lands, an object that
    // carries one is refused with the codec named in the reason.
    for closed in [6u16, 8, 23, 26] {
        let mut record = up.record.clone();
        record.codec = closed;
        let tx = Transaction::new_with_chain_id(
            uploader,
            Address::zero(),
            0,
            1,
            0,
            Vec::new(),
            Network::Testnet.chain_id().value(),
            TransactionType::StorageV3(Box::new(StorageTxV3::RegisterObject {
                record,
                shares: shares.clone(),
                lifetime_epochs: 100,
            })),
        );
        let err = Executor::apply_transaction(&mut state, &tx)
            .expect_err("a closed codec must not register");
        assert!(
            err.contains("CodecNotOpen"),
            "id {closed} refused for the wrong reason: {err}"
        );
    }
    assert_eq!(
        state.calculate_state_root(),
        root,
        "a refusal writes nothing"
    );
    assert_eq!(state.get_balance(&uploader), 1_000, "no fee, no write");
    assert_eq!(state.get_nonce(&uploader), 0);
}

/// A repair plan is a what-if read. It calls the unseen-holder transition on
/// a clone, reports the repairs that would be due, and leaves the live
/// registry byte-for-byte unchanged (no out-of-block state write).
#[test]
fn the_repair_plan_never_writes_the_live_registry() {
    use crate::storage::bud3::registry::{Bud3Query, Bud3Registry};

    let up = prepare_public_upload(b"one segment", &P, &Bud3Limits::default(), 12).unwrap();
    let shares = vec![
        (
            0,
            Share {
                validator: [10; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: [11; 32],
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];
    let mut registry = Bud3Registry::default();
    registry
        .register_object([1; 32], up.record, shares, 0, 100)
        .unwrap();
    let root_before = registry.state_root();

    let plan = registry.query_json(&Bud3Query::RepairPlan([10; 32]));
    let holder_hex = hex::encode([10u8; 32]);
    assert_eq!(plan["holder"].as_str(), Some(holder_hex.as_str()));
    assert_eq!(plan["shares_marked_lost"].as_u64(), Some(1));
    assert!(plan["objects_needing_repair"].is_array());

    assert_eq!(
        registry.state_root(),
        root_before,
        "a read must not change the state root"
    );
    let custody = registry.query_json(&Bud3Query::Custody([10; 32]));
    assert_eq!(custody["shares"][0]["lost"].as_bool(), Some(false));
}

/// The RPC read carries the admission report from the production door.
#[test]
fn the_admission_report_reaches_the_tree() {
    let report = crate::storage::bud3::admission::chain_admission_report();
    assert_eq!(
        report["checks"]["lifetime_admitted"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["checks"]["mobile_quota_admitted"].as_bool(),
        Some(true)
    );
    assert_eq!(report["placement"]["k"].as_u64(), Some(4096));
}
