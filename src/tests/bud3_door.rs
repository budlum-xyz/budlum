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
    assert_eq!(state.calculate_state_root(), root, "a refusal writes nothing");
    assert_eq!(state.get_balance(&uploader), 1_000, "no fee, no write");
    assert_eq!(state.get_nonce(&uploader), 0);
}

#[test]
fn endowment_settles_custody_rewards_and_renewal_across_epochs() {
    use crate::storage::bud3::registry::Bud3Query;

    let uploader = Address::from([21u8; 32]);
    let confirmed_holder = Address::from([30u8; 32]);
    let unconfirmed_holder = Address::from([31u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&uploader, 10_000);
    state.add_balance(&confirmed_holder, 1_000);

    let up = prepare_public_upload(b"endowment-priced payload", &P, &Bud3Limits::default(), 12)
        .unwrap();
    let key = up.record.commitment;
    let shares = vec![
        (
            0,
            Share {
                validator: [30; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: [31; 32],
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];

    apply(
        &mut state,
        &storage_tx(
            uploader,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: up.record,
                shares,
                lifetime_epochs: 10,
            },
        ),
    )
    .unwrap();

    // 0.001 BUD minimum fee (1,000 base units) splits 950 to Custody Endowment and 50 to gateway.
    let obj = state.bud3_registry.query_json(&Bud3Query::Object(key));
    assert_eq!(obj["endowment"]["total_deposited"], 950);
    assert_eq!(obj["endowment"]["gateway_paid"], 50);

    // Only holder 30 acknowledges its share; holder 31 remains pending.
    apply(
        &mut state,
        &storage_tx(confirmed_holder, 0, 1, 0, StorageTxV3::CustodyAck { object: key }),
    )
    .unwrap();

    state.advance_epoch(0, DEFAULT_CHAIN_ID);
    let earned_confirmed = state.bud3_registry.validator_custody_credit(&[30; 32]);
    let earned_unconfirmed = state
        .bud3_registry
        .validator_custody_credit(unconfirmed_holder.as_bytes());
    let forfeited = state.bud3_registry.forfeited_security_pool_total();
    assert!(earned_confirmed > 0);
    assert_eq!(earned_unconfirmed, 0);
    assert!(forfeited > 0);

    // Renewing adds another 950 base units to the object's Custody Endowment.
    apply(
        &mut state,
        &storage_tx(
            uploader,
            1,
            1,
            0,
            StorageTxV3::RenewObject {
                object: key,
                extra_epochs: 10,
            },
        ),
    )
    .unwrap();
    let obj_after = state.bud3_registry.query_json(&Bud3Query::Object(key));
    assert_eq!(obj_after["endowment"]["total_deposited"], 1_900);
    assert_eq!(obj_after["endowment"]["gateway_paid"], 100);
}

#[test]
fn bud3_sealed_grant_issue_revoke_and_not_served() {
    use crate::crypto::hpke::HpkeKeyPair;
    use crate::storage::bud3::grants::{compute_grant_tag, grant_revoke_digest, GrantRow};
    use crate::storage::bud3::keys::{
        derive_grant_one_time_keypair, derive_object_content_key, open_key_package,
        seal_key_package, sign_with_grant_one_time_key,
    };
    use crate::storage::bud3::pipeline::{prepare_sealed_upload, view_sealed};
    use crate::storage::bud3::registry::Bud3Query;

    let owner = Address::from([41u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&owner, 50_000);

    let owner_secret = [0x91u8; 32];
    let content_key = derive_object_content_key(&owner_secret, 1);
    let plaintext = b"confidential sealed post shared via unlinkable X-Wing grant";
    let up = prepare_sealed_upload(
        plaintext,
        &content_key,
        [0x77; 24],
        &P,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    let obj_commitment = up.record.commitment;
    let shares = vec![
        (
            0,
            Share {
                validator: [50; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: [51; 32],
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];

    apply(
        &mut state,
        &storage_tx(
            owner,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: up.record.clone(),
                shares,
                lifetime_epochs: 20,
            },
        ),
    )
    .unwrap();

    let nft_id = [0xA1; 32];
    apply(
        &mut state,
        &storage_tx(
            owner,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft: nft_id,
                object: obj_commitment,
            },
        ),
    )
    .unwrap();

    // Build an unlinkable view grant sealed to the grantee's X-Wing (0x647a) key.
    let grantee_hpke = HpkeKeyPair::from_seed(&[0xB3u8; 32]).unwrap();
    let grant_nonce = [0x33; 32];
    let grant_tag = compute_grant_tag(&nft_id, &grant_nonce);
    let (one_time_seed, one_time_pk) =
        derive_grant_one_time_keypair(&owner_secret, &nft_id, &grant_nonce).unwrap();
    let sealed_pkg = seal_key_package(
        grantee_hpke.public_key(),
        &grant_tag,
        &obj_commitment,
        &content_key,
    )
    .unwrap();

    let row = GrantRow {
        grant_tag,
        one_time_pk,
        sealed_key_package: sealed_pkg,
        expires_at_epoch: 15,
    };
    apply(
        &mut state,
        &storage_tx(owner, 2, 1, 0, StorageTxV3::IssueViewGrant { row }),
    )
    .unwrap();

    // Active grant serves HPKE key package with zero content_id / issuer / grantee fields.
    let active_json = state.bud3_registry.query_json(&Bud3Query::Grant(grant_tag));
    assert_eq!(active_json["status"], "active");
    assert!(active_json.get("content_id").is_none());
    assert!(active_json.get("issuer").is_none());
    assert!(active_json.get("grantee").is_none());

    let served = state
        .bud3_registry
        .grant_row(&grant_tag)
        .expect("active grant must be served");
    let (opened_obj, opened_key) =
        open_key_package(&grantee_hpke, &grant_tag, &served.sealed_key_package).unwrap();
    assert_eq!(opened_obj, obj_commitment);
    let viewed = view_sealed(&up.record, &opened_key, up.segments.concat()).unwrap();
    assert_eq!(viewed, plaintext);

    // RevokeViewGrant deletes the HPKE capsule so it is never served again.
    let revoke_sig =
        sign_with_grant_one_time_key(&one_time_seed, &grant_revoke_digest(&grant_tag)).unwrap();
    apply(
        &mut state,
        &storage_tx(
            owner,
            3,
            1,
            0,
            StorageTxV3::RevokeViewGrant {
                grant_tag,
                one_time_signature: revoke_sig,
            },
        ),
    )
    .unwrap();
    assert!(
        state.bud3_registry.grant_row(&grant_tag).is_none(),
        "revoked grant key package must never be served"
    );
    let revoked_json = state.bud3_registry.query_json(&Bud3Query::Grant(grant_tag));
    assert_eq!(revoked_json["status"], "revoked");
    assert!(revoked_json.get("sealed_key_package").is_none());
}

#[test]
fn bud3_social_delete_crypto_shredding_and_tombstone() {
    use crate::crypto::hpke::HpkeKeyPair;
    use crate::storage::bud3::delete::GrantShredAuth;
    use crate::storage::bud3::grants::{compute_grant_tag, grant_revoke_digest, GrantRow};
    use crate::storage::bud3::keys::{
        derive_grant_one_time_keypair, derive_object_content_key, seal_key_package,
        sign_with_grant_one_time_key,
    };
    use crate::storage::bud3::pipeline::prepare_sealed_upload;

    let owner = Address::from([42u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&owner, 50_000);

    let owner_secret = [0x82u8; 32];
    let content_key = derive_object_content_key(&owner_secret, 1);
    let up = prepare_sealed_upload(
        b"social post with cryptographic erasure on delete",
        &content_key,
        [0x55; 24],
        &P,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    let obj_commitment = up.record.commitment;
    let shares = vec![
        (
            0,
            Share {
                validator: [60; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: [61; 32],
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];

    apply(
        &mut state,
        &storage_tx(
            owner,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: up.record,
                shares,
                lifetime_epochs: 20,
            },
        ),
    )
    .unwrap();
    let nft_id = [0xB2; 32];
    apply(
        &mut state,
        &storage_tx(
            owner,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft: nft_id,
                object: obj_commitment,
            },
        ),
    )
    .unwrap();

    let grantee = HpkeKeyPair::from_seed(&[0xB4u8; 32]).unwrap();
    let grant_nonce = [0x99; 32];
    let grant_tag = compute_grant_tag(&nft_id, &grant_nonce);
    let (one_time_seed, one_time_pk) =
        derive_grant_one_time_keypair(&owner_secret, &nft_id, &grant_nonce).unwrap();
    let sealed_pkg = seal_key_package(
        grantee.public_key(),
        &grant_tag,
        &obj_commitment,
        &content_key,
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            owner,
            2,
            1,
            0,
            StorageTxV3::IssueViewGrant {
                row: GrantRow {
                    grant_tag,
                    one_time_pk,
                    sealed_key_package: sealed_pkg,
                    expires_at_epoch: 20,
                },
            },
        ),
    )
    .unwrap();

    let shred_sig =
        sign_with_grant_one_time_key(&one_time_seed, &grant_revoke_digest(&grant_tag)).unwrap();
    apply(
        &mut state,
        &storage_tx(
            owner,
            3,
            1,
            0,
            StorageTxV3::SocialDelete {
                nft: nft_id,
                grant_shreds: vec![GrantShredAuth {
                    grant_tag,
                    one_time_signature: shred_sig,
                }],
            },
        ),
    )
    .unwrap();

    assert!(state.bud3_registry.grant_row(&grant_tag).is_none());
    assert!(state.bud3_registry.object(&obj_commitment).is_none());
    assert!(state.bud3_registry.is_tombstoned(&obj_commitment));
}

#[test]
fn bud3_public_dedup_sealed_isolation_and_dependency_rules() {
    use crate::storage::bud3::keys::derive_object_content_key;
    use crate::storage::bud3::pipeline::prepare_sealed_upload;
    use crate::storage::bud3::registry::RegistryError;

    let alice = Address::from([71u8; 32]);
    let bob = Address::from([72u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&alice, 50_000);
    state.add_balance(&bob, 50_000);

    let shares = vec![
        (
            0,
            Share {
                validator: [80; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: [81; 32],
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];

    // Public dedup across two uploaders shares one physical object commitment.
    let pub_up =
        prepare_public_upload(b"shared public content", &P, &Bud3Limits::default(), 12).unwrap();
    let pub_key = pub_up.record.commitment;
    apply(
        &mut state,
        &storage_tx(
            alice,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: pub_up.record.clone(),
                shares: shares.clone(),
                lifetime_epochs: 10,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            bob,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: pub_up.record,
                shares: shares.clone(),
                lifetime_epochs: 15,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            alice,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft: [1; 32],
                object: pub_key,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            bob,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft: [2; 32],
                object: pub_key,
            },
        ),
    )
    .unwrap();
    assert_eq!(state.bud3_registry.refcount(&pub_key), 2);

    // Burning Alice's NFT leaves Bob's reference alive; burning Bob's tombstones.
    apply(
        &mut state,
        &storage_tx(alice, 2, 1, 0, StorageTxV3::BurnReference { nft: [1; 32] }),
    )
    .unwrap();
    assert_eq!(state.bud3_registry.refcount(&pub_key), 1);
    assert!(state.bud3_registry.object(&pub_key).is_some());

    apply(
        &mut state,
        &storage_tx(bob, 2, 1, 0, StorageTxV3::BurnReference { nft: [2; 32] }),
    )
    .unwrap();
    assert!(state.bud3_registry.is_tombstoned(&pub_key));

    // Sealed isolation: identical plaintext from Alice and Bob produces isolated objects.
    let alice_sealed = prepare_sealed_upload(
        b"identical secret bytes",
        &derive_object_content_key(&[0xAA; 32], 1),
        [0x11; 24],
        &P,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    let bob_sealed = prepare_sealed_upload(
        b"identical secret bytes",
        &derive_object_content_key(&[0xBB; 32], 1),
        [0x22; 24],
        &P,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    assert_ne!(
        alice_sealed.record.commitment,
        bob_sealed.record.commitment
    );
    let alice_base = alice_sealed.record.commitment;
    let bob_obj = bob_sealed.record.commitment;
    apply(
        &mut state,
        &storage_tx(
            alice,
            3,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: alice_sealed.record,
                shares: shares.clone(),
                lifetime_epochs: 10,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            bob,
            3,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: bob_sealed.record,
                shares: shares.clone(),
                lifetime_epochs: 10,
            },
        ),
    )
    .unwrap();

    // Cross-owner base dependency is refused.
    assert_eq!(
        state
            .bud3_registry
            .register_dependency(bob_obj, alice_base),
        Err(RegistryError::CrossOwnerDependency)
    );

    // Same-owner base dependency protects the base object until detached.
    let alice_delta = prepare_sealed_upload(
        b"alice delta edit",
        &derive_object_content_key(&[0xAA; 32], 2),
        [0x33; 24],
        &P,
        &Bud3Limits::default(),
        12,
    )
    .unwrap();
    let delta_key = alice_delta.record.commitment;
    apply(
        &mut state,
        &storage_tx(
            alice,
            4,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: alice_delta.record,
                shares,
                lifetime_epochs: 10,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            alice,
            5,
            1,
            0,
            StorageTxV3::BindNft {
                nft: [0xD1; 32],
                object: alice_base,
            },
        ),
    )
    .unwrap();
    state
        .bud3_registry
        .register_dependency(delta_key, alice_base)
        .unwrap();
    assert_eq!(state.bud3_registry.refcount(&alice_base), 2);
    assert!(
        apply(
            &mut state,
            &storage_tx(
                alice,
                6,
                1,
                0,
                StorageTxV3::BurnReference { nft: [0xD1; 32] }
            ),
        )
        .is_err(),
        "base object with live dependent must refuse deletion"
    );
    state
        .bud3_registry
        .detach_dependency(&delta_key, &alice_base, 0);
    apply(
        &mut state,
        &storage_tx(
            alice,
            6,
            1,
            0,
            StorageTxV3::BurnReference { nft: [0xD1; 32] },
        ),
    )
    .unwrap();
    assert!(state.bud3_registry.is_tombstoned(&alice_base));
}

#[test]
fn bud3_decline_content_reassigns_and_release_shares_lowers_quota_without_penalty() {
    use crate::storage::bud3::repair::build_segment_repair;

    let uploader = Address::from([90u8; 32]);
    let holder_a = Address::from([91u8; 32]);
    let holder_b = Address::from([92u8; 32]);
    let repairer = Address::from([93u8; 32]);
    let replacement = Address::from([94u8; 32]);

    let mut state = AccountState::new();
    for addr in [uploader, holder_a, holder_b, repairer, replacement] {
        state.add_balance(&addr, 20_000);
    }
    state
        .bud3_registry
        .set_validator_quota(*holder_b.as_bytes(), 100_000);

    let payload = b"content subject to voluntary decline and share release";
    let up = prepare_public_upload(payload, &P, &Bud3Limits::default(), 16).unwrap();
    let obj_key = up.record.commitment;
    let content_id = up.record.content_id;

    let shares = vec![
        (
            0,
            Share {
                validator: *holder_a.as_bytes(),
                class: Class::Full,
                first_esi: 0,
                symbols: 8,
            },
        ),
        (
            0,
            Share {
                validator: *holder_b.as_bytes(),
                class: Class::Full,
                first_esi: 8,
                symbols: 8,
            },
        ),
    ];

    apply(
        &mut state,
        &storage_tx(
            uploader,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: up.record.clone(),
                shares,
                lifetime_epochs: 20,
            },
        ),
    )
    .unwrap();

    // Holder A declines the content: no balance penalty beyond tx fee, and segment 0 becomes due for repair.
    let bal_before = state.get_balance(&holder_a);
    apply(
        &mut state,
        &storage_tx(
            holder_a,
            0,
            1,
            0,
            StorageTxV3::DeclineContent {
                content: content_id,
            },
        ),
    )
    .unwrap();
    assert_eq!(state.get_balance(&holder_a), bal_before - 1);
    assert_eq!(state.bud3_registry.repairs_due(&obj_key), vec![0]);

    // Repairer reconstructs segment 0 and assigns fresh ESIs (16..24) to `replacement`.
    let prep = build_segment_repair(
        repairer.as_bytes(),
        0,
        up.record.object_len,
        &P,
        16,
        &[(*replacement.as_bytes(), Class::Full, 8)],
        up.segments[0].clone(),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            repairer,
            0,
            1,
            0,
            StorageTxV3::RecordRepair {
                object: obj_key,
                segment: 0,
                new_shares: prep.new_shares,
                new_root: prep.new_root,
            },
        ),
    )
    .unwrap();

    // Replacement confirms its share; Holder B voluntarily releases its share and lowers quota without penalty.
    apply(
        &mut state,
        &storage_tx(
            replacement,
            0,
            1,
            0,
            StorageTxV3::CustodyAck { object: obj_key },
        ),
    )
    .unwrap();
    let holder_b_before = state.get_balance(&holder_b);
    apply(
        &mut state,
        &storage_tx(
            holder_b,
            0,
            1,
            0,
            StorageTxV3::ReleaseShares {
                object: obj_key,
                segment: Some(0),
                lower_quota_bytes: 40_000,
            },
        ),
    )
    .unwrap();
    assert_eq!(state.get_balance(&holder_b), holder_b_before - 1);
    assert_eq!(
        state.bud3_registry.validator_quota(holder_b.as_bytes()),
        60_000
    );
}

#[test]
fn bud3_missed_audit_does_not_slash_and_custody_proof_verifies() {
    use crate::storage::bud3::custody::{prove, symbol_leaf, PPM};
    use crate::storage::bud3::registry::AuditParams;

    let uploader = Address::from([101u8; 32]);
    let honest_holder = Address::from([102u8; 32]);
    let sleepy_holder = Address::from([103u8; 32]);
    let mut state = AccountState::new();
    for addr in [uploader, honest_holder, sleepy_holder] {
        state.add_balance(&addr, 50_000);
    }

    let up = prepare_public_upload(b"audited custody payload", &P, &Bud3Limits::default(), 12)
        .unwrap();
    let obj_key = up.record.commitment;
    let shares = vec![
        (
            0,
            Share {
                validator: *honest_holder.as_bytes(),
                class: Class::Full,
                first_esi: 0,
                symbols: 6,
            },
        ),
        (
            0,
            Share {
                validator: *sleepy_holder.as_bytes(),
                class: Class::Full,
                first_esi: 6,
                symbols: 6,
            },
        ),
    ];
    apply(
        &mut state,
        &storage_tx(
            uploader,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: up.record,
                shares,
                lifetime_epochs: 20,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            honest_holder,
            0,
            1,
            0,
            StorageTxV3::CustodyAck { object: obj_key },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            sleepy_holder,
            0,
            1,
            0,
            StorageTxV3::CustodyAck { object: obj_key },
        ),
    )
    .unwrap();

    // Open guaranteed audits (100% probability, 1-epoch window) for both confirmed holders.
    let opened = state.bud3_registry.open_audits(
        &[0x55; 32],
        1,
        &AuditParams {
            full_ppm: PPM,
            mobile_ppm: PPM,
            full_window: 1,
            mobile_window: 1,
        },
    );
    assert_eq!(opened, 2);

    // Honest holder builds and submits a valid CustodyProofBatch.
    let leaves: Vec<(u32, [u8; 32])> = up.segments[0]
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let open_honest = state
        .bud3_registry
        .open_audits_for(honest_holder.as_bytes());
    assert_eq!(open_honest.len(), 1);
    let (_, audit, _) = open_honest[0];
    let pos = usize::try_from(audit.position).unwrap();
    let sub = usize::try_from(audit.sub_block).unwrap();
    let proof = prove(0, &leaves, pos, &up.segments[0][pos].data, sub).unwrap();
    apply(
        &mut state,
        &storage_tx(
            honest_holder,
            1,
            1,
            0,
            StorageTxV3::CustodyProofBatch {
                proofs: vec![(obj_key, proof)],
            },
        ),
    )
    .unwrap();

    // Sleepy holder misses its window at epoch 3: balance is untouched (zero slash!),
    // while its missed-window reward routes to the security pool.
    let sleepy_balance_before = state.get_balance(&sleepy_holder);
    let missed = state.bud3_registry.close_windows(3);
    assert_eq!(missed, 1);
    assert_eq!(state.get_balance(&sleepy_holder), sleepy_balance_before);
    assert!(state.bud3_registry.validator_custody_credit(honest_holder.as_bytes()) > 0);
    assert_eq!(
        state
            .bud3_registry
            .validator_custody_credit(sleepy_holder.as_bytes()),
        0
    );
}

#[test]
fn bud3_e2e_upload_register_view() {
    use crate::storage::bud3::placement::Candidate;
    use crate::storage::bud3::placement::PlacementRow;
    use crate::storage::bud3::rpc::Bud3RpcService;
    use crate::storage::bud3::upload::UploadSessionManager;
    use crate::storage::bud3::view::{view_from_network, MemorySymbolNetwork, MIN_PAID_VIEW_FEE_ATOMS};

    let uploader = Address::from([111u8; 32]);
    let payer = Address::from([112u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&uploader, 100_000);

    let candidates: Vec<Candidate> = (0..4u8)
        .map(|i| Candidate {
            validator: [120 + i; 32],
            account: [120 + i; 32],
            class: Class::Full,
            stake: 5_000,
            free_quota_bytes: u64::MAX,
            network: None,
        })
        .collect();
    let row = PlacementRow {
        n_full: 2,
        s_full: 6,
        n_mobile: 0,
        s_mobile: 0,
    };

    let original = b"full B.U.D. 3.0 upload -> block register -> second-device network view".repeat(25);
    let mut upload_mgr = UploadSessionManager::new(Bud3Limits::default());
    let sid = upload_mgr
        .open_session(
            (*uploader.as_bytes(), [1; 16]),
            original.len() as u64,
            0,
            25,
            false,
            1_000,
        )
        .unwrap();
    for chunk in original.chunks(199) {
        upload_mgr.append_chunk(sid, chunk, 1_001).unwrap();
    }
    let finished = upload_mgr
        .finish_session(sid, &P, &row, &candidates, &state.bud3_registry, 1_002)
        .unwrap();
    let obj_key = finished.record.commitment;

    // Commit RegisterObject on chain through Executor::apply_transaction.
    apply(&mut state, &storage_tx(uploader, 0, 1, 0, finished.unsigned_tx.clone())).unwrap();

    // Distribute coded symbols to the assigned custody holders on the network.
    let mut net = MemorySymbolNetwork::default();
    if let StorageTxV3::RegisterObject { shares, .. } = &finished.unsigned_tx {
        for (seg, sh) in shares {
            let start = sh.first_esi as usize;
            let end = start + sh.symbols as usize;
            net.store_holder_share(
                sh.validator,
                obj_key,
                *seg,
                finished.segments[*seg as usize][start..end].to_vec(),
            );
        }
    }

    // Second device reconstructs bit-identical content from network holders.
    let recovered = view_from_network(&state.bud3_registry, &obj_key, None, &net).unwrap();
    assert_eq!(recovered, original);

    // RPC service serves `bud_storageGetContent` only when paid and runs reveal sessions from network.
    let mut rpc = Bud3RpcService::default();
    assert!(rpc
        .handle(
            "bud_storageGetContent",
            &serde_json::json!({
                "payer": hex::encode(payer.as_bytes()),
                "object": hex::encode(obj_key),
                "fee_paid_atoms": 0
            }),
            &state.bud3_registry,
            &net,
            (&row, &candidates, 1_005),
        )
        .is_err());
    let paid_resp = rpc
        .handle(
            "bud_storageGetContent",
            &serde_json::json!({
                "payer": hex::encode(payer.as_bytes()),
                "object": hex::encode(obj_key),
                "fee_paid_atoms": MIN_PAID_VIEW_FEE_ATOMS
            }),
            &state.bud3_registry,
            &net,
            (&row, &candidates, 1_005),
        )
        .unwrap();
    assert_eq!(
        hex::decode(paid_resp["content_hex"].as_str().unwrap()).unwrap(),
        original
    );
}

#[test]
fn bud3_e2e_replace_object_preserves_nft_binding_and_slashes_mismatch() {
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::replace::ReplaceAttestation;

    let alice = Address::from([131u8; 32]);
    let proposer = Address::from([132u8; 32]);
    let mut state = AccountState::new();
    state.add_balance(&alice, 100_000);
    state.add_balance(&proposer, 100_000);

    let body = b"replaceable canonical payload".repeat(40);
    let old_up = prepare_public_upload(&body, &P, &Bud3Limits::default(), 48).unwrap();
    let old_key = old_up.record.commitment;
    let old_shares = vec![
        (
            0,
            Share {
                validator: [201; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 16,
            },
        ),
        (
            0,
            Share {
                validator: [202; 32],
                class: Class::Full,
                first_esi: 16,
                symbols: 16,
            },
        ),
        (
            0,
            Share {
                validator: [203; 32],
                class: Class::Full,
                first_esi: 32,
                symbols: 16,
            },
        ),
    ];
    let nft = [0x99u8; 32];
    apply(
        &mut state,
        &storage_tx(
            alice,
            0,
            1,
            0,
            StorageTxV3::RegisterObject {
                record: old_up.record.clone(),
                shares: old_shares,
                lifetime_epochs: 20,
            },
        ),
    )
    .unwrap();
    apply(
        &mut state,
        &storage_tx(
            alice,
            1,
            1,
            0,
            StorageTxV3::BindNft {
                nft,
                object: old_key,
            },
        ),
    )
    .unwrap();

    // Build a valid replacement record for the identical ContentId under a distinct coding layout.
    let p_alt = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 256,
        fps: 10,
        k_max: 64,
    };
    let new_up = prepare_public_upload(&body, &p_alt, &Bud3Limits::default(), 24).unwrap();
    let new_key = new_up.record.commitment;
    assert_ne!(old_key, new_key);
    assert_eq!(old_up.record.content_id, new_up.record.content_id);

    let attestations = vec![
        ReplaceAttestation {
            validator: [201u8; 32],
            verified_content_id: old_up.record.content_id,
        },
        ReplaceAttestation {
            validator: [202u8; 32],
            verified_content_id: old_up.record.content_id,
        },
        ReplaceAttestation {
            validator: [203u8; 32],
            verified_content_id: old_up.record.content_id,
        },
    ];
    let new_shares = vec![(
        0,
        Share {
            validator: [201; 32],
            class: Class::Full,
            first_esi: 0,
            symbols: new_up.record.symbols_per_segment,
        },
    )];
    apply(
        &mut state,
        &storage_tx(
            proposer,
            0,
            1,
            0,
            StorageTxV3::ReplaceObject {
                old_object: old_key,
                new_record: new_up.record,
                new_shares,
                attestations,
                proposer_stake: 50_000,
            },
        ),
    )
    .unwrap();

    assert!(state.bud3_registry.object(&old_key).is_none());
    assert_eq!(
        state
            .bud3_registry
            .object(&new_key)
            .unwrap()
            .references
            .len(),
        1
    );
}





