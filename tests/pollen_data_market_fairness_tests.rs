//! End-to-end integration tests for Pollen data-market access isolation,
//! per-owner protected-content capacity bounds, duration-proportional
//! occupancy deposit calculation, stale-counter overwrite guards, and
//! chain-aware post-quantum encryption policy enforcement.

use budlum_core::bns::{CreateNameOffer, OfferKind};
use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::pollen::data_rights::{
    HPKE_SUITE_MLKEM768_X25519, HPKE_SUITE_X25519_ONLY, MAINNET_MIN_ENCRYPTION_POLICY_VERSION,
};
use budlum_core::pollen::offers::{
    compute_offer_occupancy_deposit, MarketplaceRegistry, MAX_NAME_OFFER_TTL_EPOCHS,
    MAX_PROTECTED_CONTENT_PER_OWNER, NAME_OFFER_DEPOSIT_PER_EPOCH_ATOMS,
};
use budlum_core::pollen::{AccessGrant, AiDataInputRef, DataAsset, EncryptionPolicy, Signature64};
use budlum_core::storage::content_id::ContentId;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

#[test]
fn grant_for_asset_a_cannot_authorize_declared_perception_of_asset_b() {
    let mut registry = MarketplaceRegistry::new();
    let victim = addr(0x10);
    let attacker = addr(0x20);

    // Victim owns expensive Asset B.
    let asset_b = DataAsset::new(
        victim,
        ContentId::of(b"victim-secret-dataset"),
        [0xBB; 32],
        true,
    );
    registry
        .register_data_asset(asset_b.clone())
        .expect("register victim asset B");

    // Attacker creates their own cheap Asset A and issues Grant A to themselves.
    let asset_a = DataAsset::new(
        attacker,
        ContentId::of(b"attacker-dummy-data"),
        [0xAA; 32],
        true,
    );
    registry
        .register_data_asset(asset_a.clone())
        .expect("register attacker asset A");
    let mut grant_a = AccessGrant::new_unsigned(
        asset_a.asset_id,
        attacker,
        attacker,
        attacker,
        1,
        1,
        100,
        5,
        [0x01; 32],
    );
    grant_a.owner_signature = Signature64([0x11; 64]);
    let grant_a_id = registry
        .create_access_grant_by_owner(grant_a)
        .expect("create self-grant A");

    let ref_a = AiDataInputRef {
        asset_id: asset_a.asset_id,
        grant_id: grant_a_id,
    }
    .encode();

    // Valid for Asset A itself.
    registry
        .validate_ai_read_ref(&ref_a, &attacker, 10)
        .expect("valid grant A for asset A");
    registry
        .validate_ai_declared_asset(&ref_a, &asset_a.asset_id, &attacker)
        .expect("matching declared asset A must succeed");

    // Confused-deputy attack: present valid (Asset A, Grant A) in input_ref while
    // declaring perception access to Victim's Asset B. MUST FAIL CLOSED!
    let err = registry
        .validate_ai_declared_asset(&ref_a, &asset_b.asset_id, &attacker)
        .expect_err("grant for Asset A MUST NEVER authorize declared Asset B");
    assert!(
        err.contains("different asset"),
        "expected cross-asset refusal message, got: {err}"
    );
}

#[test]
fn consume_ai_read_grant_refuses_revoked_asset() {
    let mut registry = MarketplaceRegistry::new();
    let owner = addr(0x31);
    let grantee = addr(0x32);

    let asset = DataAsset::new(owner, ContentId::of(b"revocable-dataset"), [0x33; 32], true);
    registry
        .register_data_asset(asset.clone())
        .expect("register asset");
    let mut grant = AccessGrant::new_unsigned(
        asset.asset_id,
        owner,
        grantee,
        grantee,
        100,
        1,
        100,
        5,
        [0x02; 32],
    );
    grant.owner_signature = Signature64([0x22; 64]);
    let grant_id = registry
        .create_access_grant_by_owner(grant)
        .expect("create grant");

    // Owner revokes the DataAsset; consuming the grant MUST now fail closed.
    registry
        .revoke_data_asset(&asset.asset_id, &owner)
        .expect("owner revokes asset");
    let err = registry
        .consume_ai_read_grant(&grant_id, &grantee, 10)
        .expect_err("revoked DataAsset must block consume_ai_read_grant");
    assert!(
        err.contains("inactive") || err.contains("revoked"),
        "expected revoked/inactive refusal, got: {err}"
    );
}

#[test]
fn bind_content_to_asset_enforces_per_owner_cap_without_blocking_other_owners() {
    let mut registry = MarketplaceRegistry::new();
    let owner_a = addr(0x41);
    let owner_b = addr(0x42);

    for i in 0..MAX_PROTECTED_CONTENT_PER_OWNER {
        let label = format!("owner-a-manifest-{i}");
        let cid = ContentId::of(label.as_bytes());
        let asset = DataAsset::new(owner_a, cid, [(i % 251) as u8; 32], true);
        registry
            .register_data_asset(asset.clone())
            .expect("register asset within cap");
        registry
            .bind_content_to_asset(cid, asset.asset_id, owner_a)
            .expect("bind within per-owner cap");
    }

    // One more binding for owner_a MUST be refused.
    let overflow_cid = ContentId::of(b"owner-a-manifest-overflow");
    let overflow_asset = DataAsset::new(owner_a, overflow_cid, [0x99; 32], true);
    registry
        .register_data_asset(overflow_asset.clone())
        .expect("register overflow asset");
    let err = registry
        .bind_content_to_asset(overflow_cid, overflow_asset.asset_id, owner_a)
        .expect_err("single owner must not exceed MAX_PROTECTED_CONTENT_PER_OWNER");
    assert!(
        err.contains("maximum protected content bindings"),
        "expected per-owner protected content refusal, got: {err}"
    );

    // Independent owner_b MUST remain unaffected.
    let b_cid = ContentId::of(b"owner-b-manifest-0");
    let b_asset = DataAsset::new(owner_b, b_cid, [0x77; 32], true);
    registry
        .register_data_asset(b_asset.clone())
        .expect("register owner_b asset");
    registry
        .bind_content_to_asset(b_cid, b_asset.asset_id, owner_b)
        .expect("other owner must still be able to bind protected content");
}

#[test]
fn name_offer_occupancy_deposit_scales_linearly_and_blocks_stale_counter_overwrite() {
    // Duration-proportional occupancy deposit validation.
    assert!(compute_offer_occupancy_deposit(0).is_err());
    assert!(compute_offer_occupancy_deposit(MAX_NAME_OFFER_TTL_EPOCHS + 1).is_err());
    let d1 = compute_offer_occupancy_deposit(1).expect("1 epoch");
    let d10 = compute_offer_occupancy_deposit(10).expect("10 epochs");
    assert_eq!(d1, NAME_OFFER_DEPOSIT_PER_EPOCH_ATOMS);
    assert_eq!(d10, 10 * NAME_OFFER_DEPOSIT_PER_EPOCH_ATOMS);

    // Stale counter overwrite guard on create_name_offer.
    let mut registry = MarketplaceRegistry::new();
    let seller_a = addr(0x51);
    let seller_b = addr(0x52);
    let req_a = CreateNameOffer {
        name: "alpha.bud".into(),
        price_atoms: 1_000_000,
        duration: 10,
        kind: OfferKind::Primary,
        expires_at_epoch: 50,
    };
    let id0 = registry
        .create_name_offer(seller_a, req_a, 1)
        .expect("seller A creates offer 0");
    assert_eq!(id0, 0);

    // Simulate snapshot counter lagging behind live keys: MUST refuse without overwriting seller A.
    registry.next_name_offer_id = 0;
    let req_b = CreateNameOffer {
        name: "bravo.bud".into(),
        price_atoms: 500_000,
        duration: 10,
        kind: OfferKind::Primary,
        expires_at_epoch: 50,
    };
    let err = registry
        .create_name_offer(seller_b, req_b, 1)
        .expect_err("stale next_name_offer_id must refuse instead of overwriting seller A");
    assert!(err.contains("already live"), "unexpected err: {err}");
    let preserved = registry.get_name_offer(0).expect("offer 0 preserved");
    assert_eq!(preserved.seller, seller_a);
    assert_eq!(preserved.name, "alpha.bud");
}

#[test]
fn mainnet_encryption_policy_refuses_classical_x25519_and_installs_post_quantum_default() {
    let mut registry = MarketplaceRegistry::new();
    let mainnet_id = Network::Mainnet.chain_id().0;

    // Classical X25519-only policy MUST be refused on mainnet.
    let classical = EncryptionPolicy {
        version: 1,
        hpke_suite_id: HPKE_SUITE_X25519_ONLY,
        min_public_key_bytes: 32,
        max_grant_duration_blocks: 10_000,
        deprecated_after_block: None,
        active: true,
    };
    let err = registry
        .set_encryption_policy_for_chain(classical, mainnet_id)
        .expect_err("classical X25519 policy must be refused on mainnet");
    assert!(err.contains("refused on mainnet"), "unexpected err: {err}");

    // Installing the default post-quantum policy wires EncryptionPolicy::post_quantum and succeeds.
    let ver = registry
        .install_post_quantum_default_policy(mainnet_id, 50_000)
        .expect("mainnet PQ default policy installs");
    assert_eq!(ver, MAINNET_MIN_ENCRYPTION_POLICY_VERSION);
    let installed = registry
        .get_encryption_policy(ver)
        .expect("installed PQ policy readable");
    assert_eq!(installed.hpke_suite_id, HPKE_SUITE_MLKEM768_X25519);
    assert_eq!(installed.max_grant_duration_blocks, 50_000);
}
