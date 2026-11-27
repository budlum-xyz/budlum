//! Security regression tests for `DataLayerRegistry` confidentiality, nonce replay,
//! blinding-salt non-zero enforcement, and per-owner record bounds.

use budlum_core::crypto::ctx::PRIVATE_TRANSFER_V1;
use budlum_core::crypto::pq::{ml_dsa_public_key, ml_dsa_sign};
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::privacy::data_layering::{
    compute_layer_commitment, layer_transition_digest, DataLayerError, DataLayerRegistry,
    DataPrivacyLayer, LayerOwnerAuth,
};
use sha3::{Digest, Sha3_256};

const TEST_CHAIN_ID: u64 = 45_261;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, context: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{context}: {e:?}"),
    }
}

fn sign_transition(
    seed: &[u8; 32],
    pk: &[u8],
    record_id: &[u8; 32],
    nonce: u64,
    from: DataPrivacyLayer,
    to: DataPrivacyLayer,
    binding: &[u8; 32],
) -> LayerOwnerAuth {
    let digest = layer_transition_digest(TEST_CHAIN_ID, record_id, nonce, from, to, binding);
    let sig = must(
        ml_dsa_sign(
            SchemeId::ML_DSA_65,
            seed,
            &digest,
            PRIVATE_TRANSFER_V1,
            &[0u8; 32],
        ),
        "ml_dsa_sign",
    );
    LayerOwnerAuth {
        chain_id: TEST_CHAIN_ID,
        nonce,
        owner_ml_dsa_65_pk: pk.to_vec(),
        signature: sig,
    }
}

#[test]
fn confidential_default_refuses_zero_declared_byte_len() {
    let seed = [0x41u8; 32];
    let pk = must(ml_dsa_public_key(SchemeId::ML_DSA_65, &seed), "pk");
    let mut reg = must(DataLayerRegistry::new(TEST_CHAIN_ID), "registry");

    let err = reg.register_confidential_default([0x11; 32], [0x22; 32], 0, &pk);
    assert_eq!(
        err,
        Err(DataLayerError::ZeroParameter("declared_byte_len")),
        "zero-byte confidential record must be rejected"
    );
}

#[test]
fn declassify_to_public_refuses_all_zero_blinding_salt() {
    let seed = [0x42u8; 32];
    let pk = must(ml_dsa_public_key(SchemeId::ML_DSA_65, &seed), "pk");
    let mut reg = must(DataLayerRegistry::new(TEST_CHAIN_ID), "registry");

    let record_id = [0x33u8; 32];
    let plaintext = b"secret payload".to_vec();
    let pt_digest: [u8; 32] = Sha3_256::digest(&plaintext).into();
    let zero_salt = [0u8; 32];
    let bad_commitment =
        compute_layer_commitment(&record_id, &zero_salt, &pt_digest, plaintext.len() as u64);

    must(
        reg.register_confidential_default(record_id, bad_commitment, plaintext.len() as u64, &pk),
        "register",
    );

    let auth = sign_transition(
        &seed,
        &pk,
        &record_id,
        0,
        DataPrivacyLayer::K3Confidential,
        DataPrivacyLayer::K1Public,
        &pt_digest,
    );
    let res = reg.declassify_to_public(&record_id, plaintext, Some(&zero_salt), &auth);
    assert_eq!(
        res,
        Err(DataLayerError::ZeroParameter("blind_salt")),
        "all-zero blinding salt destroys commitment hiding and must be rejected"
    );
}

#[test]
fn transition_nonce_u64_max_fails_closed_instead_of_saturating_replay() {
    let seed = [0x43u8; 32];
    let pk = must(ml_dsa_public_key(SchemeId::ML_DSA_65, &seed), "pk");
    let mut reg = must(DataLayerRegistry::new(TEST_CHAIN_ID), "registry");

    let record_id = [0x44u8; 32];
    let commitment = [0x55u8; 32];
    must(
        reg.register_confidential_default(record_id, commitment, 16, &pk),
        "register",
    );

    // Round-trip through JSON to simulate a restored record whose transition_nonce
    // is already at u64::MAX (where saturating_add(1) would pin the nonce forever).
    let mut val = must(serde_json::to_value(&reg), "to_value");
    let key_hex = hex::encode(record_id);
    if let Some(rec_obj) = val
        .get_mut("records")
        .and_then(|r| r.as_object_mut())
        .and_then(|m| m.get_mut(&key_hex))
        .and_then(|o| o.as_object_mut())
    {
        rec_obj.insert("transition_nonce".to_string(), serde_json::json!(u64::MAX));
    } else {
        panic!("could not locate serialized record key {key_hex} in DataLayerRegistry");
    }
    let mut reg_max: DataLayerRegistry = must(serde_json::from_value(val), "from_value");
    assert_eq!(
        reg_max.record(&record_id).map(|r| r.transition_nonce),
        Some(u64::MAX)
    );

    let grant_tag = [0x77u8; 32];
    let auth = sign_transition(
        &seed,
        &pk,
        &record_id,
        u64::MAX,
        DataPrivacyLayer::K3Confidential,
        DataPrivacyLayer::K3Confidential,
        &grant_tag,
    );
    let err = reg_max.issue_confidential_grant(&record_id, grant_tag, &auth);
    assert!(
        err.is_err(),
        "transition_nonce == u64::MAX must fail closed rather than saturating and permitting replay"
    );
    assert!(
        reg_max
            .record(&record_id)
            .is_some_and(|r| !r.active_grant_tags.contains(&grant_tag)),
        "failed transition must not mutate active_grant_tags"
    );
}

#[test]
fn single_owner_cannot_exhaust_global_data_layer_registry() {
    let seed = [0x45u8; 32];
    let pk = must(ml_dsa_public_key(SchemeId::ML_DSA_65, &seed), "pk");
    let mut reg = must(DataLayerRegistry::new(TEST_CHAIN_ID), "registry");

    let mut inserted = 0usize;
    for i in 1u32..=300u32 {
        let mut rid = [0u8; 32];
        rid[0..4].copy_from_slice(&i.to_le_bytes());
        rid[31] = 0xAB;
        match reg.register_confidential_default(rid, [0x99; 32], 32, &pk) {
            Ok(_) => inserted += 1,
            Err(_) => break,
        }
    }
    assert!(
        inserted <= 256,
        "a single owner inserted {inserted} records; per-owner quota must bound state below 256"
    );
}
