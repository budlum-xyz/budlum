#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Shared golden accept and reject vectors for K-G.6 (node <-> mobile light client).
//!
//! Pins exact byte-for-byte agreement between `budlum-types` / `budlum-mobile-core`
//! and the canonical fixture files under `tests/vectors/light_client/v1/`.

use std::path::PathBuf;

use budlum_mobile_core::{
    crypto::{ctx, pq, scheme::SchemeId},
    CheckpointSummary, CheckpointVerifyError, HandoffCertificate, HandoffError, MobileLightClient,
    PqSignatureEntry, QcBlob, TrustedCheckpoint, ValidatorEntry, ValidatorSetSnapshot,
};
use budlum_types::{
    checkpoint::pq_signing_message,
    handoff::{set_digest, HandoffSignature},
    Address,
};

fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/light_client/v1")
}

fn fixture_sets() -> (
    ValidatorSetSnapshot,
    Vec<[u8; 32]>,
    ValidatorSetSnapshot,
    Vec<[u8; 32]>,
) {
    let mut s4 = Vec::new();
    let mut e4 = Vec::new();
    let mut s5 = Vec::new();
    let mut e5 = Vec::new();
    for i in 0u8..4 {
        let mut seed4 = [0x40u8; 32];
        seed4[0] = i + 1;
        let pk4 = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed4).expect("pk4");
        let mut addr4 = [0u8; 32];
        addr4[0] = 0x10 + i;
        addr4[31] = 0x04;
        s4.push(seed4);
        e4.push(ValidatorEntry {
            address: Address::from(addr4),
            // Stakes: [1_000, 1_000, 1_000, 7_000] -> total 10_000.
            // Signers [0, 1, 2] hold 3/4 seats (> 2/3) but only 3_000/10_000 stake (<= 2/3).
            // Signers [1, 2, 3] hold 3/4 seats (> 2/3) and 9_000/10_000 stake (> 2/3).
            stake: if i < 3 { 1_000 } else { 7_000 },
            bls_public_key: vec![0xB4 ^ i; 96],
            pop_signature: vec![0xC4 ^ i; 48],
            pq_public_key: pk4,
        });

        let mut seed5 = [0x50u8; 32];
        seed5[0] = i + 1;
        let pk5 = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed5).expect("pk5");
        let mut addr5 = [0u8; 32];
        addr5[0] = 0x20 + i;
        addr5[31] = 0x05;
        s5.push(seed5);
        e5.push(ValidatorEntry {
            address: Address::from(addr5),
            stake: 1_500 * u64::from(i + 1),
            bls_public_key: vec![0xB5 ^ i; 96],
            pop_signature: vec![0xC5 ^ i; 48],
            pq_public_key: pk5,
        });
    }
    (
        ValidatorSetSnapshot::new(4, e4),
        s4,
        ValidatorSetSnapshot::new(5, e5),
        s5,
    )
}

#[test]
fn shared_golden_accept_and_reject_vectors_match_fixture() {
    let chain_id: u64 = 45_261;
    let (snap4, seeds4, snap5, seeds5) = fixture_sets();
    let randomness = [0xA5u8; 32];
    let block_hash_200 = "20".repeat(32);
    let state_root_200 = "30".repeat(32);
    let block_hash_300 = "40".repeat(32);
    let state_root_300 = "50".repeat(32);

    // Sign epoch-4 QcBlob with validators 1, 2, 3 (stake 1000 + 1000 + 7000 = 9000 / 10000 > 2/3, seats 3 / 4 >= 3).
    let mut qc4_sigs = Vec::new();
    for idx in [1usize, 2, 3] {
        let validator_index = u32::try_from(idx).unwrap();
        let msg = pq_signing_message(4, 200, &block_hash_200, validator_index);
        let sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seeds4[idx],
            &msg,
            ctx::QC_V2,
            &[0u8; 32],
        )
        .expect("qc4 sig");
        qc4_sigs.push(PqSignatureEntry {
            validator_index,
            validator_address: snap4.validators[idx].address.to_hex(),
            pq_signature: sig,
        });
    }
    let qc4 = QcBlob::new(4, 200, block_hash_200.clone(), qc4_sigs);
    let qc4_wire = qc4.to_bytes().expect("qc4 wire");

    // Sign HandoffCertificate 4 -> 5 with all 4 committee members (4 * 3 = 12 > 8 = 4 * 2, stake 10_000 / 10_000).
    let out4 = snap4.to_handoff_members();
    let in5 = snap5.to_handoff_members();
    let mut handoff = HandoffCertificate::unsigned(chain_id, 4, &out4, &in5, randomness);
    let ho_msg = handoff.signing_message();
    for (idx, seed) in seeds4.iter().enumerate() {
        let sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            seed,
            &ho_msg,
            ctx::HANDOFF_V1,
            &[0u8; 32],
        )
        .expect("ho sig");
        handoff.insert_signature(u32::try_from(idx).unwrap(), sig);
    }

    // Sign epoch-5 QcBlob with validators 1, 2, 3 (stake 3000 + 4500 + 6000 = 13500 / 15000 > 2/3, seats 3 / 4 >= 3).
    let mut qc5_sigs = Vec::new();
    for idx in [1usize, 2, 3] {
        let validator_index = u32::try_from(idx).unwrap();
        let msg = pq_signing_message(5, 300, &block_hash_300, validator_index);
        let sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seeds5[idx],
            &msg,
            ctx::QC_V2,
            &[0u8; 32],
        )
        .expect("qc5 sig");
        qc5_sigs.push(PqSignatureEntry {
            validator_index,
            validator_address: snap5.validators[idx].address.to_hex(),
            pq_signature: sig,
        });
    }
    let qc5 = QcBlob::new(5, 300, block_hash_300.clone(), qc5_sigs);

    let dir = vector_dir();
    if std::env::var_os("WRITE_LC_VECTORS").is_some() {
        std::fs::write(dir.join("qc_epoch4_h200.bin"), &qc4_wire).expect("write qc4");
        let meta = serde_json::json!({
            "chain_id": chain_id,
            "epoch4_set_hash": snap4.set_hash,
            "epoch5_set_hash": snap5.set_hash,
            "epoch4_handoff_set_digest_hex": hex::encode(set_digest(chain_id, 4, &out4)),
            "epoch5_handoff_set_digest_hex": hex::encode(set_digest(chain_id, 5, &in5)),
            "handoff_signing_message_hex": hex::encode(&ho_msg),
            "qc4_merkle_root": qc4.merkle_root,
            "qc5_merkle_root": qc5.merkle_root,
            "qc4_signing_message_idx1_hex": hex::encode(pq_signing_message(4, 200, &block_hash_200, 1)),
        });
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_string_pretty(&meta).unwrap() + "\n",
        )
        .expect("write metadata");
    }

    let pinned_qc4_wire = std::fs::read(dir.join("qc_epoch4_h200.bin")).expect("read qc4 fixture");
    assert_eq!(
        qc4_wire, pinned_qc4_wire,
        "QC V2 binary wire vector drifted"
    );

    let meta_raw = std::fs::read_to_string(dir.join("metadata.json")).expect("read metadata.json");
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).expect("parse metadata.json");
    assert_eq!(meta["epoch4_set_hash"].as_str().unwrap(), snap4.set_hash);
    assert_eq!(meta["epoch5_set_hash"].as_str().unwrap(), snap5.set_hash);
    assert_eq!(
        meta["handoff_signing_message_hex"].as_str().unwrap(),
        hex::encode(&ho_msg)
    );
    assert_eq!(meta["qc4_merkle_root"].as_str().unwrap(), qc4.merkle_root);
    assert_eq!(meta["qc5_merkle_root"].as_str().unwrap(), qc5.merkle_root);

    // Golden ACCEPT path: decode QC wire -> verify -> follow handoff -> verify next epoch QC.
    let decoded_qc4 =
        QcBlob::from_bytes(&pinned_qc4_wire, snap4.validators.len()).expect("decode qc4");
    let anchor = TrustedCheckpoint {
        height: 100,
        block_hash: "10".repeat(32),
        set_hash: snap4.set_hash.clone(),
    };
    let mut client = MobileLightClient::new(anchor, chain_id).expect("bootstrap");
    let h200 = CheckpointSummary {
        height: 200,
        block_hash: block_hash_200.clone(),
        state_root: state_root_200,
    };
    let verified200 = client
        .verify_and_advance(&h200, &decoded_qc4, &snap4)
        .expect("verify epoch 4 checkpoint");
    assert_eq!(verified200.height, 200);

    // Golden REJECT vectors:
    // 1) Non-forward height replay (200 <= trusted 200) is refused.
    assert!(matches!(
        client.verify_pq_checkpoint(&h200, &decoded_qc4, &snap4),
        Err(CheckpointVerifyError::NotForward { .. })
    ));

    // 2) Handoff with wrong randomness is refused.
    assert_eq!(
        client.verify_handoff_certificate(&handoff, &out4, [0x00; 32]),
        Err(HandoffError::Randomness)
    );

    // 3) Handoff with unsorted signatures is refused.
    let mut unsorted = handoff.clone();
    unsorted.signatures.swap(0, 1);
    assert_eq!(
        client.verify_handoff_certificate(&unsorted, &out4, randomness),
        Err(HandoffError::Order)
    );

    // 4) Handoff with seat quorum shortfall (3 of 4 seats -> 3*3 = 9 > 8, so 2 of 4 seats -> 2*3 = 6 <= 8) is refused.
    let mut seat_short = HandoffCertificate::unsigned(chain_id, 4, &out4, &in5, randomness);
    for idx in [2usize, 3] {
        let sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seeds4[idx],
            &ho_msg,
            ctx::HANDOFF_V1,
            &[0u8; 32],
        )
        .unwrap();
        seat_short.signatures.push(HandoffSignature {
            index: u32::try_from(idx).unwrap(),
            signature: sig,
        });
    }
    assert_eq!(
        client.verify_handoff_certificate(&seat_short, &out4, randomness),
        Err(HandoffError::Quorum {
            signed: 2,
            committee: 4,
        })
    );

    // 5) Handoff with sufficient seats (3 of 4: 3*3 = 9 > 8) but insufficient stake (3000 / 10000 <= 2/3) is refused!
    let mut stake_short = HandoffCertificate::unsigned(chain_id, 4, &out4, &in5, randomness);
    for idx in [0usize, 1, 2] {
        let sig = pq::ml_dsa_sign(
            SchemeId::ML_DSA_65,
            &seeds4[idx],
            &ho_msg,
            ctx::HANDOFF_V1,
            &[0u8; 32],
        )
        .unwrap();
        stake_short.signatures.push(HandoffSignature {
            index: u32::try_from(idx).unwrap(),
            signature: sig,
        });
    }
    assert_eq!(
        client.verify_handoff_certificate(&stake_short, &out4, randomness),
        Err(HandoffError::Quorum {
            signed: 3,
            committee: 4,
        })
    );

    // 6) Honest handoff succeeds and rotates trusted set_hash to epoch 5; epoch 5 checkpoint verifies.
    let epoch = client
        .follow_handoffs(&snap4, &[(handoff, snap5.clone())], &|_| randomness)
        .expect("follow handoff 4->5");
    assert_eq!(epoch, 5);
    let h300 = CheckpointSummary {
        height: 300,
        block_hash: block_hash_300,
        state_root: state_root_300,
    };
    let verified300 = client
        .verify_and_advance(&h300, &qc5, &snap5)
        .expect("verify epoch 5 checkpoint");
    assert_eq!(verified300.height, 300);
    assert_eq!(verified300.epoch, 5);
}
