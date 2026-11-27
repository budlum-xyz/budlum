use budlum_nipopow::envelope::{DecodeError, EvidenceEnvelope};
use budlum_nipopow::{
    hash_block, leading_zero_bits, ChainBuilder, Hash32, NipopowProof, PowHeader, SecurityParams,
    TrustedAnchor,
};

fn mine_custom(parent: Hash32, height: u64, level: u8, interlink: Vec<Hash32>) -> PowHeader {
    let mut nonce = 0u64;
    loop {
        let id = hash_block(&parent, height, nonce, level, &interlink);
        if leading_zero_bits(&id) >= u32::from(level) {
            return PowHeader {
                id,
                parent,
                height,
                nonce,
                level,
                interlink,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[test]
fn proof_anchor_mismatch_is_rejected() {
    let anchor = [0xAA; 32];
    let mut chain = ChainBuilder::new(anchor);
    for _ in 0..8 {
        chain.push(2);
    }
    let mut proof = chain.build_proof(2);
    let params = SecurityParams::new(2, 2, 4).expect("valid params");
    assert!(proof.verify(&chain.trusted_anchor(), &params));

    // Rewriting `proof.anchor` to a foreign digest must fail verification.
    proof.anchor = [0xFF; 32];
    assert!(
        !proof.verify(&chain.trusted_anchor(), &params),
        "NipopowProof::verify must bind proof.anchor to TrustedAnchor.id"
    );
}

#[test]
fn suffix_contiguous_parent_step_cannot_teleport_height() {
    let anchor = [0xBB; 32];
    let params = SecurityParams::new(2, 2, 4).expect("valid params");

    // `h1` legitimately sits at height 1 above genesis anchor.
    let h1 = mine_custom(anchor, 1, 2, vec![[0u8; 32], [0u8; 32]]);
    // `h2` names `h1.id` ONLY as its direct `parent` (zero interlink!) yet claims height 2^40.
    let fake_height = 1u64 << 40;
    let h2 = mine_custom(h1.id, fake_height, 2, vec![[0u8; 32], [0u8; 32]]);
    let head = mine_custom(h2.id, fake_height + 1, 2, vec![[0u8; 32], [0u8; 32]]);

    let forged = NipopowProof {
        prefix: vec![head],
        suffix: vec![h2, h1],
        anchor,
    };
    assert!(
        !forged.verify(&TrustedAnchor::genesis(anchor), &params),
        "a direct parent link in suffix without an interlink pointer must require height + 1"
    );
}

#[test]
fn envelope_decode_rejects_all_zero_header_digest() {
    let env = EvidenceEnvelope {
        family: 6,
        chain_id: 45261,
        height: 42,
        header_digest: [0u8; 32],
        attestation: vec![0x01, 0x02],
    };
    assert_eq!(
        EvidenceEnvelope::decode(&env.encode()),
        Err(DecodeError::UnsetField),
        "all-zero header_digest must be rejected as UnsetField"
    );
}
