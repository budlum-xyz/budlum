//! The common finality-evidence envelope: the canonical byte container every
//! external-family verifier emits into and the settlement layer ingests.
//!
//! Encode is deterministic; decode is fail-closed. A malformed envelope is a
//! value, never a panic.

use budlum_nipopow::envelope::{DecodeError, EvidenceEnvelope};

fn sample() -> EvidenceEnvelope {
    EvidenceEnvelope {
        family: 6, // the PoW family tag this crate's proofs belong to
        chain_id: 45261,
        height: 133_700,
        header_digest: [0x5au8; 32],
        attestation: vec![0x11, 0x22, 0x33, 0x44],
    }
}

#[test]
fn roundtrip_restores_the_exact_envelope() {
    let env = sample();
    let bytes = env.encode();
    let back = EvidenceEnvelope::decode(&bytes).expect("a self-encoded envelope must decode");
    assert_eq!(env, back);
}

#[test]
fn encoding_is_deterministic() {
    assert_eq!(sample().encode(), sample().encode());
}

#[test]
fn decode_rejects_wrong_magic() {
    let mut bytes = sample().encode();
    bytes[0] ^= 0x01;
    assert_eq!(
        EvidenceEnvelope::decode(&bytes),
        Err(DecodeError::WrongMagic)
    );
}

#[test]
fn decode_rejects_unsupported_version() {
    let mut bytes = sample().encode();
    bytes[8] = 0x02;
    assert_eq!(
        EvidenceEnvelope::decode(&bytes),
        Err(DecodeError::UnsupportedVersion)
    );
}

#[test]
fn decode_rejects_zero_family_and_zero_chain() {
    let mut env = sample();
    env.family = 0;
    assert_eq!(
        EvidenceEnvelope::decode(&env.encode()),
        Err(DecodeError::UnsetField)
    );
    let mut env = sample();
    env.chain_id = 0;
    assert_eq!(
        EvidenceEnvelope::decode(&env.encode()),
        Err(DecodeError::UnsetField)
    );
}

#[test]
fn decode_rejects_empty_attestation() {
    let mut env = sample();
    env.attestation = Vec::new();
    assert_eq!(
        EvidenceEnvelope::decode(&env.encode()),
        Err(DecodeError::UnsetField)
    );
}

#[test]
fn decode_rejects_truncated_body_and_tag() {
    let bytes = sample().encode();
    for take in [0usize, 8, 9, 17, 25, bytes.len() - 1, bytes.len() - 31] {
        assert!(
            EvidenceEnvelope::decode(&bytes[..take]).is_err(),
            "take={take}"
        );
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let mut bytes = sample().encode();
    bytes.extend_from_slice(&[0xde, 0xad]);
    assert_eq!(
        EvidenceEnvelope::decode(&bytes),
        Err(DecodeError::LengthMismatch)
    );
}

#[test]
fn decode_rejects_oversized_attestation() {
    let mut bytes = sample().encode();
    // attested length field sits at offset 8+1+1+8+8+32; forge a 1 GiB length.
    let len_off = 8 + 1 + 1 + 8 + 8 + 32;
    bytes[len_off..len_off + 4].copy_from_slice(&(1u32 << 30).to_le_bytes());
    assert_eq!(
        EvidenceEnvelope::decode(&bytes),
        Err(DecodeError::AttestationTooLarge)
    );
}

#[test]
fn tampered_attestation_breaks_the_tag() {
    let mut bytes = sample().encode();
    let att_off = 8 + 1 + 1 + 8 + 8 + 32 + 4;
    bytes[att_off] ^= 0x80;
    assert_eq!(
        EvidenceEnvelope::decode(&bytes),
        Err(DecodeError::TagMismatch)
    );
}

#[test]
fn envelope_binds_chain_and_height() {
    let a = sample();
    let mut b = sample();
    b.chain_id = 45260;
    assert_ne!(a.encode(), b.encode());
    let mut c = sample();
    c.height += 1;
    assert_ne!(a.encode(), c.encode());
}
