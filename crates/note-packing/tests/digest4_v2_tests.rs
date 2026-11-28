//! 256-bit Digest4 note commitment and nullifier parity and refusal tests.

use budlum_note_packing::digest4::{
    note_commitment_v2, note_nullifier_v2, Digest4, HashSuiteId, SuiteTaggedCommitment,
};
use budlum_note_packing::GOLDILOCKS_P;

#[test]
fn all_zero_digest_is_refused_by_constructor_and_decoder() {
    let zero = Digest4::try_new([0, 0, 0, 0]).expect("zero limbs are canonical");
    assert!(
        SuiteTaggedCommitment::from_poseidon_digest4(zero).is_none(),
        "all-zero Poseidon Digest4 must never be accepted as a valid V2 commitment"
    );

    for suite in [
        HashSuiteId::PoseidonG12V1,
        HashSuiteId::Sha3_256V1,
        HashSuiteId::Blake3_256V1,
    ] {
        let mut wire = [0u8; 33];
        wire[0] = suite.as_byte();
        assert!(
            SuiteTaggedCommitment::decode(&wire).is_none(),
            "all-zero digest for suite {suite:?} must fail closed"
        );
    }
}

#[test]
fn note_commitment_v2_is_full_256bit_injective_in_all_recipient_bytes() {
    let blinding = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888];
    let recipient_a = [0xAAu8; 32];
    let mut recipient_b = recipient_a;
    // Flip ONLY the very last byte (byte 31) - a 64-bit recipient_tag would miss this!
    recipient_b[31] ^= 0x01;

    let c_a = note_commitment_v2(1_000, blinding, &recipient_a).expect("valid v2 commitment");
    let c_b = note_commitment_v2(1_000, blinding, &recipient_b).expect("valid v2 commitment");

    assert_eq!(c_a.suite, HashSuiteId::PoseidonG12V1);
    assert_ne!(
        c_a.digest, c_b.digest,
        "byte 31 of recipient must affect commitment"
    );

    // Must be a full 256-bit 4-limb digest, not 64-bit truncated.
    let d_a = Digest4::from_bytes_checked(&c_a.digest).expect("canonical 4 limbs");
    assert!(!d_a.is_single_limb_truncated());
    assert!(!d_a.is_zero());

    // Refuses zero blinding, zero recipient, and non-canonical inputs.
    assert!(note_commitment_v2(1_000, [0, 0], &recipient_a).is_none());
    assert!(note_commitment_v2(1_000, blinding, &[0u8; 32]).is_none());
    assert!(note_commitment_v2(GOLDILOCKS_P, blinding, &recipient_a).is_none());
    assert!(note_commitment_v2(1_000, [GOLDILOCKS_P, 1], &recipient_a).is_none());
}

#[test]
fn note_nullifier_v2_binds_commitment_and_256bit_secret() {
    let blinding = [42, 99];
    let recipient = [0x7Bu8; 32];
    let c1 = note_commitment_v2(500, blinding, &recipient).expect("c1");
    let c2 = note_commitment_v2(501, blinding, &recipient).expect("c2");
    let secret = [10, 20, 30, 40];

    let n1 = note_nullifier_v2(secret, &c1).expect("n1");
    let n2 = note_nullifier_v2(secret, &c2).expect("n2");
    assert_ne!(
        n1.digest, n2.digest,
        "nullifier must bind the specific commitment"
    );
    assert_ne!(
        n1.digest, c1.digest,
        "nullifier domain must separate from commitment"
    );

    // Refuses all-zero secret, non-canonical secret limb, and non-Poseidon commitment.
    assert!(note_nullifier_v2([0, 0, 0, 0], &c1).is_none());
    assert!(note_nullifier_v2([GOLDILOCKS_P, 1, 2, 3], &c1).is_none());
    let sha_comm = SuiteTaggedCommitment {
        suite: HashSuiteId::Sha3_256V1,
        digest: [0x99u8; 32],
    };
    assert!(note_nullifier_v2(secret, &sha_comm).is_none());
}
