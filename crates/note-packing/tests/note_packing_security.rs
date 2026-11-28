use budlum_note_packing::{Digest4, HashSuiteId, SuiteTaggedCommitment};

#[test]
fn poseidon_all_zero_digest4_is_rejected() {
    let zero_d4 = Digest4::try_new([0, 0, 0, 0]).expect("canonical field limbs");
    assert_eq!(
        SuiteTaggedCommitment::from_poseidon_digest4(zero_d4),
        None,
        "all-zero Digest4 must be rejected by SuiteTaggedCommitment"
    );
}

#[test]
fn all_zero_wire_commitments_are_rejected_across_all_suites() {
    for suite in [
        HashSuiteId::PoseidonG12V1,
        HashSuiteId::Sha3_256V1,
        HashSuiteId::Blake3_256V1,
    ] {
        let mut raw = [0u8; 33];
        raw[0] = suite.as_byte();
        assert_eq!(
            SuiteTaggedCommitment::decode(&raw),
            None,
            "all-zero commitment under {suite:?} must fail decode"
        );
    }
}

#[test]
fn v1_64bit_zero_padded_commitments_are_rejected_for_sha3_and_blake3() {
    for suite in [HashSuiteId::Sha3_256V1, HashSuiteId::Blake3_256V1] {
        let mut truncated = [0u8; 33];
        truncated[0] = suite.as_byte();
        truncated[1..9].copy_from_slice(&42u64.to_le_bytes());
        assert_eq!(
            SuiteTaggedCommitment::decode(&truncated),
            None,
            "64-bit zero-padded digest under {suite:?} must fail decode"
        );
    }
}
