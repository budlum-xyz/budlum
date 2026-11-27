//! Security regression tests for validator-set uniqueness, zero-stake/empty-set
//! refusals, and rogue duplicate PQ public-key vote amplification in
//! `budlum-types`.

use budlum_types::checkpoint::{ValidatorEntry, ValidatorSetSnapshot};
use budlum_types::handoff::{member_set_is_valid, HandoffCertificate, HandoffError, HandoffMember};
use budlum_types::Address;

#[test]
fn handoff_rejects_duplicate_pq_public_key_vote_amplification_and_zero_address() {
    let shared_pq = vec![0xAAu8; 32];
    let members = vec![
        HandoffMember {
            address: vec![1u8; 32],
            bls_public_key: vec![1u8; 48],
            pop_signature: vec![1u8; 96],
            pq_public_key: shared_pq.clone(),
            stake: 100,
        },
        HandoffMember {
            address: vec![2u8; 32],
            bls_public_key: vec![2u8; 48],
            pop_signature: vec![2u8; 96],
            pq_public_key: shared_pq,
            stake: 100,
        },
    ];
    assert!(
        !member_set_is_valid(&members),
        "duplicate pq_public_key across two addresses allows single-key double voting"
    );

    let mut cert = HandoffCertificate::unsigned(45_261, 1, &members, &members, [7u8; 32]);
    cert.insert_signature(0, vec![0x55; 64]);
    cert.insert_signature(1, vec![0x55; 64]);
    assert_eq!(
        cert.verify_with(&members, [7u8; 32], |_, _, _| Ok(())),
        Err(HandoffError::OutgoingSet)
    );

    // All-zero address must also be refused.
    let zero_addr = vec![HandoffMember {
        address: vec![0u8; 32],
        bls_public_key: vec![1u8; 48],
        pop_signature: vec![1u8; 96],
        pq_public_key: vec![3u8; 32],
        stake: 100,
    }];
    assert!(!member_set_is_valid(&zero_addr));
}

#[test]
fn validator_set_snapshot_rejects_empty_zero_stake_zero_addr_and_duplicates() {
    let empty = ValidatorSetSnapshot::new(1, vec![]);
    assert!(
        empty.validate_metadata().is_err(),
        "empty validator set must fail metadata validation"
    );

    let zero_stake = ValidatorSetSnapshot::new(
        1,
        vec![ValidatorEntry {
            address: Address::from([1u8; 32]),
            stake: 0,
            bls_public_key: vec![1u8; 48],
            pop_signature: vec![1u8; 96],
            pq_public_key: vec![1u8; 32],
        }],
    );
    assert!(
        zero_stake.validate_metadata().is_err(),
        "zero-stake validator must fail metadata validation"
    );

    let zero_addr = ValidatorSetSnapshot::new(
        1,
        vec![ValidatorEntry {
            address: Address::zero(),
            stake: 100,
            bls_public_key: vec![1u8; 48],
            pop_signature: vec![1u8; 96],
            pq_public_key: vec![1u8; 32],
        }],
    );
    assert!(
        zero_addr.validate_metadata().is_err(),
        "zero-address validator must fail metadata validation"
    );

    let dup_addr = ValidatorSetSnapshot::new(
        1,
        vec![
            ValidatorEntry {
                address: Address::from([2u8; 32]),
                stake: 100,
                bls_public_key: vec![1u8; 48],
                pop_signature: vec![1u8; 96],
                pq_public_key: vec![1u8; 32],
            },
            ValidatorEntry {
                address: Address::from([2u8; 32]),
                stake: 100,
                bls_public_key: vec![2u8; 48],
                pop_signature: vec![2u8; 96],
                pq_public_key: vec![2u8; 32],
            },
        ],
    );
    assert!(
        dup_addr.validate_metadata().is_err(),
        "duplicate validator address must fail metadata validation"
    );

    let dup_pq = ValidatorSetSnapshot::new(
        1,
        vec![
            ValidatorEntry {
                address: Address::from([3u8; 32]),
                stake: 100,
                bls_public_key: vec![1u8; 48],
                pop_signature: vec![1u8; 96],
                pq_public_key: vec![9u8; 32],
            },
            ValidatorEntry {
                address: Address::from([4u8; 32]),
                stake: 100,
                bls_public_key: vec![2u8; 48],
                pop_signature: vec![2u8; 96],
                pq_public_key: vec![9u8; 32],
            },
        ],
    );
    assert!(
        dup_pq.validate_metadata().is_err(),
        "duplicate pq_public_key across distinct addresses must fail metadata validation"
    );
}
