//! The shared Poseidon definition equals Plonky3's own permutation.
//!
//! `budlum-note-packing::poseidon` carries the round constants and the MDS matrix
//! of the Goldilocks width-12 Poseidon1 instance as plain data, so the wallet, the
//! zkVM and the node can share one definition without a dependency on Plonky3.
//! A copy that is typed in can drift by one digit and every test of the copy
//! passes against itself. This test runs both permutations on the same states.

use budlum_note_packing::poseidon;
use p3_field::PrimeField64;
use p3_goldilocks::poseidon1::default_goldilocks_poseidon1_12;
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;

fn plonky3(state: [u64; 12]) -> [u64; 12] {
    let permutation = default_goldilocks_poseidon1_12();
    let lanes: [Goldilocks; 12] = state.map(Goldilocks::new);
    permutation
        .permute(lanes)
        .map(|lane| lane.as_canonical_u64())
}

/// A linear congruential walk over canonical field values: fixed, reproducible and
/// varied enough to touch every lane and every round constant.
fn states(count: usize) -> Vec<[u64; 12]> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut state = [0u64; 12];
        for lane in &mut state {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *lane = x % 0xFFFF_FFFF_0000_0001;
        }
        out.push(state);
    }
    out
}

#[test]
fn the_shared_permutation_matches_plonky3_on_the_zero_state() {
    assert_eq!(poseidon::permute([0u64; 12]), plonky3([0u64; 12]));
}

#[test]
fn the_shared_permutation_matches_plonky3_on_an_incrementing_state() {
    let mut state = [0u64; 12];
    for (index, lane) in state.iter_mut().enumerate() {
        *lane = u64::try_from(index).unwrap_or(0);
    }
    assert_eq!(poseidon::permute(state), plonky3(state));
}

#[test]
fn the_shared_permutation_matches_plonky3_on_pseudorandom_states() {
    for (index, state) in states(64).into_iter().enumerate() {
        assert_eq!(
            poseidon::permute(state),
            plonky3(state),
            "state number {index} differs from Plonky3"
        );
    }
}

#[test]
fn the_node_function_is_the_first_four_lanes_of_the_permutation() {
    let left = [11u64, 12, 13, 14];
    let right = [21u64, 22, 23, 24];
    let mut state = [0u64; 12];
    state[..4].copy_from_slice(&left);
    state[4..8].copy_from_slice(&right);
    let expected = plonky3(state);
    assert_eq!(
        poseidon::compress(left, right),
        [expected[0], expected[1], expected[2], expected[3]]
    );
}
