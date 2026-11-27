//! Security regression tests for `budlum-bpqs`:
//! 1. `BpqsVerifierLog::accept_at_height` refuses replaying the same
//!    `(root, epoch)` signature under a different `EpochWindow`.
//! 2. `merkle::verify_path` refuses out-of-headroom leaf indices (`>= 2^T_LOG2`)
//!    and non-canonical padding bytes in root/path/leaf lanes.
//! 3. `BpqsSigner::ceremonial_keygen` and `fresh_device` refuse an all-zero
//!    master root seed.

use budlum_bpqs::epoch::EpochWindow;
use budlum_bpqs::error::BpqsError;
use budlum_bpqs::hash::Sha3_256Hash;
use budlum_bpqs::merkle;
use budlum_bpqs::params::{BpqsParams, ParamsTestFast};
use budlum_bpqs::sign::{BpqsPublicKey, BpqsSigner, BpqsVerifierLog};

type P = ParamsTestFast;
type H = Sha3_256Hash;

#[test]
fn verifier_log_refuses_epoch_replay_across_window_swap() {
    let mut signer =
        BpqsSigner::<P, H>::fresh_device([0x42u8; 32], EpochWindow(8)).expect("keygen");
    let sig = signer.sign_at_height(3, b"anchor").expect("sign epoch 0");

    let mut log = BpqsVerifierLog::new_allow_test_params();
    log.accept_at_height::<H, P>(signer.public(), 3, b"anchor", &sig)
        .expect("first acceptance succeeds");

    // Re-wrap the exact same Merkle root with a wider EpochWindow(16):
    // height 5 still maps to epoch 0, and `accept_at_height` MUST refuse replay.
    let swapped_pk = BpqsPublicKey::<P>::from_parts(signer.public().root, EpochWindow(16), P::NAME);
    let err = log
        .accept_at_height::<H, P>(&swapped_pk, 5, b"anchor", &sig)
        .expect_err("replaying the same (root, epoch) with a swapped EpochWindow must fail");
    assert_eq!(
        err,
        BpqsError::QuotaExceeded {
            epoch: 0,
            attempted: 2
        }
    );
}

#[test]
fn merkle_verify_path_refuses_out_of_headroom_index_and_non_canonical_padding() {
    let leaf_count = 1usize << P::T_LOG2;
    let mut vks = Vec::with_capacity(leaf_count);
    for i in 0..leaf_count {
        let mut lane = [0u8; 32];
        lane[0] = (i as u8).wrapping_add(1);
        vks.push(lane);
    }
    let (root, levels) = merkle::build_tree::<H, P>(&vks).expect("build tree");
    let path = merkle::auth_path::<P>(&levels, 3).expect("auth path");
    merkle::verify_path::<H, P>(&vks[3], 3, &path, &root).expect("honest leaf 3 verifies");

    // Out-of-headroom index `leaf_count + 3` aliases leaf 3 in low bits -> MUST fail closed.
    let err = merkle::verify_path::<H, P>(&vks[3], leaf_count + 3, &path, &root)
        .expect_err("out-of-headroom leaf index must fail closed");
    assert!(matches!(err, BpqsError::Malformed(_)));

    // Non-zero unused padding in path tail or expected_root past P::N -> MUST fail closed.
    let mut dirty_path = path;
    dirty_path[P::T_LOG2][0] = 0x01;
    assert!(matches!(
        merkle::verify_path::<H, P>(&vks[3], 3, &dirty_path, &root),
        Err(BpqsError::Malformed(_))
    ));

    let mut dirty_root = root;
    if let Some(slot) = dirty_root.get_mut(P::N) {
        *slot = 0xFF;
        assert!(matches!(
            merkle::verify_path::<H, P>(&vks[3], 3, &path, &dirty_root),
            Err(BpqsError::Malformed(_))
        ));
    }
}

#[test]
fn ceremonial_keygen_and_fresh_device_refuse_all_zero_root_seed() {
    assert!(matches!(
        BpqsSigner::<P, H>::ceremonial_keygen([0u8; 32], EpochWindow(8)),
        Err(BpqsError::Malformed(_))
    ));
    assert!(matches!(
        BpqsSigner::<P, H>::fresh_device([0u8; 32], EpochWindow(8)),
        Err(BpqsError::Malformed(_))
    ));
}
