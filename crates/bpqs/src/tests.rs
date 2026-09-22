//! Crate-level battery: cross-parameter self-consistency, wire-size contract,
//! refusal semantics that span modules, and the L3 row's code path. The
//! per-module unit tests live next to the modules; this file asserts the
//! behavior of the composition.
//!
//! KAT freeze: the battery below feeds frozen vectors into one digest; any
//! construction drift (chain padding, domain bytes, packaging, tree shape)
//! shows up as a digest change the reviewer diffs. The frozen constant is
//! carried plainly so "regenerate & paste" is a deliberate, reviewable edit.

use crate::domains;
use crate::epoch::{prf_epoch_seed, EpochWindow};
use crate::error::BpqsError;
use crate::hash::{BpqsHash, Sha3_256Hash};
use crate::params::{BpqsParams, ParamsL3, ParamsL5, ParamsTestFast};
use crate::sign::{keygen_root, sign_at_height, verify_at_height, BpqsSigner};
use crate::wots;
use sha3::{Digest, Sha3_256};

type H = Sha3_256Hash;

/// A small-tree row sharing the L3 lane width: exercises the N=24 code path
/// at test cost (the canonical L3 row's T_LOG2=16 is ceremony-scale).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ParamsFastL3;

impl BpqsParams for ParamsFastL3 {
    const N: usize = 24;
    const WIN: u32 = 16;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
    const LEN: usize = 51;
    const T_LOG2: usize = 4;
    const NAME: &'static str = "bpqs-fast-l3-test-only";
}

#[test]
fn l3_code_path_roundtrips() {
    let signer = BpqsSigner::<ParamsFastL3, H>::ceremonial_keygen([7u8; 32], EpochWindow(4))
        .unwrap_or_else(|e| panic!("l3 keygen: {e}"));
    let sig = sign_at_height::<H, ParamsFastL3>(&signer, 9, 0, b"anchor")
        .unwrap_or_else(|e| panic!("l3 sign: {e}"));
    verify_at_height::<H, ParamsFastL3>(signer.public(), 9, b"anchor", &sig)
        .unwrap_or_else(|e| panic!("l3 verify: {e}"));
}

#[test]
fn signature_wire_size_matches_the_cost_model() {
    // L5: 4 (epoch) + 67*32 (chains) + 16*32 (path) = 2660 ≈ 2.7 KB.
    let bytes = 4 + ParamsL5::LEN * 32 + ParamsL5::T_LOG2 * 32;
    assert_eq!(bytes, 2660, "L5 wire sketch drifted");
    assert!(bytes < 3200, "research-doc claim: sig stays ≈2.7-3.2 KB");
    let bytes_l3 = 4 + ParamsL3::LEN * 32 + ParamsL3::T_LOG2 * 32;
    assert_eq!(bytes_l3, 2148);
}

#[test]
fn quota_violation_is_epoch_scoped_not_window_scoped() {
    let signer = BpqsSigner::<ParamsTestFast, H>::ceremonial_keygen([1u8; 32], EpochWindow(2))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    // Four mints inside epoch 1 (heights 2,3 share it), then refusal there,
    // then epoch 2 (height 4) signs again: the quota binds the epoch,
    // not the call history.
    for count in 0..4u32 {
        sign_at_height::<H, ParamsTestFast>(&signer, 2, count, b"x")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(matches!(
        sign_at_height::<H, ParamsTestFast>(&signer, 3, 4, b"x"),
        Err(BpqsError::QuotaExceeded { epoch: 1, .. })
    ));
    sign_at_height::<H, ParamsTestFast>(&signer, 4, 0, b"x")
        .unwrap_or_else(|e| panic!("epoch flip must reset the quota view: {e}"));
}

#[test]
fn keygen_root_wrapper_equals_full_signer_public() {
    let a = keygen_root::<H, ParamsTestFast>([5u8; 32], EpochWindow(2))
        .unwrap_or_else(|e| panic!("wrapper keygen: {e}"));
    let b = BpqsSigner::<ParamsTestFast, H>::ceremonial_keygen([5u8; 32], EpochWindow(2))
        .unwrap_or_else(|e| panic!("signer keygen: {e}"));
    assert_eq!(a, b.public().clone());
}

#[test]
fn epoch_chain_derivation_is_message_independent() {
    // Two signatures from the same epoch key have the same Merkle leaf;
    // only the message-bound Winternitz segments differ. This pins the
    // structural claim the few-time relaxation rests on.
    let seed = prf_epoch_seed::<H>(&[3u8; 32], 5);
    let chains = wots::epoch_secret_chains::<H, ParamsTestFast>(&seed);
    let vk = wots::vk_of_chains::<H, ParamsTestFast>(&chains);
    for msg in [&b"one"[..], &b"two"[..]] {
        let bound = Sha3_256Hash::digest32(domains::MESSAGE_BIND, &[msg]);
        let sig = wots::sign_chains::<H, ParamsTestFast>(&chains, &bound);
        let rebuilt = wots::verify_chains::<H, ParamsTestFast>(&sig, &bound);
        assert_eq!(rebuilt, vk, "any message must rebuild the same leaf");
    }
}

/// Machine-lane test: the canonical L5 ceremony (65536 epoch keys, ~minutes
/// in a debug profile). Not part of `cargo test`; run explicitly with
/// `cargo test -p budlum-bpqs --release -- --ignored full_size_ceremony_l5`.
#[test]
#[ignore = "ceremony-scale keygen; run in release on a machine lane"]
fn full_size_ceremony_l5() {
    let signer = BpqsSigner::<ParamsL5, H>::ceremonial_keygen([0xA5u8; 32], EpochWindow(4096))
        .unwrap_or_else(|e| panic!("l5 ceremony: {e}"));
    let sig = sign_at_height::<H, ParamsL5>(&signer, 1_000_000, 0, b"anchor")
        .unwrap_or_else(|e| panic!("l5 sign: {e}"));
    verify_at_height::<H, ParamsL5>(signer.public(), 1_000_000, b"anchor", &sig)
        .unwrap_or_else(|e| panic!("l5 verify: {e}"));
}

/// KAT freeze: sign fixed (seed, window, height, msg) tuples on both fast
/// rows, verify each, then digest the meaningful wire bytes. Frozen on
/// 2026-09-19 with the M1 battery's first green run.
#[test]
fn kat_freeze_digest_is_stable() {
    let mut kat_hasher = Sha3_256::new();
    for (seed_byte, window, height, msg) in [
        (0x01u8, 2u64, 5u64, b"alpha" as &[u8]),
        (0x02, 2, 7, b"beta"),
        (0x03, 4, 9, b"gamma"),
        (0x04, 4, 12, b"delta"),
    ] {
        let seed = [seed_byte; 32];
        let signer = BpqsSigner::<ParamsTestFast, H>::ceremonial_keygen(seed, EpochWindow(window))
            .unwrap_or_else(|e| panic!("kat keygen: {e}"));
        let sig = sign_at_height::<H, ParamsTestFast>(&signer, height, 0, msg)
            .unwrap_or_else(|e| panic!("kat sign: {e}"));
        verify_at_height::<H, ParamsTestFast>(signer.public(), height, msg, &sig)
            .unwrap_or_else(|e| panic!("kat verify: {e}"));
        kat_hasher.update(sig.epoch.to_le_bytes());
        for lane in sig.chains[..ParamsTestFast::LEN].iter() {
            kat_hasher.update(lane);
        }
        for lane in sig.path[..ParamsTestFast::T_LOG2].iter() {
            kat_hasher.update(lane);
        }
        kat_hasher.update(signer.public().root);
        kat_hasher.update([window as u8, height as u8]);
    }
    let l3 = BpqsSigner::<ParamsFastL3, H>::ceremonial_keygen([9u8; 32], EpochWindow(4))
        .unwrap_or_else(|e| panic!("kat l3 keygen: {e}"));
    let sig3 = sign_at_height::<H, ParamsFastL3>(&l3, 10, 0, b"omega")
        .unwrap_or_else(|e| panic!("kat l3 sign: {e}"));
    verify_at_height::<H, ParamsFastL3>(l3.public(), 10, b"omega", &sig3)
        .unwrap_or_else(|e| panic!("kat l3 verify: {e}"));
    kat_hasher.update(l3.public().root);
    kat_hasher.update(sig3.epoch.to_le_bytes());

    let out: [u8; 32] = kat_hasher.finalize().into();
    assert_eq!(
        out, EXPECTED_KAT_DIGEST,
        "KAT freeze drifted - investigate, never update blindly"
    );
}

/// The frozen digest of the KAT battery. Frozen 2026-09-19, commit marking
/// the M1 battery green; an editor who changes it must say why in the commit
/// message (the test prints the live value, so forgery is visible in CI).
const EXPECTED_KAT_DIGEST: [u8; 32] = [
    1, 5, 136, 57, 252, 64, 120, 126, 206, 29, 138, 213, 188, 93, 218, 15, 27, 94, 166, 173, 245,
    185, 163, 141, 44, 24, 241, 74, 252, 246, 158, 105,
];
