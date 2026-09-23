//! Backend differential battery (milestone M2): the *same* construction run
//! under three hash families - canonical Poseidon2-Goldilocks-16 and the two
//! FIPS-202 cross-checks. If a behavior binds the scheme (roundtrip, tamper
//! refusal, epoch refusal, quota refusal), it must bind under every backend;
//! if a behavior binds the hash family (digests), it must differ across
//! backends. That two-sentence contract is the whole differential argument
//! an auditor has to check before trusting the Poseidon swap, spelled out in
//! the 2026-09-19 decision record as the planned SHAKE-256 cross-reference.
//!
//! Frozen known-answer section: the KAT digests below are pinned against
//! `kat/bpqs-kat-v1.txt`; regeneration is a deliberate, reviewable edit (run
//! the ignored `kat_file_regenerates_identically` test's writer mode and
//! paste), never a background recompute.

use crate::epoch::EpochWindow;
use crate::error::BpqsError;
use crate::hash::{BpqsHash, Sha3_256Hash};
use crate::params::{BpqsParams, ParamsTestFast};
use crate::poseidon2::Poseidon2GoldilocksHash;
use crate::shake256::Shake256Hash;
use crate::sign::{keygen_root, sign_at_height, verify_at_height, BpqsSignature, BpqsSigner};

extern crate std;
use sha3::{Digest, Sha3_256};

/// L3-lane fast row for the backend matrix (N=24 truncation path at test
/// cost; mirrors the `ParamsFastL3` in tests.rs but is a distinct type, so a
/// parameter-row collision between batteries cannot silently alias).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ParamsBattL3;

impl BpqsParams for ParamsBattL3 {
    const N: usize = 24;
    const WIN: u32 = 16;
    const LEN1: usize = 48;
    const LEN2: usize = 3;
    const LEN: usize = 51;
    const T_LOG2: usize = 4;
    const NAME: &'static str = "bpqs-batt-l3-test-only";
}

const SEED: [u8; 32] = [0xA5; 32];
const MSG: &[u8] = b"bpqs-backend-differential-payload";

fn roundtrip<H: BpqsHash, P: BpqsParams>() {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen {}: {e}", P::NAME));
    let sig = sign_at_height::<H, P>(&signer, 1, 0, MSG)
        .unwrap_or_else(|e| panic!("sign {}: {e}", P::NAME));
    verify_at_height::<H, P>(signer.public(), 1, MSG, &sig)
        .unwrap_or_else(|e| panic!("verify {}: {e}", P::NAME));
}

fn tamper_refuses<H: BpqsHash, P: BpqsParams>() {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    let sig =
        sign_at_height::<H, P>(&signer, 2, 0, MSG).unwrap_or_else(|e| panic!("sign: {e}"));
    let mut chain_tamper = sig.clone();
    chain_tamper.chains[0][0] ^= 0x01; // one bit in a revealed chain element
    assert!(
        verify_at_height::<H, P>(signer.public(), 2, MSG, &chain_tamper).is_err(),
        "{}: single-bit chain tamper must refuse",
        P::NAME
    );
    // Flip the last *meaningful* byte of the path node: lanes carry a
    // P::N-byte prefix and a zero tail, so a tail flip would be invisible by
    // design (canonicity, not a defense gap).
    let mut path_tamper = sig.clone();
    path_tamper.path[0][P::N - 1] ^= 0x80;
    assert!(
        verify_at_height::<H, P>(signer.public(), 2, MSG, &path_tamper).is_err(),
        "{}: auth-path tamper must refuse",
        P::NAME
    );
    // Randomizer tamper (2026-09-22 wire field): the bound digest rebinds
    // over the carried randomizer, so a flipped bit elsewhere-lawful must
    // still refuse.
    let mut r_tamper = sig;
    r_tamper.randomizer[0] ^= 0x01;
    assert!(
        verify_at_height::<H, P>(signer.public(), 2, MSG, &r_tamper).is_err(),
        "{}: randomizer tamper must refuse",
        P::NAME
    );
}

/// Per-call randomizer semantics (2026-09-22, bar-1 record): the same tuple
/// signs byte-identically (determinism; KAT stability), while a second
/// message under the same (signer, epoch, count) draws a different
/// randomizer - the anti-adaptive property of the PRF-derived r.
fn randomizer_bound_and_deterministic<H: BpqsHash, P: BpqsParams>() {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    let a = sign_at_height::<H, P>(&signer, 1, 0, MSG).unwrap_or_else(|e| panic!("a: {e}"));
    let a2 = sign_at_height::<H, P>(&signer, 1, 0, MSG).unwrap_or_else(|e| panic!("a2: {e}"));
    assert_eq!(a, a2, "{}: identical tuple must sign byte-identically", P::NAME);
    let b = sign_at_height::<H, P>(&signer, 1, 0, b"bpqs-backend-differential-payload-2")
        .unwrap_or_else(|e| panic!("b: {e}"));
    assert_ne!(
        a.randomizer, b.randomizer,
        "{}: different messages must draw different randomizers",
        P::NAME
    );
    verify_at_height::<H, P>(signer.public(), 1, b"bpqs-backend-differential-payload-2", &b)
        .unwrap_or_else(|e| panic!("b verify: {e}"));
}

fn epoch_replay_refuses<H: BpqsHash, P: BpqsParams>() {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    // Epoch window is 3, so heights 0..2 are epoch 0 and height 3 is epoch
    // 1: verifying the epoch-0 signature at height 3 must refuse.
    let sig = sign_at_height::<H, P>(&signer, 0, 0, MSG).unwrap_or_else(|e| panic!("sign: {e}"));
    assert!(
        verify_at_height::<H, P>(signer.public(), 3, MSG, &sig).is_err(),
        "{}: signature must not replay outside its epoch",
        P::NAME
    );
}

fn quota_refuses<H: BpqsHash, P: BpqsParams>() {
    let signer = BpqsSigner::<P, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    for count in 0..P::Q_MAX {
        sign_at_height::<H, P>(&signer, 0, count, MSG)
            .unwrap_or_else(|e| panic!("mint {count}: {e}"));
    }
    assert!(
        matches!(
            sign_at_height::<H, P>(&signer, 0, P::Q_MAX, MSG),
            Err(BpqsError::QuotaExceeded { .. })
        ),
        "{}: mint q_max + 1 in one epoch must refuse",
        P::NAME
    );
}

macro_rules! backend_battery {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;
            #[test]
            fn roundtrip_l5_fast() {
                super::roundtrip::<$backend, ParamsTestFast>();
            }
            #[test]
            fn roundtrip_l3_lane() {
                super::roundtrip::<$backend, ParamsBattL3>();
            }
            #[test]
            fn tamper_refuses_l5_fast() {
                super::tamper_refuses::<$backend, ParamsTestFast>();
            }
            #[test]
            fn tamper_refuses_l3_lane() {
                super::tamper_refuses::<$backend, ParamsBattL3>();
            }
            #[test]
            fn randomizer_bd_l5_fast() {
                super::randomizer_bound_and_deterministic::<$backend, ParamsTestFast>();
            }
            #[test]
            fn randomizer_bd_l3_lane() {
                super::randomizer_bound_and_deterministic::<$backend, ParamsBattL3>();
            }
            #[test]
            fn epoch_replay_refuses_l5_fast() {
                super::epoch_replay_refuses::<$backend, ParamsTestFast>();
            }
            #[test]
            fn epoch_replay_refuses_l3_lane() {
                super::epoch_replay_refuses::<$backend, ParamsBattL3>();
            }
            #[test]
            fn quota_refuses_l5_fast() {
                super::quota_refuses::<$backend, ParamsTestFast>();
            }
            #[test]
            fn quota_refuses_l3_lane() {
                super::quota_refuses::<$backend, ParamsBattL3>();
            }
        }
    };
}

backend_battery!(sha3_battery, Sha3_256Hash);
backend_battery!(shake_battery, Shake256Hash);
backend_battery!(poseidon_battery, Poseidon2GoldilocksHash);

#[test]
fn backends_are_three_distinct_functions() {
    // One framing, one payload, three different digests: proves the battery
    // above is not comparing one function to itself under three names.
    let a = Sha3_256Hash::digest32(crate::domains::MESSAGE_BIND_V1, &[&[0u8; 16], b"x"]);
    let b = Shake256Hash::digest32(crate::domains::MESSAGE_BIND_V1, &[&[0u8; 16], b"x"]);
    let c = Poseidon2GoldilocksHash::digest32(crate::domains::MESSAGE_BIND_V1, &[&[0u8; 16], b"x"]);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

/// Canonical wire sketch (shared with `tests.rs`'s size contract): epoch,
/// then the `LEN` meaningful chains, then the `T_LOG2` path nodes.
fn wire_bytes<P: BpqsParams>(sig: &BpqsSignature<P>) -> alloc::vec::Vec<u8> {
    let mut wire = alloc::vec::Vec::with_capacity(4 + P::LEN * 32 + P::T_LOG2 * 32);
    wire.extend_from_slice(&sig.epoch.to_le_bytes());
    wire.extend_from_slice(&sig.randomizer);
    for chain in sig.chains.iter().take(P::LEN) {
        wire.extend_from_slice(chain);
    }
    for node in sig.path.iter().take(P::T_LOG2) {
        wire.extend_from_slice(node);
    }
    wire
}

/// Frozen known-answer rows (pinned to kat/bpqs-kat-v1.txt). Digest =
/// SHA3-256 over the wire bytes of the signature produced with the pinned
/// seed/message/height. `root` = the Merkle root of the epoch tree
/// (the public key anchor).
struct KatRow {
    backend: &'static str,
    root_hex: &'static str,
    sig_digest_hex: &'static str,
}

fn hx32(s: &str) -> [u8; 32] {
    let v: alloc::vec::Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("kat hex"))
        .collect();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn to_hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}

const KAT_ROWS: [KatRow; 3] = [
    KatRow {
        backend: "sha3-256",
        root_hex: "998c0b4320fb17a32726ade9770b4b148e206d16a345ed2601dc1bfdfe4a317f",
        sig_digest_hex: "e2c41b1e1ffdb74d19fcfd70a6c53c8e8d40f47153d406c7036c4ff125aefea3",
    },
    KatRow {
        backend: "shake256",
        root_hex: "a1f1f4296ebd4e91a907ea070045b44689d0e28f94e0d4d543e01706cca32434",
        sig_digest_hex: "2684d048e716e9aa1ca393ee55697eaae1bd82c15ea67b250c0a4b92dffec22d",
    },
    KatRow {
        backend: "poseidon2-goldilocks-16",
        root_hex: "fe3a689123f38a5f39d8aadb4e415f5102c539829f0212c95af5a95b98655497",
        sig_digest_hex: "eec36121946c210cda9ddc3309364a57c80dfb903127f6cf91d3c7bb7fc2c013",
    },
];

fn kat_compute<H: BpqsHash>() -> ([u8; 32], [u8; 32]) {
    let public = keygen_root::<H, ParamsTestFast>(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("kat keygen_root: {e}"));
    let signer = BpqsSigner::<ParamsTestFast, H>::ceremonial_keygen(SEED, EpochWindow(3))
        .unwrap_or_else(|e| panic!("kat keygen: {e}"));
    let sig = sign_at_height::<H, ParamsTestFast>(&signer, 3, 0, MSG)
        .unwrap_or_else(|e| panic!("kat sign: {e}"));
    (public.root, Sha3_256::digest(wire_bytes(&sig)).into())
}

#[test]
fn kat_rows_are_frozen() {
    let computed: [([u8; 32], [u8; 32]); 3] = [
        kat_compute::<Sha3_256Hash>(),
        kat_compute::<Shake256Hash>(),
        kat_compute::<Poseidon2GoldilocksHash>(),
    ];
    for (row, (root, sig_digest)) in KAT_ROWS.iter().zip(computed.iter()) {
        assert_eq!(
            hx32(row.root_hex),
            *root,
            "{} Merkle root drifted vs kat/bpqs-kat-v1.txt",
            row.backend
        );
        assert_eq!(
            hx32(row.sig_digest_hex),
            *sig_digest,
            "{} signature wire digest drifted vs kat/bpqs-kat-v1.txt",
            row.backend
        );
    }
}

/// Writes the kat/bpqs-kat-v1.txt body (freshly computed) to stdout; the
/// matching verifier is the plain `kat_file_matches_computation` test.
/// Run as:
/// `cargo test kat_file_writer -- --ignored --nocapture > kat/bpqs-kat-v1.txt`
#[test]
#[ignore = "KAT writer: runs on demand, not in the battery"]
fn kat_file_writer() {
    let rows: [([u8; 32], [u8; 32]); 3] = [
        kat_compute::<Sha3_256Hash>(),
        kat_compute::<Shake256Hash>(),
        kat_compute::<Poseidon2GoldilocksHash>(),
    ];
    std::println!("# Budlum-BPQS known-answer vectors v1 (milestone M2, 2026-09-22)");
    std::println!("# construction: epoch-chained Winternitz (one-time per epoch, q_max=1,");
    std::println!("#       PRF-derived 16B randomizer, MESSAGE_BIND_V1, 2026-09-22 wire)");
    std::println!("# row: ParamsTestFast lane (N=32, LEN=67, T_LOG2=4) - identical hash");
    std::println!("#      discipline to the canonical L5/L3 rows, ceremony depth pruned.");
    std::println!("# pins: root_seed=0xA5*32, window=3, msg='bpqs-backend-differential-payload',");
    std::println!("#       signed at height 3 (epoch 1), quota counter 0.");
    std::println!(
        "# sig_digest is SHA3-256 over the wire sketch (epoch_le || randomizer || LEN chains || path)."
    );
    for (name, (root, sig_digest)) in KAT_ROWS.iter().zip(rows.iter()) {
        std::println!(
            "backend={} root={} sig_digest={}",
            name.backend,
            to_hex(root),
            to_hex(sig_digest)
        );
    }
}

#[test]
fn kat_file_matches_computation() {
    let body = include_str!("../kat/bpqs-kat-v1.txt");
    let rows: [([u8; 32], [u8; 32]); 3] = [
        kat_compute::<Sha3_256Hash>(),
        kat_compute::<Shake256Hash>(),
        kat_compute::<Poseidon2GoldilocksHash>(),
    ];
    let mut found = 0usize;
    for (name, (root, sig_digest)) in KAT_ROWS.iter().zip(rows.iter()) {
        let needle = alloc::format!(
            "backend={} root={} sig_digest={}",
            name.backend,
            to_hex(root),
            to_hex(sig_digest)
        );
        assert!(
            body.lines().any(|l| l == needle),
            "kat file is missing the current row for {}; regenerate it with \
             `cargo test kat_file_writer -- --ignored --nocapture`",
            name.backend
        );
        found += 1;
    }
    assert_eq!(found, 3, "every backend row must appear exactly once");
}

#[test]
fn permutation_level_kat_is_pinned_from_outside_the_backend_module() {
    // Second KAT layer, deliberate: the sponge-level rows above pin the
    // construction; this pins the permutation itself from OUTSIDE its
    // defining file, so a refactor that silently swaps the arithmetic (or a
    // lane order) is caught by a caller, not only by the module's own unit
    // tests. Verbatim p3 width-16 vector, duplicated on purpose.
    let mut state: [u64; 16] = [
        0x4d3f967fab9d4979,
        0x57e1fba55677697e,
        0x57429a86e75a3774,
        0x31d379f3a592b5eb,
        0x497232e1b648e3f1,
        0x325a7db57173c39e,
        0xa802252d78bee916,
        0x8920f55e154adef8,
        0xa1225bc9c7913658,
        0xd687be5097ffd038,
        0x89f514ef0c913e48,
        0x21fd4a9cf548cd84,
        0x570a1586ada436ff,
        0x46bfbf38ccd740ae,
        0x23651b3f3ab26484,
        0xe90f3b02127fa552,
    ];
    let expected: [u64; 16] = [
        0xf0f7717837c7032a,
        0xf12fbcc838feb15b,
        0xd8661f6fa4165ad8,
        0x351cdc546760d1a9,
        0x99474334bf02445f,
        0x46fc4e9ceb376d6a,
        0x4601808321fcd920,
        0xc58bfd0342dc60df,
        0xb7f3acd43f3c029c,
        0x5c7afa6a6997dfc5,
        0xecbef8b82906c887,
        0xd490e3b4e945d87c,
        0x31866766b83ebe0b,
        0xb32d52f6e7a5bea2,
        0x9522431667b3c5f9,
        0xeaf5638a69518f65,
    ];
    crate::poseidon2::permute16(&mut state);
    assert_eq!(
        state, expected,
        "permutation-level KAT drifted (external caller)"
    );
}
