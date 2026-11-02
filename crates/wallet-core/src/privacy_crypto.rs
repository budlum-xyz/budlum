//! Field-native Poseidon helpers matching in-repo `budzero/bud-vm`.
//!
//! MUST stay byte-for-byte aligned with:
//! - `budzero/bud-vm/src/lib.rs` (`poseidon4_hash_state`, `DOMAIN_NULLIFIER`)
//! - `budzero/bud-proof` PrivacyCommit / NullifierCheck AIR
//!
//! Wallet-core intentionally does **not** depend on bud-vm (mobile/WASM
//! Footprint); this is a deliberate duplicated primitive with lock tests.
//! The schedule is the full 30-round one (`R_F = 8`, `R_P = 22`), not the
//! four-round truncation this file used to carry: a wallet primitive that
//! lags the proving system produces commitments no proof can open.

/// Domain separator for nullifier derivation, ASCII "NULLIFER".
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552;

const GOLDILOCKS_P: u64 = 18_446_744_069_414_584_321;

const MDS: [[u64; 8]; 8] = [
    [7, 1, 3, 8, 8, 3, 4, 9],
    [9, 7, 1, 3, 8, 8, 3, 4],
    [4, 9, 7, 1, 3, 8, 8, 3],
    [3, 4, 9, 7, 1, 3, 8, 8],
    [8, 3, 4, 9, 7, 1, 3, 8],
    [8, 8, 3, 4, 9, 7, 1, 3],
    [3, 8, 8, 3, 4, 9, 7, 1],
    [1, 3, 8, 8, 3, 4, 9, 7],
];

/// The 30-round Poseidon1 round constants for Goldilocks width 8, copied
/// from `budzero/bud-vm` (`POSEIDON_RC_FULL`) where the proving system
/// constrains them.
///
/// The first four rows are the ones this file used to carry alone, which is
/// why the truncation looked like a match: `rc_matrix_lock` below pins both
/// the prefix and the last row, so a copy that stops short again fails.
///
/// Round schedule: `R_F = 8` (4 leading + 4 trailing), `R_P = 22` partial
/// rounds that apply the S-box to lane 0 only, `alpha = 7`.
const RC: [[u64; 8]; 30] = [
    // round  0 (full)
    [
        0xdd5743e7f2a5a5d9,
        0xcb3a864e58ada44b,
        0xffa2449ed32f8cdc,
        0x42025f65d6bd13ee,
        0x7889175e25506323,
        0x34b98bb03d24b737,
        0xbdcc535ecc4faa2a,
        0x5b20ad869fc0d033,
    ],
    // round  1 (full)
    [
        0xf1dda5b9259dfcb4,
        0x27515210be112d59,
        0x4227d1718c766c3f,
        0x26d333161a5bd794,
        0x49b938957bf4b026,
        0x4a56b5938b213669,
        0x1120426b48c8353d,
        0x6b323c3f10a56cad,
    ],
    // round  2 (full)
    [
        0xce57d6245ddca6b2,
        0xb1fc8d402bba1eb1,
        0xb5c5096ca959bd04,
        0x6db55cd306d31f7f,
        0xc49d293a81cb9641,
        0x1ce55a4fe979719f,
        0xa92e60a9d178a4d1,
        0x002cc64973bcfd8c,
    ],
    // round  3 (full)
    [
        0xcea721cce82fb11b,
        0xe5b55eb8098ece81,
        0x4e30525c6f1ddd66,
        0x43c6702827070987,
        0xaca68430a7b5762a,
        0x3674238634df9c93,
        0x88cee1c825e33433,
        0xde99ae8d74b57176,
    ],
    // round  4 (partial)
    [
        0x488897d85ff51f56,
        0x1140737ccb162218,
        0xa7eeb9215866ed35,
        0x9bd2976fee49fcc9,
        0xc0c8f0de580a3fcc,
        0x4fb2dae6ee8fc793,
        0x343a89f35f37395b,
        0x223b525a77ca72c8,
    ],
    // round  5 (partial)
    [
        0x56ccb62574aaa918,
        0xc4d507d8027af9ed,
        0xa080673cf0b7e95c,
        0xf0184884eb70dcf8,
        0x044f10b0cb3d5c69,
        0xe9e3f7993938f186,
        0x1b761c80e772f459,
        0x606cec607a1b5fac,
    ],
    // round  6 (partial)
    [
        0x14a0c2e1d45f03cd,
        0x4eace8855398574f,
        0xf905ca7103eff3e6,
        0xf8c8f8d20862c059,
        0xb524fe8bdd678e5a,
        0xfbb7865901a1ec41,
        0x014ef1197d341346,
        0x9725e20825d07394,
    ],
    // round  7 (partial)
    [
        0xfdb25aef2c5bae3b,
        0xbe5402dc598c971e,
        0x93a5711f04cdca3d,
        0xc45a9a5b2f8fb97b,
        0xfe8946a924933545,
        0x2af997a27369091c,
        0xaa62c88e0b294011,
        0x058eb9d810ce9f74,
    ],
    // round  8 (partial)
    [
        0xb3cb23eced349ae4,
        0xa3648177a77b4a84,
        0x43153d905992d95d,
        0xf4e2a97cda44aa4b,
        0x5baa2702b908682f,
        0x082923bdf4f750d1,
        0x98ae09a325893803,
        0xf8a6475077968838,
    ],
    // round  9 (partial)
    [
        0xceb0735bf00b2c5f,
        0x0a1a5d953888e072,
        0x2fcb190489f94475,
        0xb5be06270dec69fc,
        0x739cb934b09acf8b,
        0x537750b75ec7f25b,
        0xe9dd318bae1f3961,
        0xf7462137299efe1a,
    ],
    // round 10 (partial)
    [
        0xb1f6b8eee9adb940,
        0xbdebcc8a809dfe6b,
        0x40fc1f791b178113,
        0x3ac1c3362d014864,
        0x9a016184bdb8aeba,
        0x95f2394459fbc25e,
        0xe3f34a07a76a66c2,
        0x8df25f9ad98b1b96,
    ],
    // round 11 (partial)
    [
        0x85ffc27171439d9d,
        0xddcb9a2dcfd26910,
        0x26b5ba4bf3afb94e,
        0xffff9cc7c7651e2f,
        0x8c88364698280b55,
        0xebc114167b910501,
        0x2d77b4d89ecfb516,
        0x332e0828eba151f2,
    ],
    // round 12 (partial)
    [
        0x46fa6a6450dd4735,
        0xd00db7dd92384a33,
        0x5fd4fb751f3a5fc5,
        0x496fb90c0bb65ea2,
        0xf3baec0bb87cc5c7,
        0x862a3c0a7d4c7713,
        0xbf5f38336a3f47d8,
        0x41ad9dbc1394a20c,
    ],
    // round 13 (partial)
    [
        0xcc535945b7dbf0f7,
        0x82af2bc93685bcec,
        0x8e4c8d0c8cebfccd,
        0x17cb39417e84597e,
        0xd4a965a8c749b232,
        0xa2cab040f33f3ee5,
        0xa98811a1fed4e3a6,
        0x1cc48b54f377e2a1,
    ],
    // round 14 (partial)
    [
        0xe40cd4f6c5609a27,
        0x11de79ebca97a4a4,
        0x9177c73d8b7e929d,
        0x2a6fe8085797e792,
        0x3de6e93329f8d5ae,
        0x3f7af9125da962ff,
        0xd710682cfc77d3ac,
        0x48faf05f3b053cf4,
    ],
    // round 15 (partial)
    [
        0x287db8630da89c8b,
        0x4d0de32053cb30e9,
        0x8b37a4f20c5ada7b,
        0xe7cc6ebe78c84ecf,
        0x240bdc0a66a2610d,
        0x8299e7f02caa1650,
        0x380a53fefb6e754e,
        0x684a1d8cf8eb6810,
    ],
    // round 16 (partial)
    [
        0xe839452eb4b8a5e1,
        0xb03fa62e90626af4,
        0x11a688602fbc5efc,
        0x30dda75c355a2d62,
        0x0f712adcb73810de,
        0xffdc1102187f1ae1,
        0x40c34f398254b99c,
        0xede021b9dc289a4a,
    ],
    // round 17 (partial)
    [
        0x8b7b05225c4e7dad,
        0x3bc794346f9d9ff9,
        0xfccb5a57f2ca86ff,
        0xbb1502015a7da9d4,
        0xd7e0a35d4352a015,
        0x27af7a44f8160931,
        0xc37442f6782f4615,
        0xbdf392a9bd095dcb,
    ],
    // round 18 (partial)
    [
        0xc17f55037cf00de9,
        0xbcffedd34c71a874,
        0x5eb45d2a8133d1f2,
        0xbabe251e1612ebdf,
        0x3efeb9fbe438c536,
        0x2d7cef97b4afe1cf,
        0xe5de1b4660016c0b,
        0xcdcc26c332f5657c,
    ],
    // round 19 (partial)
    [
        0xe01dd653daf15809,
        0xb0a6bdd4b41094b5,
        0x27eac858b0b03a05,
        0x51d43b5e93adbdc0,
        0x8b89a23b0fea5fc9,
        0xdc8ac3b14f7f2fc1,
        0xe793f82f1efec039,
        0x9f6f2cf8969e7b80,
    ],
    // round 20 (partial)
    [
        0x49d45382e0f21d4a,
        0x5f4ad1797cd72786,
        0x4dc3dbebfd45f795,
        0x03a3ef84dba6e1bc,
        0x204bc9b3d3fc4c01,
        0x9ad706081e89b9ba,
        0x638bfb4d840e9f89,
        0x5ef2938cd095ae35,
    ],
    // round 21 (partial)
    [
        0x42cca18ebeb265c8,
        0xb7b2ec5c29aecbf8,
        0x0d84f9535dc78f0f,
        0x04e64ad942e77b8c,
        0xb4880dffffc9da0b,
        0x16db16d9c29adeb1,
        0x09bbaf2a0590cd1e,
        0x76460e74961fcf8d,
    ],
    // round 22 (partial)
    [
        0xed12a2276dfa1553,
        0x0b5acec5de0436fd,
        0x3c6cfea033a1f0a8,
        0x2b5ecefe546cac15,
        0x6e2d82884cd3bf6f,
        0xc134878d1add7b83,
        0x997963422eb7a280,
        0x5e834537ac648cf6,
    ],
    // round 23 (partial)
    [
        0x89e779214737c0b7,
        0x1a8c05e8581ad95b,
        0x8d18b72796437cf7,
        0xe7252c949e04b106,
        0x53267c4fd174585a,
        0xa16ef5d9c81dad47,
        0xda65191937270a46,
        0xcb2a5b55f2df664c,
    ],
    // round 24 (partial)
    [
        0x854aee2dc1924137,
        0xf37013c9d479ece6,
        0x0e163bc0630c4696,
        0x384ee64955048f76,
        0xf65d814e28ee4ec5,
        0xe57bc564fd82f1b1,
        0x4b338937b6876614,
        0x66ee0b04ed43cd8d,
    ],
    // round 25 (partial)
    [
        0x49884bf25f4ef15d,
        0xeb51fe28de1c6f54,
        0x2cd64e84fce8dfcc,
        0x29164a96a541a013,
        0x173ce7558f4cacb8,
        0xeb5b1ce5877c89e9,
        0x5faff4b0f5217bf6,
        0xac42d0b1c20f205e,
    ],
    // round 26 (full)
    [
        0xfb1d6bf0ca43221b,
        0x97b0a1b01d6a2955,
        0x08c60bd622952b30,
        0x43f2be0f9e24147c,
        0xfa7268b7d3730f5d,
        0x43a6c419a23983bb,
        0xcd77c1f7b29b113c,
        0xcfa43c9db8eec29f,
    ],
    // round 27 (full)
    [
        0xcaaa95a6c7365dec,
        0x0a91193f798f3be0,
        0x1104497652735dc6,
        0x35aecb93663b515e,
        0x8dbc9916065aa858,
        0xada8f7a0266579ed,
        0x524dee7bec1ea789,
        0xa93aee9dd5af9521,
    ],
    // round 28 (full)
    [
        0x9d1f1b54750d707e,
        0x7c9feab87096d5dc,
        0xa2e1fb19f9d4261b,
        0xb714deb448de6346,
        0x225d1f0d011c5403,
        0x1549b7f1d28cedc0,
        0xaef3e46f97d43942,
        0x6dfc7ffe0b38bf08,
    ],
    // round 29 (full)
    [
        0x7de853fdc542b663,
        0xa68ecc96610657b2,
        0xe88bb5428af289b1,
        0xd7cfa1504c5569f5,
        0x78a9aad0d642d30a,
        0xd68315f2353dce52,
        0x46e56300f86fcfd5,
        0x323d95332b145fd6,
    ],
];

/// Full rounds of the instance: four leading and four trailing.
const FULL_ROUNDS: usize = 8;

/// The 30-round Poseidon1 permutation over Goldilocks (alpha=7, width=8),
/// the same function `budzero/bud-vm` runs and `budzero/bud-proof`
/// constrains.
///
/// It keeps its historical name so call sites do not churn, but it is **not**
/// a four-round truncation any more, and it must not become one again: a
/// wallet that computed a four-round commitment while the chain proved the
/// thirty-round one would produce notes and nullifiers the chain never
/// recorded, which is the drift `poseidon4_hash3_canonical_output_lock` below
/// is pinned against.
#[must_use]
pub fn poseidon4_hash_state(mut s: [u64; 8]) -> u64 {
    const P: u64 = GOLDILOCKS_P;
    let sbox = |x: u64| -> u64 {
        let x2 = ((x as u128 * x as u128) % P as u128) as u64;
        let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
        (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
    };
    let half_full = FULL_ROUNDS / 2;
    for (round, round_rc) in RC.iter().enumerate() {
        for i in 0..8 {
            s[i] = ((s[i] as u128 + round_rc[i] as u128) % P as u128) as u64;
        }
        // Full rounds apply the S-box to every lane; partial rounds only to
        // lane 0. That asymmetry is the whole point of the partial rounds -
        // they raise the algebraic degree cheaply - so a copy that skipped it
        // would compute a different function under the same name.
        if round < half_full || round >= RC.len() - half_full {
            for lane in s.iter_mut() {
                *lane = sbox(*lane);
            }
        } else {
            s[0] = sbox(s[0]);
        }
        let mut next = [0u64; 8];
        for i in 0..8 {
            let mut sum: u128 = 0;
            for j in 0..8 {
                sum = (sum + MDS[i][j] as u128 * s[j] as u128) % P as u128;
            }
            next[i] = sum as u64;
        }
        s = next;
    }
    s[0]
}

#[must_use]
pub fn poseidon4_hash(a: u64, b: u64) -> u64 {
    poseidon4_hash_state([a, b, 0, 0, 0, 0, 0, 0])
}

/// PrivacyCommit absorption: Poseidon3(amount, recipient, blinding).
#[must_use]
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    poseidon4_hash_state([a, b, c, 0, 0, 0, 0, 0])
}

/// Commitment = Poseidon3(amount, recipient_tag, blinding)
#[must_use]
/// Parameter order matches VM PrivacyCommit opcode:
/// `poseidon4_hash3(amount, blinding, recipient_tag)`. Blinding is full u64
/// From register (no u32 truncation). Recipient tag from imm field (i32).
pub fn privacy_commit(amount: u64, blinding: u64, recipient_tag: u64) -> u64 {
    poseidon4_hash3(amount, blinding, recipient_tag)
}

/// Nullifier = Poseidon2(secret, DOMAIN_NULLIFIER)
#[must_use]
pub fn privacy_nullifier(secret: u64) -> u64 {
    poseidon4_hash(secret, DOMAIN_NULLIFIER)
}

// Packing is `budlum-note-packing`'s single definition, re-exported under the
// names the wallet already used. The chain indexes commitments and nullifiers
// by exactly these bytes, so the wallet must not hold its own copy of the
// rule: a one-byte divergence produces a nullifier the chain never recorded,
// and the spend it was meant to prevent goes through.
pub use budlum_note_packing::{field_from_hash, hash_from_field, is_packed};

/// Map a 32-byte Budlum address into a Goldilocks field tag (first 8 LE bytes
/// Reduced mod P). Used as PrivacyCommit recipient limb when full address
/// Does not fit in one field element.
#[must_use]
pub fn address_to_recipient_tag(addr: &[u8; 32]) -> u64 {
    // Destructured rather than sliced-and-`try_into`-ed. Both express "take
    // the first eight bytes", but slicing leaves a panic branch that the
    // compiler cannot see is dead, so the honest `.expect()` on it is a claim
    // a reader has to verify. A pattern on a fixed-size array is checked when
    // the crate is built: there is no branch left to reason about.
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = *addr;
    let raw = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
    // BLG-0282 (P17-F16, accepted with documentation): `%` is not a
    // constant-time modular reduction and this fold consumes secret note
    // material. Accepted because wallet-core is unwired to any network or
    // consensus path (the node's own fold lives in bud-state, matching this
    // one byte-for-byte), so there is no remote observer to time against.
    // A constant-time rewrite happens in BOTH places together, if this ever
    // joins a hot path - changing one alone would split the two folds,
    // which is the worse bug.
    raw % GOLDILOCKS_P
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_nullifier_constant_matches_spec() {
        assert_eq!(DOMAIN_NULLIFIER, 0x4e55_4c4c_4946_4552);
    }

    #[test]
    fn poseidon_two_vs_three_absorb_differ() {
        let a = poseidon4_hash(1, 2);
        let b = poseidon4_hash3(1, 2, 0);
        // State [1,2,0,...] vs [1,2,0,...] - hash3 with c=0 equals hash2
        assert_eq!(a, b);
        assert_ne!(poseidon4_hash3(1, 2, 3), a);
    }

    #[test]
    fn commit_nullifier_roundtrip_shapes() {
        let c = privacy_commit(100, 99, 7); // S1: (amount, blinding, recipient_tag)
        let n = privacy_nullifier(0xA11CE);
        assert_ne!(c, 0);
        assert_ne!(n, 0);
        assert_eq!(field_from_hash(&hash_from_field(c)), c);
    }
}

/// Element-wise Poseidon constants lock test.
/// Ensures wallet-core MDS/RC match bud-vm/src/lib.rs exactly.
/// If someone changes constants in one file but not the other,
/// This test catches the desync before it breaks all privacy proofs.
#[cfg(test)]
mod poseidon_lock_tests {
    use super::*;

    #[test]
    fn mds_matrix_lock() {
        assert_eq!(
            MDS[0],
            [7, 1, 3, 8, 8, 3, 4, 9],
            "MDS row 0 mismatch with bud-vm"
        );
        assert_eq!(
            MDS[7],
            [1, 3, 8, 8, 3, 4, 9, 7],
            "MDS row 7 mismatch with bud-vm"
        );
        assert_eq!(
            MDS[5],
            [8, 8, 3, 4, 9, 7, 1, 3],
            "MDS row 5 mismatch with bud-vm"
        );
    }

    #[test]
    fn rc_matrix_lock() {
        // The table used to hold four rows, which is what made the truncation
        // invisible here: every pinned row matched. The count and the last row
        // are pinned so a copy that stops short fails instead.
        assert_eq!(RC.len(), FULL_ROUNDS + 22, "schedule must be 30 rounds");
        assert_eq!(
            RC[0][0], 0xdd5743e7f2a5a5d9,
            "RC[0][0] mismatch with bud-vm"
        );
        assert_eq!(
            RC[0][1], 0xcb3a864e58ada44b,
            "RC[0][1] mismatch with bud-vm"
        );
        assert_eq!(
            RC[3][0], 0xcea721cce82fb11b,
            "RC[3][0] mismatch with bud-vm"
        );
        assert_eq!(
            RC[29][7], 0x323d_9533_2b14_5fd6,
            "the last round of the schedule must match bud-vm"
        );
    }

    #[test]
    fn poseidon4_hash3_canonical_output_lock() {
        let h = poseidon4_hash3(1, 2, 3);
        assert_ne!(h, 0, "hash must be non-zero");
        // Lock: these exact outputs were computed from the bud-vm constants
        // and the 30-round schedule (`R_F = 8`, `R_P = 22`). The previous
        // values here were the four-round outputs, so this test used to pin
        // the drift instead of catching it.
        assert_eq!(h, 8_772_090_386_064_251_099, "hash3 must match bud-vm");
        assert_eq!(
            poseidon4_hash(1, 2),
            10_612_780_834_355_398_184,
            "hash2 must match bud-vm"
        );
    }

    /// The partial rounds are what make this the full instance: if the copy
    /// ever runs the S-box on every lane for all rounds, the schedule is a
    /// different function even with the same constants.
    #[test]
    fn partial_rounds_are_partial() {
        let all_full: u64 = {
            // Same constants, every round full, kept local so the assertion
            // says something about the shipped function rather than about a
            // second copy in the crate.
            const P: u64 = GOLDILOCKS_P;
            let sbox = |x: u64| -> u64 {
                let x2 = ((x as u128 * x as u128) % P as u128) as u64;
                let x4 = ((x2 as u128 * x2 as u128) % P as u128) as u64;
                (((x4 as u128 * x2 as u128) % P as u128 * x as u128) % P as u128) as u64
            };
            let mut s = [1u64, 2, 3, 0, 0, 0, 0, 0];
            for round_rc in RC.iter() {
                for i in 0..8 {
                    s[i] = ((s[i] as u128 + round_rc[i] as u128) % P as u128) as u64;
                }
                for lane in s.iter_mut() {
                    *lane = sbox(*lane);
                }
                let mut next = [0u64; 8];
                for i in 0..8 {
                    let mut sum: u128 = 0;
                    for j in 0..8 {
                        sum = (sum + MDS[i][j] as u128 * s[j] as u128) % P as u128;
                    }
                    next[i] = sum as u64;
                }
                s = next;
            }
            s[0]
        };
        assert_ne!(
            poseidon4_hash3(1, 2, 3),
            all_full,
            "the shipped permutation must use partial rounds"
        );
    }
}
