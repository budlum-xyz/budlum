//! Canonical hash backend: Poseidon2 over Goldilocks, width 16 (the "p3
//! parameters" named in the 2026-09-19 decision record). This module is a
//! straightline, allocation-free port of the reference permutation so the
//! auditor reads one file instead of a dependency stack.
//!
//! ## Provenance (auditors: verify these three anchors)
//!
//! 1. Construction: Poseidon2, eprint 2023/323. Parameters for this
//!    instance: field = Goldilocks (p = 2^64 - 2^32 + 1), state width
//!    t = 16, S-box x^7, R_F = 8 full rounds (4 initial + 4 terminal),
//!    R_P = 22 partial rounds (128-bit margin per the paper's script).
//! 2. Round constants + internal diagonal: Plonky3/Plonky3
//!    `goldilocks/src/poseidon2.rs`, Grain LFSR seed parameters
//!    `field_type=1, alpha=7, n=64, t=16, R_F=8, R_P=22`
//!    (`generate_constants.py --field goldilocks --width 16`).
//! 3. Cross-check: the unit test below carries the upstream width-16
//!    known-answer vector verbatim; if this port ever drifts from the p3
//!    arithmetic the constant pin fails loudly.
//!
//! ## Byte binding (BPQS-POSEIDON2-SPONGE-v0): hash, not raw permutation
//!
//! [`super::hash::BpqsHash`] speaks bytes. The binding from the canonical
//! framing bytes (see `hash.rs`) to the sponge:
//!
//! - chunk the framing as little-endian 4-byte groups; each u32 maps to one
//!   field element. u32 < p always, so the encoding is *injective* - no mod
//!   reduction ever touches input entropy (the bar-1 argument leans on this).
//! - absorb into a 16-element state with rate 8 / capacity 8 using the
//!   overwrite sponge (state[i] = block[i]); element padding appends a single
//!   `1` element, then zeros to the next rate boundary; permute once per
//!   block.
//! - squeeze the first 4 state elements as canonical little-endian u64s,
//!   giving exactly 32 bytes. Capacity is 8 x 64 = 512 bits, so the sponge
//!   budget exceeds the 256-bit output by a factor of two on both axes.
//!
//! ## Field arithmetic: constant time, not `%`
//!
//! `fe_add`/`fe_mul` originally read `(a as u128 OP b as u128) % p`. That is
//! the clearest possible spelling and it was the wrong one here. On 64-bit
//! targets a `u128 % u128` does not lower to an instruction: rustc emits a
//! call to compiler-rt `__umodti3`, a software division whose iteration count
//! depends on the operand bits. The permutation is fed by secret material on
//! the BPQS signing path, so the division's data-dependent timing is a
//! candidate leak - named in the 2026-09-23 constant-time review as the only
//! outstanding one in this module.
//!
//! Both are now division-free and route every secret-fed conditional
//! correction through `cmov`: `fe_add` is one wrapping add plus a conditional
//! move-backed subtract, and `fe_mul` reduces the 128-bit product with the
//! Goldilocks identities 2^64 == 2^32 - 1 and 2^96 == -1 (mod p). This
//! deliberately avoids raw bool-derived masked selects, which LLVM has been
//! observed lowering back into short data-dependent branches. The values are
//! unchanged - `fe_matches_modular_reference` pins the new path against the
//! old `%` formula over boundary and random inputs, and the upstream
//! known-answer vector below is the second, independent anchor.
//!
//! Clarity still belongs to the audit, which is why the reduction carries its
//! derivation above the code rather than a reference to it.

// initial external round constants, 4 vectors x 16 lanes
const RC_EXT_INIT: [[u64; 16]; 4] = [
    [
        0x15ebea3fc73397c3,
        0xd73cd9fbfe8e275c,
        0x8c096bfce77f6c26,
        0x4e128f68b53d8fea,
        0x29b779a36b2763f6,
        0xfe2adc6fb65acd08,
        0x8d2520e725ad0955,
        0x1c2392b214624d2a,
        0x37482118206dcc6e,
        0x2f829bed19be019a,
        0x2fe298cb6f8159b0,
        0x2bbad982deccdbbf,
        0xbad568b8cc60a81e,
        0xb86a814265baad10,
        0xbec2005513b3acb3,
        0x6bf89b59a07c2a94,
    ],
    [
        0xa25deeb835e230f5,
        0x3c5bad8512b8b12a,
        0x7230f73c3cb7a4f2,
        0xa70c87f095c74d0f,
        0x6b7606b830bb2e80,
        0x6cd467cfc4f24274,
        0xfeed794df42a9b0a,
        0x8cf7cf6163b7dbd3,
        0x9a6e9dda597175a0,
        0xaa52295a684faf7b,
        0x017b811cc3589d8d,
        0x55bfb699b6181648,
        0xc2ccaf71501c2421,
        0x1707950327596402,
        0xdd2fcdcd42a8229f,
        0x8b9d7d5b27778a21,
    ],
    [
        0xac9a05525f9cf512,
        0x2ba125c58627b5e8,
        0xc74e91250a8147a5,
        0xa3e64b640d5bb384,
        0xf53047d18d1f9292,
        0xbaaeddacae3a6374,
        0xf2d0914a808b3db1,
        0x18af1a3742bfa3b0,
        0x9a621ef50c55bdb8,
        0xc615f4d1cc5466f3,
        0xb7fbac19a35cf793,
        0xd2b1a15ba517e46d,
        0x4a290c4d7fd26f6f,
        0x4f0cf1bb1770c4c4,
        0x548345386cd377f5,
        0x33978d2789fddd42,
    ],
    [
        0xab78c59deb77e211,
        0xc485b2a933d2be7f,
        0xbde3792c00c03c53,
        0xab4cefe8f893d247,
        0xc5c0e752eab7f85f,
        0xdbf5a76f893bafea,
        0xa91f6003e3d984de,
        0x099539077f311e87,
        0x097ec52232f9559e,
        0x53641bdf8991e48c,
        0x2afe9711d5ed9d7c,
        0xa7b13d3661b5d117,
        0x5a0e243fe7af6556,
        0x1076fae8932d5f00,
        0x9b53a83d434934e3,
        0xed3fd595a3c0344a,
    ],
];

// terminal external round constants, 4 vectors x 16 lanes
const RC_EXT_FIN: [[u64; 16]; 4] = [
    [
        0xdacf46dc1c31a045,
        0x5d2e3c121eb387f2,
        0x51f8b0658b124499,
        0x1e7dbd1daa72167d,
        0x8275015a25c55b88,
        0xe8521c24ac7a70b3,
        0x6521d121c40b3f67,
        0xac12de797de135b0,
        0xafa28ead79f6ed6a,
        0x685174a7a8d26f0b,
        0xeff92a08d35d9874,
        0x3058734b76dd123a,
        0xfa55dcfba429f79c,
        0x559294d4324c7728,
        0x7a770f53012dc178,
        0xedd8f7c408f3883b,
    ],
    [
        0x39b533cf8d795fa5,
        0x160ef9de243a8c0a,
        0x431d52da6215fe3f,
        0x54c51a2a2ef6d528,
        0x9b13892b46ff9d16,
        0x263c46fcee210289,
        0xb738c96d25aabdc4,
        0x5c33a5203996d38f,
        0x2626496e7c98d8dd,
        0xc669e0a52785903a,
        0xaecde726c8ae1f47,
        0x039343ef3a81e999,
        0x2615ceaf044a54f9,
        0x7e41e834662b66e1,
        0x4ca5fd4895335783,
        0x64b334d02916f2b0,
    ],
    [
        0x87268837389a6981,
        0x034b75bcb20a6274,
        0x58e658296cc2cd6e,
        0xe2d0f759acc31df4,
        0x81a652e435093e20,
        0x0b72b6e0172eaf47,
        0x4aec43cec577d66d,
        0xde78365b028a84e6,
        0x444e19569adc0ee4,
        0x942b2451fa40d1da,
        0xe24506623ea5bd6c,
        0x082854bf2ef7c743,
        0x69dbbc566f59d62e,
        0x248c38d02a7b5cb2,
        0x4f4e8f8c09d15edb,
        0xd96682f188d310cf,
    ],
    [
        0x6f9a25d56818b54c,
        0xb6cefed606546cd9,
        0x5bc07523da38a67b,
        0x7df5a3c35b8111cf,
        0xaaa2cc5d4db34bb0,
        0x9e673ff22a4653f8,
        0xbd8b278d60739c62,
        0xe10d20f6925b8815,
        0xf6c87b91dd4da2bf,
        0xfed623e2f71b6f1a,
        0xa0f02fa52a94d0d3,
        0xbb5794711b39fa16,
        0xd3b94fba9d005c7f,
        0x15a26e89fad946c9,
        0xf3cb87db8a67cf49,
        0x400d2bf56aa2a577,
    ],
];

// internal round constants, lane 0 only
const RC_INTERNAL: [u64; 22] = [
    0x28eff4b01103d100,
    0x60400ca3e2685a45,
    0x1c8636beb3389b84,
    0xac1332b60e13eff0,
    0x2adafcc364e20f87,
    0x79ffc2b14054ea0b,
    0x3f98e4c0908f0a05,
    0xcdb230bc4e8a06c4,
    0x1bcaf7705b152a74,
    0xd9bca249a82a7470,
    0x91e24af19bf82551,
    0xa62b43ba5cb78858,
    0xb4898117472e797f,
    0xb3228bca606cdaa0,
    0x844461051bca39c9,
    0xf3411581f6617d68,
    0xf7fd50646782b533,
    0x6ca664253c18fb48,
    0x2d2fcdec0886a08f,
    0x29da00dd799b575e,
    0x47d966cc3b6e1e93,
    0xde884e9a17ced59e,
];

// internal diffusion diagonal, state[i] = state[i]*DIAG[i] + sum(state)
const DIAG: [u64; 16] = [
    0xfffffffeffffffff,
    0x0000000000000001,
    0x0000000000000002,
    0x7fffffff80000001,
    0x0000000000000003,
    0x0000000000000004,
    0x7fffffff80000000,
    0xfffffffefffffffe,
    0xfffffffefffffffd,
    0xdfffffff20000001,
    0xefffffff10000001,
    0xf7ffffff08000001,
    0x1fffffffe0000000,
    0x0ffffffff0000000,
    0x07fffffff8000000,
    0xfffffffe00000002,
];

/// Goldilocks field order: p = 2^64 - 2^32 + 1.
pub const GOLDILOCKS_P: u64 = 0xffff_ffff_0000_0001;

/// Sponge rate (state elements) for the byte binding.
const RATE: usize = 8;
/// State width of the permutation (paper parameter t).
pub const WIDTH: usize = 16;

use cmov::Cmov;

/// Conditional move on `u64` with a bool-shaped condition.
///
/// The `cmov` crate takes a `u8` condition specifically so the compiler does
/// not get to re-interpret a masked select as an ordinary boolean branch. On
/// x86/x86_64 this lowers through the CMOV instruction family; on aarch64 it
/// lowers through CSEL; other targets use the crate's documented best-effort
/// fallback.
#[inline]
fn cmov_if(mut keep: u64, replace: u64, condition: bool) -> u64 {
    keep.cmovnz(&replace, u8::from(condition));
    keep
}

/// Conditional subtract of `p`: returns `x - p` when `x >= p`, otherwise `x`.
#[inline]
fn fe_sub_p(x: u64) -> u64 {
    let (diff, borrow) = x.overflowing_sub(GOLDILOCKS_P);
    // borrow == true  <=>  x < p  =>  keep x
    // borrow == false <=>  x >= p =>  keep diff
    cmov_if(x, diff, !borrow)
}

#[inline]
fn fe_add(a: u64, b: u64) -> u64 {
    // Inputs are canonical (< p), so a + b < 2p < 2^65: at most one fold, and
    // the 65th bit is the add's own carry-out.
    let (sum, carry) = a.overflowing_add(b);
    let (diff, borrow) = sum.overflowing_sub(GOLDILOCKS_P);
    // Fold when the true sum reached 2^64 (carry) or when the truncated sum is
    // already >= p (no borrow). The OR stays at the bool level; `cmov_if`
    // widens it only as the u8 condition expected by the conditional-move
    // backend.
    let fold = carry | !borrow;
    cmov_if(sum, diff, fold)
}

/// Goldilocks reduction of a 128-bit product, using p = 2^64 - 2^32 + 1, i.e.
/// 2^64 == 2^32 - 1 (mod p) and 2^96 == -1 (mod p).
///
/// Splitting `x = x_lo + 2^64 * (x_hi_lo + 2^32 * x_hi_hi)`:
///   2^64 * x_hi_lo == (2^32 - 1) * x_hi_lo, and
///   2^96 * x_hi_hi == -x_hi_hi.
/// The folds below implement exactly that, with the borrow/carry corrections
/// applied as arithmetic rather than as branches.
#[inline]
fn fe_reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & 0xFFFF_FFFF;

    // x_lo - x_hi_hi  (the 2^96 == -1 fold); a borrow costs another 2^32 - 1.
    let (t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    let t0 = cmov_if(t0, t0.wrapping_sub(0xFFFF_FFFF), borrow);

    // + x_hi_lo * (2^32 - 1)  (the 2^64 == 2^32 - 1 fold).
    let t1 = x_hi_lo.wrapping_mul(0xFFFF_FFFF);
    let (t2, carry) = t0.overflowing_add(t1);
    let t2 = cmov_if(t2, t2.wrapping_add(0xFFFF_FFFF), carry);

    // t2 < 2p at this point (pinned by `reduce128_output_stays_below_2p`), so
    // a single conditional subtract canonicalises it.
    fe_sub_p(t2)
}

#[inline]
fn fe_mul(a: u64, b: u64) -> u64 {
    fe_reduce128(u128::from(a) * u128::from(b))
}

/// S-box x^7 (three multiplications).
#[inline]
fn fe_pow7(x: u64) -> u64 {
    let x2 = fe_mul(x, x);
    let x4 = fe_mul(x2, x2);
    fe_mul(fe_mul(x4, x2), x)
}

/// The 4x4 MDS block, matrix [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
/// evaluated with p3's addition-only schedule.
#[inline]
fn apply_mat4(x: &mut [u64; WIDTH], base: usize) {
    let x0 = x[base];
    let x1 = x[base + 1];
    let x2 = x[base + 2];
    let x3 = x[base + 3];
    let t01 = fe_add(x0, x1);
    let t23 = fe_add(x2, x3);
    let t0123 = fe_add(t01, t23);
    let t01123 = fe_add(t0123, x1);
    let t01233 = fe_add(t0123, x3);
    // Order matters: x3 and x1 are written before x0 and x2 are consumed.
    x[base + 3] = fe_add(t01233, fe_add(x0, x0));
    x[base + 1] = fe_add(t01123, fe_add(x2, x2));
    x[base] = fe_add(t01123, t01);
    x[base + 2] = fe_add(t01233, t23);
}

/// External linear layer: M4 per 4-block, then the circulant sums pass.
fn m_external(state: &mut [u64; WIDTH]) {
    apply_mat4(state, 0);
    apply_mat4(state, 4);
    apply_mat4(state, 8);
    apply_mat4(state, 12);
    let mut sums = [0u64; 4];
    for j in 0..4 {
        for k in 0..4 {
            sums[k] = fe_add(sums[k], state[4 * j + k]);
        }
    }
    for (i, elem) in state.iter_mut().enumerate() {
        *elem = fe_add(*elem, sums[i % 4]);
    }
}

/// Internal linear layer: state[i] = state[i] * DIAG[i] + sum(state).
fn m_internal(state: &mut [u64; WIDTH]) {
    let mut sum = 0u64;
    for elem in state.iter() {
        sum = fe_add(sum, *elem);
    }
    for (i, elem) in state.iter_mut().enumerate() {
        *elem = fe_add(fe_mul(*elem, DIAG[i]), sum);
    }
}

/// The full Poseidon2 permutation on one 16-element Goldilocks state.
///
/// Initial external layer, 4+(4) full rounds around 22 partial rounds;
/// matches Plonky3 `default_goldilocks_poseidon2_16` step for step.
pub fn permute16(state: &mut [u64; WIDTH]) {
    m_external(state);
    for rc in RC_EXT_INIT.iter() {
        for (i, elem) in state.iter_mut().enumerate() {
            *elem = fe_pow7(fe_add(*elem, rc[i]));
        }
        m_external(state);
    }
    for rc in RC_INTERNAL.iter() {
        state[0] = fe_pow7(fe_add(state[0], *rc));
        m_internal(state);
    }
    for rc in RC_EXT_FIN.iter() {
        for (i, elem) in state.iter_mut().enumerate() {
            *elem = fe_pow7(fe_add(*elem, rc[i]));
        }
        m_external(state);
    }
}

/// Hash the canonical framing bytes with the BPQS-POSEIDON2-SPONGE-v0
/// binding documented in the module header.
fn sponge_digest(frame: &[u8]) -> [u8; 32] {
    let mut elems = alloc::vec::Vec::with_capacity(frame.len() / 4 + 2);
    for chunk in frame.chunks(4) {
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        elems.push(u64::from(u32::from_le_bytes(buf)));
    }
    elems.push(1); // element-level 10* padding: one 1, then implicit zeros
    let mut state = [0u64; WIDTH];
    for block in elems.chunks(RATE) {
        state[..RATE].fill(0);
        state[..block.len()].copy_from_slice(block);
        permute16(&mut state);
    }
    let mut out = [0u8; 32];
    for (i, elem) in state[..4].iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&elem.to_le_bytes());
    }
    out
}

/// The canonical backend of the research line: Poseidon2-Goldilocks-16
/// behind the [`super::hash::BpqsHash`] seam. The 2026-09-19 decision made
/// this the primary; SHA3-256 and SHAKE-256 stay as the audit cross-checks.
pub struct Poseidon2GoldilocksHash;

impl super::hash::BpqsHash for Poseidon2GoldilocksHash {
    fn digest32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        sponge_digest(&super::hash::frame_bytes(domain, parts))
    }
}

#[cfg(test)]
mod poseidon2_tests {
    use super::*;
    use crate::hash::BpqsHash;

    #[test]
    fn p3_width16_known_answer_vector() {
        // Verbatim from Plonky3 `test_default_goldilocks_poseidon2_width_16`.
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
        permute16(&mut state);
        assert_eq!(state, expected, "p3-port drift: permutation diverged");
    }

    /// The reference the constant-time path replaced. Kept here, in the test
    /// module only, so the equivalence claim is checked against the actual
    /// prior formula rather than against a restatement of it.
    fn ref_add(a: u64, b: u64) -> u64 {
        ((u128::from(a) + u128::from(b)) % u128::from(GOLDILOCKS_P)) as u64
    }

    fn ref_mul(a: u64, b: u64) -> u64 {
        ((u128::from(a) * u128::from(b)) % u128::from(GOLDILOCKS_P)) as u64
    }

    /// A small deterministic PRNG: the crate is `no_std` on the hash path and
    /// a test must not be the reason a dev-dependency enters the tree.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Boundary values where a fold, a borrow or a carry is actually
    /// exercised. `0xffff_ffff_0000_0000` and `0xffff_fffe_ffff_ffff` are in
    /// this list because an earlier draft of `fe_reduce128` returned
    /// `p + 2` and `p + 5` for their squares: the reduction leaves a result
    /// below 2p, not below p, and dropping the final conditional subtract
    /// produced a NON-CANONICAL element that still satisfied every
    /// `x == y (mod p)` style assertion. The KAT caught it; so does this.
    const EDGES: [u64; 11] = [
        0,
        1,
        2,
        GOLDILOCKS_P - 1,
        GOLDILOCKS_P - 2,
        (GOLDILOCKS_P - 1) / 2,
        0xFFFF_FFFF,
        0x1_0000_0000,
        0xFFFF_FFFF_0000_0000,
        0xFFFF_FFFE_FFFF_FFFF,
        u64::MAX % GOLDILOCKS_P,
    ];

    #[test]
    fn fe_matches_modular_reference() {
        for &a in &EDGES {
            for &b in &EDGES {
                assert_eq!(fe_add(a, b), ref_add(a, b), "fe_add({a:#x}, {b:#x})");
                assert_eq!(fe_mul(a, b), ref_mul(a, b), "fe_mul({a:#x}, {b:#x})");
            }
        }

        let mut seed = 0x2026_0923_B9F5_u64 | 1;
        for _ in 0..20_000 {
            let a = xorshift(&mut seed) % GOLDILOCKS_P;
            let b = xorshift(&mut seed) % GOLDILOCKS_P;
            assert_eq!(fe_add(a, b), ref_add(a, b), "fe_add({a:#x}, {b:#x})");
            assert_eq!(fe_mul(a, b), ref_mul(a, b), "fe_mul({a:#x}, {b:#x})");
        }
    }

    #[test]
    fn fe_output_is_always_canonical() {
        // Not the same claim as the one above: two values can be congruent
        // mod p and still differ as u64, and the sponge squeezes elements as
        // raw little-endian bytes. A non-canonical element would change the
        // digest without changing the field value.
        let mut seed = 0x0BAD_C0DE_1234_5678_u64;
        for &a in &EDGES {
            for &b in &EDGES {
                assert!(fe_add(a, b) < GOLDILOCKS_P);
                assert!(fe_mul(a, b) < GOLDILOCKS_P);
            }
        }
        for _ in 0..20_000 {
            let a = xorshift(&mut seed) % GOLDILOCKS_P;
            let b = xorshift(&mut seed) % GOLDILOCKS_P;
            assert!(
                fe_add(a, b) < GOLDILOCKS_P,
                "fe_add left {a:#x}+{b:#x} >= p"
            );
            assert!(
                fe_mul(a, b) < GOLDILOCKS_P,
                "fe_mul left {a:#x}*{b:#x} >= p"
            );
        }
    }

    #[test]
    fn reduce128_output_stays_below_2p() {
        // The single conditional subtract in `fe_reduce128` is only sufficient
        // because the folded value is < 2p. That is a precondition of the
        // algorithm, so it is measured rather than asserted in a comment.
        fn folded_before_final_subtract(x: u128) -> u64 {
            let x_lo = x as u64;
            let x_hi = (x >> 64) as u64;
            let (t0, borrow) = x_lo.overflowing_sub(x_hi >> 32);
            let t0 = cmov_if(t0, t0.wrapping_sub(0xFFFF_FFFF), borrow);
            let t1 = (x_hi & 0xFFFF_FFFF).wrapping_mul(0xFFFF_FFFF);
            let (t2, carry) = t0.overflowing_add(t1);
            cmov_if(t2, t2.wrapping_add(0xFFFF_FFFF), carry)
        }
        let two_p = u128::from(GOLDILOCKS_P) * 2;
        let mut seed = 0x5EED_5EED_5EED_5EED_u64;
        for &a in &EDGES {
            for &b in &EDGES {
                let t = folded_before_final_subtract(u128::from(a) * u128::from(b));
                assert!(
                    u128::from(t) < two_p,
                    "fold of {a:#x}*{b:#x} reached {t:#x}"
                );
            }
        }
        for _ in 0..20_000 {
            let a = xorshift(&mut seed) % GOLDILOCKS_P;
            let b = xorshift(&mut seed) % GOLDILOCKS_P;
            let t = folded_before_final_subtract(u128::from(a) * u128::from(b));
            assert!(
                u128::from(t) < two_p,
                "fold of {a:#x}*{b:#x} reached {t:#x}"
            );
        }
    }

    #[test]
    fn fe_sub_p_selects_correctly_at_boundaries() {
        assert_eq!(fe_sub_p(0), 0);
        assert_eq!(fe_sub_p(GOLDILOCKS_P - 1), GOLDILOCKS_P - 1);
        assert_eq!(fe_sub_p(GOLDILOCKS_P), 0);
        assert_eq!(fe_sub_p(GOLDILOCKS_P + 1), 1);
        assert_eq!(fe_sub_p(u64::MAX), u64::MAX - GOLDILOCKS_P);
    }

    #[test]
    fn field_arithmetic_mod_boundaries() {
        assert_eq!(fe_add(GOLDILOCKS_P - 1, 1), 0, "p-1 + 1 == 0 mod p");
        assert_eq!(fe_add(GOLDILOCKS_P - 1, GOLDILOCKS_P - 1), GOLDILOCKS_P - 2);
        assert_eq!(fe_mul(GOLDILOCKS_P - 1, GOLDILOCKS_P - 1), 1, "(-1)^2 == 1");
        // p = 2^64 - 2^32 + 1  =>  2^64 == 2^32 - 1 (mod p).
        assert_eq!(
            fe_mul(0x1_0000_0000, 0x1_0000_0000),
            0xffff_ffff,
            "2^64 == 2^32 - 1 mod p"
        );
        assert_eq!(fe_pow7(0), 0);
        assert_eq!(fe_pow7(1), 1);
        assert_eq!(fe_pow7(2), 128);
    }

    #[test]
    fn tail_padding_ambiguity_is_killed_by_frame_lengths() {
        // Honest accounting for the bar-1 write-up: at the raw sponge level
        // the final 4-byte chunk is right-padded with element zeros, so
        // b"\xab" and b"\xab\0\0\0" would map to the *same* element stream.
        // That ambiguity cannot occur in the construction because every part
        // enters the sponge through `frame_bytes`, whose u32le length
        // prefixes differ for parts of different length. This test pins that
        // the frame path separates exactly those cases.
        let a = Poseidon2GoldilocksHash::digest32(b"D", &[&[0xab]]);
        let b = Poseidon2GoldilocksHash::digest32(b"D", &[&[0xab, 0x00]]);
        let c = Poseidon2GoldilocksHash::digest32(b"D", &[&[0xab, 0x00, 0x00]]);
        let d = Poseidon2GoldilocksHash::digest32(b"D", &[&[0xab, 0x00, 0x00, 0x00]]);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(c, d);
        // Four zero bytes pad exactly one chunk: b"\xab\0\0\0\0" (u32 0xab) vs
        // b"\xab" embedded in a longer frame still disagree via the prefix.
        // And a direct sponge-level sanity check that the module's own
        // documentation describes this boundary truthfully:
        assert_eq!(
            sponge_digest(&[0xab]),
            sponge_digest(&[0xab, 0x00, 0x00, 0x00])
        );
    }

    #[test]
    fn hash_face_matches_sha3_contract() {
        let a = Poseidon2GoldilocksHash::digest32(b"DOM-A", &[b"payload"]);
        let b = Poseidon2GoldilocksHash::digest32(b"DOM-B", &[b"payload"]);
        assert_ne!(a, b, "domain separation must hold under Poseidon too");
        let x = Poseidon2GoldilocksHash::digest32(b"D", &[b"ab", b"c"]);
        let y = Poseidon2GoldilocksHash::digest32(b"D", &[b"a", b"bc"]);
        assert_ne!(x, y, "part boundaries must be visible");
        // Same framing, different backend: digests must differ (the two
        // families share zero structure).
        assert_ne!(
            a,
            crate::hash::Sha3_256Hash::digest32(b"DOM-A", &[b"payload"]),
        );
    }
}
