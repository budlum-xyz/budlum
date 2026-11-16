//! ML-DSA-87 verification (FIPS 204, algorithms 3 and 8) as `BudISA` code.
//!
//! The arithmetic is over `q = 8380417`. The machine computes in a 64 bit
//! prime field and has no integer division, so every reduction is built
//! from a multiplication, a mask and an exact division by a power of two:
//!
//! * a product by a fixed constant uses the quotient estimate of Shoup:
//!   with `z' = floor(z * 2^34 / q)`, `b * z - floor(b * z' / 2^34) * q`
//!   lies in `[0, 2q)` for every `b` below 2^28;
//! * a general value is folded with `2^23 = 8191 (mod q)` until it is
//!   below `2q`, then one conditional subtraction makes it canonical;
//! * the high bits of `Decompose` come from a Barrett quotient by
//!   `2 * gamma2`.
//!
//! Each of these is stated with its bound where it is emitted; the bounds
//! are what keeps a field operation equal to the integer operation it
//! stands for.
//!
//! A check of the standard that fails stops the run with a failed
//! assertion: the program has no "false" result, it either halts or it
//! does not.

use super::asm::{Asm, Label, Reg, R, ZERO};
use super::keccak::{Domain, Keccak, Rate};

/// The modulus.
pub const Q: u64 = 8_380_417;
const N: u64 = 256;
/// Rows of the matrix.
const K: u64 = 8;
/// Columns of the matrix.
const L: u64 = 7;
/// Dropped bits of `t`.
const D_BITS: u32 = 13;
const GAMMA1: u64 = 1 << 19;
const GAMMA2: u64 = (Q - 1) / 32;
const TAU: u64 = 60;
const BETA: u64 = 120;
const OMEGA: u64 = 75;
/// Bytes of the challenge seed.
const C_TILDE: u64 = 64;
/// Bytes of `rho` in the public key.
const RHO: u64 = 32;
/// Bytes of one packed polynomial of `t1` (10 bits a coefficient).
const T1_POLY: u64 = 320;
/// Bytes of one packed polynomial of `z` (20 bits a coefficient).
const Z_POLY: u64 = 640;

/// Bytes of an ML-DSA-87 public key.
pub const PUBLIC_KEY_BYTES: u64 = RHO + K * T1_POLY;
/// Bytes of an ML-DSA-87 signature.
pub const SIGNATURE_BYTES: u64 = C_TILDE + L * Z_POLY + OMEGA + K;
/// Bytes of `tr` and of `mu`.
pub const DIGEST_BYTES: u64 = 64;
/// Bytes of the packed `w1`: four bits a coefficient.
pub const W1_BYTES: u64 = K * N / 2;

/// A primitive 512th root of unity modulo `q` (FIPS 204, section 2.5).
const ZETA: u64 = 1753;
/// `256^-1 mod q`.
const N_INVERSE: u64 = 8_347_681;
/// `2^23 mod q`.
const FOLD: u64 = (1 << 23) - Q;
const SHOUP_BITS: u32 = 34;
const BARRETT_BITS: u32 = 40;

const fn pow_mod(base: u64, mut exponent: u64) -> u64 {
    let mut base = base % Q;
    let mut result = 1u64;
    while exponent > 0 {
        if exponent % 2 == 1 {
            result = result.saturating_mul(base) % Q;
        }
        base = base.saturating_mul(base) % Q;
        exponent /= 2;
    }
    result
}

/// `zetas[k] = ZETA^BitRev8(k) mod q` (FIPS 204, appendix B).
fn zetas() -> Vec<u64> {
    (0u32..256)
        .map(|k| pow_mod(ZETA, u64::from(k.reverse_bits() >> 24)))
        .collect()
}

/// `floor(z * 2^34 / q)`, the companion of a constant `z < q`.
const fn shoup(z: u64) -> u64 {
    (z << SHOUP_BITS) / Q
}

/// `x -= m` when `x >= m`.
fn conditional_subtract(asm: &mut Asm, x: Reg, m: Reg, t: Reg) {
    asm.gte(t, x, m);
    asm.mul(t, t, m);
    asm.sub(x, x, t);
}

/// Registers the number theoretic transforms keep their constants in.
struct NttRegs {
    q: Reg,
    q2: Reg,
    mask: Reg,
    inverse: Reg,
    zeta: Reg,
    zeta_shoup: Reg,
}

const NTT: NttRegs = NttRegs {
    q: R[20],
    q2: R[21],
    mask: R[22],
    inverse: R[23],
    zeta: R[24],
    zeta_shoup: R[25],
};

impl NttRegs {
    fn emit_constants(&self, asm: &mut Asm) {
        asm.li(self.q, Q);
        asm.li(self.q2, 2 * Q);
        asm.li(self.mask, (1 << SHOUP_BITS) - 1);
        asm.li(self.inverse, 1 << SHOUP_BITS);
        asm.inv(self.inverse, self.inverse);
    }

    fn emit_zeta(&self, asm: &mut Asm, z: u64) {
        asm.li(self.zeta, z);
        asm.li(self.zeta_shoup, shoup(z));
    }

    /// `out = value * zeta mod q`, in `[0, 2q)`, for `value < 2^28`:
    /// `value * zeta' < 2^62` stays below the field modulus and the
    /// quotient estimate is the true quotient or one less.
    fn emit_mul(&self, asm: &mut Asm, out: Reg, value: Reg, t: Reg) {
        asm.mul(t, value, self.zeta_shoup);
        asm.and(out, t, self.mask);
        asm.sub(t, t, out);
        asm.mul(t, t, self.inverse);
        asm.mul(t, t, self.q);
        asm.mul(out, value, self.zeta);
        asm.sub(out, out, t);
    }
}

/// Registers of the folding reduction.
struct FoldRegs {
    mask: Reg,
    power: Reg,
    fold: Reg,
    q: Reg,
}

impl FoldRegs {
    fn emit_constants(&self, asm: &mut Asm) {
        asm.li(self.mask, (1 << 23) - 1);
        asm.li(self.power, 1 << 23);
        asm.li(self.fold, FOLD);
        asm.li(self.q, Q);
    }

    /// Reduce `x <= bound` to `[0, q)`. Each fold writes `x = hi * 2^23 +
    /// lo` as `hi * (2^23 mod q) + lo`, which is congruent and smaller;
    /// the bound is tracked here, and the loop ends once it is below `2q`.
    fn emit_reduce(&self, asm: &mut Asm, x: Reg, bound: u64, t: Reg) {
        let mut bound = bound;
        while bound >= 2 * Q {
            asm.and(t, x, self.mask);
            asm.sub(x, x, t);
            asm.div(x, x, self.power);
            asm.mul(x, x, self.fold);
            asm.add(x, x, t);
            bound = (bound >> 23)
                .saturating_mul(FOLD)
                .saturating_add((1 << 23) - 1);
        }
        conditional_subtract(asm, x, self.q, t);
    }
}

/// The memory and the subroutines of the verifier in one program.
#[derive(Debug, Clone, Copy)]
pub struct MlDsa {
    xof_out: u64,
    xof_in: u64,
    spill: u64,
    signs: u64,
    matrix: u64,
    z: u64,
    t1: u64,
    challenge: u64,
    challenge_in: u64,
    w: u64,
    hints: u64,
    ntt: Label,
    inverse_ntt: Label,
    sample_matrix_entry: Label,
    sample_in_ball: Label,
}

impl MlDsa {
    /// Reserve the memory of the verifier and the labels of its
    /// subroutines. [`Self::emit_subroutines`] must be placed once.
    pub fn new(asm: &mut Asm) -> Self {
        Self {
            xof_out: asm.alloc(Rate::R168.bytes()),
            xof_in: asm.alloc(Rate::R168.bytes()),
            spill: asm.alloc(2),
            signs: asm.alloc(8),
            // One spare cell: a rejected candidate is written before it is
            // known to be rejected.
            matrix: asm.alloc(K * L * N + 1),
            z: asm.alloc(L * N),
            t1: asm.alloc(K * N),
            challenge: asm.alloc(N),
            challenge_in: asm.alloc(C_TILDE + Rate::R136.bytes()),
            w: asm.alloc(K * N),
            hints: asm.alloc(K * N),
            ntt: asm.label(),
            inverse_ntt: asm.label(),
            sample_matrix_entry: asm.label(),
            sample_in_ball: asm.label(),
        }
    }

    /// The verification of FIPS 204, algorithm 8, after `mu`: decode the
    /// key and the signature, rebuild `w1` and compare the challenge.
    ///
    /// `public_key` and `signature` are the byte cells of the inputs, `mu`
    /// the 64 byte cells of the message representative. `w1_out` receives
    /// the 1024 bytes of the packed `w1`; the caller hashes `mu || w1` and
    /// compares the result with the first 64 bytes of the signature.
    pub fn emit_verify_core(
        &self,
        asm: &mut Asm,
        keccak: &Keccak,
        public_key: u64,
        signature: u64,
        w1_out: u64,
    ) {
        asm.region("decode");
        self.emit_decode_t1(asm, public_key.saturating_add(RHO));
        self.emit_decode_z(asm, signature.saturating_add(C_TILDE));
        self.emit_decode_hints(asm, signature.saturating_add(C_TILDE + L * Z_POLY));

        asm.region("expand_a");
        self.emit_expand_matrix(asm, keccak, public_key);

        asm.region("sample_in_ball");
        for at in 0..C_TILDE {
            asm.load_abs(R[1], signature.saturating_add(at));
            asm.store_abs(self.challenge_in.saturating_add(at), R[1]);
        }
        keccak.emit_hash(asm, self.challenge_in, C_TILDE, Rate::R136, Domain::Shake);
        asm.call(self.sample_in_ball);

        asm.region("ntt_calls");
        for j in 0..L {
            asm.li(R[1], Asm::address(self.z.saturating_add(j * N)));
            asm.call(self.ntt);
        }
        asm.li(R[1], Asm::address(self.challenge));
        asm.call(self.ntt);
        for i in 0..K {
            asm.li(R[1], Asm::address(self.t1.saturating_add(i * N)));
            asm.call(self.ntt);
        }

        asm.region("combine");
        for i in 0..K {
            self.emit_combine_row(asm, i);
        }
        asm.region("ntt_calls");
        for i in 0..K {
            asm.li(R[1], Asm::address(self.w.saturating_add(i * N)));
            asm.call(self.inverse_ntt);
        }

        asm.region("use_hint");
        self.emit_use_hint(asm, w1_out);
    }

    /// `t1`: 10 bits a coefficient, four coefficients in five bytes, each
    /// stored as `t1 * 2^13`, which is below `q` (1023 * 8192 = q - 1).
    fn emit_decode_t1(&self, asm: &mut Asm, packed: u64) {
        let (source, target, end) = (R[1], R[2], R[3]);
        asm.li(source, Asm::address(packed));
        asm.li(target, Asm::address(self.t1));
        asm.li(end, Asm::address(packed.saturating_add(K * T1_POLY)));
        let (c3, c4, c15, c16, c63, c64, c256, scale, step_in, step_out) = (
            R[10], R[11], R[12], R[13], R[14], R[15], R[16], R[17], R[18], R[19],
        );
        asm.li(c3, 3);
        asm.li(c4, 4);
        asm.li(c15, 15);
        asm.li(c16, 16);
        asm.li(c63, 63);
        asm.li(c64, 64);
        asm.li(c256, 256);
        asm.li(scale, 1 << D_BITS);
        asm.li(step_in, Asm::address(5));
        asm.li(step_out, Asm::address(4));
        let (b0, b1, b2, b3, b4, t) = (R[4], R[5], R[6], R[7], R[8], R[9]);
        let top = asm.here();
        asm.load(b0, source, 0);
        asm.load(b1, source, 1);
        asm.load(b2, source, 2);
        asm.load(b3, source, 3);
        asm.load(b4, source, 4);
        // c0 = b0 + (b1 & 3) * 256, and b1 becomes b1 >> 2.
        asm.and(t, b1, c3);
        asm.sub(b1, b1, t);
        asm.div(b1, b1, c4);
        asm.mul(t, t, c256);
        asm.add(b0, b0, t);
        // c1 = (b1 >> 2) + (b2 & 15) * 64, and b2 becomes b2 >> 4.
        asm.and(t, b2, c15);
        asm.sub(b2, b2, t);
        asm.div(b2, b2, c16);
        asm.mul(t, t, c64);
        asm.add(b1, b1, t);
        // c2 = (b2 >> 4) + (b3 & 63) * 16, and b3 becomes b3 >> 6.
        asm.and(t, b3, c63);
        asm.sub(b3, b3, t);
        asm.div(b3, b3, c64);
        asm.mul(t, t, c16);
        asm.add(b2, b2, t);
        // c3 = (b3 >> 6) + b4 * 4.
        asm.mul(b4, b4, c4);
        asm.add(b3, b3, b4);
        for (at, coefficient) in (0u64..).zip([b0, b1, b2, b3]) {
            asm.mul(coefficient, coefficient, scale);
            asm.store(target, at, coefficient);
        }
        asm.add(source, source, step_in);
        asm.add(target, target, step_out);
        asm.neq(t, source, end);
        asm.jnz(t, top);
    }

    /// `z`: 20 bits a coefficient, two coefficients in five bytes. A
    /// packed value `v` stands for `gamma1 - v`, so the norm bound
    /// `|z| < gamma1 - beta` is `beta < v < 2 * gamma1 - beta`. The
    /// coefficient is stored modulo `q`.
    fn emit_decode_z(&self, asm: &mut Asm, packed: u64) {
        let (source, target, end) = (R[1], R[2], R[3]);
        asm.li(source, Asm::address(packed));
        asm.li(target, Asm::address(self.z));
        asm.li(end, Asm::address(packed.saturating_add(L * Z_POLY)));
        let (c15, c16, c256, c4096, c65536, low, high, offset, q, step_in, step_out) = (
            R[10], R[11], R[12], R[13], R[14], R[15], R[16], R[17], R[18], R[19], R[20],
        );
        asm.li(c15, 15);
        asm.li(c16, 16);
        asm.li(c256, 256);
        asm.li(c4096, 4096);
        asm.li(c65536, 65536);
        asm.li(low, BETA);
        asm.li(high, 2 * GAMMA1 - BETA);
        asm.li(offset, GAMMA1 + Q);
        asm.li(q, Q);
        asm.li(step_in, Asm::address(5));
        asm.li(step_out, Asm::address(2));
        let (b0, b1, b2, b3, b4, t) = (R[4], R[5], R[6], R[7], R[8], R[9]);
        let top = asm.here();
        asm.load(b0, source, 0);
        asm.load(b1, source, 1);
        asm.load(b2, source, 2);
        asm.load(b3, source, 3);
        asm.load(b4, source, 4);
        // v0 = b0 + b1 * 2^8 + (b2 & 15) * 2^16, and b2 becomes b2 >> 4.
        asm.and(t, b2, c15);
        asm.sub(b2, b2, t);
        asm.div(b2, b2, c16);
        asm.mul(b1, b1, c256);
        asm.add(b0, b0, b1);
        asm.mul(t, t, c65536);
        asm.add(b0, b0, t);
        // v1 = (b2 >> 4) + b3 * 2^4 + b4 * 2^12.
        asm.mul(b3, b3, c16);
        asm.add(b2, b2, b3);
        asm.mul(b4, b4, c4096);
        asm.add(b2, b2, b4);
        for (at, v) in (0u64..).zip([b0, b2]) {
            asm.gt(t, v, low);
            asm.assert(t);
            asm.lt(t, v, high);
            asm.assert(t);
            // gamma1 - v modulo q: gamma1 + q - v is in (0, 2q).
            asm.sub(v, offset, v);
            conditional_subtract(asm, v, q, t);
            asm.store(target, at, v);
        }
        asm.add(source, source, step_in);
        asm.add(target, target, step_out);
        asm.neq(t, source, end);
        asm.jnz(t, top);
    }

    /// The hints (FIPS 204, algorithm 21). `packed` holds `omega` indices
    /// and `k` running totals. A malformed encoding stops the run.
    fn emit_decode_hints(&self, asm: &mut Asm, packed: u64) {
        // Clear the hint vectors.
        let (pointer, end, eight, t) = (R[1], R[2], R[3], R[4]);
        asm.li(pointer, Asm::address(self.hints));
        asm.li(end, Asm::address(self.hints.saturating_add(K * N)));
        asm.li(eight, 8);
        let clear = asm.here();
        asm.store(pointer, 0, ZERO);
        asm.add(pointer, pointer, eight);
        asm.neq(t, pointer, end);
        asm.jnz(t, clear);

        let (index, one, omega, first) = (R[10], R[12], R[13], R[14]);
        let (limit, offset, value, previous) = (R[1], R[4], R[5], R[8]);
        let (a, b) = (R[2], R[6]);
        asm.li(index, 0);
        asm.li(one, 1);
        asm.li(omega, OMEGA);
        for i in 0..K {
            asm.load_abs(limit, packed.saturating_add(OMEGA + i));
            asm.gte(a, limit, index);
            asm.assert(a);
            asm.lte(a, limit, omega);
            asm.assert(a);
            asm.mov(first, index);
            let top = asm.here();
            let done = asm.label();
            asm.gte(a, index, limit);
            asm.jnz(a, done);
            asm.mul(offset, index, eight);
            asm.load(value, offset, packed);
            // Within one polynomial the indices rise strictly.
            let skip = asm.label();
            asm.lte(b, index, first);
            asm.jnz(b, skip);
            asm.load(previous, offset, packed.saturating_sub(1));
            asm.lt(b, previous, value);
            asm.assert(b);
            asm.bind(skip);
            asm.mul(value, value, eight);
            asm.store(value, self.hints.saturating_add(i * N), one);
            asm.add(index, index, one);
            asm.jmp(top);
            asm.bind(done);
        }
        // The unused indices are zero.
        let top = asm.here();
        let done = asm.label();
        asm.gte(a, index, omega);
        asm.jnz(a, done);
        asm.mul(offset, index, eight);
        asm.load(value, offset, packed);
        asm.eq(b, value, ZERO);
        asm.assert(b);
        asm.add(index, index, one);
        asm.jmp(top);
        asm.bind(done);
    }

    /// The matrix (FIPS 204, algorithm 32): entry `(r, s)` is sampled from
    /// SHAKE128 of `rho || s || r`.
    fn emit_expand_matrix(&self, asm: &mut Asm, keccak: &Keccak, rho: u64) {
        for at in 0..RHO {
            asm.load_abs(R[1], rho.saturating_add(at));
            asm.store_abs(self.xof_in.saturating_add(at), R[1]);
        }
        // The padding of the one block: 34 bytes of input, the domain
        // byte, zeros, and the final bit.
        let rate = Rate::R168.bytes();
        for at in (RHO + 2)..rate {
            let byte = if at == RHO + 2 {
                0x1F
            } else if at == rate - 1 {
                0x80
            } else {
                0
            };
            if byte == 0 {
                asm.store_abs(self.xof_in.saturating_add(at), ZERO);
            } else {
                asm.li(R[1], byte);
                asm.store_abs(self.xof_in.saturating_add(at), R[1]);
            }
        }
        for r in 0..K {
            for s in 0..L {
                asm.li(R[1], s);
                asm.store_abs(self.xof_in.saturating_add(RHO), R[1]);
                asm.li(R[1], r);
                asm.store_abs(self.xof_in.saturating_add(RHO + 1), R[1]);
                keccak.clear(asm);
                asm.li(R[1], Asm::address(self.xof_in));
                keccak.absorb(asm, Rate::R168);
                keccak.permute(asm);
                asm.li(
                    R[1],
                    Asm::address(self.matrix.saturating_add((r * L + s) * N)),
                );
                asm.call(self.sample_matrix_entry);
            }
        }
    }

    /// Row `i` of `A * z - c * t1 * 2^d` in the transform domain. The sum
    /// of seven products below `q^2`, plus `q^2`, minus one more product,
    /// is positive and below `8 * q^2 < 2^50`.
    fn emit_combine_row(&self, asm: &mut Asm, row: u64) {
        let fold = FoldRegs {
            mask: R[5],
            power: R[6],
            fold: R[7],
            q: R[8],
        };
        let (index, end, eight, q_squared) = (R[1], R[2], R[3], R[4]);
        asm.li(index, 0);
        asm.li(end, Asm::address(N));
        asm.li(eight, 8);
        asm.li(q_squared, Q * Q);
        fold.emit_constants(asm);
        let (sum, a, b, t) = (R[10], R[11], R[12], R[13]);
        let top = asm.here();
        for column in 0..L {
            asm.load(a, index, self.matrix.saturating_add((row * L + column) * N));
            asm.load(b, index, self.z.saturating_add(column * N));
            if column == 0 {
                asm.mul(sum, a, b);
            } else {
                asm.mul(a, a, b);
                asm.add(sum, sum, a);
            }
        }
        asm.load(a, index, self.challenge);
        asm.load(b, index, self.t1.saturating_add(row * N));
        asm.mul(a, a, b);
        asm.add(sum, sum, q_squared);
        asm.sub(sum, sum, a);
        fold.emit_reduce(asm, sum, 8 * Q * Q, t);
        asm.store(index, self.w.saturating_add(row * N), sum);
        asm.add(index, index, eight);
        asm.neq(t, index, end);
        asm.jnz(t, top);
    }

    /// `UseHint` and the packing of `w1` (FIPS 204, algorithms 36, 40 and
    /// 28), two coefficients to a byte.
    ///
    /// With `r = a * 2 * gamma2 + b`, `0 <= b < 2 * gamma2`: the high bits
    /// are `a` when `b <= gamma2` and `a + 1` otherwise, wrapping from 16
    /// to 0, and the low part is positive exactly when `0 < b <= gamma2`.
    fn emit_use_hint(&self, asm: &mut Asm, out: u64) {
        let divisor = 2 * GAMMA2;
        let (index, end, target, eight) = (R[1], R[2], R[3], R[4]);
        let (estimate, mask, inverse, d, gamma2, c16, c15) =
            (R[5], R[6], R[7], R[8], R[9], R[10], R[11]);
        asm.li(index, 0);
        asm.li(end, Asm::address(K * N));
        asm.li(target, Asm::address(out));
        asm.li(eight, 8);
        asm.li(estimate, (1 << BARRETT_BITS) / divisor);
        asm.li(mask, (1 << BARRETT_BITS) - 1);
        asm.li(inverse, 1 << BARRETT_BITS);
        asm.inv(inverse, inverse);
        asm.li(d, divisor);
        asm.li(gamma2, GAMMA2);
        asm.li(c16, 16);
        asm.li(c15, 15);
        let (r, hint, high, low, t, u, byte) = (R[12], R[13], R[14], R[15], R[16], R[17], R[18]);
        let top = asm.here();
        for half in 0..2u64 {
            asm.load(r, index, self.w.saturating_add(half));
            asm.load(hint, index, self.hints.saturating_add(half));
            // high = floor(r * m / 2^40), the quotient by 2 * gamma2 or
            // one less (r < 2^23, m < 2^22: nothing wraps).
            asm.mul(high, r, estimate);
            asm.and(low, high, mask);
            asm.sub(high, high, low);
            asm.mul(high, high, inverse);
            asm.mul(low, high, d);
            asm.sub(low, r, low);
            asm.gte(t, low, d);
            asm.mul(u, t, d);
            asm.sub(low, low, u);
            asm.add(high, high, t);
            // Round to the nearest multiple: b > gamma2 goes up.
            asm.gt(t, low, gamma2);
            asm.add(high, high, t);
            // positive = (b > 0) and not (b > gamma2).
            asm.gt(u, low, ZERO);
            asm.not(t, t);
            asm.mul(u, u, t);
            // 16 wraps to 0; the low part is then negative, and `u` is
            // already 0 in both ways of getting here.
            asm.eq(t, high, c16);
            asm.mul(t, t, c16);
            asm.sub(high, high, t);
            // w1 = high + hint * (+1 or -1) mod 16.
            asm.mul(u, u, hint);
            asm.add(u, u, u);
            asm.add(high, high, c16);
            asm.sub(high, high, hint);
            asm.add(high, high, u);
            asm.and(high, high, c15);
            if half == 0 {
                asm.mov(byte, high);
            } else {
                asm.mul(high, high, c16);
                asm.add(byte, byte, high);
            }
        }
        asm.store(target, 0, byte);
        asm.add(index, index, c16);
        asm.add(target, target, eight);
        asm.neq(t, index, end);
        asm.jnz(t, top);
    }

    /// Place the subroutines.
    pub fn emit_subroutines(&self, asm: &mut Asm, keccak: &Keccak) {
        asm.region("ntt");
        asm.bind(self.ntt);
        Self::emit_ntt(asm);
        asm.ret();
        asm.bind(self.inverse_ntt);
        Self::emit_inverse_ntt(asm);
        asm.ret();

        asm.region("rej_ntt_poly");
        asm.bind(self.sample_matrix_entry);
        self.emit_sample_matrix_entry(asm, keccak);
        asm.ret();

        asm.region("sample_in_ball");
        asm.bind(self.sample_in_ball);
        self.emit_sample_in_ball(asm, keccak);
        asm.ret();
    }

    /// The forward transform (FIPS 204, algorithm 41) of the polynomial at
    /// the byte address in `R[1]`, in place. Coefficients go in below `2q`
    /// and stay there between layers; they come out canonical.
    fn emit_ntt(asm: &mut Asm) {
        let (pointer, a, b, t, u) = (R[1], R[2], R[3], R[4], R[5]);
        NTT.emit_constants(asm);
        let table = zetas();
        let mut next = table.iter().skip(1);
        let mut len = N / 2;
        while len >= 1 {
            let mut start = 0;
            while start < N {
                let Some(zeta) = next.next() else { return };
                NTT.emit_zeta(asm, *zeta);
                for j in start..start + len {
                    asm.load(a, pointer, j);
                    asm.load(b, pointer, j + len);
                    NTT.emit_mul(asm, t, b, u);
                    // a + t and a + 2q - t are below 4q.
                    asm.add(b, a, NTT.q2);
                    asm.sub(b, b, t);
                    asm.add(a, a, t);
                    conditional_subtract(asm, a, NTT.q2, u);
                    conditional_subtract(asm, b, NTT.q2, u);
                    asm.store(pointer, j, a);
                    asm.store(pointer, j + len, b);
                }
                start += 2 * len;
            }
            len /= 2;
        }
        for j in 0..N {
            asm.load(a, pointer, j);
            conditional_subtract(asm, a, NTT.q, u);
            asm.store(pointer, j, a);
        }
    }

    /// The inverse transform (FIPS 204, algorithm 42), in place, with the
    /// final scaling by `256^-1`. Canonical in, canonical out.
    fn emit_inverse_ntt(asm: &mut Asm) {
        let (pointer, a, b, t, u) = (R[1], R[2], R[3], R[4], R[5]);
        NTT.emit_constants(asm);
        let table = zetas();
        let mut next = table.iter().skip(1).rev();
        let mut len = 1;
        while len < N {
            let mut start = 0;
            while start < N {
                let Some(zeta) = next.next() else { return };
                NTT.emit_zeta(asm, Q - *zeta);
                for j in start..start + len {
                    asm.load(a, pointer, j);
                    asm.load(b, pointer, j + len);
                    // a + 2q - b is in (0, 4q): below 2^28.
                    asm.add(t, a, NTT.q2);
                    asm.sub(t, t, b);
                    asm.add(a, a, b);
                    conditional_subtract(asm, a, NTT.q2, u);
                    asm.store(pointer, j, a);
                    NTT.emit_mul(asm, b, t, u);
                    asm.store(pointer, j + len, b);
                }
                start += 2 * len;
            }
            len *= 2;
        }
        NTT.emit_zeta(asm, N_INVERSE);
        for j in 0..N {
            asm.load(a, pointer, j);
            NTT.emit_mul(asm, b, a, u);
            conditional_subtract(asm, b, NTT.q, u);
            asm.store(pointer, j, b);
        }
    }

    /// `RejNTTPoly` (FIPS 204, algorithm 30). The state holds the first
    /// output block of the XOF; `R[1]` holds the byte address of the 256
    /// coefficients. Three bytes make a 23 bit candidate, kept when it is
    /// below `q`.
    fn emit_sample_matrix_entry(&self, asm: &mut Asm, keccak: &Keccak) {
        let (target, count) = (R[20], R[21]);
        let (c127, c256, c65536, q, eight) = (R[22], R[23], R[24], R[25], R[26]);
        asm.store_abs(self.spill, R[1]);
        asm.store_abs(self.spill.saturating_add(1), ZERO);
        let block = asm.here();
        let done = asm.label();
        asm.li(R[1], Asm::address(self.xof_out));
        keccak.squeeze_block(asm, Rate::R168);
        asm.load_abs(target, self.spill);
        asm.load_abs(count, self.spill.saturating_add(1));
        asm.li(c127, 127);
        asm.li(c256, 256);
        asm.li(c65536, 65536);
        asm.li(q, Q);
        asm.li(eight, 8);
        let (b0, b1, b2, keep, t) = (R[1], R[2], R[3], R[4], R[5]);
        for candidate in 0..Rate::R168.bytes() / 3 {
            let at = self.xof_out.saturating_add(candidate * 3);
            asm.load_abs(b0, at);
            asm.load_abs(b1, at.saturating_add(1));
            asm.load_abs(b2, at.saturating_add(2));
            asm.and(b2, b2, c127);
            asm.mul(b1, b1, c256);
            asm.mul(b2, b2, c65536);
            asm.add(b0, b0, b1);
            asm.add(b0, b0, b2);
            // Written first, kept by moving the pointer on only when the
            // candidate is below q.
            asm.store(target, 0, b0);
            asm.lt(keep, b0, q);
            asm.mul(t, keep, eight);
            asm.add(target, target, t);
            asm.add(count, count, keep);
            asm.eq(t, count, c256);
            asm.jnz(t, done);
        }
        asm.store_abs(self.spill, target);
        asm.store_abs(self.spill.saturating_add(1), count);
        keccak.permute(asm);
        asm.jmp(block);
        asm.bind(done);
    }

    /// `SampleInBall` (FIPS 204, algorithm 29). The state holds the first
    /// output block of SHAKE256 of the challenge seed. Coefficients are
    /// stored modulo `q`: 0, 1 or `q - 1`.
    fn emit_sample_in_ball(&self, asm: &mut Asm, keccak: &Keccak) {
        let rate = Rate::R136.bytes();
        asm.li(R[1], Asm::address(self.xof_out));
        keccak.squeeze_block(asm, Rate::R136);
        // The first eight bytes are the signs; they are kept apart because
        // the output block is reused.
        for at in 0..8 {
            asm.load_abs(R[1], self.xof_out.saturating_add(at));
            asm.store_abs(self.signs.saturating_add(at), R[1]);
        }
        for at in 0..N {
            asm.store_abs(self.challenge.saturating_add(at), ZERO);
        }
        let (pointer, end) = (R[20], R[21]);
        asm.li(pointer, Asm::address(self.xof_out.saturating_add(8)));
        asm.li(end, Asm::address(self.xof_out.saturating_add(rate)));
        let (t, j, eight, bound, offset, moved, sign, constant) =
            (R[1], R[2], R[3], R[4], R[6], R[7], R[8], R[9]);
        for (step, i) in (0u64..).zip(N - TAU..N) {
            let top = asm.here();
            let have = asm.label();
            asm.neq(t, pointer, end);
            asm.jnz(t, have);
            keccak.permute(asm);
            asm.li(R[1], Asm::address(self.xof_out));
            keccak.squeeze_block(asm, Rate::R136);
            asm.li(pointer, Asm::address(self.xof_out));
            asm.li(end, Asm::address(self.xof_out.saturating_add(rate)));
            asm.bind(have);
            asm.load(j, pointer, 0);
            asm.li(eight, 8);
            asm.add(pointer, pointer, eight);
            asm.li(bound, i);
            asm.gt(t, j, bound);
            asm.jnz(t, top);
            // c[i] = c[j]; c[j] = 1 or -1 by sign bit `step`.
            asm.mul(offset, j, eight);
            asm.load(moved, offset, self.challenge);
            asm.store_abs(self.challenge.saturating_add(i), moved);
            asm.load_abs(sign, self.signs.saturating_add(step / 8));
            asm.li(constant, 1 << (step % 8));
            asm.and(sign, sign, constant);
            asm.neq(sign, sign, ZERO);
            asm.li(constant, Q - 2);
            asm.mul(sign, sign, constant);
            asm.li(constant, 1);
            asm.add(sign, sign, constant);
            asm.store(offset, self.challenge, sign);
        }
    }

    /// Call the forward transform on the polynomial at the byte address in
    /// `R[1]`.
    ///
    /// The call is exposed for the tests, which run the transform alone
    /// against the schoolbook product.
    pub fn call_ntt(&self, asm: &mut Asm) {
        asm.call(self.ntt);
    }

    /// Call the inverse transform on the polynomial at the byte address in
    /// `R[1]`.
    ///
    /// The call is exposed for the tests, next to [`Self::call_ntt`].
    pub fn call_inverse_ntt(&self, asm: &mut Asm) {
        asm.call(self.inverse_ntt);
    }
}
