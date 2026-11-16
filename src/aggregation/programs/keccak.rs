//! Keccak-f[1600] and the sponge, as `BudISA` code.
//!
//! The machine has field arithmetic and a bitwise AND, no XOR, no shift and
//! no rotation. A lane of the state is kept as two 32 bit limbs, low limb
//! first, and the three missing operations are built from what is there:
//!
//! * `a ^ b = a + b - 2 * (a & b)`: four instructions, exact for limbs
//!   below 2^32 because nothing wraps the field;
//! * `!b & c = c - (b & c)`;
//! * a rotation splits each limb at a bit with a mask and an exact
//!   division by a power of two, and joins the pieces again.
//!
//! Byte strings live in memory one byte per cell. [`Keccak::absorb`] packs
//! four of them into a limb and [`emit_squeeze`] splits a limb back into
//! four bytes, so every value the sponge hands out is a byte by
//! construction.
//!
//! Every subroutine here may change registers 1 to 29. A caller that needs
//! a value across a call keeps it in memory.

use super::asm::{Asm, Label, Reg, R, ZERO};

/// The round constants of Keccak-f[1600] (FIPS 202, section 3.2.5).
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rotation of lane `(x, y)`, indexed `x + 5 * y` (FIPS 202, table 2).
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Limbs of the state: 25 lanes of two limbs.
const STATE_LIMBS: u64 = 50;
const LIMB_BITS: u32 = 32;

/// The rate of a sponge, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rate {
    /// 136 bytes: SHAKE256, SHA3-256 and Keccak-256.
    R136,
    /// 168 bytes: SHAKE128.
    R168,
}

impl Rate {
    /// The rate in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::R136 => 136,
            Self::R168 => 168,
        }
    }

    const fn limbs(self) -> u64 {
        self.bytes() / 4
    }
}

/// The domain byte a sponge pads with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// SHAKE128 and SHAKE256.
    Shake,
    /// SHA3-256.
    Sha3,
    /// Keccak-256, the hash of the claim layer.
    Keccak,
}

impl Domain {
    const fn byte(self) -> u64 {
        match self {
            Self::Shake => 0x1F,
            Self::Sha3 => 0x06,
            Self::Keccak => 0x01,
        }
    }
}

/// The memory and the subroutines of the sponge in one program.
#[derive(Debug, Clone, Copy)]
pub struct Keccak {
    state: u64,
    scratch: u64,
    constants: u64,
    permute: Label,
    clear: Label,
    absorb_136: Label,
    absorb_168: Label,
    squeeze_136: Label,
    squeeze_168: Label,
}

/// `d = a ^ b` for limbs below 2^32. `d` may be `a` or `b`; `s` is scratch.
fn xor(asm: &mut Asm, d: Reg, a: Reg, b: Reg, s: Reg) {
    asm.and(s, a, b);
    asm.add(d, a, b);
    asm.add(s, s, s);
    asm.sub(d, d, s);
}

const fn limb_cell(base: u64, lane: u64, limb: u64) -> u64 {
    base.saturating_add(lane.saturating_mul(2))
        .saturating_add(limb)
}

impl Keccak {
    /// Reserve the memory of the sponge and the labels of its subroutines.
    /// [`Self::emit_init`] must run before the first permutation and
    /// [`Self::emit_subroutines`] must be placed once, outside the main
    /// line of the program.
    pub fn new(asm: &mut Asm) -> Self {
        Self {
            state: asm.alloc(STATE_LIMBS),
            scratch: asm.alloc(STATE_LIMBS),
            constants: asm.alloc(48),
            permute: asm.label(),
            clear: asm.label(),
            absorb_136: asm.label(),
            absorb_168: asm.label(),
            squeeze_136: asm.label(),
            squeeze_168: asm.label(),
        }
    }

    /// Write the round constants to memory. Memory the program did not
    /// write is not trusted, so the table is built by the program itself.
    pub fn emit_init(&self, asm: &mut Asm) {
        let mut cell = self.constants;
        for constant in ROUND_CONSTANTS {
            for limb in [constant % (1 << LIMB_BITS), constant >> LIMB_BITS] {
                if limb == 0 {
                    asm.store_abs(cell, ZERO);
                } else {
                    asm.li(R[1], limb);
                    asm.store_abs(cell, R[1]);
                }
                cell = cell.saturating_add(1);
            }
        }
    }

    /// Call Keccak-f[1600] on the state.
    pub fn permute(&self, asm: &mut Asm) {
        asm.call(self.permute);
    }

    /// Set the state to zero.
    pub fn clear(&self, asm: &mut Asm) {
        asm.call(self.clear);
    }

    /// XOR one block of `rate` bytes into the state. `R[1]` holds the byte
    /// address of the first byte cell of the block.
    pub fn absorb(&self, asm: &mut Asm, rate: Rate) {
        asm.call(match rate {
            Rate::R136 => self.absorb_136,
            Rate::R168 => self.absorb_168,
        });
    }

    /// Write the first `rate` bytes of the state to byte cells. `R[1]`
    /// holds the byte address of the first cell.
    pub fn squeeze_block(&self, asm: &mut Asm, rate: Rate) {
        asm.call(match rate {
            Rate::R136 => self.squeeze_136,
            Rate::R168 => self.squeeze_168,
        });
    }

    /// Hash the `len` byte cells at `message`: pad them in place (the
    /// cells after the message, up to the end of its last block, are
    /// overwritten), clear the state and absorb every block. The output is
    /// then read with [`emit_squeeze`]. Returns the padded length.
    pub fn emit_hash(
        &self,
        asm: &mut Asm,
        message: u64,
        len: u64,
        rate: Rate,
        domain: Domain,
    ) -> u64 {
        let rate_bytes = rate.bytes();
        let padded = (len / rate_bytes)
            .saturating_add(1)
            .saturating_mul(rate_bytes);
        let last = padded.saturating_sub(1);
        for at in len..padded {
            let mut byte = 0u64;
            if at == len {
                byte = byte.saturating_add(domain.byte());
            }
            if at == last {
                byte = byte.saturating_add(0x80);
            }
            let cell = message.saturating_add(at);
            if byte == 0 {
                asm.store_abs(cell, ZERO);
            } else {
                asm.li(R[1], byte);
                asm.store_abs(cell, R[1]);
            }
        }
        self.clear(asm);
        let mut block = 0u64;
        while block < padded {
            asm.li(R[1], Asm::address(message.saturating_add(block)));
            self.absorb(asm, rate);
            self.permute(asm);
            block = block.saturating_add(rate_bytes);
        }
        padded
    }

    /// Write the first `limbs` limbs of the state as bytes, four per limb,
    /// to the cells from `to` on (an absolute cell, or an offset from the
    /// byte address in `base`).
    pub fn emit_squeeze(&self, asm: &mut Asm, base: Option<Reg>, to: u64, limbs: u64) {
        let (c255, c256, limb, byte) = (R[2], R[3], R[5], R[6]);
        asm.li(c255, 255);
        asm.li(c256, 256);
        for index in 0..limbs {
            asm.load_abs(limb, self.state.saturating_add(index));
            for k in 0..4u64 {
                let cell = to.saturating_add(index.saturating_mul(4)).saturating_add(k);
                let value = if k == 3 {
                    limb
                } else {
                    asm.and(byte, limb, c255);
                    asm.sub(limb, limb, byte);
                    asm.div(limb, limb, c256);
                    byte
                };
                match base {
                    Some(base) => asm.store(base, cell, value),
                    None => asm.store_abs(cell, value),
                }
            }
        }
    }

    /// Place the subroutines.
    pub fn emit_subroutines(&self, asm: &mut Asm) {
        asm.region("keccak_f");
        asm.bind(self.permute);
        self.emit_permutation(asm);
        asm.ret();

        asm.region("sponge");
        asm.bind(self.clear);
        for index in 0..STATE_LIMBS {
            asm.store_abs(self.state.saturating_add(index), ZERO);
        }
        asm.ret();
        for (label, rate) in [(self.absorb_136, Rate::R136), (self.absorb_168, Rate::R168)] {
            asm.bind(label);
            self.emit_absorb(asm, rate);
            asm.ret();
        }
        for (label, rate) in [
            (self.squeeze_136, Rate::R136),
            (self.squeeze_168, Rate::R168),
        ] {
            asm.bind(label);
            self.emit_squeeze(asm, Some(R[1]), 0, rate.limbs());
            asm.ret();
        }
    }

    fn emit_absorb(&self, asm: &mut Asm, rate: Rate) {
        let (c8, c16, c24) = (R[2], R[3], R[4]);
        asm.li(c8, 1 << 8);
        asm.li(c16, 1 << 16);
        asm.li(c24, 1 << 24);
        for index in 0..rate.limbs() {
            let first = index.saturating_mul(4);
            asm.load(R[5], R[1], first);
            asm.load(R[6], R[1], first.saturating_add(1));
            asm.load(R[7], R[1], first.saturating_add(2));
            asm.load(R[8], R[1], first.saturating_add(3));
            asm.mul(R[6], R[6], c8);
            asm.mul(R[7], R[7], c16);
            asm.mul(R[8], R[8], c24);
            asm.add(R[5], R[5], R[6]);
            asm.add(R[5], R[5], R[7]);
            asm.add(R[5], R[5], R[8]);
            let cell = self.state.saturating_add(index);
            asm.load_abs(R[9], cell);
            xor(asm, R[9], R[9], R[5], R[10]);
            asm.store_abs(cell, R[9]);
        }
    }

    /// The 24 rounds. Registers: 1 to 10 the column parities, then the
    /// work of rho and chi; 11 to 20 the theta effect; 21 and 22 the
    /// constants of the rotation by one; 23 to 27 scratch; 28 the pointer
    /// to the round constant; 29 its end.
    fn emit_permutation(&self, asm: &mut Asm) {
        let pointer = R[28];
        let end = R[29];
        asm.li(pointer, Asm::address(self.constants));
        asm.li(end, Asm::address(self.constants.saturating_add(48)));
        let top = asm.here();
        self.emit_theta(asm);
        self.emit_rho_pi(asm);
        self.emit_chi_iota(asm, pointer);
        asm.li(R[23], 16);
        asm.add(pointer, pointer, R[23]);
        asm.neq(R[23], pointer, end);
        asm.jnz(R[23], top);
    }

    /// Column parities into registers 1 to 10 and the theta effect
    /// `D[x] = C[x - 1] ^ rot(C[x + 1], 1)` into registers 11 to 20.
    fn emit_theta(&self, asm: &mut Asm) {
        let (word, scratch) = (R[23], R[24]);
        for (x, column) in COLUMN.iter().enumerate() {
            let x = u64::try_from(x).unwrap_or(0);
            for (limb, parity) in (0u64..).zip(column.iter().copied()) {
                asm.load_abs(parity, limb_cell(self.state, x, limb));
                for y in 1..5u64 {
                    asm.load_abs(
                        word,
                        limb_cell(self.state, x.saturating_add(y.saturating_mul(5)), limb),
                    );
                    xor(asm, parity, parity, word, scratch);
                }
            }
        }
        let (mask, power) = (R[21], R[22]);
        asm.li(mask, (1 << 31) - 1);
        asm.li(power, 1 << 31);
        let (t1, t2, t3, t4, s) = (R[23], R[24], R[25], R[26], R[27]);
        for (x, effect) in EFFECT.iter().enumerate() {
            let (Some(next), Some(previous)) = (COLUMN.get((x + 1) % 5), COLUMN.get((x + 4) % 5))
            else {
                continue;
            };
            let [lo, hi] = *next;
            // Rotate the next column left by one bit.
            asm.and(t1, lo, mask);
            asm.sub(t2, lo, t1);
            asm.div(t2, t2, power);
            asm.and(t3, hi, mask);
            asm.sub(t4, hi, t3);
            asm.div(t4, t4, power);
            asm.add(t1, t1, t1);
            asm.add(t1, t1, t4);
            asm.add(t3, t3, t3);
            asm.add(t3, t3, t2);
            let [previous_lo, previous_hi] = *previous;
            let [effect_lo, effect_hi] = *effect;
            xor(asm, effect_lo, t1, previous_lo, s);
            xor(asm, effect_hi, t3, previous_hi, s);
        }
    }

    /// `B[y, 2x + 3y] = rot(A[x, y] ^ D[x], r[x, y])`, from the state into
    /// the scratch state.
    fn emit_rho_pi(&self, asm: &mut Asm) {
        for (lane, rotation) in (0u64..).zip(ROTATIONS) {
            let x = lane % 5;
            let y = lane / 5;
            let Some(effect) = usize::try_from(x).ok().and_then(|x| EFFECT.get(x)) else {
                continue;
            };
            let [effect_lo, effect_hi] = *effect;
            let (mut lo, mut hi, s) = (R[1], R[2], R[3]);
            asm.load_abs(lo, limb_cell(self.state, lane, 0));
            asm.load_abs(hi, limb_cell(self.state, lane, 1));
            xor(asm, lo, lo, effect_lo, s);
            xor(asm, hi, hi, effect_hi, s);
            let mut amount = rotation;
            if amount >= LIMB_BITS {
                core::mem::swap(&mut lo, &mut hi);
                amount -= LIMB_BITS;
            }
            if amount != 0 {
                // Split each limb at bit `32 - amount`; the low pieces move
                // up by `amount`, the high pieces move to the other limb.
                let split = LIMB_BITS - amount;
                let (mask, power, shift) = (R[4], R[5], R[6]);
                asm.li(mask, (1u64 << split) - 1);
                asm.li(power, 1u64 << split);
                asm.li(shift, 1u64 << amount);
                let (lo_low, lo_high, hi_low, hi_high) = (R[7], R[8], R[9], R[10]);
                asm.and(lo_low, lo, mask);
                asm.sub(lo_high, lo, lo_low);
                asm.div(lo_high, lo_high, power);
                asm.and(hi_low, hi, mask);
                asm.sub(hi_high, hi, hi_low);
                asm.div(hi_high, hi_high, power);
                asm.mul(lo_low, lo_low, shift);
                asm.add(lo_low, lo_low, hi_high);
                asm.mul(hi_low, hi_low, shift);
                asm.add(hi_low, hi_low, lo_high);
                lo = lo_low;
                hi = hi_low;
            }
            let target = y.saturating_add(((2 * x).saturating_add(3 * y) % 5).saturating_mul(5));
            asm.store_abs(limb_cell(self.scratch, target, 0), lo);
            asm.store_abs(limb_cell(self.scratch, target, 1), hi);
        }
    }

    /// `A[x, y] = B[x, y] ^ (!B[x + 1, y] & B[x + 2, y])`, from the scratch
    /// state back into the state, and the round constant into lane 0.
    fn emit_chi_iota(&self, asm: &mut Asm, constant_pointer: Reg) {
        let (t, out, s, constant) = (R[11], R[12], R[13], R[14]);
        for y in 0..5u64 {
            for (x, lane) in (0u64..).zip(COLUMN) {
                for (limb, register) in (0u64..).zip(lane) {
                    asm.load_abs(
                        register,
                        limb_cell(self.scratch, x.saturating_add(y.saturating_mul(5)), limb),
                    );
                }
            }
            for x in 0..5usize {
                let (Some(here), Some(next), Some(after)) = (
                    COLUMN.get(x),
                    COLUMN.get((x + 1) % 5),
                    COLUMN.get((x + 2) % 5),
                ) else {
                    continue;
                };
                let lane = u64::try_from(x)
                    .unwrap_or(0)
                    .saturating_add(y.saturating_mul(5));
                for (limb, ((a, b), c)) in
                    (0u64..).zip(here.iter().zip(next.iter()).zip(after.iter()))
                {
                    asm.and(t, *b, *c);
                    asm.sub(t, *c, t);
                    xor(asm, out, *a, t, s);
                    if lane == 0 {
                        asm.load(constant, constant_pointer, limb);
                        xor(asm, out, out, constant, s);
                    }
                    asm.store_abs(limb_cell(self.state, lane, limb), out);
                }
            }
        }
    }

    /// The first cell of the state: 50 limbs, lane `x + 5 * y` at limbs
    /// `2 * lane` (low) and `2 * lane + 1` (high).
    #[must_use]
    pub const fn state(&self) -> u64 {
        self.state
    }
}

/// Registers of the five column values of a row or a parity: low and high
/// limb of each.
const COLUMN: [[Reg; 2]; 5] = [
    [R[1], R[2]],
    [R[3], R[4]],
    [R[5], R[6]],
    [R[7], R[8]],
    [R[9], R[10]],
];

/// Registers of the theta effect of the five columns.
const EFFECT: [[Reg; 2]; 5] = [
    [R[11], R[12]],
    [R[13], R[14]],
    [R[15], R[16]],
    [R[17], R[18]],
    [R[19], R[20]],
];
