//! Byte strings in memory: one byte per cell.
//!
//! The input of a program is whatever its prover put in memory. Before a
//! cell is used as a byte it is checked to be one; everything the hashing
//! and the decoding do afterwards relies on that.

use super::asm::{Asm, Label, R};

/// The byte subroutines of one program.
#[derive(Debug, Clone, Copy)]
pub struct Bytes {
    check: Label,
    copy: Label,
}

impl Bytes {
    /// Reserve the labels. [`Self::emit_subroutines`] must be placed once.
    pub fn new(asm: &mut Asm) -> Self {
        Self {
            check: asm.label(),
            copy: asm.label(),
        }
    }

    /// Stop unless each of the `cells` cells from `first` on holds a byte.
    pub fn check(&self, asm: &mut Asm, first: u64, cells: u64) {
        asm.li(R[1], Asm::address(first));
        asm.li(R[2], Asm::address(first.saturating_add(cells)));
        asm.call(self.check);
    }

    /// Copy `cells` byte cells to `to`, from the byte address in `R[1]`,
    /// and stop unless each holds a byte. `R[1]` is left at the cell after
    /// the last one read, so a record can be read field by field.
    pub fn copy_from_pointer(&self, asm: &mut Asm, to: u64, cells: u64) {
        asm.li(R[2], Asm::address(to));
        asm.li(R[3], Asm::address(cells));
        asm.add(R[3], R[3], R[1]);
        asm.call(self.copy);
    }

    /// Copy the byte cells from the address in `R[1]` up to the one in
    /// `R[3]` to the address in `R[2]`, checking each.
    pub fn call_copy(&self, asm: &mut Asm) {
        asm.call(self.copy);
    }

    /// Place the subroutines.
    pub fn emit_subroutines(&self, asm: &mut Asm) {
        asm.region("bytes");
        asm.bind(self.check);
        {
            let (pointer, end, mask, eight, byte, t) = (R[1], R[2], R[3], R[4], R[5], R[6]);
            asm.li(mask, 255);
            asm.li(eight, 8);
            let top = asm.here();
            asm.load(byte, pointer, 0);
            asm.and(t, byte, mask);
            asm.eq(t, t, byte);
            asm.assert(t);
            asm.add(pointer, pointer, eight);
            asm.neq(t, pointer, end);
            asm.jnz(t, top);
            asm.ret();
        }
        asm.bind(self.copy);
        {
            let (source, target, end, mask, eight, byte, t) =
                (R[1], R[2], R[3], R[4], R[5], R[6], R[7]);
            asm.li(mask, 255);
            asm.li(eight, 8);
            let top = asm.here();
            asm.load(byte, source, 0);
            asm.and(t, byte, mask);
            asm.eq(t, t, byte);
            asm.assert(t);
            asm.store(target, 0, byte);
            asm.add(source, source, eight);
            asm.add(target, target, eight);
            asm.neq(t, source, end);
            asm.jnz(t, top);
            asm.ret();
        }
    }
}

/// Write constant bytes to the cells from `to` on.
pub fn emit_constant(asm: &mut Asm, to: u64, bytes: &[u8]) {
    for (at, byte) in (0u64..).zip(bytes) {
        asm.li(R[1], u64::from(*byte));
        asm.store_abs(to.saturating_add(at), R[1]);
    }
}

/// Copy `len` cells between two fixed places.
pub fn emit_copy(asm: &mut Asm, to: u64, from: u64, len: u64) {
    for at in 0..len {
        asm.load_abs(R[1], from.saturating_add(at));
        asm.store_abs(to.saturating_add(at), R[1]);
    }
}

/// Stop unless the `len` cells at `a` equal the `len` cells at `b`.
pub fn emit_assert_equal(asm: &mut Asm, a: u64, b: u64, len: u64) {
    for at in 0..len {
        asm.load_abs(R[1], a.saturating_add(at));
        asm.load_abs(R[2], b.saturating_add(at));
        asm.eq(R[3], R[1], R[2]);
        asm.assert(R[3]);
    }
}
