//! PulAir: the statement and the batch layout of the PUL stamp.
//!
//! A stamp claims, for a batch of transactions, that each `(txid,
//! from_address, suite_id)` carries a valid signature of its suite. This
//! module fixes what is proven and how a batch is laid out for the chips:
//!
//! * [`PulStatement`] and its canonical encoding (length-prefixed fields);
//! * [`absorb_states`]: the Keccak-f inputs of the sponge over the encoded
//!   batch (rate 136 bytes, pad10*1 with the Keccak domain byte), which the
//!   Keccak chip proves;
//! * [`prove_batch`] / [`verify_batch`]: the chip proof of those
//!   permutations together with the statements it was made for.
//!
//! What this does not yet do, and so what no claim may rest on: the
//! chip AIR exposes no public inputs, so `verify_batch` recomputes the sponge
//! inputs from the statements and checks the proof, but the proof itself is
//! not bound to those inputs inside the AIR; and the ML-DSA verification
//! is not part of the trace. Both are the remaining
//! work.

use crate::keccak_chip::{prove_keccak_f, verify_keccak_f, KeccakChipError};
use bud_proof::plonky3_prover::ChipProof;

/// The Keccak-256 rate in bytes.
pub const RATE_BYTES: usize = 136;

/// One proven transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulStatement {
    pub txid: [u8; 32],
    pub from_address: [u8; 32],
    pub suite_id: u16,
}

impl PulStatement {
    /// The canonical encoding: each field preceded by its little-endian u64
    /// length.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 * 8 + 32 + 32 + 2);
        for field in [
            &self.txid[..],
            &self.from_address[..],
            &self.suite_id.to_be_bytes()[..],
        ] {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }
}

/// The encoded batch: the statement count, then every statement.
#[must_use]
pub fn encode_batch(statements: &[PulStatement]) -> Vec<u8> {
    let mut out = (statements.len() as u64).to_le_bytes().to_vec();
    for statement in statements {
        out.extend_from_slice(&statement.encode());
    }
    out
}

/// The Keccak-f input state of every absorption of the sponge over `bytes`.
#[must_use]
pub fn absorb_states(bytes: &[u8]) -> Vec<[u64; 25]> {
    let mut padded = bytes.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE_BYTES) {
        padded.push(0);
    }
    if let Some(last) = padded.last_mut() {
        *last |= 0x80;
    }
    let mut state = [0u64; 25];
    let mut inputs = Vec::with_capacity(padded.len() / RATE_BYTES);
    for block in padded.chunks(RATE_BYTES) {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(lane);
            state[i] ^= u64::from_le_bytes(word);
        }
        inputs.push(state);
        let mut next = state;
        keccak_f(&mut next);
        state = next;
    }
    inputs
}

/// Keccak-f[1600], the reference permutation (FIPS 202).
fn keccak_f(a: &mut [u64; 25]) {
    const RC: [u64; 24] = [
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
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

/// A batch proof: the statements and the chip proof over their sponge.
pub struct PulBatchProof {
    pub statements: Vec<PulStatement>,
    pub keccak: ChipProof,
}

/// Prove the sponge of a batch with the Keccak chip.
///
/// # Errors
///
/// An empty batch or a chip refusal.
pub fn prove_batch(statements: Vec<PulStatement>) -> Result<PulBatchProof, KeccakChipError> {
    if statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    let inputs = absorb_states(&encode_batch(&statements));
    let keccak = prove_keccak_f(&inputs)?;
    Ok(PulBatchProof { statements, keccak })
}

/// Verify a batch proof (see the module note on what is not yet bound).
///
/// # Errors
///
/// An empty batch or a chip proof that does not verify.
pub fn verify_batch(proof: &PulBatchProof) -> Result<(), KeccakChipError> {
    if proof.statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    verify_keccak_f(&proof.keccak)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_permutation_matches_tiny_keccak() {
        let mut ours = [7u64; 25];
        let mut theirs = ours;
        keccak_f(&mut ours);
        tiny_keccak::keccakf(&mut theirs);
        assert_eq!(ours, theirs);
    }

    #[test]
    fn a_batch_proves_and_verifies() {
        let statement = PulStatement {
            txid: [1; 32],
            from_address: [2; 32],
            suite_id: 1,
        };
        assert_eq!(
            absorb_states(&encode_batch(std::slice::from_ref(&statement))).len(),
            1
        );
        let proof = prove_batch(vec![statement]).expect("proves");
        assert!(verify_batch(&proof).is_ok());
        assert!(prove_batch(Vec::new()).is_err());
    }
}
