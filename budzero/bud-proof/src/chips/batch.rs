//! BatchAir: the statement and the batch layout of the signature-aggregation stamp.
//!
//! A stamp claims, for a batch of transactions, that each `(txid,
//! from_address, suite_id)` carries a valid signature of its suite. This
//! module fixes what is proven and how a batch is laid out for the chips:
//!
//! * [`BatchStatement`] and its canonical encoding (length-prefixed fields);
//! * [`absorb_states`]: the Keccak-f inputs of the sponge over the encoded
//!   batch (rate 136 bytes, pad10*1 with the Keccak domain byte), which the
//!   Keccak chip proves;
//! * [`prove_batch`] / [`verify_batch`]: the chip proof of those
//!   permutations together with the statements it was made for.
//!
//! What this does not yet do, and so what no claim may rest on: the chip AIR
//! exposes no public inputs, so nothing inside the proof binds the sponge
//! inputs to the statements, and the ML-DSA verification is not part of the
//! trace. Because a chip proof of one batch of permutations therefore verifies
//! beside *any* statement list, [`verify_batch`] refuses every batch instead
//! of accepting one it cannot bind - a verifier that says yes to whatever it is
//! handed is worse than one that says nothing. Both gaps are the remaining
//! work, and the refusal is lifted with the binding.

use crate::chips::keccak::{
    prove_bound_keccak_f, prove_keccak_f, verify_bound_keccak_f, verify_keccak_f, BoundKeccakProof,
    KeccakChipError,
};
use crate::plonky3_prover::ChipProof;

/// The Keccak-256 rate in bytes.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub const RATE_BYTES: usize = 136;

/// One proven transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct BatchStatement {
    pub txid: [u8; 32],
    pub from_address: [u8; 32],
    pub suite_id: u16,
}

impl BatchStatement {
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
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn encode_batch(statements: &[BatchStatement]) -> Vec<u8> {
    let mut out = (statements.len() as u64).to_le_bytes().to_vec();
    for statement in statements {
        out.extend_from_slice(&statement.encode());
    }
    out
}

/// Pads `bytes` with Keccak `pad10*1` into 136-byte (17-lane) rate blocks.
#[must_use]
pub fn pad_rate_blocks(bytes: &[u8]) -> Vec<[u64; 17]> {
    let mut padded = bytes.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE_BYTES) {
        padded.push(0);
    }
    if let Some(last) = padded.last_mut() {
        *last |= 0x80;
    }
    let mut blocks = Vec::with_capacity(padded.len() / RATE_BYTES);
    for block in padded.chunks(RATE_BYTES) {
        let mut lanes = [0u64; 17];
        for (i, lane) in block.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(lane);
            lanes[i] = u64::from_le_bytes(word);
        }
        blocks.push(lanes);
    }
    blocks
}

/// The Keccak-f input state of every absorption of the sponge over `bytes`.
#[must_use]
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn absorb_states(bytes: &[u8]) -> Vec<[u64; 25]> {
    let blocks = pad_rate_blocks(bytes);
    let mut state = [0u64; 25];
    let mut inputs = Vec::with_capacity(blocks.len());
    for block in blocks {
        for (dst, src) in state.iter_mut().zip(block.iter()) {
            *dst ^= *src;
        }
        inputs.push(state);
        let mut next = state;
        keccak_f(&mut next);
        state = next;
    }
    inputs
}

/// Keccak-f[1600], the reference permutation (FIPS 202).
/// Reference 24-round `Keccak-f[1600]` permutation on a 25-lane state.
pub fn keccak_f(a: &mut [u64; 25]) {
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
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub struct BatchProof {
    pub statements: Vec<BatchStatement>,
    pub keccak: ChipProof,
}

/// Prove the sponge of a batch with the Keccak chip.
///
/// # Errors
///
/// An empty batch or a chip refusal.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn prove_batch(statements: Vec<BatchStatement>) -> Result<BatchProof, KeccakChipError> {
    if statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    let inputs = absorb_states(&encode_batch(&statements));
    let keccak = prove_keccak_f(&inputs)?;
    Ok(BatchProof { statements, keccak })
}

/// Verify a batch proof.
///
/// # Errors
///
/// An empty batch, a chip proof that does not verify, or - always, until the
/// statement binding exists - the unbound-proof refusal.
///
/// # Why it refuses
///
/// The chip AIR exposes no public inputs and the trace is the whole proof, so
/// the verification says only "some batch of permutations was run". It does not
/// say which, and nothing in it is tied to `proof.statements`: a valid chip
/// proof produced for unrelated inputs, or replayed from an earlier batch,
/// verifies beside any statement list. The previous version verified the chip
/// proof and returned `Ok`, which certified statements that were never proven -
/// on a stamp-verification path that is exactly a forged sigagg stamp. Fail-closed
/// until the AIR binds the sponge inputs of the batch.
/// exposed for: the proof/VM crate's test-and-tooling surface - production readers land with the prover wiring.
pub fn verify_batch(proof: &BatchProof) -> Result<(), KeccakChipError> {
    if proof.statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    verify_keccak_f(&proof.keccak)?;
    Err(KeccakChipError::UnboundProof)
}

/// A cryptographically bound batch proof: the statements, each sponge
/// permutation's output state, and the [`BoundKeccakProof`] certifying that
/// every absorbed state maps to its output under `Keccak-f[1600]`.
#[derive(Clone)]
/// WIRING: called by Phase 3 recursive batch proving and verification.
pub struct BoundBatchProof {
    pub statements: Vec<BatchStatement>,
    pub outputs: Vec<[u64; 25]>,
    pub keccak: BoundKeccakProof,
}

/// Proves the Keccak-256 sponge over a statement batch with every absorbed
/// state and permutation output bound inside `BoundKeccakAir`.
///
/// # Errors
///
/// Refuses an empty batch or a chip-proving failure.
/// WIRING: called by Phase 3 recursive batch proving and verification.
pub fn prove_bound_batch(
    statements: Vec<BatchStatement>,
) -> Result<BoundBatchProof, KeccakChipError> {
    if statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    let inputs = absorb_states(&encode_batch(&statements));
    let (keccak, outputs) = prove_bound_keccak_f(&inputs)?;
    Ok(BoundBatchProof {
        statements,
        outputs,
        keccak,
    })
}

/// Verifies a [`BoundBatchProof`] without running `Keccak-f[1600]` in the
/// verifier: reconstructs each absorption input solely by XORing the padded
/// statement rate blocks into the prior proven output state, then verifies the
/// bound Keccak STARK and returns the 32-byte Keccak-256 digest of the batch.
///
/// # Errors
///
/// Refuses empty batches, mismatched output counts, replayed proofs for other
/// statements, tampered intermediate states, or invalid STARK proofs.
/// WIRING: called by Phase 3 recursive batch proving and verification.
pub fn verify_bound_batch(proof: &BoundBatchProof) -> Result<[u8; 32], KeccakChipError> {
    if proof.statements.is_empty() {
        return Err(KeccakChipError::Empty);
    }
    let blocks = pad_rate_blocks(&encode_batch(&proof.statements));
    if proof.outputs.len() != blocks.len() {
        return Err(KeccakChipError::ShapeMismatch);
    }
    let mut inputs = Vec::with_capacity(blocks.len());
    for (idx, block) in blocks.iter().enumerate() {
        let mut state = if idx == 0 {
            [0u64; 25]
        } else {
            proof.outputs[idx - 1]
        };
        for (dst, src) in state.iter_mut().zip(block.iter()) {
            *dst ^= *src;
        }
        inputs.push(state);
    }
    verify_bound_keccak_f(&inputs, &proof.outputs, &proof.keccak)?;
    let last = proof.outputs.last().ok_or(KeccakChipError::Empty)?;
    let mut digest = [0u8; 32];
    for (i, word) in last.iter().take(4).enumerate() {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(digest)
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

    fn statement(seed: u8) -> BatchStatement {
        BatchStatement {
            txid: [seed; 32],
            from_address: [seed.wrapping_add(1); 32],
            suite_id: u16::from(seed),
        }
    }

    /// The prover produces the chip proof of the batch's sponge; the verifier
    /// refuses it, because nothing binds that proof to these statements.
    ///
    /// The previous test asserted `verify_batch(&proof).is_ok()` and so locked
    /// the gap in: it is the only reason nothing caught a verifier that accepted
    /// arbitrary statement lists.
    #[test]
    fn a_batch_proves_but_the_unbound_proof_is_refused() {
        let statement = statement(1);
        assert_eq!(
            absorb_states(&encode_batch(std::slice::from_ref(&statement))).len(),
            1
        );
        let proof = prove_batch(vec![statement]).expect("proves");
        assert_eq!(verify_batch(&proof), Err(KeccakChipError::UnboundProof));
        assert!(prove_batch(Vec::new()).is_err());
    }

    /// A chip proof is not a statement: the same proof verifies beside any
    /// statement list, and it is refused beside every one of them.
    #[test]
    fn a_proof_from_another_batch_does_not_verify_these_statements() {
        let honest = prove_batch(vec![statement(1)]).expect("proves");
        let replayed = BatchProof {
            statements: vec![statement(9)],
            keccak: honest.keccak.clone(),
        };
        assert_eq!(verify_batch(&replayed), Err(KeccakChipError::UnboundProof));

        let honest_again = BatchProof {
            statements: vec![statement(1)],
            keccak: honest.keccak,
        };
        assert_eq!(
            verify_batch(&honest_again),
            Err(KeccakChipError::UnboundProof),
            "the honest batch is refused too: the refusal is not a statement check"
        );
    }

    fn keccak256_reference(bytes: &[u8]) -> [u8; 32] {
        use tiny_keccak::{Hasher, Keccak};
        let mut h = Keccak::v256();
        h.update(bytes);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    }

    #[test]
    fn bound_batch_proves_and_verifies_multi_block_sponge() {
        let statements = vec![statement(1), statement(2), statement(3)];
        let expected = keccak256_reference(&encode_batch(&statements));
        let proof = prove_bound_batch(statements).expect("bound batch proves");
        assert!(
            proof.outputs.len() >= 2,
            "3 statements must span multiple 136-byte sponge blocks"
        );
        let verified_digest = verify_bound_batch(&proof).expect("bound batch verifies");
        assert_eq!(verified_digest, expected);
    }

    #[test]
    fn bound_batch_rejects_replayed_statements_and_tampered_sponge_states() {
        let honest = prove_bound_batch(vec![statement(1), statement(2)]).expect("proves");

        // Replaying the same chip proof beside a different statement list must fail.
        let replayed = BoundBatchProof {
            statements: vec![statement(9), statement(2)],
            outputs: honest.outputs.clone(),
            keccak: honest.keccak.clone(),
        };
        assert!(verify_bound_batch(&replayed).is_err());

        // Tampering an intermediate sponge output lane must fail.
        let mut bad_mid = honest.clone();
        bad_mid.outputs[0][17] ^= 1;
        assert!(verify_bound_batch(&bad_mid).is_err());

        // Tampering the final digest lane must fail.
        let mut bad_final = honest.clone();
        let last_idx = bad_final.outputs.len() - 1;
        bad_final.outputs[last_idx][0] ^= 1;
        assert!(verify_bound_batch(&bad_final).is_err());

        // Truncating outputs must fail with ShapeMismatch.
        let mut truncated = honest;
        truncated.outputs.pop();
        assert_eq!(
            verify_bound_batch(&truncated),
            Err(KeccakChipError::ShapeMismatch)
        );
    }
}
