//! Canonical program set - the ZKVM-side half of the regeneration gate.
//!
//! The regeneration gate (xtask) independently reproduces the canonical
//! programs and pins their hashes. This module holds the same set on the
//! proof side, so the verifier can warn - or refuse - when a proof was
//! produced for a program that is not part of the canonical set. The two
//! sides are cross-pinned: the gate checks that this file still lists the
//! exact values it pins, and `prove_and_verify_canonical_program` proves
//! that a canonical proof survives the check.
//!
//! The hashes are Keccak-256 over the little-endian instruction words,
//! matching `adapter.rs::program_hash_of`.

use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 of a program's little-endian instruction words. Kept here so
/// the canonical set can be re-derived from source independently of the
/// prover's own path (the gate does the same computation with its own
/// Keccak).
pub fn program_hash_of(program: &[u64]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for &inst in program {
        hasher.update(&inst.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// The canonical program hashes, in the order the gate pins them:
/// storage-challenge, matmul guest [2,3,2], private-transfer check,
/// syscall-context check.
///
/// Pinned 2026-08-28. If a canonical program changes, BOTH this table and
/// the gate's pins must change together - the gate asserts that.
pub const CANONICAL_PROGRAM_HASHES: [&str; 4] = [
    // Storage challenge: [VerifyMerkle rd=1 rs1=2 rs2=3 imm=256, Halt].
    "3adbf9c8e6afb8ef243e9063ad25ccd2b890d91e2bd88816a1a909ce2c5b15d4",
    // Matmul guest [2,3,2].
    "4c4e86b4d34230df02acb991eb3111e459fb8bf06dd2b65b78c143b7f8b7e8c7",
    // Private-transfer check (12 instructions).
    "313a4da25d92952dbd14ce71c2f30fdab7cd47a397a612403f7da1562dabf154",
    // Syscall-context check (7 instructions).
    "30cf71d4f910cd7f8adf8178e0f2c44ec9c4209252212ff4a0a74f3c6a15fd69",
];

/// True if the program hash is one of the canonical ones.
pub fn is_canonical_program_hash(hash: &[u8; 32]) -> bool {
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    CANONICAL_PROGRAM_HASHES.contains(&hex.as_str())
}

/// Combined digest of the whole canonical set: Keccak-256 over the
/// concatenated canonical hashes (raw bytes). The regeneration gate emits
/// this as its `canonical-set` token, so a proof-side check and the gate
/// agree on one value.
pub fn canonical_set_digest() -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for hex in CANONICAL_PROGRAM_HASHES {
        let bytes = hex_bytes(hex).expect("canonical hash must be hex");
        hasher.update(&bytes);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_canonical_hashes_are_well_formed() {
        for hex in CANONICAL_PROGRAM_HASHES {
            assert_eq!(hex.len(), 64, "a canonical hash must be 32 bytes of hex");
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn canonical_set_digest_is_deterministic() {
        assert_eq!(canonical_set_digest(), canonical_set_digest());
    }

    #[test]
    fn canonical_hashes_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for hex in CANONICAL_PROGRAM_HASHES {
            assert!(seen.insert(hex), "duplicate canonical hash {hex}");
        }
    }

    #[test]
    fn the_four_programs_are_pinned_exactly_as_the_gate_pins_them() {
        // The first entry is the storage-challenge hash (measured from the
        // gate's own reproduction); the second is the matmul token. If this
        // test drifts, the gate's discovery will flag it, and the gate's own
        // cross-pin test (in xtask) checks this file's contents against its
        // pins.
        assert_eq!(
            CANONICAL_PROGRAM_HASHES[0],
            "3adbf9c8e6afb8ef243e9063ad25ccd2b890d91e2bd88816a1a909ce2c5b15d4"
        );
        assert_eq!(
            CANONICAL_PROGRAM_HASHES[1],
            "4c4e86b4d34230df02acb991eb3111e459fb8bf06dd2b65b78c143b7f8b7e8c7"
        );
        assert_eq!(
            CANONICAL_PROGRAM_HASHES[2],
            "313a4da25d92952dbd14ce71c2f30fdab7cd47a397a612403f7da1562dabf154"
        );
        assert_eq!(
            CANONICAL_PROGRAM_HASHES[3],
            "30cf71d4f910cd7f8adf8178e0f2c44ec9c4209252212ff4a0a74f3c6a15fd69"
        );
    }
}

#[cfg(test)]
mod digest_crosscheck {
    use super::*;

    #[test]
    fn gate_token_crosscheck() {
        // The regeneration gate emits `canonical-set <hex16>`; the first 16
        // hex chars must equal this. Measured 2026-08-28 from the gate run.
        let d = canonical_set_digest();
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(&hex[..16], "7068f0e7209ca558");
    }
}
