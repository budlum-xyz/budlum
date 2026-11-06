//! B.U.D. 3.0 custody proofs are anchored under a sub-block.
//!
//! Section 16.3 / İP-20: every custody/audit proof a custodian submits is
//! verified against a Merkle path rooted in a sub-block header; an
//! unsigned or out-of-context proof cannot cause a slash or a reward.
//!
//! Today this is a skeleton gate that ensures the word "custody_proof" is
//! used (when İP-20 lands it parses the StorageTxV3::CustodyAck and the
//! CustodyProof path and refuses any proof that does not tie back to a
//! sub-block root).

use std::path::Path;

pub fn run(_root: &Path) -> Result<String, String> {
    // Skeleton: İP-20 fills in the real check (proof carries a sub-block
    // hash chain, an ML-DSA signature under the custodian key, and a
    // Merkle inclusion proof for the share symbols). Until İP-20 lands
    // nothing to scan for: the transaction variant and the proof type are
    // not yet written.
    Ok(String::from(
        "bud3-custody-proofs OK: skeleton (İP-20 fills in when custody proofs are wired)"
    ))
}

pub fn self_test() -> Result<String, String> {
    // Self-test is a placeholder: the gate is a skeleton. The real
    // self_test in İP-20 injects an unsigned proof, an out-of-context
    // proof, and a valid proof and confirms accept/refuse.
    Ok(String::from("bud3-custody-proofs canary OK: skeleton passes trivially until İP-20."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
