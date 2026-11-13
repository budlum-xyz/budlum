//! ZK QC fault proof verifier.
//!
//! This module is fail-closed on testnet. It refuses every ZK QC fault
//! proof. A BudZero STARK verifier is not integrated yet. No pairing
//! based SNARK sits on a Budlum verification path.

/// ZK QC fault proof challenge is closed on testnet.
pub const ZK_QC_FAULT_PROOF_CLOSED_ON_TESTNET: bool = true;

/// Verify a ZK QC fault proof. Always refuses until a BudZero STARK
/// verifier is integrated.
pub fn verify_zk_qc_fault_proof(_proof_bytes: &[u8], _merkle_root: &str) -> Result<(), String> {
    Err("ZK QC fault proof verifier not implemented - ZK domain attestations cannot be challenged until ZK verifier integration. This is fail-closed: no invalid ZK attestation can be finalized via this path.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_qc_fault_proof_is_closed_on_testnet() {
        const { assert!(ZK_QC_FAULT_PROOF_CLOSED_ON_TESTNET) };
        let result = verify_zk_qc_fault_proof(&[1, 2, 3], "root");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("ZK QC fault proof verifier not implemented"));
    }

    #[test]
    fn zk_qc_fault_proof_verifier_refuses_empty_proof() {
        assert!(verify_zk_qc_fault_proof(&[], "").is_err());
    }
}
