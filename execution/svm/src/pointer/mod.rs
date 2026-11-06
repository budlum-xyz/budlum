//! Stateless SPL Token pointer codec (`WP-52`, `Section 8.8`).
//!
//! An SPL pointer mint/program holds **zero** shadow balances and **zero**
//! local delegate allowances in `ee/svm/account`: every transfer, delegate
//! approval, and balance/allowance query is forwarded over `UniversalCall` to
//! the asset's `home_ee`.

use serde::{Deserialize, Serialize};

/// Canonical stateless SPL pointer operations routed by the UEL coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplPointerOp {
    Transfer {
        to: [u8; 32],
        amount: u128,
    },
    Approve {
        delegate: [u8; 32],
        amount: u128,
    },
    TransferFrom {
        owner: [u8; 32],
        to: [u8; 32],
        amount: u128,
    },
    BalanceOf {
        owner: [u8; 32],
    },
    Allowance {
        owner: [u8; 32],
        delegate: [u8; 32],
    },
}

/// Encode an [`SplPointerOp`] for submission to an SVM pointer address.
pub fn encode_spl_pointer_op(op: &SplPointerOp) -> Result<Vec<u8>, String> {
    serde_json::to_vec(op).map_err(|e| format!("SPL pointer encode error: {e}"))
}

/// Decode an [`SplPointerOp`] received at an SVM pointer address.
pub fn decode_spl_pointer_op(bytes: &[u8]) -> Result<SplPointerOp, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("SPL pointer decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spl_pointer_op_roundtrips_without_local_storage() {
        let op = SplPointerOp::Approve {
            delegate: [0xAB; 32],
            amount: 125_000,
        };
        let Ok(raw) = encode_spl_pointer_op(&op) else {
            panic!("encode");
        };
        let Ok(back) = decode_spl_pointer_op(&raw) else {
            panic!("decode");
        };
        assert_eq!(back, op);
    }
}
