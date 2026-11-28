//! Stateless SPL Token pointer codec (`Section 8.8`).
//!
//! An SPL pointer mint/program holds **zero** shadow balances and **zero**
//! local delegate allowances in `ee/svm/account`: every transfer, delegate
//! approval, and balance/allowance query is forwarded over `UniversalCall` to
//! the asset's `home_ee`.

use serde::{Deserialize, Serialize};

/// Hard byte cap on a serialized [`SplPointerOp`] JSON envelope (4 KiB).
pub const MAX_SPL_POINTER_OP_BYTES: usize = 4_096;

/// Canonical stateless SPL pointer operations routed by the UEL coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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

/// Validate semantic invariants of an [`SplPointerOp`].
///
/// Rejects zero-address recipients/delegates/owners and zero-value transfers
/// on state-mutating operations while permitting `Approve { amount: 0 }` for
/// allowance revocation and read-only `BalanceOf`/`Allowance` queries.
pub fn validate_spl_pointer_op(op: &SplPointerOp) -> Result<(), String> {
    match op {
        SplPointerOp::Transfer { to, amount } => {
            if *to == [0u8; 32] {
                return Err("SPL pointer transfer recipient cannot be zero address".to_string());
            }
            if *amount == 0 {
                return Err("SPL pointer transfer amount must be non-zero".to_string());
            }
        }
        SplPointerOp::Approve { delegate, .. } => {
            if *delegate == [0u8; 32] {
                return Err("SPL pointer approve delegate cannot be zero address".to_string());
            }
        }
        SplPointerOp::TransferFrom { owner, to, amount } => {
            if *owner == [0u8; 32] {
                return Err("SPL pointer transfer_from owner cannot be zero address".to_string());
            }
            if *to == [0u8; 32] {
                return Err(
                    "SPL pointer transfer_from recipient cannot be zero address".to_string()
                );
            }
            if *amount == 0 {
                return Err("SPL pointer transfer_from amount must be non-zero".to_string());
            }
        }
        SplPointerOp::BalanceOf { .. } | SplPointerOp::Allowance { .. } => {}
    }
    Ok(())
}

/// Encode an [`SplPointerOp`] for submission to an SVM pointer address.
pub fn encode_spl_pointer_op(op: &SplPointerOp) -> Result<Vec<u8>, String> {
    validate_spl_pointer_op(op)?;
    serde_json::to_vec(op).map_err(|e| format!("SPL pointer encode error: {e}"))
}

/// Decode an [`SplPointerOp`] received at an SVM pointer address.
pub fn decode_spl_pointer_op(bytes: &[u8]) -> Result<SplPointerOp, String> {
    if bytes.is_empty() {
        return Err("SPL pointer decode error: empty payload".to_string());
    }
    if bytes.len() > MAX_SPL_POINTER_OP_BYTES {
        return Err(format!(
            "SPL pointer decode error: payload size {} exceeds cap {}",
            bytes.len(),
            MAX_SPL_POINTER_OP_BYTES
        ));
    }
    let op: SplPointerOp =
        serde_json::from_slice(bytes).map_err(|e| format!("SPL pointer decode error: {e}"))?;
    validate_spl_pointer_op(&op)?;
    Ok(op)
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

    #[test]
    fn spl_pointer_allows_zero_amount_approve_for_revocation_and_valid_transfer_from() {
        let revoke = SplPointerOp::Approve {
            delegate: [0x12; 32],
            amount: 0,
        };
        let raw = encode_spl_pointer_op(&revoke).unwrap();
        assert_eq!(decode_spl_pointer_op(&raw).unwrap(), revoke);

        let tf = SplPointerOp::TransferFrom {
            owner: [0x11; 32],
            to: [0x22; 32],
            amount: 77,
        };
        let raw_tf = encode_spl_pointer_op(&tf).unwrap();
        assert_eq!(decode_spl_pointer_op(&raw_tf).unwrap(), tf);
    }

    #[test]
    fn red_spl_pointer_rejects_oversized_valid_json_and_empty_payload() {
        assert!(decode_spl_pointer_op(&[]).is_err());

        let valid = encode_spl_pointer_op(&SplPointerOp::BalanceOf { owner: [0x55; 32] }).unwrap();
        let mut padded = vec![b' '; MAX_SPL_POINTER_OP_BYTES + 16];
        padded.extend_from_slice(&valid);
        let err = decode_spl_pointer_op(&padded).unwrap_err();
        assert!(err.contains("exceeds cap"), "unexpected err: {err}");
    }

    #[test]
    fn red_spl_pointer_rejects_unknown_json_fields() {
        let raw = br#"{"approve":{"delegate":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"amount":10,"smuggled":true}}"#;
        assert!(decode_spl_pointer_op(raw).is_err());
    }

    #[test]
    fn red_spl_pointer_rejects_zero_recipient_and_zero_amount() {
        let zero_to = SplPointerOp::Transfer {
            to: [0u8; 32],
            amount: 100,
        };
        assert!(encode_spl_pointer_op(&zero_to).is_err());
        let raw_zero_to = serde_json::to_vec(&zero_to).unwrap();
        assert!(decode_spl_pointer_op(&raw_zero_to).is_err());

        let zero_amt = SplPointerOp::Transfer {
            to: [0x11; 32],
            amount: 0,
        };
        assert!(encode_spl_pointer_op(&zero_amt).is_err());
        let raw_zero_amt = serde_json::to_vec(&zero_amt).unwrap();
        assert!(decode_spl_pointer_op(&raw_zero_amt).is_err());
    }

    #[test]
    fn red_spl_pointer_rejects_zero_delegate_and_invalid_transfer_from() {
        let zero_del = SplPointerOp::Approve {
            delegate: [0u8; 32],
            amount: 10,
        };
        let raw_del = serde_json::to_vec(&zero_del).unwrap();
        assert!(decode_spl_pointer_op(&raw_del).is_err());

        let zero_owner = SplPointerOp::TransferFrom {
            owner: [0u8; 32],
            to: [0x22; 32],
            amount: 10,
        };
        let raw_owner = serde_json::to_vec(&zero_owner).unwrap();
        assert!(decode_spl_pointer_op(&raw_owner).is_err());

        let zero_to = SplPointerOp::TransferFrom {
            owner: [0x11; 32],
            to: [0u8; 32],
            amount: 10,
        };
        let raw_to = serde_json::to_vec(&zero_to).unwrap();
        assert!(decode_spl_pointer_op(&raw_to).is_err());

        let zero_amt = SplPointerOp::TransferFrom {
            owner: [0x11; 32],
            to: [0x22; 32],
            amount: 0,
        };
        let raw_amt = serde_json::to_vec(&zero_amt).unwrap();
        assert!(decode_spl_pointer_op(&raw_amt).is_err());
    }
}
