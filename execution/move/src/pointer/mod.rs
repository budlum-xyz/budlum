//! Stateless Aptos `fungible_asset` and `coin` pointer codec (`Section 8.8`).
//!
//! A Move asset pointer holds **zero** local `CoinStore` / `FungibleStore`
//! balances and **zero** local allowance resources in `ee/move/state`: every
//! operation delegates synchronously to the asset's `home_ee`.

use serde::{Deserialize, Serialize};

/// Hard byte cap on a serialized [`MovePointerOp`] JSON envelope (4 KiB).
pub const MAX_MOVE_POINTER_OP_BYTES: usize = 4_096;

/// Move pointer flavor (`0x1::fungible_asset` vs `0x1::coin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovePointerFlavor {
    FungibleAsset,
    Coin,
}

/// Canonical stateless Move pointer operations routed by the UEL coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MovePointerOp {
    Transfer {
        flavor: MovePointerFlavor,
        to: [u8; 32],
        amount: u128,
    },
    Approve {
        flavor: MovePointerFlavor,
        spender: [u8; 32],
        amount: u128,
    },
    TransferFrom {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
        to: [u8; 32],
        amount: u128,
    },
    Balance {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
    },
    Allowance {
        flavor: MovePointerFlavor,
        owner: [u8; 32],
        spender: [u8; 32],
    },
}

/// Validate semantic invariants of a [`MovePointerOp`].
///
/// Rejects zero-address recipients/spenders/owners and zero-value transfers on
/// state-mutating operations while permitting `Approve { amount: 0 }` for
/// allowance revocation and read-only `Balance`/`Allowance` queries.
pub fn validate_move_pointer_op(op: &MovePointerOp) -> Result<(), String> {
    match op {
        MovePointerOp::Transfer { to, amount, .. } => {
            if *to == [0u8; 32] {
                return Err("Move pointer transfer recipient cannot be zero address".to_string());
            }
            if *amount == 0 {
                return Err("Move pointer transfer amount must be non-zero".to_string());
            }
        }
        MovePointerOp::Approve { spender, .. } => {
            if *spender == [0u8; 32] {
                return Err("Move pointer approve spender cannot be zero address".to_string());
            }
        }
        MovePointerOp::TransferFrom {
            owner, to, amount, ..
        } => {
            if *owner == [0u8; 32] {
                return Err("Move pointer transfer_from owner cannot be zero address".to_string());
            }
            if *to == [0u8; 32] {
                return Err(
                    "Move pointer transfer_from recipient cannot be zero address".to_string(),
                );
            }
            if *amount == 0 {
                return Err("Move pointer transfer_from amount must be non-zero".to_string());
            }
        }
        MovePointerOp::Balance { .. } | MovePointerOp::Allowance { .. } => {}
    }
    Ok(())
}

/// Encode a [`MovePointerOp`] for submission to a Move pointer address.
pub fn encode_move_pointer_op(op: &MovePointerOp) -> Result<Vec<u8>, String> {
    validate_move_pointer_op(op)?;
    serde_json::to_vec(op).map_err(|e| format!("Move pointer encode error: {e}"))
}

/// Decode a [`MovePointerOp`] received at a Move pointer address.
pub fn decode_move_pointer_op(bytes: &[u8]) -> Result<MovePointerOp, String> {
    if bytes.is_empty() {
        return Err("Move pointer decode error: empty payload".to_string());
    }
    if bytes.len() > MAX_MOVE_POINTER_OP_BYTES {
        return Err(format!(
            "Move pointer decode error: payload size {} exceeds cap {}",
            bytes.len(),
            MAX_MOVE_POINTER_OP_BYTES
        ));
    }
    let op: MovePointerOp =
        serde_json::from_slice(bytes).map_err(|e| format!("Move pointer decode error: {e}"))?;
    validate_move_pointer_op(&op)?;
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_pointer_op_roundtrips_for_fungible_asset_and_coin() {
        for flavor in [MovePointerFlavor::FungibleAsset, MovePointerFlavor::Coin] {
            let op = MovePointerOp::Transfer {
                flavor,
                to: [0xCD; 32],
                amount: 99_000,
            };
            let Ok(raw) = encode_move_pointer_op(&op) else {
                panic!("encode");
            };
            let Ok(back) = decode_move_pointer_op(&raw) else {
                panic!("decode");
            };
            assert_eq!(back, op);
        }
    }

    #[test]
    fn move_pointer_allows_zero_amount_approve_and_valid_transfer_from() {
        let revoke = MovePointerOp::Approve {
            flavor: MovePointerFlavor::Coin,
            spender: [0x33; 32],
            amount: 0,
        };
        let raw = encode_move_pointer_op(&revoke).unwrap();
        assert_eq!(decode_move_pointer_op(&raw).unwrap(), revoke);

        let tf = MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::FungibleAsset,
            owner: [0x11; 32],
            to: [0x22; 32],
            amount: 42,
        };
        let raw_tf = encode_move_pointer_op(&tf).unwrap();
        assert_eq!(decode_move_pointer_op(&raw_tf).unwrap(), tf);
    }

    #[test]
    fn red_move_pointer_rejects_oversized_valid_json_and_empty_payload() {
        assert!(decode_move_pointer_op(&[]).is_err());

        let valid = encode_move_pointer_op(&MovePointerOp::Balance {
            flavor: MovePointerFlavor::Coin,
            owner: [0x55; 32],
        })
        .unwrap();
        let mut padded = vec![b' '; MAX_MOVE_POINTER_OP_BYTES + 16];
        padded.extend_from_slice(&valid);
        let err = decode_move_pointer_op(&padded).unwrap_err();
        assert!(err.contains("exceeds cap"), "unexpected err: {err}");
    }

    #[test]
    fn red_move_pointer_rejects_unknown_json_fields() {
        let raw = br#"{"approve":{"flavor":"coin","spender":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"amount":10,"evil":true}}"#;
        assert!(decode_move_pointer_op(raw).is_err());
    }

    #[test]
    fn red_move_pointer_rejects_zero_recipient_and_zero_amount() {
        let zero_to = MovePointerOp::Transfer {
            flavor: MovePointerFlavor::Coin,
            to: [0u8; 32],
            amount: 100,
        };
        assert!(encode_move_pointer_op(&zero_to).is_err());
        let raw_zero_to = serde_json::to_vec(&zero_to).unwrap();
        assert!(decode_move_pointer_op(&raw_zero_to).is_err());

        let zero_amt = MovePointerOp::Transfer {
            flavor: MovePointerFlavor::FungibleAsset,
            to: [0x11; 32],
            amount: 0,
        };
        assert!(encode_move_pointer_op(&zero_amt).is_err());
        let raw_zero_amt = serde_json::to_vec(&zero_amt).unwrap();
        assert!(decode_move_pointer_op(&raw_zero_amt).is_err());
    }

    #[test]
    fn red_move_pointer_rejects_zero_spender_and_invalid_transfer_from() {
        let zero_sp = MovePointerOp::Approve {
            flavor: MovePointerFlavor::Coin,
            spender: [0u8; 32],
            amount: 10,
        };
        let raw_sp = serde_json::to_vec(&zero_sp).unwrap();
        assert!(decode_move_pointer_op(&raw_sp).is_err());

        let zero_owner = MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::FungibleAsset,
            owner: [0u8; 32],
            to: [0x22; 32],
            amount: 10,
        };
        let raw_owner = serde_json::to_vec(&zero_owner).unwrap();
        assert!(decode_move_pointer_op(&raw_owner).is_err());

        let zero_to = MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::Coin,
            owner: [0x11; 32],
            to: [0u8; 32],
            amount: 10,
        };
        let raw_to = serde_json::to_vec(&zero_to).unwrap();
        assert!(decode_move_pointer_op(&raw_to).is_err());

        let zero_amt = MovePointerOp::TransferFrom {
            flavor: MovePointerFlavor::Coin,
            owner: [0x11; 32],
            to: [0x22; 32],
            amount: 0,
        };
        let raw_amt = serde_json::to_vec(&zero_amt).unwrap();
        assert!(decode_move_pointer_op(&raw_amt).is_err());
    }
}
