//! Stateless Aptos `fungible_asset` and `coin` pointer codec (`WP-52`, `Section 8.8`).
//!
//! A Move asset pointer holds **zero** local `CoinStore` / `FungibleStore`
//! balances and **zero** local allowance resources in `ee/move/state`: every
//! operation delegates synchronously to the asset's `home_ee`.

use serde::{Deserialize, Serialize};

/// Move pointer flavor (`0x1::fungible_asset` vs `0x1::coin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovePointerFlavor {
    FungibleAsset,
    Coin,
}

/// Canonical stateless Move pointer operations routed by the UEL coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Encode a [`MovePointerOp`] for submission to a Move pointer address.
pub fn encode_move_pointer_op(op: &MovePointerOp) -> Result<Vec<u8>, String> {
    serde_json::to_vec(op).map_err(|e| format!("Move pointer encode error: {e}"))
}

/// Decode a [`MovePointerOp`] received at a Move pointer address.
pub fn decode_move_pointer_op(bytes: &[u8]) -> Result<MovePointerOp, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("Move pointer decode error: {e}"))
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
}
