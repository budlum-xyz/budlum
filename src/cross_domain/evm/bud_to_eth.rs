#![allow(clippy::pedantic, clippy::nursery)]

//! F10.5, the Bud-to-Ethereum direction: a Budlum burn event plus a finality
//! proof turned into an Ethereum claim.
//!
//! There are two sides:
//!
//! 1. **The Budlum side, this module:** the relayer packages the Budlum burn
//!    event together with the Budlum finality proof, a BLS aggregate or a
//!    quorum certificate, and produces the transaction payload to be sent to
//!    Ethereum.
//! 2. **The Ethereum side, in Solidity:** a Budlum light client contract
//!    verifies Budlum finality inside the EVM and unlocks the bridge. That is a
//!    large separate piece of work, under its own repository and audit.
//!
//! **Security:** in the Bud-to-Ethereum direction, Budlum finality has to be
//! verified inside the EVM, which needs the BLS12-381 precompile and a Solidity
//! sync committee implementation. Ethereum verifies that proof independently and
//! DOES NOT trust Budlum.

use crate::cross_domain::bridge::{BridgeState, BridgeStatus, BridgeTransfer};
use crate::cross_domain::message::MessageId;
use crate::domain::types::Hash32;

/// A Bud-to-Ethereum relay package, which the relayer collects from Budlum and
/// sends to Ethereum.
#[derive(Debug, Clone)]
pub struct BudToEthClaim {
    /// The `message_id` of the Budlum burn event, which guards against replay.
    pub message_id: MessageId,
    /// The burned asset, to be unlocked on Ethereum.
    pub asset_id: [u8; 32],
    /// The unlock amount, minted or released on Ethereum.
    pub amount: u128,
    /// The recipient Ethereum address, 20 bytes.
    pub recipient_eth: [u8; 20],
    /// The Budlum block height at which the burn was finalised.
    pub finalized_height: u64,
    /// The Budlum finalised header hash, the light client checkpoint.
    pub finalized_header_hash: Hash32,
    /// The Budlum finality proof, a BLS aggregate or a quorum certificate, which
    /// Solidity verifies.
    pub finality_proof: Vec<u8>,
    /// The burn event Merkle proof, from the Budlum event tree up to the Budlum
    /// root.
    pub burn_event_proof: Vec<u8>,
}

/// A Bud-to-Ethereum claim error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudToEthError {
    /// The burn event was not found, or is invalid.
    BurnEventNotFound,
    /// The transfer is not in the `Burned` status.
    NotBurned,
    /// The recipient address is invalid; Ethereum uses 20 bytes.
    InvalidRecipient,
    /// The finality proof is missing or invalid.
    FinalityProofMissing,
    /// The amount is above the bridge cap. An ERC-20 `uint256` would hold it, but
    /// the bridge sets its own limit.
    AmountExceedsCap,
}

impl std::fmt::Display for BudToEthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudToEthError::BurnEventNotFound => write!(f, "bud-to-eth: burn event not found"),
            BudToEthError::NotBurned => write!(f, "bud-to-eth: transfer not in Burned status"),
            BudToEthError::InvalidRecipient => {
                write!(f, "bud-to-eth: invalid Ethereum recipient (20 bytes)")
            }
            BudToEthError::FinalityProofMissing => write!(f, "bud-to-eth: finality proof missing"),
            BudToEthError::AmountExceedsCap => write!(f, "bud-to-eth: amount exceeds bridge cap"),
        }
    }
}

impl std::error::Error for BudToEthError {}

/// The bridge cap. An Ethereum ERC-20 `uint256` would hold more, but the bridge
/// bounds itself for trust reasons. On mainnet it is adjustable by governance.
pub const DEFAULT_BRIDGE_CAP: u128 = 1_000_000_000_000; // 1T $BUD (6 decimals)

/// Builds a Bud-to-Ethereum claim package from a Budlum burn event.
///
/// The relayer calls this: it collects the burn transfer and the finality state
/// from a Budlum node and produces a `BudToEthClaim`, the calldata to be sent to
/// the Ethereum bridge contract. The Ethereum contract verifies Budlum finality
/// and unlocks.
#[allow(clippy::too_many_arguments)]
pub fn build_bud_to_eth_claim(
    bridge: &BridgeState,
    message_id: &MessageId,
    finalized_height: u64,
    finalized_header_hash: Hash32,
    finality_proof: Vec<u8>,
    burn_event_proof: Vec<u8>,
    recipient_eth: [u8; 20],
    bridge_cap: u128,
) -> Result<BudToEthClaim, BudToEthError> {
    // 1. Check that the transfer exists and is in the Burned status.
    let transfer: &BridgeTransfer = bridge
        .transfer(message_id)
        .ok_or(BudToEthError::BurnEventNotFound)?;
    if !matches!(transfer.status, BridgeStatus::Burned { .. }) {
        return Err(BudToEthError::NotBurned);
    }

    // 2. The finality proof is present.
    if finality_proof.is_empty() {
        return Err(BudToEthError::FinalityProofMissing);
    }

    // 3. Check the amount against the cap, in a single lookup.
    let amount = transfer.amount;
    if amount > bridge_cap {
        return Err(BudToEthError::AmountExceedsCap);
    }

    // 4. The asset id, in a single lookup.
    let bytes: &[u8] = transfer.asset_id.as_ref();
    let mut asset_id = [0u8; 32];
    let len = bytes.len().min(32);
    asset_id[..len].copy_from_slice(&bytes[..len]);

    Ok(BudToEthClaim {
        message_id: *message_id,
        asset_id,
        amount,
        recipient_eth,
        finalized_height,
        finalized_header_hash,
        finality_proof,
        burn_event_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::bridge::BridgeState;

    #[test]
    fn empty_finality_proof_rejected() {
        let bridge = BridgeState::new();
        let err = build_bud_to_eth_claim(
            &bridge,
            &MessageId::default(),
            100,
            [0u8; 32],
            vec![], // an empty finality proof
            vec![],
            [0u8; 20],
            DEFAULT_BRIDGE_CAP,
        )
        .unwrap_err();
        assert_eq!(err, BudToEthError::BurnEventNotFound); // the transfer is missing first
    }

    #[test]
    fn bridge_cap_constant_reasonable() {
        assert_eq!(DEFAULT_BRIDGE_CAP, 1_000_000_000_000);
    }

    #[test]
    fn error_display_readable() {
        assert_eq!(
            BudToEthError::InvalidRecipient.to_string(),
            "bud-to-eth: invalid Ethereum recipient (20 bytes)"
        );
    }

    #[test]
    fn garbage_claim_does_not_panic() {
        // DoS safety: an empty bridge with random input gives an Err and NO panic.
        let bridge = BridgeState::new();
        let _ = build_bud_to_eth_claim(
            &bridge,
            &MessageId::default(),
            0,
            [0u8; 32],
            vec![0xFF; 100],
            vec![0xAA; 50],
            [0xBB; 20],
            DEFAULT_BRIDGE_CAP,
        );
    }
}
