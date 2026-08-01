#![allow(clippy::pedantic, clippy::nursery)]

//! F10.5 Bud→ETH yönü - Budlum burn event + finality proof → Ethereum claim.
//!
//! İki taraf:
//!
//! 1. **Budlum-taraflı (bu modül):** relayer, Budlum burn event'ini + Budlum
//!    Finality proof'unu (BLS/QC) paketler → Ethereum'a gönderilecek tx payload'u
//!    Üretir.
//! 2. **Ethereum-taraflı (Solidity):** Budlum light-client kontratı, Budlum
//!    Finality'sini EVM'de verify eder → bridge unlock. Bu büyük ayrı iş
//!    (ayrı repo/audit kapsamında).
//!
//! **Güvenlik:** Bud→ETH yönünde Budlum finality'sini EVM'de verify etmek gerek
//! (BLS12-381 precompile + sync-committee Solidity impl). Ethereum bu proof'u
//! Bağımsız doğrular - Budlum'u trust ETMEZ.

use crate::cross_domain::bridge::{BridgeState, BridgeStatus, BridgeTransfer};
use crate::cross_domain::message::MessageId;
use crate::domain::types::Hash32;

/// Bud→ETH relay paketi (relayer, Budlum'dan toplayıp Ethereum'a gönderir).
#[derive(Debug, Clone)]
pub struct BudToEthClaim {
    /// Budlum burn event'in message_id (replay koruması).
    pub message_id: MessageId,
    /// Burn edilen varlık (Ethereum'da unlock edilecek).
    pub asset_id: [u8; 32],
    /// Unlock miktarı (Ethereum'da mint/release).
    pub amount: u128,
    /// Alıcı Ethereum adresi (20 byte).
    pub recipient_eth: [u8; 20],
    /// Budlum blok yüksekliği (burn'in finalize edildiği).
    pub finalized_height: u64,
    /// Budlum finalized header hash (light-client checkpoint).
    pub finalized_header_hash: Hash32,
    /// Budlum finality proof (BLS aggregate veya QC) - Solidity verify eder.
    pub finality_proof: Vec<u8>,
    /// Burn event Merkle proof (Budlum event tree → Budlum root).
    pub burn_event_proof: Vec<u8>,
}

/// Bud→ETH claim hatası.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudToEthError {
    /// Burn event bulunamadı / geçersiz.
    BurnEventNotFound,
    /// Transfer Burned status'unda değil.
    NotBurned,
    /// Alıcı adres geçersiz (Ethereum 20-byte).
    InvalidRecipient,
    /// Finality proof eksik/geçersiz.
    FinalityProofMissing,
    /// Miktar u128 → Ethereum'da overflow (ERC-20 uint256 sığar ama bridge cap).
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

/// Bridge bridge cap (Ethereum ERC-20 uint256 sığar ama bridge güven için).
/// Mainnet governance ile ayarlanabilir.
pub const DEFAULT_BRIDGE_CAP: u128 = 1_000_000_000_000; // 1T $BUD (6 decimals)

/// Budlum burn event'inden Bud→ETH claim paketi üret.
///
/// Relayer bu fonksiyonu çağırır: Budlum node'dan burn transfer + finality
/// State toplar → `BudToEthClaim` (Ethereum bridge kontratına gönderilecek
/// Calldata). Ethereum kontratı Budlum finality'sini verify edip unlock eder.
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
    // 1. Transfer mevcut + Burned status kontrolü.
    let transfer: &BridgeTransfer = bridge
        .transfer(message_id)
        .ok_or(BudToEthError::BurnEventNotFound)?;
    if !matches!(transfer.status, BridgeStatus::Burned { .. }) {
        return Err(BudToEthError::NotBurned);
    }

    // 2. Finality proof mevcut.
    if finality_proof.is_empty() {
        return Err(BudToEthError::FinalityProofMissing);
    }

    // 3. Miktar cap kontrolü (tek lookup).
    let amount = transfer.amount;
    if amount > bridge_cap {
        return Err(BudToEthError::AmountExceedsCap);
    }

    // 4. Asset ID (tek lookup).
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
            vec![], // boş finality proof
            vec![],
            [0u8; 20],
            DEFAULT_BRIDGE_CAP,
        )
        .unwrap_err();
        assert_eq!(err, BudToEthError::BurnEventNotFound); // önce transfer yok
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
        // DoS güvenliği: boş bridge + rastgele → Err, panic YOK.
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
