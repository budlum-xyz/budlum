//! V5 transfers the node accepts.
//!
//! A wallet built on this crate (browser, mobile) signs a transfer here and
//! submits the JSON [`signed_transfer_json`] returns through
//! `bud_sendRawTransaction`. The signing hash is the node's
//! `Transaction::signing_hash` for a V5 `Transfer`: SHA3-256 over the domain
//! tag `BDLM_TX_V5` and the preimage below, fields little endian. Both sides
//! pin the same test vector, so a change on either side fails a test.

use crate::Wallet;
use sha3::{Digest, Sha3_256};

/// The signature version of an ML-DSA-87 single-signer transaction.
pub const SIGNATURE_VERSION_V5: u32 = 5;
/// The signature version of a composite (ML-DSA-87 and Ed25519) transaction.
pub const SIGNATURE_VERSION_V7: u32 = 7;
/// The node's type tag of `TransactionType::Transfer`.
const TRANSFER_TAG: u8 = 0;

/// A transfer before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTransfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub max_fee: u64,
    pub priority_fee: u64,
    pub nonce: u64,
    pub timestamp_ms: u128,
    pub chain_id: u64,
}

impl UnsignedTransfer {
    /// The hash the node verifies the signature over (V5).
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        self.signing_hash_for(SIGNATURE_VERSION_V5, b"BDLM_TX_V5")
    }

    /// The hash of the V7 composite transaction (`BDLM_TX_V7`).
    #[must_use]
/// exposed for: the wallet crate's SDK surface — in-tree readers land with the wallet wiring wave.
    pub fn signing_hash_v7(&self) -> [u8; 32] {
        self.signing_hash_for(SIGNATURE_VERSION_V7, b"BDLM_TX_V7")
    }

    fn signing_hash_for(&self, version: u32, domain: &[u8]) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(160);
        preimage.push(TRANSFER_TAG);
        preimage.extend_from_slice(&self.from);
        preimage.extend_from_slice(&self.to);
        for value in [
            self.amount,
            self.fee,
            self.max_fee,
            self.priority_fee,
            self.nonce,
        ] {
            preimage.extend_from_slice(&value.to_le_bytes());
        }
        // `data`: a length-prefixed byte string, empty for a transfer.
        preimage.extend_from_slice(&0u64.to_le_bytes());
        preimage.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        preimage.extend_from_slice(&self.chain_id.to_le_bytes());
        preimage.extend_from_slice(&version.to_le_bytes());
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(&preimage);
        hasher.finalize().into()
    }
}

/// A JSON array of bytes, the way the node's JSON reads a `Vec<u8>`.
fn byte_array(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("[{}]", items.join(","))
}

/// Sign `transfer` with `wallet` and return the transaction JSON
/// `bud_sendRawTransaction` takes. The sender is the wallet's address,
/// whatever `transfer.from` held.
#[must_use]
pub fn signed_transfer_json(wallet: &Wallet, transfer: &UnsignedTransfer) -> String {
    let mut transfer = transfer.clone();
    transfer.from = wallet.address();
    let hash = transfer.signing_hash();
    let signature = wallet.sign(&hash);
    let public_key = wallet.public_key();
    format!(
        concat!(
            "{{\"from\":\"{from}\",\"to\":\"{to}\",\"amount\":{amount},\"fee\":{fee},",
            "\"max_fee\":{max_fee},\"priority_fee\":{priority_fee},\"nonce\":{nonce},",
            "\"data\":[],\"timestamp\":{timestamp},\"hash\":\"{hash}\",",
            "\"signature\":{signature},\"signer_public_key\":{public_key},",
            "\"authorization\":null,\"chain_id\":{chain_id},",
            "\"signature_version\":{version},\"tx_type\":\"Transfer\"}}"
        ),
        from = hex::encode(transfer.from),
        to = hex::encode(transfer.to),
        amount = transfer.amount,
        fee = transfer.fee,
        max_fee = transfer.max_fee,
        priority_fee = transfer.priority_fee,
        nonce = transfer.nonce,
        timestamp = transfer.timestamp_ms,
        hash = hex::encode(hash),
        signature = byte_array(signature.as_ref()),
        public_key = byte_array(public_key.as_ref()),
        chain_id = transfer.chain_id,
        version = SIGNATURE_VERSION_V5,
    )
}

/// Sign `transfer` as a V7 composite transaction and return the JSON
/// `bud_sendRawTransaction` takes. The sender is the account's V3
/// address, whatever `transfer.from` held. `rnd` is 32 fresh random bytes for
/// the hedged ML-DSA signature.
///
/// # Errors
///
/// The signing error text when the suite cannot sign.
/// exposed for: the wallet crate's SDK surface — in-tree readers land with the wallet wiring wave.
pub fn signed_transfer_v7_json(
    account: &crate::crypto::key_derivation::UserAccount,
    transfer: &UnsignedTransfer,
    rnd: &[u8; 32],
) -> Result<String, String> {
    let mut transfer = transfer.clone();
    transfer.from = account.address;
    let hash = transfer.signing_hash_v7();
    let signature = account
        .signing
        .sign(crate::crypto::ctx::TX_V7, &hash, rnd)
        .map_err(|e| e.to_string())?;
    // The witness key is the composite key followed by the recovery digest.
    let mut witness_key = account.public.encode();
    witness_key.extend_from_slice(&crate::crypto::address_v3::key_digest(
        &account.recovery_public_key,
    ));
    Ok(format!(
        concat!(
            "{{\"from\":\"{from}\",\"to\":\"{to}\",\"amount\":{amount},\"fee\":{fee},",
            "\"max_fee\":{max_fee},\"priority_fee\":{priority_fee},\"nonce\":{nonce},",
            "\"data\":[],\"timestamp\":{timestamp},\"hash\":\"{hash}\",",
            "\"signature\":{signature},\"signer_public_key\":{public_key},",
            "\"authorization\":null,\"chain_id\":{chain_id},",
            "\"signature_version\":{version},\"tx_type\":\"Transfer\"}}"
        ),
        from = hex::encode(transfer.from),
        to = hex::encode(transfer.to),
        amount = transfer.amount,
        fee = transfer.fee,
        max_fee = transfer.max_fee,
        priority_fee = transfer.priority_fee,
        nonce = transfer.nonce,
        timestamp = transfer.timestamp_ms,
        hash = hex::encode(hash),
        signature = byte_array(&signature.encode()),
        public_key = byte_array(&witness_key),
        chain_id = transfer.chain_id,
        version = SIGNATURE_VERSION_V7,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The V7 vector the node pins in `src/wallet/mod.rs`.
    #[test]
    fn the_v7_signing_hash_matches_the_node_vector() {
        let transfer = UnsignedTransfer {
            from: [0x11; 32],
            to: [0x22; 32],
            amount: 1_000_000,
            fee: 1_000,
            max_fee: 1_000,
            priority_fee: 0,
            nonce: 3,
            timestamp_ms: 1_800_000_000_000,
            chain_id: 45_261,
        };
        assert_eq!(
            hex::encode(transfer.signing_hash_v7()),
            "616f18ed47f2a635b224c368855a4e21a8fe6231b7353c6465ac32ce964de3f7"
        );
    }

    #[test]
    fn a_signed_v7_transfer_names_the_v3_address_and_version_7() {
        use crate::crypto::key_derivation::RootSecret;
        let account = RootSecret::derive(&[7u8; 32], "")
            .unwrap()
            .user_account(0, 0)
            .unwrap();
        let transfer = UnsignedTransfer {
            from: [0u8; 32],
            to: [0x22; 32],
            amount: 5,
            fee: 1,
            max_fee: 1,
            priority_fee: 0,
            nonce: 0,
            timestamp_ms: 1,
            chain_id: 45_261,
        };
        let json = signed_transfer_v7_json(&account, &transfer, &[1u8; 32]).unwrap();
        assert!(json.contains(&format!("\"from\":\"{}\"", hex::encode(account.address))));
        assert!(json.contains("\"signature_version\":7"));
        let mut named = transfer;
        named.from = account.address;
        assert!(json.contains(&hex::encode(named.signing_hash_v7())));
    }

    /// The same vector the node pins in `src/wallet/mod.rs`
    /// (`the_v5_transfer_signing_hash_matches_the_published_vector`).
    #[test]
    fn the_signing_hash_matches_the_node_vector() {
        let transfer = UnsignedTransfer {
            from: [0x11; 32],
            to: [0x22; 32],
            amount: 1_000_000,
            fee: 1_000,
            max_fee: 1_000,
            priority_fee: 0,
            nonce: 3,
            timestamp_ms: 1_800_000_000_000,
            chain_id: 45_261,
        };
        assert_eq!(
            hex::encode(transfer.signing_hash()),
            "fb982bceadd9bbd150970eda0e6103abcbba874b3d3622452d8e6a0bb1c22d8e"
        );
    }

    #[test]
    fn a_signed_transfer_names_the_wallet_and_carries_the_hash() {
        let wallet = Wallet::from_entropy(&[7u8; 32]).expect("a 256-bit entropy");
        let transfer = UnsignedTransfer {
            from: [0u8; 32],
            to: [0x22; 32],
            amount: 5,
            fee: 1,
            max_fee: 1,
            priority_fee: 0,
            nonce: 0,
            timestamp_ms: 1,
            chain_id: 45_261,
        };
        let json = signed_transfer_json(&wallet, &transfer);
        assert!(json.contains(&format!(
            "\"from\":\"{}\"",
            wallet.address_hex().trim_start_matches("0x")
        )));
        let mut named = transfer.clone();
        named.from = wallet.address();
        assert!(json.contains(&hex::encode(named.signing_hash())));
        assert!(json.contains("\"signature_version\":5"));
    }
}
