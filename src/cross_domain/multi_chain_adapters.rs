//! Multi-family [`ChainAdapter`] implementations extending the Universal Relayer
//! beyond EVM to Bitcoin SPV, Cosmos ICS-23/IAVL, and Solana bank-hash proofs.
//!
//! Each adapter pairs deterministic proof assembly (`assemble_*_observation`)
//! with network-free, trusted-anchor verification (`verify_observation`) so the
//! relayer and consensus verification paths share one fail-closed implementation:
//! - [`BitcoinSpvChainAdapter`] delegates raw transaction inclusion to
//!   [`crate::cross_domain::external::bitcoin_spv::verify_spv_raw_tx_inclusion`]
//!   (enforcing CVE-2017-12842 64-byte tx refusal and CVE-2012-2459 duplicate
//!   sibling refusal).
//! - [`CosmosIcs23ChainAdapter`] verifies ICS-23/IAVL SHA-256 existence proofs
//!   against an anchored Tendermint `app_hash` and enforces a non-empty store
//!   key prefix to prevent cross-module key confusion.
//! - [`SolanaBankChainAdapter`] verifies Solana `bank_hash` commitment binding
//!   over `(parent_bank_hash, accounts_delta_root, tx_root, slot)` together with
//!   account and transaction Merkle inclusion proofs.

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::chain_adapter::{AdapterError, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::external::bitcoin_spv::{sha256d, verify_spv_raw_tx_inclusion};
use crate::domain::types::Hash32;

/// Default custom domain identifier assigned to Cosmos ICS-23 chains.
pub const COSMOS_DEFAULT_CHAIN_DOMAIN_ID: u32 = 118;

/// Minimum confirmation depth required for Bitcoin SPV relay admissibility.
pub const MIN_BITCOIN_SPV_CONFIRMATIONS: u32 = 6;

/// Hard decode cap for serialized family receipt proof payloads (128 KiB).
const MAX_FAMILY_PROOF_BYTES: u64 = 128 * 1024;

/// Maximum ICS-23 inner operations allowed in one existence proof.
const MAX_ICS23_INNER_OPS: usize = 64;

/// Maximum byte length for ICS-23 prefix/suffix slices and store keys/values.
const MAX_ICS23_FIELD_BYTES: usize = 4096;

/// Maximum Merkle depth for Solana account and transaction inclusion branches.
const MAX_SOLANA_BRANCH_DEPTH: usize = 64;

fn decode_bounded<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AdapterError> {
    bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_FAMILY_PROOF_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| {
            AdapterError::ProofVerificationFailed(format!(
                "family proof payload failed bounded decode within {MAX_FAMILY_PROOF_BYTES} bytes: {e}"
            ))
        })
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, AdapterError> {
    let bytes = bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_FAMILY_PROOF_BYTES)
        .serialize(value)
        .map_err(|e| {
            AdapterError::ProofGenerationFailed(format!("family proof encode failed: {e}"))
        })?;
    Ok(bytes)
}

fn update_sha256_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn encode_uvarint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn encode_svarint(v: i64, out: &mut Vec<u8>) {
    let zigzag = ((v << 1) ^ (v >> 63)) as u64;
    encode_uvarint(zigzag, out);
}

// ============================================================================
// 1. Bitcoin SPV ChainAdapter
// ============================================================================

/// Serialized Bitcoin SPV receipt proof carried inside `RelayerExternalResult::receipt_proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinSpvReceiptProof {
    /// Raw legacy-stripped Bitcoin transaction bytes (non-empty, never 64 bytes).
    pub stripped_tx: Vec<u8>,
    /// Zero-based transaction index inside the Bitcoin block.
    pub tx_index: u32,
    /// Double-SHA256 Merkle sibling branch from `txid` up to `merkle_root`.
    pub branch: Vec<Hash32>,
    /// Verified confirmation depth of the containing block header.
    pub confirmations: u32,
    /// Whether this transaction is expected to occupy coinbase position (`tx_index == 0`).
    pub expect_coinbase: bool,
}

/// Assemble a Bitcoin SPV [`RelayerExternalResult`] carrying `proof` anchored to `merkle_root`.
///
/// # Errors
///
/// Fails closed if `merkle_root` is zero or if serialization exceeds the bounded proof cap.
pub fn assemble_bitcoin_spv_observation(
    proof: &BitcoinSpvReceiptProof,
    merkle_root: Hash32,
) -> Result<RelayerExternalResult, AdapterError> {
    if merkle_root == [0u8; 32] {
        return Err(AdapterError::ProofGenerationFailed(
            "Bitcoin SPV merkle_root anchor cannot be zero".into(),
        ));
    }
    let txid = sha256d(&proof.stripped_tx);
    let receipt_proof = encode_bounded(proof)?;
    Ok(RelayerExternalResult {
        chain: ExternalChain::Bitcoin,
        tx_hash: hex::encode(txid),
        success: true,
        message: None,
        receipt_proof,
        external_state_root: merkle_root,
    })
}

/// Fail-closed `ChainAdapter` for Bitcoin SPV transaction inclusion proofs.
#[derive(Debug, Clone)]
pub struct BitcoinSpvChainAdapter {
    trusted_merkle_root: Option<Hash32>,
    min_confirmations: u32,
}

impl BitcoinSpvChainAdapter {
    /// Create a Bitcoin SPV adapter anchored to an optional verified header `merkle_root`.
    #[must_use]
    pub const fn new(trusted_merkle_root: Option<Hash32>, min_confirmations: u32) -> Self {
        Self {
            trusted_merkle_root,
            min_confirmations,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for BitcoinSpvChainAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Bitcoin
    }

    fn trusted_observation_root(&self) -> Option<Hash32> {
        self.trusted_merkle_root
    }

    fn check_fit_for_relay(&self) -> Result<(), AdapterError> {
        let root = self.trusted_merkle_root.ok_or_else(|| {
            AdapterError::Other(
                "BitcoinSpvChainAdapter requires a trusted header merkle_root".into(),
            )
        })?;
        if root == [0u8; 32] {
            return Err(AdapterError::Other(
                "BitcoinSpvChainAdapter trusted merkle_root cannot be zero".into(),
            ));
        }
        if self.min_confirmations < MIN_BITCOIN_SPV_CONFIRMATIONS {
            return Err(AdapterError::Other(format!(
                "BitcoinSpvChainAdapter min_confirmations {} is below {MIN_BITCOIN_SPV_CONFIRMATIONS}",
                self.min_confirmations
            )));
        }
        Ok(())
    }

    async fn generate_receipt_proof(
        &self,
        _tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        Err(AdapterError::ProofGenerationFailed(
            "Bitcoin SPV proof generation requires raw transaction bytes via assemble_bitcoin_spv_observation"
                .into(),
        ))
    }

    fn verify_receipt_proof(
        &self,
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ProofVerificationFailed(
            "bare MerkleProof is refused for Bitcoin; supply a BitcoinSpvReceiptProof via verify_observation"
                .into(),
        ))
    }

    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        if result.chain != ExternalChain::Bitcoin {
            return Err(AdapterError::UnsupportedChain(result.chain));
        }
        if !result.success {
            return Err(AdapterError::ProofVerificationFailed(
                "Bitcoin external observation reported execution failure".into(),
            ));
        }
        let trusted_root = self.trusted_merkle_root.ok_or_else(|| {
            AdapterError::ProofVerificationFailed(
                "BitcoinSpvChainAdapter has no trusted merkle_root anchor".into(),
            )
        })?;
        if trusted_root == [0u8; 32] || result.external_state_root != trusted_root {
            return Err(AdapterError::ProofVerificationFailed(
                "Bitcoin observation state root does not match trusted header merkle_root".into(),
            ));
        }

        let payload: BitcoinSpvReceiptProof = decode_bounded(&result.receipt_proof)?;
        if payload.confirmations < self.min_confirmations {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Bitcoin confirmations {} below required {}",
                payload.confirmations, self.min_confirmations
            )));
        }
        let verified = verify_spv_raw_tx_inclusion(
            &payload.stripped_tx,
            &trusted_root,
            payload.tx_index,
            &payload.branch,
            payload.expect_coinbase,
        )
        .map_err(|e| AdapterError::ProofVerificationFailed(format!("Bitcoin SPV failed: {e}")))?;

        let expected_tx_hex = hex::encode(verified.txid);
        if result.tx_hash != expected_tx_hex {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Bitcoin observation tx_hash {} does not match verified txid {expected_tx_hex}",
                result.tx_hash
            )));
        }
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Err(AdapterError::SubmissionFailed(
            "offline BitcoinSpvChainAdapter refuses live network broadcast".into(),
        ))
    }

    async fn wait_for_confirmation(
        &self,
        _tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        Err(AdapterError::ConfirmationTimeout)
    }
}

// ============================================================================
// 2. Cosmos ICS-23 / IAVL ChainAdapter
// ============================================================================

/// Single ICS-23 inner tree step: `SHA256(prefix || child || suffix)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ics23InnerOp {
    /// Leading inner-node bytes (height/size/version varints and optional left sibling).
    pub prefix: Vec<u8>,
    /// Trailing inner-node bytes (optional right sibling).
    pub suffix: Vec<u8>,
}

/// Serialized Cosmos ICS-23/IAVL existence proof carried inside `RelayerExternalResult::receipt_proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosmosIcs23ReceiptProof {
    /// Full store key (must start with the adapter's configured `store_prefix`).
    pub store_key: Vec<u8>,
    /// Raw store value committed under `store_key`.
    pub value: Vec<u8>,
    /// IAVL leaf height (must be 0 for a leaf).
    pub iavl_height: i64,
    /// IAVL leaf version (`>= 1`).
    pub iavl_version: i64,
    /// IAVL leaf subtree size (must be 1 for a leaf).
    pub iavl_size: i64,
    /// Ordered ICS-23 inner operations folding the leaf up to `app_hash`.
    pub inner_ops: Vec<Ics23InnerOp>,
}

/// Compute the canonical Cosmos receipt binding hash (`BDLM_COSMOS_RECEIPT_TX_V1`)
/// over `(store_key, value, iavl_height, iavl_version, iavl_size)`.
#[must_use]
pub fn compute_cosmos_receipt_tx_hash(proof: &CosmosIcs23ReceiptProof) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_COSMOS_RECEIPT_TX_V1");
    update_sha256_len_prefixed(&mut hasher, &proof.store_key);
    update_sha256_len_prefixed(&mut hasher, &proof.value);
    hasher.update(proof.iavl_height.to_le_bytes());
    hasher.update(proof.iavl_version.to_le_bytes());
    hasher.update(proof.iavl_size.to_le_bytes());
    hasher.finalize().into()
}

/// Deterministically fold an ICS-23/IAVL existence proof to its 32-byte `app_hash`.
///
/// # Errors
///
/// Fails closed on empty/oversized keys or values, non-leaf height/size,
/// non-positive version, or excessive/oversized inner operations.
pub fn compute_ics23_existence_root(
    proof: &CosmosIcs23ReceiptProof,
) -> Result<Hash32, AdapterError> {
    if proof.store_key.is_empty() || proof.store_key.len() > MAX_ICS23_FIELD_BYTES {
        return Err(AdapterError::ProofVerificationFailed(
            "Cosmos ICS-23 store_key length out of bounds".into(),
        ));
    }
    if proof.value.is_empty() || proof.value.len() > MAX_ICS23_FIELD_BYTES {
        return Err(AdapterError::ProofVerificationFailed(
            "Cosmos ICS-23 value length out of bounds".into(),
        ));
    }
    if proof.iavl_height != 0 || proof.iavl_size != 1 || proof.iavl_version < 1 {
        return Err(AdapterError::ProofVerificationFailed(
            "Cosmos IAVL leaf requires height=0, size=1, version>=1".into(),
        ));
    }
    if proof.inner_ops.len() > MAX_ICS23_INNER_OPS {
        return Err(AdapterError::ProofVerificationFailed(format!(
            "Cosmos ICS-23 inner_ops count {} exceeds {MAX_ICS23_INNER_OPS}",
            proof.inner_ops.len()
        )));
    }

    // Standard IAVL leaf encoding:
    // SHA256(svarint(height) || svarint(size) || svarint(version) || uvarint(key.len) || key || uvarint(32) || SHA256(value))
    let val_hash: [u8; 32] = Sha256::digest(&proof.value).into();
    let mut leaf_preimage = Vec::with_capacity(64 + proof.store_key.len());
    encode_svarint(proof.iavl_height, &mut leaf_preimage);
    encode_svarint(proof.iavl_size, &mut leaf_preimage);
    encode_svarint(proof.iavl_version, &mut leaf_preimage);
    encode_uvarint(proof.store_key.len() as u64, &mut leaf_preimage);
    leaf_preimage.extend_from_slice(&proof.store_key);
    encode_uvarint(32, &mut leaf_preimage);
    leaf_preimage.extend_from_slice(&val_hash);

    let mut acc: Hash32 = Sha256::digest(&leaf_preimage).into();

    for op in &proof.inner_ops {
        if op.prefix.len() > MAX_ICS23_FIELD_BYTES || op.suffix.len() > MAX_ICS23_FIELD_BYTES {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos ICS-23 inner_op prefix/suffix exceeds size ceiling".into(),
            ));
        }
        if op.prefix.is_empty() && op.suffix.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos ICS-23 inner_op cannot have both empty prefix and empty suffix".into(),
            ));
        }
        // Prefix and suffix are separated by the fixed 32-byte child digest per ICS-23 InnerOp.
        let mut inner_buf = Vec::with_capacity(op.prefix.len() + 32 + op.suffix.len());
        inner_buf.extend_from_slice(&op.prefix);
        inner_buf.extend_from_slice(&acc);
        inner_buf.extend_from_slice(&op.suffix);
        acc = Sha256::digest(&inner_buf).into();
    }

    Ok(acc)
}

/// Assemble a Cosmos ICS-23 [`RelayerExternalResult`] anchored to `app_hash`.
///
/// # Errors
///
/// Fails closed if `app_hash` is zero or if serialization exceeds the bounded proof cap.
pub fn assemble_cosmos_ics23_observation(
    chain_domain_id: u32,
    proof: &CosmosIcs23ReceiptProof,
    app_hash: Hash32,
) -> Result<RelayerExternalResult, AdapterError> {
    if app_hash == [0u8; 32] {
        return Err(AdapterError::ProofGenerationFailed(
            "Cosmos app_hash anchor cannot be zero".into(),
        ));
    }
    let tx_hash = hex::encode(compute_cosmos_receipt_tx_hash(proof));
    let receipt_proof = encode_bounded(proof)?;
    Ok(RelayerExternalResult {
        chain: ExternalChain::Custom(chain_domain_id),
        tx_hash,
        success: true,
        message: None,
        receipt_proof,
        external_state_root: app_hash,
    })
}

/// Fail-closed `ChainAdapter` for Cosmos/Tendermint ICS-23 existence proofs.
#[derive(Debug, Clone)]
pub struct CosmosIcs23ChainAdapter {
    chain_domain_id: u32,
    store_prefix: Vec<u8>,
    trusted_app_hash: Option<Hash32>,
}

impl CosmosIcs23ChainAdapter {
    /// Create a Cosmos ICS-23 adapter bound to `chain_domain_id`, required
    /// `store_prefix`, and anchored Tendermint `trusted_app_hash`.
    #[must_use]
    pub const fn new(
        chain_domain_id: u32,
        store_prefix: Vec<u8>,
        trusted_app_hash: Option<Hash32>,
    ) -> Self {
        Self {
            chain_domain_id,
            store_prefix,
            trusted_app_hash,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for CosmosIcs23ChainAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Custom(self.chain_domain_id)
    }

    fn trusted_observation_root(&self) -> Option<Hash32> {
        self.trusted_app_hash
    }

    fn check_fit_for_relay(&self) -> Result<(), AdapterError> {
        if self.store_prefix.is_empty() || self.store_prefix.len() > MAX_ICS23_FIELD_BYTES {
            return Err(AdapterError::Other(
                "CosmosIcs23ChainAdapter requires a non-empty bounded store_prefix".into(),
            ));
        }
        let app_hash = self.trusted_app_hash.ok_or_else(|| {
            AdapterError::Other("CosmosIcs23ChainAdapter requires a trusted app_hash".into())
        })?;
        if app_hash == [0u8; 32] {
            return Err(AdapterError::Other(
                "CosmosIcs23ChainAdapter trusted app_hash cannot be zero".into(),
            ));
        }
        Ok(())
    }

    async fn generate_receipt_proof(
        &self,
        _tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        Err(AdapterError::ProofGenerationFailed(
            "Cosmos ICS-23 proof generation uses assemble_cosmos_ics23_observation".into(),
        ))
    }

    fn verify_receipt_proof(
        &self,
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ProofVerificationFailed(
            "bare MerkleProof is refused for Cosmos; supply CosmosIcs23ReceiptProof via verify_observation"
                .into(),
        ))
    }

    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        if result.chain != self.chain_type() {
            return Err(AdapterError::UnsupportedChain(result.chain));
        }
        if !result.success {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos external observation reported execution failure".into(),
            ));
        }
        let trusted_root = self.trusted_app_hash.ok_or_else(|| {
            AdapterError::ProofVerificationFailed(
                "CosmosIcs23ChainAdapter has no trusted app_hash anchor".into(),
            )
        })?;
        if trusted_root == [0u8; 32] || result.external_state_root != trusted_root {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos observation state root does not match trusted app_hash".into(),
            ));
        }

        let payload: CosmosIcs23ReceiptProof = decode_bounded(&result.receipt_proof)?;
        if !payload.store_key.starts_with(&self.store_prefix) {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos ICS-23 store_key does not match required store_prefix".into(),
            ));
        }
        let computed_root = compute_ics23_existence_root(&payload)?;
        if computed_root != trusted_root {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos ICS-23 folded root does not match trusted app_hash".into(),
            ));
        }
        let expected_tx_hex = hex::encode(compute_cosmos_receipt_tx_hash(&payload));
        if result.tx_hash != expected_tx_hex {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Cosmos observation tx_hash {} does not match proof digest {expected_tx_hex}",
                result.tx_hash
            )));
        }
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Err(AdapterError::SubmissionFailed(
            "offline CosmosIcs23ChainAdapter refuses live network broadcast".into(),
        ))
    }

    async fn wait_for_confirmation(
        &self,
        _tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        Err(AdapterError::ConfirmationTimeout)
    }
}

// ============================================================================
// 3. Solana Bank-Hash & Account Inclusion ChainAdapter
// ============================================================================

/// Compute the domain-separated Solana account leaf (`BDLM_SOL_ACCOUNT_LEAF_V1`).
#[must_use]
pub fn compute_solana_account_leaf(
    account_pubkey: &Hash32,
    account_data_hash: &Hash32,
    lamports: u64,
) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_SOL_ACCOUNT_LEAF_V1");
    hasher.update(account_pubkey);
    hasher.update(account_data_hash);
    hasher.update(lamports.to_le_bytes());
    hasher.finalize().into()
}

/// Compute the domain-separated Solana transaction leaf (`BDLM_SOL_TX_LEAF_V1`).
#[must_use]
pub fn compute_solana_tx_leaf(tx_signature_hash: &Hash32, slot: u64) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_SOL_TX_LEAF_V1");
    hasher.update(tx_signature_hash);
    hasher.update(slot.to_le_bytes());
    hasher.finalize().into()
}

/// Fold a Solana account/tx Merkle branch under `BDLM_SOL_ACCOUNT_NODE_V1`.
#[must_use]
pub fn compute_solana_merkle_root(leaf: &Hash32, branch: &[(Hash32, bool)]) -> Hash32 {
    let mut acc = *leaf;
    for (sibling, sibling_is_right) in branch {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_SOL_ACCOUNT_NODE_V1");
        if *sibling_is_right {
            hasher.update(acc);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(acc);
        }
        acc = hasher.finalize().into();
    }
    acc
}

/// Compute the deterministic Solana bank-hash commitment (`BDLM_SOL_BANK_COMMITMENT_V1`)
/// binding `parent_bank_hash`, `accounts_delta_root`, `tx_root`, and `slot`.
#[must_use]
pub fn compute_solana_bank_commitment(
    parent_bank_hash: &Hash32,
    accounts_delta_root: &Hash32,
    tx_root: &Hash32,
    slot: u64,
) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_SOL_BANK_COMMITMENT_V1");
    hasher.update(parent_bank_hash);
    hasher.update(accounts_delta_root);
    hasher.update(tx_root);
    hasher.update(slot.to_le_bytes());
    hasher.finalize().into()
}

/// Serialized Solana bank-hash + account + transaction inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAccountReceiptProof {
    /// Confirmed Solana slot.
    pub slot: u64,
    /// Parent slot's bank hash.
    pub parent_bank_hash: Hash32,
    /// Account public key proven under `accounts_delta_root`.
    pub account_pubkey: Hash32,
    /// Digest of the account data bytes at `slot`.
    pub account_data_hash: Hash32,
    /// Account lamports balance at `slot`.
    pub lamports: u64,
    /// Merkle branch proving the account leaf into `accounts_delta_root`.
    pub account_branch: Vec<(Hash32, bool)>,
    /// 32-byte digest of the confirmed Solana transaction signature.
    pub tx_signature_hash: Hash32,
    /// Merkle branch proving the tx leaf into `tx_root`.
    pub tx_branch: Vec<(Hash32, bool)>,
}

/// Assemble a Solana [`RelayerExternalResult`] anchored to `bank_hash`.
///
/// # Errors
///
/// Fails closed if `bank_hash` or `tx_signature_hash` is zero or encoding exceeds bounds.
pub fn assemble_solana_bank_observation(
    proof: &SolanaAccountReceiptProof,
    bank_hash: Hash32,
) -> Result<RelayerExternalResult, AdapterError> {
    if bank_hash == [0u8; 32] {
        return Err(AdapterError::ProofGenerationFailed(
            "Solana bank_hash anchor cannot be zero".into(),
        ));
    }
    if proof.tx_signature_hash == [0u8; 32] {
        return Err(AdapterError::ProofGenerationFailed(
            "Solana tx_signature_hash cannot be zero".into(),
        ));
    }
    let receipt_proof = encode_bounded(proof)?;
    Ok(RelayerExternalResult {
        chain: ExternalChain::Solana,
        tx_hash: hex::encode(proof.tx_signature_hash),
        success: true,
        message: None,
        receipt_proof,
        external_state_root: bank_hash,
    })
}

/// Fail-closed `ChainAdapter` for Solana bank-hash + account/tx inclusion proofs.
#[derive(Debug, Clone)]
pub struct SolanaBankChainAdapter {
    trusted_bank_hash: Option<Hash32>,
    trusted_accounts_delta_root: Option<Hash32>,
    trusted_tx_root: Option<Hash32>,
    min_confirmed_slot: u64,
}

impl SolanaBankChainAdapter {
    /// Create a Solana bank-hash adapter anchored to verified Tower BFT roots.
    #[must_use]
    pub const fn new(
        trusted_bank_hash: Option<Hash32>,
        trusted_accounts_delta_root: Option<Hash32>,
        trusted_tx_root: Option<Hash32>,
        min_confirmed_slot: u64,
    ) -> Self {
        Self {
            trusted_bank_hash,
            trusted_accounts_delta_root,
            trusted_tx_root,
            min_confirmed_slot,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for SolanaBankChainAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Solana
    }

    fn trusted_observation_root(&self) -> Option<Hash32> {
        self.trusted_bank_hash
    }

    fn check_fit_for_relay(&self) -> Result<(), AdapterError> {
        let bank = self.trusted_bank_hash.ok_or_else(|| {
            AdapterError::Other("SolanaBankChainAdapter requires a trusted bank_hash".into())
        })?;
        let acct = self.trusted_accounts_delta_root.ok_or_else(|| {
            AdapterError::Other(
                "SolanaBankChainAdapter requires a trusted accounts_delta_root".into(),
            )
        })?;
        let tx = self.trusted_tx_root.ok_or_else(|| {
            AdapterError::Other("SolanaBankChainAdapter requires a trusted tx_root".into())
        })?;
        if bank == [0u8; 32] || acct == [0u8; 32] || tx == [0u8; 32] {
            return Err(AdapterError::Other(
                "SolanaBankChainAdapter anchors cannot be zero".into(),
            ));
        }
        if self.min_confirmed_slot == 0 {
            return Err(AdapterError::Other(
                "SolanaBankChainAdapter min_confirmed_slot must be > 0".into(),
            ));
        }
        Ok(())
    }

    async fn generate_receipt_proof(
        &self,
        _tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        Err(AdapterError::ProofGenerationFailed(
            "Solana proof generation uses assemble_solana_bank_observation".into(),
        ))
    }

    fn verify_receipt_proof(
        &self,
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ProofVerificationFailed(
            "bare MerkleProof is refused for Solana; supply SolanaAccountReceiptProof via verify_observation"
                .into(),
        ))
    }

    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        if result.chain != ExternalChain::Solana {
            return Err(AdapterError::UnsupportedChain(result.chain));
        }
        if !result.success {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana external observation reported execution failure".into(),
            ));
        }
        let trusted_bank = self.trusted_bank_hash.ok_or_else(|| {
            AdapterError::ProofVerificationFailed("missing trusted Solana bank_hash".into())
        })?;
        let trusted_acct = self.trusted_accounts_delta_root.ok_or_else(|| {
            AdapterError::ProofVerificationFailed(
                "missing trusted Solana accounts_delta_root".into(),
            )
        })?;
        let trusted_tx = self.trusted_tx_root.ok_or_else(|| {
            AdapterError::ProofVerificationFailed("missing trusted Solana tx_root".into())
        })?;
        if trusted_bank == [0u8; 32] || result.external_state_root != trusted_bank {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana observation state root does not match trusted bank_hash".into(),
            ));
        }

        let payload: SolanaAccountReceiptProof = decode_bounded(&result.receipt_proof)?;
        if payload.slot < self.min_confirmed_slot {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Solana slot {} is below required min_confirmed_slot {}",
                payload.slot, self.min_confirmed_slot
            )));
        }
        if payload.account_branch.len() > MAX_SOLANA_BRANCH_DEPTH
            || payload.tx_branch.len() > MAX_SOLANA_BRANCH_DEPTH
        {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana Merkle branch exceeds depth ceiling".into(),
            ));
        }
        if payload.account_pubkey == [0u8; 32] || payload.tx_signature_hash == [0u8; 32] {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana account_pubkey and tx_signature_hash must be non-zero".into(),
            ));
        }

        let acct_leaf = compute_solana_account_leaf(
            &payload.account_pubkey,
            &payload.account_data_hash,
            payload.lamports,
        );
        let acct_root = compute_solana_merkle_root(&acct_leaf, &payload.account_branch);
        if acct_root != trusted_acct {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana account Merkle root does not match trusted accounts_delta_root".into(),
            ));
        }

        let tx_leaf = compute_solana_tx_leaf(&payload.tx_signature_hash, payload.slot);
        let tx_root = compute_solana_merkle_root(&tx_leaf, &payload.tx_branch);
        if tx_root != trusted_tx {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana tx Merkle root does not match trusted tx_root".into(),
            ));
        }

        let bank_commitment = compute_solana_bank_commitment(
            &payload.parent_bank_hash,
            &acct_root,
            &tx_root,
            payload.slot,
        );
        if bank_commitment != trusted_bank {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana bank commitment does not match trusted bank_hash".into(),
            ));
        }

        let expected_tx_hex = hex::encode(payload.tx_signature_hash);
        if result.tx_hash != expected_tx_hex {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "Solana observation tx_hash {} does not match tx_signature_hash {expected_tx_hex}",
                result.tx_hash
            )));
        }
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Err(AdapterError::SubmissionFailed(
            "offline SolanaBankChainAdapter refuses live network broadcast".into(),
        ))
    }

    async fn wait_for_confirmation(
        &self,
        _tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        Err(AdapterError::ConfirmationTimeout)
    }
}
