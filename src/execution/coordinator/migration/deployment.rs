//! Source-transaction and receipt proofs for EVM deployment authority (8.12.2 item 2).
//!
//! Proves both the deployment transaction (`transactionsRoot`) and its receipt
//! (`receiptsRoot`), recovering the deployer from the signed transaction and
//! deriving the created contract address. Supports both direct `CREATE` and
//! factory deployments (`FactoryCreationEvidence`, where migration authority
//! belongs to the account that deployed the factory).
//! Convenience: public EVM deployment transaction, receipt, and factory authority verifier (WP-34).

use super::DeploymentEvidence;
use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::receipt::{self, ReceiptError};
use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};
/// Deterministic EIP-1014 `CREATE2` contract address `keccak256(0xff || deployer || salt || keccak256(init_code))[12..32]`.
#[must_use]
pub fn compute_create2_address(deployer: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let init_hash = mpt::keccak256(init_code);
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend_from_slice(deployer);
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(&init_hash);
    let digest = mpt::keccak256(&preimage);
    let mut out = [0u8; 20];
    if let Some(src) = digest.get(12..32) {
        out.copy_from_slice(src);
    }
    out
}
use serde::{Deserialize, Serialize};

/// Maximum RLP proof nodes accepted per transaction or receipt trie walk.
pub const MAX_PROOF_NODES: usize = 64;

/// Deterministic derivation rule proving how a verified factory created `contract`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryDerivation {
    /// Factory executed `CREATE` at `factory_nonce`.
    Create { factory_nonce: u64 },
    /// Factory executed `CREATE2` with `salt` and `init_code`.
    Create2 { salt: [u8; 32], init_code: Vec<u8> },
}

/// Evidence proving the deployer of a factory that created the migrated contract
/// (directive 8.12.2 item 2: factory rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryCreationEvidence {
    /// Direct `CREATE` deployment proof of the factory contract itself.
    pub factory_deployment: Box<DeploymentProof>,
    /// Deterministic `CREATE` or `CREATE2` derivation from the factory address.
    pub derivation: FactoryDerivation,
}

/// Source-chain evidence proving who holds migration authority for `contract`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentProof {
    /// Finalized source block supplying `transactions_root` and `receipts_root`.
    pub deployment_block: u64,
    /// Transaction index in `deployment_block`.
    pub transaction_index: u64,
    /// Raw signed legacy, EIP-2930, or EIP-1559 transaction.
    pub transaction: Vec<u8>,
    /// Transaction MPT proof keyed by `rlp(transaction_index)`.
    pub transaction_proof: Vec<Vec<u8>>,
    /// Finalized block's `transactionsRoot`.
    pub transactions_root: [u8; 32],
    /// Receipt MPT proof at the same `transaction_index`.
    pub receipt_proof: Vec<Vec<u8>>,
    /// Finalized block's `receiptsRoot`.
    pub receipts_root: [u8; 32],
    /// Optional factory deployment proof when `transaction` called a factory.
    #[serde(default)]
    pub factory: Option<FactoryCreationEvidence>,
}

impl DeploymentProof {
    /// Total MPT proof nodes verified across this deployment (including factory proof).
    #[must_use]
    pub fn proof_node_count(&self) -> usize {
        let base = self
            .transaction_proof
            .len()
            .saturating_add(self.receipt_proof.len());
        match &self.factory {
            Some(fac) => base.saturating_add(fac.factory_deployment.proof_node_count()),
            None => base,
        }
    }
}

/// Refusal reason for deployment authority verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentProofError {
    ProofTooLarge,
    TransactionTrie(MptError),
    ReceiptTrie(MptError),
    TransactionMismatch,
    Rlp(RlpError),
    Receipt(ReceiptError),
    Signature(RecoverError),
    UnsupportedTransactionType(u8),
    InvalidTransaction,
    MissingChainId,
    SourceChainMismatch { signed: u64, expected: u64 },
    DeploymentReverted,
    FactoryDeploymentRequiresExecutionEvidence,
    FactoryAddressMismatch,
    NestedFactoryUnsupported,
}

impl std::fmt::Display for DeploymentProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofTooLarge => {
                write!(f, "deployment proof: exceeds {MAX_PROOF_NODES} nodes")
            }
            Self::TransactionTrie(e) => write!(f, "deployment transaction trie: {e}"),
            Self::ReceiptTrie(e) => write!(f, "deployment receipt trie: {e}"),
            Self::TransactionMismatch => {
                write!(f, "deployment proof: supplied tx mismatches proven tx")
            }
            Self::Rlp(e) => write!(f, "deployment proof: rlp: {e}"),
            Self::Receipt(e) => write!(f, "deployment proof: receipt: {e}"),
            Self::Signature(e) => write!(f, "deployment proof: signature: {e}"),
            Self::UnsupportedTransactionType(kind) => {
                write!(f, "deployment proof: unsupported tx type {kind:#x}")
            }
            Self::InvalidTransaction => write!(f, "deployment proof: invalid signed tx"),
            Self::MissingChainId => write!(f, "deployment proof: missing EIP-155 chain id"),
            Self::SourceChainMismatch { signed, expected } => write!(
                f,
                "deployment proof: signed chain {signed}, expected {expected}"
            ),
            Self::DeploymentReverted => write!(f, "deployment proof: deployment reverted"),
            Self::FactoryDeploymentRequiresExecutionEvidence => write!(
                f,
                "deployment proof: factory call requires factory creation evidence"
            ),
            Self::FactoryAddressMismatch => {
                write!(f, "deployment proof: tx target does not match proven factory")
            }
            Self::NestedFactoryUnsupported => {
                write!(f, "deployment proof: nested factory chain is not supported")
            }
        }
    }
}

impl std::error::Error for DeploymentProofError {}

impl From<RlpError> for DeploymentProofError {
    fn from(error: RlpError) -> Self {
        Self::Rlp(error)
    }
}

impl From<ReceiptError> for DeploymentProofError {
    fn from(error: ReceiptError) -> Self {
        Self::Receipt(error)
    }
}

impl From<RecoverError> for DeploymentProofError {
    fn from(error: RecoverError) -> Self {
        Self::Signature(error)
    }
}

/// Verifies deployment authority against finalized source-chain roots.
pub fn verify_deployment(
    proof: &DeploymentProof,
    expected_source_chain_id: u64,
) -> Result<DeploymentEvidence, DeploymentProofError> {
    if proof.transaction_proof.len() > MAX_PROOF_NODES
        || proof.receipt_proof.len() > MAX_PROOF_NODES
    {
        return Err(DeploymentProofError::ProofTooLarge);
    }
    let key = transaction_key(proof.transaction_index);
    let proven_tx = mpt::verify(
        &proof.transaction_proof,
        &proof.transactions_root,
        &key,
    )
    .map_err(DeploymentProofError::TransactionTrie)?;
    if proven_tx != proof.transaction {
        return Err(DeploymentProofError::TransactionMismatch);
    }
    let proven_receipt = mpt::verify(&proof.receipt_proof, &proof.receipts_root, &key)
        .map_err(DeploymentProofError::ReceiptTrie)?;
    let decoded_receipt = receipt::decode_receipt(&proven_receipt)?;
    if !decoded_receipt.status {
        return Err(DeploymentProofError::DeploymentReverted);
    }
    let tx = decode_signed_transaction(&proof.transaction)?;
    if tx.chain_id != expected_source_chain_id {
        return Err(DeploymentProofError::SourceChainMismatch {
            signed: tx.chain_id,
            expected: expected_source_chain_id,
        });
    }
    if tx.to.is_empty() {
        let deployer = recover_address(&tx.signing_digest, &tx.signature)?;
        let contract = create_address(&deployer, tx.nonce);
        return Ok(DeploymentEvidence {
            contract,
            deployer,
            deployment_block: proof.deployment_block,
        });
    }

    let Some(factory_ev) = &proof.factory else {
        return Err(DeploymentProofError::FactoryDeploymentRequiresExecutionEvidence);
    };
    if factory_ev.factory_deployment.factory.is_some() {
        return Err(DeploymentProofError::NestedFactoryUnsupported);
    }
    let _ = recover_address(&tx.signing_digest, &tx.signature)?;
    let factory_info = verify_deployment(&factory_ev.factory_deployment, expected_source_chain_id)?;
    if factory_info.deployment_block > proof.deployment_block {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    if tx.to.as_slice() != factory_info.contract {
        return Err(DeploymentProofError::FactoryAddressMismatch);
    }
    let created = match &factory_ev.derivation {
        FactoryDerivation::Create { factory_nonce } => {
            create_address(&factory_info.contract, *factory_nonce)
        }
        FactoryDerivation::Create2 { salt, init_code } => {
            compute_create2_address(&factory_info.contract, salt, init_code)
        }
    };
    Ok(DeploymentEvidence {
        contract: created,
        deployer: factory_info.deployer,
        deployment_block: proof.deployment_block,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedDeploymentTransaction {
    chain_id: u64,
    nonce: u64,
    to: Vec<u8>,
    signing_digest: [u8; 32],
    signature: Vec<u8>,
}

fn decode_signed_transaction(
    raw: &[u8],
) -> Result<SignedDeploymentTransaction, DeploymentProofError> {
    match raw.first().copied() {
        Some(0x01) => decode_typed_transaction(raw, 0x01),
        Some(0x02) => decode_typed_transaction(raw, 0x02),
        Some(kind @ (0x00 | 0x03..=0x7f)) => {
            Err(DeploymentProofError::UnsupportedTransactionType(kind))
        }
        Some(_) => decode_legacy_transaction(raw),
        None => Err(DeploymentProofError::InvalidTransaction),
    }
}

fn decode_legacy_transaction(
    raw: &[u8],
) -> Result<SignedDeploymentTransaction, DeploymentProofError> {
    let fields = list_fields(rlp::decode(raw)?)?;
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8] = fields.as_slice() else {
        return Err(DeploymentProofError::InvalidTransaction);
    };
    let nonce = rlp::decode_uint(f0)?;
    let to = rlp::as_bytes(f3)?.to_vec();
    if !to.is_empty() && to.len() != 20 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let v = rlp::decode_uint(f6)?;
    let (chain_id, recovery_id) = match v {
        27 | 28 => return Err(DeploymentProofError::MissingChainId),
        35.. => {
            let parity = (v - 35) % 2;
            ((v - 35) / 2, u8::from(parity != 0))
        }
        _ => return Err(DeploymentProofError::InvalidTransaction),
    };
    let unsigned = vec![
        f0.clone(),
        f1.clone(),
        f2.clone(),
        f3.clone(),
        f4.clone(),
        f5.clone(),
        Item::String(uint_bytes(chain_id)),
        Item::String(Vec::new()),
        Item::String(Vec::new()),
    ];
    let signing_digest = mpt::keccak256(&rlp::encode(&Item::List(unsigned)));
    let sig = signature(f7, f8, recovery_id)?;
    Ok(SignedDeploymentTransaction {
        chain_id,
        nonce,
        to,
        signing_digest,
        signature: sig,
    })
}

fn decode_typed_transaction(
    raw: &[u8],
    kind: u8,
) -> Result<SignedDeploymentTransaction, DeploymentProofError> {
    let payload = raw.get(1..).ok_or(DeploymentProofError::InvalidTransaction)?;
    let fields = list_fields(rlp::decode(payload)?)?;
    let (field_count, to_index, sig_index) = match kind {
        0x01 => (11usize, 4usize, 8usize),
        0x02 => (12usize, 5usize, 9usize),
        _ => return Err(DeploymentProofError::UnsupportedTransactionType(kind)),
    };
    if fields.len() != field_count {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let f0 = fields.first().ok_or(DeploymentProofError::InvalidTransaction)?;
    let f1 = fields.get(1).ok_or(DeploymentProofError::InvalidTransaction)?;
    let f_to = fields
        .get(to_index)
        .ok_or(DeploymentProofError::InvalidTransaction)?;
    let f_v = fields
        .get(sig_index)
        .ok_or(DeploymentProofError::InvalidTransaction)?;
    let f_r = fields
        .get(sig_index + 1)
        .ok_or(DeploymentProofError::InvalidTransaction)?;
    let f_s = fields
        .get(sig_index + 2)
        .ok_or(DeploymentProofError::InvalidTransaction)?;
    let unsigned_slice = fields
        .get(..sig_index)
        .ok_or(DeploymentProofError::InvalidTransaction)?;

    let chain_id = rlp::decode_uint(f0)?;
    let nonce = rlp::decode_uint(f1)?;
    let to = rlp::as_bytes(f_to)?.to_vec();
    if !to.is_empty() && to.len() != 20 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let recovery_id = u8::try_from(rlp::decode_uint(f_v)?)
        .map_err(|_| DeploymentProofError::InvalidTransaction)?;
    let signing_digest = typed_signing_digest(kind, unsigned_slice);
    let sig = signature(f_r, f_s, recovery_id)?;
    Ok(SignedDeploymentTransaction {
        chain_id,
        nonce,
        to,
        signing_digest,
        signature: sig,
    })
}

fn typed_signing_digest(kind: u8, unsigned_fields: &[Item]) -> [u8; 32] {
    let mut encoded = vec![kind];
    encoded.extend_from_slice(&rlp::encode(&Item::List(unsigned_fields.to_vec())));
    mpt::keccak256(&encoded)
}

fn signature(
    r: &Item,
    s: &Item,
    recovery_id: u8,
) -> Result<Vec<u8>, DeploymentProofError> {
    if recovery_id > 1 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&signature_word(r)?);
    out.extend_from_slice(&signature_word(s)?);
    out.push(recovery_id);
    Ok(out)
}

fn signature_word(item: &Item) -> Result<[u8; 32], DeploymentProofError> {
    let bytes = rlp::as_bytes(item)?;
    if bytes.len() > 32 || bytes.first() == Some(&0) {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let mut word = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let dst = word
        .get_mut(start..)
        .ok_or(DeploymentProofError::InvalidTransaction)?;
    dst.copy_from_slice(bytes);
    Ok(word)
}

fn list_fields(item: Item) -> Result<Vec<Item>, DeploymentProofError> {
    match item {
        Item::List(fields) => Ok(fields),
        Item::String(_) => Err(DeploymentProofError::InvalidTransaction),
    }
}

fn transaction_key(index: u64) -> Vec<u8> {
    rlp::encode(&Item::String(uint_bytes(index)))
}

fn uint_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    bytes.get(first..).unwrap_or(&[]).to_vec()
}

/// Yellow Paper direct `CREATE` address derivation.
#[must_use]
pub fn create_address(deployer: &[u8; 20], nonce: u64) -> [u8; 20] {
    let encoded = rlp::encode(&Item::List(vec![
        Item::String(deployer.to_vec()),
        Item::String(uint_bytes(nonce)),
    ]));
    let hash = mpt::keccak256(&encoded);
    let [_, _, _, _, _, _, _, _, _, _, _, _, addr @ ..] = hash;
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_CHAIN_ID: u64 = 11_155_111;
    const DEPLOYER: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const CONTRACT: &str = "a3183498b579bd228aa2b62101c40cc1da978f24";
    const LEGACY_TX: &[&str] = &[
        "f85807843b9aca00830f4240808084600060008401546d72a02f6a69a52fb40df1378d854d",
        "62a2c0d6cc6757bad78f8f2f85b1626815ce4fa8a01752541e338fd7331899b91e94dc7f9c",
        "f88f6ba8abc872ab59aaf63369d4e6c9",
    ];
    const EIP2930_TX: &[&str] = &[
        "01f85983aa36a707843b9aca00830f424080808460006000c001a00921e6a6a60e8bd9e435",
        "fc8f7b89198d086fe1893a3d7f2e4026b1fb1d5ccdfaa04b8e8555ce5b95ca35a894e2ece5",
        "37c587022401dfa7d651119906ade57683a5",
    ];
    const EIP1559_TX: &[&str] = &[
        "02f85e83aa36a707843b9aca008477359400830f424080808460006000c080a0a896962372",
        "8e3c5b60a88efffb4d932215941cd1a9617c7a2a1e5a461d741c95a002cb9d7135e8f73cec",
        "3c3fe0d26b7fb6ca7e7f424e5a50c6a2bb51e6171a53ac",
    ];
    const FACTORY_CALL_TX: &[&str] = &[
        "02f87283aa36a707843b9aca008477359400830f4240940000000000000000000000000000",
        "000000000001808460006000c001a0730024c2629653c28245eb059229ca12c1cd7a035aa2",
        "2a6d3d6ba37a360bfd68a0307436296b309a8006de811e3196e2a698deefd6e0a040e8055b",
        "73346e7bab6d",
    ];

    fn address(text: &str) -> [u8; 20] {
        hex::decode(text).expect("hex").try_into().expect("address")
    }

    fn receipt(success: bool, tx_type: u8) -> Vec<u8> {
        let item = Item::List(vec![
            Item::String(if success { vec![1] } else { Vec::new() }),
            Item::String(uint_bytes(21_000)),
            Item::String(vec![0; 256]),
            Item::List(Vec::new()),
        ]);
        let mut encoded = if tx_type == 0 { Vec::new() } else { vec![tx_type] };
        encoded.extend_from_slice(&rlp::encode(&item));
        encoded
    }

    fn proof(parts: &[&str], success: bool) -> DeploymentProof {
        let joined: String = parts.iter().copied().collect();
        let transaction = hex::decode(joined).expect("tx hex");
        let tx_type = match transaction.first().copied() {
            Some(kind @ (0x01 | 0x02)) => kind,
            _ => 0,
        };
        let rec = receipt(success, tx_type);
        let key = transaction_key(0);
        let path = mpt::hp_encode(&mpt::to_nibbles(&key), true);
        let tx_node = rlp::encode(&Item::List(vec![
            Item::String(path.clone()),
            Item::String(transaction.clone()),
        ]));
        let rec_node = rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(rec),
        ]));
        DeploymentProof {
            deployment_block: 18_999_000,
            transaction_index: 0,
            transaction,
            transaction_proof: vec![tx_node.clone()],
            transactions_root: mpt::keccak256(&tx_node),
            receipt_proof: vec![rec_node.clone()],
            receipts_root: mpt::keccak256(&rec_node),
            factory: None,
        }
    }

    #[test]
    fn deployment_proof_binds_receipt_sender_and_contract_address() {
        for tx in [LEGACY_TX, EIP2930_TX, EIP1559_TX] {
            let evidence = verify_deployment(&proof(tx, true), SOURCE_CHAIN_ID)
                .expect("signed deployment verifies");
            assert_eq!(evidence.contract, address(CONTRACT));
            assert_eq!(evidence.deployer, address(DEPLOYER));
            assert_eq!(evidence.deployment_block, 18_999_000);
        }
    }

    #[test]
    fn deployment_proof_refuses_wrong_chain_revert_or_unproven_factory() {
        assert_eq!(
            verify_deployment(&proof(LEGACY_TX, true), SOURCE_CHAIN_ID + 1),
            Err(DeploymentProofError::SourceChainMismatch {
                signed: SOURCE_CHAIN_ID,
                expected: SOURCE_CHAIN_ID + 1,
            })
        );
        assert_eq!(
            verify_deployment(&proof(LEGACY_TX, false), SOURCE_CHAIN_ID),
            Err(DeploymentProofError::DeploymentReverted)
        );
        assert_eq!(
            verify_deployment(&proof(FACTORY_CALL_TX, true), SOURCE_CHAIN_ID),
            Err(DeploymentProofError::FactoryDeploymentRequiresExecutionEvidence)
        );
    }
}
