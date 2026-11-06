//! Source-transaction and receipt proofs for EVM deployment authority.
//!
//! A canonical Ethereum receipt does not carry the RPC-only `from` and
//! `contractAddress` fields. The migration kit therefore proves both the
//! transaction and its receipt. It recovers the sender from the signed
//! transaction, derives the direct `CREATE` address from `(sender, nonce)`, and
//! checks that the proven receipt succeeded. An RPC receipt JSON document is
//! never an authority proof.

use super::DeploymentEvidence;
use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::receipt::{self, ReceiptError};
use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};

/// One transaction trie descent cannot consume more nodes than this bound.
const MAX_PROOF_NODES: usize = 64;

/// The source-chain evidence needed before an EIP-712 authorization is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentProof {
    /// The finalized source block that supplied both trie roots.
    pub source_block: u64,
    /// The transaction's index in that block.
    pub transaction_index: u64,
    /// The raw signed legacy, EIP-2930, or EIP-1559 transaction.
    pub transaction: Vec<u8>,
    /// The transaction MPT proof, keyed by `rlp(transaction_index)`.
    pub transaction_proof: Vec<Vec<u8>>,
    /// The finalized block's `transactionsRoot`.
    pub transactions_root: [u8; 32],
    /// The receipt MPT proof at the same transaction index.
    pub receipt_proof: Vec<Vec<u8>>,
    /// The finalized block's `receiptsRoot`.
    pub receipts_root: [u8; 32],
}

impl DeploymentProof {
    /// The number of proof nodes whose verification is chargeable.
    #[must_use]
    pub fn proof_node_count(&self) -> usize {
        self.transaction_proof.len() + self.receipt_proof.len()
    }
}

/// Why deployment evidence was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentProofError {
    /// One of the two proofs exceeds the node bound.
    ProofTooLarge,
    /// The transaction proof does not verify against `transactionsRoot`.
    TransactionTrie(MptError),
    /// The receipt proof does not verify against `receiptsRoot`.
    ReceiptTrie(MptError),
    /// The transaction supplied beside the proof is not the proven value.
    TransactionMismatch,
    /// The transaction or receipt envelope is malformed.
    Rlp(RlpError),
    /// The receipt envelope is malformed.
    Receipt(ReceiptError),
    /// The source transaction signature is invalid.
    Signature(RecoverError),
    /// The transaction uses a type this verifier does not support.
    UnsupportedTransactionType(u8),
    /// The signed transaction does not have the expected schema.
    InvalidTransaction,
    /// An unprotected legacy transaction cannot bind the expected source chain.
    MissingChainId,
    /// The signed transaction belongs to another source chain.
    SourceChainMismatch { signed: u64, expected: u64 },
    /// The proven deployment transaction reverted.
    DeploymentReverted,
    /// The transaction calls an existing contract instead of direct `CREATE`.
    FactoryDeploymentRequiresExecutionEvidence,
}

impl std::fmt::Display for DeploymentProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofTooLarge => write!(f, "deployment proof: over {MAX_PROOF_NODES} nodes"),
            Self::TransactionTrie(e) => write!(f, "deployment transaction trie: {e}"),
            Self::ReceiptTrie(e) => write!(f, "deployment receipt trie: {e}"),
            Self::TransactionMismatch => write!(
                f,
                "deployment proof: the supplied transaction is not the proven transaction"
            ),
            Self::Rlp(e) => write!(f, "deployment proof: rlp: {e}"),
            Self::Receipt(e) => write!(f, "deployment proof: receipt: {e}"),
            Self::Signature(e) => write!(f, "deployment proof: signature: {e}"),
            Self::UnsupportedTransactionType(kind) => {
                write!(f, "deployment proof: unsupported transaction type {kind:#x}")
            }
            Self::InvalidTransaction => write!(f, "deployment proof: invalid signed transaction"),
            Self::MissingChainId => write!(f, "deployment proof: missing EIP-155 chain id"),
            Self::SourceChainMismatch { signed, expected } => write!(
                f,
                "deployment proof: signed for source chain {signed}, expected {expected}"
            ),
            Self::DeploymentReverted => write!(f, "deployment proof: the deployment reverted"),
            Self::FactoryDeploymentRequiresExecutionEvidence => write!(
                f,
                "deployment proof: factory deployment needs execution evidence for the created address"
            ),
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

/// Verifies deployment authority against roots from one finalized source block.
///
/// Only direct `CREATE` is accepted in this slice. A factory call has no
/// canonical created-address field in either the transaction or the receipt, so
/// accepting the caller's claimed address would invent authority. Factory
/// support needs an execution proof and is refused rather than guessed.
///
/// # Errors
///
/// [`DeploymentProofError`] when either MPT proof fails, the transaction and
/// receipt do not match, the source chain differs, the signature is invalid,
/// the deployment reverted, or the transaction is not a direct creation.
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
    let proven_transaction = mpt::verify(
        &proof.transaction_proof,
        &proof.transactions_root,
        &key,
    )
    .map_err(DeploymentProofError::TransactionTrie)?;
    if proven_transaction != proof.transaction {
        return Err(DeploymentProofError::TransactionMismatch);
    }
    let proven_receipt = mpt::verify(&proof.receipt_proof, &proof.receipts_root, &key)
        .map_err(DeploymentProofError::ReceiptTrie)?;
    let receipt = receipt::decode_receipt(&proven_receipt)?;
    if !receipt.status {
        return Err(DeploymentProofError::DeploymentReverted);
    }
    let transaction = decode_signed_transaction(&proof.transaction)?;
    if transaction.chain_id != expected_source_chain_id {
        return Err(DeploymentProofError::SourceChainMismatch {
            signed: transaction.chain_id,
            expected: expected_source_chain_id,
        });
    }
    if !transaction.to.is_empty() {
        return Err(DeploymentProofError::FactoryDeploymentRequiresExecutionEvidence);
    }
    let deployer = recover_address(&transaction.signing_digest, &transaction.signature)?;
    let contract = create_address(&deployer, transaction.nonce);
    Ok(DeploymentEvidence {
        contract,
        deployer,
        source_block: proof.source_block,
    })
}

/// The fields needed to recover a direct creation's sender and address.
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
        Some(0x00 | 0x03..=0x7f) => Err(DeploymentProofError::UnsupportedTransactionType(raw[0])),
        Some(_) => decode_legacy_transaction(raw),
        None => Err(DeploymentProofError::InvalidTransaction),
    }
}

fn decode_legacy_transaction(
    raw: &[u8],
) -> Result<SignedDeploymentTransaction, DeploymentProofError> {
    let fields = list_fields(rlp::decode(raw)?)?;
    if fields.len() != 9 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let nonce = rlp::decode_uint(&fields[0])?;
    let to = rlp::as_bytes(&fields[3])?.to_vec();
    if !to.is_empty() && to.len() != 20 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let v = rlp::decode_uint(&fields[6])?;
    let (chain_id, recovery_id) = match v {
        27 | 28 => return Err(DeploymentProofError::MissingChainId),
        35.. => {
            let parity = (v - 35) % 2;
            ((v - 35) / 2, if parity == 0 { 0 } else { 1 })
        }
        _ => return Err(DeploymentProofError::InvalidTransaction),
    };
    let mut unsigned = fields[..6].to_vec();
    unsigned.push(Item::String(uint_bytes(chain_id)));
    unsigned.push(Item::String(Vec::new()));
    unsigned.push(Item::String(Vec::new()));
    let signing_digest = mpt::keccak256(&rlp::encode(&Item::List(unsigned)));
    let signature = signature(&fields[7], &fields[8], recovery_id)?;
    Ok(SignedDeploymentTransaction {
        chain_id,
        nonce,
        to,
        signing_digest,
        signature,
    })
}

fn decode_typed_transaction(
    raw: &[u8],
    kind: u8,
) -> Result<SignedDeploymentTransaction, DeploymentProofError> {
    let fields = list_fields(rlp::decode(&raw[1..])?)?;
    let (field_count, to_index, signature_index) = match kind {
        0x01 => (11, 4, 8),
        0x02 => (12, 5, 9),
        _ => return Err(DeploymentProofError::UnsupportedTransactionType(kind)),
    };
    if fields.len() != field_count {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let chain_id = rlp::decode_uint(&fields[0])?;
    let nonce = rlp::decode_uint(&fields[1])?;
    let to = rlp::as_bytes(&fields[to_index])?.to_vec();
    if !to.is_empty() && to.len() != 20 {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let recovery_id = rlp::decode_uint(&fields[signature_index])?;
    let recovery_id = u8::try_from(recovery_id)
        .map_err(|_| DeploymentProofError::InvalidTransaction)?;
    let signing_digest = typed_signing_digest(kind, &fields[..signature_index]);
    let signature = signature(
        &fields[signature_index + 1],
        &fields[signature_index + 2],
        recovery_id,
    )?;
    Ok(SignedDeploymentTransaction {
        chain_id,
        nonce,
        to,
        signing_digest,
        signature,
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
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&signature_word(r)?);
    signature.extend_from_slice(&signature_word(s)?);
    signature.push(recovery_id);
    Ok(signature)
}

fn signature_word(item: &Item) -> Result<[u8; 32], DeploymentProofError> {
    let bytes = rlp::as_bytes(item)?;
    if bytes.len() > 32 || bytes.first() == Some(&0) {
        return Err(DeploymentProofError::InvalidTransaction);
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(word)
}

fn list_fields(item: Item) -> Result<Vec<Item>, DeploymentProofError> {
    match item {
        Item::List(fields) => Ok(fields),
        Item::String(_) => Err(DeploymentProofError::InvalidTransaction),
    }
}

/// The plain receipts-and-transactions trie key: RLP of a minimal integer.
fn transaction_key(index: u64) -> Vec<u8> {
    rlp::encode(&Item::String(uint_bytes(index)))
}

fn uint_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// The Yellow Paper's direct `CREATE` address rule (not `CREATE2`).
fn create_address(deployer: &[u8; 20], nonce: u64) -> [u8; 20] {
    let encoded = rlp::encode(&Item::List(vec![
        Item::String(deployer.to_vec()),
        Item::String(uint_bytes(nonce)),
    ]));
    let hash = mpt::keccak256(&encoded);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_CHAIN_ID: u64 = 11_155_111;
    const DEPLOYER: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const CONTRACT: &str = "a3183498b579bd228aa2b62101c40cc1da978f24";
    const LEGACY_TRANSACTION: &str = "f85807843b9aca00830f4240808084600060008401546d72a02f6a69a52fb40df1378d854d62a2c0d6cc6757bad78f8f2f85b1626815ce4fa8a01752541e338fd7331899b91e94dc7f9cf88f6ba8abc872ab59aaf63369d4e6c9";
    const EIP2930_TRANSACTION: &str = "01f85983aa36a707843b9aca00830f424080808460006000c001a00921e6a6a60e8bd9e435fc8f7b89198d086fe1893a3d7f2e4026b1fb1d5ccdfaa04b8e8555ce5b95ca35a894e2ece537c587022401dfa7d651119906ade57683a5";
    const EIP1559_TRANSACTION: &str = "02f85e83aa36a707843b9aca008477359400830f424080808460006000c080a0a8969623728e3c5b60a88efffb4d932215941cd1a9617c7a2a1e5a461d741c95a002cb9d7135e8f73cec3c3fe0d26b7fb6ca7e7f424e5a50c6a2bb51e6171a53ac";
    const FACTORY_CALL_TRANSACTION: &str = "02f87283aa36a707843b9aca008477359400830f4240940000000000000000000000000000000000000001808460006000c001a0730024c2629653c28245eb059229ca12c1cd7a035aa22a6d3d6ba37a360bfd68a0307436296b309a8006de811e3196e2a698deefd6e0a040e8055b73346e7bab6d";

    fn address(text: &str) -> [u8; 20] {
        hex::decode(text).expect("hex").try_into().expect("address")
    }

    fn receipt(success: bool, transaction_type: u8) -> Vec<u8> {
        let item = Item::List(vec![
            Item::String(if success { vec![1] } else { Vec::new() }),
            Item::String(uint_bytes(21_000)),
            Item::String(vec![0; 256]),
            Item::List(Vec::new()),
        ]);
        let mut encoded = if transaction_type == 0 {
            Vec::new()
        } else {
            vec![transaction_type]
        };
        encoded.extend_from_slice(&rlp::encode(&item));
        encoded
    }

    fn proof(transaction: &str, success: bool) -> DeploymentProof {
        let transaction = hex::decode(transaction).expect("transaction hex");
        let transaction_type = match transaction.first().copied() {
            Some(kind @ (0x01 | 0x02)) => kind,
            _ => 0,
        };
        let receipt = receipt(success, transaction_type);
        let key = transaction_key(0);
        let path = mpt::hp_encode(&mpt::to_nibbles(&key), true);
        let transaction_node = rlp::encode(&Item::List(vec![
            Item::String(path.clone()),
            Item::String(transaction.clone()),
        ]));
        let receipt_node = rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(receipt),
        ]));
        DeploymentProof {
            source_block: 19_000_000,
            transaction_index: 0,
            transaction,
            transaction_proof: vec![transaction_node.clone()],
            transactions_root: mpt::keccak256(&transaction_node),
            receipt_proof: vec![receipt_node.clone()],
            receipts_root: mpt::keccak256(&receipt_node),
        }
    }

    #[test]
    fn deployment_proof_binds_receipt_sender_and_contract_address() {
        for transaction in [LEGACY_TRANSACTION, EIP2930_TRANSACTION, EIP1559_TRANSACTION] {
            let evidence = verify_deployment(&proof(transaction, true), SOURCE_CHAIN_ID)
                .expect("the independently signed transaction verifies");
            assert_eq!(evidence.contract, address(CONTRACT));
            assert_eq!(evidence.deployer, address(DEPLOYER));
            assert_eq!(evidence.source_block, 19_000_000);
        }
    }

    #[test]
    fn deployment_proof_refuses_another_chain_a_revert_or_a_substituted_transaction() {
        assert_eq!(
            verify_deployment(&proof(LEGACY_TRANSACTION, true), SOURCE_CHAIN_ID + 1),
            Err(DeploymentProofError::SourceChainMismatch {
                signed: SOURCE_CHAIN_ID,
                expected: SOURCE_CHAIN_ID + 1,
            })
        );
        assert_eq!(
            verify_deployment(&proof(LEGACY_TRANSACTION, false), SOURCE_CHAIN_ID),
            Err(DeploymentProofError::DeploymentReverted)
        );
        let mut substituted = proof(LEGACY_TRANSACTION, true);
        substituted.transaction = hex::decode(EIP1559_TRANSACTION).expect("hex");
        assert_eq!(
            verify_deployment(&substituted, SOURCE_CHAIN_ID),
            Err(DeploymentProofError::TransactionMismatch)
        );
    }

    #[test]
    fn factory_call_is_not_accepted_as_a_created_address_proof() {
        assert_eq!(
            verify_deployment(&proof(FACTORY_CALL_TRANSACTION, true), SOURCE_CHAIN_ID),
            Err(DeploymentProofError::FactoryDeploymentRequiresExecutionEvidence)
        );
    }

    #[test]
    fn deployment_proof_is_bounded_before_hashing() {
        let mut too_large = proof(LEGACY_TRANSACTION, true);
        too_large.transaction_proof = vec![Vec::new(); MAX_PROOF_NODES + 1];
        assert_eq!(
            verify_deployment(&too_large, SOURCE_CHAIN_ID),
            Err(DeploymentProofError::ProofTooLarge)
        );
    }

    #[test]
    fn direct_create_address_matches_the_independently_derived_address() {
        assert_eq!(create_address(&address(DEPLOYER), 7), address(CONTRACT));
    }
}
