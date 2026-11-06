//! Ethereum account and storage proofs for the EVM migration kit (directive 8.12.2).
//!
//! * `verify_account` proves `{nonce, balance_be, storageRoot, codeHash}` of a
//!   contract at a finalized block, keyed by `keccak256(address)` in the state trie.
//! * `verify_storage` proves one 32-byte slot keyed by `keccak256(slot)` in the
//!   contract's storage trie against `storageRoot`.
//!
//! Node count is capped before any node is decoded or hashed.

use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use serde::{Deserialize, Serialize};

/// Maximum RLP proof nodes accepted in one MPT descent.
pub const MAX_PROOF_NODES: usize = 64;

/// An Ethereum account decoded from a verified state-trie leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmAccount {
    /// Account nonce (`RLP` field 0).
    pub nonce: u64,
    /// Full 256-bit big-endian balance word (`RLP` field 1; up to 32 bytes).
    pub balance_be: [u8; 32],
    /// Storage trie root (`RLP` field 2, 32 bytes).
    pub storage_root: [u8; 32],
    /// `keccak256(code)` (`RLP` field 3, 32 bytes).
    pub code_hash: [u8; 32],
}

impl EvmAccount {
    /// Low `u128` wei balance when the source balance fits in 128 bits (`None` above `2^128 - 1`).
    #[must_use]
    pub fn balance_u128(&self) -> Option<u128> {
        if self.balance_be.get(..16).is_some_and(|hi| hi.iter().any(|b| *b != 0)) {
            return None;
        }
        let lo: [u8; 16] = self.balance_be.get(16..32)?.try_into().ok()?;
        Some(u128::from_be_bytes(lo))
    }
}

/// Refusal reason for an Ethereum account or storage MPT proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountProofError {
    /// Proof carries more nodes than [`MAX_PROOF_NODES`].
    ProofTooLarge,
    /// Trie walk rejected the proof.
    Trie(MptError),
    /// Node or leaf value is not canonical RLP.
    Rlp(RlpError),
    /// Proven leaf is not a 4-field account list.
    NotAnAccount,
    /// Integer field exceeds Ethereum width (`nonce > 8B`, `balance > 32B`, or `slot > 32B`).
    FieldTooWide,
    /// `storageRoot` or `codeHash` is not 32 bytes.
    InvalidHashLength,
    /// Supplied bytecode does not hash to proven `codeHash`.
    CodeHashMismatch,
}

impl std::fmt::Display for AccountProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProofTooLarge => {
                write!(f, "evm proof: exceeds {MAX_PROOF_NODES} nodes")
            }
            Self::Trie(e) => write!(f, "evm proof: {e}"),
            Self::Rlp(e) => write!(f, "evm proof: rlp: {e}"),
            Self::NotAnAccount => write!(f, "evm proof: not a four-field account"),
            Self::FieldTooWide => write!(f, "evm proof: account field too wide"),
            Self::InvalidHashLength => {
                write!(f, "evm proof: storage root and code hash must be 32 bytes")
            }
            Self::CodeHashMismatch => {
                write!(f, "evm proof: bytecode does not match proven codeHash")
            }
        }
    }
}

impl std::error::Error for AccountProofError {}

impl From<MptError> for AccountProofError {
    fn from(e: MptError) -> Self {
        Self::Trie(e)
    }
}

impl From<RlpError> for AccountProofError {
    fn from(e: RlpError) -> Self {
        Self::Rlp(e)
    }
}

fn account_key(address: &[u8; 20]) -> [u8; 32] {
    mpt::keccak256(address)
}

fn storage_key(slot: &[u8; 32]) -> [u8; 32] {
    mpt::keccak256(slot)
}

fn right_aligned_32(bytes: &[u8]) -> Result<[u8; 32], AccountProofError> {
    if bytes.len() > 32 {
        return Err(AccountProofError::FieldTooWide);
    }
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let Some(dst) = out.get_mut(start..) else {
        return Err(AccountProofError::FieldTooWide);
    };
    dst.copy_from_slice(bytes);
    Ok(out)
}

fn fixed_hash(item: &Item) -> Result<[u8; 32], AccountProofError> {
    let bytes = rlp::as_bytes(item)?;
    bytes
        .try_into()
        .map_err(|_| AccountProofError::InvalidHashLength)
}

/// Verifies the state-trie account proof of `address` against finalized `state_root`.
pub fn verify_account(
    proof_nodes: &[Vec<u8>],
    state_root: &[u8; 32],
    address: &[u8; 20],
) -> Result<EvmAccount, AccountProofError> {
    if proof_nodes.len() > MAX_PROOF_NODES {
        return Err(AccountProofError::ProofTooLarge);
    }
    let value = mpt::verify(proof_nodes, state_root, &account_key(address))?;
    decode_account(&value)
}

fn decode_account(value: &[u8]) -> Result<EvmAccount, AccountProofError> {
    let item = rlp::decode(value)?;
    let Item::List(fields) = item else {
        return Err(AccountProofError::NotAnAccount);
    };
    let [f0, f1, f2, f3] = fields.as_slice() else {
        return Err(AccountProofError::NotAnAccount);
    };
    let nonce = rlp::decode_uint(f0)?;
    let bal_bytes = rlp::as_bytes(f1)?;
    if bal_bytes.first() == Some(&0) {
        return Err(AccountProofError::Rlp(RlpError::NonCanonicalInt));
    }
    let balance_be = right_aligned_32(bal_bytes)?;
    let storage_root = fixed_hash(f2)?;
    let code_hash = fixed_hash(f3)?;
    Ok(EvmAccount {
        nonce,
        balance_be,
        storage_root,
        code_hash,
    })
}

/// Verifies a storage-trie proof for `slot` against `storage_root`.
///
/// `Ok(None)` indicates canonical absence (zero slot in Ethereum storage).
pub fn verify_storage(
    proof_nodes: &[Vec<u8>],
    storage_root: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<[u8; 32]>, AccountProofError> {
    if proof_nodes.len() > MAX_PROOF_NODES {
        return Err(AccountProofError::ProofTooLarge);
    }
    match mpt::verify(proof_nodes, storage_root, &storage_key(slot)) {
        Ok(value) => Ok(Some(decode_storage_value(&value)?)),
        Err(MptError::KeyNotFound) => Ok(None),
        Err(e) => Err(AccountProofError::Trie(e)),
    }
}

fn decode_storage_value(value: &[u8]) -> Result<[u8; 32], AccountProofError> {
    let item = rlp::decode(value)?;
    let bytes = rlp::as_bytes(&item)?;
    if bytes.first() == Some(&0) {
        return Err(AccountProofError::Rlp(RlpError::NonCanonicalInt));
    }
    right_aligned_32(bytes)
}

/// Computes `keccak256(code)`.
#[must_use]
pub fn code_hash(code: &[u8]) -> [u8; 32] {
    mpt::keccak256(code)
}

/// Verifies that `code` hashes to `proven_code_hash`.
pub fn check_code(code: &[u8], proven_code_hash: &[u8; 32]) -> Result<(), AccountProofError> {
    if code_hash(code) == *proven_code_hash {
        Ok(())
    } else {
        Err(AccountProofError::CodeHashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uint_bytes(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    fn leaf(key: &[u8], value: Vec<u8>) -> Vec<u8> {
        let path = mpt::hp_encode(&mpt::to_nibbles(key), true);
        rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(value),
        ]))
    }

    fn account_value(
        nonce: u64,
        balance: u128,
        storage_root: [u8; 32],
        code_hash: [u8; 32],
    ) -> Vec<u8> {
        rlp::encode(&Item::List(vec![
            Item::String(uint_bytes(u128::from(nonce))),
            Item::String(uint_bytes(balance)),
            Item::String(storage_root.to_vec()),
            Item::String(code_hash.to_vec()),
        ]))
    }

    fn storage_fixture(slot: &[u8; 32], value: u128) -> (Vec<u8>, [u8; 32]) {
        let node = leaf(
            &storage_key(slot),
            rlp::encode(&Item::String(uint_bytes(value))),
        );
        let root = mpt::keccak256(&node);
        (node, root)
    }

    #[test]
    fn evm_account_proof_reads_code_hash() {
        let address = [0x11u8; 20];
        let code = b"contract Token {}".to_vec();
        let slot = [0x42u8; 32];
        let (storage_node, storage_root) = storage_fixture(&slot, 7);

        let node = leaf(
            &account_key(&address),
            account_value(3, 5, storage_root, code_hash(&code)),
        );
        let state_root = mpt::keccak256(&node);
        let proof = vec![node];

        let account = verify_account(&proof, &state_root, &address).expect("proof verifies");
        assert_eq!(account.nonce, 3);
        assert_eq!(account.balance_u128(), Some(5));
        assert_eq!(account.storage_root, storage_root);
        assert_eq!(account.code_hash, code_hash(&code));
        assert!(check_code(&code, &account.code_hash).is_ok());
        assert_eq!(
            check_code(b"contract Other {}", &account.code_hash),
            Err(AccountProofError::CodeHashMismatch)
        );

        let mut expected = [0u8; 32];
        expected[31] = 7;

        let storage_proof = vec![storage_node];
        let proven = verify_storage(&storage_proof, &account.storage_root, &slot)
            .expect("storage proof verifies");
        assert_eq!(proven, Some(expected));
    }

    #[test]
    fn evm_storage_proof_refuses_wrong_slot() {
        let slot = [0x42u8; 32];
        let (node, storage_root) = storage_fixture(&slot, 7);
        let proof = vec![node];
        assert_eq!(
            verify_storage(&proof, &storage_root, &[0x43u8; 32]),
            Err(AccountProofError::Trie(MptError::PathMismatch))
        );
    }

    #[test]
    fn evm_account_proof_is_bounded_and_accepts_256bit_balance() {
        let too_many = vec![Vec::new(); MAX_PROOF_NODES + 1];
        assert_eq!(
            verify_account(&too_many, &[0u8; 32], &[0u8; 20]),
            Err(AccountProofError::ProofTooLarge)
        );
        assert_eq!(
            verify_storage(&too_many, &[0u8; 32], &[0u8; 32]),
            Err(AccountProofError::ProofTooLarge)
        );

        // 24-byte uint256 balance (> u128::MAX) decodes cleanly; 33-byte balance is refused.
        let valid_24b = rlp::encode(&Item::List(vec![
            Item::String(Vec::new()),
            Item::String(vec![0x01; 24]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
        ]));
        let acc = decode_account(&valid_24b).expect("24-byte uint256 balance valid");
        assert_eq!(acc.balance_u128(), None);

        let too_wide_33b = rlp::encode(&Item::List(vec![
            Item::String(Vec::new()),
            Item::String(vec![0xff; 33]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
        ]));
        assert_eq!(decode_account(&too_wide_33b), Err(AccountProofError::FieldTooWide));
    }
}
