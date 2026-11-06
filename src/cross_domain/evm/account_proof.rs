//! Ethereum account and storage proofs for the migration kit.
//!
//! Directive 8.12.2 items 3 and 4: a migrated contract continues at the same
//! address, with the same code and the same storage, and the proof of the
//! source state is verified here rather than trusted from the relayer, which is
//! the `relayer_produces` model the receipt path uses.
//!
//! * The account proof proves `{nonce, balance, storageRoot, codeHash}` of the
//!   contract at a finalised block, keyed by `keccak256(address)`: the state trie
//!   is a secure trie, so the address is hashed before it becomes a path.
//! * A storage proof proves one slot, keyed by `keccak256(slot)` in the storage
//!   trie and rooted at the `storageRoot` the account proof produced; the value
//!   is the RLP encoding of the big-endian word.
//!
//! Nothing here touches the network, and no proof can state a bound about
//! itself: the node count is capped before a node is read. The caller is the
//! migration door in `crate::execution::coordinator::migration`; the EVM
//! environment that installs the account is WP-27 and is not here yet.

use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::rlp::{self, Item, RlpError};

/// The largest proof this module accepts, counted in RLP nodes.
///
/// An honest proof of one account or one slot is a handful of nodes: the
/// descent is at most 64 nibbles and a node consumes at least one nibble. The
/// cap is generous and it exists so a relayer cannot hand the verifier a
/// ten-thousand-node list and make it hash every entry first.
const MAX_PROOF_NODES: usize = 64;

/// An Ethereum account as the state trie stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmAccount {
    /// The account nonce: `RLP` integer field 0.
    pub nonce: u64,
    /// The account balance in wei: `RLP` integer field 1.
    pub balance: u128,
    /// The root of the account's storage trie: field 2.
    pub storage_root: [u8; 32],
    /// `keccak256` of the account's code: field 3.
    pub code_hash: [u8; 32],
}

/// Why an account or a storage proof was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountProofError {
    /// The proof carries more nodes than `MAX_PROOF_NODES`.
    ProofTooLarge,
    /// The trie walk rejected the proof.
    Trie(MptError),
    /// A node or a value was not canonical RLP.
    Rlp(RlpError),
    /// The proven value is not a four-field account.
    NotAnAccount,
    /// A field is wider than the Ethereum schema allows.
    FieldTooWide,
    /// A storage root or code hash is not exactly 32 bytes.
    InvalidHashLength,
    /// The code carries a hash the proven account does not hold.
    CodeHashMismatch,
}

impl std::fmt::Display for AccountProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountProofError::ProofTooLarge => write!(f, "evm proof: over {MAX_PROOF_NODES} nodes"),
            AccountProofError::Trie(e) => write!(f, "evm proof: {e}"),
            AccountProofError::Rlp(e) => write!(f, "evm proof: rlp: {e}"),
            AccountProofError::NotAnAccount => write!(f, "evm proof: not a four-field account"),
            AccountProofError::FieldTooWide => write!(f, "evm proof: account field too wide"),
            AccountProofError::InvalidHashLength => {
                write!(f, "evm proof: storage root and code hash must be 32 bytes")
            }
            AccountProofError::CodeHashMismatch => write!(f, "evm proof: wrong code for the account"),
        }
    }
}

impl std::error::Error for AccountProofError {}

impl From<MptError> for AccountProofError {
    fn from(e: MptError) -> Self {
        AccountProofError::Trie(e)
    }
}

impl From<RlpError> for AccountProofError {
    fn from(e: RlpError) -> Self {
        AccountProofError::Rlp(e)
    }
}

/// The state-trie key of an address: `keccak256(address)`.
fn account_key(address: &[u8; 20]) -> [u8; 32] {
    mpt::keccak256(address)
}

/// The storage-trie key of a slot: `keccak256(slot)`, the slot read as a
/// 32-byte big-endian word.
fn storage_key(slot: &[u8; 32]) -> [u8; 32] {
    mpt::keccak256(slot)
}

/// Right-aligns a big-endian word into `N` bytes.
fn right_aligned<const N: usize>(bytes: &[u8]) -> Result<[u8; N], AccountProofError> {
    if bytes.len() > N {
        return Err(AccountProofError::FieldTooWide);
    }
    let mut out = [0u8; N];
    let start = N - bytes.len();
    out[start..].copy_from_slice(bytes);
    Ok(out)
}

/// Reads a fixed hash field. Unlike an integer, a short value is not padded.
fn fixed_hash(item: &Item) -> Result<[u8; 32], AccountProofError> {
    let bytes = rlp::as_bytes(item)?;
    if bytes.len() != 32 {
        return Err(AccountProofError::InvalidHashLength);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

/// Verifies the account proof of `address` against a finalised state root.
///
/// # Errors
///
/// [`AccountProofError`] when the proof is larger than the cap, when a node is
/// missing or the path does not match, when a node is not canonical RLP, or
/// when the proven value is not a four-field account.
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

/// Decodes the four-field account value a state-trie leaf holds.
fn decode_account(value: &[u8]) -> Result<EvmAccount, AccountProofError> {
    let item = rlp::decode(value)?;
    let Item::List(fields) = item else {
        return Err(AccountProofError::NotAnAccount);
    };
    if fields.len() != 4 {
        return Err(AccountProofError::NotAnAccount);
    }
    let nonce = rlp::decode_uint(&fields[0])?;
    let balance = u128::from_be_bytes(right_aligned::<16>(rlp::as_bytes(&fields[1])?)?);
    let storage_root = fixed_hash(&fields[2])?;
    let code_hash = fixed_hash(&fields[3])?;
    Ok(EvmAccount {
        nonce,
        balance,
        storage_root,
        code_hash,
    })
}

/// Verifies a storage proof of one slot against the account's storage root.
///
/// `Ok(None)` means the trie does not hold the slot, which is the canonical
/// encoding of the value zero in Ethereum: `SSTORE` of zero deletes the slot.
///
/// # Errors
///
/// [`AccountProofError`] when the proof is larger than the cap, when a node is
/// missing or the path does not match, or when the proven value is wider than
/// one word.
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

/// Decodes a storage-trie leaf value into a 32-byte word.
fn decode_storage_value(value: &[u8]) -> Result<[u8; 32], AccountProofError> {
    let item = rlp::decode(value)?;
    right_aligned::<32>(rlp::as_bytes(&item)?)
}

/// The code hash of a contract: `keccak256(code)`. The empty code hashes to the
/// canonical `0xc5d2...a470`, the value an account with no code carries.
#[must_use]
pub fn code_hash(code: &[u8]) -> [u8; 32] {
    mpt::keccak256(code)
}

/// Checks that `code` is the code the account proof carries.
///
/// # Errors
///
/// [`AccountProofError::CodeHashMismatch`] when the bytes hash to another value.
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

    /// A big-endian integer with the RLP rule applied: no leading zero.
    fn uint_bytes(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    /// A one-node trie holding one key: the honest shape of a one-entry trie.
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

    /// A storage fixture: one slot holding `value`, and the root of its trie.
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

        let account = verify_account(&proof, &state_root, &address).expect("the proof verifies");
        assert_eq!(account.nonce, 3);
        assert_eq!(account.balance, 5);
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
            .expect("the storage proof verifies");
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
    fn evm_account_proof_is_bounded() {
        let too_many = vec![Vec::new(); MAX_PROOF_NODES + 1];
        assert_eq!(
            verify_account(&too_many, &[0u8; 32], &[0u8; 20]),
            Err(AccountProofError::ProofTooLarge)
        );
        assert_eq!(
            verify_storage(&too_many, &[0u8; 32], &[0u8; 32]),
            Err(AccountProofError::ProofTooLarge)
        );
    }

    #[test]
    fn evm_account_proof_refuses_a_value_that_is_not_an_account() {
        let short = rlp::encode(&Item::List(vec![Item::String(uint_bytes(1))]));
        assert_eq!(decode_account(&short), Err(AccountProofError::NotAnAccount));
        let wide = rlp::encode(&Item::List(vec![
            Item::String(Vec::new()),
            Item::String(vec![0xff; 17]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
        ]));
        assert_eq!(decode_account(&wide), Err(AccountProofError::FieldTooWide));
        let short_hash = rlp::encode(&Item::List(vec![
            Item::String(Vec::new()),
            Item::String(Vec::new()),
            Item::String(vec![0u8; 31]),
            Item::String(vec![0u8; 32]),
        ]));
        assert_eq!(
            decode_account(&short_hash),
            Err(AccountProofError::InvalidHashLength)
        );
    }
}
