//! The EVM migration kit's verification core (directive 8.12).
//!
//! An EVM application leaves its old network and its contract continues on
//! Budlum at the same address, with the same code and the same storage. This
//! module decides whether a migration is allowed, and it makes no I/O:
//!
//! 1. **Authorization.** Authority belongs to the account that deployed the
//!    contract: an EIP-712 `MigrationAuthorization(address contract, uint256
//!    budlumChainId, uint256 sourceBlock)` signature, in a domain bound to the
//!    chain id and the contract, so it cannot be replayed.
//! 2. **Account proof.** The account at the finalised `sourceBlock` is proven
//!    against the source state root (`crate::cross_domain::evm::account_proof`).
//! 3. **Storage chunks.** Each slot is proven against the storage root.
//! 4. **Finalization.** The record the account door installs: same address,
//!    code whose hash equals the proven code hash, proven storage root, and
//!    `imported_from`. The old native balance does not travel.
//!
//! The `bud-migrate` binary is the caller. The transaction door (WP-34 2/3)
//! and the installing EVM environment (WP-27) are not in this tree yet, so this
//! is the verification, not the state write.

use std::collections::BTreeMap;

use crate::cross_domain::evm::account_proof::{self, AccountProofError, EvmAccount};
use crate::cross_domain::evm::mpt;
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};

pub mod dependencies;

pub use dependencies::{dependency_report, DependencyReport};

/// The EIP-712 domain name of a migration authorization.
const DOMAIN_NAME: &str = "Budlum Migration";
/// The EIP-712 domain version.
const DOMAIN_VERSION: &str = "1";
/// The EIP-712 domain type of a migration authorization.
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/// The EIP-712 type of a migration authorization.
const AUTHORIZATION_TYPE: &str =
    "MigrationAuthorization(address contract,uint256 budlumChainId,uint256 sourceBlock)";
/// The largest number of proven slots one chunk may carry.
const MAX_CHUNK_SLOTS: usize = 4096;

/// The EIP-712 authorization a deploying account signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationAuthorization {
    /// The contract the authorization is for, 20 bytes.
    pub contract: [u8; 20],
    /// The Budlum chain id the signature is bound to.
    pub budlum_chain_id: u64,
    /// The finalised source block the state is read at.
    pub source_block: u64,
    /// The 65-byte `r || s || v` signature of the deploying account.
    pub signature: Vec<u8>,
}

impl MigrationAuthorization {
    /// The EIP-712 type hash of the authorization struct.
    fn type_hash() -> [u8; 32] {
        mpt::keccak256(AUTHORIZATION_TYPE.as_bytes())
    }

    /// The EIP-712 domain separator: chain id and contract both bind it.
    fn domain_separator(contract: &[u8; 20], chain_id: u64) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_TYPE.as_bytes()));
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_NAME.as_bytes()));
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_VERSION.as_bytes()));
        encoded.extend_from_slice(&word_from_u64(chain_id));
        encoded.extend_from_slice(&word_from_address(contract));
        mpt::keccak256(&encoded)
    }

    /// The EIP-712 struct hash of the three authorization fields.
    fn struct_hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(128);
        encoded.extend_from_slice(&Self::type_hash());
        encoded.extend_from_slice(&word_from_address(&self.contract));
        encoded.extend_from_slice(&word_from_u64(self.budlum_chain_id));
        encoded.extend_from_slice(&word_from_u64(self.source_block));
        mpt::keccak256(&encoded)
    }

    /// The digest the deploying account signs:
    /// `keccak256(0x1901 || domainSeparator || structHash)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(66);
        encoded.extend_from_slice(&[0x19, 0x01]);
        encoded.extend_from_slice(&Self::domain_separator(&self.contract, self.budlum_chain_id));
        encoded.extend_from_slice(&self.struct_hash());
        mpt::keccak256(&encoded)
    }
}

/// The deployment a migration points at, as the source chain's finalised
/// evidence establishes it.
///
/// `deployer` is the account that deployed the contract, or the account that
/// deployed the factory when a factory deployed it (directive 8.12.2 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentEvidence {
    /// The deployed contract address.
    pub contract: [u8; 20],
    /// The account with migration authority.
    pub deployer: [u8; 20],
    /// The source block the deployment was finalised in.
    pub source_block: u64,
}

/// Why a migration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The authorization signs for another chain.
    ChainMismatch { signed: u64, expected: u64 },
    /// The authorization names another contract than the deployment.
    ContractMismatch,
    /// The authorization and the deployment name different source blocks.
    SourceBlockMismatch,
    /// The signature is not a recoverable secp256k1 signature.
    Signature(RecoverError),
    /// The signing account is not the account with migration authority.
    NotTheDeployer {
        signed: [u8; 20],
        deployer: [u8; 20],
    },
    /// The account proof or a storage proof was refused.
    Proof(AccountProofError),
    /// The offered code is not the code the proven account holds.
    CodeHashMismatch,
    /// The target address already holds an account.
    AddressOccupied,
    /// A chunk names another contract than the plan.
    ChunkContractMismatch,
    /// A chunk names another source block than the plan.
    ChunkBlockMismatch,
    /// A chunk carries more slots than the bound.
    ChunkTooLarge { slots: usize, max: usize },
    /// The storage root does not hold the slot the chunk claims.
    SlotAbsent([u8; 32]),
    /// The chunk claims a value the storage root does not prove.
    SlotValueMismatch {
        slot: [u8; 32],
        claimed: [u8; 32],
        proven: [u8; 32],
    },
    /// A slot arrives twice with two different values.
    SlotConflicts { slot: [u8; 32] },
}

impl ImportError {
    /// The message of a refusal that carries no data.
    fn message(&self) -> &'static str {
        match self {
            ImportError::ContractMismatch => "the authorization names another contract",
            ImportError::SourceBlockMismatch => "the authorization names another source block",
            ImportError::CodeHashMismatch => "the code does not match the proven code hash",
            ImportError::AddressOccupied => "the target address already holds an account",
            ImportError::ChunkContractMismatch => "the chunk names another contract",
            ImportError::ChunkBlockMismatch => "the chunk names another source block",
            _ => "refused",
        }
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::ChainMismatch { signed, expected } => {
                write!(f, "migration: signed for chain {signed}, running {expected}")
            }
            ImportError::Signature(e) => write!(f, "migration: signature: {e}"),
            ImportError::Proof(e) => write!(f, "migration: {e}"),
            ImportError::NotTheDeployer { signed, deployer } => write!(
                f,
                "migration: 0x{} signed, 0x{} deployed",
                hex::encode(signed),
                hex::encode(deployer)
            ),
            ImportError::ChunkTooLarge { slots, max } => {
                write!(f, "migration: {slots} slots, the bound is {max}")
            }
            ImportError::SlotAbsent(slot) => {
                write!(f, "migration: no slot 0x{}", hex::encode(slot))
            }
            ImportError::SlotValueMismatch {
                slot,
                claimed,
                proven,
            } => write!(
                f,
                "migration: slot 0x{}: claimed 0x{}, proven 0x{}",
                hex::encode(slot),
                hex::encode(claimed),
                hex::encode(proven)
            ),
            ImportError::SlotConflicts { slot } => {
                write!(f, "migration: slot 0x{} conflicts", hex::encode(slot))
            }
            other => write!(f, "migration: {}", other.message()),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<AccountProofError> for ImportError {
    fn from(e: AccountProofError) -> Self {
        ImportError::Proof(e)
    }
}

/// One proven storage slot, with the proof that proves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageEntry {
    /// The slot, 32 bytes.
    pub slot: [u8; 32],
    /// The value the chunk claims for the slot.
    pub value: [u8; 32],
    /// The storage-proof nodes against the contract's storage root.
    pub proof_nodes: Vec<Vec<u8>>,
}

/// The payload of `MigrationTx::ImportEvmStorageChunk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEvmStorageChunk {
    /// The contract the chunk belongs to.
    pub contract: [u8; 20],
    /// The finalised source block the proofs were made at.
    pub source_block: u64,
    /// The proven slots.
    pub slots: Vec<StorageEntry>,
}

/// Everything one migration start needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRequest {
    /// The Budlum chain id the node runs.
    pub chain_id: u64,
    pub source_domain: String,
    /// The source deployment.
    pub evidence: DeploymentEvidence,
    /// The deploying account's EIP-712 authorization.
    pub authorization: MigrationAuthorization,
    pub state_root: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
    /// The contract code the relayer carries.
    pub code: Vec<u8>,
    pub occupied: bool,
}

/// Where a finished import came from: the directive's `imported_from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSource {
    /// The source domain name, as the domain registry names it.
    pub domain: String,
    /// The finalised source block.
    pub block: u64,
    /// The source contract address.
    pub address: [u8; 20],
}

/// The record `FinalizeEvmImport` produces: what the account door installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRecord {
    /// The address the contract continues at, the same as the source address.
    pub address: [u8; 20],
    /// The code the address holds.
    pub code: Vec<u8>,
    /// `keccak256(code)`, equal to the proven code hash.
    pub code_hash: [u8; 32],
    /// The storage root the imported slots are proven against.
    pub storage_root: [u8; 32],
    /// The imported slots as `(slot, value)` pairs, ordered by slot.
    pub storage: Vec<([u8; 32], [u8; 32])>,
    /// Where the account came from. The old native balance is deliberately not
    /// part of it: it does not travel.
    pub imported_from: ImportSource,
}

/// A migration that has been authorized and whose source account is proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    source: ImportSource,
    account: EvmAccount,
    code: Vec<u8>,
    storage: BTreeMap<[u8; 32], [u8; 32]>,
}

/// Starts a migration: checks the authority and proves the source account.
///
/// # Errors
///
/// [`ImportError`] naming the first refusal: a chain, contract or block
/// mismatch between the authorization and the deployment, a signature that
/// recovers to another account, an occupied target address, or an account
/// proof that does not prove the offered code.
pub fn begin_import(request: MigrationRequest) -> Result<MigrationPlan, ImportError> {
    if request.authorization.budlum_chain_id != request.chain_id {
        return Err(ImportError::ChainMismatch {
            signed: request.authorization.budlum_chain_id,
            expected: request.chain_id,
        });
    }
    if request.authorization.contract != request.evidence.contract {
        return Err(ImportError::ContractMismatch);
    }
    if request.authorization.source_block != request.evidence.source_block {
        return Err(ImportError::SourceBlockMismatch);
    }
    let signer = recover_address(
        &request.authorization.digest(),
        &request.authorization.signature,
    )
    .map_err(ImportError::Signature)?;
    if signer != request.evidence.deployer {
        return Err(ImportError::NotTheDeployer {
            signed: signer,
            deployer: request.evidence.deployer,
        });
    }
    if request.occupied {
        return Err(ImportError::AddressOccupied);
    }
    let account = account_proof::verify_account(
        &request.account_proof,
        &request.state_root,
        &request.evidence.contract,
    )?;
    account_proof::check_code(&request.code, &account.code_hash)?;
    Ok(MigrationPlan {
        source: ImportSource {
            domain: request.source_domain,
            block: request.evidence.source_block,
            address: request.evidence.contract,
        },
        account,
        code: request.code,
        storage: BTreeMap::new(),
    })
}

impl MigrationPlan {
    /// The proven source account.
    #[must_use]
    pub fn account(&self) -> &EvmAccount {
        &self.account
    }

    /// Imports one chunk of proven storage slots and returns how many it took.
    ///
    /// # Errors
    ///
    /// [`ImportError`] when the chunk names another contract or block, when it
    /// carries more slots than the bound, when a slot is not in the storage
    /// root, when a claimed value is not the proven value, or when one slot
    /// arrives twice with two values.
    pub fn import_chunk(&mut self, chunk: &ImportEvmStorageChunk) -> Result<usize, ImportError> {
        if chunk.contract != self.source.address {
            return Err(ImportError::ChunkContractMismatch);
        }
        if chunk.source_block != self.source.block {
            return Err(ImportError::ChunkBlockMismatch);
        }
        if chunk.slots.len() > MAX_CHUNK_SLOTS {
            return Err(ImportError::ChunkTooLarge {
                slots: chunk.slots.len(),
                max: MAX_CHUNK_SLOTS,
            });
        }
        let mut imported = 0usize;
        for entry in &chunk.slots {
            let proven = account_proof::verify_storage(
                &entry.proof_nodes,
                &self.account.storage_root,
                &entry.slot,
            )?;
            let Some(proven) = proven else {
                return Err(ImportError::SlotAbsent(entry.slot));
            };
            if proven != entry.value {
                return Err(ImportError::SlotValueMismatch {
                    slot: entry.slot,
                    claimed: entry.value,
                    proven,
                });
            }
            if let Some(existing) = self.storage.get(&entry.slot) {
                if *existing != entry.value {
                    return Err(ImportError::SlotConflicts { slot: entry.slot });
                }
            }
            self.storage.insert(entry.slot, entry.value);
            imported += 1;
        }
        Ok(imported)
    }

    /// Finalizes the import into the record the account door installs.
    ///
    /// # Errors
    ///
    /// [`ImportError::CodeHashMismatch`] when the code no longer hashes to the
    /// proven code hash.
    pub fn finalize(self) -> Result<MigrationRecord, ImportError> {
        let MigrationPlan {
            source,
            account,
            code,
            storage,
        } = self;
        let proven_code_hash = account_proof::code_hash(&code);
        if proven_code_hash != account.code_hash {
            return Err(ImportError::CodeHashMismatch);
        }
        let storage = storage.into_iter().collect();
        Ok(MigrationRecord {
            address: source.address,
            code,
            code_hash: proven_code_hash,
            storage_root: account.storage_root,
            storage,
            imported_from: source,
        })
    }
}

/// A 32-byte big-endian ABI word holding a `u64`.
fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// A 32-byte big-endian ABI word holding an address, left-padded with zeroes.
fn word_from_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{self, Item};

    /// The deploying account of the fixture: the key was chosen once and the
    /// address below is `keccak256(pubkey)[12..]`.
    const DEPLOYER: &str = "4a5383ee4db7729a7391c5eb0f4a7ba4b54592c3";
    /// The contract address of the fixture.
    const CONTRACT: &str = "1111111111111111111111111111111111111111";
    /// The testnet chain id the fixture signs for.
    const CHAIN_ID: u64 = 45_261;
    /// The finalised source block of the fixture.
    const SOURCE_BLOCK: u64 = 19_000_000;
    /// The EIP-712 digest of the fixture, computed independently.
    const DIGEST: &str = "e478fbf2de0afb26c016dc0c7b6c3aa5f7cdf8bd24e7fa5288c65a70ab231b61";
    /// The signature of `DIGEST` by `DEPLOYER`.
    const SIGNATURE: &str = "7af821799fb21b71b7122537279cfa28d5f47a3c5eb2d19d9c2a2e8506190b2a28f996eda74ef31781c1d10e941b91a41436c8bd8d1e06fbec663c77befbc4d91b";

    fn address_of(text: &str) -> [u8; 20] {
        let bytes = hex::decode(text).expect("hex");
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        address
    }

    fn authorization() -> MigrationAuthorization {
        MigrationAuthorization {
            contract: address_of(CONTRACT),
            budlum_chain_id: CHAIN_ID,
            source_block: SOURCE_BLOCK,
            signature: hex::decode(SIGNATURE).expect("hex"),
        }
    }

    fn evidence(deployer: [u8; 20]) -> DeploymentEvidence {
        DeploymentEvidence {
            contract: address_of(CONTRACT),
            deployer,
            source_block: SOURCE_BLOCK,
        }
    }

    /// A big-endian integer with the RLP rule applied: no leading zero.
    fn uint_bytes(value: u128) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    /// A one-node trie holding one key.
    fn leaf(key: &[u8], value: Vec<u8>) -> Vec<u8> {
        let path = mpt::hp_encode(&mpt::to_nibbles(key), true);
        rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(value),
        ]))
    }

    /// A slot fixture: the proof node and the storage root that holds it.
    fn slot_fixture(slot: &[u8; 32], value: u128) -> (Vec<u8>, [u8; 32]) {
        let node = leaf(
            &mpt::keccak256(slot),
            rlp::encode(&Item::String(uint_bytes(value))),
        );
        let root = mpt::keccak256(&node);
        (node, root)
    }

    /// The code every test migrates.
    fn code() -> Vec<u8> {
        b"contract Token {}".to_vec()
    }

    /// A complete request: authorized, proven, and one storage slot.
    fn request() -> (MigrationRequest, [u8; 32]) {
        let slot = [0x42u8; 32];
        let (_, storage_root) = slot_fixture(&slot, 42);
        let account_node = leaf(
            &mpt::keccak256(&address_of(CONTRACT)),
            rlp::encode(&Item::List(vec![
                Item::String(uint_bytes(1)),
                Item::String(Vec::new()),
                Item::String(storage_root.to_vec()),
                Item::String(account_proof::code_hash(&code()).to_vec()),
            ])),
        );
        let state_root = mpt::keccak256(&account_node);
        let request = MigrationRequest {
            chain_id: CHAIN_ID,
            source_domain: "sepolia".to_string(),
            evidence: evidence(address_of(DEPLOYER)),
            authorization: authorization(),
            state_root,
            account_proof: vec![account_node],
            code: code(),
            occupied: false,
        };
        (request, storage_root)
    }

    #[test]
    fn migration_authorization_digest_is_the_eip712_digest() {
        assert_eq!(
            hex::encode(authorization().digest()),
            DIGEST,
            "the domain separator and struct hash must match an independently computed EIP-712 digest"
        );
    }

    #[test]
    fn uel_migration_requires_deployer_authorization() {
        // The authorized deployer passes.
        assert!(begin_import(request().0).is_ok());

        // Another account in the deployment evidence is not the signer.
        let mut other = request().0;
        other.evidence = evidence([0x99u8; 20]);
        assert_eq!(
            begin_import(other),
            Err(ImportError::NotTheDeployer {
                signed: address_of(DEPLOYER),
                deployer: [0x99u8; 20],
            })
        );

        // A signature made for another chain does not authorize this one.
        let mut other_chain = request().0;
        other_chain.authorization.budlum_chain_id = CHAIN_ID + 1;
        assert_eq!(
            begin_import(other_chain),
            Err(ImportError::ChainMismatch {
                signed: CHAIN_ID + 1,
                expected: CHAIN_ID,
            })
        );

        // A truncated signature is refused before anything else is read.
        let mut truncated = request().0;
        truncated.authorization.signature.truncate(64);
        assert!(matches!(
            begin_import(truncated),
            Err(ImportError::Signature(RecoverError::Length))
        ));
    }

    #[test]
    fn migration_refuses_occupied_address() {
        let mut request = request().0;
        request.occupied = true;
        assert_eq!(begin_import(request), Err(ImportError::AddressOccupied));
    }

    #[test]
    fn migration_preserves_address_code_and_storage_root() {
        let (request, storage_root) = request();
        let mut plan = begin_import(request).expect("the request is authorized and proven");
        assert_eq!(plan.account().nonce, 1);
        assert_eq!(plan.account().balance, 0);

        let slot = [0x42u8; 32];
        let (storage_node, _) = slot_fixture(&slot, 42);
        let mut value = [0u8; 32];
        value[31] = 42;
        let chunk = ImportEvmStorageChunk {
            contract: address_of(CONTRACT),
            source_block: SOURCE_BLOCK,
            slots: vec![StorageEntry {
                slot,
                value,
                proof_nodes: vec![storage_node],
            }],
        };
        assert_eq!(plan.import_chunk(&chunk).expect("the chunk verifies"), 1);

        let record = plan.finalize().expect("the code still matches");
        assert_eq!(record.address, address_of(CONTRACT));
        assert_eq!(record.code, code());
        assert_eq!(record.code_hash, account_proof::code_hash(&code()));
        assert_eq!(record.storage_root, storage_root);
        assert_eq!(record.storage, vec![(slot, value)]);
        assert_eq!(record.imported_from.domain, "sepolia");
        assert_eq!(record.imported_from.block, SOURCE_BLOCK);
        assert_eq!(record.imported_from.address, address_of(CONTRACT));
    }

    #[test]
    fn migration_chunk_refuses_what_the_root_does_not_prove() {
        let (request, _) = request();
        let mut plan = begin_import(request).expect("the request is authorized and proven");
        let slot = [0x42u8; 32];
        let (storage_node, _) = slot_fixture(&slot, 42);

        // A claimed value that is not the proven value.
        let mut value = [0u8; 32];
        value[31] = 43;
        let wrong_value = ImportEvmStorageChunk {
            contract: address_of(CONTRACT),
            source_block: SOURCE_BLOCK,
            slots: vec![StorageEntry {
                slot,
                value,
                proof_nodes: vec![storage_node.clone()],
            }],
        };
        assert!(matches!(
            plan.import_chunk(&wrong_value),
            Err(ImportError::SlotValueMismatch { .. })
        ));

        // A slot the trie does not hold.
        let absent = ImportEvmStorageChunk {
            contract: address_of(CONTRACT),
            source_block: SOURCE_BLOCK,
            slots: vec![StorageEntry {
                slot: [0x43u8; 32],
                value: [0u8; 32],
                proof_nodes: vec![storage_node.clone()],
            }],
        };
        assert!(matches!(
            plan.import_chunk(&absent),
            Err(ImportError::Proof(AccountProofError::Trie(_)))
        ));

        // A chunk for another contract, and one for another block.
        let mut other_contract = absent.clone();
        other_contract.contract = [0x22u8; 20];
        assert_eq!(plan.import_chunk(&other_contract), Err(ImportError::ChunkContractMismatch));
        let mut other_block = absent.clone();
        other_block.source_block = SOURCE_BLOCK + 1;
        assert_eq!(plan.import_chunk(&other_block), Err(ImportError::ChunkBlockMismatch));

        // The honest chunk is still accepted after the refusals.
        let mut value = [0u8; 32];
        value[31] = 42;
        let honest = ImportEvmStorageChunk {
            contract: address_of(CONTRACT),
            source_block: SOURCE_BLOCK,
            slots: vec![StorageEntry {
                slot,
                value,
                proof_nodes: vec![storage_node],
            }],
        };
        assert_eq!(plan.import_chunk(&honest).expect("verifies"), 1);
    }

    #[test]
    fn migration_refuses_code_the_account_does_not_hold() {
        let mut request = request().0;
        request.code = b"contract Other {}".to_vec();
        assert_eq!(
            begin_import(request),
            Err(ImportError::Proof(AccountProofError::CodeHashMismatch))
        );
    }
}
