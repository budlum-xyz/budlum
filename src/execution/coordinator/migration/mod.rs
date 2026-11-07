//! EVM Migration Kit verification core and state-installing door (directive 8.12).
//!
//! 1. **Authorization (`8.12.2 item 2`):** Proven deployment transaction and receipt
//!    (direct `CREATE` or factory rule) plus EIP-712 `MigrationAuthorization`.
//! 2. **Account proof (`8.12.2 item 3`):** MPT state proof at finalized `source_block`.
//! 3. **Storage chunks (`8.12.2 item 4`):** `MigrationTx::ImportEvmStorageChunk`
//!    proving slots against `storageRoot` atomically (`G-4`).
//! 4. **Finalization (`8.12.2 items 5-9`):** `MigrationTx::FinalizeEvmImport` rebuilds
//!    the complete storage trie, refuses occupied targets, charges the migration fee to
//!    the migrator, leaves native ETH balance at `0`, and installs the contract at its
//!    exact 20-byte address into `ee/evm/{account,code,storage}` with `imported_from`.

use std::collections::BTreeMap;

use crate::core::account::{AccountState, BudEnvUnit};
use crate::core::address::Address;
use crate::cross_domain::evm::account_proof::{self, AccountProofError, EvmAccount};
use crate::cross_domain::evm::mpt;
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};
use crate::execution::coordinator::alias::derive_contract_account;
use crate::execution::coordinator::evm_ee::EvmAccountRecord;
use crate::execution::coordinator::state::{
    ExecutionState, NS_EVM_ACCOUNT, NS_EVM_CODE, NS_EVM_STORAGE,
};
use crate::execution::coordinator::universal_call::EVM_UNIVERSAL_PRECOMPILE;
use crate::tokenomics::reward_pool::reward_pool_account;
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};

pub mod dependencies;
pub mod deployment;
pub mod fee;
pub mod storage_root;

pub use dependencies::{dependency_report, DependencyReport};
pub use deployment::{
    create_address, verify_deployment, DeploymentProof, DeploymentProofError,
    FactoryCreationEvidence, FactoryDerivation,
};
pub use fee::{
    quote_migration_fee, MigrationFeeOverflow, MigrationFeeQuote, MigrationFeeSchedule,
    MigrationUsage,
};

const DOMAIN_NAME: &str = "Budlum Migration";
const DOMAIN_VERSION: &str = "1";
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const AUTHORIZATION_TYPE: &str =
    "MigrationAuthorization(address contract,uint256 budlumChainId,uint256 sourceBlock)";
/// Maximum proven storage slots carried in one `ImportEvmStorageChunk`.
pub const MAX_CHUNK_SLOTS: usize = 4096;

/// EIP-712 `MigrationAuthorization` signed by the account with deployment authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAuthorization {
    pub contract: [u8; 20],
    pub budlum_chain_id: u64,
    pub source_block: u64,
    pub signature: Vec<u8>,
}

impl MigrationAuthorization {
    fn type_hash() -> [u8; 32] {
        mpt::keccak256(AUTHORIZATION_TYPE.as_bytes())
    }

    fn domain_separator(contract: &[u8; 20], chain_id: u64) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_TYPE.as_bytes()));
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_NAME.as_bytes()));
        encoded.extend_from_slice(&mpt::keccak256(DOMAIN_VERSION.as_bytes()));
        encoded.extend_from_slice(&word_from_u64(chain_id));
        encoded.extend_from_slice(&word_from_address(contract));
        mpt::keccak256(&encoded)
    }

    fn struct_hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(128);
        encoded.extend_from_slice(&Self::type_hash());
        encoded.extend_from_slice(&word_from_address(&self.contract));
        encoded.extend_from_slice(&word_from_u64(self.budlum_chain_id));
        encoded.extend_from_slice(&word_from_u64(self.source_block));
        mpt::keccak256(&encoded)
    }

    /// EIP-712 signing digest `keccak256(0x1901 || domainSeparator || structHash)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(66);
        encoded.extend_from_slice(&[0x19, 0x01]);
        encoded.extend_from_slice(&Self::domain_separator(
            &self.contract,
            self.budlum_chain_id,
        ));
        encoded.extend_from_slice(&self.struct_hash());
        mpt::keccak256(&encoded)
    }
}

/// Verified deployment authority record from finalized source-chain proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentEvidence {
    pub contract: [u8; 20],
    pub deployer: [u8; 20],
    pub deployment_block: u64,
}

/// Deterministic migration refusal reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    ChainMismatch { signed: u64, expected: u64 },
    ContractMismatch,
    SourceBlockMismatch,
    DeploymentAfterSource {
        deployment_block: u64,
        source_block: u64,
    },
    Signature(RecoverError),
    NotTheDeployer {
        signed: [u8; 20],
        deployer: [u8; 20],
    },
    Deployment(DeploymentProofError),
    Proof(AccountProofError),
    CodeHashMismatch,
    AddressOccupied,
    MigrationAlreadyPending,
    NoPendingMigration,
    ChunkContractMismatch,
    ChunkBlockMismatch,
    ChunkTooLarge { slots: usize, max: usize },
    SlotAbsent([u8; 32]),
    SlotValueMismatch {
        slot: [u8; 32],
        claimed: [u8; 32],
        proven: [u8; 32],
    },
    SlotConflicts { slot: [u8; 32] },
    StorageRootMismatch {
        expected: [u8; 32],
        computed: [u8; 32],
    },
    Fee(MigrationFeeOverflow),
    InsufficientMigratorBalance(String),
    StateError(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainMismatch { signed, expected } => {
                write!(f, "migration: signed for chain {signed}, running {expected}")
            }
            Self::ContractMismatch => write!(f, "migration: contract mismatch"),
            Self::SourceBlockMismatch => write!(f, "migration: source block mismatch"),
            Self::DeploymentAfterSource {
                deployment_block,
                source_block,
            } => write!(
                f,
                "migration: deployment block {deployment_block} > state block {source_block}"
            ),
            Self::Signature(e) => write!(f, "migration: signature: {e}"),
            Self::NotTheDeployer { signed, deployer } => write!(
                f,
                "migration: 0x{} signed, 0x{} deployed",
                hex::encode(signed),
                hex::encode(deployer)
            ),
            Self::Deployment(e) => write!(f, "migration: {e}"),
            Self::Proof(e) => write!(f, "migration: {e}"),
            Self::CodeHashMismatch => write!(f, "migration: bytecode mismatches proven hash"),
            Self::AddressOccupied => write!(f, "migration: target address already occupied"),
            Self::MigrationAlreadyPending => write!(f, "migration: import already pending"),
            Self::NoPendingMigration => write!(f, "migration: no pending import for contract"),
            Self::ChunkContractMismatch => write!(f, "migration: chunk contract mismatch"),
            Self::ChunkBlockMismatch => write!(f, "migration: chunk block mismatch"),
            Self::ChunkTooLarge { slots, max } => {
                write!(f, "migration: {slots} slots exceeds bound {max}")
            }
            Self::SlotAbsent(slot) => write!(f, "migration: absent slot 0x{}", hex::encode(slot)),
            Self::SlotValueMismatch {
                slot,
                claimed,
                proven,
            } => write!(
                f,
                "migration: slot 0x{} claimed 0x{} != proven 0x{}",
                hex::encode(slot),
                hex::encode(claimed),
                hex::encode(proven)
            ),
            Self::SlotConflicts { slot } => {
                write!(f, "migration: conflicting values for slot 0x{}", hex::encode(slot))
            }
            Self::StorageRootMismatch { expected, computed } => write!(
                f,
                "migration: storage root 0x{} != proven 0x{}",
                hex::encode(computed),
                hex::encode(expected)
            ),
            Self::Fee(e) => write!(f, "migration: {e}"),
            Self::InsufficientMigratorBalance(m) => write!(f, "migration fee: {m}"),
            Self::StateError(m) => write!(f, "migration state: {m}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<DeploymentProofError> for ImportError {
    fn from(error: DeploymentProofError) -> Self {
        Self::Deployment(error)
    }
}

impl From<AccountProofError> for ImportError {
    fn from(e: AccountProofError) -> Self {
        Self::Proof(e)
    }
}

impl From<MigrationFeeOverflow> for ImportError {
    fn from(error: MigrationFeeOverflow) -> Self {
        Self::Fee(error)
    }
}

/// One proven storage slot in a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEntry {
    pub slot: [u8; 32],
    pub value: [u8; 32],
    pub proof_nodes: Vec<Vec<u8>>,
}

/// Payload of `MigrationTx::ImportEvmStorageChunk` (8.12.2 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEvmStorageChunk {
    pub contract: [u8; 20],
    pub source_block: u64,
    pub slots: Vec<StorageEntry>,
}

/// Inputs starting a verified EVM contract migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRequest {
    pub chain_id: u64,
    pub source_chain_id: u64,
    pub source_domain: String,
    pub source_block: u64,
    pub deployment: DeploymentProof,
    pub authorization: MigrationAuthorization,
    pub state_root: [u8; 32],
    pub account_proof: Vec<Vec<u8>>,
    pub code: Vec<u8>,
    pub occupied: bool,
}

/// Proven provenance recorded on the migrated EVM account (`imported_from`, 8.12.2 item 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSource {
    pub domain: String,
    pub block: u64,
    pub address: [u8; 20],
}

/// Completed migration output installed by `FinalizeEvmImport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub address: [u8; 20],
    pub nonce: u64,
    pub code: Vec<u8>,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
    pub storage: Vec<([u8; 32], [u8; 32])>,
    pub imported_from: ImportSource,
    pub usage: MigrationUsage,
    pub fee: MigrationFeeQuote,
}

/// In-progress verified EVM migration staged in `ExecutionState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    source: ImportSource,
    account: EvmAccount,
    code: Vec<u8>,
    storage: BTreeMap<[u8; 32], [u8; 32]>,
    proof_nodes: u64,
}

/// Consensus-level EVM migration transaction variants ( 2/3 door).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationTx {
    /// Verifies deployment authority + account proof and stages a [`MigrationPlan`].
    BeginEvmImport(Box<MigrationRequest>),
    /// Proves and stages a batch of storage slots into a pending [`MigrationPlan`].
    ImportEvmStorageChunk(ImportEvmStorageChunk),
    /// Verifies complete `storage_root`, charges migration fee, and installs EVM state.
    FinalizeEvmImport { contract: [u8; 20] },
}

/// Outcome returned when applying a [`MigrationTx`] in a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationTxOutcome {
    Started { contract: [u8; 20], source_block: u64 },
    ChunkImported { contract: [u8; 20], slots: usize },
    Finalized(Box<MigrationRecord>),
}

/// Verifies deployment authority and the finalized source account proof.
pub fn begin_import(request: MigrationRequest) -> Result<MigrationPlan, ImportError> {
    if request.authorization.budlum_chain_id != request.chain_id {
        return Err(ImportError::ChainMismatch {
            signed: request.authorization.budlum_chain_id,
            expected: request.chain_id,
        });
    }
    if request.authorization.source_block != request.source_block {
        return Err(ImportError::SourceBlockMismatch);
    }
    if request.deployment.deployment_block > request.source_block {
        return Err(ImportError::DeploymentAfterSource {
            deployment_block: request.deployment.deployment_block,
            source_block: request.source_block,
        });
    }
    if request.occupied {
        return Err(ImportError::AddressOccupied);
    }
    let evidence = verify_deployment(&request.deployment, request.source_chain_id)?;
    if request.authorization.contract != evidence.contract {
        return Err(ImportError::ContractMismatch);
    }
    let signer = recover_address(
        &request.authorization.digest(),
        &request.authorization.signature,
    )
    .map_err(ImportError::Signature)?;
    if signer != evidence.deployer {
        return Err(ImportError::NotTheDeployer {
            signed: signer,
            deployer: evidence.deployer,
        });
    }
    let account = account_proof::verify_account(
        &request.account_proof,
        &request.state_root,
        &evidence.contract,
    )?;
    account_proof::check_code(&request.code, &account.code_hash)?;
    let proof_nodes = request
        .deployment
        .proof_node_count()
        .checked_add(request.account_proof.len())
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(MigrationFeeOverflow)?;
    Ok(MigrationPlan {
        source: ImportSource {
            domain: request.source_domain,
            block: request.source_block,
            address: evidence.contract,
        },
        account,
        code: request.code,
        storage: BTreeMap::new(),
        proof_nodes,
    })
}

impl MigrationPlan {
    /// Proven source account metadata.
    #[must_use]
    pub fn account(&self) -> &EvmAccount {
        &self.account
    }

    /// Source provenance metadata.
    #[must_use]
    pub fn source(&self) -> &ImportSource {
        &self.source
    }

    /// Atomically verifies and imports one chunk of storage slots (`G-4`: all or nothing).
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
        let mut staged = self.storage.clone();
        let mut next_nodes = self.proof_nodes;
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
            if let Some(existing) = staged.get(&entry.slot) {
                if *existing != entry.value {
                    return Err(ImportError::SlotConflicts { slot: entry.slot });
                }
            }
            staged.insert(entry.slot, entry.value);
            let entry_nodes =
                u64::try_from(entry.proof_nodes.len()).map_err(|_| MigrationFeeOverflow)?;
            next_nodes = next_nodes
                .checked_add(entry_nodes)
                .ok_or(MigrationFeeOverflow)?;
        }
        self.storage = staged;
        self.proof_nodes = next_nodes;
        Ok(chunk.slots.len())
    }

    /// Finalizes the staged migration into a complete [`MigrationRecord`].
    pub fn finalize(
        self,
        fee_schedule: &MigrationFeeSchedule,
    ) -> Result<MigrationRecord, ImportError> {
        let Self {
            source,
            account,
            code,
            storage,
            proof_nodes,
        } = self;
        let proven_code_hash = account_proof::code_hash(&code);
        if proven_code_hash != account.code_hash {
            return Err(ImportError::CodeHashMismatch);
        }
        let computed_storage_root = storage_root::compute_storage_root(&storage);
        if computed_storage_root != account.storage_root {
            return Err(ImportError::StorageRootMismatch {
                expected: account.storage_root,
                computed: computed_storage_root,
            });
        }
        let usage = MigrationUsage {
            proof_nodes,
            code_bytes: u64::try_from(code.len()).map_err(|_| MigrationFeeOverflow)?,
            storage_slots: u64::try_from(storage.len()).map_err(|_| MigrationFeeOverflow)?,
        };
        let fee = quote_migration_fee(usage, fee_schedule)?;
        let storage_vec = storage.into_iter().collect();
        Ok(MigrationRecord {
            address: source.address,
            nonce: account.nonce.max(1),
            code,
            code_hash: proven_code_hash,
            storage_root: account.storage_root,
            storage: storage_vec,
            imported_from: source,
            usage,
            fee,
        })
    }
}

/// Returns `true` when `addr20` is occupied in UEL EVM state, collides with a native alias
/// or precompile, or already carries native balance (`8.12.2 item 6`).
pub fn is_evm_address_occupied(
    account_state: &AccountState,
    exec_state: &ExecutionState,
    addr20: &[u8; 20],
) -> Result<bool, ImportError> {
    if addr20 == &EVM_UNIVERSAL_PRECOMPILE {
        return Ok(true);
    }
    if exec_state.check_evm_alias_collision(addr20).is_err() {
        return Ok(true);
    }
    if exec_state
        .read(NS_EVM_ACCOUNT, addr20)
        .map_err(ImportError::StateError)?
        .is_some()
    {
        return Ok(true);
    }
    let bud_addr = derive_contract_account(EeId::EVM, addr20);
    if account_state.get_attos_balance(&bud_addr) > 0 {
        return Ok(true);
    }
    Ok(false)
}

fn evm_storage_key(addr: &[u8; 20], slot: &[u8; 32]) -> [u8; 52] {
    let mut k = [0u8; 52];
    if let Some(a) = k.get_mut(..20) {
        a.copy_from_slice(addr);
    }
    if let Some(s) = k.get_mut(20..52) {
        s.copy_from_slice(slot);
    }
    k
}

/// Applies one [`MigrationTx`] atomically against `state` ( 2/3 installation door).
///
/// Charges the verified migration fee from `migrator` to `reward_pool_account()` on
/// `FinalizeEvmImport`, installs code and storage at `record.address`, records
/// `imported_from`, and leaves the contract's native balance at `0`.
pub fn apply_migration_tx(
    state: &mut AccountState,
    migrator: &Address,
    tx: MigrationTx,
    fee_schedule: &MigrationFeeSchedule,
) -> Result<MigrationTxOutcome, ImportError> {
    match tx {
        MigrationTx::BeginEvmImport(mut req) => {
            let target = req.authorization.contract;
            let hex_addr = hex::encode(target);
            if state
                .execution_state
                .pending_evm_migrations
                .contains_key(&hex_addr)
            {
                return Err(ImportError::MigrationAlreadyPending);
            }
            let live_occupied =
                is_evm_address_occupied(state, &state.execution_state, &target)?;
            req.occupied = req.occupied || live_occupied;
            let plan = begin_import(*req)?;
            let actual = plan.source().address;
            let actual_hex = hex::encode(actual);
            if state
                .execution_state
                .pending_evm_migrations
                .contains_key(&actual_hex)
            {
                return Err(ImportError::MigrationAlreadyPending);
            }
            if is_evm_address_occupied(state, &state.execution_state, &actual)? {
                return Err(ImportError::AddressOccupied);
            }
            let source_block = plan.source().block;
            state
                .execution_state
                .pending_evm_migrations
                .insert(actual_hex, plan);
            Ok(MigrationTxOutcome::Started {
                contract: actual,
                source_block,
            })
        }
        MigrationTx::ImportEvmStorageChunk(chunk) => {
            let hex_addr = hex::encode(chunk.contract);
            let plan = state
                .execution_state
                .pending_evm_migrations
                .get_mut(&hex_addr)
                .ok_or(ImportError::NoPendingMigration)?;
            let count = plan.import_chunk(&chunk)?;
            Ok(MigrationTxOutcome::ChunkImported {
                contract: chunk.contract,
                slots: count,
            })
        }
        MigrationTx::FinalizeEvmImport { contract } => {
            if is_evm_address_occupied(state, &state.execution_state, &contract)? {
                return Err(ImportError::AddressOccupied);
            }
            let hex_addr = hex::encode(contract);
            let plan = state
                .execution_state
                .pending_evm_migrations
                .get(&hex_addr)
                .cloned()
                .ok_or(ImportError::NoPendingMigration)?;
            let record = plan.finalize(fee_schedule)?;

            let acct_rec = EvmAccountRecord {
                nonce: record.nonce,
                code_hash: Some(hex::encode(record.code_hash)),
                imported_from: Some(record.imported_from.clone()),
            };
            let acct_bytes = serde_json::to_vec(&acct_rec)
                .map_err(|e| ImportError::StateError(e.to_string()))?;

            // Charge migrator BEFORE mutating execution namespaces (`G-4` atomicity).
            if record.fee.total_attos > 0 {
                let pool = reward_pool_account();
                state
                    .transfer_attos_in_unit(
                        migrator,
                        &pool,
                        record.fee.total_attos,
                        BudEnvUnit::EvmWei,
                    )
                    .map_err(ImportError::InsufficientMigratorBalance)?;
            }

            state
                .execution_state
                .write(NS_EVM_CODE, &record.code_hash, Some(&record.code))
                .map_err(ImportError::StateError)?;
            state
                .execution_state
                .write(NS_EVM_ACCOUNT, &record.address, Some(&acct_bytes))
                .map_err(ImportError::StateError)?;
            for (slot, val) in &record.storage {
                if *val != [0u8; 32] {
                    let sk = evm_storage_key(&record.address, slot);
                    state
                        .execution_state
                        .write(NS_EVM_STORAGE, &sk, Some(val))
                        .map_err(ImportError::StateError)?;
                }
            }
            state
                .execution_state
                .pending_evm_migrations
                .remove(&hex_addr);

            Ok(MigrationTxOutcome::Finalized(Box::new(record)))
        }
    }
}

fn word_from_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    if let Some(dst) = word.get_mut(24..32) {
        dst.copy_from_slice(&value.to_be_bytes());
    }
    word
}

fn word_from_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    if let Some(dst) = word.get_mut(12..32) {
        dst.copy_from_slice(address);
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::account::ATTOS_PER_ATOM;
    use crate::cross_domain::evm::rlp::{self, Item};
    use crate::execution::coordinator::evm_ee::compute_create2_address;
    use crate::execution::coordinator::foreign::ethereum::sign_eip1559_tx;
    use crate::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
    use crate::execution::coordinator::{
        ExecutionCoordinator, UelAction, UelReceiptStatus, UelTx,
    };
    use crate::rpc::compat::ethereum::handle_eth_jsonrpc;
    use budlum_uel_abi::BlockContext;
    use k256::ecdsa::SigningKey as SecpSigningKey;

    const DEPLOYER: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const CONTRACT: &str = "a3183498b579bd228aa2b62101c40cc1da978f24";
    const SOURCE_CHAIN_ID: u64 = 11_155_111;
    const DEPLOYMENT_TX_PARTS: &[&str] = &[
        "f85807843b9aca00830f4240808084600060008401546d72a02f6a69a52fb40df1378d854d",
        "62a2c0d6cc6757bad78f8f2f85b1626815ce4fa8a01752541e338fd7331899b91e94dc7f9c",
        "f88f6ba8abc872ab59aaf63369d4e6c9",
    ];
    const CHAIN_ID: u64 = 45_261;
    const SOURCE_BLOCK: u64 = 19_000_000;
    const DIGEST: &str = "1c54f42d9a721ba55e152ed0e5c46755a98f842b49ce6b7f62fdb21fd2e4873c";
    const SIG_PARTS: &[&str] = &[
        "edc403919610bc9e64e52cbc8c6cd59251aaa6281ead68fc06491493037f84b1",
        "3a475a7f48338c4109062580d6452955c8049f557658f7a04956a7d8365ff0741c",
    ];
    const OTHER_SIG_PARTS: &[&str] = &[
        "7af821799fb21b71b7122537279cfa28d5f47a3c5eb2d19d9c2a2e8506190b2a",
        "28f996eda74ef31781c1d10e941b91a41436c8bd8d1e06fbec663c77befbc4d91b",
    ];

    fn decode_joined(parts: &[&str]) -> Vec<u8> {
        let s: String = parts.iter().copied().collect();
        hex::decode(s).expect("hex")
    }

    fn address_of(text: &str) -> [u8; 20] {
        hex::decode(text).expect("hex").try_into().expect("20 bytes")
    }

    fn authorization() -> MigrationAuthorization {
        MigrationAuthorization {
            contract: address_of(CONTRACT),
            budlum_chain_id: CHAIN_ID,
            source_block: SOURCE_BLOCK,
            signature: decode_joined(SIG_PARTS),
        }
    }

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

    fn deployment_proof() -> DeploymentProof {
        let transaction = decode_joined(DEPLOYMENT_TX_PARTS);
        let receipt = rlp::encode(&Item::List(vec![
            Item::String(vec![1]),
            Item::String(uint_bytes(21_000)),
            Item::String(vec![0; 256]),
            Item::List(Vec::new()),
        ]));
        let key = rlp::encode(&Item::String(Vec::new()));
        let path = mpt::hp_encode(&mpt::to_nibbles(&key), true);
        let tx_node = rlp::encode(&Item::List(vec![
            Item::String(path.clone()),
            Item::String(transaction.clone()),
        ]));
        let rec_node = rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(receipt),
        ]));
        DeploymentProof {
            deployment_block: SOURCE_BLOCK - 1_000,
            transaction_index: 0,
            transaction,
            transaction_proof: vec![tx_node.clone()],
            transactions_root: mpt::keccak256(&tx_node),
            receipt_proof: vec![rec_node.clone()],
            receipts_root: mpt::keccak256(&rec_node),
            factory: None,
        }
    }

    fn fee_schedule() -> MigrationFeeSchedule {
        MigrationFeeSchedule {
            bgu_per_proof_node: 10,
            bgu_per_code_byte: 2,
            bgu_per_storage_slot: 100,
            attos_per_bgu: 3,
            attos_per_storage_byte: 5,
        }
    }

    fn slot_fixture(slot: &[u8; 32], value: u128) -> (Vec<u8>, [u8; 32]) {
        let node = leaf(
            &mpt::keccak256(slot),
            rlp::encode(&Item::String(uint_bytes(value))),
        );
        let root = mpt::keccak256(&node);
        (node, root)
    }

    fn sample_code() -> Vec<u8> {
        // Runtime EVM code: `PUSH0 SLOAD PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN`
        // Returns the 32-byte word stored at slot 0x00!
        vec![0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]
    }

    fn request_with_code(code: Vec<u8>, slot: [u8; 32], val: u128) -> (MigrationRequest, [u8; 32]) {
        let (_, storage_root) = slot_fixture(&slot, val);
        let account_node = leaf(
            &mpt::keccak256(&address_of(CONTRACT)),
            rlp::encode(&Item::List(vec![
                Item::String(uint_bytes(1)),
                Item::String(uint_bytes(99_000_000_000_000_000_000)),
                Item::String(storage_root.to_vec()),
                Item::String(account_proof::code_hash(&code).to_vec()),
            ])),
        );
        let state_root = mpt::keccak256(&account_node);
        let req = MigrationRequest {
            chain_id: CHAIN_ID,
            source_chain_id: SOURCE_CHAIN_ID,
            source_domain: String::from("sepolia"),
            source_block: SOURCE_BLOCK,
            deployment: deployment_proof(),
            authorization: authorization(),
            state_root,
            account_proof: vec![account_node],
            code,
            occupied: false,
        };
        (req, storage_root)
    }

    #[test]
    fn uel_migration_requires_deployer_authorization() {
        assert_eq!(hex::encode(authorization().digest()), DIGEST);
        let (req, _) = request_with_code(sample_code(), [0u8; 32], 42);
        assert!(begin_import(req.clone()).is_ok());

        let mut other = req.clone();
        other.authorization.signature = decode_joined(OTHER_SIG_PARTS);
        assert!(matches!(
            begin_import(other),
            Err(ImportError::NotTheDeployer { .. })
        ));

        let mut other_chain = req.clone();
        other_chain.authorization.budlum_chain_id = CHAIN_ID + 1;
        assert_eq!(
            begin_import(other_chain),
            Err(ImportError::ChainMismatch {
                signed: CHAIN_ID + 1,
                expected: CHAIN_ID,
            })
        );

        let mut truncated = req;
        truncated.authorization.signature.truncate(64);
        assert!(matches!(
            begin_import(truncated),
            Err(ImportError::Signature(RecoverError::Length))
        ));
    }

    #[test]
    fn migration_refuses_code_the_account_does_not_hold() {
        let (mut request, _) = request_with_code(sample_code(), [0u8; 32], 42);
        request.code = b"contract Other {}".to_vec();
        assert_eq!(
            begin_import(request),
            Err(ImportError::Proof(AccountProofError::CodeHashMismatch))
        );
    }

    #[test]
    fn migration_refuses_occupied_address() {
        let (mut req, _) = request_with_code(sample_code(), [0u8; 32], 42);
        req.occupied = true;
        assert_eq!(begin_import(req), Err(ImportError::AddressOccupied));

        // Live coordinator check: pre-existing EVM account at target refuses BeginEvmImport.
        let mut state = AccountState::new();
        let migrator = Address::from([0x71u8; 32]);
        state.credit_account(&migrator, 100);
        state
            .execution_state
            .write(NS_EVM_ACCOUNT, &address_of(CONTRACT), Some(b"{}"))
            .expect("occupy target");
        let (live_req, _) = request_with_code(sample_code(), [0u8; 32], 42);
        assert_eq!(
            apply_migration_tx(
                &mut state,
                &migrator,
                MigrationTx::BeginEvmImport(Box::new(live_req)),
                &fee_schedule(),
            ),
            Err(ImportError::AddressOccupied)
        );
    }

    #[test]
    fn migration_preserves_address_code_and_storage_root() {
        let code = b"contract Token {}".to_vec();
        let slot = [0x42u8; 32];
        let (req, storage_root) = request_with_code(code.clone(), slot, 42);
        let mut plan = begin_import(req).expect("authorized and proven");

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
        assert_eq!(plan.import_chunk(&chunk).expect("chunk verifies"), 1);

        let record = plan.finalize(&fee_schedule()).expect("finalizes");
        assert_eq!(record.address, address_of(CONTRACT));
        assert_eq!(record.code, code);
        assert_eq!(record.code_hash, account_proof::code_hash(&record.code));
        assert_eq!(record.storage_root, storage_root);
        assert_eq!(record.storage, vec![(slot, value)]);
        assert_eq!(record.imported_from.domain, "sepolia");
        assert_eq!(record.imported_from.block, SOURCE_BLOCK);
        assert_eq!(record.imported_from.address, address_of(CONTRACT));
        assert_eq!(record.fee.total_attos, 927);
    }

    #[test]
    fn migration_import_chunk_failure_is_atomic_g4() {
        let slot = [0x42u8; 32];
        let (req, _) = request_with_code(sample_code(), slot, 42);
        let mut plan = begin_import(req).expect("plan");
        let before = plan.clone();

        let (storage_node, _) = slot_fixture(&slot, 42);
        let mut good_val = [0u8; 32];
        good_val[31] = 42;
        let mut bad_val = [0u8; 32];
        bad_val[31] = 99;

        // Entry 0 passes, entry 1 fails -> plan must remain completely unchanged!
        let mixed = ImportEvmStorageChunk {
            contract: address_of(CONTRACT),
            source_block: SOURCE_BLOCK,
            slots: vec![
                StorageEntry {
                    slot,
                    value: good_val,
                    proof_nodes: vec![storage_node.clone()],
                },
                StorageEntry {
                    slot,
                    value: bad_val,
                    proof_nodes: vec![storage_node],
                },
            ],
        };
        assert!(plan.import_chunk(&mixed).is_err());
        assert_eq!(plan, before);
    }

    #[test]
    fn migration_factory_create2_authority_belongs_to_factory_deployer() {
        // Key 1 = factory deployer; Key 2 = caller invoking factory.
        let factory_sk = [0x01u8; 32];
        let caller_sk = [0x02u8; 32];
        let fac_signing = SecpSigningKey::from_bytes((&factory_sk).into()).expect("sk1");
        let fac_deployer = address_of(DEPLOYER);

        let fac_proof = deployment_proof();
        let factory_addr = address_of(CONTRACT);
        let salt = [0x77u8; 32];
        let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
        let child_contract = compute_create2_address(&factory_addr, &salt, &init_code);

        let caller_tx = sign_eip1559_tx(
            &caller_sk,
            SOURCE_CHAIN_ID,
            0,
            1_000,
            2_000,
            100_000,
            Some(factory_addr),
            0,
            &init_code,
            &[],
        )
        .expect("sign caller factory invocation");
        let receipt = {
            let mut r = vec![0x02];
            r.extend_from_slice(&rlp::encode(&Item::List(vec![
                Item::String(vec![1]),
                Item::String(uint_bytes(80_000)),
                Item::String(vec![0; 256]),
                Item::List(Vec::new()),
            ])));
            r
        };
        let key = rlp::encode(&Item::String(Vec::new()));
        let path = mpt::hp_encode(&mpt::to_nibbles(&key), true);
        let tx_node = rlp::encode(&Item::List(vec![
            Item::String(path.clone()),
            Item::String(caller_tx.clone()),
        ]));
        let rec_node = rlp::encode(&Item::List(vec![Item::String(path), Item::String(receipt)]));
        let child_dep = DeploymentProof {
            deployment_block: SOURCE_BLOCK - 500,
            transaction_index: 0,
            transaction: caller_tx,
            transaction_proof: vec![tx_node.clone()],
            transactions_root: mpt::keccak256(&tx_node),
            receipt_proof: vec![rec_node.clone()],
            receipts_root: mpt::keccak256(&rec_node),
            factory: Some(FactoryCreationEvidence {
                factory_deployment: Box::new(fac_proof),
                derivation: FactoryDerivation::Create2 { salt, init_code },
            }),
        };

        let ev = verify_deployment(&child_dep, SOURCE_CHAIN_ID).expect("factory proof valid");
        assert_eq!(ev.contract, child_contract);
        assert_eq!(ev.deployer, fac_deployer);

        let mut auth = MigrationAuthorization {
            contract: child_contract,
            budlum_chain_id: CHAIN_ID,
            source_block: SOURCE_BLOCK,
            signature: Vec::new(),
        };
        let (sig, rec_id) = fac_signing
            .sign_prehash_recoverable(&auth.digest())
            .expect("sign auth");
        auth.signature.extend_from_slice(&sig.to_bytes());
        auth.signature.push(rec_id.to_byte());

        let code = sample_code();
        let empty_root = storage_root::compute_storage_root(&BTreeMap::new());
        let acc_node = leaf(
            &mpt::keccak256(&child_contract),
            rlp::encode(&Item::List(vec![
                Item::String(uint_bytes(1)),
                Item::String(Vec::new()),
                Item::String(empty_root.to_vec()),
                Item::String(account_proof::code_hash(&code).to_vec()),
            ])),
        );
        let req = MigrationRequest {
            chain_id: CHAIN_ID,
            source_chain_id: SOURCE_CHAIN_ID,
            source_domain: String::from("sepolia"),
            source_block: SOURCE_BLOCK,
            deployment: child_dep,
            authorization: auth,
            state_root: mpt::keccak256(&acc_node),
            account_proof: vec![acc_node],
            code,
            occupied: false,
        };
        assert!(begin_import(req).is_ok());
    }

    #[test]
    fn migration_tx_installs_sepolia_erc20_and_executes_live_in_evm_ee() {
        let mut state = AccountState::new();
        let mut coord = ExecutionCoordinator::new();
        let migrator = Address::from([0x81u8; 32]);
        let caller = Address::from([0x82u8; 32]);
        let proposer = Address::from([0x83u8; 32]);
        state.credit_account(&migrator, 100);
        state.credit_account(&caller, 100);
        let initial_supply = state.total_bud_committed_attos();

        let slot0 = [0u8; 32];
        let code = sample_code();
        let (req, _) = request_with_code(code.clone(), slot0, 0xBEEF);
        let sched = MigrationFeeSchedule::TESTNET_DEFAULT;

        coord
            .apply_evm_migration(
                &mut state,
                &migrator,
                MigrationTx::BeginEvmImport(Box::new(req)),
                &sched,
            )
            .expect("BeginEvmImport");

        let (storage_node, _) = slot_fixture(&slot0, 0xBEEF);
        let mut val_word = [0u8; 32];
        val_word[30] = 0xBE;
        val_word[31] = 0xEF;
        coord
            .apply_evm_migration(
                &mut state,
                &migrator,
                MigrationTx::ImportEvmStorageChunk(ImportEvmStorageChunk {
                    contract: address_of(CONTRACT),
                    source_block: SOURCE_BLOCK,
                    slots: vec![StorageEntry {
                        slot: slot0,
                        value: val_word,
                        proof_nodes: vec![storage_node],
                    }],
                }),
                &sched,
            )
            .expect("ImportEvmStorageChunk");

        let out = coord
            .apply_evm_migration(
                &mut state,
                &migrator,
                MigrationTx::FinalizeEvmImport {
                    contract: address_of(CONTRACT),
                },
                &sched,
            )
            .expect("FinalizeEvmImport");
        let MigrationTxOutcome::Finalized(rec) = out else {
            panic!("expected Finalized");
        };
        assert!(rec.fee.total_attos > 0);
        assert_eq!(state.total_bud_committed_attos(), initial_supply);

        // Source ETH balance (99 ETH) did NOT travel: contract native balance is 0!
        let contract_bud = derive_contract_account(EeId::EVM, &address_of(CONTRACT));
        assert_eq!(state.get_attos_balance(&contract_bud), 0);

        // Live call in `EvmEe` at the exact Sepolia address returns imported slot 0 (`0xBEEF`)!
        let recs = state
            .execute_uel_block(
                &mut coord,
                BlockContext {
                    height: 1,
                    timestamp_ms: 1_762_000_000_000,
                    chain_id: CHAIN_ID,
                    prev_randao: [0; 32],
                    base_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS,
                },
                proposer,
                &[UelTx {
                    tx_hash: [0x99u8; 32],
                    sender: caller,
                    nonce: 0,
                    ee: EeId::EVM,
                    action: UelAction::Call {
                        target: address_of(CONTRACT).to_vec(),
                        input: Vec::new(),
                    },
                    value_attos: 0,
                    gas_limit_bgu: 200_000,
                    max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 2,
                    max_priority_fee_per_bgu_attos: 0,
                }],
            )
            .expect("execute migrated contract in EvmEe");
        assert_eq!(recs[0].status, UelReceiptStatus::Success);
        assert_eq!(recs[0].output.as_slice(), &val_word);
        assert_eq!(
            state.total_bud_committed_attos()
                + u128::from(state.burned_total) * u128::from(ATTOS_PER_ATOM),
            initial_supply
        );

        // Ethereum RPC `eth_getCode` and `bud_getImportedContract` see the migrated contract!
        let get_code_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getCode",
            "params": [format!("0x{CONTRACT}"), "latest"]
        })
        .to_string();
        let get_code_resp: serde_json::Value =
            serde_json::from_str(&handle_eth_jsonrpc(&state, &get_code_req)).expect("json");
        assert_eq!(
            get_code_resp["result"].as_str(),
            Some(format!("0x{}", hex::encode(&code)).as_str())
        );

        let get_imp_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "bud_getImportedContract",
            "params": [format!("0x{CONTRACT}")]
        })
        .to_string();
        let get_imp_resp: serde_json::Value =
            serde_json::from_str(&handle_eth_jsonrpc(&state, &get_imp_req)).expect("json");
        assert_eq!(get_imp_resp["result"]["domain"].as_str(), Some("sepolia"));
        assert_eq!(
            get_imp_resp["result"]["block"].as_u64(),
            Some(SOURCE_BLOCK)
        );
    }
}
