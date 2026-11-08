//! `revm::Database` adapters over `HostApi` and `HostRead` (`Section 8.7.1`).
//!
//! State layout in the coordinator's sparse-Merkle overlay:
//! - `ee/evm/account`: key = 20B EVM address, value = 40B (`nonce` u64 LE || `code_hash` 32B)
//! - `ee/evm/code`: key = 32-byte `keccak256` code hash, value = raw bytecode bytes
//! - `ee/evm/storage`: key = 52 bytes (`address` 20B || `slot` 32B BE), value = 32B BE word
//! - `uel/alias`: key = 21 bytes (`[EeId::EVM.0]` || `address` 20B) or 20 bytes (`address`),
//!   checked to refuse `CREATE`/`CREATE2` collisions against post-quantum local aliases.

use std::collections::BTreeMap;
use std::fmt;

use budlum_uel_abi::{
    BudAmount, EeId, EeIdentity, EeLog, HostApi, HostError, HostRead, Namespace, UniversalCall,
    UniversalResult, MAX_LOG_TOPICS,
};
use revm::database_interface::{DBErrorMarker, Database};
use revm::primitives::{Address, Bytes, Log, StorageKey, StorageValue, B256, KECCAK_EMPTY, U256};
use revm::state::{AccountInfo, Bytecode, EvmState};
use sha2::{Digest, Sha256};

pub const NS_EVM_ACCOUNT: &str = "ee/evm/account";
pub const NS_EVM_CODE: &str = "ee/evm/code";
pub const NS_EVM_STORAGE: &str = "ee/evm/storage";
pub const NS_UEL_ALIAS: &str = "uel/alias";

/// Error bridged from `HostRead` / `HostApi` into `revm::Database`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDbError(pub String);

impl fmt::Display for HostDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostDbError {}

impl DBErrorMarker for HostDbError {}

impl From<HostError> for HostDbError {
    fn from(err: HostError) -> Self {
        Self(err.to_string())
    }
}

pub fn ns(name: &str) -> Result<Namespace, HostDbError> {
    Namespace::new(name).map_err(|e| HostDbError(e.to_string()))
}

pub fn evm_identity(address: Address) -> EeIdentity {
    EeIdentity {
        ee: EeId::EVM,
        id: address.as_slice().to_vec(),
    }
}

fn encode_account_meta(nonce: u64, code_hash: B256) -> [u8; 40] {
    let mut out = [0u8; 40];
    if let Some((n_dst, c_dst)) = out.split_at_mut_checked(8) {
        n_dst.copy_from_slice(&nonce.to_le_bytes());
        c_dst.copy_from_slice(code_hash.as_slice());
    }
    out
}

fn decode_account_meta(bytes: &[u8]) -> Result<(u64, B256), HostDbError> {
    if bytes.len() != 40 {
        return Err(HostDbError(format!(
            "corrupt ee/evm/account value of {} bytes",
            bytes.len()
        )));
    }
    let mut nonce_bytes = [0u8; 8];
    if let Some(src) = bytes.get(..8) {
        nonce_bytes.copy_from_slice(src);
    }
    let mut hash_bytes = [0u8; 32];
    if let Some(src) = bytes.get(8..40) {
        hash_bytes.copy_from_slice(src);
    }
    Ok((u64::from_le_bytes(nonce_bytes), B256::from(hash_bytes)))
}

fn storage_slot_key(address: Address, slot: StorageKey) -> [u8; 52] {
    let mut key = [0u8; 52];
    if let Some((addr_dst, slot_dst)) = key.split_at_mut_checked(20) {
        addr_dst.copy_from_slice(address.as_slice());
        slot_dst.copy_from_slice(&slot.to_be_bytes::<32>());
    }
    key
}

fn deterministic_block_hash(chain_id: u64, number: u64) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_EVM_BLOCKHASH_V1");
    hasher.update(chain_id.to_le_bytes());
    hasher.update(number.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    B256::from(digest)
}

fn read_basic_from_host(
    host: &dyn HostRead,
    address: Address,
) -> Result<Option<AccountInfo>, HostDbError> {
    let ns_acc = ns(NS_EVM_ACCOUNT)?;
    let raw_meta = host.read(&ns_acc, address.as_slice())?;
    let BudAmount(balance_attos) = host.bud_balance(&evm_identity(address))?;

    match raw_meta {
        None if balance_attos == 0 => Ok(None),
        None => Ok(Some(AccountInfo {
            balance: U256::from(balance_attos),
            nonce: 0,
            code_hash: KECCAK_EMPTY,
            code: None,
            ..AccountInfo::default()
        })),
        Some(bytes) => {
            let (nonce, code_hash) = decode_account_meta(&bytes)?;
            let code = if code_hash == KECCAK_EMPTY || code_hash.is_zero() {
                Some(Bytecode::default())
            } else {
                None
            };
            Ok(Some(AccountInfo {
                balance: U256::from(balance_attos),
                nonce,
                code_hash,
                code,
                ..AccountInfo::default()
            }))
        }
    }
}

fn read_code_from_host(host: &dyn HostRead, code_hash: B256) -> Result<Bytecode, HostDbError> {
    if code_hash == KECCAK_EMPTY || code_hash.is_zero() {
        return Ok(Bytecode::default());
    }
    let ns_code = ns(NS_EVM_CODE)?;
    let Some(bytes) = host.read(&ns_code, code_hash.as_slice())? else {
        return Ok(Bytecode::default());
    };
    if bytes.is_empty() {
        return Ok(Bytecode::default());
    }
    let raw = Bytes::from(bytes);
    Ok(Bytecode::new_raw_checked(raw.clone()).unwrap_or_else(|_| Bytecode::new_legacy(raw)))
}

fn read_storage_from_host(
    host: &dyn HostRead,
    address: Address,
    index: StorageKey,
) -> Result<StorageValue, HostDbError> {
    let ns_store = ns(NS_EVM_STORAGE)?;
    let key = storage_slot_key(address, index);
    let Some(bytes) = host.read(&ns_store, &key)? else {
        return Ok(U256::ZERO);
    };
    if bytes.len() > 32 {
        return Err(HostDbError(format!(
            "corrupt ee/evm/storage value of {} bytes",
            bytes.len()
        )));
    }
    Ok(U256::from_be_slice(&bytes))
}

pub fn check_pq_alias_in_host(host: &dyn HostRead, address: Address) -> Result<bool, HostDbError> {
    let ns_alias = ns(NS_UEL_ALIAS)?;
    let mut tagged = [0u8; 21];
    if let Some((tag, body)) = tagged.split_first_mut() {
        *tag = EeId::EVM.0;
        body.copy_from_slice(address.as_slice());
    }
    if host.read(&ns_alias, &tagged)?.is_some() {
        return Ok(true);
    }
    Ok(host.read(&ns_alias, address.as_slice())?.is_some())
}

/// Read-write `revm::Database` backed by `HostApi`.
pub struct HostDb<'a> {
    pub host: &'a mut dyn HostApi,
    pub chain_id: u64,
}

impl<'a> HostDb<'a> {
    pub fn new(host: &'a mut dyn HostApi, chain_id: u64) -> Self {
        Self { host, chain_id }
    }

    pub fn has_pq_alias(&self, address: Address) -> Result<bool, HostDbError> {
        check_pq_alias_in_host(self.host, address)
    }

    pub fn universal_call(&mut self, call: UniversalCall) -> Result<UniversalResult, HostError> {
        self.host.universal_call(call)
    }
}

impl Database for HostDb<'_> {
    type Error = HostDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        read_basic_from_host(self.host, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        read_code_from_host(self.host, code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        read_storage_from_host(self.host, address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(deterministic_block_hash(self.chain_id, number))
    }
}

/// Read-only `revm::Database` backed by `HostRead` for `ExecutionEnvironment::query`.
pub struct ReadOnlyHostDb<'a> {
    pub host: &'a dyn HostRead,
    pub chain_id: u64,
}

impl<'a> ReadOnlyHostDb<'a> {
    pub fn new(host: &'a dyn HostRead, chain_id: u64) -> Self {
        Self { host, chain_id }
    }

    pub fn has_pq_alias(&self, address: Address) -> Result<bool, HostDbError> {
        check_pq_alias_in_host(self.host, address)
    }
}

impl Database for ReadOnlyHostDb<'_> {
    type Error = HostDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        read_basic_from_host(self.host, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        read_code_from_host(self.host, code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        read_storage_from_host(self.host, address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(deterministic_block_hash(self.chain_id, number))
    }
}

fn u256_to_u128_clamped(val: U256) -> Result<u128, HostError> {
    u128::try_from(val).map_err(|_| HostError::Invalid("EVM balance exceeds u128 attoBUD".into()))
}

/// Persist finalized `revm` state diff and logs into `HostApi` in canonical key order.
pub fn commit_evm_state(
    host: &mut dyn HostApi,
    state: &EvmState,
    logs: &[Log],
) -> Result<(), HostError> {
    let ns_acc = Namespace::new(NS_EVM_ACCOUNT).map_err(|e| HostError::Invalid(e.to_string()))?;
    let ns_code = Namespace::new(NS_EVM_CODE).map_err(|e| HostError::Invalid(e.to_string()))?;
    let ns_store = Namespace::new(NS_EVM_STORAGE).map_err(|e| HostError::Invalid(e.to_string()))?;

    // Sort touched accounts canonically by 20-byte address for deterministic HostApi writes.
    let mut ordered = BTreeMap::new();
    for (addr, acc) in state {
        if acc.is_touched() {
            ordered.insert(*addr, acc);
        }
    }

    let mut debits: Vec<(Address, u128)> = Vec::new();
    let mut credits: Vec<(Address, u128)> = Vec::new();

    for (&addr, acc) in &ordered {
        let orig_bal = u256_to_u128_clamped(acc.original_info().balance)?;
        let curr_bal = u256_to_u128_clamped(acc.info.balance)?;
        if curr_bal < orig_bal {
            debits.push((addr, orig_bal - curr_bal));
        } else if curr_bal > orig_bal {
            credits.push((addr, curr_bal - orig_bal));
        }

        if acc.is_selfdestructed() {
            host.write(&ns_acc, addr.as_slice(), None)?;
            let mut slots: Vec<_> = acc.storage.iter().collect();
            slots.sort_by_key(|(k, _)| *k);
            for (slot_key, _) in slots {
                let key = storage_slot_key(addr, *slot_key);
                host.write(&ns_store, &key, None)?;
            }
            continue;
        }

        let code_hash = acc.info.code_hash;
        if code_hash != KECCAK_EMPTY && !code_hash.is_zero() {
            if let Some(code) = &acc.info.code {
                let raw = code.original_byte_slice();
                if !raw.is_empty() {
                    host.write(&ns_code, code_hash.as_slice(), Some(raw))?;
                }
            }
        }

        if acc.info.nonce == 0 && (code_hash == KECCAK_EMPTY || code_hash.is_zero()) {
            host.write(&ns_acc, addr.as_slice(), None)?;
        } else {
            let meta = encode_account_meta(acc.info.nonce, code_hash);
            host.write(&ns_acc, addr.as_slice(), Some(&meta))?;
        }

        let mut slots: Vec<_> = acc.storage.iter().collect();
        slots.sort_by_key(|(k, _)| *k);
        for (slot_key, slot) in slots {
            if slot.original_value != slot.present_value {
                let key = storage_slot_key(addr, *slot_key);
                if slot.present_value.is_zero() {
                    host.write(&ns_store, &key, None)?;
                } else {
                    let word = slot.present_value.to_be_bytes::<32>();
                    host.write(&ns_store, &key, Some(&word))?;
                }
            }
        }
    }

    // Reconcile native attoBUD movements across touched EVM accounts.
    let mut d_idx = 0usize;
    let mut c_idx = 0usize;
    while d_idx < debits.len() && c_idx < credits.len() {
        let (from_addr, rem_d) = debits[d_idx];
        let (to_addr, rem_c) = credits[c_idx];
        let step = rem_d.min(rem_c);
        if step > 0 {
            host.bud_transfer(&evm_identity(from_addr), &evm_identity(to_addr), step)?;
        }
        debits[d_idx].1 -= step;
        credits[c_idx].1 -= step;
        if debits[d_idx].1 == 0 {
            d_idx += 1;
        }
        if credits[c_idx].1 == 0 {
            c_idx += 1;
        }
    }
    // Any remaining debit (e.g. SELFDESTRUCT burn) moves to 0x0000...0000.
    for &(from_addr, rem_d) in debits.get(d_idx..).unwrap_or(&[]) {
        if rem_d > 0 && from_addr != Address::ZERO {
            host.bud_transfer(&evm_identity(from_addr), &evm_identity(Address::ZERO), rem_d)?;
        }
    }

    for log in logs {
        let topics: Vec<Vec<u8>> = log
            .data
            .topics()
            .iter()
            .take(MAX_LOG_TOPICS)
            .map(|t| t.as_slice().to_vec())
            .collect();
        host.emit_log(EeLog {
            emitter: evm_identity(log.address),
            topics,
            data: log.data.data.to_vec(),
        })?;
    }

    Ok(())
}
