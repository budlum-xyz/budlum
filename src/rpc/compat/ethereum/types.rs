//! Wire types, 2048-bit EIP-standard log Bloom calculation, and `execution_root`
//! block/receipt serializers for the Ethereum JSON-RPC gateway (`WP-28`).

use serde::{Deserialize, Serialize};

use crate::cross_domain::evm::mpt::keccak256;

/// Format a `u64` quantity as minimal `"0x..."` Ethereum hex (`"0x0"` for zero).
///
/// Convenience: shared across `eth_*` response formatters.
#[must_use]
pub fn format_u64_hex(val: u64) -> String {
    format!("0x{val:x}")
}

/// Format a `u128` quantity (wei / attoBUD) as minimal `"0x..."` Ethereum hex.
///
/// Convenience: shared across `eth_getBalance`, `eth_gasPrice`, and `eth_feeHistory`.
#[must_use]
pub fn format_u128_hex(val: u128) -> String {
    format!("0x{val:x}")
}

/// Format raw bytes as lowercase `"0x..."` Ethereum hex.
///
/// Convenience: shared across `eth_getCode`, `eth_call`, and hash serializers.
#[must_use]
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Parse a `"0x..."` Ethereum quantity into `u64`.
///
/// Convenience: used when parsing block numbers, gas limits, and filter bounds.
pub fn parse_quantity_u64(raw: &str) -> Result<u64, String> {
    let trimmed = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    if trimmed.is_empty() {
        return Err("empty hex quantity".into());
    }
    u64::from_str_radix(trimmed, 16).map_err(|e| format!("invalid hex quantity '{raw}': {e}"))
}

/// Parse a 20-byte `"0x..."` Ethereum address.
///
/// Convenience: used across `eth_getBalance`, `eth_getCode`, `eth_call`, and `eth_getLogs`.
pub fn parse_eth_address(raw: &str) -> Result<[u8; 20], String> {
    let clean = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    let decoded = hex::decode(clean).map_err(|e| format!("invalid hex address: {e}"))?;
    decoded
        .try_into()
        .map_err(|_| "expected 20-byte Ethereum address".to_string())
}

/// Parse a 32-byte `"0x..."` hash or storage slot (left-padding shorter quantities for slots).
///
/// Convenience: used by `eth_getStorageAt`, `eth_getBlockByHash`, and `eth_getTransactionByHash`.
pub fn parse_eth_word32(raw: &str, allow_short_quantity: bool) -> Result<[u8; 32], String> {
    let clean = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    if clean.len() > 64 {
        return Err("hex value exceeds 32 bytes".into());
    }
    if !allow_short_quantity && clean.len() != 64 {
        return Err("expected 32-byte hex hash".into());
    }
    let padded = if clean.len() % 2 == 1 {
        format!("0{clean}")
    } else {
        clean.to_string()
    };
    let bytes = hex::decode(&padded).map_err(|e| format!("invalid hex word: {e}"))?;
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    if let Some(dst) = out.get_mut(start..) {
        dst.copy_from_slice(&bytes);
    }
    Ok(out)
}

/// Block selector accepted by `eth_getBalance`, `eth_call`, `eth_getBlockByNumber`, etc.
///
/// Convenience: deserializes standard Ethereum block tags and hex block numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSelector {
    Latest,
    Earliest,
    Pending,
    Safe,
    Finalized,
    Number(u64),
}

impl BlockSelector {
    /// Parse an optional Ethereum block parameter (`None` defaults to `Latest`).
    ///
    /// Convenience: shared across state-reading RPC endpoints.
    pub fn parse_opt(param: Option<&str>) -> Result<Self, String> {
        match param.unwrap_or("latest") {
            "latest" => Ok(Self::Latest),
            "earliest" => Ok(Self::Earliest),
            "pending" => Ok(Self::Pending),
            "safe" => Ok(Self::Safe),
            "finalized" => Ok(Self::Finalized),
            other => parse_quantity_u64(other).map(Self::Number),
        }
    }

    /// Resolve this selector against the node's current head height.
    ///
    /// Convenience: maps symbolic tags onto concrete block heights.
    #[must_use]
    pub const fn resolve(self, head_height: u64) -> Option<u64> {
        match self {
            Self::Latest | Self::Pending | Self::Safe | Self::Finalized => Some(head_height),
            Self::Earliest => Some(0),
            Self::Number(n) if n <= head_height => Some(n),
            Self::Number(_) => None,
        }
    }
}

/// Call request object passed to `eth_call`, `eth_estimateGas`, `eth_createAccessList`,
/// and `debug_traceCall`.
///
/// Convenience: serde input model for Ethereum call simulation endpoints.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthCallObject {
    pub from: Option<String>,
    pub to: Option<String>,
    pub gas: Option<String>,
    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub value: Option<String>,
    /// Modern `input` calldata field (`EIP-1474`).
    pub input: Option<String>,
    /// Legacy `data` calldata alias accepted for ethers/viem/Foundry compatibility.
    pub data: Option<String>,
}

impl EthCallObject {
    /// Extract decoded calldata bytes from `input` (preferred) or `data`.
    ///
    /// Convenience: normalizes `input` vs `data` across Ethereum tooling versions.
    pub fn decoded_input(&self) -> Result<Vec<u8>, String> {
        let Some(hex_str) = self.input.as_deref().or(self.data.as_deref()) else {
            return Ok(Vec::new());
        };
        let clean = hex_str
            .strip_prefix("0x")
            .or_else(|| hex_str.strip_prefix("0X"))
            .unwrap_or(hex_str);
        if clean.is_empty() {
            return Ok(Vec::new());
        }
        hex::decode(clean).map_err(|e| format!("invalid calldata hex: {e}"))
    }
}

/// Indexed EVM log record stored for receipts, `eth_getLogs`, and `logs` subscriptions.
///
/// Convenience: canonical log representation in the Ethereum compatibility layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthLogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub transaction_hash: [u8; 32],
    pub transaction_index: u32,
    pub log_index: u32,
    pub removed: bool,
}

impl EthLogEntry {
    /// Serialize to the standard Ethereum JSON-RPC log object.
    ///
    /// Convenience: used by `eth_getLogs`, receipts, and `eth_subscribe("logs")`.
    #[must_use]
    pub fn to_rpc_json(&self) -> serde_json::Value {
        let topics_hex: Vec<String> = self.topics.iter().map(|t| format_bytes_hex(t)).collect();
        serde_json::json!({
            "address": format_bytes_hex(&self.address),
            "topics": topics_hex,
            "data": format_bytes_hex(&self.data),
            "blockNumber": format_u64_hex(self.block_number),
            "blockHash": format_bytes_hex(&self.block_hash),
            "transactionHash": format_bytes_hex(&self.transaction_hash),
            "transactionIndex": format_u64_hex(u64::from(self.transaction_index)),
            "logIndex": format_u64_hex(u64::from(self.log_index)),
            "removed": self.removed,
        })
    }
}

fn bloom_insert(bloom: &mut [u8; 256], item: &[u8]) {
    let hash = keccak256(item);
    for pair_idx in [0usize, 2, 4] {
        let Some(hi) = hash.get(pair_idx).copied() else {
            continue;
        };
        let Some(lo) = hash.get(pair_idx + 1).copied() else {
            continue;
        };
        let bit_pos = (u16::from_be_bytes([hi, lo]) & 2047) as usize;
        let byte_idx = 255usize.saturating_sub(bit_pos / 8);
        let mask = 1u8 << (bit_pos % 8);
        if let Some(slot) = bloom.get_mut(byte_idx) {
            *slot |= mask;
        }
    }
}

/// Compute the Yellow Paper 2048-bit (256-byte) logs Bloom filter over `logs`.
///
/// Convenience: populates `logsBloom` on blocks and transaction receipts.
#[must_use]
pub fn compute_logs_bloom(logs: &[EthLogEntry]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for log in logs {
        bloom_insert(&mut bloom, &log.address);
        for topic in &log.topics {
            bloom_insert(&mut bloom, topic);
        }
    }
    bloom
}

/// Summary of an executed Ethereum transaction stored in `EthCompatState`.
///
/// Convenience: serves `eth_getTransactionBy*` and `eth_getTransactionReceipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthStoredTx {
    pub hash: [u8; 32],
    pub tx_type: u8,
    pub chain_id: u64,
    pub nonce: u64,
    pub from: [u8; 20],
    pub to: Option<[u8; 20]>,
    pub contract_address: Option<[u8; 20]>,
    pub value_wei: u128,
    pub input: Vec<u8>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub cumulative_gas_used: u64,
    pub effective_gas_price: u128,
    pub status_success: bool,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub transaction_index: u32,
    pub logs: Vec<EthLogEntry>,
}

impl EthStoredTx {
    /// Standard Ethereum JSON-RPC transaction object.
    ///
    /// Convenience: returned by `eth_getTransactionByHash` and `eth_getTransactionByBlock*`.
    #[must_use]
    pub fn to_tx_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hash": format_bytes_hex(&self.hash),
            "type": format_u64_hex(u64::from(self.tx_type)),
            "chainId": format_u64_hex(self.chain_id),
            "nonce": format_u64_hex(self.nonce),
            "blockHash": format_bytes_hex(&self.block_hash),
            "blockNumber": format_u64_hex(self.block_number),
            "transactionIndex": format_u64_hex(u64::from(self.transaction_index)),
            "from": format_bytes_hex(&self.from),
            "to": self.to.map(|a| format_bytes_hex(&a)),
            "value": format_u128_hex(self.value_wei),
            "gas": format_u64_hex(self.gas_limit),
            "gasPrice": format_u128_hex(self.effective_gas_price),
            "input": format_bytes_hex(&self.input),
        })
    }

    /// Standard Ethereum JSON-RPC receipt object.
    ///
    /// Convenience: returned by `eth_getTransactionReceipt` and `eth_getBlockReceipts`.
    #[must_use]
    pub fn to_receipt_json(&self) -> serde_json::Value {
        let bloom = compute_logs_bloom(&self.logs);
        let logs_json: Vec<serde_json::Value> =
            self.logs.iter().map(EthLogEntry::to_rpc_json).collect();
        serde_json::json!({
            "transactionHash": format_bytes_hex(&self.hash),
            "transactionIndex": format_u64_hex(u64::from(self.transaction_index)),
            "blockHash": format_bytes_hex(&self.block_hash),
            "blockNumber": format_u64_hex(self.block_number),
            "from": format_bytes_hex(&self.from),
            "to": self.to.map(|a| format_bytes_hex(&a)),
            "cumulativeGasUsed": format_u64_hex(self.cumulative_gas_used),
            "effectiveGasPrice": format_u128_hex(self.effective_gas_price),
            "gasUsed": format_u64_hex(self.gas_used),
            "contractAddress": self.contract_address.map(|a| format_bytes_hex(&a)),
            "logs": logs_json,
            "logsBloom": format_bytes_hex(&bloom),
            "type": format_u64_hex(u64::from(self.tx_type)),
            "status": if self.status_success { "0x1" } else { "0x0" },
        })
    }
}

/// Block projection served by `eth_getBlockByNumber`, `eth_getBlockByHash`, and `newHeads`.
///
/// Per Section `8.10` item 5, `stateRoot` carries Budlum's `execution_root`
/// (`BDLM_UEL_ROOT_V1` sparse-Merkle commitment), NOT a Patricia MPT root.
///
/// Convenience: canonical block view for the Ethereum compatibility gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthBlockRecord {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    /// UEL `execution_root` (`BDLM_UEL_ROOT_V1`), serialized in the `stateRoot` field.
    pub execution_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub beneficiary: [u8; 20],
    pub gas_limit: u64,
    pub gas_used: u64,
    pub base_fee_per_gas_wei: u128,
    pub timestamp_secs: u64,
    pub tx_hashes: Vec<[u8; 32]>,
    pub logs_bloom: [u8; 256],
}

impl EthBlockRecord {
    /// Serialize this block to standard Ethereum JSON-RPC (`full_txs = true` embeds tx objects).
    ///
    /// Convenience: shared by `eth_getBlockByNumber`, `eth_getBlockByHash`, and `newHeads`.
    #[must_use]
    pub fn to_rpc_json(&self, full_txs: Option<&[EthStoredTx]>) -> serde_json::Value {
        let txs_val = match full_txs {
            Some(list) => {
                serde_json::Value::Array(list.iter().map(EthStoredTx::to_tx_json).collect())
            }
            None => serde_json::Value::Array(
                self.tx_hashes
                    .iter()
                    .map(|h| serde_json::Value::String(format_bytes_hex(h)))
                    .collect(),
            ),
        };
        serde_json::json!({
            "number": format_u64_hex(self.number),
            "hash": format_bytes_hex(&self.hash),
            "parentHash": format_bytes_hex(&self.parent_hash),
            "sha3Uncles": format_bytes_hex(&[0u8; 32]),
            "miner": format_bytes_hex(&self.beneficiary),
            "stateRoot": format_bytes_hex(&self.execution_root),
            "transactionsRoot": format_bytes_hex(&self.transactions_root),
            "receiptsRoot": format_bytes_hex(&self.receipts_root),
            "logsBloom": format_bytes_hex(&self.logs_bloom),
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "gasLimit": format_u64_hex(self.gas_limit),
            "gasUsed": format_u64_hex(self.gas_used),
            "timestamp": format_u64_hex(self.timestamp_secs),
            "baseFeePerGas": format_u128_hex(self.base_fee_per_gas_wei),
            "mixHash": format_bytes_hex(&[0u8; 32]),
            "nonce": "0x0000000000000000",
            "uncles": [],
            "transactions": txs_val,
        })
    }
}
