//! Deterministic wire payloads between the Execution Coordinator and
//! `budlum-ee-wasm` (`EeId::WASM = 0x02`, `WP-29`).

use serde::{Deserialize, Serialize};

/// Canonical transaction operations executed by `budlum-ee-wasm` (`Section 8.6.1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmTxAction {
    StoreCode {
        /// Base64-encoded `.wasm` binary.
        wasm_b64: String,
    },
    Instantiate {
        code_id: u64,
        admin: Option<String>,
        label: String,
        /// Base64-encoded JSON instantiate message.
        msg_b64: String,
        funds_ubud: u64,
    },
    Instantiate2 {
        code_id: u64,
        admin: Option<String>,
        label: String,
        msg_b64: String,
        funds_ubud: u64,
        /// Base64-encoded salt.
        salt_b64: String,
    },
    Execute {
        contract: String,
        /// Base64-encoded JSON execute message.
        msg_b64: String,
        funds_ubud: u64,
    },
    Migrate {
        contract: String,
        new_code_id: u64,
        msg_b64: String,
    },
    BankSend {
        to_address: String,
        amount_ubud: u64,
    },
}

/// Canonical view queries served by `budlum-ee-wasm::view` (`Section 8.11.5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmViewAction {
    SmartQuery {
        contract: String,
        /// Base64-encoded JSON query message.
        query_b64: String,
    },
    RawQuery {
        contract: String,
        /// Base64-encoded storage key.
        key_b64: String,
    },
    ContractInfo {
        contract: String,
    },
    CodeInfo {
        code_id: u64,
    },
}

/// Stored metadata for an instantiated CosmWasm contract under `ee/wasm/contract`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredContractInfo {
    pub code_id: u64,
    pub creator: String,
    pub admin: Option<String>,
    pub label: String,
    pub created_height: u64,
}

/// Stored metadata for uploaded Wasm code under `ee/wasm/code`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCodeMeta {
    pub code_id: u64,
    pub creator: String,
    pub checksum_hex: String,
}
