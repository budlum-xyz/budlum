//! CosmWasm JSON message/query schema, `BudlumMsg::UniversalCall`,
//! `BudlumQuery::UniversalView`, RFC 4648 Base64 (`Binary`), and BIP-173
//! `"bud"` Bech32 address helpers ( &, `Sections 8.7.2, 8.15`).

use serde::{Deserialize, Serialize};

/// Canonical Bech32 human-readable prefix for Budlum WASM/Cosmos addresses.
pub const BUD_BECH32_HRP: &str = "bud";

/// Custom `CosmosMsg::Custom(BudlumMsg)` extension (`Section 8.7.2` WASM row,).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumMsg {
    /// Atomic cross-environment call; response arrives via `SubMsg` `reply`.
    UniversalCall {
        target_ee: u8,
        /// Base64-encoded target address in `target_ee`.
        target: String,
        /// Base64-encoded native call payload for `target_ee`.
        input: String,
        /// Value in attoBUD (`u128` encoded as decimal string, CosmWasm `Uint128` convention).
        #[serde(default = "zero_string")]
        value_attos: String,
        gas_limit_bgu: u64,
        #[serde(default)]
        is_static: bool,
    },
}

fn zero_string() -> String {
    String::from("0")
}

/// Custom `QueryRequest::Custom(BudlumQuery)` read-only extension (`Section 8.7.2`,).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudlumQuery {
    /// Static cross-environment view call (`static = true`).
    UniversalView {
        target_ee: u8,
        /// Base64-encoded target address in `target_ee`.
        target: String,
        /// Base64-encoded native query payload for `target_ee`.
        input: String,
        gas_limit_bgu: u64,
    },
}

/// CosmWasm `Coin { denom, amount }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwCoin {
    pub denom: String,
    pub amount: String,
}

/// CosmWasm `BlockInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwBlockInfo {
    pub height: u64,
    /// Nanoseconds since UNIX epoch encoded as string (`Timestamp` JSON layout).
    pub time: String,
    pub chain_id: String,
}

/// CosmWasm `ContractInfo` inside `Env`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwEnvContract {
    pub address: String,
}

/// CosmWasm `TransactionInfo` inside `Env`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwTxInfo {
    pub index: u32,
}

/// CosmWasm `Env` JSON passed to `instantiate`, `execute`, `migrate`, `reply`, `query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwEnv {
    pub block: CwBlockInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<CwTxInfo>,
    pub contract: CwEnvContract,
}

/// CosmWasm `MessageInfo` JSON passed to `instantiate` and `execute`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwMessageInfo {
    pub sender: String,
    pub funds: Vec<CwCoin>,
}

/// CosmWasm `Attribute { key, value }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwAttribute {
    pub key: String,
    pub value: String,
}

/// CosmWasm `Event { type, attributes }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwEvent {
    #[serde(rename = "type")]
    pub ty: String,
    pub attributes: Vec<CwAttribute>,
}

/// CosmWasm `ReplyOn` policy for `SubMsg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CwReplyOn {
    Always,
    Error,
    Success,
    #[default]
    Never,
}

/// CosmWasm `BankMsg`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwBankMsg {
    Send {
        to_address: String,
        amount: Vec<CwCoin>,
    },
    Burn {
        amount: Vec<CwCoin>,
    },
}

/// CosmWasm `WasmMsg`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwWasmMsg {
    Execute {
        contract_addr: String,
        /// Base64-encoded JSON execute message.
        msg: String,
        #[serde(default)]
        funds: Vec<CwCoin>,
    },
    Instantiate {
        #[serde(default)]
        admin: Option<String>,
        code_id: u64,
        /// Base64-encoded JSON instantiate message.
        msg: String,
        #[serde(default)]
        funds: Vec<CwCoin>,
        label: String,
    },
    Instantiate2 {
        #[serde(default)]
        admin: Option<String>,
        code_id: u64,
        label: String,
        msg: String,
        #[serde(default)]
        funds: Vec<CwCoin>,
        salt: String,
    },
    Migrate {
        contract_addr: String,
        new_code_id: u64,
        msg: String,
    },
}

/// CosmWasm `CosmosMsg<BudlumMsg>`.
///
/// `Staking`, `Distribution`, `Gov`, and `Ibc` variants deserialize cleanly so the
/// worker can deterministically refuse them with an explicit error (`Section 8.15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwCosmosMsg {
    Bank(CwBankMsg),
    Custom(BudlumMsg),
    Wasm(CwWasmMsg),
    Staking(serde_json::Value),
    Distribution(serde_json::Value),
    Gov(serde_json::Value),
    Ibc(serde_json::Value),
    Stargate {
        type_url: String,
        value: String,
    },
}

/// CosmWasm `SubMsg<BudlumMsg>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwSubMsg {
    pub id: u64,
    pub msg: CwCosmosMsg,
    #[serde(default)]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    pub reply_on: CwReplyOn,
}

/// CosmWasm `Response<BudlumMsg>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CwResponse {
    #[serde(default)]
    pub messages: Vec<CwSubMsg>,
    #[serde(default)]
    pub attributes: Vec<CwAttribute>,
    #[serde(default)]
    pub events: Vec<CwEvent>,
    #[serde(default)]
    pub data: Option<String>,
}

/// CosmWasm `ContractResult<T>` (`{"ok": ...}` or `{"error": "..."}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwContractResult<T> {
    Ok(T),
    Error(String),
}

/// CosmWasm `SubMsgResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwSubMsgResponse {
    pub events: Vec<CwEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// CosmWasm `SubMsgResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwSubMsgResult {
    Ok(CwSubMsgResponse),
    Error(String),
}

/// CosmWasm `Reply` passed to the contract's `reply(env, msg)` entry point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CwReply {
    pub id: u64,
    pub result: CwSubMsgResult,
}

/// CosmWasm `BankQuery`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwBankQuery {
    Balance { address: String, denom: String },
    AllBalances { address: String },
}

/// CosmWasm `WasmQuery`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwWasmQuery {
    Smart {
        contract_addr: String,
        /// Base64-encoded query JSON.
        msg: String,
    },
    Raw {
        contract_addr: String,
        /// Base64-encoded storage key.
        key: String,
    },
    ContractInfo {
        contract_addr: String,
    },
}

/// CosmWasm `QueryRequest<BudlumQuery>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwQueryRequest {
    Bank(CwBankQuery),
    Custom(BudlumQuery),
    Wasm(CwWasmQuery),
    Staking(serde_json::Value),
    Distribution(serde_json::Value),
    Ibc(serde_json::Value),
    Stargate { path: String, data: String },
}

/// CosmWasm `SystemError` returned to `chain_query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwSystemError {
    InvalidRequest { error: String, request: String },
    InvalidResponse { error: String, response: String },
    NoSuchContract { addr: String },
    NoSuchCode { code_id: u64 },
    Unknown {},
    UnsupportedRequest { kind: String },
}

/// CosmWasm `SystemResult<T>` returned to `chain_query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CwSystemResult<T> {
    Ok(T),
    Error(CwSystemError),
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard RFC 4648 Base64 encoder for CosmWasm `Binary` JSON fields.
#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let b0 = c.first().copied().unwrap_or(0);
        let b1 = c.get(1).copied().unwrap_or(0);
        let b2 = c.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for shift in [18u32, 12, 6, 0] {
            let idx = ((n >> shift) & 0x3f) as usize;
            out.push(B64_ALPHABET.get(idx).copied().unwrap_or(b'A') as char);
        }
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let b0 = rem.first().copied().unwrap_or(0);
        let n = u32::from(b0) << 16;
        out.push(B64_ALPHABET.get(((n >> 18) & 0x3f) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_ALPHABET.get(((n >> 12) & 0x3f) as usize).copied().unwrap_or(b'A') as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let b0 = rem.first().copied().unwrap_or(0);
        let b1 = rem.get(1).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8);
        out.push(B64_ALPHABET.get(((n >> 18) & 0x3f) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_ALPHABET.get(((n >> 12) & 0x3f) as usize).copied().unwrap_or(b'A') as char);
        out.push(B64_ALPHABET.get(((n >> 6) & 0x3f) as usize).copied().unwrap_or(b'A') as char);
        out.push('=');
    }
    out
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard RFC 4648 Base64 decoder for CosmWasm `Binary` JSON fields.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(String::from("invalid base64 length"));
    }
    let mut out = Vec::with_capacity((bytes.len() / 4).saturating_mul(3));
    for (chunk_idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = chunk_idx.saturating_add(1) * 4 == bytes.len();
        let c0 = chunk.first().copied().unwrap_or(0);
        let c1 = chunk.get(1).copied().unwrap_or(0);
        let c2 = chunk.get(2).copied().unwrap_or(0);
        let c3 = chunk.get(3).copied().unwrap_or(0);
        let v0 = b64_val(c0).ok_or_else(|| String::from("bad base64 char"))?;
        let v1 = b64_val(c1).ok_or_else(|| String::from("bad base64 char"))?;
        if c2 == b'=' {
            if !is_last || c3 != b'=' || (v1 & 0x0f) != 0 {
                return Err(String::from("invalid base64 padding"));
            }
            out.push((v0 << 2) | (v1 >> 4));
        } else if c3 == b'=' {
            let v2 = b64_val(c2).ok_or_else(|| String::from("bad base64 char"))?;
            if !is_last || (v2 & 0x03) != 0 {
                return Err(String::from("invalid base64 padding"));
            }
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
        } else {
            let v2 = b64_val(c2).ok_or_else(|| String::from("bad base64 char"))?;
            let v3 = b64_val(c3).ok_or_else(|| String::from("bad base64 char"))?;
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len().saturating_mul(2).saturating_add(1));
    for b in hrp.bytes() {
        out.push(b >> 5);
    }
    out.push(0);
    for b in hrp.bytes() {
        out.push(b & 0x1f);
    }
    out
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1u32 << to_bits).saturating_sub(1);
    let mut ret = Vec::new();
    for &value in data {
        let v = u32::from(value);
        if (v >> from_bits) != 0 {
            return Err(String::from("bit group out of range"));
        }
        acc = (acc << from_bits) | v;
        bits = bits.saturating_add(from_bits);
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(String::from("non-zero trailing padding bits"));
    }
    Ok(ret)
}

/// Encode raw 20-byte or 32-byte canonical address into `bud1...` Bech32.
pub fn bud_addr_humanize(canonical: &[u8]) -> Result<String, String> {
    if canonical.len() != 20 && canonical.len() != 32 {
        return Err(format!(
            "canonical address must be 20 or 32 bytes, got {}",
            canonical.len()
        ));
    }
    let data5 = convert_bits(canonical, 8, 5, true)?;
    let mut values = bech32_hrp_expand(BUD_BECH32_HRP);
    values.extend_from_slice(&data5);
    values.extend_from_slice(&[0u8; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    let mut out = String::with_capacity(BUD_BECH32_HRP.len() + 1 + data5.len() + 6);
    out.push_str(BUD_BECH32_HRP);
    out.push('1');
    for d in &data5 {
        let ch = BECH32_CHARSET
            .get(usize::from(*d))
            .copied()
            .ok_or_else(|| String::from("bad 5-bit value"))?;
        out.push(ch as char);
    }
    for i in 0..6u32 {
        let d = ((polymod >> (5 * (5 - i))) & 31) as usize;
        let ch = BECH32_CHARSET
            .get(d)
            .copied()
            .ok_or_else(|| String::from("bad checksum value"))?;
        out.push(ch as char);
    }
    Ok(out)
}

/// Validate and decode a lowercase `bud1...` Bech32 address into its 20-byte or
/// 32-byte canonical representation.
pub fn bud_addr_canonicalize(human: &str) -> Result<Vec<u8>, String> {
    if human.len() < 12 || human.len() > 90 {
        return Err(String::from("bech32 address length out of range"));
    }
    if human.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(String::from("bech32 address must be lowercase"));
    }
    let Some(data_part) = human.strip_prefix("bud1") else {
        return Err(String::from("address must start with 'bud1'"));
    };
    if data_part.len() < 6 {
        return Err(String::from("bech32 checksum missing"));
    }
    let mut vals5 = Vec::with_capacity(data_part.len());
    for b in data_part.bytes() {
        let Some(pos) = BECH32_CHARSET.iter().position(|&c| c == b) else {
            return Err(String::from("invalid bech32 character"));
        };
        vals5.push(pos as u8);
    }
    let mut chk = bech32_hrp_expand(BUD_BECH32_HRP);
    chk.extend_from_slice(&vals5);
    if bech32_polymod(&chk) != 1 {
        return Err(String::from("invalid bech32 checksum"));
    }
    let payload5_len = vals5.len().saturating_sub(6);
    let payload5 = vals5
        .get(..payload5_len)
        .ok_or_else(|| String::from("short bech32 payload"))?;
    let raw = convert_bits(payload5, 5, 8, false)?;
    if raw.len() != 20 && raw.len() != 32 {
        return Err(format!(
            "decoded address must be 20 or 32 bytes, got {}",
            raw.len()
        ));
    }
    Ok(raw)
}
