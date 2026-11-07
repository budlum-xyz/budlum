//! Ethereum foreign transaction envelope decoding and secp256k1 recovery.
//!
//! Implements section 8.6.2 (`Foreign::Ethereum`):
//! - Canonical RLP decoding (`cross_domain::evm::rlp`).
//! - EIP-155 chain ID `45261` strictly required across types `0`, `1`, `2`, `4`.
//! - Type `3` (EIP-4844 blob transactions) explicitly refused (section 8.15).
//! - Low-`s` (EIP-2) secp256k1 sender recovery (`crypto::secp256k1_recover`).

use crate::cross_domain::evm::rlp::{self, Item};
use crate::crypto::secp256k1_recover::recover_address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Canonical Budlum EVM chain identifier (section 8.6.2).
pub const BUDLUM_EVM_CHAIN_ID: u64 = 45_261;

/// EIP-2930 / EIP-1559 access list entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// EIP-7702 account code delegation authorization tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmAuthTuple {
    pub chain_id: u64,
    pub address: [u8; 20],
    pub nonce: u64,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Decoded and signature-verified Ethereum foreign transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedEthereumTx {
    /// Raw transaction hash `keccak256(raw_tx)`.
    pub tx_hash: [u8; 32],
    /// EIP-2718 transaction type (`0`, `1`, `2`, or `4`).
    pub tx_type: u8,
    /// Verified chain ID (`45261`).
    pub chain_id: u64,
    /// Recovered 20-byte secp256k1 sender address.
    pub sender: [u8; 20],
    /// Sender EVM nonce.
    pub nonce: u64,
    /// Gas limit in EVM gas (1 EVM gas = 1 BGU at launch).
    pub gas_limit: u64,
    /// Maximum total fee per gas in wei (attoBUD).
    pub max_fee_per_gas_wei: u128,
    /// Maximum priority fee per gas in wei (attoBUD).
    pub max_priority_fee_per_gas_wei: u128,
    /// Call target (`None` for contract creation).
    pub to: Option<[u8; 20]>,
    /// Value transferred in wei (attoBUD).
    pub value_wei: u128,
    /// Calldata or initcode bytes.
    pub data: Vec<u8>,
    /// Optional EIP-2930 / EIP-1559 access list.
    pub access_list: Vec<EvmAccessListEntry>,
    /// EIP-7702 authorization list (non-empty for type `4`).
    pub authorization_list: Vec<EvmAuthTuple>,
}

/// Why an Ethereum raw transaction was refused at envelope decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthereumEnvelopeError {
    Empty,
    BlobTxUnsupported,
    UnsupportedTxType(u8),
    MalformedRlp(String),
    WrongChainId { expected: u64, got: u64 },
    MissingEip155ChainId,
    FeeCapBelowTip,
    Type4MissingTarget,
    Type4EmptyAuthorizationList,
    InvalidSignature(String),
}

impl std::fmt::Display for EthereumEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty raw Ethereum transaction"),
            Self::BlobTxUnsupported => write!(f, "EIP-4844 type-3 blob transactions are refused"),
            Self::UnsupportedTxType(t) => write!(f, "unsupported EIP-2718 tx type 0x{t:02x}"),
            Self::MalformedRlp(m) => write!(f, "malformed Ethereum RLP: {m}"),
            Self::WrongChainId { expected, got } => {
                write!(f, "wrong EVM chain ID: expected {expected}, got {got}")
            }
            Self::MissingEip155ChainId => write!(f, "legacy tx lacks EIP-155 chain ID protection"),
            Self::FeeCapBelowTip => write!(f, "maxPriorityFeePerGas exceeds maxFeePerGas"),
            Self::Type4MissingTarget => write!(f, "EIP-7702 tx requires a 20-byte target"),
            Self::Type4EmptyAuthorizationList => {
                write!(f, "EIP-7702 authorization list must not be empty")
            }
            Self::InvalidSignature(m) => write!(f, "invalid secp256k1 signature: {m}"),
        }
    }
}

fn decode_u128_be(item: &Item) -> Result<u128, EthereumEnvelopeError> {
    let bytes = rlp::as_bytes(item)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if bytes.len() > 16 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "integer exceeds 128 bits",
        )));
    }
    if bytes.first().copied() == Some(0) {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "non-canonical leading zero in integer",
        )));
    }
    let mut buf = [0u8; 16];
    let start = 16usize.saturating_sub(bytes.len());
    if let Some(dst) = buf.get_mut(start..) {
        dst.copy_from_slice(bytes);
    }
    Ok(u128::from_be_bytes(buf))
}

pub(crate) fn encode_u128_item(val: u128) -> Item {
    if val == 0 {
        return Item::String(Vec::new());
    }
    let be = val.to_be_bytes();
    let skip = be.iter().take_while(|b| **b == 0).count();
    let slice = be.get(skip..).unwrap_or(&[]);
    Item::String(slice.to_vec())
}

fn decode_scalar32(item: &Item) -> Result<[u8; 32], EthereumEnvelopeError> {
    let bytes = rlp::as_bytes(item)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if bytes.len() > 32 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "signature scalar exceeds 32 bytes",
        )));
    }
    if bytes.first().copied() == Some(0) {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "non-canonical leading zero in scalar",
        )));
    }
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    if let Some(dst) = out.get_mut(start..) {
        dst.copy_from_slice(bytes);
    }
    Ok(out)
}

fn decode_to(item: &Item) -> Result<Option<[u8; 20]>, EthereumEnvelopeError> {
    let bytes = rlp::as_bytes(item)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let arr: [u8; 20] = bytes.try_into().map_err(|_| {
        EthereumEnvelopeError::MalformedRlp(String::from("target must be empty or 20 bytes"))
    })?;
    Ok(Some(arr))
}

fn decode_access_list(item: &Item) -> Result<Vec<EvmAccessListEntry>, EthereumEnvelopeError> {
    let Item::List(entries) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "access_list must be an RLP list",
        )));
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Item::List(fields) = entry else {
            return Err(EthereumEnvelopeError::MalformedRlp(String::from(
                "access_list item must be a 2-element list",
            )));
        };
        let (Some(addr_it), Some(keys_it), None) =
            (fields.first(), fields.get(1), fields.get(2))
        else {
            return Err(EthereumEnvelopeError::MalformedRlp(String::from(
                "access_list item arity mismatch",
            )));
        };
        let addr_bytes =
            rlp::as_bytes(addr_it).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
        let address: [u8; 20] = addr_bytes.try_into().map_err(|_| {
            EthereumEnvelopeError::MalformedRlp(String::from("access_list address is not 20 bytes"))
        })?;
        let Item::List(key_items) = keys_it else {
            return Err(EthereumEnvelopeError::MalformedRlp(String::from(
                "access_list storage_keys must be a list",
            )));
        };
        let mut storage_keys = Vec::with_capacity(key_items.len());
        for k_it in key_items {
            let kb = rlp::as_bytes(k_it)
                .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
            let k32: [u8; 32] = kb.try_into().map_err(|_| {
                EthereumEnvelopeError::MalformedRlp(String::from(
                    "access_list storage key must be 32 bytes",
                ))
            })?;
            storage_keys.push(k32);
        }
        out.push(EvmAccessListEntry {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

fn encode_access_list(list: &[EvmAccessListEntry]) -> Item {
    Item::List(
        list.iter()
            .map(|e| {
                Item::List(vec![
                    Item::String(e.address.to_vec()),
                    Item::List(
                        e.storage_keys
                            .iter()
                            .map(|k| Item::String(k.to_vec()))
                            .collect(),
                    ),
                ])
            })
            .collect(),
    )
}

fn decode_auth_list(item: &Item) -> Result<Vec<EvmAuthTuple>, EthereumEnvelopeError> {
    let Item::List(entries) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "authorization_list must be an RLP list",
        )));
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Item::List(fields) = entry else {
            return Err(EthereumEnvelopeError::MalformedRlp(String::from(
                "authorization tuple must be a 6-element list",
            )));
        };
        if fields.len() != 6 {
            return Err(EthereumEnvelopeError::MalformedRlp(String::from(
                "authorization tuple arity must be 6",
            )));
        }
        let chain_id = fields
            .first()
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing chain_id")))
            .and_then(|it| {
                rlp::decode_uint(it).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))
            })?;
        let addr_b = fields
            .get(1)
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing address")))
            .and_then(|it| {
                rlp::as_bytes(it).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))
            })?;
        let address: [u8; 20] = addr_b.try_into().map_err(|_| {
            EthereumEnvelopeError::MalformedRlp(String::from("auth tuple address must be 20 bytes"))
        })?;
        let nonce = fields
            .get(2)
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing nonce")))
            .and_then(|it| {
                rlp::decode_uint(it).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))
            })?;
        let y_u64 = fields
            .get(3)
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing y_parity")))
            .and_then(|it| {
                rlp::decode_uint(it).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))
            })?;
        let y_parity = u8::try_from(y_u64).map_err(|_| {
            EthereumEnvelopeError::MalformedRlp(String::from("y_parity out of u8 range"))
        })?;
        if y_parity > 1 {
            return Err(EthereumEnvelopeError::InvalidSignature(String::from(
                "authorization y_parity must be 0 or 1",
            )));
        }
        let r = fields
            .get(4)
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing r")))
            .and_then(decode_scalar32)?;
        let s = fields
            .get(5)
            .ok_or_else(|| EthereumEnvelopeError::MalformedRlp(String::from("missing s")))
            .and_then(decode_scalar32)?;
        out.push(EvmAuthTuple {
            chain_id,
            address,
            nonce,
            y_parity,
            r,
            s,
        });
    }
    Ok(out)
}

fn recover_from_sig_parts(
    signing_hash: &[u8; 32],
    y_parity: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 20], EthereumEnvelopeError> {
    if y_parity > 1 {
        return Err(EthereumEnvelopeError::InvalidSignature(String::from(
            "y_parity must be 0 or 1",
        )));
    }
    let mut sig = [0u8; 65];
    if let Some(dst) = sig.get_mut(..32) {
        dst.copy_from_slice(r);
    }
    if let Some(dst) = sig.get_mut(32..64) {
        dst.copy_from_slice(s);
    }
    if let Some(v_slot) = sig.get_mut(64) {
        *v_slot = y_parity;
    }
    recover_address(signing_hash, &sig)
        .map_err(|e| EthereumEnvelopeError::InvalidSignature(e.to_string()))
}

/// Decodes a raw Ethereum signed transaction and recovers its sender on `expected_chain_id`.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn decode_ethereum_tx(
    raw: &[u8],
    expected_chain_id: u64,
) -> Result<DecodedEthereumTx, EthereumEnvelopeError> {
    let Some(&first) = raw.first() else {
        return Err(EthereumEnvelopeError::Empty);
    };
    let tx_hash: [u8; 32] = Keccak256::digest(raw).into();
    if first >= 0xc0 {
        return decode_legacy_eip155(raw, tx_hash, expected_chain_id);
    }
    let payload = raw.get(1..).unwrap_or(&[]);
    match first {
        0x01 => decode_eip2930(payload, tx_hash, expected_chain_id),
        0x02 => decode_eip1559(payload, tx_hash, expected_chain_id),
        0x03 => Err(EthereumEnvelopeError::BlobTxUnsupported),
        0x04 => decode_eip7702(payload, tx_hash, expected_chain_id),
        other => Err(EthereumEnvelopeError::UnsupportedTxType(other)),
    }
}

fn decode_legacy_eip155(
    raw: &[u8],
    tx_hash: [u8; 32],
    expected_chain_id: u64,
) -> Result<DecodedEthereumTx, EthereumEnvelopeError> {
    let item = rlp::decode(raw).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let Item::List(fields) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "legacy tx must be an RLP list",
        )));
    };
    if fields.len() != 9 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "legacy tx must have 9 RLP elements",
        )));
    }
    let nonce = rlp::decode_uint(fields.first().ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let gas_price = decode_u128_be(fields.get(1).ok_or(EthereumEnvelopeError::Empty)?)?;
    let gas_limit = rlp::decode_uint(fields.get(2).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let to = decode_to(fields.get(3).ok_or(EthereumEnvelopeError::Empty)?)?;
    let value_wei = decode_u128_be(fields.get(4).ok_or(EthereumEnvelopeError::Empty)?)?;
    let data = rlp::as_bytes(fields.get(5).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?
        .to_vec();
    let v = rlp::decode_uint(fields.get(6).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if v == 27 || v == 28 || v < 35 {
        return Err(EthereumEnvelopeError::MissingEip155ChainId);
    }
    let adjusted = v - 35;
    let chain_id = adjusted / 2;
    let y_parity = (adjusted % 2) as u8;
    if chain_id != expected_chain_id {
        return Err(EthereumEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    let r = decode_scalar32(fields.get(7).ok_or(EthereumEnvelopeError::Empty)?)?;
    let s = decode_scalar32(fields.get(8).ok_or(EthereumEnvelopeError::Empty)?)?;

    let mut unsigned_fields: Vec<Item> = fields.iter().take(6).cloned().collect();
    unsigned_fields.push(Item::String(rlp::encode_uint(chain_id)));
    unsigned_fields.push(Item::String(Vec::new()));
    unsigned_fields.push(Item::String(Vec::new()));
    let sig_preimage = rlp::encode(&Item::List(unsigned_fields));
    let signing_hash: [u8; 32] = Keccak256::digest(&sig_preimage).into();
    let sender = recover_from_sig_parts(&signing_hash, y_parity, &r, &s)?;

    Ok(DecodedEthereumTx {
        tx_hash,
        tx_type: 0,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei: gas_price,
        max_priority_fee_per_gas_wei: gas_price,
        to,
        value_wei,
        data,
        access_list: Vec::new(),
        authorization_list: Vec::new(),
    })
}

fn decode_eip2930(
    payload: &[u8],
    tx_hash: [u8; 32],
    expected_chain_id: u64,
) -> Result<DecodedEthereumTx, EthereumEnvelopeError> {
    let item =
        rlp::decode(payload).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let Item::List(fields) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-2930 payload must be an RLP list",
        )));
    };
    if fields.len() != 11 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-2930 tx must have 11 elements",
        )));
    }
    let chain_id = rlp::decode_uint(fields.first().ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if chain_id != expected_chain_id {
        return Err(EthereumEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    let nonce = rlp::decode_uint(fields.get(1).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let gas_price = decode_u128_be(fields.get(2).ok_or(EthereumEnvelopeError::Empty)?)?;
    let gas_limit = rlp::decode_uint(fields.get(3).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let to = decode_to(fields.get(4).ok_or(EthereumEnvelopeError::Empty)?)?;
    let value_wei = decode_u128_be(fields.get(5).ok_or(EthereumEnvelopeError::Empty)?)?;
    let data = rlp::as_bytes(fields.get(6).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?
        .to_vec();
    let access_list = decode_access_list(fields.get(7).ok_or(EthereumEnvelopeError::Empty)?)?;
    let y_u64 = rlp::decode_uint(fields.get(8).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let y_parity = u8::try_from(y_u64).map_err(|_| {
        EthereumEnvelopeError::InvalidSignature(String::from("y_parity exceeds u8"))
    })?;
    let r = decode_scalar32(fields.get(9).ok_or(EthereumEnvelopeError::Empty)?)?;
    let s = decode_scalar32(fields.get(10).ok_or(EthereumEnvelopeError::Empty)?)?;

    let unsigned: Vec<Item> = fields.iter().take(8).cloned().collect();
    let mut preimage = vec![0x01];
    preimage.extend_from_slice(&rlp::encode(&Item::List(unsigned)));
    let signing_hash: [u8; 32] = Keccak256::digest(&preimage).into();
    let sender = recover_from_sig_parts(&signing_hash, y_parity, &r, &s)?;

    Ok(DecodedEthereumTx {
        tx_hash,
        tx_type: 1,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei: gas_price,
        max_priority_fee_per_gas_wei: gas_price,
        to,
        value_wei,
        data,
        access_list,
        authorization_list: Vec::new(),
    })
}

fn decode_eip1559(
    payload: &[u8],
    tx_hash: [u8; 32],
    expected_chain_id: u64,
) -> Result<DecodedEthereumTx, EthereumEnvelopeError> {
    let item =
        rlp::decode(payload).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let Item::List(fields) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-1559 payload must be an RLP list",
        )));
    };
    if fields.len() != 12 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-1559 tx must have 12 elements",
        )));
    }
    let chain_id = rlp::decode_uint(fields.first().ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if chain_id != expected_chain_id {
        return Err(EthereumEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    let nonce = rlp::decode_uint(fields.get(1).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let max_priority_fee_per_gas_wei =
        decode_u128_be(fields.get(2).ok_or(EthereumEnvelopeError::Empty)?)?;
    let max_fee_per_gas_wei = decode_u128_be(fields.get(3).ok_or(EthereumEnvelopeError::Empty)?)?;
    if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
        return Err(EthereumEnvelopeError::FeeCapBelowTip);
    }
    let gas_limit = rlp::decode_uint(fields.get(4).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let to = decode_to(fields.get(5).ok_or(EthereumEnvelopeError::Empty)?)?;
    let value_wei = decode_u128_be(fields.get(6).ok_or(EthereumEnvelopeError::Empty)?)?;
    let data = rlp::as_bytes(fields.get(7).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?
        .to_vec();
    let access_list = decode_access_list(fields.get(8).ok_or(EthereumEnvelopeError::Empty)?)?;
    let y_u64 = rlp::decode_uint(fields.get(9).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let y_parity = u8::try_from(y_u64).map_err(|_| {
        EthereumEnvelopeError::InvalidSignature(String::from("y_parity exceeds u8"))
    })?;
    let r = decode_scalar32(fields.get(10).ok_or(EthereumEnvelopeError::Empty)?)?;
    let s = decode_scalar32(fields.get(11).ok_or(EthereumEnvelopeError::Empty)?)?;

    let unsigned: Vec<Item> = fields.iter().take(9).cloned().collect();
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&rlp::encode(&Item::List(unsigned)));
    let signing_hash: [u8; 32] = Keccak256::digest(&preimage).into();
    let sender = recover_from_sig_parts(&signing_hash, y_parity, &r, &s)?;

    Ok(DecodedEthereumTx {
        tx_hash,
        tx_type: 2,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        to,
        value_wei,
        data,
        access_list,
        authorization_list: Vec::new(),
    })
}

fn decode_eip7702(
    payload: &[u8],
    tx_hash: [u8; 32],
    expected_chain_id: u64,
) -> Result<DecodedEthereumTx, EthereumEnvelopeError> {
    let item =
        rlp::decode(payload).map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let Item::List(fields) = item else {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-7702 payload must be an RLP list",
        )));
    };
    if fields.len() != 13 {
        return Err(EthereumEnvelopeError::MalformedRlp(String::from(
            "EIP-7702 tx must have 13 elements",
        )));
    }
    let chain_id = rlp::decode_uint(fields.first().ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    if chain_id != expected_chain_id {
        return Err(EthereumEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    let nonce = rlp::decode_uint(fields.get(1).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let max_priority_fee_per_gas_wei =
        decode_u128_be(fields.get(2).ok_or(EthereumEnvelopeError::Empty)?)?;
    let max_fee_per_gas_wei = decode_u128_be(fields.get(3).ok_or(EthereumEnvelopeError::Empty)?)?;
    if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
        return Err(EthereumEnvelopeError::FeeCapBelowTip);
    }
    let gas_limit = rlp::decode_uint(fields.get(4).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let Some(target) = decode_to(fields.get(5).ok_or(EthereumEnvelopeError::Empty)?)? else {
        return Err(EthereumEnvelopeError::Type4MissingTarget);
    };
    let value_wei = decode_u128_be(fields.get(6).ok_or(EthereumEnvelopeError::Empty)?)?;
    let data = rlp::as_bytes(fields.get(7).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?
        .to_vec();
    let access_list = decode_access_list(fields.get(8).ok_or(EthereumEnvelopeError::Empty)?)?;
    let authorization_list =
        decode_auth_list(fields.get(9).ok_or(EthereumEnvelopeError::Empty)?)?;
    if authorization_list.is_empty() {
        return Err(EthereumEnvelopeError::Type4EmptyAuthorizationList);
    }
    let y_u64 = rlp::decode_uint(fields.get(10).ok_or(EthereumEnvelopeError::Empty)?)
        .map_err(|e| EthereumEnvelopeError::MalformedRlp(e.to_string()))?;
    let y_parity = u8::try_from(y_u64).map_err(|_| {
        EthereumEnvelopeError::InvalidSignature(String::from("y_parity exceeds u8"))
    })?;
    let r = decode_scalar32(fields.get(11).ok_or(EthereumEnvelopeError::Empty)?)?;
    let s = decode_scalar32(fields.get(12).ok_or(EthereumEnvelopeError::Empty)?)?;

    let unsigned: Vec<Item> = fields.iter().take(10).cloned().collect();
    let mut preimage = vec![0x04];
    preimage.extend_from_slice(&rlp::encode(&Item::List(unsigned)));
    let signing_hash: [u8; 32] = Keccak256::digest(&preimage).into();
    let sender = recover_from_sig_parts(&signing_hash, y_parity, &r, &s)?;

    Ok(DecodedEthereumTx {
        tx_hash,
        tx_type: 4,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        to: Some(target),
        value_wei,
        data,
        access_list,
        authorization_list,
    })
}

/// Signs and encodes a canonical EIP-1559 (type-2) Ethereum transaction.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn sign_eip1559_tx(
    secret_key: &[u8; 32],
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas_wei: u128,
    max_fee_per_gas_wei: u128,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: u128,
    data: &[u8],
    access_list: &[EvmAccessListEntry],
) -> Result<Vec<u8>, String> {
    use k256::ecdsa::SigningKey;

    let signing_key =
        SigningKey::from_bytes(secret_key.into()).map_err(|e| format!("bad secp256k1 key: {e}"))?;
    let to_item = match to {
        Some(addr) => Item::String(addr.to_vec()),
        None => Item::String(Vec::new()),
    };
    let mut fields = vec![
        Item::String(rlp::encode_uint(chain_id)),
        Item::String(rlp::encode_uint(nonce)),
        encode_u128_item(max_priority_fee_per_gas_wei),
        encode_u128_item(max_fee_per_gas_wei),
        Item::String(rlp::encode_uint(gas_limit)),
        to_item,
        encode_u128_item(value_wei),
        Item::String(data.to_vec()),
        encode_access_list(access_list),
    ];
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&rlp::encode(&Item::List(fields.clone())));
    let digest: [u8; 32] = Keccak256::digest(&preimage).into();
    let (sig, rec_id) = signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| format!("secp256k1 sign failed: {e}"))?;
    let sig_bytes = sig.to_bytes();
    let r_slice = sig_bytes.get(..32).unwrap_or(&[]);
    let s_slice = sig_bytes.get(32..64).unwrap_or(&[]);
    let r_skip = r_slice.iter().take_while(|b| **b == 0).count();
    let s_skip = s_slice.iter().take_while(|b| **b == 0).count();
    fields.push(Item::String(rlp::encode_uint(u64::from(rec_id.to_byte()))));
    fields.push(Item::String(r_slice.get(r_skip..).unwrap_or(&[]).to_vec()));
    fields.push(Item::String(s_slice.get(s_skip..).unwrap_or(&[]).to_vec()));
    let mut raw = vec![0x02];
    raw.extend_from_slice(&rlp::encode(&Item::List(fields)));
    Ok(raw)
}

/// Derives the 20-byte Ethereum address corresponding to a 32-byte secp256k1 secret key.
/// WIRING: exercised by the Unified Execution Layer coordinator and compatibility gateways.
pub fn evm_address_from_secret_key(secret_key: &[u8; 32]) -> Result<[u8; 20], String> {
    use k256::ecdsa::SigningKey;

    let signing_key =
        SigningKey::from_bytes(secret_key.into()).map_err(|e| format!("bad secp256k1 key: {e}"))?;
    let uncompressed = signing_key.verifying_key().to_encoded_point(false);
    let pub_bytes = uncompressed.as_bytes();
    let xy = pub_bytes
        .get(1..)
        .ok_or_else(|| String::from("invalid uncompressed secp256k1 point"))?;
    let digest: [u8; 32] = Keccak256::digest(xy).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, addr @ ..] = digest;
    Ok(addr)
}
