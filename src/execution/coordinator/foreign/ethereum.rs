//! `Foreign::Ethereum` RLP transaction decoding and `secp256k1` `ecrecover` (`WP-27`).
//!
//! Accepts EIP-155 legacy (`0x00`), EIP-2930 (`0x01`), EIP-1559 (`0x02`), and
//! EIP-7702 (`0x04`) transactions bound to Budlum chain ID `45261`, while
//! refusing pre-EIP-155 legacy signatures and EIP-4844 blob (`0x03`) envelopes.
//! Convenience: public Foreign::Ethereum EIP-1559/2930/7702 RLP envelope surface (WP-27).

use std::fmt;

use k256::Secp256k1;

use crate::cross_domain::evm::mpt::keccak256;
use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};

/// Canonical Budlum EIP-155 chain identifier (Section 8.6.2).
pub const BUDLUM_EVM_CHAIN_ID: u64 = 45261;

/// Supported Ethereum transaction envelope types on Budlum (`WP-27`).
///
/// Convenience: exposed for RPC compatibility and coordinator lane routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EthTxType {
    /// Legacy RLP transaction carrying an EIP-155 replay-protected `v`.
    LegacyEip155 = 0x00,
    /// EIP-2930 access-list transaction (`0x01 || rlp(...)`).
    Eip2930 = 0x01,
    /// EIP-1559 dynamic-fee transaction (`0x02 || rlp(...)`).
    Eip1559 = 0x02,
    /// EIP-7702 set-code authorization transaction (`0x04 || rlp(...)`).
    Eip7702 = 0x04,
}

/// Access-list entry `(address20, storage_keys)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthAccessTuple {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// EIP-7702 signed authorization tuple `(chain_id, address, nonce, y_parity, r, s)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip7702Authorization {
    pub chain_id: u64,
    pub address: [u8; 20],
    pub nonce: u64,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Decoded and signature-verified `Foreign::Ethereum` transaction.
///
/// Convenience: consumed by coordinator foreign-lane execution and EVM RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEthTx {
    pub tx_type: EthTxType,
    pub chain_id: u64,
    pub sender: [u8; 20],
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas_wei: u128,
    pub max_priority_fee_per_gas_wei: u128,
    pub to: Option<[u8; 20]>,
    pub value_wei: u128,
    pub input: Vec<u8>,
    pub access_list: Vec<EthAccessTuple>,
    pub authorizations: Vec<Eip7702Authorization>,
    pub tx_hash: [u8; 32],
}

/// Deterministic refusals when decoding or verifying an Ethereum foreign envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthEnvelopeError {
    EmptyEnvelope,
    BlobTransactionUnsupported,
    UnsupportedTransactionType(u8),
    Rlp(RlpError),
    WrongFieldCount { expected: usize, actual: usize },
    ExpectedList,
    ExpectedBytes,
    LeadingZeroScalar,
    ScalarOverflow,
    InvalidAddressLength(usize),
    MissingEip155ReplayProtection,
    WrongChainId { expected: u64, actual: u64 },
    InvalidParityBit(u64),
    InvalidSignature,
    HighSSignature,
    EmptyAuthorizationList,
    PriorityFeeAboveMaxFee {
        priority_fee_per_gas_wei: u128,
        max_fee_per_gas_wei: u128,
    },
}

impl fmt::Display for EthEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEnvelope => write!(f, "empty Ethereum transaction envelope"),
            Self::BlobTransactionUnsupported => {
                write!(f, "EIP-4844 type-3 blob transactions are refused on Budlum")
            }
            Self::UnsupportedTransactionType(t) => {
                write!(f, "unsupported EIP-2718 transaction type 0x{t:02x}")
            }
            Self::Rlp(e) => write!(f, "invalid RLP in Ethereum envelope: {e}"),
            Self::WrongFieldCount { expected, actual } => {
                write!(f, "expected {expected} RLP fields, got {actual}")
            }
            Self::ExpectedList => write!(f, "expected RLP list"),
            Self::ExpectedBytes => write!(f, "expected RLP byte string"),
            Self::LeadingZeroScalar => write!(f, "non-canonical leading zero in RLP integer"),
            Self::ScalarOverflow => write!(f, "RLP integer exceeds target width"),
            Self::InvalidAddressLength(n) => {
                write!(f, "Ethereum `to` field must be 0 or 20 bytes, got {n}")
            }
            Self::MissingEip155ReplayProtection => {
                write!(f, "pre-EIP-155 unprotected legacy signature refused")
            }
            Self::WrongChainId { expected, actual } => {
                write!(f, "wrong EVM chain_id: expected {expected}, got {actual}")
            }
            Self::InvalidParityBit(v) => write!(f, "invalid signature yParity {v}"),
            Self::InvalidSignature => write!(f, "secp256k1 signature recovery failed"),
            Self::HighSSignature => write!(f, "non-canonical high-s ECDSA signature refused"),
            Self::EmptyAuthorizationList => {
                write!(f, "EIP-7702 transaction requires non-empty authorization_list")
            }
            Self::PriorityFeeAboveMaxFee {
                priority_fee_per_gas_wei,
                max_fee_per_gas_wei,
            } => write!(
                f,
                "maxPriorityFeePerGas {priority_fee_per_gas_wei} exceeds \
                 maxFeePerGas {max_fee_per_gas_wei} (revm TipAboveFeeCap)"
            ),
        }
    }
}

impl std::error::Error for EthEnvelopeError {}

impl From<RlpError> for EthEnvelopeError {
    fn from(value: RlpError) -> Self {
        Self::Rlp(value)
    }
}

/// Recover the 20-byte Ethereum signer address from `(msg_hash, y_parity, r, s)`
/// enforcing EIP-2 canonical low-`s` (`s <= n / 2`) over `k256::Secp256k1`.
///
/// Convenience: shared between `Foreign::Ethereum` envelopes and `Adopt` dual-sig checks.
pub fn ecrecover_eth_address(
    msg_hash: &[u8; 32],
    y_parity: u8,
    r_bytes: &[u8; 32],
    s_bytes: &[u8; 32],
) -> Result<[u8; 20], EthEnvelopeError> {
    let _curve = Secp256k1;
    if y_parity > 1 {
        return Err(EthEnvelopeError::InvalidParityBit(u64::from(y_parity)));
    }
    let mut sig65 = [0u8; 65];
    if let Some((first64, last1)) = sig65.split_at_mut_checked(64) {
        if let Some((r_dst, s_dst)) = first64.split_at_mut_checked(32) {
            r_dst.copy_from_slice(r_bytes);
            s_dst.copy_from_slice(s_bytes);
        }
        if let Some(v_slot) = last1.first_mut() {
            *v_slot = y_parity;
        }
    }
    recover_address(msg_hash, &sig65).map_err(|err| match err {
        RecoverError::HighS => EthEnvelopeError::HighSSignature,
        RecoverError::RecoveryId => EthEnvelopeError::InvalidParityBit(u64::from(y_parity)),
        RecoverError::Length | RecoverError::Range | RecoverError::NoPoint => {
            EthEnvelopeError::InvalidSignature
        }
    })
}

/// Decode a raw Ethereum transaction (`Legacy`, `0x01`, `0x02`, `0x04`), enforce
/// `expected_chain_id`, and recover its 20-byte `secp256k1` sender.
///
/// Convenience: entry point for `Foreign::Ethereum` validation and `eth_sendRawTransaction`.
pub fn decode_and_recover_eth_tx(
    raw: &[u8],
    expected_chain_id: u64,
) -> Result<DecodedEthTx, EthEnvelopeError> {
    let Some((&first, rest)) = raw.split_first() else {
        return Err(EthEnvelopeError::EmptyEnvelope);
    };
    let tx_hash = keccak256(raw);
    if first >= 0xc0 {
        decode_legacy_eip155(raw, expected_chain_id, tx_hash)
    } else {
        match first {
            0x01 => decode_eip2930(rest, expected_chain_id, tx_hash),
            0x02 => decode_eip1559(rest, expected_chain_id, tx_hash),
            0x03 => Err(EthEnvelopeError::BlobTransactionUnsupported),
            0x04 => decode_eip7702(rest, expected_chain_id, tx_hash),
            other => Err(EthEnvelopeError::UnsupportedTransactionType(other)),
        }
    }
}

fn as_list(item: &Item) -> Result<&[Item], EthEnvelopeError> {
    match item {
        Item::List(v) => Ok(v.as_slice()),
        Item::String(_) => Err(EthEnvelopeError::ExpectedList),
    }
}

fn as_bytes(item: &Item) -> Result<&[u8], EthEnvelopeError> {
    match item {
        Item::String(b) => Ok(b.as_slice()),
        Item::List(_) => Err(EthEnvelopeError::ExpectedBytes),
    }
}

fn parse_u64_be(item: &Item) -> Result<u64, EthEnvelopeError> {
    let bytes = as_bytes(item)?;
    if bytes.first() == Some(&0) {
        return Err(EthEnvelopeError::LeadingZeroScalar);
    }
    if bytes.len() > 8 {
        return Err(EthEnvelopeError::ScalarOverflow);
    }
    let mut acc = 0u64;
    for &b in bytes {
        acc = (acc << 8) | u64::from(b);
    }
    Ok(acc)
}

fn parse_u128_be(item: &Item) -> Result<u128, EthEnvelopeError> {
    let bytes = as_bytes(item)?;
    if bytes.first() == Some(&0) {
        return Err(EthEnvelopeError::LeadingZeroScalar);
    }
    if bytes.len() > 16 {
        return Err(EthEnvelopeError::ScalarOverflow);
    }
    let mut acc = 0u128;
    for &b in bytes {
        acc = (acc << 8) | u128::from(b);
    }
    Ok(acc)
}

fn parse_sig_word(item: &Item) -> Result<[u8; 32], EthEnvelopeError> {
    let bytes = as_bytes(item)?;
    if bytes.first() == Some(&0) {
        return Err(EthEnvelopeError::LeadingZeroScalar);
    }
    if bytes.len() > 32 {
        return Err(EthEnvelopeError::ScalarOverflow);
    }
    let mut out = [0u8; 32];
    let pad = 32 - bytes.len();
    if let Some((_, tail)) = out.split_at_mut_checked(pad) {
        tail.copy_from_slice(bytes);
    }
    Ok(out)
}

fn parse_to(item: &Item) -> Result<Option<[u8; 20]>, EthEnvelopeError> {
    let bytes = as_bytes(item)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let Ok(addr) = <[u8; 20]>::try_from(bytes) else {
        return Err(EthEnvelopeError::InvalidAddressLength(bytes.len()));
    };
    Ok(Some(addr))
}

fn parse_access_list(item: &Item) -> Result<Vec<EthAccessTuple>, EthEnvelopeError> {
    let entries = as_list(item)?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let pair = as_list(entry)?;
        let [addr_item, keys_item] = pair else {
            return Err(EthEnvelopeError::WrongFieldCount {
                expected: 2,
                actual: pair.len(),
            });
        };
        let addr_bytes = as_bytes(addr_item)?;
        let Ok(address) = <[u8; 20]>::try_from(addr_bytes) else {
            return Err(EthEnvelopeError::InvalidAddressLength(addr_bytes.len()));
        };
        let raw_keys = as_list(keys_item)?;
        let mut storage_keys = Vec::with_capacity(raw_keys.len());
        for k in raw_keys {
            let kb = as_bytes(k)?;
            let Ok(word) = <[u8; 32]>::try_from(kb) else {
                return Err(EthEnvelopeError::ScalarOverflow);
            };
            storage_keys.push(word);
        }
        out.push(EthAccessTuple {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

fn parse_authorizations(item: &Item) -> Result<Vec<Eip7702Authorization>, EthEnvelopeError> {
    let entries = as_list(item)?;
    if entries.is_empty() {
        return Err(EthEnvelopeError::EmptyAuthorizationList);
    }
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = as_list(entry)?;
        let [cid, addr_item, nonce_item, yp_item, r_item, s_item] = fields else {
            return Err(EthEnvelopeError::WrongFieldCount {
                expected: 6,
                actual: fields.len(),
            });
        };
        let chain_id = parse_u64_be(cid)?;
        let addr_bytes = as_bytes(addr_item)?;
        let Ok(address) = <[u8; 20]>::try_from(addr_bytes) else {
            return Err(EthEnvelopeError::InvalidAddressLength(addr_bytes.len()));
        };
        let nonce = parse_u64_be(nonce_item)?;
        let yp = parse_u64_be(yp_item)?;
        if yp > 1 {
            return Err(EthEnvelopeError::InvalidParityBit(yp));
        }
        let r = parse_sig_word(r_item)?;
        let s = parse_sig_word(s_item)?;
        out.push(Eip7702Authorization {
            chain_id,
            address,
            nonce,
            y_parity: yp as u8,
            r,
            s,
        });
    }
    Ok(out)
}

fn rlp_u64(val: u64) -> Item {
    if val == 0 {
        return Item::String(Vec::new());
    }
    let be = val.to_be_bytes();
    let first_nz = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let slice = be.get(first_nz..).unwrap_or(&[]);
    Item::String(slice.to_vec())
}

fn typed_signing_hash(type_byte: u8, unsigned_fields: Vec<Item>) -> [u8; 32] {
    let encoded = rlp::encode(&Item::List(unsigned_fields));
    let mut preimage = Vec::with_capacity(1 + encoded.len());
    preimage.push(type_byte);
    preimage.extend_from_slice(&encoded);
    keccak256(&preimage)
}

fn decode_legacy_eip155(
    raw: &[u8],
    expected_chain_id: u64,
    tx_hash: [u8; 32],
) -> Result<DecodedEthTx, EthEnvelopeError> {
    let decoded = rlp::decode(raw)?;
    let fields = as_list(&decoded)?;
    let [f_nonce, f_gp, f_gas, f_to, f_val, f_data, f_v, f_r, f_s] = fields else {
        return Err(EthEnvelopeError::WrongFieldCount {
            expected: 9,
            actual: fields.len(),
        });
    };
    let nonce = parse_u64_be(f_nonce)?;
    let gas_price = parse_u128_be(f_gp)?;
    let gas_limit = parse_u64_be(f_gas)?;
    let to = parse_to(f_to)?;
    let value_wei = parse_u128_be(f_val)?;
    let input = as_bytes(f_data)?.to_vec();
    let v = parse_u64_be(f_v)?;
    if v == 27 || v == 28 || v < 35 {
        return Err(EthEnvelopeError::MissingEip155ReplayProtection);
    }
    let shifted = v - 35;
    let chain_id = shifted / 2;
    let y_parity = (shifted % 2) as u8;
    if chain_id != expected_chain_id {
        return Err(EthEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            actual: chain_id,
        });
    }
    let r = parse_sig_word(f_r)?;
    let s = parse_sig_word(f_s)?;

    let signing_rlp = rlp::encode(&Item::List(vec![
        f_nonce.clone(),
        f_gp.clone(),
        f_gas.clone(),
        f_to.clone(),
        f_val.clone(),
        f_data.clone(),
        rlp_u64(chain_id),
        Item::String(Vec::new()),
        Item::String(Vec::new()),
    ]));
    let sighash = keccak256(&signing_rlp);
    let sender = ecrecover_eth_address(&sighash, y_parity, &r, &s)?;

    Ok(DecodedEthTx {
        tx_type: EthTxType::LegacyEip155,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei: gas_price,
        max_priority_fee_per_gas_wei: gas_price,
        to,
        value_wei,
        input,
        access_list: Vec::new(),
        authorizations: Vec::new(),
        tx_hash,
    })
}

fn decode_eip2930(
    payload: &[u8],
    expected_chain_id: u64,
    tx_hash: [u8; 32],
) -> Result<DecodedEthTx, EthEnvelopeError> {
    let decoded = rlp::decode(payload)?;
    let fields = as_list(&decoded)?;
    let [f_cid, f_nonce, f_gp, f_gas, f_to, f_val, f_data, f_al, f_yp, f_r, f_s] = fields else {
        return Err(EthEnvelopeError::WrongFieldCount {
            expected: 11,
            actual: fields.len(),
        });
    };
    let chain_id = parse_u64_be(f_cid)?;
    if chain_id != expected_chain_id {
        return Err(EthEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            actual: chain_id,
        });
    }
    let nonce = parse_u64_be(f_nonce)?;
    let gas_price = parse_u128_be(f_gp)?;
    let gas_limit = parse_u64_be(f_gas)?;
    let to = parse_to(f_to)?;
    let value_wei = parse_u128_be(f_val)?;
    let input = as_bytes(f_data)?.to_vec();
    let access_list = parse_access_list(f_al)?;
    let yp = parse_u64_be(f_yp)?;
    if yp > 1 {
        return Err(EthEnvelopeError::InvalidParityBit(yp));
    }
    let r = parse_sig_word(f_r)?;
    let s = parse_sig_word(f_s)?;

    let sighash = typed_signing_hash(
        0x01,
        vec![
            f_cid.clone(),
            f_nonce.clone(),
            f_gp.clone(),
            f_gas.clone(),
            f_to.clone(),
            f_val.clone(),
            f_data.clone(),
            f_al.clone(),
        ],
    );
    let sender = ecrecover_eth_address(&sighash, yp as u8, &r, &s)?;

    Ok(DecodedEthTx {
        tx_type: EthTxType::Eip2930,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei: gas_price,
        max_priority_fee_per_gas_wei: gas_price,
        to,
        value_wei,
        input,
        access_list,
        authorizations: Vec::new(),
        tx_hash,
    })
}

fn decode_eip1559(
    payload: &[u8],
    expected_chain_id: u64,
    tx_hash: [u8; 32],
) -> Result<DecodedEthTx, EthEnvelopeError> {
    let decoded = rlp::decode(payload)?;
    let fields = as_list(&decoded)?;
    let [f_cid, f_nonce, f_prio, f_max, f_gas, f_to, f_val, f_data, f_al, f_yp, f_r, f_s] = fields
    else {
        return Err(EthEnvelopeError::WrongFieldCount {
            expected: 12,
            actual: fields.len(),
        });
    };
    let chain_id = parse_u64_be(f_cid)?;
    if chain_id != expected_chain_id {
        return Err(EthEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            actual: chain_id,
        });
    }
    let nonce = parse_u64_be(f_nonce)?;
    let max_priority_fee_per_gas_wei = parse_u128_be(f_prio)?;
    let max_fee_per_gas_wei = parse_u128_be(f_max)?;
    if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
        return Err(EthEnvelopeError::PriorityFeeAboveMaxFee {
            priority_fee_per_gas_wei,
            max_fee_per_gas_wei,
        });
    }
    let gas_limit = parse_u64_be(f_gas)?;
    let to = parse_to(f_to)?;
    let value_wei = parse_u128_be(f_val)?;
    let input = as_bytes(f_data)?.to_vec();
    let access_list = parse_access_list(f_al)?;
    let yp = parse_u64_be(f_yp)?;
    if yp > 1 {
        return Err(EthEnvelopeError::InvalidParityBit(yp));
    }
    let r = parse_sig_word(f_r)?;
    let s = parse_sig_word(f_s)?;

    let sighash = typed_signing_hash(
        0x02,
        vec![
            f_cid.clone(),
            f_nonce.clone(),
            f_prio.clone(),
            f_max.clone(),
            f_gas.clone(),
            f_to.clone(),
            f_val.clone(),
            f_data.clone(),
            f_al.clone(),
        ],
    );
    let sender = ecrecover_eth_address(&sighash, yp as u8, &r, &s)?;

    Ok(DecodedEthTx {
        tx_type: EthTxType::Eip1559,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        to,
        value_wei,
        input,
        access_list,
        authorizations: Vec::new(),
        tx_hash,
    })
}

fn decode_eip7702(
    payload: &[u8],
    expected_chain_id: u64,
    tx_hash: [u8; 32],
) -> Result<DecodedEthTx, EthEnvelopeError> {
    let decoded = rlp::decode(payload)?;
    let fields = as_list(&decoded)?;
    let [f_cid, f_nonce, f_prio, f_max, f_gas, f_to, f_val, f_data, f_al, f_auth, f_yp, f_r, f_s] =
        fields
    else {
        return Err(EthEnvelopeError::WrongFieldCount {
            expected: 13,
            actual: fields.len(),
        });
    };
    let chain_id = parse_u64_be(f_cid)?;
    if chain_id != expected_chain_id {
        return Err(EthEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            actual: chain_id,
        });
    }
    let nonce = parse_u64_be(f_nonce)?;
    let max_priority_fee_per_gas_wei = parse_u128_be(f_prio)?;
    let max_fee_per_gas_wei = parse_u128_be(f_max)?;
    if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
        return Err(EthEnvelopeError::PriorityFeeAboveMaxFee {
            priority_fee_per_gas_wei,
            max_fee_per_gas_wei,
        });
    }
    let gas_limit = parse_u64_be(f_gas)?;
    let Some(to_addr) = parse_to(f_to)? else {
        return Err(EthEnvelopeError::InvalidAddressLength(0));
    };
    let value_wei = parse_u128_be(f_val)?;
    let input = as_bytes(f_data)?.to_vec();
    let access_list = parse_access_list(f_al)?;
    let authorizations = parse_authorizations(f_auth)?;
    let yp = parse_u64_be(f_yp)?;
    if yp > 1 {
        return Err(EthEnvelopeError::InvalidParityBit(yp));
    }
    let r = parse_sig_word(f_r)?;
    let s = parse_sig_word(f_s)?;

    let sighash = typed_signing_hash(
        0x04,
        vec![
            f_cid.clone(),
            f_nonce.clone(),
            f_prio.clone(),
            f_max.clone(),
            f_gas.clone(),
            f_to.clone(),
            f_val.clone(),
            f_data.clone(),
            f_al.clone(),
            f_auth.clone(),
        ],
    );
    let sender = ecrecover_eth_address(&sighash, yp as u8, &r, &s)?;

    Ok(DecodedEthTx {
        tx_type: EthTxType::Eip7702,
        chain_id,
        sender,
        nonce,
        gas_limit,
        max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei,
        to: Some(to_addr),
        value_wei,
        input,
        access_list,
        authorizations,
        tx_hash,
    })
}

/// Deterministic `secp256k1` signing helper for unit/conformance tests.
#[cfg(test)]
pub(crate) fn sign_secp256k1_test(
    priv_key: &[u8; 32],
    msg_hash: &[u8; 32],
) -> (u8, [u8; 32], [u8; 32]) {
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::scalar::IsHigh;
    use k256::elliptic_curve::sec1::ToSec1Point;
    use k256::elliptic_curve::PrimeField;
    use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};

    let d = Scalar::from_repr((*priv_key).into()).unwrap();
    let z = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*msg_hash));
    for ctr in 1u64..1000 {
        let mut seed = [0u8; 32];
        let mut h_in = Vec::with_capacity(72);
        h_in.extend_from_slice(priv_key);
        h_in.extend_from_slice(msg_hash);
        h_in.extend_from_slice(&ctr.to_le_bytes());
        seed.copy_from_slice(&keccak256(&h_in));
        let Some(k) = Option::<Scalar>::from(Scalar::from_repr(seed.into())) else {
            continue;
        };
        if bool::from(k.is_zero()) {
            continue;
        }
        let r_pt = AffinePoint::from(ProjectivePoint::GENERATOR * k);
        let compressed = r_pt.to_sec1_point(true);
        let comp_bytes = compressed.as_bytes();
        let (first_tag, rem) = comp_bytes.split_first().unwrap();
        let mut y_parity = *first_tag - 0x02;
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(rem.get(..32).unwrap());
        let r_scalar = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(r_bytes));
        if bool::from(r_scalar.is_zero()) {
            continue;
        }
        // Only accept R points with x < n so ecrecover(r_bytes) needs no x + n branch.
        if Option::<Scalar>::from(Scalar::from_repr(r_bytes.into())).is_none() {
            continue;
        }
        let k_inv = k.invert().unwrap();
        let mut s_scalar = k_inv * (z + r_scalar * d);
        if bool::from(s_scalar.is_zero()) {
            continue;
        }
        if bool::from(s_scalar.is_high()) {
            s_scalar = -s_scalar;
            y_parity ^= 1;
        }
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(s_scalar.to_repr().as_slice());
        return (y_parity, r_bytes, s_bytes);
    }
    panic!("failed to sign test message");
}

/// Derive the 20-byte Ethereum address corresponding to `priv_key` in tests.
#[cfg(test)]
pub(crate) fn eth_address_of_secret(priv_key: &[u8; 32]) -> [u8; 20] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    use k256::elliptic_curve::PrimeField;
    use k256::{AffinePoint, ProjectivePoint, Scalar};

    let d = Scalar::from_repr((*priv_key).into()).unwrap();
    let pub_pt = AffinePoint::from(ProjectivePoint::GENERATOR * d).to_sec1_point(false);
    let digest = keccak256(&pub_pt.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    addr
}

#[cfg(test)]
mod tests {
    //! Signed-vector coverage for the EIP-1559 fee-market invariant
    //! (`maxPriorityFeePerGas <= maxFeePerGas`, revm's `TipAboveFeeCap`).

    use super::*;
    use crate::cross_domain::evm::mpt::keccak256;
    use crate::cross_domain::evm::rlp::Item as RlpItem;

    const TEST_PK: [u8; 32] = [0x5a; 32];
    const LANE_CHAIN_ID: u64 = 45_261;

    fn uint_be(v: u128) -> RlpItem {
        if v == 0 {
            return RlpItem::String(Vec::new());
        }
        let be = v.to_be_bytes();
        let nz = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        RlpItem::String(be[nz..].to_vec())
    }

    fn sig_scalar(word: &[u8; 32]) -> RlpItem {
        let nz = word.iter().position(|&b| b != 0).unwrap_or(word.len());
        RlpItem::String(word[nz..].to_vec())
    }

    fn finish_typed(tx_type: u8, mut unsigned: Vec<RlpItem>) -> Vec<u8> {
        let mut sign_buf = vec![tx_type];
        sign_buf.extend_from_slice(&rlp::encode(&RlpItem::List(unsigned.clone())));
        let sighash = keccak256(&sign_buf);
        let (yp, r, s) = sign_secp256k1_test(&TEST_PK, &sighash);
        unsigned.push(uint_be(u128::from(yp)));
        unsigned.push(sig_scalar(&r));
        unsigned.push(sig_scalar(&s));
        let mut raw = vec![tx_type];
        raw.extend_from_slice(&rlp::encode(&RlpItem::List(unsigned)));
        raw
    }

    fn build_eip1559(priority: u128, max_fee: u128) -> Vec<u8> {
        let unsigned = vec![
            uint_be(u128::from(LANE_CHAIN_ID)),
            uint_be(0),
            uint_be(priority),
            uint_be(max_fee),
            uint_be(21_000),
            RlpItem::String([0x22; 20].to_vec()),
            uint_be(1_000_000_000_000_000),
            RlpItem::String(Vec::new()),
            RlpItem::List(Vec::new()),
        ];
        finish_typed(0x02, unsigned)
    }

    fn build_eip7702(priority: u128, max_fee: u128) -> Vec<u8> {
        let authorization = RlpItem::List(vec![
            uint_be(u128::from(LANE_CHAIN_ID)),
            RlpItem::String([0x33; 20].to_vec()),
            uint_be(0),
            uint_be(0),
            RlpItem::String(vec![0x11; 32]),
            RlpItem::String(vec![0x22; 32]),
        ]);
        let unsigned = vec![
            uint_be(u128::from(LANE_CHAIN_ID)),
            uint_be(0),
            uint_be(priority),
            uint_be(max_fee),
            uint_be(21_000),
            RlpItem::String([0x22; 20].to_vec()),
            uint_be(0),
            RlpItem::String(Vec::new()),
            RlpItem::List(Vec::new()),
            RlpItem::List(vec![authorization]),
        ];
        finish_typed(0x04, unsigned)
    }

    fn expected_refusal(priority: u128, max_fee: u128) -> EthEnvelopeError {
        EthEnvelopeError::PriorityFeeAboveMaxFee {
            priority_fee_per_gas_wei: priority,
            max_fee_per_gas_wei: max_fee,
        }
    }

    #[test]
    fn eip1559_tip_above_fee_cap_refused() {
        let raw = build_eip1559(3_000_000_000, 2_000_000_000);
        let err = decode_and_recover_eth_tx(&raw, LANE_CHAIN_ID).unwrap_err();
        assert_eq!(err, expected_refusal(3_000_000_000, 2_000_000_000));
    }

    #[test]
    fn eip1559_tip_at_fee_cap_accepted() {
        let raw = build_eip1559(2_000_000_000, 2_000_000_000);
        let tx = decode_and_recover_eth_tx(&raw, LANE_CHAIN_ID).unwrap();
        assert_eq!(tx.max_priority_fee_per_gas_wei, 2_000_000_000);
        assert_eq!(tx.max_fee_per_gas_wei, 2_000_000_000);
    }

    #[test]
    fn eip7702_tip_above_fee_cap_refused() {
        let raw = build_eip7702(3_000_000_000, 2_000_000_000);
        let err = decode_and_recover_eth_tx(&raw, LANE_CHAIN_ID).unwrap_err();
        assert_eq!(err, expected_refusal(3_000_000_000, 2_000_000_000));
    }

    #[test]
    fn eip7702_tip_at_fee_cap_accepted() {
        let raw = build_eip7702(2_000_000_000, 2_000_000_000);
        let tx = decode_and_recover_eth_tx(&raw, LANE_CHAIN_ID).unwrap();
        assert_eq!(tx.tx_type, EthTxType::Eip7702);
        assert_eq!(tx.authorizations.len(), 1);
    }
}
