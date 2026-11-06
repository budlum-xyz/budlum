//! The `Foreign::Ethereum` transaction envelope (directive 8.2, the `Ethereum`
//! row of the foreign envelope table: raw RLP transaction, secp256k1, EIP-155
//! chain id, EVM account nonce; type 0 (EIP-155 only), 1, 2 and 4; type 3
//! (blob) refused).
//!
//! A foreign Ethereum transaction is a RAW, signed Ethereum-format transaction
//! signed for the Budlum foreign lane. It is not a wrapper and it is not
//! namespaced by a Budlum chain number: replay protection is the EIP-155
//! chain id inside the signature, so an envelope signed for another chain can
//! never be replayed here. The testnet lane signs for `45261`; mainnet signs
//! for `45260`, so the caller passes its configured chain id instead of
//! reading a crate-wide default.
//!
//! Envelope layouts (canonical RLP per the Yellow Paper appendix B):
//!
//! * `0x00`, legacy (the bare RLP, no type byte): `[nonce, gasPrice, gasLimit,
//!   to, value, data, v, r, s]`.
//!   `to` is the empty string for a creation. Only EIP-155 signatures are
//!   accepted (`v >= 35`); the unprotected `v = 27 | 28` encoding carries no
//!   chain binding and is refused.
//! * `0x01`, access list (EIP-2930): `[chainId, nonce, gasPrice, gasLimit,
//!   to, value, data, accessList, signatureYParity, signatureR, signatureS]`.
//! * `0x02`, fee market (EIP-1559): `[chainId, nonce, maxPriorityFeePerGas,
//!   maxFeePerGas, gasLimit, to, value, data, accessList,
//!   signatureYParity, signatureR, signatureS]`.
//! * `0x04`, set code (EIP-7702): the EIP-1559 layout with an additional
//!   `authorizationList` before the signature fields.
//! * `0x03`, blob (EIP-4844): refused, like every other type byte.
//!
//! The envelope checks (and only these):
//!
//! * the canonical RLP form (leading zeros, non-minimal forms and trailing
//!   bytes are refused inside the in-tree decoder),
//! * the field count of the envelope,
//! * `to` is the empty string or 20 bytes,
//! * every word is at most 32 bytes (`value` and the fee fields keep their
//!   full 256-bit width as left-padded `[u8; 32]`; `chainId`, `nonce`,
//!   `gasLimit` and `v` fit in a `u64`, a wider field is refused),
//! * the access list is a list of 20-byte addresses and lists of 32-byte
//!   storage keys,
//! * the authorization list (`0x04`) is a list of 6-item EIP-7702 entries
//!   (`chainId`, 20-byte `address`, `nonce`, `yParity` in `{0, 1}`, `r`, `s`).
//!   The authorization signatures themselves are NOT verified here: they are
//!   EIP-7702 execution semantics, evaluated by the EVM worker when the
//!   worker lands,
//! * the EIP-1559/EIP-7702 fee invariant `maxPriorityFeePerGas <=
//!   maxFeePerGas`,
//! * the chain id is the configured lane chain id (both the typed chain id
//!   and the legacy `v`-derived one), which is the replay protection,
//! * the outer signature recovers a sender; high-`s` is refused inside
//!   `recover_address` (EIP-2).
//!
//! WIRING: the WP-27 foreign-lane door consumes this once the EVM
//! environment lands. Until then the module is exercised by its tests,
//! mirroring the scheduler's landing.

use crate::cross_domain::evm::rlp::{as_bytes, decode, decode_uint, encode, Item, RlpError};
use crate::crypto::secp256k1_recover::{recover_address, RecoverError};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// The testnet chain id the foreign lane envelopes name (directive 8.2). The
/// caller passes its configured chain id; this constant names only the
/// testnet lane.
pub const TESTNET_FOREIGN_CHAIN_ID: u64 = 45261;

/// The gas fields, which differ by envelope type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignEvmGas {
    /// Legacy (`0x00`) and access-list (`0x01`) envelopes.
    Legacy {
        /// One gas price for all gas.
        gas_price: [u8; 32],
    },
    /// Fee-market (`0x02`) and set-code (`0x04`) envelopes.
    FeeMarket {
        /// The total fee cap.
        max_fee_per_gas: [u8; 32],
        /// The tip addressed to the block proposer.
        max_priority_fee_per_gas: [u8; 32],
    },
}

/// Where the envelope pays value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignEvmTo {
    /// The empty `to`: a contract creation.
    Creation,
    /// A call to an account.
    Address([u8; 20]),
}

/// One EIP-2930 access-list item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignEvmAccessItem {
    /// The account whose storage is touched.
    pub address: [u8; 20],
    /// The storage keys declared up front.
    pub storage_keys: Vec<[u8; 32]>,
}

/// One EIP-7702 authorization-list item, shape checked only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignEvmAuthorization {
    /// The chain the delegation authorizes; `0` means every chain.
    pub chain_id: u64,
    /// The contract whose code the authority delegates.
    pub address: [u8; 20],
    /// The authority account's nonce at signing time.
    pub nonce: u64,
    /// The parity of the authorization signature.
    pub y_parity: u8,
    /// The authorization signature `r`.
    pub r: [u8; 32],
    /// The authorization signature `s`.
    pub s: [u8; 32],
}

/// Which envelope the bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignEvmEnvelope {
    /// `0x00`, only with an EIP-155 signature.
    LegacyEip155,
    /// `0x01`, access list (EIP-2930).
    AccessList,
    /// `0x02`, fee market (EIP-1559).
    FeeMarket,
    /// `0x04`, set code (EIP-7702).
    SetCode,
}

/// A parsed and sender-verified foreign Ethereum transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignEvmTransaction {
    /// The envelope the bytes carry.
    pub envelope: ForeignEvmEnvelope,
    /// The chain id the signature names.
    pub chain_id: u64,
    /// The sender's nonce.
    pub nonce: u64,
    /// The gas limit.
    pub gas_limit: u64,
    /// The value target.
    pub to: ForeignEvmTo,
    /// The wei value, left-padded to 32 bytes.
    pub value: [u8; 32],
    /// The calldata.
    pub data: Vec<u8>,
    /// The decoded access list; empty for `0x00` and `0x02`.
    pub access_list: Vec<ForeignEvmAccessItem>,
    /// The gas fields, per envelope type.
    pub gas: ForeignEvmGas,
    /// The decoded authorization list; empty except for `0x04`.
    pub authorization_list: Vec<ForeignEvmAuthorization>,
    /// The recovered sender address.
    pub sender: [u8; 20],
}

/// Why a foreign Ethereum envelope is refused.
#[derive(Debug, Error)]
pub enum ForeignEvmError {
    /// Not one of `0x00`, `0x01`, `0x02`, `0x04`. `0x03` (blob) and every
    /// unknown type are refused.
    #[error("the envelope type is not supported (blob 0x03 and unknown types are refused)")]
    UnsupportedEnvelopeType,
    /// The RLP form is not canonical, or a length prefix is invalid.
    #[error("rlp: {0}")]
    Rlp(#[from] RlpError),
    /// The item count does not match the envelope type.
    #[error("the field count {got} does not match the envelope (expected {expected})")]
    InvalidFieldCount {
        /// The envelope's field count.
        expected: usize,
        /// The decoded item count.
        got: usize,
    },
    /// A word is wider than 32 bytes.
    #[error("a word is wider than 32 bytes")]
    FieldTooWide,
    /// The `to` field is neither empty nor 20 bytes.
    #[error("the to field is neither empty nor 20 bytes")]
    InvalidToField,
    /// The access list is not a list of (20-byte address, list of 32-byte keys).
    #[error("the access list shape is not valid")]
    MalformedAccessList,
    /// An authorization entry is not a 6-item EIP-7702 list.
    #[error("the authorization list shape is not valid")]
    MalformedAuthorizationList,
    /// A legacy signature with `v < 35`: no chain binding, replayable.
    #[error("unprotected legacy signature: v is below 35")]
    UnprotectedLegacy,
    /// Signed for a chain other than the configured lane chain id.
    #[error("chain id mismatch: expected {expected}, the envelope names {got}")]
    ChainIdMismatch {
        /// The configured lane chain id.
        expected: u64,
        /// The chain id the envelope names.
        got: u64,
    },
    /// The priority fee exceeds the max fee.
    #[error("the max priority fee exceeds the max fee")]
    PriorityFeeAboveMaxFee,
    /// The outer signature does not recover a sender.
    #[error("sender recovery: {0}")]
    Recover(#[from] RecoverError),
}

/// The body parts of a decoded envelope, extracted per type.
struct BodyParts {
    chain_id: Option<u64>,
    nonce: u64,
    gas: ForeignEvmGas,
    gas_limit: u64,
    to: ForeignEvmTo,
    value: [u8; 32],
    data: Vec<u8>,
    access_list: Vec<ForeignEvmAccessItem>,
    authorization_list: Vec<ForeignEvmAuthorization>,
}

/// Left-pads a byte string into 32 bytes; `Err(FieldTooWide)` above 32 bytes.
fn word_32(item: &Item) -> Result<[u8; 32], ForeignEvmError> {
    let bytes = as_bytes(item)?;
    if bytes.len() > 32 {
        return Err(ForeignEvmError::FieldTooWide);
    }
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(word)
}

/// Extracts the `to` field.
fn to_field(item: &Item) -> Result<ForeignEvmTo, ForeignEvmError> {
    let bytes = as_bytes(item)?;
    match bytes.len() {
        0 => Ok(ForeignEvmTo::Creation),
        20 => {
            let mut address = [0u8; 20];
            address.copy_from_slice(bytes);
            Ok(ForeignEvmTo::Address(address))
        }
        _ => Err(ForeignEvmError::InvalidToField),
    }
}

/// Decodes the access list; refuses anything else.
fn access_list(item: &Item) -> Result<Vec<ForeignEvmAccessItem>, ForeignEvmError> {
    let entries = match item {
        Item::List(entries) => entries,
        Item::String(_) => return Err(ForeignEvmError::MalformedAccessList),
    };
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let pair = match entry {
            Item::List(pair) if pair.len() == 2 => pair,
            _ => return Err(ForeignEvmError::MalformedAccessList),
        };
        let address_bytes = as_bytes(&pair[0]).map_err(|_| ForeignEvmError::MalformedAccessList)?;
        if address_bytes.len() != 20 {
            return Err(ForeignEvmError::MalformedAccessList);
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(address_bytes);
        let keys = match &pair[1] {
            Item::List(keys) => keys,
            Item::String(_) => return Err(ForeignEvmError::MalformedAccessList),
        };
        let mut storage_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = as_bytes(key).map_err(|_| ForeignEvmError::MalformedAccessList)?;
            if key_bytes.len() != 32 {
                return Err(ForeignEvmError::MalformedAccessList);
            }
            let mut storage_key = [0u8; 32];
            storage_key.copy_from_slice(key_bytes);
            storage_keys.push(storage_key);
        }
        decoded.push(ForeignEvmAccessItem {
            address,
            storage_keys,
        });
    }
    Ok(decoded)
}

/// Decodes the authorization list (EIP-7702); shape checked only.
fn authorization_list(item: &Item) -> Result<Vec<ForeignEvmAuthorization>, ForeignEvmError> {
    let entries = match item {
        Item::List(entries) => entries,
        Item::String(_) => return Err(ForeignEvmError::MalformedAuthorizationList),
    };
    let mut decoded = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = match entry {
            Item::List(fields) if fields.len() == 6 => fields,
            _ => return Err(ForeignEvmError::MalformedAuthorizationList),
        };
        let chain_id =
            decode_uint(&fields[0]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        let address_bytes =
            as_bytes(&fields[1]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        if address_bytes.len() != 20 {
            return Err(ForeignEvmError::MalformedAuthorizationList);
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(address_bytes);
        let nonce =
            decode_uint(&fields[2]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        let parity_bytes =
            as_bytes(&fields[3]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        // Canonical integer zero is the empty string; `[0x00]` is refused.
        let y_parity = match parity_bytes {
            [] => 0,
            [1] => 1,
            _ => return Err(ForeignEvmError::MalformedAuthorizationList),
        };
        let r = word_32(&fields[4]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        let s = word_32(&fields[5]).map_err(|_| ForeignEvmError::MalformedAuthorizationList)?;
        decoded.push(ForeignEvmAuthorization {
            chain_id,
            address,
            nonce,
            y_parity,
            r,
            s,
        });
    }
    Ok(decoded)
}

/// Extracts the body parts per envelope type.
fn extract_body(envelope: ForeignEvmEnvelope, body: &[Item]) -> Result<BodyParts, ForeignEvmError> {
    match envelope {
        ForeignEvmEnvelope::LegacyEip155 => Ok(BodyParts {
            chain_id: None,
            nonce: decode_uint(&body[0]).map_err(ForeignEvmError::Rlp)?,
            gas: ForeignEvmGas::Legacy {
                gas_price: word_32(&body[1])?,
            },
            gas_limit: decode_uint(&body[2]).map_err(ForeignEvmError::Rlp)?,
            to: to_field(&body[3])?,
            value: word_32(&body[4])?,
            data: as_bytes(&body[5])?.to_vec(),
            access_list: Vec::new(),
            authorization_list: Vec::new(),
        }),
        ForeignEvmEnvelope::AccessList => Ok(BodyParts {
            chain_id: Some(decode_uint(&body[0]).map_err(ForeignEvmError::Rlp)?),
            nonce: decode_uint(&body[1]).map_err(ForeignEvmError::Rlp)?,
            gas: ForeignEvmGas::Legacy {
                gas_price: word_32(&body[2])?,
            },
            gas_limit: decode_uint(&body[3]).map_err(ForeignEvmError::Rlp)?,
            to: to_field(&body[4])?,
            value: word_32(&body[5])?,
            data: as_bytes(&body[6])?.to_vec(),
            access_list: access_list(&body[7])?,
            authorization_list: Vec::new(),
        }),
        ForeignEvmEnvelope::FeeMarket | ForeignEvmEnvelope::SetCode => {
            let max_priority_fee_per_gas = word_32(&body[2])?;
            let max_fee_per_gas = word_32(&body[3])?;
            if max_priority_fee_per_gas > max_fee_per_gas {
                return Err(ForeignEvmError::PriorityFeeAboveMaxFee);
            }
            let mut authorizations = Vec::new();
            if envelope == ForeignEvmEnvelope::SetCode {
                authorizations = authorization_list(&body[9])?;
            }
            Ok(BodyParts {
                chain_id: Some(decode_uint(&body[0]).map_err(ForeignEvmError::Rlp)?),
                nonce: decode_uint(&body[1]).map_err(ForeignEvmError::Rlp)?,
                gas: ForeignEvmGas::FeeMarket {
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                },
                gas_limit: decode_uint(&body[4]).map_err(ForeignEvmError::Rlp)?,
                to: to_field(&body[5])?,
                value: word_32(&body[6])?,
                data: as_bytes(&body[7])?.to_vec(),
                access_list: access_list(&body[8])?,
                authorization_list: authorizations,
            })
        }
    }
}

/// The canonical RLP item for an integer: the empty string encodes zero.
fn uint_item(n: u64) -> Item {
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    Item::String(be[start..].to_vec())
}

fn keccak_digest(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// The typed-envelope digest: `keccak(typeByte || rlp(body))`.
fn typed_digest(type_byte: u8, body: &[Item]) -> [u8; 32] {
    let body_bytes = encode(&Item::List(body.to_vec()));
    let mut preimage = Vec::with_capacity(1 + body_bytes.len());
    preimage.push(type_byte);
    preimage.extend_from_slice(&body_bytes);
    keccak_digest(&preimage)
}

/// The legacy EIP-155 digest: `keccak(rlp([...body, chainId, 0, 0]))`.
fn legacy_digest(body: &[Item], chain_id: u64) -> [u8; 32] {
    let mut items = body.to_vec();
    items.push(uint_item(chain_id));
    items.push(uint_item(0));
    items.push(uint_item(0));
    keccak_digest(&encode(&Item::List(items)))
}

/// The typed envelope's `yParity` item: zero is the empty string (canonical
/// RLP integer zero), one is a single `0x01`. `[0x00]` is the non-minimal
/// zero and is refused.
fn parity_byte(item: &Item) -> Result<u8, ForeignEvmError> {
    match as_bytes(item)? {
        [] => Ok(0),
        [1] => Ok(1),
        _ => Err(ForeignEvmError::Recover(RecoverError::RecoveryId)),
    }
}

/// Parses and sender-verifies a foreign Ethereum transaction.
///
/// `expected_chain_id` is the configured lane chain id (testnet `45261`); a
/// signature for any other chain is refused, which is the replay protection.
///
/// # Errors
///
/// [`ForeignEvmError`] for a malformed, replayed, mis-priced or unrecoverable
/// envelope.
pub fn parse_foreign_ethereum_transaction(
    bytes: &[u8],
    expected_chain_id: u64,
) -> Result<ForeignEvmTransaction, ForeignEvmError> {
    let first = bytes
        .first()
        .copied()
        .ok_or(ForeignEvmError::UnsupportedEnvelopeType)?;
    let legacy = first >= 0xc0;
    let typed = matches!(first, 0x01 | 0x02 | 0x04);
    // Everything else, including 0x00 (a type byte is not a legacy envelope)
    // and 0x03 (blob), is refused.
    if !legacy && !typed {
        return Err(ForeignEvmError::UnsupportedEnvelopeType);
    }

    let (envelope, items) = if legacy {
        let items = match decode(bytes)? {
            Item::List(items) => items,
            Item::String(_) => return Err(ForeignEvmError::UnsupportedEnvelopeType),
        };
        (ForeignEvmEnvelope::LegacyEip155, items)
    } else {
        let envelope = match first {
            0x01 => ForeignEvmEnvelope::AccessList,
            0x02 => ForeignEvmEnvelope::FeeMarket,
            _ => ForeignEvmEnvelope::SetCode,
        };
        let items = match decode(&bytes[1..])? {
            Item::List(items) => items,
            Item::String(_) => return Err(ForeignEvmError::UnsupportedEnvelopeType),
        };
        (envelope, items)
    };

    let expected = match envelope {
        ForeignEvmEnvelope::LegacyEip155 => 9,
        ForeignEvmEnvelope::AccessList => 11,
        ForeignEvmEnvelope::FeeMarket => 12,
        ForeignEvmEnvelope::SetCode => 13,
    };
    if items.len() != expected {
        return Err(ForeignEvmError::InvalidFieldCount {
            expected,
            got: items.len(),
        });
    }

    let (body, signature_items) = items.split_at(items.len() - 3);
    let parts = extract_body(envelope, body)?;

    let r_word = word_32(&signature_items[1])?;
    let s_word = word_32(&signature_items[2])?;

    let (chain_id, y_parity, digest) = if legacy {
        let v = decode_uint(&signature_items[0]).map_err(ForeignEvmError::Rlp)?;
        let diff = v
            .checked_sub(35)
            .ok_or(ForeignEvmError::UnprotectedLegacy)?;
        (
            diff / 2,
            u8::from(diff % 2 == 1),
            legacy_digest(body, diff / 2),
        )
    } else {
        (
            parts
                .chain_id
                .ok_or(ForeignEvmError::UnsupportedEnvelopeType)?,
            parity_byte(&signature_items[0])?,
            typed_digest(first, body),
        )
    };

    if chain_id != expected_chain_id {
        return Err(ForeignEvmError::ChainIdMismatch {
            expected: expected_chain_id,
            got: chain_id,
        });
    }

    let mut signature = [0u8; 65];
    signature[..32].copy_from_slice(&r_word);
    signature[32..64].copy_from_slice(&s_word);
    signature[64] = y_parity;
    let sender = recover_address(&digest, &signature)?;

    Ok(ForeignEvmTransaction {
        envelope,
        chain_id,
        nonce: parts.nonce,
        gas_limit: parts.gas_limit,
        to: parts.to,
        value: parts.value,
        data: parts.data,
        access_list: parts.access_list,
        gas: parts.gas,
        authorization_list: parts.authorization_list,
        sender,
    })
}

#[cfg(test)]
mod tests {
    //! Happy-path fixtures are real RFC 6979 signatures from the Hardhat
    //! account `f39fd6e51aad88f6f4ce6ab8827279cfffb92266`, signed for chain
    //! `45261` (FX_WRONG_CHAIN signs for Sepolia on purpose). FX_HIGH_S flips
    //! the signature into the upper half of the order. The fixtures were
    //! produced and recovery-verified with coincurve; the tree carries no
    //! other copy of them.

    use super::*;

    const SENDER: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const TARGET: [u8; 20] = [0x11; 20];
    const DELEGATE: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
        0xef, 0x12, 0x34, 0x56, 0x78,
    ];

    const FX_LEGACY_CALL: &str = "f8730a8477359400830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756d830161bda0447fa68a13e6a9529a4667c48a704ae2140ed08e8cb424faab7677cb69e018a5a0441ab3d090aeaefdf236b7acc44c914f09b5d594ddeb1225f16c3a8eccad247c";
    const FX_LEGACY_CREATE: &str = "f8580b8477359400830186a08080856080604052830161bea08847b6fa5d2e7c8404f0fe90e032faf836931a8699352c0d9bcd13b3eae2081fa029a06f2ace7b36e66733ed1f4d942e97349c6ada5070a5a3a2872a0c9f3cfc96";
    const FX_2930_CALL: &str = "01f8ad82b0cd0c8477359400830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756df838f7941111111111111111111111111111111111111111e1a0000000000000000000000000000000000000000000000000000000000000000001a07e61f9c0eb1bab1621625511b839f56325bccdd5737a2ea0089da4244ec94e7ea061a3a4570931a28664b1bbcd438ccf8027113fd85c3cbb6393fec5c8947d0dbb";
    const FX_1559_CALL: &str = "02f87a82b0cd0d8459682f008506fc23ac00830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756dc080a0e5dc337bfedfae717879ef74251547f1232290ae5dc7df5f23dd4b187c613cf7a0276e0f3f7ea76660660a50891f07bf524514d79245528e6a41f1fce6371d904a";
    const FX_7702_CALL: &str = "04f8da82b0cd0e8459682f008506fc23ac00830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756dc0f85ef85c82b0cd941234567890abcdef1234567890abcdef123456788080a03c42265674281d7d9972788f6e0b115b1977e1d450974466b94ebe2e2f419e0ba06cee430b364af8b959da49a95268cec6a6d221c64ef3279eeeb947b64262949280a0069c87e6c8c2bfafc7c8a0182be49da1d30460dc682df0c1224c85a2073476b3a04a6706ea06a09c47bc9a8163ea53cbf9562229d05d6bf8d2853c00601d3d550a";
    const FX_BLOB: &str = "03c382b0cd";
    const FX_UNKNOWN_TYPE: &str = "05c382b0cd";
    const FX_UNPROTECTED: &str = "f8700f8477359400830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756d1ca08d6dd8af5e8727a2044844fb29dbee47802b20130c8d26cda0ea09d5c71da00aa064701481c4c8e5cdbee4f315272cef9a7535e23dc467432469ed5fd9c23491bd";
    const FX_WRONG_CHAIN: &str = "f874108477359400830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756d8401546d72a0823d5ae0f8b593dcc286558ecdb51f9894189a998d02d458771934332742bc99a07057a44d5ee9d56eea52cce4004cf490a21fbb39ccfd03a61ae04d456c6b769d";
    const FX_PRIORITY_ABOVE_MAX: &str = "02f87b82b0cd118509502f90008506fc23ac00830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756dc001a0865fec9ad18b55260f5993801e84d941739f227120e86b5bad915d834c140865a038232896e64b9deff4bc7b5c6e5f0c28942979fa6ba96338cd80c4282a9d8038";
    const FX_HIGH_S: &str = "02f87a82b0cd128459682f008506fc23ac00830186a0941111111111111111111111111111111111111111808c68656c6c6f206275646c756dc001a02e774726e8e52156808ece5fc048be02682bba9c1b1546f62284dec909abb55fa09e556e13d14f33039ecc75b9af3e1186c157d81c52576a514b0b9dd394415665";

    fn word_of(n: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&n.to_be_bytes());
        word
    }

    fn sender_of(tx: &ForeignEvmTransaction) -> String {
        hex::encode(tx.sender)
    }

    #[test]
    fn foreign_ethereum_legacy_call_recovers_its_signer() {
        let tx = parse_foreign_ethereum_transaction(
            &hex::decode(FX_LEGACY_CALL).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        )
        .expect("parses");
        assert_eq!(tx.envelope, ForeignEvmEnvelope::LegacyEip155);
        assert_eq!(tx.chain_id, 45261);
        assert_eq!(tx.nonce, 10);
        assert_eq!(tx.gas_limit, 100_000);
        assert_eq!(tx.to, ForeignEvmTo::Address(TARGET));
        assert_eq!(tx.value, [0u8; 32]);
        assert_eq!(tx.data, b"hello budlum");
        assert!(tx.access_list.is_empty());
        assert_eq!(
            tx.gas,
            ForeignEvmGas::Legacy {
                gas_price: word_of(2_000_000_000)
            }
        );
        assert!(tx.authorization_list.is_empty());
        assert_eq!(sender_of(&tx), SENDER);
    }

    #[test]
    fn foreign_ethereum_legacy_creation_parses() {
        let tx = parse_foreign_ethereum_transaction(
            &hex::decode(FX_LEGACY_CREATE).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        )
        .expect("parses");
        assert_eq!(tx.envelope, ForeignEvmEnvelope::LegacyEip155);
        assert_eq!(tx.nonce, 11);
        assert_eq!(tx.to, ForeignEvmTo::Creation);
        assert_eq!(tx.data, [0x60, 0x80, 0x60, 0x40, 0x52]);
        assert_eq!(sender_of(&tx), SENDER);
    }

    #[test]
    fn foreign_ethereum_access_list_parses() {
        let tx = parse_foreign_ethereum_transaction(
            &hex::decode(FX_2930_CALL).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        )
        .expect("parses");
        assert_eq!(tx.envelope, ForeignEvmEnvelope::AccessList);
        assert_eq!(tx.nonce, 12);
        assert_eq!(tx.access_list.len(), 1);
        assert_eq!(tx.access_list[0].address, TARGET);
        assert_eq!(tx.access_list[0].storage_keys, vec![[0u8; 32]]);
        assert_eq!(
            tx.gas,
            ForeignEvmGas::Legacy {
                gas_price: word_of(2_000_000_000)
            }
        );
        assert_eq!(sender_of(&tx), SENDER);
    }

    #[test]
    fn foreign_ethereum_fee_market_parses() {
        let tx = parse_foreign_ethereum_transaction(
            &hex::decode(FX_1559_CALL).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        )
        .expect("parses");
        assert_eq!(tx.envelope, ForeignEvmEnvelope::FeeMarket);
        assert_eq!(tx.nonce, 13);
        assert_eq!(
            tx.gas,
            ForeignEvmGas::FeeMarket {
                max_fee_per_gas: word_of(30_000_000_000),
                max_priority_fee_per_gas: word_of(1_500_000_000),
            }
        );
        assert_eq!(sender_of(&tx), SENDER);
    }

    #[test]
    fn foreign_ethereum_set_code_parses() {
        let tx = parse_foreign_ethereum_transaction(
            &hex::decode(FX_7702_CALL).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        )
        .expect("parses");
        assert_eq!(tx.envelope, ForeignEvmEnvelope::SetCode);
        assert_eq!(tx.nonce, 14);
        assert_eq!(tx.authorization_list.len(), 1);
        let auth = &tx.authorization_list[0];
        assert_eq!(auth.chain_id, 45261);
        assert_eq!(auth.address, DELEGATE);
        assert_eq!(auth.nonce, 0);
        assert_eq!(auth.y_parity, 0);
        assert_eq!(
            hex::encode(auth.r),
            "3c42265674281d7d9972788f6e0b115b1977e1d450974466b94ebe2e2f419e0b"
        );
        assert_eq!(
            hex::encode(auth.s),
            "6cee430b364af8b959da49a95268cec6a6d221c64ef3279eeeb947b642629492"
        );
        assert_eq!(sender_of(&tx), SENDER);
    }

    #[test]
    fn foreign_ethereum_blob_type_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_BLOB).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(ForeignEvmError::UnsupportedEnvelopeType)
        ));
    }

    #[test]
    fn foreign_ethereum_unknown_type_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_UNKNOWN_TYPE).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(ForeignEvmError::UnsupportedEnvelopeType)
        ));
    }

    #[test]
    fn foreign_ethereum_empty_input_is_refused() {
        let result = parse_foreign_ethereum_transaction(&[], TESTNET_FOREIGN_CHAIN_ID);
        assert!(matches!(
            result,
            Err(ForeignEvmError::UnsupportedEnvelopeType)
        ));
    }

    #[test]
    fn foreign_ethereum_unprotected_legacy_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_UNPROTECTED).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(result, Err(ForeignEvmError::UnprotectedLegacy)));
    }

    #[test]
    fn foreign_ethereum_wrong_chain_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_WRONG_CHAIN).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(ForeignEvmError::ChainIdMismatch {
                expected: 45261,
                got: 11155111,
            })
        ));
    }

    #[test]
    fn foreign_ethereum_high_s_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_HIGH_S).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(ForeignEvmError::Recover(RecoverError::HighS))
        ));
    }

    #[test]
    fn foreign_ethereum_priority_fee_above_max_fee_is_refused() {
        let result = parse_foreign_ethereum_transaction(
            &hex::decode(FX_PRIORITY_ABOVE_MAX).expect("hex"),
            TESTNET_FOREIGN_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(ForeignEvmError::PriorityFeeAboveMaxFee)
        ));
    }

    #[test]
    fn foreign_ethereum_malformed_access_list_is_refused() {
        let bad_access = Item::List(vec![Item::List(vec![
            Item::String(vec![0x99; 19]),
            Item::List(vec![]),
        ])]);
        let body = vec![
            uint_item(45261),
            uint_item(12),
            uint_item(2_000_000_000),
            uint_item(100_000),
            Item::String(TARGET.to_vec()),
            uint_item(0),
            Item::String(b"hi".to_vec()),
            bad_access,
            uint_item(1),
            Item::String(vec![0x11; 32]),
            Item::String(vec![0x22; 32]),
        ];
        let mut raw = vec![0x01];
        raw.extend_from_slice(&encode(&Item::List(body)));
        let result = parse_foreign_ethereum_transaction(&raw, TESTNET_FOREIGN_CHAIN_ID);
        assert!(matches!(result, Err(ForeignEvmError::MalformedAccessList)));
    }

    #[test]
    fn foreign_ethereum_malformed_authorization_list_is_refused() {
        // An authorization with five items instead of six.
        let bad_auth = Item::List(vec![Item::List(vec![
            uint_item(45261),
            Item::String(DELEGATE.to_vec()),
            uint_item(0),
            Item::String(vec![0x00]),
            Item::String(vec![0x33; 32]),
        ])]);
        let body = vec![
            uint_item(45261),
            uint_item(14),
            uint_item(1_500_000_000),
            uint_item(30_000_000_000),
            uint_item(100_000),
            Item::String(TARGET.to_vec()),
            uint_item(0),
            Item::String(b"hi".to_vec()),
            Item::List(vec![]),
            bad_auth,
            uint_item(0),
            Item::String(vec![0x33; 32]),
            Item::String(vec![0x44; 32]),
        ];
        let mut raw = vec![0x04];
        raw.extend_from_slice(&encode(&Item::List(body)));
        let result = parse_foreign_ethereum_transaction(&raw, TESTNET_FOREIGN_CHAIN_ID);
        assert!(matches!(
            result,
            Err(ForeignEvmError::MalformedAuthorizationList)
        ));
    }

    #[test]
    fn foreign_ethereum_invalid_to_field_is_refused() {
        let body = vec![
            uint_item(45261),
            uint_item(17),
            uint_item(1_500_000_000),
            uint_item(30_000_000_000),
            uint_item(100_000),
            Item::String(vec![0x77; 21]),
            uint_item(0),
            Item::String(b"hi".to_vec()),
            Item::List(vec![]),
            uint_item(0),
            Item::String(vec![0x33; 32]),
            Item::String(vec![0x44; 32]),
        ];
        let mut raw = vec![0x02];
        raw.extend_from_slice(&encode(&Item::List(body)));
        let result = parse_foreign_ethereum_transaction(&raw, TESTNET_FOREIGN_CHAIN_ID);
        assert!(matches!(result, Err(ForeignEvmError::InvalidToField)));
    }

    #[test]
    fn foreign_ethereum_non_canonical_integer_is_refused() {
        // A chain id with a leading zero is not canonical.
        let body = vec![
            Item::String(vec![0x00, 0x01]),
            uint_item(13),
            uint_item(1_500_000_000),
            uint_item(30_000_000_000),
            uint_item(100_000),
            Item::String(TARGET.to_vec()),
            uint_item(0),
            Item::String(b"hi".to_vec()),
            Item::List(vec![]),
            uint_item(0),
            Item::String(vec![0x33; 32]),
            Item::String(vec![0x44; 32]),
        ];
        let mut raw = vec![0x02];
        raw.extend_from_slice(&encode(&Item::List(body)));
        let result = parse_foreign_ethereum_transaction(&raw, TESTNET_FOREIGN_CHAIN_ID);
        assert!(matches!(result, Err(ForeignEvmError::Rlp(_))));
    }
}
