//! `Foreign::Cosmos` (`cosmos.tx.v1beta1.TxRaw`) decoding and `secp256k1`
//! `SIGN_MODE_DIRECT` verification (`WP-29`, `Section 8.6.2`).
//!
//! Accepts `cosmos.tx.v1beta1.TxRaw` signed under `SIGN_MODE_DIRECT` (`1`) for
//! chain ID `budlum-testnet-1`, derives the 20-byte Cosmos address
//! `RIPEMD-160(SHA-256(compressed_secp256k1_pubkey))` and `bud1...` Bech32
//! address, enforces low-`s` ECDSA malleability protection, and restricts body
//! messages to the `Section 8.6.1` WASM message subset (`MsgStoreCode`,
//! `MsgInstantiateContract`, `MsgInstantiateContract2`, `MsgExecuteContract`,
//! `MsgMigrateContract`, and `MsgSend`). `StakingMsg`, `DistributionMsg`,
//! `GovMsg`, and IBC messages are deterministically refused.

use std::fmt;

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use prost::Message;
use sha2::{Digest as _, Sha256};

use crate::object_layer::family::encoding::bech32_encode;

/// Canonical Cosmos chain identifier for Budlum testnet (`Section 8.6.2`, `KR-34`).
pub const BUDLUM_COSMOS_CHAIN_ID: &str = "budlum-testnet-1";

/// Bech32 human-readable prefix for Budlum Cosmos/WASM addresses (`Section 8.4.2`).
pub const COSMOS_ADDRESS_HRP: &str = "bud";

/// Protobuf `SignMode::SIGN_MODE_DIRECT` (`cosmos.tx.signing.v1beta1.SignMode`).
pub const SIGN_MODE_DIRECT: i32 = 1;

/// Protobuf `type_url` for compressed `secp256k1` public keys.
pub const SECP256K1_PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

/// Maximum accepted `TxRaw` wire byte length (`2 MiB`, bounded against DoS).
pub const MAX_COSMOS_TX_BYTES: usize = 2 * 1024 * 1024;

/// Half order of `secp256k1` (`n / 2`, big-endian) for low-`s` enforcement.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Protobuf `google.protobuf.Any`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ProtoAny {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// Protobuf `cosmos.tx.v1beta1.TxRaw`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TxRawProto {
    #[prost(bytes = "vec", tag = "1")]
    pub body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_info_bytes: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub signatures: Vec<Vec<u8>>,
}

/// Protobuf `cosmos.tx.v1beta1.TxBody`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TxBodyProto {
    #[prost(message, repeated, tag = "1")]
    pub messages: Vec<ProtoAny>,
    #[prost(string, tag = "2")]
    pub memo: String,
    #[prost(uint64, tag = "3")]
    pub timeout_height: u64,
}

/// Protobuf `cosmos.base.v1beta1.Coin`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CosmosCoinProto {
    #[prost(string, tag = "1")]
    pub denom: String,
    #[prost(string, tag = "2")]
    pub amount: String,
}

/// Protobuf `cosmos.tx.v1beta1.ModeInfo.Single`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ModeInfoSingleProto {
    #[prost(int32, tag = "1")]
    pub mode: i32,
}

/// Protobuf `cosmos.tx.v1beta1.ModeInfo`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ModeInfoProto {
    #[prost(message, optional, tag = "1")]
    pub single: Option<ModeInfoSingleProto>,
}

/// Protobuf `cosmos.tx.v1beta1.SignerInfo`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SignerInfoProto {
    #[prost(message, optional, tag = "1")]
    pub public_key: Option<ProtoAny>,
    #[prost(message, optional, tag = "2")]
    pub mode_info: Option<ModeInfoProto>,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
}

/// Protobuf `cosmos.tx.v1beta1.Fee`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CosmosFeeProto {
    #[prost(message, repeated, tag = "1")]
    pub amount: Vec<CosmosCoinProto>,
    #[prost(uint64, tag = "2")]
    pub gas_limit: u64,
    #[prost(string, tag = "3")]
    pub payer: String,
    #[prost(string, tag = "4")]
    pub granter: String,
}

/// Protobuf `cosmos.tx.v1beta1.AuthInfo`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct AuthInfoProto {
    #[prost(message, repeated, tag = "1")]
    pub signer_infos: Vec<SignerInfoProto>,
    #[prost(message, optional, tag = "2")]
    pub fee: Option<CosmosFeeProto>,
}

/// Protobuf `cosmos.tx.v1beta1.SignDoc`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SignDocProto {
    #[prost(bytes = "vec", tag = "1")]
    pub body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_info_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(uint64, tag = "4")]
    pub account_number: u64,
}

/// Protobuf `cosmos.crypto.secp256k1.PubKey`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct Secp256k1PubKeyProto {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
}

/// Protobuf `cosmos.bank.v1beta1.MsgSend`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgSendProto {
    #[prost(string, tag = "1")]
    pub from_address: String,
    #[prost(string, tag = "2")]
    pub to_address: String,
    #[prost(message, repeated, tag = "3")]
    pub amount: Vec<CosmosCoinProto>,
}

/// Protobuf `cosmwasm.wasm.v1.MsgStoreCode`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgStoreCodeProto {
    #[prost(string, tag = "1")]
    pub sender: String,
    #[prost(bytes = "vec", tag = "2")]
    pub wasm_byte_code: Vec<u8>,
}

/// Protobuf `cosmwasm.wasm.v1.MsgInstantiateContract`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgInstantiateContractProto {
    #[prost(string, tag = "1")]
    pub sender: String,
    #[prost(string, tag = "2")]
    pub admin: String,
    #[prost(uint64, tag = "3")]
    pub code_id: u64,
    #[prost(string, tag = "4")]
    pub label: String,
    #[prost(bytes = "vec", tag = "5")]
    pub msg: Vec<u8>,
    #[prost(message, repeated, tag = "6")]
    pub funds: Vec<CosmosCoinProto>,
}

/// Protobuf `cosmwasm.wasm.v1.MsgInstantiateContract2`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgInstantiateContract2Proto {
    #[prost(string, tag = "1")]
    pub sender: String,
    #[prost(string, tag = "2")]
    pub admin: String,
    #[prost(uint64, tag = "3")]
    pub code_id: u64,
    #[prost(string, tag = "4")]
    pub label: String,
    #[prost(bytes = "vec", tag = "5")]
    pub msg: Vec<u8>,
    #[prost(message, repeated, tag = "6")]
    pub funds: Vec<CosmosCoinProto>,
    #[prost(bytes = "vec", tag = "7")]
    pub salt: Vec<u8>,
    #[prost(bool, tag = "8")]
    pub fix_msg: bool,
}

/// Protobuf `cosmwasm.wasm.v1.MsgExecuteContract`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgExecuteContractProto {
    #[prost(string, tag = "1")]
    pub sender: String,
    #[prost(string, tag = "2")]
    pub contract: String,
    #[prost(bytes = "vec", tag = "3")]
    pub msg: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub funds: Vec<CosmosCoinProto>,
}

/// Protobuf `cosmwasm.wasm.v1.MsgMigrateContract`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MsgMigrateContractProto {
    #[prost(string, tag = "1")]
    pub sender: String,
    #[prost(string, tag = "2")]
    pub contract: String,
    #[prost(uint64, tag = "3")]
    pub code_id: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub msg: Vec<u8>,
}

/// Accepted WASM / Cosmos body message variants (`Section 8.6.1`).
///
/// Convenience: routed from `Foreign::Cosmos` and `ExecuteCall(WASM)` into `budlum-ee-wasm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmosWasmMsg {
    StoreCode(MsgStoreCodeProto),
    InstantiateContract(MsgInstantiateContractProto),
    InstantiateContract2(MsgInstantiateContract2Proto),
    ExecuteContract(MsgExecuteContractProto),
    MigrateContract(MsgMigrateContractProto),
    BankSend {
        from_address: String,
        to_address: String,
        amount_ubud: u64,
    },
}

/// Decoded and signature-verified `Foreign::Cosmos` transaction (`WP-29`).
///
/// Convenience: consumed by coordinator foreign-lane execution and Cosmos RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCosmosTx {
    pub tx_hash: [u8; 32],
    pub sender_raw: [u8; 20],
    pub sender_bech32: String,
    pub pubkey_compressed: [u8; 33],
    pub account_number: u64,
    pub sequence: u64,
    pub gas_limit: u64,
    pub fee_ubud: u64,
    pub memo: String,
    pub timeout_height: u64,
    pub messages: Vec<CosmosWasmMsg>,
}

/// Refusal reasons when decoding or verifying a `Foreign::Cosmos` `TxRaw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmosEnvelopeError {
    EmptyOrOversized(usize),
    ProtobufDecode(String),
    WrongSignerCount(usize),
    MissingPublicKey,
    UnsupportedPubKeyType(String),
    InvalidPublicKeyBytes,
    UnsupportedSignMode(i32),
    InvalidSignatureLength(usize),
    SignatureHighS,
    InvalidSignature,
    MissingFee,
    ZeroGasLimit,
    InvalidCoinDenom(String),
    InvalidCoinAmount(String),
    EmptyMessages,
    UnsupportedMessageType(String),
    SenderMismatch { expected: String, actual: String },
}

impl fmt::Display for CosmosEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyOrOversized(n) => write!(f, "Cosmos TxRaw length {n} out of bounds"),
            Self::ProtobufDecode(e) => write!(f, "Cosmos protobuf decode failed: {e}"),
            Self::WrongSignerCount(n) => write!(f, "expected exactly 1 Cosmos signer, got {n}"),
            Self::MissingPublicKey => write!(f, "missing SignerInfo.public_key"),
            Self::UnsupportedPubKeyType(t) => write!(f, "unsupported Cosmos pubkey type_url: {t}"),
            Self::InvalidPublicKeyBytes => write!(f, "invalid 33-byte compressed secp256k1 pubkey"),
            Self::UnsupportedSignMode(m) => {
                write!(f, "unsupported Cosmos sign mode {m} (require SIGN_MODE_DIRECT = 1)")
            }
            Self::InvalidSignatureLength(n) => {
                write!(f, "expected 64-byte secp256k1 signature, got {n}")
            }
            Self::SignatureHighS => write!(f, "secp256k1 signature s exceeds half order"),
            Self::InvalidSignature => write!(f, "Cosmos SIGN_MODE_DIRECT signature invalid"),
            Self::MissingFee => write!(f, "missing AuthInfo.fee"),
            Self::ZeroGasLimit => write!(f, "Cosmos fee gas_limit must be non-zero"),
            Self::InvalidCoinDenom(d) => write!(f, "unsupported Cosmos coin denom '{d}' (ubud)"),
            Self::InvalidCoinAmount(a) => write!(f, "invalid Cosmos coin amount '{a}'"),
            Self::EmptyMessages => write!(f, "Cosmos TxBody contains zero messages"),
            Self::UnsupportedMessageType(u) => {
                write!(f, "Cosmos message type_url '{u}' is refused on Budlum")
            }
            Self::SenderMismatch { expected, actual } => {
                write!(f, "message sender '{actual}' does not match signer '{expected}'")
            }
        }
    }
}

impl std::error::Error for CosmosEnvelopeError {}

/// ISO/IEC 10118-3 `RIPEMD-160` digest used purely for standard Cosmos 20-byte
/// address derivation `RIPEMD-160(SHA-256(pubkey_compressed_33))`.
///
/// Convenience: exposed for Cosmos RPC and address derivation helpers.
#[must_use]
pub fn ripemd160(msg: &[u8]) -> [u8; 20] {
    const K_LEFT: [u32; 5] = [
        0x0000_0000,
        0x5a82_7999,
        0x6ed9_eba1,
        0x8f1b_bcdc,
        0xa953_fd4e,
    ];
    const K_RIGHT: [u32; 5] = [
        0x50a2_8be6,
        0x5c4d_d124,
        0x6d70_3ef3,
        0x7a6d_76e9,
        0x0000_0000,
    ];
    const R_LEFT: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9,
        5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8,
        12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    const R_RIGHT: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8,
        12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11,
        15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    const S_LEFT: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12,
        15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14,
        15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11,
        8, 5, 6,
    ];
    const S_RIGHT: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7,
        12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11,
        14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13,
        11, 11,
    ];

    const fn round_fn(j: usize, x: u32, y: u32, z: u32) -> u32 {
        if j < 16 {
            x ^ y ^ z
        } else if j < 32 {
            (x & y) | (!x & z)
        } else if j < 48 {
            (x | !y) ^ z
        } else if j < 64 {
            (x & z) | (y & !z)
        } else {
            x ^ (y | !z)
        }
    }

    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut buf = Vec::with_capacity(msg.len().saturating_add(72));
    buf.extend_from_slice(msg);
    buf.push(0x80);
    while buf.len() % 64 != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&bit_len.to_le_bytes());

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    for block in buf.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (dst, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            if let Ok(arr) = <[u8; 4]>::try_from(chunk) {
                *dst = u32::from_le_bytes(arr);
            }
        }
        let (mut al, mut bl, mut cl, mut dl, mut el) = (h0, h1, h2, h3, h4);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h0, h1, h2, h3, h4);

        for j in 0..80usize {
            let rnd = j / 16;
            let rl = R_LEFT.get(j).copied().unwrap_or(0);
            let rr = R_RIGHT.get(j).copied().unwrap_or(0);
            let sl = S_LEFT.get(j).copied().unwrap_or(0);
            let sr = S_RIGHT.get(j).copied().unwrap_or(0);
            let kl = K_LEFT.get(rnd).copied().unwrap_or(0);
            let kr = K_RIGHT.get(rnd).copied().unwrap_or(0);
            let xl = words.get(rl).copied().unwrap_or(0);
            let xr = words.get(rr).copied().unwrap_or(0);

            let tl = al
                .wrapping_add(round_fn(j, bl, cl, dl))
                .wrapping_add(xl)
                .wrapping_add(kl)
                .rotate_left(sl)
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = tl;

            let tr = ar
                .wrapping_add(round_fn(79usize.saturating_sub(j), br, cr, dr))
                .wrapping_add(xr)
                .wrapping_add(kr)
                .rotate_left(sr)
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = tr;
        }

        let t = h1.wrapping_add(cl).wrapping_add(dr);
        h1 = h2.wrapping_add(dl).wrapping_add(er);
        h2 = h3.wrapping_add(el).wrapping_add(ar);
        h3 = h4.wrapping_add(al).wrapping_add(br);
        h4 = h0.wrapping_add(bl).wrapping_add(cr);
        h0 = t;
    }

    let mut out = [0u8; 20];
    for (dst, word) in out.chunks_exact_mut(4).zip([h0, h1, h2, h3, h4]) {
        dst.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Derive the 20-byte Cosmos raw address `RIPEMD-160(SHA-256(pubkey_33))` after
/// verifying that `pubkey_33` is a valid compressed `secp256k1` curve point.
///
/// Convenience: used by `Foreign::Cosmos` verification and Cosmos RPC account queries.
pub fn cosmos_address_from_compressed_pubkey(
    pubkey_33: &[u8],
) -> Result<[u8; 20], CosmosEnvelopeError> {
    let _ = decompress_secp256k1_pubkey(pubkey_33)?;
    let sha: [u8; 32] = Sha256::digest(pubkey_33).into();
    Ok(ripemd160(&sha))
}

/// Format a 20-byte Cosmos raw address as `bud1...` Bech32 (`Section 8.4.2`).
///
/// Convenience: canonical Cosmos/WASM address encoding on Budlum.
#[must_use]
pub fn cosmos_bech32_address(raw_20: &[u8; 20]) -> String {
    bech32_encode(COSMOS_ADDRESS_HRP, raw_20)
}

fn decompress_secp256k1_pubkey(pubkey_33: &[u8]) -> Result<AffinePoint, CosmosEnvelopeError> {
    if pubkey_33.len() != 33 {
        return Err(CosmosEnvelopeError::InvalidPublicKeyBytes);
    }
    let Some((tag_slice, x_slice)) = pubkey_33.split_at_checked(1) else {
        return Err(CosmosEnvelopeError::InvalidPublicKeyBytes);
    };
    let y_is_odd = match tag_slice.first().copied() {
        Some(0x02) => false,
        Some(0x03) => true,
        _ => return Err(CosmosEnvelopeError::InvalidPublicKeyBytes),
    };
    let x_bytes =
        FieldBytes::try_from(x_slice).map_err(|_| CosmosEnvelopeError::InvalidPublicKeyBytes)?;
    Option::<AffinePoint>::from(AffinePoint::decompress(
        &x_bytes,
        k256::elliptic_curve::subtle::Choice::from(u8::from(y_is_odd)),
    ))
    .ok_or(CosmosEnvelopeError::InvalidPublicKeyBytes)
}

/// Verify a 64-byte compact `(r || s)` low-`s` `secp256k1` ECDSA signature over
/// `SHA-256(sign_doc_bytes)` using audited `k256` curve arithmetic.
pub fn verify_cosmos_secp256k1_direct(
    pubkey_33: &[u8],
    sign_doc_bytes: &[u8],
    sig_64: &[u8],
) -> Result<(), CosmosEnvelopeError> {
    if sig_64.len() != 64 {
        return Err(CosmosEnvelopeError::InvalidSignatureLength(sig_64.len()));
    }
    let Some((r_slice, s_slice)) = sig_64.split_at_checked(32) else {
        return Err(CosmosEnvelopeError::InvalidSignatureLength(sig_64.len()));
    };
    if s_slice > SECP256K1_HALF_ORDER.as_slice() {
        return Err(CosmosEnvelopeError::SignatureHighS);
    }
    let pub_point = decompress_secp256k1_pubkey(pubkey_33)?;
    let r_fb = FieldBytes::try_from(r_slice).map_err(|_| CosmosEnvelopeError::InvalidSignature)?;
    let s_fb = FieldBytes::try_from(s_slice).map_err(|_| CosmosEnvelopeError::InvalidSignature)?;
    let r = Option::<Scalar>::from(Scalar::from_repr(r_fb))
        .ok_or(CosmosEnvelopeError::InvalidSignature)?;
    let s = Option::<Scalar>::from(Scalar::from_repr(s_fb))
        .ok_or(CosmosEnvelopeError::InvalidSignature)?;
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return Err(CosmosEnvelopeError::InvalidSignature);
    }

    let digest: [u8; 32] = Sha256::digest(sign_doc_bytes).into();
    let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(digest));
    let s_inv = Option::<Scalar>::from(s.invert()).ok_or(CosmosEnvelopeError::InvalidSignature)?;
    let u1 = e * s_inv;
    let u2 = r * s_inv;
    let r_prime = (ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(pub_point) * u2)
        .to_affine()
        .to_sec1_point(true);
    let r_prime_bytes = r_prime.as_bytes();
    let Some(rx_slice) = r_prime_bytes.get(1..33) else {
        return Err(CosmosEnvelopeError::InvalidSignature);
    };
    let rx_fb = FieldBytes::try_from(rx_slice).map_err(|_| CosmosEnvelopeError::InvalidSignature)?;
    let rx_scalar = <Scalar as Reduce<FieldBytes>>::reduce(&rx_fb);
    if rx_scalar != r {
        return Err(CosmosEnvelopeError::InvalidSignature);
    }
    Ok(())
}

fn parse_ubud_coins(coins: &[CosmosCoinProto]) -> Result<u64, CosmosEnvelopeError> {
    let mut total: u64 = 0;
    for c in coins {
        if c.denom != "ubud" {
            return Err(CosmosEnvelopeError::InvalidCoinDenom(c.denom.clone()));
        }
        let amt = c
            .amount
            .parse::<u64>()
            .map_err(|_| CosmosEnvelopeError::InvalidCoinAmount(c.amount.clone()))?;
        total = total
            .checked_add(amt)
            .ok_or_else(|| CosmosEnvelopeError::InvalidCoinAmount(c.amount.clone()))?;
    }
    Ok(total)
}

fn decode_body_message(
    any: &ProtoAny,
    expected_sender: &str,
) -> Result<CosmosWasmMsg, CosmosEnvelopeError> {
    match any.type_url.as_str() {
        "/cosmwasm.wasm.v1.MsgStoreCode" => {
            let m = MsgStoreCodeProto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.sender != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.sender,
                });
            }
            Ok(CosmosWasmMsg::StoreCode(m))
        }
        "/cosmwasm.wasm.v1.MsgInstantiateContract" => {
            let m = MsgInstantiateContractProto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.sender != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.sender,
                });
            }
            let _ = parse_ubud_coins(&m.funds)?;
            Ok(CosmosWasmMsg::InstantiateContract(m))
        }
        "/cosmwasm.wasm.v1.MsgInstantiateContract2" => {
            let m = MsgInstantiateContract2Proto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.sender != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.sender,
                });
            }
            let _ = parse_ubud_coins(&m.funds)?;
            Ok(CosmosWasmMsg::InstantiateContract2(m))
        }
        "/cosmwasm.wasm.v1.MsgExecuteContract" => {
            let m = MsgExecuteContractProto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.sender != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.sender,
                });
            }
            let _ = parse_ubud_coins(&m.funds)?;
            Ok(CosmosWasmMsg::ExecuteContract(m))
        }
        "/cosmwasm.wasm.v1.MsgMigrateContract" => {
            let m = MsgMigrateContractProto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.sender != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.sender,
                });
            }
            Ok(CosmosWasmMsg::MigrateContract(m))
        }
        "/cosmos.bank.v1beta1.MsgSend" => {
            let m = MsgSendProto::decode(any.value.as_slice())
                .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
            if m.from_address != expected_sender {
                return Err(CosmosEnvelopeError::SenderMismatch {
                    expected: expected_sender.to_string(),
                    actual: m.from_address,
                });
            }
            let amount_ubud = parse_ubud_coins(&m.amount)?;
            Ok(CosmosWasmMsg::BankSend {
                from_address: m.from_address,
                to_address: m.to_address,
                amount_ubud,
            })
        }
        other => Err(CosmosEnvelopeError::UnsupportedMessageType(
            other.to_string(),
        )),
    }
}

/// Decode a protobuf `cosmos.tx.v1beta1.TxRaw` and verify its `SIGN_MODE_DIRECT`
/// `secp256k1` signature against `(expected_chain_id, account_number)`.
///
/// Convenience: called by coordinator foreign-lane admission and CometBFT `broadcast_tx_*`.
pub fn decode_and_verify_cosmos_tx(
    raw_tx: &[u8],
    expected_chain_id: &str,
    account_number: u64,
) -> Result<DecodedCosmosTx, CosmosEnvelopeError> {
    if raw_tx.is_empty() || raw_tx.len() > MAX_COSMOS_TX_BYTES {
        return Err(CosmosEnvelopeError::EmptyOrOversized(raw_tx.len()));
    }
    let tx_hash: [u8; 32] = Sha256::digest(raw_tx).into();
    let tx_raw = TxRawProto::decode(raw_tx)
        .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
    if tx_raw.signatures.len() != 1 {
        return Err(CosmosEnvelopeError::WrongSignerCount(
            tx_raw.signatures.len(),
        ));
    }
    let auth = AuthInfoProto::decode(tx_raw.auth_info_bytes.as_slice())
        .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
    if auth.signer_infos.len() != 1 {
        return Err(CosmosEnvelopeError::WrongSignerCount(
            auth.signer_infos.len(),
        ));
    }
    let Some(signer_info) = auth.signer_infos.first() else {
        return Err(CosmosEnvelopeError::WrongSignerCount(0));
    };
    let mode = signer_info
        .mode_info
        .as_ref()
        .and_then(|m| m.single.as_ref())
        .map_or(0, |s| s.mode);
    if mode != SIGN_MODE_DIRECT {
        return Err(CosmosEnvelopeError::UnsupportedSignMode(mode));
    }

    let Some(pk_any) = signer_info.public_key.as_ref() else {
        return Err(CosmosEnvelopeError::MissingPublicKey);
    };
    if pk_any.type_url != SECP256K1_PUBKEY_TYPE_URL {
        return Err(CosmosEnvelopeError::UnsupportedPubKeyType(
            pk_any.type_url.clone(),
        ));
    }
    let pk_proto = Secp256k1PubKeyProto::decode(pk_any.value.as_slice())
        .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
    let pubkey_compressed: [u8; 33] = pk_proto
        .key
        .as_slice()
        .try_into()
        .map_err(|_| CosmosEnvelopeError::InvalidPublicKeyBytes)?;
    let sender_raw = cosmos_address_from_compressed_pubkey(&pubkey_compressed)?;
    let sender_bech32 = cosmos_bech32_address(&sender_raw);

    let sign_doc = SignDocProto {
        body_bytes: tx_raw.body_bytes.clone(),
        auth_info_bytes: tx_raw.auth_info_bytes.clone(),
        chain_id: expected_chain_id.to_string(),
        account_number,
    };
    let sign_doc_bytes = sign_doc.encode_to_vec();
    let Some(sig_bytes) = tx_raw.signatures.first() else {
        return Err(CosmosEnvelopeError::WrongSignerCount(0));
    };
    verify_cosmos_secp256k1_direct(&pubkey_compressed, &sign_doc_bytes, sig_bytes)?;

    let Some(fee) = auth.fee.as_ref() else {
        return Err(CosmosEnvelopeError::MissingFee);
    };
    if fee.gas_limit == 0 {
        return Err(CosmosEnvelopeError::ZeroGasLimit);
    }
    let fee_ubud = parse_ubud_coins(&fee.amount)?;

    let body = TxBodyProto::decode(tx_raw.body_bytes.as_slice())
        .map_err(|e| CosmosEnvelopeError::ProtobufDecode(e.to_string()))?;
    if body.messages.is_empty() {
        return Err(CosmosEnvelopeError::EmptyMessages);
    }
    let mut messages = Vec::with_capacity(body.messages.len());
    for any in &body.messages {
        messages.push(decode_body_message(any, &sender_bech32)?);
    }

    Ok(DecodedCosmosTx {
        tx_hash,
        sender_raw,
        sender_bech32,
        pubkey_compressed,
        account_number,
        sequence: signer_info.sequence,
        gas_limit: fee.gas_limit,
        fee_ubud,
        memo: body.memo,
        timeout_height: body.timeout_height,
        messages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test-only `secp256k1` `SIGN_MODE_DIRECT` signer built on `k256`
    /// scalar/point arithmetic (deterministic nonce `k`).
    fn test_sign_cosmos_direct(
        priv_scalar_bytes: &[u8; 32],
        sign_doc_bytes: &[u8],
    ) -> ([u8; 33], [u8; 64]) {
        let d = Scalar::from_repr((*priv_scalar_bytes).into()).unwrap();
        let pub_pt = (ProjectivePoint::GENERATOR * d).to_affine().to_sec1_point(true);
        let pub33: [u8; 33] = pub_pt.as_bytes().try_into().unwrap();

        let digest: [u8; 32] = Sha256::digest(sign_doc_bytes).into();
        let e = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(digest));
        let mut nonce_h = Sha256::new();
        nonce_h.update(b"TEST_COSMOS_NONCE");
        nonce_h.update(priv_scalar_bytes);
        nonce_h.update(digest);
        let k_digest: [u8; 32] = nonce_h.finalize().into();
        let k = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(k_digest));
        let big_r = (ProjectivePoint::GENERATOR * k).to_affine().to_sec1_point(true);
        let rx_fb = FieldBytes::try_from(&big_r.as_bytes()[1..33]).unwrap();
        let r = <Scalar as Reduce<FieldBytes>>::reduce(&rx_fb);
        let k_inv = k.invert().unwrap();
        let mut s = k_inv * (e + r * d);
        let s_bytes: [u8; 32] = s.to_bytes().into();
        if s_bytes > SECP256K1_HALF_ORDER {
            s = -s;
        }
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r.to_bytes().as_slice());
        sig[32..].copy_from_slice(s.to_bytes().as_slice());
        (pub33, sig)
    }

    #[test]
    fn ripemd160_matches_iso_10118_3_vectors() {
        assert_eq!(
            hex::encode(ripemd160(b"")),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex::encode(ripemd160(b"abc")),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
        assert_eq!(
            hex::encode(ripemd160(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
        );
    }

    #[test]
    fn cosmos_tx_raw_verifies_direct_sig_and_refuses_staking_and_wrong_chain() {
        let sk = [0x33u8; 32];
        let d = Scalar::from_repr(sk.into()).unwrap();
        let pub_pt = (ProjectivePoint::GENERATOR * d).to_affine().to_sec1_point(true);
        let pub33: [u8; 33] = pub_pt.as_bytes().try_into().unwrap();
        let raw20 = cosmos_address_from_compressed_pubkey(&pub33).unwrap();
        let sender = cosmos_bech32_address(&raw20);
        assert!(sender.starts_with("bud1"));

        let send_msg = MsgSendProto {
            from_address: sender.clone(),
            to_address: cosmos_bech32_address(&[0x77; 20]),
            amount: vec![CosmosCoinProto {
                denom: "ubud".to_string(),
                amount: "500".to_string(),
            }],
        };
        let body = TxBodyProto {
            messages: vec![ProtoAny {
                type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                value: send_msg.encode_to_vec(),
            }],
            memo: "wp29".to_string(),
            timeout_height: 0,
        };
        let body_bytes = body.encode_to_vec();
        let pk_proto = Secp256k1PubKeyProto {
            key: pub33.to_vec(),
        };
        let auth = AuthInfoProto {
            signer_infos: vec![SignerInfoProto {
                public_key: Some(ProtoAny {
                    type_url: SECP256K1_PUBKEY_TYPE_URL.to_string(),
                    value: pk_proto.encode_to_vec(),
                }),
                mode_info: Some(ModeInfoProto {
                    single: Some(ModeInfoSingleProto {
                        mode: SIGN_MODE_DIRECT,
                    }),
                }),
                sequence: 0,
            }],
            fee: Some(CosmosFeeProto {
                amount: vec![CosmosCoinProto {
                    denom: "ubud".to_string(),
                    amount: "25".to_string(),
                }],
                gas_limit: 200_000,
                payer: String::new(),
                granter: String::new(),
            }),
        };
        let auth_info_bytes = auth.encode_to_vec();
        let sign_doc = SignDocProto {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_info_bytes.clone(),
            chain_id: BUDLUM_COSMOS_CHAIN_ID.to_string(),
            account_number: 7,
        };
        let (_, sig) = test_sign_cosmos_direct(&sk, &sign_doc.encode_to_vec());
        let raw = TxRawProto {
            body_bytes,
            auth_info_bytes: auth_info_bytes.clone(),
            signatures: vec![sig.to_vec()],
        }
        .encode_to_vec();

        let decoded = decode_and_verify_cosmos_tx(&raw, BUDLUM_COSMOS_CHAIN_ID, 7).unwrap();
        assert_eq!(decoded.sender_bech32, sender);
        assert_eq!(decoded.sequence, 0);
        assert_eq!(decoded.fee_ubud, 25);

        // Wrong chain_id or account_number must fail signature verification.
        assert_eq!(
            decode_and_verify_cosmos_tx(&raw, "cosmoshub-4", 7),
            Err(CosmosEnvelopeError::InvalidSignature)
        );
        assert_eq!(
            decode_and_verify_cosmos_tx(&raw, BUDLUM_COSMOS_CHAIN_ID, 8),
            Err(CosmosEnvelopeError::InvalidSignature)
        );

        // Staking/Gov/IBC message types must be refused.
        let bad_body = TxBodyProto {
            messages: vec![ProtoAny {
                type_url: "/cosmos.staking.v1beta1.MsgDelegate".to_string(),
                value: vec![1, 2, 3],
            }],
            memo: String::new(),
            timeout_height: 0,
        }
        .encode_to_vec();
        let bad_doc = SignDocProto {
            body_bytes: bad_body.clone(),
            auth_info_bytes: auth_info_bytes.clone(),
            chain_id: BUDLUM_COSMOS_CHAIN_ID.to_string(),
            account_number: 7,
        };
        let (_, bad_sig) = test_sign_cosmos_direct(&sk, &bad_doc.encode_to_vec());
        let bad_raw = TxRawProto {
            body_bytes: bad_body,
            auth_info_bytes,
            signatures: vec![bad_sig.to_vec()],
        }
        .encode_to_vec();
        assert!(matches!(
            decode_and_verify_cosmos_tx(&bad_raw, BUDLUM_COSMOS_CHAIN_ID, 7),
            Err(CosmosEnvelopeError::UnsupportedMessageType(_))
        ));
    }
}
