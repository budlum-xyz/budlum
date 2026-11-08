//! Cosmos (`cosmos.tx.v1beta1.TxRaw`) foreign envelope decoding and verification.
//!
//! Implements section 8.6.2 (`Foreign::Cosmos`) and  item 4:
//! - Protobuf `TxRaw`, `TxBody`, `AuthInfo`, `SignDoc` (`SIGN_MODE_DIRECT` = 1).
//! - Chain ID `budlum-testnet-1`, `account_number`, and `sequence` replay checks.
//! - Secp256k1 ECDSA verification (`k256`, EIP-2 low-`s`) and canonical 20-byte
//!   Cosmos address derivation `RIPEMD160(SHA256(compressed_pubkey_33))`.

use crate::execution::coordinator::alias::derive_foreign_cosmos_bech32;
use k256::ecdsa::{Signature, VerifyingKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical Cosmos Compatibility Lane chain ID (section 8.6.2).
pub const BUDLUM_COSMOS_CHAIN_ID: &str = "budlum-testnet-1";

/// Protobuf `SIGN_MODE_DIRECT` enum constant (`cosmos.tx.signing.v1beta1.SignMode`).
pub const SIGN_MODE_DIRECT: i32 = 1;

/// Cosmos `google.protobuf.Any` message wrapper.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoAny {
    #[prost(string, tag = "1")]
    pub type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// Cosmos `cosmos.base.v1beta1.Coin`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoCoin {
    #[prost(string, tag = "1")]
    pub denom: String,
    #[prost(string, tag = "2")]
    pub amount: String,
}

/// Cosmos `cosmos.tx.v1beta1.TxBody`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoTxBody {
    #[prost(message, repeated, tag = "1")]
    pub messages: Vec<ProtoAny>,
    #[prost(string, tag = "2")]
    pub memo: String,
    #[prost(uint64, tag = "3")]
    pub timeout_height: u64,
}

/// Cosmos `cosmos.tx.v1beta1.ModeInfo.Single`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoModeSingle {
    #[prost(int32, tag = "1")]
    pub mode: i32,
}

/// Cosmos `cosmos.tx.v1beta1.ModeInfo`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoModeInfo {
    #[prost(message, optional, tag = "1")]
    pub single: Option<ProtoModeSingle>,
}

/// Cosmos `cosmos.crypto.secp256k1.PubKey`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoSecp256k1PubKey {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
}

/// Cosmos `cosmos.tx.v1beta1.SignerInfo`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoSignerInfo {
    #[prost(message, optional, tag = "1")]
    pub public_key: Option<ProtoAny>,
    #[prost(message, optional, tag = "2")]
    pub mode_info: Option<ProtoModeInfo>,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
}

/// Cosmos `cosmos.tx.v1beta1.Fee`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoFee {
    #[prost(message, repeated, tag = "1")]
    pub amount: Vec<ProtoCoin>,
    #[prost(uint64, tag = "2")]
    pub gas_limit: u64,
}

/// Cosmos `cosmos.tx.v1beta1.AuthInfo`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoAuthInfo {
    #[prost(message, repeated, tag = "1")]
    pub signer_infos: Vec<ProtoSignerInfo>,
    #[prost(message, optional, tag = "2")]
    pub fee: Option<ProtoFee>,
}

/// Cosmos `cosmos.tx.v1beta1.TxRaw`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoTxRaw {
    #[prost(bytes = "vec", tag = "1")]
    pub body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_info_bytes: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub signatures: Vec<Vec<u8>>,
}

/// Cosmos `cosmos.tx.v1beta1.SignDoc`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoSignDoc {
    #[prost(bytes = "vec", tag = "1")]
    pub body_bytes: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub auth_info_bytes: Vec<u8>,
    #[prost(string, tag = "3")]
    pub chain_id: String,
    #[prost(uint64, tag = "4")]
    pub account_number: u64,
}

/// Permitted Cosmos message type URLs on the UEL WASM Compatibility Lane (8.6.1).
pub const ALLOWED_COSMOS_MSG_TYPES: &[&str] = &[
    "/cosmwasm.wasm.v1.MsgStoreCode",
    "/cosmwasm.wasm.v1.MsgInstantiateContract",
    "/cosmwasm.wasm.v1.MsgInstantiateContract2",
    "/cosmwasm.wasm.v1.MsgExecuteContract",
    "/cosmwasm.wasm.v1.MsgMigrateContract",
    "/cosmos.bank.v1beta1.MsgSend",
];

/// Decoded and verified Cosmos `TxRaw` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedCosmosTx {
    pub tx_hash: [u8; 32],
    pub sender_addr20: [u8; 20],
    pub sender_bech32: String,
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    pub gas_limit: u64,
    pub fee_ubud: u128,
    pub message_types: Vec<String>,
    pub message_payloads: Vec<Vec<u8>>,
}

/// Why a Cosmos `TxRaw` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmosEnvelopeError {
    MalformedProto(String),
    WrongChainId { expected: String, got: String },
    UnsupportedSignMode(i32),
    UnsupportedPubKeyType(String),
    DisallowedMessageType(String),
    EmptyMessages,
    InvalidSignature(String),
    InvalidFee(String),
}

impl std::fmt::Display for CosmosEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedProto(m) => write!(f, "malformed Cosmos protobuf: {m}"),
            Self::WrongChainId { expected, got } => {
                write!(f, "wrong Cosmos chain_id: expected {expected}, got {got}")
            }
            Self::UnsupportedSignMode(m) => write!(f, "unsupported Cosmos SignMode {m}"),
            Self::UnsupportedPubKeyType(t) => write!(f, "unsupported Cosmos pubkey type {t}"),
            Self::DisallowedMessageType(t) => write!(f, "disallowed Cosmos message type {t}"),
            Self::EmptyMessages => write!(f, "Cosmos TxBody carries no messages"),
            Self::InvalidSignature(m) => write!(f, "invalid Cosmos secp256k1 signature: {m}"),
            Self::InvalidFee(m) => write!(f, "invalid Cosmos fee: {m}"),
        }
    }
}

/// Pure-Rust ISO/IEC 10118-3 RIPEMD-160 digest used solely for canonical
/// 20-byte Cosmos address derivation `RIPEMD160(SHA256(compressed_pubkey))`.
#[must_use]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    const RL: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0,
        9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10,
        0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15,
        13,
    ];
    const RR: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15,
        8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3,
        11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9,
        11,
    ];
    const SL: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12,
        15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14,
        15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14,
        11, 8, 5, 6,
    ];
    const SR: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7,
        12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8,
        11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15,
        13, 11, 11,
    ];

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (data.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xefcd_ab89;
    let mut h2: u32 = 0x98ba_dcfe;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xc3d2_e1f0;

    for chunk in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (word_slot, word_bytes) in x.iter_mut().zip(chunk.chunks_exact(4)) {
            if let Ok(arr) = <[u8; 4]>::try_from(word_bytes) {
                *word_slot = u32::from_le_bytes(arr);
            }
        }
        let (mut al, mut bl, mut cl, mut dl, mut el) = (h0, h1, h2, h3, h4);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h0, h1, h2, h3, h4);

        for j in 0..80 {
            let (fl, kl) = match j {
                0..=15 => (bl ^ cl ^ dl, 0x0000_0000),
                16..=31 => ((bl & cl) | (!bl & dl), 0x5a82_7999),
                32..=47 => ((bl | !cl) ^ dl, 0x6ed9_eba1),
                48..=63 => ((bl & dl) | (cl & !dl), 0x8f1b_bcdc),
                _ => (bl ^ (cl | !dl), 0xa953_fd4e),
            };
            let rl_idx = RL.get(j).copied().unwrap_or(0);
            let sl_rot = SL.get(j).copied().unwrap_or(0);
            let xl = x.get(rl_idx).copied().unwrap_or(0);
            let tl = al
                .wrapping_add(fl)
                .wrapping_add(xl)
                .wrapping_add(kl)
                .rotate_left(sl_rot)
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = tl;

            let (fr, kr) = match j {
                0..=15 => (br ^ (cr | !dr), 0x50a2_8be6),
                16..=31 => ((br & dr) | (cr & !dr), 0x5c4d_d124),
                32..=47 => ((br | !cr) ^ dr, 0x6d70_3ef3),
                48..=63 => ((br & cr) | (!br & dr), 0x7a6d_76e9),
                _ => (br ^ cr ^ dr, 0x0000_0000),
            };
            let rr_idx = RR.get(j).copied().unwrap_or(0);
            let sr_rot = SR.get(j).copied().unwrap_or(0);
            let xr = x.get(rr_idx).copied().unwrap_or(0);
            let tr = ar
                .wrapping_add(fr)
                .wrapping_add(xr)
                .wrapping_add(kr)
                .rotate_left(sr_rot)
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
    for (idx, word) in [h0, h1, h2, h3, h4].into_iter().enumerate() {
        let start = idx * 4;
        if let Some(dst) = out.get_mut(start..start + 4) {
            dst.copy_from_slice(&word.to_le_bytes());
        }
    }
    out
}

/// Derives the 20-byte Cosmos account address from a 33-byte compressed secp256k1 key.
#[must_use]
pub fn cosmos_addr20_from_compressed_pubkey(pubkey33: &[u8; 33]) -> [u8; 20] {
    let sha: [u8; 32] = Sha256::digest(pubkey33).into();
    ripemd160(&sha)
}

/// Decodes and verifies a `cosmos.tx.v1beta1.TxRaw` envelope.
pub fn decode_cosmos_tx(
    tx_raw_bytes: &[u8],
    chain_id: &str,
    account_number: u64,
    expected_chain_id: &str,
) -> Result<DecodedCosmosTx, CosmosEnvelopeError> {
    if chain_id != expected_chain_id {
        return Err(CosmosEnvelopeError::WrongChainId {
            expected: expected_chain_id.to_string(),
            got: chain_id.to_string(),
        });
    }
    let tx_hash: [u8; 32] = Sha256::digest(tx_raw_bytes).into();
    let tx_raw = ProtoTxRaw::decode(tx_raw_bytes)
        .map_err(|e| CosmosEnvelopeError::MalformedProto(e.to_string()))?;
    if tx_raw.signatures.len() != 1 {
        return Err(CosmosEnvelopeError::MalformedProto(String::from(
            "Cosmos TxRaw must carry exactly one signature",
        )));
    }
    let body = ProtoTxBody::decode(tx_raw.body_bytes.as_slice())
        .map_err(|e| CosmosEnvelopeError::MalformedProto(e.to_string()))?;
    if body.messages.is_empty() {
        return Err(CosmosEnvelopeError::EmptyMessages);
    }
    let mut message_types = Vec::with_capacity(body.messages.len());
    let mut message_payloads = Vec::with_capacity(body.messages.len());
    for msg in &body.messages {
        if !ALLOWED_COSMOS_MSG_TYPES.contains(&msg.type_url.as_str()) {
            return Err(CosmosEnvelopeError::DisallowedMessageType(
                msg.type_url.clone(),
            ));
        }
        message_types.push(msg.type_url.clone());
        message_payloads.push(msg.value.clone());
    }

    let auth = ProtoAuthInfo::decode(tx_raw.auth_info_bytes.as_slice())
        .map_err(|e| CosmosEnvelopeError::MalformedProto(e.to_string()))?;
    if auth.signer_infos.len() != 1 {
        return Err(CosmosEnvelopeError::MalformedProto(String::from(
            "Cosmos AuthInfo must carry exactly one SignerInfo",
        )));
    }
    let signer_info = auth
        .signer_infos
        .first()
        .ok_or_else(|| CosmosEnvelopeError::MalformedProto(String::from("missing SignerInfo")))?;
    let mode = signer_info
        .mode_info
        .as_ref()
        .and_then(|m| m.single.as_ref())
        .map(|s| s.mode)
        .unwrap_or(0);
    if mode != SIGN_MODE_DIRECT {
        return Err(CosmosEnvelopeError::UnsupportedSignMode(mode));
    }

    let pk_any = signer_info
        .public_key
        .as_ref()
        .ok_or_else(|| CosmosEnvelopeError::MalformedProto(String::from("missing public_key")))?;
    if pk_any.type_url != "/cosmos.crypto.secp256k1.PubKey" {
        return Err(CosmosEnvelopeError::UnsupportedPubKeyType(
            pk_any.type_url.clone(),
        ));
    }
    let pk_msg = ProtoSecp256k1PubKey::decode(pk_any.value.as_slice())
        .map_err(|e| CosmosEnvelopeError::MalformedProto(e.to_string()))?;
    let pk33: [u8; 33] = pk_msg.key.as_slice().try_into().map_err(|_| {
        CosmosEnvelopeError::InvalidSignature(String::from(
            "compressed secp256k1 pubkey must be 33 bytes",
        ))
    })?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pk33)
        .map_err(|e| CosmosEnvelopeError::InvalidSignature(e.to_string()))?;

    let sig_bytes = tx_raw
        .signatures
        .first()
        .ok_or_else(|| CosmosEnvelopeError::InvalidSignature(String::from("missing sig")))?;
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| CosmosEnvelopeError::InvalidSignature(e.to_string()))?;
    if sig.normalize_s().is_some() {
        return Err(CosmosEnvelopeError::InvalidSignature(String::from(
            "high-s secp256k1 signature refused",
        )));
    }

    let sign_doc = ProtoSignDoc {
        body_bytes: tx_raw.body_bytes.clone(),
        auth_info_bytes: tx_raw.auth_info_bytes.clone(),
        chain_id: chain_id.to_string(),
        account_number,
    };
    let sign_doc_bytes = sign_doc.encode_to_vec();
    use k256::ecdsa::signature::Verifier as _;
    verifying_key
        .verify(&sign_doc_bytes, &sig)
        .map_err(|e| CosmosEnvelopeError::InvalidSignature(e.to_string()))?;

    let fee = auth
        .fee
        .as_ref()
        .ok_or_else(|| CosmosEnvelopeError::InvalidFee(String::from("missing Fee")))?;
    let mut fee_ubud = 0u128;
    for coin in &fee.amount {
        if coin.denom != "ubud" {
            return Err(CosmosEnvelopeError::InvalidFee(format!(
                "unsupported fee denom `{}`",
                coin.denom
            )));
        }
        let parsed: u128 = coin
            .amount
            .parse()
            .map_err(|_| CosmosEnvelopeError::InvalidFee(String::from("bad fee amount")))?;
        fee_ubud = fee_ubud.saturating_add(parsed);
    }

    let sender_addr20 = cosmos_addr20_from_compressed_pubkey(&pk33);
    let sender_bech32 = derive_foreign_cosmos_bech32(&sender_addr20);

    Ok(DecodedCosmosTx {
        tx_hash,
        sender_addr20,
        sender_bech32,
        chain_id: chain_id.to_string(),
        account_number,
        sequence: signer_info.sequence,
        gas_limit: fee.gas_limit,
        fee_ubud,
        message_types,
        message_payloads,
    })
}

/// Builds and signs a canonical `SIGN_MODE_DIRECT` Cosmos `TxRaw` envelope.
pub fn sign_cosmos_tx_direct(
    secret_key: &[u8; 32],
    chain_id: &str,
    account_number: u64,
    sequence: u64,
    gas_limit: u64,
    fee_ubud: u128,
    messages: Vec<(String, Vec<u8>)>,
) -> Result<Vec<u8>, String> {
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::{Signature as K256Sig, SigningKey};

    let signing_key =
        SigningKey::from_bytes(secret_key.into()).map_err(|e| format!("bad secp256k1 key: {e}"))?;
    let compressed = signing_key.verifying_key().to_encoded_point(true);
    let pk_msg = ProtoSecp256k1PubKey {
        key: compressed.as_bytes().to_vec(),
    };
    let body = ProtoTxBody {
        messages: messages
            .into_iter()
            .map(|(type_url, value)| ProtoAny { type_url, value })
            .collect(),
        memo: String::new(),
        timeout_height: 0,
    };
    let auth = ProtoAuthInfo {
        signer_infos: vec![ProtoSignerInfo {
            public_key: Some(ProtoAny {
                type_url: String::from("/cosmos.crypto.secp256k1.PubKey"),
                value: pk_msg.encode_to_vec(),
            }),
            mode_info: Some(ProtoModeInfo {
                single: Some(ProtoModeSingle {
                    mode: SIGN_MODE_DIRECT,
                }),
            }),
            sequence,
        }],
        fee: Some(ProtoFee {
            amount: vec![ProtoCoin {
                denom: String::from("ubud"),
                amount: fee_ubud.to_string(),
            }],
            gas_limit,
        }),
    };
    let body_bytes = body.encode_to_vec();
    let auth_info_bytes = auth.encode_to_vec();
    let sign_doc = ProtoSignDoc {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: auth_info_bytes.clone(),
        chain_id: chain_id.to_string(),
        account_number,
    };
    let raw_sig: K256Sig = signing_key.sign(&sign_doc.encode_to_vec());
    let low_s = raw_sig.normalize_s().unwrap_or(raw_sig);
    let tx_raw = ProtoTxRaw {
        body_bytes,
        auth_info_bytes,
        signatures: vec![low_s.to_bytes().to_vec()],
    };
    Ok(tx_raw.encode_to_vec())
}
