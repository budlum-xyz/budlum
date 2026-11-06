//! Aptos (`SignedTransaction` BCS) foreign envelope decoding and verification.
//!
//! Implements section 8.6.2 (`Foreign::Aptos`) and WP-32 items 2 & 4:
//! - Chain ID `205` (`45261 mod 256`), `sequence_number`, and `expiration_timestamp_secs`.
//! - Authenticators: `Ed25519` (`0`), `MultiEd25519` (`1`), and `SingleSender`
//!   secp256k1 (`2`). OIDC keyless accounts are refused at launch (section 8.15).
//! - Pins the Aptos authentication-key scheme table and proves `0xBD`
//!   (`MOVE_ALIAS_SCHEME_BYTE`) is unused.

use crate::execution::coordinator::alias::MOVE_ALIAS_SCHEME_BYTE;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use k256::ecdsa::{Signature as SecpSig, VerifyingKey as SecpVerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Canonical Budlum Aptos Compatibility Lane chain ID (`45261 % 256 = 205`).
pub const BUDLUM_APTOS_CHAIN_ID: u8 = 205;

/// Pinned Aptos authentication-key scheme bytes in `aptos-types` (`Scheme` enum).
///
/// - `0x00`: `Ed25519`
/// - `0x01`: `MultiEd25519`
/// - `0x02`: `SingleKey` (`AnyPublicKey`: Ed25519 / Secp256k1 / Secp256r1 / Keyless)
/// - `0x03`: `MultiKey`
/// - `0xFC`: `DeriveObjectAddressFromGuid`
/// - `0xFD`: `DeriveObjectAddressFromSeed`
/// - `0xFE`: `DeriveResourceAccountAddress`
///
/// `0xBD` (`MOVE_ALIAS_SCHEME_BYTE`) is outside this table so no Aptos account
/// authentication key can collide with a native Budlum Move alias.
pub const PINNED_APTOS_SCHEME_BYTES: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE];

/// Returns `true` if `scheme` is used by the pinned Aptos authentication-key table.
#[must_use]
pub fn is_aptos_auth_scheme_byte(scheme: u8) -> bool {
    PINNED_APTOS_SCHEME_BYTES.contains(&scheme)
}

/// Asserts at runtime/test time that `MOVE_ALIAS_SCHEME_BYTE` (`0xBD`) is unused.
#[must_use]
pub fn move_alias_scheme_is_disjoint() -> bool {
    !is_aptos_auth_scheme_byte(MOVE_ALIAS_SCHEME_BYTE)
}

/// Supported Aptos transaction payload variants (section 8.6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AptosPayloadKind {
    Script(Vec<u8>),
    ModuleBundle(Vec<u8>),
    EntryFunction {
        module_address: [u8; 32],
        module_name: String,
        function_name: String,
        args_bcs: Vec<u8>,
    },
}

/// Decoded and verified Aptos `SignedTransaction`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedAptosTx {
    pub tx_hash: [u8; 32],
    pub sender: [u8; 32],
    pub sequence_number: u64,
    pub payload: AptosPayloadKind,
    pub max_gas_amount: u64,
    pub gas_unit_price: u64,
    pub expiration_timestamp_secs: u64,
    pub chain_id: u8,
}

/// Why an Aptos `SignedTransaction` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AptosEnvelopeError {
    MalformedBcs(String),
    WrongChainId { expected: u8, got: u8 },
    Expired { now_secs: u64, expiration_secs: u64 },
    UnsupportedAuthenticator(u32),
    KeylessOidcUnsupported,
    SenderAuthKeyMismatch,
    InvalidSignature(String),
}

impl std::fmt::Display for AptosEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedBcs(m) => write!(f, "malformed Aptos BCS: {m}"),
            Self::WrongChainId { expected, got } => {
                write!(f, "wrong Aptos chain_id: expected {expected}, got {got}")
            }
            Self::Expired {
                now_secs,
                expiration_secs,
            } => write!(
                f,
                "Aptos tx expired at {expiration_secs}s (block timestamp {now_secs}s)"
            ),
            Self::UnsupportedAuthenticator(v) => {
                write!(f, "unsupported Aptos authenticator variant {v}")
            }
            Self::KeylessOidcUnsupported => {
                write!(f, "Aptos OIDC keyless accounts are refused at launch")
            }
            Self::SenderAuthKeyMismatch => {
                write!(f, "Aptos authenticator key does not derive sender address")
            }
            Self::InvalidSignature(m) => write!(f, "invalid Aptos signature: {m}"),
        }
    }
}

fn read_uleb128_u32(buf: &[u8], cur: &mut usize) -> Result<u32, AptosEnvelopeError> {
    let mut val = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let b = *buf
            .get(*cur)
            .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("unexpected EOF")))?;
        *cur += 1;
        val |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            if shift > 0 && b == 0 {
                return Err(AptosEnvelopeError::MalformedBcs(String::from(
                    "non-canonical ULEB128",
                )));
            }
            return Ok(val);
        }
        shift += 7;
    }
    Err(AptosEnvelopeError::MalformedBcs(String::from(
        "ULEB128 overflow",
    )))
}

pub(crate) fn write_uleb128_u32(mut val: u32, out: &mut Vec<u8>) {
    loop {
        let mut b = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(b);
            break;
        }
        b |= 0x80;
        out.push(b);
    }
}

fn read_bcs_bytes(buf: &[u8], cur: &mut usize) -> Result<Vec<u8>, AptosEnvelopeError> {
    let len = read_uleb128_u32(buf, cur)? as usize;
    let slice = buf
        .get(*cur..*cur + len)
        .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("truncated BCS bytes")))?;
    *cur += len;
    Ok(slice.to_vec())
}

fn read_u64_le(buf: &[u8], cur: &mut usize) -> Result<u64, AptosEnvelopeError> {
    let slice = buf
        .get(*cur..*cur + 8)
        .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("truncated u64")))?;
    *cur += 8;
    let arr: [u8; 8] = slice
        .try_into()
        .map_err(|_| AptosEnvelopeError::MalformedBcs(String::from("bad u64")))?;
    Ok(u64::from_le_bytes(arr))
}

fn aptos_signing_message(raw_tx_bytes: &[u8]) -> Vec<u8> {
    let prefix: [u8; 32] = Sha3_256::digest(b"APTOS::RawTransaction").into();
    let mut out = Vec::with_capacity(32 + raw_tx_bytes.len());
    out.extend_from_slice(&prefix);
    out.extend_from_slice(raw_tx_bytes);
    out
}

/// Derives an Aptos Ed25519 single-signer account address `SHA3-256(pk32 || 0x00)`.
#[must_use]
pub fn aptos_ed25519_address(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(pubkey);
    h.update([0x00]);
    h.finalize().into()
}

/// Derives an Aptos SingleKey secp256k1 account address `SHA3-256(0x01 || pk65 || 0x02)`.
#[must_use]
pub fn aptos_singlekey_secp256k1_address(uncompressed_pk65: &[u8; 65]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update([0x01]);
    h.update(uncompressed_pk65);
    h.update([0x02]);
    h.finalize().into()
}

/// Decodes and verifies a BCS-encoded Aptos `SignedTransaction`.
pub fn decode_aptos_tx(
    bcs_bytes: &[u8],
    expected_chain_id: u8,
    now_timestamp_secs: u64,
) -> Result<DecodedAptosTx, AptosEnvelopeError> {
    let mut cur = 0usize;
    let sender_slice = bcs_bytes
        .get(cur..cur + 32)
        .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("missing sender")))?;
    let sender: [u8; 32] = sender_slice
        .try_into()
        .map_err(|_| AptosEnvelopeError::MalformedBcs(String::from("bad sender")))?;
    cur += 32;
    let sequence_number = read_u64_le(bcs_bytes, &mut cur)?;

    let payload_tag = read_uleb128_u32(bcs_bytes, &mut cur)?;
    let payload = match payload_tag {
        0 => AptosPayloadKind::Script(read_bcs_bytes(bcs_bytes, &mut cur)?),
        1 => AptosPayloadKind::ModuleBundle(read_bcs_bytes(bcs_bytes, &mut cur)?),
        2 => {
            let mod_addr_s = bcs_bytes.get(cur..cur + 32).ok_or_else(|| {
                AptosEnvelopeError::MalformedBcs(String::from("missing module address"))
            })?;
            let module_address: [u8; 32] = mod_addr_s
                .try_into()
                .map_err(|_| AptosEnvelopeError::MalformedBcs(String::from("bad module addr")))?;
            cur += 32;
            let mod_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let module_name = String::from_utf8(mod_bytes)
                .map_err(|_| AptosEnvelopeError::MalformedBcs(String::from("bad module utf8")))?;
            let fn_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let function_name = String::from_utf8(fn_bytes)
                .map_err(|_| AptosEnvelopeError::MalformedBcs(String::from("bad fn utf8")))?;
            let args_bcs = read_bcs_bytes(bcs_bytes, &mut cur)?;
            AptosPayloadKind::EntryFunction {
                module_address,
                module_name,
                function_name,
                args_bcs,
            }
        }
        other => {
            return Err(AptosEnvelopeError::MalformedBcs(format!(
                "unsupported TransactionPayload variant {other}"
            )));
        }
    };

    let max_gas_amount = read_u64_le(bcs_bytes, &mut cur)?;
    let gas_unit_price = read_u64_le(bcs_bytes, &mut cur)?;
    let expiration_timestamp_secs = read_u64_le(bcs_bytes, &mut cur)?;
    let chain_id = *bcs_bytes
        .get(cur)
        .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("missing chain_id")))?;
    cur += 1;

    if chain_id != expected_chain_id {
        return Err(AptosEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            got: chain_id,
        });
    }
    if now_timestamp_secs > expiration_timestamp_secs {
        return Err(AptosEnvelopeError::Expired {
            now_secs: now_timestamp_secs,
            expiration_secs: expiration_timestamp_secs,
        });
    }

    let raw_tx_bytes = bcs_bytes
        .get(..cur)
        .ok_or_else(|| AptosEnvelopeError::MalformedBcs(String::from("bad raw_tx slice")))?;
    let signing_msg = aptos_signing_message(raw_tx_bytes);

    let auth_variant = read_uleb128_u32(bcs_bytes, &mut cur)?;
    match auth_variant {
        0 => {
            let pk_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let sig_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let pk32: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
                AptosEnvelopeError::InvalidSignature(String::from("Ed25519 pubkey != 32 bytes"))
            })?;
            if aptos_ed25519_address(&pk32) != sender {
                return Err(AptosEnvelopeError::SenderAuthKeyMismatch);
            }
            let sig64: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                AptosEnvelopeError::InvalidSignature(String::from("Ed25519 sig != 64 bytes"))
            })?;
            let vk = VerifyingKey::from_bytes(&pk32)
                .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
            let sig = Signature::from_bytes(&sig64);
            vk.verify(&signing_msg, &sig)
                .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
        }
        1 => {
            let pks_concat = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let sigs_concat = read_bcs_bytes(bcs_bytes, &mut cur)?;
            if pks_concat.len() < 33 || !(pks_concat.len() - 1).is_multiple_of(32) {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "malformed MultiEd25519 public key bundle",
                )));
            }
            let threshold = *pks_concat.last().unwrap_or(&0) as usize;
            let n_keys = (pks_concat.len() - 1) / 32;
            if threshold == 0 || threshold > n_keys || threshold > 32 {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "invalid MultiEd25519 threshold",
                )));
            }
            let mut auth_h = Sha3_256::new();
            auth_h.update(&pks_concat);
            auth_h.update([0x01]);
            let derived: [u8; 32] = auth_h.finalize().into();
            if derived != sender {
                return Err(AptosEnvelopeError::SenderAuthKeyMismatch);
            }
            if sigs_concat.len() < 4 || !(sigs_concat.len() - 4).is_multiple_of(64) {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "malformed MultiEd25519 signature bundle",
                )));
            }
            let sig_count = (sigs_concat.len() - 4) / 64;
            if sig_count < threshold {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "MultiEd25519 below threshold",
                )));
            }
            let bitmap_slice = sigs_concat.get(sigs_concat.len() - 4..).unwrap_or(&[]);
            let bitmap_arr: [u8; 4] = bitmap_slice
                .try_into()
                .map_err(|_| AptosEnvelopeError::InvalidSignature(String::from("bad bitmap")))?;
            let bitmap = u32::from_be_bytes(bitmap_arr);
            let mut sig_idx = 0usize;
            for bit in 0..n_keys {
                if (bitmap & (1u32 << (31 - bit))) == 0 {
                    continue;
                }
                let pk_s = pks_concat
                    .get(bit * 32..(bit + 1) * 32)
                    .ok_or_else(|| AptosEnvelopeError::InvalidSignature(String::from("pk idx")))?;
                let sig_s = sigs_concat
                    .get(sig_idx * 64..(sig_idx + 1) * 64)
                    .ok_or_else(|| AptosEnvelopeError::InvalidSignature(String::from("sig idx")))?;
                sig_idx += 1;
                let pk32: [u8; 32] = pk_s
                    .try_into()
                    .map_err(|_| AptosEnvelopeError::InvalidSignature(String::from("pk len")))?;
                let sig64: [u8; 64] = sig_s
                    .try_into()
                    .map_err(|_| AptosEnvelopeError::InvalidSignature(String::from("sig len")))?;
                let vk = VerifyingKey::from_bytes(&pk32)
                    .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
                vk.verify(&signing_msg, &Signature::from_bytes(&sig64))
                    .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
            }
            if sig_idx != sig_count {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "MultiEd25519 bitmap count mismatch",
                )));
            }
        }
        2 => {
            let key_variant = read_uleb128_u32(bcs_bytes, &mut cur)?;
            if key_variant == 3 || key_variant == 4 {
                return Err(AptosEnvelopeError::KeylessOidcUnsupported);
            }
            if key_variant != 1 {
                return Err(AptosEnvelopeError::UnsupportedAuthenticator(key_variant));
            }
            let pk_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let sig_variant = read_uleb128_u32(bcs_bytes, &mut cur)?;
            if sig_variant != 1 {
                return Err(AptosEnvelopeError::UnsupportedAuthenticator(sig_variant));
            }
            let sig_bytes = read_bcs_bytes(bcs_bytes, &mut cur)?;
            let pk65: [u8; 65] = pk_bytes.as_slice().try_into().map_err(|_| {
                AptosEnvelopeError::InvalidSignature(String::from(
                    "SingleKey secp256k1 pubkey != 65 bytes",
                ))
            })?;
            if aptos_singlekey_secp256k1_address(&pk65) != sender {
                return Err(AptosEnvelopeError::SenderAuthKeyMismatch);
            }
            let vk = SecpVerifyingKey::from_sec1_bytes(&pk65)
                .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
            let sig = SecpSig::from_slice(&sig_bytes)
                .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
            if sig.normalize_s().is_some() {
                return Err(AptosEnvelopeError::InvalidSignature(String::from(
                    "high-s secp256k1 signature refused",
                )));
            }
            use k256::ecdsa::signature::Verifier as _;
            let msg_digest: [u8; 32] = Sha3_256::digest(&signing_msg).into();
            vk.verify(&msg_digest, &sig)
                .map_err(|e| AptosEnvelopeError::InvalidSignature(e.to_string()))?;
        }
        3 | 4 => return Err(AptosEnvelopeError::KeylessOidcUnsupported),
        other => return Err(AptosEnvelopeError::UnsupportedAuthenticator(other)),
    }

    if cur != bcs_bytes.len() {
        return Err(AptosEnvelopeError::MalformedBcs(String::from(
            "trailing bytes after Aptos SignedTransaction",
        )));
    }

    let mut tx_h = Sha3_256::new();
    tx_h.update(Sha3_256::digest(b"APTOS::Transaction"));
    tx_h.update([0x00]);
    tx_h.update(bcs_bytes);
    let tx_hash: [u8; 32] = tx_h.finalize().into();

    Ok(DecodedAptosTx {
        tx_hash,
        sender,
        sequence_number,
        payload,
        max_gas_amount,
        gas_unit_price,
        expiration_timestamp_secs,
        chain_id,
    })
}

/// Encodes and signs a single-signer Ed25519 Aptos `SignedTransaction`.
pub fn sign_aptos_ed25519_tx(
    secret_seed: &[u8; 32],
    sequence_number: u64,
    payload: &AptosPayloadKind,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: u64,
    chain_id: u8,
) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};

    let sk = SigningKey::from_bytes(secret_seed);
    let pk32 = sk.verifying_key().to_bytes();
    let sender = aptos_ed25519_address(&pk32);

    let mut raw = Vec::new();
    raw.extend_from_slice(&sender);
    raw.extend_from_slice(&sequence_number.to_le_bytes());
    match payload {
        AptosPayloadKind::Script(code) => {
            write_uleb128_u32(0, &mut raw);
            write_uleb128_u32(code.len() as u32, &mut raw);
            raw.extend_from_slice(code);
        }
        AptosPayloadKind::ModuleBundle(bundle) => {
            write_uleb128_u32(1, &mut raw);
            write_uleb128_u32(bundle.len() as u32, &mut raw);
            raw.extend_from_slice(bundle);
        }
        AptosPayloadKind::EntryFunction {
            module_address,
            module_name,
            function_name,
            args_bcs,
        } => {
            write_uleb128_u32(2, &mut raw);
            raw.extend_from_slice(module_address);
            write_uleb128_u32(module_name.len() as u32, &mut raw);
            raw.extend_from_slice(module_name.as_bytes());
            write_uleb128_u32(function_name.len() as u32, &mut raw);
            raw.extend_from_slice(function_name.as_bytes());
            write_uleb128_u32(args_bcs.len() as u32, &mut raw);
            raw.extend_from_slice(args_bcs);
        }
    }
    raw.extend_from_slice(&max_gas_amount.to_le_bytes());
    raw.extend_from_slice(&gas_unit_price.to_le_bytes());
    raw.extend_from_slice(&expiration_timestamp_secs.to_le_bytes());
    raw.push(chain_id);

    let sig = sk.sign(&aptos_signing_message(&raw));
    let mut signed = raw;
    write_uleb128_u32(0, &mut signed);
    write_uleb128_u32(32, &mut signed);
    signed.extend_from_slice(&pk32);
    write_uleb128_u32(64, &mut signed);
    signed.extend_from_slice(&sig.to_bytes());
    signed
}
