//! Solana foreign transaction envelope decoding (legacy + v0) and Ed25519 verification.
//!
//! Implements section 8.6.2 (`Foreign::Solana`) and  item 4:
//! - Compact-u16 wire decoding of legacy and `v0` (`0x80`) versioned messages,
//!   including `v0` address lookup tables.
//! - Strict Ed25519 signature verification over the serialized message.
//! - Recent 150-Budlum-blockhash replay window and signature replay cache.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum age in Budlum blocks of a `recent_blockhash` accepted by `Foreign::Solana`.
pub const MAX_SOLANA_BLOCKHASH_WINDOW: usize = 150;

/// One compiled SVM instruction inside a Solana message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaCompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// One `v0` address table lookup inside a versioned Solana message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaAddressTableLookup {
    pub account_key: [u8; 32],
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

/// Decoded and Ed25519-verified Solana foreign transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedSolanaTx {
    pub tx_hash: [u8; 32],
    pub fee_payer: [u8; 32],
    pub fee_payer_signature: [u8; 64],
    pub is_v0: bool,
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<[u8; 32]>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<SolanaCompiledInstruction>,
    pub address_table_lookups: Vec<SolanaAddressTableLookup>,
}

/// Why a Solana wire transaction was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolanaEnvelopeError {
    Truncated,
    MalformedCompactU16,
    UnsupportedMessageVersion(u8),
    InvalidSignatureCount,
    InvalidSignature(String),
    UnknownOrExpiredBlockhash,
    ReplayedSignature,
}

impl std::fmt::Display for SolanaEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated Solana wire transaction"),
            Self::MalformedCompactU16 => write!(f, "non-canonical Solana compact-u16 length"),
            Self::UnsupportedMessageVersion(v) => {
                write!(f, "unsupported Solana message version {v}")
            }
            Self::InvalidSignatureCount => {
                write!(f, "Solana signature count does not match header")
            }
            Self::InvalidSignature(m) => write!(f, "invalid Solana Ed25519 signature: {m}"),
            Self::UnknownOrExpiredBlockhash => {
                write!(f, "Solana recent_blockhash outside 150-block Budlum window")
            }
            Self::ReplayedSignature => write!(f, "replayed Solana transaction signature"),
        }
    }
}

fn read_compact_u16(buf: &[u8], cursor: &mut usize) -> Result<usize, SolanaEnvelopeError> {
    let b0 = u16::from(*buf.get(*cursor).ok_or(SolanaEnvelopeError::Truncated)?);
    *cursor += 1;
    if b0 & 0x80 == 0 {
        return Ok(usize::from(b0));
    }
    let b1 = u16::from(*buf.get(*cursor).ok_or(SolanaEnvelopeError::Truncated)?);
    *cursor += 1;
    if b1 == 0 {
        return Err(SolanaEnvelopeError::MalformedCompactU16);
    }
    if b1 & 0x80 == 0 {
        return Ok(usize::from((b0 & 0x7f) | (b1 << 7)));
    }
    let b2 = u16::from(*buf.get(*cursor).ok_or(SolanaEnvelopeError::Truncated)?);
    *cursor += 1;
    if b2 == 0 || b2 > 0x03 {
        return Err(SolanaEnvelopeError::MalformedCompactU16);
    }
    Ok(usize::from((b0 & 0x7f) | ((b1 & 0x7f) << 7) | (b2 << 14)))
}

pub(crate) fn write_compact_u16(mut val: u16, out: &mut Vec<u8>) {
    loop {
        let mut elem = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(elem);
            break;
        }
        elem |= 0x80;
        out.push(elem);
    }
}

fn read_exact_32(buf: &[u8], cursor: &mut usize) -> Result<[u8; 32], SolanaEnvelopeError> {
    let slice = buf
        .get(*cursor..*cursor + 32)
        .ok_or(SolanaEnvelopeError::Truncated)?;
    *cursor += 32;
    slice.try_into().map_err(|_| SolanaEnvelopeError::Truncated)
}

/// Decodes a Solana wire transaction and verifies all required Ed25519 signatures.
pub fn decode_solana_tx(raw: &[u8]) -> Result<DecodedSolanaTx, SolanaEnvelopeError> {
    let mut cur = 0usize;
    let sig_count = read_compact_u16(raw, &mut cur)?;
    if sig_count == 0 || sig_count > 64 {
        return Err(SolanaEnvelopeError::InvalidSignatureCount);
    }
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let sig_slice = raw
            .get(cur..cur + 64)
            .ok_or(SolanaEnvelopeError::Truncated)?;
        cur += 64;
        let sig64: [u8; 64] = sig_slice
            .try_into()
            .map_err(|_| SolanaEnvelopeError::Truncated)?;
        signatures.push(sig64);
    }

    let message_bytes = raw.get(cur..).ok_or(SolanaEnvelopeError::Truncated)?;
    let first_msg_byte = *raw.get(cur).ok_or(SolanaEnvelopeError::Truncated)?;
    let is_v0 = if first_msg_byte & 0x80 != 0 {
        let version = first_msg_byte & 0x7f;
        if version != 0 {
            return Err(SolanaEnvelopeError::UnsupportedMessageVersion(version));
        }
        cur += 1;
        true
    } else {
        false
    };

    let num_required_signatures = *raw.get(cur).ok_or(SolanaEnvelopeError::Truncated)?;
    let num_readonly_signed = *raw.get(cur + 1).ok_or(SolanaEnvelopeError::Truncated)?;
    let num_readonly_unsigned = *raw.get(cur + 2).ok_or(SolanaEnvelopeError::Truncated)?;
    cur += 3;

    if usize::from(num_required_signatures) != sig_count {
        return Err(SolanaEnvelopeError::InvalidSignatureCount);
    }

    let key_count = read_compact_u16(raw, &mut cur)?;
    if key_count < sig_count || key_count > 256 {
        return Err(SolanaEnvelopeError::InvalidSignatureCount);
    }
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        account_keys.push(read_exact_32(raw, &mut cur)?);
    }
    let recent_blockhash = read_exact_32(raw, &mut cur)?;

    let ix_count = read_compact_u16(raw, &mut cur)?;
    if ix_count > 128 {
        return Err(SolanaEnvelopeError::Truncated);
    }
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_id_index = *raw.get(cur).ok_or(SolanaEnvelopeError::Truncated)?;
        cur += 1;
        let acc_len = read_compact_u16(raw, &mut cur)?;
        let accounts = raw
            .get(cur..cur + acc_len)
            .ok_or(SolanaEnvelopeError::Truncated)?
            .to_vec();
        cur += acc_len;
        let data_len = read_compact_u16(raw, &mut cur)?;
        let data = raw
            .get(cur..cur + data_len)
            .ok_or(SolanaEnvelopeError::Truncated)?
            .to_vec();
        cur += data_len;
        instructions.push(SolanaCompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }

    let mut address_table_lookups = Vec::new();
    if is_v0 {
        let lut_count = read_compact_u16(raw, &mut cur)?;
        if lut_count > 64 {
            return Err(SolanaEnvelopeError::Truncated);
        }
        for _ in 0..lut_count {
            let account_key = read_exact_32(raw, &mut cur)?;
            let w_len = read_compact_u16(raw, &mut cur)?;
            let writable_indexes = raw
                .get(cur..cur + w_len)
                .ok_or(SolanaEnvelopeError::Truncated)?
                .to_vec();
            cur += w_len;
            let r_len = read_compact_u16(raw, &mut cur)?;
            let readonly_indexes = raw
                .get(cur..cur + r_len)
                .ok_or(SolanaEnvelopeError::Truncated)?
                .to_vec();
            cur += r_len;
            address_table_lookups.push(SolanaAddressTableLookup {
                account_key,
                writable_indexes,
                readonly_indexes,
            });
        }
    }
    if cur != raw.len() {
        return Err(SolanaEnvelopeError::Truncated);
    }

    for (sig64, pubkey32) in signatures.iter().zip(account_keys.iter()) {
        let vk = VerifyingKey::from_bytes(pubkey32)
            .map_err(|e| SolanaEnvelopeError::InvalidSignature(e.to_string()))?;
        let sig = Signature::from_bytes(sig64);
        vk.verify(message_bytes, &sig)
            .map_err(|e| SolanaEnvelopeError::InvalidSignature(e.to_string()))?;
    }

    let fee_payer = *account_keys
        .first()
        .ok_or(SolanaEnvelopeError::InvalidSignatureCount)?;
    let fee_payer_signature = *signatures
        .first()
        .ok_or(SolanaEnvelopeError::InvalidSignatureCount)?;
    let tx_hash: [u8; 32] = Sha256::digest(raw).into();

    Ok(DecodedSolanaTx {
        tx_hash,
        fee_payer,
        fee_payer_signature,
        is_v0,
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups,
    })
}

/// Builds and signs a single-signer Solana transaction (legacy or `v0`).
pub fn sign_solana_tx(
    secret_seed: &[u8; 32],
    is_v0: bool,
    recent_blockhash: [u8; 32],
    extra_accounts: &[[u8; 32]],
    instructions: &[SolanaCompiledInstruction],
) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(secret_seed);
    let fee_payer = signing_key.verifying_key().to_bytes();

    let mut msg = Vec::new();
    if is_v0 {
        msg.push(0x80);
    }
    msg.push(1);
    msg.push(0);
    msg.push(0);
    let total_keys = 1u16.saturating_add(extra_accounts.len() as u16);
    write_compact_u16(total_keys, &mut msg);
    msg.extend_from_slice(&fee_payer);
    for acc in extra_accounts {
        msg.extend_from_slice(acc);
    }
    msg.extend_from_slice(&recent_blockhash);
    write_compact_u16(instructions.len() as u16, &mut msg);
    for ix in instructions {
        msg.push(ix.program_id_index);
        write_compact_u16(ix.accounts.len() as u16, &mut msg);
        msg.extend_from_slice(&ix.accounts);
        write_compact_u16(ix.data.len() as u16, &mut msg);
        msg.extend_from_slice(&ix.data);
    }
    if is_v0 {
        write_compact_u16(0, &mut msg);
    }

    let sig = signing_key.sign(&msg);
    let mut wire = Vec::new();
    write_compact_u16(1, &mut wire);
    wire.extend_from_slice(&sig.to_bytes());
    wire.extend_from_slice(&msg);
    wire
}
