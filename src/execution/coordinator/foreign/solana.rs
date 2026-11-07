//! Solana foreign transaction envelope decoding (legacy + v0) and Ed25519 verification.
//!
//! Implements section 8.6.2 (`Foreign::Solana`) and  item 4:
//! - Compact-u16 wire decoding of legacy and `v0` (`0x80`) versioned messages,
//!   including `v0` address lookup tables.
//! - Strict Ed25519 signature verification over the serialized message.
//! - Recent 150-Budlum-blockhash replay window and signature replay cache.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum age in Budlum blocks of a `recent_blockhash` accepted by `Foreign::Solana`.
pub const MAX_SOLANA_BLOCKHASH_WINDOW: usize = 150;

/// Solana's maximum serialized transaction packet size.
pub const MAX_SOLANA_TRANSACTION_BYTES: usize = 1_232;

const MAX_SOLANA_BASE64_BYTES: usize = 1_644;

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
    PacketTooLarge,
    HeaderInconsistent,
    DuplicateSigner { index: usize },
    ProgramIdOutOfRange,
    AccountIndexOutOfRange,
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
            Self::PacketTooLarge => write!(f, "Solana transaction exceeds the packet-size limit"),
            Self::HeaderInconsistent => write!(f, "Solana header bands exceed the account list"),
            Self::DuplicateSigner { index } => {
                write!(f, "duplicate Solana signer at account index {index}")
            }
            Self::ProgramIdOutOfRange => {
                write!(f, "Solana program id is not a static account")
            }
            Self::AccountIndexOutOfRange => {
                write!(f, "Solana instruction account index is out of range")
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
    if raw.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(SolanaEnvelopeError::PacketTooLarge);
    }
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
    if usize::from(num_readonly_signed) > sig_count
        || usize::from(num_readonly_unsigned) > key_count - sig_count
    {
        return Err(SolanaEnvelopeError::HeaderInconsistent);
    }
    for (index, key) in account_keys[..sig_count].iter().enumerate() {
        if account_keys[..index].contains(key) {
            return Err(SolanaEnvelopeError::DuplicateSigner { index });
        }
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

    for instruction in &instructions {
        if usize::from(instruction.program_id_index) >= key_count {
            return Err(SolanaEnvelopeError::ProgramIdOutOfRange);
        }
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
    let resolved_account_count = address_table_lookups.iter().fold(key_count, |count, lookup| {
        count
            .saturating_add(lookup.writable_indexes.len())
            .saturating_add(lookup.readonly_indexes.len())
    });
    for instruction in &instructions {
        if instruction
            .accounts
            .iter()
            .any(|index| usize::from(*index) >= resolved_account_count)
        {
            return Err(SolanaEnvelopeError::AccountIndexOutOfRange);
        }
    }

    for (sig64, pubkey32) in signatures.iter().zip(account_keys.iter()) {
        let vk = VerifyingKey::from_bytes(pubkey32)
            .map_err(|e| SolanaEnvelopeError::InvalidSignature(e.to_string()))?;
        let sig = Signature::from_bytes(sig64);
        vk.verify_strict(message_bytes, &sig)
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

const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decodes a fixed-width Solana base58 value without truncating overflow.
pub fn decode_solana_base58<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
    if text.len() > N.saturating_mul(2).saturating_add(2) {
        return Err("base58 value exceeds its fixed-width encoding bound");
    }
    let input = text.as_bytes();
    if input.is_empty() {
        return Err("empty base58 value");
    }
    let zeros = input.iter().take_while(|byte| **byte == b'1').count();
    if zeros > N {
        return Err("base58 value has too many leading zero bytes");
    }

    // Little-endian base-256 digits. Each base58 digit multiplies the complete
    // value by 58, so leading `1`s remain explicit zero bytes rather than being
    // confused with the significant digit buffer.
    let mut digits = Vec::<u8>::new();
    for &byte in &input[zeros..] {
        let digit = BASE58_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or("character outside the Solana base58 alphabet")? as u32;
        let mut carry = digit;
        for value in &mut digits {
            carry += u32::from(*value) * 58;
            *value = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry != 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
        if zeros.saturating_add(digits.len()) > N {
            return Err("base58 value exceeds the requested byte width");
        }
    }

    let mut out = [0u8; N];
    let start = N - digits.len();
    for (offset, digit) in digits.iter().rev().enumerate() {
        out[start + offset] = *digit;
    }
    Ok(out)
}

/// Encodes bytes in the base58 alphabet used by Solana keys and signatures.
#[must_use]
pub fn encode_solana_base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Vec::<u8>::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry != 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros.saturating_add(digits.len()));
    out.extend(std::iter::repeat_n('1', zeros));
    for digit in digits.iter().rev() {
        out.push(char::from(BASE58_ALPHABET[usize::from(*digit)]));
    }
    out
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes canonical padded base64 for one bounded Solana transaction.
pub fn decode_solana_base64(text: &str) -> Result<Vec<u8>, &'static str> {
    let input = text.as_bytes();
    if input.len() > MAX_SOLANA_BASE64_BYTES {
        return Err("base64 transaction exceeds the packet-size encoding bound");
    }
    if input.len() % 4 != 0 {
        return Err("base64 transaction length is not a quartet boundary");
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let quartet_count = input.len() / 4;
    for (index, quartet) in input.chunks_exact(4).enumerate() {
        let last = index + 1 == quartet_count;
        let a = base64_digit(quartet[0]).ok_or("invalid base64 first digit")?;
        let b = base64_digit(quartet[1]).ok_or("invalid base64 second digit")?;
        out.push((a << 2) | (b >> 4));

        match (quartet[2], quartet[3]) {
            (b'=', b'=') if last => {
                if b & 0x0f != 0 {
                    return Err("non-zero base64 spare bits");
                }
            }
            (c, b'=') if last => {
                let c = base64_digit(c).ok_or("invalid base64 third digit")?;
                if c & 0x03 != 0 {
                    return Err("non-zero base64 spare bits");
                }
                out.push((b << 4) | (c >> 2));
            }
            (b'=', _) | (_, b'=') => return Err("base64 padding outside the final quartet"),
            (c, d) => {
                let c = base64_digit(c).ok_or("invalid base64 third digit")?;
                let d = base64_digit(d).ok_or("invalid base64 fourth digit")?;
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
        }
    }
    if out.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err("decoded transaction exceeds the packet-size limit");
    }
    Ok(out)
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

#[cfg(test)]
mod encoding_tests {
    use super::*;

    #[test]
    fn base58_preserves_leading_zeroes_and_never_panics() {
        let zeroes = [0u8; 32];
        let encoded_zeroes = "1".repeat(32);
        assert_eq!(decode_solana_base58::<32>(&encoded_zeroes), Ok(zeroes));
        assert_eq!(encode_solana_base58(&zeroes), encoded_zeroes);

        let mut one = [0u8; 32];
        one[31] = 1;
        let encoded_one = format!("{}2", "1".repeat(31));
        assert_eq!(decode_solana_base58::<32>(&encoded_one), Ok(one));
        assert_eq!(encode_solana_base58(&one), encoded_one);

        assert!(decode_solana_base58::<32>(&"1".repeat(33)).is_err());
        assert!(decode_solana_base58::<32>("0").is_err());
    }

    #[test]
    fn base58_round_trip_covers_every_byte_value() {
        let mut value = [0u8; 64];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let encoded = encode_solana_base58(&value);
        assert_eq!(decode_solana_base58::<64>(&encoded), Ok(value));
    }

    #[test]
    fn base64_is_canonical_and_packet_bounded() {
        assert_eq!(decode_solana_base64(""), Ok(Vec::new()));
        assert_eq!(decode_solana_base64("Zg=="), Ok(b"f".to_vec()));
        assert_eq!(decode_solana_base64("Zm8="), Ok(b"fo".to_vec()));
        assert_eq!(decode_solana_base64("Zm9v"), Ok(b"foo".to_vec()));
        assert!(decode_solana_base64("Zh==").is_err());
        assert!(decode_solana_base64("Zm9=").is_err());
        assert!(decode_solana_base64("Zg=").is_err());
        assert!(decode_solana_base64("=m9v").is_err());
        assert!(decode_solana_base64(&"A".repeat(MAX_SOLANA_BASE64_BYTES + 4)).is_err());
    }
}
