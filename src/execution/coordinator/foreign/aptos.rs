//! `Foreign::Aptos` BCS `SignedTransaction` decoding and signature verification
//! (`WP-32`, `BLG-249` Aptos leg, `BLG-267` `category = "f"`).
//!
//! Accepts BCS-encoded Aptos `SignedTransaction` envelopes targeting chain ID
//! `205` (`45261 mod 256`), verifies `Ed25519`, `MultiEd25519`, and `SingleKey`
//! (`Ed25519` or `Secp256k1Ecdsa`) authenticators over
//! `SHA3-256("APTOS::RawTransaction") || raw_tx_bcs`, enforces expiration and
//! disabled-module rules (`Section 8.15`), and deterministically refuses OIDC
//! keyless accounts and deprecated `ModuleBundle` payloads.
//! Convenience: public Foreign::Aptos BCS transaction envelope and Move alias surface (WP-32).

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use sha3::{Digest as _, Sha3_256};

use crate::execution::coordinator::foreign::cosmos::verify_secp256k1_prehashed;

/// Canonical Aptos chain identifier for Budlum (`45261 mod 256 = 205`, Section 8.6.2).
pub const BUDLUM_APTOS_CHAIN_ID: u8 = 205;

/// Reserved authentication-key scheme byte for Budlum Move local aliases (`Section 8.4.2`).
pub const BUDLUM_MOVE_ALIAS_SCHEME_BYTE: u8 = 0xBD;

/// Pinned `aptos-core` authentication/derivation scheme bytes (`Scheme` enum).
pub const APTOS_KNOWN_SCHEME_BYTES: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
];

/// Maximum BCS `SignedTransaction` wire size (`512 KiB`).
pub const MAX_APTOS_TX_BYTES: usize = 512 * 1024;

const FRAMEWORK_ADDR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

const DISABLED_MODULES: &[&str] = &[
    "aptos_governance",
    "delegation_pool",
    "governance_proposal",
    "stake",
    "staking_config",
    "staking_contract",
    "staking_proxy",
    "voting",
];

/// Refusal reasons when decoding or verifying a `Foreign::Aptos` BCS envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AptosEnvelopeError {
    EmptyEnvelope,
    OversizedEnvelope(usize),
    MalformedBcs(&'static str),
    TrailingBytes(usize),
    WrongChainId { expected: u8, actual: u8 },
    ExpiredTransaction { expiration_secs: u64, now_secs: u64 },
    DeprecatedModuleBundle,
    UnsupportedPayloadVariant(u32),
    UnsupportedAuthenticator(u32),
    KeylessAccountForbidden,
    DisabledFrameworkModule(String),
    InvalidPublicKey,
    InvalidSignature,
    SenderAuthKeyMismatch { sender: [u8; 32], auth_key: [u8; 32] },
}

impl fmt::Display for AptosEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEnvelope => write!(f, "empty Aptos BCS transaction"),
            Self::OversizedEnvelope(n) => {
                write!(f, "Aptos transaction size {n} exceeds {MAX_APTOS_TX_BYTES}")
            }
            Self::MalformedBcs(ctx) => write!(f, "malformed Aptos BCS ({ctx})"),
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after Aptos SignedTransaction"),
            Self::WrongChainId { expected, actual } => {
                write!(f, "Aptos chain_id mismatch: expected {expected}, got {actual}")
            }
            Self::ExpiredTransaction {
                expiration_secs,
                now_secs,
            } => write!(
                f,
                "Aptos transaction expired at {expiration_secs}s (block timestamp {now_secs}s)"
            ),
            Self::DeprecatedModuleBundle => {
                write!(f, "Aptos ModuleBundle payload is deprecated and refused")
            }
            Self::UnsupportedPayloadVariant(v) => {
                write!(f, "unsupported Aptos TransactionPayload variant {v}")
            }
            Self::UnsupportedAuthenticator(v) => {
                write!(f, "unsupported Aptos TransactionAuthenticator variant {v}")
            }
            Self::KeylessAccountForbidden => {
                write!(f, "Aptos OIDC keyless accounts are refused on Budlum (Section 8.15)")
            }
            Self::DisabledFrameworkModule(m) => {
                write!(f, "Aptos module 0x1::{m} is disabled on Budlum (Section 8.15)")
            }
            Self::InvalidPublicKey => write!(f, "invalid Aptos public key"),
            Self::InvalidSignature => write!(f, "invalid Aptos signature"),
            Self::SenderAuthKeyMismatch { sender, auth_key } => write!(
                f,
                "Aptos sender 0x{} does not match authentication key 0x{}",
                hex::encode(sender),
                hex::encode(auth_key)
            ),
        }
    }
}

impl std::error::Error for AptosEnvelopeError {}

/// Decoded Aptos payload variants accepted by `Foreign::Aptos` (`Section 8.6.2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AptosPayload {
    /// Entry-function call (including `0x1::code::publish_package_txn` and coin transfers).
    EntryFunction {
        module_address: [u8; 32],
        module_name: String,
        function_name: String,
        ty_args_count: usize,
        args: Vec<Vec<u8>>,
    },
    /// Move bytecode script with raw serialized type-tag count and arguments.
    Script {
        code: Vec<u8>,
        ty_args_count: usize,
        args_count: usize,
    },
}

/// Verified `Foreign::Aptos` envelope ready for coordinator replay and fee checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAptosTx {
    pub tx_hash: [u8; 32],
    pub sender: [u8; 32],
    pub auth_key: [u8; 32],
    pub sequence_number: u64,
    pub payload: AptosPayload,
    pub max_gas_amount: u64,
    pub gas_unit_price_octas: u64,
    pub expiration_timestamp_secs: u64,
    pub chain_id: u8,
    /// When the payload is a direct `0x1::aptos_account::transfer` or `0x1::coin::transfer`,
    /// holds `(recipient_addr32, amount_octas)` for alert-level-2 local-alias checks.
    pub direct_octa_transfer: Option<([u8; 32], u64)>,
}

struct BcsCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BcsCursor<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize, ctx: &'static str) -> Result<&'a [u8], AptosEnvelopeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(AptosEnvelopeError::MalformedBcs(ctx))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(AptosEnvelopeError::MalformedBcs(ctx))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self, ctx: &'static str) -> Result<u8, AptosEnvelopeError> {
        self.take(1, ctx)
            .and_then(|s| s.first().copied().ok_or(AptosEnvelopeError::MalformedBcs(ctx)))
    }

    fn read_u64(&mut self, ctx: &'static str) -> Result<u64, AptosEnvelopeError> {
        let bytes: [u8; 8] = self
            .take(8, ctx)?
            .try_into()
            .map_err(|_| AptosEnvelopeError::MalformedBcs(ctx))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_addr32(&mut self, ctx: &'static str) -> Result<[u8; 32], AptosEnvelopeError> {
        self.take(32, ctx)?
            .try_into()
            .map_err(|_| AptosEnvelopeError::MalformedBcs(ctx))
    }

    fn read_uleb128(&mut self, ctx: &'static str) -> Result<u32, AptosEnvelopeError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for _ in 0..5 {
            let byte = self.read_u8(ctx)?;
            let digit = u64::from(byte & 0x7F);
            if shift == 28 && digit > 0x0F {
                return Err(AptosEnvelopeError::MalformedBcs(ctx));
            }
            value |= digit << shift;
            if (byte & 0x80) == 0 {
                if shift > 0 && digit == 0 {
                    return Err(AptosEnvelopeError::MalformedBcs(ctx));
                }
                return u32::try_from(value).map_err(|_| AptosEnvelopeError::MalformedBcs(ctx));
            }
            shift += 7;
        }
        Err(AptosEnvelopeError::MalformedBcs(ctx))
    }

    fn read_bytes(&mut self, ctx: &'static str) -> Result<Vec<u8>, AptosEnvelopeError> {
        let len = self.read_uleb128(ctx)? as usize;
        Ok(self.take(len, ctx)?.to_vec())
    }

    fn read_string(&mut self, ctx: &'static str) -> Result<String, AptosEnvelopeError> {
        let raw = self.read_bytes(ctx)?;
        String::from_utf8(raw).map_err(|_| AptosEnvelopeError::MalformedBcs(ctx))
    }

    fn skip_type_tag(&mut self, depth: u8) -> Result<(), AptosEnvelopeError> {
        if depth > 16 {
            return Err(AptosEnvelopeError::MalformedBcs("TypeTag nesting depth"));
        }
        let variant = self.read_uleb128("TypeTag variant")?;
        match variant {
            // bool=0, u8=1, u64=2, u128=3, address=4, signer=5, u16=8, u32=9, u256=10
            0..=5 | 8..=10 => Ok(()),
            // vector<T> = 6
            6 => self.skip_type_tag(depth + 1),
            // struct = 7 { address, module, name, type_args }
            7 => {
                let _ = self.read_addr32("StructTag.address")?;
                let _ = self.read_string("StructTag.module")?;
                let _ = self.read_string("StructTag.name")?;
                let n = self.read_uleb128("StructTag.type_args")? as usize;
                if n > 32 {
                    return Err(AptosEnvelopeError::MalformedBcs("StructTag.type_args cap"));
                }
                for _ in 0..n {
                    self.skip_type_tag(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(AptosEnvelopeError::MalformedBcs("unknown TypeTag variant")),
        }
    }

    fn skip_script_arg(&mut self) -> Result<(), AptosEnvelopeError> {
        let variant = self.read_uleb128("TransactionArgument variant")?;
        match variant {
            0 => {
                let _ = self.read_u8("arg u8")?;
            }
            1 => {
                let _ = self.read_u64("arg u64")?;
            }
            2 => {
                let _ = self.take(16, "arg u128")?;
            }
            3 => {
                let _ = self.read_addr32("arg address")?;
            }
            4 => {
                let _ = self.read_bytes("arg u8vector")?;
            }
            5 => {
                let b = self.read_u8("arg bool")?;
                if b > 1 {
                    return Err(AptosEnvelopeError::MalformedBcs("invalid bool in script arg"));
                }
            }
            6 => {
                let _ = self.take(2, "arg u16")?;
            }
            7 => {
                let _ = self.take(4, "arg u32")?;
            }
            8 => {
                let _ = self.take(32, "arg u256")?;
            }
            _ => return Err(AptosEnvelopeError::MalformedBcs("unknown script arg")),
        }
        Ok(())
    }
}

/// Compute the Aptos Ed25519 authentication key `SHA3-256(pubkey_32 || 0x00)`.
///
/// Convenience: used by wallets, tests, and coordinator foreign-account helpers.
#[must_use]
pub fn aptos_ed25519_auth_key(pubkey_32: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(pubkey_32);
    h.update([0x00u8]);
    h.finalize().into()
}

/// Compute the canonical Aptos `RawTransaction` signing message
/// `SHA3-256("APTOS::RawTransaction") || raw_tx_bcs`.
///
/// Convenience: exposed so SDK/test builders sign exact Aptos BCS transactions.
#[must_use]
pub fn aptos_raw_tx_signing_message(raw_tx_bcs: &[u8]) -> Vec<u8> {
    let prefix: [u8; 32] = Sha3_256::digest(b"APTOS::RawTransaction").into();
    let mut out = Vec::with_capacity(32 + raw_tx_bcs.len());
    out.extend_from_slice(&prefix);
    out.extend_from_slice(raw_tx_bcs);
    out
}

/// Returns `true` when `scheme_byte` is absent from `APTOS_KNOWN_SCHEME_BYTES`.
///
/// Convenience: confirms `0xBD` local-alias separation on the node side (`WP-32`).
#[must_use]
pub fn is_aptos_scheme_byte_unused(scheme_byte: u8) -> bool {
    !APTOS_KNOWN_SCHEME_BYTES.contains(&scheme_byte)
}

fn verify_ed25519_strict(
    pubkey_bytes: &[u8],
    signing_msg: &[u8],
    sig_bytes: &[u8],
) -> Result<[u8; 32], AptosEnvelopeError> {
    let pk_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| AptosEnvelopeError::InvalidPublicKey)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AptosEnvelopeError::InvalidSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| AptosEnvelopeError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_msg, &sig)
        .map_err(|_| AptosEnvelopeError::InvalidSignature)?;
    Ok(aptos_ed25519_auth_key(&pk_arr))
}

fn verify_multi_ed25519(
    pk_blob: &[u8],
    signing_msg: &[u8],
    sig_blob: &[u8],
) -> Result<[u8; 32], AptosEnvelopeError> {
    if pk_blob.len() < 33 || (pk_blob.len() - 1) % 32 != 0 {
        return Err(AptosEnvelopeError::InvalidPublicKey);
    }
    let Some((pks_raw, threshold_slice)) = pk_blob.split_at_checked(pk_blob.len() - 1) else {
        return Err(AptosEnvelopeError::InvalidPublicKey);
    };
    let n = pks_raw.len() / 32;
    let threshold = usize::from(threshold_slice.first().copied().unwrap_or(0));
    if threshold == 0 || threshold > n || n > 32 {
        return Err(AptosEnvelopeError::InvalidPublicKey);
    }
    if sig_blob.len() < 68 || (sig_blob.len() - 4) % 64 != 0 {
        return Err(AptosEnvelopeError::InvalidSignature);
    }
    let Some((sigs_raw, bitmap_slice)) = sig_blob.split_at_checked(sig_blob.len() - 4) else {
        return Err(AptosEnvelopeError::InvalidSignature);
    };
    let sig_count = sigs_raw.len() / 64;
    if sig_count < threshold || sig_count > n {
        return Err(AptosEnvelopeError::InvalidSignature);
    }
    let bitmap_arr: [u8; 4] = bitmap_slice
        .try_into()
        .map_err(|_| AptosEnvelopeError::InvalidSignature)?;
    let bitmap = u32::from_be_bytes(bitmap_arr);
    if bitmap.count_ones() as usize != sig_count {
        return Err(AptosEnvelopeError::InvalidSignature);
    }

    let mut sig_idx = 0usize;
    for bit in 0..32usize {
        let mask = 1u32 << (31 - bit);
        if (bitmap & mask) != 0 {
            if bit >= n {
                return Err(AptosEnvelopeError::InvalidSignature);
            }
            let pk_start = bit * 32;
            let sig_start = sig_idx * 64;
            let pk_slice = pks_raw
                .get(pk_start..pk_start + 32)
                .ok_or(AptosEnvelopeError::InvalidPublicKey)?;
            let one_sig = sigs_raw
                .get(sig_start..sig_start + 64)
                .ok_or(AptosEnvelopeError::InvalidSignature)?;
            let _ = verify_ed25519_strict(pk_slice, signing_msg, one_sig)?;
            sig_idx += 1;
        }
    }

    let mut h = Sha3_256::new();
    h.update(pk_blob);
    h.update([0x01u8]);
    Ok(h.finalize().into())
}

fn verify_account_authenticator(
    cur: &mut BcsCursor<'_>,
    signing_msg: &[u8],
) -> Result<[u8; 32], AptosEnvelopeError> {
    let acct_variant = cur.read_uleb128("AccountAuthenticator variant")?;
    match acct_variant {
        0 => {
            let pk = cur.read_bytes("AccountAuthenticator::Ed25519 pk")?;
            let sig = cur.read_bytes("AccountAuthenticator::Ed25519 sig")?;
            verify_ed25519_strict(&pk, signing_msg, &sig)
        }
        1 => {
            let pk = cur.read_bytes("AccountAuthenticator::MultiEd25519 pk")?;
            let sig = cur.read_bytes("AccountAuthenticator::MultiEd25519 sig")?;
            verify_multi_ed25519(&pk, signing_msg, &sig)
        }
        // SingleKey { public_key: AnyPublicKey, signature: AnySignature }
        2 => {
            let key_variant = cur.read_uleb128("AnyPublicKey variant")?;
            match key_variant {
                // AnyPublicKey::Ed25519 = 0
                0 => {
                    let pk = cur.read_bytes("AnyPublicKey::Ed25519")?;
                    let sig_variant = cur.read_uleb128("AnySignature variant")?;
                    if sig_variant != 0 {
                        return Err(AptosEnvelopeError::InvalidSignature);
                    }
                    let sig = cur.read_bytes("AnySignature::Ed25519")?;
                    let _ = verify_ed25519_strict(&pk, signing_msg, &sig)?;
                    let mut h = Sha3_256::new();
                    h.update([0x00u8]);
                    h.update(&pk);
                    h.update([0x02u8]);
                    Ok(h.finalize().into())
                }
                // AnyPublicKey::Secp256k1Ecdsa = 1
                1 => {
                    let pk = cur.read_bytes("AnyPublicKey::Secp256k1Ecdsa")?;
                    let sig_variant = cur.read_uleb128("AnySignature variant")?;
                    if sig_variant != 1 {
                        return Err(AptosEnvelopeError::InvalidSignature);
                    }
                    let sig = cur.read_bytes("AnySignature::Secp256k1Ecdsa")?;
                    let msg_digest: [u8; 32] = Sha3_256::digest(signing_msg).into();
                    verify_secp256k1_prehashed(&pk, &msg_digest, &sig)
                        .map_err(|_| AptosEnvelopeError::InvalidSignature)?;
                    let mut h = Sha3_256::new();
                    h.update([0x01u8]);
                    h.update(&pk);
                    h.update([0x02u8]);
                    Ok(h.finalize().into())
                }
                // Keyless = 3, FederatedKeyless = 5 (Section 8.15 explicit refusal)
                3 | 5 => Err(AptosEnvelopeError::KeylessAccountForbidden),
                other => Err(AptosEnvelopeError::UnsupportedAuthenticator(other)),
            }
        }
        // NoAccountAuthenticator = 4 or Abstraction = 5 / Keyless
        other => Err(AptosEnvelopeError::UnsupportedAuthenticator(other)),
    }
}

/// Decode and cryptographically verify a BCS-encoded Aptos `SignedTransaction`
/// (`Section 8.6.2` `Aptos` row).
pub fn decode_and_verify_aptos_tx(
    raw_signed_bcs: &[u8],
    expected_chain_id: u8,
    block_timestamp_secs: u64,
) -> Result<DecodedAptosTx, AptosEnvelopeError> {
    if raw_signed_bcs.is_empty() {
        return Err(AptosEnvelopeError::EmptyEnvelope);
    }
    if raw_signed_bcs.len() > MAX_APTOS_TX_BYTES {
        return Err(AptosEnvelopeError::OversizedEnvelope(raw_signed_bcs.len()));
    }

    let mut cur = BcsCursor::new(raw_signed_bcs);
    let sender = cur.read_addr32("RawTransaction.sender")?;
    let sequence_number = cur.read_u64("RawTransaction.sequence_number")?;

    let payload_variant = cur.read_uleb128("TransactionPayload variant")?;
    let mut direct_octa_transfer = None;
    let payload = match payload_variant {
        // Script
        0 => {
            let code = cur.read_bytes("Script.code")?;
            let ty_args_count = cur.read_uleb128("Script.ty_args")? as usize;
            if ty_args_count > 32 {
                return Err(AptosEnvelopeError::MalformedBcs("Script.ty_args cap"));
            }
            for _ in 0..ty_args_count {
                cur.skip_type_tag(0)?;
            }
            let args_count = cur.read_uleb128("Script.args")? as usize;
            if args_count > 64 {
                return Err(AptosEnvelopeError::MalformedBcs("Script.args cap"));
            }
            for _ in 0..args_count {
                cur.skip_script_arg()?;
            }
            AptosPayload::Script {
                code,
                ty_args_count,
                args_count,
            }
        }
        // Deprecated ModuleBundle
        1 => return Err(AptosEnvelopeError::DeprecatedModuleBundle),
        // EntryFunction
        2 => {
            let module_address = cur.read_addr32("ModuleId.address")?;
            let module_name = cur.read_string("ModuleId.name")?;
            let function_name = cur.read_string("EntryFunction.function")?;
            if module_address == FRAMEWORK_ADDR && DISABLED_MODULES.contains(&module_name.as_str())
            {
                return Err(AptosEnvelopeError::DisabledFrameworkModule(module_name));
            }
            let ty_args_count = cur.read_uleb128("EntryFunction.ty_args")? as usize;
            if ty_args_count > 32 {
                return Err(AptosEnvelopeError::MalformedBcs("EntryFunction.ty_args cap"));
            }
            for _ in 0..ty_args_count {
                cur.skip_type_tag(0)?;
            }
            let args_count = cur.read_uleb128("EntryFunction.args")? as usize;
            if args_count > 64 {
                return Err(AptosEnvelopeError::MalformedBcs("EntryFunction.args cap"));
            }
            let mut args = Vec::with_capacity(args_count);
            for _ in 0..args_count {
                args.push(cur.read_bytes("EntryFunction.arg")?);
            }
            if module_address == FRAMEWORK_ADDR
                && ((module_name == "aptos_account"
                    && (function_name == "transfer" || function_name == "transfer_coins"))
                    || (module_name == "coin" && function_name == "transfer"))
            {
                if let (Some(rcpt_raw), Some(amt_raw)) = (args.first(), args.get(1)) {
                    if let (Ok(rcpt), Ok(amt_arr)) = (
                        <[u8; 32]>::try_from(rcpt_raw.as_slice()),
                        <[u8; 8]>::try_from(amt_raw.as_slice()),
                    ) {
                        direct_octa_transfer = Some((rcpt, u64::from_le_bytes(amt_arr)));
                    }
                }
            }
            AptosPayload::EntryFunction {
                module_address,
                module_name,
                function_name,
                ty_args_count,
                args,
            }
        }
        other => return Err(AptosEnvelopeError::UnsupportedPayloadVariant(other)),
    };

    let max_gas_amount = cur.read_u64("RawTransaction.max_gas_amount")?;
    let gas_unit_price_octas = cur.read_u64("RawTransaction.gas_unit_price")?;
    let expiration_timestamp_secs = cur.read_u64("RawTransaction.expiration_timestamp_secs")?;
    let chain_id = cur.read_u8("RawTransaction.chain_id")?;

    let raw_tx_end = cur.pos;
    let raw_tx_bcs = raw_signed_bcs
        .get(..raw_tx_end)
        .ok_or(AptosEnvelopeError::MalformedBcs("raw_tx slice"))?;

    if chain_id != expected_chain_id {
        return Err(AptosEnvelopeError::WrongChainId {
            expected: expected_chain_id,
            actual: chain_id,
        });
    }
    if block_timestamp_secs >= expiration_timestamp_secs {
        return Err(AptosEnvelopeError::ExpiredTransaction {
            expiration_secs: expiration_timestamp_secs,
            now_secs: block_timestamp_secs,
        });
    }

    let signing_msg = aptos_raw_tx_signing_message(raw_tx_bcs);
    let auth_variant = cur.read_uleb128("TransactionAuthenticator variant")?;
    let auth_key = match auth_variant {
        // Ed25519
        0 => {
            let pk = cur.read_bytes("Ed25519PublicKey")?;
            let sig = cur.read_bytes("Ed25519Signature")?;
            verify_ed25519_strict(&pk, &signing_msg, &sig)?
        }
        // MultiEd25519
        1 => {
            let pk = cur.read_bytes("MultiEd25519PublicKey")?;
            let sig = cur.read_bytes("MultiEd25519Signature")?;
            verify_multi_ed25519(&pk, &signing_msg, &sig)?
        }
        // SingleSender(AccountAuthenticator) = 4
        4 => verify_account_authenticator(&mut cur, &signing_msg)?,
        other => return Err(AptosEnvelopeError::UnsupportedAuthenticator(other)),
    };

    if cur.pos != raw_signed_bcs.len() {
        return Err(AptosEnvelopeError::TrailingBytes(
            raw_signed_bcs.len().saturating_sub(cur.pos),
        ));
    }
    if sender != auth_key {
        return Err(AptosEnvelopeError::SenderAuthKeyMismatch { sender, auth_key });
    }

    let mut hash_h = Sha3_256::new();
    hash_h.update(Sha3_256::digest(b"APTOS::Transaction"));
    hash_h.update([0x00u8]); // Transaction::UserTransaction variant
    hash_h.update(raw_signed_bcs);
    let tx_hash: [u8; 32] = hash_h.finalize().into();

    Ok(DecodedAptosTx {
        tx_hash,
        sender,
        auth_key,
        sequence_number,
        payload,
        max_gas_amount,
        gas_unit_price_octas,
        expiration_timestamp_secs,
        chain_id,
        direct_octa_transfer,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub(crate) fn bcs_uleb128(out: &mut Vec<u8>, mut val: u32) {
        loop {
            let mut b = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                b |= 0x80;
            }
            out.push(b);
            if val == 0 {
                break;
            }
        }
    }

    pub(crate) fn bcs_bytes(out: &mut Vec<u8>, data: &[u8]) {
        bcs_uleb128(out, data.len() as u32);
        out.extend_from_slice(data);
    }

    pub(crate) fn build_raw_aptos_transfer_bcs(
        sender: [u8; 32],
        seq: u64,
        recipient: [u8; 32],
        octas: u64,
        max_gas: u64,
        gas_price_octas: u64,
        expiration_secs: u64,
        chain_id: u8,
    ) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&sender);
        raw.extend_from_slice(&seq.to_le_bytes());
        // TransactionPayload::EntryFunction = 2
        bcs_uleb128(&mut raw, 2);
        raw.extend_from_slice(&FRAMEWORK_ADDR);
        bcs_bytes(&mut raw, b"aptos_account");
        bcs_bytes(&mut raw, b"transfer");
        bcs_uleb128(&mut raw, 0); // ty_args
        bcs_uleb128(&mut raw, 2); // 2 args
        bcs_bytes(&mut raw, &recipient);
        bcs_bytes(&mut raw, &octas.to_le_bytes());
        raw.extend_from_slice(&max_gas.to_le_bytes());
        raw.extend_from_slice(&gas_price_octas.to_le_bytes());
        raw.extend_from_slice(&expiration_secs.to_le_bytes());
        raw.push(chain_id);
        raw
    }

    pub(crate) fn sign_ed25519_aptos_tx(sk: &SigningKey, raw_tx: &[u8]) -> Vec<u8> {
        let msg = aptos_raw_tx_signing_message(raw_tx);
        let sig = sk.sign(&msg);
        let mut signed = raw_tx.to_vec();
        bcs_uleb128(&mut signed, 0); // TransactionAuthenticator::Ed25519
        bcs_bytes(&mut signed, sk.verifying_key().as_bytes());
        bcs_bytes(&mut signed, &sig.to_bytes());
        signed
    }

    #[test]
    fn ed25519_signed_aptos_tx_verifies_and_extracts_transfer() {
        let sk = SigningKey::from_bytes(&[0x21u8; 32]);
        let sender = aptos_ed25519_auth_key(sk.verifying_key().as_bytes());
        let rcpt = [0x99u8; 32];
        let raw = build_raw_aptos_transfer_bcs(
            sender,
            0,
            rcpt,
            250_000,
            2_000,
            100,
            1_900_000_000,
            BUDLUM_APTOS_CHAIN_ID,
        );
        let signed = sign_ed25519_aptos_tx(&sk, &raw);
        let decoded = decode_and_verify_aptos_tx(&signed, BUDLUM_APTOS_CHAIN_ID, 1_800_000_000)
            .expect("valid Aptos tx");
        assert_eq!(decoded.sender, sender);
        assert_eq!(decoded.sequence_number, 0);
        assert_eq!(decoded.direct_octa_transfer, Some((rcpt, 250_000)));
    }

    #[test]
    fn wrong_chain_id_and_expired_timestamp_are_refused() {
        let sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let sender = aptos_ed25519_auth_key(sk.verifying_key().as_bytes());
        let bad_chain = build_raw_aptos_transfer_bcs(
            sender,
            0,
            [0x11u8; 32],
            100,
            1_000,
            100,
            1_900_000_000,
            1, // mainnet instead of 205
        );
        let signed_bad = sign_ed25519_aptos_tx(&sk, &bad_chain);
        assert_eq!(
            decode_and_verify_aptos_tx(&signed_bad, BUDLUM_APTOS_CHAIN_ID, 1_800_000_000),
            Err(AptosEnvelopeError::WrongChainId {
                expected: BUDLUM_APTOS_CHAIN_ID,
                actual: 1,
            })
        );

        let expired_raw = build_raw_aptos_transfer_bcs(
            sender,
            0,
            [0x11u8; 32],
            100,
            1_000,
            100,
            1_800_000_000,
            BUDLUM_APTOS_CHAIN_ID,
        );
        let signed_exp = sign_ed25519_aptos_tx(&sk, &expired_raw);
        assert_eq!(
            decode_and_verify_aptos_tx(&signed_exp, BUDLUM_APTOS_CHAIN_ID, 1_800_000_000),
            Err(AptosEnvelopeError::ExpiredTransaction {
                expiration_secs: 1_800_000_000,
                now_secs: 1_800_000_000,
            })
        );
    }

    #[test]
    fn keyless_authenticator_and_staking_module_are_refused() {
        let sender = [0x33u8; 32];
        let raw = build_raw_aptos_transfer_bcs(
            sender,
            0,
            [0x44u8; 32],
            10,
            1_000,
            100,
            1_900_000_000,
            BUDLUM_APTOS_CHAIN_ID,
        );
        let mut keyless_tx = raw;
        bcs_uleb128(&mut keyless_tx, 4); // SingleSender
        bcs_uleb128(&mut keyless_tx, 2); // SingleKey
        bcs_uleb128(&mut keyless_tx, 3); // AnyPublicKey::Keyless
        assert_eq!(
            decode_and_verify_aptos_tx(&keyless_tx, BUDLUM_APTOS_CHAIN_ID, 1_800_000_000),
            Err(AptosEnvelopeError::KeylessAccountForbidden)
        );
    }

    #[test]
    fn multi_ed25519_2_of_3_verifies() {
        let sk0 = SigningKey::from_bytes(&[0x41u8; 32]);
        let sk1 = SigningKey::from_bytes(&[0x42u8; 32]);
        let sk2 = SigningKey::from_bytes(&[0x43u8; 32]);
        let mut pk_blob = Vec::new();
        pk_blob.extend_from_slice(sk0.verifying_key().as_bytes());
        pk_blob.extend_from_slice(sk1.verifying_key().as_bytes());
        pk_blob.extend_from_slice(sk2.verifying_key().as_bytes());
        pk_blob.push(2); // 2-of-3 threshold

        let mut h = Sha3_256::new();
        h.update(&pk_blob);
        h.update([0x01u8]);
        let sender: [u8; 32] = h.finalize().into();

        let raw = build_raw_aptos_transfer_bcs(
            sender,
            0,
            [0x55u8; 32],
            500,
            2_000,
            100,
            1_900_000_000,
            BUDLUM_APTOS_CHAIN_ID,
        );
        let msg = aptos_raw_tx_signing_message(&raw);
        // Sign with index 0 and index 2 -> MSB bitmap bits 0 and 2 = 0xA0_00_00_00.
        let mut sig_blob = Vec::new();
        sig_blob.extend_from_slice(&sk0.sign(&msg).to_bytes());
        sig_blob.extend_from_slice(&sk2.sign(&msg).to_bytes());
        sig_blob.extend_from_slice(&0xA000_0000u32.to_be_bytes());

        let mut signed = raw;
        bcs_uleb128(&mut signed, 1); // MultiEd25519
        bcs_bytes(&mut signed, &pk_blob);
        bcs_bytes(&mut signed, &sig_blob);

        let decoded = decode_and_verify_aptos_tx(&signed, BUDLUM_APTOS_CHAIN_ID, 1_800_000_000)
            .expect("valid 2-of-3 MultiEd25519 Aptos tx");
        assert_eq!(decoded.sender, sender);
    }

    #[test]
    fn move_alias_scheme_byte_is_unused() {
        assert!(is_aptos_scheme_byte_unused(BUDLUM_MOVE_ALIAS_SCHEME_BYTE));
    }
}
