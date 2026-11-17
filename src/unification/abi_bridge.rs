//! Cross-VM and multi-language canonical call envelope bridge (`S-3`, `D-1`, `D-3`).
//!
//! Enables a contract or actor in any source domain and execution language
//! (Solidity/Vyper on EVM, Move on Aptos/Sui, Rust on Solana SVM/CosmWasm/NEAR,
//! Cairo on Starknet, Bitcoin Script, FunC/Tact on TON, Aiken/Plutus on
//! Cardano, RISC-V, and `BudZero`) to formulate a deterministic, verified call
//! envelope targeting any other executable domain without mutating either
//! chain's consensus rules or virtual machine semantics.
//!
//! WIRING: wired through `src/unification/mod.rs` and the read-only JSON-RPC
//! door `bud_encodeCrossVmCall` in `src/rpc/api.rs` and `src/rpc/server.rs`.

use crate::domain::types::{DomainId, Hash32};
use crate::unification::domain_catalog::UniversalDomainCatalog;
use crate::unification::output_composer::{CanonicalValue, LanguageTag};
use crate::unification::{hash_domain_fields, validate_safe_label};
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeSet;

/// Maximum number of typed arguments accepted in a single cross-VM call.
pub const MAX_CROSS_VM_ARGS: usize = 32;

/// Maximum length of a single argument's name in bytes.
pub const MAX_CROSS_VM_ARG_NAME_LEN: usize = 64;

/// Maximum byte length of a single argument payload.
pub const MAX_CROSS_VM_ARG_BYTES: usize = 16 * 1024;

/// Maximum byte length of a target method or entrypoint identifier.
pub const MAX_CROSS_VM_METHOD_LEN: usize = 128;

/// Maximum encoded target payload size in bytes (64 KiB).
pub const MAX_CROSS_VM_PAYLOAD_BYTES: usize = 64 * 1024;

/// Target wire layout projected for the destination execution environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetWireEncoding {
    /// 4-byte method selector + 32-byte big-endian ABI-aligned argument words (EVM / Solidity / Vyper).
    EvmAbi32,
    /// Little-endian length-prefixed binary layout for Solana SVM / NEAR / Rust entrypoints.
    BorshLe,
    /// Little-endian ULEB128-length binary layout for MoveVM (Aptos / Sui).
    BcsLe,
    /// Canonical sorted JSON object payload for CosmWasm / JSON-ABI domains.
    JsonCanonical,
    /// Domain-separated raw length-prefixed binary payload for UTXO / Cairo / TVM / Plutus / `BudZero`.
    RawCanonical,
}

impl TargetWireEncoding {
    /// Selects the canonical native wire encoding for a target execution environment byte.
    #[must_use]
    pub const fn for_ee(ee_id: u8) -> Self {
        match ee_id {
            x if x == EeId::EVM.0 => Self::EvmAbi32,
            x if x == EeId::SVM.0 || x == EeId::NEAR_WASM.0 || x == EeId::POLKAVM.0 => {
                Self::BorshLe
            }
            x if x == EeId::MOVE.0 || x == EeId::MOVE_SUI.0 => Self::BcsLe,
            x if x == EeId::WASM.0 => Self::JsonCanonical,
            _ => Self::RawCanonical,
        }
    }

    /// Stable wire tag string folded into the envelope commitment.
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::EvmAbi32 => "evm_abi32",
            Self::BorshLe => "borsh_le",
            Self::BcsLe => "bcs_le",
            Self::JsonCanonical => "json_canonical",
            Self::RawCanonical => "raw_canonical",
        }
    }
}

/// One named typed argument in a cross-VM call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalCallArg {
    pub name: String,
    pub value: CanonicalValue,
}

/// Input describing a cross-VM call before validation and wire projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossVmCallRequest {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_language: LanguageTag,
    pub target_language: LanguageTag,
    pub method: String,
    pub args: Vec<CanonicalCallArg>,
    /// Optional explicit wire encoding override; when `None`, inferred from the
    /// target domain's registered execution environment.
    #[serde(default)]
    pub encoding_override: Option<TargetWireEncoding>,
    /// Caller-supplied monotonic nonce preventing cross-call replay.
    pub nonce: u64,
}

/// Deterministic, cryptographically committed cross-VM call envelope ready for
/// target-domain dispatch without modifying either chain's inner rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossVmCallEnvelope {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_ee_id: u8,
    pub target_ee_id: u8,
    pub source_language: LanguageTag,
    pub target_language: LanguageTag,
    pub method: String,
    pub args: Vec<CanonicalCallArg>,
    pub target_encoding: TargetWireEncoding,
    pub nonce: u64,
    pub encoded_payload: Vec<u8>,
    pub envelope_hash: Hash32,
}

/// Errors returned while validating, encoding, or verifying a cross-VM call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AbiBridgeError {
    #[error("unknown domain id {0}")]
    UnknownDomain(DomainId),
    #[error("domain id {0} does not expose an execution environment")]
    DomainNotExecutable(DomainId),
    #[error("invalid cross-VM method: {0}")]
    InvalidMethod(String),
    #[error("invalid cross-VM argument: {0}")]
    InvalidArg(String),
    #[error("too many arguments ({0} > {MAX_CROSS_VM_ARGS})")]
    TooManyArgs(usize),
    #[error("duplicate argument name: {0}")]
    DuplicateArgName(String),
    #[error("encoded payload too large ({0} > {MAX_CROSS_VM_PAYLOAD_BYTES})")]
    PayloadTooLarge(usize),
    #[error("cross-VM envelope hash or payload integrity mismatch")]
    EnvelopeIntegrityMismatch,
}

/// Stateless canonical cross-VM ABI bridge.
pub struct CrossVmBridge;

impl CrossVmBridge {
    /// Validates `request` against `catalog`, projects its arguments into the
    /// target execution environment's native wire format, and commits to the
    /// complete envelope with a domain-separated SHA3-256 hash.
    ///
    /// # Errors
    ///
    /// Returns [`AbiBridgeError`] when either domain is unknown or
    /// non-executable, arguments violate bounds, or the projected payload
    /// exceeds [`MAX_CROSS_VM_PAYLOAD_BYTES`].
    pub fn encode_call(
        catalog: &UniversalDomainCatalog,
        request: &CrossVmCallRequest,
    ) -> Result<CrossVmCallEnvelope, AbiBridgeError> {
        let src = catalog
            .get(request.source_domain)
            .ok_or(AbiBridgeError::UnknownDomain(request.source_domain))?;
        let source_ee_id = src
            .execution_env_id
            .ok_or(AbiBridgeError::DomainNotExecutable(request.source_domain))?;
        let dst = catalog
            .get(request.target_domain)
            .ok_or(AbiBridgeError::UnknownDomain(request.target_domain))?;
        let target_ee_id = dst
            .execution_env_id
            .ok_or(AbiBridgeError::DomainNotExecutable(request.target_domain))?;

        validate_method_name(&request.method)?;
        validate_args(&request.args)?;

        let target_encoding = request
            .encoding_override
            .unwrap_or_else(|| TargetWireEncoding::for_ee(target_ee_id));
        let encoded_payload =
            project_wire_payload(target_encoding, &request.method, &request.args)?;
        let envelope_hash = compute_envelope_hash(&EnvelopeHashInput {
            source_domain: request.source_domain,
            target_domain: request.target_domain,
            source_ee_id,
            target_ee_id,
            source_language: &request.source_language,
            target_language: &request.target_language,
            method: &request.method,
            target_encoding,
            nonce: request.nonce,
            encoded_payload: &encoded_payload,
        });

        Ok(CrossVmCallEnvelope {
            source_domain: request.source_domain,
            target_domain: request.target_domain,
            source_ee_id,
            target_ee_id,
            source_language: request.source_language.clone(),
            target_language: request.target_language.clone(),
            method: request.method.clone(),
            args: request.args.clone(),
            target_encoding,
            nonce: request.nonce,
            encoded_payload,
            envelope_hash,
        })
    }

    /// Independently re-validates a [`CrossVmCallEnvelope`], re-projects its
    /// target wire payload, and verifies its canonical `envelope_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`AbiBridgeError`] if any field is malformed or tampered with.
    pub fn verify_envelope(envelope: &CrossVmCallEnvelope) -> Result<(), AbiBridgeError> {
        validate_method_name(&envelope.method)?;
        validate_args(&envelope.args)?;
        let expected_payload =
            project_wire_payload(envelope.target_encoding, &envelope.method, &envelope.args)?;
        if expected_payload != envelope.encoded_payload {
            return Err(AbiBridgeError::EnvelopeIntegrityMismatch);
        }
        let expected_hash = compute_envelope_hash(&EnvelopeHashInput {
            source_domain: envelope.source_domain,
            target_domain: envelope.target_domain,
            source_ee_id: envelope.source_ee_id,
            target_ee_id: envelope.target_ee_id,
            source_language: &envelope.source_language,
            target_language: &envelope.target_language,
            method: &envelope.method,
            target_encoding: envelope.target_encoding,
            nonce: envelope.nonce,
            encoded_payload: &expected_payload,
        });
        if expected_hash != envelope.envelope_hash {
            return Err(AbiBridgeError::EnvelopeIntegrityMismatch);
        }
        Ok(())
    }
}

fn validate_method_name(method: &str) -> Result<(), AbiBridgeError> {
    validate_safe_label("method", method, MAX_CROSS_VM_METHOD_LEN)
        .map_err(AbiBridgeError::InvalidMethod)?;
    if !method
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'))
    {
        return Err(AbiBridgeError::InvalidMethod(String::from(
            "method may only contain ASCII alphanumeric, '_', ':', '.', or '-'",
        )));
    }
    Ok(())
}

fn validate_args(args: &[CanonicalCallArg]) -> Result<(), AbiBridgeError> {
    if args.len() > MAX_CROSS_VM_ARGS {
        return Err(AbiBridgeError::TooManyArgs(args.len()));
    }
    let mut seen = BTreeSet::new();
    for arg in args {
        validate_safe_label("arg.name", &arg.name, MAX_CROSS_VM_ARG_NAME_LEN)
            .map_err(AbiBridgeError::InvalidArg)?;
        if !seen.insert(arg.name.as_str()) {
            return Err(AbiBridgeError::DuplicateArgName(arg.name.clone()));
        }
        if arg.value.byte_len() > MAX_CROSS_VM_ARG_BYTES {
            return Err(AbiBridgeError::InvalidArg(format!(
                "argument '{}' exceeds {MAX_CROSS_VM_ARG_BYTES}-byte limit",
                arg.name
            )));
        }
    }
    Ok(())
}

fn project_wire_payload(
    encoding: TargetWireEncoding,
    method: &str,
    args: &[CanonicalCallArg],
) -> Result<Vec<u8>, AbiBridgeError> {
    let payload = match encoding {
        TargetWireEncoding::EvmAbi32 => encode_evm_abi32(method, args),
        TargetWireEncoding::BorshLe => encode_borsh_le(method, args),
        TargetWireEncoding::BcsLe => encode_bcs_le(method, args),
        TargetWireEncoding::JsonCanonical => encode_json_canonical(method, args)?,
        TargetWireEncoding::RawCanonical => encode_raw_canonical(method, args),
    };
    if payload.len() > MAX_CROSS_VM_PAYLOAD_BYTES {
        return Err(AbiBridgeError::PayloadTooLarge(payload.len()));
    }
    Ok(payload)
}

fn push_abi_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len_word = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&len_word.to_be_bytes());
    out.extend_from_slice(&word);
    out.extend_from_slice(bytes);
    let rem = bytes.len() % 32;
    if rem != 0 {
        out.resize(out.len().saturating_add(32 - rem), 0);
    }
}

fn encode_evm_abi32(method: &str, args: &[CanonicalCallArg]) -> Vec<u8> {
    let mut selector_hasher = Sha3_256::new();
    selector_hasher.update(b"BDLM_EVM_SELECTOR_V1");
    selector_hasher.update(method.as_bytes());
    let digest: [u8; 32] = selector_hasher.finalize().into();

    let mut out = Vec::with_capacity(4 + args.len().saturating_mul(32));
    out.extend_from_slice(&digest[..4]);
    for arg in args {
        match &arg.value {
            CanonicalValue::Bool(b) => {
                let mut word = [0u8; 32];
                word[31] = u8::from(*b);
                out.extend_from_slice(&word);
            }
            CanonicalValue::U64(v) => {
                let mut word = [0u8; 32];
                word[24..].copy_from_slice(&v.to_be_bytes());
                out.extend_from_slice(&word);
            }
            CanonicalValue::U128(v) => {
                let mut word = [0u8; 32];
                word[16..].copy_from_slice(&v.to_be_bytes());
                out.extend_from_slice(&word);
            }
            CanonicalValue::I128(v) => {
                let fill = if *v < 0 { 0xFF } else { 0x00 };
                let mut word = [fill; 32];
                word[16..].copy_from_slice(&v.to_be_bytes());
                out.extend_from_slice(&word);
            }
            CanonicalValue::Bytes32(h) => out.extend_from_slice(h),
            CanonicalValue::Bytes(b) => push_abi_bytes(&mut out, b),
            CanonicalValue::Text(s) => push_abi_bytes(&mut out, s.as_bytes()),
            CanonicalValue::Address { ee_id, raw } => {
                let mut tag_word = [0u8; 32];
                tag_word[31] = *ee_id;
                out.extend_from_slice(&tag_word);
                push_abi_bytes(&mut out, raw);
            }
            CanonicalValue::AssetAmount { asset_id, amount } => {
                out.extend_from_slice(asset_id);
                let mut word = [0u8; 32];
                word[16..].copy_from_slice(&amount.to_be_bytes());
                out.extend_from_slice(&word);
            }
        }
    }
    out
}

fn encode_borsh_le(method: &str, args: &[CanonicalCallArg]) -> Vec<u8> {
    let mut out = Vec::new();
    let method_len = u32::try_from(method.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&method_len.to_le_bytes());
    out.extend_from_slice(method.as_bytes());
    let count = u32::try_from(args.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for arg in args {
        match &arg.value {
            CanonicalValue::Bool(b) => {
                out.push(0x01);
                out.push(u8::from(*b));
            }
            CanonicalValue::U64(v) => {
                out.push(0x02);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::U128(v) => {
                out.push(0x03);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::I128(v) => {
                out.push(0x04);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::Bytes32(h) => {
                out.push(0x05);
                out.extend_from_slice(h);
            }
            CanonicalValue::Bytes(b) => {
                out.push(0x06);
                let l = u32::try_from(b.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(b);
            }
            CanonicalValue::Text(s) => {
                out.push(0x07);
                let l = u32::try_from(s.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            CanonicalValue::Address { ee_id, raw } => {
                out.push(0x08);
                out.push(*ee_id);
                let l = u32::try_from(raw.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(raw);
            }
            CanonicalValue::AssetAmount { asset_id, amount } => {
                out.push(0x09);
                out.extend_from_slice(asset_id);
                out.extend_from_slice(&amount.to_le_bytes());
            }
        }
    }
    out
}

fn push_uleb128(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn encode_bcs_le(method: &str, args: &[CanonicalCallArg]) -> Vec<u8> {
    let mut out = Vec::new();
    push_uleb128(&mut out, method.len());
    out.extend_from_slice(method.as_bytes());
    push_uleb128(&mut out, args.len());
    for arg in args {
        match &arg.value {
            CanonicalValue::Bool(b) => {
                out.push(0x01);
                out.push(u8::from(*b));
            }
            CanonicalValue::U64(v) => {
                out.push(0x02);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::U128(v) => {
                out.push(0x03);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::I128(v) => {
                out.push(0x04);
                out.extend_from_slice(&v.to_le_bytes());
            }
            CanonicalValue::Bytes32(h) => {
                out.push(0x05);
                out.extend_from_slice(h);
            }
            CanonicalValue::Bytes(b) => {
                out.push(0x06);
                push_uleb128(&mut out, b.len());
                out.extend_from_slice(b);
            }
            CanonicalValue::Text(s) => {
                out.push(0x07);
                push_uleb128(&mut out, s.len());
                out.extend_from_slice(s.as_bytes());
            }
            CanonicalValue::Address { ee_id, raw } => {
                out.push(0x08);
                out.push(*ee_id);
                push_uleb128(&mut out, raw.len());
                out.extend_from_slice(raw);
            }
            CanonicalValue::AssetAmount { asset_id, amount } => {
                out.push(0x09);
                out.extend_from_slice(asset_id);
                out.extend_from_slice(&amount.to_le_bytes());
            }
        }
    }
    out
}

fn encode_json_canonical(
    method: &str,
    args: &[CanonicalCallArg],
) -> Result<Vec<u8>, AbiBridgeError> {
    let mut arg_map = serde_json::Map::new();
    let mut sorted: Vec<&CanonicalCallArg> = args.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for arg in sorted {
        let json_val = match &arg.value {
            CanonicalValue::Bool(b) => serde_json::Value::Bool(*b),
            CanonicalValue::U64(v) => serde_json::Value::String(v.to_string()),
            CanonicalValue::U128(v) => serde_json::Value::String(v.to_string()),
            CanonicalValue::I128(v) => serde_json::Value::String(v.to_string()),
            CanonicalValue::Bytes32(h) => {
                serde_json::Value::String(format!("0x{}", hex::encode(h)))
            }
            CanonicalValue::Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
            CanonicalValue::Text(s) => serde_json::Value::String(s.clone()),
            CanonicalValue::Address { ee_id, raw } => serde_json::json!({
                "ee_id": ee_id,
                "raw": format!("0x{}", hex::encode(raw)),
            }),
            CanonicalValue::AssetAmount { asset_id, amount } => serde_json::json!({
                "amount": amount.to_string(),
                "asset_id": format!("0x{}", hex::encode(asset_id)),
            }),
        };
        arg_map.insert(arg.name.clone(), json_val);
    }
    let mut root = serde_json::Map::new();
    root.insert(String::from("args"), serde_json::Value::Object(arg_map));
    root.insert(
        String::from("method"),
        serde_json::Value::String(String::from(method)),
    );
    serde_json::to_vec(&serde_json::Value::Object(root))
        .map_err(|e| AbiBridgeError::InvalidArg(e.to_string()))
}

fn encode_raw_canonical(method: &str, args: &[CanonicalCallArg]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"BDLM_RAW_CALL_V1");
    let mlen = u32::try_from(method.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&mlen.to_le_bytes());
    out.extend_from_slice(method.as_bytes());
    let alen = u32::try_from(args.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&alen.to_le_bytes());
    for arg in args {
        let nlen = u32::try_from(arg.name.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(arg.name.as_bytes());
        let commitment = arg.value.commitment_hash();
        out.extend_from_slice(&commitment);
    }
    out
}

struct EnvelopeHashInput<'a> {
    source_domain: DomainId,
    target_domain: DomainId,
    source_ee_id: u8,
    target_ee_id: u8,
    source_language: &'a LanguageTag,
    target_language: &'a LanguageTag,
    method: &'a str,
    target_encoding: TargetWireEncoding,
    nonce: u64,
    encoded_payload: &'a [u8],
}

fn compute_envelope_hash(input: &EnvelopeHashInput<'_>) -> Hash32 {
    let src_d = input.source_domain.to_le_bytes();
    let dst_d = input.target_domain.to_le_bytes();
    let ee_pair = [input.source_ee_id, input.target_ee_id];
    let src_lang = input.source_language.encode_bytes();
    let dst_lang = input.target_language.encode_bytes();
    let nonce_bytes = input.nonce.to_le_bytes();
    hash_domain_fields(
        b"BDLM_UNIF_CROSS_VM_CALL_V1",
        &[
            &src_d,
            &dst_d,
            &ee_pair,
            &src_lang,
            &dst_lang,
            input.method.as_bytes(),
            input.target_encoding.as_tag().as_bytes(),
            &nonce_bytes,
            input.encoded_payload,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_verifies_cross_vm_calls_across_evm_move_svm_and_cosmwasm() {
        let catalog = UniversalDomainCatalog::with_canonical_ecosystems();

        // Ethereum (domain 3, EVM) -> Sui (domain 7, Move) automatically uses BCS wire layout.
        let evm_to_move = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 7,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::Move,
                method: String::from("dex::settle_swap"),
                args: vec![
                    CanonicalCallArg {
                        name: String::from("amount_in"),
                        value: CanonicalValue::U128(1_500_000),
                    },
                    CanonicalCallArg {
                        name: String::from("recipient"),
                        value: CanonicalValue::Address {
                            ee_id: EeId::MOVE_SUI.0,
                            raw: vec![0xAB; 32],
                        },
                    },
                ],
                encoding_override: None,
                nonce: 42,
            },
        )
        .expect("EVM -> MoveVM call encodes cleanly");
        assert_eq!(evm_to_move.target_encoding, TargetWireEncoding::BcsLe);
        CrossVmBridge::verify_envelope(&evm_to_move).expect("envelope verifies cleanly");

        // Solana (domain 4, SVM) -> Ethereum (domain 3, EVM) uses 32-byte ABI layout.
        let svm_to_evm = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 4,
                target_domain: 3,
                source_language: LanguageTag::RustSvm,
                target_language: LanguageTag::Solidity,
                method: String::from("releaseEscrow"),
                args: vec![CanonicalCallArg {
                    name: String::from("ok"),
                    value: CanonicalValue::Bool(true),
                }],
                encoding_override: None,
                nonce: 7,
            },
        )
        .expect("SVM -> EVM call encodes cleanly");
        assert_eq!(svm_to_evm.target_encoding, TargetWireEncoding::EvmAbi32);
        assert_eq!(svm_to_evm.encoded_payload.len(), 4 + 32);
        CrossVmBridge::verify_envelope(&svm_to_evm).expect("EVM envelope verifies");

        // Cosmos Hub (domain 5, CosmWasm) uses deterministic sorted JSON canonical encoding.
        let eth_to_cosmos = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 5,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::RustCosmWasm,
                method: String::from("ibc_settle"),
                args: vec![
                    CanonicalCallArg {
                        name: String::from("zeta"),
                        value: CanonicalValue::U64(9),
                    },
                    CanonicalCallArg {
                        name: String::from("alpha"),
                        value: CanonicalValue::Text(String::from("budlum")),
                    },
                ],
                encoding_override: None,
                nonce: 99,
            },
        )
        .expect("EVM -> CosmWasm call encodes cleanly");
        assert_eq!(
            eth_to_cosmos.target_encoding,
            TargetWireEncoding::JsonCanonical
        );
        let json_str = std::str::from_utf8(&eth_to_cosmos.encoded_payload).expect("valid utf8");
        assert!(json_str.find("\"alpha\"").unwrap() < json_str.find("\"zeta\"").unwrap());
        CrossVmBridge::verify_envelope(&eth_to_cosmos).expect("CosmWasm envelope verifies");

        // Tampering with payload or hash must fail verification.
        let mut tampered = svm_to_evm.clone();
        tampered.encoded_payload[4] ^= 0xFF;
        assert_eq!(
            CrossVmBridge::verify_envelope(&tampered),
            Err(AbiBridgeError::EnvelopeIntegrityMismatch)
        );
    }

    #[test]
    fn refuses_unknown_non_executable_bad_methods_duplicate_args_and_oversized_values() {
        let catalog = UniversalDomainCatalog::with_canonical_ecosystems();

        // Unknown target domain
        let err = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 99_999,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::Move,
                method: String::from("transfer"),
                args: Vec::new(),
                encoding_override: None,
                nonce: 1,
            },
        )
        .unwrap_err();
        assert_eq!(err, AbiBridgeError::UnknownDomain(99_999));

        // Pure storage domain (15 = IPFS) is not directly executable
        let err = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 15,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::RustCosmWasm,
                method: String::from("pin"),
                args: Vec::new(),
                encoding_override: None,
                nonce: 1,
            },
        )
        .unwrap_err();
        assert_eq!(err, AbiBridgeError::DomainNotExecutable(15));

        // Shell-injection-like method rejected
        let err = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 7,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::Move,
                method: String::from("transfer;rm -rf /"),
                args: Vec::new(),
                encoding_override: None,
                nonce: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(err, AbiBridgeError::InvalidMethod(_)));

        // Duplicate argument name rejected
        let err = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 5,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::RustCosmWasm,
                method: String::from("execute_swap"),
                args: vec![
                    CanonicalCallArg {
                        name: String::from("x"),
                        value: CanonicalValue::U128(1),
                    },
                    CanonicalCallArg {
                        name: String::from("x"),
                        value: CanonicalValue::U128(2),
                    },
                ],
                encoding_override: None,
                nonce: 2,
            },
        )
        .unwrap_err();
        assert_eq!(err, AbiBridgeError::DuplicateArgName(String::from("x")));

        // Oversized single argument rejected before projection
        let err = CrossVmBridge::encode_call(
            &catalog,
            &CrossVmCallRequest {
                source_domain: 3,
                target_domain: 7,
                source_language: LanguageTag::Solidity,
                target_language: LanguageTag::Move,
                method: String::from("upload"),
                args: vec![CanonicalCallArg {
                    name: String::from("blob"),
                    value: CanonicalValue::Bytes(vec![0u8; MAX_CROSS_VM_ARG_BYTES + 1]),
                }],
                encoding_override: None,
                nonce: 3,
            },
        )
        .unwrap_err();
        assert!(matches!(err, AbiBridgeError::InvalidArg(_)));
    }
}
