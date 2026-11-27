//! Pinned Aptos scheme-byte table, Move binary module verifier, and `0x1`
//! framework dispatch (Aptos leg).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};

use budlum_uel_abi::BlockContext;

/// Hard byte cap on a Move module binary payload (2 MiB) enforced before JSON decoding.
pub const MAX_MOVE_MODULE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum byte length of a Move resource tag or event type identifier.
pub const MAX_MOVE_TAG_LEN: usize = 256;

/// Maximum inline payload byte length for a Move instruction literal, event, or call input (1 MiB).
pub const MAX_MOVE_OP_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Maximum byte length of a cross-EE `UniversalCall` target address inside Move bytecode.
pub const MAX_MOVE_UNIVERSAL_TARGET_LEN: usize = 128;

/// Highest valid canonical UEL `EeId` discriminant (`EeId::RV32 = 0x0C`).
pub const MAX_MOVE_KNOWN_EE_ID: u8 = 0x0C;

/// Exact `aptos-labs/aptos-core` commit SHA audited for authentication-key scheme bytes
/// (`types/src/transaction/authenticator.rs`, `Scheme` enum) and recorded in `deny.toml`.
pub const APTOS_PINNED_COMMIT: &str = "81d89f428fe8e4b69d53b4916993e9a930afc37c";

/// Reserved Budlum Move local-alias authentication-key scheme byte (Section 8.4.2 rule 2).
pub const BUDLUM_MOVE_ALIAS_SCHEME_BYTE: u8 = 0xBD;

/// Complete list of `Scheme` discriminant bytes defined in pinned `aptos-core`
/// (`types/src/transaction/authenticator.rs`).
pub const APTOS_USED_SCHEME_BYTES: &[u8] = &[
    0x00, // Ed25519
    0x01, // MultiEd25519
    0x02, // SingleKey
    0x03, // MultiKey
    0x04, // Abstraction
    0x05, // DeriveDomainAbstraction
    0xFA, // NoScheme (250)
    0xFB, // DeriveAuid (251)
    0xFC, // DeriveObjectAddressFromObject (252)
    0xFD, // DeriveObjectAddressFromGuid (253)
    0xFE, // DeriveObjectAddressFromSeed (254)
    0xFF, // DeriveResourceAccountAddress (255)
];

/// Move binary module magic prefix (`0xA11CEB0B`).
pub const MOVE_MODULE_MAGIC: [u8; 4] = [0xA1, 0x1C, 0xEB, 0x0B];

/// Supported Move binary format versions (Aptos Move v5..=v7).
pub const MOVE_MIN_VERSION: u32 = 5;
pub const MOVE_MAX_VERSION: u32 = 7;

/// Framework address `0x0...01`.
pub const FRAMEWORK_ADDRESS: [u8; 32] = {
    let mut out = [0u8; 32];
    out[31] = 1;
    out
};

/// Disabled Aptos-specific governance and staking module names under `0x1`
/// (canonical Move block context specification).
pub const DISABLED_FRAMEWORK_MODULES: &[&str] = &[
    "aptos_governance",
    "delegation_pool",
    "governance_proposal",
    "stake",
    "staking_config",
    "staking_contract",
    "staking_proxy",
    "voting",
];

/// Returns `true` iff `scheme_byte` is unused by every authentication/derivation
/// scheme in the pinned `aptos-core` revision.
#[must_use]
pub fn is_scheme_byte_unused_in_pinned_aptos(scheme_byte: u8) -> bool {
    !APTOS_USED_SCHEME_BYTES.contains(&scheme_byte)
}

/// Derive the canonical 32-byte Move local alias `SHA3-256(local32 || 0xBD)`
/// (Section 8.4.2).
#[must_use]
pub fn derive_move_alias(local_address: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(local_address);
    h.update([BUDLUM_MOVE_ALIAS_SCHEME_BYTE]);
    h.finalize().into()
}

/// Returns `true` when `(address, module_name)` refers to a disabled Aptos
/// staking or governance module under `0x1`.
#[must_use]
pub fn is_disabled_framework_module(address: &[u8; 32], module_name: &str) -> bool {
    *address == FRAMEWORK_ADDRESS && DISABLED_FRAMEWORK_MODULES.contains(&module_name)
}

/// Deterministic Budlum epoch/block randomness seed bound to `0x1::randomness`
/// (canonical Move block context specification).
#[must_use]
pub fn derive_move_randomness(block: &BlockContext, caller: &[u8; 32], call_seq: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_MOVE_RANDOMNESS_V1");
    h.update(block.height.to_le_bytes());
    h.update(block.timestamp_ms.to_le_bytes());
    h.update(block.chain_id.to_le_bytes());
    h.update(caller);
    h.update(call_seq.to_le_bytes());
    h.finalize().into()
}

/// Portable Move module envelope validated at publish time and stored under `ee/move/state`.
///
/// Modules begin with `MOVE_MODULE_MAGIC` (`0xA11CEB0B`), a `u32` LE version in `5..=7`,
/// followed by JSON/BCS-encoded [`CompiledMoveModule`] descriptors so both raw Move magic
/// headers and deterministic entry-function execution are verified without unsafe code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledMoveModule {
    pub address: [u8; 32],
    pub name: String,
    pub functions: Vec<MoveFunctionDef>,
}

/// Entry or view function definition inside a [`CompiledMoveModule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveFunctionDef {
    pub name: String,
    pub is_entry: bool,
    pub is_view: bool,
    pub code: Vec<MoveOp>,
}

/// Deterministic sequential Move VM bytecode instruction set (`Block-STM` disabled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveOp {
    /// Store literal bytes into a named resource under the signer's account.
    WriteResource {
        resource_tag: String,
        value: Vec<u8>,
    },
    /// Copy execution argument `arg_index` into `resource_tag` under the signer's account.
    WriteResourceFromArg {
        resource_tag: String,
        arg_index: usize,
    },
    /// Read `resource_tag` under `owner` (or signer when `None`) and push as return value.
    ReadResource {
        owner: Option<[u8; 32]>,
        resource_tag: String,
    },
    /// Transfer `octas` (`1 octa = 10^10 attoBUD`) from signer to `recipient`.
    TransferOctas { recipient: [u8; 32], octas: u64 },
    /// Invoke `0x1::budlum_universal::call` from Move into another UEL environment.
    UniversalCall {
        target_ee: u8,
        target: Vec<u8>,
        input: Vec<u8>,
        value_octas: u64,
        gas_bgu: u64,
    },
    /// Emit an indexed Move event under `event_type`.
    EmitEvent {
        event_type: String,
        payload: Vec<u8>,
    },
    /// Deterministically abort execution with an Aptos `u64` abort code.
    Abort { code: u64 },
    /// Push literal bytes to the function return values.
    ReturnConst { bytes: Vec<u8> },
}

/// Validate a Move resource tag or event type identifier: non-empty, bounded
/// in length, and restricted to visible non-whitespace ASCII (`0x21..=0x7E`)
/// so control characters or whitespace cannot collide with `ee/move/state` keys.
#[must_use]
pub fn is_valid_move_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_MOVE_TAG_LEN
        && tag.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

fn validate_move_op(op: &MoveOp, is_view: bool) -> Result<(), String> {
    if is_view {
        let mutates_state = match op {
            MoveOp::WriteResource { .. }
            | MoveOp::WriteResourceFromArg { .. }
            | MoveOp::TransferOctas { .. }
            | MoveOp::EmitEvent { .. } => true,
            MoveOp::UniversalCall { value_octas, .. } => *value_octas > 0,
            MoveOp::ReadResource { .. } | MoveOp::Abort { .. } | MoveOp::ReturnConst { .. } => {
                false
            }
        };
        if mutates_state {
            return Err("Move view function cannot contain state-mutating operations".to_string());
        }
    }

    match op {
        MoveOp::WriteResource {
            resource_tag,
            value,
        } => {
            if !is_valid_move_tag(resource_tag) {
                return Err(format!("invalid Move resource_tag '{resource_tag}'"));
            }
            if value.len() > MAX_MOVE_OP_PAYLOAD_BYTES {
                return Err("Move WriteResource value exceeds payload cap".to_string());
            }
        }
        MoveOp::WriteResourceFromArg { resource_tag, .. }
        | MoveOp::ReadResource { resource_tag, .. } => {
            if !is_valid_move_tag(resource_tag) {
                return Err(format!("invalid Move resource_tag '{resource_tag}'"));
            }
        }
        MoveOp::TransferOctas { recipient, octas } => {
            if *recipient == [0u8; 32] {
                return Err("Move TransferOctas recipient cannot be zero address".to_string());
            }
            if *octas == 0 {
                return Err("Move TransferOctas amount must be non-zero".to_string());
            }
        }
        MoveOp::UniversalCall {
            target_ee,
            target,
            input,
            gas_bgu,
            ..
        } => {
            if *target_ee > MAX_MOVE_KNOWN_EE_ID {
                return Err(format!("unknown Move UniversalCall target_ee {target_ee}"));
            }
            if target.is_empty() || target.len() > MAX_MOVE_UNIVERSAL_TARGET_LEN {
                return Err("Move UniversalCall target length out of bounds".to_string());
            }
            if input.len() > MAX_MOVE_OP_PAYLOAD_BYTES {
                return Err("Move UniversalCall input exceeds payload cap".to_string());
            }
            if *gas_bgu == 0 {
                return Err("Move UniversalCall gas_bgu must be non-zero".to_string());
            }
        }
        MoveOp::EmitEvent {
            event_type,
            payload,
        } => {
            if !is_valid_move_tag(event_type) {
                return Err(format!("invalid Move event_type '{event_type}'"));
            }
            if payload.len() > MAX_MOVE_OP_PAYLOAD_BYTES {
                return Err("Move EmitEvent payload exceeds payload cap".to_string());
            }
        }
        MoveOp::ReturnConst { bytes } => {
            if bytes.len() > MAX_MOVE_OP_PAYLOAD_BYTES {
                return Err("Move ReturnConst payload exceeds payload cap".to_string());
            }
        }
        MoveOp::Abort { .. } => {}
    }
    Ok(())
}

/// Encode a [`CompiledMoveModule`] with the canonical Move binary header
/// (`0xA11CEB0B` + version `7` LE + descriptor bytes).
pub fn encode_move_module(module: &CompiledMoveModule) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(module).map_err(|e| format!("module encode failed: {e}"))?;
    let total_len = 8usize.saturating_add(body.len());
    if total_len > MAX_MOVE_MODULE_BYTES {
        return Err(format!(
            "Move module encoded size {total_len} exceeds cap {MAX_MOVE_MODULE_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&MOVE_MODULE_MAGIC);
    out.extend_from_slice(&7u32.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Verify Move binary header (`0xA11CEB0B`, version `5..=7`), size cap,
/// publisher/address rules, unique function names, view-purity invariants,
/// disabled-framework guards, and instruction bounds.
pub fn verify_move_module_bytes(
    bytes: &[u8],
    expected_publisher: Option<&[u8; 32]>,
) -> Result<CompiledMoveModule, String> {
    if bytes.len() < 8 {
        return Err("Move module shorter than 8-byte binary header".to_string());
    }
    if bytes.len() > MAX_MOVE_MODULE_BYTES {
        return Err(format!(
            "Move module size {} exceeds cap {MAX_MOVE_MODULE_BYTES}",
            bytes.len()
        ));
    }
    if bytes.get(0..4) != Some(MOVE_MODULE_MAGIC.as_slice()) {
        return Err("invalid Move binary magic (expected 0xA11CEB0B)".to_string());
    }
    let ver_bytes: [u8; 4] = bytes
        .get(4..8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| "missing Move binary version".to_string())?;
    let version = u32::from_le_bytes(ver_bytes);
    if !(MOVE_MIN_VERSION..=MOVE_MAX_VERSION).contains(&version) {
        return Err(format!("unsupported Move bytecode version {version}"));
    }
    let body = bytes.get(8..).unwrap_or_default();
    let module: CompiledMoveModule = serde_json::from_slice(body)
        .map_err(|e| format!("Move module bytecode verification failed: {e}"))?;
    if module.address == [0u8; 32] {
        return Err("Move module address cannot be zero address".to_string());
    }
    if !is_valid_move_ident(&module.name) {
        return Err(format!("invalid Move module identifier '{}'", module.name));
    }
    if is_disabled_framework_module(&module.address, &module.name) {
        return Err(format!(
            "Aptos module 0x1::{} is disabled on Budlum",
            module.name
        ));
    }
    if let Some(publisher) = expected_publisher {
        if &module.address != publisher {
            return Err(format!(
                "Move module address 0x{} does not match publisher 0x{}",
                hex::encode(module.address),
                hex::encode(publisher)
            ));
        }
    }
    if module.functions.len() > 256 {
        return Err("Move module exceeds 256-function verification cap".to_string());
    }
    let mut seen_names = BTreeSet::new();
    for func in &module.functions {
        if !is_valid_move_ident(&func.name) {
            return Err(format!("invalid Move function identifier '{}'", func.name));
        }
        if !seen_names.insert(func.name.as_str()) {
            return Err(format!(
                "duplicate Move function identifier '{}'",
                func.name
            ));
        }
        if func.is_entry && func.is_view {
            return Err(format!(
                "Move function '{}' cannot be both entry and view",
                func.name
            ));
        }
        if func.code.len() > 4_096 {
            return Err(format!(
                "Move function '{}' exceeds 4096-instruction cap",
                func.name
            ));
        }
        for op in &func.code {
            validate_move_op(op, func.is_view)?;
        }
    }
    Ok(module)
}

#[must_use]
pub fn is_valid_move_ident(name: &str) -> bool {
    let Some(first) = name.bytes().next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') || name.len() > 128 {
        return false;
    }
    name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Minimal BCS helper encoding `(bool, vector<u8>)` for `0x1::budlum_universal::call`.
#[must_use]
pub fn bcs_encode_bool_and_bytes(ok: bool, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + data.len());
    out.push(u8::from(ok));
    bcs_push_uleb128(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    out
}

pub fn bcs_push_uleb128(out: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_module(functions: Vec<MoveFunctionDef>) -> CompiledMoveModule {
        CompiledMoveModule {
            address: [0x33u8; 32],
            name: "vault".to_string(),
            functions,
        }
    }

    #[test]
    fn red_verify_move_module_rejects_oversized_bytes() {
        let mut raw = Vec::with_capacity(2 * 1024 * 1024 + 64);
        raw.extend_from_slice(&MOVE_MODULE_MAGIC);
        raw.extend_from_slice(&7u32.to_le_bytes());
        raw.resize(2 * 1024 * 1024 + 32, b' ');
        let err = verify_move_module_bytes(&raw, None).unwrap_err();
        assert!(
            err.contains("exceeds") || err.contains("cap") || err.contains("size"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn red_verify_move_module_rejects_zero_address() {
        let m = CompiledMoveModule {
            address: [0u8; 32],
            name: "vault".to_string(),
            functions: Vec::new(),
        };
        let raw = encode_move_module(&m).unwrap();
        assert!(verify_move_module_bytes(&raw, None).is_err());
    }

    #[test]
    fn red_verify_move_module_rejects_duplicate_function_names() {
        let f = MoveFunctionDef {
            name: "dup".to_string(),
            is_entry: true,
            is_view: false,
            code: vec![MoveOp::ReturnConst { bytes: vec![1] }],
        };
        let m = sample_module(vec![f.clone(), f]);
        let raw = encode_move_module(&m).unwrap();
        assert!(verify_move_module_bytes(&raw, None).is_err());
    }

    #[test]
    fn red_verify_move_module_rejects_entry_and_view_together() {
        let m = sample_module(vec![MoveFunctionDef {
            name: "both".to_string(),
            is_entry: true,
            is_view: true,
            code: vec![MoveOp::ReturnConst { bytes: vec![1] }],
        }]);
        let raw = encode_move_module(&m).unwrap();
        assert!(verify_move_module_bytes(&raw, None).is_err());
    }

    #[test]
    fn red_verify_move_module_rejects_mutating_op_inside_view_function() {
        let mutating_ops = vec![
            MoveOp::WriteResource {
                resource_tag: "0x33::vault::State".to_string(),
                value: vec![1],
            },
            MoveOp::WriteResourceFromArg {
                resource_tag: "0x33::vault::State".to_string(),
                arg_index: 0,
            },
            MoveOp::TransferOctas {
                recipient: [0x44u8; 32],
                octas: 1,
            },
            MoveOp::EmitEvent {
                event_type: "0x33::vault::Evt".to_string(),
                payload: vec![1],
            },
            MoveOp::UniversalCall {
                target_ee: 0x01,
                target: vec![0xAA; 20],
                input: vec![],
                value_octas: 5,
                gas_bgu: 10_000,
            },
        ];
        for op in mutating_ops {
            let m = sample_module(vec![MoveFunctionDef {
                name: "sneaky_view".to_string(),
                is_entry: false,
                is_view: true,
                code: vec![op],
            }]);
            let raw = encode_move_module(&m).unwrap();
            assert!(
                verify_move_module_bytes(&raw, None).is_err(),
                "view function must reject state-mutating op"
            );
        }
    }

    #[test]
    fn red_verify_move_module_rejects_invalid_tags_transfers_and_universal_calls() {
        let bad_ops = vec![
            MoveOp::WriteResource {
                resource_tag: String::new(),
                value: vec![1],
            },
            MoveOp::ReadResource {
                owner: None,
                resource_tag: "bad\ntag".to_string(),
            },
            MoveOp::EmitEvent {
                event_type: "bad tag".to_string(),
                payload: vec![1],
            },
            MoveOp::TransferOctas {
                recipient: [0u8; 32],
                octas: 10,
            },
            MoveOp::TransferOctas {
                recipient: [0x44; 32],
                octas: 0,
            },
            MoveOp::UniversalCall {
                target_ee: 0xFF,
                target: vec![0xAA; 20],
                input: vec![],
                value_octas: 0,
                gas_bgu: 10_000,
            },
            MoveOp::UniversalCall {
                target_ee: 0x01,
                target: Vec::new(),
                input: vec![],
                value_octas: 0,
                gas_bgu: 10_000,
            },
            MoveOp::UniversalCall {
                target_ee: 0x01,
                target: vec![0xAA; 20],
                input: vec![],
                value_octas: 0,
                gas_bgu: 0,
            },
        ];
        for op in bad_ops {
            let m = sample_module(vec![MoveFunctionDef {
                name: "entry_fn".to_string(),
                is_entry: true,
                is_view: false,
                code: vec![op],
            }]);
            let raw = encode_move_module(&m).unwrap();
            assert!(verify_move_module_bytes(&raw, None).is_err());
        }
    }

    #[test]
    fn verify_move_module_accepts_valid_entry_and_pure_view_ops() {
        let m = sample_module(vec![
            MoveFunctionDef {
                name: "mutate".to_string(),
                is_entry: true,
                is_view: false,
                code: vec![
                    MoveOp::WriteResource {
                        resource_tag: "0x33::vault::State".to_string(),
                        value: vec![1, 2, 3],
                    },
                    MoveOp::TransferOctas {
                        recipient: [0x44u8; 32],
                        octas: 50,
                    },
                    MoveOp::EmitEvent {
                        event_type: "0x33::vault::Done".to_string(),
                        payload: vec![9],
                    },
                    MoveOp::UniversalCall {
                        target_ee: MAX_MOVE_KNOWN_EE_ID,
                        target: vec![0xAA; 20],
                        input: vec![0x01],
                        value_octas: 1,
                        gas_bgu: 10_000,
                    },
                ],
            },
            MoveFunctionDef {
                name: "inspect".to_string(),
                is_entry: false,
                is_view: true,
                code: vec![
                    MoveOp::ReadResource {
                        owner: None,
                        resource_tag: "0x33::vault::State".to_string(),
                    },
                    MoveOp::UniversalCall {
                        target_ee: 0x01,
                        target: vec![0xAA; 20],
                        input: vec![],
                        value_octas: 0,
                        gas_bgu: 5_000,
                    },
                    MoveOp::ReturnConst { bytes: vec![42] },
                    MoveOp::Abort { code: 7 },
                ],
            },
        ]);
        let raw = encode_move_module(&m).unwrap();
        assert_eq!(
            verify_move_module_bytes(&raw, Some(&[0x33u8; 32])).unwrap(),
            m
        );
    }

    #[test]
    fn verify_move_module_rejects_oversized_op_payloads_and_tags() {
        let long_tag = "a".repeat(MAX_MOVE_TAG_LEN + 1);
        assert!(!is_valid_move_tag(&long_tag));
        assert!(is_valid_move_tag(&"a".repeat(MAX_MOVE_TAG_LEN)));

        let oversized_target = sample_module(vec![MoveFunctionDef {
            name: "bad_target".to_string(),
            is_entry: true,
            is_view: false,
            code: vec![MoveOp::UniversalCall {
                target_ee: 0x01,
                target: vec![0xAA; MAX_MOVE_UNIVERSAL_TARGET_LEN + 1],
                input: vec![],
                value_octas: 0,
                gas_bgu: 10_000,
            }],
        }]);
        let raw_t = encode_move_module(&oversized_target).unwrap();
        assert!(verify_move_module_bytes(&raw_t, None).is_err());

        let huge_const = sample_module(vec![MoveFunctionDef {
            name: "huge_const".to_string(),
            is_entry: true,
            is_view: false,
            code: vec![MoveOp::ReturnConst {
                bytes: vec![1u8; MAX_MOVE_OP_PAYLOAD_BYTES + 1],
            }],
        }]);
        assert!(encode_move_module(&huge_const).is_err());
    }
}
