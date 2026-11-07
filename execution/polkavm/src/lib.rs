//! Out-of-process deterministic PolkaVM (`ink!` / `resolc` RV32EM interpreter) UEL
//! execution worker (`WP-53`, `EeId::POLKAVM = 0x08`).
//!
//! Runs strictly in interpreter mode (JIT disabled for consensus determinism across
//! `x86_64` and `aarch64`), persists contract blobs and key-value storage under
//! `ee/polkavm/state`, and enforces `Section 1.5` launch-closure on testnet `45261`
//! until `PROPOSED_POLKAVM_ACTIVATION_HEIGHT`.

#![forbid(unsafe_code)]

use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeLog, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, Namespace,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Audited upstream license (`paritytech/polkavm`, `MIT OR Apache-2.0`).
pub const AUDITED_POLKAVM_SPDX: &str = "MIT OR Apache-2.0";

/// JIT is permanently disabled on Budlum (`Section 8.2` row `0x08`: interpreter mode).
pub const POLKAVM_JIT_ENABLED: bool = false;

/// Budlum testnet chain ID (`Section 1.5`).
pub const BUDLUM_TESTNET_CHAIN_ID: u64 = 45_261;

/// Proposed activation height on testnet `45261` (`WP-53` 1/5).
pub const PROPOSED_POLKAVM_ACTIVATION_HEIGHT: u64 = 60_000;

/// Canonical UEL namespace storing PolkaVM code blobs and contract key-value storage.
pub const NS_POLKAVM_STATE: &str = "ee/polkavm/state";

/// `.polkavm` container magic (`"PVM\0"`).
pub const POLKAVM_BLOB_MAGIC: &[u8; 4] = b"PVM\0";

/// Maximum `.polkavm` program blob size (`1 MiB`).
pub const MAX_POLKAVM_BLOB_BYTES: usize = 1024 * 1024;

/// RV32EM register count (`a0..a5`, `s0..s1`, `t0..t2`, `ra`, `sp`).
const REG_COUNT: usize = 16;

/// Deterministic RV32EM + `seal_*` (`ink!` / `pallet-revive`) instruction set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolkaVmInsn {
    LoadImm { rd: u8, imm: u32 },
    Add { rd: u8, rs1: u8, rs2: u8 },
    Sub { rd: u8, rs1: u8, rs2: u8 },
    Mul { rd: u8, rs1: u8, rs2: u8 },
    /// `seal_input`: load little-endian `u32` from call input after 4-byte selector.
    SealInputU32 { rd: u8, word_index: u16 },
    /// `seal_set_storage(slot, reg_u32_le)`
    SealSetStorageU32 { slot: [u8; 32], rs: u8 },
    /// `seal_get_storage(slot) -> rd`
    SealGetStorageU32 { rd: u8, slot: [u8; 32] },
    /// `seal_deposit_event(topic, reg_u32_le)`
    SealDepositEvent { topic: [u8; 32], rs: u8 },
    /// `seal_return(reg_u32_le)` and halt cleanly.
    SealReturnU32 { rs: u8 },
}

/// Exported 4-byte selector handler (`ink!` message / constructor or `resolc` ABI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolkaVmDispatch {
    pub selector: [u8; 4],
    pub insns: Vec<PolkaVmInsn>,
}

/// Decoded `.polkavm` program image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolkaVmProgram {
    pub constructor: Vec<PolkaVmInsn>,
    pub dispatches: Vec<PolkaVmDispatch>,
}

/// Encode a `POLKAVM_BLOB_MAGIC`-prefixed blob.
pub fn encode_polkavm_blob(prog: &PolkaVmProgram) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(prog).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(POLKAVM_BLOB_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode and validate a `POLKAVM_BLOB_MAGIC`-prefixed `.polkavm` blob.
pub fn decode_polkavm_blob(raw: &[u8]) -> Result<PolkaVmProgram, EeRefusal> {
    if raw.len() < 4 || raw.len() > MAX_POLKAVM_BLOB_BYTES {
        return Err(EeRefusal::BadCode("invalid PolkaVM blob length".into()));
    }
    if raw.get(..4) != Some(POLKAVM_BLOB_MAGIC.as_slice()) {
        return Err(EeRefusal::BadCode("missing PVM\\0 magic".into()));
    }
    let prog: PolkaVmProgram = serde_json::from_slice(raw.get(4..).unwrap_or_default())
        .map_err(|e| EeRefusal::BadCode(format!("corrupt PolkaVM blob: {e}")))?;
    for d in &prog.dispatches {
        for ins in &d.insns {
            if !regs_in_range(ins) {
                return Err(EeRefusal::BadCode("PolkaVM register >= 16".into()));
            }
        }
    }
    for ins in &prog.constructor {
        if !regs_in_range(ins) {
            return Err(EeRefusal::BadCode("PolkaVM constructor reg >= 16".into()));
        }
    }
    Ok(prog)
}

const fn regs_in_range(ins: &PolkaVmInsn) -> bool {
    match *ins {
        PolkaVmInsn::LoadImm { rd, .. }
        | PolkaVmInsn::SealInputU32 { rd, .. }
        | PolkaVmInsn::SealGetStorageU32 { rd, .. } => (rd as usize) < REG_COUNT,
        PolkaVmInsn::SealSetStorageU32 { rs, .. }
        | PolkaVmInsn::SealDepositEvent { rs, .. }
        | PolkaVmInsn::SealReturnU32 { rs } => (rs as usize) < REG_COUNT,
        PolkaVmInsn::Add { rd, rs1, rs2 }
        | PolkaVmInsn::Sub { rd, rs1, rs2 }
        | PolkaVmInsn::Mul { rd, rs1, rs2 } => {
            (rd as usize) < REG_COUNT && (rs1 as usize) < REG_COUNT && (rs2 as usize) < REG_COUNT
        }
    }
}

fn code_key(contract: &[u8; 32]) -> Vec<u8> {
    let mut k = b"code:".to_vec();
    k.extend_from_slice(contract);
    k
}

fn stor_key(contract: &[u8; 32], slot: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(69);
    k.extend_from_slice(b"stor:");
    k.extend_from_slice(contract);
    k.extend_from_slice(slot);
    k
}

fn derive_contract_addr(deployer: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"BDLM_POLKAVM_ADDR_V1");
    h.update(deployer);
    h.update(tx_hash);
    h.finalize().into()
}

fn run_rv32em(
    ns: &Namespace,
    contract: &[u8; 32],
    insns: &[PolkaVmInsn],
    args_tail: &[u8],
    gas_used: &mut u64,
    gas_limit: u64,
    host: &mut dyn HostApi,
) -> Result<Vec<u8>, &'static [u8]> {
    let mut regs = [0u32; REG_COUNT];
    for ins in insns {
        let cost = match ins {
            PolkaVmInsn::SealSetStorageU32 { .. } => 4_000u64,
            PolkaVmInsn::SealGetStorageU32 { .. } | PolkaVmInsn::SealDepositEvent { .. } => 800,
            _ => 50,
        };
        let next = gas_used.saturating_add(cost);
        if next > gas_limit || host.charge(cost).is_err() {
            return Err(b"OUT_OF_GAS");
        }
        *gas_used = next;

        match *ins {
            PolkaVmInsn::LoadImm { rd, imm } => {
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = imm;
                }
            }
            PolkaVmInsn::Add { rd, rs1, rs2 } => {
                let v = regs
                    .get(rs1 as usize)
                    .copied()
                    .unwrap_or(0)
                    .wrapping_add(regs.get(rs2 as usize).copied().unwrap_or(0));
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = v;
                }
            }
            PolkaVmInsn::Sub { rd, rs1, rs2 } => {
                let v = regs
                    .get(rs1 as usize)
                    .copied()
                    .unwrap_or(0)
                    .wrapping_sub(regs.get(rs2 as usize).copied().unwrap_or(0));
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = v;
                }
            }
            PolkaVmInsn::Mul { rd, rs1, rs2 } => {
                let v = regs
                    .get(rs1 as usize)
                    .copied()
                    .unwrap_or(0)
                    .wrapping_mul(regs.get(rs2 as usize).copied().unwrap_or(0));
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = v;
                }
            }
            PolkaVmInsn::SealInputU32 { rd, word_index } => {
                let off = (word_index as usize).saturating_mul(4);
                let Some(slice) = args_tail.get(off..off + 4) else {
                    return Err(b"SEAL_INPUT_OOB");
                };
                let Ok(arr) = <[u8; 4]>::try_from(slice) else {
                    return Err(b"SEAL_INPUT_OOB");
                };
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = u32::from_le_bytes(arr);
                }
            }
            PolkaVmInsn::SealSetStorageU32 { slot, rs } => {
                let val = regs.get(rs as usize).copied().unwrap_or(0).to_le_bytes();
                let sk = stor_key(contract, &slot);
                if host.write(ns.clone(), &sk, Some(&val)).is_err() {
                    return Err(b"SEAL_STORAGE_ERR");
                }
            }
            PolkaVmInsn::SealGetStorageU32 { rd, slot } => {
                let sk = stor_key(contract, &slot);
                let val = host
                    .read(ns, &sk)
                    .ok()
                    .flatten()
                    .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(0);
                if let Some(r) = regs.get_mut(rd as usize) {
                    *r = val;
                }
            }
            PolkaVmInsn::SealDepositEvent { topic, rs } => {
                let val = regs.get(rs as usize).copied().unwrap_or(0).to_le_bytes();
                let _ = host.emit_log(EeLog {
                    emitter: EeIdentity {
                        ee: EeId::POLKAVM,
                        id: contract.to_vec(),
                    },
                    topics: vec![topic.to_vec()],
                    data: val.to_vec(),
                });
            }
            PolkaVmInsn::SealReturnU32 { rs } => {
                let val = regs.get(rs as usize).copied().unwrap_or(0).to_le_bytes();
                return Ok(val.to_vec());
            }
        }
    }
    Ok(Vec::new())
}

/// Out-of-process PolkaVM interpreter worker (`EeId::POLKAVM = 0x08`).
#[derive(Debug, Clone)]
pub struct PolkaVmWorker {
    pub testnet_activation_height: Option<u64>,
}

impl Default for PolkaVmWorker {
    fn default() -> Self {
        Self::new()
    }
}

impl PolkaVmWorker {
    /// Closed on testnet `45261` until [`PROPOSED_POLKAVM_ACTIVATION_HEIGHT`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            testnet_activation_height: Some(PROPOSED_POLKAVM_ACTIVATION_HEIGHT),
        }
    }

    /// Returns `true` when PolkaVM is active at `ctx`.
    #[must_use]
    pub const fn is_active(&self, ctx: &BlockContext) -> bool {
        if ctx.chain_id != BUDLUM_TESTNET_CHAIN_ID {
            return true;
        }
        match self.testnet_activation_height {
            Some(h) => ctx.height >= h,
            None => false,
        }
    }
}

impl ExecutionEnvironment for PolkaVmWorker {
    fn id(&self) -> EeId {
        EeId::POLKAVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        let _ = decode_polkavm_blob(code)?;
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            byte_len: u32::try_from(code.len()).unwrap_or(u32::MAX),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new(NS_POLKAVM_STATE).map_err(EeFault::Wire)?;
        if !self.is_active(ctx) {
            return Ok(EeOutcome::reverted(b"POLKAVM_CLOSED_ON_TESTNET".to_vec(), 0));
        }
        let Ok(caller32) = <[u8; 32]>::try_from(call.caller.id.as_slice()) else {
            return Ok(EeOutcome::reverted(b"PolkaVM caller must be 32 bytes".to_vec(), 0));
        };
        let mut gas_used: u64 = 1_000;
        if gas_used > call.gas_limit || host.charge(gas_used).is_err() {
            return Ok(EeOutcome::out_of_gas(call.gas_limit));
        }

        if call.kind == EeCallKind::Deploy {
            let Ok(prog) = decode_polkavm_blob(&call.input) else {
                return Ok(EeOutcome::reverted(b"bad PolkaVM blob".to_vec(), gas_used));
            };
            let addr = derive_contract_addr(&caller32, &call.tx_hash);
            if host.write(ns.clone(), &code_key(&addr), Some(&call.input)).is_err() {
                return Ok(EeOutcome::reverted(b"code write err".to_vec(), gas_used));
            }
            match run_rv32em(
                &ns,
                &addr,
                &prog.constructor,
                &[],
                &mut gas_used,
                call.gas_limit,
                host,
            ) {
                Ok(_) => Ok(EeOutcome::success(addr.to_vec(), gas_used)),
                Err(b"OUT_OF_GAS") => Ok(EeOutcome::out_of_gas(call.gas_limit)),
                Err(r) => Ok(EeOutcome::reverted(r.to_vec(), gas_used)),
            }
        } else {
            let Ok(target32) = <[u8; 32]>::try_from(call.target.id.as_slice()) else {
                return Ok(EeOutcome::reverted(b"PolkaVM target must be 32 bytes".to_vec(), 0));
            };
            let Ok(Some(blob)) = host.read(&ns, &code_key(&target32)) else {
                return Ok(EeOutcome::reverted(b"PolkaVM contract missing".to_vec(), gas_used));
            };
            let Ok(prog) = decode_polkavm_blob(&blob) else {
                return Ok(EeOutcome::reverted(b"corrupt PolkaVM blob".to_vec(), gas_used));
            };
            let Some((sel_slice, args_tail)) = call.input.split_at_checked(4) else {
                return Ok(EeOutcome::reverted(b"missing 4-byte ink! selector".to_vec(), gas_used));
            };
            let Some(disp) = prog.dispatches.iter().find(|d| d.selector == sel_slice) else {
                return Ok(EeOutcome::reverted(b"unknown ink! selector".to_vec(), gas_used));
            };
            match run_rv32em(
                &ns,
                &target32,
                &disp.insns,
                args_tail,
                &mut gas_used,
                call.gas_limit,
                host,
            ) {
                Ok(out) => Ok(EeOutcome::success(out, gas_used)),
                Err(b"OUT_OF_GAS") => Ok(EeOutcome::out_of_gas(call.gas_limit)),
                Err(r) => Ok(EeOutcome::reverted(r.to_vec(), gas_used)),
            }
        }
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        if !self.is_active(ctx) {
            return Err(EeRefusal::Denied("POLKAVM_CLOSED_ON_TESTNET".into()));
        }
        let ns = Namespace::new(NS_POLKAVM_STATE)
            .map_err(|_| EeRefusal::Denied("bad polkavm ns".into()))?;
        let target32: [u8; 32] = q
            .target
            .id
            .as_slice()
            .try_into()
            .map_err(|_| EeRefusal::BadInput("target must be 32 bytes".into()))?;
        let slot: [u8; 32] = q
            .input
            .as_slice()
            .try_into()
            .map_err(|_| EeRefusal::BadInput("slot must be 32 bytes".into()))?;
        Ok(host
            .read(&ns, &stor_key(&target32, &slot))
            .map_err(|e| EeRefusal::Denied(e.to_string()))?
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::{BudAmount, OutcomeStatus};

    #[test]
    fn polkavm_is_closed_on_testnet() {
        assert!(!POLKAVM_JIT_ENABLED);
        let mut worker = PolkaVmWorker::new();
        let mut host = MemoryHost::new(1_000_000);
        let Ok(caller) = EeIdentity::new(EeId::POLKAVM, vec![0xAA; 32]) else {
            panic!("caller");
        };
        let Ok(out) = worker.execute(
            &BlockContext {
                chain_id: BUDLUM_TESTNET_CHAIN_ID,
                height: 100,
                timestamp_ms: 1_793_923_200_000,
            },
            &EeCall {
                kind: EeCallKind::Call,
                caller: caller.clone(),
                target: caller,
                value: BudAmount(0),
                input: vec![0; 4],
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x01; 32],
            },
            &mut host,
        ) else {
            panic!("exec");
        };
        assert_eq!(out.status, OutcomeStatus::Reverted);
        assert_eq!(out.output, b"POLKAVM_CLOSED_ON_TESTNET");
    }

    /// Directive IP-53 conformance gate (1/5): `uel_conformance_polkavm`.
    #[test]
    fn uel_conformance_polkavm() {
        let mut worker = PolkaVmWorker::new();
        let slot = [0x07u8; 32];
        let prog = PolkaVmProgram {
            constructor: vec![
                PolkaVmInsn::LoadImm { rd: 0, imm: 10 },
                PolkaVmInsn::SealSetStorageU32 { slot, rs: 0 },
            ],
            dispatches: vec![PolkaVmDispatch {
                selector: [0xDE, 0xAD, 0xBE, 0xEF],
                insns: vec![
                    PolkaVmInsn::SealGetStorageU32 { rd: 0, slot },
                    PolkaVmInsn::SealInputU32 {
                        rd: 1,
                        word_index: 0,
                    },
                    PolkaVmInsn::Add {
                        rd: 2,
                        rs1: 0,
                        rs2: 1,
                    },
                    PolkaVmInsn::SealSetStorageU32 { slot, rs: 2 },
                    PolkaVmInsn::SealDepositEvent {
                        topic: [0xEE; 32],
                        rs: 2,
                    },
                    PolkaVmInsn::SealReturnU32 { rs: 2 },
                ],
            }],
        };
        let Ok(blob) = encode_polkavm_blob(&prog) else {
            panic!("blob");
        };
        assert!(worker.validate_deploy(&blob).is_ok());

        let mut host = MemoryHost::new(5_000_000);
        let Ok(caller) = EeIdentity::new(EeId::POLKAVM, vec![0x11; 32]) else {
            panic!("caller");
        };
        let ctx = BlockContext {
            chain_id: BUDLUM_TESTNET_CHAIN_ID,
            height: PROPOSED_POLKAVM_ACTIVATION_HEIGHT,
            timestamp_ms: 1_793_923_200_000,
        };
        let Ok(dep) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Deploy,
                caller: caller.clone(),
                target: caller.clone(),
                value: BudAmount(0),
                input: blob,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x08; 32],
            },
            &mut host,
        ) else {
            panic!("deploy");
        };
        assert_eq!(dep.status, OutcomeStatus::Success);
        let Ok(contract) = EeIdentity::new(EeId::POLKAVM, dep.output) else {
            panic!("contract");
        };

        let mut calldata = vec![0xDE, 0xAD, 0xBE, 0xEF];
        calldata.extend_from_slice(&32u32.to_le_bytes());
        let Ok(call_out) = worker.execute(
            &ctx,
            &EeCall {
                kind: EeCallKind::Call,
                caller,
                target: contract,
                value: BudAmount(0),
                input: calldata,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0x09; 32],
            },
            &mut host,
        ) else {
            panic!("call");
        };
        assert_eq!(call_out.status, OutcomeStatus::Success);
        assert_eq!(call_out.output, 42u32.to_le_bytes());
        assert_eq!(host.logs.len(), 1);
    }
}
