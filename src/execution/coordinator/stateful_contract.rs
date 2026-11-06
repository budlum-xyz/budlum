//! Stateful contract deployment and execution for `TransactionType::ContractCall` (`BLG-248`).
//!
//! Legacy `ContractCall` executed raw BudZKVM bytecode statelessly and generated
//! a full STARK proof inside every validator (`BLG-248`, `BLG-040`). When a
//! `ContractCall` payload begins with [`STATEFUL_CONTRACT_MAGIC`]
//! (`BDLM_UEL_STATEFUL_V1`), the coordinator decodes a [`StatefulContractEnvelope`]:
//!
//! * `Deploy`: checks [`DeployPolicy`], validates bytecode, derives the canonical
//!   contract address via [`derive_contract_account`], stores the program under
//!   `ee/budzero/program`, initializes declared slots under `ee/budzero/storage`,
//!   and registers the sender's alias in `uel/alias`.
//! * `Call`: loads the deployed program from `ee/budzero/program` through
//!   [`OverlayCore`] + [`BlockReadCache`], populates initial storage slots from
//!   `ee/budzero/storage`, runs BudZero VM in execution-only mode, writes all
//!   `vm.state_writes` back into `ee/budzero/storage`, and commits atomically
//!   into [`AccountState`].

use bud_isa::Instruction;
use bud_vm::Vm;
use budlum_uel_abi::{EeId, HostApi, HostRead, Namespace};

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::Transaction;
use crate::execution::coordinator::accounts::derive_contract_account;
use crate::execution::coordinator::commitment::{NS_BUDZERO_PROGRAM, NS_BUDZERO_STORAGE};
use crate::execution::coordinator::deploy_policy::DeployPolicy;
use crate::execution::coordinator::overlay::{
    BlockReadCache, ExecutionOverlay, NoopDispatcher, OverlayCore,
};
use crate::execution::zkvm::DEFAULT_CONTRACT_GAS_LIMIT;

/// Domain-separated prefix identifying a stateful UEL `ContractCall` payload.
pub const STATEFUL_CONTRACT_MAGIC: &[u8; 20] = b"BDLM_UEL_STATEFUL_V1";

const STATEFUL_VM_MEMORY_BYTES: usize = 8192;
const MAX_DECLARED_SLOTS: usize = 256;

/// Decoded stateful contract operation carried inside `Transaction::data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatefulContractEnvelope {
    /// Deploy `code` with initial `(slot, value)` storage entries.
    Deploy {
        code: Vec<u8>,
        init_slots: Vec<(u64, u64)>,
    },
    /// Invoke deployed `contract`, pre-loading `declared_slots` into VM storage.
    Call {
        contract: Address,
        declared_slots: Vec<u64>,
        call_inputs: Vec<(u64, u64)>,
        gas_limit: u64,
    },
}

impl StatefulContractEnvelope {
    /// Encode this envelope with [`STATEFUL_CONTRACT_MAGIC`] for `Transaction::data`.
    ///
    /// Convenience: used by SDK builders and stateful contract tests.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(STATEFUL_CONTRACT_MAGIC.as_slice());
        match self {
            Self::Deploy { code, init_slots } => {
                out.push(0x01);
                out.extend_from_slice(&(code.len() as u32).to_le_bytes());
                out.extend_from_slice(code);
                out.extend_from_slice(&(init_slots.len() as u32).to_le_bytes());
                for (slot, val) in init_slots {
                    out.extend_from_slice(&slot.to_le_bytes());
                    out.extend_from_slice(&val.to_le_bytes());
                }
            }
            Self::Call {
                contract,
                declared_slots,
                call_inputs,
                gas_limit,
            } => {
                out.push(0x02);
                out.extend_from_slice(&contract.0);
                out.extend_from_slice(&gas_limit.to_le_bytes());
                out.extend_from_slice(&(declared_slots.len() as u32).to_le_bytes());
                for slot in declared_slots {
                    out.extend_from_slice(&slot.to_le_bytes());
                }
                out.extend_from_slice(&(call_inputs.len() as u32).to_le_bytes());
                for (slot, val) in call_inputs {
                    out.extend_from_slice(&slot.to_le_bytes());
                    out.extend_from_slice(&val.to_le_bytes());
                }
            }
        }
        out
    }

    /// Decode a `STATEFUL_CONTRACT_MAGIC`-prefixed payload.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let Some((magic, mut cur)) = data.split_at_checked(STATEFUL_CONTRACT_MAGIC.len()) else {
            return Err("payload shorter than stateful contract header".into());
        };
        if magic != STATEFUL_CONTRACT_MAGIC {
            return Err("invalid stateful contract header".into());
        }
        let (&tag, rest) = cur
            .split_first()
            .ok_or_else(|| "missing stateful contract op tag".to_string())?;
        cur = rest;
        match tag {
            0x01 => {
                let code_len = read_u32(&mut cur)? as usize;
                let Some((code, rest)) = cur.split_at_checked(code_len) else {
                    return Err("truncated deploy bytecode".into());
                };
                cur = rest;
                let slot_count = read_u32(&mut cur)? as usize;
                if slot_count > MAX_DECLARED_SLOTS {
                    return Err("too many initial storage slots".into());
                }
                let mut init_slots = Vec::with_capacity(slot_count);
                for _ in 0..slot_count {
                    let s = read_u64(&mut cur)?;
                    let v = read_u64(&mut cur)?;
                    init_slots.push((s, v));
                }
                if !cur.is_empty() {
                    return Err("trailing bytes in stateful deploy envelope".into());
                }
                Ok(Self::Deploy {
                    code: code.to_vec(),
                    init_slots,
                })
            }
            0x02 => {
                let Some((addr_bytes, rest)) = cur.split_at_checked(32) else {
                    return Err("truncated contract address".into());
                };
                let arr: [u8; 32] = addr_bytes
                    .try_into()
                    .map_err(|_| "invalid contract address length".to_string())?;
                cur = rest;
                let gas_limit = read_u64(&mut cur)?;
                let decl_count = read_u32(&mut cur)? as usize;
                if decl_count > MAX_DECLARED_SLOTS {
                    return Err("too many declared storage slots".into());
                }
                let mut declared_slots = Vec::with_capacity(decl_count);
                for _ in 0..decl_count {
                    declared_slots.push(read_u64(&mut cur)?);
                }
                let input_count = read_u32(&mut cur)? as usize;
                if input_count > MAX_DECLARED_SLOTS {
                    return Err("too many call input slots".into());
                }
                let mut call_inputs = Vec::with_capacity(input_count);
                for _ in 0..input_count {
                    let s = read_u64(&mut cur)?;
                    let v = read_u64(&mut cur)?;
                    call_inputs.push((s, v));
                }
                if !cur.is_empty() {
                    return Err("trailing bytes in stateful call envelope".into());
                }
                Ok(Self::Call {
                    contract: Address(arr),
                    declared_slots,
                    call_inputs,
                    gas_limit,
                })
            }
            other => Err(format!("unknown stateful contract op 0x{other:02x}")),
        }
    }
}

fn read_u32(cur: &mut &[u8]) -> Result<u32, String> {
    let Some((head, tail)) = cur.split_at_checked(4) else {
        return Err("unexpected EOF reading u32".into());
    };
    let arr: [u8; 4] = head.try_into().map_err(|_| "bad u32 slice".to_string())?;
    *cur = tail;
    Ok(u32::from_le_bytes(arr))
}

fn read_u64(cur: &mut &[u8]) -> Result<u64, String> {
    let Some((head, tail)) = cur.split_at_checked(8) else {
        return Err("unexpected EOF reading u64".into());
    };
    let arr: [u8; 8] = head.try_into().map_err(|_| "bad u64 slice".to_string())?;
    *cur = tail;
    Ok(u64::from_le_bytes(arr))
}

fn decode_checked_budzero(code: &[u8]) -> Result<Vec<u64>, String> {
    if code.is_empty() || !code.len().is_multiple_of(8) {
        return Err("BudZero bytecode must be non-empty and 8-byte aligned".into());
    }
    let mut words = Vec::with_capacity(code.len() / 8);
    for chunk in code.chunks_exact(8) {
        let arr: [u8; 8] = chunk
            .try_into()
            .map_err(|_| "bad instruction word".to_string())?;
        let raw = u64::from_le_bytes(arr);
        Instruction::decode_for_mainnet(raw, bud_isa::MainnetActivation::default())
            .map_err(|e| e.to_string())?;
        words.push(raw);
    }
    Ok(words)
}

/// Deterministic contract address derived from `(deployer, nonce, code)`.
///
/// Convenience: used by SDK callers and tests to predict deployed contract addresses.
pub fn derive_budzero_contract_address(
    deployer: &Address,
    nonce: u64,
    code: &[u8],
) -> Result<Address, String> {
    let nonce_bytes = nonce.to_le_bytes();
    let seed = hash_fields_bytes(&[
        b"BDLM_UEL_STATEFUL_V1",
        &deployer.0,
        &nonce_bytes,
        code,
    ]);
    derive_contract_account(EeId::BUDZERO, &seed).map_err(|e| e.to_string())
}

fn storage_slot_key(contract: &Address, slot: u64) -> [u8; 40] {
    let mut out = [0u8; 40];
    if let Some((head, tail)) = out.split_at_mut_checked(32) {
        head.copy_from_slice(&contract.0);
        tail.copy_from_slice(&slot.to_le_bytes());
    }
    out
}

/// Returns `true` when `tx.data` carries a stateful UEL contract envelope.
#[must_use]
pub fn is_stateful_contract_payload(data: &[u8]) -> bool {
    data.starts_with(STATEFUL_CONTRACT_MAGIC)
}

/// Execute a stateful `ContractCall` through the UEL coordinator overlay (`BLG-248`).
pub fn execute_stateful_contract_tx(
    tx: &Transaction,
    state: &mut AccountState,
    policy: &DeployPolicy,
) -> Result<Option<Address>, String> {
    let env = StatefulContractEnvelope::decode(&tx.data)?;
    match env {
        StatefulContractEnvelope::Deploy { code, init_slots } => {
            policy
                .check_deploy_allowed(EeId::BUDZERO)
                .map_err(|e| e.to_string())?;
            let _ = decode_checked_budzero(&code)?;
            let contract_addr = derive_budzero_contract_address(&tx.from, tx.nonce, &code)?;
            if state
                .uel_state
                .read(NS_BUDZERO_PROGRAM, &contract_addr.0)
                .is_some()
            {
                return Err("contract address already occupied".into());
            }

            let mut cache = BlockReadCache::new();
            let mut disp = NoopDispatcher;
            let mut core =
                OverlayCore::new(state, &mut cache, EeId::BUDZERO, DEFAULT_CONTRACT_GAS_LIMIT);
            {
                let mut host = ExecutionOverlay::new(&mut core, &mut disp);
                let prog_ns = Namespace::new(NS_BUDZERO_PROGRAM).map_err(|e| e.to_string())?;
                let store_ns = Namespace::new(NS_BUDZERO_STORAGE).map_err(|e| e.to_string())?;
                host.write(&prog_ns, &contract_addr.0, Some(&code))
                    .map_err(|e| e.to_string())?;
                for (slot, val) in init_slots {
                    let key = storage_slot_key(&contract_addr, slot);
                    host.write(&store_ns, &key, Some(&val.to_le_bytes()))
                        .map_err(|e| e.to_string())?;
                }
            }
            core.commit_root(state)?;
            state
                .uel_state
                .ensure_alias_registered(&tx.from, EeId::BUDZERO)
                .map_err(|e| e.to_string())?;
            Ok(Some(contract_addr))
        }
        StatefulContractEnvelope::Call {
            contract,
            declared_slots,
            call_inputs,
            gas_limit,
        } => {
            let capped_limit = gas_limit.clamp(1, DEFAULT_CONTRACT_GAS_LIMIT);
            let mut cache = BlockReadCache::new();
            let mut disp = NoopDispatcher;
            let prog_ns = Namespace::new(NS_BUDZERO_PROGRAM).map_err(|e| e.to_string())?;
            let store_ns = Namespace::new(NS_BUDZERO_STORAGE).map_err(|e| e.to_string())?;

            let mut core = OverlayCore::new(state, &mut cache, EeId::BUDZERO, capped_limit);
            let code_bytes = HostRead::read(&core, &prog_ns, &contract.0)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "deployed BudZero contract not found".to_string())?;
            let program = decode_checked_budzero(&code_bytes)?;

            let mut vm = Vm::with_mainnet_mode(STATEFUL_VM_MEMORY_BYTES, capped_limit, true);
            vm.context.set_sender_bytes(&tx.from.0);
            vm.context.nonce = tx.nonce;
            vm.context.block_height = state.current_block_height;

            for slot in declared_slots {
                let key = storage_slot_key(&contract, slot);
                if let Some(raw) =
                    HostRead::read(&core, &store_ns, &key).map_err(|e| e.to_string())?
                {
                    if let Ok(arr) = raw.as_slice().try_into() {
                        vm.storage.insert(slot, u64::from_le_bytes(arr));
                    }
                }
            }
            for (slot, val) in call_inputs {
                vm.storage.insert(slot, val);
            }

            let receipt = vm.run_receipt(&program);
            if !receipt.success {
                return Err(match receipt.error {
                    Some(e) => format!("stateful BudZero call reverted: {e:?}"),
                    None => "stateful BudZero call reverted".into(),
                });
            }

            {
                let mut host = ExecutionOverlay::new(&mut core, &mut disp);
                host.charge(receipt.gas_used).map_err(|e| e.to_string())?;
                for (slot, val) in &vm.state_writes {
                    let key = storage_slot_key(&contract, *slot);
                    host.write(&store_ns, &key, Some(&val.to_le_bytes()))
                        .map_err(|e| e.to_string())?;
                }
            }
            core.commit_root(state)?;
            state
                .uel_state
                .ensure_alias_registered(&tx.from, EeId::BUDZERO)
                .map_err(|e| e.to_string())?;
            Ok(None)
        }
    }
}

/// Read a persistent `u64` storage slot of a deployed BudZero contract.
///
/// Convenience: exposed for RPC queries and stateful contract tests.
#[must_use]
pub fn read_budzero_contract_slot(
    state: &AccountState,
    contract: &Address,
    slot: u64,
) -> Option<u64> {
    let key = storage_slot_key(contract, slot);
    let raw = state.uel_state.read(NS_BUDZERO_STORAGE, &key)?;
    let arr: [u8; 8] = raw.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::Opcode;

    fn counter_increment_bytecode() -> Vec<u8> {
        // r1 = SRead(slot 0); r2 = 1; r3 = r1 + r2; SWrite(slot 0, r3); Halt
        let instrs = [
            Instruction {
                opcode: Opcode::Load,
                rd: 10,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::SRead,
                rd: 1,
                rs1: 10,
                rs2: 0,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 1,
            },
            Instruction {
                opcode: Opcode::Add,
                rd: 3,
                rs1: 1,
                rs2: 2,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::SWrite,
                rd: 0,
                rs1: 10,
                rs2: 3,
                imm: 0,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ];
        let mut out = Vec::new();
        for ins in instrs {
            out.extend_from_slice(&ins.encode().to_le_bytes());
        }
        out
    }

    #[test]
    fn stateful_contract_deploys_and_persists_storage_across_calls() {
        let mut state = AccountState::new();
        let alice = Address([0x55; 32]);
        let code = counter_increment_bytecode();
        let policy = DeployPolicy::phase1_default();

        // 1. Deploy counter initialized to slot 0 = 40.
        let mut deploy_tx = Transaction::new(
            alice,
            Address::zero(),
            0,
            StatefulContractEnvelope::Deploy {
                code: code.clone(),
                init_slots: vec![(0, 40)],
            }
            .encode(),
        );
        deploy_tx.nonce = 1;
        let contract = execute_stateful_contract_tx(&deploy_tx, &mut state, &policy)
            .unwrap()
            .unwrap();
        assert_eq!(read_budzero_contract_slot(&state, &contract, 0), Some(40));

        // 2. Call #1 increments slot 0 -> 41.
        let mut call1 = Transaction::new(
            alice,
            contract,
            0,
            StatefulContractEnvelope::Call {
                contract,
                declared_slots: vec![0],
                call_inputs: Vec::new(),
                gas_limit: 500_000,
            }
            .encode(),
        );
        call1.nonce = 2;
        execute_stateful_contract_tx(&call1, &mut state, &policy).unwrap();
        assert_eq!(read_budzero_contract_slot(&state, &contract, 0), Some(41));

        // 3. Call #2 reads persisted 41 and increments slot 0 -> 42!
        let mut call2 = call1;
        call2.nonce = 3;
        execute_stateful_contract_tx(&call2, &mut state, &policy).unwrap();
        assert_eq!(read_budzero_contract_slot(&state, &contract, 0), Some(42));
    }
}
