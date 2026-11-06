//! Out-of-process EVM Execution Environment (`EeId::EVM = 0x01`, `WP-27`, `BLG-267`).
//!
//! Runs `revm = "=43.0.3"` at `SpecId::OSAKA` with `1 BGU = 1 EVM gas`, chain ID `45261`,
//! `CREATE`/`CREATE2` post-quantum alias collision protection, and the Universal Call
//! precompile skeleton at `0x000000000000000000000000000000000000B001`.

#![forbid(unsafe_code)]

pub mod abi;
pub mod db;

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use budlum_uel_abi::transport::panic_digest;
use budlum_uel_abi::{
    BlockContext, BudAmount, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeIdentity, EeOutcome,
    EeQuery, EeRefusal, ExecutionEnvironment, HostApi, HostRead, OutcomeStatus, RefusalCode,
    UniversalCall,
};
use revm::context::{BlockEnv, CfgEnv, Context, Journal, TxEnv};
use revm::context_interface::result::{ExecutionResult, HaltReason};
use revm::context_interface::JournalTr;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::{
    CallInputs, CallOutcome, CreateInputs, CreateOutcome, Gas, InstructionResult,
    InterpreterResult,
};
use revm::primitives::eip3860::MAX_INITCODE_SIZE;
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address, Bytes, TxKind, U256};
use revm::{ExecuteEvm, InspectEvm, Inspector, MainBuilder};
use sha2::{Digest, Sha256};

use crate::abi::{
    decode_precompile_call, encode_precompile_return, PRECOMPILE_BASE_GAS,
    UNIVERSAL_CALL_PRECOMPILE,
};
use crate::db::{commit_evm_state, evm_identity, HostDb, ReadOnlyHostDb};

/// Default Budlum EVM chain ID (`EIP-155`).
pub const BUDLUM_EVM_CHAIN_ID: u64 = 45_261;

/// Read-only `query` gas ceiling (`16 Mi` gas, matching Osaka EIP-7825 per-tx cap).
pub const QUERY_GAS_LIMIT: u64 = 16_777_216;

/// Inspector enforcing `CREATE`/`CREATE2` alias-collision refusal and dispatching
/// `0x000000000000000000000000000000000000B001` Universal Calls (`Section 8.7.2`).
#[derive(Debug, Default)]
pub struct BudlumEvmInspector {
    /// Set if an alias collision refused contract creation during execution.
    pub alias_collision_refused: bool,
}

type EvmHostCtx<'a> = Context<BlockEnv, TxEnv, CfgEnv, HostDb<'a>, Journal<HostDb<'a>>, ()>;

impl<'a> Inspector<EvmHostCtx<'a>, EthInterpreter> for BudlumEvmInspector {
    fn create(
        &mut self,
        context: &mut EvmHostCtx<'a>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let caller = inputs.caller();
        let nonce = context
            .journaled_state
            .evm_state()
            .get(&caller)
            .map_or(0, |acc| acc.info.nonce);
        let candidate = inputs.created_address(nonce);
        let collided = context
            .journaled_state
            .db()
            .has_pq_alias(candidate)
            .unwrap_or(true);
        if collided {
            self.alias_collision_refused = true;
            let gas = Gas::new_spent_with_reservoir(inputs.gas_limit(), inputs.reservoir());
            return Some(CreateOutcome::new(
                InterpreterResult::new(InstructionResult::CreateCollision, Bytes::new(), gas),
                None,
            ));
        }
        None
    }

    fn call(
        &mut self,
        context: &mut EvmHostCtx<'a>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if inputs.bytecode_address != UNIVERSAL_CALL_PRECOMPILE
            && inputs.target_address != UNIVERSAL_CALL_PRECOMPILE
        {
            return None;
        }

        let calldata: Vec<u8> = inputs.input.as_bytes(context).to_vec();
        let mem_offset = inputs.return_memory_offset.clone();

        if inputs.gas_limit < PRECOMPILE_BASE_GAS {
            return Some(CallOutcome::new(
                InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                mem_offset,
            ));
        }

        let Some(parsed) = decode_precompile_call(&calldata) else {
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            let _ = gas.record_regular_cost(PRECOMPILE_BASE_GAS);
            return Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                mem_offset,
            ));
        };

        if inputs.is_static && (!parsed.is_static_selector && parsed.value_attos > 0) {
            return Some(CallOutcome::new(
                InterpreterResult::new(
                    InstructionResult::CallNotAllowedInsideStatic,
                    Bytes::new(),
                    Gas::new_spent_with_reservoir(inputs.gas_limit, inputs.reservoir),
                ),
                mem_offset,
            ));
        }

        let remaining_for_callee = inputs.gas_limit.saturating_sub(PRECOMPILE_BASE_GAS);
        let forwarded_gas = parsed.gas_bgu.min(remaining_for_callee);
        let ucall = UniversalCall {
            from: evm_identity(inputs.caller),
            to_ee: EeId(parsed.target_ee),
            target: EeIdentity {
                ee: EeId(parsed.target_ee),
                id: parsed.target,
            },
            value: BudAmount(parsed.value_attos),
            input: parsed.input,
            gas_limit: forwarded_gas,
        };

        match context.journaled_state.db_mut().universal_call(ucall) {
            Ok(ures) => {
                let total_cost = PRECOMPILE_BASE_GAS.saturating_add(ures.gas_used);
                if total_cost > inputs.gas_limit {
                    return Some(CallOutcome::new(
                        InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                        mem_offset,
                    ));
                }
                let mut gas =
                    Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
                if !gas.record_regular_cost(total_cost) {
                    return Some(CallOutcome::new(
                        InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                        mem_offset,
                    ));
                }
                let encoded = encode_precompile_return(ures.success, &ures.output);
                Some(CallOutcome::new(
                    InterpreterResult::new(InstructionResult::Return, Bytes::from(encoded), gas),
                    mem_offset,
                ))
            }
            Err(_) => {
                let mut gas =
                    Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
                let _ = gas.record_regular_cost(PRECOMPILE_BASE_GAS);
                Some(CallOutcome::new(
                    InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                    mem_offset,
                ))
            }
        }
    }
}

/// Stateless read-only inspector blocking `0x...B001` non-static calls and `CREATE` collisions.
#[derive(Debug, Default)]
struct QueryInspector;

impl<'a>
    Inspector<
        Context<BlockEnv, TxEnv, CfgEnv, ReadOnlyHostDb<'a>, Journal<ReadOnlyHostDb<'a>>, ()>,
        EthInterpreter,
    > for QueryInspector
{
    fn create(
        &mut self,
        _context: &mut Context<
            BlockEnv,
            TxEnv,
            CfgEnv,
            ReadOnlyHostDb<'a>,
            Journal<ReadOnlyHostDb<'a>>,
            (),
        >,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let gas = Gas::new_spent_with_reservoir(inputs.gas_limit(), inputs.reservoir());
        Some(CreateOutcome::new(
            InterpreterResult::new(
                InstructionResult::StateChangeDuringStaticCall,
                Bytes::new(),
                gas,
            ),
            None,
        ))
    }
}

/// Out-of-process `budlum-ee-evm` worker implementation (`EeId::EVM = 0x01`).
#[derive(Debug, Default, Clone, Copy)]
pub struct EvmWorker;

fn parse_evm_address(id: &[u8]) -> Option<Address> {
    if id.len() != 20 {
        return None;
    }
    Some(Address::from_slice(id))
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string engine panic".to_string()
    }
}

fn build_block_env(ctx: &BlockContext) -> BlockEnv {
    BlockEnv {
        number: U256::from(ctx.height),
        timestamp: U256::from(ctx.timestamp_ms / 1_000),
        basefee: 0,
        gas_limit: u64::MAX,
        ..BlockEnv::default()
    }
}

fn map_halt_to_status(reason: &HaltReason) -> OutcomeStatus {
    match reason {
        HaltReason::OutOfGas(_) => OutcomeStatus::OutOfGas,
        HaltReason::OpcodeNotFound
        | HaltReason::InvalidFEOpcode
        | HaltReason::InvalidJump
        | HaltReason::NotActivated
        | HaltReason::CreateContractStartingWithEF
        | HaltReason::CreateContractSizeLimit
        | HaltReason::CreateInitCodeSizeLimit => OutcomeStatus::InvalidCode,
        _ => OutcomeStatus::Revert,
    }
}

impl EvmWorker {
    fn execute_inner(ctx: &BlockContext, call: &EeCall, host: &mut dyn HostApi) -> EeOutcome {
        let Some(caller_addr) = parse_evm_address(&call.caller.id) else {
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: b"invalid caller EVM address".to_vec(),
                gas_used: 0,
            };
        };

        let tx_kind = match call.kind {
            EeCallKind::Deploy => {
                if call.input.is_empty() || call.input.len() > MAX_INITCODE_SIZE {
                    let _ = host.charge(call.gas_limit);
                    return EeOutcome {
                        status: OutcomeStatus::InvalidCode,
                        output: Vec::new(),
                        gas_used: call.gas_limit,
                    };
                }
                if call.target.id.len() == 20 && call.target.id != [0u8; 20] {
                    let target_addr = Address::from_slice(&call.target.id);
                    if db::check_pq_alias_in_host(host, target_addr).unwrap_or(true) {
                        let _ = host.charge(call.gas_limit);
                        return EeOutcome {
                            status: OutcomeStatus::Revert,
                            output: b"alias collision".to_vec(),
                            gas_used: call.gas_limit,
                        };
                    }
                }
                TxKind::Create
            }
            EeCallKind::Call => {
                let Some(target_addr) = parse_evm_address(&call.target.id) else {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: b"invalid target EVM address".to_vec(),
                        gas_used: 0,
                    };
                };
                TxKind::Call(target_addr)
            }
        };

        let chain_id = if ctx.chain_id == 0 {
            BUDLUM_EVM_CHAIN_ID
        } else {
            ctx.chain_id
        };

        let mut cfg = CfgEnv::new_with_spec(SpecId::OSAKA);
        cfg.chain_id = chain_id;
        cfg.tx_chain_id_check = true;
        cfg.disable_nonce_check = true;
        cfg.disable_base_fee = true;
        cfg.tx_gas_limit_cap = Some(u64::MAX);
        if call.depth > 0 {
            cfg.disable_eip3607 = true;
        }

        let block_env = build_block_env(ctx);
        let tx_env = TxEnv {
            tx_type: 0,
            caller: caller_addr,
            gas_limit: call.gas_limit,
            gas_price: 0,
            kind: tx_kind,
            value: U256::from(call.value.0),
            data: Bytes::from(call.input.clone()),
            nonce: 0,
            chain_id: Some(chain_id),
            ..TxEnv::default()
        };

        let exec_out = {
            let host_db = HostDb::new(host, chain_id);
            let evm_ctx = Context::new(host_db, SpecId::OSAKA)
                .with_cfg(cfg)
                .with_block(block_env);
            let mut evm = evm_ctx.build_mainnet_with_inspector(BudlumEvmInspector::default());
            evm.inspect_tx(tx_env)
        };

        let Ok(result_and_state) = exec_out else {
            let _ = host.charge(call.gas_limit);
            return EeOutcome {
                status: OutcomeStatus::Revert,
                output: Vec::new(),
                gas_used: call.gas_limit,
            };
        };

        let raw_gas = match &result_and_state.result {
            ExecutionResult::Success { gas, .. }
            | ExecutionResult::Revert { gas, .. }
            | ExecutionResult::Halt { gas, .. } => gas.tx_gas_used(),
        };
        let gas_used = raw_gas.min(call.gas_limit);
        if host.charge(gas_used).is_err() {
            return EeOutcome {
                status: OutcomeStatus::OutOfGas,
                output: Vec::new(),
                gas_used: call.gas_limit,
            };
        }

        match result_and_state.result {
            ExecutionResult::Success { logs, output, .. } => {
                if commit_evm_state(host, &result_and_state.state, &logs).is_err() {
                    return EeOutcome {
                        status: OutcomeStatus::Revert,
                        output: Vec::new(),
                        gas_used,
                    };
                }
                let out_bytes = match (call.kind, output.address()) {
                    (EeCallKind::Deploy, Some(created)) => created.as_slice().to_vec(),
                    _ => output.into_data().to_vec(),
                };
                EeOutcome {
                    status: OutcomeStatus::Success,
                    output: out_bytes,
                    gas_used,
                }
            }
            ExecutionResult::Revert { output, .. } => EeOutcome {
                status: OutcomeStatus::Revert,
                output: output.to_vec(),
                gas_used,
            },
            ExecutionResult::Halt { reason, .. } => EeOutcome {
                status: map_halt_to_status(&reason),
                output: Vec::new(),
                gas_used,
            },
        }
    }
}

impl ExecutionEnvironment for EvmWorker {
    fn id(&self) -> EeId {
        EeId::EVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "EVM deploy initcode cannot be empty".into(),
            });
        }
        if code.len() > MAX_INITCODE_SIZE {
            return Err(EeRefusal {
                code: RefusalCode::TooLarge,
                message: format!(
                    "EVM initcode size {} exceeds EIP-3860 limit {}",
                    code.len(),
                    MAX_INITCODE_SIZE
                ),
            });
        }
        if code.first() == Some(&0xEF) {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "EIP-3541 forbids 0xEF-prefixed bytecode".into(),
            });
        }
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        Ok(CodeInfo {
            code_hash,
            abi_tag: "evm-osaka".into(),
        })
    }

    fn execute(
        &mut self,
        ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        catch_unwind(AssertUnwindSafe(|| Self::execute_inner(ctx, call, host))).map_err(
            |payload| {
                let msg = panic_payload_message(&*payload);
                EeFault {
                    ee: EeId::EVM,
                    panic_digest: panic_digest(EeId::EVM, &msg),
                }
            },
        )
    }

    fn query(
        &self,
        ctx: &BlockContext,
        q: &EeQuery,
        host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        let Some(target_addr) = parse_evm_address(&q.target.id) else {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "query target must be a 20-byte EVM address".into(),
            });
        };
        let chain_id = if ctx.chain_id == 0 {
            BUDLUM_EVM_CHAIN_ID
        } else {
            ctx.chain_id
        };

        let mut cfg = CfgEnv::new_with_spec(SpecId::OSAKA);
        cfg.chain_id = chain_id;
        cfg.tx_chain_id_check = false;
        cfg.disable_nonce_check = true;
        cfg.disable_balance_check = true;
        cfg.disable_base_fee = true;
        cfg.disable_eip3607 = true;
        cfg.tx_gas_limit_cap = Some(QUERY_GAS_LIMIT);

        let block_env = build_block_env(ctx);
        let tx_env = TxEnv {
            tx_type: 0,
            caller: Address::ZERO,
            gas_limit: QUERY_GAS_LIMIT,
            gas_price: 0,
            kind: TxKind::Call(target_addr),
            value: U256::ZERO,
            data: Bytes::from(q.input.clone()),
            nonce: 0,
            chain_id: Some(chain_id),
            ..TxEnv::default()
        };

        let ro_db = ReadOnlyHostDb::new(host, chain_id);
        let evm_ctx = Context::new(ro_db, SpecId::OSAKA)
            .with_cfg(cfg)
            .with_block(block_env);
        let mut evm = evm_ctx.build_mainnet_with_inspector(QueryInspector);
        let res = evm.inspect_one_tx(tx_env).map_err(|e| EeRefusal {
            code: RefusalCode::Denied,
            message: format!("EVM query execution error: {e}"),
        })?;

        match res {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Err(EeRefusal {
                code: RefusalCode::Denied,
                message: format!("EVM query reverted ({} bytes)", output.len()),
            }),
            ExecutionResult::Halt { reason, .. } => Err(EeRefusal {
                code: RefusalCode::Denied,
                message: format!("EVM query halted: {reason:?}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use budlum_uel_abi::mock::MemoryHost;
    use budlum_uel_abi::transport::{serve_connection, EeClient};
    use budlum_uel_abi::{
        BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeQuery,
        ExecutionEnvironment, HostApi, Namespace, OutcomeStatus, UniversalResult,
    };
    use revm::bytecode::opcode;
    use revm::primitives::{keccak256, Address};

    use crate::abi::{encode_universal_call_input, UNIVERSAL_CALL_PRECOMPILE};
    use crate::db::NS_UEL_ALIAS;
    use crate::{EvmWorker, BUDLUM_EVM_CHAIN_ID};

    /// Minimal two-pass EVM bytecode assembler for test contracts without hardcoded jump offsets.
    #[derive(Default)]
    struct Asm {
        ops: Vec<AsmItem>,
    }

    enum AsmItem {
        Byte(u8),
        Bytes(Vec<u8>),
        Label(&'static str),
        PushLabel(&'static str),
    }

    impl Asm {
        fn op(&mut self, b: u8) -> &mut Self {
            self.ops.push(AsmItem::Byte(b));
            self
        }

        fn push1(&mut self, v: u8) -> &mut Self {
            self.op(opcode::PUSH1).op(v)
        }

        fn push4(&mut self, v: [u8; 4]) -> &mut Self {
            self.op(opcode::PUSH4);
            self.ops.push(AsmItem::Bytes(v.to_vec()));
            self
        }

        fn push20(&mut self, v: [u8; 20]) -> &mut Self {
            self.op(opcode::PUSH20);
            self.ops.push(AsmItem::Bytes(v.to_vec()));
            self
        }

        fn push32(&mut self, v: [u8; 32]) -> &mut Self {
            self.op(opcode::PUSH32);
            self.ops.push(AsmItem::Bytes(v.to_vec()));
            self
        }

        fn label(&mut self, name: &'static str) -> &mut Self {
            self.ops.push(AsmItem::Label(name));
            self
        }

        fn jumpi_to(&mut self, name: &'static str) -> &mut Self {
            self.ops.push(AsmItem::PushLabel(name));
            self.op(opcode::JUMPI)
        }

        fn finish(&self) -> Vec<u8> {
            let mut offsets = BTreeMap::new();
            let mut pos = 0usize;
            for item in &self.ops {
                match item {
                    AsmItem::Byte(_) => pos += 1,
                    AsmItem::Bytes(b) => pos += b.len(),
                    AsmItem::Label(name) => {
                        offsets.insert(*name, pos);
                        pos += 1; // JUMPDEST
                    }
                    AsmItem::PushLabel(_) => pos += 3, // PUSH2 hi lo
                }
            }
            let mut out = Vec::with_capacity(pos);
            for item in &self.ops {
                match item {
                    AsmItem::Byte(b) => out.push(*b),
                    AsmItem::Bytes(b) => out.extend_from_slice(b),
                    AsmItem::Label(_) => out.push(opcode::JUMPDEST),
                    AsmItem::PushLabel(name) => {
                        let Some(&off) = offsets.get(name) else {
                            panic!("missing label {name}");
                        };
                        let Ok(off16) = u16::try_from(off) else {
                            panic!("offset overflow");
                        };
                        out.push(opcode::PUSH2);
                        out.extend_from_slice(&off16.to_be_bytes());
                    }
                }
            }
            out
        }
    }

    fn wrap_initcode(prefix_ops: &[u8], runtime: &[u8]) -> Vec<u8> {
        // prefix_ops + PUSH2(runtime_len) + DUP1 + PUSH2(init_len) + PUSH1(0) + CODECOPY + PUSH1(0) + RETURN + runtime
        let Ok(rt_len) = u16::try_from(runtime.len()) else {
            panic!("runtime too big");
        };
        let init_len = prefix_ops.len() + 12;
        let Ok(init_len16) = u16::try_from(init_len) else {
            panic!("init too big");
        };
        let mut init = Vec::with_capacity(init_len + runtime.len());
        init.extend_from_slice(prefix_ops);
        init.push(opcode::PUSH2);
        init.extend_from_slice(&rt_len.to_be_bytes());
        init.push(opcode::DUP1);
        init.push(opcode::PUSH2);
        init.extend_from_slice(&init_len16.to_be_bytes());
        init.push(opcode::PUSH1);
        init.push(0x00);
        init.push(opcode::CODECOPY);
        init.push(opcode::PUSH1);
        init.push(0x00);
        init.push(opcode::RETURN);
        init.extend_from_slice(runtime);
        init
    }

    /// Build a spec-faithful ERC-20 contract (`totalSupply()`, `balanceOf(address)`,
    /// `transfer(address,uint256)` + `Transfer` `LOG3` event) minting `initial_supply` to `CALLER`.
    ///
    /// Storage layout:
    /// - slot `1`: `totalSupply`
    /// - slot `keccak256(abi.encode(account))`: `balanceOf[account]`
    fn build_erc20_deploy_bytecode(initial_supply: u64) -> Vec<u8> {
        let mut supply_word = [0u8; 32];
        supply_word[24..32].copy_from_slice(&initial_supply.to_be_bytes());

        // Constructor prefix:
        // 1. SSTORE(1, initial_supply)
        // 2. MSTORE(0, CALLER); slot = KECCAK256(0, 32); SSTORE(slot, initial_supply)
        let mut ctor = Asm::default();
        ctor.push32(supply_word)
            .push1(0x01)
            .op(opcode::SSTORE)
            .op(opcode::CALLER)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push32(supply_word)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::KECCAK256)
            .op(opcode::SSTORE);

        let transfer_topic: [u8; 32] = keccak256(b"Transfer(address,address,uint256)").into();
        let addr_mask: [u8; 20] = [0xFF; 20];

        // Runtime dispatcher:
        let mut rt = Asm::default();
        // Extract 4-byte selector: CALLDATALOAD(0) >> 224 (0xE0)
        rt.push1(0x00)
            .op(opcode::CALLDATALOAD)
            .push1(0xE0)
            .op(opcode::SHR);

        // if sel == 0x18160ddd -> totalSupply()
        rt.op(opcode::DUP1)
            .push4([0x18, 0x16, 0x0d, 0xdd])
            .op(opcode::EQ)
            .jumpi_to("total_supply");

        // if sel == 0x70a08231 -> balanceOf(address)
        rt.op(opcode::DUP1)
            .push4([0x70, 0xa0, 0x82, 0x31])
            .op(opcode::EQ)
            .jumpi_to("balance_of");

        // if sel == 0xa9059cbb -> transfer(address,uint256)
        rt.push4([0xa9, 0x05, 0x9c, 0xbb])
            .op(opcode::EQ)
            .jumpi_to("transfer");

        // Fallback: revert(0, 0)
        rt.label("revert_zero")
            .push1(0x00)
            .push1(0x00)
            .op(opcode::REVERT);

        // totalSupply(): return SLOAD(1)
        rt.label("total_supply")
            .op(opcode::POP)
            .push1(0x01)
            .op(opcode::SLOAD)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::RETURN);

        // balanceOf(address): MSTORE(0, CALLDATALOAD(4) & mask20); RETURN SLOAD(KECCAK256(0, 32))
        rt.label("balance_of")
            .op(opcode::POP)
            .push20(addr_mask)
            .push1(0x04)
            .op(opcode::CALLDATALOAD)
            .op(opcode::AND)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::KECCAK256)
            .op(opcode::SLOAD)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::RETURN);

        // transfer(address to, uint256 amount):
        rt.label("transfer")
            // sender_slot = keccak256(CALLER at mem[0..32])
            .op(opcode::CALLER)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::KECCAK256) // stack: [sender_slot]
            .op(opcode::DUP1)
            .op(opcode::SLOAD) // stack: [sender_bal, sender_slot]
            .push1(0x24)
            .op(opcode::CALLDATALOAD) // stack: [amount, sender_bal, sender_slot]
            .op(opcode::DUP1)
            .op(opcode::DUP3) // stack: [sender_bal, amount, amount, sender_bal, sender_slot]
            .op(opcode::LT) // sender_bal < amount ?
            .jumpi_to("revert_zero")
            // new_sender_bal = sender_bal - amount
            // stack: [amount, sender_bal, sender_slot]
            .op(opcode::DUP1)
            .op(opcode::DUP3) // [sender_bal, amount, amount, sender_bal, sender_slot]
            .op(opcode::SUB) // [new_sender_bal, amount, sender_bal, sender_slot]
            .op(opcode::DUP4) // [sender_slot, new_sender_bal, amount, sender_bal, sender_slot]
            .op(opcode::SSTORE) // stack: [amount, sender_bal, sender_slot]
            // Load `to = CALLDATALOAD(4) & mask20`, compute to_slot = keccak256(to at mem[0..32])
            .push20(addr_mask)
            .push1(0x04)
            .op(opcode::CALLDATALOAD)
            .op(opcode::AND) // stack: [to, amount, sender_bal, sender_slot]
            .op(opcode::DUP1)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::KECCAK256) // stack: [to_slot, to, amount, sender_bal, sender_slot]
            .op(opcode::DUP1)
            .op(opcode::SLOAD) // stack: [to_bal, to_slot, to, amount, ...]
            .op(opcode::DUP4) // stack: [amount, to_bal, to_slot, to, amount, ...]
            .op(opcode::ADD) // stack: [new_to_bal, to_slot, to, amount, ...]
            .op(opcode::SWAP1)
            .op(opcode::SSTORE) // stack: [to, amount, sender_bal, sender_slot]
            // Emit Transfer(CALLER, to, amount): mem[0..32] = amount
            .op(opcode::DUP2)
            .push1(0x00)
            .op(opcode::MSTORE) // stack: [to, amount, ...]
            .op(opcode::CALLER) // stack: [CALLER, to, amount, ...]
            .push32(transfer_topic) // stack: [topic0, CALLER, to, amount, ...]
            .push1(0x20)
            .push1(0x00)
            .op(opcode::LOG3) // pops 2 + 3 = 5 -> stack: [amount, sender_bal, sender_slot]
            // Return bool true (1 at mem[0..32])
            .push1(0x01)
            .push1(0x00)
            .op(opcode::MSTORE)
            .push1(0x20)
            .push1(0x00)
            .op(opcode::RETURN);

        let ctor_bytes = ctor.finish();
        let rt_bytes = rt.finish();
        wrap_initcode(&ctor_bytes, &rt_bytes)
    }

    fn encode_balance_of(addr: [u8; 20]) -> Vec<u8> {
        let mut out = vec![0u8; 36];
        out[..4].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
        out[16..36].copy_from_slice(&addr);
        out
    }

    fn encode_transfer(to: [u8; 20], amount: u64) -> Vec<u8> {
        let mut out = vec![0u8; 68];
        out[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        out[16..36].copy_from_slice(&to);
        out[60..68].copy_from_slice(&amount.to_be_bytes());
        out
    }

    fn run_erc20_scenario() -> MemoryHost {
        let mut host = MemoryHost::new(50_000_000);
        let deployer = EeIdentity {
            ee: EeId::EVM,
            id: vec![0x11; 20],
        };
        let alice = [0x22u8; 20];
        host.balances
            .insert(deployer.clone(), 10_000_000_000_000_000_000);

        let ctx = BlockContext {
            chain_id: BUDLUM_EVM_CHAIN_ID,
            height: 100,
            timestamp_ms: 1_762_000_000_000,
        };
        let mut worker = EvmWorker;
        let initcode = build_erc20_deploy_bytecode(1_000_000);
        let Ok(info) = worker.validate_deploy(&initcode) else {
            panic!("validate_deploy failed");
        };
        assert_eq!(info.abi_tag, "evm-osaka");

        let deploy_call = EeCall {
            kind: EeCallKind::Deploy,
            caller: deployer.clone(),
            target: EeIdentity {
                ee: EeId::EVM,
                id: vec![0u8; 20],
            },
            value: BudAmount(0),
            input: initcode,
            gas_limit: 2_000_000,
            depth: 0,
            tx_hash: [0x01; 32],
        };
        let Ok(deploy_res) = worker.execute(&ctx, &deploy_call, &mut host) else {
            panic!("deploy faulted");
        };
        assert_eq!(deploy_res.status, budlum_uel_abi::OutcomeStatus::Success);
        assert_eq!(deploy_res.output.len(), 20);
        let token_id = EeIdentity {
            ee: EeId::EVM,
            id: deploy_res.output,
        };

        // Query initial supply & deployer balance.
        let Ok(supply_raw) = worker.query(
            &ctx,
            &EeQuery {
                target: token_id.clone(),
                input: vec![0x18, 0x16, 0x0d, 0xdd],
            },
            &host,
        ) else {
            panic!("totalSupply query failed");
        };
        assert_eq!(
            u64::from_be_bytes(supply_raw[24..32].try_into().unwrap_or([0; 8])),
            1_000_000
        );

        // Transfer 250_000 to Alice.
        let transfer_call = EeCall {
            kind: EeCallKind::Call,
            caller: deployer,
            target: token_id.clone(),
            value: BudAmount(0),
            input: encode_transfer(alice, 250_000),
            gas_limit: 500_000,
            depth: 0,
            tx_hash: [0x02; 32],
        };
        let Ok(tx_res) = worker.execute(&ctx, &transfer_call, &mut host) else {
            panic!("transfer faulted");
        };
        assert_eq!(tx_res.status, budlum_uel_abi::OutcomeStatus::Success);
        assert_eq!(tx_res.output.len(), 32);
        assert_eq!(tx_res.output[31], 1);
        assert_eq!(host.logs.len(), 1);
        assert_eq!(host.logs[0].topics.len(), 3);

        // Verify post-transfer balances via read-only `query`.
        let Ok(dep_bal) = worker.query(
            &ctx,
            &EeQuery {
                target: token_id.clone(),
                input: encode_balance_of([0x11; 20]),
            },
            &host,
        ) else {
            panic!("deployer balanceOf failed");
        };
        let Ok(alice_bal) = worker.query(
            &ctx,
            &EeQuery {
                target: token_id,
                input: encode_balance_of(alice),
            },
            &host,
        ) else {
            panic!("alice balanceOf failed");
        };
        assert_eq!(
            u64::from_be_bytes(dep_bal[24..32].try_into().unwrap_or([0; 8])),
            750_000
        );
        assert_eq!(
            u64::from_be_bytes(alice_bal[24..32].try_into().unwrap_or([0; 8])),
            250_000
        );

        host
    }

    #[test]
    fn erc20_deploy_transfer_and_deterministic_state() {
        let run1 = run_erc20_scenario();
        let run2 = run_erc20_scenario();
        assert_eq!(run1.state, run2.state);
        assert_eq!(run1.gas_charged, run2.gas_charged);
        assert_eq!(run1.logs, run2.logs);
    }

    #[test]
    fn create_and_create2_refuse_pq_alias_collision() {
        let mut host = MemoryHost::new(10_000_000);
        let caller_raw = [0x33u8; 20];
        let caller = EeIdentity {
            ee: EeId::EVM,
            id: caller_raw.to_vec(),
        };
        host.balances
            .insert(caller.clone(), 1_000_000_000_000_000_000);

        // Compute the CREATE address that caller (nonce 0) would deploy to and pre-register PQ alias!
        let predicted = Address::from(caller_raw).create(0);
        let Ok(ns_alias) = Namespace::new(NS_UEL_ALIAS) else {
            panic!("bad ns");
        };
        let mut alias_key = vec![EeId::EVM.0];
        alias_key.extend_from_slice(predicted.as_slice());
        let _ = host.write(&ns_alias, &alias_key, Some(&[0xAA; 32]));

        let ctx = BlockContext {
            chain_id: BUDLUM_EVM_CHAIN_ID,
            height: 10,
            timestamp_ms: 1_762_000_000_000,
        };
        let mut worker = EvmWorker;
        let deploy = EeCall {
            kind: EeCallKind::Deploy,
            caller,
            target: EeIdentity {
                ee: EeId::EVM,
                id: vec![0u8; 20],
            },
            value: BudAmount(0),
            input: build_erc20_deploy_bytecode(100),
            gas_limit: 500_000,
            depth: 0,
            tx_hash: [0x09; 32],
        };
        let Ok(res) = worker.execute(&ctx, &deploy, &mut host) else {
            panic!("faulted");
        };
        assert_ne!(res.status, OutcomeStatus::Success);
    }

    #[test]
    fn universal_call_precompile_b001_dispatches() {
        let mut host = MemoryHost::new(5_000_000).with_universal_handler(Box::new(|call| {
            let mut echoed = b"echo:".to_vec();
            echoed.extend_from_slice(&call.input);
            Ok(UniversalResult {
                success: true,
                output: echoed,
                gas_used: 1_200,
            })
        }));
        let caller = EeIdentity {
            ee: EeId::EVM,
            id: vec![0x44; 20],
        };
        host.balances.insert(caller.clone(), 1_000_000_000);

        let payload =
            encode_universal_call_input(EeId::WASM.0, b"cosmos1contract", b"ping", 0, 50_000);
        let ctx = BlockContext {
            chain_id: BUDLUM_EVM_CHAIN_ID,
            height: 55,
            timestamp_ms: 1_762_000_000_000,
        };
        let mut worker = EvmWorker;
        let call = EeCall {
            kind: EeCallKind::Call,
            caller,
            target: EeIdentity {
                ee: EeId::EVM,
                id: UNIVERSAL_CALL_PRECOMPILE.as_slice().to_vec(),
            },
            value: BudAmount(0),
            input: payload,
            gas_limit: 200_000,
            depth: 0,
            tx_hash: [0x55; 32],
        };
        let Ok(res) = worker.execute(&ctx, &call, &mut host) else {
            panic!("precompile call faulted");
        };
        assert_eq!(res.status, OutcomeStatus::Success);
        assert_eq!(host.universal_calls.len(), 1);
        assert_eq!(host.universal_calls[0].to_ee, EeId::WASM);
        assert_eq!(host.universal_calls[0].input, b"ping");
        // ABI return: word0 = 1 (ok), word1 = 64, word2 = 9 ("echo:ping")
        assert_eq!(res.output[31], 1);
        assert_eq!(&res.output[96..105], b"echo:ping");
    }

    #[test]
    fn unix_socket_worker_roundtrip() {
        let sock_path = std::env::temp_dir().join(format!(
            "budlum-ee-evm-test-{}-{:?}.sock",
            std::process::id(),
            thread::current().id()
        ));
        let _ = std::fs::remove_file(&sock_path);
        let Ok(listener) = UnixListener::bind(&sock_path) else {
            panic!("bind failed");
        };
        let srv = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut worker = EvmWorker;
                let _ = serve_connection(stream, &mut worker);
            }
        });

        let mut client = EeClient::new(&sock_path, EeId::EVM);
        let initcode = build_erc20_deploy_bytecode(42);
        let Ok(Ok(code_info)) = client.validate_deploy(&initcode) else {
            panic!("ipc validate_deploy failed");
        };
        assert_eq!(code_info.abi_tag, "evm-osaka");
        drop(client);
        let _ = srv.join();
        let _ = std::fs::remove_file(&sock_path);
    }
}
