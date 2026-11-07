//! EVM Universal Call precompile (`0x000000000000000000000000000000000000B001`,
//! `Section 8.7.2` & `8.7.3`).
//!
//! Dispatches `call(uint8,bytes,bytes,uint256,uint64)` and
//! `staticCall(uint8,bytes,bytes,uint64)` to `HostApi::universal_call` and
//! records a journaled `UniversalCallExecuted(uint8 ee, bytes target, bool ok)`
//! log from `0x...B001` so EVM indexers observe cross-VM invocations.

use budlum_uel_abi::{BudAmount, EeId, EeIdentity, UniversalCall};
use revm::context::{BlockEnv, CfgEnv, Context, Journal, TxEnv};
use revm::context_interface::JournalTr;
use revm::interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{Bytes, Log, LogData, B256};

use crate::abi::{
    decode_precompile_call, encode_precompile_return, PRECOMPILE_BASE_GAS,
    UNIVERSAL_CALL_PRECOMPILE,
};
use crate::db::{evm_identity, HostDb};

/// `keccak256("UniversalCallExecuted(uint8,bytes,bool)")`.
pub const UNIVERSAL_CALL_EXECUTED_TOPIC0: [u8; 32] = [
    0xea, 0x6f, 0x80, 0x57, 0xef, 0xfc, 0x57, 0x9e, 0xc4, 0xfd, 0xcc, 0x82, 0x72, 0xe4, 0x27, 0xc5,
    0x68, 0x85, 0xa2, 0x1e, 0x67, 0xba, 0xd5, 0xcc, 0x8d, 0xc9, 0x7d, 0x44, 0xda, 0xee, 0x32, 0xe3,
];

type EvmHostCtx<'a> = Context<BlockEnv, TxEnv, CfgEnv, HostDb<'a>, Journal<HostDb<'a>>, ()>;

/// ABI-encode event data `(uint8 ee, bytes target, bool ok)` for `UniversalCallExecuted`.
#[must_use]
pub fn encode_universal_call_executed_data(ee: u8, target: &[u8], ok: bool) -> Vec<u8> {
    let padded_len = target.len().div_ceil(32) * 32;
    // Head: 3 words (ee, offset=96, ok), Tail: len word + padded target bytes
    let mut out = vec![0u8; 96 + 32 + padded_len];
    if let Some(s) = out.get_mut(31) {
        *s = ee;
    }
    if let Some(s) = out.get_mut(63) {
        *s = 96;
    }
    if ok {
        if let Some(s) = out.get_mut(95) {
            *s = 1;
        }
    }
    let len_be = (target.len() as u64).to_be_bytes();
    if let Some(dst) = out.get_mut(120..128) {
        dst.copy_from_slice(&len_be);
    }
    if let Some(dst) = out.get_mut(128..128 + target.len()) {
        dst.copy_from_slice(target);
    }
    out
}

/// Intercept and execute a call targeting `UNIVERSAL_CALL_PRECOMPILE` (`0x...B001`).
pub(crate) fn handle_universal_precompile_call(
    context: &mut EvmHostCtx<'_>,
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
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        let _ = gas.record_regular_cost(PRECOMPILE_BASE_GAS);
        return Some(CallOutcome::new(
            InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
            mem_offset,
        ));
    };

    let is_static = inputs.is_static || parsed.is_static_selector;
    if is_static && (!parsed.is_static_selector && parsed.value_attos > 0) {
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
    let target_copy = parsed.target.clone();
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
        is_static,
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
            if !is_static {
                let ev_data = encode_universal_call_executed_data(
                    parsed.target_ee,
                    &target_copy,
                    ures.success,
                );
                context.journaled_state.log(Log {
                    address: UNIVERSAL_CALL_PRECOMPILE,
                    data: LogData::new_unchecked(
                        vec![B256::from(UNIVERSAL_CALL_EXECUTED_TOPIC0)],
                        Bytes::from(ev_data),
                    ),
                });
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
