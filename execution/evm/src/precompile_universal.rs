//! EVM Universal Call precompile (`0x000000000000000000000000000000000000B001`,
//! `Section 8.7.2` & `8.7.3`).
//!
//! Dispatches `call(uint8,bytes,bytes,uint256,uint64)` and
//! `staticCall(uint8,bytes,bytes,uint64)` to `HostApi::universal_call` and
//! records a journaled `UniversalCallExecuted(uint8 ee, bytes target, bool ok)`
//! log from `0x...B001` so EVM indexers observe cross-VM invocations.

use budlum_uel_abi::{BudAmount, EeId, EeIdentity, Namespace, UniversalCall};
use revm::context::{BlockEnv, CfgEnv, Context, Journal, TxEnv};
use revm::context_interface::JournalTr;
use revm::interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult};
use revm::primitives::{keccak256, Bytes, Log, LogData, B256};

use crate::abi::{
    decode_precompile_call, decode_uol_call, decode_uol_offer_bytes, encode_precompile_return,
    encode_uol_offer_bytes, uol_selector, DecodedUolCall, UolOfferRecord, NS_UEL_ASSETS,
    PRECOMPILE_BASE_GAS, UNIVERSAL_CALL_PRECOMPILE, UOL_PRECOMPILE, UOL_PRECOMPILE_GAS,
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

fn uol_bal_key(class_id: &[u8; 32], holder: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32 + holder.len());
    k.extend_from_slice(b"uol:bal:");
    k.extend_from_slice(class_id);
    k.extend_from_slice(holder);
    k
}

fn uol_holder_key(asset_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(11 + 32);
    k.extend_from_slice(b"uol:holder:");
    k.extend_from_slice(asset_id);
    k
}

fn uol_offer_key(offer_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(10 + 32);
    k.extend_from_slice(b"uol:offer:");
    k.extend_from_slice(offer_id);
    k
}

fn uol_read_balance(
    host: &dyn budlum_uel_abi::HostRead,
    ns: &Namespace,
    class_id: &[u8; 32],
    holder: &[u8],
) -> Option<u128> {
    let bytes = host.read(ns, &uol_bal_key(class_id, holder)).ok()??;
    if bytes.len() != 16 {
        return None;
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Some(u128::from_le_bytes(arr))
}

fn uol_revert(
    msg: &[u8],
    gas: Gas,
    mem_offset: std::ops::Range<usize>,
) -> Option<CallOutcome> {
    Some(CallOutcome::new(
        InterpreterResult::new(InstructionResult::Revert, Bytes::copy_from_slice(msg), gas),
        mem_offset,
    ))
}

fn uol_write_balance(
    host: &mut dyn budlum_uel_abi::HostApi,
    ns: &Namespace,
    class_id: &[u8; 32],
    holder: &[u8],
    bal: u128,
) -> Result<(), budlum_uel_abi::HostError> {
    let le = bal.to_le_bytes();
    let val = (bal > 0).then_some(le.as_slice());
    host.write(ns, &uol_bal_key(class_id, holder), val)
}

fn uol_block_height(context: &EvmHostCtx<'_>) -> u64 {
    let limbs = context.block.number.as_limbs();
    if limbs[1] | limbs[2] | limbs[3] != 0 {
        u64::MAX
    } else {
        limbs[0]
    }
}

fn handle_uol_precompile_call(
    context: &mut EvmHostCtx<'_>,
    inputs: &mut CallInputs,
) -> Option<CallOutcome> {
    if inputs.bytecode_address != UOL_PRECOMPILE && inputs.target_address != UOL_PRECOMPILE {
        return None;
    }
    let calldata: Vec<u8> = inputs.input.as_bytes(context).to_vec();
    let mem_offset = inputs.return_memory_offset.clone();
    if inputs.gas_limit < UOL_PRECOMPILE_GAS {
        return Some(CallOutcome::new(
            InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
            mem_offset,
        ));
    }
    let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
    if !gas.record_regular_cost(UOL_PRECOMPILE_GAS) {
        return Some(CallOutcome::new(
            InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
            mem_offset,
        ));
    }
    let Some(decoded) = decode_uol_call(&calldata) else {
        return uol_revert(b"invalid UOL precompile calldata", gas, mem_offset);
    };
    let Ok(ns) = Namespace::new(NS_UEL_ASSETS) else {
        return uol_revert(b"invalid uel/assets namespace", gas, mem_offset);
    };
    let caller20: [u8; 20] = inputs.caller.into_array();
    let block_height = uol_block_height(context);

    match decoded {
        DecodedUolCall::BalanceOf { class_id, holder } => {
            let bal = uol_read_balance(context.journaled_state.db().host, &ns, &class_id, &holder)
                .unwrap_or(0);
            let mut word = [0u8; 32];
            if let Some(dst) = word.get_mut(16..32) {
                dst.copy_from_slice(&bal.to_be_bytes());
            }
            Some(CallOutcome::new(
                InterpreterResult::new(
                    InstructionResult::Return,
                    Bytes::copy_from_slice(&word),
                    gas,
                ),
                mem_offset,
            ))
        }
        DecodedUolCall::HolderOf { asset_id } => {
            let holder = context
                .journaled_state
                .db()
                .host
                .read(&ns, &uol_holder_key(&asset_id))
                .ok()
                .flatten()
                .unwrap_or_default();
            let mut out = vec![0u8; 64 + holder.len().div_ceil(32) * 32];
            if let Some(s) = out.get_mut(31) {
                *s = 32;
            }
            if let Some(dst) = out.get_mut(56..64) {
                let len_be = u64::try_from(holder.len()).unwrap_or(u64::MAX).to_be_bytes();
                dst.copy_from_slice(&len_be);
            }
            if !holder.is_empty() {
                if let Some(dst) = out.get_mut(64..64 + holder.len()) {
                    dst.copy_from_slice(&holder);
                }
            }
            Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Return, Bytes::from(out), gas),
                mem_offset,
            ))
        }
        DecodedUolCall::Transfer {
            class_id,
            asset_id,
            to,
            amount,
        } => {
            if inputs.is_static {
                return uol_revert(b"UOL transfer inside static call", gas, mem_offset);
            }
            if to.is_empty() {
                return uol_revert(b"UOL empty recipient", gas, mem_offset);
            }
            if asset_id == [0u8; 32] && amount == 0 {
                return uol_revert(
                    b"UOL transfer requires asset or non-zero amount",
                    gas,
                    mem_offset,
                );
            }
            let host = &mut *context.journaled_state.db_mut().host;
            let Ok(cp) = host.checkpoint_begin() else {
                return uol_revert(b"UOL checkpoint begin failed", gas, mem_offset);
            };
            if asset_id != [0u8; 32] {
                let hk = uol_holder_key(&asset_id);
                let Some(cur) = host.read(&ns, &hk).ok().flatten() else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL unknown asset", gas, mem_offset);
                };
                if cur.as_slice() != caller20 {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL caller is not asset holder", gas, mem_offset);
                }
                if host.write(&ns, &hk, Some(&to)).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL host write failed", gas, mem_offset);
                }
            }
            if amount > 0 {
                let from_bal = uol_read_balance(host, &ns, &class_id, &caller20).unwrap_or(0);
                let Some(rem) = from_bal.checked_sub(amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL insufficient balance", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &class_id, &caller20, rem).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL host write failed", gas, mem_offset);
                }
                let to_bal = uol_read_balance(host, &ns, &class_id, &to).unwrap_or(0);
                let Some(next_to) = to_bal.checked_add(amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL balance overflow", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &class_id, &to, next_to).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL host write failed", gas, mem_offset);
                }
            }
            if host.checkpoint_commit(cp).is_err() {
                let _ = host.checkpoint_rollback(cp);
                return uol_revert(b"UOL checkpoint commit failed", gas, mem_offset);
            }
            let mut topic = [0u8; 32];
            if let Some(dst) = topic.get_mut(..4) {
                dst.copy_from_slice(&uol_selector("transfer(bytes32,bytes32,bytes,uint128)"));
            }
            context.journaled_state.log(Log {
                address: UOL_PRECOMPILE,
                data: LogData::new_unchecked(
                    vec![B256::from(topic)],
                    Bytes::copy_from_slice(&asset_id),
                ),
            });
            let mut ok_word = [0u8; 32];
            ok_word[31] = 1;
            Some(CallOutcome::new(
                InterpreterResult::new(
                    InstructionResult::Return,
                    Bytes::copy_from_slice(&ok_word),
                    gas,
                ),
                mem_offset,
            ))
        }
        DecodedUolCall::Offer {
            class_id,
            asset_id,
            taker,
            payment,
            amount,
            expiry,
        } => {
            if inputs.is_static {
                return uol_revert(b"UOL offer inside static call", gas, mem_offset);
            }
            if asset_id == [0u8; 32] && amount == 0 {
                return uol_revert(
                    b"UOL offer requires asset or non-zero amount",
                    gas,
                    mem_offset,
                );
            }
            if expiry > 0 && block_height > expiry {
                return uol_revert(b"UOL offer already expired", gas, mem_offset);
            }
            if !payment.is_empty() && payment.len() != 16 && payment.len() != 48 {
                return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
            }
            let host = &mut *context.journaled_state.db_mut().host;
            if asset_id != [0u8; 32] {
                let Some(cur) = host.read(&ns, &uol_holder_key(&asset_id)).ok().flatten() else {
                    return uol_revert(b"UOL unknown asset", gas, mem_offset);
                };
                if cur.as_slice() != caller20 {
                    return uol_revert(b"UOL offerer does not hold asset", gas, mem_offset);
                }
            }
            if amount > 0 && uol_read_balance(host, &ns, &class_id, &caller20).unwrap_or(0) < amount
            {
                return uol_revert(b"UOL offerer balance exhausted", gas, mem_offset);
            }
            let mut preimage = Vec::with_capacity(96 + taker.len() + payment.len());
            preimage.extend_from_slice(b"BDLM_UOL_OFFER_V1");
            preimage.extend_from_slice(&caller20);
            preimage.extend_from_slice(&class_id);
            preimage.extend_from_slice(&asset_id);
            preimage.extend_from_slice(&taker);
            preimage.extend_from_slice(&payment);
            preimage.extend_from_slice(&amount.to_le_bytes());
            preimage.extend_from_slice(&expiry.to_le_bytes());
            let offer_id: [u8; 32] = keccak256(&preimage).into();
            let enc = encode_uol_offer_bytes(&UolOfferRecord {
                maker: caller20,
                class_id,
                asset_id,
                taker,
                payment,
                amount,
                expiry,
            });
            if host
                .write(&ns, &uol_offer_key(&offer_id), Some(&enc))
                .is_err()
            {
                return uol_revert(b"UOL offer write failed", gas, mem_offset);
            }
            Some(CallOutcome::new(
                InterpreterResult::new(
                    InstructionResult::Return,
                    Bytes::copy_from_slice(&offer_id),
                    gas,
                ),
                mem_offset,
            ))
        }
        DecodedUolCall::Accept { offer_id } => {
            if inputs.is_static {
                return uol_revert(b"UOL accept inside static call", gas, mem_offset);
            }
            let ok = uol_offer_key(&offer_id);
            let caller_id = evm_identity(inputs.caller);
            let host = &mut *context.journaled_state.db_mut().host;
            let Ok(Some(raw)) = host.read(&ns, &ok) else {
                return uol_revert(b"UOL unknown offerId", gas, mem_offset);
            };
            let Some(offer) = decode_uol_offer_bytes(&raw) else {
                return uol_revert(b"corrupt UOL offer record", gas, mem_offset);
            };
            if offer.expiry > 0 && block_height > offer.expiry {
                return uol_revert(b"UOL offer expired", gas, mem_offset);
            }
            if !offer.taker.is_empty() && offer.taker.as_slice() != caller20 {
                return uol_revert(b"UOL unauthorized taker", gas, mem_offset);
            }
            let Ok(cp) = host.checkpoint_begin() else {
                return uol_revert(b"UOL checkpoint begin failed", gas, mem_offset);
            };
            if let Ok(pay_arr) = <[u8; 16]>::try_from(offer.payment.as_slice()) {
                let pay_attos = u128::from_le_bytes(pay_arr);
                if pay_attos > 0 {
                    let maker_id = EeIdentity {
                        ee: EeId::EVM,
                        id: offer.maker.to_vec(),
                    };
                    if host.bud_transfer(&caller_id, &maker_id, pay_attos).is_err() {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(b"UOL native payment failed", gas, mem_offset);
                    }
                }
            } else if offer.payment.len() == 48 {
                let Some(class_slice) = offer.payment.get(..32) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let Some(amt_slice) = offer.payment.get(32..48) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let Ok(pay_class) = <[u8; 32]>::try_from(class_slice) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let Ok(pay_arr) = <[u8; 16]>::try_from(amt_slice) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let pay_amt = u128::from_le_bytes(pay_arr);
                if pay_amt > 0 {
                    let payer_bal = uol_read_balance(host, &ns, &pay_class, &caller20).unwrap_or(0);
                    let Some(rem_pay) = payer_bal.checked_sub(pay_amt) else {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(b"UOL taker payment balance exhausted", gas, mem_offset);
                    };
                    if uol_write_balance(host, &ns, &pay_class, &caller20, rem_pay).is_err() {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(b"UOL payment write failed", gas, mem_offset);
                    }
                    let maker_pay =
                        uol_read_balance(host, &ns, &pay_class, &offer.maker).unwrap_or(0);
                    let Some(next_maker_pay) = maker_pay.checked_add(pay_amt) else {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(b"UOL payment overflow", gas, mem_offset);
                    };
                    if uol_write_balance(host, &ns, &pay_class, &offer.maker, next_maker_pay)
                        .is_err()
                    {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(b"UOL payment write failed", gas, mem_offset);
                    }
                }
            } else if !offer.payment.is_empty() {
                let _ = host.checkpoint_rollback(cp);
                return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
            }
            if offer.asset_id != [0u8; 32] {
                let hk = uol_holder_key(&offer.asset_id);
                let Some(cur_holder) = host.read(&ns, &hk).ok().flatten() else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL offer asset missing", gas, mem_offset);
                };
                if cur_holder.as_slice() != offer.maker {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL maker no longer holds offered asset", gas, mem_offset);
                }
                if host.write(&ns, &hk, Some(&caller20)).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL holder write failed", gas, mem_offset);
                }
            }
            if offer.amount > 0 {
                let maker_bal =
                    uol_read_balance(host, &ns, &offer.class_id, &offer.maker).unwrap_or(0);
                let Some(rem) = maker_bal.checked_sub(offer.amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL maker balance exhausted", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &offer.class_id, &offer.maker, rem).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL maker write failed", gas, mem_offset);
                }
                let taker_bal =
                    uol_read_balance(host, &ns, &offer.class_id, &caller20).unwrap_or(0);
                let Some(next_taker) = taker_bal.checked_add(offer.amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL balance overflow", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &offer.class_id, &caller20, next_taker).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL taker write failed", gas, mem_offset);
                }
            }
            if host.write(&ns, &ok, None).is_err() {
                let _ = host.checkpoint_rollback(cp);
                return uol_revert(b"UOL offer delete failed", gas, mem_offset);
            }
            if host.checkpoint_commit(cp).is_err() {
                let _ = host.checkpoint_rollback(cp);
                return uol_revert(b"UOL checkpoint commit failed", gas, mem_offset);
            }
            let mut topic = [0u8; 32];
            if let Some(dst) = topic.get_mut(..4) {
                dst.copy_from_slice(&uol_selector("accept(bytes32)"));
            }
            context.journaled_state.log(Log {
                address: UOL_PRECOMPILE,
                data: LogData::new_unchecked(
                    vec![B256::from(topic)],
                    Bytes::copy_from_slice(&offer_id),
                ),
            });
            let mut ok_word = [0u8; 32];
            ok_word[31] = 1;
            Some(CallOutcome::new(
                InterpreterResult::new(
                    InstructionResult::Return,
                    Bytes::copy_from_slice(&ok_word),
                    gas,
                ),
                mem_offset,
            ))
        }
    }
}

/// Intercept and execute a call targeting `UNIVERSAL_CALL_PRECOMPILE` (`0x...B001`)
/// or `UOL_PRECOMPILE` (`0x...B002`).
pub(crate) fn handle_universal_precompile_call(
    context: &mut EvmHostCtx<'_>,
    inputs: &mut CallInputs,
) -> Option<CallOutcome> {
    if let Some(uol) = handle_uol_precompile_call(context, inputs) {
        return Some(uol);
    }
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
