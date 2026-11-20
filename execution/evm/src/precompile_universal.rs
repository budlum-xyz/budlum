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
use revm::interpreter::{
    CallInputs, CallOutcome, CallScheme, Gas, InstructionResult, InterpreterResult,
};
use revm::primitives::{keccak256, Address, Bytes, Log, LogData, B256, U256};

use crate::abi::{
    decode_precompile_call, decode_uol_call, decode_uol_offer_bytes, encode_precompile_return,
    encode_uol_offer_bytes, precompile_word_gas, uol_selector, DecodedUolCall, UolOfferRecord,
    MAX_PRECOMPILE_BYTES, NS_UEL_ASSETS, PRECOMPILE_BASE_GAS, UNIVERSAL_CALL_PRECOMPILE,
    UOL_PRECOMPILE, UOL_PRECOMPILE_GAS,
};
use crate::db::{evm_identity, HostDb};

/// Frame-scoped record of a `0x...B001` caller debit synced into Revm state.
/// Restored if an enclosing EVM call frame later reverts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrecompileValueDebit {
    pub caller: Address,
    pub amount: U256,
}

/// `keccak256("UniversalCallExecuted(uint8,bytes,bool)")`.
pub const UNIVERSAL_CALL_EXECUTED_TOPIC0: [u8; 32] = [
    0xea, 0x6f, 0x80, 0x57, 0xef, 0xfc, 0x57, 0x9e, 0xc4, 0xfd, 0xcc, 0x82, 0x72, 0xe4, 0x27, 0xc5,
    0x68, 0x85, 0xa2, 0x1e, 0x67, 0xba, 0xd5, 0xcc, 0x8d, 0xc9, 0x7d, 0x44, 0xda, 0xee, 0x32, 0xe3,
];

type EvmHostCtx<'a> = Context<BlockEnv, TxEnv, CfgEnv, HostDb<'a>, Journal<HostDb<'a>>, ()>;

fn precompile_scheme_allowed(scheme: CallScheme) -> bool {
    matches!(scheme, CallScheme::Call | CallScheme::StaticCall)
}

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
) -> Result<u128, &'static [u8]> {
    match host.read(ns, &uol_bal_key(class_id, holder)) {
        Ok(None) => Ok(0),
        Ok(Some(bytes)) => {
            let Ok(arr) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                return Err(b"UOL corrupt balance");
            };
            Ok(u128::from_le_bytes(arr))
        }
        Err(_) => Err(b"UOL balance read failed"),
    }
}

fn uol_revert(msg: &[u8], gas: Gas, mem_offset: std::ops::Range<usize>) -> Option<CallOutcome> {
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
    // These host-backed operations must execute in the precompile's own
    // address context. DELEGATECALL/CALLCODE change the storage/caller context
    // while still executing code at the precompile address; never dispatch
    // those schemes into mutable host operations.
    if !precompile_scheme_allowed(inputs.scheme) {
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        if !gas.record_regular_cost(UOL_PRECOMPILE_GAS) {
            return Some(CallOutcome::new(
                InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                inputs.return_memory_offset.clone(),
            ));
        }
        return Some(CallOutcome::new(
            InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
            inputs.return_memory_offset.clone(),
        ));
    }
    let calldata: Vec<u8> = inputs.input.as_bytes(context).to_vec();
    let mem_offset = inputs.return_memory_offset.clone();
    let entry_gas = UOL_PRECOMPILE_GAS.saturating_add(precompile_word_gas(calldata.len()));
    if inputs.gas_limit < entry_gas {
        return Some(CallOutcome::new(
            InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
            mem_offset,
        ));
    }
    let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
    if !gas.record_regular_cost(entry_gas) {
        return Some(CallOutcome::new(
            InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
            mem_offset,
        ));
    }
    if calldata.len() > MAX_PRECOMPILE_BYTES {
        return uol_revert(b"UOL calldata exceeds maximum size", gas, mem_offset);
    }
    if !inputs.call_value().is_zero() {
        return uol_revert(b"UOL precompile rejects native msg.value", gas, mem_offset);
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
            let bal = match uol_read_balance(
                context.journaled_state.db().host,
                &ns,
                &class_id,
                &holder,
            ) {
                Ok(v) => v,
                Err(msg) => return uol_revert(msg, gas, mem_offset),
            };
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
            let holder = match context
                .journaled_state
                .db()
                .host
                .read(&ns, &uol_holder_key(&asset_id))
            {
                Ok(Some(raw)) => raw,
                Ok(None) => Vec::new(),
                Err(_) => return uol_revert(b"UOL holder read failed", gas, mem_offset),
            };
            let mut out = vec![0u8; 64 + holder.len().div_ceil(32) * 32];
            if !gas.record_regular_cost(precompile_word_gas(out.len())) {
                return Some(CallOutcome::new(
                    InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                    mem_offset,
                ));
            }
            if let Some(s) = out.get_mut(31) {
                *s = 32;
            }
            if let Some(dst) = out.get_mut(56..64) {
                let len_be = u64::try_from(holder.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes();
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
                let from_bal = match uol_read_balance(host, &ns, &class_id, &caller20) {
                    Ok(v) => v,
                    Err(msg) => {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(msg, gas, mem_offset);
                    }
                };
                let Some(rem) = from_bal.checked_sub(amount) else {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL insufficient balance", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &class_id, &caller20, rem).is_err() {
                    let _ = host.checkpoint_rollback(cp);
                    return uol_revert(b"UOL host write failed", gas, mem_offset);
                }
                let to_bal = match uol_read_balance(host, &ns, &class_id, &to) {
                    Ok(v) => v,
                    Err(msg) => {
                        let _ = host.checkpoint_rollback(cp);
                        return uol_revert(msg, gas, mem_offset);
                    }
                };
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
            if amount > 0 {
                let bal = match uol_read_balance(host, &ns, &class_id, &caller20) {
                    Ok(v) => v,
                    Err(msg) => return uol_revert(msg, gas, mem_offset),
                };
                if bal < amount {
                    return uol_revert(b"UOL offerer balance exhausted", gas, mem_offset);
                }
            }
            let mut preimage = Vec::with_capacity(112 + taker.len() + payment.len());
            preimage.extend_from_slice(b"BDLM_UOL_OFFER_V1");
            preimage.extend_from_slice(&caller20);
            preimage.extend_from_slice(&class_id);
            preimage.extend_from_slice(&asset_id);
            preimage.extend_from_slice(&(taker.len() as u64).to_le_bytes());
            preimage.extend_from_slice(&taker);
            preimage.extend_from_slice(&(payment.len() as u64).to_le_bytes());
            preimage.extend_from_slice(&payment);
            preimage.extend_from_slice(&amount.to_le_bytes());
            preimage.extend_from_slice(&expiry.to_le_bytes());
            let offer_id: [u8; 32] = keccak256(&preimage).into();
            let offer_key = uol_offer_key(&offer_id);
            match host.read(&ns, &offer_key) {
                Ok(Some(_)) => return uol_revert(b"UOL offer already exists", gas, mem_offset),
                Ok(None) => {}
                Err(_) => return uol_revert(b"UOL offer read failed", gas, mem_offset),
            }
            let Some(enc) = encode_uol_offer_bytes(&UolOfferRecord {
                maker: caller20,
                class_id,
                asset_id,
                taker,
                payment,
                amount,
                expiry,
            }) else {
                return uol_revert(b"UOL offer payload too large", gas, mem_offset);
            };
            if host.write(&ns, &offer_key, Some(&enc)).is_err() {
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
            let offer = {
                let host = &*context.journaled_state.db().host;
                let Ok(Some(raw)) = host.read(&ns, &ok) else {
                    return uol_revert(b"UOL unknown offerId", gas, mem_offset);
                };
                let Some(offer) = decode_uol_offer_bytes(&raw) else {
                    return uol_revert(b"corrupt UOL offer record", gas, mem_offset);
                };
                offer
            };
            if offer.expiry > 0 && block_height > offer.expiry {
                return uol_revert(b"UOL offer expired", gas, mem_offset);
            }
            if !offer.taker.is_empty() && offer.taker.as_slice() != caller20 {
                return uol_revert(b"UOL unauthorized taker", gas, mem_offset);
            }
            let native_pay_attos =
                if let Ok(pay_arr) = <[u8; 16]>::try_from(offer.payment.as_slice()) {
                    Some(u128::from_le_bytes(pay_arr))
                } else {
                    None
                };
            let native_pay_checkpoint = if let Some(pay_attos) = native_pay_attos {
                if pay_attos > 0 {
                    let maker_addr = Address::from(offer.maker);
                    if context.journaled_state.load_account(inputs.caller).is_err()
                        || context.journaled_state.load_account(maker_addr).is_err()
                    {
                        return uol_revert(b"UOL payment account load failed", gas, mem_offset);
                    }
                    let jcp = context.journaled_state.checkpoint();
                    match context.journaled_state.transfer(
                        inputs.caller,
                        maker_addr,
                        U256::from(pay_attos),
                    ) {
                        Ok(None) => Some(jcp),
                        Ok(Some(_)) | Err(_) => {
                            context.journaled_state.checkpoint_revert(jcp);
                            return uol_revert(b"UOL native payment failed", gas, mem_offset);
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let rollback_all = |context: &mut EvmHostCtx<'_>, cp: Option<u64>| {
                if let Some(id) = cp {
                    let _ = context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_rollback(id);
                }
                if let Some(jcp) = native_pay_checkpoint {
                    context.journaled_state.checkpoint_revert(jcp);
                }
            };
            let Ok(cp) = context.journaled_state.db_mut().host.checkpoint_begin() else {
                rollback_all(context, None);
                return uol_revert(b"UOL checkpoint begin failed", gas, mem_offset);
            };
            if native_pay_attos.is_none() && offer.payment.len() == 48 {
                let (Some(class_slice), Some(amt_slice)) =
                    (offer.payment.get(..32), offer.payment.get(32..48))
                else {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let (Ok(pay_class), Ok(pay_arr)) = (
                    <[u8; 32]>::try_from(class_slice),
                    <[u8; 16]>::try_from(amt_slice),
                ) else {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
                };
                let pay_amt = u128::from_le_bytes(pay_arr);
                if pay_amt > 0 {
                    let host = &mut *context.journaled_state.db_mut().host;
                    let payer_bal = match uol_read_balance(host, &ns, &pay_class, &caller20) {
                        Ok(v) => v,
                        Err(msg) => {
                            rollback_all(context, Some(cp));
                            return uol_revert(msg, gas, mem_offset);
                        }
                    };
                    let Some(rem_pay) = payer_bal.checked_sub(pay_amt) else {
                        rollback_all(context, Some(cp));
                        return uol_revert(b"UOL taker payment balance exhausted", gas, mem_offset);
                    };
                    if uol_write_balance(host, &ns, &pay_class, &caller20, rem_pay).is_err() {
                        rollback_all(context, Some(cp));
                        return uol_revert(b"UOL payment write failed", gas, mem_offset);
                    }
                    let maker_pay = match uol_read_balance(host, &ns, &pay_class, &offer.maker) {
                        Ok(v) => v,
                        Err(msg) => {
                            rollback_all(context, Some(cp));
                            return uol_revert(msg, gas, mem_offset);
                        }
                    };
                    let Some(next_maker_pay) = maker_pay.checked_add(pay_amt) else {
                        rollback_all(context, Some(cp));
                        return uol_revert(b"UOL payment overflow", gas, mem_offset);
                    };
                    if uol_write_balance(host, &ns, &pay_class, &offer.maker, next_maker_pay)
                        .is_err()
                    {
                        rollback_all(context, Some(cp));
                        return uol_revert(b"UOL payment write failed", gas, mem_offset);
                    }
                }
            } else if native_pay_attos.is_none() && !offer.payment.is_empty() {
                rollback_all(context, Some(cp));
                return uol_revert(b"unsupported UOL offer payment encoding", gas, mem_offset);
            }
            if offer.asset_id != [0u8; 32] {
                let hk = uol_holder_key(&offer.asset_id);
                let host = &mut *context.journaled_state.db_mut().host;
                let Some(cur_holder) = host.read(&ns, &hk).ok().flatten() else {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL offer asset missing", gas, mem_offset);
                };
                if cur_holder.as_slice() != offer.maker {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL maker no longer holds offered asset", gas, mem_offset);
                }
                if host.write(&ns, &hk, Some(&caller20)).is_err() {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL holder write failed", gas, mem_offset);
                }
            }
            if offer.amount > 0 {
                let host = &mut *context.journaled_state.db_mut().host;
                let maker_bal = match uol_read_balance(host, &ns, &offer.class_id, &offer.maker) {
                    Ok(v) => v,
                    Err(msg) => {
                        rollback_all(context, Some(cp));
                        return uol_revert(msg, gas, mem_offset);
                    }
                };
                let Some(rem) = maker_bal.checked_sub(offer.amount) else {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL maker balance exhausted", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &offer.class_id, &offer.maker, rem).is_err() {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL maker write failed", gas, mem_offset);
                }
                let taker_bal = match uol_read_balance(host, &ns, &offer.class_id, &caller20) {
                    Ok(v) => v,
                    Err(msg) => {
                        rollback_all(context, Some(cp));
                        return uol_revert(msg, gas, mem_offset);
                    }
                };
                let Some(next_taker) = taker_bal.checked_add(offer.amount) else {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL balance overflow", gas, mem_offset);
                };
                if uol_write_balance(host, &ns, &offer.class_id, &caller20, next_taker).is_err() {
                    rollback_all(context, Some(cp));
                    return uol_revert(b"UOL taker write failed", gas, mem_offset);
                }
            }
            if context
                .journaled_state
                .db_mut()
                .host
                .write(&ns, &ok, None)
                .is_err()
            {
                rollback_all(context, Some(cp));
                return uol_revert(b"UOL offer delete failed", gas, mem_offset);
            }
            if context
                .journaled_state
                .db_mut()
                .host
                .checkpoint_commit(cp)
                .is_err()
            {
                rollback_all(context, Some(cp));
                return uol_revert(b"UOL checkpoint commit failed", gas, mem_offset);
            }
            if let Some(jcp) = native_pay_checkpoint {
                let _ = jcp;
                context.journaled_state.checkpoint_commit();
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
    recorded_debit: &mut Option<PrecompileValueDebit>,
) -> Option<CallOutcome> {
    if let Some(uol) = handle_uol_precompile_call(context, inputs) {
        return Some(uol);
    }
    if inputs.bytecode_address != UNIVERSAL_CALL_PRECOMPILE
        && inputs.target_address != UNIVERSAL_CALL_PRECOMPILE
    {
        return None;
    }
    // Cross-VM calls are host effects and must not inherit a delegate's
    // address/storage context. Match the UOL precompile's scheme policy.
    if !precompile_scheme_allowed(inputs.scheme) {
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        if !gas.record_regular_cost(PRECOMPILE_BASE_GAS) {
            return Some(CallOutcome::new(
                InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                inputs.return_memory_offset.clone(),
            ));
        }
        return Some(CallOutcome::new(
            InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
            inputs.return_memory_offset.clone(),
        ));
    }

    let calldata: Vec<u8> = inputs.input.as_bytes(context).to_vec();
    let mem_offset = inputs.return_memory_offset.clone();
    let entry_gas = PRECOMPILE_BASE_GAS.saturating_add(precompile_word_gas(calldata.len()));

    if inputs.gas_limit < entry_gas {
        return Some(CallOutcome::new(
            InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
            mem_offset,
        ));
    }
    if !inputs.call_value().is_zero() {
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        let _ = gas.record_regular_cost(entry_gas);
        return Some(CallOutcome::new(
            InterpreterResult::new(
                InstructionResult::Revert,
                Bytes::from_static(b"universal precompile rejects native msg.value"),
                gas,
            ),
            mem_offset,
        ));
    }

    let Some(parsed) = decode_precompile_call(&calldata) else {
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        let _ = gas.record_regular_cost(entry_gas);
        return Some(CallOutcome::new(
            InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
            mem_offset,
        ));
    };

    if inputs.is_static && !parsed.is_static_selector {
        return Some(CallOutcome::new(
            InterpreterResult::new(
                InstructionResult::CallNotAllowedInsideStatic,
                Bytes::new(),
                Gas::new_spent_with_reservoir(inputs.gas_limit, inputs.reservoir),
            ),
            mem_offset,
        ));
    }
    let is_static = inputs.is_static || parsed.is_static_selector;
    let value_u256 = U256::from(parsed.value_attos);
    if !value_u256.is_zero() {
        if context.journaled_state.load_account(inputs.caller).is_err() {
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            let _ = gas.record_regular_cost(entry_gas);
            return Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                mem_offset,
            ));
        }
        let has_funds = context
            .journaled_state
            .evm_state()
            .get(&inputs.caller)
            .is_some_and(|acc| acc.info.balance >= value_u256);
        if !has_funds {
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            let _ = gas.record_regular_cost(entry_gas);
            return Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::OutOfFunds, Bytes::new(), gas),
                mem_offset,
            ));
        }
    }

    let remaining_for_callee = inputs.gas_limit.saturating_sub(entry_gas);
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

    let host_cp = if !is_static {
        let Ok(cp) = context.journaled_state.db_mut().host.checkpoint_begin() else {
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            let _ = gas.record_regular_cost(entry_gas);
            return Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                mem_offset,
            ));
        };
        Some(cp)
    } else {
        None
    };

    match context.journaled_state.db_mut().universal_call(ucall) {
        Ok(ures) => {
            if ures.output.len() > MAX_PRECOMPILE_BYTES {
                if let Some(cp) = host_cp {
                    let _ = context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_rollback(cp);
                }
                return Some(CallOutcome::new(
                    InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                    mem_offset,
                ));
            }
            let encoded = encode_precompile_return(ures.success, &ures.output);
            let total_cost = entry_gas
                .saturating_add(ures.gas_used)
                .saturating_add(precompile_word_gas(encoded.len()));
            if total_cost > inputs.gas_limit {
                if let Some(cp) = host_cp {
                    let _ = context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_rollback(cp);
                }
                return Some(CallOutcome::new(
                    InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                    mem_offset,
                ));
            }
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            if !gas.record_regular_cost(total_cost) {
                if let Some(cp) = host_cp {
                    let _ = context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_rollback(cp);
                }
                return Some(CallOutcome::new(
                    InterpreterResult::new_oog(inputs.gas_limit, inputs.reservoir),
                    mem_offset,
                ));
            }
            if let Some(cp) = host_cp {
                if ures.success {
                    if context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_commit(cp)
                        .is_err()
                    {
                        let _ = context
                            .journaled_state
                            .db_mut()
                            .host
                            .checkpoint_rollback(cp);
                        return Some(CallOutcome::new(
                            InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                            mem_offset,
                        ));
                    }
                    if !value_u256.is_zero() {
                        if !context
                            .journaled_state
                            .balance_incr(inputs.caller, U256::ZERO)
                            .is_ok()
                        {
                            let _ = context
                                .journaled_state
                                .db_mut()
                                .host
                                .checkpoint_rollback(cp);
                            return Some(CallOutcome::new(
                                InterpreterResult::new(
                                    InstructionResult::Revert,
                                    Bytes::new(),
                                    gas,
                                ),
                                mem_offset,
                            ));
                        }
                        if let Some(acc) = context
                            .journaled_state
                            .evm_state_mut()
                            .get_mut(&inputs.caller)
                        {
                            acc.info.balance = acc.info.balance.saturating_sub(value_u256);
                            acc.mark_touch();
                            *recorded_debit = Some(PrecompileValueDebit {
                                caller: inputs.caller,
                                amount: value_u256,
                            });
                        }
                    }
                } else {
                    let _ = context
                        .journaled_state
                        .db_mut()
                        .host
                        .checkpoint_rollback(cp);
                }
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
            Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Return, Bytes::from(encoded), gas),
                mem_offset,
            ))
        }
        Err(_) => {
            if let Some(cp) = host_cp {
                let _ = context
                    .journaled_state
                    .db_mut()
                    .host
                    .checkpoint_rollback(cp);
            }
            let mut gas =
                Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
            let _ = gas.record_regular_cost(entry_gas);
            Some(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Revert, Bytes::new(), gas),
                mem_offset,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::precompile_scheme_allowed;
    use revm::interpreter::CallScheme;

    #[test]
    fn host_precompiles_reject_delegate_and_callcode_schemes() {
        assert!(precompile_scheme_allowed(CallScheme::Call));
        assert!(precompile_scheme_allowed(CallScheme::StaticCall));
        assert!(!precompile_scheme_allowed(CallScheme::DelegateCall));
        assert!(!precompile_scheme_allowed(CallScheme::CallCode));
    }

    #[test]
    fn precompile_abi_enforces_megabyte_ceiling_and_word_gas() {
        use crate::abi::{
            decode_precompile_call, decode_uol_call, encode_uol_offer_bytes, precompile_word_gas,
            UolOfferRecord, MAX_PRECOMPILE_BYTES, PRECOMPILE_WORD_GAS,
        };
        assert_eq!(precompile_word_gas(0), 0);
        assert_eq!(precompile_word_gas(1), PRECOMPILE_WORD_GAS);
        assert_eq!(precompile_word_gas(33), 2 * PRECOMPILE_WORD_GAS);
        assert!(decode_precompile_call(&vec![0u8; MAX_PRECOMPILE_BYTES + 1]).is_none());
        assert!(decode_uol_call(&vec![0u8; MAX_PRECOMPILE_BYTES + 1]).is_none());
        let huge = UolOfferRecord {
            maker: [1; 20],
            class_id: [2; 32],
            asset_id: [3; 32],
            taker: vec![0u8; MAX_PRECOMPILE_BYTES + 1],
            payment: Vec::new(),
            amount: 1,
            expiry: 10,
        };
        assert!(encode_uol_offer_bytes(&huge).is_none());
    }

    #[test]
    fn uol_transfer_fails_closed_on_recipient_balance_read_error_without_wiping_balance() {
        use crate::abi::{uol_selector, NS_UEL_ASSETS, UOL_PRECOMPILE};
        use crate::{EvmWorker, BUDLUM_EVM_CHAIN_ID};
        use budlum_uel_abi::mock::MemoryHost;
        use budlum_uel_abi::{
            BlockContext, BudAmount, EeCall, EeCallKind, EeId, EeIdentity, EeLog,
            ExecutionEnvironment, HostApi, HostError, HostRead, Namespace, OutOfGas, OutcomeStatus,
            UniversalCall, UniversalResult,
        };

        struct FailCreditReadHost {
            inner: MemoryHost,
            fail_key: Vec<u8>,
        }
        impl HostRead for FailCreditReadHost {
            fn read(&self, ns: &Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, HostError> {
                if key == self.fail_key.as_slice() {
                    return Err(HostError::Invalid("injected uol credit read error".into()));
                }
                self.inner.read(ns, key)
            }
            fn bud_balance(&self, who: &EeIdentity) -> Result<BudAmount, HostError> {
                self.inner.bud_balance(who)
            }
        }
        impl HostApi for FailCreditReadHost {
            fn write(
                &mut self,
                ns: &Namespace,
                key: &[u8],
                value: Option<&[u8]>,
            ) -> Result<(), HostError> {
                self.inner.write(ns, key, value)
            }
            fn universal_call(
                &mut self,
                call: UniversalCall,
            ) -> Result<UniversalResult, HostError> {
                self.inner.universal_call(call)
            }
            fn emit_log(&mut self, log: EeLog) -> Result<(), HostError> {
                self.inner.emit_log(log)
            }
            fn charge(&mut self, bgu: u64) -> Result<(), OutOfGas> {
                self.inner.charge(bgu)
            }
            fn bud_transfer(
                &mut self,
                from: &EeIdentity,
                to: &EeIdentity,
                attos: u128,
            ) -> Result<(), HostError> {
                self.inner.bud_transfer(from, to, attos)
            }
            fn checkpoint_begin(&mut self) -> Result<u64, HostError> {
                self.inner.checkpoint_begin()
            }
            fn checkpoint_commit(&mut self, id: u64) -> Result<(), HostError> {
                self.inner.checkpoint_commit(id)
            }
            fn checkpoint_rollback(&mut self, id: u64) -> Result<(), HostError> {
                self.inner.checkpoint_rollback(id)
            }
        }

        let mut host = MemoryHost::new(10_000_000);
        let sender_raw = [0x11u8; 20];
        let recipient_raw = [0x22u8; 20];
        let class_id = [0xAAu8; 32];
        let Ok(ns_assets) = Namespace::new(NS_UEL_ASSETS) else {
            panic!("ns");
        };
        let sender_key = super::uol_bal_key(&class_id, &sender_raw);
        let recipient_key = super::uol_bal_key(&class_id, &recipient_raw);
        let _ = host.write(&ns_assets, &sender_key, Some(&100u128.to_le_bytes()));
        let _ = host.write(&ns_assets, &recipient_key, Some(&500u128.to_le_bytes()));

        // Encode transfer(bytes32 class_id, bytes32 asset_id=0, bytes to=recipient_raw, uint128 amount=10)
        let mut cd = Vec::new();
        cd.extend_from_slice(&uol_selector("transfer(bytes32,bytes32,bytes,uint128)"));
        cd.extend_from_slice(&class_id);
        cd.extend_from_slice(&[0u8; 32]); // asset_id = 0
        let mut off_word = [0u8; 32];
        off_word[31] = 128; // dynamic bytes offset = 4 * 32
        cd.extend_from_slice(&off_word);
        let mut amt_word = [0u8; 32];
        amt_word[16..32].copy_from_slice(&10u128.to_be_bytes());
        cd.extend_from_slice(&amt_word);
        let mut len_word = [0u8; 32];
        len_word[31] = 20;
        cd.extend_from_slice(&len_word);
        let mut padded_to = [0u8; 32];
        padded_to[..20].copy_from_slice(&recipient_raw);
        cd.extend_from_slice(&padded_to);

        let mut faulty = FailCreditReadHost {
            inner: host,
            fail_key: recipient_key.clone(),
        };
        let mut worker = EvmWorker;
        let Ok(sender_id) = EeIdentity::new(EeId::EVM, sender_raw.to_vec()) else {
            panic!("sender");
        };
        let Ok(uol_id) = EeIdentity::new(EeId::EVM, UOL_PRECOMPILE.into_array().to_vec()) else {
            panic!("uol");
        };
        let Ok(out) = worker.execute(
            &BlockContext {
                chain_id: BUDLUM_EVM_CHAIN_ID,
                height: 10,
                timestamp_ms: 1_793_923_200_000,
            },
            &EeCall {
                kind: EeCallKind::Call,
                caller: sender_id,
                target: uol_id,
                value: BudAmount(0),
                input: cd,
                gas_limit: 500_000,
                depth: 0,
                tx_hash: [0xF5; 32],
            },
            &mut faulty,
        ) else {
            panic!("execute");
        };
        assert_eq!(
            out.status,
            OutcomeStatus::Revert,
            "UOL transfer must fail closed on recipient balance read error instead of wiping recipient to 0 + amount"
        );
        // Verify both sender (100) and recipient (500) balances remained completely intact.
        let Ok(Some(s_raw)) = faulty.inner.read(&ns_assets, &sender_key) else {
            panic!("sender bal missing");
        };
        let Ok(Some(r_raw)) = faulty.inner.read(&ns_assets, &recipient_key) else {
            panic!("recipient bal missing");
        };
        assert_eq!(s_raw, 100u128.to_le_bytes().to_vec());
        assert_eq!(r_raw, 500u128.to_le_bytes().to_vec());
    }
}
