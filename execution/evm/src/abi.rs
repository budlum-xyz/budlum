//! Solidity ABI codec for the UEL Universal Call precompile at
//! `0x000000000000000000000000000000000000B001` (`Section 8.7.2`) and the
//! Universal Object Layer precompile at `0x000000000000000000000000000000000000B002`
//! (`Section 9.4`).

use revm::primitives::{address, keccak256, Address};

/// Canonical EVM precompile address for cross-EE Universal Calls (`0x...B001`).
pub const UNIVERSAL_CALL_PRECOMPILE: Address =
    address!("0x000000000000000000000000000000000000b001");

/// Canonical EVM precompile address for Universal Object Layer (`0x...B002`).
pub const UOL_PRECOMPILE: Address = address!("0x000000000000000000000000000000000000b002");

/// `keccak256("call(uint8,bytes,bytes,uint256,uint64)")[..4]`.
pub const SEL_UNIVERSAL_CALL: [u8; 4] = [0x25, 0xd4, 0xd8, 0x1b];

/// `keccak256("staticCall(uint8,bytes,bytes,uint64)")[..4]`.
pub const SEL_UNIVERSAL_STATIC_CALL: [u8; 4] = [0xf9, 0xe4, 0x11, 0xde];

/// Base BGU cost charged for invoking the `0x...B001` precompile skeleton.
pub const PRECOMPILE_BASE_GAS: u64 = 500;

/// Base BGU cost charged for invoking the `0x...B002` UOL precompile.
pub const UOL_PRECOMPILE_GAS: u64 = 2_600;

/// Linear BGU cost per 32-byte calldata or returndata word on UEL/UOL precompiles.
pub const PRECOMPILE_WORD_GAS: u64 = 3;

/// BGU charged per byte of permanent state a UOL record adds, matching the
/// EVM state-growth schedule applied to newly persisted storage bytes.
pub const UOL_STATE_GROWTH_GAS_PER_BYTE: u64 = 16;

/// Length of a UOL offer `taker` (an EVM address); empty means any taker.
pub const UOL_TAKER_LEN: usize = 20;

/// Hard ceiling (1 MiB) on precompile calldata and decoded dynamic byte slices.
pub const MAX_PRECOMPILE_BYTES: usize = 1024 * 1024;

/// Compute linear word gas (`3 * ceil(len / 32)`), saturating on overflow.
#[must_use]
pub fn precompile_word_gas(byte_len: usize) -> u64 {
    let words = u64::try_from(byte_len.div_ceil(32)).unwrap_or(u64::MAX);
    words.saturating_mul(PRECOMPILE_WORD_GAS)
}

/// Host namespace storing canonical UOL balances, asset holders, and offers.
pub const NS_UEL_ASSETS: &str = "uel/assets";

/// Parsed invocation of `IBudlumUniversalPrecompile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPrecompileCall {
    pub is_static_selector: bool,
    pub target_ee: u8,
    pub target: Vec<u8>,
    pub input: Vec<u8>,
    pub value_attos: u128,
    pub gas_bgu: u64,
}

fn read_word(buf: &[u8], offset: usize) -> Option<&[u8]> {
    let end = offset.checked_add(32)?;
    buf.get(offset..end)
}

fn read_usize_word(buf: &[u8], offset: usize) -> Option<usize> {
    let word = read_word(buf, offset)?;
    if word.get(..24)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(word.get(24..32)?);
    usize::try_from(u64::from_be_bytes(tail)).ok()
}

fn read_u64_word(buf: &[u8], offset: usize) -> Option<u64> {
    let word = read_word(buf, offset)?;
    if word.get(..24)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(word.get(24..32)?);
    Some(u64::from_be_bytes(tail))
}

fn read_u128_word(buf: &[u8], offset: usize) -> Option<u128> {
    let word = read_word(buf, offset)?;
    if word.get(..16)?.iter().any(|&b| b != 0) {
        return None;
    }
    let mut tail = [0u8; 16];
    tail.copy_from_slice(word.get(16..32)?);
    Some(u128::from_be_bytes(tail))
}

fn read_u8_word(buf: &[u8], offset: usize) -> Option<u8> {
    let word = read_word(buf, offset)?;
    if word.get(..31)?.iter().any(|&b| b != 0) {
        return None;
    }
    word.get(31).copied()
}

fn read_dyn_bytes(
    args: &[u8],
    head_offset: usize,
    min_tail_offset: usize,
) -> Option<(usize, usize, Vec<u8>)> {
    let rel = read_usize_word(args, head_offset)?;
    if rel < min_tail_offset || !rel.is_multiple_of(32) {
        return None;
    }
    let len = read_usize_word(args, rel)?;
    if len > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let data_start = rel.checked_add(32)?;
    let data_end = data_start.checked_add(len)?;
    let padded_len = len.div_ceil(32).checked_mul(32)?;
    let padded_end = data_start.checked_add(padded_len)?;
    if args.get(data_end..padded_end)?.iter().any(|&b| b != 0) {
        return None;
    }
    Some((rel, padded_end, args.get(data_start..data_end)?.to_vec()))
}

/// Verify that dynamic ABI tail slices are pairwise disjoint and partition
/// `head_len..args_len` with zero unreferenced gap or trailing bytes.
fn tails_cover_exact(head_len: usize, args_len: usize, spans: &[(usize, usize)]) -> bool {
    let mut sorted = spans.to_vec();
    sorted.sort_unstable_by_key(|&(start, _)| start);
    let mut cursor = head_len;
    for (start, end) in sorted {
        if start != cursor || end < start {
            return false;
        }
        cursor = end;
    }
    cursor == args_len
}

/// Decode Solidity calldata targeting `0x000000000000000000000000000000000000B001`.
#[must_use]
pub fn decode_precompile_call(calldata: &[u8]) -> Option<ParsedPrecompileCall> {
    if calldata.len() > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let sel = calldata.get(..4)?;
    let args = calldata.get(4..)?;
    if sel == SEL_UNIVERSAL_CALL {
        const HEAD_LEN: usize = 32 * 5;
        if args.len() < HEAD_LEN {
            return None;
        }
        let target_ee = read_u8_word(args, 0)?;
        let (t_rel, t_end, target) = read_dyn_bytes(args, 32, HEAD_LEN)?;
        let (i_rel, i_end, input) = read_dyn_bytes(args, 64, HEAD_LEN)?;
        if !tails_cover_exact(HEAD_LEN, args.len(), &[(t_rel, t_end), (i_rel, i_end)]) {
            return None;
        }
        let value_attos = read_u128_word(args, 96)?;
        let gas_bgu = read_u64_word(args, 128)?;
        Some(ParsedPrecompileCall {
            is_static_selector: false,
            target_ee,
            target,
            input,
            value_attos,
            gas_bgu,
        })
    } else if sel == SEL_UNIVERSAL_STATIC_CALL {
        const HEAD_LEN: usize = 32 * 4;
        if args.len() < HEAD_LEN {
            return None;
        }
        let target_ee = read_u8_word(args, 0)?;
        let (t_rel, t_end, target) = read_dyn_bytes(args, 32, HEAD_LEN)?;
        let (i_rel, i_end, input) = read_dyn_bytes(args, 64, HEAD_LEN)?;
        if !tails_cover_exact(HEAD_LEN, args.len(), &[(t_rel, t_end), (i_rel, i_end)]) {
            return None;
        }
        let gas_bgu = read_u64_word(args, 96)?;
        Some(ParsedPrecompileCall {
            is_static_selector: true,
            target_ee,
            target,
            input,
            value_attos: 0,
            gas_bgu,
        })
    } else {
        None
    }
}

/// ABI-encode `(bool ok, bytes ret)` as returned by `IBudlumUniversalPrecompile`.
#[must_use]
pub fn encode_precompile_return(ok: bool, ret: &[u8]) -> Vec<u8> {
    let padded_len = ret.len().div_ceil(32) * 32;
    let mut out = vec![0u8; 96 + padded_len];
    if ok {
        if let Some(slot) = out.get_mut(31) {
            *slot = 1;
        }
    }
    // Offset to `bytes ret` tuple tail is 64 (0x40).
    if let Some(slot) = out.get_mut(63) {
        *slot = 64;
    }
    let len_be = (ret.len() as u64).to_be_bytes();
    if let Some(dst) = out.get_mut(88..96) {
        dst.copy_from_slice(&len_be);
    }
    if let Some(dst) = out.get_mut(96..96 + ret.len()) {
        dst.copy_from_slice(ret);
    }
    out
}

/// ABI-encode a `call(uint8,bytes,bytes,uint256,uint64)` payload (used by tests and callers).
#[must_use]
pub fn encode_universal_call_input(
    ee: u8,
    target: &[u8],
    input: &[u8],
    value_attos: u128,
    gas_bgu: u64,
) -> Vec<u8> {
    let target_padded = target.len().div_ceil(32) * 32;
    let input_padded = input.len().div_ceil(32) * 32;
    let head_bytes = 32 * 5;
    let target_offset = head_bytes;
    let input_offset = target_offset + 32 + target_padded;
    let total = 4 + input_offset + 32 + input_padded;
    let mut out = vec![0u8; total];

    if let Some(dst) = out.get_mut(..4) {
        dst.copy_from_slice(&SEL_UNIVERSAL_CALL);
    }
    let body = &mut out[4..];
    body[31] = ee;
    body[56..64].copy_from_slice(&(target_offset as u64).to_be_bytes());
    body[88..96].copy_from_slice(&(input_offset as u64).to_be_bytes());
    body[112..128].copy_from_slice(&value_attos.to_be_bytes());
    body[152..160].copy_from_slice(&gas_bgu.to_be_bytes());

    body[target_offset + 24..target_offset + 32]
        .copy_from_slice(&(target.len() as u64).to_be_bytes());
    body[target_offset + 32..target_offset + 32 + target.len()].copy_from_slice(target);

    body[input_offset + 24..input_offset + 32].copy_from_slice(&(input.len() as u64).to_be_bytes());
    body[input_offset + 32..input_offset + 32 + input.len()].copy_from_slice(input);
    out
}

/// Decoded invocation targeting `UOL_PRECOMPILE` (`0x...B002`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedUolCall {
    BalanceOf {
        class_id: [u8; 32],
        holder: Vec<u8>,
    },
    HolderOf {
        asset_id: [u8; 32],
    },
    Transfer {
        class_id: [u8; 32],
        asset_id: [u8; 32],
        to: Vec<u8>,
        amount: u128,
    },
    Offer {
        class_id: [u8; 32],
        asset_id: [u8; 32],
        taker: Vec<u8>,
        payment: Vec<u8>,
        amount: u128,
        expiry: u64,
    },
    Accept {
        offer_id: [u8; 32],
    },
}

/// Stored UOL precompile offer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UolOfferRecord {
    pub maker: [u8; 20],
    pub class_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub taker: Vec<u8>,
    pub payment: Vec<u8>,
    pub amount: u128,
    pub expiry: u64,
}

#[must_use]
pub fn uol_selector(sig: &str) -> [u8; 4] {
    let d: [u8; 32] = keccak256(sig.as_bytes()).into();
    [d[0], d[1], d[2], d[3]]
}

#[must_use]
pub fn decode_uol_call(calldata: &[u8]) -> Option<DecodedUolCall> {
    if calldata.len() > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let sel = calldata.get(..4)?;
    let args = calldata.get(4..)?;
    if sel == uol_selector("balanceOf(bytes32,bytes)") {
        const HEAD_LEN: usize = 32 * 2;
        if args.len() < HEAD_LEN {
            return None;
        }
        let mut class_id = [0u8; 32];
        class_id.copy_from_slice(read_word(args, 0)?);
        let (h_rel, h_end, holder) = read_dyn_bytes(args, 32, HEAD_LEN)?;
        if !tails_cover_exact(HEAD_LEN, args.len(), &[(h_rel, h_end)]) {
            return None;
        }
        return Some(DecodedUolCall::BalanceOf { class_id, holder });
    }
    if sel == uol_selector("holderOf(bytes32)") {
        if args.len() != 32 {
            return None;
        }
        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(read_word(args, 0)?);
        return Some(DecodedUolCall::HolderOf { asset_id });
    }
    if sel == uol_selector("transfer(bytes32,bytes32,bytes,uint128)") {
        const HEAD_LEN: usize = 32 * 4;
        if args.len() < HEAD_LEN {
            return None;
        }
        let mut class_id = [0u8; 32];
        class_id.copy_from_slice(read_word(args, 0)?);
        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(read_word(args, 32)?);
        let (to_rel, to_end, to) = read_dyn_bytes(args, 64, HEAD_LEN)?;
        if !tails_cover_exact(HEAD_LEN, args.len(), &[(to_rel, to_end)]) {
            return None;
        }
        let amount = read_u128_word(args, 96)?;
        return Some(DecodedUolCall::Transfer {
            class_id,
            asset_id,
            to,
            amount,
        });
    }
    if sel == uol_selector("offer(bytes32,bytes32,bytes,bytes,uint128,uint64)") {
        const HEAD_LEN: usize = 32 * 6;
        if args.len() < HEAD_LEN {
            return None;
        }
        let mut class_id = [0u8; 32];
        class_id.copy_from_slice(read_word(args, 0)?);
        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(read_word(args, 32)?);
        let (tk_rel, tk_end, taker) = read_dyn_bytes(args, 64, HEAD_LEN)?;
        let (py_rel, py_end, payment) = read_dyn_bytes(args, 96, HEAD_LEN)?;
        if !tails_cover_exact(HEAD_LEN, args.len(), &[(tk_rel, tk_end), (py_rel, py_end)]) {
            return None;
        }
        let amount = read_u128_word(args, 128)?;
        let expiry = read_u64_word(args, 160)?;
        return Some(DecodedUolCall::Offer {
            class_id,
            asset_id,
            taker,
            payment,
            amount,
            expiry,
        });
    }
    if sel == uol_selector("accept(bytes32)") {
        if args.len() != 32 {
            return None;
        }
        let mut offer_id = [0u8; 32];
        offer_id.copy_from_slice(read_word(args, 0)?);
        return Some(DecodedUolCall::Accept { offer_id });
    }
    None
}

#[must_use]
pub fn encode_uol_offer_bytes(offer: &UolOfferRecord) -> Option<Vec<u8>> {
    if offer.taker.len() > MAX_PRECOMPILE_BYTES || offer.payment.len() > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let taker_len = u32::try_from(offer.taker.len()).ok()?;
    let pay_len = u32::try_from(offer.payment.len()).ok()?;
    let cap = 116usize
        .checked_add(offer.taker.len())?
        .checked_add(offer.payment.len())?;
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&offer.maker);
    out.extend_from_slice(&offer.class_id);
    out.extend_from_slice(&offer.asset_id);
    out.extend_from_slice(&offer.amount.to_le_bytes());
    out.extend_from_slice(&offer.expiry.to_le_bytes());
    out.extend_from_slice(&taker_len.to_le_bytes());
    out.extend_from_slice(&offer.taker);
    out.extend_from_slice(&pay_len.to_le_bytes());
    out.extend_from_slice(&offer.payment);
    Some(out)
}

#[must_use]
pub fn decode_uol_offer_bytes(raw: &[u8]) -> Option<UolOfferRecord> {
    if raw.len() < 116 {
        return None;
    }
    let mut maker = [0u8; 20];
    maker.copy_from_slice(raw.get(..20)?);
    let mut class_id = [0u8; 32];
    class_id.copy_from_slice(raw.get(20..52)?);
    let mut asset_id = [0u8; 32];
    asset_id.copy_from_slice(raw.get(52..84)?);
    let mut amt_arr = [0u8; 16];
    amt_arr.copy_from_slice(raw.get(84..100)?);
    let amount = u128::from_le_bytes(amt_arr);
    let mut exp_arr = [0u8; 8];
    exp_arr.copy_from_slice(raw.get(100..108)?);
    let expiry = u64::from_le_bytes(exp_arr);
    let mut tl_arr = [0u8; 4];
    tl_arr.copy_from_slice(raw.get(108..112)?);
    let taker_len = usize::try_from(u32::from_le_bytes(tl_arr)).ok()?;
    if taker_len > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let taker_end = 112usize.checked_add(taker_len)?;
    let taker = raw.get(112..taker_end)?.to_vec();
    let mut pl_arr = [0u8; 4];
    let pl_end = taker_end.checked_add(4)?;
    pl_arr.copy_from_slice(raw.get(taker_end..pl_end)?);
    let pay_len = usize::try_from(u32::from_le_bytes(pl_arr)).ok()?;
    if pay_len > MAX_PRECOMPILE_BYTES {
        return None;
    }
    let pay_end = pl_end.checked_add(pay_len)?;
    if raw.len() != pay_end {
        return None;
    }
    let payment = raw.get(pl_end..pay_end)?.to_vec();
    Some(UolOfferRecord {
        maker,
        class_id,
        asset_id,
        taker,
        payment,
        amount,
        expiry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evmee03_abi_rejects_head_tail_overlap_unaligned_dirty_padding_trailing_and_oversized_offer()
    {
        // 1. Head/tail overlap: dynamic `target` offset points inside the 160-byte head (rel = 0).
        let mut overlap = Vec::from(SEL_UNIVERSAL_CALL);
        let mut head = vec![0u8; 160];
        head[31] = 2; // target_ee = 2 (also read as len=2 if rel=0!)
                      // target offset = 0 (aliases head word 0!)
                      // input offset = 160
        head[88..96].copy_from_slice(&160u64.to_be_bytes());
        overlap.extend_from_slice(&head);
        overlap.extend_from_slice(&[0u8; 32]); // input len = 0
        assert!(
            decode_precompile_call(&overlap).is_none(),
            "dynamic offset pointing into ABI head must be refused"
        );

        // 2. Unaligned dynamic offset (rel = 161, not a multiple of 32) with valid
        //    length + zero-padded bytes laid out right at offset 161.
        let mut unaligned = Vec::from(SEL_UNIVERSAL_CALL);
        let mut uhead = vec![0u8; 160];
        uhead[31] = 2; // target_ee
        uhead[56..64].copy_from_slice(&161u64.to_be_bytes()); // unaligned target offset
        uhead[88..96].copy_from_slice(&256u64.to_be_bytes()); // aligned input offset
        uhead[152..160].copy_from_slice(&100u64.to_be_bytes()); // gas
        unaligned.extend_from_slice(&uhead);
        let mut utail = vec![0u8; 128]; // bytes 160..288
        utail[1 + 31] = 2; // len = 2 at rel = 161
        utail[1 + 32] = b'a';
        utail[1 + 33] = b'b';
        // input at rel = 256 (utail[96..128]) has len = 0
        unaligned.extend_from_slice(&utail);
        assert!(
            decode_precompile_call(&unaligned).is_none(),
            "non-32-byte-aligned dynamic offset must be refused"
        );

        // 3. Non-zero dirty padding in dynamic `bytes` tail.
        let mut dirty_pad = encode_universal_call_input(2, b"ab", b"cd", 0, 100);
        // target starts at 4 + 160 + 32 = 196, len = 2, padding is 198..228.
        dirty_pad[198] = 0xFF;
        assert!(
            decode_precompile_call(&dirty_pad).is_none(),
            "dirty non-zero padding in ABI bytes tail must be refused"
        );

        // 4. Trailing garbage bytes on fixed-size UOL calls holderOf(bytes32) & accept(bytes32).
        let mut holder_trailing = Vec::from(uol_selector("holderOf(bytes32)"));
        holder_trailing.extend_from_slice(&[0x11u8; 32]);
        holder_trailing.extend_from_slice(&[0x22u8; 4]);
        assert!(
            decode_uol_call(&holder_trailing).is_none(),
            "holderOf(bytes32) with trailing garbage must be refused"
        );
        let mut accept_trailing = Vec::from(uol_selector("accept(bytes32)"));
        accept_trailing.extend_from_slice(&[0x11u8; 32]);
        accept_trailing.push(0x00);
        assert!(
            decode_uol_call(&accept_trailing).is_none(),
            "accept(bytes32) with trailing bytes must be refused"
        );

        // 5. decode_uol_offer_bytes must enforce MAX_PRECOMPILE_BYTES on taker and payment.
        let huge_taker_len = u32::try_from(MAX_PRECOMPILE_BYTES + 1).expect("u32");
        let mut huge_raw = Vec::with_capacity(116 + MAX_PRECOMPILE_BYTES + 1);
        huge_raw.extend_from_slice(&[0x11u8; 20]); // maker
        huge_raw.extend_from_slice(&[0x22u8; 32]); // class_id
        huge_raw.extend_from_slice(&[0x33u8; 32]); // asset_id
        huge_raw.extend_from_slice(&1u128.to_le_bytes()); // amount
        huge_raw.extend_from_slice(&10u64.to_le_bytes()); // expiry
        huge_raw.extend_from_slice(&huge_taker_len.to_le_bytes());
        huge_raw.resize(huge_raw.len() + MAX_PRECOMPILE_BYTES + 1, 0xAA);
        huge_raw.extend_from_slice(&0u32.to_le_bytes()); // pay_len = 0
        assert!(
            decode_uol_offer_bytes(&huge_raw).is_none(),
            "decode_uol_offer_bytes must reject taker exceeding MAX_PRECOMPILE_BYTES"
        );

        // 6. Trailing unreferenced garbage bytes and aliased dynamic offsets on
        //    dynamic precompile calls (`call`, `staticCall`, `balanceOf`, `transfer`, `offer`)
        //    must be refused.
        let mut call_trailing = encode_universal_call_input(2, b"ab", b"cd", 0, 100);
        call_trailing.extend_from_slice(&[0u8; 32]);
        assert!(
            decode_precompile_call(&call_trailing).is_none(),
            "UniversalCall with unreferenced trailing word must be refused"
        );

        // Aliased dynamic offsets: both `target` and `input` point to offset 160!
        let mut aliased = Vec::from(SEL_UNIVERSAL_CALL);
        let mut ahead = vec![0u8; 160];
        ahead[31] = 2;
        ahead[56..64].copy_from_slice(&160u64.to_be_bytes());
        ahead[88..96].copy_from_slice(&160u64.to_be_bytes());
        ahead[152..160].copy_from_slice(&100u64.to_be_bytes());
        aliased.extend_from_slice(&ahead);
        let mut atail = vec![0u8; 64];
        atail[31] = 2;
        atail[32] = b'x';
        atail[33] = b'y';
        aliased.extend_from_slice(&atail);
        assert!(
            decode_precompile_call(&aliased).is_none(),
            "aliased dynamic offsets (target == input) must be refused"
        );
    }
}
