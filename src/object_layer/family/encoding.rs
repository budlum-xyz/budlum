//! Small, self-contained wire helpers the family profiles share.
//!
//! The families read four encodings: EVM ABI words, Cosmos bech32 strings,
//! Solana base58 and Borsh, and Move BCS. Each helper here is the minimum a
//! translator needs, written out so the object layer adds no dependency to
//! the workspace (the dependency policy is set elsewhere). Every reader is
//! bounds-checked and returns an error instead of panicking: these bytes come
//! from another chain.
//!
//! WIRING: the block executor reaches this module through the
//! `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` door, and RPC reads it
//! through `bud_getCharter`, `bud_getAssetClass`, `bud_getAsset` and the
//! other object-layer read methods. Both land in a later step; until then
//! the state is held by `SettlementRegistries::object_layer` and closed on
//! the testnet by `ACTIVATION`.

use sha3::{Digest, Keccak256};

/// A read past the end, or a value that does not fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

/// Keccak-256, the EVM event-selector and EIP-55 hash.
#[must_use]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(bytes));
    out
}

/// A forward-only reader over untrusted bytes.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError("length overflow"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(WireError("read past end"))?;
        self.at = end;
        Ok(slice)
    }

    pub fn array32(&mut self) -> Result<[u8; 32], WireError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32_le(&mut self) -> Result<u32, WireError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    pub fn u64_le(&mut self) -> Result<u64, WireError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    /// BCS sequence length: ULEB128, at most 2^31 - 1, canonical form only.
    pub fn uleb128(&mut self) -> Result<u64, WireError> {
        let mut value: u64 = 0;
        for shift in (0..32).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if shift > 0 && byte == 0 {
                    return Err(WireError("non-canonical uleb128"));
                }
                if value > u64::from(u32::MAX >> 1) {
                    return Err(WireError("uleb128 above 2^31"));
                }
                return Ok(value);
            }
        }
        Err(WireError("uleb128 too long"))
    }

    /// Borsh / BCS `Option<T>` tag. Only 0 and 1 are valid.
    pub fn option_tag(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError("option tag is neither 0 nor 1")),
        }
    }

    /// The reader consumed every byte. Trailing bytes are refused so one
    /// event has exactly one encoding.
    pub fn finish(&self) -> Result<(), WireError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError("trailing bytes"))
        }
    }
}

// ---------------------------------------------------------------- EVM ABI

/// The `index`-th 32-byte ABI word of `data`.
pub fn abi_word(data: &[u8], index: usize) -> Result<[u8; 32], WireError> {
    let start = index.checked_mul(32).ok_or(WireError("word overflow"))?;
    let mut r = Reader::new(data);
    r.take(start)?;
    r.array32()
}

/// An ABI `address` word: twelve zero bytes, then twenty.
pub fn abi_address(word: &[u8; 32]) -> Result<[u8; 20], WireError> {
    if word.iter().take(12).any(|b| *b != 0) {
        return Err(WireError("address word has dirty high bytes"));
    }
    let mut out = [0u8; 20];
    for (o, w) in out.iter_mut().zip(word.iter().skip(12)) {
        *o = *w;
    }
    Ok(out)
}

/// An ABI unsigned word that must fit in `u128`.
pub fn abi_u128(word: &[u8; 32]) -> Result<u128, WireError> {
    if word.iter().take(16).any(|b| *b != 0) {
        return Err(WireError("uint word above u128"));
    }
    let mut b = [0u8; 16];
    for (o, w) in b.iter_mut().zip(word.iter().skip(16)) {
        *o = *w;
    }
    Ok(u128::from_be_bytes(b))
}

/// A dynamic ABI `bytes` value whose head word sits at `head_index`.
pub fn abi_bytes(data: &[u8], head_index: usize) -> Result<Vec<u8>, WireError> {
    let offset = usize::try_from(abi_u128(&abi_word(data, head_index)?)?)
        .map_err(|_| WireError("offset too large"))?;
    if offset % 32 != 0 {
        return Err(WireError("unaligned bytes offset"));
    }
    let len = usize::try_from(abi_u128(&abi_word(data, offset / 32)?)?)
        .map_err(|_| WireError("length too large"))?;
    let mut r = Reader::new(data);
    r.take(offset + 32)?;
    let value = r.take(len)?.to_vec();
    let padded = len.div_ceil(32) * 32;
    let padding = r.take(padded - len)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(WireError("dirty bytes padding"));
    }
    r.finish()?;
    Ok(value)
}

/// EIP-55 mixed-case display of a 20-byte address.
#[must_use]
pub fn eip55(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    let nibbles = hash.iter().flat_map(|b| [b >> 4, b & 0x0f]);
    for (c, nibble) in lower.chars().zip(nibbles) {
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------- base58

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bitcoin-alphabet base58, the Solana address display.
#[must_use]
pub fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes.iter().skip(zeros) {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .filter_map(|d| BASE58_ALPHABET.get(usize::from(*d)))
            .map(|c| char::from(*c)),
    );
    out
}

/// Test-only: the endpoints never hand Budlum a base58 string, so only
/// the round-trip test decodes one.
#[cfg(test)]
fn base58_decode(text: &str) -> Result<Vec<u8>, WireError> {
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes().skip(zeros) {
        let value = BASE58_ALPHABET
            .iter()
            .position(|a| *a == c)
            .ok_or(WireError("not a base58 character"))? as u32;
        let mut carry = value;
        for byte in &mut bytes {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

// ---------------------------------------------------------------- bech32

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|b| b & 0x1f));
    out
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, WireError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::new();
    for value in data {
        let v = u32::from(*value);
        if v >> from != 0 {
            return Err(WireError("value out of range"));
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return Err(WireError("invalid bech32 padding"));
    }
    Ok(out)
}

/// BIP-173 bech32, the Cosmos SDK account and contract address display.
#[must_use]
pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let five = convert_bits(data, 8, 5, true).unwrap_or_default();
    let mut values = bech32_hrp_expand(hrp);
    values.extend(&five);
    values.extend([0u8; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    let mut out = String::with_capacity(hrp.len() + 1 + five.len() + 6);
    out.push_str(hrp);
    out.push('1');
    let checksum = (0..6).map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8);
    for d in five.iter().copied().chain(checksum) {
        if let Some(c) = BECH32_CHARSET.get(usize::from(d)) {
            out.push(char::from(*c));
        }
    }
    out
}

/// Decode a lower-case bech32 string to (hrp, bytes).
pub fn bech32_decode(text: &str) -> Result<(String, Vec<u8>), WireError> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(WireError("bech32 must be lower case"));
    }
    let (hrp, rest) = text
        .rsplit_once('1')
        .ok_or(WireError("no bech32 separator"))?;
    if hrp.is_empty() || rest.len() < 6 || text.len() > 90 {
        return Err(WireError("bad bech32 length"));
    }
    let mut values = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        let v = BECH32_CHARSET
            .iter()
            .position(|a| *a == c)
            .ok_or(WireError("not a bech32 character"))?;
        values.push(v as u8);
    }
    let mut check = bech32_hrp_expand(hrp);
    check.extend(&values);
    if bech32_polymod(&check) != 1 {
        return Err(WireError("bad bech32 checksum"));
    }
    let body = values
        .get(..values.len().saturating_sub(6))
        .ok_or(WireError("bad bech32 length"))?;
    let data = convert_bits(body, 5, 8, false)?;
    Ok((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_matches_the_reference_vector() {
        // EIP-55 test vector.
        let raw = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut a = [0u8; 20];
        a.copy_from_slice(&raw);
        assert_eq!(eip55(&a), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn base58_round_trips_and_keeps_leading_zeros() {
        // The Solana system program id is 32 zero bytes.
        assert_eq!(
            base58_encode(&[0u8; 32]),
            "11111111111111111111111111111111"
        );
        let bytes = [0u8, 0, 1, 2, 3, 250, 255];
        assert_eq!(base58_decode(&base58_encode(&bytes)).unwrap(), bytes);
        assert_eq!(base58_encode(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn bech32_round_trips_and_rejects_a_bad_checksum() {
        // BIP-173 valid vector.
        assert!(bech32_decode("a12uel5l").is_ok());
        let data = [7u8; 20];
        let text = bech32_encode("wasm", &data);
        let (hrp, back) = bech32_decode(&text).unwrap();
        assert_eq!(hrp, "wasm");
        assert_eq!(back, data);
        let mut broken = text.clone();
        let last = broken.pop().unwrap();
        broken.push(if last == 'q' { 'p' } else { 'q' });
        assert!(bech32_decode(&broken).is_err());
    }

    #[test]
    fn uleb128_refuses_non_canonical_forms() {
        assert_eq!(Reader::new(&[0x80, 0x01]).uleb128().unwrap(), 128);
        assert!(Reader::new(&[0x80, 0x00]).uleb128().is_err());
        assert!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x0f])
            .uleb128()
            .is_err());
    }

    #[test]
    fn abi_bytes_refuses_dirty_padding() {
        let mut data = vec![0u8; 32];
        data[31] = 0x20; // offset
        let mut len = [0u8; 32];
        len[31] = 1;
        data.extend(len);
        let mut body = [0u8; 32];
        body[0] = 0xaa;
        data.extend(body);
        assert_eq!(abi_bytes(&data, 0).unwrap(), vec![0xaa]);
        let last = data.len() - 1;
        data[last] = 1;
        assert!(abi_bytes(&data, 0).is_err());
    }
}
