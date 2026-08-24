//! In-tree Recursive Length Prefix (RLP) - Ethereum Yellow Paper Appendix B.
//!
//! A minimal, auditable, independent implementation. **NO alloy and NO ethers**;
//! RFC Q3 selects `in_tree`, which fits the minimal-dependency rule and
//! cargo-deny. Keccak256 is not used on the RLP side, only in the MPT node
//! hash; RLP is pure byte encoding.
//!
//! # Canonical encoding rules (Yellow Paper Appendix B)
//!
//! 1. A single byte in `0x00..=0x7f` encodes as itself.
//! 2. A string of 0 to 55 bytes encodes as `[0x80 + len, ...bytes]`.
//! 3. A string above 55 bytes encodes as
//!    `[0xb7 + len_of_len, ...len_be, ...bytes]`.
//! 4. A list with a payload of 0 to 55 bytes encodes as
//!    `[0xc0 + len, ...payload]`.
//! 5. A list with a payload above 55 bytes encodes as
//!    `[0xf7 + len_of_len, ...len_be, ...payload]`.
//!
//! `len_of_len` is the minimum number of bytes expressing the big-endian
//! length; a leading zero is FORBIDDEN, and a non-canonical encoding is REFUSED
//! at decoding time.
//!
//! # The negative test seals
//!
//! Decoding checks canonical form: a leading-zero length, a length-prefixed
//! encoding that did not use the minimal form, trailing bytes that fail to be
//! consumed, and truncation are all an `Err`. This is critical for security,
//! because it is the surface on which a proof would be invented.

use serde::{Deserialize, Serialize};

/// The RLP item hierarchy: a byte string or a list of items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A raw byte string; this is not an integer encoding, and the caller parses
    /// it.
    String(Vec<u8>),
    /// Ordered item list.
    List(Vec<Item>),
}

/// An RLP encoding or decoding error, including a canonical-form violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpError {
    /// An unexpected end: the input was cut short of a complete encoding.
    UnexpectedEof,
    /// An invalid length prefix, for example a declared length the payload cannot
    /// satisfy.
    InvalidLengthPrefix,
    /// A non-canonical encoding: a leading-zero length, or the minimal form left
    /// unused.
    NonCanonical,
    /// Trailing bytes left unconsumed after decoding, which is an injection
    /// surface.
    TrailingBytes,
    /// The list nesting depth was exceeded, a DoS guard; RLP can technically nest
    /// arbitrarily deep.
    NestingTooDeep,
}

impl std::fmt::Display for RlpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RlpError::UnexpectedEof => write!(f, "rlp: unexpected end of input"),
            RlpError::InvalidLengthPrefix => write!(f, "rlp: invalid length prefix"),
            RlpError::NonCanonical => write!(f, "rlp: non-canonical encoding"),
            RlpError::TrailingBytes => write!(f, "rlp: trailing bytes after item"),
            RlpError::NestingTooDeep => write!(f, "rlp: nesting too deep"),
        }
    }
}

impl std::error::Error for RlpError {}

/// The maximum list depth for RLP encoding, a DoS guard against decoding
/// endlessly nested lists.
const MAX_DEPTH: usize = 32;

/// Encodes an RLP `Item` canonically.
pub fn encode(item: &Item) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(item, &mut out);
    out
}

fn encode_into(item: &Item, out: &mut Vec<u8>) {
    match item {
        Item::String(bytes) => encode_string(bytes, out),
        Item::List(items) => {
            let mut payload = Vec::new();
            for child in items {
                encode_into(child, &mut payload);
            }
            encode_length(payload.len(), 0xc0, out);
            out.extend_from_slice(&payload);
        }
    }
}

fn encode_string(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        // Kural 1: tek byte < 0x80 → byte kendisi.
        out.push(bytes[0]);
    } else {
        encode_length(bytes.len(), 0x80, out);
        out.extend_from_slice(bytes);
    }
}

/// Writes the length prefix. `offset` is 0x80 for a string or 0xc0 for a list.
///
/// A length of 0 to 55 gives `[offset + len]`; above 55 it gives
/// `[offset + 55 + len_of_len, ...len_be]`.
fn encode_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + (len as u8));
    } else {
        let len_be = trim_leading_zeros(len);
        out.push(offset + 55 + (len_be.len() as u8));
        out.extend_from_slice(&len_be);
    }
}

/// Returns a `usize` big-endian in the minimal number of bytes, with NO leading
/// zero.
fn trim_leading_zeros(n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let be = n.to_be_bytes();
    // Skip up to the first non-zero byte.
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    be[start..].to_vec()
}

/// Decodes an RLP byte stream. **The whole input must be consumed**; trailing
/// bytes are FORBIDDEN.
pub fn decode(input: &[u8]) -> Result<Item, RlpError> {
    let (item, rest) = decode_at(input, 0)?;
    if !rest.is_empty() {
        return Err(RlpError::TrailingBytes);
    }
    Ok(item)
}

/// Decodes one item from `input[consumed..]`, returning the item and the
/// remaining bytes.
fn decode_at(input: &[u8], depth: usize) -> Result<(Item, &[u8]), RlpError> {
    if depth > MAX_DEPTH {
        return Err(RlpError::NestingTooDeep);
    }
    if input.is_empty() {
        return Err(RlpError::UnexpectedEof);
    }
    let first = input[0];

    // Rule 1: a single byte below 0x80 is the byte string containing it.
    if first < 0x80 {
        return Ok((Item::String(vec![first]), &input[1..]));
    }
    // Rule 2: a short string, 0x80 up to 0xb7.
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        let payload = take_exact(&input[1..], len)?;
        return Ok((Item::String(payload.to_vec()), &input[1 + len..]));
    }
    // Rule 3: a long string, 0xb8 through 0xbf.
    if first <= 0xbf {
        let len_of_len = (first - 0xb7) as usize;
        let len = decode_length_value(&input[1..], len_of_len)?;
        let payload_start = 1 + len_of_len;
        let payload = take_exact(&input[payload_start..], len)?;
        return Ok((
            Item::String(payload.to_vec()),
            &input[payload_start + len..],
        ));
    }
    // Rule 4: a short list, 0xc0 through 0xf7.
    if first <= 0xf7 {
        let len = (first - 0xc0) as usize;
        let payload = take_exact(&input[1..], len)?;
        let items = decode_list_items(payload, depth)?;
        return Ok((Item::List(items), &input[1 + len..]));
    }
    // Rule 5: a long list, 0xf8 through 0xff.
    let len_of_len = (first - 0xf7) as usize;
    let len = decode_length_value(&input[1..], len_of_len)?;
    let payload_start = 1 + len_of_len;
    let payload = take_exact(&input[payload_start..], len)?;
    let items = decode_list_items(payload, depth)?;
    Ok((Item::List(items), &input[payload_start + len..]))
}

/// Reads a big-endian length from `len_of_len` bytes, with a **canonical check**:
/// a leading zero and a zero length are FORBIDDEN.
fn decode_length_value(input: &[u8], len_of_len: usize) -> Result<usize, RlpError> {
    let len_bytes = take_exact(input, len_of_len)?;
    // Canonical form: with len_of_len of 1 it is a single byte, and above 1 the
    // first byte cannot be zero.
    if len_of_len > 1 && len_bytes[0] == 0 {
        return Err(RlpError::NonCanonical);
    }
    if len_of_len == 1 && len_bytes[0] < 56 {
        // The minimal-length rule: a length below 56 must not use the long form.
        return Err(RlpError::NonCanonical);
    }
    let mut len = 0usize;
    for &b in len_bytes {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or(RlpError::InvalidLengthPrefix)?;
    }
    Ok(len)
}

/// Takes `n` bytes from `input`, or `UnexpectedEof` if there are too few.
fn take_exact(input: &[u8], n: usize) -> Result<&[u8], RlpError> {
    if input.len() < n {
        return Err(RlpError::UnexpectedEof);
    }
    Ok(&input[..n])
}

/// Decodes a list payload by splitting it into items, one after another, all of
/// which must be consumed.
fn decode_list_items(payload: &[u8], depth: usize) -> Result<Vec<Item>, RlpError> {
    let mut items = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (item, remaining) = decode_at(rest, depth + 1)?;
        items.push(item);
        rest = remaining;
    }
    Ok(items)
}

// ---------------------------------------------------------------------------
// Convenience: integer encoding and decoding. The RLP integer rule FORBIDS a
// leading zero.
// ---------------------------------------------------------------------------

/// Encodes a `u64` as an RLP integer; zero becomes the empty string, 0x80.
pub fn encode_uint(n: u64) -> Vec<u8> {
    let bytes = trim_leading_zeros_u64(n);
    encode(&Item::String(bytes))
}

fn trim_leading_zeros_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    be[start..].to_vec()
}

/// Parses an RLP item as a big-endian integer; a leading zero is FORBIDDEN and
/// gives `NonCanonical`.
pub fn decode_uint(item: &Item) -> Result<u64, RlpError> {
    let bytes = match item {
        Item::String(b) => b,
        _ => return Err(RlpError::NonCanonical),
    };
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(RlpError::NonCanonical); // a leading-zero integer encoding
    }
    if bytes.is_empty() {
        return Ok(0); // the empty string is the integer 0, canonically
    }
    if bytes.len() > 8 {
        return Err(RlpError::InvalidLengthPrefix); // it overflows a u64
    }
    let mut n = 0u64;
    for &b in bytes {
        n = n
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as u64))
            .ok_or(RlpError::InvalidLengthPrefix)?;
    }
    Ok(n)
}

/// Returns the raw bytes of a byte-string item, a helper for extracting struct
/// fields.
pub fn as_bytes(item: &Item) -> Result<&[u8], RlpError> {
    match item {
        Item::String(b) => Ok(b),
        _ => Err(RlpError::NonCanonical),
    }
}

/// A serde-safe wrapper for the snapshot and RPC surface: a
/// `#[serde(transparent)]` `Vec<u8>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RlpBytes(pub Vec<u8>);

impl RlpBytes {
    pub fn from_item(item: &Item) -> Self {
        RlpBytes(encode(item))
    }
    pub fn decode(&self) -> Result<Item, RlpError> {
        decode(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- The official Ethereum RLP test vectors, known-answer tests ----

    /// The canonical vectors of `rlptest.txt`, from the Yellow Paper and
    /// ethereum/tests.
    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn kat_empty_string() {
        assert_eq!(encode(&Item::String(vec![])), hex("80"));
        assert_eq!(decode(&hex("80")).unwrap(), Item::String(vec![]));
    }

    #[test]
    fn kat_dog() {
        // "dog" = 0x646f67 → 0x83646f67
        assert_eq!(encode(&Item::String(b"dog".to_vec())), hex("83646f67"));
        assert_eq!(
            decode(&hex("83646f67")).unwrap(),
            Item::String(b"dog".to_vec())
        );
    }

    #[test]
    fn kat_empty_list() {
        assert_eq!(encode(&Item::List(vec![])), hex("c0"));
        assert_eq!(decode(&hex("c0")).unwrap(), Item::List(vec![]));
    }

    #[test]
    fn cat_dog_list() {
        // ["cat","dog"] = 0xc8 83636174 83646f67
        let item = Item::List(vec![
            Item::String(b"cat".to_vec()),
            Item::String(b"dog".to_vec()),
        ]);
        assert_eq!(encode(&item), hex("c88363617483646f67"));
        assert_eq!(decode(&hex("c88363617483646f67")).unwrap(), item);
    }

    #[test]
    fn kat_long_string() {
        // "Lorem ipsum dolor sit amet, consectetur adipisicing elit" (56 bytes → long)
        let s = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
        assert_eq!(s.len(), 56);
        let mut expected = vec![0xb8u8, 56];
        expected.extend_from_slice(s);
        assert_eq!(encode(&Item::String(s.to_vec())), expected);
        assert_eq!(decode(&expected).unwrap(), Item::String(s.to_vec()));
    }

    #[test]
    fn kat_single_byte_zero() {
        // [0x00] → 0x00 (single byte rule, < 0x80)
        assert_eq!(encode(&Item::String(vec![0x00])), hex("00"));
        assert_eq!(decode(&hex("00")).unwrap(), Item::String(vec![0x00]));
    }

    #[test]
    fn kat_single_byte_high() {
        // [0x0f] → 0x0f (single byte, < 0x80)
        assert_eq!(encode(&Item::String(vec![0x0f])), hex("0f"));
    }

    #[test]
    fn kat_byte_0x80() {
        // [0x80] → 0x8180 (single byte == 0x80 → short string rule)
        assert_eq!(encode(&Item::String(vec![0x80])), hex("8180"));
        assert_eq!(decode(&hex("8180")).unwrap(), Item::String(vec![0x80]));
    }

    #[test]
    fn kat_integer_zero() {
        assert_eq!(encode_uint(0), hex("80")); // 0 → empty → 0x80
        assert_eq!(encode_uint(0x0f), hex("0f")); // 15 → single byte
        assert_eq!(encode_uint(0x0400), hex("820400")); // 1024 → 2-byte string
    }

    #[test]
    fn kat_nested_list() {
        // [[], [[]], [[], [[]]]] - classic nested test
        let item = Item::List(vec![
            Item::List(vec![]),
            Item::List(vec![Item::List(vec![])]),
            Item::List(vec![
                Item::List(vec![]),
                Item::List(vec![Item::List(vec![])]),
            ]),
        ]);
        // Expected: 0xc7 c0 c1 c0 c3 c0 c1 c0
        assert_eq!(encode(&item), hex("c7c0c1c0c3c0c1c0"));
        assert_eq!(decode(&hex("c7c0c1c0c3c0c1c0")).unwrap(), item);
    }

    // ---- The negative and canonical-form tests, the security seals ----

    #[test]
    fn neg_trailing_bytes_rejected() {
        // "dog" (0x83646f67) + trailing 0xff → TrailingBytes
        let bad = hex("83646f67ff");
        assert_eq!(decode(&bad).unwrap_err(), RlpError::TrailingBytes);
    }

    #[test]
    fn neg_leading_zero_length_rejected() {
        // Long-string 1-byte length with leading zero: 0xb8 00 → NonCanonical
        // (0 bytes payload as long-form is non-canonical)
        assert_eq!(decode(&hex("b800")).unwrap_err(), RlpError::NonCanonical);
    }

    #[test]
    fn neg_minimal_len_violation_rejected() {
        // Long-form string with 1-byte length < 56: 0xb8 05 68656c6c6f → NonCanonical
        // ("hello" is 5 bytes, should use short-form 0x85)
        let bad = hex("b80568656c6c6f");
        assert_eq!(decode(&bad).unwrap_err(), RlpError::NonCanonical);
    }

    #[test]
    fn neg_truncated_payload_rejected() {
        // Declares len=3 but only 2 bytes: 0x83 646f → UnexpectedEof
        assert_eq!(decode(&hex("836466")).unwrap_err(), RlpError::UnexpectedEof);
    }

    #[test]
    fn neg_empty_input_rejected() {
        assert_eq!(decode(&[]).unwrap_err(), RlpError::UnexpectedEof);
    }

    #[test]
    fn neg_integer_leading_zero_rejected() {
        // Integer 0 as 0x00 00 (leading zero) → NonCanonical
        let item = Item::String(vec![0x00, 0x00]);
        assert_eq!(decode_uint(&item).unwrap_err(), RlpError::NonCanonical);
    }

    // ---- Roundtrip (fuzz-benzeri) ----

    #[test]
    fn roundtrip_arbitrary_strings() {
        for n in &[0usize, 1, 2, 55, 56, 100, 256] {
            let bytes: Vec<u8> = (0..*n).map(|i| (i % 251) as u8).collect();
            let item = Item::String(bytes.clone());
            let enc = encode(&item);
            assert_eq!(decode(&enc).unwrap(), item, "roundtrip n={n}");
        }
    }

    #[test]
    fn roundtrip_nested_lists() {
        let item = Item::List(vec![
            Item::String(b"hello".to_vec()),
            Item::List(vec![Item::String(vec![0xff; 60]), Item::String(vec![])]),
            Item::List(vec![]),
        ]);
        let enc = encode(&item);
        assert_eq!(decode(&enc).unwrap(), item);
    }

    #[test]
    fn rlp_bytes_serde_roundtrip() {
        let item = Item::List(vec![Item::String(b"abc".to_vec()), Item::String(vec![])]);
        let rb = RlpBytes::from_item(&item);
        // With `#[serde(transparent)]` over `Vec<u8>`, serde_json serialises it as
        // a byte array.
        let json = serde_json::to_string(&rb).unwrap();
        assert!(json.starts_with('['), "byte-array serde: {json}");
        let back: RlpBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decode().unwrap(), item);
    }
}
