//! In-tree Recursive Length Prefix (RLP) - Ethereum Yellow Paper Appendix B.
//!
//! Minimal, denetlenebilir, bağımsız impl. **alloy/ethers YOK** (RFC Q3 = in_tree;
//! Minimal-dep + cargo-deny kuralıyla uyumlu). Keccak256 RLP tarafında kullanılmaz
//! (sadece MPT node hash'inde); RLP saf byte encoding'dir.
//!
//! # Canonical encoding kuralları (Yellow Paper Appendix B)
//!
//! 1. Tek byte `0x00..=0x7f` → byte kendisi.
//! 2. String (0..=55 bytes) → `[0x80 + len, ...bytes]`.
//! 3. String (>55 bytes) → `[0xb7 + len_of_len, ...len_be, ...bytes]`.
//! 4. List (payload 0..=55 bytes) → `[0xc0 + len, ...payload]`.
//! 5. List (payload >55 bytes) → `[0xf7 + len_of_len, ...len_be, ...payload]`.
//!
//! `len_of_len` = big-endian length'i ifade eden minimum bayt sayısı (leading
//! Zero YASAK - canonical olmayan encoding decoding'de RED).
//!
//! # Negatif test mühürleri
//!
//! Decode'da canonical-form denetimi: leading-zero length, minimum-length
//! Kullanılmamış uzunluk-önekli encoding, trailing bytes (tüketime başarısız),
//! Truncation → hepsi `Err`. Bu güvenlik için kritik (kanıtı uydurma yüzeyi).

use serde::{Deserialize, Serialize};

/// RLP item hiyerarşisi: byte-string veya list-of-items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Ham byte string (integer encoding değil - caller ayrıştırır).
    String(Vec<u8>),
    /// Ordered item list.
    List(Vec<Item>),
}

/// RLP encode/decode hatası (canonical-form ihlali dahil).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpError {
    /// Beklenmeyen bitiş (girdi encodingsiz kesti).
    UnexpectedEof,
    /// Geçersiz uzunluk öneki (ör. payload'a yetmeyen declared len).
    InvalidLengthPrefix,
    /// Canonical olmayan encoding (leading-zero len / minimal-len kullanılmamış).
    NonCanonical,
    /// Decode sonrası tüketilmemiş trailing bytes (inject yüzeyi).
    TrailingBytes,
    /// List derinliği aşımı (DoS koruması; RLP teknik olarak derin olabilir).
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

/// RLP encode için maksimum liste derinliği (DoS: sonsuz iç içe list decode koruması).
const MAX_DEPTH: usize = 32;

/// Bir RLP `Item`'i canonical olarak encode eder.
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

/// Uzunluk önekini yazar. `offset` = 0x80 (string) veya 0xc0 (list).
/// 0..=55 → `[offset + len]`; >55 → `[offset + 55 + len_of_len, ...len_be]`.
fn encode_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + (len as u8));
    } else {
        let len_be = trim_leading_zeros(len);
        out.push(offset + 55 + (len_be.len() as u8));
        out.extend_from_slice(&len_be);
    }
}

/// Bir usize'ı big-endian olarak minimal bayt sayısıyla döndürür (leading zero YOK).
fn trim_leading_zeros(n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let be = n.to_be_bytes();
    // İlk non-zero bayta kadar atla.
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    be[start..].to_vec()
}

/// Bir RLP byte akışını decode eder. **Tüm girdi tüketilmelidir** (trailing YASAK).
pub fn decode(input: &[u8]) -> Result<Item, RlpError> {
    let (item, rest) = decode_at(input, 0)?;
    if !rest.is_empty() {
        return Err(RlpError::TrailingBytes);
    }
    Ok(item)
}

/// `input[consumed..]`'dan bir item decode eder; (item, kalan-bytes) döner.
fn decode_at(input: &[u8], depth: usize) -> Result<(Item, &[u8]), RlpError> {
    if depth > MAX_DEPTH {
        return Err(RlpError::NestingTooDeep);
    }
    if input.is_empty() {
        return Err(RlpError::UnexpectedEof);
    }
    let first = input[0];

    // Kural 1: tek byte < 0x80 → byte-string([byte]).
    if first < 0x80 {
        return Ok((Item::String(vec![first]), &input[1..]));
    }
    // Kural 2: short string [0x80..=0xb7).
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        let payload = take_exact(&input[1..], len)?;
        return Ok((Item::String(payload.to_vec()), &input[1 + len..]));
    }
    // Kural 3: long string [0xb8..=0xbf].
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
    // Kural 4: short list [0xc0..=0xf7].
    if first <= 0xf7 {
        let len = (first - 0xc0) as usize;
        let payload = take_exact(&input[1..], len)?;
        let items = decode_list_items(payload, depth)?;
        return Ok((Item::List(items), &input[1 + len..]));
    }
    // Kural 5: long list [0xf8..=0xff].
    let len_of_len = (first - 0xf7) as usize;
    let len = decode_length_value(&input[1..], len_of_len)?;
    let payload_start = 1 + len_of_len;
    let payload = take_exact(&input[payload_start..], len)?;
    let items = decode_list_items(payload, depth)?;
    Ok((Item::List(items), &input[payload_start + len..]))
}

/// `len_of_len` bayttan big-endian uzunluk okur; **canonical denetim** (leading zero / sıfır-len YASAK).
fn decode_length_value(input: &[u8], len_of_len: usize) -> Result<usize, RlpError> {
    let len_bytes = take_exact(input, len_of_len)?;
    // Canonical: len_of_len=1 ise tek bayt; >1 ise ilk bayt sıfır olamaz.
    if len_of_len > 1 && len_bytes[0] == 0 {
        return Err(RlpError::NonCanonical);
    }
    if len_of_len == 1 && len_bytes[0] < 56 {
        // Minimal-len kuralı: 56'dan küçük uzunluk long-form kullanmamalı.
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

/// `input`'tan `n` bayt alır; yetmezse `UnexpectedEof`.
fn take_exact(input: &[u8], n: usize) -> Result<&[u8], RlpError> {
    if input.len() < n {
        return Err(RlpError::UnexpectedEof);
    }
    Ok(&input[..n])
}

/// Liste payload'ını item'lara bölerek decode eder (her item peş peşe, tümü tüketilmeli).
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
// Convenience: integer encode/decode (RLP integer kuralı - leading zero YASAK)
// ---------------------------------------------------------------------------

/// Bir u64'ü RLP integer olarak encode eder (0 → empty string → 0x80).
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

/// RLP item'ini big-endian integer olarak parse eder (leading zero YASAK → NonCanonical).
pub fn decode_uint(item: &Item) -> Result<u64, RlpError> {
    let bytes = match item {
        Item::String(b) => b,
        _ => return Err(RlpError::NonCanonical),
    };
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(RlpError::NonCanonical); // leading zero integer encoding
    }
    if bytes.is_empty() {
        return Ok(0); // empty string = integer 0 (canonical)
    }
    if bytes.len() > 8 {
        return Err(RlpError::InvalidLengthPrefix); // u64 taşması
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

/// Byte-string item'inden ham bytes döner (struct field extraction yardımcısı).
pub fn as_bytes(item: &Item) -> Result<&[u8], RlpError> {
    match item {
        Item::String(b) => Ok(b),
        _ => Err(RlpError::NonCanonical),
    }
}

/// Serde-güvenli wrapper (snapshot/RPC yüzeyi için - `#[serde(transparent)]` `Vec<u8>`).
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---- Ethereum resmi RLP test-vectors (KAT) ----

    /// `rlptest.txt` kanonik vectors (yellow paper + ethereum/tests).
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

    // ---- Negatif / canonical-form testleri (güvenlik mühürleri) ----

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
        // `#[serde(transparent)] Vec<u8>` → serde_json byte-array olarak serileştirir.
        let json = serde_json::to_string(&rb).unwrap();
        assert!(json.starts_with('['), "byte-array serde: {json}");
        let back: RlpBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decode().unwrap(), item);
    }
}
