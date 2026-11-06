//! Integer, base58 and base64 readers over the Solana wire alphabet.
//!
//! The readers refuse rather than guess. A compact-`u16` whose upper bits carry
//! data, a base58 digit outside the alphabet, a base64 quartet with a non-zero
//! trailing bit, a length prefix that does not land on a boundary: each of them
//! would decode into a value the signer never wrote, so each is an error here as
//! well. Nothing in this module allocates beyond the value it returns.

/// Why a wire read was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The input ended before the field did.
    Truncated,
    /// Bytes remained after the last field of the message.
    TrailingBytes,
    /// A base58 character outside `1-9A-HJ-NP-Za-km-z`, or a base58 value whose
    /// leading zero bytes do not fit the target width.
    BadBase58,
    /// A base64 character outside the standard alphabet, or padding that is not
    /// canonical (a non-zero trailing bit, a bare `=` quartet, `=` before the
    /// end).
    BadBase64,
    /// A base64 encoding whose `=` count implies a length the input cannot have.
    BadBase64Length,
    /// A compact-`u16` whose two highest bits are set. It is not a length.
    BadCompactLength,
}

impl core::fmt::Display for ReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Truncated => "message ended before the field did",
            Self::TrailingBytes => "bytes after the last message field",
            Self::BadBase58 => "character outside the base58 alphabet",
            Self::BadBase64 => "non-canonical base64",
            Self::BadBase64Length => "base64 padding does not fit the input length",
            Self::BadCompactLength => "compact-u16 length bit set",
        };
        f.write_str(text)
    }
}

/// The 58-character Solana base58 alphabet.
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Maps a base58 byte to its digit, or `None` outside the alphabet.
fn base58_digit(byte: u8) -> Option<u8> {
    let mut index = 0usize;
    while index < BASE58_ALPHABET.len() {
        if BASE58_ALPHABET[index] == byte {
            // The alphabet is 58 characters, so the digit fits in a `u8`.
            return Some(index as u8);
        }
        index += 1;
    }
    None
}

/// Decodes base58 into exactly `N` bytes.
///
/// Leading `1`s are leading zero bytes, as in Bitcoin's encoding. The value is
/// accumulated in a big-endian scratch buffer of `N` bytes; an accumulation that
/// would carry past the first byte is a value too wide for `N` and is refused
/// rather than truncated.
pub fn base58_decode_exact<const N: usize>(text: &str) -> Result<[u8; N], ReadError> {
    let input = text.as_bytes();
    let mut zeros = 0usize;
    while zeros < input.len() && input[zeros] == b'1' {
        zeros += 1;
    }
    if zeros > N {
        return Err(ReadError::BadBase58);
    }

    let mut number = [0u8; N];
    let mut filled = 0usize;
    for &byte in &input[zeros..] {
        let mut carry = u32::from(base58_digit(byte).ok_or(ReadError::BadBase58)?);
        // Multiply the accumulated number by 58 and add the digit.
        let mut index = N;
        while index > 0 {
            index -= 1;
            let value = u32::from(number[index]) * 58 + carry;
            number[index] = (value & 0xFF) as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return Err(ReadError::BadBase58);
        }
        let first_used = number.iter().position(|&b| b != 0).map_or(N, |p| p);
        let width = N - first_used;
        if width > filled {
            filled = width;
        }
    }

    // `zeros` leading zero bytes, then the accumulated value in the tail.
    if zeros + filled > N {
        return Err(ReadError::BadBase58);
    }
    let mut out = [0u8; N];
    let start = N - filled;
    out[zeros..].copy_from_slice(&number[start..]);
    Ok(out)
}

/// Maps a base64 byte to its 6-bit value, or `None` outside the alphabet.
fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes standard, padded base64.
///
/// The encoding must be canonical: the padding must make the length a multiple
/// of four, `=` may appear only at the end, and the bits the padding replaces
/// must be zero. A signature whose base64 carries non-zero spare bits decodes to
/// a different byte string at a stricter decoder, so it is refused here.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, ReadError> {
    let input = text.as_bytes();
    if input.len() % 4 != 0 {
        return Err(ReadError::BadBase64Length);
    }
    let mut padding = 0usize;
    while padding < input.len() && input[input.len() - 1 - padding] == b'=' {
        padding += 1;
    }
    if padding > 2 {
        return Err(ReadError::BadBase64);
    }

    let body = &input[..input.len() - padding];
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 3);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for &byte in body {
        let digit = u32::from(base64_digit(byte).ok_or(ReadError::BadBase64)?);
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xFF) as u8);
        }
    }
    // The bits left over must be zero, and they must be exactly the bits the
    // padding accounts for.
    let expected_spare = match padding {
        0 => 0,
        1 => 2,
        _ => 4,
    };
    if bits != expected_spare || (accumulator & ((1 << bits) - 1)) != 0 {
        return Err(ReadError::BadBase64);
    }
    Ok(out)
}

/// A cursor over a message.
///
/// Every read is bounds-checked and every length prefix is checked against the
/// bytes that remain, so a truncated or over-long message is refused at the
/// field that overran rather than at the end of the parse.
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Starts at the first byte.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// How many bytes remain.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    /// True when every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Takes `count` bytes.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than `count` bytes remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], ReadError> {
        if self.remaining() < count {
            return Err(ReadError::Truncated);
        }
        let start = self.offset;
        self.offset += count;
        Ok(&self.bytes[start..self.offset])
    }

    /// Takes one byte.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] at the end of the message.
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    /// Takes a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than four bytes remain.
    pub fn u32_le(&mut self) -> Result<u32, ReadError> {
        let raw = self.take(4)?;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(raw);
        Ok(u32::from_le_bytes(bytes))
    }

    /// Takes a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than eight bytes remain.
    pub fn u64_le(&mut self) -> Result<u64, ReadError> {
        let raw = self.take(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(raw);
        Ok(u64::from_le_bytes(bytes))
    }

    /// Takes a 32-byte hash.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than 32 bytes remain.
    pub fn hash32(&mut self) -> Result<[u8; 32], ReadError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    /// Takes a 32-byte public key.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than 32 bytes remain.
    pub fn pubkey(&mut self) -> Result<[u8; 32], ReadError> {
        self.hash32()
    }

    /// Takes a 64-byte Ed25519 signature.
    ///
    /// # Errors
    ///
    /// [`ReadError::Truncated`] when fewer than 64 bytes remain.
    pub fn signature(&mut self) -> Result<[u8; 64], ReadError> {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.take(64)?);
        Ok(out)
    }

    /// Reads a compact-`u16` length (Solana's short-vec prefix) and then that
    /// many bytes.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadCompactLength`] when the two high bits are set, and
    /// [`ReadError::Truncated`] when the body or the continuation byte is
    /// missing.
    pub fn short_vec(&mut self) -> Result<&'a [u8], ReadError> {
        let length = self.compact_u16()?;
        self.take(usize::from(length))
    }

    /// Reads a compact-`u16` length without a body.
    ///
    /// # Errors
    ///
    /// [`ReadError::BadCompactLength`] when the two high bits are set: that
    /// encoding names a wider length than the message grammar has.
    /// [`ReadError::Truncated`] when the continuation byte is missing.
    pub fn compact_u16(&mut self) -> Result<u16, ReadError> {
        let first = self.u8()?;
        if first & 0x80 == 0 {
            return Ok(u16::from(first));
        }
        if first & 0xC0 != 0x80 {
            return Err(ReadError::BadCompactLength);
        }
        let second = self.u8()?;
        Ok(u16::from(first & 0x7F) | (u16::from(second) << 7))
    }

    /// Refuses unless every byte has been consumed.
    ///
    /// # Errors
    ///
    /// [`ReadError::TrailingBytes`] when bytes remain.
    pub const fn finish(&self) -> Result<(), ReadError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ReadError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_roundtrips_a_known_vector_and_refuses_wide_values() {
        // The system program id, the best known 32-byte zero-ish base58 string.
        let system = base58_decode_exact::<32>("11111111111111111111111111111111").unwrap();
        assert_eq!(system, [0u8; 32]);

        // 32 bytes of 0xFF is wider than the alphabet can name in one key.
        assert_eq!(
            base58_decode_exact::<32>("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(ReadError::BadBase58)
        );
        // `0`, `O`, `I` and `l` are not base58 characters.
        assert_eq!(
            base58_decode_exact::<32>("11111111111111111111111111111110"),
            Err(ReadError::BadBase58)
        );
        // A value that fits exactly at 32 bytes is accepted.
        let max = base58_decode_exact::<32>("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG").unwrap();
        assert_eq!(max.len(), 32);
    }

    #[test]
    fn base58_of_one_byte_width_is_zero_padded() {
        // `1` is one leading zero byte and no value; two `1`s are two zero bytes.
        assert_eq!(base58_decode_exact::<1>("1").unwrap(), [0u8]);
        assert_eq!(base58_decode_exact::<2>("1").unwrap(), [0u8, 0]);
        assert_eq!(base58_decode_exact::<32>("1").unwrap(), [0u8; 32]);
    }

    #[test]
    fn base64_accepts_canonical_and_refuses_spare_bits() {
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(base64_decode("AA==").unwrap(), vec![0u8]);
        assert_eq!(base64_decode("AAA=").unwrap(), vec![0u8, 0]);
        assert_eq!(base64_decode("AAAA").unwrap(), vec![0u8, 0, 0]);
        // `AB==` decodes to 0x00 with a non-zero spare bit: not canonical.
        assert_eq!(base64_decode("AB=="), Err(ReadError::BadBase64));
        assert_eq!(base64_decode("AAB="), Err(ReadError::BadBase64));
        // A bare `=` quartet, `=` away from the end, a bad length, a bad digit.
        assert_eq!(base64_decode("===="), Err(ReadError::BadBase64));
        assert_eq!(base64_decode("AA=A"), Err(ReadError::BadBase64));
        assert_eq!(base64_decode("AAA"), Err(ReadError::BadBase64Length));
        assert_eq!(base64_decode("AA*A"), Err(ReadError::BadBase64));
    }

    #[test]
    fn compact_u16_reads_one_and_two_byte_forms() {
        assert_eq!(Reader::new(&[0x05]).compact_u16().unwrap(), 5);
        // 0x80 0x01 is 128.
        assert_eq!(Reader::new(&[0x80, 0x01]).compact_u16().unwrap(), 128);
        // 0xFF 0x7F is the largest two-byte form: 16383.
        assert_eq!(Reader::new(&[0xFF, 0x7F]).compact_u16().unwrap(), 16383);
        // The high bit pair `11` names a wider form the grammar does not have.
        assert_eq!(
            Reader::new(&[0xC0, 0x01]).compact_u16(),
            Err(ReadError::BadCompactLength)
        );
        assert_eq!(Reader::new(&[0x80]).compact_u16(), Err(ReadError::Truncated));
    }

    #[test]
    fn short_vec_is_bounded_by_the_message() {
        // A three-byte body, prefixed with its length.
        let mut reader = Reader::new(&[0x03, 1, 2, 3]);
        assert_eq!(reader.short_vec().unwrap(), &[1u8, 2, 3]);
        assert_eq!(reader.finish(), Ok(()));

        // A length longer than the body is refused at the body read.
        let mut reader = Reader::new(&[0x09, 1, 2, 3]);
        assert_eq!(reader.short_vec(), Err(ReadError::Truncated));

        // Bytes after the last field are refused.
        let reader = Reader::new(&[0x01, 0x00]);
        assert_eq!(reader.finish(), Err(ReadError::TrailingBytes));
    }

    #[test]
    fn reads_are_exact_widths() {
        let mut reader = Reader::new(&[0u8; 100]);
        assert!(reader.hash32().is_ok());
        assert!(reader.pubkey().is_ok());
        assert_eq!(reader.remaining(), 4);
        assert_eq!(reader.signature(), Err(ReadError::Truncated));
        assert_eq!(reader.u32_le(), Ok(0));
        assert_eq!(reader.u64_le(), Err(ReadError::Truncated));
    }
}
