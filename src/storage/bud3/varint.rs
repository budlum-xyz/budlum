//! Bounded unsigned LEB128.
//!
//! Each BOF-1 varint field has a byte ceiling (`profile` and `codec` 2 bytes,
//! `dictionary` 4 bytes, lengths 9 bytes). The decoder refuses a longer
//! encoding, a non-minimal encoding (a trailing zero group), and a value that
//! does not fit in `u64`, so one value has exactly one encoding.
//! Convenience: public canonical bounded LEB128 varint codec for BOF-1 and symbol framing.

/// Why a varint was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// The input ended inside the varint.
    Truncated,
    /// More bytes than the field allows.
    TooLong { max_bytes: usize },
    /// A trailing zero group: the same value has a shorter encoding.
    NonMinimal,
    /// The value does not fit in 64 bits.
    Overflow,
}

/// Append `value` as LEB128.
pub fn write(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The encoded length of `value`.
#[must_use]
pub const fn len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    if bits == 0 {
        1
    } else {
        bits.div_ceil(7)
    }
}

/// Read one varint of at most `max_bytes` bytes from the front of `input`.
/// Returns the value and the number of bytes consumed.
///
/// # Errors
///
/// [`VarintError`] for a truncated, over-long, non-minimal or overflowing
/// encoding.
pub fn read(input: &[u8], max_bytes: usize) -> Result<(u64, usize), VarintError> {
    let mut value: u64 = 0;
    for (i, byte) in input.iter().copied().enumerate() {
        if i >= max_bytes || i >= 10 {
            return Err(VarintError::TooLong { max_bytes });
        }
        let group = u64::from(byte & 0x7f);
        let shift = 7 * i as u32;
        if shift == 63 && group > 1 {
            return Err(VarintError::Overflow);
        }
        value |= group << shift;
        if byte & 0x80 == 0 {
            if i > 0 && group == 0 {
                return Err(VarintError::NonMinimal);
            }
            return Ok((value, i + 1));
        }
    }
    Err(VarintError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_at_the_edges() {
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write(&mut buf, v);
            assert_eq!(buf.len(), len(v), "len agrees for {v}");
            assert_eq!(read(&buf, 10), Ok((v, buf.len())));
        }
    }

    #[test]
    fn varint_refuses_bad_encodings() {
        assert_eq!(read(&[], 9), Err(VarintError::Truncated));
        assert_eq!(read(&[0x80], 9), Err(VarintError::Truncated));
        assert_eq!(read(&[0x80, 0x00], 9), Err(VarintError::NonMinimal));
        assert_eq!(
            read(&[0xff, 0xff, 0x03], 2),
            Err(VarintError::TooLong { max_bytes: 2 })
        );
        // 2^64 needs a tenth group of 2.
        let over = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(read(&over, 10), Err(VarintError::Overflow));
        // u64::MAX needs ten bytes, so a 9-byte length field refuses it.
        let mut max = Vec::new();
        write(&mut max, u64::MAX);
        assert_eq!(read(&max, 9), Err(VarintError::TooLong { max_bytes: 9 }));
    }

    #[test]
    fn nine_bytes_hold_every_length_up_to_2_pow_63() {
        let mut buf = Vec::new();
        write(&mut buf, (1u64 << 63) - 1);
        assert_eq!(buf.len(), 9);
        assert!(read(&buf, 9).is_ok());
    }
}
