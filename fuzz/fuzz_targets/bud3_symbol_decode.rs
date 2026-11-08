#![no_main]

//! RFC 6330 segment decoder robustness target.
//!
//! Symbols come from untrusted holders. The input is cut into a segment
//! length and a list of `(esi, symbol)` records; the decoder must refuse a
//! malformed symbol with a typed error and never panic, and a decoded segment
//! has exactly the declared length.

use budlum_core::storage::bud3::{Meter, Profile, SegmentDecoder, Symbol};
use libfuzzer_sys::fuzz_target;

const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 32,
    fps: 10,
    k_max: 64,
};

fuzz_target!(|data: &[u8]| {
    let Some((head, mut rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let len = u64::from(u16::from_le_bytes(*head)) % (P.segment_bytes() + 2);
    let Ok(mut dec) = SegmentDecoder::new(0, len, &P) else {
        return;
    };
    let mut meter = Meter::new(1 << 20, 1 << 12);
    while let Some((hdr, tail)) = rest.split_first_chunk::<4>() {
        let esi = u32::from_le_bytes(*hdr) & 0x00ff_ffff;
        let size = usize::from(hdr[3] % 40);
        let take = size.min(tail.len());
        let (sym, next) = tail.split_at(take);
        rest = next;
        let symbol = Symbol { segment: 0, esi, data: sym.to_vec() };
        if let Ok(Some(bytes)) = dec.push(symbol, &mut meter) {
            assert_eq!(bytes.len() as u64, len);
            break;
        }
    }
});
