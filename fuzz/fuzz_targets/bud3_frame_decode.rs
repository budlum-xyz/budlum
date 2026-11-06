#![no_main]

//! Optical frame parser robustness target.
//!
//! A frame is read off a screen by a camera, so its bytes come from outside
//! the tree and may be anything at all: a truncated header, a wrong magic, a
//! symbol longer than one QR symbol can carry, or a frame that reads fine and
//! presents a symbol the profile cannot use. The reader must answer with a
//! typed error and never panic, and a frame that is accepted must present the
//! symbol it names.

use budlum_core::storage::bud3::frames::{frame_for_symbol, symbol_from_frame};
use budlum_core::storage::bud3::Symbol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(symbol) = symbol_from_frame(data) {
        // An accepted frame is canonical: writing the symbol back gives the
        // same bytes, so one frame has one encoding.
        assert_eq!(frame_for_symbol(&symbol).ok().as_deref(), Some(data));
        // The symbol a frame presents is never empty and never larger than one
        // QR symbol can carry.
        assert!(!symbol.data.is_empty());
        assert!(symbol.data.len() <= 2953);
    }
    // A symbol built from the input also round trips through a frame when it
    // fits, which covers the writer side of the pair.
    if let Some((head, body)) = data.split_first_chunk::<8>() {
        let segment = u64::from_le_bytes(*head);
        let esi = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        let take = body.len().min(400);
        let (slice, _) = body.split_at(take);
        if !slice.is_empty() {
            let symbol = Symbol {
                segment,
                esi,
                data: slice.to_vec(),
            };
            if let Ok(frame) = frame_for_symbol(&symbol) {
                assert_eq!(symbol_from_frame(&frame).ok(), Some(symbol));
            }
        }
    }
});
