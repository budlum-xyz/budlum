#![no_main]

//! Worker-socket frame codec robustness target (WP-09).
//!
//! The bytes come from another process. Success and typed `FrameError`s are
//! both expected; a panic, an allocation past the 16 MiB bound, or a decode that
//! is not stable under re-encoding is a finding.

use budlum_uel_abi::frame::{decode_frame, encode_frame, read_frame, MAX_FRAME_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let slice = decode_frame(data);
    let mut reader = data;
    let streamed = read_frame(&mut reader);
    // The two readers agree on the verdict class.
    assert_eq!(slice.is_ok(), streamed.is_ok());
    if let Ok((envelope, used)) = slice {
        assert!(used <= MAX_FRAME_BYTES + 4);
        // A frame that decoded re-encodes and decodes to the same envelope.
        if let Ok(bytes) = encode_frame(&envelope) {
            let again = decode_frame(&bytes).map(|(e, _)| e);
            assert_eq!(again, Ok(envelope));
        }
    }
});
