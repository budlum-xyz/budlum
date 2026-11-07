#![no_main]

//! B.U.D. 3.0 optical frame wire parser (`Bud3Frame::from_wire_bytes`) robustness target.
//!
//! Asserts panic-free decoding on arbitrary untrusted camera/wire bytes and canonical
//! round-trip (`to_wire_bytes() == data`) for every accepted `Bud3Frame`.

use budlum_core::storage::bud3::frame::Bud3Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = Bud3Frame::from_wire_bytes(data) {
        let reencoded = frame.to_wire_bytes();
        assert_eq!(reencoded, data, "canonical: one Bud3Frame, one wire encoding");
    }
});
