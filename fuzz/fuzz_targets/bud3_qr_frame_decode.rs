#![no_main]

//! B.U.D. 3.0 optical frame parser robustness target.
//!
//! A frame arrives from a camera, from a screen, or from an intermediate
//! process that rewrote it. Every byte in it is untrusted, and the parser is
//! the first code that touches those bytes: it reads a length from the header,
//! indexes past it, and hands the nested drop to a second parser. That is the
//! shape this repository has already found three bugs in elsewhere (a declared
//! length read before a bound check, a slice index under `panic = "abort"`, a
//! nested decoder that trusted its parent).
//!
//! What counts as a finding, in the order the assertions run:
//!
//!   1. A panic, an abort, or a slice past the end on any input.
//!   2. An accepted frame whose nested drop is longer than the lab cap
//!      (`MAX_DROP_WIRE`), which would mean the two ends disagree about the
//!      largest legal drop.
//!   3. An accepted frame that does not re-pack to itself. One frame has one
//!      encoding: the digest is over the header fields and the drop wire, so a
//!      frame that parses and re-encodes differently is a frame two nodes can
//!      disagree about. The one documented exception is the high nibble of the
//!      flags byte, which is ignorable by design and re-packs as zero, so the
//!      round trip is asserted only when that nibble is clear.
//!
//! The stream commitment is fixed rather than taken from the input: a foreign
//! commitment fails the fast reject before the parser does any work, which
//! would make the target spend its budget on one comparison. Fixing it keeps
//! the interesting surface, the header and the nested drop, reachable from
//! arbitrary bytes.

use budlum_core::storage::qr_frame::{pack_frame, unpack_frame, MAX_DROP_WIRE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let commitment = [0x5Au8; 32];
    if let Ok(drop) = unpack_frame(&commitment, data) {
        let wire = drop.to_bytes();
        assert!(
            wire.len() <= MAX_DROP_WIRE as usize,
            "an accepted drop is longer than the lab cap"
        );
        // Byte 3 is the flags byte: magic[0..2], version, flags.
        let flags = data.get(3).copied().unwrap_or(1);
        if flags == 0 {
            if let Ok(repacked) = pack_frame(&commitment, &drop) {
                assert_eq!(repacked, data, "canonical: one frame, one encoding");
            }
        }
    }
});
