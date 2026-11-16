#![no_main]

//! Claim frame parser robustness target.
//!
//! A claim frame arrives on `agg/frame` from any peer and inside every block
//! body once aggregation is on. Its header carries four lengths, and the
//! parser is the first code that reads them.
//!
//! What counts as a finding, in the order the assertions run:
//!
//!   1. A panic, an abort or a slice past the end on any input.
//!   2. An accepted frame over a limit it was decoded under: the limits are
//!      checked from the header, before anything is read for them.
//!   3. An accepted frame that does not encode back to the input. A frame has
//!      one encoding: its hash goes into the block header, so a frame that
//!      parses and re-encodes differently is a frame two nodes disagree about.
//!   4. A panic in the structure rules or in the fold of the shape on a frame
//!      that decoded. They run on every decoded frame, valid or not.

use budlum_core::aggregation::frame::{ClaimFrame, FrameLimits};
use libfuzzer_sys::fuzz_target;

/// Small limits, so the fuzzer reaches the limit checks with short inputs.
const LIMITS: FrameLimits = FrameLimits {
    max_claims: 64,
    max_proof_bytes: 1024,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = ClaimFrame::decode(data, &LIMITS) {
        assert!(frame.claims.len() <= LIMITS.max_claims);
        assert!(frame.proof.len() <= LIMITS.max_proof_bytes);
        assert!(frame.segments.len() <= frame.claims.len());
        assert_eq!(frame.encode(), data, "a frame has one encoding");
        for domain in [0u32, 7] {
            if let Ok(facts) = frame.check_structure(domain, &LIMITS) {
                assert_eq!(facts.claim_digests.len(), frame.claims.len());
                assert!(frame.hash(domain).is_ok());
            }
        }
    }
});
