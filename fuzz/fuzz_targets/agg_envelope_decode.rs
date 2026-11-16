#![no_main]

//! Aggregation envelope parser robustness target.
//!
//! An envelope arrives on `agg/object` from any peer. It carries a heavy
//! object: a signature with its key, a proof or an opening.
//!
//! What counts as a finding, in the order the assertions run:
//!
//!   1. A panic, an abort or a slice past the end on any input.
//!   2. An accepted envelope whose payload is over the limit it was decoded
//!      under.
//!   3. An accepted envelope that does not encode back to the input. The
//!      object id is the hash of the envelope bytes, so a second encoding of
//!      one object would be a second id for it, and the rule that an object
//!      is admitted once would not hold.
//!   4. A panic in native verification on an envelope that decoded. The
//!      payload is attacker bytes and the verifier splits it by fixed lengths.

use budlum_core::aggregation::envelope::Envelope;
use budlum_core::aggregation::object::derive_claim;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use libfuzzer_sys::fuzz_target;

/// Above the largest signature object (7219 bytes), so a full object fits.
const MAX_PAYLOAD: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::decode(data, MAX_PAYLOAD) {
        assert!(envelope.payload.len() <= MAX_PAYLOAD);
        assert_eq!(envelope.encode(), data, "an envelope has one encoding");
        let _ = envelope.object_id();
        let _ = derive_claim(&SchemeStatusRegistry::genesis(), &envelope);
    }
});
