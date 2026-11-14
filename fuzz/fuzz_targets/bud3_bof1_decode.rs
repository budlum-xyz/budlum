#![no_main]

//! BOF-1 object parser robustness target.
//!
//! An object comes from untrusted holders. A typed `Bof1Error` and success are
//! both expected; a panic, a copy past the meter, or an accepted object that
//! does not re-encode to the same bytes is a finding (one object, one
//! encoding).

use budlum_core::storage::bud3::{Meter, Object};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut meter = Meter::for_object(1 << 20);
    if let Ok(obj) = Object::decode(data, &mut meter) {
        assert!(obj.payload.len() <= 1 << 20);
        assert_eq!(obj.encode(), data, "canonical: one object, one encoding");
        let _ = obj.raw_public_content();
    }
});
