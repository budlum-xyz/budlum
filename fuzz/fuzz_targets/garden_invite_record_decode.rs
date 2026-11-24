#![no_main]

//! The Garden invite record decoder reads untrusted text.
//!
//! A record reaches a phone through a link fragment, a QR code, a clipboard
//! line or a local announcement, and every one of those paths is under a
//! stranger's control: anyone may hand a phone a string and ask it to join a
//! Garden. The decoder reads a version, five fixed-width fields, every length
//! that follows from the record itself, and a variable number of addresses,
//! then proves it consumed the whole body.
//!
//! What counts as a finding, in the order the assertions run:
//!
//!   1. A panic or an abort on any input. This parser reads lengths from the
//!      record and must answer a short record with the field it lacks, not
//!      with an index past the end (`panic = "abort"` in the node profile
//!      turns either into a dead validator).
//!   2. An accepted record that does not re-encode to the exact text it came
//!      from. One record has one encoding: the signature is over the fields,
//!      so a record two nodes re-encode differently is a record they will
//!      disagree about later.
//!   3. An accepted record longer than the byte budget directive 5.4 sets
//!      (`MAX_RECORD_BYTES`), which no phone could scan and no link could
//!      carry.

use libfuzzer_sys::fuzz_target;
use budlum_core::garden::invite_record::{GardenInviteRecord, MAX_RECORD_BYTES};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(record) = GardenInviteRecord::decode(text) {
        let re_encoded = record
            .encode()
            .expect("an accepted record must re-encode inside the budget");
        assert_eq!(
            re_encoded, text,
            "an accepted record must re-encode to itself"
        );
        assert!(
            re_encoded.len() <= MAX_RECORD_BYTES,
            "an accepted record must sit inside the {} byte budget, got {}",
            MAX_RECORD_BYTES,
            re_encoded.len()
        );
    }
});
