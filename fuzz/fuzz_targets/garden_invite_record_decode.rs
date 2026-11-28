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
//!   2. An accepted record that does not round-trip cleanly to its canonical
//!      link form. One record has one canonical link encoding: the signature
//!      is over the fields, so a record two nodes re-encode differently is a
//!      record they will disagree about later.
//!   3. An accepted record whose canonical link exceeds the byte budget
//!      directive 5.4 sets (`MAX_RECORD_LINK_BYTES`), which no phone could
//!      scan and no link could carry.

use budlum_core::garden::record::{GardenRecord, MAX_RECORD_LINK_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(record) = GardenRecord::parse(text) {
        let re_encoded = record.to_link();
        assert!(
            re_encoded.len() <= MAX_RECORD_LINK_BYTES,
            "an accepted record must sit inside the {} byte budget, got {}",
            MAX_RECORD_LINK_BYTES,
            re_encoded.len()
        );
        let reparsed = GardenRecord::parse(&re_encoded)
            .expect("an accepted record's canonical link must parse back");
        assert_eq!(
            reparsed, record,
            "an accepted record must round-trip cleanly through its canonical link"
        );
    }
});
