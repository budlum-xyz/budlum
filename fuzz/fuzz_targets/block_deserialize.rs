#![no_main]

//! Block decode, disk path and wire path.
//!
//! `bincode` over `Block` is the database encoding. The network decoder is
//! `NetworkMessage::from_bytes_validated` (prost, then the `TryFrom`
//! conversions with their nested bincode payloads). Every peer reaches that
//! function, so it is fed the same bytes here. Any `Err` is fine. A panic or
//! an unbounded allocation is a finding.

use budlum_core::network::protocol::NetworkMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _: Result<budlum_core::core::block::Block, _> = bincode::deserialize(data);

    if let Ok(message) = NetworkMessage::from_bytes_validated(data) {
        // A message that decoded must also encode again without a panic.
        let _ = message.to_bytes();
    }
});
