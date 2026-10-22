#![no_main]

//! F10.1 EVM RLP decoder robustness target.
//!
//! Any byte string may be supplied by an untrusted relayer. Success and typed
//! Decode errors are both expected outcomes; a panic, abort, or sanitizer
//! Finding is not.

use budlum_core::cross_domain::evm::rlp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rlp::decode(data);
});
