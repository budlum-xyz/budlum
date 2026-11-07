//! Fuzz harness for all four Compatibility Lane foreign transaction decoders (`WP-28`/`WP-32`).

#![no_main]

use budlum_core::execution::coordinator::foreign::aptos::decode_and_verify_aptos_tx;
use budlum_core::execution::coordinator::foreign::cosmos::decode_and_verify_cosmos_tx;
use budlum_core::execution::coordinator::foreign::ethereum::decode_and_verify_ethereum_tx;
use budlum_core::execution::coordinator::foreign::solana::decode_and_verify_solana_tx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let _ = decode_and_verify_ethereum_tx(data);
    let _ = decode_and_verify_solana_tx(data);
    let _ = decode_and_verify_aptos_tx(data);
    let _ = decode_and_verify_cosmos_tx(data, "budlum-1", 0);
});
