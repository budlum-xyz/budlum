//! Fuzz harness for the four Compatibility Lane foreign transaction decoders.

#![no_main]

use budlum_core::execution::coordinator::foreign::aptos::{decode_aptos_tx, BUDLUM_APTOS_CHAIN_ID};
use budlum_core::execution::coordinator::foreign::cosmos::{
    decode_cosmos_tx, BUDLUM_COSMOS_CHAIN_ID,
};
use budlum_core::execution::coordinator::foreign::ethereum::{
    decode_ethereum_tx, BUDLUM_EVM_CHAIN_ID,
};
use budlum_core::execution::coordinator::foreign::solana::decode_solana_tx;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let _ = decode_ethereum_tx(data, BUDLUM_EVM_CHAIN_ID);
    let _ = decode_solana_tx(data);
    let _ = decode_aptos_tx(data, BUDLUM_APTOS_CHAIN_ID, 0);
    let _ = decode_cosmos_tx(data, BUDLUM_COSMOS_CHAIN_ID, 0, BUDLUM_COSMOS_CHAIN_ID);
});
