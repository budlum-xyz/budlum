//! Print canonical network genesis hashes (Task 3 §3.1 operator helper).
//!
//! ```bash
//! cargo run --example print_genesis_hash
//! ```
fn main() {
    use budlum_core::chain::genesis::{devnet_genesis, mainnet_genesis, testnet_genesis};

    let mainnet = mainnet_genesis().build_genesis_block();
    let testnet = testnet_genesis().build_genesis_block();
    let devnet = devnet_genesis().build_genesis_block();

    println!("MAINNET_HASH={}", mainnet.hash);
    println!("MAINNET_STATE_ROOT={}", mainnet.state_root);
    println!("MAINNET_VALIDATOR_SET_HASH={}", mainnet.validator_set_hash);
    println!("MAINNET_CHAIN_ID={}", mainnet.chain_id);
    println!("MAINNET_TIMESTAMP={}", mainnet.timestamp);
    println!("TESTNET_HASH={}", testnet.hash);
    println!("DEVNET_HASH={}", devnet.hash);
}
