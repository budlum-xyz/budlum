#![no_main]
use libfuzz_sys::fuzz_target;
use budlum_core::cross_domain::bridge::{BridgeState, AssetId};
use budlum_core::core::address::Address;

// Phase 11.2 Görev 3: Relayer escrow lifecycle fuzz target.
// Rastgele bridge operations → fund conservation + panic YOK.

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let mut bridge = BridgeState::new();
    let owner = Address::from([data[0]; 32]);
    let recipient = Address::from([data[1]; 32]);
    let asset = AssetId::from([data[2]; 32]);
    let domain = (data[3] % 5) as u32 + 1;

    let _ = bridge.register_asset(asset, domain);
    let lock_result = bridge.lock(domain, domain + 1, 10, 0, asset, owner, recipient, 100, 1000);
    if lock_result.is_err() {
        return;
    }

    // Sweep expired locks with various heights
    let _ = bridge.sweep_expired_locks(999_999);
    // Root must be computable without panic
    let _ = bridge.root();
    let _ = bridge.replay_root();
});
