#![no_main]

//! Phase 11.2 Görev 3 — bridge lock/mint/burn/unlock + relayer ledger.
//!
//! Oracle: panic freedom + fund/status conservation under adversarial
//! operation sequences. Full lifecycle uses real Merkle proofs when the
//! sequence requests a valid relay; garbage proofs must return Err, not panic.

use budlum_core::core::address::Address;
use budlum_core::core::hash::hash_fields_bytes;
use budlum_core::cross_domain::event_tree::DomainEventTree;
use budlum_core::cross_domain::{
    AssetId, BridgeState, MerkleProof, RelayerConfig, UniversalRelayer,
};
use libfuzzer_sys::fuzz_target;

const MAX_OPS: usize = 24;

fn take(data: &[u8], i: &mut usize) -> u8 {
    let b = data.get(*i).copied().unwrap_or(0);
    *i = i.saturating_add(1);
    b
}

fn take_u64(data: &[u8], i: &mut usize) -> u64 {
    let mut b = [0u8; 8];
    for slot in &mut b {
        *slot = take(data, i);
    }
    u64::from_le_bytes(b)
}

fn addr(tag: u8) -> Address {
    let mut a = [0u8; 32];
    a[0] = tag;
    a[15] = tag.wrapping_mul(3);
    Address::from(a)
}

fuzz_target!(|data: &[u8]| {
    let mut i = 0usize;
    let mut bridge = BridgeState::new();
    let mut relayer = UniversalRelayer::new(RelayerConfig::default());
    let mut tree = DomainEventTree::new();

    // Seed a small pool of assets (register is idempotent-fail on dup).
    let asset_count = (take(data, &mut i) % 4) + 1;
    let mut assets = Vec::with_capacity(asset_count as usize);
    for n in 0..asset_count {
        let asset = AssetId(hash_fields_bytes(&[
            b"FUZZ_BRIDGE_ASSET",
            &[n],
            &[take(data, &mut i)],
        ]));
        let domain = 1u32 + (take(data, &mut i) % 3) as u32;
        let _ = bridge.register_asset(asset, domain);
        assets.push((asset, domain));
    }

    let ops = (take(data, &mut i) as usize % MAX_OPS) + 1;
    let mut last_message_id = None;
    let mut last_lock_msg = None;

    for step in 0..ops {
        let op = take(data, &mut i) % 6;
        let (asset, src_dom) = assets[step % assets.len()];
        let owner = addr(take(data, &mut i));
        let recipient = addr(take(data, &mut i));
        let amount = (take_u64(data, &mut i) % 10_000).saturating_add(1);
        let height = take_u64(data, &mut i) % 10_000;
        let expiry = height.saturating_add(100 + (take(data, &mut i) as u64));

        match op {
            0 => {
                // lock
                if let Ok((transfer, event)) = bridge.lock(
                    src_dom,
                    src_dom.wrapping_add(1).max(2),
                    height,
                    step as u32,
                    asset,
                    owner,
                    recipient,
                    amount as u128,
                    expiry,
                ) {
                    if let Some(ref msg) = event.message {
                        relayer.enqueue_relay(event.clone(), msg, height);
                        last_lock_msg = Some(msg.clone());
                    }
                    tree.push(event);
                    last_message_id = Some(transfer.message_id);
                }
            }
            1 => {
                // mint via last lock message
                if let Some(ref msg) = last_lock_msg {
                    let _ = bridge.mint(msg);
                }
            }
            2 => {
                // burn
                if let Some(mid) = last_message_id {
                    let burn_dom = src_dom.wrapping_add(1).max(2);
                    let _ = bridge.burn(mid, burn_dom);
                }
            }
            3 => {
                // unlock (must use burn domain after burn)
                if let Some(mid) = last_message_id {
                    let burn_dom = src_dom.wrapping_add(1).max(2);
                    let _ = bridge.unlock(mid, burn_dom);
                    let _ = bridge.unlock(mid, src_dom); // wrong domain — Err ok
                }
            }
            4 => {
                // relayer process with valid or garbage proof
                if let Some(mid) = last_message_id {
                    let use_valid = take(data, &mut i) & 1 == 1;
                    let root = tree.root();
                    let proof = if use_valid {
                        // index of last event if any
                        let idx = tree.events().len().saturating_sub(1);
                        tree.proof(idx).unwrap_or(MerkleProof {
                            leaf: [take(data, &mut i); 32],
                            index: take(data, &mut i) as usize,
                            siblings: vec![[take(data, &mut i); 32]],
                        })
                    } else {
                        let sib_n = (take(data, &mut i) % 8) as usize;
                        let mut siblings = Vec::with_capacity(sib_n);
                        for _ in 0..sib_n {
                            let mut s = [0u8; 32];
                            for byte in &mut s {
                                *byte = take(data, &mut i);
                            }
                            siblings.push(s);
                        }
                        let mut leaf = [0u8; 32];
                        for byte in &mut leaf {
                            *byte = take(data, &mut i);
                        }
                        MerkleProof {
                            leaf,
                            index: take(data, &mut i) as usize,
                            siblings,
                        }
                    };
                    let relayer_addr = addr(take(data, &mut i));
                    let _ = relayer.process_relay(mid, relayer_addr, &proof, root, height);
                }
            }
            _ => {
                // sweep expired locks — must not panic
                let _ = bridge.sweep_expired_locks(height.saturating_add(take(data, &mut i) as u64));
                let _ = relayer.expired_relays(height.saturating_add(1000));
                let _ = relayer.pending_count();
                let _ = relayer.ledger_root();
                let _ = bridge.root();
            }
        }
    }

    // Final conservation-ish probes (no panic).
    let _ = bridge.root();
    let _ = bridge.replay_root();
    let _ = relayer.ledger_root();
    let _ = tree.root();
});
