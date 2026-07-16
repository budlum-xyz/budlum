#![no_main]

use budlum_core::core::address::Address;
use budlum_core::core::block::BlockHeader;
use libfuzzer_sys::fuzz_target;

fn take_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    u64::from_le_bytes(bytes)
}

fn take_u128(data: &[u8], offset: usize) -> u128 {
    let mut bytes = [0u8; 16];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    u128::from_le_bytes(bytes)
}

fn take_32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + idx).copied().unwrap_or_default();
    }
    bytes
}

fn hex32(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let producer = if data.first().copied().unwrap_or_default() & 1 == 1 {
        Some(Address::from(take_32(data, 97)))
    } else {
        None
    };

    // BlockHeader alanları genişlerse bu literal bilinçli olarak derleme
    // hatası verir (E0063) — fuzz harness'inin çekirdek tipten drift'i
    // CI'da anında yakalanır (sahte-yeşil kapı yok). Alan eklerken
    // burada da karşılığını fuzz byte'larından besleyin.
    let header = BlockHeader {
        index: take_u64(data, 1),
        hash: hex32(take_32(data, 9)),
        previous_hash: hex32(take_32(data, 41)),
        timestamp: take_u128(data, 73),
        producer,
        chain_id: take_u64(data, 193),
        state_root: hex32(take_32(data, 129)),
        tx_root: hex32(take_32(data, 161)),
        slashing_evidence: None,
        nonce: take_u64(data, 201),
        epoch: take_u64(data, 209),
        slot: take_u64(data, 217),
        vrf_output: data.get(225..257).unwrap_or(&[]).to_vec(),
        vrf_proof: data.get(257..289).unwrap_or(&[]).to_vec(),
        validator_set_hash: hex32(take_32(data, 289)),
        storage_root: None,
    };

    let _ = bincode::serialize(&header);
});
