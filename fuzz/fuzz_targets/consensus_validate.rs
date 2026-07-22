#![no_main]

// NOT: BlockHeader struct'ına yeni alan eklendiğinde bu hedef E0063 ile
// derlenemez. Alanlar burada TAM olarak doldurulmalıdır — CI'daki
// "Fuzz Quick (Task 8.5)" kapısı bunu yakalar. (2026-07-16'da
// chain_id/nonce/epoch/slot/vrf_* eklendiğinde hedef çürümüştü.)

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
    let flag = data.first().copied().unwrap_or_default();
    let producer = if flag & 1 == 1 {
        Some(Address::from(take_32(data, 97)))
    } else {
        None
    };
    let storage_root = if flag & 2 == 2 {
        Some(take_32(data, 273))
    } else {
        None
    };

    let header = BlockHeader {
        index: take_u64(data, 1),
        hash: hex32(take_32(data, 9)),
        previous_hash: hex32(take_32(data, 41)),
        timestamp: take_u128(data, 73),
        producer,
        state_root: hex32(take_32(data, 129)),
        tx_root: hex32(take_32(data, 161)),
        chain_id: take_u64(data, 193),
        nonce: take_u64(data, 201),
        epoch: take_u64(data, 209),
        slot: take_u64(data, 217),
        vrf_output: data.get(225..241).unwrap_or_default().to_vec(),
        vrf_proof: data.get(241..273).unwrap_or_default().to_vec(),
        validator_set_hash: hex32(take_32(data, 305)),
        slashing_evidence: None,
        storage_root,
    };

    let _ = bincode::serialize(&header);
});
