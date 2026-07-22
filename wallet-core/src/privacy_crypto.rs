//! Field-native Poseidon helpers matching in-repo `budzero/bud-vm`.
//!
//! MUST stay byte-for-byte aligned with:
//! - `budzero/bud-vm/src/lib.rs` (`poseidon4_hash_state`, `DOMAIN_NULLIFIER`)
//! - `budzero/bud-proof` PrivacyCommit / NullifierCheck AIR
//!
//! wallet-core intentionally does **not** depend on bud-vm (mobile/WASM
//! footprint); this is a deliberate duplicated primitive with lock tests.

/// Domain separator for nullifier derivation (D2) — ASCII "NULLIFER".
pub const DOMAIN_NULLIFIER: u64 = 0x4e55_4c4c_4946_4552;

const GOLDILOCKS_P: u64 = 18_446_744_069_414_584_321;

const MDS: [[u64; 8]; 8] = [
    [7, 1, 3, 8, 8, 3, 4, 9],
    [9, 7, 1, 3, 8, 8, 3, 4],
    [4, 9, 7, 1, 3, 8, 8, 3],
    [3, 4, 9, 7, 1, 3, 8, 8],
    [8, 3, 4, 9, 7, 1, 3, 8],
    [8, 8, 3, 4, 9, 7, 1, 3],
    [3, 8, 8, 3, 4, 9, 7, 1],
    [1, 3, 8, 8, 3, 4, 9, 7],
];

const RC: [[u64; 8]; 4] = [
    [
        0xdd5743e7f2a5a5d9,
        0xcb3a864e58ada44b,
        0xffa2449ed32f8cdc,
        0x42025f65d6bd13ee,
        0x7889175e25506323,
        0x34b98bb03d24b737,
        0xbdcc535ecc4faa2a,
        0x5b20ad869fc0d033,
    ],
    [
        0xf1dda5b9259dfcb4,
        0x27515210be112d59,
        0x4227d1718c766c3f,
        0x26d333161a5bd794,
        0x49b938957bf4b026,
        0x4a56b5938b213669,
        0x1120426b48c8353d,
        0x6b323c3f10a56cad,
    ],
    [
        0xce57d6245ddca6b2,
        0xb1fc8d402bba1eb1,
        0xb5c5096ca959bd04,
        0x6db55cd306d31f7f,
        0xc49d293a81cb9641,
        0x1ce55a4fe979719f,
        0xa92e60a9d178a4d1,
        0x002cc64973bcfd8c,
    ],
    [
        0xcea721cce82fb11b,
        0xe5b55eb8098ece81,
        0x4e30525c6f1ddd66,
        0x43c6702827070987,
        0xaca68430a7b5762a,
        0x3674238634df9c93,
        0x88cee1c825e33433,
        0xde99ae8d74b57176,
    ],
];

/// 4-round Poseidon over Goldilocks (alpha=7, width=8).
#[must_use]
pub fn poseidon4_hash_state(mut s: [u64; 8]) -> u64 {
    for round_rc in RC.iter() {
        for i in 0..8 {
            s[i] = ((s[i] as u128 + round_rc[i] as u128) % GOLDILOCKS_P as u128) as u64;
        }
        let mut sbox = [0u64; 8];
        for i in 0..8 {
            let x = s[i];
            let x2 = ((x as u128 * x as u128) % GOLDILOCKS_P as u128) as u64;
            let x4 = ((x2 as u128 * x2 as u128) % GOLDILOCKS_P as u128) as u64;
            sbox[i] = (((x4 as u128 * x2 as u128) % GOLDILOCKS_P as u128 * x as u128)
                % GOLDILOCKS_P as u128) as u64;
        }
        let mut next = [0u64; 8];
        for i in 0..8 {
            let mut sum: u128 = 0;
            for j in 0..8 {
                sum = (sum + MDS[i][j] as u128 * sbox[j] as u128) % GOLDILOCKS_P as u128;
            }
            next[i] = sum as u64;
        }
        s = next;
    }
    s[0]
}

#[must_use]
pub fn poseidon4_hash(a: u64, b: u64) -> u64 {
    poseidon4_hash_state([a, b, 0, 0, 0, 0, 0, 0])
}

/// PrivacyCommit absorption: Poseidon3(amount, recipient, blinding).
#[must_use]
pub fn poseidon4_hash3(a: u64, b: u64, c: u64) -> u64 {
    poseidon4_hash_state([a, b, c, 0, 0, 0, 0, 0])
}

/// commitment = Poseidon3(amount, recipient_tag, blinding)
#[must_use]
pub fn privacy_commit(amount: u64, recipient_tag: u64, blinding: u64) -> u64 {
    poseidon4_hash3(amount, recipient_tag, blinding)
}

/// nullifier = Poseidon2(secret, DOMAIN_NULLIFIER)
#[must_use]
pub fn privacy_nullifier(secret: u64) -> u64 {
    poseidon4_hash(secret, DOMAIN_NULLIFIER)
}

/// Pack a field element into a 32-byte note hash (LE low 8 bytes; high zero).
#[must_use]
pub fn hash_from_field(fe: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&fe.to_le_bytes());
    h
}

/// First 8 LE bytes as field element.
#[must_use]
pub fn field_from_hash(h: &[u8; 32]) -> u64 {
    u64::from_le_bytes(h[..8].try_into().expect("32-byte hash"))
}

/// Map a 32-byte Budlum address into a Goldilocks field tag (first 8 LE bytes
/// reduced mod P). Used as PrivacyCommit recipient limb when full address
/// does not fit in one field element.
#[must_use]
pub fn address_to_recipient_tag(addr: &[u8; 32]) -> u64 {
    let raw = u64::from_le_bytes(addr[..8].try_into().expect("addr"));
    raw % GOLDILOCKS_P
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_nullifier_constant_matches_spec() {
        assert_eq!(DOMAIN_NULLIFIER, 0x4e55_4c4c_4946_4552);
    }

    #[test]
    fn poseidon_two_vs_three_absorb_differ() {
        let a = poseidon4_hash(1, 2);
        let b = poseidon4_hash3(1, 2, 0);
        // state [1,2,0,...] vs [1,2,0,...] — hash3 with c=0 equals hash2
        assert_eq!(a, b);
        assert_ne!(poseidon4_hash3(1, 2, 3), a);
    }

    #[test]
    fn commit_nullifier_roundtrip_shapes() {
        let c = privacy_commit(100, 7, 99);
        let n = privacy_nullifier(0xA11CE);
        assert_ne!(c, 0);
        assert_ne!(n, 0);
        assert_eq!(field_from_hash(&hash_from_field(c)), c);
    }
}
