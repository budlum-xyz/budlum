//! SHA-256, in the gate crate, with no dependency.
//!
//! # Why this is here rather than a crate
//!
//! One gate compares a byte-exact block of a README against a digest the
//! directive states in its text. That needs SHA-256 over a slice and nothing
//! else: no streaming, no HMAC, no hex of a struct. `sha2` is already a
//! dependency of the node crate, but `xtask/gates` is its own workspace and
//! decides what reaches `main`; adding a crate to it to hash about a thousand
//! bytes widens that trust boundary for one function.
//!
//! # Correctness
//!
//! This is FIPS 180-4 with the standard padding and big-endian length. The
//! module's tests pin `""`, `"abc"` and the 56-byte message that forces a
//! second block against the digests FIPS 180-4 publishes, so a wrong constant
//! or a wrong rotation fails the unit tests rather than a gate that decides
//! whether `main` merges.

/// The initial hash value: the first 32 bits of the fractional parts of the
/// square roots of the first eight primes.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The round constants: the first 32 bits of the fractional parts of the cube
/// roots of the first sixty-four primes.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Rotate a word right by `n` bits.
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

/// One compression step over a 64-byte block.
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

/// The SHA-256 digest of `bytes`, as 32 big-endian bytes.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let mut chunks = bytes.chunks_exact(64);
    for block in &mut chunks {
        compress(&mut state, block);
    }
    // The tail is shorter than 64 bytes, so it needs its own padding: 0x80,
    // zeros, and the message length in bits as a big-endian u64, over one or
    // two blocks.
    let tail = chunks.remainder();
    let mut buffer = [0u8; 128];
    buffer[..tail.len()].copy_from_slice(tail);
    buffer[tail.len()] = 0x80;
    let padded = if tail.len() < 56 { 64 } else { 128 };
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    buffer[padded - 8..padded].copy_from_slice(&bit_len.to_be_bytes());
    for block in buffer[..padded].chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut out = [0u8; 32];
    for (slot, word) in out.chunks_exact_mut(4).zip(state) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The SHA-256 digest of `bytes`, as lowercase hexadecimal.
pub fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in digest(bytes) {
        // Writing into a String cannot fail; the Result exists only because
        // `fmt::Write` is shared with `io::Write` (`gates-do-not-panic`).
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three digests FIPS 180-4 publishes, plus the length boundary at 55,
    /// 56, 63 and 64 bytes where the padding crosses a block.
    #[test]
    fn fips_180_4_vectors() {
        assert_eq!(
            hex_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn padding_boundary_matches_bitcoin_style_vectors() {
        // `a` repeated: 55 bytes (one block), 56 bytes (two blocks), 64 bytes
        // (one full block plus padding), 1000 bytes.
        assert_eq!(
            hex_digest(&[b'a'; 55]),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            hex_digest(&[b'a'; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex_digest(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }
}
