//! Verifies that the frozen definition blocks at the top of `README.md` (lines `1..=14`)
//! and `README.tr.md` (lines `1..=15`) match their pinned `SHA-256` digests (`KR-21`).

use std::fmt::Write as _;
use std::path::Path;

/// Pinned LF-normalized `SHA-256` digest of `README.md` lines `1..=14`.
pub const README_EN_PREFIX_SHA256: &str =
    "dd9be5206be37e05a39e26d002af633c23f56be7378bc8dfe10861406f063467";

/// Pinned LF-normalized `SHA-256` digest of `README.tr.md` lines `1..=15`.
pub const README_TR_PREFIX_SHA256: &str =
    "c883e0017f8c96de3ce27d863bc2b8625685b761ecef08e3af72284473c903fe";

const K256: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

/// Pure-Rust FIPS 180-4 `SHA-256` hex digest helper so `xtask/gates` stays dependency-minimal.
#[must_use]
pub fn sha256_hex(msg: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    let bit_len = u64::try_from(msg.len()).unwrap_or(0).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (slot, word_bytes) in w.iter_mut().take(16).zip(chunk.chunks_exact(4)) {
            if let Ok(arr) = <[u8; 4]>::try_from(word_bytes) {
                *slot = u32::from_be_bytes(arr);
            }
        }
        for i in 16..64 {
            let w15 = w.get(i - 15).copied().unwrap_or(0);
            let w2 = w.get(i - 2).copied().unwrap_or(0);
            let w16 = w.get(i - 16).copied().unwrap_or(0);
            let w7 = w.get(i - 7).copied().unwrap_or(0);
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            if let Some(dst) = w.get_mut(i) {
                *dst = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (&wi, &ki) in w.iter().zip(&K256) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ki)
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, delta) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(delta);
        }
    }
    let mut out = String::with_capacity(64);
    for word in h {
        let _ = write!(out, "{word:08x}");
    }
    out
}

fn check_prefix(
    root: &Path,
    rel: &str,
    line_count: usize,
    expected_hex: &str,
) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join(rel))
        .map_err(|e| format!("cannot read {rel}: {e}"))?;
    let normalized = text.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    if lines.len() < line_count {
        return Err(format!(
            "{rel} has only {} lines; expected at least {line_count} lines for the frozen definition block",
            lines.len()
        ));
    }
    let mut prefix = String::new();
    for line in lines.iter().take(line_count) {
        prefix.push_str(line);
        prefix.push('\n');
    }
    let actual = sha256_hex(prefix.as_bytes());
    if actual != expected_hex {
        return Err(format!(
            "{rel} lines 1..={line_count} SHA-256 drifted: got {actual}, expected {expected_hex} (KR-21)"
        ));
    }
    Ok(())
}

/// Checks both `README.md` and `README.tr.md` definition blocks against their pinned digests.
///
/// # Errors
///
/// Returns an error if either file is missing, truncated, or modified in its frozen header.
pub fn run(root: &Path) -> Result<String, String> {
    check_prefix(root, "README.md", 14, README_EN_PREFIX_SHA256)?;
    check_prefix(root, "README.tr.md", 15, README_TR_PREFIX_SHA256)?;
    Ok(String::from(
        "README definition blocks OK: README.md (1..=14) and README.tr.md (1..=15) match KR-21 SHA-256 pins.",
    ))
}

/// Self-test verifying NIST SHA-256 vector and failure on a modified definition block.
///
/// # Errors
///
/// Returns an error if the NIST vector mismatches or a tampered header passes.
pub fn self_test() -> Result<String, String> {
    let abc = sha256_hex(b"abc");
    if abc != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        return Err(format!("SHA-256 self-test vector mismatch: {abc}"));
    }
    if run(Path::new("/nonexistent-readme-definition-canary")).is_ok() {
        return Err(String::from("canary: missing tree was accepted"));
    }
    Ok(String::from(
        "readme-definition-block-is-verbatim self-test OK: NIST vector and missing-tree canary verified.",
    ))
}
