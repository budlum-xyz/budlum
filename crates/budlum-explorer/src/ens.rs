//! ENS: namehash (EIP-137) and `contenthash` (EIP-1577) resolution.
//!
//! # What the browser wants from ENS
//!
//! Asking an ENS server and accepting its answer reduces this browser's entire
//! verification claim to that server's honesty. What is wanted is a **proof**: a
//! Merkle-Patricia proof binding the `namehash(name)` key to the storage slot of
//! the resolver contract, with the state root that proof is bound to living in a
//! verified Ethereum header.
//!
//! Budlum's `src/cross_domain/evm/` layer already does half of this work:
//! `header.rs`, `mpt.rs`, `sync_committee.rs`, `verify.rs`. Budlum Explorer is a
//! **consumer** of that layer, not a copy of it: namehash and contenthash
//! resolution live here, MPT verification does not. This module produces an
//! `MptProofRequest` and an `EvmProofVerifier` implementation verifies it; if the
//! proof cannot be verified the answer is labelled
//! [`crate::evidence::Strength::RpcClaimOnly`] and is not called verified.
//!
//! Erasing that distinction would put "proven" and "somebody said so" under the
//! same badge.

use sha3::{Digest, Keccak256};

/// EIP-137 namehash.
///
/// ```text
/// namehash([])            = 0x00 * 32
/// namehash([label, ...])  = keccak256(namehash(...) || keccak256(label))
/// ```
#[must_use]
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    for label in name.split('.').rev() {
        let label_hash: [u8; 32] = Keccak256::digest(label.as_bytes()).into();
        let mut h = Keccak256::new();
        h.update(node);
        h.update(label_hash);
        node = h.finalize().into();
    }
    node
}

/// The keccak-256 of a single label.
#[must_use]
pub fn labelhash(label: &str) -> [u8; 32] {
    Keccak256::digest(label.as_bytes()).into()
}

/// The target that comes out of an EIP-1577 `contenthash` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentHash {
    /// `ipfs-ns` (0xe3): the body is a CID.
    Ipfs(Vec<u8>),
    /// `ipns-ns` (0xe5): the body is an IPNS key. Resolving it requires a
    /// signature chain and this version does not verify one.
    Ipns(Vec<u8>),
    /// `swarm-ns` (0xe4).
    Swarm(Vec<u8>),
    /// `arweave-ns` (0xb29910): the body is a transaction id.
    Arweave(Vec<u8>),
    /// `onion3` (0xbd): the body is an onion address.
    Onion3(String),
}

/// Upper bound on an EIP-1577 `contenthash` byte string so hostile RPC
/// responses cannot force unbounded allocation before protocol checks run.
///
/// WIRING: ENS contenthash ceiling constant.
pub const MAX_CONTENTHASH_BYTES: usize = 2048;

/// Read a canonical unsigned-varint: rejects trailing zero bytes (overlong
/// encodings) and 10th-byte shifts that overflow `u64`.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        // Reject non-canonical trailing zero bytes (e.g. `0xe3 0x81 0x00`).
        if i > 0 && *b == 0 {
            return None;
        }
        // On the 10th byte (shift == 63) only bit 0 fits in a u64.
        if shift == 63 && (*b & 0x7f) > 1 {
            return None;
        }
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

/// Validate a Tor v3 onion host: exactly 56 lowercase RFC 4648 base32
/// characters (`a-z`, `2-7`), optionally followed by `.onion`.
fn is_valid_onion3(s: &str) -> bool {
    let host = s.strip_suffix(".onion").unwrap_or(s);
    host.len() == 56 && host.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// Decode a `contenthash` byte string.
///
/// # Errors
///
/// An empty or oversized field, a corrupt or non-canonical varint, an invalid
/// `onion3` address, or a protocol this browser has no fetcher for. For an
/// unrecognized protocol nothing is **guessed**: a target whose network is
/// unknown, if downgraded to HTTPS, would make the user believe an unverified
/// page was verified.
pub fn decode_contenthash(bytes: &[u8]) -> Result<ContentHash, String> {
    if bytes.is_empty() {
        return Err(String::from(
            "the contenthash is empty: the name is not bound to any content",
        ));
    }
    if bytes.len() > MAX_CONTENTHASH_BYTES {
        return Err(format!(
            "the contenthash is {} bytes, above the {} byte ceiling",
            bytes.len(),
            MAX_CONTENTHASH_BYTES
        ));
    }
    let (proto, n) =
        read_varint(bytes).ok_or_else(|| String::from("the protocol varint is corrupt"))?;
    let body = &bytes[n..];
    if body.is_empty() {
        return Err(format!(
            "protocol {proto:#x} was declared but the body is empty"
        ));
    }
    match proto {
        0xe3 => Ok(ContentHash::Ipfs(body.to_vec())),
        0xe5 => Ok(ContentHash::Ipns(body.to_vec())),
        0xe4 => Ok(ContentHash::Swarm(body.to_vec())),
        0xb2_9910 => Ok(ContentHash::Arweave(body.to_vec())),
        0xbd => {
            let text = String::from_utf8(body.to_vec())
                .map_err(|_| String::from("the onion3 body is not UTF-8"))?;
            if !is_valid_onion3(&text) {
                return Err(String::from(
                    "the onion3 body is not a valid 56-character lowercase base32 v3 onion address",
                ));
            }
            Ok(ContentHash::Onion3(text))
        }
        other => Err(format!(
            "there is no fetcher for contenthash protocol {other:#x}; the browser does not know \
             which network to fetch it from and does not guess"
        )),
    }
}

/// The MPT proof requested for an ENS resolver storage slot.
///
/// This struct is a **request**, not an answer. Verification is done by Budlum's
/// `cross_domain/evm/mpt.rs` layer; Budlum Explorer labels the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptProofRequest {
    /// `namehash(name)`: the node the resolver uses as its key.
    pub node: [u8; 32],
    /// The address of the resolver contract being asked (20 bytes).
    pub resolver: [u8; 20],
    /// The Ethereum state root the proof is bound to.
    pub state_root: [u8; 32],
}

impl MptProofRequest {
    #[must_use]
    pub fn new(name: &str, resolver: [u8; 20], state_root: [u8; 32]) -> Self {
        Self {
            node: namehash(name),
            resolver,
            state_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namehash_matches_eip_137_vectors() {
        assert_eq!(namehash(""), [0u8; 32]);
        assert_eq!(
            hex::encode(namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn labelhash_matches_the_documented_value() {
        assert_eq!(
            hex::encode(labelhash("eth")),
            "4f5b812789fc606be1b3b16908db13fc7a9adf7ca72641f84d75b47069d3d7f0"
        );
    }

    #[test]
    fn contenthash_ipfs_decodes_to_a_cid_body() {
        // The example from the ensdomains/content-hash README.
        let raw = hex::decode(
            "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f",
        )
        .unwrap();
        match decode_contenthash(&raw).unwrap() {
            ContentHash::Ipfs(body) => {
                // The body is CIDv1 dag-pb sha2-256: 0x01 0x70 0x12 0x20 ...
                assert_eq!(&body[..4], &[0x01, 0x70, 0x12, 0x20]);
            }
            other => panic!("expected ipfs, got {other:?}"),
        }
    }

    #[test]
    fn contenthash_swarm_decodes() {
        let raw = hex::decode(
            "e40101701b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162",
        )
        .unwrap();
        assert!(matches!(
            decode_contenthash(&raw).unwrap(),
            ContentHash::Swarm(_)
        ));
    }

    #[test]
    fn an_unknown_protocol_is_refused_not_downgraded() {
        let raw = vec![0x7f, 0x01, 0x02];
        let err = decode_contenthash(&raw).unwrap_err();
        assert!(err.contains("no fetcher"), "{err}");
    }

    #[test]
    fn an_empty_contenthash_says_so() {
        assert!(decode_contenthash(&[]).is_err());
    }

    #[test]
    fn exp02_rejects_overlong_overflowing_varints_oversized_and_invalid_onion3() {
        // Overlong trailing-zero varint for 0xe3 (ipfs-ns): 0xe3 0x81 0x00 instead of 0xe3 0x01.
        let overlong = [0xe3u8, 0x81, 0x00, 0x01, 0x70, 0x12, 0x20];
        assert!(
            decode_contenthash(&overlong).is_err(),
            "overlong varint must be refused"
        );

        // 10th-byte u64 overflow in varint (bits past bit 63).
        let mut overflow = vec![0x80u8; 9];
        overflow.push(0x02);
        overflow.push(0x01);
        assert!(
            decode_contenthash(&overflow).is_err(),
            "u64-overflowing varint must be refused"
        );

        // Oversized contenthash payload (> 2048 bytes).
        let mut huge = vec![0xe3u8, 0x01];
        huge.resize(2051, 0x41);
        assert!(
            decode_contenthash(&huge).is_err(),
            "oversized contenthash must be refused"
        );

        // Arbitrary scheme/CRLF/path strings smuggled inside onion3 (0xbd 0x01).
        for bad in [
            "https://evil.com/phish",
            "evil.onion\r\nX-Injected: 1",
            "../../etc/passwd",
            "not-base32-upper-AAAA",
            "short",
        ] {
            let mut raw = vec![0xbdu8, 0x01];
            raw.extend_from_slice(bad.as_bytes());
            assert!(
                decode_contenthash(&raw).is_err(),
                "malformed onion3 {bad:?} must be refused"
            );
        }

        // Valid 56-char lowercase base32 Tor v3 onion address (with and without .onion).
        let valid_host = "a2b3c4d5e6f7g2h3i4j5k6l7m2n3o4p5q6r7s2t3u4v5w6x7y2z3a4b5";
        assert_eq!(valid_host.len(), 56);
        let mut raw_bare = vec![0xbdu8, 0x01];
        raw_bare.extend_from_slice(valid_host.as_bytes());
        assert_eq!(
            decode_contenthash(&raw_bare).unwrap(),
            ContentHash::Onion3(valid_host.to_string())
        );

        let valid_with_suffix = format!("{valid_host}.onion");
        let mut raw_suffix = vec![0xbdu8, 0x01];
        raw_suffix.extend_from_slice(valid_with_suffix.as_bytes());
        assert_eq!(
            decode_contenthash(&raw_suffix).unwrap(),
            ContentHash::Onion3(valid_with_suffix)
        );
    }
}
