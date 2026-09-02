//! IPFS CID parsing and byte verification.
//!
//! A `.eth` name can point, through ENS, at an IPFS CID. That CID is content
//! addressed, so even without a Budlum manifest it is **verifiable**: the hash
//! of the fetched bytes must equal the multihash the CID carries.
//!
//! # What is supported and what is not
//!
//! Supported: `CIDv0` (`Qm...`, base58btc, `dag-pb`, `sha2-256`) and the form
//! of `CIDv1` with the `raw` codec (0x55) and a `sha2-256` multihash. These are
//! files addressed as a **single block**, and verifying them is an equality
//! check.
//!
//! Not supported: **multi-block** content under `dag-pb`, a `UnixFS` DAG. The
//! reason is that verification there is not an equality but a DAG walk: the
//! root block's protobuf has to be parsed, the child links extracted, each
//! child fetched separately and the pieces joined in order. That is work that
//! can be done wrongly in silence; it was not done, and it is **said not to
//! have been done**. Such a CID returns
//! [`CidVerdict::UnsupportedMultiblock`], and the scanner does not show the
//! page as verified.
//!
//! Erasing that distinction would erase this scanner's only claim.

use sha2::{Digest, Sha256};

/// The base58btc alphabet, as used by Bitcoin.
const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// multicodec: the sha2-256 multihash code.
const MH_SHA2_256: u64 = 0x12;
/// multicodec: the `raw` content type.
const CODEC_RAW: u64 = 0x55;
/// multicodec: the `dag-pb` content type.
const CODEC_DAG_PB: u64 = 0x70;

/// A parsed CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cid {
    pub version: u8,
    pub codec: u64,
    pub digest: [u8; 32],
}

/// The verdict that can be reached about a CID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidVerdict {
    /// The bytes were verifiable and were verified.
    Verified,
    /// The bytes could have been verified and were not: the hash does not match.
    DigestMismatch { expected: String, produced: String },
    /// dag-pb: it may not be a single block, and this version does not walk a
    /// DAG.
    UnsupportedMultiblock,
}

/// Decodes base58btc.
fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let val = u32::try_from(B58.iter().position(|c| *c == ch)?).ok()?;
        let mut carry = val;
        for byte in out.iter_mut().rev() {
            let x = u32::from(*byte) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Leading '1's are zero bytes.
    for ch in s.bytes() {
        if ch == b'1' {
            out.insert(0, 0);
        } else {
            break;
        }
    }
    Some(out)
}

/// Decode multibase base32 (RFC 4648, lowercase, unpadded).
fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for ch in s.chars() {
        let v = match ch {
            'a'..='z' => ch as u32 - 'a' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return None,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Read an unsigned varint; returns (value, bytes consumed).
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
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

/// Parses a CID string.
///
/// # Errors
///
/// An unrecognised multibase, an unsupported version, codec or hash, or a
/// malformed length.
pub fn parse(s: &str) -> Result<Cid, String> {
    let bytes = if s.len() == 46 && s.starts_with("Qm") {
        b58_decode(s).ok_or_else(|| String::from("base58btc could not be decoded"))?
    } else if let Some(rest) = s.strip_prefix('b') {
        b32_decode(rest).ok_or_else(|| String::from("base32 could not be decoded"))?
    } else if let Some(rest) = s.strip_prefix('z') {
        b58_decode(rest).ok_or_else(|| String::from("base58btc could not be decoded"))?
    } else if let Some(rest) = s.strip_prefix('f') {
        hex::decode(rest).map_err(|e| format!("base16 could not be decoded: {e}"))?
    } else {
        return Err(format!(
            "unrecognised multibase prefix; the CID {:?} is neither a CIDv0 nor a supported CIDv1 encoding",
            s.chars().next().unwrap_or('?')
        ));
    };
    parse_bytes(&bytes)
}

/// Parses a binary CID.
///
/// # Errors
///
/// Every shape the spec requires to be refused: an unknown version, a bare
/// multihash that is not `0x12 0x20`, a wrong length, or an unknown hash
/// type.
pub fn parse_bytes(bytes: &[u8]) -> Result<Cid, String> {
    // CIDv0: a bare 34-byte sha2-256 multihash.
    if bytes.len() == 34 && bytes[0] == 0x12 && bytes[1] == 0x20 {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[2..34]);
        return Ok(Cid {
            version: 0,
            codec: CODEC_DAG_PB,
            digest,
        });
    }

    let (version, n) =
        read_varint(bytes).ok_or_else(|| String::from("the version varint is malformed"))?;
    if version != 1 {
        return Err(format!(
            "CID version {version} is not supported; only CIDv0 and CIDv1 exist"
        ));
    }
    let rest = &bytes[n..];
    let (codec, n2) =
        read_varint(rest).ok_or_else(|| String::from("the codec varint is malformed"))?;
    let rest = &rest[n2..];
    let (mh_code, n3) =
        read_varint(rest).ok_or_else(|| String::from("the multihash code is malformed"))?;
    let rest = &rest[n3..];
    let (mh_len, n4) =
        read_varint(rest).ok_or_else(|| String::from("the multihash length is malformed"))?;
    let rest = &rest[n4..];

    if mh_code != MH_SHA2_256 {
        return Err(format!(
            "multihash {mh_code:#x} is not supported; this scanner cannot verify a digest \
             function other than sha2-256, and it does not hide that it cannot"
        ));
    }
    if mh_len != 32 || rest.len() != 32 {
        return Err(format!(
            "a sha2-256 digest must be 32 bytes; {mh_len} was declared and {} bytes are present",
            rest.len()
        ));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(rest);
    Ok(Cid {
        version: 1,
        codec,
        digest,
    })
}

/// Verifies the fetched bytes against the CID.
#[must_use]
pub fn verify(cid: &Cid, bytes: &[u8]) -> CidVerdict {
    // dag-pb: the bytes are a protobuf node, not raw content. Whether it is a
    // single block or many cannot be known without parsing, and this version
    // does not parse.
    if cid.codec == CODEC_DAG_PB {
        return CidVerdict::UnsupportedMultiblock;
    }
    if cid.codec != CODEC_RAW {
        return CidVerdict::UnsupportedMultiblock;
    }
    let produced: [u8; 32] = Sha256::digest(bytes).into();
    if produced == cid.digest {
        CidVerdict::Verified
    } else {
        CidVerdict::DigestMismatch {
            expected: hex::encode(cid.digest),
            produced: hex::encode(produced),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_v1_raw_hello_from_the_spec() {
        // specs.ipfs.tech/cid: the CIDv1 raw form of the bytes "hello".
        let s = "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq";
        let cid = parse(s).expect("the spec example must parse");
        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, CODEC_RAW);
        assert_eq!(
            hex::encode(cid.digest),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(verify(&cid, b"hello"), CidVerdict::Verified);
    }

    #[test]
    fn wrong_bytes_are_refused_with_both_digests() {
        let cid = parse("bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq").unwrap();
        match verify(&cid, b"goodbye") {
            CidVerdict::DigestMismatch { expected, produced } => {
                assert_ne!(expected, produced);
            }
            other => panic!("a mismatch was expected, got {other:?}"),
        }
    }

    #[test]
    fn cid_v0_parses_but_is_not_claimed_verified() {
        // A Qm... CID is dag-pb: the bytes may be a UnixFS node. The digest is
        // read, but nothing is called verified.
        let s = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        let cid = parse(s).expect("the CIDv0 must parse");
        assert_eq!(cid.version, 0);
        assert_eq!(cid.codec, CODEC_DAG_PB);
        assert_eq!(verify(&cid, b"whatever"), CidVerdict::UnsupportedMultiblock);
    }

    #[test]
    fn an_unknown_multibase_is_refused_not_guessed() {
        assert!(parse("Xnotacid").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn a_non_sha256_multihash_is_refused_by_name() {
        // CIDv1 plus raw plus blake2b-256 (0xb220) plus 32 bytes.
        let mut bytes = vec![0x01, 0x55, 0xa0, 0xe4, 0x02, 0x20];
        bytes.extend_from_slice(&[0u8; 32]);
        let err = parse_bytes(&bytes).unwrap_err();
        assert!(err.contains("is not supported"), "{err}");
    }

    #[test]
    fn a_truncated_digest_is_refused() {
        let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
        bytes.extend_from_slice(&[0u8; 31]);
        assert!(parse_bytes(&bytes).is_err());
    }
}
