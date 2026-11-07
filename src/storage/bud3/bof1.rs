//! BOF-1, the B.U.D. 3.0 object format.
//!
//! The object carries only what cannot be derived. Segment count, frame
//! count and the video commitment follow from the object length and the
//! profile, so they are not written. Repair symbols are not written either:
//! they are regenerated from the source symbols.
//!
//! Canonical binary layout (integers are bounded LEB128):
//!
//! | Field | Type | Present | Notes |
//! |---|---|---|---|
//! | `magic` | `[2]` | always | `B3` |
//! | `version` | `u8` | always | `1` |
//! | `flags` | `u8` | always | bit0 sealed, bit1 live segment, bit2 has base, bit3 has context; other bits 0 |
//! | `profile` | varint (2) | always | registered profile id, P0 = 0 |
//! | `codec` | varint (2) | always | A0 codec id |
//! | `dictionary` | varint (4) | always | 0 = none |
//! | `base` | `[32]` | bit2 | content id digest of the base object |
//! | `content_len` | varint (9) | always | 0 in a sealed object |
//! | `content_digest` | `[32]` | always | SHA-256 (public) or HMAC-SHA-256 (sealed) |
//! | `payload_len` | varint (9) | always | |
//! | `prev_object` | `[32]` | bit1 | commitment of the previous live segment |
//! | `context_manifest` | `[32]` | bit3 | refused at testnet launch |
//! | `payload` | bytes | always | `payload_len` bytes, nothing after |
//!
//! The parser never panics, never allocates from an untrusted length before
//! it has checked the bytes are there, and charges a [`Meter`] for the copy.
//!
//! exposed for: B.U.D. 3.0 object codec/header pipeline, CLI tools, and explorer inspection (`WP-18`).

use super::content_id::{ContentId, ContentIdKind};
use super::limits::{Profile, ProfileId};
use super::meter::{Meter, MeterError};
use super::varint::{self, VarintError};

/// `B3`.
pub const MAGIC: [u8; 2] = *b"B3";
/// The only version.
pub const VERSION: u8 = 1;

const MAX_PROFILE_BYTES: usize = 2;
const MAX_CODEC_BYTES: usize = 2;
const MAX_DICTIONARY_BYTES: usize = 4;
const MAX_LEN_BYTES: usize = 9;

/// A0 codec id.
pub type CodecId = u16;

/// The raw codec: the payload is the content.
pub const CODEC_RAW: CodecId = 0;

/// The registered codec ids. Id 9 is reserved and never valid.
#[must_use]
pub const fn codec_is_registered(id: CodecId) -> bool {
    bud_codec::registry::is_registered(id)
}

/// Codecs open at testnet launch. The format-specific codecs 14 to 22 open
/// only after their own acceptance gate, and the rest stay closed.
#[must_use]
pub const fn codec_is_open_on_testnet(id: CodecId) -> bool {
    matches!(id, 0 | 1 | 2 | 3 | 4 | 10 | 11)
}

/// The header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u8);

impl Flags {
    /// The payload is encrypted and the content id is keyed.
    pub const SEALED: u8 = 1 << 0;
    /// The object is one segment of a live stream.
    pub const LIVE: u8 = 1 << 1;
    /// The object depends on a base object (delta or derivation).
    pub const HAS_BASE: u8 = 1 << 2;
    /// The object depends on a shared compression context.
    pub const HAS_CONTEXT: u8 = 1 << 3;
    const KNOWN: u8 = Self::SEALED | Self::LIVE | Self::HAS_BASE | Self::HAS_CONTEXT;

    /// Flags from their byte. Unknown bits are refused.
    ///
    /// # Errors
    ///
    /// [`Bof1Error::UnknownFlags`].
    pub const fn from_byte(b: u8) -> Result<Self, Bof1Error> {
        if b & !Self::KNOWN != 0 {
            return Err(Bof1Error::UnknownFlags(b));
        }
        Ok(Self(b))
    }

    /// The byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `bit` is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

/// Why an object was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bof1Error {
    /// Not `B3`.
    BadMagic,
    /// Not version 1.
    BadVersion(u8),
    /// A flag bit outside the four defined ones.
    UnknownFlags(u8),
    /// The profile id is not registered.
    UnknownProfile(u64),
    /// The codec id is not registered.
    UnknownCodec(u64),
    /// The dictionary index is not registered.
    UnknownDictionary(u64),
    /// The context manifest bit is set; no context is registered yet.
    ContextNotOpen,
    /// A sealed object wrote a non-zero `content_len`.
    SealedContentLen,
    /// The input ended inside a field.
    Truncated(&'static str),
    /// A varint field is malformed.
    Varint(&'static str, VarintError),
    /// Bytes after the payload.
    TrailingBytes(u64),
    /// The meter refused the payload copy.
    Budget(MeterError),
    /// The content does not match the header (digest, length or codec).
    ContentMismatch,
}

impl From<MeterError> for Bof1Error {
    fn from(e: MeterError) -> Self {
        Self::Budget(e)
    }
}

/// The registered dictionary indices. Only 0 (no dictionary) until the
/// dictionary registry opens.
#[must_use]
pub const fn dictionary_is_registered(index: u32) -> bool {
    index == 0
}

/// The BOF-1 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Flags.
    pub flags: Flags,
    /// Profile id.
    pub profile: ProfileId,
    /// A0 codec id.
    pub codec: CodecId,
    /// Dictionary index; 0 = none.
    pub dictionary: u32,
    /// Base object digest, present with [`Flags::HAS_BASE`].
    pub base: Option<[u8; 32]>,
    /// Content length; 0 in a sealed object.
    pub content_len: u64,
    /// Content digest.
    pub content_digest: [u8; 32],
    /// Payload length.
    pub payload_len: u64,
    /// Previous live segment commitment, present with [`Flags::LIVE`].
    pub prev_object: Option<[u8; 32]>,
    /// Context manifest id, present with [`Flags::HAS_CONTEXT`].
    pub context_manifest: Option<[u8; 32]>,
}

impl Header {
    /// The profile this header names.
    #[must_use]
    pub const fn profile(&self) -> Option<Profile> {
        Profile::by_id(self.profile)
    }

    /// Whether the object is sealed.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.flags.has(Flags::SEALED)
    }
}

/// A BOF-1 object: header and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The header.
    pub header: Header,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn rest(&self) -> &'a [u8] {
        self.input.get(self.pos..).unwrap_or(&[])
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Bof1Error> {
        let end = self.pos.checked_add(n).ok_or(Bof1Error::Truncated(field))?;
        let bytes = self
            .input
            .get(self.pos..end)
            .ok_or(Bof1Error::Truncated(field))?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, Bof1Error> {
        self.take(1, field)?
            .first()
            .copied()
            .ok_or(Bof1Error::Truncated(field))
    }

    fn array32(&mut self, field: &'static str) -> Result<[u8; 32], Bof1Error> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32, field)?);
        Ok(out)
    }

    fn varint(&mut self, max: usize, field: &'static str) -> Result<u64, Bof1Error> {
        let (v, used) = varint::read(self.rest(), max).map_err(|e| Bof1Error::Varint(field, e))?;
        self.pos = self.pos.saturating_add(used);
        Ok(v)
    }
}

impl Object {
    /// A public object with the raw codec: the payload is the content.
    #[must_use]
    pub fn raw_public(content: &[u8]) -> Self {
        let id = ContentId::public(content);
        Self {
            header: Header {
                flags: Flags::default(),
                profile: Profile::P0.id,
                codec: CODEC_RAW,
                dictionary: 0,
                base: None,
                content_len: id.len,
                content_digest: id.digest,
                payload_len: content.len() as u64,
                prev_object: None,
                context_manifest: None,
            },
            payload: content.to_vec(),
        }
    }

    /// A public object whose payload is `payload`, coded with `codec`. The
    /// payload must decode to exactly `content` under the codec: an object
    /// never carries a payload that produces different content.
    ///
    /// # Errors
    ///
    /// [`Bof1Error::ContentMismatch`] when the payload does not decode to the
    /// content under the codec.
    pub fn public_coded(
        codec: CodecId,
        payload: Vec<u8>,
        content: &[u8],
    ) -> Result<Self, Bof1Error> {
        let id = ContentId::public(content);
        if codec == CODEC_RAW {
            if payload != content {
                return Err(Bof1Error::ContentMismatch);
            }
            return Ok(Self::raw_public(content));
        }
        let decoded =
            bud_codec::decode(codec, &payload, id.len).map_err(|_| Bof1Error::ContentMismatch)?;
        if decoded != content {
            return Err(Bof1Error::ContentMismatch);
        }
        Ok(Self {
            header: Header {
                flags: Flags::default(),
                profile: Profile::P0.id,
                codec,
                dictionary: 0,
                base: None,
                content_len: id.len,
                content_digest: id.digest,
                payload_len: payload.len() as u64,
                prev_object: None,
                context_manifest: None,
            },
            payload,
        })
    }

    /// The canonical binary encoding. A field is written exactly when its
    /// flag is set, so the encoding never disagrees with the flags.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let h = &self.header;
        let mut out = Vec::with_capacity(self.payload.len().saturating_add(128));
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(h.flags.bits());
        varint::write(&mut out, u64::from(h.profile));
        varint::write(&mut out, u64::from(h.codec));
        varint::write(&mut out, u64::from(h.dictionary));
        if h.flags.has(Flags::HAS_BASE) {
            out.extend_from_slice(&h.base.unwrap_or([0u8; 32]));
        }
        varint::write(&mut out, h.content_len);
        out.extend_from_slice(&h.content_digest);
        varint::write(&mut out, self.payload.len() as u64);
        if h.flags.has(Flags::LIVE) {
            out.extend_from_slice(&h.prev_object.unwrap_or([0u8; 32]));
        }
        if h.flags.has(Flags::HAS_CONTEXT) {
            out.extend_from_slice(&h.context_manifest.unwrap_or([0u8; 32]));
        }
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse the canonical binary encoding.
    ///
    /// # Errors
    ///
    /// [`Bof1Error`] for any deviation from the canonical form: wrong magic or
    /// version, unknown flag, profile, codec or dictionary, a malformed or
    /// over-long varint, a truncated field, bytes after the payload, or a
    /// payload the meter does not cover.
    pub fn decode(input: &[u8], meter: &mut Meter) -> Result<Self, Bof1Error> {
        let mut r = Reader::new(input);
        if r.take(2, "magic")? != MAGIC {
            return Err(Bof1Error::BadMagic);
        }
        let version = r.byte("version")?;
        if version != VERSION {
            return Err(Bof1Error::BadVersion(version));
        }
        let flags = Flags::from_byte(r.byte("flags")?)?;
        if flags.has(Flags::HAS_CONTEXT) {
            return Err(Bof1Error::ContextNotOpen);
        }
        let profile_raw = r.varint(MAX_PROFILE_BYTES, "profile")?;
        let profile = ProfileId::try_from(profile_raw)
            .ok()
            .filter(|p| Profile::by_id(*p).is_some())
            .ok_or(Bof1Error::UnknownProfile(profile_raw))?;
        let codec_raw = r.varint(MAX_CODEC_BYTES, "codec")?;
        let codec = CodecId::try_from(codec_raw)
            .ok()
            .filter(|c| codec_is_registered(*c))
            .ok_or(Bof1Error::UnknownCodec(codec_raw))?;
        let dict_raw = r.varint(MAX_DICTIONARY_BYTES, "dictionary")?;
        let dictionary = u32::try_from(dict_raw)
            .ok()
            .filter(|d| dictionary_is_registered(*d))
            .ok_or(Bof1Error::UnknownDictionary(dict_raw))?;
        let base = if flags.has(Flags::HAS_BASE) {
            Some(r.array32("base")?)
        } else {
            None
        };
        let content_len = r.varint(MAX_LEN_BYTES, "content_len")?;
        if flags.has(Flags::SEALED) && content_len != 0 {
            return Err(Bof1Error::SealedContentLen);
        }
        let content_digest = r.array32("content_digest")?;
        let payload_len = r.varint(MAX_LEN_BYTES, "payload_len")?;
        let prev_object = if flags.has(Flags::LIVE) {
            Some(r.array32("prev_object")?)
        } else {
            None
        };
        let rest = r.rest();
        let rest_len = rest.len() as u64;
        if rest_len < payload_len {
            return Err(Bof1Error::Truncated("payload"));
        }
        if rest_len > payload_len {
            return Err(Bof1Error::TrailingBytes(rest_len - payload_len));
        }
        meter.charge_bytes(payload_len)?;
        Ok(Self {
            header: Header {
                flags,
                profile,
                codec,
                dictionary,
                base,
                content_len,
                content_digest,
                payload_len,
                prev_object,
                context_manifest: None,
            },
            payload: rest.to_vec(),
        })
    }

    /// The content of a public raw object, checked against its header. Other
    /// codecs decode in the codec crate; this is the raw path.
    ///
    /// # Errors
    ///
    /// [`Bof1Error::ContentMismatch`] when the object is sealed, uses another
    /// codec, or its payload does not match the content length and digest.
    pub fn raw_public_content(&self) -> Result<&[u8], Bof1Error> {
        let h = &self.header;
        if h.is_sealed() || h.codec != CODEC_RAW {
            return Err(Bof1Error::ContentMismatch);
        }
        let id = ContentId {
            kind: ContentIdKind::Public,
            digest: h.content_digest,
            len: h.content_len,
        };
        if !id.matches_public(&self.payload) {
            return Err(Bof1Error::ContentMismatch);
        }
        Ok(&self.payload)
    }

    /// The content of a public object, checked against its header. The
    /// payload decodes under the header's codec to exactly the content the
    /// header commits to.
    ///
    /// # Errors
    ///
    /// [`Bof1Error::ContentMismatch`] when the object is sealed, the payload
    /// does not decode under the codec, or the decoded content does not match
    /// the content length and digest.
    pub fn public_content(&self) -> Result<Vec<u8>, Bof1Error> {
        let h = &self.header;
        if h.is_sealed() {
            return Err(Bof1Error::ContentMismatch);
        }
        if h.codec == CODEC_RAW {
            return self.raw_public_content().map(|bytes| bytes.to_vec());
        }
        let content = bud_codec::decode(h.codec, &self.payload, h.content_len)
            .map_err(|_| Bof1Error::ContentMismatch)?;
        let id = ContentId {
            kind: ContentIdKind::Public,
            digest: h.content_digest,
            len: h.content_len,
        };
        if !id.matches_public(&content) {
            return Err(Bof1Error::ContentMismatch);
        }
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meter() -> Meter {
        Meter::for_object(1 << 20)
    }

    #[test]
    fn raw_object_round_trips_and_is_at_most_header_larger() {
        let content = b"hello, budlum".repeat(10);
        let obj = Object::raw_public(&content);
        let bytes = obj.encode();
        let back = Object::decode(&bytes, &mut meter()).unwrap();
        assert_eq!(back, obj);
        assert_eq!(back.raw_public_content().unwrap(), &content[..]);
        let header_len = bytes.len() - content.len();
        assert!(
            header_len <= 2 + 1 + 1 + 1 + 1 + 1 + 9 + 32 + 9,
            "{header_len}"
        );
    }

    #[test]
    fn bof1_golden_header() {
        let obj = Object::raw_public(b"abc");
        let bytes = obj.encode();
        let mut want = vec![b'B', b'3', 1, 0, 0, 0, 0, 3];
        want.extend_from_slice(
            &hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap(),
        );
        want.push(3);
        want.extend_from_slice(b"abc");
        assert_eq!(bytes, want);
    }

    #[test]
    fn non_canonical_objects_are_refused() {
        let good = Object::raw_public(b"abc").encode();
        let mut m = meter();

        let mut b = good.clone();
        b[0] = b'X';
        assert_eq!(Object::decode(&b, &mut m), Err(Bof1Error::BadMagic));

        let mut b = good.clone();
        b[2] = 2;
        assert_eq!(Object::decode(&b, &mut m), Err(Bof1Error::BadVersion(2)));

        let mut b = good.clone();
        b[3] = 0x10;
        assert_eq!(
            Object::decode(&b, &mut m),
            Err(Bof1Error::UnknownFlags(0x10))
        );

        let mut b = good.clone();
        b[3] = Flags::HAS_CONTEXT;
        assert_eq!(Object::decode(&b, &mut m), Err(Bof1Error::ContextNotOpen));

        let mut b = good.clone();
        b[4] = 1;
        assert_eq!(
            Object::decode(&b, &mut m),
            Err(Bof1Error::UnknownProfile(1))
        );

        let mut b = good.clone();
        b[5] = 9;
        assert_eq!(Object::decode(&b, &mut m), Err(Bof1Error::UnknownCodec(9)));

        let mut b = good.clone();
        b[6] = 1;
        assert_eq!(
            Object::decode(&b, &mut m),
            Err(Bof1Error::UnknownDictionary(1))
        );

        let mut b = good.clone();
        b.push(0);
        assert_eq!(Object::decode(&b, &mut m), Err(Bof1Error::TrailingBytes(1)));

        let b = &good[..good.len() - 1];
        assert_eq!(
            Object::decode(b, &mut m),
            Err(Bof1Error::Truncated("payload"))
        );

        for cut in 0..good.len() - 3 {
            assert!(
                Object::decode(&good[..cut], &mut m).is_err(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn sealed_object_must_hide_the_content_length() {
        let mut obj = Object::raw_public(b"abc");
        obj.header.flags = Flags::from_byte(Flags::SEALED).unwrap();
        let b = obj.encode();
        assert_eq!(
            Object::decode(&b, &mut meter()),
            Err(Bof1Error::SealedContentLen)
        );
        obj.header.content_len = 0;
        let parsed = Object::decode(&obj.encode(), &mut meter()).unwrap();
        assert!(parsed.header.is_sealed());
        assert_eq!(
            parsed.raw_public_content(),
            Err(Bof1Error::ContentMismatch),
            "a sealed object is never read as public content"
        );
    }

    #[test]
    fn a_huge_declared_payload_allocates_nothing() {
        let mut b = Object::raw_public(b"").encode();
        // Rewrite payload_len (the last byte, 0) as 2^62 with nine bytes.
        b.pop();
        varint::write(&mut b, 1 << 62);
        assert_eq!(
            Object::decode(&b, &mut meter()),
            Err(Bof1Error::Truncated("payload"))
        );
    }

    #[test]
    fn the_meter_bounds_the_payload_copy() {
        let b = Object::raw_public(&[7u8; 100]).encode();
        let mut small = Meter::new(99, 10);
        assert!(matches!(
            Object::decode(&b, &mut small),
            Err(Bof1Error::Budget(MeterError::Bytes { asked: 100, .. }))
        ));
    }

    #[test]
    fn tampered_payload_does_not_match_the_content() {
        let mut obj = Object::raw_public(b"abc");
        obj.payload = b"axc".to_vec();
        assert_eq!(obj.raw_public_content(), Err(Bof1Error::ContentMismatch));
    }

    #[test]
    fn base_and_live_fields_round_trip() {
        let mut obj = Object::raw_public(b"delta");
        obj.header.flags = Flags::from_byte(Flags::HAS_BASE | Flags::LIVE).unwrap();
        obj.header.base = Some([1u8; 32]);
        obj.header.prev_object = Some([2u8; 32]);
        let back = Object::decode(&obj.encode(), &mut meter()).unwrap();
        assert_eq!(back, obj);
    }

    #[test]
    fn testnet_codec_set() {
        assert!(codec_is_open_on_testnet(CODEC_RAW));
        assert!(!codec_is_registered(9));
        assert!(!codec_is_open_on_testnet(8));
        assert!(codec_is_registered(26));
        assert!(!codec_is_registered(27));
    }
}
