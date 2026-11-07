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
//! Convenience: public BOF-1 container API consumed by upload/view pipelines, gateway, and fuzz targets.

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
    /// The live-stream segment bit is set; live streaming is closed at testnet launch.
    LiveNotOpen,
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
    /// Canonical BOF-1 text representation is malformed.
    TextFormat(&'static str),
    /// Decoded BOF-1 text failed the trailing object commitment check.
    CommitmentMismatch,
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

    /// Enforce testnet admission rules on a parsed object: live-stream bit1,
    /// shared-context bit3, and closed codecs are refused.
    ///
    /// # Errors
    ///
    /// Returns [`Bof1Error`] when a closed flag or codec is carried.
    pub const fn validate_testnet(&self) -> Result<(), Bof1Error> {
        if self.header.flags.has(Flags::LIVE) {
            return Err(Bof1Error::LiveNotOpen);
        }
        if self.header.flags.has(Flags::HAS_CONTEXT) {
            return Err(Bof1Error::ContextNotOpen);
        }
        if !codec_is_open_on_testnet(self.header.codec) {
            return Err(Bof1Error::UnknownCodec(self.header.codec as u64));
        }
        Ok(())
    }

    /// Render the canonical BOF-1 text representation (`BUD3-OBJECT 1` ...
    /// `end commitment=<64 hex>`). Source frames carry URL-safe unpadded base64
    /// slices of the canonical binary object; repair lines carry `derived`.
    ///
    /// # Errors
    ///
    /// Returns [`Bof1Error`] if the header profile cannot segment the object.
    pub fn encode_text(&self, repair_per_segment: u32) -> Result<String, Bof1Error> {
        use std::fmt::Write as _;
        let profile = self
            .header
            .profile()
            .ok_or(Bof1Error::UnknownProfile(u64::from(self.header.profile)))?;
        let bin = self.encode();
        let seg = super::segment::Segmentation::new(bin.len() as u64, &profile)
            .ok_or(Bof1Error::TextFormat("segmentation"))?;
        let commitment = super::segment::object_commitment(&bin, &profile)
            .ok_or(Bof1Error::TextFormat("commitment"))?;

        let mut out = String::from("BUD3-OBJECT 1\n");
        if self.header.flags.bits() == 0 {
            let _ = writeln!(
                out,
                "profile {} codec {} dictionary {}",
                self.header.profile, self.header.codec, self.header.dictionary
            );
        } else {
            let _ = writeln!(
                out,
                "profile {} codec {} dictionary {} flags {}",
                self.header.profile,
                self.header.codec,
                self.header.dictionary,
                self.header.flags.bits()
            );
        }
        if let Some(base) = &self.header.base {
            let _ = writeln!(out, "base {}", hex::encode(base));
        }
        if let Some(prev) = &self.header.prev_object {
            let _ = writeln!(out, "prev_object {}", hex::encode(prev));
        }
        let _ = writeln!(
            out,
            "content len={} digest={}",
            self.header.content_len,
            hex::encode(self.header.content_digest)
        );
        let _ = writeln!(out, "payload len={}", self.payload.len());

        let fps = u64::from(profile.fps.max(1));
        let sym_size = usize::from(profile.symbol_size);
        let mut frame_ordinal = 0u64;
        let mut current_second: Option<u64> = None;

        for seg_idx in 0..seg.count() {
            let range = seg
                .byte_range(seg_idx)
                .ok_or(Bof1Error::TextFormat("segment range"))?;
            let start = usize::try_from(range.start).map_err(|_| Bof1Error::TextFormat("range"))?;
            let end = usize::try_from(range.end).map_err(|_| Bof1Error::TextFormat("range"))?;
            let seg_bytes = bin
                .get(start..end)
                .ok_or(Bof1Error::TextFormat("segment slice"))?;
            let k_u64 = seg
                .source_symbols(seg_idx)
                .ok_or(Bof1Error::TextFormat("source symbols"))?;
            let k = u32::try_from(k_u64).map_err(|_| Bof1Error::TextFormat("k overflow"))?;

            for (esi_usize, chunk) in seg_bytes.chunks(sym_size).enumerate() {
                let sec = frame_ordinal / fps;
                if current_second != Some(sec) {
                    let _ = writeln!(out, "second {sec}");
                    current_second = Some(sec);
                }
                let encoded = base64url_encode(chunk);
                let _ = writeln!(out, " S {seg_idx} {esi_usize} {encoded}");
                frame_ordinal = frame_ordinal.saturating_add(1);
            }

            for r in 0..repair_per_segment {
                let sec = frame_ordinal / fps;
                if current_second != Some(sec) {
                    let _ = writeln!(out, "second {sec}");
                    current_second = Some(sec);
                }
                let esi = k.saturating_add(r);
                let _ = writeln!(out, " R {seg_idx} {esi} derived");
                frame_ordinal = frame_ordinal.saturating_add(1);
            }
        }

        let _ = writeln!(out, "end commitment={}", hex::encode(commitment.0));
        Ok(out)
    }

    /// Parse the canonical BOF-1 text representation back into an [`Object`],
    /// verifying header consistency, frame ordering, repair markers, and the
    /// trailing `end commitment=<64 hex>` digest. Any single-character mutation
    /// is refused.
    ///
    /// # Errors
    ///
    /// Returns [`Bof1Error`] on syntax, bounds, header, or commitment mismatch.
    pub fn decode_text(text: &str, meter: &mut Meter) -> Result<Self, Bof1Error> {
        if text.is_empty() || !text.ends_with('\n') {
            return Err(Bof1Error::TextFormat("missing trailing newline"));
        }
        let body = text
            .strip_suffix('\n')
            .ok_or(Bof1Error::TextFormat("newline"))?;
        let mut lines = body.split('\n');

        let magic_line = lines.next().ok_or(Bof1Error::TextFormat("missing header"))?;
        if magic_line != "BUD3-OBJECT 1" {
            return Err(Bof1Error::TextFormat("bad magic line"));
        }

        let prof_line = lines
            .next()
            .ok_or(Bof1Error::TextFormat("missing profile line"))?;
        let prof_tokens: Vec<&str> = prof_line.split(' ').collect();
        if prof_tokens.len() != 6 && prof_tokens.len() != 8 {
            return Err(Bof1Error::TextFormat("bad profile line"));
        }
        if prof_tokens.first().copied() != Some("profile")
            || prof_tokens.get(2).copied() != Some("codec")
            || prof_tokens.get(4).copied() != Some("dictionary")
        {
            return Err(Bof1Error::TextFormat("bad profile keywords"));
        }
        let profile_id = parse_strict_u16(
            prof_tokens
                .get(1)
                .copied()
                .ok_or(Bof1Error::TextFormat("profile"))?,
        )?;
        let profile = Profile::by_id(profile_id)
            .ok_or(Bof1Error::UnknownProfile(u64::from(profile_id)))?;
        let codec_id = parse_strict_u16(
            prof_tokens
                .get(3)
                .copied()
                .ok_or(Bof1Error::TextFormat("codec"))?,
        )?;
        let dict_id = parse_strict_u32(
            prof_tokens
                .get(5)
                .copied()
                .ok_or(Bof1Error::TextFormat("dictionary"))?,
        )?;
        let flags_byte = if prof_tokens.len() == 8 {
            if prof_tokens.get(6).copied() != Some("flags") {
                return Err(Bof1Error::TextFormat("bad flags keyword"));
            }
            let raw = parse_strict_u16(
                prof_tokens
                    .get(7)
                    .copied()
                    .ok_or(Bof1Error::TextFormat("flags"))?,
            )?;
            if raw == 0 || raw > u16::from(u8::MAX) {
                return Err(Bof1Error::TextFormat("non-canonical flags"));
            }
            raw as u8
        } else {
            0u8
        };
        let flags = Flags::from_byte(flags_byte)?;

        let mut next_line = lines
            .next()
            .ok_or(Bof1Error::TextFormat("missing content line"))?;
        let expected_base = if flags.has(Flags::HAS_BASE) {
            let hex_str = next_line
                .strip_prefix("base ")
                .ok_or(Bof1Error::TextFormat("missing base line"))?;
            let arr = decode_strict_lower_hex32(hex_str)?;
            next_line = lines
                .next()
                .ok_or(Bof1Error::TextFormat("missing line after base"))?;
            Some(arr)
        } else {
            None
        };
        let expected_prev = if flags.has(Flags::LIVE) {
            let hex_str = next_line
                .strip_prefix("prev_object ")
                .ok_or(Bof1Error::TextFormat("missing prev_object line"))?;
            let arr = decode_strict_lower_hex32(hex_str)?;
            next_line = lines
                .next()
                .ok_or(Bof1Error::TextFormat("missing line after prev_object"))?;
            Some(arr)
        } else {
            None
        };

        let content_rest = next_line
            .strip_prefix("content len=")
            .ok_or(Bof1Error::TextFormat("bad content line"))?;
        let (len_str, digest_hex) = content_rest
            .split_once(" digest=")
            .ok_or(Bof1Error::TextFormat("bad content digest"))?;
        let expected_content_len = parse_strict_u64(len_str)?;
        let expected_digest = decode_strict_lower_hex32(digest_hex)?;

        let payload_line = lines
            .next()
            .ok_or(Bof1Error::TextFormat("missing payload line"))?;
        let payload_len_str = payload_line
            .strip_prefix("payload len=")
            .ok_or(Bof1Error::TextFormat("bad payload line"))?;
        let expected_payload_len = parse_strict_u64(payload_len_str)?;

        let fps = u64::from(profile.fps.max(1));
        let sym_size = usize::from(profile.symbol_size);
        let mut raw_object = Vec::new();
        let mut current_second: Option<u64> = None;
        let mut frame_ordinal = 0u64;
        let mut cur_seg = 0u64;
        let mut next_source_esi = 0u32;
        let mut next_repair_esi: Option<u32> = None;
        let mut saw_end: Option<[u8; 32]> = None;

        for line in lines {
            if saw_end.is_some() {
                return Err(Bof1Error::TextFormat("lines after end"));
            }
            if let Some(commit_hex) = line.strip_prefix("end commitment=") {
                saw_end = Some(decode_strict_lower_hex32(commit_hex)?);
                continue;
            }
            if let Some(sec_str) = line.strip_prefix("second ") {
                let sec = parse_strict_u64(sec_str)?;
                let expected_sec = frame_ordinal / fps;
                if sec != expected_sec || current_second == Some(sec) {
                    return Err(Bof1Error::TextFormat("bad second grouping"));
                }
                current_second = Some(sec);
                continue;
            }
            let expected_sec = frame_ordinal / fps;
            if current_second != Some(expected_sec) {
                return Err(Bof1Error::TextFormat("frame outside second group"));
            }
            if let Some(s_rest) = line.strip_prefix(" S ") {
                let parts: Vec<&str> = s_rest.split(' ').collect();
                if parts.len() != 3 {
                    return Err(Bof1Error::TextFormat("bad S line"));
                }
                let seg_idx = parse_strict_u64(
                    parts
                        .first()
                        .copied()
                        .ok_or(Bof1Error::TextFormat("S seg"))?,
                )?;
                let esi = parse_strict_u32(
                    parts
                        .get(1)
                        .copied()
                        .ok_or(Bof1Error::TextFormat("S esi"))?,
                )?;
                let b64 = parts
                    .get(2)
                    .copied()
                    .ok_or(Bof1Error::TextFormat("S data"))?;
                if seg_idx == cur_seg + 1 && next_source_esi > 0 {
                    cur_seg = seg_idx;
                    next_source_esi = 0;
                    next_repair_esi = None;
                }
                if seg_idx != cur_seg || next_repair_esi.is_some() || esi != next_source_esi {
                    return Err(Bof1Error::TextFormat("S sequence order"));
                }
                let chunk = base64url_decode(b64)?;
                if chunk.is_empty() || chunk.len() > sym_size {
                    return Err(Bof1Error::TextFormat("S chunk size"));
                }
                meter.charge_bytes(chunk.len() as u64)?;
                raw_object.extend_from_slice(&chunk);
                next_source_esi = next_source_esi
                    .checked_add(1)
                    .ok_or(Bof1Error::TextFormat("esi overflow"))?;
                frame_ordinal = frame_ordinal.saturating_add(1);
            } else if let Some(r_rest) = line.strip_prefix(" R ") {
                let parts: Vec<&str> = r_rest.split(' ').collect();
                if parts.len() != 3 {
                    return Err(Bof1Error::TextFormat("bad R line"));
                }
                let seg_idx = parse_strict_u64(
                    parts
                        .first()
                        .copied()
                        .ok_or(Bof1Error::TextFormat("R seg"))?,
                )?;
                let esi = parse_strict_u32(
                    parts
                        .get(1)
                        .copied()
                        .ok_or(Bof1Error::TextFormat("R esi"))?,
                )?;
                if parts.get(2).copied() != Some("derived") {
                    return Err(Bof1Error::TextFormat("R marker must be derived"));
                }
                if seg_idx != cur_seg || next_source_esi == 0 {
                    return Err(Bof1Error::TextFormat("R segment mismatch"));
                }
                let expected_r = next_repair_esi.unwrap_or(next_source_esi);
                if esi != expected_r {
                    return Err(Bof1Error::TextFormat("R sequence order"));
                }
                next_repair_esi = Some(
                    esi.checked_add(1)
                        .ok_or(Bof1Error::TextFormat("R esi overflow"))?,
                );
                frame_ordinal = frame_ordinal.saturating_add(1);
            } else {
                return Err(Bof1Error::TextFormat("unknown line"));
            }
        }

        let expected_commitment =
            saw_end.ok_or(Bof1Error::TextFormat("missing end commitment"))?;
        let actual_commitment = super::segment::object_commitment(&raw_object, &profile)
            .ok_or(Bof1Error::CommitmentMismatch)?;
        if actual_commitment.0 != expected_commitment {
            return Err(Bof1Error::CommitmentMismatch);
        }

        let decoded = Self::decode(&raw_object, meter)?;
        if decoded.header.flags != flags
            || decoded.header.profile != profile_id
            || decoded.header.codec != codec_id
            || decoded.header.dictionary != dict_id
            || decoded.header.base != expected_base
            || decoded.header.prev_object != expected_prev
            || decoded.header.content_len != expected_content_len
            || decoded.header.content_digest != expected_digest
            || decoded.header.payload_len != expected_payload_len
        {
            return Err(Bof1Error::TextFormat("header mismatch with binary payload"));
        }
        Ok(decoded)
    }
}

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_char(six_bits: u8) -> char {
    B64URL_ALPHABET
        .get(usize::from(six_bits & 0x3f))
        .copied()
        .map_or('A', char::from)
}

fn b64url_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(4).div_ceil(3));
    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(b64url_char(b0 >> 2));
        out.push(b64url_char(((b0 & 0x03) << 4) | (b1 >> 4)));
        if chunk.len() > 1 {
            out.push(b64url_char(((b1 & 0x0f) << 2) | (b2 >> 6)));
        }
        if chunk.len() > 2 {
            out.push(b64url_char(b2 & 0x3f));
        }
    }
    out
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, Bof1Error> {
    let rem = s.len() % 4;
    if rem == 1 {
        return Err(Bof1Error::TextFormat("invalid base64url length"));
    }
    let mut out = Vec::with_capacity(s.len().saturating_mul(3) / 4);
    for quad in s.as_bytes().chunks(4) {
        let v0 = b64url_val(*quad.first().ok_or(Bof1Error::TextFormat("b64"))?)
            .ok_or(Bof1Error::TextFormat("bad base64url char"))?;
        let v1 = b64url_val(*quad.get(1).ok_or(Bof1Error::TextFormat("b64"))?)
            .ok_or(Bof1Error::TextFormat("bad base64url char"))?;
        out.push((v0 << 2) | (v1 >> 4));
        if let Some(&c2) = quad.get(2) {
            let v2 = b64url_val(c2).ok_or(Bof1Error::TextFormat("bad base64url char"))?;
            if quad.len() == 2 && (v1 & 0x0f) != 0 {
                return Err(Bof1Error::TextFormat("non-zero base64url tail bits"));
            }
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
            if let Some(&c3) = quad.get(3) {
                let v3 = b64url_val(c3).ok_or(Bof1Error::TextFormat("bad base64url char"))?;
                out.push(((v2 & 0x03) << 6) | v3);
            } else if (v2 & 0x03) != 0 {
                return Err(Bof1Error::TextFormat("non-zero base64url tail bits"));
            }
        } else if (v1 & 0x0f) != 0 {
            return Err(Bof1Error::TextFormat("non-zero base64url tail bits"));
        }
    }
    Ok(out)
}

fn parse_strict_u64(s: &str) -> Result<u64, Bof1Error> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
        return Err(Bof1Error::TextFormat("non-canonical integer"));
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Bof1Error::TextFormat("invalid integer"));
    }
    s.parse::<u64>()
        .map_err(|_| Bof1Error::TextFormat("integer overflow"))
}

fn parse_strict_u32(s: &str) -> Result<u32, Bof1Error> {
    let v = parse_strict_u64(s)?;
    u32::try_from(v).map_err(|_| Bof1Error::TextFormat("u32 overflow"))
}

fn parse_strict_u16(s: &str) -> Result<u16, Bof1Error> {
    let v = parse_strict_u64(s)?;
    u16::try_from(v).map_err(|_| Bof1Error::TextFormat("u16 overflow"))
}

fn decode_strict_lower_hex32(s: &str) -> Result<[u8; 32], Bof1Error> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Bof1Error::TextFormat("expected 64 lowercase hex chars"));
    }
    let bytes = hex::decode(s).map_err(|_| Bof1Error::TextFormat("hex"))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
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

    #[test]
    fn bud3_text_format_round_trips() {
        let content = b"canonical text representation round-trip".repeat(90);
        let obj = Object::raw_public(&content);
        let text = obj.encode_text(2).unwrap();
        assert!(text.starts_with("BUD3-OBJECT 1\nprofile 0 codec 0 dictionary 0\n"));
        assert!(text.contains("\nsecond 0\n S 0 0 "));
        assert!(text.contains(" derived\nend commitment="));

        let parsed = Object::decode_text(&text, &mut meter()).unwrap();
        assert_eq!(parsed.encode(), obj.encode());

        // Zero-byte content also enters a valid BOF-1 object and round-trips through text.
        let empty = Object::raw_public(b"");
        let empty_text = empty.encode_text(1).unwrap();
        assert_eq!(
            Object::decode_text(&empty_text, &mut meter())
                .unwrap()
                .encode(),
            empty.encode()
        );

        // Mutating a commitment character or symbol payload character is refused.
        let mut bad = text.into_bytes();
        let last_hex = bad.len() - 2;
        bad[last_hex] = if bad[last_hex] == b'0' { b'1' } else { b'0' };
        let bad_str = String::from_utf8(bad).unwrap();
        assert!(Object::decode_text(&bad_str, &mut meter()).is_err());
    }

    #[test]
    fn live_flag_refused_on_testnet() {
        let mut obj = Object::raw_public(b"segment");
        obj.header.flags = Flags::from_byte(Flags::LIVE).unwrap();
        obj.header.prev_object = Some([4u8; 32]);
        assert_eq!(obj.validate_testnet(), Err(Bof1Error::LiveNotOpen));
    }
}
