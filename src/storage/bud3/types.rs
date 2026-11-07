//! The shared vocabulary of section 6.2, in one place.
//!
//! The directive names a term, a code name and a definition for each of the
//! twenty fields a B.U.D. 3.0 reader has to agree on. Most of those names are
//! already the type that implements them: `ContentId` lives in
//! [`super::content_id`], `Profile` in [`super::limits`], `Symbol` in
//! [`super::fountain`]. This module is for the terms that are *not* a new
//! algorithm but a shape two packages would otherwise each invent:
//!
//! * [`Frame`] - a symbol plus the header that makes it readable on its own.
//! * [`QrVideo`] - the presentation of frames, which is not part of any identity.
//! * [`CustodyShare`] - one holder's ESIs of one segment. [`super::placement`]
//!   carries the spec of a share; this is the share as a holder stores it, with
//!   the root it can prove against.
//! * [`PlacementGroup`] - the holders of one segment and the depth `f`.
//! * [`RefCount`] - the reference counter, one to many owners and bound objects.
//! * [`AggregationVolume`] - the small-object container of section 6.12.
//! * [`Payload`], [`SourceSymbol`], [`RepairSymbol`] - the three names section
//!   6.2 defines by position rather than by structure.
//! * [`LogicalPath`], [`OpticalPath`] - G4 and G5 as values, so "the two paths
//!   agree" is a comparison of two values rather than a claim in a document.
//!
//! # Why these are here and not beside their first user
//!
//! Section 6.2 is the one place the directive defines a word, and packages
//! WP-18 to WP-22 each read it. A `Frame` declared in `qr.rs` would be a second
//! definition the moment `two_path.rs` needed one, and two definitions of a
//! frame is exactly how B.U.D. 2.0 ended up with three recipe models. The types
//! here are small and total: each one is a named shape over data another module
//! already produced, never a rule of its own.
//!
//! # Status: the vocabulary is declared, the door that uses it is not open
//!
//! Every type here is written for a caller that lands with a later package, and
//! saying so once is more honest than twenty notes saying it twenty times:
//!
//! * [`Frame`] and [`QrVideo`] are constructed by the optical path (section 6.4,
//!   Y9) and read by the video commitment (section 6.15), which is WP-19.
//! * [`CustodyShare`] and [`PlacementGroup`] are written by the placement step
//!   (Y13) and read by the audit draw (section 6.11), which is WP-20/WP-21.
//! * [`RefCount`] is moved by `BindNft` and `BurnReference` (section 6.8), which
//!   is WP-22.
//! * [`AggregationVolume`] is section 6.12's container and is opened by the same
//!   upload door, WP-21.
//!
//! Until those doors open, the tests in this file and `src/tests/bud3_types.rs`
//! are the callers: they build each value from the parts the pipeline really
//! produces, so the shape is checked against the encoder rather than against a
//! copy of itself.
//! Convenience: shared Section 6.2 B.U.D. 3.0 vocabulary consumed across WP-18..25 modules.

use serde::{Deserialize, Serialize};

use crate::core::hash::hash_fields_bytes;

pub use super::content_id::{ContentId, ContentIdKind, ContentKey};
pub use super::limits::{Profile, ProfileId};

/// Registered codec identifier in the BOF-1 object header (section 6.3.2).
pub type CodecId = u16;

/// Canonical 32-byte Merkle commitment over an object's segments (section 6.3.3).
pub type ObjectCommitment = [u8; 32];

/// Canonical B.U.D. 3.0 object header and coded payload (section 6.2 / 6.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    /// Content identifier of the decoded bytes.
    pub content_id: ContentId,
    /// Coding profile identifier (`0` for canonical `P0`).
    pub profile: ProfileId,
    /// Registered codec identifier (`0` for raw).
    pub codec: CodecId,
    /// Optional registered dictionary identifier (`0` when absent).
    pub dictionary_id: u32,
    /// Bit flags (`bit0` = sealed; `bit1` live and `bit3` context manifest closed on testnet).
    pub flags: u8,
    /// Coded payload bytes (`A0` output).
    pub payload: Payload,
}

/// One segment of an encoded object (section 6.3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// Zero-based segment index inside the object.
    pub index: u64,
    /// Number of source symbols `k` in this segment.
    pub k: u32,
    /// Byte length of each symbol in this segment.
    pub symbol_size: u16,
    /// Segment root over the segment's source symbols.
    pub root: [u8; 32],
}

/// One fountain symbol (`esi < k` source, `esi >= k` repair; section 6.2 / 6.3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    /// Zero-based segment index inside the object.
    pub segment: u64,
    /// Encoding Symbol Identifier (`0..k` source, `k..` repair).
    pub esi: u32,
    /// Symbol payload bytes.
    pub data: Vec<u8>,
}

/// Epoch placement table over an object's segments (section 6.2 / 6.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementTable {
    /// Epoch for which placement was derived.
    pub epoch: u64,
    /// Object commitment placed in this epoch.
    pub commitment: ObjectCommitment,
    /// Ordered placement groups, one per segment.
    pub groups: Vec<PlacementGroup>,
}

/// Compute the domain-separated leaf digest of one symbol's payload bytes.
#[must_use]
pub fn symbol_leaf(data: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_BUD3_SYMBOL_V1", &[0x00], data])
}

/// Fold an ordered `(esi, leaf)` list into a custody share's `symbol_root`.
#[must_use]
pub fn symbol_root(leaves: &[(u32, [u8; 32])]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for (esi, leaf) in leaves {
        acc = hash_fields_bytes(&[b"BDLM_BUD3_SYMBOLS_V1", &acc, &esi.to_le_bytes(), leaf]);
    }
    hash_fields_bytes(&[b"BDLM_BUD3_SYMBOLS_V1", &(leaves.len() as u64).to_le_bytes(), &acc])
}

/// Fold segment roots into the object's canonical 32-byte commitment.
#[must_use]
pub fn object_commitment(segment_roots: &[[u8; 32]]) -> ObjectCommitment {
    let mut acc = [0u8; 32];
    for root in segment_roots {
        acc = hash_fields_bytes(&[b"BDLM_BUD3_OBJECT_V1", &[0x01], &acc, root]);
    }
    hash_fields_bytes(&[
        b"BDLM_BUD3_OBJECT_V1",
        &[0x00],
        &(segment_roots.len() as u64).to_le_bytes(),
        &acc,
    ])
}

/// The A0 payload: the shortest complete representation of the content.
///
/// A newtype and not a bare `Vec<u8>` because the payload and the content are
/// the two things the codec register exists to keep apart, and a signature that
/// says `&[u8]` cannot say which one it was given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload(pub Vec<u8>);

impl Payload {
    /// The payload bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The payload length, which is the object header's `payload_len`.
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }

    /// An empty payload is still a payload: zero content codes to zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A source symbol: an ESI below `k`, a slice of the segment bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSymbol(pub Symbol);

/// A repair symbol: an ESI at or above `k`, derived from the source symbols.
///
/// The type is separate because section 6.3.2 rule 6 says repair symbols are
/// never written into an object. A function that takes a [`RepairSymbol`]
/// cannot be handed a source symbol by mistake, and one that takes a
/// [`SourceSymbol`] cannot be handed a derived value whose bytes are not part
/// of the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairSymbol(pub Symbol);

/// One optical frame: a header and the symbol it presents (section 6.2).
///
/// The header carries what a still frame must say on its own, because a camera
/// can start reading a video at any second: the object commitment, the segment
/// and the profile. The symbol follows. Nothing here is a pixel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// The object the frame belongs to.
    pub commitment: ObjectCommitment,
    /// The profile the frame is drawn at.
    pub profile: ProfileId,
    /// The symbol the frame presents.
    pub symbol: Symbol,
}

impl Frame {
    /// The frame for a symbol of a known object.
    #[must_use]
    pub fn of(commitment: ObjectCommitment, profile: ProfileId, symbol: Symbol) -> Self {
        Self {
            commitment,
            profile,
            symbol,
        }
    }

    /// The frame's payload, which is the symbol's bytes: the input of the
    /// video commitment (section 6.15) and of nothing else.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.symbol.data
    }

    /// Whether the frame is a source (below `k`) or a repair (at or above it).
    #[must_use]
    pub fn is_source(&self, k: u32) -> bool {
        self.symbol.esi < k
    }
}

/// The presentation of frames as a QR video (section 6.17).
///
/// A presentation and nothing else: section 6.15 rule 3 says the PNG, the BDLV
/// container and the H.264 stream never reach an identity. The type therefore
/// carries the frame rate and the frames, and no field for a raster, so an
/// identity cannot accidentally be computed over one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QrVideo {
    /// Frames per second, which is part of the video commitment.
    pub fps: u16,
    /// The frames in play order.
    pub frames: Vec<Frame>,
}

impl QrVideo {
    /// The seconds of video at `fps` a frame list occupies.
    ///
    /// Rounded up: a partial second is a second of video, and a reader that
    /// stopped at the last complete second would drop the tail.
    #[must_use]
    pub fn seconds(&self) -> u64 {
        if self.fps == 0 {
            return 0;
        }
        u64::try_from(self.frames.len())
            .unwrap_or(u64::MAX)
            .div_ceil(u64::from(self.fps))
    }
}

/// One holder's share of one segment: the ESIs it carries and the root it can
/// prove them against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyShare {
    /// The object the share belongs to.
    pub commitment: ObjectCommitment,
    /// Segment index in that object.
    pub segment: u64,
    /// The ESIs this holder carries, ascending and distinct.
    pub esi: Vec<u32>,
    /// The symbol root the ESIs fold to ([`super::custody::symbol_root`]).
    pub symbol_root: [u8; 32],
}

impl CustodyShare {
    /// How many symbols the share holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.esi.len()
    }

    /// A share with no ESI places no symbol and is refused by every caller.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.esi.is_empty()
    }

    /// Whether the ESI list is strictly ascending, which is what makes the
    /// symbol root reproducible from the share alone.
    #[must_use]
    pub fn esi_is_ordered(&self) -> bool {
        self.esi.windows(2).all(|w| w[0] < w[1])
    }
}

/// The holders of one segment and the durability depth `f` (section 6.9.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementGroup {
    /// Segment index in the object.
    pub segment: u64,
    /// Full validators that hold a share.
    pub n_full: u32,
    /// Symbols each Full holder carries.
    pub s_full: u32,
    /// Mobile validators that hold a share.
    pub n_mobile: u32,
    /// Symbols each Mobile holder carries.
    pub s_mobile: u32,
    /// Shares the segment may lose and still decode.
    pub f: u32,
    /// The holders, in rendezvous rank order.
    pub holder: Vec<[u8; 32]>,
}

impl PlacementGroup {
    /// Symbols the segment is spread over.
    #[must_use]
    pub fn symbols(&self) -> u64 {
        u64::from(self.n_full) * u64::from(self.s_full)
            + u64::from(self.n_mobile) * u64::from(self.s_mobile)
    }

    /// Whether the group carries `k + 2` symbols for a segment of `k` source
    /// symbols, which is section 6.13's single-surviving-validator floor.
    #[must_use]
    pub fn covers(&self, k: u32) -> bool {
        self.symbols() >= u64::from(k) + 2
    }
}

/// A reference counter: how many references and bound objects name an object.
///
/// Section 6.8: an object is deleted when its counter reaches zero, and the
/// two terms are counted apart because they are released by different
/// transactions (`BurnReference` and a dependent object's deletion).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RefCount {
    /// NFTs and other references naming the object.
    pub references: u32,
    /// Objects that are bound to this one (delta or derived content).
    pub bound: u32,
}

impl RefCount {
    /// The total, which zero means the object may be deleted.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.references.saturating_add(self.bound)
    }

    /// Whether the object is unreferenced and may be deleted.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.total() == 0
    }

    /// Take one reference. Saturates rather than wrapping: a counter that
    /// wrapped would delete a live object.
    pub fn add_reference(&mut self) {
        self.references = self.references.saturating_add(1);
    }

    /// Release one reference, refusing to go below zero.
    ///
    /// # Errors
    ///
    /// The word `references` when none is held: a release with no reference is
    /// a state corruption, not a no-op.
    pub fn release_reference(&mut self) -> Result<(), &'static str> {
        if self.references == 0 {
            return Err("references");
        }
        self.references -= 1;
        Ok(())
    }
}

/// The small-object container of section 6.12.
///
/// Small objects collect into one volume, the volume is coded as one segment,
/// and each member keeps a Merkle proof of its own bytes. The type carries the
/// volume's ceiling and its members; the coding path lands with WP-21.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationVolume {
    /// The default volume ceiling in bytes (4 MiB, section 6.12).
    pub capacity_bytes: u64,
    /// The members, in the order their bytes are laid out.
    pub members: Vec<ContentId>,
}

impl AggregationVolume {
    /// The default volume ceiling: 4 MiB (section 6.12).
    pub const DEFAULT_CAPACITY_BYTES: u64 = 4 * 1024 * 1024;

    /// An empty volume at the default ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capacity_bytes: Self::DEFAULT_CAPACITY_BYTES,
            members: Vec::new(),
        }
    }

    /// Whether the volume has no member.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Whether `extra` more bytes fit under the ceiling.
    #[must_use]
    pub fn admits(&self, used_bytes: u64, extra: u64) -> bool {
        used_bytes.saturating_add(extra) <= self.capacity_bytes
    }
}

impl Default for AggregationVolume {
    fn default() -> Self {
        Self::new()
    }
}

/// The logical path (G4): object to frames to content, with no pixel produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalPath {
    /// The object and its frames are the same values the encoder produced.
    Encoder,
}

/// The optical path (G5): object to QR images to a screen and a camera, and
/// back to frames.
///
/// The only difference from [`LogicalPath`] is the raster in the middle, which
/// is why section 6.15 rule 3 keeps it out of every identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpticalPath {
    /// The frames came back through a rasteriser and a reader.
    Raster,
}

/// Which of the two paths produced a value (G4 and G5, section 6.5).
///
/// The two-path gate (`two_path.rs`) compares values that carry this, so a
/// mismatch names the path that broke rather than a generic inequality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Path {
    /// G4: no raster.
    Logical(LogicalPath),
    /// G5: through a rasteriser and a reader.
    Optical(OpticalPath),
}

impl Path {
    /// Whether this path produces pixels, i.e. is the optical one.
    #[must_use]
    pub const fn is_optical(&self) -> bool {
        matches!(self, Self::Optical(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(esi: u32) -> Symbol {
        Symbol {
            segment: 0,
            esi,
            data: vec![u8::try_from(esi % 256).unwrap_or(0); 4],
        }
    }

    #[test]
    fn a_frame_is_a_header_and_a_symbol_and_nothing_else() {
        let commitment = [7u8; 32];
        let frame = Frame::of(commitment, 0, symbol(3));
        assert_eq!(frame.payload(), &[3u8; 4]);
        assert!(frame.is_source(4));
        assert!(!frame.is_source(3));
        // The frame's size is its fields: no raster, no header bytes beyond the
        // two named ones. A presentation byte would have to be a new field.
        assert_eq!(
            frame,
            Frame {
                commitment,
                profile: 0,
                symbol: symbol(3),
            }
        );
    }

    #[test]
    fn a_qr_video_counts_seconds_at_its_own_rate() {
        let frames: Vec<Frame> = (0..21)
            .map(|i| Frame::of([1u8; 32], 0, symbol(i)))
            .collect();
        let video = QrVideo { fps: 10, frames };
        assert_eq!(video.seconds(), 3, "a partial second is a second");
        assert_eq!(
            QrVideo {
                fps: 0,
                frames: Vec::new()
            }
            .seconds(),
            0,
            "a zero frame rate has no second to name"
        );
    }

    #[test]
    fn a_custody_share_is_ordered_and_never_empty_for_a_placed_segment() {
        let share = CustodyShare {
            commitment: [2u8; 32],
            segment: 1,
            esi: vec![0, 1, 2, 5],
            symbol_root: [9u8; 32],
        };
        assert_eq!(share.len(), 4);
        assert!(!share.is_empty());
        assert!(share.esi_is_ordered());
        let shuffled = CustodyShare {
            esi: vec![2, 1],
            ..share.clone()
        };
        assert!(!shuffled.esi_is_ordered(), "the root would not reproduce");
    }

    #[test]
    fn a_placement_group_covers_k_plus_two_or_it_does_not() {
        let group = PlacementGroup {
            segment: 0,
            n_full: 4,
            s_full: 96,
            n_mobile: 64,
            s_mobile: 12,
            f: 20,
            holder: vec![[0u8; 32]; 68],
        };
        assert_eq!(group.symbols(), 4 * 96 + 64 * 12);
        assert!(group.covers(400));
        assert!(!group.covers(1152));
    }

    #[test]
    fn a_ref_counter_reaches_zero_only_when_both_terms_do() {
        let mut count = RefCount::default();
        assert!(count.is_zero());
        count.add_reference();
        assert_eq!(count.total(), 1);
        assert!(!count.is_zero());
        // A bound object keeps it alive after the reference is released.
        count.bound = 1;
        assert_eq!(count.release_reference(), Ok(()));
        assert_eq!(count.total(), 1, "the bound object still names it");
        count.bound = 0;
        assert!(count.is_zero());
        assert_eq!(
            count.release_reference(),
            Err("references"),
            "a release with nothing held is corruption, not a no-op"
        );
    }

    #[test]
    fn a_volume_admits_under_its_ceiling_and_not_at_one_byte_over() {
        let volume = AggregationVolume::new();
        assert_eq!(volume.capacity_bytes, 4 * 1024 * 1024);
        assert!(volume.admits(4 * 1024 * 1024 - 1, 1));
        assert!(!volume.admits(4 * 1024 * 1024, 1));
        // A sum that would overflow saturates above the ceiling instead of
        // wrapping back under it, so a hostile length cannot slip in.
        assert!(!volume.admits(u64::MAX, 1));
    }

    #[test]
    fn only_one_path_produces_pixels() {
        assert!(!Path::Logical(LogicalPath::Encoder).is_optical());
        assert!(Path::Optical(OpticalPath::Raster).is_optical());
    }
}
