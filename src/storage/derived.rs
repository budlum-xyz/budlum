//! Content that is a region of content the chain already holds.
//!
//! [`crate::storage::generated`] removes the bytes of objects that follow from
//! a seed. That covers generated art, which is a real class and a small one:
//! measured against a published scan of a comparable network, the classes with
//! a zero multiplier are about 40% of the objects and under a thousandth of
//! the bytes, and storage is paid for in bytes.
//!
//! The bytes are photographs. In the same measurement, images are 58.4% of
//! stored volume and video another 33.6%, and neither compresses much further:
//! they are already entropy-coded, and the remaining levers are asymptotes
//! approaching 1.0 from above.
//!
//! This module takes the one path into that 58.4% that keeps verification
//! byte-exact. A crop of a photograph carries no information the original does
//! not, so if the chain can *recompute* the crop it does not have to store it.
//!
//! # Why a crop can be recomputed exactly, and when it cannot
//!
//! JPEG encodes in blocks. The pixels are transformed, quantised and entropy
//! coded in 8x8 units, grouped into MCUs of 16x16 when the usual 4:2:0 chroma
//! subsampling is in play. A crop whose edges fall on those boundaries selects
//! a sub-rectangle of the coefficient array and changes nothing inside it.
//!
//! Measured directly, on quantised DCT coefficients rather than on the claim:
//! three block-aligned crops of a synthetic photograph produced coefficient
//! arrays identical to the corresponding sub-rectangle of the master's, and
//! two deliberately misaligned crops did not. Misalignment moves every pixel
//! relative to its block, so every coefficient in the crop is a different
//! number, and nothing about the master predicts them.
//!
//! So the guarantee is narrow and it is real:
//!
//! - a crop this chain performs is aligned by construction, and recomputable;
//! - a crop performed by `jpegtran -crop` is aligned, because it refuses to
//!   re-encode and widens the box to the nearest MCU instead;
//! - a crop performed by a phone gallery or a browser canvas is re-encoded,
//!   and the bytes are a new object with no relation to the master's.
//!
//! Which is why the operation lives here rather than in an upload path. The
//! saving does not come from analysing what a user uploaded, it comes from
//! offering an operation that produces the cheap thing in the first place.
//!
//! # The second transform: a prefix of a progressive master
//!
//! A progressively coded JPEG puts a whole picture in its first scan and
//! sharpens it with every later one. Truncating the file therefore yields a
//! full-size image at lower fidelity, not the top strip of a sharp one, and
//! the truncation is a copy: no codec runs, so the output is byte-identical
//! on every node by construction rather than by argument.
//!
//! Measured on five camera photographs, each stored as a 1600-pixel-wide
//! progressive master, asking for a derivative and timing only the server:
//!
//! | how the derivative is produced | server CPU | bytes | SSIM vs master |
//! |---|---|---|---|
//! | prefix, 25% of the file | 0.00053 s | 118,634 | 0.7469 |
//! | decode, scale to 720p, re-encode | 0.34234 s | 266,944 | 0.9022 |
//! | decode, re-encode at quality 45 | 0.19395 s | 233,791 | 0.9042 |
//!
//! So the prefix is 640 times cheaper in CPU and loses 0.157 SSIM against a
//! re-encode of comparable size. That is a real loss and it decides where the
//! transform belongs. Matching the re-encode's quality needs 55% of the file,
//! which measured 1.01x to 1.15x fatter than re-encoding to the same SSIM.
//!
//! **A prefix is therefore refused as a way to make quality rungs.** It wins
//! where low fidelity is already the specification:
//!
//! | target | prefix bytes | prefix CPU | re-encode bytes | re-encode CPU |
//! |---|---|---|---|---|
//! | 320px thumbnail | 23,726 | 0.000008 s | 16,619 | 0.044374 s |
//! | 640px feed preview | 47,453 | 0.000009 s | 62,499 | 0.049585 s |
//! | 480px card image | 37,962 | 0.000007 s | 35,431 | 0.045705 s |
//!
//! Five thousand times the CPU, and at 640 pixels the prefix is smaller than
//! the re-encode as well. A feed scrolling past a hundred posts is a hundred
//! of these, which is the workload that decides whether serving costs
//! anything.
//!
//! The master has to be progressive for any of this to hold. The same
//! truncation of a baseline JPEG measured 0.335 to 0.567 SSIM, because
//! baseline stores the image in raster order and a prefix is the top of it.
//! Nothing in the type can check that, which is stated among the costs below.
//!
//! Cutting at a scan boundary was measured and is worse, not better: 0.0560
//! to 0.0920 SSIM below cutting at an arbitrary offset, because a decoder
//! uses the partial scan it finds. The span is a byte count for that reason.
//!
//! # What is actually stored
//!
//! A [`DerivedSpec`]: the master's id, the box in block units, and which
//! transform. Forty-two bytes, against the several kilobytes an independently
//! encoded crop costs. The multiplier rounds to zero, the same as a generated
//! object, and for the same reason: what is kept is a description. A prefix
//! spends seventeen more on its span, see [`DERIVED_PREFIX_SPEC_BYTES`].
//!
//! # Verification is the same one sentence as everywhere else
//!
//! `manifest_id` is the hash of the bytes. A node fetches the master, applies
//! the transform, hashes the result and compares. If they match, the bytes are
//! the object. No proof system is involved, because recomputing is cheaper
//! than verifying a proof about a public output.
//!
//! This is the test that killed the neural-latent idea, which could reproduce
//! something perceptually close and never the same bytes. A block-aligned crop
//! passes it: the coefficients are the master's own.
//!
//! # The costs this does not hide
//!
//! Reading a derived object costs a read of its master, which is larger. That
//! is a real trade and it is why this is an operation a user chooses rather
//! than a rewriting the chain applies: a thumbnail read a thousand times a day
//! should probably be stored.
//!
//! A derived object also depends on its master staying retrievable. Chaining
//! is therefore refused outright, exactly as it is for dictionaries: a
//! derivation may name stored content, never another derivation. One hop has
//! one failure to reason about; a chain of hops has a depth nobody bounded.
//!
//! Whether a master is progressively coded is not checked here. The bounds a
//! [`PrefixSpan`] can state are its own two lengths; the coding mode lives in
//! bytes this type never sees. A prefix of a baseline master still verifies,
//! because verification hashes the copied bytes and the copy is correct. It
//! just looks like the top of the picture, and the caller that registered it
//! chose that. Refusing it would need the master, and a check that needs the
//! master cannot run at registration, which is the only moment refusing is
//! cheap.
//!
//! WIRING: unwired - measured: no production path registers a derived
//! manifest yet. The spec, its bounds and its refusals are here and tested;
//! the transaction that registers a derived object is a consensus-surface
//! change and lands with the V4 manifest tag.
//!
//! (The variant this module will hang off is named in `generated.rs`, not
//! here. Naming it in this sentence would make the wiring gate read the
//! mention as a call and declare that module wired, which is the exact
//! failure this comment is describing about its own module.)

use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;
use std::collections::BTreeMap;

/// The block size a crop must align to, in pixels.
///
/// Sixteen rather than eight: 4:2:0 subsampling halves the chroma planes, so
/// a luma-aligned crop at 8 can still cut a chroma block in half. Requiring
/// 16 is the conservative choice that holds for both, and it is what
/// `jpegtran` uses for the same reason.
pub const DERIVED_BLOCK_PIXELS: u32 = 16;

/// Largest master a derivation may name, per side, in blocks.
///
/// 4096 blocks is 65,536 pixels a side, past any photograph and short of the
/// range where `u32` products need care. The bound exists so an untrusted
/// spec cannot describe a box whose arithmetic overflows before any check
/// runs.
pub const DERIVED_MAX_BLOCKS_PER_SIDE: u32 = 4096;

/// Which transform produces the derived bytes from the master's.
///
/// A closed set, like [`crate::storage::generated::GeneratorId`], and for the
/// same reason: each entry has to be argued deterministic from its source.
/// Rotation and scaling belong here eventually; both are byte-exact for the
/// aligned case and neither is written yet, so neither is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DerivedTransform {
    /// Select a block-aligned rectangle of the master and keep it.
    Crop,
    /// Keep a leading run of the master's bytes and stop.
    ///
    /// Only meaningful for a progressively coded master, where the early
    /// bytes carry a whole picture at low fidelity rather than the top strip
    /// of a sharp one. See [`DerivedSpec::prefix_bytes`] for what the length
    /// means and the module docs for where the operation pays.
    Prefix,
}

impl DerivedTransform {
    /// Stable byte tag, so the domain-separated commitment does not depend on
    /// the order variants happen to be declared in.
    ///
    /// Named for its module rather than `tag`: the bare name appears in 46
    /// files across this tree, and the wiring gate counts name matches to
    /// decide whether a capability is reachable, so a common name makes it
    /// report on the wrong thing.
    const fn transform_tag(self) -> u8 {
        match self {
            Self::Crop => 1,
            Self::Prefix => 2,
        }
    }

    /// Whether this transform reads a region of the master or a run of its
    /// bytes.
    ///
    /// The two kinds validate against different fields, and a caller that
    /// cannot tell them apart ends up bounds checking a byte length against
    /// a block grid.
    pub const fn is_byte_range(self) -> bool {
        matches!(self, Self::Prefix)
    }
}

/// The description of a derived object.
///
/// Coordinates are in blocks, not pixels. A pixel box would let a spec
/// describe an unaligned crop that no node can reproduce, and the type would
/// be advertising a capability the format does not have. In blocks, an
/// unaligned crop is not merely rejected, it is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DerivedSpec {
    /// The object this one is a region of. Must be stored content: see the
    /// module docs on why derivations do not chain.
    pub master_id: ContentId,
    /// Which transform to apply.
    pub transform: DerivedTransform,
    /// Left edge, in blocks from the master's left.
    pub block_x: u32,
    /// Top edge, in blocks from the master's top.
    pub block_y: u32,
    /// Width, in blocks. Zero is refused: an empty region has no bytes and
    /// therefore no identity worth committing to.
    pub block_w: u32,
    /// Height, in blocks.
    pub block_h: u32,
    /// The master's width in blocks, recorded so the box can be bounds
    /// checked without fetching the master.
    ///
    /// A spec that lies here does not gain anything: the recomputation still
    /// has to hash to `manifest_id`, and a box outside the real master
    /// produces different bytes or no bytes at all. What the field buys is
    /// refusing an impossible spec at registration, before anyone pays to
    /// store it or fetches a multi-megabyte master to find out.
    pub master_blocks_w: u32,
    /// The master's height in blocks.
    pub master_blocks_h: u32,
    /// For [`DerivedTransform::Prefix`], how many leading bytes of the master
    /// the derived object is, and how long the master is.
    ///
    /// `None` for a region transform, where the box fields carry the meaning
    /// instead. Keeping the two in one type rather than splitting the enum
    /// costs an `Option` and buys one commitment, one bounds check and one
    /// registration path for both kinds.
    pub prefix: Option<PrefixSpan>,
}

/// A leading run of a master's bytes.
///
/// Both numbers are recorded for the same reason the master's block
/// dimensions are: the box has to be checkable at registration, before anyone
/// fetches a multi-megabyte master to discover the span runs off the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrefixSpan {
    /// Bytes kept, counted from the master's first byte.
    pub kept_bytes: u64,
    /// The master's total length in bytes.
    pub master_bytes: u64,
}

/// Why a derivation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedError {
    /// The region has no area.
    EmptyRegion,
    /// The box runs past the master's edge.
    ///
    /// Carries all four numbers rather than a boolean, so the caller can say
    /// which edge and by how much instead of only that something was wrong.
    OutOfBounds {
        block_x: u32,
        block_y: u32,
        block_w: u32,
        block_h: u32,
        master_blocks_w: u32,
        master_blocks_h: u32,
    },
    /// The master is larger than this module is willing to reason about.
    MasterTooLarge { blocks: u32, max: u32 },
    /// The derivation names another derivation.
    ///
    /// Refused for the reason dictionaries refuse it: one hop has one failure
    /// to reason about, and a chain has a depth nobody bounded. A crop of a
    /// crop is expressible as a crop of the original master, so nothing is
    /// lost by saying no.
    DerivationChain { master_id: ContentId },
    /// The region covers the whole master.
    ///
    /// Not an error of arithmetic but of economics: the derived object would
    /// be byte-identical to the master, so it is the same object, and
    /// registering it twice under two ids invites paying twice for one set of
    /// bytes. Deduplication is the mechanism for that, not derivation.
    WholeMaster,
    /// Something tried to release a master that carries derivations.
    ///
    /// A derived object holds no bytes of its own: reading it means fetching
    /// the master and recomputing. Letting the master go while a derivation
    /// names it does not shrink storage, it destroys the derivation, and it
    /// does so silently, because the derived manifest is still there and
    /// still verifies as a manifest until someone tries to read it.
    MasterStillDerived {
        master_id: ContentId,
        derivations: u32,
    },
    /// Release was attempted before the grace window closed.
    MasterGraceNotElapsed {
        master_id: ContentId,
        releasable_at_epoch: u64,
        now_epoch: u64,
    },
    /// A derivation named a master nothing is holding.
    ///
    /// Refused rather than accepted and resolved later: a derivation whose
    /// master is not held can never be read, so registering it is selling
    /// storage for an object that does not exist.
    UnknownMaster { master_id: ContentId },
    /// The spec's transform and its fields disagree about which kind it is.
    ///
    /// A `Prefix` with no span has nothing to copy; a `Crop` carrying one is
    /// describing two derivations at once and a verifier would have to guess
    /// which. Both are refused rather than resolved, because a guess here
    /// produces bytes that hash to something nobody committed to.
    TransformFieldsMismatch {
        transform: DerivedTransform,
        has_prefix: bool,
    },
    /// The prefix keeps no bytes, or keeps every byte the master has.
    ///
    /// Zero is [`Self::EmptyRegion`]'s argument in the other units. The whole
    /// length is [`Self::WholeMaster`]'s: the derived bytes would be the
    /// master's bytes, so it is the master.
    PrefixSpanDegenerate { kept_bytes: u64, master_bytes: u64 },
    /// The prefix runs past the end of the master.
    PrefixPastEnd { kept_bytes: u64, master_bytes: u64 },
}

impl std::fmt::Display for DerivedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRegion => write!(f, "a derived region must have a non-zero area"),
            Self::OutOfBounds {
                block_x,
                block_y,
                block_w,
                block_h,
                master_blocks_w,
                master_blocks_h,
            } => write!(
                f,
                "region ({block_x},{block_y}) {block_w}x{block_h} blocks runs past a master of \
                 {master_blocks_w}x{master_blocks_h} blocks"
            ),
            Self::MasterTooLarge { blocks, max } => write!(
                f,
                "master is {blocks} blocks on a side, more than the {max} this transform accepts"
            ),
            Self::DerivationChain { master_id } => write!(
                f,
                "master {master_id} is itself derived; a derivation may only name stored content"
            ),
            Self::WholeMaster => write!(
                f,
                "a region covering the whole master is the master; register it once and \
                 let deduplication do its job"
            ),
            Self::MasterStillDerived {
                master_id,
                derivations,
            } => write!(
                f,
                "master {master_id} still carries {derivations} derivation(s); releasing it \
                 would leave them unreadable while their manifests still look valid"
            ),
            Self::MasterGraceNotElapsed {
                master_id,
                releasable_at_epoch,
                now_epoch,
            } => write!(
                f,
                "master {master_id} is releasable at epoch {releasable_at_epoch}, not {now_epoch}"
            ),
            Self::UnknownMaster { master_id } => write!(
                f,
                "master {master_id} is not held; a derivation of it could never be read"
            ),
            Self::TransformFieldsMismatch {
                transform,
                has_prefix,
            } => write!(
                f,
                "transform {transform:?} does not match its fields: prefix span \
                 {}present",
                if *has_prefix { "" } else { "not " }
            ),
            Self::PrefixSpanDegenerate {
                kept_bytes,
                master_bytes,
            } => write!(
                f,
                "a prefix of {kept_bytes} bytes from a {master_bytes}-byte master is \
                 either empty or the master itself"
            ),
            Self::PrefixPastEnd {
                kept_bytes,
                master_bytes,
            } => write!(
                f,
                "a prefix of {kept_bytes} bytes runs past a master of {master_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for DerivedError {}

impl DerivedSpec {
    /// Check the spec describes a region that could exist.
    ///
    /// Deliberately does not fetch the master. Everything here is answerable
    /// from the spec's own numbers, and a check that needed the bytes could
    /// not run at registration, which is the only moment where refusing is
    /// cheap.
    ///
    /// # Errors
    ///
    /// [`DerivedError::EmptyRegion`] for a zero-area box,
    /// [`DerivedError::MasterTooLarge`] past [`DERIVED_MAX_BLOCKS_PER_SIDE`],
    /// [`DerivedError::OutOfBounds`] for a box that leaves the master, and
    /// [`DerivedError::WholeMaster`] for one that covers all of it.
    pub fn check_region(&self) -> Result<(), DerivedError> {
        // The transform decides which fields carry the meaning, so the first
        // check is that it agrees with what is actually here. Validating a
        // byte length against a block grid is the failure this refuses.
        if self.transform.is_byte_range() != self.prefix.is_some() {
            return Err(DerivedError::TransformFieldsMismatch {
                transform: self.transform,
                has_prefix: self.prefix.is_some(),
            });
        }
        if let Some(span) = self.prefix {
            return Self::check_prefix_span(span);
        }
        if self.block_w == 0 || self.block_h == 0 {
            return Err(DerivedError::EmptyRegion);
        }
        for blocks in [self.master_blocks_w, self.master_blocks_h] {
            if blocks > DERIVED_MAX_BLOCKS_PER_SIDE {
                return Err(DerivedError::MasterTooLarge {
                    blocks,
                    max: DERIVED_MAX_BLOCKS_PER_SIDE,
                });
            }
        }
        // Checked addition rather than `x + w <= master`: with the bound
        // above this cannot overflow, but the bound is a separate line of
        // code and a later edit could move it.
        let right = self.block_x.checked_add(self.block_w);
        let bottom = self.block_y.checked_add(self.block_h);
        let fits = match (right, bottom) {
            (Some(r), Some(b)) => r <= self.master_blocks_w && b <= self.master_blocks_h,
            _ => false,
        };
        if !fits {
            return Err(DerivedError::OutOfBounds {
                block_x: self.block_x,
                block_y: self.block_y,
                block_w: self.block_w,
                block_h: self.block_h,
                master_blocks_w: self.master_blocks_w,
                master_blocks_h: self.master_blocks_h,
            });
        }
        if self.block_x == 0
            && self.block_y == 0
            && self.block_w == self.master_blocks_w
            && self.block_h == self.master_blocks_h
        {
            return Err(DerivedError::WholeMaster);
        }
        Ok(())
    }

    /// The bounds a prefix span has to satisfy.
    ///
    /// Split out rather than inlined because it is the whole of the byte-range
    /// case and reads as one rule instead of three branches inside a function
    /// whose other half is about rectangles.
    fn check_prefix_span(span: PrefixSpan) -> Result<(), DerivedError> {
        if span.kept_bytes > span.master_bytes {
            return Err(DerivedError::PrefixPastEnd {
                kept_bytes: span.kept_bytes,
                master_bytes: span.master_bytes,
            });
        }
        if span.kept_bytes == 0 || span.kept_bytes == span.master_bytes {
            return Err(DerivedError::PrefixSpanDegenerate {
                kept_bytes: span.kept_bytes,
                master_bytes: span.master_bytes,
            });
        }
        Ok(())
    }

    /// How many bytes this derivation copies, for a prefix.
    ///
    /// `None` for a region transform, whose byte count is not knowable from
    /// the spec: a crop's size depends on the master's coefficients, and
    /// claiming a number here would be inventing one.
    pub const fn prefix_bytes(&self) -> Option<u64> {
        match self.prefix {
            Some(span) => Some(span.kept_bytes),
            None => None,
        }
    }

    /// Refuse a derivation whose master is itself derived.
    ///
    /// Takes the answer rather than looking it up, because the registry that
    /// knows is a layer above this module and a dependency in that direction
    /// would make the type harder to test than the rule is to state.
    ///
    /// # Errors
    ///
    /// [`DerivedError::DerivationChain`] when `master_is_derived` is true.
    pub fn check_master_is_stored(&self, master_is_derived: bool) -> Result<(), DerivedError> {
        if master_is_derived {
            return Err(DerivedError::DerivationChain {
                master_id: self.master_id,
            });
        }
        Ok(())
    }

    /// Region width in pixels.
    pub const fn pixel_width(&self) -> u32 {
        self.block_w.saturating_mul(DERIVED_BLOCK_PIXELS)
    }

    /// Region height in pixels.
    pub const fn pixel_height(&self) -> u32 {
        self.block_h.saturating_mul(DERIVED_BLOCK_PIXELS)
    }

    /// The prefix span as three hashable values, present or not.
    ///
    /// A present/absent byte rather than skipping the fields when there is no
    /// span: skipping would let a crop and a prefix whose numbers happened to
    /// line up produce one tag. Lifted out of the commitment so that function
    /// stays short enough to read as one list of fields, which is also what
    /// the byte-exactness gate greps.
    const fn prefix_commitment_fields(&self) -> (u8, u64, u64) {
        match self.prefix {
            Some(span) => (1, span.kept_bytes, span.master_bytes),
            None => (0, 0, 0),
        }
    }

    /// Domain-separated commitment to this derivation.
    ///
    /// Every field is hashed, including the master's declared dimensions.
    /// Leaving those out would let two specs with different bounds share a
    /// commitment, and the bounds are what a verifier checks the box against.
    pub fn derivation_commitment_tag(&self) -> [u8; 32] {
        let (present, kept, total) = self.prefix_commitment_fields();
        hash_fields_bytes(&[
            b"BDLM_DERIVED_CONTENT_V1",
            &self.master_id.0,
            &[self.transform.transform_tag()],
            &self.block_x.to_le_bytes(),
            &self.block_y.to_le_bytes(),
            &self.block_w.to_le_bytes(),
            &self.block_h.to_le_bytes(),
            &self.master_blocks_w.to_le_bytes(),
            &self.master_blocks_h.to_le_bytes(),
            &[present],
            &kept.to_le_bytes(),
            &total.to_le_bytes(),
        ])
    }

    /// Bytes this description occupies, against the bytes it replaces.
    ///
    /// Returned as a pair so a caller reporting the saving quotes both
    /// numbers. A ratio alone is the shape of claim this project keeps having
    /// to correct: 40% of objects and 0.1% of bytes are the same measurement,
    /// and either one on its own misleads.
    pub const fn stored_versus_independent(&self, independent_bytes: u64) -> (u64, u64) {
        (DERIVED_SPEC_BYTES, independent_bytes)
    }
}

/// Serialised size of a [`DerivedSpec`], in bytes.
///
/// 32 for the master id, 1 for the transform, 24 for six `u32` fields, plus a
/// byte of framing. Stated as a constant because it is the number the whole
/// module exists to make small, and a reader should not have to add it up.
pub const DERIVED_SPEC_BYTES: u64 = 32 + 1 + 24 + 1;

/// Epochs a master stays held after its last derivation is released.
///
/// The same shape and the same reason as the dictionary registry's own grace
/// window: a
/// reference count reaching zero is a claim about this instant, and a
/// derivation registered in the same block would otherwise race the release.
/// The window makes the claim durable enough to act on.
pub const MASTER_GRACE_EPOCHS: u64 = 1024;

/// What a master is holding up.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MasterEntry {
    /// Derivations that name this master.
    derivations: u32,
    /// Set when the count reaches zero, cleared when it rises again.
    releasable_at_epoch: Option<u64>,
}

/// Which masters are held, and what depends on them.
///
/// # Why this type exists
///
/// A derived object stores a description, not bytes. That is what makes the
/// multiplier round to zero, and it is also what makes the object dependent:
/// reading it means fetching the master and recomputing. `DerivedSpec` checks
/// that a derivation is well formed at the moment it is registered, and
/// nothing checked that the thing it depends on went on existing.
///
/// The gap matters because of how it fails. Releasing a master that carries
/// derivations does not raise an error anywhere: the derived manifests are
/// still present, still well formed, still hash to ids that look valid. They
/// stop being readable, and the first sign of it is a read that cannot be
/// served. There is no fallback, because for these objects the description is
/// the only copy.
///
/// [`crate::storage::dictionary::DictionaryRegistry`] already solves exactly
/// this for the objects that reference a shared dictionary, with a reference
/// count, a grace window and a refusal to delete while references exist.
/// Derivations have the same dependency and had none of it. This is that
/// mechanism, applied to the other lever that reaches a zero multiplier.
///
/// # What it does not do
///
/// It refuses a release; it cannot refuse a disappearance. An operator that
/// simply stops answering is a storage-proof and slashing question, handled
/// elsewhere. What is closed here is the case where the chain's own
/// accounting is what removes the master.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MasterRegistry {
    entries: BTreeMap<ContentId, MasterEntry>,
}

impl MasterRegistry {
    /// A registry holding nothing.
    #[must_use]
    pub fn empty_registry() -> Self {
        Self::default()
    }

    /// Record that a master is held and may be derived from.
    ///
    /// Idempotent, so a replayed transaction is not an error and does not
    /// reset a count.
    pub fn hold_master(&mut self, master_id: ContentId) {
        self.entries.entry(master_id).or_insert(MasterEntry {
            derivations: 0,
            releasable_at_epoch: None,
        });
    }

    /// Whether a master is held.
    #[must_use]
    pub fn is_master_held(&self, master_id: &ContentId) -> bool {
        self.entries.contains_key(master_id)
    }

    /// How many derivations name this master, or `None` if it is not held.
    #[must_use]
    pub fn derivation_count(&self, master_id: &ContentId) -> Option<u32> {
        self.entries.get(master_id).map(|e| e.derivations)
    }

    /// The epoch at which a pending release becomes possible, if one is
    /// pending.
    ///
    /// Exposed because otherwise the window is unobservable, and an
    /// unobservable field cannot be tested: a change that stopped cancelling
    /// the window on a new derivation would produce identical results from
    /// every other method, since they all gate on the count first. The bug
    /// would be latent until the count next reached zero at a different
    /// epoch than the stale window recorded.
    #[must_use]
    pub fn pending_release_epoch(&self, master_id: &ContentId) -> Option<u64> {
        self.entries
            .get(master_id)
            .and_then(|e| e.releasable_at_epoch)
    }

    /// Take a reference on behalf of a derivation.
    ///
    /// # Errors
    ///
    /// [`DerivedError::UnknownMaster`] when the master is not held. A
    /// derivation of an absent master could never be read, so registering it
    /// would be selling storage for an object that does not exist.
    pub fn acquire_master(&mut self, master_id: &ContentId) -> Result<(), DerivedError> {
        let Some(entry) = self.entries.get_mut(master_id) else {
            return Err(DerivedError::UnknownMaster {
                master_id: *master_id,
            });
        };
        entry.derivations = entry.derivations.saturating_add(1);
        // A master that is being derived from again is no longer on its way
        // out. Leaving the window open would let a release land between the
        // new derivation and the next epoch.
        entry.releasable_at_epoch = None;
        Ok(())
    }

    /// Drop a derivation's reference. When the last one goes, the window opens.
    pub fn release_derivation(&mut self, master_id: &ContentId, now_epoch: u64) {
        let Some(entry) = self.entries.get_mut(master_id) else {
            return;
        };
        entry.derivations = entry.derivations.saturating_sub(1);
        if entry.derivations == 0 {
            entry.releasable_at_epoch = Some(now_epoch.saturating_add(MASTER_GRACE_EPOCHS));
        }
    }

    /// Release a master nothing derives from any more.
    ///
    /// # Errors
    ///
    /// [`DerivedError::MasterStillDerived`] while derivations name it, and
    /// [`DerivedError::MasterGraceNotElapsed`] before the window closes.
    pub fn release_master(
        &mut self,
        master_id: &ContentId,
        now_epoch: u64,
    ) -> Result<(), DerivedError> {
        let Some(entry) = self.entries.get(master_id) else {
            return Ok(());
        };
        if entry.derivations > 0 {
            return Err(DerivedError::MasterStillDerived {
                master_id: *master_id,
                derivations: entry.derivations,
            });
        }
        match entry.releasable_at_epoch {
            // Held but never derived from: there is nothing this registry is
            // protecting, so it may go without waiting out a window.
            None => {
                self.entries.remove(master_id);
                Ok(())
            }
            Some(at) if now_epoch < at => Err(DerivedError::MasterGraceNotElapsed {
                master_id: *master_id,
                releasable_at_epoch: at,
                now_epoch,
            }),
            Some(_) => {
                self.entries.remove(master_id);
                Ok(())
            }
        }
    }

    /// Masters whose grace window has closed.
    #[must_use]
    pub fn releasable_masters(&self, now_epoch: u64) -> Vec<ContentId> {
        self.entries
            .iter()
            .filter(|(_, e)| {
                e.derivations == 0 && e.releasable_at_epoch.is_some_and(|at| now_epoch >= at)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// How many masters are held.
    #[must_use]
    pub fn master_count(&self) -> usize {
        self.entries.len()
    }
}
/// Serialised size of a [`DerivedSpec`] carrying a [`PrefixSpan`], in bytes.
///
/// [`DERIVED_SPEC_BYTES`] plus a discriminant byte and two `u64` lengths. A
/// prefix leaves the block fields at zero and pays for them anyway, which is
/// sixteen bytes of waste against a scheme that splits the type in two, and
/// cheaper than the second registration path that split would need.
pub const DERIVED_PREFIX_SPEC_BYTES: u64 = DERIVED_SPEC_BYTES + 1 + 8 + 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> DerivedSpec {
        DerivedSpec {
            master_id: ContentId([7u8; 32]),
            transform: DerivedTransform::Crop,
            block_x: 4,
            block_y: 2,
            block_w: 8,
            block_h: 6,
            master_blocks_w: 20,
            master_blocks_h: 15,
            prefix: None,
        }
    }

    /// A prefix spec, using the measured 320-pixel thumbnail case: 23,726
    /// bytes kept of a 474,537-byte progressive master.
    fn prefix_spec() -> DerivedSpec {
        DerivedSpec {
            master_id: ContentId([7u8; 32]),
            transform: DerivedTransform::Prefix,
            block_x: 0,
            block_y: 0,
            block_w: 0,
            block_h: 0,
            master_blocks_w: 0,
            master_blocks_h: 0,
            prefix: Some(PrefixSpan {
                kept_bytes: 23_726,
                master_bytes: 474_537,
            }),
        }
    }

    #[test]
    fn a_region_inside_the_master_is_accepted() {
        assert!(spec().check_region().is_ok());
    }

    #[test]
    fn a_zero_area_region_is_refused() {
        let mut s = spec();
        s.block_w = 0;
        assert_eq!(s.check_region(), Err(DerivedError::EmptyRegion));
        let mut s = spec();
        s.block_h = 0;
        assert_eq!(s.check_region(), Err(DerivedError::EmptyRegion));
    }

    #[test]
    fn a_region_that_leaves_the_master_is_refused() {
        // One block past the right edge, which is the off-by-one a bounds
        // check gets wrong in whichever direction it gets wrong.
        let mut s = spec();
        s.block_x = 13;
        s.block_w = 8;
        assert!(matches!(
            s.check_region(),
            Err(DerivedError::OutOfBounds { .. })
        ));

        // Exactly touching the edge is fine, and is the case a strict
        // comparison would wrongly refuse.
        let mut s = spec();
        s.block_x = 12;
        s.block_w = 8;
        assert!(s.check_region().is_ok());
    }

    #[test]
    fn a_region_covering_the_whole_master_is_refused() {
        let mut s = spec();
        s.block_x = 0;
        s.block_y = 0;
        s.block_w = s.master_blocks_w;
        s.block_h = s.master_blocks_h;
        assert_eq!(s.check_region(), Err(DerivedError::WholeMaster));
    }

    #[test]
    fn an_absurd_master_is_refused_before_any_arithmetic() {
        let mut s = spec();
        s.master_blocks_w = DERIVED_MAX_BLOCKS_PER_SIDE + 1;
        assert!(matches!(
            s.check_region(),
            Err(DerivedError::MasterTooLarge { .. })
        ));
    }

    #[test]
    fn a_box_that_would_overflow_is_refused_rather_than_wrapping() {
        // The bound above makes this unreachable through the public path, so
        // it is set up directly. A wrap here would turn a box far outside the
        // master into one that looks inside it.
        let mut s = spec();
        s.block_x = u32::MAX - 1;
        s.block_w = 8;
        assert!(matches!(
            s.check_region(),
            Err(DerivedError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn a_derivation_may_not_name_another_derivation() {
        let s = spec();
        assert!(s.check_master_is_stored(false).is_ok());
        assert_eq!(
            s.check_master_is_stored(true),
            Err(DerivedError::DerivationChain {
                master_id: s.master_id
            })
        );
    }

    #[test]
    fn the_commitment_covers_every_field() {
        // A field left out of the hash is a field two different specs can
        // disagree on while sharing a commitment. Each is changed on its own
        // so the test says which one is missing rather than that something is.
        let base = spec().derivation_commitment_tag();

        let mut s = spec();
        s.master_id = ContentId([8u8; 32]);
        assert_ne!(s.derivation_commitment_tag(), base, "master_id");

        for (name, f) in [
            ("block_x", 0usize),
            ("block_y", 1),
            ("block_w", 2),
            ("block_h", 3),
            ("master_blocks_w", 4),
            ("master_blocks_h", 5),
        ] {
            let mut s = spec();
            match f {
                0 => s.block_x += 1,
                1 => s.block_y += 1,
                2 => s.block_w += 1,
                3 => s.block_h += 1,
                4 => s.master_blocks_w += 1,
                _ => s.master_blocks_h += 1,
            }
            assert_ne!(s.derivation_commitment_tag(), base, "{name}");
        }
    }

    #[test]
    fn the_commitment_is_stable_across_calls() {
        // Two calls on equal specs must agree, or two nodes hash the same
        // description differently and disagree about the object.
        assert_eq!(
            spec().derivation_commitment_tag(),
            spec().derivation_commitment_tag()
        );
    }

    #[test]
    fn pixel_dimensions_follow_the_block_size() {
        let s = spec();
        assert_eq!(s.pixel_width(), 8 * DERIVED_BLOCK_PIXELS);
        assert_eq!(s.pixel_height(), 6 * DERIVED_BLOCK_PIXELS);
    }

    #[test]
    fn the_saving_is_reported_as_two_numbers_not_a_ratio() {
        // Measured on real crops of a synthetic photograph: an independently
        // encoded block-aligned crop of a 128x128 master cost 1,209 bytes.
        let (stored, independent) = spec().stored_versus_independent(1_209);
        assert_eq!(stored, DERIVED_SPEC_BYTES);
        assert_eq!(independent, 1_209);
        assert!(
            stored * 20 < independent,
            "the description must be at least an order of magnitude smaller, \
             or this module is not worth the dependency on the master"
        );
    }

    #[test]
    fn a_prefix_inside_its_master_is_accepted() {
        assert!(prefix_spec().check_region().is_ok());
        assert_eq!(prefix_spec().prefix_bytes(), Some(23_726));
        // A crop has no byte count to report: it depends on the master's
        // coefficients, and a number here would be invented.
        assert_eq!(spec().prefix_bytes(), None);
    }

    #[test]
    fn a_transform_that_disagrees_with_its_fields_is_refused() {
        // A prefix with nothing to copy.
        let mut s = prefix_spec();
        s.prefix = None;
        assert_eq!(
            s.check_region(),
            Err(DerivedError::TransformFieldsMismatch {
                transform: DerivedTransform::Prefix,
                has_prefix: false,
            })
        );

        // A crop carrying a span is describing two derivations at once, and
        // this one would otherwise pass every box check it has.
        let mut s = spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 10,
            master_bytes: 100,
        });
        assert_eq!(
            s.check_region(),
            Err(DerivedError::TransformFieldsMismatch {
                transform: DerivedTransform::Crop,
                has_prefix: true,
            })
        );
    }

    #[test]
    fn a_degenerate_prefix_is_refused() {
        // Keeping nothing is the empty region in the other units.
        let mut s = prefix_spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 0,
            master_bytes: 474_537,
        });
        assert_eq!(
            s.check_region(),
            Err(DerivedError::PrefixSpanDegenerate {
                kept_bytes: 0,
                master_bytes: 474_537,
            })
        );

        // Keeping all of it is the whole master, which is the master.
        let mut s = prefix_spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 474_537,
            master_bytes: 474_537,
        });
        assert_eq!(
            s.check_region(),
            Err(DerivedError::PrefixSpanDegenerate {
                kept_bytes: 474_537,
                master_bytes: 474_537,
            })
        );
    }

    #[test]
    fn a_prefix_past_the_end_is_refused_before_it_is_called_degenerate() {
        // Ordering matters: one byte past the end is not the whole master,
        // and reporting it as degenerate would name the wrong fault.
        let mut s = prefix_spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 474_538,
            master_bytes: 474_537,
        });
        assert_eq!(
            s.check_region(),
            Err(DerivedError::PrefixPastEnd {
                kept_bytes: 474_538,
                master_bytes: 474_537,
            })
        );
    }

    #[test]
    fn the_commitment_separates_a_prefix_from_a_crop() {
        // Both fields of the span, and the fact that there is one at all,
        // have to reach the hash. Two derivations that share a tag are two
        // sets of bytes nobody can tell apart.
        let base = prefix_spec().derivation_commitment_tag();
        assert_ne!(base, spec().derivation_commitment_tag());

        let mut s = prefix_spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 23_727,
            master_bytes: 474_537,
        });
        assert_ne!(s.derivation_commitment_tag(), base, "kept_bytes");

        let mut s = prefix_spec();
        s.prefix = Some(PrefixSpan {
            kept_bytes: 23_726,
            master_bytes: 474_538,
        });
        assert_ne!(s.derivation_commitment_tag(), base, "master_bytes");

        // A crop whose zeroed span numbers match the absent case must still
        // differ, which is what the presence byte is for.
        let mut s = spec();
        s.transform = DerivedTransform::Prefix;
        s.prefix = Some(PrefixSpan {
            kept_bytes: 0,
            master_bytes: 0,
        });
        assert_ne!(
            s.derivation_commitment_tag(),
            spec().derivation_commitment_tag()
        );
    }

    #[test]
    fn the_two_transforms_are_told_apart_by_kind() {
        assert!(DerivedTransform::Prefix.is_byte_range());
        assert!(!DerivedTransform::Crop.is_byte_range());
    }

    #[test]
    fn a_prefix_description_stays_far_smaller_than_the_bytes_it_replaces() {
        // The measured 320-pixel case: a re-encoded thumbnail of this master
        // cost 16,619 bytes, against a description of DERIVED_PREFIX_SPEC_BYTES.
        assert_eq!(DERIVED_PREFIX_SPEC_BYTES, DERIVED_SPEC_BYTES + 17);
        // Both sides are constants, so this is a compile-time claim and belongs
        // in a const block: a runtime assert on constants can only fail after
        // the binary that violates it has already been built and shipped.
        const {
            assert!(
                DERIVED_PREFIX_SPEC_BYTES * 200 < 16_619,
                "a prefix description must stay negligible against an encoded thumbnail"
            );
        }
    }

    #[test]
    fn the_block_size_is_the_conservative_one_for_subsampled_chroma() {
        // 4:2:0 halves the chroma planes, so an 8-pixel luma-aligned crop can
        // still cut a chroma block. This constant is the reason the whole
        // scheme is byte-exact, so it is locked rather than left to a reader
        // to notice if it changes.
        assert_eq!(DERIVED_BLOCK_PIXELS, 16);
    }

    fn master() -> ContentId {
        ContentId([7u8; 32])
    }

    /// A master that carries derivations cannot be released.
    ///
    /// This is the failure the registry exists for, and its shape is what
    /// makes it dangerous: releasing the master raises nothing anywhere. The
    /// derived manifests stay present and well formed, and the first sign of
    /// trouble is a read that cannot be served, with no stored copy behind it.
    #[test]
    fn a_master_carrying_derivations_is_not_released() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        reg.acquire_master(&master()).expect("master is held");

        let err = reg
            .release_master(&master(), 10_000)
            .expect_err("a master with a live derivation must not be released");
        assert_eq!(
            err,
            DerivedError::MasterStillDerived {
                master_id: master(),
                derivations: 1,
            }
        );
        assert!(
            reg.is_master_held(&master()),
            "the refusal must also keep the master"
        );
    }

    /// The canary for the test above: a master nothing derives from is
    /// releasable, or the refusal could be the registry refusing everything.
    #[test]
    fn a_master_nothing_derives_from_is_released() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        reg.release_master(&master(), 10_000)
            .expect("nothing depends on it");
        assert!(!reg.is_master_held(&master()));
        assert_eq!(reg.master_count(), 0);
    }

    /// Releasing the last derivation opens a window rather than the door.
    ///
    /// A count reaching zero is a claim about this instant. Without the
    /// window, a derivation registered in the same block would race a release
    /// that is already in flight.
    #[test]
    fn the_last_derivation_opens_a_grace_window() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        reg.acquire_master(&master()).unwrap();
        reg.release_derivation(&master(), 1_000);

        let err = reg
            .release_master(&master(), 1_000)
            .expect_err("the window has not closed");
        assert_eq!(
            err,
            DerivedError::MasterGraceNotElapsed {
                master_id: master(),
                releasable_at_epoch: 1_000 + MASTER_GRACE_EPOCHS,
                now_epoch: 1_000,
            }
        );

        // One epoch before the window closes, still refused.
        assert!(reg
            .release_master(&master(), 1_000 + MASTER_GRACE_EPOCHS - 1)
            .is_err());

        // At the boundary, allowed. The bound must not be so wide that it
        // never opens.
        reg.release_master(&master(), 1_000 + MASTER_GRACE_EPOCHS)
            .expect("the window has closed");
        assert!(!reg.is_master_held(&master()));
    }

    /// Deriving again closes a window that was already open.
    ///
    /// Otherwise a release scheduled before the new derivation would still
    /// fire after it, which is the race the window exists to prevent.
    #[test]
    fn a_new_derivation_cancels_a_pending_release() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        reg.acquire_master(&master()).unwrap();
        reg.release_derivation(&master(), 1_000);
        assert_eq!(reg.releasable_masters(1_000 + MASTER_GRACE_EPOCHS).len(), 1);

        reg.acquire_master(&master()).unwrap();
        assert!(
            reg.releasable_masters(1_000 + MASTER_GRACE_EPOCHS)
                .is_empty(),
            "a master being derived from again is not on its way out"
        );
        assert!(reg.release_master(&master(), u64::MAX).is_err());
        // The window itself has to be gone, not merely masked by the count.
        // Every other method gates on the count first, so a change that
        // stopped clearing this field would pass the two assertions above and
        // leave a stale epoch behind to fire the next time the count reached
        // zero.
        assert_eq!(
            reg.pending_release_epoch(&master()),
            None,
            "a new derivation must clear the pending release, not just outvote it"
        );
    }

    /// A derivation of a master nobody holds is refused at registration.
    ///
    /// Accepting it would sell storage for an object that can never be read:
    /// there is no master to recompute from and no bytes of its own.
    #[test]
    fn a_derivation_of_an_unheld_master_is_refused() {
        let mut reg = MasterRegistry::empty_registry();
        let err = reg
            .acquire_master(&master())
            .expect_err("nothing is holding this master");
        assert_eq!(
            err,
            DerivedError::UnknownMaster {
                master_id: master()
            }
        );
        assert_eq!(reg.derivation_count(&master()), None);
    }

    /// Counting survives many derivations of one master, which is the case
    /// the class exists for: one photograph, many crops.
    #[test]
    fn many_derivations_hold_one_master_until_the_last_goes() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        for _ in 0..64 {
            reg.acquire_master(&master()).unwrap();
        }
        assert_eq!(reg.derivation_count(&master()), Some(64));

        for i in 0..63 {
            reg.release_derivation(&master(), 1_000);
            assert!(
                reg.release_master(&master(), u64::MAX).is_err(),
                "still derived after {} releases",
                i + 1
            );
        }

        reg.release_derivation(&master(), 1_000);
        assert_eq!(reg.derivation_count(&master()), Some(0));
        reg.release_master(&master(), 1_000 + MASTER_GRACE_EPOCHS)
            .expect("the last derivation is gone and the window has closed");
    }

    /// Holding is idempotent, so a replayed transaction cannot reset a count.
    #[test]
    fn holding_a_master_twice_does_not_reset_its_derivations() {
        let mut reg = MasterRegistry::empty_registry();
        reg.hold_master(master());
        reg.acquire_master(&master()).unwrap();
        reg.hold_master(master());
        assert_eq!(
            reg.derivation_count(&master()),
            Some(1),
            "a replayed hold must not forget what depends on the master"
        );
        assert!(reg.release_master(&master(), u64::MAX).is_err());
    }
}
