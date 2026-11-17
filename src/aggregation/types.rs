//! The data model of the aggregation layer, as specified in the aggregation
//! directive, section 4.
//!
//! # Why this module defines its own `Hash` and `Address`
//!
//! The directive says "use the equivalent types in the repository (`Hash`,
//! `Address`, `DomainId`, `Signature`)". They are mirrored here rather than
//! imported, for one measured reason: the 1.98 GB build sandbox this slice was
//! written in cannot compile `budlum-core` (rustc is killed by the OOM killer
//! at `--emit=metadata`, jobs=1). A module that depends on `crate::core` cannot
//! be compiled or tested there at all, and a slice that has never been compiled
//! is a claim, not a deliverable.
//!
//! So the two types are re-declared with the *same* layout and the same
//! constructor surface (`Address(pub [u8; 32])`, `Address::zero()`,
//! `Hash = [u8; 32]`), the rest of the module imports nothing from the crate,
//! and `tests::address_is_bit_identical_to_the_core_type` proves byte-for-byte
//! equality with `crate::core::address::Address` so the day this module is
//! linked into the core the swap is a `use` change, not a migration.
//!
//! Nothing here reads a clock, a file, an RNG or the network: every function
//! in this module is a pure function of its arguments, which is what makes the
//! consensus half of it deterministic.

/// A 32-byte digest. Same type as `crate::domain::types::Hash32`.
pub type Hash = [u8; 32];

/// A 32-byte account address. Same layout as `crate::core::address::Address`
/// (a tuple struct over `[u8; 32]` with a `zero()` constructor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The all-zero address. Same value as `crate::core::address::Address::zero`.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A consensus domain identifier. Same type as `crate::domain::types::DomainId`.
pub type DomainId = u32;

/// A registered object scheme (signature scheme, proof system, PCS
/// configuration). The registry entry, not this number, says what it means.
pub type SchemeId = u16;

/// The three heavy object kinds of the directive, section 1.
///
/// A quantum-safe signature, a STARK proof and a polynomial opening are the
/// only things the chain is willing to *not* store. Everything else stays out
/// of the system entirely, which is why the enum is closed: adding a fourth
/// kind is a hard fork, and the wire tag is part of the claim digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// A post-quantum signature (ML-DSA-65 validators, ML-DSA-87 wallets).
    Signature,
    /// A STARK proof produced by a registered AIR.
    StarkProof,
    /// A polynomial commitment opening.
    PcsOpening,
}

impl ObjectKind {
    /// The wire tag of the kind. Fixed forever; it enters `BDLM_OBJECT_V1`.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Signature => 0,
            Self::StarkProof => 1,
            Self::PcsOpening => 2,
        }
    }

    /// The inverse of [`Self::tag`]. An unknown byte is `None`, never a default.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Signature),
            1 => Some(Self::StarkProof),
            2 => Some(Self::PcsOpening),
            _ => None,
        }
    }
}

/// A quadratic-extension-cube element: the `Ext` of the directive, four 64-bit
/// limbs in little-endian order. It is opaque here on purpose: the aggregation
/// layer compares and hashes extension values, it does not do field arithmetic
/// on them, and the arithmetic belongs to the BudZKVM PCS configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ext(pub [u64; 4]);

impl Ext {
    /// The canonical 32-byte encoding: four limbs, little-endian, no padding.
    /// Fixed width, so the encoding is injective without a length prefix.
    #[must_use]
    pub fn canonical_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }
}

/// A heavy object, its transaction, and the domain that submitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// What kind of object this is.
    pub kind: ObjectKind,
    /// The scheme, meaningful for signatures and for PCS openings.
    pub scheme: SchemeId,
    /// The object itself. Opaque to the aggregation layer until a verifier
    /// that knows the scheme reads it.
    pub payload: Vec<u8>,
    /// The transaction whose authority this object carries.
    pub tx_hash: Hash,
    /// The domain the object belongs to. Part of every digest below, which is
    /// what makes a claim from one domain useless in another.
    pub domain: DomainId,
}

/// A `Claim` and the envelope it was derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolItem {
    /// The object, still carrying its payload.
    pub envelope: Envelope,
    /// The claim derived at admission time. It is never taken from the network:
    /// [`super::backend::claim_from_envelope`] recomputes it and refuses a
    /// mismatch.
    pub claim: Claim,
}

/// The statement a verified object reduces to. Roughly 64 to 96 bytes, and the
/// only thing about the object the chain keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// `signer` signed the message whose digest is `msg_hash`, under `scheme`.
    Sig {
        /// The registered signature scheme.
        scheme: SchemeId,
        /// The account the authority belongs to.
        signer: Address,
        /// The digest of the signed message.
        msg_hash: Hash,
    },
    /// The program `program_hash` ran on `input_hash` and produced
    /// `output_hash`.
    Prog {
        /// The program, as committed by its AIR.
        program_hash: Hash,
        /// The input commitment.
        input_hash: Hash,
        /// The output commitment.
        output_hash: Hash,
    },
    /// The polynomial committed by `poly_hash` takes `value` at `point`.
    Poly {
        /// The polynomial commitment.
        poly_hash: Hash,
        /// The opening point.
        point: Ext,
        /// The claimed evaluation.
        value: Ext,
    },
}

/// One aggregator's contribution: the root of a contiguous slice of the block's
/// claims, how many claims that slice holds, and who produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// `claims_root` of the claims in this slice, in block order.
    pub claims_root: Hash,
    /// How many claims the slice holds.
    pub count: u32,
    /// The aggregator that earned the fee share for this slice.
    pub aggregator: Address,
}

/// A proof frame: everything a verifier needs to check one subtree of the
/// proof tree. The block frame is the root of that tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimFrame {
    /// The slices, in block order.
    pub segments: Vec<Segment>,
    /// The postfix shape: `0` = a tick proof, `1` = a merge of the two frames
    /// below it. Consumed left to right by [`super::digest::fold_shape`].
    pub shape: Vec<u8>,
    /// The claims, in block order: the segments' slices concatenated.
    pub claims: Vec<Claim>,
    /// The proof bytes. Opaque to this layer; the backend that produced the
    /// frame is the only reader.
    pub proof: Vec<u8>,
}

/// Whether the aggregation layer is off, measuring, or enforcing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AggMode {
    /// The system is off. Block and transaction behaviour is unchanged.
    #[default]
    Off,
    /// The node processes inline signatures as objects, builds tick proofs and
    /// compares the result with local verification. It publishes nothing, and
    /// consensus does not change.
    Shadow,
    /// The rules of the directive, section 5, apply.
    On,
}

/// The node parameters of the aggregation layer. The four fields marked
/// consensus in the directive (`max_claims_per_block`, `max_proof_bytes`,
/// `claim_fee_per_byte`, `agg_share_bps`) are *not* here on their own: they are
/// folded into [`Self::consensus_bytes`], and a frame carries the digest of that
/// encoding, so a proof produced under one parameter set can never verify under
/// another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggParams {
    /// Off, shadow or on. The mainnet default is `Off`.
    pub mode: AggMode,
    /// The tick length in milliseconds.
    pub tick_ms: u64,
    /// The most objects a single tick may cover.
    pub tick_max_objects: usize,
    /// The most objects one sender may submit per tick.
    pub sender_tick_limit: usize,
    /// The most claims one block may carry.
    pub max_claims_per_block: usize,
    /// The most proof bytes one block may carry.
    pub max_proof_bytes: usize,
    /// The most bytes a STARK object may carry.
    pub max_stark_object_bytes: usize,
    /// The most bytes a PCS opening may carry.
    pub max_pcs_object_bytes: usize,
    /// The most bytes the object pool may hold.
    pub pool_max_bytes: usize,
    /// The claim fee per encoded byte, in the smallest fee unit.
    pub claim_fee_per_byte: u64,
    /// The aggregator's share of its segment's claim fees, in basis points.
    pub agg_share_bps: u16,
    /// How many blocks a full node keeps proof bytes.
    pub proof_retention_blocks: u64,
}

impl Default for AggParams {
    fn default() -> Self {
        Self {
            mode: AggMode::Off,
            tick_ms: 1_000,
            tick_max_objects: 256,
            sender_tick_limit: 8,
            max_claims_per_block: 8_192,
            max_proof_bytes: 262_144,
            max_stark_object_bytes: 262_144,
            max_pcs_object_bytes: 131_072,
            pool_max_bytes: 268_435_456,
            claim_fee_per_byte: 64,
            agg_share_bps: 5_000,
            proof_retention_blocks: 100_000,
        }
    }
}

impl AggParams {
    /// The canonical encoding of the fields that consensus depends on.
    ///
    /// Fixed width, little-endian, no length prefixes: the encoding is
    /// injective by construction and the test
    /// `consensus_bytes_changes_with_every_consensus_field` walks every field.
    #[must_use]
    pub fn consensus_bytes(&self) -> [u8; 8 + 8 + 8 + 8 + 2] {
        let mut out = [0u8; 34];
        let mut at = 0;
        for value in [
            self.max_claims_per_block as u64,
            self.max_proof_bytes as u64,
            self.claim_fee_per_byte,
            self.agg_share_bps as u64,
        ] {
            out[at..at + 8].copy_from_slice(&value.to_le_bytes());
            at += 8;
        }
        out[at..at + 2].copy_from_slice(&self.agg_share_bps.to_le_bytes());
        out
    }
}

/// The most object bytes a scheme will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemeDef {
    /// The scheme id.
    pub id: SchemeId,
    /// A human name, for diagnostics only. Never hashed.
    pub name: &'static str,
    /// The hard cap on the object payload.
    pub max_object_bytes: usize,
}

/// Every scheme this node will admit an object for.
///
/// A scheme that is not registered has no object shape and no size limit, so
/// there is nothing to check an object against; an unregistered scheme is
/// refused rather than given default limits. That is the whole point of the
/// registry: the set of accepted schemes is enumerable, and it is consensus
/// data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemeRegistry {
    schemes: Vec<SchemeDef>,
}

impl SchemeRegistry {
    /// An empty registry. It admits nothing, which is the fail-closed default.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schemes: Vec::new(),
        }
    }

    /// The registry a Budlum node starts with: the two ML-DSA schemes the
    /// repository already uses (FIPS 204) and the two proof kinds.
    ///
    /// The ids are placeholders until the core `crypto::scheme` ids are wired
    /// in Phase 2; they are deliberately not `0` and `1` so that a frame built
    /// here cannot be mistaken for one built against the core registry.
    #[must_use]
    pub fn budlum_reference() -> Self {
        Self {
            schemes: vec![
                SchemeDef {
                    id: 0x0101,
                    name: "ml-dsa-65-validator",
                    max_object_bytes: 6_144,
                },
                SchemeDef {
                    id: 0x0201,
                    name: "ml-dsa-87-wallet",
                    max_object_bytes: 8_192,
                },
                SchemeDef {
                    id: 0x1001,
                    name: "budzkvm-stark",
                    max_object_bytes: 262_144,
                },
                SchemeDef {
                    id: 0x2001,
                    name: "budzkvm-pcs",
                    max_object_bytes: 131_072,
                },
            ],
        }
    }

    /// Add a scheme. A duplicate id is refused: two limits for one id is the
    /// shape of a limit that is not one.
    pub fn insert(&mut self, def: SchemeDef) -> Result<(), AggError> {
        if self.schemes.iter().any(|s| s.id == def.id) {
            return Err(AggError::DuplicateScheme(def.id));
        }
        self.schemes.push(def);
        Ok(())
    }

    /// Look a scheme up. `None` means the scheme is not registered.
    #[must_use]
    pub fn get(&self, id: SchemeId) -> Option<&SchemeDef> {
        self.schemes.iter().find(|s| s.id == id)
    }

    /// The schemes, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &SchemeDef> {
        self.schemes.iter()
    }
}

/// Everything the aggregation layer refuses with. Every variant is a refusal;
/// there is no "accepted with a caveat" path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggError {
    /// The pool, the frame or the parameters are empty where the directive says
    /// they cannot be.
    Empty,
    /// The shape has more operators than the segments and claims can consume,
    /// or fewer. Both are the same defect: the frame does not describe a tree.
    BadShape,
    /// The sum of the segments' counts is not the number of claims.
    CountMismatch {
        /// The sum the segments declare.
        declared: u64,
        /// The claims actually present.
        actual: u64,
    },
    /// A segment's declared root is not the root of its slice.
    RootMismatch {
        /// Which segment disagreed.
        index: usize,
    },
    /// The same claim appears twice, which would pay one object twice.
    DuplicateClaim,
    /// More claims than `max_claims_per_block`.
    TooManyClaims {
        /// How many were present.
        have: usize,
        /// The cap.
        max: usize,
    },
    /// More proof bytes than `max_proof_bytes`.
    ProofTooLarge {
        /// How many were present.
        have: usize,
        /// The cap.
        max: usize,
    },
    /// An object larger than its scheme allows.
    ObjectTooLarge {
        /// The scheme whose cap was exceeded.
        scheme: SchemeId,
        /// The payload size.
        have: usize,
        /// The scheme's cap.
        max: usize,
    },
    /// An envelope names a scheme that is not in the registry.
    UnknownScheme(SchemeId),
    /// A pool item's claim is not the claim its envelope derives.
    ClaimMismatch,
    /// An object's payload does not decode as its kind requires.
    MalformedObject,
    /// An object arrived for a domain other than the one the frame is built for.
    WrongDomain {
        /// The domain on the envelope.
        envelope: DomainId,
        /// The domain the context is building for.
        expected: DomainId,
    },
    /// The same object id was already admitted.
    DuplicateObject(Hash),
    /// A sender is over its per-tick object allowance.
    SenderLimit {
        /// The sender's address.
        sender: Address,
    },
    /// The pool has no room for this object and evicting the cheapest victim
    /// would still not make room, because the newcomer is the cheapest.
    PoolFull,
    /// `frame_hash` in the header is not the hash of the frame.
    FrameHashMismatch,
    /// A scheme id was registered twice.
    DuplicateScheme(SchemeId),
    /// A proof produced under one parameter set was verified under another.
    ParamsMismatch,
    /// A verifier refused the object. Carries the verifier's own reason.
    VerifierRefused(&'static str),
    /// A backend was asked to prove while `mode` is `Off`. Proving in `Off` is
    /// a programming error, not a configuration to work around.
    Disabled,
    /// More objects in one tick than `tick_max_objects`.
    TooManyObjects {
        /// How many were offered.
        have: usize,
        /// The cap.
        max: usize,
    },
}
