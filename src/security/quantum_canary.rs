//! Quantum canary: puzzles whose solution proves a cryptographic break.
//!
//! Genesis fixes a set of puzzles. Each one is built from a label so that
//! nobody holds its solution: a curve point with no known discrete logarithm,
//! a lattice or hash-based public key with no secret key, a hash whose
//! collision nobody knows. Whoever solves one proves the underlying
//! assumption is gone, and the chain reacts in the block that accepts the
//! proof (INV-09).
//!
//! # Claim protocol
//!
//! 1. `CanaryCommit` publishes `H(canary, proof, claimer)`.
//! 2. A reveal with a commitment aged at least [`CANARY_REVEAL_DELAY`] and
//!    at most [`CANARY_REVEAL_WINDOW`] blocks may receive claim credit.
//! 3. Any valid proof raises the alarm immediately, even if the commit book
//!    is full or the publisher has no eligible commitment. A proof copied from
//!    the mempool cannot earn claim credit without an earlier commitment.
//! 4. If an uncredited proof raised the alarm first, only a commitment that
//!    was already mature when the proof appeared on chain may claim it later;
//!    the first eligible reveal wins. Publishing early can sacrifice credit.
//!
//! This module holds the puzzles, the proof checks, the claim book and the
//! alarm state machine. The transaction types that carry commit and reveal
//! are wired separately.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;

/// Blocks a commit must age before its reveal counts.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const CANARY_REVEAL_DELAY: u64 = 100;
/// Blocks after which an unrevealed commit expires.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const CANARY_REVEAL_WINDOW: u64 = 10_000;
/// Commits the book holds at once.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const MAX_PENDING_COMMITS: usize = 4096;
/// Commits one claimer may hold at once. A flood from one address cannot push
/// an honest commit out of the book.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const MAX_PENDING_PER_CLAIMER: usize = 16;
/// Longest message of a collision proof.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const MAX_COLLISION_MESSAGE_LEN: usize = 64 * 1024;
/// Largest proof a `CanaryReveal` carries: two collision messages and their
/// length prefixes, the largest proof of any puzzle.
pub const MAX_CANARY_PROOF_BYTES: usize = 2 * MAX_COLLISION_MESSAGE_LEN + 8;
/// Reward for the first valid claim, in atoms. Zero until governance sets it.
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub const QUANTUM_CANARY_BOUNTY_ATOMS: u64 = 0;

const GENESIS_LABEL: &[u8] = b"BDLM_QUANTUM_CANARY_V1";
const COMMIT_TAG: &[u8] = b"BDLM_CANARY_COMMIT_V1";
const SET_TAG: &[u8] = b"BDLM_CANARY_SET_V1";
const BLS_G1_DST: &[u8] = b"BDLM_QUANTUM_CANARY_V1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
const SECP256K1_DST: &[u8] = b"BDLM_QUANTUM_CANARY_V1_SECP256K1_XMD:SHA-256_SSWU_RO_";
const P256_DST: &[u8] = b"BDLM_QUANTUM_CANARY_V1_P256_XMD:SHA-256_SSWU_RO_";

/// The puzzles of the canary set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanaryId {
    /// Discrete logarithm on P-192.
    Ecc192,
    /// Discrete logarithm on P-224.
    Ecc224,
    /// Discrete logarithm on secp256k1.
    EccK1,
    /// Discrete logarithm on P-256.
    EccR1,
    /// Discrete logarithm on ristretto255.
    Ecc25519,
    /// Discrete logarithm on BLS12-381 G1.
    BlsG1,
    /// A valid ML-DSA-65 signature under a key nobody holds.
    Lat65,
    /// A valid ML-DSA-87 signature under a key nobody holds.
    Lat87,
    /// A valid SLH-DSA-SHAKE-256s signature under a key nobody holds.
    Slh256s,
    /// A SHA3-256 collision.
    HashSha3,
    /// A SHA-256 collision.
    HashSha256,
    /// A Keccak-256 collision.
    HashKeccak,
}

/// How far the chain reacts to a solved canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlarmLevel {
    /// No classical curve has fallen.
    Clear,
    /// Kiragi: a 192-bit curve fell. Profiles warn; TEE shortcuts close.
    Watch,
    /// Don: a 224-bit curve fell. Classical-backed domains take no new messages.
    Restrict,
    /// Zemheri: a 256-bit curve fell. Classical-backed domains are isolated and
    /// the BLS half drops out of finality.
    Isolate,
}

/// Breaks that are not a curve falling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlarmKind {
    /// The ML-DSA family is broken (Kafes).
    LatticeBreak,
    /// The SLH-DSA family is broken (Hash-Imza).
    HashSigBreak,
    /// A hash function used by the chain collides (Hash).
    HashBreak,
}

/// What a solved canary changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub enum CanaryEffect {
    /// Raises the curve alarm level to at least this.
    Level(AlarmLevel),
    /// Adds this kind of break.
    Kind(AlarmKind),
}

impl CanaryId {
    /// Every puzzle, in the order genesis lists them.
    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub const ALL: [Self; 12] = [
        Self::Ecc192,
        Self::Ecc224,
        Self::EccK1,
        Self::EccR1,
        Self::Ecc25519,
        Self::BlsG1,
        Self::Lat65,
        Self::Lat87,
        Self::Slh256s,
        Self::HashSha3,
        Self::HashSha256,
        Self::HashKeccak,
    ];

    /// The wire code of the puzzle: its position in [`Self::ALL`], used by the
    /// transaction encoding and the state serialization.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ecc192 => 0,
            Self::Ecc224 => 1,
            Self::EccK1 => 2,
            Self::EccR1 => 3,
            Self::Ecc25519 => 4,
            Self::BlsG1 => 5,
            Self::Lat65 => 6,
            Self::Lat87 => 7,
            Self::Slh256s => 8,
            Self::HashSha3 => 9,
            Self::HashSha256 => 10,
            Self::HashKeccak => 11,
        }
    }

    /// The puzzle of a wire code, `None` for a code no puzzle has.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// The canonical name used in hashes and in the genesis record.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ecc192 => "C-ECC-192",
            Self::Ecc224 => "C-ECC-224",
            Self::EccK1 => "C-ECC-K1",
            Self::EccR1 => "C-ECC-R1",
            Self::Ecc25519 => "C-ECC-25519",
            Self::BlsG1 => "C-BLS-G1",
            Self::Lat65 => "C-LAT-65",
            Self::Lat87 => "C-LAT-87",
            Self::Slh256s => "C-SLH-256S",
            Self::HashSha3 => "C-H-SHA3",
            Self::HashSha256 => "C-H-SHA256",
            Self::HashKeccak => "C-H-KECCAK",
        }
    }

    /// The effect of a valid proof (section 6.4).
    #[must_use]
    pub const fn effect(self) -> CanaryEffect {
        match self {
            Self::Ecc192 => CanaryEffect::Level(AlarmLevel::Watch),
            Self::Ecc224 => CanaryEffect::Level(AlarmLevel::Restrict),
            Self::EccK1 | Self::EccR1 | Self::Ecc25519 | Self::BlsG1 => {
                CanaryEffect::Level(AlarmLevel::Isolate)
            }
            Self::Lat65 | Self::Lat87 => CanaryEffect::Kind(AlarmKind::LatticeBreak),
            Self::Slh256s => CanaryEffect::Kind(AlarmKind::HashSigBreak),
            Self::HashSha3 | Self::HashSha256 | Self::HashKeccak => {
                CanaryEffect::Kind(AlarmKind::HashBreak)
            }
        }
    }

    /// The puzzle: a compressed point, a public key, or empty for a collision
    /// puzzle (the hash function is the puzzle).
    #[must_use]
    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub fn puzzle(self) -> Vec<u8> {
        match self {
            Self::Ecc192 => weierstrass::try_and_increment::<p192::NistP192>(self),
            Self::Ecc224 => weierstrass::try_and_increment::<p224::NistP224>(self),
            Self::EccK1 => weierstrass::hash_to_curve_k1(),
            Self::EccR1 => weierstrass::hash_to_curve_r1(),
            Self::Ecc25519 => ristretto_puzzle(),
            Self::BlsG1 => bls_puzzle(),
            Self::Lat65 => xof_key(self, crate::crypto::scheme::SchemeId::ML_DSA_65),
            Self::Lat87 => xof_key(self, crate::crypto::scheme::SchemeId::ML_DSA_87),
            Self::Slh256s => xof_key(self, crate::crypto::scheme::SchemeId::SLH_DSA_SHAKE_256S),
            Self::HashSha3 | Self::HashSha256 | Self::HashKeccak => Vec::new(),
        }
    }

    /// Whether `proof` solves this puzzle.
    ///
    /// Proof encodings: a curve puzzle takes the scalar `d` with `d * G = P`
    /// (big endian, the field size of the curve; little endian for
    /// ristretto255); a signature puzzle takes `u16 message length || message
    /// || signature`; a hash puzzle takes `u32 length || m1 || u32 length ||
    /// m2`.
    #[must_use]
    pub fn verify(self, proof: &[u8]) -> bool {
        match self {
            Self::Ecc192 => weierstrass::check::<p192::NistP192>(&self.puzzle(), proof),
            Self::Ecc224 => weierstrass::check::<p224::NistP224>(&self.puzzle(), proof),
            Self::EccK1 => weierstrass::check::<k256::Secp256k1>(&self.puzzle(), proof),
            Self::EccR1 => weierstrass::check::<p256::NistP256>(&self.puzzle(), proof),
            Self::Ecc25519 => ristretto_check(&self.puzzle(), proof),
            Self::BlsG1 => bls_check(&self.puzzle(), proof),
            Self::Lat65 => signature_check(self, crate::crypto::scheme::SchemeId::ML_DSA_65, proof),
            Self::Lat87 => signature_check(self, crate::crypto::scheme::SchemeId::ML_DSA_87, proof),
            Self::Slh256s => signature_check(
                self,
                crate::crypto::scheme::SchemeId::SLH_DSA_SHAKE_256S,
                proof,
            ),
            Self::HashSha3 => collision_check(proof, |m| Sha3_256::digest(m).to_vec()),
            Self::HashSha256 => collision_check(proof, |m| sha2::Sha256::digest(m).to_vec()),
            Self::HashKeccak => collision_check(proof, |m| sha3::Keccak256::digest(m).to_vec()),
        }
    }
}

/// The SHAKE256 label of a puzzle: `BDLM_QUANTUM_CANARY_V1 || id`.
fn label(id: CanaryId) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(GENESIS_LABEL.len() as u64).to_le_bytes());
    out.extend_from_slice(GENESIS_LABEL);
    out.extend_from_slice(&(id.name().len() as u64).to_le_bytes());
    out.extend_from_slice(id.name().as_bytes());
    out
}

fn xof_key(id: CanaryId, scheme: crate::crypto::scheme::SchemeId) -> Vec<u8> {
    use shake::{ExtendableOutput, Update, XofReader};
    let len = crate::crypto::pq::public_key_len(scheme).unwrap_or(0);
    let mut hasher = shake::Shake256::default();
    // The label is variable-length, so its length goes first: concatenation
    // without lengths is not injective across the fields that follow.
    let lbl = label(id);
    hasher.update(&(lbl.len() as u64).to_le_bytes());
    hasher.update(&lbl);
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; len];
    reader.read(&mut key);
    key
}

fn signature_check(id: CanaryId, scheme: crate::crypto::scheme::SchemeId, proof: &[u8]) -> bool {
    let Some((len_bytes, rest)) = proof.split_first_chunk::<2>() else {
        return false;
    };
    let message_len = usize::from(u16::from_be_bytes(*len_bytes));
    if rest.len() < message_len {
        return false;
    }
    let (message, signature) = rest.split_at(message_len);
    // The canary check ignores the chain's scheme registry on purpose: a
    // proof must keep working after the family it breaks is deprecated.
    crate::crypto::pq::verify(
        scheme,
        &id.puzzle(),
        message,
        crate::crypto::ctx::CANARY_V1,
        signature,
    )
    .is_ok()
}

fn collision_check(proof: &[u8], digest: impl Fn(&[u8]) -> Vec<u8>) -> bool {
    fn take(input: &[u8]) -> Option<(&[u8], &[u8])> {
        let (len, rest) = input.split_first_chunk::<4>()?;
        let len = u32::from_be_bytes(*len) as usize;
        if len > MAX_COLLISION_MESSAGE_LEN || rest.len() < len {
            return None;
        }
        Some(rest.split_at(len))
    }
    let Some((m1, rest)) = take(proof) else {
        return false;
    };
    let Some((m2, rest)) = take(rest) else {
        return false;
    };
    rest.is_empty() && m1 != m2 && digest(m1) == digest(m2)
}

mod weierstrass {
    use super::{label, CanaryId, SECP256K1_DST, P256_DST};
    use hash2curve::ExpandMsgXmd;
    use k256::elliptic_curve::array::typenum::Unsigned;
    use k256::elliptic_curve::group::Group;
    use k256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
    use k256::elliptic_curve::{CurveArithmetic, Field, FieldBytes, FieldBytesSize, PrimeField};
    use sha3::{Digest, Sha3_256};

    type Encoded<C> = k256::elliptic_curve::sec1::Sec1Point<C>;

    fn decode<C>(bytes: &[u8]) -> Option<C::AffinePoint>
    where
        C: CurveArithmetic,
        C::AffinePoint: FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let encoded = Encoded::<C>::from_bytes(bytes).ok()?;
        Option::from(C::AffinePoint::from_sec1_point(&encoded))
    }

    /// Try-and-increment (no RFC 9380 suite exists for P-192 and P-224):
    /// `x = SHA3-256(label || counter)` cut to the field size, even `y`, the
    /// counter rises until `x` is on the curve. A cut `x` at or above the
    /// prime is not a field element and simply fails to decode.
    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub(super) fn try_and_increment<C>(id: CanaryId) -> Vec<u8>
    where
        C: CurveArithmetic,
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let size = <FieldBytesSize<C> as Unsigned>::USIZE;
        for counter in 0u32.. {
            let mut hasher = Sha3_256::new();
            hasher.update(label(id));
            hasher.update(counter.to_be_bytes());
            let digest = hasher.finalize();
            let mut compressed = Vec::with_capacity(1 + size);
            compressed.push(0x02);
            compressed.extend_from_slice(&digest[..size]);
            if let Some(point) = decode::<C>(&compressed) {
                return point.to_sec1_point(true).as_bytes().to_vec();
            }
        }
        unreachable!("the counter space is not exhausted")
    }

    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub(super) fn hash_to_curve_k1() -> Vec<u8> {
        let point = hash2curve::hash_from_bytes::<k256::Secp256k1, ExpandMsgXmd<sha2::Sha256>>(
            &[&label(CanaryId::EccK1)],
            &[SECP256K1_DST],
        )
        .unwrap_or_else(|_| unreachable!("expand_message_xmd accepts these lengths"));
        k256::AffinePoint::from(point)
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }

    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub(super) fn hash_to_curve_r1() -> Vec<u8> {
        let point = hash2curve::hash_from_bytes::<p256::NistP256, ExpandMsgXmd<sha2::Sha256>>(
            &[&label(CanaryId::EccR1)],
            &[P256_DST],
        )
        .unwrap_or_else(|_| unreachable!("expand_message_xmd accepts these lengths"));
        p256::AffinePoint::from(point)
            .to_sec1_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Whether `proof` is the canonical big-endian scalar `d` with
    /// `d * G = point`.
    pub(super) fn check<C>(point: &[u8], proof: &[u8]) -> bool
    where
        C: CurveArithmetic,
        C::AffinePoint: FromSec1Point<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let Some(target) = decode::<C>(point) else {
            return false;
        };
        if proof.len() != <FieldBytesSize<C> as Unsigned>::USIZE {
            return false;
        }
        let repr = match FieldBytes::<C>::try_from(proof) {
            Ok(repr) => repr,
            Err(_) => return false,
        };
        let scalar: Option<C::Scalar> = Option::from(C::Scalar::from_repr(repr));
        let Some(scalar) = scalar else {
            return false;
        };
        if bool::from(scalar.is_zero()) {
            return false;
        }
        let product = C::ProjectivePoint::generator() * scalar;
        product == C::ProjectivePoint::from(target)
    }
}

fn ristretto_puzzle() -> Vec<u8> {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use shake::{ExtendableOutput, Update, XofReader};
    // Element map of RFC 9496 section 4.3.4 over 64 uniform bytes, drawn from
    // SHAKE256 of the label.
    let mut hasher = shake::Shake256::default();
    hasher.update(&label(CanaryId::Ecc25519));
    let mut reader = hasher.finalize_xof();
    let mut uniform = [0u8; 64];
    reader.read(&mut uniform);
    RistrettoPoint::from_uniform_bytes(&uniform)
        .compress()
        .as_bytes()
        .to_vec()
}

fn ristretto_check(point: &[u8], proof: &[u8]) -> bool {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    let Ok(point) = <[u8; 32]>::try_from(point) else {
        return false;
    };
    let Some(target) = CompressedRistretto(point).decompress() else {
        return false;
    };
    let Ok(proof) = <[u8; 32]>::try_from(proof) else {
        return false;
    };
    let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof)) else {
        return false;
    };
    scalar != Scalar::ZERO && RISTRETTO_BASEPOINT_POINT * scalar == target
}

fn bls_puzzle() -> Vec<u8> {
    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    use bls12_381::{G1Affine, G1Projective};
    let point = <G1Projective as HashToCurve<ExpandMsgXmd<sha2_010::Sha256>>>::hash_to_curve(
        std::iter::once(label(CanaryId::BlsG1).as_slice()),
        BLS_G1_DST,
    );
    G1Affine::from(point).to_compressed().to_vec()
}

fn bls_check(point: &[u8], proof: &[u8]) -> bool {
    use bls12_381::{G1Affine, G1Projective, Scalar};
    let Ok(point) = <[u8; 48]>::try_from(point) else {
        return false;
    };
    let Some(target) = Option::<G1Affine>::from(G1Affine::from_compressed(&point)) else {
        return false;
    };
    let Ok(mut be) = <[u8; 32]>::try_from(proof) else {
        return false;
    };
    // The library reads scalars little endian; proofs are big endian like the
    // other curves.
    be.reverse();
    let Some(scalar) = Option::<Scalar>::from(Scalar::from_bytes(&be)) else {
        return false;
    };
    scalar != Scalar::zero() && G1Projective::generator() * scalar == G1Projective::from(target)
}

/// The set digest pinned at genesis: every puzzle, in order, length prefixed.
#[must_use]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub fn genesis_digest() -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, SET_TAG);
    for id in CanaryId::ALL {
        absorb(&mut hasher, id.name().as_bytes());
        absorb(&mut hasher, &id.puzzle());
    }
    hasher.finalize().into()
}

fn absorb(hasher: &mut Sha3_256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

/// `H(canary, proof, claimer)`: what a `CanaryCommit` publishes.
#[must_use]
pub fn commit_hash(id: CanaryId, proof: &[u8], claimer: &Address) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, COMMIT_TAG);
    absorb(&mut hasher, id.name().as_bytes());
    absorb(&mut hasher, proof);
    absorb(&mut hasher, claimer.as_bytes());
    hasher.finalize().into()
}

/// Why a commit or reveal was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub enum CanaryError {
    /// The same commitment is already pending for this claimer.
    DuplicateCommit,
    /// The claimer already holds [`MAX_PENDING_PER_CLAIMER`] commits.
    ClaimerQuota,
    /// Every global slot is occupied by an unexpired commitment.
    BookFull,
    /// No pending commit matches the reveal and its claimer.
    UnknownCommit,
    /// The reveal came before [`CANARY_REVEAL_DELAY`] blocks passed.
    RevealTooEarly,
    /// The reveal came after [`CANARY_REVEAL_WINDOW`] blocks.
    RevealExpired,
    /// The proof does not solve the puzzle.
    InvalidProof,
    /// The zero address is reserved for an alarm without a credited claim.
    ZeroClaimer,
}

impl AlarmLevel {
    /// The wire name of the level, with alarm names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Watch => "watch (kiragi)",
            Self::Restrict => "restrict (don)",
            Self::Isolate => "isolate (zemheri)",
        }
    }
}

impl AlarmKind {
    /// The wire name of the break, with alarm names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LatticeBreak => "lattice-break (kafes)",
            Self::HashSigBreak => "hash-signature-break (hash-imza)",
            Self::HashBreak => "hash-break (hash)",
        }
    }
}

/// A pending commit is keyed by `(claimer, commitment)`: a commitment copied
/// from the mempool and committed first under another address occupies a
/// different key and cannot squat the real claimer's slot.
type PendingKey = ([u8; 32], [u8; 32]);

/// A solved canary and who solved it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub struct CanaryClaim {
    /// Height of the winning commit.
    pub commit_height: u64,
    /// The claimer of the winning commit.
    pub claimer: Address,
    /// Height of the block that accepted the reveal.
    pub accepted_height: u64,
}

/// The alarm the chain is in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuantumAlarmState {
    level: Option<AlarmLevel>,
    kinds: BTreeSet<AlarmKind>,
    solved: BTreeMap<CanaryId, CanaryClaim>,
}

impl QuantumAlarmState {
    /// The curve alarm level. It never falls on its own.
    #[must_use]
    pub fn level(&self) -> AlarmLevel {
        self.level.unwrap_or(AlarmLevel::Clear)
    }

    /// The breaks that are not a curve falling.
    #[must_use]
    pub fn kinds(&self) -> &BTreeSet<AlarmKind> {
        &self.kinds
    }

    /// Whether `kind` is active.
    #[must_use]
    pub fn has(&self, kind: AlarmKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// The credited claim for `id`, if any. A solved canary may have no
    /// credited claim when its alarm was raised by an uncommitted proof.
    #[must_use]
    pub fn claim(&self, id: CanaryId) -> Option<&CanaryClaim> {
        self.solved
            .get(&id)
            .filter(|claim| claim.claimer != Address::zero())
    }

    /// Whether any canary is solved.
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn is_alarmed(&self) -> bool {
        !self.solved.is_empty()
    }

    fn apply(&mut self, id: CanaryId, claim: CanaryClaim) {
        if self.solved.contains_key(&id) {
            return;
        }
        match id.effect() {
            CanaryEffect::Level(level) => {
                self.level = Some(self.level().max(level));
            }
            CanaryEffect::Kind(kind) => {
                self.kinds.insert(kind);
            }
        }
        self.solved.insert(id, claim);
    }
}

/// Pending commits and the alarm state they drive.
#[derive(Debug, Clone, Default)]
pub struct CanaryBook {
    /// Commit height by `(claimer, commitment)`.
    pending: BTreeMap<PendingKey, u64>,
    alarm: QuantumAlarmState,
}

impl CanaryBook {
    /// An empty book: no commits, no alarm.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The alarm state.
    #[must_use]
    pub fn alarm(&self) -> &QuantumAlarmState {
        &self.alarm
    }

    /// Commits pending now.
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Records a `CanaryCommit` accepted at `height`.
    ///
    /// # Errors
    ///
    /// [`CanaryError::DuplicateCommit`] for a commitment this claimer already
    /// has pending, [`CanaryError::ClaimerQuota`] past the per-claimer limit,
    /// [`CanaryError::BookFull`] when all unexpired slots are occupied, or
    /// [`CanaryError::ZeroClaimer`] for the reserved zero address. A full
    /// book refuses the newcomer; it never revokes an unexpired commit.
    pub fn commit(
        &mut self,
        height: u64,
        claimer: Address,
        commitment: [u8; 32],
    ) -> Result<(), CanaryError> {
        if claimer == Address::zero() {
            return Err(CanaryError::ZeroClaimer);
        }
        self.prune(height);
        let key = (*claimer.as_bytes(), commitment);
        if self.pending.contains_key(&key) {
            return Err(CanaryError::DuplicateCommit);
        }
        let held = self
            .pending
            .range((key.0, [0u8; 32])..=(key.0, [0xff; 32]))
            .count();
        if held >= MAX_PENDING_PER_CLAIMER {
            return Err(CanaryError::ClaimerQuota);
        }
        if self.pending.len() >= MAX_PENDING_COMMITS {
            return Err(CanaryError::BookFull);
        }
        self.pending.insert(key, height);
        Ok(())
    }

    /// Accept a valid proof and immediately raise the alarm, irrespective of
    /// the commitment book. Returns a claim only for an eligible commitment;
    /// an uncommitted or premature publisher cannot take a solver's credit.
    ///
    /// # Errors
    ///
    /// [`CanaryError::InvalidProof`] if the proof does not solve the puzzle.
    /// A refused reveal leaves the book unchanged.
    pub fn reveal(
        &mut self,
        height: u64,
        claimer: Address,
        id: CanaryId,
        proof: &[u8],
    ) -> Result<Option<CanaryClaim>, CanaryError> {
        self.reveal_with_verifier(height, claimer, id, proof, |id, proof| id.verify(proof))
    }

    // Kept private: production always passes the actual puzzle verifier above.
    // Injecting it here lets tests exercise the alarm without a real break of
    // a genesis-pinned cryptographic puzzle.
    fn reveal_with_verifier(
        &mut self,
        height: u64,
        claimer: Address,
        id: CanaryId,
        proof: &[u8],
        verify: impl FnOnce(CanaryId, &[u8]) -> bool,
    ) -> Result<Option<CanaryClaim>, CanaryError> {
        if !verify(id, proof) {
            return Err(CanaryError::InvalidProof);
        }
        let key = (*claimer.as_bytes(), commit_hash(id, proof, &claimer));
        let pending = self.pending.get(&key).copied();
        let eligible = pending.filter(|commit_height| {
            let age = height.saturating_sub(*commit_height);
            (CANARY_REVEAL_DELAY..=CANARY_REVEAL_WINDOW).contains(&age)
        });
        if pending.is_some_and(|committed| height.saturating_sub(committed) > CANARY_REVEAL_WINDOW)
        {
            self.pending.remove(&key);
        }

        let previous = self.alarm.solved.get(&id).copied();
        let creditable = eligible.filter(|commit_height| match previous {
            None => true,
            // A commitment created after the proof was seen must not earn
            // credit merely by waiting out the delay. It had to be mature
            // before the alarm made that proof public on chain.
            Some(record) if record.claimer == Address::zero() => record
                .accepted_height
                .checked_sub(*commit_height)
                .is_some_and(|age| age >= CANARY_REVEAL_DELAY),
            Some(_) => false,
        });
        if let Some(commit_height) = eligible {
            self.pending.remove(&key);
            if creditable.is_some() {
                let claim = CanaryClaim {
                    commit_height,
                    claimer,
                    accepted_height: height,
                };
                if previous.is_none() {
                    self.alarm.apply(id, claim);
                } else {
                    // The alarm effect already applies; replace only its
                    // explicitly uncredited record with the qualifying claim.
                    self.alarm.solved.insert(id, claim);
                }
                return Ok(Some(claim));
            }
        }
        if previous.is_none() {
            self.alarm.apply(
                id,
                CanaryClaim {
                    commit_height: 0,
                    claimer: Address::zero(),
                    accepted_height: height,
                },
            );
        }
        Ok(None)
    }

    /// Marks `id` solved without a proof, for tests of what the alarm changes.
    #[cfg(test)]
    pub(crate) fn force_solved(&mut self, id: CanaryId, claim: CanaryClaim) {
        self.alarm.apply(id, claim);
    }

    /// Drops commits older than the reveal window.
    /// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
    pub fn prune(&mut self, height: u64) {
        self.pending
            .retain(|_, committed| height.saturating_sub(*committed) <= CANARY_REVEAL_WINDOW);
    }
}

/// One solved canary as the RPC shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub struct SolvedCanaryView {
    /// The puzzle name.
    pub canary: &'static str,
    /// The credited claimer, hex; all zeroes means the alarm has no claim.
    pub claimer: String,
    /// Height of the winning commit.
    pub commit_height: u64,
    /// Height of the block that accepted the reveal.
    pub accepted_height: u64,
}

/// The alarm as the RPC shows it: level, breaks, solved canaries, pending
/// commits and the rules the level sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// WIRING: the canary surface - the reveal/bounty doors that consume these belong to the guard-execution path, wiring pending.
pub struct QuantumAlarmView {
    /// The level name.
    pub level: &'static str,
    /// The active breaks that are not a curve falling.
    pub kinds: Vec<&'static str>,
    /// The solved canaries, in canary order.
    pub solved: Vec<SolvedCanaryView>,
    /// Commits waiting for their reveal.
    pub pending_commits: usize,
    /// The pinned digest of the canary set.
    pub canary_set_digest: String,
    /// Whether TEE shortcuts are open.
    pub tee_shortcuts_open: bool,
    /// The intake rule for classical-class messages: open, wait or stopped.
    pub classical_intake: &'static str,
    /// Whether finality still needs the BLS certificate.
    pub bls_required_for_finality: bool,
}

impl CanaryBook {
    /// The alarm as the RPC shows it.
    #[must_use]
    pub fn view(&self) -> QuantumAlarmView {
        use super::alarm_effects::{
            bls_required_for_finality, classical_intake, tee_shortcuts_open, ClassicalIntake,
        };
        QuantumAlarmView {
            level: self.alarm.level().name(),
            kinds: self.alarm.kinds().iter().map(|k| k.name()).collect(),
            solved: self
                .alarm
                .solved
                .iter()
                .map(|(id, claim)| SolvedCanaryView {
                    canary: id.name(),
                    claimer: hex::encode(claim.claimer.as_bytes()),
                    commit_height: claim.commit_height,
                    accepted_height: claim.accepted_height,
                })
                .collect(),
            pending_commits: self.pending.len(),
            canary_set_digest: hex::encode(genesis_digest()),
            tee_shortcuts_open: tee_shortcuts_open(&self.alarm),
            classical_intake: match classical_intake(&self.alarm) {
                ClassicalIntake::Open => "open",
                ClassicalIntake::Wait(_) => "wait",
                ClassicalIntake::Stopped => "stopped",
            },
            bls_required_for_finality: bls_required_for_finality(&self.alarm),
        }
    }

    /// Whether the book holds nothing: no pending commit and no solved canary.
    /// An empty book stays out of the state root, so a chain that never saw a
    /// canary transaction keeps its pinned roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.alarm.solved.is_empty()
    }

    /// The digest of the book: every pending commit and every solved canary in
    /// key order. The alarm level and kinds are derived from the solved set,
    /// so they are not hashed twice.
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        let mut pending = Vec::with_capacity(self.pending.len() * 72);
        for ((claimer, commitment), height) in &self.pending {
            pending.extend_from_slice(claimer);
            pending.extend_from_slice(commitment);
            pending.extend_from_slice(&height.to_le_bytes());
        }
        let mut solved = Vec::with_capacity(self.alarm.solved.len() * 49);
        for (id, claim) in &self.alarm.solved {
            solved.push(id.code());
            solved.extend_from_slice(&claim.commit_height.to_le_bytes());
            solved.extend_from_slice(claim.claimer.as_bytes());
            solved.extend_from_slice(&claim.accepted_height.to_le_bytes());
        }
        hash_fields_bytes(&[
            b"BDLM_CANARY_STATE_V1",
            &(self.pending.len() as u64).to_le_bytes(),
            &pending,
            &(self.alarm.solved.len() as u64).to_le_bytes(),
            &solved,
        ])
    }
}

/// The serialized form of a [`CanaryBook`]: the map keys are not strings, so
/// the book goes through plain vectors. Level and kinds are rebuilt from the
/// solved list when the book is read back.
#[derive(Serialize, Deserialize)]
struct CanaryBookWire {
    /// `(claimer, commitment, commit height)`.
    pending: Vec<([u8; 32], [u8; 32], u64)>,
    /// `(canary code, commit height, claimer, accepted height)`.
    solved: Vec<(u8, u64, [u8; 32], u64)>,
}

impl Serialize for CanaryBook {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        CanaryBookWire {
            pending: self
                .pending
                .iter()
                .map(|((claimer, commitment), height)| (*claimer, *commitment, *height))
                .collect(),
            solved: self
                .alarm
                .solved
                .iter()
                .map(|(id, claim)| {
                    (
                        id.code(),
                        claim.commit_height,
                        *claim.claimer.as_bytes(),
                        claim.accepted_height,
                    )
                })
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CanaryBook {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CanaryBookWire::deserialize(deserializer)?;
        if wire.pending.len() > MAX_PENDING_COMMITS {
            return Err(serde::de::Error::custom(
                "canary book over its commit bound",
            ));
        }
        let mut book = Self::new();
        for (claimer, commitment, height) in wire.pending {
            book.pending.insert((claimer, commitment), height);
        }
        for (code, commit_height, claimer, accepted_height) in wire.solved {
            let id = CanaryId::from_code(code)
                .ok_or_else(|| serde::de::Error::custom("unknown canary code"))?;
            book.alarm.apply(
                id,
                CanaryClaim {
                    commit_height,
                    claimer: Address(claimer),
                    accepted_height,
                },
            );
        }
        Ok(book)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address([n; 32])
    }

    #[test]
    fn every_id_has_a_unique_name_and_an_effect() {
        let names: BTreeSet<&str> = CanaryId::ALL.iter().map(|id| id.name()).collect();
        assert_eq!(names.len(), CanaryId::ALL.len());
        assert_eq!(
            CanaryId::Ecc192.effect(),
            CanaryEffect::Level(AlarmLevel::Watch)
        );
        assert_eq!(
            CanaryId::Ecc224.effect(),
            CanaryEffect::Level(AlarmLevel::Restrict)
        );
        for id in [
            CanaryId::EccK1,
            CanaryId::EccR1,
            CanaryId::Ecc25519,
            CanaryId::BlsG1,
        ] {
            assert_eq!(
                id.effect(),
                CanaryEffect::Level(AlarmLevel::Isolate),
                "{id:?}"
            );
        }
        assert_eq!(
            CanaryId::Lat65.effect(),
            CanaryEffect::Kind(AlarmKind::LatticeBreak)
        );
        assert_eq!(
            CanaryId::Lat87.effect(),
            CanaryEffect::Kind(AlarmKind::LatticeBreak)
        );
        assert_eq!(
            CanaryId::Slh256s.effect(),
            CanaryEffect::Kind(AlarmKind::HashSigBreak)
        );
        for id in [
            CanaryId::HashSha3,
            CanaryId::HashSha256,
            CanaryId::HashKeccak,
        ] {
            assert_eq!(
                id.effect(),
                CanaryEffect::Kind(AlarmKind::HashBreak),
                "{id:?}"
            );
        }
    }

    #[test]
    fn puzzles_are_deterministic_and_distinct() {
        let first: Vec<Vec<u8>> = CanaryId::ALL.iter().map(|id| id.puzzle()).collect();
        let second: Vec<Vec<u8>> = CanaryId::ALL.iter().map(|id| id.puzzle()).collect();
        assert_eq!(first, second);
        let keyed: BTreeSet<&Vec<u8>> = first.iter().filter(|p| !p.is_empty()).collect();
        assert_eq!(
            keyed.len(),
            9,
            "the nine keyed puzzles are pairwise distinct"
        );
        assert_eq!(genesis_digest(), genesis_digest());
    }

    #[test]
    fn puzzle_shapes() {
        assert_eq!(CanaryId::Ecc192.puzzle().len(), 1 + 24);
        assert_eq!(CanaryId::Ecc224.puzzle().len(), 1 + 28);
        assert_eq!(CanaryId::EccK1.puzzle().len(), 1 + 32);
        assert_eq!(CanaryId::EccR1.puzzle().len(), 1 + 32);
        assert_eq!(CanaryId::Ecc25519.puzzle().len(), 32);
        assert_eq!(CanaryId::BlsG1.puzzle().len(), 48);
        assert_eq!(CanaryId::Lat65.puzzle().len(), 1952);
        assert_eq!(CanaryId::Lat87.puzzle().len(), 2592);
        assert_eq!(CanaryId::Slh256s.puzzle().len(), 64);
    }

    #[test]
    fn curve_puzzles_reject_a_guess_and_the_empty_proof() {
        for id in [
            CanaryId::Ecc192,
            CanaryId::Ecc224,
            CanaryId::EccK1,
            CanaryId::EccR1,
            CanaryId::Ecc25519,
            CanaryId::BlsG1,
        ] {
            assert!(!id.verify(&[]), "{id:?}");
            assert!(!id.verify(&[0u8; 32]), "{id:?}: zero is not a solution");
            let mut one = [0u8; 32];
            one[31] = 1;
            assert!(
                !id.verify(&one),
                "{id:?}: d = 1 would make the puzzle the generator"
            );
        }
    }

    #[test]
    fn signature_puzzles_reject_garbage() {
        for id in [CanaryId::Lat65, CanaryId::Lat87, CanaryId::Slh256s] {
            assert!(!id.verify(&[]));
            assert!(!id.verify(&[0u8; 64]));
            let mut proof = vec![0u8, 4];
            proof.extend_from_slice(b"test");
            proof.extend_from_slice(&vec![7u8; 5000]);
            assert!(!id.verify(&proof), "{id:?}");
        }
    }

    fn collision_proof(m1: &[u8], m2: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in [m1, m2] {
            out.extend_from_slice(&(m.len() as u32).to_be_bytes());
            out.extend_from_slice(m);
        }
        out
    }

    #[test]
    fn collision_puzzles_reject_equal_and_unequal_messages() {
        for id in [
            CanaryId::HashSha3,
            CanaryId::HashSha256,
            CanaryId::HashKeccak,
        ] {
            assert!(!id.verify(&collision_proof(b"same", b"same")), "{id:?}");
            assert!(!id.verify(&collision_proof(b"one", b"two")), "{id:?}");
            assert!(!id.verify(&[]), "{id:?}");
            let mut trailing = collision_proof(b"one", b"two");
            trailing.push(0);
            assert!(!id.verify(&trailing), "{id:?}");
            let big = vec![0u8; MAX_COLLISION_MESSAGE_LEN + 1];
            assert!(!id.verify(&collision_proof(&big, b"x")), "{id:?}");
        }
    }

    #[test]
    fn commit_hash_binds_canary_proof_and_claimer() {
        let base = commit_hash(CanaryId::Ecc224, b"proof", &addr(1));
        assert_ne!(base, commit_hash(CanaryId::Ecc192, b"proof", &addr(1)));
        assert_ne!(base, commit_hash(CanaryId::Ecc224, b"other", &addr(1)));
        assert_ne!(base, commit_hash(CanaryId::Ecc224, b"proof", &addr(2)));
    }

    #[test]
    fn duplicate_commit_is_refused() {
        let mut book = CanaryBook::new();
        assert_eq!(
            book.commit(1, Address::zero(), [1u8; 32]),
            Err(CanaryError::ZeroClaimer)
        );
        book.commit(1, addr(1), [1u8; 32]).unwrap();
        assert_eq!(
            book.commit(2, addr(1), [1u8; 32]),
            Err(CanaryError::DuplicateCommit)
        );
    }

    /// A commitment copied from the mempool and committed first under another
    /// address must not block the real claimer.
    #[test]
    fn copied_commitment_cannot_squat_the_claimers_slot() {
        let proof = b"proof".to_vec();
        let commitment = commit_hash(CanaryId::Ecc192, &proof, &addr(1));
        let mut book = CanaryBook::new();
        book.commit(5, addr(9), commitment).unwrap();
        book.commit(6, addr(1), commitment).unwrap();
        assert_eq!(book.pending_len(), 2);
        // The real claimer's reveal finds its own commit (the proof is not a
        // solution, so it is refused for that reason and not as unknown).
        assert_eq!(
            book.reveal(300, addr(1), CanaryId::Ecc192, &proof),
            Err(CanaryError::InvalidProof)
        );
    }

    #[test]
    fn one_claimer_cannot_fill_the_book() {
        let mut book = CanaryBook::new();
        for i in 0..MAX_PENDING_PER_CLAIMER {
            book.commit(1, addr(3), [i as u8; 32]).unwrap();
        }
        assert_eq!(
            book.commit(1, addr(3), [0xee; 32]),
            Err(CanaryError::ClaimerQuota)
        );
        // Another claimer is unaffected.
        book.commit(1, addr(4), [0xee; 32]).unwrap();
    }

    #[test]
    fn full_book_never_evicts_an_unexpired_commit() {
        let mut book = CanaryBook::new();
        // The lowest address would lose the former one-per-address tie-break.
        let mut honest_address = [0u8; 32];
        honest_address[31] = 1;
        let honest_claimer = Address(honest_address);
        let proof = b"honest";
        let honest = commit_hash(CanaryId::Ecc192, proof, &honest_claimer);
        book.commit(0, honest_claimer, honest).unwrap();
        for n in 1..MAX_PENDING_COMMITS {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&(n as u16).to_be_bytes());
            book.commit(0, Address(bytes), [0xab; 32]).unwrap();
        }
        assert_eq!(book.pending_len(), MAX_PENDING_COMMITS);
        let mut newcomer = [0u8; 32];
        newcomer[..2].copy_from_slice(&(MAX_PENDING_COMMITS as u16).to_be_bytes());
        assert_eq!(
            book.commit(500, Address(newcomer), [0xcd; 32]),
            Err(CanaryError::BookFull)
        );
        assert_eq!(book.pending_len(), MAX_PENDING_COMMITS);
        assert_eq!(
            book.reveal(500, honest_claimer, CanaryId::Ecc192, proof),
            Err(CanaryError::InvalidProof),
            "the honest commitment must still be found"
        );
        assert_eq!(
            book.reveal_with_verifier(500, Address(newcomer), CanaryId::Ecc192, proof, |_, _| true),
            Ok(None),
            "a full book cannot suppress the alarm"
        );
        assert!(book.alarm().is_alarmed());
        assert!(book.alarm().claim(CanaryId::Ecc192).is_none());
        let credited = book
            .reveal_with_verifier(501, honest_claimer, CanaryId::Ecc192, proof, |_, _| true)
            .unwrap()
            .unwrap();
        assert_eq!(credited.claimer, honest_claimer);

        // Expiry, not a newcomer, releases slots and makes admission possible.
        book.commit(CANARY_REVEAL_WINDOW + 1, Address(newcomer), [0xcd; 32])
            .unwrap();
        assert_eq!(book.pending_len(), 1);
    }

    #[test]
    fn invalid_proof_without_a_commit_is_refused() {
        let mut book = CanaryBook::new();
        assert_eq!(
            book.reveal(500, addr(1), CanaryId::Ecc192, b"proof"),
            Err(CanaryError::InvalidProof)
        );
        assert!(!book.alarm().is_alarmed());
    }

    #[test]
    fn invalid_reveal_by_another_claimer_cannot_take_a_commit() {
        let mut book = CanaryBook::new();
        let proof = b"front-run attempt".to_vec();
        book.commit(10, addr(1), commit_hash(CanaryId::Ecc192, &proof, &addr(1)))
            .unwrap();
        // Whoever copies the proof from a reveal hashes it under their own
        // address and has no commit.
        assert_eq!(
            book.reveal(500, addr(2), CanaryId::Ecc192, &proof),
            Err(CanaryError::InvalidProof)
        );
    }

    #[test]
    fn reveal_timing_window_controls_credit_not_the_alarm() {
        let proof = b"p".to_vec();
        let commitment = commit_hash(CanaryId::Ecc192, &proof, &addr(1));
        let mut early = CanaryBook::new();
        early.commit(1000, addr(1), commitment).unwrap();
        assert_eq!(
            early.reveal_with_verifier(
                1000 + CANARY_REVEAL_DELAY - 1,
                addr(1),
                CanaryId::Ecc192,
                &proof,
                |_, _| true
            ),
            Ok(None),
            "a premature proof raises an uncredited alarm"
        );
        assert!(early.alarm().is_alarmed());
        assert!(early.alarm().claim(CanaryId::Ecc192).is_none());
        assert_eq!(
            early.reveal_with_verifier(1200, addr(1), CanaryId::Ecc192, &proof, |_, _| true),
            Ok(None),
            "a commitment not mature when proof became public cannot claim later"
        );

        let mut book = CanaryBook::new();
        book.commit(1000, addr(1), commitment).unwrap();
        assert_eq!(
            book.reveal_with_verifier(1100, addr(9), CanaryId::Ecc192, &proof, |_, _| true),
            Ok(None),
            "an uncommitted publisher raises the alarm without taking credit"
        );
        let copy = commit_hash(CanaryId::Ecc192, &proof, &addr(2));
        book.commit(1101, addr(2), copy).unwrap();
        let saved = serde_json::to_string(&book).unwrap();
        let mut restored: CanaryBook = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.state_root(), book.state_root());
        assert_eq!(
            restored.reveal_with_verifier(1201, addr(2), CanaryId::Ecc192, &proof, |_, _| true),
            Ok(None),
            "a commitment made after the proof was public cannot earn credit"
        );
        let claim = restored
            .reveal_with_verifier(1201, addr(1), CanaryId::Ecc192, &proof, |_, _| true)
            .unwrap()
            .unwrap();
        assert_eq!(claim.claimer, addr(1));
        assert_eq!(restored.alarm().claim(CanaryId::Ecc192), Some(&claim));
        assert_eq!(restored.pending_len(), 0);

        let mut expired = CanaryBook::new();
        expired.commit(1, addr(1), commitment).unwrap();
        assert_eq!(
            expired.reveal_with_verifier(
                CANARY_REVEAL_WINDOW + 2,
                addr(1),
                CanaryId::Ecc192,
                &proof,
                |_, _| true
            ),
            Ok(None)
        );
        assert!(expired.alarm().is_alarmed());
        assert!(expired.alarm().claim(CanaryId::Ecc192).is_none());
        assert_eq!(expired.pending_len(), 0);
    }

    #[test]
    fn invalid_proof_changes_nothing_and_keeps_the_commit() {
        let proof = vec![9u8; 24];
        let mut book = CanaryBook::new();
        book.commit(0, addr(1), commit_hash(CanaryId::Ecc192, &proof, &addr(1)))
            .unwrap();
        assert_eq!(
            book.reveal(200, addr(1), CanaryId::Ecc192, &proof),
            Err(CanaryError::InvalidProof)
        );
        assert_eq!(book.pending_len(), 1);
        assert_eq!(book.alarm().level(), AlarmLevel::Clear);
    }

    /// A collision proof is the one puzzle a test can solve, and only against
    /// a deliberately weak digest. The alarm state machine is driven directly
    /// instead.
    #[test]
    fn alarm_escalates_and_never_falls() {
        let mut state = QuantumAlarmState::default();
        assert_eq!(state.level(), AlarmLevel::Clear);
        let claim = |h| CanaryClaim {
            commit_height: h,
            claimer: addr(1),
            accepted_height: h + 100,
        };
        state.apply(CanaryId::Ecc224, claim(1));
        assert_eq!(state.level(), AlarmLevel::Restrict);
        state.apply(CanaryId::Ecc192, claim(2));
        assert_eq!(
            state.level(),
            AlarmLevel::Restrict,
            "a lower level cannot lower it"
        );
        state.apply(CanaryId::EccK1, claim(3));
        assert_eq!(state.level(), AlarmLevel::Isolate);
        state.apply(CanaryId::Lat65, claim(4));
        assert!(state.has(AlarmKind::LatticeBreak));
        assert!(!state.has(AlarmKind::HashBreak));
        state.apply(CanaryId::Lat87, claim(5));
        assert_eq!(state.kinds().len(), 1);
        assert_eq!(state.claim(CanaryId::Ecc224).unwrap().commit_height, 1);
        // A second claim of the same puzzle does not replace the first.
        state.apply(CanaryId::Ecc224, claim(99));
        assert_eq!(state.claim(CanaryId::Ecc224).unwrap().commit_height, 1);
    }

    /// The puzzles are part of genesis. Any change to the label, the
    /// try-and-increment rule, a DST or a library output moves these digests
    /// and has to be a deliberate, reviewed change.
    #[test]
    fn puzzles_are_pinned() {
        let pins: [(CanaryId, &str); 9] = [
            (
                CanaryId::Ecc192,
                "ae67a3a51d598e4b6f925c7323baa6a30b936d2d95cee72e27f65cc8f3a07d3f",
            ),
            (
                CanaryId::Ecc224,
                "f58847317cef3c6e599e6be9ae68f2ba57dcbabdb4e2f3954f3815a61740d8cf",
            ),
            (
                CanaryId::EccK1,
                "db0e34bdb082b40655fc5f2f6ddf49bceb3d332c0e4031f1566f0ffceb4cf060",
            ),
            (
                CanaryId::EccR1,
                "b30b9790da582dcea4ef6987c0ad53a086a03f7cf8c7a94f2d047fa8ca31e3d0",
            ),
            (
                CanaryId::Ecc25519,
                "b7df2d2de259ead30b35bd6d4e1cd5310c0612f38ab1f2b86912d88a7873ed5e",
            ),
            (
                CanaryId::BlsG1,
                "221166f87336643846eea07440736aeed4b32c9ab0cfc66693773238a5a0aaf1",
            ),
            (
                CanaryId::Lat65,
                "e6a9ae854deffffaf073a4a27c85a19cab0d48a3a33836d111f48abdf6313123",
            ),
            (
                CanaryId::Lat87,
                "26cb55e104557e01c865b03bbb8858ec028821431eda3183c6075cf5c9faed10",
            ),
            (
                CanaryId::Slh256s,
                "b7deea0b5b5a771b92d515f688a2573fc3637332e9b53312be816b74fcbfbfc9",
            ),
        ];
        for (id, expected) in pins {
            assert_eq!(
                hex::encode(Sha3_256::digest(id.puzzle())),
                expected,
                "{} puzzle changed",
                id.name()
            );
        }
        // The label carries its length, so the three signature puzzles
        // (`C-LAT-65`, `C-LAT-87`, `C-SLH-256S`) and the set digest were
        // re-derived when the XOF started absorbing that length: without it
        // `label` and the bytes after it were not injective, and two puzzle
        // families could be made to share a key.
        assert_eq!(
            hex::encode(genesis_digest()),
            "5f5cfb7d09594a88a89b924dd9a25827f0cba015e8a73d6708e144e40facb54b"
        );
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address([n; 32])
    }

    #[test]
    fn the_codes_roundtrip_and_follow_the_genesis_order() {
        for (index, id) in CanaryId::ALL.iter().enumerate() {
            assert_eq!(usize::from(id.code()), index);
            assert_eq!(CanaryId::from_code(id.code()), Some(*id));
        }
        assert_eq!(CanaryId::from_code(12), None);
        assert_eq!(CanaryId::from_code(255), None);
    }

    #[test]
    fn an_empty_book_is_empty_and_a_commit_changes_the_root() {
        let mut book = CanaryBook::new();
        assert!(book.is_empty());
        let empty = book.state_root();
        book.commit(10, addr(1), [7; 32]).expect("commit");
        assert!(!book.is_empty());
        assert_ne!(book.state_root(), empty);
        // The same history gives the same root.
        let mut again = CanaryBook::new();
        again.commit(10, addr(1), [7; 32]).expect("commit");
        assert_eq!(again.state_root(), book.state_root());
        // The height of the commit is part of it.
        let mut later = CanaryBook::new();
        later.commit(11, addr(1), [7; 32]).expect("commit");
        assert_ne!(later.state_root(), book.state_root());
    }

    #[test]
    fn the_book_survives_serialization_with_its_alarm() {
        let mut book = CanaryBook::new();
        book.commit(10, addr(1), [7; 32]).expect("commit");
        book.commit(11, addr(2), [8; 32]).expect("commit");
        // Solve a hash-break canary through the state machine directly: the
        // alarm is rebuilt from the solved list, so any solved entry must
        // bring its effect back.
        book.alarm.apply(
            CanaryId::Ecc224,
            CanaryClaim {
                commit_height: 3,
                claimer: addr(9),
                accepted_height: 200,
            },
        );
        book.alarm.apply(
            CanaryId::HashSha3,
            CanaryClaim {
                commit_height: 4,
                claimer: addr(9),
                accepted_height: 201,
            },
        );
        let json = serde_json::to_string(&book).expect("serialize");
        let back: CanaryBook = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.state_root(), book.state_root());
        assert_eq!(back.alarm().level(), AlarmLevel::Restrict);
        assert!(back.alarm().has(AlarmKind::HashBreak));
        assert_eq!(back.pending_len(), 2);
        // An unknown canary code is refused, not skipped.
        let bad = r#"{"pending":[],"solved":[[99,1,[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],2]]}"#;
        assert!(serde_json::from_str::<CanaryBook>(bad).is_err());
    }
}
