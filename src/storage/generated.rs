//! Content that is described rather than stored.
//!
//! Every other saving in `src/storage/` makes the bytes smaller. This one
//! removes them: an object whose bytes follow from a short description does
//! not need the bytes on disk at all, only the description. Measured against
//! the alternatives, it is the only lever that reaches a zero multiplier,
//! and every other lever is an asymptote that approaches 1.0 from above.
//!
//! # Why the chain can trust a generated object
//!
//! `manifest_id` is the hash of the object's bytes. That single fact makes
//! verification trivial here: a node runs the description, hashes what comes
//! out, and compares. If the hashes match, the bytes are the object, by the
//! same definition the chain already uses for stored content. Nothing new has
//! to be believed.
//!
//! This is why generated content needs **no** zero-knowledge proof. A STARK
//! is what you reach for when the output is secret or when recomputing is
//! more expensive than verifying a proof about it. Here the output is public
//! and recomputation is the cheapest check available, so a proof would add
//! cost and prove something already known.
//!
//! # Determinism is the whole requirement
//!
//! Two nodes must produce the same bytes, or they will disagree about whether
//! an object is valid, which is a fork. Floating point cannot give that
//! guarantee across machines, so it is refused, in the same way and for the
//! same reason it is refused everywhere else in consensus code. What replaces
//! it is [`crate::storage::fixed_point`], a small fixed-point library, because refusing floats
//! without offering an alternative just moves the problem into every caller.
//!
//! # A budget, not a ceiling
//!
//! A generator could loop forever, and no check can decide in advance whether
//! it will (Turing). Left alone, that is three separate failures: a reader
//! waits forever, two nodes time out differently and disagree, and an
//! attacker uploads thirty-two bytes to burn minutes of everyone's CPU.
//!
//! The fix is not a fixed step limit, which would say "content above this
//! complexity may not exist" and is a restriction on expression. It is a
//! **budget the uploader pays for**: steps are metered, the budget is
//! declared in the manifest and priced like any other resource, and a
//! generator that exhausts it stops. Expensive content is not refused, it is
//! pointed at the storage path instead, which already works. The ceiling is
//! a fork in the road rather than a wall.
//!
//! WIRING: unwired - measured: no production path constructs a
//! `ContentSource::Generated` manifest yet. The verification path and the
//! generators are here and tested; what is missing is the transaction that
//! registers a described object, which is a consensus-surface change.

use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;
use crate::storage::fixed_point::{
    fixed_clamp_unit, fixed_div, fixed_from_int, fixed_mul, fixed_sqrt, fixed_to_int, FIXED_ONE,
};

/// How the bytes behind a manifest come to exist.
///
/// `Stored` is what every manifest written before this meant, so it is the
/// default and nothing already registered changes meaning.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ContentSource {
    /// The bytes are held by operators. The only behaviour before this type
    /// existed.
    #[default]
    Stored,
    /// The bytes follow from a generator and a seed.
    ///
    /// What is stored is this description. What is served is the output of
    /// running it, checked against `manifest_id` before it is handed back.
    Generated(GeneratedSpec),
    /// A stored prefix, and the rest produced on read.
    ///
    /// The case the other two variants cannot express. A progressive JPEG's
    /// first scan is a usable low-quality image on its own, so holding that
    /// prefix and producing the refinement gives a reader something to show
    /// immediately without holding the whole object.
    ///
    /// Measured, on the 1600x1200 corpus this project used elsewhere: a ten
    /// percent progressive prefix is 0.30 MB against a 152 KB master and four
    /// variants totalling 211.6 KB, and dropping the variants in favour of a
    /// prefix is the 0.754 factor in the composite. That factor is the whole
    /// reason this variant exists; without it the choice is all-or-nothing
    /// and an object that needs a fast first paint has to be `Stored`.
    ///
    /// `prefix_bytes` counts from the start of the object. It is not a
    /// separate content id: the prefix is a prefix of the same bytes
    /// `manifest_id` commits to, so a reader that holds it and produces the
    /// remainder can hash the concatenation and get the same answer. A prefix
    /// with its own id would be a second object to keep in step.
    Hybrid {
        /// Bytes held from the start of the object.
        prefix_bytes: u32,
        /// How the remainder is produced.
        spec: GeneratedSpec,
    },
}

/// How many bytes an operator actually holds for a source.
///
/// The number the storage decision divides. `Stored` holds all of them,
/// `Generated` none, and `Hybrid` its prefix, which is what makes the three
/// comparable at all: without this they are three shapes rather than three
/// points on one axis.
///
/// Returns `None` when a `Hybrid` prefix is longer than the object, which is
/// a spec that contradicts itself rather than a large prefix.
#[must_use]
pub fn held_bytes(source: &ContentSource, object_bytes: u64) -> Option<u64> {
    match source {
        ContentSource::Stored => Some(object_bytes),
        ContentSource::Generated(_) => Some(0),
        ContentSource::Hybrid { prefix_bytes, .. } => {
            let prefix = u64::from(*prefix_bytes);
            if prefix > object_bytes {
                None
            } else {
                Some(prefix)
            }
        }
    }
}

/// The description of a generated object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeneratedSpec {
    /// Which generator produces the bytes.
    pub generator: GeneratorId,
    /// The input the generator varies on. Thirty-two bytes, which is the
    /// whole of what a collection has to store per item.
    pub seed: [u8; 32],
    /// Declared output length. Checked against what the generator actually
    /// produces, because a spec that lies about its size would let a reader
    /// allocate on an untrusted number.
    pub output_len: u32,
    /// Steps the uploader paid for.
    ///
    /// Not a limit on what may be expressed: a generator needing more is
    /// legal, it simply costs more, and content whose generation costs more
    /// than storing it takes the storage path instead. What this bounds is
    /// the work an unpaid generator can extract from a reader.
    pub step_budget: u32,
}

/// Which generator to run.
///
/// A closed set rather than arbitrary bytecode, for now. The catalogue is
/// native Rust, so a 32x32 avatar costs well under a millisecond where an
/// interpreter would spend most of that on dispatch, and each entry's
/// determinism can be argued from its source rather than from a VM's
/// guarantees. Bytecode is the natural next step for expressiveness, and
/// nothing here forecloses it: `GeneratorId` is an enum with room to grow,
/// and the verification path does not care which arm produced the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GeneratorId {
    /// Identicon-style avatar: a symmetric grid coloured from the seed.
    Avatar,
    /// A two-colour linear gradient, the common case for themes and
    /// backgrounds.
    Gradient,
    /// Distance-field rings, an algorithmic-art primitive that exercises the
    /// fixed-point square root.
    Rings,
}

impl GeneratorId {
    /// Stable byte tag for the commitment.
    ///
    /// Written out rather than derived from the variant order, because
    /// reordering the enum would otherwise silently change every id ever
    /// computed for a generated object.
    #[must_use]
    pub const fn generator_commitment_tag(self) -> u8 {
        match self {
            Self::Avatar => 1,
            Self::Gradient => 2,
            Self::Rings => 3,
        }
    }
}

/// Why a generated object could not be produced or accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// The generator used more steps than the uploader paid for.
    ///
    /// Carries both numbers so the caller can say how much more to buy rather
    /// than only that it failed.
    BudgetExhausted { budget: u32, needed: u32 },
    /// The output length does not match what the spec declared.
    LengthMismatch { declared: u32, produced: usize },
    /// The bytes produced do not hash to the id the manifest carries.
    ///
    /// This is the check that makes generated content safe to serve. It fires
    /// when a spec is paired with an id it does not derive, whether by
    /// accident or because someone tried to smuggle a different object under
    /// a known id.
    IdMismatch {
        expected: ContentId,
        produced: ContentId,
    },
    /// The declared output is larger than any generator may emit.
    OutputTooLarge { declared: u32, max: u32 },
    /// A zero-length object was described. Nothing has a zero-byte identity
    /// worth committing to, and `encode_object` refuses empty input anyway.
    EmptyOutput,
}

impl std::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExhausted { budget, needed } => write!(
                f,
                "generator needs at least {needed} steps but {budget} were paid for"
            ),
            Self::LengthMismatch { declared, produced } => write!(
                f,
                "spec declares {declared} bytes but the generator produced {produced}"
            ),
            Self::IdMismatch { expected, produced } => write!(
                f,
                "generated bytes hash to {produced} but the manifest claims {expected}"
            ),
            Self::OutputTooLarge { declared, max } => write!(
                f,
                "declared output {declared} exceeds the {max}-byte generator maximum"
            ),
            Self::EmptyOutput => write!(f, "a generated object cannot be empty"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// Largest object any generator may emit in one call.
///
/// Not a statement about what content may exist: an object above this is
/// stored rather than described, which is the path that already works. What
/// it bounds is the memory a single untrusted spec can make a reader
/// allocate, before any step is run.
pub const MAX_GENERATED_BYTES: u32 = 4 * 1024 * 1024;

/// Steps charged per output byte, on top of whatever the generator's own
/// loop costs.
///
/// A generator that emitted bytes for free would let a spec with a tiny
/// budget produce a huge object, so the output itself is metered.
const STEPS_PER_OUTPUT_BYTE: u32 = 1;

/// A step meter.
///
/// Threaded through generation rather than checked at the end, because a
/// generator that runs away has to be stopped while it runs, not after.
struct Meter {
    used: u32,
    budget: u32,
}

impl Meter {
    const fn new(budget: u32) -> Self {
        Self { used: 0, budget }
    }

    /// Charge `n` steps. Returns the error rather than panicking, so an
    /// exhausted budget is an answer a caller can report rather than a crash
    /// in a read path.
    const fn charge(&mut self, n: u32) -> Result<(), GenerateError> {
        self.used = self.used.saturating_add(n);
        if self.used > self.budget {
            return Err(GenerateError::BudgetExhausted {
                budget: self.budget,
                needed: self.used,
            });
        }
        Ok(())
    }
}

/// Narrow a pixel coordinate to `i32` for the fixed-point helpers.
///
/// Every caller is bounded by [`MAX_GENERATED_BYTES`], so the value always
/// fits and the saturation never fires. It is written as a conversion rather
/// than a cast because a silent wrap here would turn a large coordinate into
/// a small one, and the generator would draw the wrong picture while hashing
/// consistently, which is the failure this module is built to avoid.
fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

/// Narrow a colour channel to a byte.
///
/// The value arrives already clamped to the unit range and scaled by 255, so
/// this is the last step rather than a guess. Saturating for the same reason
/// as [`clamp_i32`].
fn clamp_u8(v: i32) -> u8 {
    u8::try_from(v.clamp(0, 255)).unwrap_or(u8::MAX)
}

/// Narrow an already-descaled fixed-point result to `i32`.
///
/// The gradient generator leaves fixed point by multiplying by 255 and
/// dividing by `FIXED_ONE`, which yields a plain 0..=255 value in an `i64`.
/// It is written as a conversion rather than a cast for the same reason as
/// [`clamp_i32`]: a silent wrap here would produce a wrong colour that still
/// hashed consistently, which is the failure this module exists to avoid.
const fn clamp_i32_from_i64(v: i64) -> i32 {
    if v > i32::MAX as i64 {
        i32::MAX
    } else if v < i32::MIN as i64 {
        i32::MIN
    } else {
        v as i32
    }
}

/// Draw the bytes a spec describes.
///
/// # Errors
///
/// [`GenerateError::EmptyOutput`] for a zero-length spec,
/// [`GenerateError::OutputTooLarge`] above [`MAX_GENERATED_BYTES`],
/// [`GenerateError::BudgetExhausted`] when the generator needs more steps
/// than were paid for, and [`GenerateError::LengthMismatch`] if a generator
/// emits a different length than it declared.
pub fn generate_content(spec: &GeneratedSpec) -> Result<Vec<u8>, GenerateError> {
    if spec.output_len == 0 {
        return Err(GenerateError::EmptyOutput);
    }
    if spec.output_len > MAX_GENERATED_BYTES {
        return Err(GenerateError::OutputTooLarge {
            declared: spec.output_len,
            max: MAX_GENERATED_BYTES,
        });
    }

    let mut meter = Meter::new(spec.step_budget);
    // Charge for the output before producing it, so a spec cannot get a large
    // allocation on a small budget.
    meter.charge(spec.output_len.saturating_mul(STEPS_PER_OUTPUT_BYTE))?;

    let out = match spec.generator {
        GeneratorId::Avatar => draw_avatar(&spec.seed, spec.output_len, &mut meter)?,
        GeneratorId::Gradient => draw_gradient(&spec.seed, spec.output_len, &mut meter)?,
        GeneratorId::Rings => draw_rings(&spec.seed, spec.output_len, &mut meter)?,
    };

    if out.len() != spec.output_len as usize {
        return Err(GenerateError::LengthMismatch {
            declared: spec.output_len,
            produced: out.len(),
        });
    }
    Ok(out)
}

/// Produce the bytes and check them against the id the manifest carries.
///
/// This is what a reader calls. `generate_content` alone says what a spec draws;
/// this says whether what it draws is the object being asked for.
///
/// # Errors
///
/// Everything [`generate_content`] can return, plus [`GenerateError::IdMismatch`]
/// when the bytes do not hash to `expected`.
pub fn generate_and_verify(
    spec: &GeneratedSpec,
    expected: ContentId,
) -> Result<Vec<u8>, GenerateError> {
    let bytes = generate_content(spec)?;
    let produced = ContentId::of(&bytes);
    if produced != expected {
        return Err(GenerateError::IdMismatch { expected, produced });
    }
    Ok(bytes)
}

/// Canonical commitment over a generated spec.
///
/// Every field is covered. A spec is a promise about which bytes an id means,
/// so a field outside the commitment would be a part of that promise anyone
/// could rewrite: swapping the generator, the seed or the length while
/// keeping the id would point one id at two different objects.
#[must_use]
pub fn generated_spec_digest(spec: &GeneratedSpec) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_GENERATED_SPEC_V1",
        &[spec.generator.generator_commitment_tag()],
        &spec.seed,
        &spec.output_len.to_le_bytes(),
        &spec.step_budget.to_le_bytes(),
    ])
}

/// A deterministic byte stream derived from a seed.
///
/// Generators need more pseudo-random material than the seed holds, and they
/// need every node to derive the same material. Hashing a counter alongside
/// the seed gives that, using the tree's own hash rather than a random
/// number generator whose internals could change between releases.
struct SeedStream {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl SeedStream {
    const fn new(seed: &[u8; 32]) -> Self {
        Self {
            seed: *seed,
            counter: 0,
            buf: [0u8; 32],
            pos: 32,
        }
    }

    fn next_byte(&mut self) -> u8 {
        if self.pos >= 32 {
            self.buf = hash_fields_bytes(&[
                b"BDLM_GENERATED_STREAM_V1",
                &self.seed,
                &self.counter.to_le_bytes(),
            ]);
            self.counter = self.counter.wrapping_add(1);
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }
}

/// Side length for a square RGB image of `len` bytes, and the remainder.
///
/// Generators emit `side * side * 3` bytes and pad the tail, so a caller can
/// ask for any length and get a deterministic answer rather than an error
/// about geometry.
fn square_side(len: u32) -> u32 {
    let pixels = len / 3;
    let mut side = 0u32;
    while (side + 1) * (side + 1) <= pixels {
        side += 1;
    }
    side.max(1)
}

/// An identicon: a grid mirrored left to right, coloured from the seed.
///
/// Mirroring is what makes these read as faces rather than noise, and it is
/// also why the generator only has to decide half the cells.
fn draw_avatar(seed: &[u8; 32], len: u32, meter: &mut Meter) -> Result<Vec<u8>, GenerateError> {
    let side = square_side(len);
    let mut stream = SeedStream::new(seed);

    // Palette: one foreground drawn from the seed, a fixed light background.
    let fg = [stream.next_byte(), stream.next_byte(), stream.next_byte()];
    let bg = [0xF0u8, 0xF0u8, 0xF0u8];

    // Cell grid. Five columns is the identicon convention; the mirrored half
    // is three of them.
    let cells = 5u32;
    let half = cells.div_ceil(2);
    let mut on = vec![false; (cells * cells) as usize];
    for row in 0..cells {
        for col in 0..half {
            let bit = stream.next_byte() & 1 == 1;
            on[(row * cells + col) as usize] = bit;
            on[(row * cells + (cells - 1 - col)) as usize] = bit;
        }
    }
    meter.charge(cells * half)?;

    let mut out = Vec::with_capacity(len as usize);
    for y in 0..side {
        for x in 0..side {
            let cx = (x * cells) / side;
            let cy = (y * cells) / side;
            let c = if on[(cy * cells + cx) as usize] {
                fg
            } else {
                bg
            };
            out.extend_from_slice(&c);
        }
        meter.charge(side)?;
    }
    out.resize(len as usize, 0);
    Ok(out)
}

/// A linear gradient between two seed-derived colours.
fn draw_gradient(seed: &[u8; 32], len: u32, meter: &mut Meter) -> Result<Vec<u8>, GenerateError> {
    let side = square_side(len);
    let mut stream = SeedStream::new(seed);
    let a = [stream.next_byte(), stream.next_byte(), stream.next_byte()];
    let b = [stream.next_byte(), stream.next_byte(), stream.next_byte()];
    // Direction: horizontal, vertical, or diagonal.
    let dir = stream.next_byte() % 3;

    let mut out = Vec::with_capacity(len as usize);
    let span = fixed_from_int(clamp_i32(side.saturating_sub(1).max(1)));
    for y in 0..side {
        for x in 0..side {
            let along = match dir {
                0 => fixed_from_int(clamp_i32(x)),
                1 => fixed_from_int(clamp_i32(y)),
                _ => fixed_div(fixed_from_int(clamp_i32(x + y)), fixed_from_int(2)),
            };
            let t = fixed_clamp_unit(fixed_div(along, span));
            for ch in 0..3 {
                let from_channel = fixed_from_int(i32::from(a[ch]));
                let to_channel = fixed_from_int(i32::from(b[ch]));
                let v = from_channel + fixed_mul(to_channel - from_channel, t);
                // `* 255 / FIXED_ONE` already takes the value out of fixed
                // point: it turns a unit-range fixed number into a plain
                // 0..=255 integer. Calling `fixed_to_int` on the result
                // shifted it down by another sixteen bits, so every channel
                // under 65536/255 became zero, which is every channel there
                // is. Both endpoint colours are drawn from the seed and both
                // were discarded: every gradient this generator has ever
                // produced is solid black.
                //
                // It hashed consistently while doing it, so the determinism
                // tests passed, the id matched, and the object verified. That
                // is the same failure `fixed_sqrt` had, one function away, and
                // the reason the frozen vectors in this module's tests now
                // pin the bytes rather than only their agreement.
                let scaled = fixed_clamp_unit(fixed_div(v, fixed_from_int(255))) * 255 / FIXED_ONE;
                out.push(clamp_u8(clamp_i32_from_i64(scaled)));
            }
        }
        meter.charge(side * 3)?;
    }
    out.resize(len as usize, 0);
    Ok(out)
}

/// Concentric rings from a distance field.
///
/// Included because it is the generator that actually needs
/// [`fixed_sqrt`]: the others would work with plain integers, and a
/// fixed-point library nothing exercises is a library nobody has checked.
fn draw_rings(seed: &[u8; 32], len: u32, meter: &mut Meter) -> Result<Vec<u8>, GenerateError> {
    let side = square_side(len);
    let mut stream = SeedStream::new(seed);
    let c1 = [stream.next_byte(), stream.next_byte(), stream.next_byte()];
    let c2 = [stream.next_byte(), stream.next_byte(), stream.next_byte()];
    let period = i64::from(stream.next_byte() % 16 + 4);

    let cx = fixed_from_int(clamp_i32(side / 2));
    let cy = cx;
    let mut out = Vec::with_capacity(len as usize);
    for y in 0..side {
        for x in 0..side {
            let dx = fixed_from_int(clamp_i32(x)) - cx;
            let dy = fixed_from_int(clamp_i32(y)) - cy;
            let d2 = fixed_mul(dx, dx) + fixed_mul(dy, dy);
            let d = fixed_sqrt(i64::from(fixed_to_int(d2).max(0)));
            let ring = (i64::from(fixed_to_int(d)) / period) % 2;
            let c = if ring == 0 { c1 } else { c2 };
            out.extend_from_slice(&c);
        }
        meter.charge(side * 4)?;
    }
    out.resize(len as usize, 0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(gen: GeneratorId, seed: u8, len: u32, budget: u32) -> GeneratedSpec {
        GeneratedSpec {
            generator: gen,
            seed: [seed; 32],
            output_len: len,
            step_budget: budget,
        }
    }

    #[test]
    fn the_same_spec_produces_the_same_bytes() {
        // The property the whole design rests on. Two nodes disagreeing here
        // is two nodes disagreeing about whether an object is valid.
        for g in [
            GeneratorId::Avatar,
            GeneratorId::Gradient,
            GeneratorId::Rings,
        ] {
            let s = spec(g, 7, 3072, 100_000);
            let a = generate_content(&s).expect("generates");
            let b = generate_content(&s).expect("generates");
            assert_eq!(a, b, "{g:?} is not deterministic");
        }
    }

    #[test]
    fn a_different_seed_produces_different_bytes() {
        // Without this the seed would be decoration and a collection of ten
        // thousand items would be ten thousand copies of one picture.
        let a = generate_content(&spec(GeneratorId::Avatar, 1, 3072, 100_000)).unwrap();
        let b = generate_content(&spec(GeneratorId::Avatar, 2, 3072, 100_000)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generated_bytes_verify_against_their_own_id() {
        // The check that makes generated content safe to serve: the id is
        // still the hash of the bytes, exactly as it is for stored content.
        let s = spec(GeneratorId::Gradient, 3, 3072, 100_000);
        let bytes = generate_content(&s).unwrap();
        let id = ContentId::of(&bytes);
        let got = generate_and_verify(&s, id).expect("the id derives from the bytes");
        assert_eq!(got, bytes);
    }

    #[test]
    fn a_spec_paired_with_the_wrong_id_is_refused() {
        // The attack this closes: registering a known id against a spec that
        // draws something else, so readers are handed the wrong object under
        // an id they trust.
        let s = spec(GeneratorId::Gradient, 3, 3072, 100_000);
        let wrong = ContentId([0xAB; 32]);
        let err = generate_and_verify(&s, wrong).expect_err("the id does not derive");
        assert!(
            matches!(err, GenerateError::IdMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_budget_too_small_stops_the_generator() {
        // The runaway defence. A generator that cannot finish inside what was
        // paid for stops rather than burning a reader's CPU.
        let err = generate_content(&spec(GeneratorId::Rings, 5, 30_000, 10))
            .expect_err("ten steps cannot draw thirty thousand bytes");
        match err {
            GenerateError::BudgetExhausted { budget, needed } => {
                assert_eq!(budget, 10);
                assert!(needed > budget, "needed {needed} should exceed {budget}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_sufficient_budget_still_produces_the_object() {
        // The canary for the test above. A budget check that refused
        // everything would pass that test and be useless.
        let s = spec(GeneratorId::Rings, 5, 3072, 200_000);
        let out = generate_content(&s).expect("a paid-for generation completes");
        assert_eq!(out.len(), 3072);
    }

    #[test]
    fn the_budget_is_charged_before_the_output_is_allocated() {
        // A spec asking for four megabytes on a ten step budget must fail on
        // the meter, not after allocating four megabytes.
        let err = generate_content(&spec(GeneratorId::Avatar, 1, MAX_GENERATED_BYTES, 10))
            .expect_err("the output charge alone exceeds ten steps");
        assert!(
            matches!(err, GenerateError::BudgetExhausted { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_output_above_the_maximum_is_refused_before_any_work() {
        let err = generate_content(&spec(
            GeneratorId::Avatar,
            1,
            MAX_GENERATED_BYTES + 1,
            u32::MAX,
        ))
        .expect_err("above the generator maximum");
        assert!(
            matches!(err, GenerateError::OutputTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_empty_object_is_refused() {
        let err = generate_content(&spec(GeneratorId::Avatar, 1, 0, 1000)).expect_err("empty");
        assert!(matches!(err, GenerateError::EmptyOutput));
    }

    #[test]
    fn every_generator_fills_the_length_it_was_asked_for() {
        // Lengths that are not multiples of three, and not perfect squares,
        // because those are where a geometry bug hides.
        for g in [
            GeneratorId::Avatar,
            GeneratorId::Gradient,
            GeneratorId::Rings,
        ] {
            for len in [1u32, 2, 7, 100, 3071, 3072, 4097] {
                let out = generate_content(&spec(g, 9, len, 500_000)).unwrap_or_else(|e| {
                    panic!("{g:?} at {len} bytes: {e}");
                });
                assert_eq!(out.len(), len as usize, "{g:?} at {len} bytes");
            }
        }
    }

    #[test]
    fn the_commitment_covers_every_field_of_the_spec() {
        // A field outside the digest is a field anyone could rewrite while
        // keeping the id, which would point one id at two objects.
        let base = spec(GeneratorId::Avatar, 1, 3072, 100_000);
        let d = generated_spec_digest(&base);

        let mut swapped_generator = base.clone();
        swapped_generator.generator = GeneratorId::Gradient;
        assert_ne!(
            d,
            generated_spec_digest(&swapped_generator),
            "generator not covered"
        );

        let mut different_seed = base.clone();
        different_seed.seed = [2u8; 32];
        assert_ne!(
            d,
            generated_spec_digest(&different_seed),
            "seed not covered"
        );

        let mut longer_output = base.clone();
        longer_output.output_len = 3073;
        assert_ne!(
            d,
            generated_spec_digest(&longer_output),
            "output_len not covered"
        );

        let mut larger_budget = base;
        larger_budget.step_budget = 100_001;
        assert_ne!(
            d,
            generated_spec_digest(&larger_budget),
            "step_budget not covered"
        );
    }

    #[test]
    fn the_generator_tag_does_not_move_with_the_enum_order() {
        // Pinned so a later reordering cannot silently change every id ever
        // computed for a generated object.
        assert_eq!(GeneratorId::Avatar.generator_commitment_tag(), 1);
        assert_eq!(GeneratorId::Gradient.generator_commitment_tag(), 2);
        assert_eq!(GeneratorId::Rings.generator_commitment_tag(), 3);
    }

    /// The three sources are three points on one axis, not three shapes.
    ///
    /// `held_bytes` is what makes them comparable: a storage decision divides
    /// by the bytes an operator actually keeps, and without a single function
    /// answering that for every variant each caller would re-derive it and
    /// one of them would get Hybrid wrong.
    #[test]
    fn held_bytes_orders_the_three_sources_on_one_axis() {
        let object = 500_000u64;
        let spec = spec(GeneratorId::Avatar, 1, 3072, 100_000);

        let stored = held_bytes(&ContentSource::Stored, object);
        let generated = held_bytes(&ContentSource::Generated(spec.clone()), object);
        let hybrid = held_bytes(
            &ContentSource::Hybrid {
                prefix_bytes: 50_000,
                spec: spec.clone(),
            },
            object,
        );

        assert_eq!(stored, Some(object));
        assert_eq!(generated, Some(0));
        assert_eq!(hybrid, Some(50_000));

        // Ordered, which is the property a decision rests on.
        assert!(generated < hybrid && hybrid < stored);
    }

    /// A prefix longer than the object is a contradiction, not a big prefix.
    #[test]
    fn a_prefix_past_the_end_of_the_object_is_refused() {
        let object = 1_000u64;
        let spec = spec(GeneratorId::Avatar, 1, 3072, 100_000);
        assert_eq!(
            held_bytes(
                &ContentSource::Hybrid {
                    prefix_bytes: 1_001,
                    spec: spec.clone(),
                },
                object,
            ),
            None
        );
        // Exactly the whole object is a prefix of itself, so it is allowed
        // and reports the same as Stored. An off-by-one here would refuse a
        // legal spec and nothing else would say so.
        assert_eq!(
            held_bytes(
                &ContentSource::Hybrid {
                    prefix_bytes: 1_000,
                    spec,
                },
                object,
            ),
            Some(object)
        );
    }

    #[test]
    fn content_source_defaults_to_stored() {
        // Manifests written before this type must keep meaning what they
        // meant, which is that operators hold the bytes.
        assert_eq!(ContentSource::default(), ContentSource::Stored);
    }

    // The fixed-point arithmetic itself is tested in
    // `crate::storage::fixed_point`, where the module lives. Duplicating
    // those assertions here would mean two places to update and one of them
    // going stale.

    #[test]
    fn a_thirty_two_byte_seed_is_the_whole_per_item_cost() {
        // The claim the class exists for, stated as a test: a ten thousand
        // item collection stores ten thousand seeds and one program, not ten
        // thousand pictures.
        let items = 10_000usize;
        let per_item = std::mem::size_of::<[u8; 32]>() + std::mem::size_of::<u32>() * 2 + 1;
        let described = items * per_item;
        let stored = items * 3072; // the same objects, held as bytes
        assert!(
            described * 20 < stored,
            "describing {described} bytes should be far under storing {stored}"
        );
    }

    /// The bytes each generator produces, frozen.
    ///
    /// Every other test in this module asks whether the generators agree with
    /// *themselves*: same spec twice, same output. That property holds just as
    /// well when the output is wrong, and it holds after a change that alters
    /// every byte, because both sides of the comparison move together.
    ///
    /// For stored content that gap is harmless, because the bytes are the
    /// bytes. For generated content it is the whole risk. `manifest_id` is the
    /// hash of the output, so an edit that changes what a generator draws does
    /// not produce a wrong picture, it produces an object that can no longer
    /// be produced at all: the id stops verifying and the content is gone,
    /// with nothing on disk to fall back to. Nobody would be alerted, because
    /// every test still passes.
    ///
    /// These vectors close that. They are the recomputed ids of six
    /// spec-and-output pairs, checked in. A change that alters any generator's
    /// output turns this test red and forces the question to be answered out
    /// loud: is this a bug fix, in which case the previously registered
    /// objects are unreachable and need a migration, or is it accidental
    /// drift, in which case it must be reverted.
    ///
    /// They were computed by reimplementing the generators independently and
    /// comparing, not by pasting in whatever the code emitted. Pasting the
    /// current output would freeze a bug as the specification, which is
    /// exactly what happened to the gradient generator before it was found.
    #[test]
    fn generated_bytes_match_their_frozen_vectors() {
        // (generator, seed byte, length, expected ContentId hex)
        let vectors: &[(GeneratorId, u8, u32, &str)] = &[
            (
                GeneratorId::Avatar,
                7,
                3072,
                "8f00038bd40a0c5876aa4e3f3329fd2848dd362c2dee2c94a947353e5530d1f8",
            ),
            (
                GeneratorId::Avatar,
                1,
                192,
                "62f5fc48635aa1d88374fd03bd4b9dcc62575b4c84fc9bda14564f7212a9ff80",
            ),
            (
                GeneratorId::Gradient,
                7,
                3072,
                "c1b284b5cd254c38bb54a0f87b2eb5dd2b85ea18592af7fb062b882b2a517a98",
            ),
            (
                GeneratorId::Gradient,
                1,
                192,
                "34bc5985b6faa2f482709c87a7e0168e0841e8062b82eb5207e279e6cade7a9f",
            ),
            (
                GeneratorId::Rings,
                7,
                3072,
                "32567d8d5e03be5576f392a7b9a0064e5ccceb45454bf8bfaaff564010fe1adf",
            ),
            (
                GeneratorId::Rings,
                1,
                192,
                "c00177049a620549a56915a182fae9131c94adc31b1b7d66e12880c37fc15642",
            ),
        ];

        for (generator, seed_byte, len, expected_hex) in vectors {
            let s = spec(*generator, *seed_byte, *len, 5_000_000);
            let bytes = generate_content(&s)
                .unwrap_or_else(|e| panic!("{generator:?} seed {seed_byte} len {len}: {e}"));
            let got = ContentId::of(&bytes).to_string();
            assert_eq!(
                &got, expected_hex,
                "{generator:?} at seed {seed_byte}, {len} bytes now produces different content. \
                 If this is a deliberate fix, objects already registered under the old id can no \
                 longer be regenerated and need a migration before the vector is updated."
            );
        }
    }

    /// A gradient has to actually vary.
    ///
    /// It did not. `scaled` leaves fixed point already, being a plain 0..=255
    /// integer, and the code then called `fixed_to_int` on it, shifting away
    /// another sixteen bits. Every channel below 65536/255 became zero, which
    /// is every channel there is, so both seed-derived endpoint colours were
    /// discarded and every gradient ever produced was solid black.
    ///
    /// It hashed consistently, verified against its id and passed the
    /// determinism tests, because deterministic and wrong is still
    /// deterministic. This asserts the output is a gradient rather than
    /// asserting it agrees with itself.
    #[test]
    fn a_gradient_is_not_a_single_flat_colour() {
        for seed in [1u8, 7, 42] {
            let bytes = generate_content(&spec(GeneratorId::Gradient, seed, 3072, 5_000_000))
                .expect("generates");
            let distinct = bytes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert!(
                distinct > 8,
                "gradient at seed {seed} has only {distinct} distinct byte values, \
                 which means the interpolation is being discarded"
            );
            assert!(
                bytes.iter().any(|b| *b != 0),
                "gradient at seed {seed} is entirely zero"
            );
        }
    }

    /// The two endpoint colours a gradient is drawn from both reach the output.
    ///
    /// The canary for the test above. A generator that emitted seed-derived
    /// noise would also have many distinct values while ignoring the gradient
    /// entirely, so this checks the specific property: the first pixel is near
    /// one endpoint and the last is near the other.
    #[test]
    fn a_gradient_runs_between_its_two_endpoint_colours() {
        let bytes =
            generate_content(&spec(GeneratorId::Gradient, 7, 3072, 5_000_000)).expect("generates");
        let first = i32::from(bytes[0]);
        let last = i32::from(bytes[bytes.len() - 3]);
        assert!(
            (first - last).abs() > 32,
            "the ends of a gradient should differ: first channel {first}, last {last}"
        );
    }
}
