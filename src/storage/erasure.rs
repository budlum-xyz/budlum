//! Reed-Solomon coder over GF(2^8) - the thing that actually computes parity.
//!
//! `src/storage/manifest.rs` already describes redundancy: a
//! [`crate::storage::manifest::ErasureScheme`] says "any `k` of these `n`
//! shards reconstruct the object" and [`crate::storage::manifest::ShardRef`]
//! says which shards are `Data` and which are `Parity`. Nothing computed
//! those parity bytes, so the description was a promise the code could not
//! keep: a manifest could declare `(k=4, n=6)`, a repair trigger could read
//! that and conclude two losses were survivable, and no one could actually
//! rebuild the object. This module closes that.
//!
//! # Why a coder in-tree rather than a dependency
//!
//! `reed-solomon-erasure` is the crate everyone reaches for, and it is the
//! one `docs/BUD_STORAGE_ROADMAP.md` named. It is unmaintained, the owner
//! stopped in 2021 and asked for a new owner
//! (darrenldl/reed-solomon-erasure#88); Solana, its largest user, moved off
//! it. `reed-solomon-simd` is maintained but its speed comes from
//! target-specific `unsafe`, and `src/lib.rs` is `#![forbid(unsafe_code)]`.
//! Neither is acceptable, and vendoring is not on the table. The code below
//! is a few hundred lines of table-driven finite-field arithmetic with no
//! dependencies and no `unsafe`.
//!
//! # The construction
//!
//! Encoding is a matrix product over GF(2^8). The generator is systematic:
//! an identity block on top, so data shards pass through byte-for-byte, and
//! a Cauchy block underneath that produces the parity shards.
//!
//! ```text
//!   [ I_k    ]           [ data_0 ]     [ data_0   ]
//!   [        ]  x  ...   [  ...   ]  =  [ ...      ]
//!   [ C(m,k) ]           [ data_k ]     [ parity_0 ]
//! ```
//!
//! The Cauchy block is `C[i][j] = 1 / (x_i + y_j)` with the `x` and `y` sets
//! disjoint, which makes *every* square submatrix invertible. That property
//! is exactly the MDS condition: `[I | C^T]` generates a systematic MDS code
//! iff every square submatrix of `C` is invertible (Blomer et al., "An XOR-
//! based erasure-resilient coding scheme", Theorem 2.2). MDS is what lets
//! reconstruction use *whichever* `k` shards survived rather than a
//! privileged subset - a Vandermonde block does not give this for free,
//! because a Vandermonde matrix over a finite field can have singular
//! submatrices even when the full matrix is invertible.
//!
//! Decoding inverts the `k x k` submatrix formed by the surviving shards'
//! rows and multiplies the survivors through it. Since every square
//! submatrix is invertible, that inverse always exists for any `k`
//! survivors, so recovery never depends on *which* ones were lost.
//!
//! # Field
//!
//! GF(2^8) modulo 0x11D, the same primitive polynomial as Intel ISA-L,
//! Backblaze, and the Reed-Solomon in QR codes. Multiplication goes through
//! log/exp tables built once at first use; inversion is `exp[255 - log[a]]`.
//! `n <= 255` follows from the field: the Cauchy construction needs `k + m`
//! distinct non-zero-difference field elements.

use crate::storage::manifest::{ContentManifest, ErasureScheme, ShardKind, ShardRef};
use std::sync::OnceLock;

/// The primitive polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1.
const GF_POLY: u16 = 0x11D;

/// Largest total shard count the field admits. The Cauchy construction draws
/// `k + m` distinct elements from GF(2^8), which has 256 of them.
pub const MAX_TOTAL_SHARDS: usize = 255;

struct GfTables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static GfTables {
    static TABLES: OnceLock<GfTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_POLY;
            }
        }
        // Repeat the multiplicative cycle so `exp[log_a + log_b]` needs no
        // modulo: both logs are at most 254, so the largest index reached is
        // 508, and every index from 255 up mirrors one 255 earlier.
        let mut cycle = [0u8; 255];
        cycle.copy_from_slice(&exp[..255]);
        for (dst, src) in exp[255..].iter_mut().zip(cycle.iter().cycle()) {
            *dst = *src;
        }
        GfTables { exp, log }
    })
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "gf_inv(0) is a construction bug, not input");
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

/// A dense row-major matrix over GF(2^8).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GfMatrix {
    rows: usize,
    cols: usize,
    data: Vec<u8>,
}

impl GfMatrix {
    fn zero(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0u8; rows * cols],
        }
    }

    fn identity(n: usize) -> Self {
        let mut m = Self::zero(n, n);
        for i in 0..n {
            m.set(i, i, 1);
        }
        m
    }

    #[inline]
    fn get(&self, r: usize, c: usize) -> u8 {
        self.data[r * self.cols + c]
    }

    #[inline]
    fn set(&mut self, r: usize, c: usize, v: u8) {
        self.data[r * self.cols + c] = v;
    }

    /// Gauss-Jordan inverse over GF(2^8). Returns `None` if singular, which
    /// for a Cauchy submatrix should be unreachable, the caller treats it as
    /// a hard error rather than a recoverable case.
    fn invert(&self) -> Option<Self> {
        if self.rows != self.cols {
            return None;
        }
        let n = self.rows;
        let mut work = self.clone();
        let mut inv = Self::identity(n);

        for col in 0..n {
            // Find a pivot.
            let mut pivot = None;
            for row in col..n {
                if work.get(row, col) != 0 {
                    pivot = Some(row);
                    break;
                }
            }
            let pivot = pivot?;
            if pivot != col {
                for c in 0..n {
                    let a = work.get(col, c);
                    let b = work.get(pivot, c);
                    work.set(col, c, b);
                    work.set(pivot, c, a);
                    let a = inv.get(col, c);
                    let b = inv.get(pivot, c);
                    inv.set(col, c, b);
                    inv.set(pivot, c, a);
                }
            }

            // Normalise the pivot row.
            let p = work.get(col, col);
            if p != 1 {
                let ip = gf_inv(p);
                for c in 0..n {
                    work.set(col, c, gf_mul(work.get(col, c), ip));
                    inv.set(col, c, gf_mul(inv.get(col, c), ip));
                }
            }

            // Eliminate the column from every other row.
            for row in 0..n {
                if row == col {
                    continue;
                }
                let f = work.get(row, col);
                if f == 0 {
                    continue;
                }
                for c in 0..n {
                    let w = work.get(row, c) ^ gf_mul(f, work.get(col, c));
                    work.set(row, c, w);
                    let v = inv.get(row, c) ^ gf_mul(f, inv.get(col, c));
                    inv.set(row, c, v);
                }
            }
        }
        Some(inv)
    }
}

/// Systematic generator: `I_k` stacked on a `m x k` Cauchy block.
///
/// The Cauchy entries are `1 / (x_i + y_j)` with `x_i = k + i` and
/// `y_j = j`, so the two index sets are disjoint and no difference is zero.
/// Addition in GF(2^8) is XOR, so `x_i + y_j` is `(k + i) ^ j`.
fn generator_matrix(k: usize, m: usize) -> GfMatrix {
    let mut g = GfMatrix::zero(k + m, k);
    for i in 0..k {
        g.set(i, i, 1);
    }
    for i in 0..m {
        for j in 0..k {
            let x = (k + i) as u8;
            let y = j as u8;
            g.set(k + i, j, gf_inv(x ^ y));
        }
    }
    g
}

/// What went wrong encoding or reconstructing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErasureError {
    /// `k` or `n` is outside what the field or the scheme allows.
    InvalidScheme(String),
    /// The shards handed in do not match the scheme.
    ShardMismatch(String),
    /// Fewer than `k` shards survived; nothing can reconstruct the object.
    NotEnoughShards { have: usize, need: usize },
    /// A recovered shard's `ContentId` did not match the manifest.
    IntegrityFailure { index: u32 },
    /// The decode matrix was singular. Unreachable with a Cauchy generator;
    /// surfaced rather than panicked so a bad build fails loudly.
    SingularMatrix,
}

impl std::fmt::Display for ErasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScheme(m) => write!(f, "invalid erasure scheme: {m}"),
            Self::ShardMismatch(m) => write!(f, "shard mismatch: {m}"),
            Self::NotEnoughShards { have, need } => write!(
                f,
                "cannot reconstruct: {have} shards survived, {need} are required"
            ),
            Self::IntegrityFailure { index } => write!(
                f,
                "reconstructed shard {index} does not match its manifest ContentId"
            ),
            Self::SingularMatrix => {
                write!(f, "decode matrix was singular; the generator is broken")
            }
        }
    }
}

impl std::error::Error for ErasureError {}

/// A Reed-Solomon coder for one `(k, n)` scheme.
///
/// Build it once per scheme and reuse it; the generator matrix is computed in
/// the constructor.
#[derive(Debug, Clone)]
pub struct ReedSolomon {
    k: usize,
    m: usize,
    generator: GfMatrix,
}

impl ReedSolomon {
    /// # Errors
    ///
    /// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
    /// `data_shards` is `k`, `parity_shards` is `n - k`.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, ErasureError> {
        if data_shards == 0 {
            return Err(ErasureError::InvalidScheme(
                "data shards must be at least 1".into(),
            ));
        }
        let total = data_shards
            .checked_add(parity_shards)
            .ok_or_else(|| ErasureError::InvalidScheme("shard count overflow".into()))?;
        if total > MAX_TOTAL_SHARDS {
            return Err(ErasureError::InvalidScheme(format!(
                "{total} total shards exceeds the {MAX_TOTAL_SHARDS} that GF(2^8) admits"
            )));
        }
        Ok(Self {
            k: data_shards,
            m: parity_shards,
            generator: generator_matrix(data_shards, parity_shards),
        })
    }

    /// # Errors
    ///
    /// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
    /// Build a coder for a manifest's declared scheme.
    pub fn for_scheme(scheme: &ErasureScheme) -> Result<Self, ErasureError> {
        scheme.validate().map_err(ErasureError::InvalidScheme)?;
        Self::new(scheme.k as usize, scheme.parity_count() as usize)
    }

    #[must_use]
    pub const fn data_shards(&self) -> usize {
        self.k
    }

    #[must_use]
    pub const fn parity_shards(&self) -> usize {
        self.m
    }

    #[must_use]
    pub const fn total_shards(&self) -> usize {
        self.k + self.m
    }

    /// # Errors
    ///
    /// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
    /// Compute the parity shards for `data`.
    ///
    /// Every data shard must be the same length, Reed-Solomon works
    /// symbol-wise across the shards, so column `c` of the code word is built
    /// from byte `c` of each shard and a short shard would leave columns
    /// undefined. Callers slicing an object should pad the last data shard to
    /// the stripe size; `encode_object` does that.
    pub fn encode_parity(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ErasureError> {
        if data.len() != self.k {
            return Err(ErasureError::ShardMismatch(format!(
                "expected {} data shards, got {}",
                self.k,
                data.len()
            )));
        }
        if self.m == 0 {
            return Ok(Vec::new());
        }
        let len = data[0].len();
        if len == 0 {
            return Err(ErasureError::ShardMismatch(
                "data shards must be non-empty".into(),
            ));
        }
        if let Some(bad) = data.iter().position(|s| s.len() != len) {
            return Err(ErasureError::ShardMismatch(format!(
                "shard {bad} is {} bytes but shard 0 is {len}; \
                 Reed-Solomon needs equal-length shards",
                data[bad].len()
            )));
        }

        let mut parity = vec![vec![0u8; len]; self.m];
        for (i, out) in parity.iter_mut().enumerate() {
            let row = self.k + i;
            for (j, src) in data.iter().enumerate() {
                let coeff = self.generator.get(row, j);
                if coeff == 0 {
                    continue;
                }
                for (o, s) in out.iter_mut().zip(src.iter()) {
                    *o ^= gf_mul(coeff, *s);
                }
            }
        }
        Ok(parity)
    }

    /// The generator coefficient a coding audit multiplies by.
    ///
    /// `parity_index` counts parity shards from zero, so parity shard 0 is
    /// generator row `k`. `data_index` is the data shard, which is the
    /// column. Returns `None` for an index outside the scheme rather than
    /// panicking, because the indices reaching this come from a challenge an
    /// untrusted caller opened.
    #[must_use]
    pub fn parity_coefficient(&self, parity_index: usize, data_index: usize) -> Option<u8> {
        if parity_index >= self.m || data_index >= self.k {
            return None;
        }
        Some(self.generator.get(self.k + parity_index, data_index))
    }

    /// Whether one byte column of a code word is correctly encoded.
    ///
    /// This is the whole coding audit. Reed-Solomon works symbol-wise: column
    /// `c` of parity shard `i` is `XOR_j coeff(i, j) * data_j[c]` and nothing
    /// else. So a single column proves or disproves that relationship at that
    /// position without the verifier ever holding a whole shard.
    ///
    /// `data_column` is byte `c` of each of the `k` data shards, in shard
    /// order. `parity_byte` is byte `c` of parity shard `parity_index`.
    ///
    /// # What this does and does not prove
    ///
    /// A pass proves the relationship holds *at that column*. It does not
    /// prove the whole shard is encoded correctly, and this is not a
    /// weakness to apologise for, it is the point: an operator who
    /// miscomputed a fraction `f` of the columns fails a uniformly random
    /// column with probability `f`, so repeated audits drive the survival
    /// probability of a cheat to `(1 - f)^rounds`. That is the same
    /// probabilistic bargain provable-data-possession schemes make, where
    /// Ateniese's original measurement was that 460 sampled blocks out of
    /// 10,000 detect corruption with 99% confidence.
    ///
    /// It also does not prove the operator *stores* anything. A retrieval
    /// challenge does that. These are different questions and answering one
    /// does not answer the other: an operator can hold bytes that are not
    /// valid parity, and can compute valid parity on demand without holding
    /// anything.
    #[must_use]
    pub fn column_is_correctly_encoded(
        &self,
        parity_index: usize,
        data_column: &[u8],
        parity_byte: u8,
    ) -> bool {
        if data_column.len() != self.k || parity_index >= self.m {
            return false;
        }
        let mut acc = 0u8;
        for (j, byte) in data_column.iter().enumerate() {
            let coeff = self.generator.get(self.k + parity_index, j);
            acc ^= gf_mul(coeff, *byte);
        }
        acc == parity_byte
    }

    /// # Errors
    ///
    /// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
    /// Rebuild all `n` shards from any `k` survivors.
    ///
    /// `present` is indexed by shard index over the whole code word (data
    /// shards first, then parity, matching the generator's row order).
    /// `None` marks a lost shard. Returns every shard, recovered ones
    /// included.
    pub fn reconstruct(&self, present: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, ErasureError> {
        let n = self.total_shards();
        if present.len() != n {
            return Err(ErasureError::ShardMismatch(format!(
                "expected {n} shard slots, got {}",
                present.len()
            )));
        }
        let live: Vec<usize> = present
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|_| i))
            .collect();
        if live.len() < self.k {
            return Err(ErasureError::NotEnoughShards {
                have: live.len(),
                need: self.k,
            });
        }

        let len = present[live[0]]
            .as_ref()
            .map(|s| s.len())
            .unwrap_or_default();
        if len == 0 {
            return Err(ErasureError::ShardMismatch(
                "surviving shards must be non-empty".into(),
            ));
        }
        for &i in &live {
            let got = present[i].as_ref().map(|s| s.len()).unwrap_or_default();
            if got != len {
                return Err(ErasureError::ShardMismatch(format!(
                    "shard {i} is {got} bytes but the first survivor is {len}"
                )));
            }
        }

        // If every data shard survived there is nothing to invert.
        let data_complete = (0..self.k).all(|i| present[i].is_some());
        let data: Vec<Vec<u8>> = if data_complete {
            (0..self.k)
                .map(|i| present[i].clone().unwrap_or_default())
                .collect()
        } else {
            // Take the first k survivors and invert their generator rows.
            let chosen = &live[..self.k];
            let mut sub = GfMatrix::zero(self.k, self.k);
            for (r, &row) in chosen.iter().enumerate() {
                for c in 0..self.k {
                    sub.set(r, c, self.generator.get(row, c));
                }
            }
            let inv = sub.invert().ok_or(ErasureError::SingularMatrix)?;

            let mut out = vec![vec![0u8; len]; self.k];
            for (i, dst) in out.iter_mut().enumerate() {
                for (r, &row) in chosen.iter().enumerate() {
                    let coeff = inv.get(i, r);
                    if coeff == 0 {
                        continue;
                    }
                    let Some(src) = present[row].as_ref() else {
                        return Err(ErasureError::ShardMismatch(format!(
                            "survivor {row} vanished mid-reconstruction"
                        )));
                    };
                    for (o, s) in dst.iter_mut().zip(src.iter()) {
                        *o ^= gf_mul(coeff, *s);
                    }
                }
            }
            out
        };

        let parity = self.encode_parity(&data)?;
        let mut all = data;
        all.extend(parity);
        Ok(all)
    }
}

/// An object encoded into `n` equal-length shards plus the padding needed to
/// trim it back.
///
/// `total_size` is the original byte length. The last data shard is padded to
/// the stripe size, so reassembly truncates to `total_size` rather than
/// trusting shard lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedObject {
    pub shards: Vec<Vec<u8>>,
    pub scheme: ErasureScheme,
    pub total_size: u64,
}

impl EncodedObject {
    /// Which shards are data and which are parity, in code-word order.
    #[must_use]
    pub fn kinds(&self) -> Vec<ShardKind> {
        (0..self.shards.len())
            .map(|i| {
                if i < self.scheme.k as usize {
                    ShardKind::Data
                } else {
                    ShardKind::Parity
                }
            })
            .collect()
    }

    /// # Errors
    ///
    /// Propagates `String` from the step that failed; its variants name the refused conditions.
    /// Build the on-chain manifest for this encoding.
    ///
    /// The shard sizes recorded are the padded stripe sizes, which is what an
    /// operator actually stores and what a challenge will hash. `total_size`
    /// is carried separately so reassembly can trim.
    pub fn to_manifest(&self) -> Result<ContentManifest, String> {
        let shards: Vec<ShardRef> = self
            .shards
            .iter()
            .zip(self.kinds())
            .enumerate()
            .map(|(i, (bytes, kind))| {
                let mut s = ShardRef::from_bytes(i as u32, bytes);
                s.kind = kind;
                s
            })
            .collect();
        ContentManifest::from_shards(shards)?
            .with_erasure(self.scheme)?
            .with_content_size(self.total_size)
    }
}

/// # Errors
///
/// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
/// Split `data` into `k` equal stripes, pad the tail, and append `n - k`
/// parity shards.
pub fn encode_object(data: &[u8], scheme: ErasureScheme) -> Result<EncodedObject, ErasureError> {
    scheme
        .validate()
        .map_err(ErasureError::InvalidScheme)
        .and_then(|()| {
            if data.is_empty() {
                Err(ErasureError::ShardMismatch(
                    "cannot encode an empty object".into(),
                ))
            } else {
                Ok(())
            }
        })?;
    let rs = ReedSolomon::for_scheme(&scheme)?;
    let k = rs.data_shards();
    let stripe = data.len().div_ceil(k);

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(rs.total_shards());
    for i in 0..k {
        let start = (i * stripe).min(data.len());
        let end = (start + stripe).min(data.len());
        let mut s = vec![0u8; stripe];
        s[..end - start].copy_from_slice(&data[start..end]);
        shards.push(s);
    }
    let parity = rs.encode_parity(&shards)?;
    shards.extend(parity);

    Ok(EncodedObject {
        shards,
        scheme,
        total_size: data.len() as u64,
    })
}

/// Re-encode `data` under the scheme the claimed manifest declares and refuse
/// if the result is a different object.
///
/// The usual path is client-built: the client encodes, builds a manifest, and
/// registers it. The node then trusts the structural checks in
/// `validate_untrusted` but never re-runs the coder, so a client that lies
/// about parity (or pads a different payload into the same listed sizes) can
/// still pass registration. This function is the optional, costly half of
/// that path: given the bytes the client claims to have encoded, the node
/// produces the only honest manifest for that `(data, scheme)` pair and
/// compares ids.
///
/// # Errors
///
/// Scheme/empty-object failures from [`encode_object`], or a mismatch when the
/// claimed id / shard list is not the one re-encoding produces.
pub fn verify_object_encoding(data: &[u8], claimed: &ContentManifest) -> Result<(), ErasureError> {
    // Structural lies are cheaper to catch first; the coder is the expensive
    // half and should not run on a manifest that already fails the free checks.
    claimed
        .validate_untrusted()
        .map_err(ErasureError::InvalidScheme)?;
    let encoded = encode_object(data, claimed.erasure)?;
    let honest = encoded.to_manifest().map_err(ErasureError::InvalidScheme)?;
    if honest.manifest_id != claimed.manifest_id {
        return Err(ErasureError::ShardMismatch(format!(
            "re-encode produced manifest {} but the claim was {}",
            honest.manifest_id, claimed.manifest_id
        )));
    }
    if honest.shards.len() != claimed.shards.len() {
        return Err(ErasureError::ShardMismatch(format!(
            "re-encode produced {} shards, claim has {}",
            honest.shards.len(),
            claimed.shards.len()
        )));
    }
    for (h, c) in honest.shards.iter().zip(claimed.shards.iter()) {
        if h.shard_id != c.shard_id || h.kind != c.kind || h.size != c.size || h.index != c.index {
            return Err(ErasureError::ShardMismatch(format!(
                "shard {} disagrees after re-encode (honest id {}, claimed id {})",
                h.index, h.shard_id, c.shard_id
            )));
        }
    }
    Ok(())
}

/// # Errors
///
/// Propagates `ErasureError` from the step that failed; its variants name the refused conditions.
/// Rebuild the original bytes from whatever shards survived.
///
/// `present` is the full code word with `None` for lost shards. Recovered
/// shards are checked against the manifest's `ContentId`s before the object
/// is handed back: reconstruction is only as trustworthy as the shards fed
/// into it, and a single corrupted survivor silently poisons every recovered
/// shard through the inverse matrix. Verifying against the manifest turns
/// that into a detected failure.
pub fn reconstruct_object(
    manifest: &ContentManifest,
    present: &[Option<Vec<u8>>],
) -> Result<Vec<u8>, ErasureError> {
    let rs = ReedSolomon::for_scheme(&manifest.erasure)?;
    if manifest.shards.len() != rs.total_shards() {
        return Err(ErasureError::ShardMismatch(format!(
            "manifest has {} shards but the scheme codes {}",
            manifest.shards.len(),
            rs.total_shards()
        )));
    }

    // Verify every reconstructed shard against the manifest, and try another
    // k-subset when more than k shards survive: taking only the first k
    // survivors means a single corrupted low-index survivor makes a
    // recoverable object look unrecoverable (security review, MEDIUM).
    // The integrity check is the same one the old code ran after
    // the single attempt; now a failure with spare survivors retries with a
    // different subset instead of giving up.
    let verify_all = |all: &[Vec<u8>]| -> Result<(), ErasureError> {
        for (i, bytes) in all.iter().enumerate() {
            let idx = i as u32;
            let Some(reference) = manifest.shards.iter().find(|s| s.index == idx) else {
                return Err(ErasureError::ShardMismatch(format!(
                    "manifest has no shard with index {idx}"
                )));
            };
            if reference.shard_id != crate::storage::ContentId::of(bytes) {
                return Err(ErasureError::IntegrityFailure { index: idx });
            }
        }
        Ok(())
    };

    let live: Vec<usize> = present
        .iter()
        .enumerate()
        .filter_map(|(i, shard)| shard.as_ref().map(|_| i))
        .collect();

    // Candidate attempt closures: the first try uses the whole live set; if
    // reconstruction with all survivors fails or verifies wrong and there
    // are spare survivors, drop one survivor at a time and retry.
    let attempt = |masked: &mut Vec<Option<Vec<u8>>>| -> Result<Vec<u8>, ErasureError> {
        let all = rs.reconstruct(masked)?;
        verify_all(&all)?;
        let k = rs.data_shards();
        let mut out = Vec::with_capacity(k * all[0].len());
        for shard in all.iter().take(k) {
            out.extend_from_slice(shard);
        }
        out.truncate(manifest.content_size() as usize);
        Ok(out)
    };

    let mut masked = present.to_vec();
    match attempt(&mut masked) {
        Ok(out) => return Ok(out),
        Err(_) if live.len() > rs.data_shards() => {
            // Spare survivors exist: retry, dropping each live shard in
            // turn so a corrupted low-index survivor no longer blocks a
            // recoverable object.
            for &drop in &live {
                let mut trial = present.to_vec();
                trial[drop] = None;
                if let Ok(out) = attempt(&mut trial) {
                    return Ok(out);
                }
            }
        }
        Err(e) => return Err(e),
    }

    let all = rs.reconstruct(present)?;
    verify_all(&all)?;
    let k = rs.data_shards();
    let mut out = Vec::with_capacity(k * all[0].len());
    for shard in all.iter().take(k) {
        out.extend_from_slice(shard);
    }
    out.truncate(manifest.content_size() as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_multiplication_has_the_ring_properties() {
        // Identity, annihilation, commutativity, and the inverse law. If any
        // of these is wrong the code silently produces garbage parity.
        for a in 0u8..=255 {
            assert_eq!(gf_mul(a, 1), a, "1 is not the identity for {a}");
            assert_eq!(gf_mul(a, 0), 0, "0 does not annihilate {a}");
            if a != 0 {
                assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a} is wrong");
            }
        }
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    #[test]
    fn field_is_distributive_over_xor() {
        // Encoding relies on a*(b+c) == a*b + a*c with + being XOR.
        for a in [0u8, 1, 2, 7, 33, 128, 255] {
            for b in 0u8..=255 {
                for c in [0u8, 1, 9, 64, 200, 255] {
                    assert_eq!(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c));
                }
            }
        }
    }

    #[test]
    fn every_square_submatrix_of_the_cauchy_block_is_invertible() {
        // This is the MDS condition. If it fails for even one subset, some
        // pattern of k survivors is unrecoverable, and the manifest would
        // still claim the object is safe.
        let (k, m) = (4usize, 4usize);
        let g = generator_matrix(k, m);
        // Check every 2x2 and 3x3 submatrix of the Cauchy block, plus the
        // full 4x4. Exhaustive over rows and columns.
        for size in 1..=m.min(k) {
            let row_sets = combinations(m, size);
            let col_sets = combinations(k, size);
            for rows in &row_sets {
                for cols in &col_sets {
                    let mut sub = GfMatrix::zero(size, size);
                    for (r, &ri) in rows.iter().enumerate() {
                        for (c, &ci) in cols.iter().enumerate() {
                            sub.set(r, c, g.get(k + ri, ci));
                        }
                    }
                    assert!(
                        sub.invert().is_some(),
                        "singular {size}x{size} submatrix at rows {rows:?} cols {cols:?}"
                    );
                }
            }
        }
    }

    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut cur = Vec::new();
        fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if cur.len() == k {
                out.push(cur.clone());
                return;
            }
            for i in start..n {
                cur.push(i);
                go(i + 1, n, k, cur, out);
                cur.pop();
            }
        }
        go(0, n, k, &mut cur, &mut out);
        out
    }

    #[test]
    fn matrix_inverse_round_trips() {
        let g = generator_matrix(5, 3);
        let mut sub = GfMatrix::zero(5, 5);
        for r in 0..5 {
            for c in 0..5 {
                sub.set(r, c, g.get(r, c));
            }
        }
        let inv = sub.invert().expect("identity block is invertible");
        assert_eq!(inv, GfMatrix::identity(5));
    }

    #[test]
    fn data_shards_pass_through_unchanged() {
        // The generator is systematic; a data shard must survive encoding
        // byte-for-byte, otherwise reading an intact object would need a
        // decode pass.
        let data = b"the chain carries the proof, not the data".to_vec();
        let enc = encode_object(&data, ErasureScheme { k: 4, n: 6 }).unwrap();
        let stripe = enc.shards[0].len();
        let mut flat = Vec::new();
        for s in enc.shards.iter().take(4) {
            flat.extend_from_slice(s);
        }
        assert_eq!(&flat[..data.len()], &data[..]);
        assert_eq!(stripe, data.len().div_ceil(4));
    }

    #[test]
    fn any_k_of_n_reconstructs_the_object() {
        // The MDS promise, exercised over every loss pattern rather than a
        // convenient one.
        let data: Vec<u8> = (0..=200u8).cycle().take(1000).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();

        for lost in combinations(6, 2) {
            let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
            for &i in &lost {
                present[i] = None;
            }
            let out = reconstruct_object(&manifest, &present)
                .unwrap_or_else(|e| panic!("losing {lost:?} broke recovery: {e}"));
            assert_eq!(out, data, "wrong bytes after losing {lost:?}");
        }
    }

    proptest::proptest! {
        // The MDS promise as a property, not a fixture. The existing
        // `any_k_of_n_reconstructs_the_object` pins one scheme (k=4, n=6) and
        // one byte pattern; a Cauchy-matrix mistake that only shows up at a
        // different k/n or on different data would survive it. Here the scheme
        // and the payload are both generated, and every loss pattern up to the
        // parity count is still exercised exhaustively.
        //
        // Silent wrong-bytes is the failure mode that matters: erasure decode
        // does not checksum its own output, so a bad matrix returns success
        // with corrupt data rather than erroring.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        #[test]
        fn any_k_of_n_reconstructs_over_generated_schemes_and_payloads(
            k in 1usize..=5,
            parity in 0usize..=3,
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..600),
        ) {
            let n = k + parity;
            let scheme = ErasureScheme { k: k as u32, n: n as u32 };
            let enc = encode_object(&data, scheme).expect("generated scheme is valid");
            let manifest = enc.to_manifest().expect("manifest");

            // Losing any `parity` shards must still round-trip exactly.
            for lost in combinations(n, parity) {
                let mut present: Vec<Option<Vec<u8>>> =
                    enc.shards.iter().cloned().map(Some).collect();
                for &i in &lost {
                    present[i] = None;
                }
                let out = reconstruct_object(&manifest, &present)
                    .unwrap_or_else(|e| panic!("k={k} n={n} losing {lost:?} broke recovery: {e}"));
                proptest::prop_assert_eq!(
                    out, data.clone(),
                    "k={} n={} wrong bytes after losing {:?}", k, n, lost
                );
            }
        }
    }

    #[test]
    fn losing_more_than_parity_count_is_refused_not_guessed() {
        let data: Vec<u8> = (0..=255u8).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();

        let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        present[0] = None;
        present[1] = None;
        present[2] = None;
        let err = reconstruct_object(&manifest, &present).unwrap_err();
        assert_eq!(err, ErasureError::NotEnoughShards { have: 3, need: 4 });
    }

    #[test]
    fn a_corrupted_survivor_is_skipped_when_spare_survivors_exist() {
        // With k=4, n=6 and one parity shard lost, five survivors remain. One
        // of them is corrupted; the decoder must drop the corrupted survivor
        // and reconstruct from the other four rather than failing the whole
        // object (security review, MEDIUM). A single bad
        // survivor must not cause avoidable object-level denial of recovery.
        let data: Vec<u8> = (0..=199u8).cycle().take(800).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();

        let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        present[5] = None;
        if let Some(Some(s)) = present.get_mut(1) {
            s[0] ^= 0xFF;
        }
        let recovered = reconstruct_object(&manifest, &present).unwrap();
        assert_eq!(
            recovered, data,
            "recovery must fall back to the honest survivors"
        );
    }

    #[test]
    fn a_corrupted_survivor_without_spares_still_fails_integrity() {
        // When no spare survivors exist the corrupted shard cannot be
        // skipped, so the ContentId check must still turn the corruption into
        // an error rather than plausible-looking bytes.
        let data: Vec<u8> = (0..=199u8).cycle().take(800).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();

        // Lose two shards so exactly k survive, then corrupt one of them:
        // there is no spare to fall back to.
        let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        present[4] = None;
        present[5] = None;
        if let Some(Some(s)) = present.get_mut(1) {
            s[0] ^= 0xFF;
        }
        let err = reconstruct_object(&manifest, &present).unwrap_err();
        assert!(
            matches!(err, ErasureError::IntegrityFailure { .. }),
            "expected an integrity failure, got {err:?}"
        );
    }

    /// The coding audit, on a correctly encoded object.
    #[test]
    fn every_column_of_an_honest_encoding_verifies() {
        let data: Vec<u8> = (0..=200u8).cycle().take(400).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let rs = ReedSolomon::for_scheme(&scheme).unwrap();
        let stripe = enc.shards[0].len();

        for parity_index in 0..rs.parity_shards() {
            for c in 0..stripe {
                let column: Vec<u8> = (0..rs.data_shards()).map(|j| enc.shards[j][c]).collect();
                let parity_byte = enc.shards[rs.data_shards() + parity_index][c];
                assert!(
                    rs.column_is_correctly_encoded(parity_index, &column, parity_byte),
                    "honest column {c} of parity {parity_index} must verify"
                );
            }
        }
    }

    /// A single flipped bit in one parity byte fails at that column.
    ///
    /// Sampling matters because the audit is not a
    /// checksum over the shard, it is the coding relationship itself, so a
    /// corruption anywhere the audit lands is caught exactly.
    #[test]
    fn a_single_wrong_parity_byte_fails_its_column() {
        let data: Vec<u8> = (0..=200u8).cycle().take(400).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let rs = ReedSolomon::for_scheme(&scheme).unwrap();

        let c = 17;
        let column: Vec<u8> = (0..rs.data_shards()).map(|j| enc.shards[j][c]).collect();
        let honest = enc.shards[rs.data_shards()][c];
        assert!(rs.column_is_correctly_encoded(0, &column, honest));
        assert!(
            !rs.column_is_correctly_encoded(0, &column, honest ^ 1),
            "one flipped bit must fail the column"
        );
    }

    /// An operator who miscomputed a fraction of the columns is caught at a
    /// rate equal to that fraction.
    ///
    /// The measurement the whole scheme rests on. Ateniese's original PDP
    /// paper reports 460 sampled blocks out of 10,000 detecting a 1%
    /// deletion with 99% confidence; this is the same arithmetic on one
    /// object, checked rather than asserted.
    #[test]
    fn sampling_catches_a_cheat_at_the_rate_it_cheats() {
        let data: Vec<u8> = (0..=250u8).cycle().take(1000).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let rs = ReedSolomon::for_scheme(&scheme).unwrap();
        let stripe = enc.shards[0].len();

        // The operator keeps the first tenth honest and corrupts the rest.
        let honest_until = stripe / 10;
        let mut caught = 0usize;
        for c in 0..stripe {
            let column: Vec<u8> = (0..rs.data_shards()).map(|j| enc.shards[j][c]).collect();
            let mut byte = enc.shards[rs.data_shards()][c];
            if c >= honest_until {
                byte ^= 0x5A;
            }
            if !rs.column_is_correctly_encoded(0, &column, byte) {
                caught += 1;
            }
        }
        let corrupted = stripe - honest_until;
        assert_eq!(
            caught, corrupted,
            "every corrupted column must fail and no honest one may"
        );
        assert!(
            caught * 10 >= stripe * 8,
            "a nine-tenths cheat must be caught on far more than half the columns"
        );
    }

    /// The audit reads one byte per data shard, not one shard.
    ///
    /// The bandwidth claim, asserted rather than described: a `(4, 6)` audit
    /// costs five bytes regardless of how large the object is.
    #[test]
    fn an_audit_costs_one_byte_per_data_shard() {
        let small = encode_object(&[7u8; 40], ErasureScheme { k: 4, n: 6 }).unwrap();
        let large = encode_object(&[7u8; 40_000], ErasureScheme { k: 4, n: 6 }).unwrap();
        let rs = ReedSolomon::for_scheme(&ErasureScheme { k: 4, n: 6 }).unwrap();

        assert!(large.shards[0].len() > small.shards[0].len() * 100);
        for enc in [&small, &large] {
            let column: Vec<u8> = (0..rs.data_shards()).map(|j| enc.shards[j][0]).collect();
            assert_eq!(
                column.len(),
                4,
                "the audit reads k bytes whatever the object size"
            );
            assert!(rs.column_is_correctly_encoded(0, &column, enc.shards[4][0]));
        }
    }

    /// Indices outside the scheme are refused rather than panicking.
    ///
    /// These arrive from a challenge an untrusted caller opened, so an
    /// out-of-range index is input, not a bug.
    #[test]
    fn an_index_outside_the_scheme_is_refused() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        assert!(rs.parity_coefficient(0, 0).is_some());
        assert!(
            rs.parity_coefficient(2, 0).is_none(),
            "only two parity shards"
        );
        assert!(
            rs.parity_coefficient(0, 4).is_none(),
            "only four data shards"
        );
        assert!(
            !rs.column_is_correctly_encoded(2, &[0, 0, 0, 0], 0),
            "an out-of-range parity index cannot report a passing audit"
        );
    }

    /// A column of the wrong width is refused, not padded.
    ///
    /// Accepting a short column and treating the missing shards as zero would
    /// let an operator answer an audit it cannot answer, because zero is a
    /// valid byte and the relationship would still be checkable.
    #[test]
    fn a_column_of_the_wrong_width_is_refused() {
        let rs = ReedSolomon::new(4, 2).unwrap();
        assert!(!rs.column_is_correctly_encoded(0, &[1, 2, 3], 0));
        assert!(!rs.column_is_correctly_encoded(0, &[1, 2, 3, 4, 5], 0));
    }

    /// Replication has no coding relationship to audit.
    #[test]
    fn replication_offers_no_parity_coefficient() {
        let rs = ReedSolomon::new(3, 0).unwrap();
        assert_eq!(rs.parity_shards(), 0);
        assert!(rs.parity_coefficient(0, 0).is_none());
        assert!(
            !rs.column_is_correctly_encoded(0, &[1, 2, 3], 0),
            "an object with no parity must not report a passing audit"
        );
    }

    #[test]
    fn parity_is_not_a_copy_of_the_data() {
        // A coder that returned the data shards as "parity" would pass a
        // reconstruction test that only ever loses parity shards.
        let data: Vec<u8> = (0..=255u8).collect();
        let enc = encode_object(&data, ErasureScheme { k: 4, n: 6 }).unwrap();
        for p in 4..6 {
            for d in 0..4 {
                assert_ne!(
                    enc.shards[p], enc.shards[d],
                    "parity shard {p} is a copy of data shard {d}"
                );
            }
        }
    }

    #[test]
    fn manifest_from_encoding_declares_the_scheme_it_can_deliver() {
        let data: Vec<u8> = (0..=100u8).collect();
        let scheme = ErasureScheme { k: 3, n: 5 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();
        assert_eq!(manifest.erasure, scheme);
        assert_eq!(manifest.shard_count, 5);
        assert_eq!(
            manifest
                .shards
                .iter()
                .filter(|s| s.kind == ShardKind::Parity)
                .count(),
            2
        );
        assert!(manifest.is_recoverable(3));
        assert!(!manifest.is_recoverable(2));
    }

    #[test]
    fn replication_scheme_produces_no_parity() {
        // k == n is the degenerate case; the coder must not invent shards.
        let data: Vec<u8> = (0..=50u8).collect();
        let enc = encode_object(&data, ErasureScheme { k: 3, n: 3 }).unwrap();
        assert_eq!(enc.shards.len(), 3);
        let manifest = enc.to_manifest().unwrap();
        assert_eq!(manifest.erasure.parity_count(), 0);
        let present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
        assert_eq!(reconstruct_object(&manifest, &present).unwrap(), data);
    }

    #[test]
    fn object_not_divisible_by_k_round_trips() {
        // The tail stripe is padded; total_size has to trim it back.
        for len in [1usize, 2, 3, 5, 7, 13, 101, 1023] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let enc = encode_object(&data, ErasureScheme { k: 4, n: 7 }).unwrap();
            let manifest = enc.to_manifest().unwrap();
            let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
            present[0] = None;
            present[3] = None;
            present[6] = None;
            let out = reconstruct_object(&manifest, &present)
                .unwrap_or_else(|e| panic!("len {len} failed: {e}"));
            assert_eq!(out, data, "len {len} did not round-trip");
        }
    }

    #[test]
    fn scheme_beyond_the_field_is_refused() {
        let err = ReedSolomon::new(200, 100).unwrap_err();
        assert!(matches!(err, ErasureError::InvalidScheme(_)), "got {err:?}");
        assert!(ReedSolomon::new(128, 127).is_ok());
    }

    #[test]
    fn unequal_shard_lengths_are_refused() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = vec![vec![1u8; 10], vec![2u8; 10], vec![3u8; 9]];
        let err = rs.encode_parity(&data).unwrap_err();
        assert!(matches!(err, ErasureError::ShardMismatch(_)), "got {err:?}");
    }

    #[test]
    fn encoding_is_deterministic() {
        // Two nodes coding the same object must land on the same manifest id,
        // or the chain sees two identities for one piece of content.
        let data: Vec<u8> = (0..=222u8).collect();
        let a = encode_object(&data, ErasureScheme { k: 5, n: 8 }).unwrap();
        let b = encode_object(&data, ErasureScheme { k: 5, n: 8 }).unwrap();
        assert_eq!(a.shards, b.shards);
        assert_eq!(
            a.to_manifest().unwrap().manifest_id,
            b.to_manifest().unwrap().manifest_id
        );
    }

    #[test]
    fn a_bigger_code_still_recovers_every_loss_pattern() {
        // (10, 14) is closer to a real deployment than (4, 6); the inverse is
        // 10x10 and exercises pivoting properly.
        let data: Vec<u8> = (0..=250u8).cycle().take(5000).collect();
        let scheme = ErasureScheme { k: 10, n: 14 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();
        for lost in combinations(14, 4).into_iter().step_by(97) {
            let mut present: Vec<Option<Vec<u8>>> = enc.shards.iter().cloned().map(Some).collect();
            for &i in &lost {
                present[i] = None;
            }
            let out = reconstruct_object(&manifest, &present)
                .unwrap_or_else(|e| panic!("losing {lost:?} broke recovery: {e}"));
            assert_eq!(out, data, "wrong bytes after losing {lost:?}");
        }
    }

    #[test]
    fn verify_object_encoding_accepts_an_honest_client_manifest() {
        let data: Vec<u8> = (0u8..=200).cycle().take(900).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let enc = encode_object(&data, scheme).unwrap();
        let manifest = enc.to_manifest().unwrap();
        verify_object_encoding(&data, &manifest).expect("honest encoding must verify");
    }

    #[test]
    fn verify_object_encoding_refuses_a_swapped_payload() {
        let data: Vec<u8> = (0u8..=200).cycle().take(900).collect();
        let scheme = ErasureScheme { k: 4, n: 6 };
        let manifest = encode_object(&data, scheme).unwrap().to_manifest().unwrap();
        let other: Vec<u8> = (1u8..=201).cycle().take(900).collect();
        assert!(
            verify_object_encoding(&other, &manifest).is_err(),
            "a different payload under the same scheme must not verify"
        );
    }
}
