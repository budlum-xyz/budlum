//! The memory structure in front of the public dedup index.
//!
//! Deduplication decides from the exact index alone. This filter sits in
//! front of it so content that was never held skips the lookup: a "no" from
//! the filter means the content is new, a "maybe" always consults the index.
//! The filter never decides on its own, and it has no false negatives: a key
//! the index holds always reads as "maybe".
//!
//! The structure is a node-local accelerator. It is not part of the chain
//! state: it is not hashed into the state root and it is not written to
//! snapshots, which carry the exact index only. A rebuilt filter answers the
//! same as the original, so nothing that follows from the index can depend on
//! the filter's history.
//!
//! The hashing is integers only, so two architectures agree bit for bit.

use std::collections::btree_map::{BTreeMap, IntoIter};

/// An object is named by its commitment.
pub type ObjectKey = [u8; 32];

/// Bits reserved per key at construction. The constant trades filter memory
/// against how often the filter says "maybe" and the index is consulted; it
/// cannot change an answer.
const BITS_PER_KEY: u64 = 16;

/// Independent bit positions per key.
const HASHES: u32 = 7;

/// The smallest filter, in bits.
const MIN_BITS: u64 = 64;

/// The key count a default-built filter is sized for. The filter grows from
/// the full key set when the count passes it.
const DEFAULT_EXPECTED: u64 = 1024;

/// A Bloom filter over content digests, sized for an expected key count.
#[derive(Debug, Clone)]
pub struct BloomFilter {
    words: Vec<u64>,
    bits: u64,
    hashes: u32,
    keys: u64,
    expected: u64,
}

/// Two 64-bit lanes squeezed out of a digest. Integers only: the same digest
/// gives the same lanes on every architecture.
fn two_hashes(digest: &[u8; 32]) -> [u64; 2] {
    let mut lanes = [0u64; 4];
    for (lane, chunk) in lanes.iter_mut().zip(digest.chunks_exact(8)) {
        let mut v = 0u64;
        for (j, b) in chunk.iter().enumerate() {
            v |= u64::from(*b) << (8 * j);
        }
        *lane = v;
    }
    [mix(lanes[0] ^ lanes[2]), mix(lanes[1] ^ lanes[3]) | 1]
}

/// An integer mixer (a 64-bit finalizer). No floats on this path.
fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    x
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::with_expected(DEFAULT_EXPECTED)
    }
}

impl BloomFilter {
    /// A filter sized for `expected` keys.
    #[must_use]
    pub fn with_expected(expected: u64) -> Self {
        let expected = expected.max(1);
        let bits = expected.saturating_mul(BITS_PER_KEY).max(MIN_BITS);
        let words = bits.div_ceil(64) as usize;
        Self {
            words: vec![0u64; words],
            bits: words as u64 * 64,
            hashes: HASHES,
            keys: 0,
            expected,
        }
    }

    /// The key count the filter is sized for.
    #[must_use]
    pub const fn expected(&self) -> u64 {
        self.expected
    }

    /// How many keys were inserted, including repeats.
    #[must_use]
    pub const fn keys(&self) -> u64 {
        self.keys
    }

    /// Remember `digest`. The filter does not grow by itself; the owner that
    /// holds the full key set rebuilds it when [`Self::keys`] passes
    /// [`Self::expected`].
    pub fn insert(&mut self, digest: &[u8; 32]) {
        let [h1, h2] = two_hashes(digest);
        for i in 0..self.hashes {
            let bit = h1.wrapping_add(u64::from(i).wrapping_mul(h2)) % self.bits;
            let word = (bit / 64) as usize;
            if let Some(w) = self.words.get_mut(word) {
                *w |= 1u64 << (bit % 64);
            }
        }
        self.keys += 1;
    }

    /// Whether `digest` may have been inserted. "No" is definitive: the
    /// filter has no false negatives. "Yes" is a hint and never a match.
    #[must_use]
    pub fn maybe_contains(&self, digest: &[u8; 32]) -> bool {
        let [h1, h2] = two_hashes(digest);
        (0..self.hashes).all(|i| {
            let bit = h1.wrapping_add(u64::from(i).wrapping_mul(h2)) % self.bits;
            let word = (bit / 64) as usize;
            self.words
                .get(word)
                .is_some_and(|w| w & (1u64 << (bit % 64)) != 0)
        })
    }
}

/// The public dedup index: content digest to the live object holding it, with
/// the filter in front.
#[derive(Debug, Clone, Default)]
pub struct DedupIndex {
    filter: BloomFilter,
    map: BTreeMap<[u8; 32], ObjectKey>,
}

/// Equality is the exact index. The filter is a lookup accelerator with a
/// history of its own; two indexes that hold the same keys are the same index
/// whatever their filters look like.
impl PartialEq for DedupIndex {
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}

impl Eq for DedupIndex {}

impl FromIterator<([u8; 32], ObjectKey)> for DedupIndex {
    fn from_iter<T: IntoIterator<Item = ([u8; 32], ObjectKey)>>(iter: T) -> Self {
        let mut index = Self::default();
        for (digest, key) in iter {
            index.insert(digest, key);
        }
        index
    }
}

impl IntoIterator for DedupIndex {
    type Item = ([u8; 32], ObjectKey);
    type IntoIter = IntoIter<[u8; 32], ObjectKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}

impl DedupIndex {
    /// The object holding `digest`, if the index holds one. A filter "no"
    /// answers without the lookup; a "maybe" always consults the exact index.
    #[must_use]
    pub fn get(&self, digest: &[u8; 32]) -> Option<&ObjectKey> {
        if !self.filter.maybe_contains(digest) {
            return None;
        }
        self.map.get(digest)
    }

    /// Map `digest` to `key`. Grows the filter from the full key set when the
    /// count passes what it was sized for. Returns the previous mapping.
    pub fn insert(&mut self, digest: [u8; 32], key: ObjectKey) -> Option<ObjectKey> {
        if self.filter.keys() >= self.filter.expected() {
            self.rebuild(self.filter.expected().saturating_mul(2).max(1));
        }
        self.filter.insert(&digest);
        self.map.insert(digest, key)
    }

    /// Drop the mapping for `digest`. The filter keeps its bits: a stale
    /// "maybe" only costs a lookup, and the filter never decides alone.
    pub fn remove(&mut self, digest: &[u8; 32]) -> Option<ObjectKey> {
        self.map.remove(digest)
    }

    /// Rebuild the filter from the full key set at a new expected count.
    fn rebuild(&mut self, expected: u64) {
        let mut filter = BloomFilter::with_expected(expected);
        for digest in self.map.keys() {
            filter.insert(digest);
        }
        self.filter = filter;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&n.to_le_bytes());
        digest
    }

    #[test]
    fn the_filter_never_misses_a_key_the_index_holds() {
        let mut filter = BloomFilter::with_expected(64);
        let keys: Vec<[u8; 32]> = (0..64).map(key).collect();
        for digest in &keys {
            filter.insert(digest);
        }
        for digest in &keys {
            assert!(
                filter.maybe_contains(digest),
                "a filter miss on an inserted key cannot happen"
            );
        }
    }

    #[test]
    fn a_filter_no_skips_the_index_and_a_maybe_consults_it() {
        let mut index = DedupIndex::default();
        index.insert(key(1), [1u8; 32]);
        assert_eq!(index.get(&key(1)), Some(&[1u8; 32]));
        // Never inserted: a "maybe" would consult the index and still find
        // nothing, so the answer is the same either way.
        assert_eq!(index.get(&key(2)), None);
        // Removal drops the mapping even if the filter keeps its bits.
        assert_eq!(index.remove(&key(1)), Some([1u8; 32]));
        assert_eq!(index.get(&key(1)), None);
    }

    #[test]
    fn the_index_grows_past_the_expected_count() {
        let mut index = DedupIndex::default();
        for n in 0..(DEFAULT_EXPECTED + 500) {
            index.insert(key(n), key(n));
        }
        for n in 0..(DEFAULT_EXPECTED + 500) {
            assert_eq!(index.get(&key(n)), Some(&key(n)), "key {n}");
        }
    }

    #[test]
    fn a_rebuilt_index_answers_the_same_as_the_original() {
        let mut index = DedupIndex::default();
        for n in 0..100u64 {
            index.insert(key(n), key(n));
        }
        index.remove(&key(7));
        let rebuilt: DedupIndex = index.clone().into_iter().collect();
        assert_eq!(rebuilt, index);
        for n in 0..100u64 {
            assert_eq!(rebuilt.get(&key(n)), index.get(&key(n)), "key {n}");
        }
    }

    #[test]
    fn the_hashing_is_integers_only_and_stable() {
        // The same digest always reaches the same bits: two filters built the
        // same way agree bit for bit.
        let mut a = BloomFilter::with_expected(8);
        let mut b = BloomFilter::with_expected(8);
        for n in 0..8u64 {
            a.insert(&key(n));
            b.insert(&key(n));
        }
        assert_eq!(a.words, b.words);
        // And the mixer has no floating point state to diverge.
        assert_eq!(mix(0), 0);
    }
}
