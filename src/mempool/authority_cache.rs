//! A bounded cache of verified transaction authorizations.
//!
//! A composite signature costs two verifications and an ML-DSA-87 one is the slow part. The
//! mempool verifies a transaction on admission and the block path would verify it again; this
//! cache remembers the positive verdict so the second look is a lookup.
//!
//! The key is a digest of everything the verdict depends on (the signing hash, the signature,
//! the signer key and any multisig authorization: the signing hash alone is not enough, since it
//! does not cover the signature and a forged signature over the same body must miss) together
//! with the commitment of the scheme status registry the verdict was made under. A status change (a family moved to `Disabled` by
//! the Frost Alarm, for example) changes the commitment, so an entry made before it can never be
//! hit after it. Only accepted authorizations are stored: a refusal is never cached, so a cache
//! hit can only repeat a verification that really succeeded, and an eviction costs one
//! re-verification and nothing else.

use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};

/// The default capacity, in entries.
/// exposed for: mempool surface - admission paths read these with the mempool wiring.
pub const DEFAULT_CAPACITY: usize = 16_384;

type Key = ([u8; 32], [u8; 32]);

/// The digest that identifies one authorization: every byte string the verdict depends on,
/// length prefixed.
#[must_use]
pub fn authorization_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update((parts.len() as u64).to_le_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A first-in first-out cache of accepted authorizations.
#[derive(Debug, Clone)]
pub struct AuthorityCache {
    capacity: usize,
    entries: HashMap<Key, ()>,
    order: VecDeque<Key>,
}

impl AuthorityCache {
    /// A cache holding at most `capacity` entries (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Whether this authorization digest was accepted under this registry commitment.
    #[must_use]
    pub fn contains(&self, digest: &[u8; 32], registry_commitment: &[u8; 32]) -> bool {
        self.entries.contains_key(&(*digest, *registry_commitment))
    }

    /// Records an accepted authorization. Call it only after a verification succeeded.
    pub fn insert_accepted(&mut self, digest: [u8; 32], registry_commitment: [u8; 32]) {
        let key = (digest, registry_commitment);
        if self.entries.contains_key(&key) {
            return;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, ());
        self.order.push_back(key);
    }

    /// The number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl Default for AuthorityCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_separates_a_forged_signature_over_the_same_body() {
        let body = [1u8; 32];
        let honest = authorization_digest(&[&body, b"sig-a", b"key", b""]);
        let forged = authorization_digest(&[&body, b"sig-b", b"key", b""]);
        assert_ne!(honest, forged);
        let mut cache = AuthorityCache::new(4);
        cache.insert_accepted(honest, [0; 32]);
        assert!(!cache.contains(&forged, &[0; 32]));
    }

    #[test]
    fn the_digest_is_not_fooled_by_moving_bytes_between_parts() {
        assert_ne!(
            authorization_digest(&[b"ab", b"c"]),
            authorization_digest(&[b"a", b"bc"])
        );
    }

    #[test]
    fn an_accepted_authorization_is_found_under_the_same_registry_only() {
        let mut cache = AuthorityCache::new(4);
        cache.insert_accepted([1; 32], [9; 32]);
        assert!(cache.contains(&[1; 32], &[9; 32]));
        assert!(!cache.contains(&[1; 32], &[8; 32]));
        assert!(!cache.contains(&[2; 32], &[9; 32]));
    }

    #[test]
    fn the_oldest_entry_goes_first_at_capacity() {
        let mut cache = AuthorityCache::new(2);
        cache.insert_accepted([1; 32], [0; 32]);
        cache.insert_accepted([2; 32], [0; 32]);
        cache.insert_accepted([3; 32], [0; 32]);
        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&[1; 32], &[0; 32]));
        assert!(cache.contains(&[3; 32], &[0; 32]));
    }

    #[test]
    fn a_repeated_insert_does_not_grow_or_reorder() {
        let mut cache = AuthorityCache::new(2);
        cache.insert_accepted([1; 32], [0; 32]);
        cache.insert_accepted([1; 32], [0; 32]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_zero_capacity_still_holds_one_entry() {
        let mut cache = AuthorityCache::new(0);
        cache.insert_accepted([1; 32], [0; 32]);
        assert!(cache.contains(&[1; 32], &[0; 32]));
    }
}
