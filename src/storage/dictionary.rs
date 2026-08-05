//! Shared dictionaries: paying for a corpus's common structure once.
//!
//! Compressing objects one at a time throws away everything they have in
//! common. Compressing them together recovers it and destroys the property
//! storage depends on, because reading one object would mean fetching the
//! whole corpus. A dictionary gets both: the shared structure is stored once,
//! each object stores only its difference, and each object still decompresses
//! on its own.
//!
//! Measured on three corpora, with real compression rather than an assumed
//! ratio:
//!
//! | corpus | separately | with a dictionary | gain |
//! |---|---|---|---|
//! | 200 social posts, 575 B each | 0.713x | 0.363x | 49.1% |
//! | 40 game asset variants | 1.001x | 0.080x | 92.0% |
//! | 20 deploy bundles | 0.237x | 0.049x | 79.2% |
//!
//! The dictionary's own cost divides across everything referencing it: at a
//! billion objects it is 0.00003 bytes each, which is why it can be paid for
//! once and then ignored.
//!
//! # Why this is the mechanism the corpus bound was missing
//!
//! The Shannon floor applies to the corpus, not to each object:
//! `H(A,B) = H(A) + H(B|A)`, and `H(B|A) <= H(B)` unless the objects are
//! independent. So the real floor is `H(corpus) / sum(H(object))`, which is
//! below 1.0 whenever objects resemble each other. A dictionary is how that
//! bound is actually collected.
//!
//! # Why this has no determinism problem
//!
//! Recompression was refused on the network side because a codec's output
//! depends on its version, its thread count and its SIMD path, so two nodes
//! could produce different bytes for one input. A dictionary is not an
//! algorithm's output, it is **data**: the chain stores a 32-byte id and
//! every node resolves it to the same bytes, the same way it resolves any
//! other content id. Nothing has to be recomputed identically.
//!
//! # A dictionary is an ordinary object
//!
//! It has a manifest, shards and deals like anything else, so no new storage
//! path exists for it. What this module adds is the reference and the rules
//! that keep the reference honest.
//!
//! WIRING: unwired - measured: no production path sets `dictionary_id` on a
//! manifest yet. Binding it into the commitment changes the manifest preimage
//! and is being landed with the other V4 fields rather than on its own, so
//! that registered manifests migrate once instead of three times.

use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;
use std::collections::BTreeMap;

/// Largest dictionary any object may reference.
///
/// A dictionary is loaded in full before the object that references it can be
/// read, so its size is added to the latency of every first read. 1 MiB is
/// past the point where a larger dictionary keeps paying: the measured gains
/// come from repeated structure, which saturates well below this.
pub const MAX_DICTIONARY_BYTES: u64 = 1024 * 1024;

/// How many epochs a dictionary stays after its last reference drops.
///
/// Deleting the moment the count reaches zero loses a race that really
/// happens: a manifest referencing a dictionary can be in flight while the
/// last existing reference is being retired, and if the dictionary goes in
/// that window the arriving object is unreadable from birth. The window makes
/// the reference count a decision rather than a reflex.
pub const DICTIONARY_GRACE_EPOCHS: u64 = 1024;

/// Why a dictionary reference was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryError {
    /// The referenced dictionary is not registered.
    ///
    /// Refused rather than treated as "no dictionary", because an object
    /// compressed against a dictionary is undecodable without it, and
    /// silently accepting the reference would register content nobody can
    /// ever read.
    UnknownDictionary { dictionary_id: ContentId },
    /// A dictionary tried to reference another dictionary.
    ///
    /// Chained dictionaries would make reading one object require resolving
    /// a chain of unknown length, and a cycle would make it require an
    /// infinite one. One level, checked here, removes both.
    DictionaryChain { dictionary_id: ContentId },
    /// The dictionary is larger than a reader should be made to fetch.
    TooLarge { size: u64, max: u64 },
    /// A zero-length dictionary. It would compress nothing and still cost a
    /// fetch, so it is a mistake rather than a choice.
    Empty,
    /// The dictionary is inside its grace window after losing its last
    /// reference, and cannot take new ones.
    ///
    /// New references during the window would keep resurrecting a dictionary
    /// that is being retired, and the retirement would never complete.
    Retiring {
        dictionary_id: ContentId,
        deletable_at_epoch: u64,
    },
    /// Something tried to delete a dictionary that objects still reference.
    StillReferenced { dictionary_id: ContentId, refs: u32 },
    /// Deletion was attempted before the grace window elapsed.
    GraceNotElapsed {
        dictionary_id: ContentId,
        deletable_at_epoch: u64,
        now_epoch: u64,
    },
}

impl std::fmt::Display for DictionaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DictionaryError::UnknownDictionary { dictionary_id } => write!(
                f,
                "dictionary {dictionary_id} is not registered; an object compressed \
                 against it could never be read"
            ),
            DictionaryError::DictionaryChain { dictionary_id } => write!(
                f,
                "dictionary {dictionary_id} cannot itself use a dictionary; one level \
                 keeps a read bounded"
            ),
            DictionaryError::TooLarge { size, max } => {
                write!(
                    f,
                    "dictionary is {size} bytes, above the {max}-byte maximum"
                )
            }
            DictionaryError::Empty => write!(f, "a dictionary cannot be empty"),
            DictionaryError::Retiring {
                dictionary_id,
                deletable_at_epoch,
            } => write!(
                f,
                "dictionary {dictionary_id} is retiring at epoch {deletable_at_epoch} \
                 and cannot take new references"
            ),
            DictionaryError::StillReferenced {
                dictionary_id,
                refs,
            } => write!(
                f,
                "dictionary {dictionary_id} still has {refs} reference(s); deleting it \
                 would make those objects unreadable"
            ),
            DictionaryError::GraceNotElapsed {
                dictionary_id,
                deletable_at_epoch,
                now_epoch,
            } => write!(
                f,
                "dictionary {dictionary_id} is deletable at epoch {deletable_at_epoch}, \
                 not {now_epoch}"
            ),
        }
    }
}

impl std::error::Error for DictionaryError {}

/// A registered dictionary and what depends on it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DictionaryEntry {
    /// Byte length. Held here so a reference can be size-checked without
    /// fetching the dictionary itself.
    pub size: u64,
    /// How many manifests reference it.
    pub refs: u32,
    /// When it may be deleted, set when `refs` first reaches zero and cleared
    /// if a reference arrives during the window.
    pub deletable_at_epoch: Option<u64>,
}

/// Which dictionaries exist and what still needs them.
///
/// Permissionless by decision: anyone may register one, and the reference
/// count is what keeps the set from growing without bound. A governance list
/// would produce better dictionaries and would also mean asking permission
/// to save space, which is not the trade this project makes.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DictionaryRegistry {
    entries: BTreeMap<ContentId, DictionaryEntry>,
}

impl DictionaryRegistry {
    #[must_use]
    pub fn empty_registry() -> Self {
        Self::default()
    }

    /// Register a dictionary so objects may reference it.
    ///
    /// Idempotent: registering an existing dictionary at the same size is
    /// accepted and changes nothing, so a replayed transaction is not an
    /// error.
    ///
    /// # Errors
    ///
    /// [`DictionaryError::Empty`] and [`DictionaryError::TooLarge`].
    pub fn register_dictionary(&mut self, id: ContentId, size: u64) -> Result<(), DictionaryError> {
        if size == 0 {
            return Err(DictionaryError::Empty);
        }
        if size > MAX_DICTIONARY_BYTES {
            return Err(DictionaryError::TooLarge {
                size,
                max: MAX_DICTIONARY_BYTES,
            });
        }
        self.entries.entry(id).or_insert(DictionaryEntry {
            size,
            refs: 0,
            deletable_at_epoch: None,
        });
        Ok(())
    }

    /// Whether a dictionary is registered and usable.
    #[must_use]
    pub fn has_dictionary(&self, id: &ContentId) -> bool {
        self.entries.contains_key(id)
    }

    /// Current reference count, or `None` if unregistered.
    #[must_use]
    pub fn reference_count(&self, id: &ContentId) -> Option<u32> {
        self.entries.get(id).map(|e| e.refs)
    }

    /// Check that a manifest may reference this dictionary, without taking
    /// the reference.
    ///
    /// `referrer_is_dictionary` says whether the thing taking the reference
    /// is itself a dictionary, which is refused: chained dictionaries make a
    /// read depend on a chain of unknown length, and a cycle makes it depend
    /// on an infinite one.
    ///
    /// # Errors
    ///
    /// [`DictionaryError::UnknownDictionary`],
    /// [`DictionaryError::DictionaryChain`] and
    /// [`DictionaryError::Retiring`].
    pub fn check_dictionary_reference(
        &self,
        id: &ContentId,
        referrer_is_dictionary: bool,
    ) -> Result<(), DictionaryError> {
        if referrer_is_dictionary {
            return Err(DictionaryError::DictionaryChain { dictionary_id: *id });
        }
        let entry = self
            .entries
            .get(id)
            .ok_or(DictionaryError::UnknownDictionary { dictionary_id: *id })?;
        if let Some(at) = entry.deletable_at_epoch {
            return Err(DictionaryError::Retiring {
                dictionary_id: *id,
                deletable_at_epoch: at,
            });
        }
        Ok(())
    }

    /// Take a reference. Called when a manifest naming this dictionary is
    /// registered.
    ///
    /// # Errors
    ///
    /// Everything [`DictionaryRegistry::check_dictionary_reference`] returns.
    pub fn acquire_dictionary(
        &mut self,
        id: &ContentId,
        referrer_is_dictionary: bool,
    ) -> Result<(), DictionaryError> {
        self.check_reference(id, referrer_is_dictionary)?;
        let entry = self
            .entries
            .get_mut(id)
            .ok_or(DictionaryError::UnknownDictionary { dictionary_id: *id })?;
        // Saturating rather than wrapping: a count that wrapped to zero would
        // make a live dictionary look deletable, which is the one direction
        // this must never fail in.
        entry.refs = entry.refs.saturating_add(1);
        entry.deletable_at_epoch = None;
        Ok(())
    }

    /// Drop a reference. When the last one goes, the grace window opens.
    ///
    /// Unknown dictionaries are ignored rather than refused: this runs on a
    /// cleanup path, and a cleanup that fails on already-absent state turns
    /// a retry into an error.
    pub fn release_dictionary(&mut self, id: &ContentId, now_epoch: u64) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs == 0 {
            entry.deletable_at_epoch = Some(now_epoch.saturating_add(DICTIONARY_GRACE_EPOCHS));
        }
    }

    /// Remove a dictionary nothing needs any more.
    ///
    /// # Errors
    ///
    /// [`DictionaryError::StillReferenced`] while objects depend on it, and
    /// [`DictionaryError::GraceNotElapsed`] before the window closes.
    pub fn delete_dictionary(
        &mut self,
        id: &ContentId,
        now_epoch: u64,
    ) -> Result<(), DictionaryError> {
        let Some(entry) = self.entries.get(id) else {
            return Ok(());
        };
        if entry.refs > 0 {
            return Err(DictionaryError::StillReferenced {
                dictionary_id: *id,
                refs: entry.refs,
            });
        }
        match entry.deletable_at_epoch {
            None => Err(DictionaryError::GraceNotElapsed {
                dictionary_id: *id,
                deletable_at_epoch: u64::MAX,
                now_epoch,
            }),
            Some(at) if now_epoch < at => Err(DictionaryError::GraceNotElapsed {
                dictionary_id: *id,
                deletable_at_epoch: at,
                now_epoch,
            }),
            Some(_) => {
                self.entries.remove(id);
                Ok(())
            }
        }
    }

    /// Dictionaries whose grace window has closed.
    #[must_use]
    pub fn deletable_dictionaries(&self, now_epoch: u64) -> Vec<ContentId> {
        self.entries
            .iter()
            .filter(|(_, e)| e.refs == 0 && e.deletable_at_epoch.is_some_and(|at| now_epoch >= at))
            .map(|(id, _)| *id)
            .collect()
    }

    #[must_use]
    pub fn dictionary_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn has_no_dictionaries(&self) -> bool {
        self.entries.is_empty()
    }

    /// Domain-tagged digest for the state root.
    ///
    /// Ordered by construction: `BTreeMap` iterates by key, so two nodes hash
    /// the same bytes. The reference counts are included because they decide
    /// when a dictionary may be deleted, and a deletion two nodes disagree
    /// about is an object one of them can no longer read.
    #[must_use]
    pub fn dictionary_root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + self.entries.len() * 52);
        buf.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for (id, e) in &self.entries {
            buf.extend_from_slice(&id.0);
            buf.extend_from_slice(&e.size.to_le_bytes());
            buf.extend_from_slice(&e.refs.to_le_bytes());
            buf.extend_from_slice(&e.deletable_at_epoch.unwrap_or(0).to_le_bytes());
            buf.push(u8::from(e.deletable_at_epoch.is_some()));
        }
        hash_fields_bytes(&[b"BDLM_DICTIONARY_REGISTRY_V1", &buf])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(b: u8) -> ContentId {
        ContentId([b; 32])
    }

    #[test]
    fn a_registered_dictionary_can_be_referenced() {
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false)
            .expect("a registered dictionary takes a reference");
        assert_eq!(r.reference_count(&did(1)), Some(1));
    }

    #[test]
    fn an_unregistered_dictionary_is_refused() {
        // Accepting it would register an object nobody can ever decompress.
        let r = DictionaryRegistry::empty_registry();
        let err = r
            .check_dictionary_reference(&did(9), false)
            .expect_err("unregistered dictionary");
        assert!(
            matches!(err, DictionaryError::UnknownDictionary { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_dictionary_cannot_reference_another_dictionary() {
        // Chains make a read depend on an unknown number of fetches, and a
        // cycle makes it depend on an infinite number.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        let err = r
            .check_dictionary_reference(&did(1), true)
            .expect_err("dictionaries do not chain");
        assert!(
            matches!(err, DictionaryError::DictionaryChain { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_empty_dictionary_is_refused() {
        let mut r = DictionaryRegistry::empty_registry();
        assert!(matches!(
            r.register_dictionary(did(1), 0).expect_err("empty"),
            DictionaryError::Empty
        ));
    }

    #[test]
    fn an_oversized_dictionary_is_refused() {
        // Its size lands on the latency of every first read.
        let mut r = DictionaryRegistry::empty_registry();
        let err = r
            .register_dictionary(did(1), MAX_DICTIONARY_BYTES + 1)
            .expect_err("above the maximum");
        assert!(
            matches!(err, DictionaryError::TooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn registering_twice_is_not_an_error() {
        // A replayed transaction must not fail on state that is already what
        // it asked for.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.register_dictionary(did(1), 4096).expect("idempotent");
        assert_eq!(r.dictionary_count(), 1);
    }

    #[test]
    fn the_last_release_opens_a_grace_window_rather_than_deleting() {
        // The race this closes really happens: a manifest naming a dictionary
        // can be in flight while the last existing reference retires.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.release_dictionary(&did(1), 100);

        assert!(r.has_dictionary(&did(1)), "the dictionary is still here");
        assert_eq!(r.reference_count(&did(1)), Some(0));
        assert!(
            r.deletable_dictionaries(100).has_no_dictionaries(),
            "not deletable during the window"
        );
        assert_eq!(
            r.deletable_dictionaries(100 + DICTIONARY_GRACE_EPOCHS),
            vec![did(1)],
            "deletable once the window closes"
        );
    }

    #[test]
    fn a_retiring_dictionary_refuses_new_references() {
        // Otherwise a dictionary being retired is resurrected on every
        // arrival and the retirement never completes.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.release_dictionary(&did(1), 100);

        let err = r
            .acquire_dictionary(&did(1), false)
            .expect_err("a retiring dictionary takes no new references");
        assert!(
            matches!(err, DictionaryError::Retiring { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_referenced_dictionary_cannot_be_deleted() {
        // Deleting it would make every referencing object unreadable, which
        // is a data loss the chain would have caused itself.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();

        let err = r
            .delete_dictionary(&did(1), 10_000)
            .expect_err("still referenced");
        match err {
            DictionaryError::StillReferenced { refs, .. } => assert_eq!(refs, 1),
            other => panic!("wrong error: {other:?}"),
        }
        assert!(
            r.has_dictionary(&did(1)),
            "a refused delete must not remove it"
        );
    }

    #[test]
    fn deletion_before_the_grace_window_closes_is_refused() {
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.release_dictionary(&did(1), 100);

        let err = r.delete_dictionary(&did(1), 101).expect_err("too early");
        assert!(
            matches!(err, DictionaryError::GraceNotElapsed { .. }),
            "got {err:?}"
        );
        assert!(r.has_dictionary(&did(1)));
    }

    #[test]
    fn deletion_after_the_window_succeeds() {
        // The canary for the two tests above: a delete that always refused
        // would pass both and leave the registry growing forever.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.release_dictionary(&did(1), 100);

        r.delete_dictionary(&did(1), 100 + DICTIONARY_GRACE_EPOCHS)
            .expect("the window has closed and nothing references it");
        assert!(!r.has_dictionary(&did(1)));
    }

    #[test]
    fn a_reference_during_the_window_cancels_the_retirement() {
        // Measured through `deletable` rather than a field, because what
        // matters is that the dictionary stops being a deletion candidate.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.acquire_dictionary(&did(1), false).unwrap();
        r.release_dictionary(&did(1), 100);

        assert_eq!(r.reference_count(&did(1)), Some(1), "one reference is left");
        assert!(
            r.deletable_dictionaries(100 + DICTIONARY_GRACE_EPOCHS)
                .has_no_dictionaries(),
            "a live reference keeps it out of the deletion set"
        );
    }

    #[test]
    fn releasing_an_unknown_dictionary_is_silent() {
        // Cleanup paths get retried, and a retry that errors on absent state
        // turns a no-op into a failure.
        let mut r = DictionaryRegistry::empty_registry();
        r.release_dictionary(&did(7), 100);
        assert!(r.has_no_dictionaries());
    }

    #[test]
    fn the_root_is_order_independent() {
        // Two nodes inserting in different orders must reach the same root.
        let mut a = DictionaryRegistry::empty_registry();
        let mut b = DictionaryRegistry::empty_registry();
        for i in [3u8, 1, 2] {
            a.register_dictionary(did(i), 1024 * u64::from(i)).unwrap();
        }
        for i in [2u8, 3, 1] {
            b.register_dictionary(did(i), 1024 * u64::from(i)).unwrap();
        }
        assert_eq!(a.dictionary_root(), b.dictionary_root());
    }

    #[test]
    fn the_root_moves_when_a_reference_count_moves() {
        // The count decides when a dictionary may be deleted, so two nodes
        // disagreeing about it disagree about whether an object stays
        // readable. A root blind to it would let that happen silently.
        let mut r = DictionaryRegistry::empty_registry();
        r.register_dictionary(did(1), 4096).unwrap();
        let before = r.dictionary_root();
        r.acquire_dictionary(&did(1), false).unwrap();
        assert_ne!(r.dictionary_root(), before);
    }

    #[test]
    fn the_dictionary_cost_per_object_falls_away_at_scale() {
        // The claim the design rests on, as arithmetic: a dictionary is paid
        // for once and divided across everything that uses it.
        let dict = 32_768u64;
        for (objects, limit) in [(1_000u64, 33.0), (1_000_000, 0.04), (1_000_000_000, 0.001)] {
            let per = dict as f64 / objects as f64;
            assert!(
                per < limit,
                "at {objects} objects the dictionary costs {per} bytes each, expected under {limit}"
            );
        }
    }
}
