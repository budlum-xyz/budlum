//! The shared compression context (Section 6.20, WP-54 step 3).
//!
//! A context is the network's common memory for one content class. It is
//! defined by a *manifest*, and the network stores only the manifest: the
//! context bytes themselves are a node-local cache, never chain state, exactly
//! as the bloom filter in [`super::dedup_index`] is node-local. A node that
//! never built the cache answers the same as one that did, one rebuild later,
//! because the cache is rebuilt from the corpus the manifest names.
//!
//! The rules this module enforces are the ones Section 6.20 states, and they
//! are refusals rather than conventions:
//!
//! 1. **Public only.** Every public object is a corpus candidate by default;
//!    sealed content never joins a context. A context codec compresses against
//!    a class-wide dictionary, and a sealed member would be a ciphertext the
//!    whole network could see itself compress against.
//! 2. **One class per context.** A context for `Records` may not carry `Image`
//!    members: the dictionary is class-specific, and a mixed context would let
//!    one class's bytes reach another class's ratios.
//! 3. **Burned content leaves.** Deleted content leaves the corpus at the
//!    *next* renewal. The renewal changes the manifest and therefore the
//!    context, but never the content id of anything dependent on it: an object
//!    may be re-coded under a new context, and its `ContentId` is the same
//!    bytes-derived value it always was (Section 6.20 madde 2.2).
//! 4. **The savings fee.** An object coded with a context codec pays a context
//!    savings fee into the Context Maintenance Pool. A full match (the content
//!    already exists) pays no extra fee: dedup is not a context win.
//! 5. **Codecs 12 and 13 only.** Both are closed in the register
//!    (`crates/bud-codec`), and the context path is closed at testnet launch:
//!    [`CONTEXT_OPEN_AT`] holds no height, so every context object is refused
//!    (T41, `bud3_closed_features_refuse`).
//!
//! No float appears anywhere: a savings ratio and a fee are integers, because
//! two nodes must agree bit for bit on what an object costs.
//!
//! WIRING: unwired - the upload path (`upload.rs`) offers a public object to
//! the context of its class, the renewal runs in the block-end maintenance of
//! Section 6.19, and `StorageTx` v3 pays the savings fee. Until those land this
//! module is exercised by `src/tests/bud3_context.rs` and its own unit tests.
//! The gate that opens it is [`CONTEXT_OPEN_AT`], which is `None` on the
//! testnet chain.

use super::content_id::ContentId;
use super::limits::GIB;
use super::stages::ContentClass;
use crate::core::hash::hash_fields_bytes;
use std::collections::BTreeSet;

/// The manifest's domain-separation tag.
///
/// WIRING: the manifest id is the value a `StorageTx` v3 record will name.
pub const CONTEXT_MANIFEST_TAG: &[u8] = b"BDLM_BUD3_CONTEXT_MANIFEST_V1";

/// The corpus fold's domain-separation tag.
///
/// WIRING: `corpus_root` hashes with this tag; the renewal writes the root.
pub const CONTEXT_CORPUS_TAG: &[u8] = b"BDLM_BUD3_CONTEXT_CORPUS_V1";

/// LZ and context (codec 12): general content against the corpus dictionary.
pub const CONTEXT_CODEC_LZ: u16 = 12;

/// The context machine (codec 13): general content with the context state.
pub const CONTEXT_CODEC_MACHINE: u16 = 13;

/// The codecs a context manifest may name. Nothing else may be a context
/// codec: a context flag on any other id would describe compression this
/// module never measured.
pub const CONTEXT_CODECS: [u16; 2] = [CONTEXT_CODEC_LZ, CONTEXT_CODEC_MACHINE];

/// TESTNET-DEFAULT: the savings fee, one thousand units of a microBUD per GiB
/// of saved payload.
///
/// The fee is charged on the bytes the context actually saved, so a member
/// whose payload the context did not shrink pays nothing.
pub const CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB: u64 = 1_000;

/// The largest corpus a manifest may name.
///
/// A renewal folds every candidate into one root, so this ceiling is what keeps
/// the fold bounded; a network that outgrows it renews more often rather than
/// carrying an unbounded manifest.
pub const MAX_CORPUS_MEMBERS: usize = 1 << 16;

/// When the context path opens. `None`: closed on this chain.
///
/// TESTNET-DEFAULT: closed. The activation height arrives with a governance
/// value after codecs 12 and 13 are measured and opened (WP-54, M7).
pub const CONTEXT_OPEN_AT: Option<u64> = None;

/// Whether a context object is admissible at `height`.
#[must_use]
pub fn context_is_open_at(height: u64) -> bool {
    CONTEXT_OPEN_AT.is_some_and(|open| height >= open)
}

/// Why the context refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// The context path is closed at this height.
    ClosedAt(u64),
    /// The manifest names a codec that is not a context codec.
    NotAContextCodec(u16),
    /// Sealed content may not join a context.
    SealedContent,
    /// The member belongs to another class than the context.
    ClassMismatch {
        /// The context's class.
        context: ContentClass,
        /// The member's class.
        member: ContentClass,
    },
    /// The corpus is already at [`MAX_CORPUS_MEMBERS`].
    CorpusFull,
    /// The member is not in the corpus, so it cannot be burned out of it.
    NotInCorpus,
}

/// One corpus member: the content it names and the object that carries it.
///
/// The commitment is not part of the content id. A member may be re-coded (a
/// better codec, a new context) and its commitment changes while its content id
/// does not, which is why both are recorded.
///
/// WIRING: the upload path builds one of these per stored object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CorpusMember {
    /// The content.
    pub content: ContentId,
    /// The object the content is stored in, as a commitment.
    pub commitment: [u8; 32],
}

impl CorpusMember {
    /// A member.
    #[must_use]
    pub const fn new(content: ContentId, commitment: [u8; 32]) -> Self {
        Self {
            content,
            commitment,
        }
    }

    /// The bytes this member contributes to the corpus fold.
    ///
    /// WIRING: `corpus_root` folds these bytes; nothing else calls it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&self.content.digest);
        out.extend_from_slice(&self.content.len.to_le_bytes());
        out.extend_from_slice(&self.commitment);
        out
    }
}

/// The fold over a corpus: every member's content digest, length and
/// commitment, in sorted order, so two nodes holding the same corpus agree.
///
/// WIRING: the renewal folds with this, and the manifest carries the result.
#[must_use]
pub fn corpus_root(members: &[CorpusMember]) -> [u8; 32] {
    let mut sorted: Vec<&CorpusMember> = members.iter().collect();
    sorted.sort();
    let mut bytes = Vec::with_capacity(sorted.len().saturating_mul(65));
    for member in sorted {
        bytes.extend_from_slice(&member.encode());
    }
    let count = u64::try_from(members.len()).unwrap_or(u64::MAX);
    hash_fields_bytes(&[CONTEXT_CORPUS_TAG, &count.to_le_bytes(), &bytes])
}

/// The manifest: everything the network needs to rebuild a context.
///
/// It carries no context bytes. A node rebuilds the cache from the corpus the
/// root names and reaches the same state.
///
/// WIRING: the settlement record carries the manifest id; RPC reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextManifest {
    /// The content class this context belongs to.
    pub class: ContentClass,
    /// The context codec, one of [`CONTEXT_CODECS`].
    pub codec: u16,
    /// The fold over the corpus.
    pub corpus_root: [u8; 32],
    /// How many members the corpus holds.
    pub member_count: u32,
    /// The epoch the renewal ran at.
    pub built_at_epoch: u64,
}

impl ContextManifest {
    /// The manifest of one class, under one context codec.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotAContextCodec`] when `codec` is not 12 or 13, and
    /// [`ContextError::CorpusFull`] when the corpus is over
    /// [`MAX_CORPUS_MEMBERS`].
    pub fn new(
        class: ContentClass,
        codec: u16,
        members: &[CorpusMember],
        built_at_epoch: u64,
    ) -> Result<Self, ContextError> {
        if !CONTEXT_CODECS.contains(&codec) {
            return Err(ContextError::NotAContextCodec(codec));
        }
        if members.len() > MAX_CORPUS_MEMBERS {
            return Err(ContextError::CorpusFull);
        }
        Ok(Self {
            class,
            codec,
            corpus_root: corpus_root(members),
            member_count: u32::try_from(members.len()).unwrap_or(u32::MAX),
            built_at_epoch,
        })
    }

    /// The manifest id a record names.
    ///
    /// The id folds the class, the codec and the corpus, so two manifests that
    /// differ in any field are two contexts, and an object coded under one is
    /// not admissible under the other.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            CONTEXT_MANIFEST_TAG,
            self.class.name().as_bytes(),
            &self.codec.to_le_bytes(),
            &self.corpus_root,
            &self.member_count.to_le_bytes(),
            &self.built_at_epoch.to_le_bytes(),
        ])
    }
}

/// The savings fee an object coded with a context codec pays.
///
/// `saved_bytes` is the payload length without the context minus the payload
/// length with it. A context that saved nothing costs nothing: the fee is a
/// share of a measured win, never a rent on belonging to a class.
///
/// WIRING: `StorageTx` v3 charges this fee at `RegisterObject`.
#[must_use]
pub const fn context_savings_fee(saved_bytes: u64) -> u64 {
    if saved_bytes == 0 {
        return 0;
    }
    let fee = saved_bytes
        .saturating_mul(CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB)
        / GIB;
    // A saving that rounds to zero still pays one unit, so the pool is never
    // fed a stream of free context objects.
    if fee == 0 {
        1
    } else {
        fee
    }
}

/// The fee an object pays when the content already exists.
///
/// A full match pays no context fee (Section 6.20 madde 2.5): the upload was
/// deduplicated, and the context saved no byte the network would otherwise have
/// stored.
///
/// WIRING: the upload path asks this before it charges a context fee.
#[must_use]
pub const fn context_fee_for_upload(saved_bytes: u64, full_match: bool) -> u64 {
    if full_match {
        0
    } else {
        context_savings_fee(saved_bytes)
    }
}

/// The Context Maintenance Pool: where every savings fee goes.
///
/// The pool is an accounting balance, not a second supply. It is paid to the
/// epoch's corpus maintainers (Section 6.20 madde 2.5) and never minted into;
/// [`Self::deposit`] is the only way it grows.
///
/// WIRING: the block-end maintenance of Section 6.19 pays the pool out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContextMaintenancePool {
    balance: u64,
    deposits: u64,
}

impl ContextMaintenancePool {
    /// An empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            balance: 0,
            deposits: 0,
        }
    }

    /// What the pool holds.
    #[must_use]
    pub const fn balance(&self) -> u64 {
        self.balance
    }

    /// How many fees the pool has taken in, so an operator can compare fees
    /// charged against fees paid out.
    #[must_use]
    pub const fn deposits(&self) -> u64 {
        self.deposits
    }

    /// Take one fee into the pool.
    pub fn deposit(&mut self, fee: u64) {
        self.balance = self.balance.saturating_add(fee);
        self.deposits = self.deposits.saturating_add(1);
    }

    /// Pay the maintainers of a renewal, at most what the pool holds.
    ///
    /// Returns what was paid, so the caller records the same number the pool
    /// lost. Asking for more than the balance is capped rather than refused: a
    /// pool that paid what it did not hold would mint.
    pub fn payout(&mut self, want: u64) -> u64 {
        let paid = want.min(self.balance);
        self.balance -= paid;
        paid
    }
}

/// One node's view of the context it serves, and the corpus behind it.
///
/// The corpus is a cache: it holds public contents that are candidates for the
/// next renewal. Nothing here is chain state and nothing here is hashed into
/// the state root; the manifest is what the chain stores.
///
/// WIRING: the upload and view paths hold one of these per node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextState {
    class: Option<ContentClass>,
    codec: u16,
    candidates: BTreeSet<CorpusMember>,
    burned: BTreeSet<[u8; 32]>,
    manifest: Option<ContextManifest>,
}

impl ContextState {
    /// An empty state: no class chosen, no members, no manifest.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            codec: CONTEXT_CODEC_LZ,
            candidates: BTreeSet::new(),
            burned: BTreeSet::new(),
            manifest: None,
        }
    }

    /// The manifest the chain currently stores, if a renewal has run.
    #[must_use]
    pub const fn manifest(&self) -> Option<&ContextManifest> {
        self.manifest.as_ref()
    }

    /// Offer a public object as a corpus candidate.
    ///
    /// `class` is the class the recogniser reached for the content (S0). The
    /// first offer fixes the context's class; every later offer must agree.
    ///
    /// WIRING: the upload path is the only caller; it offers every stored
    /// public object.
    ///
    /// # Errors
    ///
    /// [`ContextError::SealedContent`] for sealed content,
    /// [`ContextError::ClassMismatch`] when the offer belongs to another class,
    /// and [`ContextError::CorpusFull`] when the corpus is at its ceiling.
    pub fn offer(
        &mut self,
        class: ContentClass,
        sealed: bool,
        content: ContentId,
        commitment: [u8; 32],
    ) -> Result<(), ContextError> {
        if sealed {
            return Err(ContextError::SealedContent);
        }
        match self.class {
            None => self.class = Some(class),
            Some(current) if current != class => {
                return Err(ContextError::ClassMismatch {
                    context: current,
                    member: class,
                });
            }
            Some(_) => {}
        }
        if self.candidates.len() >= MAX_CORPUS_MEMBERS {
            return Err(ContextError::CorpusFull);
        }
        // A content that was burned may come back only as a fresh object; the
        // burned digest stays burned until the renewal drops it.
        self.burned.remove(&content.digest);
        self.candidates.insert(CorpusMember::new(content, commitment));
        Ok(())
    }

    /// Mark a content deleted. The member leaves the corpus at the next
    /// renewal.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotInCorpus`] when no candidate carries the digest; a
    /// deletion the corpus never held is not a context event.
    pub fn burn(&mut self, content: &ContentId) -> Result<(), ContextError> {
        let found = self
            .candidates
            .iter()
            .copied()
            .find(|member| member.content.digest == content.digest)
            .ok_or(ContextError::NotInCorpus)?;
        self.candidates.remove(&found);
        self.burned.insert(content.digest);
        Ok(())
    }

    /// Renew the context at `epoch`: fold the surviving corpus into a manifest.
    ///
    /// Every burned digest is dropped here and only here, which is what makes
    /// "burned content leaves at the next renewal" a rule rather than a
    /// promise. A dependent object may be re-coded under the new manifest; its
    /// content id never moves, because a content id is derived from the bytes.
    ///
    /// # Errors
    ///
    /// [`ContextError::NotAContextCodec`] when the codec was set to something
    /// outside [`CONTEXT_CODECS`], and [`ContextError::CorpusFull`] when the
    /// fold would exceed the ceiling.
    pub fn renew(&mut self, epoch: u64) -> Result<ContextManifest, ContextError> {
        let class = self.class.unwrap_or(ContentClass::Generic);
        let members: Vec<CorpusMember> = self
            .candidates
            .iter()
            .copied()
            .filter(|member| !self.burned.contains(&member.content.digest))
            .collect();
        let manifest = ContextManifest::new(class, self.codec, &members, epoch)?;
        self.burned.clear();
        self.manifest = Some(manifest);
        Ok(manifest)
    }

    /// Admit an object coded under this context, or refuse it while the path is
    /// closed.
    ///
    /// # Errors
    ///
    /// [`ContextError::ClosedAt`] with the height, which is the answer a testnet
    /// node gives every time until [`CONTEXT_OPEN_AT`] holds a height.
    pub fn admit_context_object(&self, height: u64) -> Result<(), ContextError> {
        if context_is_open_at(height) {
            Ok(())
        } else {
            Err(ContextError::ClosedAt(height))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(byte: u8) -> ContentId {
        ContentId::public(&[byte; 32])
    }

    fn member(byte: u8) -> CorpusMember {
        CorpusMember::new(content(byte), [byte; 32])
    }

    fn a_state() -> ContextState {
        let mut state = ContextState::new();
        for byte in 1..=4u8 {
            state
                .offer(ContentClass::Records, false, content(byte), [byte; 32])
                .unwrap();
        }
        state
    }

    #[test]
    fn the_path_is_closed_on_the_testnet_chain() {
        let state = ContextState::new();
        assert!(!context_is_open_at(0));
        assert!(!context_is_open_at(u64::MAX - 1));
        assert_eq!(
            state.admit_context_object(7),
            Err(ContextError::ClosedAt(7)),
            "a closed path names the height it refused at"
        );
        assert_eq!(CONTEXT_OPEN_AT, None);
    }

    #[test]
    fn a_sealed_or_foreign_class_offer_is_refused() {
        let mut state = ContextState::new();
        assert_eq!(
            state.offer(ContentClass::Records, true, content(1), [1; 32]),
            Err(ContextError::SealedContent)
        );
        assert!(state
            .offer(ContentClass::Records, false, content(1), [1; 32])
            .is_ok());
        assert_eq!(
            state.offer(ContentClass::Image, false, content(2), [2; 32]),
            Err(ContextError::ClassMismatch {
                context: ContentClass::Records,
                member: ContentClass::Image,
            })
        );
        // A refused offer changes nothing: the renewal still folds one member.
        assert_eq!(state.renew(0).unwrap().member_count, 1);
    }

    #[test]
    fn a_renewal_drops_every_burned_digest() {
        let mut state = a_state();
        state.renew(10).unwrap();
        state.burn(&content(2)).unwrap();
        let manifest = state.renew(11).unwrap();
        assert_eq!(manifest.member_count, 3);
        assert_eq!(
            manifest.corpus_root,
            corpus_root(&[member(1), member(3), member(4)])
        );
        // Burning content the corpus never held is not a context event.
        assert_eq!(state.burn(&content(42)), Err(ContextError::NotInCorpus));
    }

    #[test]
    fn a_manifest_refuses_a_codec_that_is_not_a_context_codec() {
        assert_eq!(
            ContextManifest::new(ContentClass::Text, 1, &[], 0),
            Err(ContextError::NotAContextCodec(1))
        );
        assert!(ContextManifest::new(ContentClass::Text, CONTEXT_CODEC_MACHINE, &[], 0).is_ok());
        // Two manifests that differ in one field are two contexts.
        let a =
            ContextManifest::new(ContentClass::Text, CONTEXT_CODEC_LZ, &[member(1)], 4).unwrap();
        let mut b = a;
        b.built_at_epoch = 5;
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn the_corpus_fold_is_order_independent_and_counts_members() {
        let forward = corpus_root(&[member(1), member(2), member(3)]);
        let backward = corpus_root(&[member(3), member(2), member(1)]);
        assert_eq!(forward, backward);
        assert_ne!(forward, corpus_root(&[member(1), member(2)]));
        assert_ne!(
            corpus_root(&[member(1), member(1)]),
            corpus_root(&[member(1)]),
            "a repeated member is a different corpus"
        );
    }

    #[test]
    fn a_zero_saving_pays_nothing() {
        assert_eq!(context_savings_fee(0), 0);
        assert_eq!(context_fee_for_upload(0, false), 0);
        assert_eq!(context_savings_fee(1), 1, "a sub-unit saving still pays one");
        assert_eq!(context_savings_fee(GIB), CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB);
        assert_eq!(
            context_savings_fee(GIB.saturating_mul(2)),
            CONTEXT_SAVINGS_FEE_MICRO_BUD_PER_GIB.saturating_mul(2)
        );
    }
}
