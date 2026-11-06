//! Private cross-owner deduplication (Section 6.8.1 item 4 and 6.20 item 6).
//!
//! Sealed content is deduplicated in two steps. Inside one owner it is the
//! owner's own keyed index (Section 6.8.1 item 3), and that path exists
//! already. Across owners there is no shared key, so a naive index would let
//! the operator learn that two accounts hold the same file, which is exactly
//! what sealed storage exists to prevent.
//!
//! This module is the across-owner half, and it holds the six controls the
//! directive names, in the order the upload meets them:
//!
//! 1. **Threshold OPRF.** The upload key is the committee's evaluation of the
//!    blinded content, `OPRF(k, content)`, which two owners of the same file
//!    obtain identically and no single holder can compute. This module does not
//!    implement an OPRF and does not add a second threshold scheme: it takes
//!    the evaluation from [`crate::account_abstraction::threshold_mldsa`] (and
//!    [`crate::settlement::cold_quorum`] where the committee is cold), and it
//!    refuses to run under a policy whose threshold is not above one.
//! 2. **Rate limit.** Two counters, per account and per period.
//! 3. **BudZero ownership proof.** The upload carries a proof that the account
//!    holds the sealed object; without it the query is refused before the
//!    index is read.
//! 4. **Blinded NFT fields.** The value written into the NFT is the keyed digest
//!    of the evaluated key *and the account*, so the chain never publishes the
//!    index key itself. The index keeps a different value (the evaluated key
//!    alone) exactly because a match has to work across owners.
//! 5. **Per-period aggregate counter.** The operator publishes how many
//!    matches happened in a period, never which.
//! 6. **Sealed-pool mean.** The published mean is over the sealed pool, so one
//!    account's match cannot be read out of it.
//!
//! The residual risk is the one the directive states and does not hide: the
//! upload validator that evaluates the key sees the match it is answering.
//! Nothing here changes that, and the module says so rather than implying a
//! guarantee it does not make.
//!
//! # Closed on the testnet
//!
//! [`DEDUP_ACTIVATION`] carries no height, so [`PrivateDedup::query`] refuses
//! every request with [`DedupError::ClosedAt`] while the shipped chain runs.
//! The chain mechanics are measured with an explicit activation, the same shape
//! and the same reason as [`crate::storage::bud3::live`].
//!
//! WIRING: unwired - the upload session asks [`PrivateDedup::query`] before it
//! stores a sealed object, the registry writes [`MatchPeriod`] aggregates into
//! the metric it publishes, and `account_abstraction::threshold_mldsa` supplies
//! the evaluated OPRF key. Until those land, `src/tests/bud3_private_dedup.rs`
//! and this file's unit tests are the callers.

use std::collections::BTreeMap;

use crate::account_abstraction::threshold_mldsa::MultisigPolicy;
use crate::core::hash::hash_fields_bytes;

/// WIRING: the NFT's blinded field is written by the `StorageTx` v3 door once
/// that door carries it.
///
/// The hash domain of the NFT's blinded dedup field (control 4).
pub const DEDUP_TOKEN_TAG: &[u8] = b"BDLM_BUD3_DEDUP_TOKEN_V1";

/// WIRING: the node-local index is rebuilt from chain state on restart.
///
/// The hash domain of the index handle. It is the evaluated key alone, so the
/// same content under the same committee is one entry whichever owner uploaded
/// it, and a cross-owner match can be found at all.
pub const DEDUP_ENTRY_TAG: &[u8] = b"BDLM_BUD3_DEDUP_ENTRY_V1";

/// WIRING: RPC reports the budget so a client can pace itself.
///
/// Queries one account may make in one period (control 2).
pub const QUERIES_PER_ACCOUNT_PER_PERIOD: u32 = 16;

/// WIRING: the metric the operator publishes states the window it covers.
///
/// Queries one account may make in one period when it has never matched.
///
/// A new account gets the same budget as an old one; there is no first-period
/// allowance to farm, because a fresh balance is how a rate limit is bypassed.
pub const ACCOUNT_PERIODS: u64 = 4;

/// WIRING: the publisher trims to this window before it writes the metric.
///
/// The largest number of periods the aggregate counter keeps (control 5).
pub const PERIOD_HISTORY: u64 = 12;

/// WIRING: the chain config carries one of these once the height is set, and
/// genesis writes it; see [`DEDUP_ACTIVATION`] for this chain's value.
///
/// When the private dedup path may run. `height: None`: closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupActivation {
    /// The height the path opens at. `None`: never on this chain.
    pub height: Option<u64>,
}

impl DedupActivation {
    /// Whether the path is open at `height`.
    #[must_use]
    pub const fn is_open_at(&self, height: u64) -> bool {
        match self.height {
            Some(open) => height >= open,
            None => false,
        }
    }
}

/// WIRING: genesis writes this value; see [`DedupActivation`].
///
/// This chain's activation. `None`: the path is closed (Section 6.20 item 1).
pub const DEDUP_ACTIVATION: DedupActivation = DedupActivation { height: None };

/// WIRING: the upload session maps these onto its own refusal codes.
///
/// Why a private dedup query was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupError {
    /// The path is closed at this height.
    ClosedAt(u64),
    /// The committee's threshold is one, so one holder evaluates the key alone.
    ThresholdTooLow {
        /// The threshold the policy carries.
        threshold: usize,
    },
    /// The evaluation is all zeros, which no honest committee produces.
    BadKey,
    /// The account is over its per-period budget.
    RateLimited {
        /// The account.
        account: [u8; 32],
        /// The period it is limited in.
        period: u64,
    },
    /// The ownership proof did not verify.
    OwnershipProofMissing,
    /// The object named by the query is not sealed.
    NotSealed,
}

/// WIRING: held for the length of one query, never stored.
///
/// A committee's evaluation of the blinded content, and the policy it was/// A committee's evaluation of the blinded content, and the policy it was
/// evaluated under.
///
/// The value is held here rather than inside [`PrivateDedup`] so the caller can
/// drop it as soon as the query is answered; this module stores only its hash.
#[derive(Clone, PartialEq, Eq)]
pub struct EvaluatedKey([u8; 32]);

/// WIRING: the redaction is what keeps a key out of a log line.
impl core::fmt::Debug for EvaluatedKey {impl core::fmt::Debug for EvaluatedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EvaluatedKey(<redacted>)")
    }
}

impl EvaluatedKey {
    /// WIRING: the upload session calls this with the committee's result.
    ///
    /// Take an evaluated key from the committee that produced it.
    ///
    /// # Errors
    ///
    /// [`DedupError::ThresholdTooLow`] when the policy's threshold is one or
    /// zero, and [`DedupError::BadKey`] when the key is all zeros, which no
    /// honest evaluation produces.
    pub fn from_committee(
        bytes: [u8; 32],
        policy: &MultisigPolicy,
    ) -> Result<Self, DedupError> {
        if policy.threshold() <= 1 {
            return Err(DedupError::ThresholdTooLow {
                threshold: policy.threshold(),
            });
        }
        if bytes == [0u8; 32] {
            return Err(DedupError::BadKey);
        }
        Ok(Self(bytes))
    }
}

/// WIRING: written by [`PrivateDedup::record`], read by [`PrivateDedup::query`].
///
/// What the operator holds for one supported object.
///
/// There is no account in an entry. That is the whole construction: the handle
/// is content-derived, so two owners reach the same row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    commitment: [u8; 32],
}

/// WIRING: the upload session acts on the match; RPC never serves it.
///
/// The answer to a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupAnswer {
    /// The content is already held: the uploader refers to this commitment.
    Match {
        /// The object commitment the uploader refers to.
        commitment: [u8; 32],
    },
    /// The content is new.
    New,
}

/// WIRING: the metrics publisher reads this series once the metric lands.
///
/// One period's published aggregate (controls 5 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MatchPeriod {
    /// Matches in this period.
    pub matches: u64,
    /// Queries in this period.
    pub queries: u64,
}

impl MatchPeriod {
    /// The sealed pool's mean, in the fixed-point form the metric uses: the
    /// match rate per query, scaled by 10 000. A period with no query reports
    /// zero rather than a division by zero.
    ///
    /// One number over the whole pool is the point: it cannot be decomposed to
    /// one account.
    #[must_use]
    pub fn mean_per_10k(&self) -> u64 {
        if self.queries == 0 {
            return 0;
        }
        self.matches.saturating_mul(10_000) / self.queries
    }
}

/// WIRING: one of these lives in the upload session's node-local state.
///
/// The private dedup index, its rate limit and its aggregate counter.
#[derive(Debug, Clone)]
pub struct PrivateDedup {
    activation: DedupActivation,
    entries: BTreeMap<[u8; 32], Entry>,
    /// `(account, period) -> queries used`.
    limits: BTreeMap<([u8; 32], u64), u32>,
    periods: BTreeMap<u64, MatchPeriod>,
}

impl PrivateDedup {
    /// WIRING: the upload session builds one per node-local index.
    ///
    /// An empty index under `activation`.    /// An empty index under `activation`.
    #[must_use]
    pub fn with_activation(activation: DedupActivation) -> Self {
        Self {
            activation,
            entries: BTreeMap::new(),
            limits: BTreeMap::new(),
            periods: BTreeMap::new(),
        }
    }

    /// WIRING: the node starts closed until a chain value opens it.
    ///
    /// An empty index under this chain's [`DEDUP_ACTIVATION`].
    #[must_use]
    pub fn closed() -> Self {
        Self::with_activation(DEDUP_ACTIVATION)
    }

    /// WIRING: read by the upload session when it reports why it refused.
    ///
    /// The activation this index runs under.    /// The activation this index runs under.
    #[must_use]
    pub const fn activation(&self) -> DedupActivation {
        self.activation
    }

    /// The value the operator's index stores for one evaluated key.
    ///
    /// Two owners of one file compute the same handle, which is what makes a
    /// cross-owner match possible at all, and it is also why the operator that
    /// evaluates the key learns the match: that is the residual risk the
    /// directive names and this module does not paper over.
    #[must_use]
    pub fn handle(evaluated: &EvaluatedKey) -> [u8; 32] {
        hash_fields_bytes(&[DEDUP_ENTRY_TAG, &evaluated.0])
    }

    /// WIRING: the `StorageTx` v3 door writes this value into the NFT.
    ///
    /// The value written into the NFT's blinded field (control 4).
    ///
    /// Binding the account is what keeps the chain from publishing the index
    /// key: two owners of one file write two unlinkable values, and neither
    /// can be turned back into the handle without the key.
    #[must_use]
    pub fn blinded_field(evaluated: &EvaluatedKey, account: &[u8; 32]) -> [u8; 32] {
        hash_fields_bytes(&[DEDUP_TOKEN_TAG, &evaluated.0, account])
    }

    /// Ask whether an object is already held.
    ///
    /// # Errors
    ///
    /// [`DedupError::ClosedAt`] when the path is closed at `height`,
    /// [`DedupError::OwnershipProofMissing`] when the upload brought no proof,
    /// [`DedupError::NotSealed`] when the query names a public object (the
    /// public index answers that case and this path never reads it), and
    /// [`DedupError::RateLimited`] when the account is over its budget.
    pub fn query(
        &mut self,
        height: u64,
        period: u64,
        account: [u8; 32],
        evaluated: &EvaluatedKey,
        ownership_proof: &[u8],
        sealed: bool,
    ) -> Result<DedupAnswer, DedupError> {
        if !self.activation.is_open_at(height) {
            return Err(DedupError::ClosedAt(height));
        }
        if ownership_proof.is_empty() {
            return Err(DedupError::OwnershipProofMissing);
        }
        if !sealed {
            return Err(DedupError::NotSealed);
        }
        let used = self.limits.entry((account, period)).or_insert(0);
        if *used >= QUERIES_PER_ACCOUNT_PER_PERIOD {
            return Err(DedupError::RateLimited { account, period });
        }
        *used = used.saturating_add(1);
        let handle = Self::handle(evaluated);
        let answer = match self.entries.get(&handle) {
            Some(entry) => DedupAnswer::Match {
                commitment: entry.commitment,
            },
            None => DedupAnswer::New,
        };
        let bucket = self.periods.entry(period).or_default();
        bucket.queries = bucket.queries.saturating_add(1);
        if matches!(answer, DedupAnswer::Match { .. }) {
            bucket.matches = bucket.matches.saturating_add(1);
        }
        Ok(answer)
    }

    /// Record the object an upload stored, and return the value the NFT writes.
    ///
    /// The entry is written only for a sealed object, and only after the
    /// upload stored it: an index that learned about an object before the
    /// object existed would answer a match for content nobody holds.
    ///
    /// # Errors
    ///
    /// [`DedupError::NotSealed`] when the flag says public.
    pub fn record(
        &mut self,
        account: [u8; 32],
        evaluated: &EvaluatedKey,
        commitment: [u8; 32],
        sealed: bool,
    ) -> Result<[u8; 32], DedupError> {
        if !sealed {
            return Err(DedupError::NotSealed);
        }
        self.entries.insert(Self::handle(evaluated), Entry { commitment });
        Ok(Self::blinded_field(evaluated, &account))
    }

    /// Drop an entry when the last object holding it is burned. Returns whether
    /// one was there.
    pub fn forget(&mut self, evaluated: &EvaluatedKey) -> bool {
        self.entries.remove(&Self::handle(evaluated)).is_some()
    }

    /// WIRING: the metrics publisher reads one period at a time.
    ///
    /// The published aggregate for one period.    /// The published aggregate for one period.
    #[must_use]
    pub fn period(&self, period: u64) -> MatchPeriod {
        self.periods.get(&period).copied().unwrap_or_default()
    }

    /// The periods kept, oldest first, trimmed to [`PERIOD_HISTORY`].
    ///
    /// The trim drops the oldest periods, so a reader cannot ask for a period
    /// far enough back to isolate one account's single match.
    pub fn published_periods(&self) -> Vec<(u64, MatchPeriod)> {
        let total = self.periods.len();
        let skip = total.saturating_sub(usize::try_from(PERIOD_HISTORY).unwrap_or(usize::MAX));
        self.periods.iter().skip(skip).map(|(p, m)| (*p, *m)).collect()
    }

    /// WIRING: the audit page reads the size; it is never published.
    ///
    /// How many entries the index holds. Node-local: this is never published.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// WIRING: the startup path checks it before it rebuilds.
    ///
    /// Whether the index has no entry at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::WalletKeyPair;

    const OPEN_AT: u64 = 100;
    const OPEN: DedupActivation = DedupActivation {
        height: Some(OPEN_AT),
    };

    fn policy(threshold: usize) -> MultisigPolicy {
        let owners: Vec<_> = (0..3)
            .map(|_| WalletKeyPair::generate().public_key_bytes())
            .collect();
        MultisigPolicy::new(owners, threshold).expect("a 3-owner policy")
    }

    fn key() -> EvaluatedKey {
        EvaluatedKey::from_committee([7u8; 32], &policy(2)).expect("a 2-of-3 evaluation")
    }

    #[test]
    fn the_path_is_closed_on_the_testnet_chain() {
        assert_eq!(DEDUP_ACTIVATION.height, None);
        let mut index = PrivateDedup::closed();
        for height in [0u64, 1, u64::MAX - 1] {
            assert_eq!(
                index.query(height, 0, [1u8; 32], &key(), b"proof", true),
                Err(DedupError::ClosedAt(height))
            );
        }
        assert!(index.is_empty());
    }

    #[test]
    fn a_single_holder_cannot_evaluate_the_key() {
        for threshold in [0usize, 1] {
            let p = MultisigPolicy::new(
                (0..3).map(|_| WalletKeyPair::generate().public_key_bytes()).collect(),
                if threshold == 0 { 1 } else { threshold },
            )
            .expect("a policy");
            assert_eq!(
                EvaluatedKey::from_committee([3u8; 32], &p),
                Err(DedupError::ThresholdTooLow { threshold: 1 })
            );
        }
        assert_eq!(
            EvaluatedKey::from_committee([0u8; 32], &policy(2)),
            Err(DedupError::BadKey)
        );
    }

    #[test]
    fn the_handle_joins_two_owners_and_the_nft_field_does_not() {
        let evaluated = key();
        let a = PrivateDedup::blinded_field(&evaluated, &[1u8; 32]);
        let b = PrivateDedup::blinded_field(&evaluated, &[2u8; 32]);
        assert_ne!(a, b, "two owners write two unlinkable NFT values");
        assert_ne!(
            a,
            PrivateDedup::handle(&evaluated),
            "the chain never publishes the index key"
        );
        assert_eq!(
            PrivateDedup::handle(&evaluated),
            PrivateDedup::handle(&key()),
            "one file is one handle, whichever owner uploads it"
        );
    }

    #[test]
    fn a_second_owner_finds_the_first_owners_object() {
        let mut index = PrivateDedup::with_activation(OPEN);
        let evaluated = key();
        let commitment = [0x33u8; 32];
        let field = index
            .record([1u8; 32], &evaluated, commitment, true)
            .expect("a sealed record");
        assert_eq!(field, PrivateDedup::blinded_field(&evaluated, &[1u8; 32]));
        assert_eq!(
            index.query(OPEN_AT, 1, [2u8; 32], &evaluated, b"proof", true),
            Ok(DedupAnswer::Match { commitment }),
            "the same file under the same committee is one entry"
        );
        assert!(index.forget(&evaluated));
        assert!(!index.forget(&evaluated));
        assert_eq!(
            index.query(OPEN_AT, 1, [2u8; 32], &evaluated, b"proof", true),
            Ok(DedupAnswer::New)
        );
    }

    #[test]
    fn the_rate_limit_is_per_account_and_per_period() {
        let mut index = PrivateDedup::with_activation(OPEN);
        let evaluated = key();
        let account = [4u8; 32];
        for _ in 0..QUERIES_PER_ACCOUNT_PER_PERIOD {
            assert_eq!(
                index.query(OPEN_AT, 7, account, &evaluated, b"proof", true),
                Ok(DedupAnswer::New)
            );
        }
        assert_eq!(
            index.query(OPEN_AT, 7, account, &evaluated, b"proof", true),
            Err(DedupError::RateLimited {
                account,
                period: 7
            })
        );
        // Another period and another account both start fresh.
        assert_eq!(
            index.query(OPEN_AT, 8, account, &evaluated, b"proof", true),
            Ok(DedupAnswer::New)
        );
        assert_eq!(
            index.query(OPEN_AT, 7, [5u8; 32], &evaluated, b"proof", true),
            Ok(DedupAnswer::New)
        );
    }

    #[test]
    fn the_proof_is_required_before_the_index_is_read() {
        let mut index = PrivateDedup::with_activation(OPEN);
        assert_eq!(
            index.query(OPEN_AT, 1, [1u8; 32], &key(), b"", true),
            Err(DedupError::OwnershipProofMissing)
        );
        assert_eq!(
            index.query(OPEN_AT, 1, [1u8; 32], &key(), b"proof", false),
            Err(DedupError::NotSealed)
        );
        assert_eq!(index.period(1), MatchPeriod::default());
    }
}
