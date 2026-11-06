//! Isolated UEL transaction mempool lanes (Section 8.6.3).
//!
//! Each envelope format owns an independent lane with its own capacity budget
//! and replay/ordering rule so congestion in one lane never starves another:
//!
//! 1. `Local` (native post-quantum envelopes, ordered by account `nonce`).
//! 2. `Ethereum` (foreign EIP-155 envelopes, ordered by EVM `nonce`).
//! 3. `Solana` (foreign versioned txs, 150-block recent blockhash window + sig dedup).
//! 4. `Aptos` (foreign BCS `SignedTransaction`, `sequence_number` + `expiration_unix_s`).
//! 5. `Cosmos` (foreign `TxRaw`, `account_number` + `sequence`).
//! 6. `Duty` (mobile/full validator duty batches, rate-limited to 1 per window).
//!
//! Block proposers draw across all non-empty lanes ordered by effective
//! priority fee per BGU (`effective_priority_fee_atto`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Recent blockhash window length for the Solana foreign lane (Section 8.6.2).
pub const SOLANA_BLOCKHASH_WINDOW: usize = 150;

/// The 32-byte digest the Solana lane keeps for a 64-byte signature.
///
/// The lane stores one digest per signature, not the signature itself, because
/// the cache outlives the transaction and a digest is not a credential.
fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(bytes).into()
}

/// Envelope lane classification (Section 8.6.3 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaneKind {
    Local,
    Ethereum,
    Solana,
    Aptos,
    Cosmos,
    Duty,
}

/// Replay and ordering metadata attached to a lane entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneReplayRule {
    /// Monotonic account nonce (`Local` and `Ethereum`).
    AccountNonce { sender: [u8; 32], nonce: u64 },
    /// Solana recent-blockhash + 64-byte signature replay check.
    SolanaWindow {
        recent_blockhash: [u8; 32],
        signature_digest: [u8; 32],
    },
    /// Aptos sequence number with strict expiration timestamp.
    AptosSequence {
        sender: [u8; 32],
        sequence: u64,
        expiration_unix_s: u64,
    },
    /// Cosmos `(account_number, sequence)` pair.
    CosmosSequence {
        sender: [u8; 32],
        account_number: u64,
        sequence: u64,
    },
    /// Validator duty batch bounded to one submission per `(validator, window_id)`.
    DutyWindow {
        validator: [u8; 32],
        window_id: u64,
    },
}

/// One admitted transaction sitting in a UEL mempool lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneEntry {
    pub tx_hash: [u8; 32],
    pub lane: LaneKind,
    pub replay: LaneReplayRule,
    pub gas_limit_bgu: u64,
    pub max_fee_per_bgu_atto: u128,
    pub max_priority_fee_per_bgu_atto: u128,
    pub raw_bytes: Vec<u8>,
}

impl LaneEntry {
    /// Effective priority tip per BGU at `base_fee_atto`, or `None` if unaffordable.
    #[must_use]
    pub fn effective_priority_fee(&self, base_fee_atto: u128) -> Option<u128> {
        let headroom = self.max_fee_per_bgu_atto.checked_sub(base_fee_atto)?;
        Some(headroom.min(self.max_priority_fee_per_bgu_atto))
    }
}

/// Refusal reasons when admitting an entry into [`MultiLaneMempool`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneAdmissionError {
    /// Replay rule variant did not match `entry.lane`.
    MismatchedReplayRule,
    /// Target lane reached its independent entry or byte cap.
    LaneFull(LaneKind),
    /// Duplicate transaction hash or replayed nonce/signature/duty window.
    ReplayRejected(&'static str),
    /// Expired Aptos transaction or unknown Solana recent blockhash.
    StaleOrExpired(&'static str),
}

impl fmt::Display for LaneAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MismatchedReplayRule => write!(f, "replay rule does not match lane kind"),
            Self::LaneFull(lane) => write!(f, "mempool lane {lane:?} is full"),
            Self::ReplayRejected(why) => write!(f, "replay rejected: {why}"),
            Self::StaleOrExpired(why) => write!(f, "stale or expired envelope: {why}"),
        }
    }
}

impl std::error::Error for LaneAdmissionError {}

#[derive(Debug, Default)]
struct SingleLane {
    entries: BTreeMap<[u8; 32], LaneEntry>,
    used_bytes: usize,
    sender_nonces: BTreeSet<([u8; 32], u64)>,
}

/// Six-lane isolated transaction pool with priority-fee cross-lane selection.
#[derive(Debug)]
pub struct MultiLaneMempool {
    max_entries_per_lane: usize,
    max_bytes_per_lane: usize,
    lanes: BTreeMap<LaneKind, SingleLane>,
    recent_blockhashes: VecDeque<[u8; 32]>,
    seen_solana_sigs: BTreeSet<[u8; 32]>,
    seen_duty_windows: BTreeSet<([u8; 32], u64)>,
}

impl MultiLaneMempool {
    /// Create a multi-lane pool with isolated per-lane entry and byte caps.
    ///
    /// Convenience: exposed for node mempool initialization and lane-isolation tests.
    #[must_use]
    pub fn new(max_entries_per_lane: usize, max_bytes_per_lane: usize) -> Self {
        Self {
            max_entries_per_lane,
            max_bytes_per_lane,
            lanes: BTreeMap::new(),
            recent_blockhashes: VecDeque::new(),
            seen_solana_sigs: BTreeSet::new(),
            seen_duty_windows: BTreeSet::new(),
        }
    }

    /// Record a new canonical Budlum block hash, retaining the latest 150 hashes.
    ///
    /// Convenience: called at block commit to advance the Solana blockhash window.
    pub fn push_recent_blockhash(&mut self, block_hash: [u8; 32]) {
        if self.recent_blockhashes.len() >= SOLANA_BLOCKHASH_WINDOW {
            let _ = self.recent_blockhashes.pop_front();
        }
        self.recent_blockhashes.push_back(block_hash);
    }

    /// Admit a verified foreign Solana envelope into the `Solana` lane.
    ///
    /// The envelope door
    /// ([`crate::execution::coordinator::foreign::solana::parse_foreign_solana`])
    /// has already checked the signatures, the account bounds and the replay set
    /// it was given. This method is the lane's own admission: it applies the same
    /// window and cache to the transaction's *own* blockhash and *first*
    /// signature, so a transaction that cleared the door cannot then jump the
    /// lane's budget or appear twice in a produced block.
    ///
    /// The signature recorded is the first, which is the fee payer's: the
    /// runtime's deduplication key for a Solana transaction.
    ///
    /// # Errors
    ///
    /// [`LaneAdmissionError::StaleOrExpired`] when the transaction's blockhash is
    /// outside the window, and [`LaneAdmissionError::ReplayRejected`] when its
    /// signature is already in the lane.
    pub fn admit_foreign_solana(
        &mut self,
        transaction: &crate::execution::coordinator::foreign::solana::ForeignSolanaTransaction,
        now_unix_s: u64,
    ) -> Result<(), LaneAdmissionError> {
        let signature = transaction.signatures.first().copied().ok_or(
            LaneAdmissionError::ReplayRejected("a Solana transaction with no signature"),
        )?;
        let entry = LaneEntry {
            // The runtime's own deduplication key for a Solana transaction is its
            // first signature, so the lane keys on the same bytes.
            tx_hash: signature[..32].try_into().map_err(|_| {
                LaneAdmissionError::ReplayRejected("a Solana signature shorter than 32 bytes")
            })?,
            lane: LaneKind::Solana,
            replay: LaneReplayRule::SolanaWindow {
                recent_blockhash: transaction.recent_blockhash,
                signature_digest: sha256_32(&signature),
            },
            // A Solana transaction carries a compute-unit limit and a
            // micro-lamport priority fee, not a BGU budget. The conversion is
            // WP-31's fee step (directive 8.9), so the lane admits the envelope
            // without pricing it and the block producer prices it later.
            gas_limit_bgu: 0,
            max_fee_per_bgu_atto: 0,
            max_priority_fee_per_bgu_atto: 0,
            raw_bytes: Vec::new(),
        };
        self.admit(entry, now_unix_s)
    }

    /// The Solana blockhash window, newest last, as the door reads it.
    #[must_use]
    pub fn solana_blockhash_window(&self) -> Vec<[u8; 32]> {
        self.recent_blockhashes.iter().copied().collect()
    }

    /// Number of queued transactions in `lane`.
    ///
    /// Convenience: exposed for per-lane Prometheus gauges.
    #[must_use]
    pub fn lane_len(&self, lane: LaneKind) -> usize {
        self.lanes.get(&lane).map_or(0, |l| l.entries.len())
    }

    /// Admit `entry` into its dedicated lane after validating lane capacity and replay rules.
    ///
    /// Convenience: entry point for local, foreign-gateway, and duty transaction submission.
    pub fn admit(&mut self, entry: LaneEntry, now_unix_s: u64) -> Result<(), LaneAdmissionError> {
        // 1. Validate lane <-> replay rule match and replay/freshness BEFORE mutating!
        let nonce_pair: Option<([u8; 32], u64)> = match (&entry.lane, &entry.replay) {
            (LaneKind::Local | LaneKind::Ethereum, LaneReplayRule::AccountNonce { sender, nonce }) => {
                Some((*sender, *nonce))
            }
            (
                LaneKind::Solana,
                LaneReplayRule::SolanaWindow {
                    recent_blockhash,
                    signature_digest,
                },
            ) => {
                if !self.recent_blockhashes.contains(recent_blockhash) {
                    return Err(LaneAdmissionError::StaleOrExpired(
                        "recent_blockhash outside 150-block window",
                    ));
                }
                if self.seen_solana_sigs.contains(signature_digest) {
                    return Err(LaneAdmissionError::ReplayRejected(
                        "duplicate Solana signature",
                    ));
                }
                None
            }
            (
                LaneKind::Aptos,
                LaneReplayRule::AptosSequence {
                    sender,
                    sequence,
                    expiration_unix_s,
                },
            ) => {
                if *expiration_unix_s <= now_unix_s {
                    return Err(LaneAdmissionError::StaleOrExpired("Aptos tx expired"));
                }
                Some((*sender, *sequence))
            }
            (
                LaneKind::Cosmos,
                LaneReplayRule::CosmosSequence {
                    sender, sequence, ..
                },
            ) => Some((*sender, *sequence)),
            (
                LaneKind::Duty,
                LaneReplayRule::DutyWindow {
                    validator,
                    window_id,
                },
            ) => {
                if self.seen_duty_windows.contains(&(*validator, *window_id)) {
                    return Err(LaneAdmissionError::ReplayRejected(
                        "second duty batch in same window",
                    ));
                }
                None
            }
            _ => return Err(LaneAdmissionError::MismatchedReplayRule),
        };

        let existing_lane = self.lanes.get(&entry.lane);
        if existing_lane.is_some_and(|l| l.entries.contains_key(&entry.tx_hash)) {
            return Err(LaneAdmissionError::ReplayRejected("duplicate tx_hash"));
        }
        if let Some(pair) = nonce_pair {
            if existing_lane.is_some_and(|l| l.sender_nonces.contains(&pair)) {
                return Err(LaneAdmissionError::ReplayRejected(
                    "duplicate sender nonce/sequence in lane",
                ));
            }
        }
        let current_len = existing_lane.map_or(0, |l| l.entries.len());
        let current_bytes = existing_lane.map_or(0, |l| l.used_bytes);
        if current_len >= self.max_entries_per_lane
            || current_bytes.saturating_add(entry.raw_bytes.len()) > self.max_bytes_per_lane
        {
            return Err(LaneAdmissionError::LaneFull(entry.lane));
        }

        // 2. Commit into the target lane only after every check succeeded.
        if let LaneReplayRule::SolanaWindow {
            signature_digest, ..
        } = &entry.replay
        {
            self.seen_solana_sigs.insert(*signature_digest);
        }
        if let LaneReplayRule::DutyWindow {
            validator,
            window_id,
        } = &entry.replay
        {
            self.seen_duty_windows.insert((*validator, *window_id));
        }
        let lane_slot = self.lanes.entry(entry.lane).or_default();
        if let Some(pair) = nonce_pair {
            lane_slot.sender_nonces.insert(pair);
        }
        lane_slot.used_bytes = lane_slot.used_bytes.saturating_add(entry.raw_bytes.len());
        lane_slot.entries.insert(entry.tx_hash, entry);
        Ok(())
    }

    /// Select transactions across all lanes ordered by descending effective priority fee per BGU,
    /// respecting `block_bgu_budget`.
    ///
    /// Convenience: called by the block proposer when assembling UEL execution batches.
    #[must_use]
    pub fn select_for_block(&self, base_fee_atto: u128, block_bgu_budget: u64) -> Vec<LaneEntry> {
        let mut candidates: Vec<(u128, LaneEntry)> = Vec::new();
        for lane in self.lanes.values() {
            for entry in lane.entries.values() {
                if let Some(tip) = entry.effective_priority_fee(base_fee_atto) {
                    candidates.push((tip, entry.clone()));
                }
            }
        }
        // Sort descending by effective priority fee, breaking ties deterministically by tx_hash.
        candidates.sort_by(|(tip_a, a), (tip_b, b)| {
            tip_b.cmp(tip_a).then_with(|| a.tx_hash.cmp(&b.tx_hash))
        });

        let mut picked = Vec::new();
        let mut used_bgu: u64 = 0;
        for (_, entry) in candidates {
            if used_bgu.saturating_add(entry.gas_limit_bgu) <= block_bgu_budget {
                used_bgu = used_bgu.saturating_add(entry.gas_limit_bgu);
                picked.push(entry);
            }
        }
        picked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ethereum_lane_never_blocks_local_or_solana_and_proposer_sorts_by_tip() {
        let mut pool = MultiLaneMempool::new(1, 4096);
        let bh = [0x77; 32];
        pool.push_recent_blockhash(bh);

        // Fill Ethereum lane to capacity (1).
        pool.admit(
            LaneEntry {
                tx_hash: [1u8; 32],
                lane: LaneKind::Ethereum,
                replay: LaneReplayRule::AccountNonce {
                    sender: [0xAA; 32],
                    nonce: 0,
                },
                gas_limit_bgu: 21_000,
                max_fee_per_bgu_atto: 100,
                max_priority_fee_per_bgu_atto: 10,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        assert_eq!(
            pool.admit(
                LaneEntry {
                    tx_hash: [2u8; 32],
                    lane: LaneKind::Ethereum,
                    replay: LaneReplayRule::AccountNonce {
                        sender: [0xBB; 32],
                        nonce: 0,
                    },
                    gas_limit_bgu: 21_000,
                    max_fee_per_bgu_atto: 100,
                    max_priority_fee_per_bgu_atto: 20,
                    raw_bytes: vec![0u8; 32],
                },
                1_000,
            ),
            Err(LaneAdmissionError::LaneFull(LaneKind::Ethereum))
        );

        // Local and Solana lanes remain completely open!
        pool.admit(
            LaneEntry {
                tx_hash: [3u8; 32],
                lane: LaneKind::Local,
                replay: LaneReplayRule::AccountNonce {
                    sender: [0xCC; 32],
                    nonce: 0,
                },
                gas_limit_bgu: 50_000,
                max_fee_per_bgu_atto: 200,
                max_priority_fee_per_bgu_atto: 80,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        pool.admit(
            LaneEntry {
                tx_hash: [4u8; 32],
                lane: LaneKind::Solana,
                replay: LaneReplayRule::SolanaWindow {
                    recent_blockhash: bh,
                    signature_digest: [0x99; 32],
                },
                gas_limit_bgu: 30_000,
                max_fee_per_bgu_atto: 150,
                max_priority_fee_per_bgu_atto: 40,
                raw_bytes: vec![0u8; 32],
            },
            1_000,
        )
        .unwrap();

        let batch = pool.select_for_block(50, 1_000_000);
        assert_eq!(batch.len(), 3);
        // Ordered by effective tip descending: Local (80), Solana (40), Ethereum (10).
        assert_eq!(batch[0].lane, LaneKind::Local);
        assert_eq!(batch[1].lane, LaneKind::Solana);
        assert_eq!(batch[2].lane, LaneKind::Ethereum);
    }

    #[test]
    fn a_verified_solana_envelope_lands_in_its_own_lane_and_never_twice() {
        use crate::execution::coordinator::foreign::solana::{
            parse_foreign_solana, ForeignSolanaTransaction,
        };
        use ed25519_dalek::{Signer, SigningKey};

        // A one-signer legacy transfer over a blockhash the lane window holds.
        let key = SigningKey::from_bytes(&[21u8; 32]);
        let blockhash = [0x7Au8; 32];
        // Header `1, 0, 1`: one signer, and the program is a readonly non-signer
        // so the readonly band covers it.
        let mut message = vec![1u8, 0, 1, 2];
        message.extend_from_slice(&key.verifying_key().to_bytes());
        message.extend_from_slice(&[0xEEu8; 32]);
        message.extend_from_slice(&blockhash);
        message.push(1);
        message.extend_from_slice(&[1, 1, 0, 1, 0]);
        let mut wire = vec![1u8];
        wire.extend_from_slice(&key.sign(&message).to_bytes());
        wire.extend_from_slice(&message);

        let mut pool = MultiLaneMempool::new(8, 4096);
        pool.push_recent_blockhash(blockhash);
        let transaction: ForeignSolanaTransaction =
            parse_foreign_solana(&wire, &[], &pool.solana_blockhash_window(), &[]).unwrap();

        // The first admission lands in the Solana lane.
        pool.admit_foreign_solana(&transaction, 1_000).unwrap();
        assert_eq!(pool.lane_len(LaneKind::Solana), 1);

        // The same transaction again is refused by the signature cache.
        assert_eq!(
            pool.admit_foreign_solana(&transaction, 1_000),
            Err(LaneAdmissionError::ReplayRejected(
                "duplicate Solana signature"
            ))
        );

        // An unknown blockhash is stale, and the window the door reads and the
        // window the lane enforces are the same list.
        let mut stale = transaction.clone();
        stale.recent_blockhash = [0x01u8; 32];
        assert!(matches!(
            pool.admit_foreign_solana(&stale, 1_000),
            Err(LaneAdmissionError::StaleOrExpired(_))
        ));
    }
}
