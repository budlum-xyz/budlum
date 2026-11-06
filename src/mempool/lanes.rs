//! Multi-lane transaction pool scheduler for UEL and validator duty envelopes.
//!
//! Implements section 8.6.3:
//! - Six isolated lanes (`Native`, `Ethereum`, `Solana`, `Aptos`, `Cosmos`, `Duty`).
//! - Independent entry and byte budgets per lane so a flood in one envelope
//!   format never evicts or blocks another lane.
//! - Per-lane replay/ordering discipline (sender nonce/sequence for account
//!   lanes; recent-blockhash signature deduplication for Solana).
//! - Deterministic cross-lane proposer selection by effective priority fee per
//!   BGU descending, then `tx_id` ascending.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Default entry ceiling for each envelope lane.
pub const DEFAULT_LANE_MAX_ENTRIES: usize = 4_096;
/// Default resident byte ceiling for each envelope lane (32 MiB).
pub const DEFAULT_LANE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Solana recent-blockhash validity window in blocks (section 8.6.2).
pub const SOLANA_RECENT_BLOCKHASH_WINDOW: usize = 150;

/// Envelope lane classification (section 8.6.3 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnvelopeLane {
    /// Native PQ Budlum transactions (`Execute`, `Transfer`, `Settlement`, etc.).
    Native,
    /// Raw RLP Ethereum transactions (`ForeignTx::Ethereum`).
    Ethereum,
    /// Versioned Solana messages (`ForeignTx::Solana`).
    Solana,
    /// BCS Aptos signed transactions (`ForeignTx::Aptos`).
    Aptos,
    /// `cosmos.tx.v1beta1.TxRaw` envelopes (`ForeignTx::Cosmos`).
    Cosmos,
    /// Rate-limited validator duty lane (presence, custody proofs, participation).
    Duty,
}

impl EnvelopeLane {
    /// All six lanes in canonical iteration order.
    pub const ALL: [Self; 6] = [
        Self::Native,
        Self::Ethereum,
        Self::Solana,
        Self::Aptos,
        Self::Cosmos,
        Self::Duty,
    ];
}

/// Lane-specific ordering credential carried at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaneOrdering {
    /// Account sequence / nonce ordering (`sender_key`, `sequence`).
    AccountSequence { sender: Vec<u8>, sequence: u64 },
    /// Solana recent-blockhash window + signature deduplication.
    RecentBlockhash {
        recent_blockhash: [u8; 32],
        signature_digest: [u8; 32],
    },
}

/// One admitted envelope entry waiting in its lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneEntry {
    pub tx_id: [u8; 32],
    pub lane: EnvelopeLane,
    pub ordering: LaneOrdering,
    pub gas_limit_bgu: u64,
    pub effective_priority_fee_attos: u128,
    pub raw_bytes: Vec<u8>,
}

/// Per-lane budget configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneBudget {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for LaneBudget {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_LANE_MAX_ENTRIES,
            max_bytes: DEFAULT_LANE_MAX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SingleLaneState {
    budget: LaneBudget,
    used_bytes: usize,
    entries: BTreeMap<[u8; 32], LaneEntry>,
    account_nonces: BTreeMap<(Vec<u8>, u64), [u8; 32]>,
    seen_solana_sigs: BTreeSet<[u8; 32]>,
}

/// Multi-lane pool enforcing isolated per-lane budgets and cross-lane priority selection.
#[derive(Debug, Clone)]
pub struct MultiLanePool {
    lanes: BTreeMap<EnvelopeLane, SingleLaneState>,
    recent_blockhashes: Vec<[u8; 32]>,
}

impl Default for MultiLanePool {
    fn default() -> Self {
        Self::new(LaneBudget::default())
    }
}

impl MultiLanePool {
    /// Builds a six-lane pool where each lane gets `default_budget`.
    #[must_use]
    pub fn new(default_budget: LaneBudget) -> Self {
        let mut lanes = BTreeMap::new();
        for lane in EnvelopeLane::ALL {
            lanes.insert(
                lane,
                SingleLaneState {
                    budget: default_budget,
                    ..SingleLaneState::default()
                },
            );
        }
        Self {
            lanes,
            recent_blockhashes: Vec::new(),
        }
    }

    /// Overrides the budget of a single lane without touching other lanes.
    ///
    /// exposed for: node configuration and duty-lane sizing (`WP-13`, `WP-27`).
    pub fn set_lane_budget(&mut self, lane: EnvelopeLane, budget: LaneBudget) {
        if let Some(st) = self.lanes.get_mut(&lane) {
            st.budget = budget;
        }
    }

    /// Records a newly finalized Budlum block hash in the 150-block Solana replay window.
    ///
    /// exposed for: block commit maintenance and Solana lane admission (`WP-31`).
    pub fn note_blockhash(&mut self, block_hash: [u8; 32]) {
        if !self.recent_blockhashes.contains(&block_hash) {
            self.recent_blockhashes.push(block_hash);
        }
        while self.recent_blockhashes.len() > SOLANA_RECENT_BLOCKHASH_WINDOW {
            self.recent_blockhashes.remove(0);
        }
    }

    /// Admits `entry` into its declared lane if the lane's own budget and replay rules pass.
    pub fn admit(&mut self, entry: LaneEntry) -> Result<(), String> {
        if entry.gas_limit_bgu == 0 {
            return Err(String::from("envelope gas_limit_bgu must be positive"));
        }
        let recent = &self.recent_blockhashes;
        let st = self
            .lanes
            .get_mut(&entry.lane)
            .ok_or_else(|| String::from("unknown envelope lane"))?;

        if st.entries.contains_key(&entry.tx_id) {
            return Err(String::from("duplicate tx_id in lane"));
        }
        let body_len = entry.raw_bytes.len();
        if st.entries.len() >= st.budget.max_entries {
            return Err(format!("lane {:?} entry budget exhausted", entry.lane));
        }
        if st.used_bytes.saturating_add(body_len) > st.budget.max_bytes {
            return Err(format!("lane {:?} byte budget exhausted", entry.lane));
        }

        match &entry.ordering {
            LaneOrdering::AccountSequence { sender, sequence } => {
                let key = (sender.clone(), *sequence);
                if st.account_nonces.contains_key(&key) {
                    return Err(String::from("conflicting sender sequence in lane"));
                }
                st.account_nonces.insert(key, entry.tx_id);
            }
            LaneOrdering::RecentBlockhash {
                recent_blockhash,
                signature_digest,
            } => {
                if !recent.contains(recent_blockhash) {
                    return Err(String::from("Solana recent_blockhash outside 150-block window"));
                }
                if st.seen_solana_sigs.contains(signature_digest) {
                    return Err(String::from("Solana signature replay refused"));
                }
                st.seen_solana_sigs.insert(*signature_digest);
            }
        }

        st.used_bytes = st.used_bytes.saturating_add(body_len);
        st.entries.insert(entry.tx_id, entry);
        Ok(())
    }

    /// Number of queued entries in `lane`.
    #[must_use]
    pub fn lane_len(&self, lane: EnvelopeLane) -> usize {
        self.lanes.get(&lane).map_or(0, |s| s.entries.len())
    }

    /// Selects ready envelopes across all lanes up to `block_bgu_limit`, ordered
    /// deterministically by `(effective_priority_fee_attos DESC, sequence ASC, tx_id ASC)`.
    #[must_use]
    pub fn select_for_block(&self, block_bgu_limit: u64) -> Vec<LaneEntry> {
        let mut candidates: Vec<&LaneEntry> = self
            .lanes
            .values()
            .flat_map(|s| s.entries.values())
            .collect();

        candidates.sort_by(|a, b| {
            let seq_a = match &a.ordering {
                LaneOrdering::AccountSequence { sequence, .. } => *sequence,
                LaneOrdering::RecentBlockhash { .. } => 0,
            };
            let seq_b = match &b.ordering {
                LaneOrdering::AccountSequence { sequence, .. } => *sequence,
                LaneOrdering::RecentBlockhash { .. } => 0,
            };
            let same_sender = match (&a.ordering, &b.ordering) {
                (
                    LaneOrdering::AccountSequence { sender: sa, .. },
                    LaneOrdering::AccountSequence { sender: sb, .. },
                ) => a.lane == b.lane && sa == sb,
                _ => false,
            };
            if same_sender {
                seq_a.cmp(&seq_b).then_with(|| a.tx_id.cmp(&b.tx_id))
            } else {
                b.effective_priority_fee_attos
                    .cmp(&a.effective_priority_fee_attos)
                    .then_with(|| seq_a.cmp(&seq_b))
                    .then_with(|| a.tx_id.cmp(&b.tx_id))
            }
        });

        let mut chosen = Vec::new();
        let mut used_bgu = 0u64;
        for item in candidates {
            if used_bgu.saturating_add(item.gas_limit_bgu) <= block_bgu_limit {
                used_bgu = used_bgu.saturating_add(item.gas_limit_bgu);
                chosen.push(item.clone());
            }
        }
        chosen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lane_does_not_block_other_lanes_and_selects_by_priority_fee() {
        let mut pool = MultiLanePool::new(LaneBudget {
            max_entries: 1,
            max_bytes: 1024,
        });
        let eth_entry = LaneEntry {
            tx_id: [1u8; 32],
            lane: EnvelopeLane::Ethereum,
            ordering: LaneOrdering::AccountSequence {
                sender: vec![0xAA; 20],
                sequence: 0,
            },
            gas_limit_bgu: 100_000,
            effective_priority_fee_attos: 10,
            raw_bytes: vec![1, 2, 3],
        };
        assert!(pool.admit(eth_entry).is_ok());

        // Ethereum lane is now full, so a second Ethereum tx is refused.
        let eth_overflow = LaneEntry {
            tx_id: [2u8; 32],
            lane: EnvelopeLane::Ethereum,
            ordering: LaneOrdering::AccountSequence {
                sender: vec![0xBB; 20],
                sequence: 0,
            },
            gas_limit_bgu: 100_000,
            effective_priority_fee_attos: 99,
            raw_bytes: vec![4, 5],
        };
        assert!(pool.admit(eth_overflow).is_err());

        // Native and Solana lanes remain completely unaffected.
        let bh = [0x77u8; 32];
        pool.note_blockhash(bh);
        let sol_entry = LaneEntry {
            tx_id: [3u8; 32],
            lane: EnvelopeLane::Solana,
            ordering: LaneOrdering::RecentBlockhash {
                recent_blockhash: bh,
                signature_digest: [0x55; 32],
            },
            gas_limit_bgu: 200_000,
            effective_priority_fee_attos: 50,
            raw_bytes: vec![9, 9],
        };
        assert!(pool.admit(sol_entry).is_ok());
        assert_eq!(pool.lane_len(EnvelopeLane::Ethereum), 1);
        assert_eq!(pool.lane_len(EnvelopeLane::Solana), 1);

        let batch = pool.select_for_block(60_000_000);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].tx_id, [3u8; 32]);
        assert_eq!(batch[1].tx_id, [1u8; 32]);
    }
}
