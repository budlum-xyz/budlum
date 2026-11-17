//! DAG (Directed Acyclic Graph) consensus engine.
//!
//! DAG-based ordering: blocks can reference multiple parents up to
//! [`DAGConfig::max_parents`]. Finality is verified by cryptographic quorum
//! certificates in `DagFinalityAdapter`, while equal-score fork ties delegate
//! to the canonical deterministic [`resolve_split_tie`] rule.

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::RwLock;

const MAX_DAG_TIPS: usize = 256;
const MAX_DAG_HISTORY: usize = 4_096;
const GENESIS_ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// DAG configuration.
#[derive(Debug, Clone)]
pub struct DAGConfig {
    /// Minimum tip votes required for a block to reach finality.
    pub min_tip_votes: u64,
    /// Maximum slot count between anchor blocks.
    pub anchor_interval: u64,
    /// Maximum number of parents per block in the DAG.
    pub max_parents: usize,
}

impl Default for DAGConfig {
    fn default() -> Self {
        Self {
            min_tip_votes: 2,
            anchor_interval: 10,
            max_parents: 2,
        }
    }
}

/// A DAG endpoint: block hash and height.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DagTip {
    hash: String,
    height: u64,
}

#[derive(Default)]
struct DagGraph {
    tips: Vec<DagTip>,
    parents: BTreeMap<String, Vec<String>>,
    order: VecDeque<String>,
}

/// DAG engine: tracks a bounded directed acyclic graph of blocks and tips.
pub struct DagEngine {
    pub config: DAGConfig,
    graph: RwLock<DagGraph>,
}

fn parse_parent_hashes(previous_hash: &str) -> Vec<String> {
    previous_hash
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

impl DagEngine {
    /// Create a new DAG consensus engine with the given configuration.
    #[must_use]
    pub const fn new(config: DAGConfig) -> Self {
        Self {
            config,
            graph: RwLock::new(DagGraph {
                tips: Vec::new(),
                parents: BTreeMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Add a validated block to the DAG, updating tips within bounded memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent list is invalid or the internal lock is poisoned.
    pub fn add_block(&self, block: &Block) -> Result<(), ConsensusError> {
        let parent_hashes = self.validate_parent_list(block)?;
        let mut graph = self
            .graph
            .write()
            .map_err(|_| ConsensusError("DAG state lock poisoned".into()))?;

        if !graph.parents.contains_key(&block.hash) {
            graph.order.push_back(block.hash.clone());
        }
        graph
            .parents
            .insert(block.hash.clone(), parent_hashes.clone());

        while graph.order.len() > MAX_DAG_HISTORY {
            if let Some(evicted) = graph.order.pop_front() {
                graph.parents.remove(&evicted);
            }
        }

        // Parents are no longer tips once built upon.
        graph.tips.retain(|tip| !parent_hashes.contains(&tip.hash));
        if !graph.tips.iter().any(|tip| tip.hash == block.hash) {
            graph.tips.push(DagTip {
                hash: block.hash.clone(),
                height: block.index,
            });
        }
        if graph.tips.len() > MAX_DAG_TIPS {
            let excess = graph.tips.len().saturating_sub(MAX_DAG_TIPS);
            graph.tips.drain(0..excess);
        }

        Ok(())
    }

    fn validate_parent_list(&self, block: &Block) -> Result<Vec<String>, ConsensusError> {
        let parent_hashes = parse_parent_hashes(&block.previous_hash);
        if block.index > 0 && parent_hashes.is_empty() {
            return Err(ConsensusError(
                "Non-genesis DAG block must reference at least one parent".into(),
            ));
        }
        if parent_hashes.len() > self.config.max_parents {
            return Err(ConsensusError(format!(
                "DAG block has {} parents, maximum is {}",
                parent_hashes.len(),
                self.config.max_parents
            )));
        }
        let mut seen = BTreeSet::new();
        for parent in &parent_hashes {
            if parent == &block.hash {
                return Err(ConsensusError(
                    "DAG block cannot reference itself as a parent".into(),
                ));
            }
            if !seen.insert(parent.as_str()) {
                return Err(ConsensusError(format!(
                    "DAG block references duplicate parent {parent}"
                )));
            }
        }
        Ok(parent_hashes)
    }

    #[cfg(test)]
    fn tips(&self) -> Vec<DagTip> {
        self.graph
            .read()
            .map(|graph| graph.tips.clone())
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn parents_of(&self, hash: &str) -> Option<Vec<String>> {
        self.graph
            .read()
            .ok()
            .and_then(|graph| graph.parents.get(hash).cloned())
    }

    fn tip_summary(&self) -> (usize, u64) {
        self.graph.read().map_or((0, 0), |graph| {
            let max_h = graph.tips.iter().map(|t| t.height).max().unwrap_or(0);
            (graph.tips.len(), max_h)
        })
    }
}

impl ConsensusEngine for DagEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        block.hash = block.calculate_hash();
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid DAG block hash. Calculated: {calculated_hash}, Existing: {}",
                block.hash
            )));
        }

        let parent_hashes = self.validate_parent_list(block)?;

        if block.index > 0 {
            let graph = self
                .graph
                .read()
                .map_err(|_| ConsensusError("DAG state lock poisoned".into()))?;
            if !graph.parents.is_empty() || !chain.is_empty() {
                for parent in &parent_hashes {
                    if parent == GENESIS_ZERO_HASH {
                        continue;
                    }
                    let known_in_dag = graph.parents.contains_key(parent)
                        || graph.tips.iter().any(|t| t.hash == *parent);
                    let known_in_chain = chain.iter().any(|b| b.hash == *parent);
                    if !known_in_dag && !known_in_chain {
                        return Err(ConsensusError(format!(
                            "DAG block references unknown parent {parent}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn record_block(
        &self,
        block: &Block,
        _storage: Option<&crate::storage::db::Storage>,
    ) -> Result<(), ConsensusError> {
        self.add_block(block)
    }

    fn consensus_type(&self) -> &'static str {
        "DAG"
    }

    fn info(&self) -> String {
        format!(
            "DAG (tips: {}, min_tip_votes: {}, anchor_interval: {})",
            self.tip_summary().0,
            self.config.min_tip_votes,
            self.config.anchor_interval
        )
    }

    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::Dag
    }

    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        let (tip_count, max_tip_height) = self.tip_summary();
        let tip_weight = (tip_count as u128).saturating_mul(1_000);
        let height = chain.last().map_or(u128::from(max_tip_height), |b| {
            u128::from(b.index.max(max_tip_height))
        });
        tip_weight.saturating_add(height)
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_score = self.fork_choice_score(current);
        let candidate_score = self.fork_choice_score(candidate);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        resolve_split_tie(
            &SplitCandidate::from_chain_tip(current, current_score),
            &SplitCandidate::from_chain_tip(candidate, candidate_score),
        ) == SplitDecision::RightWins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Block;

    fn make_block(index: u64, prev: &str) -> Block {
        let mut b = Block::new_with_chain_id(index, prev.to_string(), vec![], 1);
        b.hash = b.calculate_hash();
        b
    }

    #[test]
    fn dag_add_and_validate_block() {
        let engine = DagEngine::new(DAGConfig::default());
        let mut block = make_block(1, GENESIS_ZERO_HASH);
        engine
            .prepare_block(&mut block, &AccountState::new())
            .expect("prepare");
        assert!(engine
            .validate_block(&block, &[], &AccountState::new())
            .is_ok());
    }

    #[test]
    fn dag_rejects_too_many_parents() {
        let engine = DagEngine::new(DAGConfig::default());
        let block = make_block(1, "a,b,c");
        assert!(engine
            .validate_block(&block, &[], &AccountState::new())
            .is_err());
    }

    #[test]
    fn dag_rejects_empty_duplicate_and_unknown_parents() {
        let engine = DagEngine::new(DAGConfig::default());
        let empty = make_block(1, "");
        assert!(engine
            .validate_block(&empty, &[], &AccountState::new())
            .is_err());

        let dup = make_block(1, "aa,aa");
        assert!(engine
            .validate_block(&dup, &[], &AccountState::new())
            .is_err());

        let b1 = make_block(1, GENESIS_ZERO_HASH);
        engine.add_block(&b1).expect("add b1");
        let unknown = make_block(2, "deadbeef");
        assert!(engine
            .validate_block(&unknown, &[], &AccountState::new())
            .is_err());
    }

    #[test]
    fn dag_tips_tracking() {
        let engine = DagEngine::new(DAGConfig::default());
        let b1 = make_block(1, GENESIS_ZERO_HASH);
        let b2 = make_block(2, &b1.hash);
        engine.add_block(&b1).expect("add b1");
        engine.add_block(&b2).expect("add b2");
        let tips = engine.tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, b2.hash);
        assert_eq!(engine.parents_of(&b2.hash), Some(vec![b1.hash]));
    }
}
