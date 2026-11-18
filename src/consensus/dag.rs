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
    heights: BTreeMap<String, u64>,
    order: VecDeque<String>,
}

/// DAG engine: tracks a bounded directed acyclic graph of blocks and tips.
pub struct DagEngine {
    pub config: DAGConfig,
    graph: RwLock<DagGraph>,
}

#[must_use]
pub fn parse_parent_hashes(previous_hash: &str) -> Vec<String> {
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
                heights: BTreeMap::new(),
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
        graph.heights.insert(block.hash.clone(), block.index);

        while graph.order.len() > MAX_DAG_HISTORY {
            if let Some(evicted) = graph.order.pop_front() {
                graph.parents.remove(&evicted);
                graph.heights.remove(&evicted);
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
            for parent in &parent_hashes {
                if parent == GENESIS_ZERO_HASH {
                    continue;
                }
                let known_height = graph
                    .heights
                    .get(parent)
                    .copied()
                    .or_else(|| {
                        graph
                            .tips
                            .iter()
                            .find(|t| t.hash == *parent)
                            .map(|t| t.height)
                    })
                    .or_else(|| chain.iter().find(|b| b.hash == *parent).map(|b| b.index));
                let Some(parent_height) = known_height else {
                    return Err(ConsensusError(format!(
                        "DAG block references unknown parent {parent}"
                    )));
                };
                if parent_height >= block.index {
                    return Err(ConsensusError(format!(
                        "DAG block height {} must strictly exceed parent height {parent_height}",
                        block.index
                    )));
                }
            }
        }

        Ok(())
    }

    fn record_block(
        &self,
        block: &Block,
        _storage: Option<&crate::persistence::db::Storage>,
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
        let mut max_valid_height = 0u128;
        let mut parent_refs = 0u128;
        for block in chain {
            if block.hash != block.calculate_hash() {
                return 0;
            }
            let Ok(parents) = self.validate_parent_list(block) else {
                return 0;
            };
            max_valid_height = max_valid_height.max(u128::from(block.index));
            parent_refs = parent_refs.saturating_add(parents.len() as u128);
        }
        let graph_weight = parent_refs.saturating_mul(100);
        max_valid_height
            .saturating_mul(1_000)
            .saturating_add(graph_weight)
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

    #[test]
    fn dag_rejects_non_acyclic_parent_and_forged_fork_choice_inflation() {
        let engine = DagEngine::new(DAGConfig::default());
        let b1 = make_block(1, GENESIS_ZERO_HASH);
        let b2 = make_block(2, &b1.hash);
        engine.add_block(&b1).expect("add b1");
        engine.add_block(&b2).expect("add b2");

        // Same-height or future-height parent violates DAG acyclicity.
        let same_height = make_block(2, &b2.hash);
        assert!(engine
            .validate_block(&same_height, &[], &AccountState::new())
            .is_err());
        let regressed = make_block(1, &b2.hash);
        assert!(engine
            .validate_block(&regressed, &[], &AccountState::new())
            .is_err());

        // Comma-stuffed previous_hash exceeding max_parents must score 0, never beat an honest chain.
        let stuffed_parents = (0..64)
            .map(|i| format!("{i:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        let forged = make_block(1, &stuffed_parents);
        assert_eq!(engine.fork_choice_score(std::slice::from_ref(&forged)), 0);
        assert!(!engine.is_better_chain(&[b1, b2], &[forged]));
    }

    #[test]
    fn dag_rejects_orphan_on_empty_graph_and_plugin_enforces_timestamp_bounds() {
        use crate::domain::plugin::{
            default_domain, ConsensusDomainPlugin, DagDomainPlugin, DomainContext,
        };
        use crate::domain::types::ConsensusKind;
        use std::sync::Arc;

        let empty_engine = DagEngine::new(DAGConfig::default());
        let orphan_on_empty = make_block(1, "deadbeef");
        assert!(empty_engine
            .validate_block(&orphan_on_empty, &[], &AccountState::new())
            .is_err());

        let plugin = DagDomainPlugin::new(Arc::new(empty_engine));
        let domain = default_domain(77, ConsensusKind::Dag, 1, "dag_finality", 1);
        let state = AccountState::new();
        let ctx = DomainContext {
            domain: &domain,
            chain: &[],
            state: &state,
            sequence: 1,
        };
        let mut future_block = make_block(1, GENESIS_ZERO_HASH);
        future_block.timestamp = u128::from(u64::MAX);
        future_block.hash = future_block.calculate_hash();
        assert!(plugin.validate_domain_block(&future_block, ctx).is_err());
    }
}
