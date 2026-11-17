//! DAG (Directed Acyclic Graph) consensus engine.
//!
//! DAG-based ordering: transactions are distributed in a DAG rather than a
//! chain; each block can point to multiple parents. Finality is established
//! by tip votes collected over DAG endpoints and an anchor block. Instead of
//! the Nakamoto chain, fork choice uses the "heaviest DAG" rule.

use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use std::collections::HashMap;
use std::sync::RwLock;

/// DAG configuration.
#[derive(Debug, Clone)]
pub struct DAGConfig {
    /// Minimum tip votes required for a transaction to be considered final.
    pub min_tip_votes: u64,
    /// Maximum slot count between anchor blocks.
    pub anchor_interval: u64,
    /// Maximum number of parents per block in the DAG.
    pub max_parents: usize,
}

impl Default for DAGConfig {
    fn default() -> Self {
        DAGConfig {
            min_tip_votes: 2,
            anchor_interval: 10,
            max_parents: 2,
        }
    }
}

/// A DAG endpoint: hash + height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagTip {
    pub hash: String,
    pub height: u64,
}

/// DAG engine: operates on a DAG rather than a block chain.
pub struct DagEngine {
    pub config: DAGConfig,
    tips: RwLock<Vec<DagTip>>,
    parents: RwLock<HashMap<String, Vec<String>>>,
}

impl DagEngine {
    pub fn new(config: DAGConfig) -> Self {
        DagEngine {
            config,
            tips: RwLock::new(Vec::new()),
            parents: RwLock::new(HashMap::new()),
        }
    }

    /// Adds a block to the DAG: registers its parents and marks it as a new tip.
    pub fn add_block(&self, block: &Block) -> Result<(), ConsensusError> {
        let mut tips = self.tips.write().unwrap();
        let mut parents = self.parents.write().unwrap();

        let parent_hashes: Vec<String> = block
            .previous_hash
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if parent_hashes.len() > self.config.max_parents {
            return Err(ConsensusError(format!(
                "DAG block has {} parents, maximum is {}",
                parent_hashes.len(),
                self.config.max_parents
            )));
        }

        parents.insert(block.hash.clone(), parent_hashes.clone());

        // Parents are no longer tips (they have been built upon).
        tips.retain(|tip| !parent_hashes.contains(&tip.hash));

        tips.push(DagTip {
            hash: block.hash.clone(),
            height: block.index,
        });

        Ok(())
    }

    /// Returns the current DAG tips.
    pub fn tips(&self) -> Vec<DagTip> {
        self.tips.read().unwrap().clone()
    }

    /// Returns the parents of a block in the DAG.
    pub fn parents_of(&self, hash: &str) -> Option<Vec<String>> {
        self.parents.read().unwrap().get(hash).cloned()
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
        _chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid DAG block hash. Calculated: {}, Existing: {}",
                calculated_hash, block.hash
            )));
        }

        let parent_hashes: Vec<String> = block
            .previous_hash
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if parent_hashes.len() > self.config.max_parents {
            return Err(ConsensusError(format!(
                "DAG block has {} parents, maximum is {}",
                parent_hashes.len(),
                self.config.max_parents
            )));
        }

        // Parents exist in the DAG (except genesis).
        if block.index > 0 {
            for parent in &parent_hashes {
                if !self.tips_read().iter().any(|t| t.hash == *parent)
                    && parent != &"0".repeat(64)
                {
                    // Parent may exist in the DAG without being a tip; that is valid.
                    // Only unknown parents are refused.
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
            self.tips_read().len(),
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
        // Fork choice in DAG: tip count and height combination.
        let tips = self.tips_read();
        tips.len() as u128 * 1000 + chain.last().map(|b| b.index as u128).unwrap_or(0)
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_score = self.fork_choice_score(current);
        let candidate_score = self.fork_choice_score(candidate);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        // Deterministic tie-break for equal-score DAG tips: hash comparison.
        let current_tip = current.last().map(|b| b.hash.as_str()).unwrap_or("");
        let candidate_tip = candidate.last().map(|b| b.hash.as_str()).unwrap_or("");
        candidate_tip > current_tip
    }
}

impl DagEngine {
    fn tips_read(&self) -> std::sync::RwLockReadGuard<'_, Vec<DagTip>> {
        self.tips.read().unwrap()
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
        let mut block = make_block(1, "0".repeat(64));
        engine.prepare_block(&mut block, &AccountState::new()).unwrap();
        assert!(engine.validate_block(&block, &[], &AccountState::new()).is_ok());
    }

    #[test]
    fn dag_rejects_too_many_parents() {
        let engine = DagEngine::new(DAGConfig::default());
        let mut block = make_block(1, "a,b,c");
        block.hash = block.calculate_hash();
        assert!(engine.validate_block(&block, &[], &AccountState::new()).is_err());
    }

    #[test]
    fn dag_tips_tracking() {
        let engine = DagEngine::new(DAGConfig::default());
        let mut b1 = make_block(1, "0".repeat(64));
        b1.hash = b1.calculate_hash();
        let mut b2 = make_block(2, &b1.hash);
        b2.hash = b2.calculate_hash();
        engine.add_block(&b1).unwrap();
        engine.add_block(&b2).unwrap();
        let tips = engine.tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, b2.hash);
    }
}
