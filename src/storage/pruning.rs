//! Node classification and pruning policy.
//!
//! This is a pure policy layer. It lets CLI/config/RPC code share one
//! Fail-closed interpretation of full/archive node roles before deeper pruning
//! Mechanics are wired into storage.
//!
//! The hard-prune worker in `src/network/node.rs` reads
//! [`PruningPolicy::should_prune_historical_state`] before deleting anything,
//! so an archive node refuses the deletion rather than performing it. A node
//! with no policy set keeps the previous behaviour, which is what tests and
//! ephemeral devnet nodes rely on.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeMode {
    Full,
    Archive,
}

impl NodeMode {
    pub fn from_role(role: &str) -> Option<Self> {
        match role {
            "archive" => Some(Self::Archive),
            "validator" | "sentry" | "seed" | "rpc" | "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Archive => "archive",
        }
    }
}

impl FromStr for NodeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_role(value).ok_or_else(|| format!("unknown node mode/role: {value}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruningPolicy {
    pub mode: NodeMode,
    pub pruning_enabled: bool,
    pub finalized_snapshot_retention: bool,
    pub retention_blocks: u64,
    pub backups_enabled: bool,
    pub backup_dir_configured: bool,
}

impl PruningPolicy {
    pub fn full_node_default() -> Self {
        Self {
            mode: NodeMode::Full,
            pruning_enabled: true,
            finalized_snapshot_retention: true,
            retention_blocks: 100_000,
            backups_enabled: true,
            backup_dir_configured: true,
        }
    }

    pub fn archive_node_default() -> Self {
        Self {
            mode: NodeMode::Archive,
            pruning_enabled: false,
            finalized_snapshot_retention: true,
            retention_blocks: u64::MAX,
            backups_enabled: true,
            backup_dir_configured: true,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mode == NodeMode::Archive && self.pruning_enabled {
            return Err("archive nodes must not enable pruning".into());
        }
        if self.mode == NodeMode::Archive && (!self.backups_enabled || !self.backup_dir_configured)
        {
            return Err("archive nodes require backups_enabled=true and backup_dir".into());
        }
        if self.pruning_enabled && !self.finalized_snapshot_retention {
            return Err("pruned full nodes must retain finalized checkpoint snapshots".into());
        }
        if self.pruning_enabled && self.retention_blocks == 0 {
            return Err("pruning retention_blocks must be non-zero".into());
        }
        Ok(())
    }

    pub fn should_prune_historical_state(&self) -> bool {
        self.mode == NodeMode::Full && self.pruning_enabled
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The policy has to answer the question the deletion path asks.
    ///
    /// `should_prune_historical_state` is what the hard-prune worker reads.
    /// Before this was wired, the worker deleted on any node and the policy
    /// was a description nobody consulted.
    #[test]
    fn an_archive_node_never_permits_pruning() {
        let policy = PruningPolicy::archive_node_default();
        assert!(
            !policy.should_prune_historical_state(),
            "an archive node is the copy of last resort; one misconfigured \
             into deleting is worse than one that never existed"
        );
    }

    /// The inverse witness: the check must refuse archive nodes and nothing
    /// else. A `should_prune_historical_state` that always returned false
    /// would satisfy the test above and silently stop every deletion.
    #[test]
    fn a_full_node_with_pruning_on_still_prunes() {
        let policy = PruningPolicy::full_node_default();
        assert!(policy.should_prune_historical_state());
    }

    /// A full node that turned pruning off is also refused. The mode alone is
    /// not the answer; the flag is part of it.
    #[test]
    fn a_full_node_with_pruning_off_does_not_prune() {
        let mut policy = PruningPolicy::full_node_default();
        policy.pruning_enabled = false;
        assert!(!policy.should_prune_historical_state());
    }

    #[test]
    fn node_mode_maps_roles() {
        assert_eq!(NodeMode::from_role("archive"), Some(NodeMode::Archive));
        assert_eq!(NodeMode::from_role("validator"), Some(NodeMode::Full));
        assert_eq!(NodeMode::from_role("rpc"), Some(NodeMode::Full));
        assert_eq!(NodeMode::from_role("unknown"), None);
    }

    #[test]
    fn node_archive_rejects_pruning() {
        let mut policy = PruningPolicy::archive_node_default();
        policy.pruning_enabled = true;
        assert!(policy.validate().unwrap_err().contains("archive nodes"));
    }

    #[test]
    fn node_archive_requires_backups() {
        let mut policy = PruningPolicy::archive_node_default();
        policy.backups_enabled = false;
        assert!(policy.validate().unwrap_err().contains("backup"));

        let mut policy = PruningPolicy::archive_node_default();
        policy.backup_dir_configured = false;
        assert!(policy.validate().unwrap_err().contains("backup"));
    }

    #[test]
    fn node_full_pruning_requires_finalized_snapshot_retention() {
        let mut policy = PruningPolicy::full_node_default();
        policy.finalized_snapshot_retention = false;
        assert!(policy.validate().unwrap_err().contains("finalized"));
    }

    #[test]
    fn node_full_pruning_requires_nonzero_retention() {
        let mut policy = PruningPolicy::full_node_default();
        policy.retention_blocks = 0;
        assert!(policy.validate().unwrap_err().contains("non-zero"));
    }

    #[test]
    fn node_prune_decision_distinguishes_full_and_archive() {
        assert!(PruningPolicy::full_node_default().should_prune_historical_state());
        assert!(!PruningPolicy::archive_node_default().should_prune_historical_state());
    }
}
