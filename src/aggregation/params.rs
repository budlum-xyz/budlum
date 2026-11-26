//! The parameters of the aggregation layer.

use serde::{Deserialize, Serialize};

/// Whether the aggregation rules are in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggMode {
    /// The system is off. Behaviour does not change.
    #[default]
    Off,
    /// The node treats the inline signatures of blocks as objects, proves
    /// them and compares the result with native verification. It publishes
    /// no frame and consensus does not change.
    Shadow,
    /// The block rules of the aggregation layer are in force.
    On,
}

/// The parameters of the aggregation layer.
///
/// `max_claims_per_block`, `max_proof_bytes`, `claim_fee_per_byte` and
/// `agg_share_bps` are consensus parameters (together with the two program
/// hashes). The rest is node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AggParams {
    /// The mode. The main network default is [`AggMode::Off`].
    pub mode: AggMode,
    /// Length of a tick in milliseconds.
    pub tick_ms: u64,
    /// Most objects one tick proves.
    pub tick_max_objects: usize,
    /// Most objects one sender may submit per tick.
    pub sender_tick_limit: usize,
    /// Most claims a block frame carries. Consensus.
    pub max_claims_per_block: usize,
    /// Most proof bytes a frame carries. Consensus.
    pub max_proof_bytes: usize,
    /// Largest STARK proof object.
    pub max_stark_object_bytes: usize,
    /// Largest polynomial opening object.
    pub max_pcs_object_bytes: usize,
    /// Byte budget of the object pool.
    pub pool_max_bytes: usize,
    /// Fee per encoded claim byte. Consensus.
    pub claim_fee_per_byte: u64,
    /// Share of the claim fees paid to the aggregators, in basis points.
    /// Consensus.
    pub agg_share_bps: u16,
    /// Blocks a full node keeps proof bytes for.
    pub proof_retention_blocks: u64,
    /// Block height at which `AggMode::On` activates on public Testnet
    /// (Rung 4 of the aggregation ladder). `None` keeps `AggMode::On` closed.
    pub activation_height: Option<u64>,
    /// Require proven (non-attested-only) tick proofs on public Testnet before
    /// `AggMode::On` may activate (Rung 4).
    pub require_proven_ticks: bool,
}

impl AggParams {
    /// True when the Rung 4 Testnet activation prerequisites are declared:
    /// a positive `activation_height` and `require_proven_ticks = true`.
    #[must_use]
    pub const fn testnet_ladder_ready(&self) -> bool {
        matches!(self.activation_height, Some(h) if h > 0) && self.require_proven_ticks
    }
}

impl Default for AggParams {
    fn default() -> Self {
        Self {
            mode: AggMode::Off,
            tick_ms: 1000,
            tick_max_objects: 256,
            sender_tick_limit: 8,
            max_claims_per_block: 8192,
            max_proof_bytes: 262_144,
            max_stark_object_bytes: 262_144,
            max_pcs_object_bytes: 131_072,
            pool_max_bytes: 268_435_456,
            claim_fee_per_byte: 64,
            agg_share_bps: 5000,
            proof_retention_blocks: 100_000,
            activation_height: None,
            require_proven_ticks: false,
        }
    }
}
