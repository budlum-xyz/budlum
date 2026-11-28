//! Adaptive escrow ceiling and permissionless prover-contradiction slashing
//! guard for cross-domain bridge value flows.
//!
//! Historical bridge drains occur when a bridge permits net outflow or minting
//! `V` within one settlement window that exceeds the verifiable economic cost
//! `S_effective` of corrupting the external source domain (`V > S_effective`).
//! [`BridgeEconomicGuard`] enforces three consensus-deterministic invariants
//! using pure integer arithmetic (`u128`):
//!
//! 1. **Backing-derived window ceiling ([`effective_ceiling_atoms`])**:
//!    - [`SecurityBacking::None`] and unbonded [`SecurityBacking::Authority`]
//!      yield **zero** (`0` atoms) unconditionally.
//!    - Slashable [`SecurityBacking::SignatureSet`] is divided by
//!      `max(1, shared_consumer_count)` (over-leverage haircut) and scaled by
//!      `stake_haircut_bps / 10_000` (default `3_333` bps, matching the `1/3`
//!      Byzantine corruption lower bound), and that credit is admitted only
//!      through an attached [`ProverBond`], never above the bond's haircut:
//!      `total_weight` is the external protocol's unit, not atoms, and no
//!      conversion exists yet. Without a bond the set earns `0`.
//!    - Unslashable [`SecurityBacking::SignatureSet`] (such as Ethereum Altair
//!      sync committees), [`SecurityBacking::Work`], and [`SecurityBacking::Zk`]
//!      never earn validator-stake credit; they are strictly bounded by
//!      declared protocol caps and/or slashable [`ProverBond`] collateral
//!      scaled by `bond_haircut_bps / 10_000`.
//! 2. **Rolling height-window flow bound ([`BridgeEconomicGuard::check_and_record_flow`])**:
//!    for each configured domain and window `height / window_blocks`,
//!    `window_used_atoms + amount_atoms <= effective_ceiling_atoms` is verified
//!    before any state mutation. Domains without an explicit policy stay open
//!    so internal native domains continue unimpeded, while any configured
//!    external domain fails closed on overflow, zero ceiling, or freeze.
//! 3. **Admin-keyless contradiction breaker & prover slashing
//!    ([`BridgeEconomicGuard::submit_contradiction`])**: accepts either a
//!    hybrid-signed dual-root statement or verified protocol-level slashing
//!    evidence from [`RestakingAvsAdapter`], [`AuxPowPopAdapter`], or
//!    [`SimplexBftAdapter`], atomically freezes the domain in
//!    [`DomainGuardStatus::FrozenByContradiction`], rejects evidence replay,
//!    and invokes [`ProverBond::slash`] to cut the bonded prover and compute
//!    the challenger reward.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::external::algorand_stateproof::{
    algorand_pubkey_commitment, verify_algorand_equivocation, AlgorandEquivocationProof,
    AlgorandStateProofAdapter, PinnedAlgorandVerifier,
};
use crate::cross_domain::external::auxpow_pop::{
    verify_pop_equivocation, AuxPowPopAdapter, PinnedAuxPowAnchor, PopEquivocationProof,
};
use crate::cross_domain::external::based_preconf::{
    verify_based_preconf_equivocation, BasedPreconfAdapter, BasedPreconfEquivocationProof,
    PinnedBasedPreconfCommittee,
};
use crate::cross_domain::external::mina_recursive::{
    PinnedSuccinctGenesis, SuccinctRecursiveAdapter,
};
use crate::cross_domain::external::prover::{ProverBond, Slashing, BPS_DEN};
use crate::cross_domain::external::restaking_avs::{
    verify_restaking_slashing, PinnedRestakingAvsSet, RestakingAvsAdapter, RestakingSlashingProof,
};
use crate::cross_domain::external::simplex_bft::{
    verify_simplex_slashing, PinnedSimplexCommittee, SimplexBftAdapter, SimplexSlashingProof,
};
use crate::cross_domain::external::spec::{
    ExternalFinalityAdapter, FinalityAttestation, RawConsensusEvidence, SecurityBacking,
    VerificationPolicy,
};
use crate::cross_domain::external::stellar_fba::{
    verify_stellar_ballot_equivocation, PinnedScpTier, StellarBallotEquivocationProof,
    StellarScpAdapter,
};
use crate::cross_domain::external::ton_catchain::{
    verify_ton_catchain_equivocation, PinnedTonMasterchainAnchor, TonCatchainAdapter,
    TonCatchainEquivocationProof,
};
use crate::crypto::facts::AssumptionClass;
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

/// Canonical Budlum mainnet chain identifier where strict economic-guard domain
/// registration is mandatory.
///
/// WIRING: checked by [`BridgeEconomicGuard::for_chain_id`] and
/// [`crate::cross_domain::bridge_tx::enable_chain_economic_guard_mode`].
pub const MAINNET_GUARD_CHAIN_ID: u64 = 45_260;
/// Canonical Budlum public testnet chain identifier where strict economic-guard
/// domain registration is mandatory.
///
/// WIRING: checked by [`BridgeEconomicGuard::for_chain_id`] and
/// [`crate::cross_domain::bridge_tx::enable_chain_economic_guard_mode`].
pub const TESTNET_GUARD_CHAIN_ID: u64 = 45_261;
/// Hard fail-closed upper bound on stored contradiction and per-offender replay
/// entries. Entries are never evicted (FIFO/LRU eviction would reopen historical
/// slashing replays); once full, governance snapshot pruning is required.
///
/// WIRING: enforced prior to insertion inside
/// [`BridgeEconomicGuard::submit_contradiction`].
pub const MAX_GUARD_REPLAY_ENTRIES: usize = 65_536;

/// Number of Budlum blocks per replay-pruning epoch for contradiction evidence.
///
/// WIRING: enforced by [`BridgeEconomicGuard::prune_expired_replay_entries`] and [`BridgeEconomicGuard::submit_contradiction`].
pub const GUARD_REPLAY_EPOCH_BLOCKS: u64 = 1_000;

/// Number of recent replay epochs retained before expired contradiction replay
/// entries are deterministically pruned at epoch boundaries.
///
/// WIRING: enforced by [`BridgeEconomicGuard::prune_expired_replay_entries`].
pub const GUARD_REPLAY_RETENTION_EPOCHS: u64 = 4;

/// Default Byzantine corruption haircut on slashable validator stake (`33.33%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_STAKE_HAIRCUT_BPS: u64 = 3_333;
/// Default haircut on directly slashable prover bond collateral (`90.00%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_BOND_HAIRCUT_BPS: u64 = 9_000;
/// Default challenger reward fraction taken out of a slashed prover bond (`10.00%`).
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_FINDER_REWARD_BPS: u64 = 1_000;

/// Hard protocol ceiling on the contradiction finder reward.
///
/// The reward is carved out of the slashed prover bond, so an uncapped
/// share lets a slashed prover reclaim its own bond through a second
/// address. Capped at 20%, at least 80% of every slashed bond burns no
/// matter who reports the contradiction.
///
/// WIRING: enforced by the policy check that runs before a guard is built,
/// so a policy above the ceiling is refused at construction rather than
/// when the reward is paid out.
pub const MAX_FINDER_REWARD_BPS: u64 = 2_000;
/// Default rolling flow-accounting window length in blocks.
///
/// WIRING: default protocol constant for [`DomainCeilingPolicy`].
pub const DEFAULT_GUARD_WINDOW_BLOCKS: u64 = 7_200;

/// Admin-keyless circuit-breaker state for a guarded domain.
///
/// WIRING: stored inside [`BridgeEconomicGuard`] on [`crate::cross_domain::bridge::BridgeState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DomainGuardStatus {
    /// Normal operation subject to the rolling window ceiling.
    #[default]
    Active,
    /// Permanently halted by a cryptographically verified contradiction proof.
    /// No administrator key can trigger or silently clear this state.
    FrozenByContradiction {
        /// Budlum block height at which the contradiction was verified.
        frozen_at_height: u64,
        /// Canonical digest of the contradiction evidence that tripped the guard.
        evidence_digest: Hash32,
    },
}

/// Per-domain adaptive escrow ceiling policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCeilingPolicy {
    /// Latest verified consensus security backing reported for this domain.
    pub backing: SecurityBacking,
    /// Concurrent consumer count sharing `backing`'s slashable stake (`>= 1`).
    pub shared_consumer_count: u32,
    /// Haircut in basis points (`0..=10_000`) applied to slashable validator stake.
    pub stake_haircut_bps: u64,
    /// Haircut in basis points (`0..=10_000`) applied to slashable prover bond.
    pub bond_haircut_bps: u64,
    /// Challenger reward in basis points (`0..=10_000`) of slashed prover bond.
    pub finder_reward_bps: u64,
    /// Optional explicit window cap for verified Proof-of-Work domains.
    pub work_window_cap_atoms: u128,
    /// Minimum `PoW` `difficulty_bits` required before `work_window_cap_atoms` applies.
    pub min_work_difficulty_bits: u32,
    /// Optional explicit window cap for verified hash-STARK/zkVM domains.
    pub zk_window_cap_atoms: u128,
    /// Length of each flow-accounting window in blocks (`>= 1`).
    pub window_blocks: u64,
    /// Optional prover key authorized to sign state statements for this domain.
    pub prover_ed25519_pubkey: Option<[u8; 32]>,
    /// Optional ML-DSA-65 public key paired with `prover_ed25519_pubkey`.
    #[serde(default)]
    pub prover_pq_pubkey: Vec<u8>,
    /// Governance-pinned external finality adapter and committee configuration
    /// required by [`BridgeEconomicGuard::refresh_backing_from_adapter`] and
    /// external-adapter variants of [`BridgeEconomicGuard::submit_contradiction`].
    #[serde(default)]
    pub pinned_adapter: Option<GuardedExternalAdapter>,
}

impl Default for DomainCeilingPolicy {
    fn default() -> Self {
        Self {
            backing: SecurityBacking::None,
            shared_consumer_count: 1,
            stake_haircut_bps: DEFAULT_STAKE_HAIRCUT_BPS,
            bond_haircut_bps: DEFAULT_BOND_HAIRCUT_BPS,
            finder_reward_bps: DEFAULT_FINDER_REWARD_BPS,
            work_window_cap_atoms: 0,
            min_work_difficulty_bits: 1,
            zk_window_cap_atoms: 0,
            window_blocks: DEFAULT_GUARD_WINDOW_BLOCKS,
            prover_ed25519_pubkey: None,
            prover_pq_pubkey: Vec::new(),
            pinned_adapter: None,
        }
    }
}

/// Direction of a guarded cross-domain bridge transfer.
///
/// WIRING: Dispatched by [`BridgeEconomicGuard::check_and_record_directional_flow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeFlowDirection {
    /// Inbound mint / lock onto Budlum.
    Deposit,
    /// Outbound burn / unlock leaving Budlum.
    Withdraw,
}

/// Default timelock delay (in Budlum blocks) for oversized single withdrawals
/// when `large_withdraw_delay_blocks` is omitted (`0`).
///
/// WIRING: Consumed by [`BridgeEconomicGuard::queue_large_withdrawal`].
pub const DEFAULT_LARGE_WITHDRAW_DELAY_BLOCKS: u64 = 16;

/// Default timed circuit-breaker pause duration (in Budlum blocks) when
/// `circuit_pause_duration_blocks` is omitted (`0`).
///
/// WIRING: Consumed by [`BridgeEconomicGuard::observe_reorg_depth`].
pub const DEFAULT_CIRCUIT_PAUSE_DURATION_BLOCKS: u64 = 64;

/// Mandatory cooldown blocks after a timed reorg circuit-breaker pause expires
/// before another guardian/reorg pause can be triggered on the same domain.
///
/// Prevents compromised-guardian re-pausing griefing that could permanently
/// freeze bridge liquidity while preserving urgent one-shot incident pauses.
///
/// WIRING: Enforced by [`BridgeEconomicGuard::observe_reorg_depth_with_scope`]
/// and updated by [`BridgeEconomicGuard::resume_if_pause_expired`].
pub const REORG_PAUSE_COOLDOWN_BLOCKS: u64 = 64;

/// Scope of an active timed reorg circuit-breaker pause.
///
/// Distinguishes a total emergency freeze from an asymmetric guard that halts
/// fresh inbound deposits and unqueued fast exits while letting previously
/// matured timelocked withdrawals complete once ready.
///
/// WIRING: Recorded on [`CircuitBreakerPause::scope`] and checked by
/// [`BridgeEconomicGuard::claim_queued_withdrawal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GuardianPauseScope {
    /// Pause all inbound bridge flows, fast exits, and queued timelock claims.
    #[default]
    FullBridgeFreeze,
    /// Halt fresh inbound deposits and unqueued fast exits, while allowing
    /// already-queued withdrawals whose timelock has matured to settle.
    DepositsAndFastExitsOnly,
}

/// Per-domain asymmetric deposit/withdraw controls, single-transaction
/// withdrawal caps, and deterministic reorg auto-pause thresholds.
///
/// WIRING: Stored per domain inside `BridgeEconomicGuard::flow_controls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DomainFlowControls {
    /// Optional rolling-window ceiling for inbound deposits (`0` uses the
    /// domain's general `effective_ceiling_atoms`).
    pub deposit_window_cap_atoms: u128,
    /// Single-transaction withdrawal threshold (`0` disables timelock queueing).
    pub max_single_tx_withdraw_atoms: u128,
    /// Timelock delay in blocks for withdrawals exceeding `max_single_tx_withdraw_atoms`.
    pub large_withdraw_delay_blocks: u64,
    /// Reorg depth threshold (`>= threshold`) that triggers automatic circuit
    /// pause (`0` disables automatic reorg pauses).
    pub auto_pause_reorg_depth_threshold: u64,
    /// Duration in Budlum blocks of an automatic reorg-triggered pause.
    pub circuit_pause_duration_blocks: u64,
}

/// Active timed circuit-breaker pause triggered by an observed foreign-domain
/// reorg above the domain's configured depth threshold.
///
/// WIRING: Stored per domain inside `BridgeEconomicGuard::domain_pauses`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerPause {
    pub paused_at_height: u64,
    pub pause_expires_at_height: u64,
    pub reorg_depth: u64,
    /// Pause scope distinguishing full freezes from new-deposit-only halts.
    #[serde(default)]
    pub scope: GuardianPauseScope,
}

/// Queued oversized single withdrawal waiting for its timelock expiry.
///
/// WIRING: Returned and settled by [`BridgeEconomicGuard::claim_queued_withdrawal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedBridgeWithdrawal {
    pub withdrawal_id: Hash32,
    pub domain_id: DomainId,
    pub recipient: Address,
    pub amount_atoms: u128,
    pub queued_at_height: u64,
    pub ready_at_height: u64,
}

/// Mutable consensus state tracked per guarded external domain.
///
/// WIRING: stored per domain inside [`BridgeEconomicGuard`] and exposed via
/// [`BridgeEconomicGuard::record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEconomicRecord {
    /// Configured ceiling policy and latest verified security backing.
    pub policy: DomainCeilingPolicy,
    /// Current admin-keyless circuit-breaker status.
    pub status: DomainGuardStatus,
    /// Active window index (`height / policy.window_blocks`).
    pub active_window: u64,
    /// Cumulative atoms minted or unlocked during `active_window`.
    pub window_used_atoms: u128,
    /// Optional slashable prover bond backing this domain's attestations.
    pub prover_bond: Option<ProverBond>,
    /// Why the window accounting of this record refuses the next flow.
    ///
    /// The refusal itself already exists: [`BridgeEconomicGuard::check_and_record_flow`]
    /// and its certificate variant return [`EconomicGuardError::CeilingExceeded`]
    /// before any state change. What did not exist is a way for the caller to
    /// tell "the ceiling is what the policy says it is, and this transfer does
    /// not fit" apart from "this window saw far more flow than the policy
    /// expected, and the ceiling is still the policy number". The first is
    /// ordinary traffic control, the second is a bridge being drained, and a
    /// circuit breaker that cannot tell them apart either cries wolf on every
    /// rejection or stays silent through the drain.
    ///
    /// The breach is recorded at the moment a flow is refused for exceeding the
    /// active window ceiling. It is not inferred from repeated refusals and it
    /// adds no second mechanism: the atomic window accounting stays the only
    /// authority on how much has moved.
    #[serde(default)]
    pub window_breach: Option<WindowBreach>,
}

/// A refused flow that put its window past the policy ceiling.
///
/// Recorded once per breach and overwritten only by a later breach, so the
/// last anomalous attempt stays readable after the window rolls over and the
/// accounting resets. It is a fact about an attempt, not a claim about intent:
/// the flow was refused, nothing moved, and the numbers here are the numbers
/// the refusal carries.
///
/// WIRING: read through [`BridgeEconomicGuard::window_breaches`], the guard's
/// own sweep that a bridge operator (or a monitoring loop) calls after a
/// refused flow to find out which domains tried to move more than their
/// window allowed. The sweep is the production reader: without it the field
/// would be a number nobody asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBreach {
    /// Height at which the refused flow was presented.
    pub height: u64,
    /// Window index the refused flow belonged to.
    pub window: u64,
    /// Atoms the caller asked to move.
    pub requested_atoms: u128,
    /// Atoms already moved in that window when the refusal happened.
    pub used_atoms: u128,
    /// Ceiling the window was held to.
    pub ceiling_atoms: u128,
    /// True when a single attempt asked for more than the whole window ceiling,
    /// rather than the window reaching it through accumulation.
    pub single_attempt_over_ceiling: bool,
}

/// Governance-pinned external adapter configuration enforced by
/// [`BridgeEconomicGuard::refresh_backing_from_adapter`] and
/// [`BridgeEconomicGuard::submit_contradiction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardedExternalAdapter {
    /// Dual-quorum restaking AVS + Babylon-class EOTS adapter.
    RestakingAvs {
        /// External network identifier.
        network: String,
        /// Governance-pinned dual-quorum + EOTS committee.
        pinned: PinnedRestakingAvsSet,
    },
    /// Merged-mining `AuxPoW` + bonded `PoP` anchor adapter.
    AuxPowPop {
        /// External network identifier.
        network: String,
        /// Governance-pinned parent `PoW` and `PoP` anchor parameters.
        pinned: Box<PinnedAuxPowAnchor>,
    },
    /// 2-round Simplex / tail-forking-resistant `MonadBFT` adapter.
    SimplexBft {
        /// External network identifier.
        network: String,
        /// Governance-pinned Simplex epoch committee.
        pinned: PinnedSimplexCommittee,
    },
    /// Post-quantum ML-DSA-65 Algorand `StateProof` interval verifier.
    AlgorandStateProof {
        /// External network identifier.
        network: String,
        /// Governance-pinned Algorand `StateProof` verifier root.
        pinned: Box<PinnedAlgorandVerifier>,
    },
    /// L1-sequenced based rollup preconfirmation + FOCIL committee.
    BasedPreconf {
        /// External network identifier.
        network: String,
        /// Governance-pinned based preconfirmation committee.
        pinned: PinnedBasedPreconfCommittee,
    },
    /// TON Masterchain Catchain BFT + dynamic Shardchain anchor.
    TonCatchain {
        /// External network identifier.
        network: String,
        /// Governance-pinned TON key-block validator set anchor.
        pinned: PinnedTonMasterchainAnchor,
    },
    /// Federated Byzantine Agreement / Stellar Consensus Protocol top tier.
    StellarScp {
        /// External network identifier.
        network: String,
        /// Governance-pinned SCP top tier with verified quorum intersection.
        pinned: PinnedScpTier,
    },
    /// Succinct recursive proof + Samasika window-density genesis anchor.
    MinaRecursive {
        /// External network identifier.
        network: String,
        /// Governance-pinned succinct genesis and ML-DSA-65 aggregator anchor.
        pinned: Box<PinnedSuccinctGenesis>,
    },
}

impl GuardedExternalAdapter {
    /// Canonical single-byte adapter discriminator.
    #[must_use]
    const fn adapter_tag(&self) -> u8 {
        match self {
            Self::RestakingAvs { .. } => 1,
            Self::AuxPowPop { .. } => 2,
            Self::SimplexBft { .. } => 3,
            Self::AlgorandStateProof { .. } => 4,
            Self::BasedPreconf { .. } => 5,
            Self::TonCatchain { .. } => 6,
            Self::StellarScp { .. } => 7,
            Self::MinaRecursive { .. } => 8,
        }
    }

    /// Configured external network identifier.
    #[must_use]
    pub fn network(&self) -> &str {
        match self {
            Self::RestakingAvs { network, .. }
            | Self::AuxPowPop { network, .. }
            | Self::SimplexBft { network, .. }
            | Self::AlgorandStateProof { network, .. }
            | Self::BasedPreconf { network, .. }
            | Self::TonCatchain { network, .. }
            | Self::StellarScp { network, .. }
            | Self::MinaRecursive { network, .. } => network,
        }
    }

    /// Canonical domain-separated SHA3-256 commitment binding the adapter kind,
    /// external network name, and pinned committee digest.
    ///
    /// WIRING: compared in constant time before any external backing update,
    /// circuit-breaker freeze, or prover bond slash.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let inner = match self {
            Self::RestakingAvs { pinned, .. } => pinned.canonical_pin_digest(),
            Self::AuxPowPop { pinned, .. } => pinned.canonical_pin_digest(),
            Self::SimplexBft { pinned, .. } => pinned.canonical_pin_digest(),
            Self::AlgorandStateProof { pinned, .. } => pinned.canonical_pin_digest(),
            Self::BasedPreconf { pinned, .. } => pinned.canonical_pin_digest(),
            Self::TonCatchain { pinned, .. } => pinned.canonical_pin_digest(),
            Self::StellarScp { pinned, .. } => pinned.canonical_pin_digest(),
            Self::MinaRecursive { pinned, .. } => pinned.canonical_pin_digest(),
        };
        hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_PIN_V1",
            &[self.adapter_tag()],
            self.network().as_bytes(),
            &inner,
        ])
    }
}

/// Permissionless contradiction evidence capable of freezing a domain and
/// slashing its attached [`ProverBond`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContradictionEvidence {
    /// Bonded prover signed two distinct state roots for the same
    /// `(domain_id, domain_height)`.
    SignedProverDoubleRoot {
        /// Conflicting domain height.
        domain_height: u64,
        /// First attested state root.
        state_root_a: Hash32,
        /// Ed25519 signature over the first statement.
        ed25519_sig_a: Vec<u8>,
        /// Mandatory ML-DSA-65 co-signature when `prover_pq_pubkey` is set.
        #[serde(default)]
        pq_sig_a: Vec<u8>,
        /// Second conflicting state root (`!= state_root_a`).
        state_root_b: Hash32,
        /// Ed25519 signature over the second statement.
        ed25519_sig_b: Vec<u8>,
        /// Mandatory ML-DSA-65 co-signature when `prover_pq_pubkey` is set.
        #[serde(default)]
        pq_sig_b: Vec<u8>,
    },
    /// Verified restaking AVS or EOTS finality equivocation.
    RestakingFault {
        /// External network name.
        network: String,
        /// Governance-pinned restaking AVS quorum configuration.
        pinned: PinnedRestakingAvsSet,
        /// Cryptographic slashing proof.
        proof: Box<RestakingSlashingProof>,
    },
    /// Verified `AuxPoW`/`PoP` bonded double-anchor equivocation.
    AuxPowPopFault {
        /// External network name.
        network: String,
        /// Governance-pinned `AuxPoW`/`PoP` anchor configuration.
        pinned: Box<PinnedAuxPowAnchor>,
        /// Cryptographic `PoP` double-anchor proof.
        proof: Box<PopEquivocationProof>,
    },
    /// Verified Simplex/`MonadBFT` `DoubleNotarize` or `FinalizeAndSkip` fault.
    SimplexFault {
        /// External network name.
        network: String,
        /// Governance-pinned Simplex committee.
        pinned: PinnedSimplexCommittee,
        /// Cryptographic Simplex safety-violation proof.
        proof: Box<SimplexSlashingProof>,
    },
    /// Verified Algorand `StateProof` voter double-signature equivocation.
    AlgorandFault {
        /// External network name.
        network: String,
        /// Governance-pinned Algorand `StateProof` verifier root.
        pinned: Box<PinnedAlgorandVerifier>,
        /// Cryptographic Algorand equivocation proof.
        proof: Box<AlgorandEquivocationProof>,
    },
    /// Verified based-rollup double-preconfirmation equivocation.
    BasedPreconfFault {
        /// External network name.
        network: String,
        /// Governance-pinned based preconfirmation committee.
        pinned: PinnedBasedPreconfCommittee,
        /// Cryptographic based preconfirmation equivocation proof.
        proof: Box<BasedPreconfEquivocationProof>,
    },
    /// Verified TON Masterchain Catchain validator double-commit equivocation.
    TonCatchainFault {
        /// External network name.
        network: String,
        /// Governance-pinned TON Masterchain key-block anchor.
        pinned: PinnedTonMasterchainAnchor,
        /// Cryptographic Catchain double-commit proof.
        proof: Box<TonCatchainEquivocationProof>,
    },
    /// Verified Stellar/FBA `SCPStatementExternalize` ballot equivocation.
    StellarFbaFault {
        /// External network name.
        network: String,
        /// Governance-pinned SCP top tier.
        pinned: PinnedScpTier,
        /// Cryptographic SCP ballot equivocation proof.
        proof: Box<StellarBallotEquivocationProof>,
    },
}

/// Deterministic slashing receipt returned by
/// [`BridgeEconomicGuard::submit_contradiction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContradictionOutcome {
    /// Guarded domain frozen by the verified contradiction.
    pub domain_id: DomainId,
    /// Canonical digest of the verified contradiction evidence.
    pub evidence_digest: Hash32,
    /// Address of the bonded prover whose escrow was slashed, when present.
    pub slashed_prover: Option<Address>,
    /// Total prover bond atoms slashed (`0` when no prover bond was attached).
    pub slashed_bond_atoms: u128,
    /// Challenger reward atoms carved out of `slashed_bond_atoms`.
    pub challenger_reward_atoms: u128,
    /// Net burned prover bond atoms (`slashed_bond_atoms - challenger_reward_atoms`).
    pub burned_bond_atoms: u128,
    /// External protocol weight proven culpable (`0` for direct prover double-root).
    pub external_slashed_weight: u128,
}

/// Refusal returned by [`BridgeEconomicGuard`].
///
/// WIRING: returned by [`BridgeEconomicGuard`] checks in [`crate::cross_domain::bridge::BridgeState`]
/// and [`crate::cross_domain::bridge_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicGuardError {
    /// Domain is not registered in the economic guard.
    UnknownDomain(DomainId),
    /// Policy parameter lies outside valid protocol bounds.
    InvalidPolicy(String),
    /// Domain is frozen due to a previously verified contradiction proof.
    DomainFrozen {
        /// Frozen domain identifier.
        domain_id: DomainId,
        /// Contradiction evidence digest that froze the domain.
        evidence_digest: Hash32,
    },
    /// Requested bridge flow exceeds the domain's effective window ceiling.
    CeilingExceeded {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Requested flow amount in atoms.
        requested_atoms: u128,
        /// Already consumed flow in the active window.
        window_used_atoms: u128,
        /// Maximum effective ceiling for the active window.
        ceiling_atoms: u128,
    },
    /// Contradiction evidence digest or offender fault set was already processed.
    DuplicateEvidence(Hash32),
    /// Supplied external adapter or pinned committee does not match the
    /// domain's governance-pinned [`DomainCeilingPolicy::pinned_adapter`].
    AdapterPinMismatch {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Diagnostic mismatch reason.
        reason: String,
    },
    /// Contradiction or offender replay ledger reached its hard fail-closed cap.
    ReplayLedgerFull {
        /// Maximum entries permitted without governance snapshot pruning.
        capacity: usize,
    },
    /// Domain circuit breaker is temporarily paused following a deep reorg.
    DomainPaused {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Height at or after which timed pause recovery may resume flows.
        pause_expires_at_height: u64,
        /// Observed reorg depth that triggered the pause.
        reorg_depth: u64,
    },
    /// Domain is within the mandatory post-pause cooldown window and cannot be re-paused yet.
    ReorgPauseCooldownActive {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Current Budlum block height.
        current_height: u64,
        /// Height at or after which a new timed pause may be armed.
        cooldown_until_height: u64,
    },
    /// Withdrawal exceeds `max_single_tx_withdraw_atoms` and must use the timelock queue.
    LargeWithdrawalRequiresTimelock {
        /// Guarded domain identifier.
        domain_id: DomainId,
        /// Requested withdrawal amount in atoms.
        amount_atoms: u128,
        /// Maximum instant single-tx withdrawal cap.
        max_single_tx_withdraw_atoms: u128,
    },
    /// Queued withdrawal has not yet reached `ready_at_height`.
    WithdrawalTimelockActive {
        /// Queued withdrawal identifier.
        withdrawal_id: Hash32,
        /// Target claim height.
        ready_at_height: u64,
        /// Current Budlum block height.
        current_height: u64,
    },
    /// Queued withdrawal identifier was not found (never queued or already claimed).
    UnknownQueuedWithdrawal(Hash32),
    /// Contradiction or external adapter proof failed verification.
    InvalidEvidence(String),
}

impl std::fmt::Display for EconomicGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDomain(id) => write!(f, "domain {id} has no economic guard record"),
            Self::InvalidPolicy(msg) => write!(f, "invalid economic guard policy: {msg}"),
            Self::DomainFrozen {
                domain_id,
                evidence_digest,
            } => write!(
                f,
                "domain {domain_id} bridge flow frozen by verified contradiction {}",
                hex::encode(evidence_digest)
            ),
            Self::CeilingExceeded {
                domain_id,
                requested_atoms,
                window_used_atoms,
                ceiling_atoms,
            } => write!(
                f,
                "domain {domain_id} bridge flow exceeds adaptive escrow ceiling \
                 (requested={requested_atoms}, used={window_used_atoms}, ceiling={ceiling_atoms})"
            ),
            Self::DuplicateEvidence(d) => write!(
                f,
                "contradiction evidence {} already applied",
                hex::encode(d)
            ),
            Self::AdapterPinMismatch { domain_id, reason } => write!(
                f,
                "domain {domain_id} external adapter pin mismatch: {reason}"
            ),
            Self::ReplayLedgerFull { capacity } => write!(
                f,
                "economic guard replay ledger reached fail-closed capacity {capacity}"
            ),
            Self::DomainPaused {
                domain_id,
                pause_expires_at_height,
                reorg_depth,
            } => write!(
                f,
                "domain {domain_id} circuit breaker paused after reorg depth {reorg_depth} \
                 until height {pause_expires_at_height}"
            ),
            Self::ReorgPauseCooldownActive {
                domain_id,
                current_height,
                cooldown_until_height,
            } => write!(
                f,
                "domain {domain_id} reorg pause cooldown active until height \
                 {cooldown_until_height} (current={current_height})"
            ),
            Self::LargeWithdrawalRequiresTimelock {
                domain_id,
                amount_atoms,
                max_single_tx_withdraw_atoms,
            } => write!(
                f,
                "domain {domain_id} withdrawal {amount_atoms} exceeds single-tx limit \
                 {max_single_tx_withdraw_atoms} and requires timelock queue"
            ),
            Self::WithdrawalTimelockActive {
                withdrawal_id,
                ready_at_height,
                current_height,
            } => write!(
                f,
                "queued withdrawal {} locked until height {ready_at_height} (current={current_height})",
                hex::encode(withdrawal_id)
            ),
            Self::UnknownQueuedWithdrawal(id) => write!(
                f,
                "queued withdrawal {} does not exist",
                hex::encode(id)
            ),
            Self::InvalidEvidence(msg) => write!(f, "invalid contradiction evidence: {msg}"),
        }
    }
}

impl std::error::Error for EconomicGuardError {}

/// Canonical signing preimage for a prover state-root statement.
///
/// WIRING: signed by bonded bridge provers and verified inside
/// [`BridgeEconomicGuard::submit_contradiction`].
#[must_use]
pub fn contradiction_statement_bytes(
    domain_id: DomainId,
    domain_height: u64,
    state_root: &Hash32,
) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_ECON_GUARD_CONTRA_V1",
        &domain_id.to_le_bytes(),
        &domain_height.to_le_bytes(),
        state_root,
    ])
}

const fn mul_bps_floor(amount: u128, bps: u64) -> u128 {
    let b = bps as u128;
    let q = amount / BPS_DEN;
    let r = amount % BPS_DEN;
    q.saturating_mul(b)
        .saturating_add(r.saturating_mul(b) / BPS_DEN)
}

pub(crate) fn validate_policy(policy: &DomainCeilingPolicy) -> Result<(), EconomicGuardError> {
    if policy.shared_consumer_count == 0 {
        return Err(EconomicGuardError::InvalidPolicy(
            "shared_consumer_count must be at least 1".into(),
        ));
    }
    if policy.window_blocks == 0 {
        return Err(EconomicGuardError::InvalidPolicy(
            "window_blocks must be at least 1".into(),
        ));
    }
    if u128::from(policy.stake_haircut_bps) > BPS_DEN
        || u128::from(policy.bond_haircut_bps) > BPS_DEN
        || u128::from(policy.finder_reward_bps) > BPS_DEN
    {
        return Err(EconomicGuardError::InvalidPolicy(
            "basis-point parameters cannot exceed 10_000".into(),
        ));
    }
    if policy.finder_reward_bps > MAX_FINDER_REWARD_BPS {
        return Err(EconomicGuardError::InvalidPolicy(format!(
            "finder_reward_bps {} exceeds the protocol ceiling {MAX_FINDER_REWARD_BPS}; the \
             reward is carved from the slashed bond and an uncapped share lets the slashed \
             prover reclaim it",
            policy.finder_reward_bps
        )));
    }
    if let Some(ed_pk) = policy.prover_ed25519_pubkey {
        if bool::from(ed_pk.ct_eq(&[0u8; 32])) {
            return Err(EconomicGuardError::InvalidPolicy(
                "prover_ed25519_pubkey cannot be all-zero".into(),
            ));
        }
    }
    if !policy.prover_pq_pubkey.is_empty() {
        if policy.prover_ed25519_pubkey.is_none() {
            return Err(EconomicGuardError::InvalidPolicy(
                "prover_pq_pubkey requires prover_ed25519_pubkey".into(),
            ));
        }
        pq::validate_public_key(SchemeId::ML_DSA_65, &policy.prover_pq_pubkey).map_err(|e| {
            EconomicGuardError::InvalidPolicy(format!("invalid prover ML-DSA-65 public key: {e}"))
        })?;
    }
    if let Some(pin) = &policy.pinned_adapter {
        if pin.network().trim().is_empty() {
            return Err(EconomicGuardError::InvalidPolicy(
                "pinned_adapter network cannot be empty".into(),
            ));
        }
    }
    Ok(())
}

fn verify_domain_adapter_pin(
    domain_id: DomainId,
    expected: Option<&GuardedExternalAdapter>,
    supplied: &GuardedExternalAdapter,
) -> Result<(), EconomicGuardError> {
    let Some(exp) = expected else {
        return Err(EconomicGuardError::AdapterPinMismatch {
            domain_id,
            reason: "domain policy has no governance-pinned external adapter".into(),
        });
    };
    let exp_digest = exp.canonical_pin_digest();
    let sup_digest = supplied.canonical_pin_digest();
    if !bool::from(exp_digest.ct_eq(&sup_digest)) || exp != supplied {
        return Err(EconomicGuardError::AdapterPinMismatch {
            domain_id,
            reason: "supplied external adapter or committee disagrees with governance pin".into(),
        });
    }
    Ok(())
}

#[must_use]
fn offender_replay_key(
    domain_id: DomainId,
    adapter_tag: u8,
    fault_locus: &[u8],
    scheme: SchemeId,
    offender_identity: &[u8],
) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_ECON_GUARD_OFFENDER_V1",
        &domain_id.to_le_bytes(),
        &[adapter_tag],
        fault_locus,
        &scheme.to_be_bytes(),
        offender_identity,
    ])
}

#[must_use]
const fn hybrid_or_ed25519_scheme(has_pq: bool) -> SchemeId {
    if has_pq {
        SchemeId::ML_DSA_65
    } else {
        SchemeId::ED25519
    }
}

fn compute_incremental_slash<F>(
    slashed_offenders: &BTreeSet<Hash32>,
    domain_id: DomainId,
    adapter_tag: u8,
    fault_locus: &[u8],
    offenders: &[[u8; 32]],
    evidence_digest: Hash32,
    mut lookup: F,
) -> Result<(u128, Vec<Hash32>), EconomicGuardError>
where
    F: FnMut(&[u8; 32]) -> Option<(u128, bool)>,
{
    let mut fresh_weight = 0u128;
    let mut fresh_keys = Vec::new();
    for pk in offenders {
        let (weight, has_pq) = lookup(pk).ok_or_else(|| {
            EconomicGuardError::InvalidEvidence(
                "verified offender missing from governance-pinned committee".into(),
            )
        })?;
        let key = offender_replay_key(
            domain_id,
            adapter_tag,
            fault_locus,
            hybrid_or_ed25519_scheme(has_pq),
            pk,
        );
        if !slashed_offenders.contains(&key) {
            fresh_weight = fresh_weight.saturating_add(weight);
            fresh_keys.push(key);
        }
    }
    if fresh_keys.is_empty() {
        return Err(EconomicGuardError::DuplicateEvidence(evidence_digest));
    }
    Ok((fresh_weight, fresh_keys))
}

fn hash_security_backing(backing: &SecurityBacking) -> Hash32 {
    match backing {
        SecurityBacking::None => hash_fields_bytes(&[b"BDLM_ECON_GUARD_DOMAIN_V1", &[0u8]]),
        SecurityBacking::Authority { count } => {
            hash_fields_bytes(&[b"BDLM_ECON_GUARD_DOMAIN_V1", &[1u8], &count.to_le_bytes()])
        }
        SecurityBacking::Work { difficulty_bits } => hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_DOMAIN_V1",
            &[2u8],
            &difficulty_bits.to_le_bytes(),
        ]),
        SecurityBacking::SignatureSet {
            scheme,
            signers,
            required,
            total_weight,
            slashable,
        } => hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_DOMAIN_V1",
            &[3u8],
            scheme.name().as_bytes(),
            &signers.to_le_bytes(),
            &required.to_le_bytes(),
            &total_weight.to_le_bytes(),
            &[u8::from(*slashable)],
        ]),
        SecurityBacking::Zk {
            system,
            public_inputs_digest,
        } => {
            let sys_tag: u8 = match system.assumption_class() {
                AssumptionClass::Hash => 1,
                AssumptionClass::ClassicalPairing => 2,
            };
            hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_DOMAIN_V1",
                &[4u8],
                &[sys_tag],
                public_inputs_digest,
            ])
        }
    }
}

fn hash_prover_bond(bond: &ProverBond) -> Hash32 {
    let slash_count_le = u64::try_from(bond.slashings.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let mut slash_leaves = Vec::with_capacity(bond.slashings.len());
    for s in &bond.slashings {
        slash_leaves.push(hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_BOND_V1",
            &s.at_height.to_le_bytes(),
            &s.evidence_digest,
            &s.amount_atoms.to_le_bytes(),
            s.challenger.as_bytes(),
            &s.challenge_reward_atoms.to_le_bytes(),
        ]));
    }
    let bond_le = bond.bond_atoms.to_le_bytes();
    let ceil_le = bond.ceiling_atoms.to_le_bytes();
    let slashed_le = bond.slashed_atoms.to_le_bytes();
    let acc_le = bond.accepted.to_le_bytes();
    let ref_le = bond.refused.to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(slash_leaves.len().saturating_add(8));
    fields.push(b"BDLM_ECON_GUARD_BOND_V1");
    fields.push(bond.prover.as_bytes());
    fields.push(&bond_le);
    fields.push(&ceil_le);
    fields.push(&slashed_le);
    fields.push(&acc_le);
    fields.push(&ref_le);
    fields.push(&slash_count_le);
    for leaf in &slash_leaves {
        fields.push(leaf);
    }
    hash_fields_bytes(&fields)
}

/// Pure-integer computation of a domain's per-window bridge ceiling in atoms.
///
/// WIRING: enforced on every inbound bridge mint and unlock through
/// [`BridgeEconomicGuard::check_and_record_flow`].
///
/// Applies weakest-link economic soundness:
/// - `FrozenByContradiction` or `SecurityBacking::None` -> strictly `0`.
/// - Unslashable `SignatureSet` or `Authority` -> `0` without a live
///   [`ProverBond`], or `floor(live_bond * bond_haircut_bps / 10_000)` when
///   backed by slashable prover collateral.
/// - Slashable `SignatureSet` ->
///   `floor(floor(total_weight / shared_consumer_count) * stake_haircut_bps / 10_000)`,
///   bounded above by `bond_cap` whenever a prover bond is also attached.
/// - Verified `PoW` / hash-STARK domains -> their configured window caps (zero
///   for classical-pairing SNARKs unless covered by a bond), bounded above by
///   `bond_cap` when a prover bond is attached.
///
/// WIRING: evaluated on every guarded bridge flow inside [`BridgeEconomicGuard`].
#[must_use]
pub fn effective_ceiling_atoms(record: &DomainEconomicRecord) -> u128 {
    if matches!(
        record.status,
        DomainGuardStatus::FrozenByContradiction { .. }
    ) {
        return 0;
    }
    let policy = &record.policy;
    let bond_cap = record
        .prover_bond
        .as_ref()
        .map(|b| mul_bps_floor(b.live_atoms(), policy.bond_haircut_bps));

    match &policy.backing {
        SecurityBacking::None => 0,
        SecurityBacking::Authority { .. }
        | SecurityBacking::SignatureSet {
            slashable: false, ..
        } => bond_cap.unwrap_or(0),
        SecurityBacking::SignatureSet {
            total_weight,
            slashable: true,
            ..
        } => {
            // `total_weight` is the external protocol's own unit - a sync
            // committee counts signers, a Tendermint set sums voting power,
            // a Solana set sums lamports - and nothing here converts it to
            // atoms. Read as atoms it priced one chain's window at nothing
            // and another's at more than exists. Until a governance-pinned
            // unit lands, stake credit is admitted only through a bond and
            // never above the bond's haircut; without a bond the set earns
            // what an unslashable set earns: nothing.
            let consumers = u128::from(policy.shared_consumer_count.max(1));
            let dedicated_stake = total_weight / consumers;
            let stake_cap = mul_bps_floor(dedicated_stake, policy.stake_haircut_bps);
            bond_cap.map_or(0, |bc| stake_cap.min(bc))
        }
        SecurityBacking::Work { difficulty_bits } => {
            let work_cap = if *difficulty_bits >= policy.min_work_difficulty_bits {
                policy.work_window_cap_atoms
            } else {
                0
            };
            bond_cap.map_or(work_cap, |bc| work_cap.min(bc))
        }
        SecurityBacking::Zk { system, .. } => {
            let zk_cap = match system.assumption_class() {
                AssumptionClass::Hash => policy.zk_window_cap_atoms,
                AssumptionClass::ClassicalPairing => 0,
            };
            bond_cap.map_or(zk_cap, |bc| zk_cap.min(bc))
        }
    }
}

/// Pure-integer computation of a domain's per-window bridge ceiling derived
/// directly from its row in the [`crate::settlement::universal_finality::GlobalFinalityCertificate`].
///
/// Any domain whose certificate verdict is `Pending` or `Refuted` receives a
/// strict `0` ceiling in that block so bridge outflows halt immediately when a
/// domain leaves the `Established` bucket.
///
/// WIRING: enforced by [`BridgeEconomicGuard::check_and_record_flow_with_certificate`] on every bridge mint and unlock.
#[must_use]
pub fn effective_ceiling_from_certificate_row(
    record: &DomainEconomicRecord,
    entry: &crate::settlement::universal_finality::DomainFinalityEntry,
) -> u128 {
    if matches!(
        record.status,
        DomainGuardStatus::FrozenByContradiction { .. }
    ) {
        return 0;
    }
    if !matches!(
        entry.verdict,
        crate::settlement::universal_finality::FinalityVerdict::Established
    ) {
        return 0;
    }
    if !entry.guarantee.admits_cross_domain_value() {
        return 0;
    }
    let policy_cap = effective_ceiling_atoms(record);
    let cert_bound = crate::settlement::universal_finality::EconomicSecurityBound::derive(
        &entry.guarantee,
        entry.bond_atoms,
        entry.bond_atoms,
    );
    if cert_bound.safe_value_outflow_ceiling_atoms > 0 {
        policy_cap.min(cert_bound.safe_value_outflow_ceiling_atoms)
    } else {
        policy_cap
    }
}

/// Consensus-deterministic adaptive escrow ceiling and contradiction slashing
/// ledger embedded inside [`crate::cross_domain::bridge::BridgeState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BridgeEconomicGuard {
    domains: BTreeMap<DomainId, DomainEconomicRecord>,
    consumed_evidence: BTreeSet<Hash32>,
    #[serde(default)]
    slashed_offenders: BTreeSet<Hash32>,
    #[serde(default, with = "crate::core::map_keys")]
    consumed_evidence_epochs: BTreeMap<Hash32, u64>,
    #[serde(default, with = "crate::core::map_keys")]
    slashed_offender_epochs: BTreeMap<Hash32, u64>,
    #[serde(default)]
    replay_pruned_before_epoch: u64,
    #[serde(default)]
    require_configured_domains: bool,
    #[serde(default)]
    flow_controls: BTreeMap<DomainId, DomainFlowControls>,
    #[serde(default)]
    domain_pauses: BTreeMap<DomainId, CircuitBreakerPause>,
    #[serde(default)]
    reorg_pause_cooldown_until: BTreeMap<DomainId, u64>,
    #[serde(default)]
    deposit_window_usage: BTreeMap<DomainId, (u64, u128)>,
    #[serde(default, with = "crate::core::map_keys")]
    queued_withdrawals: BTreeMap<Hash32, QueuedBridgeWithdrawal>,
    #[serde(default)]
    next_withdrawal_nonce: u64,
}

impl BridgeEconomicGuard {
    /// Construct an empty economic guard in permissive internal-domain mode.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a fail-closed production economic guard where every inbound
    /// bridge domain MUST have an explicit [`DomainCeilingPolicy`] before any
    /// mint or unlock flow can succeed.
    ///
    /// WIRING: canonical mainnet/public-testnet constructor enforced by
    /// [`Self::for_chain_id`].
    #[must_use]
    pub fn production() -> Self {
        Self {
            require_configured_domains: true,
            ..Self::default()
        }
    }

    /// Construct an economic guard scoped to `chain_id`: strict fail-closed on
    /// mainnet ([`MAINNET_GUARD_CHAIN_ID`]) and public testnet
    /// ([`TESTNET_GUARD_CHAIN_ID`]), permissive on local devnet IDs.
    ///
    /// WIRING: invoked by
    /// [`crate::cross_domain::bridge_tx::enable_chain_economic_guard_mode`].
    #[must_use]
    pub fn for_chain_id(chain_id: u64) -> Self {
        if matches!(chain_id, MAINNET_GUARD_CHAIN_ID | TESTNET_GUARD_CHAIN_ID) {
            Self::production()
        } else {
            Self::new()
        }
    }

    /// Toggle whether inbound bridge flows on unconfigured domains fail closed
    /// with [`EconomicGuardError::UnknownDomain`].
    pub const fn set_require_configured_domains(&mut self, require: bool) {
        self.require_configured_domains = require;
    }

    /// Return `true` when unconfigured inbound domains fail closed.
    #[must_use]
    pub const fn requires_configured_domains(&self) -> bool {
        self.require_configured_domains
    }

    /// Require that `domain_id` has an explicit [`DomainCeilingPolicy`].
    ///
    /// WIRING: enforced by [`crate::cross_domain::bridge_tx`] for every flow
    /// arriving from a foreign domain registered in `external_roots`.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`] when `domain_id` is absent.
    pub fn ensure_domain_configured(&self, domain_id: DomainId) -> Result<(), EconomicGuardError> {
        if self.domains.contains_key(&domain_id) {
            Ok(())
        } else {
            Err(EconomicGuardError::UnknownDomain(domain_id))
        }
    }

    /// Return `true` when no domains, replay records, or strict flags are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.consumed_evidence.is_empty()
            && self.slashed_offenders.is_empty()
            && self.consumed_evidence_epochs.is_empty()
            && self.slashed_offender_epochs.is_empty()
            && self.replay_pruned_before_epoch == 0
            && !self.require_configured_domains
            && self.flow_controls.is_empty()
            && self.domain_pauses.is_empty()
            && self.reorg_pause_cooldown_until.is_empty()
            && self.deposit_window_usage.is_empty()
            && self.queued_withdrawals.is_empty()
            && self.next_withdrawal_nonce == 0
    }

    /// Configure asymmetric deposit/withdraw controls and reorg auto-pause
    /// parameters for `domain_id`.
    ///
    /// WIRING: Governance/bridge domain configuration door paired with
    /// [`crate::cross_domain::bridge::BridgeState`].
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`] if `domain_id` is absent.
    pub fn configure_domain_flow_controls(
        &mut self,
        domain_id: DomainId,
        controls: DomainFlowControls,
    ) -> Result<(), EconomicGuardError> {
        if !self.domains.contains_key(&domain_id) {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        }
        self.flow_controls.insert(domain_id, controls);
        Ok(())
    }

    /// Inspect any active circuit-breaker pause on `domain_id`.
    ///
    /// WIRING: Read-only telemetry accessor for bridge operators and gates.
    #[must_use]
    pub fn domain_pause(&self, domain_id: DomainId) -> Option<&CircuitBreakerPause> {
        self.domain_pauses.get(&domain_id)
    }

    fn ensure_not_paused(&self, domain_id: DomainId) -> Result<(), EconomicGuardError> {
        if let Some(pause) = self.domain_pauses.get(&domain_id) {
            return Err(EconomicGuardError::DomainPaused {
                domain_id,
                pause_expires_at_height: pause.pause_expires_at_height,
                reorg_depth: pause.reorg_depth,
            });
        }
        Ok(())
    }

    /// Trigger a timed circuit-breaker pause on `domain_id` if an observed
    /// foreign-domain reorg depth meets or exceeds its configured threshold.
    ///
    /// WIRING: Consensus reorg watcher entry point enforcing timed bridge pause.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`] if `domain_id` is absent
    /// or [`EconomicGuardError::DomainFrozen`] if the domain is permanently
    /// frozen by contradiction.
    pub fn observe_reorg_depth(
        &mut self,
        domain_id: DomainId,
        reorg_depth: u64,
        current_height: u64,
    ) -> Result<bool, EconomicGuardError> {
        self.observe_reorg_depth_with_scope(
            domain_id,
            reorg_depth,
            current_height,
            GuardianPauseScope::FullBridgeFreeze,
        )
    }

    /// Trigger a scoped timed circuit-breaker pause on `domain_id` if an
    /// observed foreign-domain reorg depth meets or exceeds its threshold and
    /// any post-pause cooldown window has expired.
    ///
    /// WIRING: Scoped consensus reorg watcher enforcing bounded pause duration
    /// and cooldown against repeated re-pausing griefing.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`],
    /// [`EconomicGuardError::DomainFrozen`], or
    /// [`EconomicGuardError::ReorgPauseCooldownActive`] when a prior pause
    /// recently expired.
    pub fn observe_reorg_depth_with_scope(
        &mut self,
        domain_id: DomainId,
        reorg_depth: u64,
        current_height: u64,
        scope: GuardianPauseScope,
    ) -> Result<bool, EconomicGuardError> {
        self.ensure_domain_not_frozen(domain_id)?;
        if !self.domains.contains_key(&domain_id) {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        }
        let Some(controls) = self.flow_controls.get(&domain_id) else {
            return Ok(false);
        };
        if controls.auto_pause_reorg_depth_threshold == 0
            || reorg_depth < controls.auto_pause_reorg_depth_threshold
        {
            return Ok(false);
        }
        if let Some(&cooldown_until_height) = self.reorg_pause_cooldown_until.get(&domain_id) {
            if current_height < cooldown_until_height {
                return Err(EconomicGuardError::ReorgPauseCooldownActive {
                    domain_id,
                    current_height,
                    cooldown_until_height,
                });
            }
        }
        let duration = if controls.circuit_pause_duration_blocks == 0 {
            DEFAULT_CIRCUIT_PAUSE_DURATION_BLOCKS
        } else {
            controls.circuit_pause_duration_blocks
        };
        let expires = current_height.saturating_add(duration);
        self.domain_pauses.insert(
            domain_id,
            CircuitBreakerPause {
                paused_at_height: current_height,
                pause_expires_at_height: expires,
                reorg_depth,
                scope,
            },
        );
        Ok(true)
    }

    /// Clear a timed reorg circuit-breaker pause once `current_height` reaches
    /// or passes `pause_expires_at_height`, and arm the mandatory cooldown window
    /// before another timed pause can re-lock the domain.
    ///
    /// Never clears `FrozenByContradiction`: contradiction freezes are permanent
    /// and fail closed with [`EconomicGuardError::DomainFrozen`].
    ///
    /// WIRING: Block-height recovery door for timed reorg pauses.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::DomainFrozen`] when permanently frozen by
    /// contradiction.
    pub fn resume_if_pause_expired(
        &mut self,
        domain_id: DomainId,
        current_height: u64,
    ) -> Result<bool, EconomicGuardError> {
        if let Some(rec) = self.domains.get(&domain_id) {
            if let DomainGuardStatus::FrozenByContradiction {
                evidence_digest, ..
            } = rec.status
            {
                return Err(EconomicGuardError::DomainFrozen {
                    domain_id,
                    evidence_digest,
                });
            }
        }
        let should_resume = self
            .domain_pauses
            .get(&domain_id)
            .is_some_and(|p| current_height >= p.pause_expires_at_height);
        if should_resume {
            self.domain_pauses.remove(&domain_id);
            self.reorg_pause_cooldown_until.insert(
                domain_id,
                current_height.saturating_add(REORG_PAUSE_COOLDOWN_BLOCKS),
            );
        }
        Ok(should_resume)
    }

    /// Inspect the guard record for `domain_id`, if configured.
    #[must_use]
    pub fn record(&self, domain_id: DomainId) -> Option<&DomainEconomicRecord> {
        self.domains.get(&domain_id)
    }

    /// Every domain whose last refused flow exceeded its window ceiling,
    /// paired with the witness of that refusal.
    ///
    /// A refused flow on its own is ordinary traffic control: the caller is
    /// told `CeilingExceeded` and nothing moves. This sweep is how an operator
    /// or a monitoring loop finds the refusals that were not ordinary, without
    /// having to poll every domain record one at a time. The result is sorted
    /// by domain id so two nodes reading the same guard see the same list.
    ///
    /// WIRING: the production reader of [`DomainEconomicRecord::window_breach`].
    #[must_use]
    pub fn window_breaches(&self) -> Vec<(DomainId, &WindowBreach)> {
        self.domains
            .iter()
            .filter_map(|(domain_id, record)| {
                record
                    .window_breach
                    .as_ref()
                    .map(|breach| (*domain_id, breach))
            })
            .collect()
    }

    /// Configure or update a domain's ceiling policy and optional prover bond.
    ///
    /// Preserves any existing `FrozenByContradiction` status and rolling-window
    /// consumption so updating a policy cannot bypass a contradiction freeze or
    /// reset active-window usage.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::InvalidPolicy`] when haircuts exceed
    /// `10_000` bps, `window_blocks == 0`, `shared_consumer_count == 0`, or an
    /// attached PQ public key fails structural validation.
    pub fn configure_domain(
        &mut self,
        domain_id: DomainId,
        policy: DomainCeilingPolicy,
        prover_bond: Option<ProverBond>,
    ) -> Result<(), EconomicGuardError> {
        validate_policy(&policy)?;
        if let Some(existing) = self.domains.get_mut(&domain_id) {
            existing.policy = policy;
            existing.prover_bond = prover_bond;
            return Ok(());
        }
        self.domains.insert(
            domain_id,
            DomainEconomicRecord {
                policy,
                status: DomainGuardStatus::Active,
                active_window: 0,
                window_used_atoms: 0,
                prover_bond,
                window_breach: None,
            },
        );
        Ok(())
    }

    /// Take the backing the external-domain intake just verified for
    /// `domain_id`. The intake is the one place evidence is verified; the
    /// guard reads what it accepted rather than verifying a second time.
    /// A domain with no ceiling policy is not an error here - it has
    /// nothing to update and routes nothing anyway - and a frozen domain
    /// keeps its freeze: a fresh backing is not a verdict on the contradiction.
    ///
    /// # Errors
    ///
    /// [`EconomicGuardError::DomainFrozen`] when the domain is frozen.
    pub fn adopt_intake_backing(
        &mut self,
        domain_id: DomainId,
        backing: SecurityBacking,
    ) -> Result<(), EconomicGuardError> {
        let Some(record) = self.domains.get_mut(&domain_id) else {
            return Ok(());
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = record.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        record.policy.backing = backing;
        Ok(())
    }

    /// Freeze `domain_id` on a contradiction the external-domain intake
    /// proved and slashed. The intake verified the conflicting proof and
    /// took the carrier's bond; the guard's part is to stop the window, so
    /// no value routes on a domain whose finality was shown false. A second
    /// freeze for the same domain is idempotent, and a domain with no
    /// ceiling policy has no window to stop.
    pub fn freeze_from_intake_contradiction(
        &mut self,
        domain_id: DomainId,
        evidence_digest: Hash32,
        height: u64,
    ) {
        if let Some(record) = self.domains.get_mut(&domain_id) {
            if matches!(record.status, DomainGuardStatus::Active) {
                record.status = DomainGuardStatus::FrozenByContradiction {
                    frozen_at_height: height,
                    evidence_digest,
                };
            }
        }
    }

    /// Verify a raw external consensus evidence bundle through one of the
    /// supported consensus adapters and update `domain_id`'s [`SecurityBacking`].
    ///
    /// # Errors
    ///
    /// Returns an error when `domain_id` is unconfigured, frozen, or the
    /// adapter rejects `evidence` under `verification_policy`.
    pub fn refresh_backing_from_adapter(
        &mut self,
        domain_id: DomainId,
        adapter_cfg: &GuardedExternalAdapter,
        evidence: &RawConsensusEvidence,
        verification_policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, EconomicGuardError> {
        let Some(existing) = self.domains.get(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = existing.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        verify_domain_adapter_pin(
            domain_id,
            existing.policy.pinned_adapter.as_ref(),
            adapter_cfg,
        )?;
        let attestation = match adapter_cfg {
            GuardedExternalAdapter::RestakingAvs { network, pinned } => {
                RestakingAvsAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::AuxPowPop { network, pinned } => {
                AuxPowPopAdapter::new(network.clone(), Some((**pinned).clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::SimplexBft { network, pinned } => {
                SimplexBftAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::AlgorandStateProof { network, pinned } => {
                AlgorandStateProofAdapter::new(network.clone(), Some((**pinned).clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::BasedPreconf { network, pinned } => {
                BasedPreconfAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::TonCatchain { network, pinned } => {
                TonCatchainAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::StellarScp { network, pinned } => {
                StellarScpAdapter::new(network.clone(), Some(pinned.clone()))
                    .verify(evidence, verification_policy)
            }
            GuardedExternalAdapter::MinaRecursive { network, pinned } => {
                SuccinctRecursiveAdapter::new(network.clone(), Some((**pinned).clone()))
                    .verify(evidence, verification_policy)
            }
        }
        .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;

        if let Some(rec) = self.domains.get_mut(&domain_id) {
            rec.policy.backing = attestation.security;
        }
        Ok(attestation)
    }

    /// Ensure `domain_id` is not frozen by a verified contradiction proof and,
    /// in strict production mode, has an explicit guard policy.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`] in strict mode when
    /// `domain_id` is absent, or [`EconomicGuardError::DomainFrozen`] when halted.
    pub fn ensure_domain_not_frozen(&self, domain_id: DomainId) -> Result<(), EconomicGuardError> {
        let Some(rec) = self.domains.get(&domain_id) else {
            if self.require_configured_domains {
                return Err(EconomicGuardError::UnknownDomain(domain_id));
            }
            return Ok(());
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = rec.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        Ok(())
    }

    /// Verify that `domain_id` is not frozen and that recording `amount_atoms`
    /// at `current_height` fits inside its adaptive escrow ceiling.
    ///
    /// When [`Self::requires_configured_domains`] is enabled, unconfigured
    /// domains fail closed with [`EconomicGuardError::UnknownDomain`];
    /// configured domains mutate nothing on refusal.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`],
    /// [`EconomicGuardError::DomainFrozen`], or
    /// [`EconomicGuardError::CeilingExceeded`] before any state change.
    fn ensure_not_paused_for_timelock_claim(
        &self,
        domain_id: DomainId,
    ) -> Result<(), EconomicGuardError> {
        if let Some(pause) = self.domain_pauses.get(&domain_id) {
            if matches!(pause.scope, GuardianPauseScope::FullBridgeFreeze) {
                return Err(EconomicGuardError::DomainPaused {
                    domain_id,
                    pause_expires_at_height: pause.pause_expires_at_height,
                    reorg_depth: pause.reorg_depth,
                });
            }
        }
        Ok(())
    }

    pub fn check_and_record_flow(
        &mut self,
        domain_id: DomainId,
        amount_atoms: u128,
        current_height: u64,
    ) -> Result<(), EconomicGuardError> {
        self.check_and_record_flow_inner(domain_id, amount_atoms, current_height, false)
    }

    fn check_and_record_flow_inner(
        &mut self,
        domain_id: DomainId,
        amount_atoms: u128,
        current_height: u64,
        allow_scoped_timelock_exit: bool,
    ) -> Result<(), EconomicGuardError> {
        if allow_scoped_timelock_exit {
            self.ensure_not_paused_for_timelock_claim(domain_id)?;
        } else {
            self.ensure_not_paused(domain_id)?;
        }
        let Some(rec) = self.domains.get(&domain_id) else {
            if self.require_configured_domains {
                return Err(EconomicGuardError::UnknownDomain(domain_id));
            }
            return Ok(());
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = rec.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        let win_len = rec.policy.window_blocks.max(1);
        let window_idx = current_height / win_len;
        let used = if window_idx == rec.active_window {
            rec.window_used_atoms
        } else {
            0
        };
        let ceiling = effective_ceiling_atoms(rec);
        let Some(next_used) = used.checked_add(amount_atoms) else {
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        };
        if next_used > ceiling || (amount_atoms == 0 && ceiling == 0) {
            self.record_window_breach(
                domain_id,
                current_height,
                window_idx,
                amount_atoms,
                used,
                ceiling,
            );
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        }
        if let Some(rec_mut) = self.domains.get_mut(&domain_id) {
            rec_mut.active_window = window_idx;
            rec_mut.window_used_atoms = next_used;
            rec_mut.window_breach = None;
        }
        Ok(())
    }

    /// Record, on the domain's record, that a flow was refused for exceeding
    /// the active window ceiling.
    ///
    /// The record is written only for a domain the guard already knows; an
    /// unknown domain has no record to annotate and its own refusal
    /// (`UnknownDomain`) already says everything there is to say. Nothing here
    /// can fail, and nothing here changes the accounting: a breach witnesses a
    /// refusal, it never charges one.
    fn record_window_breach(
        &mut self,
        domain_id: DomainId,
        height: u64,
        window: u64,
        requested_atoms: u128,
        used_atoms: u128,
        ceiling_atoms: u128,
    ) {
        if let Some(rec) = self.domains.get_mut(&domain_id) {
            rec.window_breach = Some(WindowBreach {
                height,
                window,
                requested_atoms,
                used_atoms,
                ceiling_atoms,
                single_attempt_over_ceiling: requested_atoms > ceiling_atoms,
            });
        }
    }

    /// Verify and record an inbound bridge flow while deriving the domain's
    /// ceiling directly from its [`crate::settlement::universal_finality::GlobalFinalityCertificate`]
    /// row when present.
    ///
    /// When `domain_id` appears in `certificate` with a `Pending` or `Refuted`
    /// verdict, its effective ceiling is strictly `0` in that block and the
    /// flow is refused with [`EconomicGuardError::CeilingExceeded`] before any
    /// state change.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError::UnknownDomain`],
    /// [`EconomicGuardError::DomainFrozen`], or
    /// [`EconomicGuardError::CeilingExceeded`] before any state change.
    pub fn check_and_record_flow_with_certificate(
        &mut self,
        domain_id: DomainId,
        amount_atoms: u128,
        current_height: u64,
        certificate: &crate::settlement::universal_finality::GlobalFinalityCertificate,
    ) -> Result<(), EconomicGuardError> {
        self.ensure_not_paused(domain_id)?;
        let Some(rec) = self.domains.get(&domain_id) else {
            if self.require_configured_domains {
                return Err(EconomicGuardError::UnknownDomain(domain_id));
            }
            return Ok(());
        };
        if let DomainGuardStatus::FrozenByContradiction {
            evidence_digest, ..
        } = rec.status
        {
            return Err(EconomicGuardError::DomainFrozen {
                domain_id,
                evidence_digest,
            });
        }
        let win_len = rec.policy.window_blocks.max(1);
        let window_idx = current_height / win_len;
        let used = if window_idx == rec.active_window {
            rec.window_used_atoms
        } else {
            0
        };
        let ceiling = match certificate.prove_domain(domain_id) {
            Some(proof) => effective_ceiling_from_certificate_row(rec, &proof.entry),
            None => effective_ceiling_atoms(rec),
        };
        let Some(next_used) = used.checked_add(amount_atoms) else {
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        };
        if next_used > ceiling || (amount_atoms == 0 && ceiling == 0) {
            self.record_window_breach(
                domain_id,
                current_height,
                window_idx,
                amount_atoms,
                used,
                ceiling,
            );
            return Err(EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: amount_atoms,
                window_used_atoms: used,
                ceiling_atoms: ceiling,
            });
        }
        if let Some(rec_mut) = self.domains.get_mut(&domain_id) {
            rec_mut.active_window = window_idx;
            rec_mut.window_used_atoms = next_used;
            rec_mut.window_breach = None;
        }
        Ok(())
    }

    /// Verify and record an asymmetric directional bridge transfer.
    ///
    /// WIRING: Directional bridge guard entry point enforcing asymmetric deposit
    /// caps and per-tx withdrawal timelock queueing.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError`] before mutating state if the domain is
    /// missing (strict mode), frozen, paused, exceeds its single-tx withdrawal
    /// threshold, or breaches the directional window ceiling.
    pub fn check_and_record_directional_flow(
        &mut self,
        domain_id: DomainId,
        direction: BridgeFlowDirection,
        amount_atoms: u128,
        current_height: u64,
    ) -> Result<(), EconomicGuardError> {
        match direction {
            BridgeFlowDirection::Withdraw => {
                self.ensure_not_paused(domain_id)?;
                self.ensure_domain_not_frozen(domain_id)?;
                if let Some(controls) = self.flow_controls.get(&domain_id) {
                    if controls.max_single_tx_withdraw_atoms > 0
                        && amount_atoms > controls.max_single_tx_withdraw_atoms
                    {
                        return Err(EconomicGuardError::LargeWithdrawalRequiresTimelock {
                            domain_id,
                            amount_atoms,
                            max_single_tx_withdraw_atoms: controls.max_single_tx_withdraw_atoms,
                        });
                    }
                }
                self.check_and_record_flow(domain_id, amount_atoms, current_height)
            }
            BridgeFlowDirection::Deposit => {
                self.ensure_not_paused(domain_id)?;
                if !self
                    .flow_controls
                    .get(&domain_id)
                    .is_some_and(|c| c.deposit_window_cap_atoms > 0)
                {
                    return self.check_and_record_flow(domain_id, amount_atoms, current_height);
                }
                let Some(rec) = self.domains.get(&domain_id) else {
                    if self.require_configured_domains {
                        return Err(EconomicGuardError::UnknownDomain(domain_id));
                    }
                    return Ok(());
                };
                if let DomainGuardStatus::FrozenByContradiction {
                    evidence_digest, ..
                } = rec.status
                {
                    return Err(EconomicGuardError::DomainFrozen {
                        domain_id,
                        evidence_digest,
                    });
                }
                let win_len = rec.policy.window_blocks.max(1);
                let window_idx = current_height / win_len;
                let (prev_win, prev_used) = self
                    .deposit_window_usage
                    .get(&domain_id)
                    .copied()
                    .unwrap_or((0, 0));
                let used = if prev_win == window_idx { prev_used } else { 0 };
                let base_ceiling = effective_ceiling_atoms(rec);
                let ceiling = self
                    .flow_controls
                    .get(&domain_id)
                    .filter(|c| c.deposit_window_cap_atoms > 0)
                    .map_or(base_ceiling, |c| {
                        base_ceiling.min(c.deposit_window_cap_atoms)
                    });
                let Some(next_used) = used.checked_add(amount_atoms) else {
                    return Err(EconomicGuardError::CeilingExceeded {
                        domain_id,
                        requested_atoms: amount_atoms,
                        window_used_atoms: used,
                        ceiling_atoms: ceiling,
                    });
                };
                if next_used > ceiling || (amount_atoms == 0 && ceiling == 0) {
                    self.record_window_breach(
                        domain_id,
                        current_height,
                        window_idx,
                        amount_atoms,
                        used,
                        ceiling,
                    );
                    return Err(EconomicGuardError::CeilingExceeded {
                        domain_id,
                        requested_atoms: amount_atoms,
                        window_used_atoms: used,
                        ceiling_atoms: ceiling,
                    });
                }
                self.deposit_window_usage
                    .insert(domain_id, (window_idx, next_used));
                Ok(())
            }
        }
    }

    /// Queue a large single withdrawal behind its configured block timelock.
    ///
    /// WIRING: Oversized withdrawal staging door paired with [`Self::claim_queued_withdrawal`].
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError`] when the domain is unknown (or zero
    /// amount), frozen, or paused.
    pub fn queue_large_withdrawal(
        &mut self,
        domain_id: DomainId,
        recipient: Address,
        amount_atoms: u128,
        current_height: u64,
    ) -> Result<Hash32, EconomicGuardError> {
        if amount_atoms == 0 {
            return Err(EconomicGuardError::InvalidPolicy(
                "queued withdrawal amount must be positive".into(),
            ));
        }
        if !self.domains.contains_key(&domain_id) {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        }
        self.ensure_domain_not_frozen(domain_id)?;
        self.ensure_not_paused(domain_id)?;
        let delay =
            self.flow_controls
                .get(&domain_id)
                .map_or(DEFAULT_LARGE_WITHDRAW_DELAY_BLOCKS, |c| {
                    if c.large_withdraw_delay_blocks == 0 {
                        DEFAULT_LARGE_WITHDRAW_DELAY_BLOCKS
                    } else {
                        c.large_withdraw_delay_blocks
                    }
                });
        let nonce = self.next_withdrawal_nonce;
        self.next_withdrawal_nonce = self.next_withdrawal_nonce.saturating_add(1);
        let withdrawal_id = hash_fields_bytes(&[
            b"BDLM_ECON_GUARD_TIMELOCK_WD_V1",
            &domain_id.to_le_bytes(),
            recipient.as_bytes(),
            &amount_atoms.to_le_bytes(),
            &current_height.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]);
        let queued = QueuedBridgeWithdrawal {
            withdrawal_id,
            domain_id,
            recipient,
            amount_atoms,
            queued_at_height: current_height,
            ready_at_height: current_height.saturating_add(delay),
        };
        self.queued_withdrawals.insert(withdrawal_id, queued);
        Ok(withdrawal_id)
    }

    /// Claim a timelocked withdrawal once `current_height >= ready_at_height`
    /// and the domain remains neither frozen nor paused and has available
    /// rolling-window ceiling.
    ///
    /// WIRING: Timelock release path enforcing [`Self::check_and_record_flow`] at claim height.
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError`] if the ID is unknown, timelock has not
    /// elapsed, or the domain is frozen, paused, or over ceiling.
    pub fn claim_queued_withdrawal(
        &mut self,
        withdrawal_id: Hash32,
        current_height: u64,
    ) -> Result<QueuedBridgeWithdrawal, EconomicGuardError> {
        let entry = self
            .queued_withdrawals
            .get(&withdrawal_id)
            .cloned()
            .ok_or(EconomicGuardError::UnknownQueuedWithdrawal(withdrawal_id))?;
        if current_height < entry.ready_at_height {
            return Err(EconomicGuardError::WithdrawalTimelockActive {
                withdrawal_id,
                ready_at_height: entry.ready_at_height,
                current_height,
            });
        }
        self.check_and_record_flow_inner(
            entry.domain_id,
            entry.amount_atoms,
            current_height,
            true,
        )?;
        self.queued_withdrawals.remove(&withdrawal_id);
        Ok(entry)
    }

    /// Deterministically prune replay-ledger entries from epochs older than
    /// `current_epoch - GUARD_REPLAY_RETENTION_EPOCHS`, advancing the monotonic
    /// replay horizon so pruned evidence can never be replayed and a table-fill
    /// attack in an earlier epoch cannot block fresh contradiction proofs.
    ///
    /// WIRING: invoked automatically by [`BridgeEconomicGuard::submit_contradiction`].
    pub fn prune_expired_replay_entries(&mut self, current_height: u64) -> usize {
        let current_epoch = current_height / GUARD_REPLAY_EPOCH_BLOCKS;
        let cutoff = current_epoch.saturating_sub(GUARD_REPLAY_RETENTION_EPOCHS);
        if cutoff <= self.replay_pruned_before_epoch {
            return 0;
        }
        self.replay_pruned_before_epoch = cutoff;
        let expired_evidence: Vec<Hash32> = self
            .consumed_evidence
            .iter()
            .copied()
            .filter(|digest| {
                self.consumed_evidence_epochs
                    .get(digest)
                    .copied()
                    .unwrap_or(0)
                    < cutoff
            })
            .collect();
        let mut removed = 0usize;
        for digest in expired_evidence {
            if self.consumed_evidence.remove(&digest) {
                removed = removed.saturating_add(1);
            }
            self.consumed_evidence_epochs.remove(&digest);
        }
        let expired_offenders: Vec<Hash32> = self
            .slashed_offenders
            .iter()
            .copied()
            .filter(|key| self.slashed_offender_epochs.get(key).copied().unwrap_or(0) < cutoff)
            .collect();
        for key in expired_offenders {
            if self.slashed_offenders.remove(&key) {
                removed = removed.saturating_add(1);
            }
            self.slashed_offender_epochs.remove(&key);
        }
        removed
    }

    /// Return the earliest replay epoch still accepted by this guard.
    ///
    /// WIRING: inspected alongside [`BridgeEconomicGuard::submit_contradiction`] epoch-horizon enforcement.
    #[must_use]
    pub const fn replay_pruned_before_epoch(&self) -> u64 {
        self.replay_pruned_before_epoch
    }

    /// Verify permissionless contradiction evidence, freeze `domain_id` without
    /// any admin key, and slash its attached [`ProverBond`].
    ///
    /// # Errors
    ///
    /// Returns [`EconomicGuardError`] when the domain is unknown, the evidence
    /// was already replayed, or cryptographic verification fails.
    pub fn submit_contradiction(
        &mut self,
        domain_id: DomainId,
        evidence: &ContradictionEvidence,
        challenger: Address,
        at_height: u64,
    ) -> Result<ContradictionOutcome, EconomicGuardError> {
        let Some(rec) = self.domains.get(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        let (evidence_digest, external_slashed_weight, new_offender_keys) = match evidence {
            ContradictionEvidence::SignedProverDoubleRoot {
                domain_height,
                state_root_a,
                ed25519_sig_a,
                pq_sig_a,
                state_root_b,
                ed25519_sig_b,
                pq_sig_b,
            } => {
                let Some(ed_pk) = rec.policy.prover_ed25519_pubkey else {
                    return Err(EconomicGuardError::InvalidEvidence(
                        "domain has no configured prover_ed25519_pubkey".into(),
                    ));
                };
                if bool::from(state_root_a.ct_eq(&[0u8; 32]))
                    || bool::from(state_root_b.ct_eq(&[0u8; 32]))
                    || bool::from(state_root_a.ct_eq(state_root_b))
                {
                    return Err(EconomicGuardError::InvalidEvidence(
                        "double-root proof requires two distinct non-zero state roots".into(),
                    ));
                }
                let stmt_a = contradiction_statement_bytes(domain_id, *domain_height, state_root_a);
                let stmt_b = contradiction_statement_bytes(domain_id, *domain_height, state_root_b);
                verify_signature(&stmt_a, ed25519_sig_a, &ed_pk).map_err(|e| {
                    EconomicGuardError::InvalidEvidence(format!(
                        "prover statement A Ed25519 signature invalid: {e}"
                    ))
                })?;
                verify_signature(&stmt_b, ed25519_sig_b, &ed_pk).map_err(|e| {
                    EconomicGuardError::InvalidEvidence(format!(
                        "prover statement B Ed25519 signature invalid: {e}"
                    ))
                })?;
                let pq_pk = &rec.policy.prover_pq_pubkey;
                if pq_pk.is_empty() {
                    if !pq_sig_a.is_empty() || !pq_sig_b.is_empty() {
                        return Err(EconomicGuardError::InvalidEvidence(
                            "unexpected prover ML-DSA-65 signature without configured PQ key"
                                .into(),
                        ));
                    }
                } else {
                    if pq_sig_a.is_empty() || pq_sig_b.is_empty() {
                        return Err(EconomicGuardError::InvalidEvidence(
                            "prover contradiction missing mandatory ML-DSA-65 co-signature".into(),
                        ));
                    }
                    pq::verify(
                        SchemeId::ML_DSA_65,
                        pq_pk,
                        &stmt_a,
                        crate::crypto::ctx::CROSS_DOMAIN_V1,
                        pq_sig_a,
                    )
                    .map_err(|e| {
                        EconomicGuardError::InvalidEvidence(format!(
                            "prover statement A ML-DSA-65 signature invalid: {e}"
                        ))
                    })?;
                    pq::verify(
                        SchemeId::ML_DSA_65,
                        pq_pk,
                        &stmt_b,
                        crate::crypto::ctx::CROSS_DOMAIN_V1,
                        pq_sig_b,
                    )
                    .map_err(|e| {
                        EconomicGuardError::InvalidEvidence(format!(
                            "prover statement B ML-DSA-65 signature invalid: {e}"
                        ))
                    })?;
                }
                let (low_root, high_root) = if state_root_a <= state_root_b {
                    (state_root_a, state_root_b)
                } else {
                    (state_root_b, state_root_a)
                };
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &domain_id.to_le_bytes(),
                    &domain_height.to_le_bytes(),
                    &ed_pk,
                    low_root,
                    high_root,
                ]);
                let scheme = hybrid_or_ed25519_scheme(!pq_pk.is_empty());
                let offender_key =
                    offender_replay_key(domain_id, 0, &domain_height.to_le_bytes(), scheme, &ed_pk);
                if self.slashed_offenders.contains(&offender_key) {
                    return Err(EconomicGuardError::DuplicateEvidence(digest));
                }
                (digest, 0u128, vec![offender_key])
            }
            ContradictionEvidence::RestakingFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::RestakingAvs {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_restaking_slashing(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[1u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let (incremental, keys) = match proof.as_ref() {
                    RestakingSlashingProof::RestakedEquivocation { epoch, height, .. } => {
                        let locus = hash_fields_bytes(&[
                            b"BDLM_ECON_GUARD_OFFENDER_V1",
                            &[1u8],
                            &epoch.to_le_bytes(),
                            &height.to_le_bytes(),
                        ]);
                        compute_incremental_slash(
                            &self.slashed_offenders,
                            domain_id,
                            1,
                            &locus,
                            &res.offenders,
                            digest,
                            |pk| pinned.restaked_member_info(pk),
                        )?
                    }
                    RestakingSlashingProof::EotsDoubleSign { epoch, height, .. } => {
                        let locus = hash_fields_bytes(&[
                            b"BDLM_ECON_GUARD_OFFENDER_V1",
                            &[2u8],
                            &epoch.to_le_bytes(),
                            &height.to_le_bytes(),
                        ]);
                        compute_incremental_slash(
                            &self.slashed_offenders,
                            domain_id,
                            1,
                            &locus,
                            &res.offenders,
                            digest,
                            |pk| pinned.eots_member_info(pk),
                        )?
                    }
                };
                (digest, incremental, keys)
            }
            ContradictionEvidence::AuxPowPopFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::AuxPowPop {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_pop_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[2u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let locus = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_OFFENDER_V1",
                    &proof.aux_chain_id.to_le_bytes(),
                    &proof.aux_height.to_le_bytes(),
                ]);
                let (incremental, keys) = compute_incremental_slash(
                    &self.slashed_offenders,
                    domain_id,
                    2,
                    &locus,
                    &res.offenders,
                    digest,
                    |pk| pinned.pop_member_info(pk),
                )?;
                (digest, incremental, keys)
            }
            ContradictionEvidence::SimplexFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::SimplexBft {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_simplex_slashing(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[3u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let locus = match proof.as_ref() {
                    SimplexSlashingProof::DoubleNotarize {
                        epoch,
                        view,
                        height,
                        ..
                    } => hash_fields_bytes(&[
                        b"BDLM_ECON_GUARD_OFFENDER_V1",
                        &[1u8],
                        &epoch.to_le_bytes(),
                        &view.to_le_bytes(),
                        &height.to_le_bytes(),
                    ]),
                    SimplexSlashingProof::FinalizeAndSkip { epoch, view, .. } => {
                        hash_fields_bytes(&[
                            b"BDLM_ECON_GUARD_OFFENDER_V1",
                            &[2u8],
                            &epoch.to_le_bytes(),
                            &view.to_le_bytes(),
                        ])
                    }
                };
                let (incremental, keys) = compute_incremental_slash(
                    &self.slashed_offenders,
                    domain_id,
                    3,
                    &locus,
                    &res.offenders,
                    digest,
                    |pk| pinned.validator_member_info(pk),
                )?;
                (digest, incremental, keys)
            }
            ContradictionEvidence::AlgorandFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::AlgorandStateProof {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let slashed_weight = verify_algorand_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                // Sort the conflicting message digests canonically so swapping
                // (message_a, message_b) collapses to the same digest, while
                // binding voter position and ML-DSA-65 key commitment so two
                // distinct Byzantine voters on the same pair slash independently.
                let digest_a = proof.message_a.digest();
                let digest_b = proof.message_b.digest();
                let (lo_digest, hi_digest) = if digest_a <= digest_b {
                    (&digest_a, &digest_b)
                } else {
                    (&digest_b, &digest_a)
                };
                let pk_commit = algorand_pubkey_commitment(&proof.reveal_a.mldsa65_pubkey);
                let pos_le = proof.reveal_a.position.to_le_bytes();
                let ivl_le = pinned.interval_index.to_le_bytes();
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[4u8],
                    &domain_id.to_le_bytes(),
                    &ivl_le,
                    &pos_le,
                    &pk_commit,
                    lo_digest,
                    hi_digest,
                ]);
                let locus = hash_fields_bytes(&[b"BDLM_ECON_GUARD_OFFENDER_V1", &ivl_le, &pos_le]);
                let offender_key =
                    offender_replay_key(domain_id, 4, &locus, SchemeId::ML_DSA_65, &pk_commit);
                if self.slashed_offenders.contains(&offender_key) {
                    return Err(EconomicGuardError::DuplicateEvidence(digest));
                }
                (digest, slashed_weight, vec![offender_key])
            }
            ContradictionEvidence::BasedPreconfFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::BasedPreconf {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_based_preconf_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[5u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let locus = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_OFFENDER_V1",
                    &pinned.l1_chain_id.to_le_bytes(),
                    &proof.epoch.to_le_bytes(),
                    &proof.l1_slot.to_le_bytes(),
                    &proof.l2_sequence.to_le_bytes(),
                ]);
                let (incremental, keys) = compute_incremental_slash(
                    &self.slashed_offenders,
                    domain_id,
                    5,
                    &locus,
                    &res.offenders,
                    digest,
                    |pk| pinned.member_info(pk),
                )?;
                (digest, incremental, keys)
            }
            ContradictionEvidence::TonCatchainFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::TonCatchain {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_ton_catchain_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[6u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let locus = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_OFFENDER_V1",
                    &proof.key_block_seqno.to_le_bytes(),
                    &proof.catchain_seqno.to_le_bytes(),
                    &proof.mc_seqno.to_le_bytes(),
                ]);
                let (incremental, keys) = compute_incremental_slash(
                    &self.slashed_offenders,
                    domain_id,
                    6,
                    &locus,
                    &res.offenders,
                    digest,
                    |pk| pinned.validator_member_info(pk),
                )?;
                (digest, incremental, keys)
            }
            ContradictionEvidence::StellarFbaFault {
                network,
                pinned,
                proof,
            } => {
                let supplied = GuardedExternalAdapter::StellarScp {
                    network: network.clone(),
                    pinned: pinned.clone(),
                };
                verify_domain_adapter_pin(
                    domain_id,
                    rec.policy.pinned_adapter.as_ref(),
                    &supplied,
                )?;
                let res = verify_stellar_ballot_equivocation(network, pinned, proof)
                    .map_err(|e| EconomicGuardError::InvalidEvidence(e.to_string()))?;
                let digest = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_EVIDENCE_V1",
                    &[7u8],
                    &domain_id.to_le_bytes(),
                    &res.evidence_digest,
                ]);
                let locus = hash_fields_bytes(&[
                    b"BDLM_ECON_GUARD_OFFENDER_V1",
                    &proof.slot_index.to_le_bytes(),
                ]);
                let (incremental, keys) = compute_incremental_slash(
                    &self.slashed_offenders,
                    domain_id,
                    7,
                    &locus,
                    &res.offenders,
                    digest,
                    |pk| pinned.node_member_info(pk),
                )?;
                (digest, incremental, keys)
            }
        };

        let current_epoch = at_height / GUARD_REPLAY_EPOCH_BLOCKS;
        if current_epoch < self.replay_pruned_before_epoch {
            return Err(EconomicGuardError::InvalidEvidence(
                "contradiction evidence epoch predates pruned replay horizon".into(),
            ));
        }
        let _ = self.prune_expired_replay_entries(at_height);
        if self.consumed_evidence.contains(&evidence_digest) {
            return Err(EconomicGuardError::DuplicateEvidence(evidence_digest));
        }
        if self.consumed_evidence.len().saturating_add(1) > MAX_GUARD_REPLAY_ENTRIES
            || self
                .slashed_offenders
                .len()
                .saturating_add(new_offender_keys.len())
                > MAX_GUARD_REPLAY_ENTRIES
        {
            return Err(EconomicGuardError::ReplayLedgerFull {
                capacity: MAX_GUARD_REPLAY_ENTRIES,
            });
        }
        self.consumed_evidence.insert(evidence_digest);
        self.consumed_evidence_epochs
            .insert(evidence_digest, current_epoch);
        for key in new_offender_keys {
            self.slashed_offenders.insert(key);
            self.slashed_offender_epochs.insert(key, current_epoch);
        }

        let Some(rec_mut) = self.domains.get_mut(&domain_id) else {
            return Err(EconomicGuardError::UnknownDomain(domain_id));
        };
        if matches!(rec_mut.status, DomainGuardStatus::Active) {
            rec_mut.status = DomainGuardStatus::FrozenByContradiction {
                frozen_at_height: at_height,
                evidence_digest,
            };
        }
        let finder_bps = rec_mut.policy.finder_reward_bps;
        let (slashed_prover, slashed_bond_atoms, challenger_reward_atoms, burned_bond_atoms) =
            match rec_mut.prover_bond.as_mut() {
                None => (None, 0u128, 0u128, 0u128),
                Some(bond) => {
                    let live = bond.live_atoms();
                    if live == 0 {
                        (None, 0u128, 0u128, 0u128)
                    } else {
                        let prover = bond.prover;
                        // A prover reporting its own contradiction still
                        // freezes the domain and loses the bond, but it can
                        // never route the finder reward back to itself.
                        let reward_bps = if challenger == prover { 0 } else { finder_bps };
                        let paid = mul_bps_floor(live, reward_bps).min(live);
                        bond.bond_atoms = bond.bond_atoms.saturating_sub(live);
                        bond.slashed_atoms = bond.slashed_atoms.saturating_add(live);
                        bond.slashings.push(Slashing {
                            at_height,
                            evidence_digest,
                            amount_atoms: live,
                            challenger,
                            challenge_reward_atoms: paid,
                        });
                        (Some(prover), live, paid, live.saturating_sub(paid))
                    }
                }
            };

        Ok(ContradictionOutcome {
            domain_id,
            evidence_digest,
            slashed_prover,
            slashed_bond_atoms,
            challenger_reward_atoms,
            burned_bond_atoms,
            external_slashed_weight,
        })
    }

    /// Canonical length-prefixed commitment over all guarded domain policies,
    /// rolling-window counters, freeze states, prover bonds, and consumed
    /// contradiction evidence digests.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut domain_leaves = Vec::with_capacity(self.domains.len());
        for (domain_id, rec) in &self.domains {
            let backing_hash = hash_security_backing(&rec.policy.backing);
            let (status_tag, frozen_h, frozen_ev) = match rec.status {
                DomainGuardStatus::Active => (0u8, 0u64, [0u8; 32]),
                DomainGuardStatus::FrozenByContradiction {
                    frozen_at_height,
                    evidence_digest,
                } => (1u8, frozen_at_height, evidence_digest),
            };
            let (has_ed, ed_pk) = rec
                .policy
                .prover_ed25519_pubkey
                .map_or((0u8, [0u8; 32]), |pk| (1u8, pk));
            let (has_bond, bond_hash) = rec
                .prover_bond
                .as_ref()
                .map_or((0u8, [0u8; 32]), |b| (1u8, hash_prover_bond(b)));
            let (has_pin, pin_hash) = rec
                .policy
                .pinned_adapter
                .as_ref()
                .map_or((0u8, [0u8; 32]), |pin| (1u8, pin.canonical_pin_digest()));
            domain_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_DOMAIN_V1",
                &domain_id.to_le_bytes(),
                &backing_hash,
                &rec.policy.shared_consumer_count.to_le_bytes(),
                &rec.policy.stake_haircut_bps.to_le_bytes(),
                &rec.policy.bond_haircut_bps.to_le_bytes(),
                &rec.policy.finder_reward_bps.to_le_bytes(),
                &rec.policy.work_window_cap_atoms.to_le_bytes(),
                &rec.policy.min_work_difficulty_bits.to_le_bytes(),
                &rec.policy.zk_window_cap_atoms.to_le_bytes(),
                &rec.policy.window_blocks.to_le_bytes(),
                &[has_ed],
                &ed_pk,
                &rec.policy.prover_pq_pubkey,
                &[has_pin],
                &pin_hash,
                &[status_tag],
                &frozen_h.to_le_bytes(),
                &frozen_ev,
                &rec.active_window.to_le_bytes(),
                &rec.window_used_atoms.to_le_bytes(),
                &[has_bond],
                &bond_hash,
            ]));
        }
        let strict_flag = [u8::from(self.require_configured_domains)];
        let dom_count_le = u64::try_from(domain_leaves.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let ev_count_le = u64::try_from(self.consumed_evidence.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let off_count_le = u64::try_from(self.slashed_offenders.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let mut fields: Vec<&[u8]> = Vec::with_capacity(
            domain_leaves
                .len()
                .saturating_add(self.consumed_evidence.len())
                .saturating_add(self.slashed_offenders.len())
                .saturating_add(5),
        );
        fields.push(b"BDLM_ECON_GUARD_ROOT_V1");
        fields.push(&strict_flag);
        fields.push(&dom_count_le);
        for leaf in &domain_leaves {
            fields.push(leaf);
        }
        fields.push(&ev_count_le);
        for ev in &self.consumed_evidence {
            fields.push(ev);
        }
        fields.push(&off_count_le);
        for offender in &self.slashed_offenders {
            fields.push(offender);
        }
        let pruned_epoch_le = self.replay_pruned_before_epoch.to_le_bytes();
        if self.replay_pruned_before_epoch > 0 {
            fields.push(&pruned_epoch_le);
        }
        let mut extra_control_leaves: Vec<Hash32> = Vec::new();
        for (domain_id, ctrl) in &self.flow_controls {
            extra_control_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_CTRL_V1",
                &domain_id.to_le_bytes(),
                &ctrl.deposit_window_cap_atoms.to_le_bytes(),
                &ctrl.max_single_tx_withdraw_atoms.to_le_bytes(),
                &ctrl.large_withdraw_delay_blocks.to_le_bytes(),
                &ctrl.auto_pause_reorg_depth_threshold.to_le_bytes(),
                &ctrl.circuit_pause_duration_blocks.to_le_bytes(),
            ]));
        }
        for (domain_id, pause) in &self.domain_pauses {
            let scope_byte = match pause.scope {
                GuardianPauseScope::FullBridgeFreeze => 0u8,
                GuardianPauseScope::DepositsAndFastExitsOnly => 1u8,
            };
            extra_control_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_PAUSE_V1",
                &domain_id.to_le_bytes(),
                &pause.paused_at_height.to_le_bytes(),
                &pause.pause_expires_at_height.to_le_bytes(),
                &pause.reorg_depth.to_le_bytes(),
                &[scope_byte],
            ]));
        }
        for (domain_id, until_height) in &self.reorg_pause_cooldown_until {
            extra_control_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_PAUSE_COOLDOWN_V1",
                &domain_id.to_le_bytes(),
                &until_height.to_le_bytes(),
            ]));
        }
        for (domain_id, (win_idx, used)) in &self.deposit_window_usage {
            extra_control_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_DEPOSIT_V1",
                &domain_id.to_le_bytes(),
                &win_idx.to_le_bytes(),
                &used.to_le_bytes(),
            ]));
        }
        for (wd_id, wd) in &self.queued_withdrawals {
            extra_control_leaves.push(hash_fields_bytes(&[
                b"BDLM_ECON_GUARD_QUEUE_WD_V1",
                wd_id,
                &wd.domain_id.to_le_bytes(),
                wd.recipient.as_bytes(),
                &wd.amount_atoms.to_le_bytes(),
                &wd.queued_at_height.to_le_bytes(),
                &wd.ready_at_height.to_le_bytes(),
            ]));
        }
        for leaf in &extra_control_leaves {
            fields.push(leaf);
        }
        let nonce_le = self.next_withdrawal_nonce.to_le_bytes();
        if self.next_withdrawal_nonce > 0 {
            fields.push(&nonce_le);
        }
        hash_fields_bytes(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::restaking_avs::{
        restake_vote_sign_bytes, AvsQuorumMember, AvsSignature, RestakedOperator,
    };
    use crate::crypto::facts::ObservedScheme;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};
    use crate::crypto::scheme::SchemeId;

    fn make_bond(prover: Address, bond_atoms: u128) -> ProverBond {
        ProverBond {
            prover,
            bond_atoms,
            ceiling_atoms: bond_atoms.saturating_mul(10),
            slashed_atoms: 0,
            slashings: Vec::new(),
            accepted: 0,
            refused: 0,
        }
    }

    #[test]
    fn adaptive_ceiling_enforces_zero_on_none_and_unslashable_and_applies_overleverage_haircut() {
        let mut guard = BridgeEconomicGuard::new();

        // 1. SecurityBacking::None -> strictly 0 atoms even for a 1-atom flow.
        guard
            .configure_domain(10, DomainCeilingPolicy::default(), None)
            .expect("valid default policy");
        let err = guard
            .check_and_record_flow(10, 1, 100)
            .expect_err("SecurityBacking::None must never permit non-zero bridge flow");
        assert!(matches!(
            err,
            EconomicGuardError::CeilingExceeded {
                ceiling_atoms: 0,
                ..
            }
        ));

        // 2. Unslashable SignatureSet (Altair-like) without prover bond -> 0; with 10_000 bond -> 9_000.
        let unslashable = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers: 500,
                required: 342,
                total_weight: 1_000_000_000,
                slashable: false,
            },
            ..DomainCeilingPolicy::default()
        };
        guard
            .configure_domain(11, unslashable.clone(), None)
            .unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(11).unwrap()), 0);

        let bond = make_bond(Address::from([0xB1; 32]), 10_000);
        guard.configure_domain(11, unslashable, Some(bond)).unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(11).unwrap()), 9_000);

        // 3. Slashable SignatureSet: total_weight=90_000, shared across 3 AVSs -> 30_000,
        //    * 3_333 / 10_000 = 9_999 atoms per window; rolls cleanly on next window.
        let slashable = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 90_000,
                slashable: true,
            },
            shared_consumer_count: 3,
            stake_haircut_bps: 3_333,
            window_blocks: 100,
            ..DomainCeilingPolicy::default()
        };
        // Bondless, the set earns nothing: its weight is not in atoms.
        guard.configure_domain(12, slashable.clone(), None).unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(12).unwrap()), 0);
        // With a bond whose haircut (20_000 * 90% = 18_000) clears the stake
        // cap, the stake cap is the window: 9_999.
        guard
            .configure_domain(
                12,
                slashable,
                Some(make_bond(Address::from([0xB2; 32]), 20_000)),
            )
            .unwrap();
        assert_eq!(effective_ceiling_atoms(guard.record(12).unwrap()), 9_999);

        guard.check_and_record_flow(12, 6_000, 10).unwrap();
        let root_after_first = guard.root();
        let over = guard
            .check_and_record_flow(12, 4_000, 50)
            .expect_err("6000 + 4000 > 9999 must fail closed before mutation");
        assert!(matches!(over, EconomicGuardError::CeilingExceeded { .. }));
        assert_eq!(guard.root(), root_after_first, "refusal must not mutate");
        guard.check_and_record_flow(12, 3_999, 99).unwrap();
        // Next height window [100, 200) resets usage deterministically.
        guard.check_and_record_flow(12, 9_999, 100).unwrap();
    }

    #[test]
    fn signed_prover_contradiction_freezes_domain_slashes_bond_and_refuses_replay_or_forgery() {
        let prover_ed = KeyPair::from_seed(&[0x71; 32]).unwrap();
        let prover_pq = PqKeyPair::generate();
        let prover_addr = Address::from([0x71; 32]);
        let challenger = Address::from([0xC1; 32]);

        let mut guard = BridgeEconomicGuard::new();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 1_000_000,
                slashable: true,
            },
            finder_reward_bps: 1_000, // 10%
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        guard
            .configure_domain(21, policy, Some(make_bond(prover_addr, 50_000)))
            .unwrap();

        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let stmt_a = contradiction_statement_bytes(21, 777, &root_a);
        let stmt_b = contradiction_statement_bytes(21, 777, &root_b);

        // Stripped PQ co-signature forgery must be refused without freezing or slashing.
        let root_before = guard.root();
        let sig_ed_a = prover_ed.sign(&stmt_a).to_vec();
        let sig_pq_a = prover_pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_a)
            .unwrap();
        let sig_ed_b = prover_ed.sign(&stmt_b).to_vec();
        let stripped = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 777,
            state_root_a: root_a,
            ed25519_sig_a: sig_ed_a.clone(),
            pq_sig_a: sig_pq_a.clone(),
            state_root_b: root_b,
            ed25519_sig_b: sig_ed_b.clone(),
            pq_sig_b: Vec::new(),
        };
        assert!(guard
            .submit_contradiction(21, &stripped, challenger, 800)
            .is_err());
        assert_eq!(guard.root(), root_before);

        // Genuine hybrid double-root freezes domain and slashes full 50_000 bond (5_000 finder, 45_000 burned).
        let valid = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 777,
            state_root_a: root_a,
            ed25519_sig_a: sig_ed_a,
            pq_sig_a: sig_pq_a,
            state_root_b: root_b,
            ed25519_sig_b: sig_ed_b,
            pq_sig_b: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_b)
                .unwrap(),
        };
        let outcome = guard
            .submit_contradiction(21, &valid, challenger, 800)
            .expect("valid double-root contradiction slashes and freezes");
        assert_eq!(outcome.slashed_bond_atoms, 50_000);
        assert_eq!(outcome.challenger_reward_atoms, 5_000);
        assert_eq!(outcome.burned_bond_atoms, 45_000);
        assert_ne!(guard.root(), root_before);

        // Replay of the same contradiction evidence is refused.
        let rep = guard
            .submit_contradiction(21, &valid, challenger, 801)
            .expect_err("replayed contradiction evidence must be refused");
        assert!(matches!(rep, EconomicGuardError::DuplicateEvidence(_)));

        // Frozen domain refuses every bridge flow AND survives policy reconfiguration.
        let frozen = guard
            .check_and_record_flow(21, 1, 802)
            .expect_err("frozen domain must refuse all flows");
        assert!(matches!(frozen, EconomicGuardError::DomainFrozen { .. }));
    }

    #[test]
    fn a_self_challenging_prover_burns_its_whole_bond_and_an_oversized_finder_share_is_refused() {
        let prover_ed = KeyPair::from_seed(&[0x72; 32]).unwrap();
        let prover_pq = PqKeyPair::generate();
        let prover_addr = Address::from([0x72; 32]);
        let backing = SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 4,
            required: 3,
            total_weight: 1_000_000,
            slashable: true,
        };

        // The finder reward is carved from the slashed bond, so a share above
        // the protocol ceiling would let the slashed prover reclaim it: the
        // policy is refused before it ever guards a domain.
        let mut guard = BridgeEconomicGuard::new();
        let oversized = DomainCeilingPolicy {
            backing,
            finder_reward_bps: MAX_FINDER_REWARD_BPS + 1,
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        let err = guard
            .configure_domain(22, oversized, Some(make_bond(prover_addr, 50_000)))
            .expect_err("a finder share above the ceiling is an invalid policy");
        assert!(matches!(err, EconomicGuardError::InvalidPolicy(_)));

        // At the ceiling the policy stands; a prover that reports its own
        // contradiction still freezes the domain and loses the bond, but the
        // finder reward can never flow back to it: everything burns.
        let policy = DomainCeilingPolicy {
            backing,
            finder_reward_bps: MAX_FINDER_REWARD_BPS,
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        guard
            .configure_domain(22, policy, Some(make_bond(prover_addr, 50_000)))
            .unwrap();
        let root_a = [0xA7; 32];
        let root_b = [0xB7; 32];
        let stmt_a = contradiction_statement_bytes(22, 900, &root_a);
        let stmt_b = contradiction_statement_bytes(22, 900, &root_b);
        let valid = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 900,
            state_root_a: root_a,
            ed25519_sig_a: prover_ed.sign(&stmt_a).to_vec(),
            pq_sig_a: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_a)
                .unwrap(),
            state_root_b: root_b,
            ed25519_sig_b: prover_ed.sign(&stmt_b).to_vec(),
            pq_sig_b: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_b)
                .unwrap(),
        };
        let outcome = guard
            .submit_contradiction(22, &valid, prover_addr, 901)
            .expect("the contradiction still lands when the prover reports itself");
        assert_eq!(outcome.slashed_bond_atoms, 50_000);
        assert_eq!(
            outcome.challenger_reward_atoms, 0,
            "a self-challenging prover earns nothing back"
        );
        assert_eq!(outcome.burned_bond_atoms, 50_000);
        let frozen = guard
            .check_and_record_flow(22, 1, 902)
            .expect_err("the self-reported contradiction still freezes the domain");
        assert!(matches!(frozen, EconomicGuardError::DomainFrozen { .. }));
    }

    #[test]
    fn adapter_fault_dispatch_slashes_prover_bond_and_commits_to_root() {
        let op_ed = KeyPair::from_seed(&[0x81; 32]).unwrap();
        let op_pq = PqKeyPair::generate();
        let nat_ed = KeyPair::from_seed(&[0x82; 32]).unwrap();
        let nat_pq = PqKeyPair::generate();
        let pinned = PinnedRestakingAvsSet {
            epoch: 2,
            min_withdrawal_delay: 50,
            max_shared_avs_per_operator: 4,
            min_effective_restaked_stake: 500,
            native_validators: vec![AvsQuorumMember {
                ed25519_pubkey: nat_ed.public_key_bytes(),
                stake_weight: 1_000,
                pq_pubkey: nat_pq.public_key_bytes().to_vec(),
            }],
            restaked_operators: vec![RestakedOperator {
                ed25519_pubkey: op_ed.public_key_bytes(),
                raw_stake: 2_000,
                shared_avs_count: 2,
                pq_pubkey: op_pq.public_key_bytes().to_vec(),
            }],
            eots_providers: vec![],
        };

        let net = "avs-guard-net";
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(
                31,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::RestakingAvs {
                        network: net.into(),
                        pinned: pinned.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x91; 32]), 20_000)),
            )
            .unwrap();

        let ma = restake_vote_sign_bytes(net, 2, 300, 400, &[0x01; 32]);
        let mb = restake_vote_sign_bytes(net, 2, 300, 400, &[0x02; 32]);
        let fault = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned,
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 2,
                height: 300,
                horizon_a: 400,
                batch_digest_a: [0x01; 32],
                sigs_a: vec![AvsSignature {
                    signer_pubkey: op_ed.public_key_bytes(),
                    ed25519_sig: op_ed.sign(&ma).to_vec(),
                    pq_sig: op_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ma)
                        .unwrap(),
                }],
                horizon_b: 400,
                batch_digest_b: [0x02; 32],
                sigs_b: vec![AvsSignature {
                    signer_pubkey: op_ed.public_key_bytes(),
                    ed25519_sig: op_ed.sign(&mb).to_vec(),
                    pq_sig: op_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &mb)
                        .unwrap(),
                }],
            }),
        };
        let out = guard
            .submit_contradiction(31, &fault, Address::from([0xC9; 32]), 310)
            .expect("verified restaking fault freezes domain and slashes prover bond");
        assert_eq!(out.external_slashed_weight, 1_000);
        assert_eq!(out.slashed_bond_atoms, 20_000);
        assert_eq!(out.challenger_reward_atoms, 2_000);
        assert_eq!(
            guard.record(31).unwrap().status,
            DomainGuardStatus::FrozenByContradiction {
                frozen_at_height: 310,
                evidence_digest: out.evidence_digest,
            }
        );
    }

    #[test]
    fn algorand_stateproof_fault_dispatch_slashes_bond_and_refuses_replay_or_forgery() {
        let net = "algorand-guard-net";
        let (pinned, proof, culpable_weight) =
            crate::cross_domain::external::algorand_stateproof::equivocation_support::conflicting_voter_fixture(net);

        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(
                41,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::AlgorandStateProof {
                        network: net.into(),
                        pinned: Box::new(pinned.clone()),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x92; 32]), 20_000)),
            )
            .unwrap();

        let fault = ContradictionEvidence::AlgorandFault {
            network: net.into(),
            pinned: Box::new(pinned.clone()),
            proof: Box::new(proof.clone()),
        };
        let out = guard
            .submit_contradiction(41, &fault, Address::from([0xCA; 32]), 410)
            .expect(
                "a verified Algorand voter equivocation freezes the domain and slashes the bond",
            );
        assert_eq!(out.external_slashed_weight, culpable_weight);
        assert_eq!(out.slashed_bond_atoms, 20_000);
        assert_eq!(out.challenger_reward_atoms, 2_000);
        assert_eq!(
            guard.record(41).unwrap().status,
            DomainGuardStatus::FrozenByContradiction {
                frozen_at_height: 410,
                evidence_digest: out.evidence_digest,
            }
        );

        // The same proof submitted twice is a replay, not a second slashing.
        assert!(matches!(
            guard.submit_contradiction(41, &fault, Address::from([0xCA; 32]), 411),
            Err(EconomicGuardError::DuplicateEvidence(_))
        ));

        // A forged second signature never reaches the ledger.
        let mut forged = proof;
        forged.sig_b = vec![0u8; forged.sig_b.len()];
        assert!(matches!(
            guard.submit_contradiction(
                41,
                &ContradictionEvidence::AlgorandFault {
                    network: net.into(),
                    pinned: Box::new(pinned),
                    proof: Box::new(forged),
                },
                Address::from([0xCA; 32]),
                412
            ),
            Err(EconomicGuardError::InvalidEvidence(_))
        ));
    }

    #[test]
    fn bridge_state_enforces_economic_guard_ceiling_freeze_and_root_commitment() {
        use crate::core::account::AccountState;
        use crate::cross_domain::bridge::{AssetId, BridgeState};
        use crate::cross_domain::bridge_tx::{
            configure_domain_economic_guard, report_bridge_contradiction,
        };

        let mut bridge = BridgeState::new();
        let root_empty = bridge.root();
        let asset_a = AssetId(hash_fields_bytes(&[b"guard-bridge-a"]));
        let asset_b = AssetId(hash_fields_bytes(&[b"guard-bridge-b"]));
        let owner = Address::from([0x11; 32]);
        let recipient = Address::from([0x22; 32]);
        bridge.register_asset(asset_a, 7).unwrap();
        bridge.register_asset(asset_b, 7).unwrap();

        let prover_ed = KeyPair::from_seed(&[0x55; 32]).unwrap();
        let prover_pq = PqKeyPair::generate();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 4,
                required: 3,
                total_weight: 3_000, // 3_000 * 3_333 / 10_000 = 999 atoms/window
                slashable: true,
            },
            prover_ed25519_pubkey: Some(prover_ed.public_key_bytes()),
            prover_pq_pubkey: prover_pq.public_key_bytes().to_vec(),
            ..DomainCeilingPolicy::default()
        };
        let root_pre_guard = bridge.root();
        bridge
            .economic_guard
            .configure_domain(7, policy.clone(), Some(make_bond(owner, 5_000)))
            .unwrap();
        assert_ne!(bridge.root(), root_empty);
        assert_ne!(
            bridge.root(),
            root_pre_guard,
            "BridgeState::root must commit economic_guard state"
        );

        let (_, ev_a) = bridge
            .lock(7, 2, 10, 0, asset_a, owner, recipient, 800, 200)
            .unwrap();
        let (_, ev_b) = bridge
            .lock(7, 2, 11, 1, asset_b, owner, recipient, 300, 200)
            .unwrap();
        bridge
            .mint(&ev_a.message.unwrap(), 15)
            .expect("800 <= 999 ceiling mints cleanly");
        let over = bridge
            .mint(&ev_b.message.unwrap(), 16)
            .expect_err("800 + 300 > 999 ceiling must refuse mint");
        assert!(over.0.contains("ceiling"), "got: {over:?}");

        // Exercise bridge_tx production wiring for escrowed bond locking,
        // contradiction slash, challenger reward, and strict supply conservation.
        let mut state = AccountState::new();
        state.add_balance(&owner, 20_000);
        // A caller cannot pledge someone else's balance into the escrow.
        let stranger = Address::from([0xEE; 32]);
        let foreign = configure_domain_economic_guard(
            &mut state,
            &stranger,
            7,
            policy.clone(),
            Some(make_bond(owner, 12_000)),
        )
        .expect_err("a bond naming another address must be refused");
        assert!(foreign.contains("own balance"), "got: {foreign}");
        assert_eq!(
            state.get_balance(&owner),
            20_000,
            "refusal must not move funds"
        );
        configure_domain_economic_guard(
            &mut state,
            &owner,
            7,
            policy.clone(),
            Some(make_bond(owner, 12_000)),
        )
        .unwrap();
        assert_eq!(state.get_balance(&owner), 8_000);
        // Only the recorded owner may displace or release the live bond.
        let evict = configure_domain_economic_guard(
            &mut state,
            &stranger,
            7,
            policy,
            Some(make_bond(stranger, 1)),
        )
        .expect_err("a stranger must not evict the recorded bond");
        assert!(evict.contains("recorded bond owner"), "got: {evict}");
        let sa = contradiction_statement_bytes(7, 42, &[0xA1; 32]);
        let sb = contradiction_statement_bytes(7, 42, &[0xB2; 32]);
        let ev = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 42,
            state_root_a: [0xA1; 32],
            ed25519_sig_a: prover_ed.sign(&sa).to_vec(),
            pq_sig_a: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sa)
                .unwrap(),
            state_root_b: [0xB2; 32],
            ed25519_sig_b: prover_ed.sign(&sb).to_vec(),
            pq_sig_b: prover_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sb)
                .unwrap(),
        };
        let challenger = Address::from([0xCC; 32]);
        let out = report_bridge_contradiction(&mut state, 7, &ev, challenger, 50).unwrap();
        assert_eq!(out.slashed_bond_atoms, 12_000);
        assert_eq!(out.challenger_reward_atoms, 1_200);
        assert_eq!(state.get_balance(&challenger), 1_200);
    }

    #[test]
    fn adapter_pin_mismatch_blocks_synthetic_committee_griefing_and_backing_inflation() {
        let honest_ed = KeyPair::from_seed(&[0x51; 32]).unwrap();
        let honest_pq = PqKeyPair::generate();
        let attacker_ed = KeyPair::from_seed(&[0x52; 32]).unwrap();
        let attacker_pq = PqKeyPair::generate();
        let honest_pinned = PinnedRestakingAvsSet {
            epoch: 5,
            min_withdrawal_delay: 50,
            max_shared_avs_per_operator: 4,
            min_effective_restaked_stake: 500,
            native_validators: vec![AvsQuorumMember {
                ed25519_pubkey: honest_ed.public_key_bytes(),
                stake_weight: 1_000,
                pq_pubkey: honest_pq.public_key_bytes().to_vec(),
            }],
            restaked_operators: vec![RestakedOperator {
                ed25519_pubkey: honest_ed.public_key_bytes(),
                raw_stake: 2_000,
                shared_avs_count: 2,
                pq_pubkey: honest_pq.public_key_bytes().to_vec(),
            }],
            eots_providers: Vec::new(),
        };
        let mut synthetic_pinned = honest_pinned.clone();
        synthetic_pinned.restaked_operators[0].ed25519_pubkey = attacker_ed.public_key_bytes();
        synthetic_pinned.restaked_operators[0].pq_pubkey = attacker_pq.public_key_bytes().to_vec();

        let net = "pin-guard-net";
        let ma = restake_vote_sign_bytes(net, 5, 100, 200, &[0x11; 32]);
        let mb = restake_vote_sign_bytes(net, 5, 100, 200, &[0x22; 32]);
        let synthetic_fault = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned: synthetic_pinned.clone(),
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 5,
                height: 100,
                horizon_a: 200,
                batch_digest_a: [0x11; 32],
                sigs_a: vec![AvsSignature {
                    signer_pubkey: attacker_ed.public_key_bytes(),
                    ed25519_sig: attacker_ed.sign(&ma).to_vec(),
                    pq_sig: attacker_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ma)
                        .unwrap(),
                }],
                horizon_b: 200,
                batch_digest_b: [0x22; 32],
                sigs_b: vec![AvsSignature {
                    signer_pubkey: attacker_ed.public_key_bytes(),
                    ed25519_sig: attacker_ed.sign(&mb).to_vec(),
                    pq_sig: attacker_pq
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &mb)
                        .unwrap(),
                }],
            }),
        };

        // 1. Unpinned domain refuses external fault and external refresh.
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(
                51,
                DomainCeilingPolicy::default(),
                Some(make_bond(Address::from([0x51; 32]), 50_000)),
            )
            .unwrap();
        assert!(matches!(
            guard.submit_contradiction(51, &synthetic_fault, Address::from([0xAA; 32]), 10),
            Err(EconomicGuardError::AdapterPinMismatch { domain_id: 51, .. })
        ));
        assert_eq!(guard.record(51).unwrap().status, DomainGuardStatus::Active);
        assert_eq!(
            guard
                .record(51)
                .unwrap()
                .prover_bond
                .as_ref()
                .unwrap()
                .live_atoms(),
            50_000
        );

        // 2. Domain pinned to the honest committee rejects both synthetic
        //    contradiction griefing and synthetic backing refresh.
        guard
            .configure_domain(
                51,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::RestakingAvs {
                        network: net.into(),
                        pinned: honest_pinned.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x51; 32]), 50_000)),
            )
            .unwrap();
        assert!(matches!(
            guard.submit_contradiction(51, &synthetic_fault, Address::from([0xAA; 32]), 11),
            Err(EconomicGuardError::AdapterPinMismatch { domain_id: 51, .. })
        ));
        let dummy_raw = RawConsensusEvidence {
            adapter: crate::cross_domain::external::spec::AdapterId::from_name("restaking-avs-v1"),
            evidence_version: 1,
            network: net.into(),
            payload: Vec::new(),
            declared_height: 100,
            declared_root: [0x11; 32],
            submitter: Address::from([0x51; 32]),
        };
        let strict_policy = VerificationPolicy::strict(1_700_000_000);
        assert!(matches!(
            guard.refresh_backing_from_adapter(
                51,
                &GuardedExternalAdapter::RestakingAvs {
                    network: net.into(),
                    pinned: synthetic_pinned,
                },
                &dummy_raw,
                &strict_policy,
            ),
            Err(EconomicGuardError::AdapterPinMismatch { domain_id: 51, .. })
        ));
        // Even with identical committee keys, a mismatched network name is rejected.
        assert!(matches!(
            guard.refresh_backing_from_adapter(
                51,
                &GuardedExternalAdapter::RestakingAvs {
                    network: "wrong-network".into(),
                    pinned: honest_pinned,
                },
                &dummy_raw,
                &strict_policy,
            ),
            Err(EconomicGuardError::AdapterPinMismatch { domain_id: 51, .. })
        ));
        assert_eq!(guard.record(51).unwrap().status, DomainGuardStatus::Active);
        assert_eq!(
            guard
                .record(51)
                .unwrap()
                .prover_bond
                .as_ref()
                .unwrap()
                .live_atoms(),
            50_000
        );
    }

    /// The bond door: a sender posts the bond behind a domain's ceiling policy
    /// from its own balance, only where a policy already stands, only above
    /// zero, and only the recorded owner may displace it. Under a slashable
    /// signature set the bond is what admits stake credit, so the window
    /// opens with the bond and stays shut without it.
    #[test]
    fn the_bond_door_posts_collateral_behind_a_priced_domain_and_refuses_the_rest() {
        use crate::core::account::AccountState;
        use crate::cross_domain::bridge_tx::{execute_bridge_tx, BridgeTx, BridgeTxContext};

        let mut state = AccountState::new();
        state
            .bridge_state
            .economic_guard
            .set_require_configured_domains(true);
        let prover = Address::from([0x71; 32]);
        let other = Address::from([0x72; 32]);
        state.add_balance(&prover, 10_000);
        state.add_balance(&other, 10_000);
        let ctx = |sender: Address| BridgeTxContext {
            sender,
            fee: 1,
            height: 5,
        };
        let post = |atoms: u64| BridgeTx::BondCeilingProver {
            domain_id: 31,
            bond_atoms: atoms,
        };

        // No policy yet: the bond is refused and nothing is escrowed.
        let err = execute_bridge_tx(&mut state, &ctx(prover), &post(2_000)).unwrap_err();
        assert!(
            err.to_string().contains("no bridge ceiling policy"),
            "got {err}"
        );
        assert_eq!(state.spendable_balance(&prover), 10_000);

        // Governance prices the domain: a slashable set whose credit arrives
        // only through the bond.
        state
            .bridge_state
            .economic_guard
            .configure_domain(31, signature_set_policy(3_000, 100), None)
            .expect("valid policy");
        assert_eq!(
            effective_ceiling_atoms(state.bridge_state.economic_guard.record(31).unwrap()),
            0,
            "stake credit without a bond is nothing"
        );

        let zero = execute_bridge_tx(&mut state, &ctx(prover), &post(0)).unwrap_err();
        assert!(zero.to_string().contains("zero bond"), "got {zero}");

        execute_bridge_tx(&mut state, &ctx(prover), &post(2_000)).expect("the bond posts");
        assert_eq!(
            state.spendable_balance(&prover),
            8_000,
            "the bond leaves the sender's spendable balance"
        );
        assert_eq!(
            effective_ceiling_atoms(state.bridge_state.economic_guard.record(31).unwrap()),
            999,
            "with the bond (haircut 1_800) the stake cap 999 is the window"
        );

        // A stranger cannot displace the recorded bond.
        let evict = execute_bridge_tx(&mut state, &ctx(other), &post(5_000)).unwrap_err();
        assert!(
            evict.to_string().contains("recorded bond owner"),
            "got {evict}"
        );
        assert_eq!(state.spendable_balance(&other), 10_000);

        // The owner may raise it; the old escrow comes back first.
        execute_bridge_tx(&mut state, &ctx(prover), &post(3_000)).expect("the owner raises");
        assert_eq!(state.spendable_balance(&prover), 7_000);
        assert_eq!(
            state
                .bridge_state
                .economic_guard
                .record(31)
                .and_then(|r| r.prover_bond.as_ref())
                .map(|b| b.live_atoms()),
            Some(3_000)
        );
    }

    #[test]
    fn strict_production_guard_and_external_roots_fail_closed_on_unconfigured_domains() {
        use crate::core::account::AccountState;
        use crate::cross_domain::bridge::AssetId;
        use crate::cross_domain::bridge_tx::{
            enable_chain_economic_guard_mode, execute_bridge_tx, lock, register_asset, BridgeTx,
            BridgeTxContext, BridgeTxError, LockRequest, ProvenBridgeEvent,
        };
        use crate::cross_domain::event_tree::DomainEventTree;
        use crate::domain::plugin::default_domain;
        use crate::domain::types::{ConsensusKind, DomainCommitment};
        use crate::domain::POW_HEADER_CHAIN_ADAPTER;
        use crate::registry::role::roles::RELAYER;
        use crate::settlement::domains::accept_verified_commitment;

        // 1. Mainnet (45260) and public testnet (45261) fail closed; local devnet stays permissive.
        let mut mainnet_guard = BridgeEconomicGuard::for_chain_id(MAINNET_GUARD_CHAIN_ID);
        let testnet_guard = BridgeEconomicGuard::for_chain_id(TESTNET_GUARD_CHAIN_ID);
        let mut devnet_guard = BridgeEconomicGuard::for_chain_id(45_262);
        assert!(mainnet_guard.requires_configured_domains());
        assert!(testnet_guard.requires_configured_domains());
        assert!(!devnet_guard.requires_configured_domains());
        assert!(!mainnet_guard.is_empty());
        assert_eq!(
            mainnet_guard.check_and_record_flow(99, 1, 1),
            Err(EconomicGuardError::UnknownDomain(99))
        );
        assert_eq!(
            testnet_guard.ensure_domain_not_frozen(99),
            Err(EconomicGuardError::UnknownDomain(99))
        );
        assert!(devnet_guard.check_and_record_flow(99, 1_000, 1).is_ok());

        // 2. Even on a devnet state, an external_roots-anchored foreign domain cannot mint
        //    through bridge execution without an explicit DomainCeilingPolicy.
        let mut state = AccountState::new();
        let owner = Address::from([0x61; 32]);
        let recipient = Address::from([0x62; 32]);
        let carrier = Address::from([0x63; 32]);
        let min_stake = state.registry.params().min_stake;
        state.add_balance(&owner, 500_000);
        state.add_balance(&carrier, min_stake.saturating_add(10_000));
        state
            .registry
            .register(carrier, RELAYER, min_stake, 0)
            .unwrap();
        let d77 = default_domain(77, ConsensusKind::PoW, 45_277, POW_HEADER_CHAIN_ADAPTER, 1);
        let d78 = default_domain(78, ConsensusKind::PoW, 45_278, POW_HEADER_CHAIN_ADAPTER, 1);
        crate::settlement::domains::register_domain(&mut state, d77).unwrap();
        crate::settlement::domains::register_domain(&mut state, d78).unwrap();
        let asset = AssetId::for_domain(77, b"ext-wrapped");
        register_asset(&mut state, asset, 77).unwrap();
        let (_, lock_event) = lock(
            &mut state,
            owner,
            &LockRequest {
                source_domain: 77,
                target_domain: 78,
                source_height: 1,
                event_index: 0,
                asset_id: asset,
                recipient,
                amount: 10_000,
                expiry_height: 500,
            },
            0,
            1,
        )
        .unwrap();
        let mut tree = DomainEventTree::new();
        tree.push(lock_event.clone());
        let proof = tree.proof(0).unwrap();
        let block_hash = [0xD7; 32];
        accept_verified_commitment(
            &mut state,
            DomainCommitment {
                domain_id: 77,
                domain_height: 1,
                domain_block_hash: block_hash,
                parent_domain_block_hash: [0u8; 32],
                state_root: [0x11; 32],
                tx_root: [0u8; 32],
                event_root: tree.root(),
                validator_set_hash: [0u8; 32],
                consensus_kind: ConsensusKind::PoW,
                finality_proof_hash: [0x22; 32],
                timestamp_ms: 1_000,
                sequence: 0,
                producer: None,
                state_updates: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
        // Anchor domain 77 in external_roots without configuring BridgeEconomicGuard.
        state.external_roots.insert(77, [0x77; 32]);
        let proven_lock = ProvenBridgeEvent {
            domain: 77,
            height: 1,
            sequence: 0,
            expected_block_hash: block_hash,
            event: lock_event,
            proof,
        };
        let ctx = BridgeTxContext {
            sender: carrier,
            fee: 0,
            height: 2,
        };
        let err = execute_bridge_tx(&mut state, &ctx, &BridgeTx::Mint(Box::new(proven_lock)))
            .expect_err("anchored external domain without guard policy must fail closed");
        assert!(
            matches!(err, BridgeTxError::Refused(ref msg) if msg.contains("no economic guard record")),
            "unexpected error: {err:?}"
        );
        assert_eq!(state.get_balance(&recipient), 0);

        // Toggle strict mode on state and confirm root commits the flag.
        let r_before = state.bridge_state.economic_guard.root();
        assert!(enable_chain_economic_guard_mode(
            &mut state,
            TESTNET_GUARD_CHAIN_ID
        ));
        assert_ne!(state.bridge_state.economic_guard.root(), r_before);
    }

    #[test]
    fn canonical_swap_subset_superset_algorand_and_cap_invariants_hold() {
        // 1. Restaking: incremental superset credits only the new offender;
        //    swapped (A, B) <-> (B, A) and pure subset replays are rejected.
        let op1_ed = KeyPair::from_seed(&[0x61; 32]).unwrap();
        let op1_pq = PqKeyPair::generate();
        let op2_ed = KeyPair::from_seed(&[0x62; 32]).unwrap();
        let op2_pq = PqKeyPair::generate();
        let pinned = PinnedRestakingAvsSet {
            epoch: 3,
            min_withdrawal_delay: 20,
            max_shared_avs_per_operator: 4,
            min_effective_restaked_stake: 500,
            native_validators: vec![AvsQuorumMember {
                ed25519_pubkey: op1_ed.public_key_bytes(),
                stake_weight: 1_000,
                pq_pubkey: op1_pq.public_key_bytes().to_vec(),
            }],
            restaked_operators: vec![
                RestakedOperator {
                    ed25519_pubkey: op1_ed.public_key_bytes(),
                    raw_stake: 2_000, // haircut -> 1_000
                    shared_avs_count: 2,
                    pq_pubkey: op1_pq.public_key_bytes().to_vec(),
                },
                RestakedOperator {
                    ed25519_pubkey: op2_ed.public_key_bytes(),
                    raw_stake: 3_000, // haircut -> 1_500
                    shared_avs_count: 2,
                    pq_pubkey: op2_pq.public_key_bytes().to_vec(),
                },
            ],
            eots_providers: Vec::new(),
        };
        let net = "dedup-avs-net";
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(
                61,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::RestakingAvs {
                        network: net.into(),
                        pinned: pinned.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x71; 32]), 10_000)),
            )
            .unwrap();

        let sign_op = |ed: &KeyPair, pq: &PqKeyPair, msg: &[u8]| AvsSignature {
            signer_pubkey: ed.public_key_bytes(),
            ed25519_sig: ed.sign(msg).to_vec(),
            pq_sig: pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg).unwrap(),
        };
        let ma = restake_vote_sign_bytes(net, 3, 50, 90, &[0x10; 32]);
        let mb = restake_vote_sign_bytes(net, 3, 50, 90, &[0x20; 32]);

        // Submit op1 alone -> slashes 1_000 external weight and full 10_000 bond once.
        let single_op1 = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned: pinned.clone(),
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 3,
                height: 50,
                horizon_a: 90,
                batch_digest_a: [0x10; 32],
                sigs_a: vec![sign_op(&op1_ed, &op1_pq, &ma)],
                horizon_b: 90,
                batch_digest_b: [0x20; 32],
                sigs_b: vec![sign_op(&op1_ed, &op1_pq, &mb)],
            }),
        };
        let out1 = guard
            .submit_contradiction(61, &single_op1, Address::from([0xC1; 32]), 60)
            .unwrap();
        assert_eq!(out1.external_slashed_weight, 1_000);
        assert_eq!(out1.slashed_bond_atoms, 10_000);

        // Swapping (A, B) <-> (B, A) produces the exact same canonical digest and is rejected.
        let swapped_op1 = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned: pinned.clone(),
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 3,
                height: 50,
                horizon_a: 90,
                batch_digest_a: [0x20; 32],
                sigs_a: vec![sign_op(&op1_ed, &op1_pq, &mb)],
                horizon_b: 90,
                batch_digest_b: [0x10; 32],
                sigs_b: vec![sign_op(&op1_ed, &op1_pq, &ma)],
            }),
        };
        assert_eq!(
            guard.submit_contradiction(61, &swapped_op1, Address::from([0xC1; 32]), 61),
            Err(EconomicGuardError::DuplicateEvidence(out1.evidence_digest))
        );

        // Submitting superset {op1, op2} credits ONLY op2's incremental 1_500 (never re-counting op1).
        let superset = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned: pinned.clone(),
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 3,
                height: 50,
                horizon_a: 90,
                batch_digest_a: [0x10; 32],
                sigs_a: vec![
                    sign_op(&op1_ed, &op1_pq, &ma),
                    sign_op(&op2_ed, &op2_pq, &ma),
                ],
                horizon_b: 90,
                batch_digest_b: [0x20; 32],
                sigs_b: vec![
                    sign_op(&op1_ed, &op1_pq, &mb),
                    sign_op(&op2_ed, &op2_pq, &mb),
                ],
            }),
        };
        let out2 = guard
            .submit_contradiction(61, &superset, Address::from([0xC2; 32]), 62)
            .unwrap();
        assert_eq!(out2.external_slashed_weight, 1_500);
        assert_eq!(out2.slashed_bond_atoms, 0);

        // Pure subset {op2} after {op1, op2} is now rejected as already slashed.
        let subset_op2 = ContradictionEvidence::RestakingFault {
            network: net.into(),
            pinned,
            proof: Box::new(RestakingSlashingProof::RestakedEquivocation {
                epoch: 3,
                height: 50,
                horizon_a: 90,
                batch_digest_a: [0x10; 32],
                sigs_a: vec![sign_op(&op2_ed, &op2_pq, &ma)],
                horizon_b: 90,
                batch_digest_b: [0x20; 32],
                sigs_b: vec![sign_op(&op2_ed, &op2_pq, &mb)],
            }),
        };
        assert!(matches!(
            guard.submit_contradiction(61, &subset_op2, Address::from([0xC2; 32]), 63),
            Err(EconomicGuardError::DuplicateEvidence(_))
        ));

        // 2. Algorand: swapped (message_a, message_b) is rejected for voter 0,
        //    expired forward-secure key is rejected, and distinct voter 1 on the
        //    same conflicting pair is accepted with its own 300 stake weight.
        let algo_net = "dedup-algo-net";
        let (algo_pin, (proof_v0, w0), (proof_v1, w1)) =
            crate::cross_domain::external::algorand_stateproof::equivocation_support::two_conflicting_voters_fixture(algo_net);
        guard
            .configure_domain(
                62,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::AlgorandStateProof {
                        network: algo_net.into(),
                        pinned: Box::new(algo_pin.clone()),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .unwrap();
        let a0 = guard
            .submit_contradiction(
                62,
                &ContradictionEvidence::AlgorandFault {
                    network: algo_net.into(),
                    pinned: Box::new(algo_pin.clone()),
                    proof: Box::new(proof_v0.clone()),
                },
                Address::from([0xC3; 32]),
                70,
            )
            .unwrap();
        assert_eq!(a0.external_slashed_weight, w0);

        // Swap message_a <-> message_b and sig_a <-> sig_b for voter 0 -> rejected!
        let mut swapped_v0 = proof_v0.clone();
        swapped_v0.message_a = proof_v0.message_b.clone();
        swapped_v0.message_b = proof_v0.message_a.clone();
        swapped_v0.reveal_a.mldsa65_sig = proof_v0.sig_b.clone();
        swapped_v0.sig_b = proof_v0.reveal_a.mldsa65_sig.clone();
        assert_eq!(
            guard.submit_contradiction(
                62,
                &ContradictionEvidence::AlgorandFault {
                    network: algo_net.into(),
                    pinned: Box::new(algo_pin.clone()),
                    proof: Box::new(swapped_v0),
                },
                Address::from([0xC3; 32]),
                71,
            ),
            Err(EconomicGuardError::DuplicateEvidence(a0.evidence_digest))
        );

        // Voter 1 on the exact same conflicting (message_a, message_b) succeeds!
        let a1 = guard
            .submit_contradiction(
                62,
                &ContradictionEvidence::AlgorandFault {
                    network: algo_net.into(),
                    pinned: Box::new(algo_pin.clone()),
                    proof: Box::new(proof_v1.clone()),
                },
                Address::from([0xC4; 32]),
                72,
            )
            .unwrap();
        assert_eq!(a1.external_slashed_weight, w1);
        assert_ne!(a1.evidence_digest, a0.evidence_digest);

        // Expired forward-secure key window check: rounds outside key_last_round fail closed.
        let mut expired = proof_v0;
        expired.reveal_a.key_last_round = 10_050; // attested round is 10_100..=10_102
        let exp_err = verify_algorand_equivocation(algo_net, &algo_pin, &expired)
            .expect_err("rounds past forward-secure key_last_round must fail closed");
        assert!(exp_err.to_string().contains("key lifetime"), "{exp_err}");

        // 3. Hard replay cap fails closed without evicting any existing entry.
        let mut capped = BridgeEconomicGuard::new();
        capped
            .configure_domain(
                63,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::AlgorandStateProof {
                        network: algo_net.into(),
                        pinned: Box::new(algo_pin.clone()),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .unwrap();
        for i in 0..MAX_GUARD_REPLAY_ENTRIES {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_le_bytes());
            capped.consumed_evidence.insert(h);
        }
        assert_eq!(
            capped.submit_contradiction(
                63,
                &ContradictionEvidence::AlgorandFault {
                    network: algo_net.into(),
                    pinned: Box::new(algo_pin),
                    proof: Box::new(proof_v1),
                },
                Address::from([0xC5; 32]),
                80,
            ),
            Err(EconomicGuardError::ReplayLedgerFull {
                capacity: MAX_GUARD_REPLAY_ENTRIES,
            })
        );
        assert_eq!(capped.consumed_evidence.len(), MAX_GUARD_REPLAY_ENTRIES);
        assert_eq!(capped.record(63).unwrap().status, DomainGuardStatus::Active);
    }

    #[test]
    fn based_ton_stellar_slashing_and_mina_pin_digest_enforce_hybrid_pq_and_freeze() {
        use crate::cross_domain::external::based_preconf::{
            preconf_cert_sign_bytes, BasedPreconfValidator, BasedSig,
        };
        use crate::cross_domain::external::stellar_fba::{
            compute_network_id_hash, externalize_sign_bytes, ScpExternalizeEnvelope, ScpQuorumSet,
            ScpValidatorNode,
        };
        use crate::cross_domain::external::ton_catchain::{
            catchain_commit_sign_bytes, compute_validator_list_hash, CatchainSig, TonValidator,
        };

        let k_ed = KeyPair::from_seed(&[0x73; 32]).unwrap();
        let k_pq = PqKeyPair::generate();
        let challenger = Address::from([0xD1; 32]);
        let mut guard = BridgeEconomicGuard::production();

        // 1. BasedPreconfFault: mandatory ML-DSA-65 + canonical swap replay refusal.
        let based_pin = PinnedBasedPreconfCommittee {
            epoch: 9,
            l1_chain_id: 1,
            require_focil: true,
            members: vec![BasedPreconfValidator {
                ed25519_pubkey: k_ed.public_key_bytes(),
                voting_weight: 4_200,
                pq_pubkey: k_pq.public_key_bytes().to_vec(),
            }],
        };
        guard
            .configure_domain(
                71,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::BasedPreconf {
                        network: "based-net".into(),
                        pinned: based_pin.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x81; 32]), 30_000)),
            )
            .unwrap();
        let ba = preconf_cert_sign_bytes("based-net", 9, 100, 7, &[0xA1; 32]);
        let bb = preconf_cert_sign_bytes("based-net", 9, 100, 7, &[0xB2; 32]);
        // Stripped PQ signature fails closed.
        let stripped_based = ContradictionEvidence::BasedPreconfFault {
            network: "based-net".into(),
            pinned: based_pin.clone(),
            proof: Box::new(BasedPreconfEquivocationProof {
                epoch: 9,
                l1_slot: 100,
                l2_sequence: 7,
                batch_digest_a: [0xA1; 32],
                sigs_a: vec![BasedSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&ba).to_vec(),
                    pq_sig: Vec::new(),
                }],
                batch_digest_b: [0xB2; 32],
                sigs_b: vec![BasedSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&bb).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &bb).unwrap(),
                }],
            }),
        };
        assert!(matches!(
            guard.submit_contradiction(71, &stripped_based, challenger, 90),
            Err(EconomicGuardError::InvalidEvidence(_))
        ));
        let valid_based = ContradictionEvidence::BasedPreconfFault {
            network: "based-net".into(),
            pinned: based_pin,
            proof: Box::new(BasedPreconfEquivocationProof {
                epoch: 9,
                l1_slot: 100,
                l2_sequence: 7,
                batch_digest_a: [0xA1; 32],
                sigs_a: vec![BasedSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&ba).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ba).unwrap(),
                }],
                batch_digest_b: [0xB2; 32],
                sigs_b: vec![BasedSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&bb).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &bb).unwrap(),
                }],
            }),
        };
        let based_out = guard
            .submit_contradiction(71, &valid_based, challenger, 91)
            .unwrap();
        assert_eq!(based_out.external_slashed_weight, 4_200);
        assert_eq!(based_out.slashed_bond_atoms, 30_000);
        assert_eq!(based_out.challenger_reward_atoms, 3_000);

        // 2. TonCatchainFault: verifies validator list hash + hybrid signatures + slashes weight.
        let ton_pin = PinnedTonMasterchainAnchor {
            key_block_seqno: 500,
            utime_since: 1_700_000_000,
            utime_until: 1_700_065_536,
            validators: vec![TonValidator {
                ed25519_pubkey: k_ed.public_key_bytes(),
                weight: 7_700,
                pq_pubkey: k_pq.public_key_bytes().to_vec(),
            }],
        };
        guard
            .configure_domain(
                72,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::TonCatchain {
                        network: "ton-net".into(),
                        pinned: ton_pin.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x82; 32]), 15_000)),
            )
            .unwrap();
        let vhash = compute_validator_list_hash(
            ton_pin.utime_since,
            ton_pin.utime_until,
            &ton_pin.validators,
        );
        let ta = catchain_commit_sign_bytes("ton-net", 12, &vhash, 510, &[0x31; 32], &[0x41; 32]);
        let tb = catchain_commit_sign_bytes("ton-net", 12, &vhash, 510, &[0x32; 32], &[0x42; 32]);
        let ton_fault = ContradictionEvidence::TonCatchainFault {
            network: "ton-net".into(),
            pinned: ton_pin,
            proof: Box::new(TonCatchainEquivocationProof {
                key_block_seqno: 500,
                catchain_seqno: 12,
                mc_seqno: 510,
                root_hash_a: [0x31; 32],
                file_hash_a: [0x41; 32],
                sigs_a: vec![CatchainSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&ta).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ta).unwrap(),
                }],
                root_hash_b: [0x32; 32],
                file_hash_b: [0x42; 32],
                sigs_b: vec![CatchainSig {
                    signer_pubkey: k_ed.public_key_bytes(),
                    ed25519_sig: k_ed.sign(&tb).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &tb).unwrap(),
                }],
            }),
        };
        let ton_out = guard
            .submit_contradiction(72, &ton_fault, challenger, 92)
            .unwrap();
        assert_eq!(ton_out.external_slashed_weight, 7_700);
        assert_eq!(ton_out.slashed_bond_atoms, 15_000);

        // 3. StellarFbaFault: verifies Mazieres quorum intersection + conflicting EXTERNALIZE
        //    ballots even at distinct ballot counters + slashes bonded tier node.
        let qset = ScpQuorumSet {
            threshold: 1,
            validators: vec![k_ed.public_key_bytes()],
            inner_sets: Vec::new(),
        };
        let qhash = qset.hash();
        let scp_pin = PinnedScpTier {
            network_passphrase: "Public Global Stellar Network ; September 2015".into(),
            has_bonded_slash_escrow: true,
            nodes: vec![ScpValidatorNode {
                ed25519_pubkey: k_ed.public_key_bytes(),
                quorum_set: qset,
                pq_pubkey: k_pq.public_key_bytes().to_vec(),
            }],
        };
        guard
            .configure_domain(
                73,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::StellarScp {
                        network: "stellar-net".into(),
                        pinned: scp_pin.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                Some(make_bond(Address::from([0x83; 32]), 10_000)),
            )
            .unwrap();
        let net_hash = compute_network_id_hash("stellar-net", &scp_pin.network_passphrase);
        let sa = externalize_sign_bytes(&net_hash, 888, 1, 2, &[0x51; 32], &qhash);
        let sb = externalize_sign_bytes(&net_hash, 888, 3, 5, &[0x52; 32], &qhash);
        let scp_fault = ContradictionEvidence::StellarFbaFault {
            network: "stellar-net".into(),
            pinned: scp_pin,
            proof: Box::new(StellarBallotEquivocationProof {
                slot_index: 888,
                ledger_header_hash_a: [0x51; 32],
                envelopes_a: vec![ScpExternalizeEnvelope {
                    node_id: k_ed.public_key_bytes(),
                    commit_counter: 1,
                    highest_counter: 2,
                    quorum_set_hash: qhash,
                    ed25519_sig: k_ed.sign(&sa).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sa).unwrap(),
                }],
                ledger_header_hash_b: [0x52; 32],
                envelopes_b: vec![ScpExternalizeEnvelope {
                    node_id: k_ed.public_key_bytes(),
                    commit_counter: 3,
                    highest_counter: 5,
                    quorum_set_hash: qhash,
                    ed25519_sig: k_ed.sign(&sb).to_vec(),
                    pq_sig: k_pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sb).unwrap(),
                }],
            }),
        };
        let scp_out = guard
            .submit_contradiction(73, &scp_fault, challenger, 93)
            .unwrap();
        assert_eq!(scp_out.external_slashed_weight, 1);
        assert_eq!(scp_out.slashed_bond_atoms, 10_000);

        // 4. MinaRecursive canonical pin digest binds every succinct genesis field.
        let mina_a = PinnedSuccinctGenesis {
            genesis_state_hash: [0x11; 32],
            genesis_staking_ledger_root: [0x22; 32],
            step_program_hash: [0x33; 32],
            slots_per_sub_window: 8,
            slots_per_epoch: 88,
            min_window_density_slots: 66,
            aggregator_pq_pubkey: k_pq.public_key_bytes().to_vec(),
        };
        let mut mina_b = mina_a.clone();
        mina_b.min_window_density_slots = 65;
        assert_ne!(
            GuardedExternalAdapter::MinaRecursive {
                network: "mina-net".into(),
                pinned: Box::new(mina_a),
            }
            .canonical_pin_digest(),
            GuardedExternalAdapter::MinaRecursive {
                network: "mina-net".into(),
                pinned: Box::new(mina_b),
            }
            .canonical_pin_digest(),
        );
    }

    #[test]
    fn auxpow_and_simplex_faults_reject_swapped_replays_and_slash_pinned_signers() {
        use crate::cross_domain::external::auxpow_pop::{
            pop_anchor_sign_bytes, PopAnchorSigner, PopSignature,
        };
        use crate::cross_domain::external::simplex_bft::{
            notarize_sign_bytes, SimplexSignature, SimplexValidator,
        };

        let k_ed = KeyPair::from_seed(&[0x83; 32]).unwrap();
        let k_pq = PqKeyPair::generate();
        let challenger = Address::from([0xE1; 32]);
        let mut guard = BridgeEconomicGuard::production();

        // 1. AuxPowPopFault swap invariance + exact bond weight slashing.
        let aux_pin = PinnedAuxPowAnchor {
            aux_chain_id: 42,
            trusted_parent_hash: [0x99; 32],
            max_target_bits: 0x207f_ffff,
            min_cumulative_work: [0; 32],
            min_confirmations: 1,
            pop_signers: vec![PopAnchorSigner {
                ed25519_pubkey: k_ed.public_key_bytes(),
                bond_weight: 2_500,
                pq_pubkey: k_pq.public_key_bytes().to_vec(),
            }],
        };
        guard
            .configure_domain(
                81,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::AuxPowPop {
                        network: "aux-net".into(),
                        pinned: Box::new(aux_pin.clone()),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .unwrap();
        let pop_msg_first = pop_anchor_sign_bytes("aux-net", 42, 700, &[0x11; 32], &[0x21; 32]);
        let pop_msg_second = pop_anchor_sign_bytes("aux-net", 42, 700, &[0x12; 32], &[0x22; 32]);
        let pop_first = PopSignature {
            signer_pubkey: k_ed.public_key_bytes(),
            ed25519_sig: k_ed.sign(&pop_msg_first).to_vec(),
            pq_sig: k_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &pop_msg_first)
                .unwrap(),
        };
        let pop_second = PopSignature {
            signer_pubkey: k_ed.public_key_bytes(),
            ed25519_sig: k_ed.sign(&pop_msg_second).to_vec(),
            pq_sig: k_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &pop_msg_second)
                .unwrap(),
        };
        let aux_out = guard
            .submit_contradiction(
                81,
                &ContradictionEvidence::AuxPowPopFault {
                    network: "aux-net".into(),
                    pinned: Box::new(aux_pin.clone()),
                    proof: Box::new(PopEquivocationProof {
                        aux_chain_id: 42,
                        aux_height: 700,
                        parent_hash_a: [0x11; 32],
                        aux_digest_a: [0x21; 32],
                        sigs_a: vec![pop_first.clone()],
                        parent_hash_b: [0x12; 32],
                        aux_digest_b: [0x22; 32],
                        sigs_b: vec![pop_second.clone()],
                    }),
                },
                challenger,
                100,
            )
            .unwrap();
        assert_eq!(aux_out.external_slashed_weight, 2_500);
        assert_eq!(
            guard.submit_contradiction(
                81,
                &ContradictionEvidence::AuxPowPopFault {
                    network: "aux-net".into(),
                    pinned: Box::new(aux_pin),
                    proof: Box::new(PopEquivocationProof {
                        aux_chain_id: 42,
                        aux_height: 700,
                        parent_hash_a: [0x12; 32],
                        aux_digest_a: [0x22; 32],
                        sigs_a: vec![pop_second],
                        parent_hash_b: [0x11; 32],
                        aux_digest_b: [0x21; 32],
                        sigs_b: vec![pop_first],
                    }),
                },
                challenger,
                101,
            ),
            Err(EconomicGuardError::DuplicateEvidence(
                aux_out.evidence_digest
            ))
        );

        // 2. SimplexFault DoubleNotarize swap invariance + exact stake slashing.
        let sx_pin = PinnedSimplexCommittee {
            epoch: 4,
            validators: vec![SimplexValidator {
                ed25519_pubkey: k_ed.public_key_bytes(),
                stake_weight: 6_400,
                pq_pubkey: k_pq.public_key_bytes().to_vec(),
            }],
        };
        guard
            .configure_domain(
                82,
                DomainCeilingPolicy {
                    pinned_adapter: Some(GuardedExternalAdapter::SimplexBft {
                        network: "sx-net".into(),
                        pinned: sx_pin.clone(),
                    }),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .unwrap();
        let sx_msg_first = notarize_sign_bytes("sx-net", 4, 25, &[0x61; 32]);
        let sx_msg_second = notarize_sign_bytes("sx-net", 4, 25, &[0x62; 32]);
        let sx_first = SimplexSignature {
            signer_pubkey: k_ed.public_key_bytes(),
            ed25519_sig: k_ed.sign(&sx_msg_first).to_vec(),
            pq_sig: k_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sx_msg_first)
                .unwrap(),
        };
        let sx_second = SimplexSignature {
            signer_pubkey: k_ed.public_key_bytes(),
            ed25519_sig: k_ed.sign(&sx_msg_second).to_vec(),
            pq_sig: k_pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sx_msg_second)
                .unwrap(),
        };
        let sx_out = guard
            .submit_contradiction(
                82,
                &ContradictionEvidence::SimplexFault {
                    network: "sx-net".into(),
                    pinned: sx_pin.clone(),
                    proof: Box::new(SimplexSlashingProof::DoubleNotarize {
                        epoch: 4,
                        view: 25,
                        height: 25,
                        block_digest_a: [0x61; 32],
                        sigs_a: vec![sx_first.clone()],
                        block_digest_b: [0x62; 32],
                        sigs_b: vec![sx_second.clone()],
                    }),
                },
                challenger,
                102,
            )
            .unwrap();
        assert_eq!(sx_out.external_slashed_weight, 6_400);
        assert_eq!(
            guard.submit_contradiction(
                82,
                &ContradictionEvidence::SimplexFault {
                    network: "sx-net".into(),
                    pinned: sx_pin,
                    proof: Box::new(SimplexSlashingProof::DoubleNotarize {
                        epoch: 4,
                        view: 25,
                        height: 25,
                        block_digest_a: [0x62; 32],
                        sigs_a: vec![sx_second],
                        block_digest_b: [0x61; 32],
                        sigs_b: vec![sx_first],
                    }),
                },
                challenger,
                103,
            ),
            Err(EconomicGuardError::DuplicateEvidence(
                sx_out.evidence_digest
            ))
        );
    }

    #[test]
    fn certificate_pending_or_refuted_zeroes_economic_guard_ceiling_immediately() {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::universal_finality::{
            compose, DomainFinalityEntry, FinalityGuarantee, FinalityPendingReason,
            FinalityReversibility, FinalityVerdict, FINALITY_BINDS_ALL,
        };

        let mut guard = BridgeEconomicGuard::new();
        let domain_id = 404u32;
        guard
            .configure_domain(
                domain_id,
                DomainCeilingPolicy {
                    backing: SecurityBacking::SignatureSet {
                        scheme: ObservedScheme::Secp256k1,
                        signers: 4,
                        required: 3,
                        total_weight: 300_000,
                        slashable: true,
                    },
                    stake_haircut_bps: 3_333,
                    window_blocks: 100,
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .expect("configure domain");

        let mk_entry = |verdict: FinalityVerdict| DomainFinalityEntry {
            domain_id,
            height: 12,
            checkpoint_height: 50,
            state_root: [0x11; 32],
            adapter_id: "cometbft-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x22; 32],
            guarantee_backing_hash: [0x33; 32],
            bond_atoms: 300_000,
            binds: crate::settlement::universal_finality::FinalityBinds::ALL,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: 3_333,
            },
            verdict,
        };

        let est_cert =
            compose(&[mk_entry(FinalityVerdict::Established)]).expect("established cert");
        let rec = guard.record(domain_id).expect("record");
        let est_proof = est_cert.prove_domain(domain_id).expect("established row");
        let est_ceiling = effective_ceiling_from_certificate_row(rec, &est_proof.entry);
        assert!(
            est_ceiling > 0,
            "established domain must expose positive ceiling"
        );
        guard
            .check_and_record_flow_with_certificate(domain_id, 1_000, 50, &est_cert)
            .expect("established certificate flow should be admitted");

        // In the very same block, if the domain drops to Pending, its ceiling
        // becomes strictly 0 and any bridge flow is refused without mutating state.
        let pending_cert = compose(&[mk_entry(FinalityVerdict::Pending {
            reason: FinalityPendingReason::EvidenceMissing,
        })])
        .expect("pending cert");
        let root_before_pending = guard.root();
        let pending_proof = pending_cert.prove_domain(domain_id).expect("pending row");
        assert_eq!(
            effective_ceiling_from_certificate_row(
                guard.record(domain_id).expect("record"),
                &pending_proof.entry,
            ),
            0
        );
        let pending_err = guard
            .check_and_record_flow_with_certificate(domain_id, 1, 50, &pending_cert)
            .unwrap_err();
        assert_eq!(
            pending_err,
            EconomicGuardError::CeilingExceeded {
                domain_id,
                requested_atoms: 1,
                window_used_atoms: 1_000,
                ceiling_atoms: 0,
            }
        );
        assert_eq!(guard.root(), root_before_pending);

        // Refuted verdict also yields a strict 0 ceiling.
        let refuted_cert =
            compose(&[mk_entry(FinalityVerdict::Refuted { code: 1 })]).expect("refuted cert");
        let refuted_proof = refuted_cert.prove_domain(domain_id).expect("refuted row");
        assert_eq!(
            effective_ceiling_from_certificate_row(
                guard.record(domain_id).expect("record"),
                &refuted_proof.entry,
            ),
            0
        );
        assert!(matches!(
            guard.check_and_record_flow_with_certificate(domain_id, 1, 50, &refuted_cert),
            Err(EconomicGuardError::CeilingExceeded {
                ceiling_atoms: 0,
                ..
            })
        ));
    }

    #[test]
    fn epoch_boundary_pruning_prevents_replay_table_exhaustion_attack() {
        let ed_kp = KeyPair::generate().expect("ed25519 key");
        let pq_kp = PqKeyPair::generate();
        let mut guard = BridgeEconomicGuard::new();
        let domain_id = 606u32;
        guard
            .configure_domain(
                domain_id,
                DomainCeilingPolicy {
                    prover_ed25519_pubkey: Some(ed_kp.public_key_bytes()),
                    prover_pq_pubkey: pq_kp.public_key_bytes().to_vec(),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .expect("configure domain");

        // Attacker saturates the replay ledger in epoch 0.
        for i in 0..MAX_GUARD_REPLAY_ENTRIES {
            let mut h = [0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_le_bytes());
            guard.consumed_evidence.insert(h);
            guard.consumed_evidence_epochs.insert(h, 0);
        }
        assert_eq!(guard.consumed_evidence.len(), MAX_GUARD_REPLAY_ENTRIES);

        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let stmt_a = contradiction_statement_bytes(domain_id, 99, &root_a);
        let stmt_b = contradiction_statement_bytes(domain_id, 99, &root_b);
        let evidence = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 99,
            state_root_a: root_a,
            ed25519_sig_a: ed_kp.sign(&stmt_a).to_vec(),
            pq_sig_a: pq_kp
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_a)
                .expect("pq sign a"),
            state_root_b: root_b,
            ed25519_sig_b: ed_kp.sign(&stmt_b).to_vec(),
            pq_sig_b: pq_kp
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt_b)
                .expect("pq sign b"),
        };

        // In epoch 0 the table is full, but once we cross the retention window
        // into epoch 5, expired epoch-0 entries are deterministically pruned
        // and the real contradiction succeeds and freezes the domain.
        let fresh_height = GUARD_REPLAY_EPOCH_BLOCKS
            .saturating_mul(GUARD_REPLAY_RETENTION_EPOCHS.saturating_add(1));
        let outcome = guard
            .submit_contradiction(
                domain_id,
                &evidence,
                Address::from([0x77; 32]),
                fresh_height,
            )
            .expect("epoch-boundary pruning must unblock fresh contradiction proofs");
        assert_eq!(outcome.domain_id, domain_id);
        assert_eq!(guard.replay_pruned_before_epoch(), 1);
        assert_eq!(guard.consumed_evidence.len(), 1);
        assert!(matches!(
            guard.record(domain_id).expect("record").status,
            DomainGuardStatus::FrozenByContradiction { .. }
        ));

        // Re-submitting the spent evidence trips the offender replay gate,
        // which deliberately outranks the epoch-horizon rule.
        let replay_err = guard
            .submit_contradiction(
                domain_id,
                &evidence,
                Address::from([0x77; 32]),
                fresh_height,
            )
            .unwrap_err();
        assert!(matches!(
            replay_err,
            EconomicGuardError::DuplicateEvidence(_)
        ));

        // Evidence whose epoch predates the pruned horizon is refused even
        // from an untouched prover: the ledger can no longer say whether that
        // epoch's duplicates were already spent and forgotten.
        let ed_kp2 = KeyPair::from_seed(&[0x67; 32]).unwrap();
        let pq_kp2 = PqKeyPair::generate();
        let domain2 = 607u32;
        guard
            .configure_domain(
                domain2,
                DomainCeilingPolicy {
                    prover_ed25519_pubkey: Some(ed_kp2.public_key_bytes()),
                    prover_pq_pubkey: pq_kp2.public_key_bytes().to_vec(),
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .expect("configure second domain");
        let stmt2_a = contradiction_statement_bytes(domain2, 42, &root_a);
        let stmt2_b = contradiction_statement_bytes(domain2, 42, &root_b);
        let stale = ContradictionEvidence::SignedProverDoubleRoot {
            domain_height: 42,
            state_root_a: root_a,
            ed25519_sig_a: ed_kp2.sign(&stmt2_a).to_vec(),
            pq_sig_a: pq_kp2
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt2_a)
                .unwrap(),
            state_root_b: root_b,
            ed25519_sig_b: ed_kp2.sign(&stmt2_b).to_vec(),
            pq_sig_b: pq_kp2
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &stmt2_b)
                .unwrap(),
        };
        let stale_err = guard
            .submit_contradiction(domain2, &stale, Address::from([0x78; 32]), 50)
            .unwrap_err();
        assert!(
            matches!(stale_err, EconomicGuardError::InvalidEvidence(_)),
            "pre-horizon epoch must be refused: {stale_err:?}"
        );
    }

    #[test]
    fn directional_flow_timelock_and_reorg_circuit_pause_enforce_invariants() {
        let mut guard = BridgeEconomicGuard::new();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::Work {
                difficulty_bits: 16,
            },
            work_window_cap_atoms: 1_000,
            min_work_difficulty_bits: 10,
            window_blocks: 100,
            ..DomainCeilingPolicy::default()
        };
        guard.configure_domain(88, policy, None).unwrap();
        guard
            .configure_domain_flow_controls(
                88,
                DomainFlowControls {
                    deposit_window_cap_atoms: 400,
                    max_single_tx_withdraw_atoms: 250,
                    large_withdraw_delay_blocks: 10,
                    auto_pause_reorg_depth_threshold: 4,
                    circuit_pause_duration_blocks: 20,
                },
            )
            .unwrap();

        // Asymmetric deposit cap (400) independent of withdrawal cap (1000).
        guard
            .check_and_record_directional_flow(88, BridgeFlowDirection::Deposit, 350, 10)
            .unwrap();
        assert!(matches!(
            guard.check_and_record_directional_flow(88, BridgeFlowDirection::Deposit, 60, 10),
            Err(EconomicGuardError::CeilingExceeded {
                ceiling_atoms: 400,
                ..
            })
        ));

        // Oversized single withdrawal (> 250) requires timelock queueing.
        assert!(matches!(
            guard.check_and_record_directional_flow(88, BridgeFlowDirection::Withdraw, 300, 11),
            Err(EconomicGuardError::LargeWithdrawalRequiresTimelock { .. })
        ));
        let recipient = Address::from([0x91; 32]);
        let wd_id = guard
            .queue_large_withdrawal(88, recipient, 300, 11)
            .unwrap();
        assert!(matches!(
            guard.claim_queued_withdrawal(wd_id, 20),
            Err(EconomicGuardError::WithdrawalTimelockActive {
                ready_at_height: 21,
                ..
            })
        ));

        // Reorg depth >= 4 trips timed pause and blocks both direct flows and timelock claims.
        assert!(guard.observe_reorg_depth(88, 5, 21).unwrap());
        assert!(matches!(
            guard.check_and_record_flow(88, 10, 22),
            Err(EconomicGuardError::DomainPaused { .. })
        ));
        assert!(matches!(
            guard.claim_queued_withdrawal(wd_id, 25),
            Err(EconomicGuardError::DomainPaused { .. })
        ));

        // After pause expires at height 41, resume unlocks the domain and claim succeeds.
        assert!(!guard.resume_if_pause_expired(88, 40).unwrap());
        assert!(guard.resume_if_pause_expired(88, 41).unwrap());
        let claimed = guard.claim_queued_withdrawal(wd_id, 41).unwrap();
        assert_eq!(claimed.amount_atoms, 300);

        // JSON serialization must remain valid (all map keys strings/integers).
        let json = serde_json::to_string(&guard).expect("serialize JSON");
        let parsed: BridgeEconomicGuard = serde_json::from_str(&json).expect("roundtrip JSON");
        assert_eq!(parsed.root(), guard.root());
    }

    fn pending_certificate_entry(
        domain_id: u32,
    ) -> crate::settlement::universal_finality::DomainFinalityEntry {
        crate::settlement::universal_finality::DomainFinalityEntry {
            domain_id,
            height: 1_000,
            checkpoint_height: 1_000,
            state_root: [0x13; 32],
            adapter_id: "tendermint-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [0x11; 32],
            guarantee_backing_hash: [0x22; 32],
            bond_atoms: 1_000,
            guarantee: crate::settlement::universal_finality::FinalityGuarantee {
                reversibility:
                    crate::settlement::universal_finality::FinalityReversibility::DeterministicQuorum,
                quantum_posture: crate::crypto::facts::QuantumClass::Hash,
                attestation: crate::settlement::universal_finality::FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: 3_333,
            },
            binds: crate::settlement::universal_finality::FinalityBinds::ALL,
            verdict: crate::settlement::universal_finality::FinalityVerdict::Pending {
                reason: crate::settlement::universal_finality::FinalityPendingReason::EvidenceMissing,
            },
        }
    }

    #[test]
    fn the_window_breach_sweep_names_only_the_domains_whose_last_flow_was_refused() {
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(21, signature_set_policy(3_000, 100), Some(stake_bond()))
            .expect("valid policy for the breached domain");
        guard
            .configure_domain(22, signature_set_policy(3_000, 100), Some(stake_bond()))
            .expect("valid policy for the quiet domain");

        assert!(
            guard.window_breaches().is_empty(),
            "a guard nobody has pushed past its ceiling has nothing to report"
        );

        guard
            .check_and_record_flow(21, 2_000, 100)
            .expect_err("2_000 > 999 is a breach");
        guard.check_and_record_flow(22, 900, 100).expect("900 fits");

        let breaches = guard.window_breaches();
        assert_eq!(breaches.len(), 1, "only the refused domain is named");
        assert_eq!(breaches[0].0, 21);
        assert_eq!(breaches[0].1.requested_atoms, 2_000);
        assert_eq!(breaches[0].1.ceiling_atoms, 999);
    }

    /// A bond whose 90% haircut (1_800) clears the 999-atom stake cap these
    /// tests use, so the stake cap stays the window they measure.
    fn stake_bond() -> ProverBond {
        make_bond(Address::from([0xB3; 32]), 2_000)
    }

    fn signature_set_policy(total_weight: u128, window_blocks: u64) -> DomainCeilingPolicy {
        DomainCeilingPolicy {
            backing: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ED25519),
                signers: 4,
                required: 3,
                total_weight,
                slashable: true,
            },
            shared_consumer_count: 1,
            window_blocks,
            ..DomainCeilingPolicy::default()
        }
    }

    #[test]
    fn a_single_attempt_above_the_window_ceiling_is_witnessed_as_one_breach_and_moves_nothing() {
        let mut guard = BridgeEconomicGuard::new();
        // 3_000 weight at the 33.33% stake haircut -> 999 atoms per window.
        guard
            .configure_domain(11, signature_set_policy(3_000, 100), Some(stake_bond()))
            .expect("valid signature-set policy");

        // A flow that fits leaves no breach behind: ordinary traffic is not an
        // anomaly, and a witness written on every accepted transfer would make
        // the field useless exactly when it matters.
        guard
            .check_and_record_flow(11, 500, 150)
            .expect("500 of 999 fits the window");
        assert!(
            guard
                .record(11)
                .expect("configured domain")
                .window_breach
                .is_none(),
            "an accepted flow must not be recorded as a breach"
        );

        // One attempt for more than the whole window ceiling: refused, and the
        // record says so with the numbers the refusal carried.
        let err = guard
            .check_and_record_flow(11, 1_500, 160)
            .expect_err("1_500 > 999 must be refused");
        assert!(matches!(
            err,
            EconomicGuardError::CeilingExceeded {
                requested_atoms: 1_500,
                ceiling_atoms: 999,
                ..
            }
        ));
        let breach = guard
            .record(11)
            .expect("configured domain")
            .window_breach
            .clone()
            .expect("a refused over-ceiling flow must leave a breach witness");
        assert_eq!(breach.height, 160);
        assert_eq!(breach.window, 1);
        assert_eq!(breach.requested_atoms, 1_500);
        assert_eq!(
            breach.used_atoms, 500,
            "the earlier 500-atom flow landed in this same window"
        );
        assert_eq!(breach.ceiling_atoms, 999);
        assert!(
            breach.single_attempt_over_ceiling,
            "1_500 in one attempt is larger than the entire window ceiling"
        );

        // The refusal moved nothing: what still fits in the same window is
        // accepted, measured against the 500 already there and not against the
        // refused attempt.
        guard
            .check_and_record_flow(11, 499, 161)
            .expect("500 + 499 is exactly the 999 window ceiling");
        assert!(
            guard
                .record(11)
                .expect("configured domain")
                .window_breach
                .is_none(),
            "a later accepted flow in the same window clears the witness"
        );
    }

    #[test]
    fn accumulated_flow_that_only_crosses_the_ceiling_by_pushing_it_over_is_not_a_single_attempt_breach(
    ) {
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(12, signature_set_policy(3_000, 100), Some(stake_bond()))
            .expect("valid signature-set policy");

        guard
            .check_and_record_flow(12, 600, 10)
            .expect("600 of 999 fits");
        let err = guard
            .check_and_record_flow(12, 600, 11)
            .expect_err("600 + 600 > 999 must be refused");
        assert!(matches!(
            err,
            EconomicGuardError::CeilingExceeded {
                window_used_atoms: 600,
                requested_atoms: 600,
                ..
            }
        ));
        let breach = guard
            .record(12)
            .expect("configured domain")
            .window_breach
            .clone()
            .expect("the crossing attempt is still a breach witness");
        assert_eq!(breach.used_atoms, 600);
        assert!(
            !breach.single_attempt_over_ceiling,
            "each attempt was 600, which fits on its own; the window crossed by accumulation"
        );
    }

    #[test]
    fn a_certificate_row_that_refuses_a_flow_also_witnesses_the_breach() {
        let mut guard = BridgeEconomicGuard::new();
        guard
            .configure_domain(13, signature_set_policy(3_000, 100), Some(stake_bond()))
            .expect("valid signature-set policy");
        // A Pending row holds the domain's effective ceiling at strictly zero
        // for the block, so any non-zero flow is refused there. The row is
        // composed through the real certificate composer, not hand-built: the
        // guard reads what `prove_domain` returns, and a fixture that skipped
        // composition would not exercise that.
        let certificate =
            crate::settlement::universal_finality::compose(&[pending_certificate_entry(13)])
                .expect("a single pending row seals");
        let err = guard
            .check_and_record_flow_with_certificate(13, 1, 1_050, &certificate)
            .expect_err("a Pending row holds the ceiling at zero");
        assert!(matches!(
            err,
            EconomicGuardError::CeilingExceeded {
                ceiling_atoms: 0,
                ..
            }
        ));
        let breach = guard
            .record(13)
            .expect("configured domain")
            .window_breach
            .clone()
            .expect("the certificate-refused flow is witnessed too");
        assert_eq!(breach.ceiling_atoms, 0);
        assert_eq!(breach.requested_atoms, 1);
        assert!(breach.single_attempt_over_ceiling);
    }

    fn refusal_test_certificate(
        height: u64,
    ) -> crate::settlement::universal_finality::GlobalFinalityCertificate {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::universal_finality::{
            compose, DomainFinalityEntry, FinalityBinds, FinalityGuarantee, FinalityReversibility,
            FinalityVerdict, FINALITY_BINDS_ALL,
        };
        compose(&[DomainFinalityEntry {
            domain_id: 999,
            height,
            checkpoint_height: height,
            state_root: [1; 32],
            adapter_id: "cometbft-v1".to_owned(),
            adapter_version: 1,
            finality_proof_hash: [2; 32],
            guarantee_backing_hash: [3; 32],
            bond_atoms: 100,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::DeterministicQuorum,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: true,
                fault_tolerance_bps: 10_000,
            },
            binds: FinalityBinds::ALL,
            verdict: FinalityVerdict::Established,
        }])
        .expect("valid certificate")
    }

    #[test]
    fn certificate_flow_unknown_domain_is_fail_closed_without_state_change() {
        let mut guard = BridgeEconomicGuard::production();
        let before = guard.root();
        let cert = refusal_test_certificate(10);
        assert_eq!(
            guard.check_and_record_flow_with_certificate(405, 1, 10, &cert),
            Err(EconomicGuardError::UnknownDomain(405))
        );
        assert!(guard.record(405).is_none());
        assert_eq!(guard.root(), before);
    }

    #[test]
    fn certificate_flow_frozen_domain_does_not_consume_budget() {
        let mut guard = BridgeEconomicGuard::production();
        guard
            .configure_domain(405, DomainCeilingPolicy::default(), None)
            .unwrap();
        let rec = guard.domains.get_mut(&405).unwrap();
        rec.active_window = 4;
        rec.window_used_atoms = 37;
        rec.status = DomainGuardStatus::FrozenByContradiction {
            frozen_at_height: 4,
            evidence_digest: [42; 32],
        };
        let before = guard.root();
        let cert = refusal_test_certificate(10);
        assert_eq!(
            guard.check_and_record_flow_with_certificate(405, 1, 10, &cert),
            Err(EconomicGuardError::DomainFrozen {
                domain_id: 405,
                evidence_digest: [42; 32]
            })
        );
        assert_eq!(guard.root(), before);
        let rec = guard.record(405).unwrap();
        assert_eq!((rec.active_window, rec.window_used_atoms), (4, 37));
    }

    #[test]
    fn certificate_flow_addition_overflow_is_refused_without_state_change() {
        let mut guard = BridgeEconomicGuard::production();
        guard
            .configure_domain(
                405,
                DomainCeilingPolicy {
                    window_blocks: 100,
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .unwrap();
        let rec = guard.domains.get_mut(&405).unwrap();
        rec.active_window = 0;
        rec.window_used_atoms = u128::MAX;
        let before = guard.root();
        let cert = refusal_test_certificate(10);
        let result = guard.check_and_record_flow_with_certificate(405, 1, 10, &cert);
        assert!(matches!(
            result,
            Err(EconomicGuardError::CeilingExceeded {
                domain_id: 405,
                requested_atoms: 1,
                window_used_atoms: u128::MAX,
                ..
            })
        ));
        assert_eq!(guard.root(), before);
        let rec = guard.record(405).unwrap();
        assert_eq!((rec.active_window, rec.window_used_atoms), (0, u128::MAX));
    }

    #[test]
    fn guardian_pause_cooldown_prevents_repausing_griefing() {
        let mut guard = BridgeEconomicGuard::new();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::Work {
                difficulty_bits: 16,
            },
            work_window_cap_atoms: 1_000,
            min_work_difficulty_bits: 10,
            window_blocks: 100,
            ..DomainCeilingPolicy::default()
        };
        guard.configure_domain(91, policy, None).unwrap();
        guard
            .configure_domain_flow_controls(
                91,
                DomainFlowControls {
                    deposit_window_cap_atoms: 500,
                    max_single_tx_withdraw_atoms: 250,
                    large_withdraw_delay_blocks: 10,
                    auto_pause_reorg_depth_threshold: 4,
                    circuit_pause_duration_blocks: 20,
                },
            )
            .unwrap();

        // First pause triggers cleanly and expires at height 120.
        assert!(guard.observe_reorg_depth(91, 5, 100).unwrap());
        assert!(guard.resume_if_pause_expired(91, 120).unwrap());

        // Immediate re-pause during mandatory cooldown (120..184) must fail closed.
        assert!(matches!(
            guard.observe_reorg_depth(91, 6, 125),
            Err(EconomicGuardError::ReorgPauseCooldownActive {
                domain_id: 91,
                current_height: 125,
                cooldown_until_height: 184,
            })
        ));

        // After cooldown expires at height 184, another genuine reorg pause works.
        assert!(guard.observe_reorg_depth(91, 6, 184).unwrap());
    }

    #[test]
    fn scoped_guardian_pause_blocks_deposits_and_fast_exits_while_preserving_matured_withdrawals() {
        let mut guard = BridgeEconomicGuard::new();
        let policy = DomainCeilingPolicy {
            backing: SecurityBacking::Work {
                difficulty_bits: 16,
            },
            work_window_cap_atoms: 1_000,
            min_work_difficulty_bits: 10,
            window_blocks: 200,
            ..DomainCeilingPolicy::default()
        };
        guard.configure_domain(92, policy, None).unwrap();
        guard
            .configure_domain_flow_controls(
                92,
                DomainFlowControls {
                    deposit_window_cap_atoms: 500,
                    max_single_tx_withdraw_atoms: 200,
                    large_withdraw_delay_blocks: 10,
                    auto_pause_reorg_depth_threshold: 4,
                    circuit_pause_duration_blocks: 30,
                },
            )
            .unwrap();

        // Queue a timelocked withdrawal before the incident pause starts.
        let wd_id = guard
            .queue_large_withdrawal(92, Address::from([0x77; 32]), 300, 10)
            .unwrap();

        // Guardian triggers scoped pause halting deposits and unqueued fast exits.
        assert!(guard
            .observe_reorg_depth_with_scope(92, 5, 15, GuardianPauseScope::DepositsAndFastExitsOnly)
            .unwrap());

        assert!(matches!(
            guard.check_and_record_directional_flow(92, BridgeFlowDirection::Deposit, 50, 20),
            Err(EconomicGuardError::DomainPaused { .. })
        ));
        assert!(matches!(
            guard.check_and_record_flow(92, 50, 20),
            Err(EconomicGuardError::DomainPaused { .. })
        ));

        // Already-queued withdrawal cannot be claimed early, yet once matured at
        // height 20 it can still be claimed without being held hostage by the guardian.
        assert!(matches!(
            guard.claim_queued_withdrawal(wd_id, 19),
            Err(EconomicGuardError::WithdrawalTimelockActive { .. })
        ));
        let claimed = guard.claim_queued_withdrawal(wd_id, 20).unwrap();
        assert_eq!(claimed.amount_atoms, 300);
    }
}
