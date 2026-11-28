//! Universal Blockchain Unification Engine.
//!
//! Coordinates four foundational surfaces without mutating any external chain's
//! consensus rules or any virtual machine's internal execution semantics:
//!
//! - [`domain_catalog`]: Universal chain-as-domain catalog mapping every
//!   blockchain, consensus family, virtual machine, and storage network to a
//!   canonical domain record and Merkle commitment.
//! - [`output_composer`]: Cross-VM and multi-language execution output
//!   normalizer and cycle-free DAG composer producing one Merkle-verifiable
//!   bundle from EVM, WASM, SVM, Move, Cairo, UTXO, and `BudZero` outputs.
//! - [`payment_router`]: Atomic multi-token split-tender payment router (with
//!   on-chain, POS terminal, and card-network settlement rails) and cross-domain
//!   collateral liquidation coordinator.
//! - [`abi_bridge`]: Cross-VM and multi-language canonical call envelope bridge
//!   projecting typed calls across EVM, SVM, Move, `CosmWasm`, UTXO, Cairo, and
//!   `BudZero` without altering any domain's inner rules.
//! - [`storage_fabric`]: Unified Web3 and decentralized storage fabric binding
//!   B.U.D. 3.0, IPFS, Arweave, Filecoin, Walrus, Swarm, Sia, and Storj under
//!   one verified content-addressed URI and failover resolver.
//!
//! WIRING: wired through `src/lib.rs` and the read-only JSON-RPC doors
//! `bud_getUniversalDomains`, `bud_quoteUniversalPayment`,
//! `bud_composeExecutionOutputs`, `bud_resolveUnifiedStorage`,
//! `bud_encodeCrossVmCall`, and `bud_verifyUniversalBundle` in
//! `src/rpc/api.rs` and `src/rpc/server.rs`.

pub mod abi_bridge;
pub mod domain_catalog;
pub mod output_composer;
pub mod payment_router;
pub mod storage_fabric;

pub use abi_bridge::{
    AbiBridgeError, CanonicalCallArg, CrossVmBridge, CrossVmCallEnvelope, CrossVmCallRequest,
    TargetWireEncoding,
};

pub use domain_catalog::{
    CatalogError, DomainCapability, UniversalDomainCatalog, UniversalDomainInclusionProof,
    UniversalDomainRecord,
};
pub use output_composer::{
    build_external_step_receipt_proof, build_external_step_receipt_root, AtomicityClass,
    AttestedOutputBundle, CanonicalValue, CompositionError, LanguageTag, NormalizedEvent,
    NormalizedMachineOutput, NormalizedStateEffect, OutputBinding, OutputComposer,
    OutputCompositionPlan, OutputSelector, StepReceiptAttestation, UnifiedOutputBundle,
    EXTERNAL_STEP_RECEIPT_TAG,
};
pub use payment_router::{
    universal_asset_id, verify_split_tender_supply_conservation, AssetEquivalenceClass,
    AssetEquivalenceMember, CollateralAsset, CrossDomainPosition, DeliveredPaymentProof,
    DomainTokenBalance, FinalizedPaymentProof, GuaranteedPaymentProof, LiquidationError,
    LiquidationReceipt, LiquidityQuote, PaymentCompletionLevel, PaymentError, PaymentRail,
    PaymentStatusReport, PreauthorizedSpendAccount, RefundIntent, RefundRegistry,
    SeizedCollateralLeg, SignedOfflineVoucher, SplitTenderLeg, UniversalLiquidationCoordinator,
    UniversalPaymentIntent, UniversalPaymentReceipt, UniversalPaymentRequestUri,
    UniversalPaymentRouter, OFFLINE_VOUCHER_CTX,
};
pub use storage_fabric::{
    build_storage_domain_commitment_root, build_storage_domain_inclusion_proof,
    storage_domain_commitment_leaf, ReplicaResolution, StorageFabricError, StorageNetworkKind,
    StoragePaymentRequest, StorageReplica, StorageReplicaProof, UnifiedContentRecord,
    UnifiedStorageFabric, UniversalContentUri, VerificationStrength, Web3SiteAsset,
    STORAGE_DOMAIN_COMMITMENT_TAG,
};

use crate::domain::types::Hash32;
use sha3::{Digest, Sha3_256};

/// Domain-separated SHA3-256 hash over length-prefixed byte slices.
///
/// Every slice is prefixed with its 8-byte little-endian length so distinct
/// field boundaries can never collide.
#[must_use]
pub(crate) fn hash_domain_fields(domain_tag: &[u8], fields: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(
        u64::try_from(domain_tag.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(domain_tag);
    hasher.update(
        u64::try_from(fields.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Domain-separated binary Merkle node hash (`0x01 || left || right`).
#[must_use]
pub(crate) fn merkle_node_hash(domain_tag: &[u8], left: &Hash32, right: &Hash32) -> Hash32 {
    hash_domain_fields(domain_tag, &[&[0x01], left, right])
}

/// Domain-separated binary Merkle leaf hash (`0x00 || index_le || leaf`).
#[must_use]
pub(crate) fn merkle_leaf_hash(domain_tag: &[u8], index: usize, leaf: &Hash32) -> Hash32 {
    let idx_bytes = u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes();
    hash_domain_fields(domain_tag, &[&[0x00], &idx_bytes, leaf])
}

/// Domain-separated promotion hash for an unpaired odd-level Merkle node.
///
/// Prevents CVE-2012-2459 self-duplication collisions between odd-count leaf
/// slices and slices repeating their trailing element.
#[must_use]
fn merkle_odd_hash(domain_tag: &[u8], lone: &Hash32) -> Hash32 {
    hash_domain_fields(domain_tag, &[&[0x02], lone])
}

/// Domain-separated root envelope binding exact `leaf_count` to eliminate
/// tree-length confusion between trees sharing a left complete subtree.
#[must_use]
fn merkle_root_envelope(domain_tag: &[u8], leaf_count: usize, tree_root: &Hash32) -> Hash32 {
    let count_bytes = u64::try_from(leaf_count).unwrap_or(u64::MAX).to_le_bytes();
    hash_domain_fields(domain_tag, &[&[0x03], &count_bytes, tree_root])
}

/// Computes the deterministic binary Merkle root of `leaves`.
///
/// An empty leaf slice commits to the tagged empty hash. Odd levels promote the
/// trailing node through a distinct `[0x02]` domain tag rather than duplicating
/// it, and the final root binds exact `leaves.len()` under a `[0x03]` tag.
#[must_use]
pub(crate) fn unification_merkle_root(domain_tag: &[u8], leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return hash_domain_fields(domain_tag, &[b"EMPTY"]);
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| merkle_leaf_hash(domain_tag, i, leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(merkle_node_hash(domain_tag, left, right)),
                [lone] => next.push(merkle_odd_hash(domain_tag, lone)),
                _ => {}
            }
        }
        level = next;
    }
    let tree_root = level
        .first()
        .copied()
        .unwrap_or_else(|| hash_domain_fields(domain_tag, &[b"EMPTY"]));
    merkle_root_envelope(domain_tag, leaves.len(), &tree_root)
}

/// Builds a sibling inclusion proof for `leaf_index` in `leaves`.
#[must_use]
pub(crate) fn build_merkle_proof(
    domain_tag: &[u8],
    leaves: &[Hash32],
    leaf_index: usize,
) -> Option<Vec<Hash32>> {
    if leaf_index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash32> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| merkle_leaf_hash(domain_tag, i, leaf))
        .collect();
    let mut idx = leaf_index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        if idx.is_multiple_of(2) {
            if let Some(&right) = level.get(idx + 1) {
                proof.push(right);
            }
        } else {
            proof.push(*level.get(idx - 1)?);
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [left, right] => next.push(merkle_node_hash(domain_tag, left, right)),
                [lone] => next.push(merkle_odd_hash(domain_tag, lone)),
                _ => {}
            }
        }
        level = next;
        idx /= 2;
    }
    Some(proof)
}

/// Verifies a sibling inclusion proof against `root` for `leaf` at `leaf_index`.
#[must_use]
pub(crate) fn verify_merkle_proof(
    domain_tag: &[u8],
    root: &Hash32,
    leaf_index: usize,
    leaf_count: usize,
    leaf: &Hash32,
    proof: &[Hash32],
) -> bool {
    if leaf_count == 0 || leaf_index >= leaf_count {
        return false;
    }
    let mut current = merkle_leaf_hash(domain_tag, leaf_index, leaf);
    let mut idx = leaf_index;
    let mut level_len = leaf_count;
    let mut siblings = proof.iter();
    while level_len > 1 {
        if idx.is_multiple_of(2) {
            if idx + 1 < level_len {
                let Some(sib) = siblings.next() else {
                    return false;
                };
                current = merkle_node_hash(domain_tag, &current, sib);
            } else {
                current = merkle_odd_hash(domain_tag, &current);
            }
        } else {
            let Some(sib) = siblings.next() else {
                return false;
            };
            current = merkle_node_hash(domain_tag, sib, &current);
        }
        idx /= 2;
        level_len = level_len.div_ceil(2);
    }
    siblings.next().is_none() && merkle_root_envelope(domain_tag, leaf_count, &current) == *root
}

/// Exact 256-bit unsigned product of two `u128` values, returned as `(hi, lo)`.
#[must_use]
const fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid1 = (p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (p0 & 0xFFFF_FFFF_FFFF_FFFF) | (mid1 << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid1 >> 64);
    (hi, lo)
}

/// Exact division of a 256-bit value `(hi, lo)` by a non-zero `u128` divisor.
///
/// Returns `(quotient, remainder)` when the quotient fits in `u128`, or `None`
/// if `denom == 0` or the quotient exceeds `u128::MAX`.
#[must_use]
fn div_u256_by_u128(hi: u128, lo: u128, denom: u128) -> Option<(u128, u128)> {
    if denom == 0 || hi >= denom {
        return None;
    }
    let mut rem = hi;
    let mut quot = 0u128;
    for bit in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> bit) & 1);
        quot <<= 1;
        if carry != 0 || rem >= denom {
            rem = rem.wrapping_sub(denom);
            quot |= 1;
        }
    }
    Some((quot, rem))
}

/// Computes `floor(a * b / denom)` without intermediate `u128` overflow.
///
/// Returns `None` if `denom == 0` or the final quotient exceeds `u128::MAX`.
#[must_use]
pub(crate) fn mul_div_floor(a: u128, b: u128, denom: u128) -> Option<u128> {
    let (hi, lo) = mul_u128_wide(a, b);
    let (q, _) = div_u256_by_u128(hi, lo, denom)?;
    Some(q)
}

/// Computes `ceil(a * b / denom)` without intermediate `u128` overflow.
///
/// Returns `None` if `denom == 0` or the final ceiling exceeds `u128::MAX`.
#[must_use]
pub(crate) fn mul_div_ceil(a: u128, b: u128, denom: u128) -> Option<u128> {
    let (hi, lo) = mul_u128_wide(a, b);
    let (q, r) = div_u256_by_u128(hi, lo, denom)?;
    if r == 0 {
        Some(q)
    } else {
        q.checked_add(1)
    }
}

/// Validates a short ASCII identifier (non-empty, bounded length, no control
/// bytes or path-traversal markers).
pub(crate) fn validate_safe_label(field: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("{field} length must be within 1..={max_len}"));
    }
    if value.contains("..")
        || value.contains('\\')
        || value.bytes().any(|b| b == 0 || b.is_ascii_control())
    {
        return Err(format!("{field} contains forbidden characters"));
    }
    Ok(())
}

/// Hard cap on registered domain finality anchors in [`UnificationLedger`].
const MAX_LEDGER_DOMAINS: usize = 512;

/// Hard cap on bonded liquidity solvers in [`UnificationLedger`].
const MAX_LEDGER_SOLVERS: usize = 4_096;

/// Hard cap on committed multi-VM output bundles in [`UnificationLedger`].
const MAX_LEDGER_BUNDLES: usize = 16_384;

/// Finalized security and state anchor registered for one consensus domain in
/// [`UnificationLedger`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AnchoredDomainState {
    pub domain_id: crate::domain::types::DomainId,
    pub guarantee: crate::settlement::universal_finality::FinalityGuarantee,
    pub slashable_bond_atoms: u128,
    pub routing_ceiling_atoms: u128,
    pub finalized_height: u64,
    pub finalized_state_root: Hash32,
    pub epoch_outflow_atoms: u128,
}

/// Bonded quote-solver entry securing cross-domain split-tender fulfillment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SolverBondRecord {
    pub solver_id: Hash32,
    pub bonded_atoms: u128,
    pub slashed_atoms: u128,
    pub quarantined: bool,
}

/// Binding of a [`LiquidityQuote`] to an escrowed, slashable solver identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BondedLiquidityQuote {
    pub solver_id: Hash32,
    pub quote: LiquidityQuote,
}

/// Deterministic slash receipt emitted when a solver defaults on a settled leg.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SolverSlashReceipt {
    pub intent_id: Hash32,
    pub quote_id: Hash32,
    pub solver_id: Hash32,
    pub slashed_atoms: u128,
    pub remaining_bond_atoms: u128,
    pub slash_hash: Hash32,
}

/// Atomic storage-deal input grouping owner content metadata, cryptographic
/// per-replica proofs, and split-tender payment parameters.
///
/// WIRING: Input bundle consumed by [`UnificationLedger::execute_atomic_storage_deal`].
pub struct AtomicStorageDeal<'a> {
    pub owner_id: Hash32,
    pub record: UnifiedContentRecord,
    pub replica_proofs: &'a [StorageReplicaProof],
    pub bns_name: Option<&'a str>,
    pub intent: &'a UniversalPaymentIntent,
    pub bonded_quotes: &'a [BondedLiquidityQuote],
    pub now_unix_secs: u64,
}

/// Single write-authority role permitted to lock or consume cross-domain
/// escrowed balances inside [`UnificationLedger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CrossDomainWriteAuthority {
    /// Source-chain escrow authority (canonical owner lock before finality).
    SourceEscrow,
    /// Target-chain relayer authority (never permitted to initiate direct spend locks).
    TargetRelay,
}

/// Parameters for acquiring an exclusive source-escrowed cross-domain spend lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendReservationRequest {
    pub domain_id: crate::domain::types::DomainId,
    pub asset_id: Hash32,
    pub owner_id: Hash32,
    pub amount_atoms: u128,
    pub write_authority: CrossDomainWriteAuthority,
    pub current_height: u64,
    pub ttl_blocks: u64,
}

/// Exclusive in-flight cross-domain spend reservation preventing concurrent
/// double-spends on `(domain_id, asset_id, owner_id)` until either finalized
/// or refunded after expiry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CrossDomainSpendReservation {
    pub reservation_id: Hash32,
    pub domain_id: crate::domain::types::DomainId,
    pub asset_id: Hash32,
    pub owner_id: Hash32,
    pub amount_atoms: u128,
    pub write_authority: CrossDomainWriteAuthority,
    pub initiated_height: u64,
    pub expires_at_height: u64,
    pub confirmed: bool,
}

/// Errors returned by [`UnificationLedger`] atomic in-block transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnificationExecutionError {
    #[error("unification ledger capacity limit reached")]
    CapacityExceeded,
    #[error("invalid unification ledger argument: {0}")]
    InvalidArgument(String),
    #[error("domain {0} has no finalized security anchor")]
    UnanchoredDomain(crate::domain::types::DomainId),
    #[error("cross-domain route {source_domain} -> {target_domain} violates finality bar")]
    RouteFinalityInsufficient {
        source_domain: crate::domain::types::DomainId,
        target_domain: crate::domain::types::DomainId,
    },
    #[error("domain {domain} exceeds economic outflow conservation ceiling")]
    EconomicCeilingExceeded {
        domain: crate::domain::types::DomainId,
    },
    #[error("concurrent cross-domain spend lock active for domain {domain_id}")]
    ConcurrentSpendReservationConflict {
        domain_id: crate::domain::types::DomainId,
        asset_id: Hash32,
        owner_id: Hash32,
    },
    #[error("solver is unbonded, quarantined, or under-collateralized")]
    SolverBondInsufficient,
    #[error("solver fault target not found or already slashed")]
    InvalidSlashClaim,
    #[error("bundle `{0}` was already committed or exceeds block gas cap")]
    BundleRejected(String),
    #[error("payment transition failed: {0}")]
    Payment(#[from] PaymentError),
    #[error("output composition failed: {0}")]
    Composition(#[from] CompositionError),
    #[error("storage fabric transition failed: {0}")]
    Storage(#[from] StorageFabricError),
    #[error("settlement refused by the universal finality certificate: {0}")]
    PaymentFinalityRefused(String),
}

/// Deterministic, finality-gated, all-or-nothing in-block unification ledger.
///
/// Coordinates multi-token split-tender payments, solver slashing, multi-VM
/// output bundles, and owner-authenticated storage / BNS bindings.
///
/// Every transition operates on canonical `BTreeMap` / `BTreeSet` state with
/// pure-integer arithmetic and full rollback on any leg, finality, conservation,
/// gas, or storage authorization failure.
#[derive(Debug, Clone)]
pub struct UnificationLedger {
    hub_guarantee: crate::settlement::universal_finality::FinalityGuarantee,
    domains: std::collections::BTreeMap<crate::domain::types::DomainId, AnchoredDomainState>,
    solvers: std::collections::BTreeMap<Hash32, SolverBondRecord>,
    settled_quote_obligations: std::collections::BTreeMap<(Hash32, Hash32), (Hash32, u128)>,
    slash_hashes: Vec<Hash32>,
    merchant_credits:
        std::collections::BTreeMap<(Hash32, crate::domain::types::DomainId, Hash32), u128>,
    committed_bundles: std::collections::BTreeMap<Hash32, Hash32>,
    spend_reservations: std::collections::BTreeMap<
        (crate::domain::types::DomainId, Hash32, Hash32),
        CrossDomainSpendReservation,
    >,
    router: UniversalPaymentRouter,
    storage: UnifiedStorageFabric,
}

impl UnificationLedger {
    /// Construct a new ledger anchored on Budlum's `hub_guarantee`.
    ///
    /// WIRING: Atomic in-block state transition coordinator across `payment_router`,
    /// `output_composer`, `storage_fabric`, and `settlement::universal_finality`.
    #[must_use]
    pub fn new(hub_guarantee: crate::settlement::universal_finality::FinalityGuarantee) -> Self {
        Self {
            hub_guarantee,
            domains: std::collections::BTreeMap::new(),
            solvers: std::collections::BTreeMap::new(),
            settled_quote_obligations: std::collections::BTreeMap::new(),
            slash_hashes: Vec::new(),
            merchant_credits: std::collections::BTreeMap::new(),
            committed_bundles: std::collections::BTreeMap::new(),
            spend_reservations: std::collections::BTreeMap::new(),
            router: UniversalPaymentRouter::new(),
            storage: UnifiedStorageFabric::new(),
        }
    }

    /// Anchor or advance the verified finality envelope and state root of `domain_id`.
    ///
    /// Rejects zero domain IDs, zero state roots, or height regressions.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] on invalid identifiers, height
    /// regression, or domain table capacity exhaustion.
    ///
    /// WIRING: Ingests verified `FinalityGuarantee` anchors from settlement domains.
    pub fn anchor_domain_finality(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        guarantee: crate::settlement::universal_finality::FinalityGuarantee,
        slashable_bond_atoms: u128,
        routing_ceiling_atoms: u128,
        finalized_height: u64,
        finalized_state_root: Hash32,
    ) -> Result<(), UnificationExecutionError> {
        if domain_id == 0 || finalized_state_root == [0u8; 32] {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "domain_id and finalized_state_root must be non-zero",
            )));
        }
        let prior_outflow = if let Some(existing) = self.domains.get(&domain_id) {
            if finalized_height < existing.finalized_height {
                return Err(UnificationExecutionError::InvalidArgument(String::from(
                    "finalized_height cannot regress",
                )));
            }
            existing.epoch_outflow_atoms
        } else {
            if self.domains.len() >= MAX_LEDGER_DOMAINS {
                return Err(UnificationExecutionError::CapacityExceeded);
            }
            0
        };
        self.domains.insert(
            domain_id,
            AnchoredDomainState {
                domain_id,
                guarantee,
                slashable_bond_atoms,
                routing_ceiling_atoms,
                finalized_height,
                finalized_state_root,
                epoch_outflow_atoms: prior_outflow,
            },
        );
        Ok(())
    }

    /// Deposit slashable collateral for `solver_id` to back cross-domain quotes.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] if `solver_id` is zero, `amount == 0`,
    /// the solver is quarantined after slashing, or bond arithmetic overflows.
    ///
    /// WIRING: Escrows solver bond slashed by [`Self::slash_unfulfilled_payment_leg`].
    pub fn bond_solver(
        &mut self,
        solver_id: Hash32,
        amount: u128,
    ) -> Result<u128, UnificationExecutionError> {
        if solver_id == [0u8; 32] || amount == 0 {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "solver_id and bond amount must be non-zero",
            )));
        }
        if let Some(rec) = self.solvers.get_mut(&solver_id) {
            if rec.quarantined {
                return Err(UnificationExecutionError::SolverBondInsufficient);
            }
            rec.bonded_atoms = rec
                .bonded_atoms
                .checked_add(amount)
                .ok_or(UnificationExecutionError::SolverBondInsufficient)?;
            return Ok(rec.bonded_atoms);
        }
        if self.solvers.len() >= MAX_LEDGER_SOLVERS {
            return Err(UnificationExecutionError::CapacityExceeded);
        }
        self.solvers.insert(
            solver_id,
            SolverBondRecord {
                solver_id,
                bonded_atoms: amount,
                slashed_atoms: 0,
                quarantined: false,
            },
        );
        Ok(amount)
    }

    /// Execute an atomic, finality-gated, economic-ceiling-bounded split-tender
    /// settlement across heterogeneous chains and credit `intent.merchant_id`.
    ///
    /// Guarantees complete all-or-nothing atomicity: if any leg violates route
    /// finality, domain outflow conservation, solver bond coverage, quote expiry,
    /// liquidity, or replay checks, neither `balances` nor ledger state mutates.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation on failure.
    ///
    /// WIRING: In-block universal split-tender execution path.
    pub fn execute_finality_gated_payment(
        &mut self,
        intent: &UniversalPaymentIntent,
        balances: &mut [DomainTokenBalance],
        bonded_quotes: &[BondedLiquidityQuote],
        now_unix_secs: u64,
    ) -> Result<UniversalPaymentReceipt, UnificationExecutionError> {
        self.execute_finality_gated_payment_checked(
            intent,
            balances,
            bonded_quotes,
            now_unix_secs,
            None,
        )
    }

    /// Execute the same settlement, but only when a universal finality
    /// certificate admits every leg through the [`ValueGate::UniversalPayment`]
    /// gate.
    ///
    /// `execute_finality_gated_payment` decides from the ledger's own per-domain
    /// anchors. Those anchors are a local cache: a settlement that never saw a
    /// certificate can still move value if the cache says a domain is healthy.
    /// This entry point closes that gap for callers that hold the certificate
    /// (the single decision point is `settlement::finality_gate`), and it runs
    /// before any staging so a refused settlement cannot debit even a clone.
    ///
    /// # Errors
    ///
    /// Everything `execute_finality_gated_payment` returns, plus
    /// [`UnificationExecutionError::PaymentFinalityRefused`] when the
    /// certificate's seal does not re-derive or a leg's route is not admitted.
    pub fn execute_finality_gated_payment_checked(
        &mut self,
        intent: &UniversalPaymentIntent,
        balances: &mut [DomainTokenBalance],
        bonded_quotes: &[BondedLiquidityQuote],
        now_unix_secs: u64,
        certificate: Option<&crate::settlement::GlobalFinalityCertificate>,
    ) -> Result<UniversalPaymentReceipt, UnificationExecutionError> {
        if let Some(cert) = certificate {
            // One rule, one place: the gate re-derives the certificate's own
            // seal before it reads a single row, so this call refuses a forged
            // certificate and an unadmitted route with the same door.
            let mut sources: std::collections::BTreeSet<u32> = bonded_quotes
                .iter()
                .map(|bq| bq.quote.source_domain)
                .collect();
            sources.insert(intent.target_domain);
            for source_domain in sources {
                crate::settlement::finality_gate::check_certificate_value_gate(
                    cert,
                    crate::settlement::finality_gate::ValueGate::UniversalPayment,
                    source_domain,
                    Some(intent.target_domain),
                )
                .map_err(|err| {
                    UnificationExecutionError::PaymentFinalityRefused(format!(
                        "domain {source_domain} is not admitted by the certificate: {err}"
                    ))
                })?;
            }
        }
        let target_anchor = self
            .domains
            .get(&intent.target_domain)
            .ok_or(UnificationExecutionError::UnanchoredDomain(
                intent.target_domain,
            ))?
            .clone();
        let mut solver_by_quote: std::collections::BTreeMap<Hash32, Hash32> =
            std::collections::BTreeMap::new();
        let mut raw_quotes = Vec::with_capacity(bonded_quotes.len());
        for bq in bonded_quotes {
            let Some(solver) = self.solvers.get(&bq.solver_id) else {
                return Err(UnificationExecutionError::SolverBondInsufficient);
            };
            if solver.quarantined || solver.bonded_atoms == 0 {
                return Err(UnificationExecutionError::SolverBondInsufficient);
            }
            if solver_by_quote
                .insert(bq.quote.quote_id, bq.solver_id)
                .is_some()
            {
                return Err(UnificationExecutionError::Payment(
                    PaymentError::InvalidIntent(String::from("duplicate quote_id")),
                ));
            }
            raw_quotes.push(bq.quote.clone());
        }

        // Stage router + balances on clones so post-plan finality / conservation /
        // bond failures roll back cleanly without mutating caller state.
        let mut staged_router = self.router.clone();
        let mut staged_balances = balances.to_vec();
        let receipt = staged_router.settle_payment(
            intent,
            &mut staged_balances,
            &raw_quotes,
            now_unix_secs,
        )?;

        let mut staged_outflows: std::collections::BTreeMap<crate::domain::types::DomainId, u128> =
            std::collections::BTreeMap::new();
        let mut solver_exposure: std::collections::BTreeMap<Hash32, u128> =
            std::collections::BTreeMap::new();
        let mut staged_obligations: Vec<((Hash32, Hash32), (Hash32, u128))> = Vec::new();

        for leg in &receipt.legs {
            if self
                .spend_reservations
                .get(&(leg.source_domain, leg.source_asset_id, intent.payer_id))
                .is_some_and(|r| !r.confirmed)
            {
                return Err(
                    UnificationExecutionError::ConcurrentSpendReservationConflict {
                        domain_id: leg.source_domain,
                        asset_id: leg.source_asset_id,
                        owner_id: intent.payer_id,
                    },
                );
            }
            let src = self.domains.get(&leg.source_domain).ok_or(
                UnificationExecutionError::UnanchoredDomain(leg.source_domain),
            )?;
            if leg.source_domain != intent.target_domain {
                let _route = crate::settlement::finality_gate::evaluate_route_guarantee(
                    &src.guarantee,
                    &self.hub_guarantee,
                    &target_anchor.guarantee,
                )
                .ok_or(UnificationExecutionError::RouteFinalityInsufficient {
                    source_domain: leg.source_domain,
                    target_domain: intent.target_domain,
                })?;
                let econ = crate::settlement::universal_finality::EconomicSecurityBound::derive(
                    &src.guarantee,
                    src.slashable_bond_atoms,
                    src.routing_ceiling_atoms,
                );
                let cur = staged_outflows
                    .get(&leg.source_domain)
                    .copied()
                    .unwrap_or(src.epoch_outflow_atoms);
                let next_outflow = econ
                    .check_value_outflow_conservation(cur, leg.source_debited)
                    .map_err(|_| UnificationExecutionError::EconomicCeilingExceeded {
                        domain: leg.source_domain,
                    })?;
                staged_outflows.insert(leg.source_domain, next_outflow);
            } else if src.guarantee.fault_tolerance_bps == 0 {
                return Err(UnificationExecutionError::RouteFinalityInsufficient {
                    source_domain: leg.source_domain,
                    target_domain: intent.target_domain,
                });
            }

            if let Some(qid) = leg.quote_id {
                let solver_id = solver_by_quote
                    .get(&qid)
                    .copied()
                    .ok_or(UnificationExecutionError::SolverBondInsufficient)?;
                let solver = self
                    .solvers
                    .get(&solver_id)
                    .ok_or(UnificationExecutionError::SolverBondInsufficient)?;
                let exp = solver_exposure.entry(solver_id).or_insert(0);
                *exp = exp
                    .checked_add(leg.target_delivered)
                    .ok_or(UnificationExecutionError::SolverBondInsufficient)?;
                if *exp > solver.bonded_atoms {
                    return Err(UnificationExecutionError::SolverBondInsufficient);
                }
                staged_obligations
                    .push(((receipt.intent_id, qid), (solver_id, leg.target_delivered)));
            }
        }

        let credit_key = (
            intent.merchant_id,
            intent.target_domain,
            intent.target_asset_id,
        );
        let next_credit = self
            .merchant_credits
            .get(&credit_key)
            .copied()
            .unwrap_or(0)
            .checked_add(receipt.target_amount_delivered)
            .ok_or(UnificationExecutionError::Payment(
                PaymentError::ArithmeticOverflow,
            ))?;

        // Atomic commit: every check succeeded; apply all state mutations together.
        balances.clone_from_slice(&staged_balances);
        self.router = staged_router;
        for (dom, next_out) in staged_outflows {
            if let Some(entry) = self.domains.get_mut(&dom) {
                entry.epoch_outflow_atoms = next_out;
            }
        }
        for (key, val) in staged_obligations {
            self.settled_quote_obligations.insert(key, val);
        }
        self.merchant_credits.insert(credit_key, next_credit);
        Ok(receipt)
    }

    /// Execute an atomic cross-domain payment while validating live domain
    /// active/freeze status directly against core [`crate::core::account::AccountState`].
    ///
    /// WIRING: In-block split-tender settlement door wired to core `AccountState`
    /// domain freeze and status verification.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation when any
    /// registered target or leg source domain is non-active, or any route/balance
    /// check fails.
    pub fn execute_finality_gated_payment_with_account(
        &mut self,
        account_state: &crate::core::account::AccountState,
        intent: &UniversalPaymentIntent,
        balances: &mut [DomainTokenBalance],
        bonded_quotes: &[BondedLiquidityQuote],
        now_unix_secs: u64,
    ) -> Result<UniversalPaymentReceipt, UnificationExecutionError> {
        if let Some(target_dom) = account_state.settlement.domains.get(intent.target_domain) {
            if !target_dom.is_active() {
                return Err(UnificationExecutionError::InvalidArgument(format!(
                    "target domain {} is {:?}, not Active in AccountState",
                    intent.target_domain, target_dom.status
                )));
            }
        }
        let mut snapshot = self.clone();
        let mut staged_balances = balances.to_vec();
        let receipt = snapshot.execute_finality_gated_payment(
            intent,
            &mut staged_balances,
            bonded_quotes,
            now_unix_secs,
        )?;
        for leg in &receipt.legs {
            if let Some(src_dom) = account_state.settlement.domains.get(leg.source_domain) {
                if !src_dom.is_active() {
                    return Err(UnificationExecutionError::InvalidArgument(format!(
                        "source domain {} is {:?}, not Active in AccountState",
                        leg.source_domain, src_dom.status
                    )));
                }
            }
        }
        *self = snapshot;
        balances.clone_from_slice(&staged_balances);
        Ok(receipt)
    }

    /// Acquire an exclusive cross-domain spend lock on `(domain_id, asset_id, owner_id)`
    /// under strict [`CrossDomainWriteAuthority::SourceEscrow`] ownership.
    ///
    /// WIRING: Source-escrowed double-spend lock enforced across [`Self::execute_finality_gated_payment`],
    /// [`Self::confirm_cross_domain_spend`], and [`Self::release_expired_spend_reservation`].
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] without mutating state if the write
    /// authority is not `SourceEscrow`, `amount_atoms == 0`, the domain is
    /// unanchored or safety-breached, an active reservation already exists, or
    /// `balances` has insufficient available funds.
    pub fn reserve_exclusive_cross_domain_spend(
        &mut self,
        req: &SpendReservationRequest,
        balances: &mut [DomainTokenBalance],
    ) -> Result<Hash32, UnificationExecutionError> {
        let SpendReservationRequest {
            domain_id,
            asset_id,
            owner_id,
            amount_atoms,
            write_authority,
            current_height,
            ttl_blocks,
        } = *req;
        if write_authority != CrossDomainWriteAuthority::SourceEscrow {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "cross-domain spend reservations require SourceEscrow write authority",
            )));
        }
        if amount_atoms == 0 || owner_id == [0u8; 32] || ttl_blocks == 0 {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "spend reservation requires non-zero amount, owner_id, and ttl_blocks",
            )));
        }
        let anchor = self
            .domains
            .get(&domain_id)
            .ok_or(UnificationExecutionError::UnanchoredDomain(domain_id))?;
        if anchor.guarantee.fault_tolerance_bps == 0 {
            return Err(UnificationExecutionError::RouteFinalityInsufficient {
                source_domain: domain_id,
                target_domain: domain_id,
            });
        }
        let key = (domain_id, asset_id, owner_id);
        if self.spend_reservations.contains_key(&key) {
            return Err(
                UnificationExecutionError::ConcurrentSpendReservationConflict {
                    domain_id,
                    asset_id,
                    owner_id,
                },
            );
        }
        let bal_slot = balances
            .iter_mut()
            .find(|b| {
                b.domain_id == domain_id
                    && b.asset_id == asset_id
                    && b.available_amount >= amount_atoms
            })
            .ok_or(UnificationExecutionError::Payment(
                PaymentError::InsufficientMultiDomainLiquidity {
                    shortfall: amount_atoms,
                },
            ))?;
        bal_slot.available_amount -= amount_atoms;
        let reservation_id = hash_domain_fields(
            b"BDLM_ULEDGER_SPEND_LOCK_V1",
            &[
                &domain_id.to_le_bytes(),
                &asset_id,
                &owner_id,
                &amount_atoms.to_le_bytes(),
                &current_height.to_le_bytes(),
            ],
        );
        self.spend_reservations.insert(
            key,
            CrossDomainSpendReservation {
                reservation_id,
                domain_id,
                asset_id,
                owner_id,
                amount_atoms,
                write_authority,
                initiated_height: current_height,
                expires_at_height: current_height.saturating_add(ttl_blocks),
                confirmed: false,
            },
        );
        Ok(reservation_id)
    }

    /// Finalize an exclusive spend reservation once `domain_id`'s anchored
    /// finalized height reaches or passes `proof_height`.
    ///
    /// WIRING: Finality settlement confirmation paired with [`Self::reserve_exclusive_cross_domain_spend`].
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] if no unconfirmed reservation exists
    /// or `domain_id` has not finalized up to `proof_height`.
    pub fn confirm_cross_domain_spend(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        asset_id: Hash32,
        owner_id: Hash32,
        proof_height: u64,
    ) -> Result<(), UnificationExecutionError> {
        let anchor = self
            .domains
            .get(&domain_id)
            .ok_or(UnificationExecutionError::UnanchoredDomain(domain_id))?;
        if anchor.guarantee.fault_tolerance_bps == 0 || anchor.finalized_height < proof_height {
            return Err(UnificationExecutionError::InvalidArgument(format!(
                "domain {domain_id} finalized height {} lags proof height {proof_height}",
                anchor.finalized_height
            )));
        }
        let key = (domain_id, asset_id, owner_id);
        let Some(res) = self.spend_reservations.get_mut(&key) else {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "spend reservation not found",
            )));
        };
        if res.confirmed {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "spend reservation already finalized",
            )));
        }
        res.confirmed = true;
        Ok(())
    }

    /// Release an unconfirmed spend reservation back to `balances` once
    /// `current_height >= expires_at_height`.
    ///
    /// WIRING: Deterministic TTL expiry refund paired with [`Self::reserve_exclusive_cross_domain_spend`].
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] if missing, already finalized, or
    /// before expiry.
    pub fn release_expired_spend_reservation(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        asset_id: Hash32,
        owner_id: Hash32,
        current_height: u64,
        balances: &mut [DomainTokenBalance],
    ) -> Result<u128, UnificationExecutionError> {
        let key = (domain_id, asset_id, owner_id);
        let res = self.spend_reservations.get(&key).ok_or_else(|| {
            UnificationExecutionError::InvalidArgument(String::from("spend reservation not found"))
        })?;
        if res.confirmed {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "cannot refund an already finalized spend reservation",
            )));
        }
        if current_height < res.expires_at_height {
            return Err(UnificationExecutionError::InvalidArgument(format!(
                "spend reservation active until height {} (current={current_height})",
                res.expires_at_height
            )));
        }
        let bal_slot = balances
            .iter_mut()
            .find(|b| b.domain_id == domain_id && b.asset_id == asset_id)
            .ok_or(UnificationExecutionError::InvalidArgument(String::from(
                "target DomainTokenBalance missing for reservation refund",
            )))?;
        let amount = res.amount_atoms;
        bal_slot.available_amount = bal_slot.available_amount.saturating_add(amount);
        self.spend_reservations.remove(&key);
        Ok(amount)
    }

    /// Slash and quarantine the bonded solver responsible for an unfulfilled
    /// settled payment quote leg `(intent_id, quote_id)`.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError::InvalidSlashClaim`] if the obligation
    /// does not exist or has already been settled/slashed.
    ///
    /// WIRING: Objective solver-fault slashing hook for universal payment legs.
    pub fn slash_unfulfilled_payment_leg(
        &mut self,
        intent_id: Hash32,
        quote_id: Hash32,
    ) -> Result<SolverSlashReceipt, UnificationExecutionError> {
        // Validate both the settled obligation and the bonded solver record
        // before mutating any collection so refusals leave state intact.
        let Some(&(solver_id, obligation)) =
            self.settled_quote_obligations.get(&(intent_id, quote_id))
        else {
            return Err(UnificationExecutionError::InvalidSlashClaim);
        };
        if !self.solvers.contains_key(&solver_id) {
            return Err(UnificationExecutionError::InvalidSlashClaim);
        }
        self.settled_quote_obligations
            .remove(&(intent_id, quote_id));
        let slash_hash = if let Some(solver) = self.solvers.get_mut(&solver_id) {
            let penalty = obligation.min(solver.bonded_atoms);
            solver.bonded_atoms = solver.bonded_atoms.saturating_sub(penalty);
            solver.slashed_atoms = solver.slashed_atoms.saturating_add(penalty);
            solver.quarantined = true;
            let h = hash_domain_fields(
                b"BDLM_SOLVER_SLASH_V1",
                &[
                    &intent_id,
                    &quote_id,
                    &solver_id,
                    &penalty.to_le_bytes(),
                    &solver.bonded_atoms.to_le_bytes(),
                ],
            );
            (penalty, solver.bonded_atoms, h)
        } else {
            (0, 0, [0u8; 32])
        };
        self.slash_hashes.push(slash_hash.2);
        Ok(SolverSlashReceipt {
            intent_id,
            quote_id,
            solver_id,
            slashed_atoms: slash_hash.0,
            remaining_bond_atoms: slash_hash.1,
            slash_hash: slash_hash.2,
        })
    }

    /// Verify a 2D Reed-Solomon bad-encoding, row/col mismatch, or header
    /// equivocation fraud proof for an anchored DA `domain_id`, slash its bonded
    /// collateral proportionally, and halt further routing when quorum is broken.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation if the
    /// domain is unanchored or the DA fraud proof fails verification.
    ///
    /// WIRING: Live fraud-dispute settlement door calling [`crate::cross_domain::external::da_sampling::verify_da_fraud_proof`].
    pub fn apply_da_fraud_proof(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        network: &str,
        pinned: &crate::cross_domain::external::da_sampling::PinnedDaCommittee,
        proof: &crate::cross_domain::external::da_sampling::DaFraudProof,
    ) -> Result<crate::cross_domain::external::da_sampling::DaFraudVerdict, UnificationExecutionError>
    {
        if !self.domains.contains_key(&domain_id) {
            return Err(UnificationExecutionError::UnanchoredDomain(domain_id));
        }
        let verdict = crate::cross_domain::external::da_sampling::verify_da_fraud_proof(
            network, pinned, proof,
        )
        .map_err(|e| UnificationExecutionError::InvalidArgument(e.to_string()))?;
        if let Some(dom) = self.domains.get_mut(&domain_id) {
            let cut = mul_div_floor(
                dom.slashable_bond_atoms,
                verdict.slashed_weight,
                verdict.total_committee_weight.max(1),
            )
            .unwrap_or(dom.slashable_bond_atoms)
            .min(dom.slashable_bond_atoms);
            dom.slashable_bond_atoms = dom.slashable_bond_atoms.saturating_sub(cut);
            if verdict.quorum_safety_breached {
                dom.guarantee.fault_tolerance_bps = 0;
                dom.guarantee.slashable_backing = false;
                dom.routing_ceiling_atoms = 0;
            }
            let tag = hash_domain_fields(
                b"BDLM_ULEDGER_DOMAIN_SLASH_V1",
                &[
                    &domain_id.to_le_bytes(),
                    &verdict.height.to_le_bytes(),
                    &verdict.invalid_data_root,
                    &cut.to_le_bytes(),
                ],
            );
            self.slash_hashes.push(tag);
        }
        Ok(verdict)
    }

    /// Verify slashable DAG-BFT equivocation for an anchored `domain_id`, deduct
    /// the equivocating validators' proportional bond, and freeze cross-domain
    /// outflows if `>= 1/3` of committee weight equivocated.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation if the
    /// domain is unanchored or the equivocation proof fails verification.
    ///
    /// WIRING: Live slashing settlement door calling [`crate::cross_domain::external::dag_bft::verify_dag_equivocation_proof`].
    pub fn apply_dag_equivocation_proof(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        network: &str,
        pinned: &crate::cross_domain::external::dag_bft::PinnedDagCommittee,
        proof: &crate::cross_domain::external::dag_bft::DagEquivocationProof,
    ) -> Result<crate::cross_domain::external::dag_bft::DagSlashVerdict, UnificationExecutionError>
    {
        if !self.domains.contains_key(&domain_id) {
            return Err(UnificationExecutionError::UnanchoredDomain(domain_id));
        }
        let verdict = crate::cross_domain::external::dag_bft::verify_dag_equivocation_proof(
            network, pinned, proof,
        )
        .map_err(|e| UnificationExecutionError::InvalidArgument(e.to_string()))?;
        if let Some(dom) = self.domains.get_mut(&domain_id) {
            let cut = mul_div_floor(
                dom.slashable_bond_atoms,
                verdict.slashed_weight,
                verdict.total_committee_weight.max(1),
            )
            .unwrap_or(dom.slashable_bond_atoms)
            .min(dom.slashable_bond_atoms);
            dom.slashable_bond_atoms = dom.slashable_bond_atoms.saturating_sub(cut);
            if verdict.quorum_safety_breached {
                dom.guarantee.fault_tolerance_bps = 0;
                dom.guarantee.slashable_backing = false;
                dom.routing_ceiling_atoms = 0;
            }
            let tag = hash_domain_fields(
                b"BDLM_ULEDGER_DOMAIN_SLASH_V1",
                &[
                    &domain_id.to_le_bytes(),
                    &verdict.epoch.to_le_bytes(),
                    &verdict.round.to_le_bytes(),
                    &cut.to_le_bytes(),
                ],
            );
            self.slash_hashes.push(tag);
        }
        Ok(verdict)
    }

    /// Advance an anchored PoSpace+time domain's finalized state root only after
    /// verifying a coupled [`crate::consensus::pospace::SpaceTimeDelayProof`]
    /// (signage-point filter, challenged Merkle opening, and sequential checkpoints).
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation if the
    /// domain is unanchored, height does not advance, `next_state_root` is zero,
    /// or the space-time delay proof is invalid.
    ///
    /// WIRING: Connects [`crate::consensus::pospace::verify_space_time_delay`] to
    /// unified domain progression.
    pub fn advance_pospace_domain_with_delay(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        proof: &crate::consensus::pospace::SpaceTimeDelayProof,
        expected_challenge: &Hash32,
        min_plot_size_bytes: u64,
        params: crate::consensus::pospace::SpaceTimeDelayParams,
        next_anchor: (u64, Hash32),
    ) -> Result<(), UnificationExecutionError> {
        let (next_height, next_state_root) = next_anchor;
        let Some(existing) = self.domains.get(&domain_id) else {
            return Err(UnificationExecutionError::UnanchoredDomain(domain_id));
        };
        if next_state_root == [0u8; 32] || next_height <= existing.finalized_height {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "PoSpace progression requires non-zero root and strictly increasing height",
            )));
        }
        crate::consensus::pospace::verify_space_time_delay(
            proof,
            expected_challenge,
            min_plot_size_bytes,
            params.filter_bits,
            params.difficulty,
            params.max_iterations,
        )
        .map_err(|e| UnificationExecutionError::InvalidArgument(e.to_string()))?;
        if let Some(dom) = self.domains.get_mut(&domain_id) {
            dom.finalized_height = next_height;
            dom.finalized_state_root = next_state_root;
        }
        Ok(())
    }

    /// Deterministically validate, finality-check, gas-cap, and commit an atomic
    /// multi-VM [`OutputCompositionPlan`] into the ledger.
    ///
    /// Every participating step's `domain_id` must be anchored with non-zero
    /// fault tolerance and `finalized_height >= min_finalized_height`.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] with zero state mutation on any
    /// failed step, unanchored domain, gas cap breach, or bundle replay.
    ///
    /// WIRING: In-block multi-VM unified output commitment entry point.
    pub fn commit_finalized_output_bundle(
        &mut self,
        plan: &OutputCompositionPlan,
        min_finalized_height: u64,
        max_bundle_gas_bgu: u64,
    ) -> Result<UnifiedOutputBundle, UnificationExecutionError> {
        if self.committed_bundles.len() >= MAX_LEDGER_BUNDLES {
            return Err(UnificationExecutionError::CapacityExceeded);
        }
        for step in &plan.steps {
            let anchor = self
                .domains
                .get(&step.domain_id)
                .ok_or(UnificationExecutionError::UnanchoredDomain(step.domain_id))?;
            if anchor.guarantee.fault_tolerance_bps == 0
                || !anchor.guarantee.attestation.state_root
                || anchor.finalized_height < min_finalized_height
            {
                return Err(UnificationExecutionError::BundleRejected(
                    step.step_id.clone(),
                ));
            }
        }
        let bundle = OutputComposer::compose(plan)?;
        if bundle.total_gas_bgu > max_bundle_gas_bgu
            || self.committed_bundles.contains_key(&bundle.bundle_root)
        {
            return Err(UnificationExecutionError::BundleRejected(bundle.plan_id));
        }
        self.committed_bundles
            .insert(bundle.bundle_root, bundle.steps_merkle_root);
        Ok(bundle)
    }

    /// Execute an all-or-nothing atomic storage deal: settles a finality-gated
    /// split-tender payment, registers `record` under authenticated `owner_id`
    /// only after verifying every replica against its cryptographic
    /// [`StorageReplicaProof`] (including anchored domain state roots for
    /// [`StorageReplicaProof::ExternalDomainMerkle`]), and optionally binds
    /// `bns_name` to `record.sha3_256_digest`.
    ///
    /// If replica proof verification, object registration, or BNS binding fails
    /// (for example, claiming `ErasureVerified` without a valid `Bud3Custody`
    /// proof or attempting to hijack another owner's `bns://` name), the entire
    /// payment, quote fill, domain outflow, and merchant credit roll back
    /// atomically.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] leaving both `balances` and `self`
    /// bit-for-bit identical to their pre-call state on any failure.
    ///
    /// WIRING: Unified storage deal + cross-chain split-tender settlement transition.
    pub fn execute_atomic_storage_deal(
        &mut self,
        deal: AtomicStorageDeal<'_>,
        balances: &mut [DomainTokenBalance],
    ) -> Result<(UniversalPaymentReceipt, Hash32), UnificationExecutionError> {
        let AtomicStorageDeal {
            owner_id,
            mut record,
            replica_proofs,
            bns_name,
            intent,
            bonded_quotes,
            now_unix_secs,
        } = deal;
        if owner_id != intent.payer_id {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "storage deal owner_id must equal payment intent payer_id",
            )));
        }
        if record.replicas.len() != replica_proofs.len() {
            return Err(UnificationExecutionError::InvalidArgument(format!(
                "storage deal replica count ({}) must match replica_proofs count ({})",
                record.replicas.len(),
                replica_proofs.len()
            )));
        }
        let digest = record.sha3_256_digest;
        let candidate_replicas = std::mem::take(&mut record.replicas);
        let Some(mut seed_replica) = candidate_replicas.first().cloned() else {
            return Err(UnificationExecutionError::Storage(
                StorageFabricError::InvalidMetadata(String::from(
                    "content record must declare at least one replica",
                )),
            ));
        };
        for proof in replica_proofs {
            if let StorageReplicaProof::ExternalDomainMerkle {
                domain_id,
                finalized_state_root,
                ..
            } = proof
            {
                let anchor = self
                    .domains
                    .get(domain_id)
                    .ok_or(UnificationExecutionError::UnanchoredDomain(*domain_id))?;
                if anchor.guarantee.fault_tolerance_bps == 0
                    || !anchor.guarantee.attestation.state_root
                    || anchor.finalized_state_root != *finalized_state_root
                {
                    return Err(UnificationExecutionError::InvalidArgument(format!(
                        "external storage domain {domain_id} finalized_state_root is not anchored with state_root attestation"
                    )));
                }
            }
        }
        seed_replica.verification = VerificationStrength::AttestedDeal;
        record.replicas.push(seed_replica);

        let mut snapshot = self.clone();
        let mut staged_balances = balances.to_vec();
        let receipt = snapshot.execute_finality_gated_payment(
            intent,
            &mut staged_balances,
            bonded_quotes,
            now_unix_secs,
        )?;
        let mut record_hash = snapshot.storage.register_owned_object(owner_id, record)?;
        for (replica, proof) in candidate_replicas.into_iter().zip(replica_proofs.iter()) {
            record_hash = snapshot
                .storage
                .verify_and_attach_replica(&digest, replica, proof)?;
        }
        if let Some(name) = bns_name {
            snapshot
                .storage
                .bind_owned_bns_name(owner_id, name, digest)?;
        }
        *self = snapshot;
        balances.clone_from_slice(&staged_balances);
        Ok((receipt, record_hash))
    }

    /// Read-only view of the underlying owner-authenticated storage fabric.
    ///
    /// WIRING: Exposes verified replica resolution over committed storage deals.
    #[must_use]
    pub const fn storage_fabric(&self) -> &UnifiedStorageFabric {
        &self.storage
    }

    /// Read-only lookup of a merchant's settled credit balance for `(domain, asset)`.
    ///
    /// WIRING: Exposes atomic settlement credit accounting for callers and audits.
    #[must_use]
    pub fn merchant_credit(
        &self,
        merchant_id: &Hash32,
        domain_id: crate::domain::types::DomainId,
        asset_id: &Hash32,
    ) -> u128 {
        self.merchant_credits
            .get(&(*merchant_id, domain_id, *asset_id))
            .copied()
            .unwrap_or(0)
    }

    /// Compute the single deterministic 32-byte Merkle state root committing to
    /// all domain anchors/outflows, solver bonds/slashes, payment router fills,
    /// merchant credits, committed multi-VM bundles, and storage fabric records.
    ///
    /// WIRING: Block-level commitment root for unified settlement state.
    #[must_use]
    pub fn state_root(&self) -> Hash32 {
        let domain_leaves: Vec<Hash32> = self
            .domains
            .values()
            .map(|d| {
                hash_domain_fields(
                    b"BDLM_ULEDGER_DOMAIN_V1",
                    &[
                        &d.domain_id.to_le_bytes(),
                        &d.guarantee.fault_tolerance_bps.to_le_bytes(),
                        &[u8::from(d.guarantee.slashable_backing)],
                        &d.slashable_bond_atoms.to_le_bytes(),
                        &d.routing_ceiling_atoms.to_le_bytes(),
                        &d.finalized_height.to_le_bytes(),
                        &d.finalized_state_root,
                        &d.epoch_outflow_atoms.to_le_bytes(),
                    ],
                )
            })
            .collect();
        let solver_leaves: Vec<Hash32> = self
            .solvers
            .values()
            .map(|s| {
                hash_domain_fields(
                    b"BDLM_ULEDGER_SOLVER_V1",
                    &[
                        &s.solver_id,
                        &s.bonded_atoms.to_le_bytes(),
                        &s.slashed_atoms.to_le_bytes(),
                        &[u8::from(s.quarantined)],
                    ],
                )
            })
            .collect();
        let credit_leaves: Vec<Hash32> = self
            .merchant_credits
            .iter()
            .map(|((merchant, dom, asset), amt)| {
                hash_domain_fields(
                    b"BDLM_ULEDGER_CREDIT_V1",
                    &[merchant, &dom.to_le_bytes(), asset, &amt.to_le_bytes()],
                )
            })
            .collect();
        let bundle_leaves: Vec<Hash32> = self
            .committed_bundles
            .iter()
            .map(|(b_root, s_root)| {
                hash_domain_fields(b"BDLM_ULEDGER_BUNDLE_V1", &[b_root, s_root])
            })
            .collect();
        let domains_root = unification_merkle_root(b"BDLM_ULEDGER_DOMAINS_V1", &domain_leaves);
        let solvers_root = unification_merkle_root(b"BDLM_ULEDGER_SOLVERS_V1", &solver_leaves);
        let slashes_root = unification_merkle_root(b"BDLM_ULEDGER_SLASHES_V1", &self.slash_hashes);
        let credits_root = unification_merkle_root(b"BDLM_ULEDGER_CREDITS_V1", &credit_leaves);
        let bundles_root = unification_merkle_root(b"BDLM_ULEDGER_BUNDLES_V1", &bundle_leaves);
        let router_root = self.router.state_commitment();
        let storage_root = self.storage.state_root();
        let reservation_leaves: Vec<Hash32> = self
            .spend_reservations
            .values()
            .map(|r| {
                let auth_tag: [u8; 1] = [match r.write_authority {
                    CrossDomainWriteAuthority::SourceEscrow => 1,
                    CrossDomainWriteAuthority::TargetRelay => 2,
                }];
                hash_domain_fields(
                    b"BDLM_ULEDGER_SPEND_RES_V1",
                    &[
                        &r.reservation_id,
                        &r.domain_id.to_le_bytes(),
                        &r.asset_id,
                        &r.owner_id,
                        &r.amount_atoms.to_le_bytes(),
                        &auth_tag,
                        &r.initiated_height.to_le_bytes(),
                        &r.expires_at_height.to_le_bytes(),
                        &[u8::from(r.confirmed)],
                    ],
                )
            })
            .collect();
        let reservations_root =
            unification_merkle_root(b"BDLM_ULEDGER_SPEND_LOCKS_V1", &reservation_leaves);
        if self.spend_reservations.is_empty() {
            hash_domain_fields(
                b"BDLM_UNIFICATION_STATE_ROOT_V1",
                &[
                    &domains_root,
                    &solvers_root,
                    &slashes_root,
                    &credits_root,
                    &bundles_root,
                    &router_root,
                    &storage_root,
                ],
            )
        } else {
            hash_domain_fields(
                b"BDLM_UNIFICATION_STATE_ROOT_V1",
                &[
                    &domains_root,
                    &solvers_root,
                    &slashes_root,
                    &credits_root,
                    &bundles_root,
                    &router_root,
                    &storage_root,
                    &reservations_root,
                ],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_settlement_backed_by_a_forged_certificate_is_refused_before_any_debit() {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::universal_finality::{
            compose, DomainFinalityEntry, FinalityGuarantee, FinalityReversibility,
            FinalityVerdict, FINALITY_BINDS_ALL,
        };
        use crate::unification::payment_router::RATE_SCALE;

        let hub_g = FinalityGuarantee::settlement_hub();
        let mut ledger = UnificationLedger::new(hub_g);
        ledger
            .anchor_domain_finality(1, hub_g, 3_000, 10_000, 100, [0x11; 32])
            .expect("anchor d1");
        ledger
            .anchor_domain_finality(3, hub_g, 50_000, 50_000, 200, [0x33; 32])
            .expect("anchor d3");
        let solver = [0x50; 32];
        ledger.bond_solver(solver, 1_000).expect("bond solver");

        let asset_d1 = [0x01; 32];
        let usdc_d3 = [0x03; 32];
        let mut bals = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: asset_d1,
            symbol: "BUD".into(),
            available_amount: 2_000,
        }];
        let quote = BondedLiquidityQuote {
            solver_id: solver,
            quote: LiquidityQuote {
                quote_id: [0x82; 32],
                source_domain: 1,
                source_asset_id: asset_d1,
                target_domain: 3,
                target_asset_id: usdc_d3,
                rate_scaled: RATE_SCALE,
                fee_bps: 0,
                max_target_liquidity: 500,
                valid_until_unix_secs: 5_000,
            },
        };
        let intent = UniversalPaymentIntent {
            payer_id: [0xA1; 32],
            merchant_id: [0xC3; 32],
            nonce: 1,
            target_domain: 3,
            target_asset_id: usdc_d3,
            target_amount: 100,
            max_slippage_bps: 50,
            deadline_unix_secs: 5_000,
            invoice_hash: [0x91; 32],
            rail: PaymentRail::OnChain,
        };

        let row = |domain_id: u32| DomainFinalityEntry {
            domain_id,
            height: 1,
            checkpoint_height: 10,
            state_root: [0x30; 32],
            adapter_id: "test-adapter".into(),
            adapter_version: 1,
            finality_proof_hash: [0x33; 32],
            guarantee_backing_hash: [0xBB; 32],
            bond_atoms: 3_000,
            guarantee: FinalityGuarantee {
                reversibility: FinalityReversibility::CryptographicValidity,
                quantum_posture: QuantumClass::Hash,
                attestation: FINALITY_BINDS_ALL,
                slashable_backing: false,
                fault_tolerance_bps: 9_999,
            },
            verdict: FinalityVerdict::Established,
        };
        let good = compose(&[row(1), row(3)]).expect("compose certificate");
        let mut forged = good.clone();
        forged.established_count = forged.established_count.saturating_add(1);

        // The forged certificate is refused before any staging, so neither the
        // caller's balances nor the ledger move.
        let root_before = ledger.state_root();
        let refused = ledger.execute_finality_gated_payment_checked(
            &intent,
            &mut bals,
            &[quote.clone()],
            1_000,
            Some(&forged),
        );
        assert!(
            matches!(
                refused,
                Err(UnificationExecutionError::PaymentFinalityRefused(_))
            ),
            "a forged certificate must refuse the settlement: {refused:?}"
        );
        assert_eq!(bals[0].available_amount, 2_000, "no debit on refusal");
        assert_eq!(
            ledger.state_root(),
            root_before,
            "no state change on refusal"
        );

        // The same settlement, backed by the intact certificate, is not refused
        // for its seal: the refusal above was the seal, not a blanket "no".
        let admitted = ledger.execute_finality_gated_payment_checked(
            &intent,
            &mut bals,
            &[quote],
            1_000,
            Some(&good),
        );
        assert!(
            !matches!(
                admitted,
                Err(UnificationExecutionError::PaymentFinalityRefused(_))
            ),
            "an intact certificate must not be refused for its seal: {admitted:?}"
        );

        // The unchecked door keeps its old contract: the ledger anchor alone
        // decides, so the forged certificate cannot reach it at all.
        let mut unchecked_bals = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: asset_d1,
            symbol: "BUD".into(),
            available_amount: 2_000,
        }];
        let unchecked =
            ledger.execute_finality_gated_payment(&intent, &mut unchecked_bals, &[], 1_000);
        assert!(
            !matches!(
                unchecked,
                Err(UnificationExecutionError::PaymentFinalityRefused(_))
            ),
            "the unchecked entry point never raises a certificate refusal: {unchecked:?}"
        );
    }

    #[test]
    fn wide_mul_div_avoids_u128_intermediate_overflow_and_rounds_safely() {
        let big = u128::MAX / 2;
        assert_eq!(mul_div_floor(big, 4, 4), Some(big));
        assert_eq!(mul_div_ceil(big, 4, 4), Some(big));
        // Rounding up protects payments from rounding down to zero.
        assert_eq!(mul_div_floor(1, 1, 1_000_000), Some(0));
        assert_eq!(mul_div_ceil(1, 1, 1_000_000), Some(1));
        assert_eq!(mul_div_ceil(10, 3, 4), Some(8));
        assert_eq!(mul_div_floor(10, 3, 4), Some(7));
        assert_eq!(mul_div_ceil(1, 1, 0), None);
        assert_eq!(mul_div_floor(u128::MAX, 2, 1), None);
    }

    #[test]
    fn merkle_proofs_verify_and_reject_tampering() {
        let leaves: Vec<Hash32> = (0u8..5).map(|i| [i.wrapping_add(1); 32]).collect();
        let root = unification_merkle_root(b"TEST_MERKLE", &leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = build_merkle_proof(b"TEST_MERKLE", &leaves, i).unwrap();
            assert!(verify_merkle_proof(
                b"TEST_MERKLE",
                &root,
                i,
                leaves.len(),
                leaf,
                &proof
            ));
            let mut bad_leaf = *leaf;
            bad_leaf[0] ^= 0xFF;
            assert!(!verify_merkle_proof(
                b"TEST_MERKLE",
                &root,
                i,
                leaves.len(),
                &bad_leaf,
                &proof
            ));
        }

        // Odd-leaf trees must never self-duplicate the trailing node into an
        // even sibling pair: [a, b, c] and [a, b, c, c] must produce distinct
        // internal fold structure and distinct roots at every odd level.
        let three = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
        let proof_last = build_merkle_proof(b"TEST_MERKLE", &three, 2).unwrap();
        let leaf2_hash = merkle_leaf_hash(b"TEST_MERKLE", 2, &three[2]);
        assert!(
            !proof_last.contains(&leaf2_hash),
            "odd trailing leaf was self-duplicated as its own sibling (CVE-2012-2459)"
        );
        let four_dup = vec![[0x11; 32], [0x22; 32], [0x33; 32], [0x33; 32]];
        assert_ne!(
            unification_merkle_root(b"TEST_MERKLE", &three),
            unification_merkle_root(b"TEST_MERKLE", &four_dup)
        );
        // Verify completeness and extra-sibling rejection for every leaf count 1..=11.
        for n in 1usize..=11 {
            let set: Vec<Hash32> = (0..n).map(|k| [(k as u8).wrapping_add(9); 32]).collect();
            let r = unification_merkle_root(b"TEST_MERKLE", &set);
            for (idx, item) in set.iter().enumerate() {
                let mut prf = build_merkle_proof(b"TEST_MERKLE", &set, idx).expect("proof");
                assert!(verify_merkle_proof(b"TEST_MERKLE", &r, idx, n, item, &prf));
                assert!(!verify_merkle_proof(
                    b"TEST_MERKLE",
                    &r,
                    idx,
                    n + 1,
                    item,
                    &prf
                ));
                prf.push([0xAA; 32]);
                assert!(!verify_merkle_proof(b"TEST_MERKLE", &r, idx, n, item, &prf));
            }
        }
    }

    #[test]
    fn unification_ledger_enforces_finality_conservation_slashing_and_atomic_rollback() {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};
        use crate::unification::payment_router::RATE_SCALE;
        use budlum_uel_abi::EeId;
        use std::collections::BTreeMap;

        let full_att = CommitmentAttestation {
            state_root: true,
            tx_root: true,
            event_root: true,
            parent: true,
        };
        let hub_g = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: full_att,
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        };
        let unslashable_g = FinalityGuarantee {
            slashable_backing: false,
            ..hub_g
        };

        let mut ledger = UnificationLedger::new(hub_g);
        // Domain 1: bonded slashable source (bond 3_000 -> safe ceiling = 999 atoms).
        ledger
            .anchor_domain_finality(1, hub_g, 3_000, 10_000, 100, [0x11; 32])
            .expect("anchor d1");
        // Domain 2: unslashable authority chain (admits_cross_domain_value == false).
        ledger
            .anchor_domain_finality(2, unslashable_g, 0, 10_000, 100, [0x22; 32])
            .expect("anchor d2");
        // Domain 3: bonded target settlement domain.
        ledger
            .anchor_domain_finality(3, hub_g, 50_000, 50_000, 200, [0x33; 32])
            .expect("anchor d3");

        let solver = [0x50; 32];
        ledger.bond_solver(solver, 1_000).expect("bond solver");

        let alice = [0xA1; 32];
        let bob = [0xB2; 32];
        let merchant = [0xC3; 32];
        let asset_d1 = [0x01; 32];
        let asset_d2 = [0x02; 32];
        let usdc_d3 = [0x03; 32];

        // 1. Unslashable source domain 2 is rejected with zero state mutation.
        let root_before = ledger.state_root();
        let mut unslash_bals = vec![DomainTokenBalance {
            domain_id: 2,
            asset_id: asset_d2,
            symbol: "POA".into(),
            available_amount: 500,
        }];
        let q_unslash = BondedLiquidityQuote {
            solver_id: solver,
            quote: LiquidityQuote {
                quote_id: [0x81; 32],
                source_domain: 2,
                source_asset_id: asset_d2,
                target_domain: 3,
                target_asset_id: usdc_d3,
                rate_scaled: RATE_SCALE,
                fee_bps: 0,
                max_target_liquidity: 500,
                valid_until_unix_secs: 5_000,
            },
        };
        let bad_intent = UniversalPaymentIntent {
            payer_id: alice,
            merchant_id: merchant,
            nonce: 1,
            target_domain: 3,
            target_asset_id: usdc_d3,
            target_amount: 100,
            max_slippage_bps: 50,
            deadline_unix_secs: 5_000,
            invoice_hash: [0x91; 32],
            rail: PaymentRail::OnChain,
        };
        assert_eq!(
            ledger.execute_finality_gated_payment(
                &bad_intent,
                &mut unslash_bals,
                &[q_unslash],
                1_000
            ),
            Err(UnificationExecutionError::RouteFinalityInsufficient {
                source_domain: 2,
                target_domain: 3
            })
        );
        assert_eq!(unslash_bals[0].available_amount, 500);
        assert_eq!(ledger.state_root(), root_before);

        // 2. Outflow exceeding safe_value_outflow_ceiling_atoms (999) rolls back cleanly.
        let mut alice_bals = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: asset_d1,
            symbol: "BUD".into(),
            available_amount: 2_000,
        }];
        let q_d1 = BondedLiquidityQuote {
            solver_id: solver,
            quote: LiquidityQuote {
                quote_id: [0x82; 32],
                source_domain: 1,
                source_asset_id: asset_d1,
                target_domain: 3,
                target_asset_id: usdc_d3,
                rate_scaled: RATE_SCALE,
                fee_bps: 0,
                max_target_liquidity: 1_500,
                valid_until_unix_secs: 5_000,
            },
        };
        let over_ceiling = UniversalPaymentIntent {
            target_amount: 1_000,
            nonce: 2,
            ..bad_intent.clone()
        };
        assert_eq!(
            ledger.execute_finality_gated_payment(
                &over_ceiling,
                &mut alice_bals,
                std::slice::from_ref(&q_d1),
                1_000
            ),
            Err(UnificationExecutionError::EconomicCeilingExceeded { domain: 1 })
        );
        assert_eq!(alice_bals[0].available_amount, 2_000);
        assert_eq!(ledger.state_root(), root_before);

        assert_forged_storage_deal_replicas_roll_back(
            &mut ledger,
            alice,
            &bad_intent,
            &q_d1,
            &mut alice_bals,
            root_before,
        );

        // 3. Atomic storage deal + BNS registration settles cleanly for Alice.
        let mut alice_site = UnifiedContentRecord::from_bytes(b"<h1>alice</h1>", "text/html");
        let alice_digest = alice_site.sha3_256_digest;
        alice_site.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: 1,
            native_locator: hex::encode(alice_digest),
            verification: VerificationStrength::ErasureVerified,
            available: true,
            latency_ms: 5,
        });
        let alice_proofs = [StorageReplicaProof::Bud3Custody {
            data_shards: 4,
            parity_shards: 2,
            custody_merkle_root: [0xA1; 32],
        }];
        let alice_deal = UniversalPaymentIntent {
            target_amount: 400,
            nonce: 3,
            ..bad_intent.clone()
        };
        let (deal_receipt, _) = ledger
            .execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: alice_site,
                    replica_proofs: &alice_proofs,
                    bns_name: Some("alice.bud"),
                    intent: &alice_deal,
                    bonded_quotes: std::slice::from_ref(&q_d1),
                    now_unix_secs: 1_000,
                },
                &mut alice_bals,
            )
            .expect("atomic storage deal succeeds");
        assert_eq!(alice_bals[0].available_amount, 1_600);
        assert_eq!(ledger.merchant_credit(&merchant, 3, &usdc_d3), 400);
        assert!(ledger
            .storage_fabric()
            .resolve("bns://alice.bud", VerificationStrength::ErasureVerified)
            .is_ok());

        // 4. Bob tries to hijack `bns://alice.bud` inside a paid storage deal:
        //    BNS authorization fails AND Bob's payment, quote fill, merchant credit,
        //    and ledger state_root all roll back bit-for-bit!
        let root_after_alice = ledger.state_root();
        let mut bob_bals = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: asset_d1,
            symbol: "BUD".into(),
            available_amount: 900,
        }];
        let mut bob_site = UnifiedContentRecord::from_bytes(b"<h1>hijack</h1>", "text/html");
        let bob_digest = bob_site.sha3_256_digest;
        bob_site.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: 1,
            native_locator: hex::encode(bob_digest),
            verification: VerificationStrength::ErasureVerified,
            available: true,
            latency_ms: 5,
        });
        let bob_proofs = [StorageReplicaProof::Bud3Custody {
            data_shards: 4,
            parity_shards: 2,
            custody_merkle_root: [0xB2; 32],
        }];
        let bob_deal = UniversalPaymentIntent {
            payer_id: bob,
            merchant_id: merchant,
            nonce: 1,
            target_domain: 3,
            target_asset_id: usdc_d3,
            target_amount: 200,
            max_slippage_bps: 50,
            deadline_unix_secs: 5_000,
            invoice_hash: [0x95; 32],
            rail: PaymentRail::OnChain,
        };
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: bob,
                    record: bob_site,
                    replica_proofs: &bob_proofs,
                    bns_name: Some("alice.bud"),
                    intent: &bob_deal,
                    bonded_quotes: std::slice::from_ref(&q_d1),
                    now_unix_secs: 1_000,
                },
                &mut bob_bals,
            ),
            Err(UnificationExecutionError::Storage(
                StorageFabricError::UnauthorizedOwner(_)
            ))
        ));
        assert_eq!(bob_bals[0].available_amount, 900);
        assert_eq!(ledger.merchant_credit(&merchant, 3, &usdc_d3), 400);
        assert_eq!(ledger.state_root(), root_after_alice);

        // 5. Commit a finalized multi-VM (EVM + WASM) bundle and reject replay / over-gas.
        let mut evm_vals = BTreeMap::new();
        evm_vals.insert(String::from("quote"), CanonicalValue::U128(400));
        let step_evm = NormalizedMachineOutput {
            step_id: String::from("evm_step"),
            ee_id: EeId::EVM.0,
            language: LanguageTag::Solidity,
            domain_id: 1,
            succeeded: true,
            gas_used_bgu: 21_000,
            return_data: vec![1, 2],
            typed_values: evm_vals,
            events: Vec::new(),
            state_effects: Vec::new(),
        };
        let mut wasm_vals = BTreeMap::new();
        wasm_vals.insert(String::from("in_quote"), CanonicalValue::U128(400));
        let step_wasm = NormalizedMachineOutput {
            step_id: String::from("wasm_step"),
            ee_id: EeId::WASM.0,
            language: LanguageTag::RustCosmWasm,
            domain_id: 3,
            succeeded: true,
            gas_used_bgu: 5_000,
            return_data: vec![3, 4],
            typed_values: wasm_vals,
            events: Vec::new(),
            state_effects: Vec::new(),
        };
        let plan = OutputCompositionPlan {
            plan_id: String::from("atomic_evm_wasm"),
            steps: vec![step_evm, step_wasm],
            bindings: vec![OutputBinding {
                from_step: String::from("evm_step"),
                selector: OutputSelector::TypedField {
                    key: String::from("quote"),
                },
                to_step: String::from("wasm_step"),
                target_input: String::from("in_quote"),
                enforce_match: true,
            }],
        };
        // Reject when min_finalized_height exceeds domain 1's height (100).
        assert!(ledger
            .commit_finalized_output_bundle(&plan, 150, 10_000_000)
            .is_err());
        let bundle = ledger
            .commit_finalized_output_bundle(&plan, 100, 10_000_000)
            .expect("commit finalized bundle");
        // Duplicate replay rejected.
        assert!(ledger
            .commit_finalized_output_bundle(&plan, 100, 10_000_000)
            .is_err());
        assert_ne!(bundle.bundle_root, [0u8; 32]);

        // 6. Slash defaulting solver on Alice's settled quote leg and quarantine solver.
        let slash = ledger
            .slash_unfulfilled_payment_leg(deal_receipt.intent_id, [0x82; 32])
            .expect("slash defaulting solver");
        assert_eq!(slash.slashed_atoms, 400);
        assert_eq!(slash.remaining_bond_atoms, 600);
        // Double-slash rejected; quarantined solver blocked from future deals.
        assert_eq!(
            ledger.slash_unfulfilled_payment_leg(deal_receipt.intent_id, [0x82; 32]),
            Err(UnificationExecutionError::InvalidSlashClaim)
        );
        assert_eq!(
            ledger.execute_finality_gated_payment(&bob_deal, &mut bob_bals, &[q_d1], 1_000),
            Err(UnificationExecutionError::SolverBondInsufficient)
        );
    }

    fn assert_forged_storage_deal_replicas_roll_back(
        ledger: &mut UnificationLedger,
        alice: Hash32,
        template_intent: &UniversalPaymentIntent,
        bonded_quote: &BondedLiquidityQuote,
        alice_bals: &mut [DomainTokenBalance],
        expected_root: Hash32,
    ) {
        let initial_balance = alice_bals[0].available_amount;
        let deal_intent = UniversalPaymentIntent {
            target_amount: 100,
            nonce: 290,
            ..template_intent.clone()
        };

        // (a) Empty replica set fails closed with InvalidMetadata.
        let empty_site = UnifiedContentRecord::from_bytes(b"<h1>empty</h1>", "text/html");
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: empty_site,
                    replica_proofs: &[],
                    bns_name: Some("empty.bud"),
                    intent: &deal_intent,
                    bonded_quotes: std::slice::from_ref(bonded_quote),
                    now_unix_secs: 1_000,
                },
                alice_bals,
            ),
            Err(UnificationExecutionError::Storage(
                StorageFabricError::InvalidMetadata(_)
            ))
        ));

        // (b) Missing replica proof (count mismatch) fails closed.
        let mut unproven_site = UnifiedContentRecord::from_bytes(b"<h1>unproven</h1>", "text/html");
        let unproven_digest = unproven_site.sha3_256_digest;
        unproven_site.replicas.push(StorageReplica {
            network: StorageNetworkKind::Bud3,
            domain_id: 1,
            native_locator: hex::encode(unproven_digest),
            verification: VerificationStrength::ErasureVerified,
            available: true,
            latency_ms: 5,
        });
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: unproven_site.clone(),
                    replica_proofs: &[],
                    bns_name: Some("unproven.bud"),
                    intent: &deal_intent,
                    bonded_quotes: std::slice::from_ref(bonded_quote),
                    now_unix_secs: 1_000,
                },
                alice_bals,
            ),
            Err(UnificationExecutionError::InvalidArgument(_))
        ));

        // (c) Claiming ErasureVerified with only a DeclaredDealOnly commitment fails
        //     after payment staging and rolls back balances, credits, and state_root.
        let weak_proof = [StorageReplicaProof::DeclaredDealOnly {
            deal_commitment: [0x44; 32],
        }];
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: unproven_site.clone(),
                    replica_proofs: &weak_proof,
                    bns_name: Some("unproven.bud"),
                    intent: &deal_intent,
                    bonded_quotes: std::slice::from_ref(bonded_quote),
                    now_unix_secs: 1_000,
                },
                alice_bals,
            ),
            Err(UnificationExecutionError::Storage(
                StorageFabricError::InvalidMetadata(_)
            ))
        ));

        // (d) Forged Bud3Custody proof (zero custody root) and tampered IPFS preimage
        //     both fail closed and leave ledger state untouched.
        let bad_bud3 = [StorageReplicaProof::Bud3Custody {
            data_shards: 4,
            parity_shards: 2,
            custody_merkle_root: [0u8; 32],
        }];
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: unproven_site,
                    replica_proofs: &bad_bud3,
                    bns_name: Some("unproven.bud"),
                    intent: &deal_intent,
                    bonded_quotes: std::slice::from_ref(bonded_quote),
                    now_unix_secs: 1_000,
                },
                alice_bals,
            ),
            Err(UnificationExecutionError::Storage(
                StorageFabricError::InvalidMetadata(_)
            ))
        ));

        let mut ipfs_site = UnifiedContentRecord::from_bytes(b"ipfs-verified", "text/plain");
        ipfs_site.replicas.push(StorageReplica {
            network: StorageNetworkKind::Ipfs,
            domain_id: StorageNetworkKind::Ipfs.default_domain_id(),
            native_locator: String::from(
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            ),
            verification: VerificationStrength::CryptographicHash,
            available: true,
            latency_ms: 15,
        });
        let tampered_preimage = [StorageReplicaProof::ContentHashPreimage {
            payload: b"tampered-ipfs".to_vec(),
        }];
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: alice,
                    record: ipfs_site,
                    replica_proofs: &tampered_preimage,
                    bns_name: None,
                    intent: &deal_intent,
                    bonded_quotes: std::slice::from_ref(bonded_quote),
                    now_unix_secs: 1_000,
                },
                alice_bals,
            ),
            Err(UnificationExecutionError::Storage(
                StorageFabricError::InvalidMetadata(_)
            ))
        ));

        assert_eq!(alice_bals[0].available_amount, initial_balance);
        assert_eq!(
            ledger.merchant_credit(
                &template_intent.merchant_id,
                template_intent.target_domain,
                &template_intent.target_asset_id,
            ),
            0
        );
        assert!(ledger
            .storage_fabric()
            .resolve("bns://unproven.bud", VerificationStrength::AttestedDeal)
            .is_err());
        assert_eq!(ledger.state_root(), expected_root);
    }

    #[test]
    fn atomic_storage_deal_enforces_anchored_external_merkle_and_multi_replica_proofs() {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

        let bft = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        };
        let mut ledger = UnificationLedger::new(bft);
        let asset = [0x11; 32];
        let payer = [0x21; 32];
        let merchant = [0x22; 32];
        ledger
            .anchor_domain_finality(1, bft, 50_000, 10_000, 50, [0xAA; 32])
            .unwrap();

        let payload = b"multi-network-verified-bundle";
        let mut arweave_only =
            UnifiedContentRecord::from_bytes(payload, "application/octet-stream");
        let ar_domain = StorageNetworkKind::Arweave.default_domain_id();
        let ar_tx = "arweave_tx_locator_0001";
        let ar_leaf = storage_domain_commitment_leaf(
            StorageNetworkKind::Arweave,
            ar_domain,
            &arweave_only.sha3_256_digest,
            &arweave_only.sha256_digest,
            ar_tx,
        );
        let ar_root = build_storage_domain_commitment_root(&[ar_leaf, [0x77; 32]]);
        let ar_proof_nodes =
            build_storage_domain_inclusion_proof(&[ar_leaf, [0x77; 32]], 0).unwrap();
        arweave_only.replicas.push(StorageReplica {
            network: StorageNetworkKind::Arweave,
            domain_id: ar_domain,
            native_locator: String::from(ar_tx),
            verification: VerificationStrength::MerkleRoot,
            available: true,
            latency_ms: 45,
        });
        let ar_proof = [StorageReplicaProof::ExternalDomainMerkle {
            domain_id: ar_domain,
            finalized_state_root: ar_root,
            leaf_index: 0,
            leaf_count: 2,
            proof: ar_proof_nodes.clone(),
        }];
        let intent = UniversalPaymentIntent {
            payer_id: payer,
            merchant_id: merchant,
            nonce: 1,
            target_domain: 1,
            target_asset_id: asset,
            target_amount: 250,
            max_slippage_bps: 0,
            deadline_unix_secs: 5_000,
            invoice_hash: [0x51; 32],
            rail: PaymentRail::OnChain,
        };
        let mut bals = vec![DomainTokenBalance {
            domain_id: 1,
            asset_id: asset,
            symbol: String::from("BUD"),
            available_amount: 1_000,
        }];

        // 1. Unanchored external storage domain must fail closed with UnanchoredDomain.
        assert_eq!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: payer,
                    record: arweave_only.clone(),
                    replica_proofs: &ar_proof,
                    bns_name: Some("ar.bud"),
                    intent: &intent,
                    bonded_quotes: &[],
                    now_unix_secs: 1_000,
                },
                &mut bals,
            ),
            Err(UnificationExecutionError::UnanchoredDomain(ar_domain))
        );

        // 2. Anchored external storage domain with a different finalized_state_root rejects
        //    unanchored/spoofed Merkle roots before any settlement commits.
        ledger
            .anchor_domain_finality(ar_domain, bft, 50_000, 10_000, 10, [0xEE; 32])
            .unwrap();
        let root_with_wrong_anchor = ledger.state_root();
        assert!(matches!(
            ledger.execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: payer,
                    record: arweave_only,
                    replica_proofs: &ar_proof,
                    bns_name: Some("ar.bud"),
                    intent: &intent,
                    bonded_quotes: &[],
                    now_unix_secs: 1_000,
                },
                &mut bals,
            ),
            Err(UnificationExecutionError::InvalidArgument(_))
        ));
        assert_eq!(bals[0].available_amount, 1_000);
        assert_eq!(ledger.state_root(), root_with_wrong_anchor);

        // 3. Once the external domain's finalized_state_root is anchored, a multi-replica
        //    deal (Bud3 + IPFS + Arweave + Storj) atomically verifies every proof tier.
        ledger
            .anchor_domain_finality(ar_domain, bft, 50_000, 10_000, 11, ar_root)
            .unwrap();
        let mut multi = UnifiedContentRecord::from_bytes(payload, "application/octet-stream");
        let digest_hex = hex::encode(multi.sha3_256_digest);
        multi.replicas = vec![
            StorageReplica {
                network: StorageNetworkKind::Bud3,
                domain_id: 1,
                native_locator: digest_hex,
                verification: VerificationStrength::ErasureVerified,
                available: false,
                latency_ms: 5,
            },
            StorageReplica {
                network: StorageNetworkKind::Ipfs,
                domain_id: StorageNetworkKind::Ipfs.default_domain_id(),
                native_locator: String::from(
                    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                ),
                verification: VerificationStrength::CryptographicHash,
                available: false,
                latency_ms: 20,
            },
            StorageReplica {
                network: StorageNetworkKind::Arweave,
                domain_id: ar_domain,
                native_locator: String::from(ar_tx),
                verification: VerificationStrength::MerkleRoot,
                available: true,
                latency_ms: 45,
            },
            StorageReplica {
                network: StorageNetworkKind::Storj,
                domain_id: StorageNetworkKind::Storj.default_domain_id(),
                native_locator: String::from("bucket/verified-deal.bin"),
                verification: VerificationStrength::AttestedDeal,
                available: true,
                latency_ms: 12,
            },
        ];
        let proofs = [
            StorageReplicaProof::Bud3Custody {
                data_shards: 6,
                parity_shards: 3,
                custody_merkle_root: [0xC1; 32],
            },
            StorageReplicaProof::ContentHashPreimage {
                payload: payload.to_vec(),
            },
            StorageReplicaProof::ExternalDomainMerkle {
                domain_id: ar_domain,
                finalized_state_root: ar_root,
                leaf_index: 0,
                leaf_count: 2,
                proof: ar_proof_nodes,
            },
            StorageReplicaProof::DeclaredDealOnly {
                deal_commitment: [0xD4; 32],
            },
        ];
        ledger
            .execute_atomic_storage_deal(
                AtomicStorageDeal {
                    owner_id: payer,
                    record: multi,
                    replica_proofs: &proofs,
                    bns_name: Some("multi.bud"),
                    intent: &intent,
                    bonded_quotes: &[],
                    now_unix_secs: 1_000,
                },
                &mut bals,
            )
            .expect("multi-replica verified deal commits");
        assert_eq!(bals[0].available_amount, 750);
        assert_eq!(ledger.merchant_credit(&merchant, 1, &asset), 250);
        // Requiring MerkleRoot skips offline Bud3/IPFS and weak Storj (AttestedDeal),
        // selecting the anchored Arweave MerkleRoot replica!
        let resolved = ledger
            .storage_fabric()
            .resolve("bns://multi.bud", VerificationStrength::MerkleRoot)
            .expect("anchored Arweave replica satisfies MerkleRoot");
        assert_eq!(resolved.primary.network, StorageNetworkKind::Arweave);
        assert_eq!(
            resolved.primary.verification,
            VerificationStrength::MerkleRoot
        );
    }

    #[test]
    fn exclusive_spend_lock_and_account_state_freeze_prevent_double_spend_and_bypass() {
        use crate::crypto::facts::QuantumClass;
        use crate::domain::types::ConsensusKind;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

        let bft = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        };
        let mut ledger = UnificationLedger::new(FinalityGuarantee::settlement_hub());
        ledger
            .anchor_domain_finality(1, bft, 50_000, 10_000, 10, [0x11; 32])
            .unwrap();
        ledger
            .anchor_domain_finality(2, bft, 50_000, 10_000, 10, [0x22; 32])
            .unwrap();

        let payer = [0xAA; 32];
        let merchant = [0xBB; 32];
        let asset = [0x01; 32];
        let mut bals = [
            DomainTokenBalance {
                domain_id: 1,
                asset_id: asset,
                symbol: String::from("BUD"),
                available_amount: 1_000,
            },
            DomainTokenBalance {
                domain_id: 2,
                asset_id: asset,
                symbol: String::from("BUD"),
                available_amount: 0,
            },
        ];

        // TargetRelay cannot acquire spend lock.
        assert!(matches!(
            ledger.reserve_exclusive_cross_domain_spend(
                &SpendReservationRequest {
                    domain_id: 1,
                    asset_id: asset,
                    owner_id: payer,
                    amount_atoms: 400,
                    write_authority: CrossDomainWriteAuthority::TargetRelay,
                    current_height: 10,
                    ttl_blocks: 20,
                },
                &mut bals,
            ),
            Err(UnificationExecutionError::InvalidArgument(_))
        ));

        // SourceEscrow locks 400 -> concurrent spend lock or direct payment fails.
        ledger
            .reserve_exclusive_cross_domain_spend(
                &SpendReservationRequest {
                    domain_id: 1,
                    asset_id: asset,
                    owner_id: payer,
                    amount_atoms: 400,
                    write_authority: CrossDomainWriteAuthority::SourceEscrow,
                    current_height: 10,
                    ttl_blocks: 20,
                },
                &mut bals,
            )
            .unwrap();
        assert_eq!(bals[0].available_amount, 600);
        assert!(matches!(
            ledger.reserve_exclusive_cross_domain_spend(
                &SpendReservationRequest {
                    domain_id: 1,
                    asset_id: asset,
                    owner_id: payer,
                    amount_atoms: 100,
                    write_authority: CrossDomainWriteAuthority::SourceEscrow,
                    current_height: 11,
                    ttl_blocks: 20,
                },
                &mut bals,
            ),
            Err(UnificationExecutionError::ConcurrentSpendReservationConflict { .. })
        ));

        // Finalizing before proof height 15 fails; advancing anchor to 15 confirms,
        // after which refund is permanently blocked.
        assert!(ledger
            .confirm_cross_domain_spend(1, asset, payer, 15)
            .is_err());
        ledger
            .anchor_domain_finality(1, bft, 50_000, 10_000, 15, [0x15; 32])
            .unwrap();
        ledger
            .confirm_cross_domain_spend(1, asset, payer, 15)
            .unwrap();
        assert!(ledger
            .release_expired_spend_reservation(1, asset, payer, 100, &mut bals)
            .is_err());

        // AccountState integration refuses frozen domain even when UnificationLedger is anchored.
        let mut acct_state = crate::core::account::AccountState::new();
        let dom_2 = crate::domain::plugin::default_domain(2, ConsensusKind::Bft, 200, "bft-v1", 0);
        acct_state
            .settlement
            .domains
            .register(dom_2)
            .expect("register");
        acct_state
            .settlement
            .domains
            .set_status(2, crate::domain::types::DomainStatus::Frozen)
            .expect("freeze");
        let intent = UniversalPaymentIntent {
            payer_id: payer,
            merchant_id: merchant,
            nonce: 7,
            target_domain: 2,
            target_asset_id: asset,
            target_amount: 100,
            max_slippage_bps: 500,
            deadline_unix_secs: 2_000,
            invoice_hash: [0x55; 32],
            rail: PaymentRail::OnChain,
        };
        assert!(matches!(
            ledger.execute_finality_gated_payment_with_account(
                &acct_state,
                &intent,
                &mut bals,
                &[],
                1_000,
            ),
            Err(UnificationExecutionError::InvalidArgument(_))
        ));
    }
}
