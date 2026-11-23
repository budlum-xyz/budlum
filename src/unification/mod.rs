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
///
/// The ledger anchors every consensus domain and every external domain, so
/// its ceiling has to cover both registries' ceilings. A ceiling below the
/// domain registry's own would be a trapdoor: the registry would still
/// admit a domain, the ledger would refuse to anchor it, and every
/// settlement transaction with it would fail - the chain would stop
/// settling because it had more domains than its ledger had room for.
const MAX_LEDGER_DOMAINS: usize = crate::domain::registry::MAX_REGISTERED_DOMAINS * 2;

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

/// The first `DomainId` the unification ledger hands to an external domain.
///
/// The domain id space is partitioned, and the ledger takes the one range
/// that is provably nobody else's. Bit 31 marks a Garden domain
/// ([`crate::garden::is_garden_domain_id`]), so the ledger mints names with
/// bit 30 set and bit 31 clear: `0x4000_0000..=0x7FFF_FFFF`.
///
/// The range is reserved, not merely used. A new consensus domain may not
/// be admitted with an id inside it - the ingest gate refuses it
/// ([`crate::settlement::domains::check_ingest_garden_domain_reservation`])
/// - and the ledger refuses an internal anchor there
/// ([`UnificationLedger::anchor_domain_finality`]). The ingest gate is
/// where the refusal lives on purpose: a check inside committed-block
/// replay would reject a chain whose history already holds a domain in
/// this range, and an upgraded node would fork away from an un-upgraded
/// one. Two nodes cannot disagree about which domain an id names, because
/// the id says which namespace it came from.
pub const EXTERNAL_DOMAIN_ID_PREFIX: crate::domain::types::DomainId = 0x4000_0000;

/// The last `DomainId` the unification ledger hands to an external domain.
pub const EXTERNAL_DOMAIN_ID_LIMIT: crate::domain::types::DomainId = 0x7FFF_FFFF;

/// True when `id` lies in the range reserved for the names the unification
/// ledger mints for external domains.
pub const fn is_external_domain_id(id: crate::domain::types::DomainId) -> bool {
    id >= EXTERNAL_DOMAIN_ID_PREFIX && id <= EXTERNAL_DOMAIN_ID_LIMIT
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

/// Atomic storage-deal input grouping owner content metadata with split-tender
/// payment parameters.
///
/// WIRING: Input bundle consumed by [`UnificationLedger::execute_atomic_storage_deal`].
pub struct AtomicStorageDeal<'a> {
    pub owner_id: Hash32,
    pub record: UnifiedContentRecord,
    pub bns_name: Option<&'a str>,
    pub intent: &'a UniversalPaymentIntent,
    pub bonded_quotes: &'a [BondedLiquidityQuote],
    pub now_unix_secs: u64,
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
    /// The ledger's own name for every external domain it has admitted.
    ///
    /// An external domain is addressed by its own `DomainKey`; the ledger
    /// stores domains under a numeric `DomainId`. This map is the bridge
    /// between the two, and it is the reason an external domain's finality
    /// envelope has anywhere to land.
    ///
    /// The identity is stable: the same `DomainKey` always resolves to the
    /// same `DomainId`. A ledger that handed out a fresh name per call would
    /// count the same outflow twice and slash a receipt naming a domain
    /// nobody else knows.
    external_domains: std::collections::BTreeMap<
        crate::cross_domain::external::DomainKey,
        crate::domain::types::DomainId,
    >,
    /// The next unused `DomainId` this ledger will hand to an external
    /// domain. It starts at [`EXTERNAL_DOMAIN_ID_PREFIX`] and only ever
    /// moves forward, and only when an anchor actually succeeded. Zero
    /// means the range is exhausted.
    next_external_domain_id: crate::domain::types::DomainId,
    solvers: std::collections::BTreeMap<Hash32, SolverBondRecord>,
    settled_quote_obligations: std::collections::BTreeMap<(Hash32, Hash32), (Hash32, u128)>,
    slash_hashes: Vec<Hash32>,
    merchant_credits:
        std::collections::BTreeMap<(Hash32, crate::domain::types::DomainId, Hash32), u128>,
    committed_bundles: std::collections::BTreeMap<Hash32, Hash32>,
    router: UniversalPaymentRouter,
    storage: UnifiedStorageFabric,
}

/// The part of the unification ledger that consensus state keeps.
///
/// The ledger itself is a runtime structure - its router and its storage
/// fabric have never been part of the state root, and they do not need to
/// be. What *does* belong to consensus state is the set of finality
/// anchors: the guarantees the ledger has admitted, the names it gave the
/// external domains that produced them, and the counter that hands out the
/// next name.
///
/// Those three are consensus facts. The conservation ceiling, the slashing
/// rule, and the atomic rollback all read them, and two nodes that disagree
/// about them would disagree about which payments are authorized. So they
/// live in the state root, and the ledger is rebuilt around them.
///
/// WIRING: Carried by [`crate::settlement::SettlementRegistries`] so that
/// the anchors survive a restart and enter the settlement state root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnificationAnchors {
    /// The finality anchor of every domain the ledger has admitted.
    domains: std::collections::BTreeMap<crate::domain::types::DomainId, AnchoredDomainState>,
    /// The ledger's own name for every external domain it has admitted.
    ///
    /// The key is a `DomainKey`, whose canonical string form is the 64-hex
    /// form the rest of the external registries use, so the map survives a
    /// JSON snapshot.
    #[serde(with = "crate::core::map_keys")]
    external_domains: std::collections::BTreeMap<
        crate::cross_domain::external::DomainKey,
        crate::domain::types::DomainId,
    >,
    /// The next unused `DomainId` this ledger will hand to an external
    /// domain. Zero is reserved, so the first name is one.
    #[serde(default = "first_external_domain_id")]
    next_external_domain_id: crate::domain::types::DomainId,
}

/// The counter's start value.
///
/// A counter that deserializes as zero would mean "the range is exhausted",
/// and the ledger would refuse every external domain. The default has to be
/// the first name in the range, not zero.
const fn first_external_domain_id() -> crate::domain::types::DomainId {
    EXTERNAL_DOMAIN_ID_PREFIX
}

impl Default for UnificationAnchors {
    /// A fresh anchor set starts at the first name in the reserved range.
    ///
    /// The derived `Default` would start the counter at zero, and zero is
    /// the ledger's "the range is exhausted" marker - a ledger restored
    /// from a default anchor set would refuse every external domain.
    fn default() -> Self {
        Self::new()
    }
}

impl UnificationAnchors {
    /// The anchors of a ledger that has admitted nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domains: std::collections::BTreeMap::new(),
            external_domains: std::collections::BTreeMap::new(),
            next_external_domain_id: EXTERNAL_DOMAIN_ID_PREFIX,
        }
    }

    /// The anchors, as the ledger's own state.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    #[must_use]
    pub fn domains(
        &self,
    ) -> &std::collections::BTreeMap<crate::domain::types::DomainId, AnchoredDomainState> {
        &self.domains
    }

    /// The name of every external domain the ledger has admitted.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    #[must_use]
    pub fn external_domains(
        &self,
    ) -> &std::collections::BTreeMap<
        crate::cross_domain::external::DomainKey,
        crate::domain::types::DomainId,
    > {
        &self.external_domains
    }

    /// The name the ledger will give the next external domain.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    #[must_use]
    pub fn next_external_domain_id(&self) -> crate::domain::types::DomainId {
        self.next_external_domain_id
    }

    /// True when the ledger has admitted nothing yet.
    ///
    /// An empty anchor set joins nothing to the state root, so a chain that
    /// never saw a cross-domain finality keeps its pinned roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.external_domains.is_empty()
    }

    /// The anchors' own root.
    ///
    /// The domains are hashed under their own id, so an anchor that moves
    /// from one domain to another changes the root even when the guarantees
    /// themselves did not.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        let mut leaves: Vec<Hash32> = Vec::new();
        for (domain_id, state) in &self.domains {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_ULEDGER_ANCHOR_DOMAIN_V1",
                &domain_id.to_le_bytes(),
                &state.guarantee.fault_tolerance_bps.to_le_bytes(),
                &[u8::from(state.guarantee.slashable_backing)],
                &state.slashable_bond_atoms.to_le_bytes(),
                &state.routing_ceiling_atoms.to_le_bytes(),
                &state.finalized_height.to_le_bytes(),
                &state.finalized_state_root,
                &state.epoch_outflow_atoms.to_le_bytes(),
            ]));
        }
        for (key, domain_id) in &self.external_domains {
            leaves.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_ULEDGER_ANCHOR_EXTERNAL_V1",
                &key.0,
                &domain_id.to_le_bytes(),
            ]));
        }
        crate::core::hash::hash_fields_bytes(&[b"BDLM_ULEDGER_ANCHORS_V1", &leaves])
    }
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
            external_domains: std::collections::BTreeMap::new(),
            next_external_domain_id: EXTERNAL_DOMAIN_ID_PREFIX,
            solvers: std::collections::BTreeMap::new(),
            settled_quote_obligations: std::collections::BTreeMap::new(),
            slash_hashes: Vec::new(),
            merchant_credits: std::collections::BTreeMap::new(),
            committed_bundles: std::collections::BTreeMap::new(),
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
        // The external range belongs to the names the ledger mints. A
        // consensus domain taking an id from it would make one number mean
        // two domains, and the ledger would overwrite whichever it anchored
        // second.
        if is_external_domain_id(domain_id) {
            return Err(UnificationExecutionError::InvalidArgument(String::from(
                "a consensus domain may not take the id range reserved for external domains",
            )));
        }
        self.anchor_state_into(
            domain_id,
            guarantee,
            slashable_bond_atoms,
            routing_ceiling_atoms,
            finalized_height,
            finalized_state_root,
        )
    }

    /// Anchor a domain's finality envelope under an id the caller has
    /// already chosen.
    ///
    /// The shared body of the two anchors. The internal door refuses the
    /// external id range before it gets here; the external door mints an id
    /// inside that range. Everything else is the same rule: the height may
    /// not regress, the domain table has a ceiling, and the outflow the
    /// domain has already accumulated is carried over.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] on height regression or domain
    /// table capacity exhaustion.
    fn anchor_state_into(
        &mut self,
        domain_id: crate::domain::types::DomainId,
        guarantee: crate::settlement::universal_finality::FinalityGuarantee,
        slashable_bond_atoms: u128,
        routing_ceiling_atoms: u128,
        finalized_height: u64,
        finalized_state_root: Hash32,
    ) -> Result<(), UnificationExecutionError> {
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

    /// The ledger's anchors, as consensus state keeps them.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    #[must_use]
    pub fn anchors(&self) -> UnificationAnchors {
        UnificationAnchors {
            domains: self.domains.clone(),
            external_domains: self.external_domains.clone(),
            next_external_domain_id: self.next_external_domain_id,
        }
    }

    /// Restore a ledger around anchors that consensus state kept.
    ///
    /// The router and the storage fabric are runtime structures and start
    /// empty; the anchors are the consensus facts, and they come back
    /// exactly as they were left.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    #[must_use]
    pub fn from_anchors(
        hub_guarantee: crate::settlement::universal_finality::FinalityGuarantee,
        anchors: UnificationAnchors,
    ) -> Self {
        let mut ledger = Self::new(hub_guarantee);
        ledger.restore_anchors(anchors);
        ledger
    }

    /// Load the anchors consensus state kept back into the ledger.
    ///
    /// The router and the storage fabric stay empty: they are runtime
    /// structures and were never part of the state root. The anchors are the
    /// consensus facts, and they come back exactly as they were left.
    ///
    /// # Errors
    ///
    /// This function never fails; the `Result` keeps the read surface
    /// uniform with the rest of the ledger.
    pub fn restore_anchors(&mut self, anchors: UnificationAnchors) {
        self.domains = anchors.domains;
        self.external_domains = anchors.external_domains;
        self.next_external_domain_id = anchors.next_external_domain_id;
    }

    /// Anchor an external domain's finality envelope under the ledger's own
    /// name for it.
    ///
    /// An external domain is addressed by its `DomainKey`; the ledger stores
    /// domains under a numeric `DomainId`. This is the bridge: the ledger
    /// resolves the key to the name it already gave that domain, or gives it
    /// one now, and then anchors the envelope under that name.
    ///
    /// The name is stable. The same key always resolves to the same
    /// `DomainId`, so the outflow the ledger has already counted against a
    /// domain, and the slashing receipt that names it, keep referring to the
    /// same domain. Two different domains never share a name.
    ///
    /// # Errors
    ///
    /// Returns [`UnificationExecutionError`] if the finalized state root is
    /// zero, the height regresses, the domain table is full, or the identity
    /// space is exhausted.
    ///
    /// WIRING: Admits the observed finality guarantee produced for an
    /// external domain into the ledger, so the finality conservation,
    /// slashing, and atomic rollback rules can read it.
    #[must_use]
    pub fn anchor_external_domain_finality(
        &mut self,
        key: &crate::cross_domain::external::DomainKey,
        guarantee: crate::settlement::universal_finality::FinalityGuarantee,
        slashable_bond_atoms: u128,
        routing_ceiling_atoms: u128,
        finalized_height: u64,
        finalized_state_root: Hash32,
    ) -> Result<crate::domain::types::DomainId, UnificationExecutionError> {
        // A domain the ledger has already named keeps its name. The anchor
        // may still be refused - the height may not regress, the table may be
        // full - and a refusal must not unname the domain: the outflow the
        // ledger has already counted against that name stays counted, and a
        // name that vanished would leave the receipt naming a domain nobody
        // can look up.
        if let Some(existing) = self.external_domains.get(key).copied() {
            self.anchor_state_into(
                existing,
                guarantee,
                slashable_bond_atoms,
                routing_ceiling_atoms,
                finalized_height,
                finalized_state_root,
            )?;
            return Ok(existing);
        }

        // A new domain. The name is computed but NOT committed: the anchor
        // is written first, and only an anchor that actually succeeded
        // commits the name and moves the counter.
        //
        // The other order - name first, anchor second - leaves a ghost
        // mapping behind whenever the anchor is refused: the key would point
        // at a domain the ledger never anchored, and the counter would have
        // burned an id for a domain that does not exist.
        let candidate = self.next_external_domain_id;
        if candidate == 0 || !is_external_domain_id(candidate) {
            return Err(UnificationExecutionError::CapacityExceeded);
        }
        self.anchor_state_into(
            candidate,
            guarantee,
            slashable_bond_atoms,
            routing_ceiling_atoms,
            finalized_height,
            finalized_state_root,
        )?;

        // Commit. The name and the counter move together, and neither can
        // fail, so the ledger is never half-anchored.
        self.next_external_domain_id = match candidate.checked_add(1) {
            Some(next) if is_external_domain_id(next) => next,
            // The range is exhausted. Zero says so, and the next attempt is
            // refused rather than handing out the last id twice.
            _ => 0,
        };
        self.external_domains.insert(*key, candidate);
        Ok(candidate)
    }

    /// The ledger's name for an external domain, if it has given one.
    ///
    /// # Errors
    ///
    /// This function never fails; `None` means the domain is not known.
    #[must_use]
    pub fn domain_id_for_external(
        &self,
        key: &crate::cross_domain::external::DomainKey,
    ) -> Option<crate::domain::types::DomainId> {
        self.external_domains.get(key).copied()
    }

    /// The anchored state of a domain, under the ledger's own name for it.
    ///
    /// # Errors
    ///
    /// This function never fails; `None` means the domain is not anchored.
    #[must_use]
    pub fn domain_state(
        &self,
        domain_id: crate::domain::types::DomainId,
    ) -> Option<&AnchoredDomainState> {
        self.domains.get(&domain_id)
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
    /// split-tender payment, registers `record` under authenticated `owner_id`,
    /// and optionally binds `bns_name` to `record.sha3_256_digest`.
    ///
    /// If object registration or BNS binding fails (for example, attempting to
    /// hijack another owner's `bns://` name), the entire payment, quote fill,
    /// domain outflow, and merchant credit roll back atomically.
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
            record,
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
        let digest = record.sha3_256_digest;
        let mut snapshot = self.clone();
        let mut staged_balances = balances.to_vec();
        let receipt = snapshot.execute_finality_gated_payment(
            intent,
            &mut staged_balances,
            bonded_quotes,
            now_unix_secs,
        )?;
        let record_hash = snapshot.storage.register_owned_object(owner_id, record)?;
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Every production source file that could hold the settlement chain.
    ///
    /// The list is read from disk at run time rather than baked in with
    /// `include_str!`. A baked-in path is a compile-time contract: if the
    /// file it names does not exist in this tree, the test module does not
    /// compile and every test in the crate fails to build - which reads as a
    /// red test while proving nothing at all. Reading the tree at run time
    /// keeps a missing file a test failure instead of a build failure.
    fn production_sources() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for relative in [
            "src/unification/mod.rs",
            "src/rpc/server.rs",
            "src/settlement/domains.rs",
            "src/settlement/universal_finality.rs",
            "src/settlement/registries.rs",
            "src/settlement/anchor_ledger.rs",
            "src/settlement/anchor_production.rs",
            "src/chain/chain_actor.rs",
            "src/cross_domain/external/spec.rs",
            "src/cross_domain/external/intake.rs",
            "src/cross_domain/external/profile.rs",
            "src/unification/domain_catalog.rs",
        ] {
            let path = root.join(relative);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{relative} is unreadable: {e}"));
            files.push((relative.to_string(), text));
        }
        files
    }

    /// The ledger must name an external domain for itself, and keep naming it
    /// the same way.
    ///
    /// The ledger stores domains under a numeric `DomainId`, while an external
    /// domain is addressed by its own `DomainKey`. When a domain's finality
    /// envelope arrives, the ledger has to turn one into the other. Two
    /// properties matter, and both are about the ledger staying a ledger:
    ///
    /// 1. **The name is stable.** The same domain must land on the same
    ///    `DomainId` every time, or the anchored state, the outflow that has
    ///    already been counted against it, and the slashing receipt that
    ///    names it would each be talking about a different domain.
    /// 2. **The guarantee is stored.** After the anchor, the ledger must hold
    ///    the guarantee it was given, under that name - otherwise the
    ///    finality-gated payment rules still have nothing to read.
    ///
    /// This test pins both.
    #[test]
    fn the_ledger_names_an_external_domain_and_keeps_the_guarantee() {
        use crate::cross_domain::external::DomainKey;
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

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
            fault_tolerance_bps: 10_000,
        };
        let mut ledger = UnificationLedger::new(hub_g);

        let key = DomainKey([0x77; 32]);

        // The ledger must accept an external domain by its own key.
        let assigned = ledger
            .anchor_external_domain_finality(&key, hub_g, 10_000, 100_000, 42, [0x31; 32])
            .expect("the ledger accepts an external domain");

        assert!(
            assigned != 0,
            "the ledger must not name a domain with the reserved id 0"
        );
        // The name must come from the range reserved for external domains.
        // A name drawn from the consensus range would collide with a
        // consensus domain that happens to hold the same number, and the
        // ledger keys its anchored domains by id.
        assert!(
            crate::unification::is_external_domain_id(assigned),
            "the ledger named an external domain with the id {assigned}, which lies \
             outside the reserved external range"
        );

        // The same domain must land on the same name. A ledger that hands out
        // a fresh identity per call would count the same outflow twice and
        // slash a receipt that names a domain nobody else knows.
        let again = ledger
            .anchor_external_domain_finality(&key, hub_g, 10_000, 100_000, 43, [0x32; 32])
            .expect("the ledger accepts the same external domain again");
        assert_eq!(
            assigned, again,
            "the ledger gave one external domain two identities; the outflow it \
             has already counted and the receipt that names it would then refer \
             to different domains"
        );

        // And the guarantee must actually be there, under that name.
        let anchored = ledger
            .domain_state(assigned)
            .expect("the anchored domain is readable");
        assert_eq!(
            anchored.guarantee.fault_tolerance_bps, hub_g.fault_tolerance_bps,
            "the ledger stored a different guarantee than the one it was given"
        );
        assert_eq!(
            anchored.finalized_height, 43,
            "the ledger did not advance the domain's finalized height"
        );

        // A different domain must get a different name.
        let other = ledger
            .anchor_external_domain_finality(
                &DomainKey([0x78; 32]),
                hub_g,
                10_000,
                100_000,
                7,
                [0x33; 32],
            )
            .expect("the ledger accepts a second external domain");
        assert_ne!(
            assigned, other,
            "two external domains were given the same identity"
        );
    }

    /// A refused anchor must leave nothing behind.
    ///
    /// The ledger names an external domain and anchors its finality envelope
    /// in one step. If the name were committed before the anchor, a refused
    /// anchor would leave a ghost: the key would point at a domain the
    /// ledger never anchored, and the id counter would have burned a name on
    /// a domain that does not exist. The next domain would then start one
    /// name further along, and the ghost key would still answer to a domain
    /// with no state.
    #[test]
    fn a_refused_anchor_leaves_no_ghost_mapping() {
        use crate::cross_domain::external::DomainKey;
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

        let hub_g = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: 10_000,
        };
        let mut ledger = UnificationLedger::new(hub_g);
        let key = DomainKey([0x77; 32]);
        let root_before = ledger.state_root();

        // A zero state root is refused by the anchor.
        let refused =
            ledger.anchor_external_domain_finality(&key, hub_g, 10_000, 100_000, 42, [0u8; 32]);
        assert!(
            refused.is_err(),
            "the ledger accepted an anchor with a zero finalized state root"
        );

        // No ghost mapping: the key names nothing.
        assert!(
            ledger.domain_id_for_external(&key).is_none(),
            "a refused anchor left the key naming a domain the ledger never anchored"
        );

        // And no counter drift: the refused attempt changed nothing at all.
        assert_eq!(
            ledger.state_root(),
            root_before,
            "a refused anchor mutated the ledger"
        );

        // The next successful anchor takes the FIRST name in the range, so
        // the refusal did not burn one.
        let named = ledger
            .anchor_external_domain_finality(&key, hub_g, 10_000, 100_000, 42, [0x31; 32])
            .expect("the ledger accepts an external domain");
        assert_eq!(
            named,
            crate::unification::EXTERNAL_DOMAIN_ID_PREFIX,
            "a refused anchor burned a name; the first admitted domain did not get \
             the first name in the reserved range"
        );
    }

    /// A consensus domain may not take the range reserved for external
    /// domains.
    ///
    /// The ledger keys its anchored domains by `DomainId`. If an internal
    /// domain could hold an id from the external range, the two namespaces
    /// would overlap and the ledger would overwrite whichever it anchored
    /// second - silently, and with a guarantee that belonged to the other
    /// domain.
    #[test]
    fn a_consensus_domain_cannot_take_the_external_id_range() {
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

        let hub_g = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: 10_000,
        };
        let mut ledger = UnificationLedger::new(hub_g);

        let refused = ledger.anchor_domain_finality(
            crate::unification::EXTERNAL_DOMAIN_ID_PREFIX,
            hub_g,
            10_000,
            100_000,
            5,
            [0x31; 32],
        );
        assert!(
            refused.is_err(),
            "a consensus domain took an id from the reserved external range"
        );
        assert!(
            ledger
                .domain_state(crate::unification::EXTERNAL_DOMAIN_ID_PREFIX)
                .is_none(),
            "the refused consensus anchor was stored anyway"
        );
    }

    /// A consensus domain and an external domain never share an identity.
    ///
    /// The two namespaces are apart by construction, so a consensus domain
    /// at id 1 and an external domain both anchored in the same ledger keep
    /// their own state.
    #[test]
    fn an_external_domain_never_collides_with_a_consensus_domain() {
        use crate::cross_domain::external::DomainKey;
        use crate::crypto::facts::QuantumClass;
        use crate::settlement::domains::CommitmentAttestation;
        use crate::settlement::universal_finality::{FinalityGuarantee, FinalityReversibility};

        let hub_g = FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Lattice,
            attestation: CommitmentAttestation {
                state_root: true,
                tx_root: true,
                event_root: true,
                parent: true,
            },
            slashable_backing: true,
            fault_tolerance_bps: 10_000,
        };
        let mut ledger = UnificationLedger::new(hub_g);

        ledger
            .anchor_domain_finality(1, hub_g, 10_000, 100_000, 5, [0x31; 32])
            .expect("the ledger accepts a consensus domain");
        let external = ledger
            .anchor_external_domain_finality(
                &DomainKey([0x77; 32]),
                hub_g,
                10_000,
                100_000,
                6,
                [0x32; 32],
            )
            .expect("the ledger accepts an external domain");

        assert_ne!(
            external, 1,
            "an external domain took the identity of a consensus domain"
        );
        assert!(
            ledger.domain_state(1).is_some(),
            "the consensus domain's anchored state was overwritten by the external domain"
        );
        assert!(
            ledger.domain_state(external).is_some(),
            "the external domain's anchored state is missing"
        );
        assert_eq!(
            ledger.domain_state(1).map(|d| d.finalized_height),
            Some(5),
            "the consensus domain's anchored height changed"
        );
    }

    /// The settlement finality chain must reach the unification ledger.
    ///
    /// A `FinalityGuarantee` derived from an external domain's observed
    /// backing is the only thing that can make a cross-domain payment
    /// finality-gated. That guarantee is produced in production by
    /// `src/rpc/server.rs`, and `UnificationLedger::anchor_domain_finality`
    /// is the door that admits it into the ledger. If no production path
    /// calls that door, the ledger's finality conservation, slashing, and
    /// atomic rollback rules never see a real guarantee: every route would
    /// have to be authorized by a hand-built test fixture, and the gate
    /// would be a door that nothing walks through.
    ///
    /// The chain has two links, and both must exist in production:
    ///
    /// 1. **the ledger exists** - a production path constructs a
    ///    `UnificationLedger` at all. Without this there is no ledger to
    ///    anchor anything into, and the whole type is dead weight.
    /// 2. **the guarantee enters** - a production path calls
    ///    `anchor_domain_finality` with that ledger.
    ///
    /// This test locks that chain shut. It scans the production sources for
    /// both calls and refuses to pass while the only callers are the test
    /// module itself.
    #[test]
    fn the_observed_finality_guarantee_reaches_the_unification_ledger_in_production() {
        let sources = production_sources();

        // The test module that may legitimately call into the ledger.
        let test_module_start = sources
            .iter()
            .find(|(path, _)| *path == "src/unification/mod.rs")
            .and_then(|(_, source)| source.find("#[cfg(test)]"))
            .expect("the unification test module is present");

        // Find production call sites of `name`, ignoring the declaration
        // itself and everything that lives in a `#[cfg(test)]` module.
        let production_callers = |name: &str| -> Vec<String> {
            let mut found = Vec::new();
            for (path, source) in &sources {
                for (at, _) in source.match_indices(name) {
                    // The declaration is not a call. It reads `fn name(` or
                    // `pub fn name(`; strip the space the keyword carries and
                    // check the word before the name.
                    let before = source[..at].trim_end();
                    let word = before
                        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or_default();
                    if word == "fn" {
                        continue;
                    }
                    // A call is the name immediately followed by `(`.
                    if !source[at..].starts_with(&format!("{name}(")) {
                        continue;
                    }
                    let line = source[..at].lines().count() + 1;
                    let in_test_module =
                        path == "src/unification/mod.rs" && at >= test_module_start;
                    if !in_test_module {
                        found.push(format!("{path}:{line}"));
                    }
                }
            }
            found
        };

        let constructors = production_callers("UnificationLedger::new");
        let anchors = production_callers("anchor_domain_finality");

        assert!(
            !constructors.is_empty(),
            "no production path constructs a `UnificationLedger`; \
             the ledger's finality conservation, slashing, and atomic rollback \
             rules are unreachable in production, so every finality-gated route \
             would have to be authorized by a hand-built test fixture"
        );

        assert!(
            !anchors.is_empty(),
            "no production path calls `UnificationLedger::anchor_domain_finality`; \
             the observed finality guarantee never reaches the unification ledger, \
             so the ledger's finality-gated payment rules are unreachable in production"
        );
    }

    /// Every external domain must be able to name itself in the ledger.
    ///
    /// `anchor_domain_finality` identifies a domain by `DomainId` - a
    /// `u32`. The guarantee that carries the observed backing belongs to an
    /// *external* domain, and external domains are addressed by
    /// `DomainKey([u8; 32])`. Something has to translate one into the other:
    /// either the domain carries a ledger identity from the start, or the
    /// ledger assigns one when the domain is admitted.
    ///
    /// Today nothing does. There is no `DomainKey -> DomainId` conversion in
    /// the cross-domain intake, and the universal domain catalog cannot
    /// absorb an external domain either, because
    /// `UniversalDomainCatalog::register_domain` requires a `caip2_reference`
    /// and an external intake record carries none. So an external domain
    /// cannot enter the catalog, and it cannot enter the ledger either -
    /// which is why the guarantee produced for it never reaches the ledger
    /// even after the previous chain is closed.
    ///
    /// This test refuses to let that stay invisible. It looks for the
    /// identity bridge in production and names the missing link when it
    /// cannot find it.
    #[test]
    fn an_external_domain_has_a_ledger_identity() {
        let sources = production_sources();

        let test_module_start = sources
            .iter()
            .find(|(path, _)| path == "src/unification/mod.rs")
            .and_then(|(_, source)| source.find("#[cfg(test)]"))
            .expect("the unification test module is present");

        // The bridge may be spelled in more than one way, so look for the
        // shapes it could take rather than for one name.
        let bridges = [
            "domain_id_for",
            "ledger_domain_id",
            "anchor_external_domain_finality",
        ];

        let mut production_bridges = Vec::new();
        for (path, source) in &sources {
            for bridge in bridges {
                for (at, _) in source.match_indices(bridge) {
                    // A declaration is not a bridge. It reads `fn name(` or
                    // `pub fn name(`; check the word before the name.
                    let before = source[..at].trim_end();
                    let word = before
                        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or_default();
                    if word == "fn" {
                        continue;
                    }
                    // A call is the name immediately followed by `(`.
                    if !source[at..].starts_with(&format!("{bridge}(")) {
                        continue;
                    }
                    let line = source[..at].lines().count() + 1;
                    let in_test_module =
                        path == "src/unification/mod.rs" && at >= test_module_start;
                    if !in_test_module {
                        production_bridges.push(format!("{path}:{line} {bridge}"));
                    }
                }
            }
        }

        // The bridge has to be a real one: a function that takes an external
        // domain's own `DomainKey` and hands back the numeric `DomainId` the
        // ledger stores under. A mention of the key type, on its own, is not
        // a bridge - the external intake has plenty of those, and none of
        // them reach the ledger.
        let maps_external_key = production_bridges.iter().any(|entry| {
            let path = entry.split(':').next().unwrap_or_default();
            !path.starts_with("src/unification/domain_catalog.rs")
        });

        assert!(
            maps_external_key,
            "no production path maps an external domain's `DomainKey` to the `DomainId` \
             the unification ledger stores; an external domain cannot be named in the \
             ledger at all, so its observed finality guarantee has no destination"
        );
    }
}
