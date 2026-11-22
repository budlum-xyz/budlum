//! WIRING: unwired - `RemoteStateView::verify_for_chain` and `ULP-1` routing await RPC hookup.
//!
//! `settlement::app_binding` verifies payment proofs via `LightClient::verify_global_header`,
//! and the `budlum-light` binary drives header and checkpoint sync.
//!
//! Succinct light-client verification.
//!
//! Whitepaper v1.1: a light client bootstrapped from a single trusted
//! validator-set commitment, using finality certificates as proofs. A light
//! node holds one trust anchor - a checkpoint height, the block hash at that
//! height, and the hash of the validator set that finalized it - and advances
//! it by verifying finality certificates against that set, without ever
//! downloading or replaying transaction bodies.
//!
//! Two certificate kinds are verified:
//!
//! * [`FinalityCert`] - the BLS aggregate certificate over a stake-weighted
//!   quorum (`LightClient::verify_checkpoint`). This is the whitepaper's
//!   "BLS finality certificates as proofs".
//! * [`QcBlob`] - the post-quantum quorum blob (`LightClient::verify_pq_
//! checkpoint`), the same attestation layer full nodes import.
//!
//! The verification is transport-agnostic: `LightClient::sync_plan` spells
//! out the wire requests a transport must issue (the existing `GetHeaders`
//! locator and the per-checkpoint QC blob fetch), and the `budlum-light`
//! binary drives it over a chain export. The trust rule is deliberately
//! conservative: the validator set is fixed at bootstrap, so a certificate
//! whose `set_hash` differs from the trusted one is rejected, not silently
//! followed. A set change needs a new trust anchor out-of-band.

use std::collections::BTreeMap;
use std::fmt;

use crate::chain::finality::{FinalityCert, ValidatorSetSnapshot};
use crate::consensus::qc::QcBlob;
use crate::core::block::BlockHeader;
use crate::network::protocol::is_canonical_hash;

/// Maximum number of verified un-advanced headers cached in `LightClient::linked`.
///
/// Caps light-client memory against unbounded header-segment downloads between
/// checkpoint advances while keeping full multi-epoch sync segments admissible.
pub const MAX_LINKED_HEADERS: usize = 8_192;

/// Maximum hop count permitted inside a single [`UniversalLightPacket`].
pub const MAX_UNIVERSAL_ROUTE_HOPS: usize = 4;

/// Routing safety policy enforced by [`LightClient::verify_multi_hop_light_route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniversalRoutePolicy {
    /// Maximum hop count permitted in a single multi-hop route (`1..=4`).
    pub max_hops: usize,
    /// Cumulative and per-hop outflow ceiling in basis points (`<= 2_500`).
    pub max_outflow_bps: u16,
    /// Minimum verified security weight required on every traversed domain.
    pub min_security_weight: u64,
    /// Whether the settlement hub's CRQC Frost Alarm emergency gate is active.
    pub crqc_alarm_active: bool,
    /// Require every traversed domain to hold post-quantum attestation under Frost Alarm.
    pub require_pq_on_crqc_alarm: bool,
    /// Optional caller-pinned `ULP-1` domain-set Merkle root.
    ///
    /// [`LightClient::verify_multi_hop_light_route`] anchors first to the
    /// consensus-committed [`crate::settlement::GlobalBlockHeader::ulp_domains_root`];
    /// if both `global_header.ulp_domains_root` and `trusted_domains_root` are
    /// `Some` and differ, verification fails closed. If both are `None`, value
    /// routes remain fail-closed.
    pub trusted_domains_root: Option<crate::domain::types::Hash32>,
}

impl UniversalRoutePolicy {
    /// Strict production value-routing policy: at most 4 hops, hard 25%
    /// (`2_500` bps) outflow ceiling, positive security weight, and fail-closed
    /// post-quantum enforcement whenever `crqc_alarm_active` is set.
    /// Convenience: kept for the CLI and strict light-client route callers.
    #[must_use]
    pub const fn strict_value(crqc_alarm_active: bool) -> Self {
        Self {
            max_hops: MAX_UNIVERSAL_ROUTE_HOPS,
            max_outflow_bps: crate::aggregation::universal_light_proof::MAX_ULP_OUTFLOW_BPS,
            min_security_weight: 1,
            crqc_alarm_active,
            require_pq_on_crqc_alarm: true,
            trusted_domains_root: None,
        }
    }

    /// The strict policy with a caller-pinned domain-set root. Without a
    /// pinned root every route verification fails closed, so this is the only
    /// constructor that can produce an accepting policy.
    /// Convenience: the accepting counterpart of [`Self::strict_value`], for
    /// the same multi-hop route callers; a caller that pins a domain-set root
    /// has nothing else to construct it with.
    #[must_use]
    pub const fn strict_value_pinned(
        trusted_domains_root: crate::domain::types::Hash32,
        crqc_alarm_active: bool,
    ) -> Self {
        Self {
            max_hops: MAX_UNIVERSAL_ROUTE_HOPS,
            max_outflow_bps: crate::aggregation::universal_light_proof::MAX_ULP_OUTFLOW_BPS,
            min_security_weight: 1,
            crqc_alarm_active,
            require_pq_on_crqc_alarm: true,
            trusted_domains_root: Some(trusted_domains_root),
        }
    }
}

/// One cross-domain hop `source -> destination` verified against a `ULP-1` root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalRouteHop {
    /// Finalized origin domain snapshot for this hop.
    pub source: crate::aggregation::universal_light_proof::UlpDomainSnapshot,
    /// `O(log D)` Merkle inclusion proof for `source`.
    pub source_proof: crate::aggregation::universal_light_proof::UlpDomainInclusionProof,
    /// Finalized destination domain snapshot for this hop.
    pub destination: crate::aggregation::universal_light_proof::UlpDomainSnapshot,
    /// `O(log D)` Merkle inclusion proof for `destination`.
    pub destination_proof: crate::aggregation::universal_light_proof::UlpDomainInclusionProof,
    /// Canonical non-zero packet commitment rooted in `source.event_root`.
    pub packet_commitment: crate::domain::types::Hash32,
    /// Monotonic packet sequence number along the route.
    pub sequence: u64,
    /// Value outflow moved by this hop in basis points of the domain cap.
    pub amount_bps: u16,
}

/// Multi-hop cross-domain light-client packet backed by one `ULP-1` bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalLightPacket {
    /// Succinct multi-domain `ULP-1` proof bundle anchored at the hub checkpoint.
    pub ulp_bundle: crate::aggregation::universal_light_proof::UniversalLightProofBundle,
    /// Governance-pinned `ULP-1` circuit program hash.
    pub expected_program_hash: crate::domain::types::Hash32,
    /// Contiguous sequence of cross-domain hops (`A -> B -> C ...`).
    pub hops: Vec<UniversalRouteHop>,
}

/// Verified receipt produced by [`LightClient::verify_multi_hop_light_route`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Verified single-domain finality outcome extracted from a trusted
/// [`crate::settlement::GlobalBlockHeader::finality_certificate_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDomainFinality {
    pub domain_id: u32,
    pub bucket: crate::settlement::FinalityBucket,
    pub height: u64,
    pub state_root: crate::domain::types::Hash32,
    pub verdict: crate::settlement::FinalityVerdict,
    pub guarantee: crate::settlement::FinalityGuarantee,
    pub hub_composed_guarantee: crate::settlement::FinalityGuarantee,
    pub guarantee_label: String,
}

pub struct VerifiedUniversalRoute {
    /// Finalized settlement hub checkpoint height.
    pub hub_height: u64,
    /// Settlement epoch bound inside `ULP-1`.
    pub settlement_epoch: u64,
    /// Origin domain of the first hop.
    pub origin_domain: crate::domain::types::DomainId,
    /// Terminal destination domain of the last hop.
    pub terminal_domain: crate::domain::types::DomainId,
    /// Number of verified hops.
    pub hop_count: usize,
    /// Exact sum of `amount_bps` across all hops (`<= max_outflow_bps`).
    pub cumulative_outflow_bps: u16,
    /// Whether every traversed domain carried verified post-quantum security.
    pub post_quantum_clean: bool,
    /// Domain-separated commitment over the entire verified multi-hop path.
    pub route_digest: crate::domain::types::Hash32,
}

/// The single trust anchor a light client is bootstrapped from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    /// Block height of the anchor.
    pub height: u64,
    /// Canonical block hash at `height`.
    pub block_hash: String,
    /// Hash of the validator set that finalized `height`.
    pub set_hash: String,
}

/// A checkpoint that has been cryptographically verified against the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    /// Block height of the verified checkpoint.
    pub height: u64,
    /// Canonical block hash at `height`.
    pub block_hash: String,
    /// Hash of the validator set the certificate was verified against.
    pub set_hash: String,
    /// Epoch the finality certificate belonged to.
    pub epoch: u64,
    /// The external chain's state root at `height` (64-hex), as recorded in the
    /// finalized header. A consensus step anchors this via
    /// `AccountState::anchor_external_root` so the relayer gate can validate
    /// against it. Carried here so the verified finality fact
    /// survives past the verification call.
    pub state_root: String,
}

impl VerifiedCheckpoint {
    /// The external chain's state root at [`Self::height`], as a 32-byte digest
    /// ready to anchor via `AccountState::anchor_external_root`.
    ///
    /// Returns `None` when the recorded root is not a canonical 32-byte digest:
    /// such a value would be refused by the anchor (zero / malformed), so
    /// surfacing `None` keeps the caller from anchoring garbage.
    #[must_use]
    pub fn external_root(&self) -> Option<crate::domain::types::Hash32> {
        let bytes = hex::decode(&self.state_root).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Some(root)
    }
}

/// Why a checkpoint failed light-client verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightClientError {
    /// A hash string is not a canonical 64-hex digest.
    MalformedHash(String),
    /// The header fails hash self-consistency.
    InvalidHeader(String),
    /// The certificate does not bind to the header it claims to finalize.
    CertificateBinding(String),
    /// The certificate or snapshot does not bind to the trusted validator set.
    TrustBinding(String),
    /// The cryptographic verification (BLS quorum or PQ quorum) failed.
    VerificationFailed(String),
    /// `advance` was asked to move backwards or stay put.
    NotForward { trusted: u64, candidate: u64 },
    /// A verified checkpoint carries a different validator set than the anchor.
    SetChanged { trusted: String, candidate: String },
    /// A header chain is not contiguous and parent-linked.
    HeaderChain(String),
    /// A global header does not reopen the finalized state root, or does
    /// not belong to the checkpoint it is presented for.
    GlobalHeaderBinding(String),
}

impl fmt::Display for LightClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHash(h) => write!(f, "malformed hash: {h}"),
            Self::InvalidHeader(reason) => write!(f, "invalid header: {reason}"),
            Self::CertificateBinding(reason) => {
                write!(f, "certificate does not bind to the header: {reason}")
            }
            Self::TrustBinding(reason) => {
                write!(f, "certificate does not bind to the trusted set: {reason}")
            }
            Self::VerificationFailed(reason) => {
                write!(f, "finality verification failed: {reason}")
            }
            Self::NotForward { trusted, candidate } => write!(
                f,
                "checkpoint must move strictly forward: trusted {trusted}, candidate {candidate}"
            ),
            Self::SetChanged { trusted, candidate } => write!(
                f,
                "validator set changed under the light client: trusted {trusted}, candidate {candidate}"
            ),
            Self::HeaderChain(reason) => write!(f, "header chain invalid: {reason}"),
            Self::GlobalHeaderBinding(reason) => {
                write!(f, "global header does not bind to the checkpoint: {reason}")
            }
        }
    }
}

impl std::error::Error for LightClientError {}

/// The wire requests a transport must issue from the current trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightSyncPlan {
    /// `GetHeaders { locator, limit }` starting at the trusted block hash.
    pub headers_locator: Vec<String>,
    /// The next checkpoint height the light client needs a certificate for.
    /// `None` when the anchor already sits at or above the target.
    pub next_checkpoint_height: Option<u64>,
}

/// A light client holding one trusted validator-set commitment.
#[derive(Debug, Clone)]
pub struct LightClient {
    trusted: TrustedCheckpoint,
    /// Headers (height to hash) that `verify_header_chain` linked to the
    /// trust anchor. A checkpoint is only accepted for a header in this map,
    /// so a finalized header from an unrelated fork cannot move the anchor.
    linked: BTreeMap<u64, String>,
    /// Refuse a BLS-only checkpoint. Set for a mainnet client:
    /// there, finality needs the BLS certificate and the ML-DSA-65 QC of the
    /// same signers.
    require_pq: bool,
    /// The scheme statuses this client verifies post-quantum signatures under.
    ///
    /// Genesis statuses are the default, which is right for a client built
    /// against a fresh chain and wrong for one following a live chain: the
    /// Frost Alarm demotes a broken lattice family to `Disabled` in consensus
    /// state, and every node then refuses signatures under it in the same
    /// block. A client that kept judging by genesis statuses would verify a
    /// checkpoint the network itself rejects and advance its trust anchor on
    /// it. The wire carries no registry, so a client tracking a live chain pins
    /// the chain's registry with [`Self::with_scheme_registry`], exactly as it
    /// pins the trust anchor.
    registry: crate::crypto::scheme::SchemeStatusRegistry,
}

/// What a light client's verified checkpoints rest on (Section 6.2 of the PQ
///). Shown to the user beside every answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: light-client surface - the sync doors that read it land with their wiring.
pub enum TrustMode {
    /// The validator majority: the trusted set's finality certificates (BLS
    /// and ML-DSA-65 QC) and, across set changes, the handoff chain.
    Committee,
    /// The Budlum anchor key ledger: the last PQ anchor and the root seal.
    Anchor,
}

impl TrustMode {
    /// One line naming the trust a user accepts in this mode.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Committee => "committee mode: trusts a two-thirds majority of the validator set",
            Self::Anchor => "anchor mode: trusts the Budlum anchor key ledger",
        }
    }
}

impl LightClient {
    /// Bootstrap from a single trusted checkpoint.
    ///
    /// Both hashes must be canonical 64-hex digests; anything else is a
    /// bootstrap mistake that would poison every later verification.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::MalformedHash`] when either hash is not a
    /// canonical 64-hex digest.
    pub fn new(trusted: TrustedCheckpoint) -> Result<Self, LightClientError> {
        if !is_canonical_hash(&trusted.block_hash) {
            return Err(LightClientError::MalformedHash(format!(
                "block hash {} is not a canonical 64-hex digest",
                trusted.block_hash
            )));
        }
        if !is_canonical_hash(&trusted.set_hash) {
            return Err(LightClientError::MalformedHash(format!(
                "set hash {} is not a canonical 64-hex digest",
                trusted.set_hash
            )));
        }
        Ok(Self {
            trusted,
            linked: BTreeMap::new(),
            require_pq: false,
            registry: crate::crypto::scheme::SchemeStatusRegistry::genesis(),
        })
    }

    /// Bootstrap for the network of `chain_id`. A mainnet client refuses
    /// BLS-only checkpoints: only [`Self::verify_hybrid_checkpoint`]
    /// and [`Self::verify_pq_checkpoint`] advance it.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub fn for_chain(trusted: TrustedCheckpoint, chain_id: u64) -> Result<Self, LightClientError> {
        let mut client = Self::new(trusted)?;
        client.require_pq = chain_id
            == crate::core::chain_config::Network::Mainnet
                .chain_id()
                .value();
        Ok(client)
    }

    /// Pin the chain policy this client verifies under: the scheme statuses
    /// the chain holds in consensus state.
    ///
    /// The registry is not on the wire, so the caller pins it out of band like
    /// the trust anchor. Without it the client verifies under genesis statuses,
    /// and a family the chain has disabled keeps verifying here.
    #[must_use]
    pub fn with_scheme_registry(
        mut self,
        registry: crate::crypto::scheme::SchemeStatusRegistry,
    ) -> Self {
        self.registry = registry;
        self
    }

    /// The trust this client's checkpoints rest on: the validator committee.
    #[must_use]
    pub const fn trust_mode(&self) -> TrustMode {
        TrustMode::Committee
    }

    /// Whether this client refuses BLS-only checkpoints.
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub const fn requires_pq(&self) -> bool {
        self.require_pq
    }

    /// Verify a checkpoint with both halves: the BLS certificate as
    /// [`Self::verify_checkpoint`] checks it, and the ML-DSA-65 QC blob of
    /// the same signers over the same checkpoint.
    ///
    /// # Errors
    ///
    /// Any refusal of the BLS half, or a QC that does not bind to the
    /// certificate or misses a BLS signer.
    pub fn verify_hybrid_checkpoint(
        &self,
        header: &BlockHeader,
        cert: &FinalityCert,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        let verified = self.verify_bls_half(header, cert, snapshot)?;
        // The client's pinned registry, not a fresh genesis one: a family the
        // chain has demoted to `Disabled` must stop verifying here in the same
        // block it stops verifying on every node.
        crate::domain::finality_adapter::verify_pq_quorum(&self.registry, cert, snapshot, blob)
            .map_err(LightClientError::VerificationFailed)?;
        Ok(verified)
    }

    /// The current trust anchor.
    #[must_use]
    pub const fn trusted(&self) -> &TrustedCheckpoint {
        &self.trusted
    }

    /// Reject a snapshot whose metadata is not self-consistent.
    ///
    /// The snapshot arrives with the export, so it is untrusted input. Its
    /// `set_hash` and `total_stake` must be recomputed from the validator
    /// list before they are used to enforce quorum; otherwise a crafted
    /// export could lower `total_stake` and make a minority certificate pass
    /// the light-client quorum check.
    fn validate_snapshot_metadata(snapshot: &ValidatorSetSnapshot) -> Result<(), LightClientError> {
        snapshot
            .validate_metadata()
            .map_err(LightClientError::TrustBinding)
    }

    /// Verify a BLS finality certificate checkpoint against the trusted set.
    ///
    /// The checks run in order, each binding the next layer to the previous
    /// one: the header must hash to itself and be linked to the trust anchor
    /// by an earlier `verify_header_chain` call, the certificate must name exactly
    /// that header, the certificate and the snapshot must carry the trusted
    /// validator-set hash, and finally the BLS aggregate signature must carry
    /// the stake and signer quorum (`FinalityCert::verify`).
    ///
    /// # Errors
    ///
    /// Returns a [`LightClientError`] variant for each failed binding and for
    /// a certificate whose BLS signature fails `FinalityCert::verify`.
    pub fn verify_checkpoint(
        &self,
        header: &BlockHeader,
        cert: &FinalityCert,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        if self.require_pq {
            return Err(LightClientError::VerificationFailed(
                "a BLS-only checkpoint is refused on mainnet; verify the QC blob too".into(),
            ));
        }
        self.verify_bls_half(header, cert, snapshot)
    }

    fn verify_bls_half(
        &self,
        header: &BlockHeader,
        cert: &FinalityCert,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        Self::validate_snapshot_metadata(snapshot)?;
        if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
            return Err(LightClientError::InvalidHeader(format!(
                "header hash {} is not self-consistent",
                header.hash
            )));
        }
        if self.linked.get(&header.index) != Some(&header.hash) {
            return Err(LightClientError::HeaderChain(format!(
                "header {} at height {} is not linked to the trust anchor; run verify_header_chain first",
                header.hash, header.index
            )));
        }
        if header.index != cert.checkpoint_height {
            return Err(LightClientError::CertificateBinding(format!(
                "header height {} != certificate height {}",
                header.index, cert.checkpoint_height
            )));
        }
        if header.hash != cert.checkpoint_hash {
            return Err(LightClientError::CertificateBinding(format!(
                "header hash {} != certificate hash {}",
                header.hash, cert.checkpoint_hash
            )));
        }
        if cert.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "certificate set hash {} != trusted set hash {}",
                cert.set_hash, self.trusted.set_hash
            )));
        }
        if snapshot.set_hash != cert.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot set hash {} != certificate set hash {}",
                snapshot.set_hash, cert.set_hash
            )));
        }
        cert.verify(snapshot)
            .map_err(LightClientError::VerificationFailed)?;

        Ok(VerifiedCheckpoint {
            height: header.index,
            block_hash: header.hash.clone(),
            set_hash: cert.set_hash.clone(),
            epoch: cert.epoch,
            state_root: header.state_root.clone(),
        })
    }

    /// Verify a post-quantum quorum blob checkpoint against the trusted set.
    ///
    /// The same binding chain as [`Self::verify_checkpoint`], with the BLS
    /// aggregate replaced by the PQ quorum: every signature verifies against
    /// the snapshot's PQ public keys, no validator signs twice, and the
    /// unique signers must clear the legacy stake/count threshold. This
    /// snapshot-only fallback cannot replay Instant Seat Handover without
    /// finalized block records. The chain's PQ-alarm path uses the seat table;
    /// migrating this light client requires that history and remains the work package work.
    ///
    /// # Errors
    ///
    /// Returns a [`LightClientError`] variant for each failed binding and for
    /// a PQ blob whose signatures, stake quorum or signer count do not clear
    /// `QcBlob::verify_against_snapshot`.
    pub fn verify_pq_checkpoint(
        &self,
        header: &BlockHeader,
        blob: &QcBlob,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<VerifiedCheckpoint, LightClientError> {
        Self::validate_snapshot_metadata(snapshot)?;
        if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
            return Err(LightClientError::InvalidHeader(format!(
                "header hash {} is not self-consistent",
                header.hash
            )));
        }
        if self.linked.get(&header.index) != Some(&header.hash) {
            return Err(LightClientError::HeaderChain(format!(
                "header {} at height {} is not linked to the trust anchor; run verify_header_chain first",
                header.hash, header.index
            )));
        }
        if header.index != blob.checkpoint_height {
            return Err(LightClientError::CertificateBinding(format!(
                "header height {} != blob height {}",
                header.index, blob.checkpoint_height
            )));
        }
        if header.hash != blob.checkpoint_hash {
            return Err(LightClientError::CertificateBinding(format!(
                "header hash {} != blob hash {}",
                header.hash, blob.checkpoint_hash
            )));
        }
        if snapshot.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "snapshot set hash {} != trusted set hash {}",
                snapshot.set_hash, self.trusted.set_hash
            )));
        }
        if blob.epoch != snapshot.epoch {
            return Err(LightClientError::CertificateBinding(format!(
                "blob epoch {} != snapshot epoch {}",
                blob.epoch, snapshot.epoch
            )));
        }

        let verified = blob
            .verify_against_snapshot_in(&self.registry, snapshot, None, None)
            .map_err(LightClientError::VerificationFailed)?;

        // Summed exactly, like the threshold: a saturated partial sum met a
        // saturated threshold once the stakes passed the `u64` range.
        let voted_stake: u128 = verified
            .iter()
            .filter_map(|idx| snapshot.validators.get(*idx))
            .map(|v| u128::from(v.stake))
            .sum();
        if voted_stake < snapshot.quorum_stake() {
            return Err(LightClientError::VerificationFailed(format!(
                "PQ quorum stake {} < required {}",
                voted_stake,
                snapshot.quorum_stake()
            )));
        }
        if verified.len() < snapshot.quorum_count() {
            return Err(LightClientError::VerificationFailed(format!(
                "PQ quorum signers {} < required {}",
                verified.len(),
                snapshot.quorum_count()
            )));
        }

        Ok(VerifiedCheckpoint {
            height: header.index,
            block_hash: header.hash.clone(),
            set_hash: snapshot.set_hash.clone(),
            epoch: blob.epoch,
            state_root: header.state_root.clone(),
        })
    }

    /// Verify a headers-only chain segment without any block bodies.
    ///
    /// Every header must hash to itself, consecutive headers must be
    /// contiguous and parent-linked, and the first header must continue the
    /// trust anchor: it sits exactly one height above the anchor and its
    /// parent hash is the anchor's block hash. An unanchored first header
    /// would let a crafted export substitute a self-consistent finalized
    /// segment from an unrelated fork that reuses the same validator set
    /// (CWE-345).
    ///
    /// A segment that passes is remembered: `verify_checkpoint` and
    /// `verify_pq_checkpoint` accept only a header from a linked segment.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::HeaderChain`] for a malformed or
    /// disconnected segment and [`LightClientError::NotForward`] for a header
    /// at or below the anchor.
    pub fn verify_header_chain(&mut self, headers: &[BlockHeader]) -> Result<(), LightClientError> {
        let Some(first) = headers.first() else {
            return Err(LightClientError::HeaderChain(
                "no headers supplied".to_string(),
            ));
        };
        if headers.len() > MAX_LINKED_HEADERS {
            return Err(LightClientError::HeaderChain(format!(
                "header segment length {} exceeds MAX_LINKED_HEADERS ({MAX_LINKED_HEADERS})",
                headers.len()
            )));
        }
        let mut new_heights = 0usize;
        for header in headers {
            if !is_canonical_hash(&header.hash) || header.hash != header.calculate_hash() {
                return Err(LightClientError::HeaderChain(format!(
                    "header {} is not self-consistent",
                    header.index
                )));
            }
            if header.index <= self.trusted.height {
                return Err(LightClientError::NotForward {
                    trusted: self.trusted.height,
                    candidate: header.index,
                });
            }
            if let Some(existing) = self.linked.get(&header.index) {
                if existing != &header.hash {
                    return Err(LightClientError::HeaderChain(format!(
                        "conflicting header at height {}: {} != already-linked {}",
                        header.index, header.hash, existing
                    )));
                }
            } else {
                new_heights = new_heights.saturating_add(1);
            }
        }
        if self.linked.len().saturating_add(new_heights) > MAX_LINKED_HEADERS {
            return Err(LightClientError::HeaderChain(format!(
                "linked header cache would exceed MAX_LINKED_HEADERS ({MAX_LINKED_HEADERS})"
            )));
        }
        if first.index != self.trusted.height.saturating_add(1) {
            return Err(LightClientError::HeaderChain(format!(
                "first header height {} does not continue trusted height {}",
                first.index, self.trusted.height
            )));
        }
        if first.previous_hash != self.trusted.block_hash {
            return Err(LightClientError::HeaderChain(format!(
                "first header previous hash {} != trusted block hash {}",
                first.previous_hash, self.trusted.block_hash
            )));
        }
        for pair in headers.windows(2) {
            if let [prev, curr] = pair {
                if curr.index != prev.index.saturating_add(1) || curr.previous_hash != prev.hash {
                    return Err(LightClientError::HeaderChain(format!(
                        "headers {} and {} are not contiguous and parent-linked",
                        prev.index, curr.index
                    )));
                }
            }
        }
        for header in headers {
            self.linked.insert(header.index, header.hash.clone());
        }
        Ok(())
    }

    /// Move the trust anchor to a verified checkpoint.
    ///
    /// Strictly forward, and only within the trusted validator set: a
    /// certificate over a different set is a different chain, and following
    /// it without a new out-of-band anchor would hand the adversary the
    /// light client's trust.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::NotForward`] for a checkpoint at or below
    /// the anchor and [`LightClientError::SetChanged`] for a checkpoint over
    /// a different validator set.
    pub fn advance(&mut self, verified: &VerifiedCheckpoint) -> Result<(), LightClientError> {
        if verified.height <= self.trusted.height {
            return Err(LightClientError::NotForward {
                trusted: self.trusted.height,
                candidate: verified.height,
            });
        }
        if verified.set_hash != self.trusted.set_hash {
            return Err(LightClientError::SetChanged {
                trusted: self.trusted.set_hash.clone(),
                candidate: verified.set_hash.clone(),
            });
        }
        self.trusted = TrustedCheckpoint {
            height: verified.height,
            block_hash: verified.block_hash.clone(),
            set_hash: verified.set_hash.clone(),
        };
        self.linked.retain(|height, _| *height > verified.height);
        Ok(())
    }

    /// Move the trusted validator set across set changes by following the
    /// Handoff Certificate chain. `outgoing` must be the set
    /// the client trusts; each step is a certificate and the snapshot it
    /// hands to. Only ML-DSA-65 signatures are checked, so the move holds
    /// without trusting BLS. The anchor height stays; the next checkpoint
    /// verified over the new set advances it.
    ///
    /// # Errors
    ///
    /// `epoch_randomness` is the epoch randomness the caller independently
    /// obtained for each epoch on the way; the certificate's own `randomness`
    /// field seats the handoff committee, so a certificate cannot be allowed to
    /// name it (see [`crate::consensus::handoff::HandoffCertificate::verify_in`]).
    ///
    /// # Errors
    ///
    /// [`LightClientError::TrustBinding`] when `outgoing` is not the trusted
    /// set or a snapshot is not self-consistent, and
    /// [`LightClientError::VerificationFailed`] when the chain does not verify.
    /// WIRING: light-client surface - the sync doors that read it land with their wiring.
    pub fn follow_handoffs(
        &mut self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
        chain_id: u64,
        outgoing: &ValidatorSetSnapshot,
        steps: &[(
            crate::consensus::handoff::HandoffCertificate,
            ValidatorSetSnapshot,
        )],
        epoch_randomness: &dyn Fn(u64) -> [u8; 32],
    ) -> Result<u64, LightClientError> {
        use crate::consensus::handoff::{follow_handoffs, HandoffMember};
        if outgoing.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(
                "the outgoing set is not the trusted set".into(),
            ));
        }
        outgoing
            .validate_metadata()
            .map_err(LightClientError::TrustBinding)?;
        let Some((_, last)) = steps.last() else {
            return Ok(outgoing.epoch);
        };
        let mut member_steps = Vec::with_capacity(steps.len());
        for (idx, (cert, snapshot)) in steps.iter().enumerate() {
            snapshot
                .validate_metadata()
                .map_err(LightClientError::TrustBinding)?;
            let expected_next_epoch = outgoing
                .epoch
                .checked_add((idx as u64).saturating_add(1))
                .ok_or_else(|| LightClientError::TrustBinding("handoff epoch overflow".into()))?;
            if snapshot.epoch != expected_next_epoch {
                return Err(LightClientError::TrustBinding(format!(
                    "handoff snapshot epoch {} does not match expected {}",
                    snapshot.epoch, expected_next_epoch
                )));
            }
            for entry in &snapshot.validators {
                if !entry.bls_public_key.is_empty()
                    && !crate::chain::finality::verify_pop(entry, chain_id)
                {
                    return Err(LightClientError::TrustBinding(
                        "incoming validator failed BLS proof-of-possession".into(),
                    ));
                }
            }
            member_steps.push((cert.clone(), HandoffMember::from_snapshot(snapshot)));
        }
        let trusted_members = HandoffMember::from_snapshot(outgoing);
        let (epoch, _) = follow_handoffs(
            registry,
            chain_id,
            outgoing.epoch,
            &trusted_members,
            &member_steps,
            epoch_randomness,
        )
        .map_err(|e| LightClientError::VerificationFailed(e.to_string()))?;
        self.trusted.set_hash.clone_from(&last.set_hash);
        self.require_pq = true;
        Ok(epoch)
    }

    /// The next checkpoint height strictly above the anchor, given the chain's
    /// checkpoint interval. `None` when the anchor already sits at a
    /// checkpoint at or beyond `target_height` (i.e. nothing left to fetch).
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn next_checkpoint_height(&self, interval: u64, target_height: u64) -> Option<u64> {
        if interval == 0 || self.trusted.height >= target_height {
            return None;
        }
        // Closed form: one division, not a walk of up to 2^64 heights.
        let start = self.trusted.height.checked_add(1)?;
        let rest = start % interval;
        let next = if rest == 0 {
            start
        } else {
            start.checked_add(interval - rest)?
        };
        (next <= target_height).then_some(next)
    }

    /// Verify that `header` is the global header the finalized checkpoint
    /// commits: it was built at the checkpoint's height, and the
    /// checkpoint's state root reopens with `state_root_body` and the header
    /// hash (`AccountState::root_from_opening`). The chain a light client
    /// walks is then: trust anchor, finality certificate, block, global
    /// header, and from there any root the header carries.
    ///
    /// # Errors
    ///
    /// [`LightClientError::GlobalHeaderBinding`] when the header belongs to
    /// another checkpoint or the opening does not reproduce the state root;
    /// [`LightClientError::MalformedHash`] when the checkpoint's state root
    /// is not a 32-byte digest.
    pub fn verify_global_header(
        checkpoint: &VerifiedCheckpoint,
        state_root_body: &crate::domain::types::Hash32,
        header: &crate::settlement::GlobalBlockHeader,
    ) -> Result<(), LightClientError> {
        if header.checkpoint_height != checkpoint.height {
            return Err(LightClientError::GlobalHeaderBinding(format!(
                "header was built at height {}, the checkpoint is at {}",
                header.checkpoint_height, checkpoint.height
            )));
        }
        let state_root = checkpoint
            .external_root()
            .ok_or_else(|| LightClientError::MalformedHash(checkpoint.state_root.clone()))?;
        let reopened = crate::core::account::AccountState::root_from_opening(
            state_root_body,
            &header.calculate_hash_bytes(),
        );
        if reopened != state_root {
            return Err(LightClientError::GlobalHeaderBinding(
                "the opening and the header hash do not reproduce the finalized state root"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Checks an aggregated committee batch with `bud_proof::sigagg` against the
    /// committee this light client trusts.
    ///
    /// A batch carries its own committee root, weights and key digests, so none of that
    /// authenticates it. `committee` and `verify_signature` are the caller's: the batch must
    /// carry the root derived from `committee`, every entry must match a member, every signature
    /// must verify, and the quorum is the weight of the verified signers.
    ///
    /// Convenience: exposed for light-client committee batch callers.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError::VerificationFailed`] when the aggregated
    /// batch does not match the committee, carries a signature that does not
    /// verify, or does not meet `required_weight`.
    pub fn verify_committee_batch<F>(
        batch: &bud_proof::sigagg::AggregatedSignatureBatch,
        committee: &[bud_proof::sigagg::CommitteeMember],
        required_weight: u64,
        verify_signature: F,
    ) -> Result<(), LightClientError>
    where
        F: Fn(&bud_proof::sigagg::SignerSignature, &[u8; 32]) -> bool,
    {
        bud_proof::sigagg::verify_aggregated_batch(
            batch,
            committee,
            required_weight,
            verify_signature,
        )
        .map_err(|e| {
            LightClientError::VerificationFailed(format!(
                "aggregated committee batch failed: {e:?}"
            ))
        })
    }

    /// Verifies an aggregated committee batch against `checkpoint.block_hash`
    /// and the trusted `committee`, ensuring aggregated committee batch verification stays
    /// wired on the production light-client path.
    ///
    /// Convenience: exposed for light-client checkpoint batch verification callers.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if `checkpoint.block_hash` is not a 32-byte
    /// hex digest, does not match `batch.message_digest`, or fails
    /// [`Self::verify_committee_batch`].
    pub fn apply_committee_batch_checkpoint<F>(
        &self,
        checkpoint: &VerifiedCheckpoint,
        batch: &bud_proof::sigagg::AggregatedSignatureBatch,
        committee: &[bud_proof::sigagg::CommitteeMember],
        required_weight: u64,
        verify_signature: F,
    ) -> Result<(), LightClientError>
    where
        F: Fn(&bud_proof::sigagg::SignerSignature, &[u8; 32]) -> bool,
    {
        self.ensure_checkpoint_bound_to_trust(checkpoint)?;
        if !is_canonical_hash(&checkpoint.block_hash) {
            return Err(LightClientError::MalformedHash(
                checkpoint.block_hash.clone(),
            ));
        }
        let hash_bytes = hex::decode(&checkpoint.block_hash)
            .map_err(|_| LightClientError::MalformedHash(checkpoint.block_hash.clone()))?;
        if hash_bytes.as_slice() != batch.message_digest.as_slice() {
            return Err(LightClientError::CertificateBinding(
                "aggregated committee batch message_digest does not bind to checkpoint block_hash"
                    .to_string(),
            ));
        }
        Self::verify_committee_batch(batch, committee, required_weight, verify_signature)
    }

    /// Ensures `checkpoint` carries the trusted validator-set hash and names
    /// either the current trust anchor itself or a strictly forward header
    /// previously linked to that anchor via [`Self::verify_header_chain`].
    fn ensure_checkpoint_bound_to_trust(
        &self,
        checkpoint: &VerifiedCheckpoint,
    ) -> Result<(), LightClientError> {
        if checkpoint.set_hash != self.trusted.set_hash {
            return Err(LightClientError::TrustBinding(format!(
                "checkpoint set hash {} != trusted set hash {}",
                checkpoint.set_hash, self.trusted.set_hash
            )));
        }
        if checkpoint.height < self.trusted.height {
            return Err(LightClientError::NotForward {
                trusted: self.trusted.height,
                candidate: checkpoint.height,
            });
        }
        if checkpoint.height == self.trusted.height {
            if checkpoint.block_hash != self.trusted.block_hash {
                return Err(LightClientError::TrustBinding(format!(
                    "checkpoint block hash {} != trusted block hash {} at height {}",
                    checkpoint.block_hash, self.trusted.block_hash, checkpoint.height
                )));
            }
            return Ok(());
        }
        if self.linked.get(&checkpoint.height) != Some(&checkpoint.block_hash) {
            return Err(LightClientError::HeaderChain(format!(
                "checkpoint {} at height {} is not linked to the trust anchor",
                checkpoint.block_hash, checkpoint.height
            )));
        }
        Ok(())
    }

    /// Verify a single domain's finality row and Merkle inclusion proof against
    /// a consensus-committed [`crate::settlement::GlobalBlockHeader`].
    ///
    /// Re-verifies checkpoint trust, global-header state-root binding,
    /// `finality_certificate_root == Some(certificate.certificate_digest)`,
    /// full certificate integrity (`verify_integrity`), canonical bucket lookup,
    /// and the `O(log N)` Keccak-256 Merkle inclusion path.
    ///
    /// Convenience: exposed for light-client and wallet callers reading
    /// certified domain finality without trusting an RPC node.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if checkpoint trust, global-header binding,
    /// certificate root match, certificate integrity, or Merkle inclusion fails.
    pub fn verify_finality_certificate_domain(
        &self,
        checkpoint: &VerifiedCheckpoint,
        state_root_body: &crate::domain::types::Hash32,
        global_header: &crate::settlement::GlobalBlockHeader,
        certificate: &crate::settlement::GlobalFinalityCertificate,
        proof: &crate::settlement::DomainFinalityInclusionProof,
    ) -> Result<VerifiedDomainFinality, LightClientError> {
        self.ensure_checkpoint_bound_to_trust(checkpoint)?;
        Self::verify_global_header(checkpoint, state_root_body, global_header)?;

        let Some(committed_root) = global_header.finality_certificate_root else {
            return Err(LightClientError::GlobalHeaderBinding(
                "global header carries no finality_certificate_root".into(),
            ));
        };
        if committed_root != certificate.certificate_digest {
            return Err(LightClientError::GlobalHeaderBinding(
                "certificate digest does not match global_header.finality_certificate_root".into(),
            ));
        }
        if certificate.checkpoint_height != global_header.checkpoint_height {
            return Err(LightClientError::GlobalHeaderBinding(
                "certificate checkpoint_height does not match global_header.checkpoint_height"
                    .into(),
            ));
        }
        certificate.verify_integrity().map_err(
            |err: crate::settlement::FinalityComposeError| {
                LightClientError::VerificationFailed(format!(
                    "global finality certificate integrity failed: {err:?}"
                ))
            },
        )?;
        let bucket_root = certificate.bucket_root(proof.bucket);
        if !proof.verify(&bucket_root) {
            return Err(LightClientError::VerificationFailed(
                "domain finality Merkle inclusion proof failed verification".into(),
            ));
        }
        let expected_proof = certificate
            .prove_domain(proof.entry.domain_id)
            .ok_or_else(|| {
                LightClientError::VerificationFailed(
                    "domain_id absent from verified finality certificate".into(),
                )
            })?;
        if expected_proof.entry.row_digest() != proof.entry.row_digest() {
            return Err(LightClientError::VerificationFailed(
                "domain finality row digest conflicts with certificate entry".into(),
            ));
        }
        Ok(VerifiedDomainFinality {
            domain_id: proof.entry.domain_id,
            bucket: proof.bucket,
            height: proof.entry.height,
            state_root: proof.entry.state_root,
            verdict: proof.entry.verdict,
            guarantee: proof.entry.guarantee,
            hub_composed_guarantee: proof
                .entry
                .guarantee
                .meet(&crate::settlement::FinalityGuarantee::settlement_hub()),
            guarantee_label: proof.entry.guarantee.label(),
        })
    }

    /// Verifies a multi-hop cross-domain light-client route (`A -> B -> C ...`)
    /// anchored at `checkpoint` + `global_header` through a single succinct
    /// `ULP-1` proof bundle.
    ///
    /// Verification complexity is `O(1)` STARK verification plus `O(log C)`
    /// claim-inclusion checks and `O(hops * log D)` domain-inclusion checks,
    /// independent of the total claim set `C` and external domain count `D`.
    /// Under an active CRQC Frost Alarm emergency (`policy.crqc_alarm_active`),
    /// any route traversing a domain without verified post-quantum security is
    /// rejected fail-closed before acceptance.
    ///
    /// Convenience: exposed for multi-hop universal light-client callers.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if checkpoint trust binding, global-header
    /// opening, `ULP-1` proof verification, domain Merkle inclusion, hop
    /// continuity, cycle prevention, outflow ceiling (`<= 25%`), or Frost Alarm
    /// post-quantum policy fails.
    pub fn verify_multi_hop_light_route(
        &self,
        checkpoint: &VerifiedCheckpoint,
        state_root_body: &crate::domain::types::Hash32,
        global_header: &crate::settlement::GlobalBlockHeader,
        packet: &UniversalLightPacket,
        policy: &UniversalRoutePolicy,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
    ) -> Result<VerifiedUniversalRoute, LightClientError> {
        use crate::aggregation::universal_light_proof::{
            open_universal_light_proof, MAX_ULP_OUTFLOW_BPS,
        };

        self.ensure_checkpoint_bound_to_trust(checkpoint)?;
        Self::verify_global_header(checkpoint, state_root_body, global_header)?;

        if policy.max_hops == 0 || policy.max_hops > MAX_UNIVERSAL_ROUTE_HOPS {
            return Err(LightClientError::VerificationFailed(
                "ULP-1 route policy max_hops out of bounds".into(),
            ));
        }
        let effective_ceiling = policy.max_outflow_bps.min(MAX_ULP_OUTFLOW_BPS);
        if packet.hops.is_empty() || packet.hops.len() > policy.max_hops {
            return Err(LightClientError::VerificationFailed(format!(
                "ULP-1 hop count {} outside 1..={}",
                packet.hops.len(),
                policy.max_hops
            )));
        }

        // Every trust anchor below comes from the verified global header or
        // the caller's policy, never from the packet: a bundle cannot vouch
        // for its own hub, program, or domain set.
        let verified_hub_chain_id = u32::try_from(global_header.chain_id).map_err(|_| {
            LightClientError::VerificationFailed(
                "ULP-1 verified hub chain id does not fit the domain id space".into(),
            )
        })?;
        if packet.ulp_bundle.hub_chain_id != verified_hub_chain_id {
            return Err(LightClientError::VerificationFailed(format!(
                "ULP-1 bundle hub_chain_id {} is not this hub's verified chain id {}",
                packet.ulp_bundle.hub_chain_id, verified_hub_chain_id
            )));
        }
        let canonical = crate::aggregation::universal_light_proof::compile_ulp_program(
            verified_hub_chain_id,
            usize::try_from(packet.ulp_bundle.domain_count).unwrap_or(usize::MAX),
        )
        .map_err(|e| LightClientError::VerificationFailed(e.to_string()))?;
        if packet.expected_program_hash != canonical.program_hash {
            return Err(LightClientError::VerificationFailed(
                "ULP-1 packet program hash differs from the canonical circuit".into(),
            ));
        }
        let trusted_domains_root = match (
            global_header.ulp_domains_root,
            policy.trusted_domains_root,
        ) {
            (Some(header_root), Some(policy_root)) if header_root != policy_root => {
                return Err(LightClientError::GlobalHeaderBinding(
                    "ULP-1 policy trusted_domains_root conflicts with global_header.ulp_domains_root"
                        .into(),
                ));
            }
            (Some(header_root), _) => header_root,
            (None, Some(policy_root)) => policy_root,
            (None, None) => {
                return Err(LightClientError::VerificationFailed(
                    "ULP-1 verified global header and route policy carry no trusted domains root; value routes stay fail-closed"
                        .into(),
                ));
            }
        };
        let hub_root = global_header.calculate_hash_bytes();
        // The settlement epoch the bundle must have witnessed is re-derived
        // from the trusted anchor, never taken from the packet: the same
        // canonical rule the consensus layer applies to checkpoint certificates.
        let expected_settlement_epoch =
            crate::aggregation::universal_light_proof::ulp_expected_settlement_epoch(
                global_header.chain_id,
                global_header.checkpoint_height,
            );
        let ulp_header = open_universal_light_proof(
            &packet.ulp_bundle,
            &canonical.program_hash,
            verified_hub_chain_id,
            &hub_root,
            expected_settlement_epoch,
            registry,
        )
        .map_err(|e| LightClientError::VerificationFailed(e.to_string()))?;
        if ulp_header.domains_merkle_root != trusted_domains_root {
            return Err(LightClientError::VerificationFailed(
                "ULP-1 bundle domain-set root differs from the pinned trusted root".into(),
            ));
        }

        if ulp_header.max_outflow_bps > effective_ceiling {
            return Err(LightClientError::VerificationFailed(format!(
                "ULP-1 bundle max_outflow_bps {} exceeds policy ceiling {}",
                ulp_header.max_outflow_bps, effective_ceiling
            )));
        }

        let mut visited = std::collections::BTreeSet::new();
        let mut cumulative_outflow_bps = 0u16;
        let mut post_quantum_clean = true;
        let mut route_acc = hub_root;
        let mut prev_dest: Option<&crate::aggregation::universal_light_proof::UlpDomainSnapshot> =
            None;
        let mut prev_seq: Option<u64> = None;

        for (hop_idx, hop) in packet.hops.iter().enumerate() {
            if hop.source.domain_id == hop.destination.domain_id {
                return Err(LightClientError::VerificationFailed(
                    "ULP-1 self-loop hop refused".into(),
                ));
            }
            if hop.packet_commitment == [0u8; 32] || hop.source.event_root == [0u8; 32] {
                return Err(LightClientError::VerificationFailed(
                    "ULP-1 hop missing packet_commitment or source event_root".into(),
                ));
            }
            if let Some(prev) = prev_dest {
                if hop.source != *prev {
                    return Err(LightClientError::VerificationFailed(format!(
                        "ULP-1 route discontinuity at hop {hop_idx}: source domain {} does not match prior destination {}",
                        hop.source.domain_id, prev.domain_id
                    )));
                }
            } else {
                visited.insert(hop.source.domain_id);
            }
            if !visited.insert(hop.destination.domain_id) {
                return Err(LightClientError::VerificationFailed(format!(
                    "ULP-1 route cycle detected at domain {}",
                    hop.destination.domain_id
                )));
            }
            if let Some(last_seq) = prev_seq {
                if hop.sequence <= last_seq {
                    return Err(LightClientError::VerificationFailed(
                        "ULP-1 hop sequence must strictly increase".into(),
                    ));
                }
            }
            prev_seq = Some(hop.sequence);

            // O(log D) Merkle inclusion proofs against the verified ULP-1 domain root.
            hop.source_proof
                .verify(&hop.source, &ulp_header.domains_merkle_root)
                .map_err(|e| LightClientError::VerificationFailed(e.to_string()))?;
            hop.destination_proof
                .verify(&hop.destination, &ulp_header.domains_merkle_root)
                .map_err(|e| LightClientError::VerificationFailed(e.to_string()))?;

            for endpoint in [&hop.source, &hop.destination] {
                if endpoint.security_weight < policy.min_security_weight {
                    return Err(LightClientError::VerificationFailed(format!(
                        "ULP-1 domain {} security_weight {} below minimum {}",
                        endpoint.domain_id, endpoint.security_weight, policy.min_security_weight
                    )));
                }
                if endpoint.outflow_bps > effective_ceiling {
                    return Err(LightClientError::VerificationFailed(format!(
                        "ULP-1 domain {} outflow {} bps exceeds ceiling {} bps",
                        endpoint.domain_id, endpoint.outflow_bps, effective_ceiling
                    )));
                }
                let endpoint_pq = endpoint.kind.is_post_quantum_safe(endpoint.pq_attested);
                post_quantum_clean &= endpoint_pq;
                if policy.crqc_alarm_active && policy.require_pq_on_crqc_alarm && !endpoint_pq {
                    return Err(LightClientError::VerificationFailed(format!(
                        "ULP-1 Frost Alarm refused non-PQ domain {} ({:?})",
                        endpoint.domain_id, endpoint.kind
                    )));
                }
            }

            if hop.amount_bps == 0 || hop.amount_bps > effective_ceiling {
                return Err(LightClientError::VerificationFailed(format!(
                    "ULP-1 hop {hop_idx} amount {} bps outside 1..={effective_ceiling}",
                    hop.amount_bps
                )));
            }
            cumulative_outflow_bps = cumulative_outflow_bps
                .checked_add(hop.amount_bps)
                .filter(|&sum| sum <= effective_ceiling)
                .ok_or_else(|| {
                    LightClientError::VerificationFailed(format!(
                        "ULP-1 cumulative route outflow exceeds 25% ceiling ({effective_ceiling} bps)"
                    ))
                })?;

            route_acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_ULP_OUTPUT_V1",
                &route_acc,
                &hop.source.domain_id.to_be_bytes(),
                &hop.destination.domain_id.to_be_bytes(),
                &hop.sequence.to_be_bytes(),
                &hop.amount_bps.to_be_bytes(),
                &hop.packet_commitment,
            ]);
            prev_dest = Some(&hop.destination);
        }

        let origin_domain = packet.hops.first().map_or(0, |h| h.source.domain_id);
        let terminal_domain = packet.hops.last().map_or(0, |h| h.destination.domain_id);

        Ok(VerifiedUniversalRoute {
            hub_height: checkpoint.height,
            settlement_epoch: ulp_header.settlement_epoch,
            origin_domain,
            terminal_domain,
            hop_count: packet.hops.len(),
            cumulative_outflow_bps,
            post_quantum_clean,
            route_digest: route_acc,
        })
    }

    /// Evaluates Phase-A dual finality parity between the native finality path
    /// and a secondary zkVM proof (`TA8`).
    ///
    /// Convenience: exposed for checkpoint dual-finality callers.
    #[must_use]
    pub fn evaluate_checkpoint_phase_a(
        domain_id: crate::domain::types::DomainId,
        native_result: (bool, crate::domain::types::Hash32),
        zkvm_result: Option<(bool, crate::domain::types::Hash32)>,
    ) -> crate::cross_domain::external::phase_a_dual::PhaseAVerdict {
        crate::cross_domain::external::phase_a_dual::evaluate_phase_a_dual(
            domain_id,
            native_result,
            zkvm_result,
        )
    }

    /// Classifies a finalized checkpoint height against `proven_height` under
    /// the bounded batch-proof lag rule (`TA5`).
    ///
    /// Convenience: exposed for checkpoint batch-proof status callers.
    #[must_use]
    pub const fn checkpoint_proof_status(
        block_height: u64,
        proven_height: u64,
    ) -> crate::cross_domain::external::phase_a_dual::RootProofStatus {
        crate::cross_domain::external::phase_a_dual::classify_root_proof_status(
            block_height,
            proven_height,
        )
    }

    /// The wire requests a transport must issue from this anchor: a
    /// `GetHeaders` locator rooted at the trusted hash, and the next
    /// checkpoint height a certificate is needed for.
    #[must_use]
    pub fn sync_plan(&self, interval: u64, target_height: u64) -> LightSyncPlan {
        LightSyncPlan {
            headers_locator: vec![self.trusted.block_hash.clone()],
            next_checkpoint_height: self.next_checkpoint_height(interval, target_height),
        }
    }
}

/// One sibling link in a [`RemoteStateView`] Merkle inclusion path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteMerkleStep {
    /// 32-byte sibling digest at this tree height.
    pub sibling: [u8; 32],
    /// True if `sibling` sits on the right (`H(node || sibling)`), false if on the left.
    pub sibling_is_right: bool,
}

/// Verified cross-domain remote state view (`RemoteStateView`).
///
/// Binds an external domain's finalized `remote_state_root` to a checkpointed
/// [`crate::settlement::GlobalBlockHeader`], verifies Merkle inclusion of
/// `(state_key, state_value)`. Attached ownership/capability predicates stay
/// closed until their public statement is bound to this exact leaf and domain;
/// verifying an unrelated valid STARK is not ownership evidence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemoteStateView {
    /// Source external domain identifier.
    pub remote_domain_id: u64,
    /// Committed state root of the remote domain at `header.checkpoint_height`.
    pub remote_state_root: [u8; 32],
    /// Global block header anchored at the trusted checkpoint.
    pub header: crate::settlement::GlobalBlockHeader,
    /// Key inside the remote domain state tree.
    pub state_key: Vec<u8>,
    /// Claimed state value bytes stored under `state_key`.
    pub state_value: Vec<u8>,
    /// Merkle path from leaf digest up to `remote_state_root`.
    pub inclusion_path: Vec<RemoteMerkleStep>,
    /// Reserved for a future leaf-bound ownership/capability proof. Any
    /// attached proof is refused until its relation to the leaf is specified.
    pub predicate_proof: Option<bud_proof::predicates::PredicateProof>,
}

impl RemoteStateView {
    /// Canonical commitment binding `remote_domain_id` and `remote_state_root`
    /// into `GlobalBlockHeader::domain_commitment_root`.
    #[must_use]
    pub fn expected_domain_commitment(
        remote_domain_id: u64,
        remote_state_root: &[u8; 32],
    ) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_REMOTE_STATE_VIEW_V1",
            &remote_domain_id.to_le_bytes(),
            remote_state_root,
        ])
    }

    /// Canonical leaf digest for `(state_key, state_value)`.
    #[must_use]
    pub fn leaf_digest(state_key: &[u8], state_value: &[u8]) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_REMOTE_STATE_LEAF_V1",
            state_key,
            state_value,
        ])
    }

    /// Reconstruct the Merkle root for `(state_key, state_value)` across `inclusion_path`.
    #[must_use]
    pub fn compute_merkle_root(
        state_key: &[u8],
        state_value: &[u8],
        inclusion_path: &[RemoteMerkleStep],
    ) -> [u8; 32] {
        let mut current = Self::leaf_digest(state_key, state_value);
        for step in inclusion_path {
            current = if step.sibling_is_right {
                crate::core::hash::hash_fields_bytes(&[
                    b"BDLM_REMOTE_STATE_NODE_V1",
                    &current,
                    &step.sibling,
                ])
            } else {
                crate::core::hash::hash_fields_bytes(&[
                    b"BDLM_REMOTE_STATE_NODE_V1",
                    &step.sibling,
                    &current,
                ])
            };
        }
        current
    }

    /// Verify checkpoint binding, remote domain root commitment, and state
    /// inclusion path. Unbound optional predicates remain fail-closed.
    ///
    /// # Errors
    ///
    /// Returns [`LightClientError`] if app binding is disabled on `chain_id`,
    /// global header binding fails, domain commitment mismatches, Merkle inclusion
    /// fails, or the attached `PredicateProof` is invalid.
    pub fn verify_for_chain(
        &self,
        checkpoint: &VerifiedCheckpoint,
        state_root_body: &crate::domain::types::Hash32,
        chain_id: u64,
    ) -> Result<(), LightClientError> {
        if !crate::core::chain_config::app_binding_enabled_for_chain_id(chain_id) {
            return Err(LightClientError::VerificationFailed(format!(
                "RemoteStateView app binding disabled for chain_id {chain_id}"
            )));
        }
        LightClient::verify_global_header(checkpoint, state_root_body, &self.header)?;
        let expected_domain_root =
            Self::expected_domain_commitment(self.remote_domain_id, &self.remote_state_root);
        if self.header.domain_commitment_root != expected_domain_root {
            return Err(LightClientError::GlobalHeaderBinding(
                "remote_state_root does not match header.domain_commitment_root".to_string(),
            ));
        }
        let recomputed_root =
            Self::compute_merkle_root(&self.state_key, &self.state_value, &self.inclusion_path);
        if recomputed_root != self.remote_state_root {
            return Err(LightClientError::VerificationFailed(
                "RemoteStateView Merkle inclusion proof failed".to_string(),
            ));
        }
        if self.predicate_proof.is_some() {
            return Err(LightClientError::VerificationFailed(
                "RemoteStateView predicate is not bound to the committed state leaf".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::finality::{
        pop_signing_message, sign_bls, sign_bls_pop, FinalityAggregator, Precommit, Prevote,
        ValidatorEntry,
    };
    use crate::consensus::qc::{pq_signing_message, PqSignatureEntry};
    use crate::core::address::Address;
    use crate::core::block::Block;
    use crate::crypto::primitives::{BlsKeypair, PqKeyPair};
    use bls12_381::{G1Affine, G1Projective, Scalar};

    const TEST_CHAIN_ID: u64 = crate::core::transaction::DEFAULT_CHAIN_ID;

    /// The committee batch check takes the committee and the signature check from the caller. A
    /// batch of filler bytes with the committee's own root and weights used to pass, because
    /// nothing verified a signature and the batch declared its own quorum.
    #[test]
    fn a_committee_batch_of_filler_signatures_is_refused() {
        use bud_proof::sigagg::{
            aggregate_signatures, compute_committee_root, CommitteeMember, SignatureScheme,
            SignerSignature,
        };
        let committee: Vec<CommitteeMember> = vec![
            (0, 30, SignatureScheme::Ed25519, [1u8; 32]),
            (1, 40, SignatureScheme::Bls, [2u8; 32]),
            (2, 50, SignatureScheme::MlDsa87, [3u8; 32]),
        ];
        let entries: Vec<SignerSignature> = committee
            .iter()
            .map(|&(idx, weight, scheme, key)| SignerSignature {
                signer_index: idx,
                weight,
                scheme,
                public_key_digest: key,
                signature: vec![0xA5; scheme.min_signature_len()],
                threshold_witness: None,
            })
            .collect();
        let batch = aggregate_signatures([0x42u8; 32], compute_committee_root(&committee), entries)
            .expect("a well-formed batch");

        // A verifier that checks the signatures refuses the filler.
        match LightClient::verify_committee_batch(&batch, &committee, 80, |_, _| false) {
            Err(LightClientError::VerificationFailed(message)) => {
                assert!(message.contains("InvalidSignature"), "{message}");
            }
            other => panic!("filler signatures must be refused: {other:?}"),
        }
        // Control: the same batch passes when the caller's verifier accepts it,
        assert!(LightClient::verify_committee_batch(&batch, &committee, 80, |_, _| true).is_ok());
        // and the quorum is the committee's weight, not a number the batch declares.
        assert!(LightClient::verify_committee_batch(&batch, &committee, 121, |_, _| true).is_err());
    }

    /// The trust anchor is a 64-hex digest in its one canonical spelling: an
    /// upper-case copy names the same block to a human, and a different string
    /// to every comparison the client makes.
    #[test]
    fn an_upper_case_trust_anchor_is_refused() {
        let trusted = TrustedCheckpoint {
            height: 7,
            block_hash: "AA".repeat(32),
            set_hash: "bb".repeat(32),
        };
        assert!(matches!(
            LightClient::new(trusted),
            Err(LightClientError::MalformedHash(_))
        ));
    }

    fn make_bls_key(seed: u8) -> BlsKeypair {
        let mut sk_bytes = [0u8; 64];
        sk_bytes[0] = seed + 1;
        BlsKeypair::from_seed(&sk_bytes).expect("a non-zero test seed")
    }

    fn make_bls_snapshot(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
        let mut sks = Vec::new();
        let validators: Vec<ValidatorEntry> = (0..n)
            .map(|i| {
                let key = make_bls_key(u8::try_from(i).expect("test validator count is small"));
                sks.push(key.secret_key);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = u8::try_from(i + 1).expect("test validator count is small");
                let addr = Address::from(addr_bytes);
                let pop_msg = pop_signing_message(TEST_CHAIN_ID, &addr, &key.public_key);
                let pop_sig = sign_bls_pop(&key.secret_key, &pop_msg);
                ValidatorEntry {
                    address: addr,
                    stake: stake_each,
                    bls_public_key: key.public_key.clone(),
                    pop_signature: pop_sig,
                    pq_public_key: Vec::new(),
                }
            })
            .collect();
        (ValidatorSetSnapshot::new(1, validators), sks)
    }

    fn make_block_header_at(height: u64, chain_id: u64) -> BlockHeader {
        let block = Block::new_with_chain_id(height, "0".repeat(64), Vec::new(), chain_id);
        BlockHeader::from_block(&block)
    }

    /// Produce a real BLS finality certificate for `header` signed by
    /// `signers` of the snapshot's keys (the first `signers` validators).
    fn make_valid_bls_cert(
        snapshot: &ValidatorSetSnapshot,
        sks: &[Scalar],
        header: &BlockHeader,
        signers: usize,
    ) -> FinalityCert {
        let checkpoint_hash = header.hash.clone();
        let mut agg = FinalityAggregator::new(
            crate::core::transaction::DEFAULT_CHAIN_ID,
            snapshot.epoch,
            header.index,
            checkpoint_hash.clone(),
            snapshot.clone(),
        );

        for (i, sk) in sks.iter().enumerate().take(signers) {
            let vote = Prevote {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                epoch: snapshot.epoch,
                checkpoint_height: header.index,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: snapshot.validators[i].address,
                sig_bls: vec![],
                auth_sig: Vec::new(),
            };
            let sig = sign_bls(sk, &vote.signing_message());
            let mut signed = vote;
            signed.sig_bls = sig;
            agg.add_prevote(signed).unwrap();
        }

        let mut agg_sig = G1Projective::identity();
        for (i, sk) in sks.iter().enumerate().take(signers) {
            let pc = Precommit {
                chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
                epoch: snapshot.epoch,
                checkpoint_height: header.index,
                checkpoint_hash: checkpoint_hash.clone(),
                voter_id: snapshot.validators[i].address,
                sig_bls: vec![],
                auth_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            let sig = sign_bls(sk, &pc.signing_message());
            let mut signed = pc;
            signed.sig_bls = sig.clone();
            agg.add_precommit(signed).unwrap();
            let sig_affine = G1Affine::from_compressed(&sig.try_into().unwrap()).unwrap();
            agg_sig += G1Projective::from(sig_affine);
        }

        let mut cert = agg.try_produce_cert().expect("certificate produced");
        cert.agg_sig_bls = G1Affine::from(agg_sig).to_compressed().to_vec();
        cert
    }

    #[test]
    fn a_mainnet_client_refuses_a_bls_only_checkpoint() {
        let trusted = TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        };
        let mainnet = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        let client = LightClient::for_chain(trusted.clone(), mainnet).expect("anchor");
        assert!(client.requires_pq());
        assert_eq!(client.trust_mode(), TrustMode::Committee);
        let (snapshot, _) = make_bls_snapshot(1, 100);
        let header = make_block_header_at(1, mainnet);
        let cert = FinalityCert {
            epoch: 1,
            checkpoint_height: 1,
            checkpoint_hash: header.hash.clone(),
            chain_id: mainnet,
            agg_sig_bls: Vec::new(),
            bitmap: vec![1],
            set_hash: snapshot.set_hash.clone(),
            seat_table_version: 0,
        };
        let err = client
            .verify_checkpoint(&header, &cert, &snapshot)
            .expect_err("BLS-only is refused before any binding check");
        assert!(matches!(err, LightClientError::VerificationFailed(_)));
        assert!(!LightClient::for_chain(trusted, TEST_CHAIN_ID)
            .expect("anchor")
            .requires_pq());
    }

    #[test]
    fn bootstrap_rejects_malformed_hashes() {
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "short".into(),
            set_hash: "0".repeat(64),
        })
        .is_err());
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: "not-a-hash".into(),
        })
        .is_err());
        assert!(LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .is_ok());
    }

    #[test]
    fn verifies_a_real_bls_checkpoint_and_advances() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        let verified = client
            .verify_checkpoint(&header, &cert, &snapshot)
            .expect("honest checkpoint verifies");
        assert_eq!(verified.height, 10);
        assert_eq!(verified.block_hash, header.hash);
        assert_eq!(verified.set_hash, snapshot.set_hash);

        client.advance(&verified).expect("advance");
        assert_eq!(client.trusted().height, 10);
        assert_eq!(client.trusted().block_hash, header.hash);
    }

    #[test]
    fn rejects_a_certificate_for_a_different_header() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.checkpoint_hash = "1".repeat(64);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::CertificateBinding(_))
        ));
    }

    #[test]
    fn rejects_a_certificate_over_a_different_validator_set() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.set_hash = "f".repeat(64);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::TrustBinding(_))
        ));
    }

    #[test]
    fn rejects_a_certificate_below_the_quorum() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        // Produce a valid three-of-four certificate, then shrink the bitmap
        // to two signers: two of four validators is not a 2/3 quorum, so the
        // certificate must be rejected at the cryptographic step, not the
        // binding steps.
        let mut cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);
        cert.bitmap = vec![0b0000_0011];

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        assert!(matches!(
            client.verify_checkpoint(&header, &cert, &snapshot),
            Err(LightClientError::VerificationFailed(_))
        ));
    }

    /// A verified checkpoint exposes the external state root
    /// as an anchorable Hash32; non-32-byte / non-hex roots are refused.
    #[test]
    fn verified_checkpoint_exposes_anchorable_external_root() {
        let cp = VerifiedCheckpoint {
            height: 5,
            block_hash: "a".repeat(64),
            set_hash: "b".repeat(64),
            epoch: 2,
            state_root: "c".repeat(64),
        };
        assert_eq!(cp.external_root(), Some([0xcc; 32]));

        let short = VerifiedCheckpoint {
            height: 5,
            block_hash: "a".repeat(64),
            set_hash: "b".repeat(64),
            epoch: 2,
            state_root: "c".repeat(62),
        };
        assert_eq!(short.external_root(), None);

        let nonhex = VerifiedCheckpoint {
            height: 5,
            block_hash: "a".repeat(64),
            set_hash: "b".repeat(64),
            epoch: 2,
            state_root: "zz".repeat(32),
        };
        assert_eq!(nonhex.external_root(), None);
    }

    #[test]
    fn advance_rejects_regression_and_set_change() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let cert = make_valid_bls_cert(&snapshot, &sks, &header, 3);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        let verified = client
            .verify_checkpoint(&header, &cert, &snapshot)
            .expect("honest checkpoint verifies");

        // Same height is not forward.
        let mut other = client.clone();
        assert!(matches!(
            other.advance(&VerifiedCheckpoint {
                height: 0,
                block_hash: "0".repeat(64),
                set_hash: snapshot.set_hash,
                epoch: 1,
                state_root: String::new(),
            }),
            Err(LightClientError::NotForward { .. })
        ));

        // A different set hash is a different chain.
        let mut changed = client.clone();
        assert!(matches!(
            changed.advance(&VerifiedCheckpoint {
                height: 1,
                block_hash: "1".repeat(64),
                set_hash: "f".repeat(64),
                epoch: 1,
                state_root: String::new(),
            }),
            Err(LightClientError::SetChanged { .. })
        ));

        client.advance(&verified).expect("forward advance");
    }

    #[test]
    fn verifies_a_real_pq_checkpoint_and_advances() {
        let (snapshot, keys) = make_pq_snapshot(3, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let blob = make_pq_blob(&snapshot, &keys, &header);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        let verified = client
            .verify_pq_checkpoint(&header, &blob, &snapshot)
            .expect("honest PQ checkpoint verifies");
        assert_eq!(verified.height, 10);

        client.advance(&verified).expect("advance");
        assert_eq!(client.trusted().height, 10);
    }

    /// The client verifies PQ signatures under the registry it was pinned to,
    /// not a fresh genesis registry.
    ///
    /// The Frost Alarm demotes a lattice family to `Disabled` in consensus
    /// state and every node refuses signatures under it in the same block. A
    /// client that verified under `SchemeStatusRegistry::genesis()` kept
    /// accepting them, printed `CHECKPOINT VERIFIED`, and advanced its trust
    /// anchor on a checkpoint the network itself rejects.
    #[test]
    fn a_pinned_registry_decides_whether_the_pq_half_verifies() {
        use crate::crypto::scheme::{SchemeId, SchemeStatus, SchemeStatusRegistry};

        let (snapshot, keys) = make_pq_snapshot(3, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let blob = make_pq_blob(&snapshot, &keys, &header);
        let trusted = TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        };
        let mut linked = LightClient::new(trusted.clone()).expect("bootstrap");
        linked.linked.insert(header.index, header.hash.clone());
        linked
            .verify_pq_checkpoint(&header, &blob, &snapshot)
            .expect("the genesis statuses accept the blob");

        // The same blob, judged by a chain that has disabled the family the
        // validators signed with.
        let (mut schemes, suites) = SchemeStatusRegistry::genesis().entries();
        for (id, status) in &mut schemes {
            if *id == SchemeId::ML_DSA_65.0 {
                *status = SchemeStatus::Disabled.to_byte();
            }
        }
        let disabled =
            SchemeStatusRegistry::from_entries(&schemes, &suites).expect("a full registry");
        assert!(!disabled.scheme_verifies(SchemeId::ML_DSA_65));

        let mut pinned = LightClient::new(trusted)
            .expect("bootstrap")
            .with_scheme_registry(disabled);
        pinned.linked.insert(header.index, header.hash.clone());
        assert!(
            matches!(
                pinned.verify_pq_checkpoint(&header, &blob, &snapshot),
                Err(LightClientError::VerificationFailed(_))
            ),
            "a family the chain disabled must not verify here"
        );
    }

    #[test]
    fn pq_path_rejects_a_duplicate_signer_blob() {
        let (snapshot, keys) = make_pq_snapshot(3, 1000);
        let header = make_block_header_at(10, TEST_CHAIN_ID);
        let mut blob = make_pq_blob(&snapshot, &keys, &header);
        // Duplicate the first signature: the same validator signing twice is
        // one attestation, not two (canary, qcblob_quorum).
        let dup = blob.pq_signatures[0].clone();
        blob.pq_signatures.push(dup);
        blob.merkle_root = QcBlob::compute_merkle_root(&blob.pq_signatures);

        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();
        client.linked.insert(header.index, header.hash.clone());

        assert!(matches!(
            client.verify_pq_checkpoint(&header, &blob, &snapshot),
            Err(LightClientError::VerificationFailed(_))
        ));
    }

    #[test]
    fn header_chain_requires_contiguity_and_forward_motion() {
        let (snapshot, _sks) = make_bls_snapshot(4, 1000);
        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash,
        })
        .unwrap();

        let h1 = make_block_header_at(1, TEST_CHAIN_ID);
        let mut h2 = make_block_header_at(2, TEST_CHAIN_ID);
        h2.previous_hash = h1.hash.clone();
        h2.hash = h2.calculate_hash();
        assert!(client.verify_header_chain(&[h1.clone(), h2]).is_ok());

        // A gap breaks the chain.
        let h3 = make_block_header_at(3, TEST_CHAIN_ID);
        let broken = [h1, h3];
        assert!(client.verify_header_chain(&broken).is_err());

        // A header at or below the anchor is not forward.
        let anchor_header = make_block_header_at(0, TEST_CHAIN_ID);
        assert!(matches!(
            client.verify_header_chain(&[anchor_header]),
            Err(LightClientError::NotForward { .. })
        ));
    }

    /// A finalized header that `verify_header_chain` never linked to the
    /// anchor is refused, even with a valid certificate (audit).
    #[test]
    fn checkpoint_requires_a_header_linked_to_the_anchor() {
        let (snapshot, sks) = make_bls_snapshot(4, 1000);
        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: "0".repeat(64),
            set_hash: snapshot.set_hash.clone(),
        })
        .unwrap();

        let mut h1 = make_block_header_at(1, TEST_CHAIN_ID);
        h1.previous_hash = "0".repeat(64);
        h1.hash = h1.calculate_hash();
        let mut h2 = make_block_header_at(2, TEST_CHAIN_ID);
        h2.previous_hash = h1.hash.clone();
        h2.hash = h2.calculate_hash();

        // A self-consistent header of an unrelated fork at the same height.
        let mut fork = make_block_header_at(2, TEST_CHAIN_ID);
        fork.previous_hash = "9".repeat(64);
        fork.hash = fork.calculate_hash();
        let fork_cert = make_valid_bls_cert(&snapshot, &sks, &fork, 3);
        let cert = make_valid_bls_cert(&snapshot, &sks, &h2, 3);

        // Nothing is linked yet.
        assert!(matches!(
            client.verify_checkpoint(&h2, &cert, &snapshot),
            Err(LightClientError::HeaderChain(_))
        ));

        client
            .verify_header_chain(&[h1, h2.clone()])
            .expect("segment continues the anchor");
        assert!(client.verify_checkpoint(&h2, &cert, &snapshot).is_ok());
        assert!(matches!(
            client.verify_checkpoint(&fork, &fork_cert, &snapshot),
            Err(LightClientError::HeaderChain(_))
        ));
    }

    /// The next checkpoint height is computed in closed form (audit):
    /// a huge target must not loop height by height.
    #[test]
    fn next_checkpoint_height_is_closed_form() {
        let client = LightClient::new(TrustedCheckpoint {
            height: 4,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();
        assert_eq!(client.next_checkpoint_height(10, u64::MAX), Some(10));
        assert_eq!(client.next_checkpoint_height(5, 100), Some(5));
        assert_eq!(client.next_checkpoint_height(10, 9), None);
        assert_eq!(client.next_checkpoint_height(0, 100), None);
        assert_eq!(client.next_checkpoint_height(1, 100), Some(5));
        assert_eq!(
            client.next_checkpoint_height(u64::MAX, u64::MAX),
            Some(u64::MAX)
        );
        let top = LightClient::new(TrustedCheckpoint {
            height: u64::MAX,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();
        assert_eq!(top.next_checkpoint_height(3, u64::MAX), None);
    }

    #[test]
    fn sync_plan_targets_the_next_checkpoint() {
        let client = LightClient::new(TrustedCheckpoint {
            height: 4,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();

        assert_eq!(client.next_checkpoint_height(10, 50), Some(10));
        assert_eq!(client.next_checkpoint_height(10, 9), None);
        assert_eq!(client.next_checkpoint_height(10, 20), Some(10));

        let plan = client.sync_plan(10, 50);
        assert_eq!(plan.headers_locator, vec!["0".repeat(64)]);
        assert_eq!(plan.next_checkpoint_height, Some(10));

        let at_checkpoint = LightClient::new(TrustedCheckpoint {
            height: 10,
            block_hash: "0".repeat(64),
            set_hash: "0".repeat(64),
        })
        .unwrap();
        assert_eq!(at_checkpoint.next_checkpoint_height(10, 50), Some(20));
    }

    // ---- PQ helpers ----

    fn make_pq_snapshot(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<PqKeyPair>) {
        let mut keys = Vec::new();
        let validators: Vec<ValidatorEntry> = (0..n)
            .map(|i| {
                let key = PqKeyPair::generate();
                keys.push(key);
                let mut addr_bytes = [0u8; 32];
                addr_bytes[0] = u8::try_from(i + 1).expect("test index fits u8");
                ValidatorEntry {
                    address: Address::from(addr_bytes),
                    stake: stake_each,
                    bls_public_key: Vec::new(),
                    pop_signature: Vec::new(),
                    pq_public_key: keys.last().unwrap().public_key_bytes().to_vec(),
                }
            })
            .collect();
        (ValidatorSetSnapshot::new(1, validators), keys)
    }

    fn make_pq_blob(
        snapshot: &ValidatorSetSnapshot,
        keys: &[PqKeyPair],
        header: &BlockHeader,
    ) -> QcBlob {
        let entries: Vec<PqSignatureEntry> = snapshot
            .validators
            .iter()
            .enumerate()
            .map(|(idx, validator)| {
                let message = pq_signing_message(
                    snapshot.epoch,
                    header.index,
                    &header.hash,
                    u32::try_from(idx).expect("test validator count is small"),
                );
                let sig = keys[idx]
                    .sign(crate::crypto::ctx::QC_V2, &message)
                    .expect("sign");
                PqSignatureEntry {
                    validator_index: u32::try_from(idx).expect("test validator count is small"),
                    validator_address: validator.address.to_string(),
                    pq_signature: sig,
                }
            })
            .collect();
        QcBlob::new(snapshot.epoch, header.index, header.hash.clone(), entries)
    }

    /// a global header binds to a verified checkpoint through the state
    /// root opening; a header from another checkpoint, a tampered header or
    /// a wrong opening is refused.
    #[test]
    fn a_global_header_binds_to_its_checkpoint_through_the_state_root() {
        use crate::core::account::AccountState;
        use crate::settlement::GlobalBlockHeader;

        let mut state = AccountState::new();
        let header = GlobalBlockHeader {
            version: 2,
            global_height: 0,
            previous_global_hash: [0u8; 32],
            chain_id: TEST_CHAIN_ID,
            timestamp_ms: 1,
            domain_registry_root: [1u8; 32],
            domain_commitment_root: [2u8; 32],
            message_root: [3u8; 32],
            bridge_state_root: [4u8; 32],
            replay_nonce_root: [5u8; 32],
            proposer: None,
            settlement_finality_root: [6u8; 32],
            storage_root: None,
            ai_root: None,
            identity_root: None,
            checkpoint_height: 10,
            external_intake_root: None,
            app_binding_root: None,
            delegation_root: None,
            object_layer_root: None,
            proof_root: Some([7u8; 32]),
            proven_height: 10,
            ulp_domains_root: None,
            finality_certificate_root: None,
        };
        state.global_header_summary = header.calculate_hash_bytes();
        let body = state.state_root_body();
        let checkpoint = VerifiedCheckpoint {
            height: 10,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
            epoch: 1,
            state_root: state.calculate_state_root(),
        };
        assert!(LightClient::verify_global_header(&checkpoint, &body, &header).is_ok());

        let mut tampered = header.clone();
        tampered.domain_commitment_root = [9u8; 32];
        assert!(matches!(
            LightClient::verify_global_header(&checkpoint, &body, &tampered),
            Err(LightClientError::GlobalHeaderBinding(_))
        ));

        let mut elsewhere = header.clone();
        elsewhere.checkpoint_height = 20;
        assert!(matches!(
            LightClient::verify_global_header(&checkpoint, &body, &elsewhere),
            Err(LightClientError::GlobalHeaderBinding(_))
        ));

        assert!(matches!(
            LightClient::verify_global_header(&checkpoint, &[7u8; 32], &header),
            Err(LightClientError::GlobalHeaderBinding(_))
        ));
    }

    #[test]
    fn remote_state_view_verifies_inclusion_and_refuses_unbound_predicates() {
        use crate::core::account::AccountState;
        use crate::settlement::GlobalBlockHeader;
        use bud_proof::predicates::{
            prove_predicate, verify_predicate, PredicateKind, PredicateStatement,
        };

        let key = b"domain:eth:vault:alice".to_vec();
        let value = b"balance:1000000".to_vec();
        let sibling_a = [0x11u8; 32];
        let sibling_b = [0x22u8; 32];
        let path = vec![
            RemoteMerkleStep {
                sibling: sibling_a,
                sibling_is_right: true,
            },
            RemoteMerkleStep {
                sibling: sibling_b,
                sibling_is_right: false,
            },
        ];
        let remote_root = RemoteStateView::compute_merkle_root(&key, &value, &path);
        let remote_domain_id = 42u64;
        let domain_commitment_root =
            RemoteStateView::expected_domain_commitment(remote_domain_id, &remote_root);

        // A valid, independent quorum proof must not confer ownership over
        // this unrelated state leaf merely because its STARK verifies.
        let pred_proof = prove_predicate(&PredicateStatement {
            kind: PredicateKind::Yk6ThresholdQuorum,
            lhs: 4,
            rhs: 4,
            aux: 1,
            chain_id: TEST_CHAIN_ID,
        })
        .expect("independent quorum predicate proves");
        verify_predicate(&pred_proof).expect("unrelated predicate really does verify");

        let mut state = AccountState::new();
        let header = GlobalBlockHeader {
            version: 2,
            global_height: 0,
            previous_global_hash: [0u8; 32],
            chain_id: TEST_CHAIN_ID,
            timestamp_ms: 1,
            domain_registry_root: [1u8; 32],
            domain_commitment_root,
            message_root: [3u8; 32],
            bridge_state_root: [4u8; 32],
            replay_nonce_root: [5u8; 32],
            proposer: None,
            settlement_finality_root: [6u8; 32],
            storage_root: None,
            ai_root: None,
            identity_root: None,
            checkpoint_height: 10,
            external_intake_root: None,
            app_binding_root: None,
            delegation_root: None,
            object_layer_root: None,
            proof_root: Some([7u8; 32]),
            proven_height: 10,
            ulp_domains_root: None,
            finality_certificate_root: None,
        };
        state.global_header_summary = header.calculate_hash_bytes();
        let body = state.state_root_body();
        let checkpoint = VerifiedCheckpoint {
            height: 10,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
            epoch: 1,
            state_root: state.calculate_state_root(),
        };

        let view = RemoteStateView {
            remote_domain_id,
            remote_state_root: remote_root,
            header,
            state_key: key,
            state_value: value,
            inclusion_path: path,
            predicate_proof: None,
        };
        // The door is open on devnet and remains closed on testnet and mainnet.
        let closed_chain = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        assert!(matches!(
            view.verify_for_chain(&checkpoint, &body, closed_chain),
            Err(LightClientError::VerificationFailed(reason))
                if reason.contains("app binding disabled")
        ));
        let testnet_chain = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        assert!(matches!(
            view.verify_for_chain(&checkpoint, &body, testnet_chain),
            Err(LightClientError::VerificationFailed(reason))
                if reason.contains("app binding disabled")
        ));
        let open_chain = crate::core::chain_config::Network::Devnet
            .chain_id()
            .value();
        assert!(view
            .verify_for_chain(&checkpoint, &body, open_chain)
            .is_ok());

        let mut tampered_val = view.clone();
        tampered_val.state_value = b"balance:9999999".to_vec();
        assert!(matches!(
            tampered_val.verify_for_chain(&checkpoint, &body, open_chain),
            Err(LightClientError::VerificationFailed(_))
        ));

        let mut unbound_pred = view;
        unbound_pred.predicate_proof = Some(pred_proof);
        assert!(matches!(
            unbound_pred.verify_for_chain(&checkpoint, &body, open_chain),
            Err(LightClientError::VerificationFailed(reason))
                if reason.contains("not bound to the committed state leaf")
        ));
    }

    #[test]
    fn verify_header_chain_refuses_conflicting_fork_and_committee_batch_binds_trust() {
        use bud_proof::sigagg::{
            aggregate_signatures, compute_committee_root, CommitteeMember, SignatureScheme,
            SignerSignature,
        };

        let h0 = make_block_header_at(0, TEST_CHAIN_ID);
        let trusted_set = "ab".repeat(32);
        let mut client = LightClient::new(TrustedCheckpoint {
            height: 0,
            block_hash: h0.hash.clone(),
            set_hash: trusted_set.clone(),
        })
        .unwrap();

        let b1_a = Block::new_with_chain_id(1, h0.hash.clone(), Vec::new(), TEST_CHAIN_ID);
        let h1_a = BlockHeader::from_block(&b1_a);
        client
            .verify_header_chain(std::slice::from_ref(&h1_a))
            .expect("initial honest segment links");
        // Idempotent replay of the exact same header stays accepted.
        client
            .verify_header_chain(std::slice::from_ref(&h1_a))
            .expect("identical header replay stays accepted");

        // Conflicting fork header at already-linked height 1 MUST be refused.
        let mut h1_fork = h1_a.clone();
        h1_fork.state_root = "44".repeat(32);
        h1_fork.hash = h1_fork.calculate_hash();
        let err = client
            .verify_header_chain(&[h1_fork])
            .expect_err("conflicting fork header must not overwrite linked entry");
        assert!(matches!(err, LightClientError::HeaderChain(_)));

        // Over-cap segment (> MAX_LINKED_HEADERS) is refused immediately.
        let oversized = vec![h1_a.clone(); MAX_LINKED_HEADERS + 1];
        assert!(matches!(
            client.verify_header_chain(&oversized),
            Err(LightClientError::HeaderChain(_))
        ));

        // `apply_committee_batch_checkpoint` enforces trusted set_hash and linked header binding.
        let committee: Vec<CommitteeMember> = vec![(0, 100, SignatureScheme::MlDsa87, [0x55; 32])];
        let linked_hash_bytes: [u8; 32] = hex::decode(&h1_a.hash).unwrap().try_into().unwrap();
        let batch = aggregate_signatures(
            linked_hash_bytes,
            compute_committee_root(&committee),
            vec![SignerSignature {
                signer_index: 0,
                weight: 100,
                scheme: SignatureScheme::MlDsa87,
                public_key_digest: [0x55; 32],
                signature: vec![0x01; SignatureScheme::MlDsa87.min_signature_len()],
                threshold_witness: None,
            }],
        )
        .unwrap();
        let good_cp = VerifiedCheckpoint {
            height: 1,
            block_hash: h1_a.hash.clone(),
            set_hash: trusted_set.clone(),
            epoch: 0,
            state_root: h1_a.state_root.clone(),
        };
        client
            .apply_committee_batch_checkpoint(&good_cp, &batch, &committee, 100, |_, _| true)
            .expect("linked checkpoint with trusted set_hash passes");

        // Foreign validator set_hash rejected.
        let wrong_set = VerifiedCheckpoint {
            set_hash: "cd".repeat(32),
            ..good_cp.clone()
        };
        assert!(matches!(
            client.apply_committee_batch_checkpoint(
                &wrong_set,
                &batch,
                &committee,
                100,
                |_, _| true,
            ),
            Err(LightClientError::TrustBinding(_))
        ));

        // Unlinked height 99 rejected even with matching message_digest.
        let unlinked = VerifiedCheckpoint {
            height: 99,
            ..good_cp
        };
        assert!(matches!(
            client
                .apply_committee_batch_checkpoint(&unlinked, &batch, &committee, 100, |_, _| true,),
            Err(LightClientError::HeaderChain(_))
        ));
    }

    #[test]
    fn ulp_v1_multi_domain_scaling_and_multi_hop_frost_alarm_and_outflow_enforcement() {
        use std::time::Instant;

        use crate::aggregation::universal_light_proof::{
            compile_ulp_program, prove_ulp_domain_inclusion, prove_universal_light_proof,
            UlpDomainKind, UlpDomainSnapshot,
        };
        use crate::core::account::AccountState;
        use crate::crypto::scheme::SchemeStatusRegistry;
        use crate::settlement::GlobalBlockHeader;

        let registry = SchemeStatusRegistry::genesis();
        let hub_chain_id: u32 = 45_262;
        let agg_seed = [0x42u8; 32];

        // Anchor checkpoint + finalized GlobalBlockHeader on a real LightClient.
        let mut state = AccountState::new();
        let global_header = GlobalBlockHeader {
            version: 2,
            global_height: 25,
            previous_global_hash: [0x10; 32],
            chain_id: u64::from(hub_chain_id),
            timestamp_ms: 1_795_000_000_000,
            domain_registry_root: [0x19; 32],
            domain_commitment_root: [0x20; 32],
            message_root: [0x30; 32],
            bridge_state_root: [0x40; 32],
            replay_nonce_root: [0x50; 32],
            proposer: None,
            settlement_finality_root: [0x60; 32],
            storage_root: None,
            ai_root: None,
            identity_root: None,
            checkpoint_height: 25,
            external_intake_root: Some([0x70; 32]),
            app_binding_root: None,
            delegation_root: None,
            object_layer_root: None,
            proof_root: Some([0x80; 32]),
            proven_height: 25,
            ulp_domains_root: None,
            finality_certificate_root: None,
        };
        let hub_root = global_header.calculate_hash_bytes();
        state.global_header_summary = hub_root;
        let state_body = state.state_root_body();
        let anchor_block_hash = "aa".repeat(32);
        let anchor_set_hash = "bb".repeat(32);
        let checkpoint = VerifiedCheckpoint {
            height: 25,
            block_hash: anchor_block_hash.clone(),
            set_hash: anchor_set_hash.clone(),
            epoch: 5,
            state_root: state.calculate_state_root(),
        };
        let client = LightClient::new(TrustedCheckpoint {
            height: 25,
            block_hash: anchor_block_hash,
            set_hash: anchor_set_hash,
        })
        .unwrap();

        let all_six = [
            UlpDomainSnapshot {
                domain_id: 1,
                external_chain_id: 1_001,
                kind: UlpDomainKind::BitcoinSpv,
                prev_height: 870_000,
                finalized_height: 870_006,
                state_root: [0x11; 32],
                event_root: [0x21; 32],
                anchor_hash: [0x31; 32],
                security_weight: 500_000,
                pq_attested: true,
                outflow_bps: 800,
            },
            UlpDomainSnapshot {
                domain_id: 2,
                external_chain_id: 2_002,
                kind: UlpDomainKind::SuccinctRecursive,
                prev_height: 410_000,
                finalized_height: 410_012,
                state_root: [0x12; 32],
                event_root: [0x22; 32],
                anchor_hash: [0x32; 32],
                security_weight: 300_000,
                pq_attested: true,
                outflow_bps: 700,
            },
            UlpDomainSnapshot {
                domain_id: 3,
                external_chain_id: 3_003,
                kind: UlpDomainKind::PoSpaceVdf,
                prev_height: 5_200_000,
                finalized_height: 5_200_008,
                state_root: [0x13; 32],
                event_root: [0x23; 32],
                anchor_hash: [0x33; 32],
                security_weight: 450_000,
                pq_attested: true,
                outflow_bps: 600,
            },
            UlpDomainSnapshot {
                domain_id: 4,
                external_chain_id: 1,
                kind: UlpDomainKind::EthereumSync,
                prev_height: 11_000_000,
                finalized_height: 11_000_032,
                state_root: [0x14; 32],
                event_root: [0x24; 32],
                anchor_hash: [0x34; 32],
                security_weight: 900_000,
                pq_attested: false, // classical BLS12-381 sync committee
                outflow_bps: 900,
            },
            UlpDomainSnapshot {
                domain_id: 5,
                external_chain_id: 5_005,
                kind: UlpDomainKind::TendermintBft,
                prev_height: 22_000_000,
                finalized_height: 22_000_001,
                state_root: [0x15; 32],
                event_root: [0x25; 32],
                anchor_hash: [0x35; 32],
                security_weight: 250_000,
                pq_attested: false, // classical Ed25519 committee
                outflow_bps: 500,
            },
            UlpDomainSnapshot {
                domain_id: 6,
                external_chain_id: 6_006,
                kind: UlpDomainKind::DagBft,
                prev_height: 9_100_000,
                finalized_height: 9_100_005,
                state_root: [0x16; 32],
                event_root: [0x26; 32],
                anchor_hash: [0x36; 32],
                security_weight: 380_000,
                pq_attested: true,
                outflow_bps: 400,
            },
        ];

        // Benchmark real ULP-1 proving & verification across D = 1, 3, 6 domains.
        // The settlement epoch must be the canonical one derived from the hub
        // anchor (checkpoint_height / epoch_len_for_chain_id(chain_id)); devnet
        // 45262 has epoch length 10 and checkpoint height 25 -> epoch 2.
        let expected_settlement_epoch =
            crate::aggregation::universal_light_proof::ulp_expected_settlement_epoch(
                u64::from(hub_chain_id),
                global_header.checkpoint_height,
            );
        assert_eq!(expected_settlement_epoch, 2);
        let mut six_bundle_opt = None;
        for d in [1usize, 3, 6] {
            let subset = all_six.get(..d).unwrap();
            let compiled = compile_ulp_program(hub_chain_id, d).unwrap();
            let (bundle, sorted, metrics) = prove_universal_light_proof(
                &compiled,
                expected_settlement_epoch,
                hub_root,
                subset,
                &agg_seed,
                d as u64,
                &registry,
            )
            .expect("ULP-1 prove succeeds");
            let inc = prove_ulp_domain_inclusion(&sorted, 1).unwrap();
            let t_ver = Instant::now();
            let hdr = crate::aggregation::universal_light_proof::open_universal_light_proof(
                &bundle,
                &compiled.program_hash,
                hub_chain_id,
                &hub_root,
                expected_settlement_epoch,
                &registry,
            )
            .expect("ULP-1 verify succeeds");
            inc.verify(sorted.first().unwrap(), &hdr.domains_merkle_root)
                .expect("O(log D) leaf verify succeeds");
            let verify_us = t_ver.elapsed().as_micros();
            println!(
                "ULP_METRIC domains={d} vm_steps={} prove_ms={} verify_us={verify_us} stark_obj_bytes={} pcs_obj_bytes={} verify_stark_tx_bytes={} master_frame_bytes={} domain_merkle_bytes={}",
                metrics.vm_trace_steps,
                metrics.prove_ms,
                metrics.stark_object_bytes,
                metrics.pcs_object_bytes,
                metrics.verify_stark_tx_bytes,
                metrics.master_frame_bytes,
                inc.encoded_len(),
            );
            assert!(
                metrics.verify_stark_tx_bytes < metrics.pcs_object_bytes,
                "Phase 5 split-STARK statement must be strictly smaller than full FRI PCS object"
            );
            if d == 6 {
                six_bundle_opt = Some((compiled.program_hash, bundle, sorted));
            }
        }

        let (prog_hash, bundle6, sorted6) = six_bundle_opt.unwrap();
        let pinned_root = bundle6.domains_merkle_root;

        // Statement binding: with the full snapshot set every declared
        // header field must be the one the proof witnessed.
        {
            use crate::aggregation::universal_light_proof::open_universal_light_proof_with_snapshots;
            open_universal_light_proof_with_snapshots(
                &bundle6,
                &prog_hash,
                hub_chain_id,
                &hub_root,
                expected_settlement_epoch,
                &sorted6,
                &registry,
            )
            .expect("the honest bundle's declarations are its statement");
            let mut lied_epoch = bundle6.clone();
            lied_epoch.settlement_epoch += 1;
            assert!(
                open_universal_light_proof_with_snapshots(
                    &lied_epoch,
                    &prog_hash,
                    hub_chain_id,
                    &hub_root,
                    expected_settlement_epoch,
                    &sorted6,
                    &registry,
                )
                .is_err(),
                "a declared epoch the proof never witnessed must be refused"
            );
            let mut lied_root = bundle6.clone();
            lied_root.domains_merkle_root[0] ^= 0xFF;
            assert!(
                open_universal_light_proof_with_snapshots(
                    &lied_root,
                    &prog_hash,
                    hub_chain_id,
                    &hub_root,
                    expected_settlement_epoch,
                    &sorted6,
                    &registry,
                )
                .is_err(),
                "a declared domain root that is not the leaves' fold must be refused"
            );
            let mut lied_outflow = bundle6.clone();
            lied_outflow.max_outflow_bps = lied_outflow.max_outflow_bps.saturating_sub(1);
            assert!(
                open_universal_light_proof_with_snapshots(
                    &lied_outflow,
                    &prog_hash,
                    hub_chain_id,
                    &hub_root,
                    expected_settlement_epoch,
                    &sorted6,
                    &registry,
                )
                .is_err(),
                "a declared outflow ceiling off the witnessed one must be refused"
            );
        }
        let snap = |id: u32| sorted6.iter().find(|s| s.domain_id == id).unwrap().clone();
        let proof = |id: u32| prove_ulp_domain_inclusion(&sorted6, id).unwrap();

        // 1. 2-hop post-quantum-clean route (BitcoinSpv -> SuccinctRecursive -> PoSpaceVdf)
        //    succeeds even under active CRQC Frost Alarm (`strict_value(true)`).
        let pq_route = UniversalLightPacket {
            ulp_bundle: bundle6.clone(),
            expected_program_hash: prog_hash,
            hops: vec![
                UniversalRouteHop {
                    source: snap(1),
                    source_proof: proof(1),
                    destination: snap(2),
                    destination_proof: proof(2),
                    packet_commitment: [0xA1; 32],
                    sequence: 10,
                    amount_bps: 1_200,
                },
                UniversalRouteHop {
                    source: snap(2),
                    source_proof: proof(2),
                    destination: snap(3),
                    destination_proof: proof(3),
                    packet_commitment: [0xA2; 32],
                    sequence: 11,
                    amount_bps: 1_300, // cumulative 2_500 bps == exact 25% cap
                },
            ],
        };
        let t_hop = Instant::now();
        let verified = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &pq_route,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, true),
                &registry,
            )
            .expect("PQ-clean multi-hop route passes under Frost Alarm");
        println!(
            "ULP_METRIC multi_hop=3_domains_2_hops verify_us={} cumulative_bps={} pq_clean={}",
            t_hop.elapsed().as_micros(),
            verified.cumulative_outflow_bps,
            verified.post_quantum_clean
        );
        assert_eq!(verified.origin_domain, 1);
        assert_eq!(verified.terminal_domain, 3);
        assert_eq!(verified.hop_count, 2);
        assert_eq!(verified.cumulative_outflow_bps, 2_500);
        assert!(verified.post_quantum_clean);

        // 2. Classical hop (EthereumSync domain 4, pq_attested = false) succeeds in
        //    peacetime (`strict_value(false)`) with `post_quantum_clean == false`,
        //    and FAILS CLOSED under Frost Alarm (`strict_value(true)`).
        let mixed_route = UniversalLightPacket {
            ulp_bundle: bundle6.clone(),
            expected_program_hash: prog_hash,
            hops: vec![
                UniversalRouteHop {
                    source: snap(1),
                    source_proof: proof(1),
                    destination: snap(4),
                    destination_proof: proof(4),
                    packet_commitment: [0xB1; 32],
                    sequence: 20,
                    amount_bps: 500,
                },
                UniversalRouteHop {
                    source: snap(4),
                    source_proof: proof(4),
                    destination: snap(3),
                    destination_proof: proof(3),
                    packet_commitment: [0xB2; 32],
                    sequence: 21,
                    amount_bps: 500,
                },
            ],
        };
        let peacetime = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &mixed_route,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .expect("mixed route passes when Frost Alarm is inactive");
        assert!(!peacetime.post_quantum_clean);
        let alarm_err = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &mixed_route,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, true),
                &registry,
            )
            .expect_err("Frost Alarm must reject non-PQ hop fail-closed");
        assert!(alarm_err.to_string().contains("Frost Alarm"));

        // 3. Exceeding 25% outflow ceiling (2_501 bps) is rejected fail-closed.
        let mut over_cap = pq_route.clone();
        if let Some(last) = over_cap.hops.last_mut() {
            last.amount_bps = 1_301;
        }
        assert!(client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &over_cap,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .is_err());

        // 4. Forged destination state_root breaks O(log D) domain Merkle proof.
        let mut forged_leaf = pq_route.clone();
        if let Some(first) = forged_leaf.hops.first_mut() {
            first.destination.state_root[0] ^= 0xFF;
        }
        assert!(client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &forged_leaf,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .is_err());

        // 5. Cycle A -> B -> A is rejected.
        let cycle_route = UniversalLightPacket {
            ulp_bundle: bundle6,
            expected_program_hash: prog_hash,
            hops: vec![
                UniversalRouteHop {
                    source: snap(1),
                    source_proof: proof(1),
                    destination: snap(2),
                    destination_proof: proof(2),
                    packet_commitment: [0xC1; 32],
                    sequence: 1,
                    amount_bps: 100,
                },
                UniversalRouteHop {
                    source: snap(2),
                    source_proof: proof(2),
                    destination: snap(1),
                    destination_proof: proof(1),
                    packet_commitment: [0xC2; 32],
                    sequence: 2,
                    amount_bps: 100,
                },
            ],
        };
        assert!(client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &cycle_route,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .is_err());

        // 6. A bundle proved for another hub is not accepted as this hub's
        //    finality: the verified header's chain id is the anchor.
        let mut foreign_hub = pq_route.clone();
        foreign_hub.ulp_bundle.hub_chain_id = hub_chain_id + 1;
        let foreign_err = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &foreign_hub,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .expect_err("a foreign hub id must be refused against the verified header");
        assert!(foreign_err.to_string().contains("verified chain id"));

        // 7. A packet-declared program hash that differs from the canonical
        //    circuit is refused before any proof work.
        let mut forged_program = pq_route.clone();
        forged_program.expected_program_hash[0] ^= 0x01;
        let program_err = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &forged_program,
                &UniversalRoutePolicy::strict_value_pinned(pinned_root, false),
                &registry,
            )
            .expect_err("a non-canonical program hash must be refused");
        assert!(program_err.to_string().contains("canonical circuit"));

        // 8. Without a header or policy domain-set root the route fails closed.
        let unpinned_err = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &pq_route,
                &UniversalRoutePolicy::strict_value(false),
                &registry,
            )
            .expect_err("an unanchored header with unpinned policy must fail closed");
        assert!(unpinned_err.to_string().contains("no trusted domains root"));

        // 9. A pinned root that differs from the bundle's domain set refuses
        //    the route even though every proof inside the bundle verifies.
        let mut wrong_root = pinned_root;
        wrong_root[0] ^= 0xFF;
        let wrong_root_err = client
            .verify_multi_hop_light_route(
                &checkpoint,
                &state_body,
                &global_header,
                &pq_route,
                &UniversalRoutePolicy::strict_value_pinned(wrong_root, false),
                &registry,
            )
            .expect_err("a mismatched pinned root must refuse the route");
        assert!(wrong_root_err.to_string().contains("pinned trusted root"));

        // 10. When `global_header.ulp_domains_root` commits the consensus
        //     domain-set root, `UniversalRoutePolicy::strict_value(true)` succeeds
        //     with zero out-of-band pinning, while a conflicting policy pin or a
        //     bundle proven over a different domain set is refused fail-closed.
        let mut anchored_header = global_header;
        anchored_header.ulp_domains_root = Some(pinned_root);
        let anchored_hub_root = anchored_header.calculate_hash_bytes();
        let mut anchored_state = AccountState::new();
        anchored_state.global_header_summary = anchored_hub_root;
        let anchored_body = anchored_state.state_root_body();
        let anchored_cp = VerifiedCheckpoint {
            height: 25,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
            epoch: 5,
            state_root: anchored_state.calculate_state_root(),
        };
        let compiled6 = compile_ulp_program(hub_chain_id, 6).unwrap();
        let (anchored_bundle, _, _) = prove_universal_light_proof(
            &compiled6,
            expected_settlement_epoch,
            anchored_hub_root,
            &all_six,
            &agg_seed,
            99,
            &registry,
        )
        .expect("anchored ULP-1 prove succeeds");
        let mut anchored_pq_route = pq_route;
        anchored_pq_route.ulp_bundle = anchored_bundle;

        let verified_anchored = client
            .verify_multi_hop_light_route(
                &anchored_cp,
                &anchored_body,
                &anchored_header,
                &anchored_pq_route,
                &UniversalRoutePolicy::strict_value(true),
                &registry,
            )
            .expect("header-anchored strict_value route succeeds under Frost Alarm");
        assert_eq!(verified_anchored.origin_domain, 1);
        assert_eq!(verified_anchored.terminal_domain, 3);
        assert_eq!(verified_anchored.cumulative_outflow_bps, 2_500);
        assert!(verified_anchored.post_quantum_clean);

        let conflict_err = client
            .verify_multi_hop_light_route(
                &anchored_cp,
                &anchored_body,
                &anchored_header,
                &anchored_pq_route,
                &UniversalRoutePolicy::strict_value_pinned(wrong_root, false),
                &registry,
            )
            .expect_err("conflicting policy pin must fail closed against header ulp_domains_root");
        assert!(matches!(
            conflict_err,
            LightClientError::GlobalHeaderBinding(_)
        ));
    }

    #[test]
    fn verify_finality_certificate_domain_accepts_certified_row_and_rejects_tampering() {
        use crate::core::account::AccountState;
        use crate::core::address::Address;
        use crate::crypto::facts::{AssumptionClass, CryptoFacts, ObservedScheme};
        use crate::domain::types::{
            ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
        };
        use crate::settlement::{FinalityBucket, GlobalBlockHeader};

        let mut state = AccountState::new();
        let dom = ConsensusDomain {
            id: 42,
            kind: ConsensusKind::Bft,
            status: DomainStatus::Active,
            domain_chain_id: 42_000,
            operator: Some(Address::from([2u8; 32])),
            operator_bond: crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
            config_hash: [0xA1; 32],
            validator_set_hash: [0xB2; 32],
            finality_adapter: "tendermint-v1".into(),
            min_confirmations: 1,
            bridge_enabled: true,
            block_hash_scheme: RootScheme::Sha256,
            state_root_scheme: RootScheme::Sha256,
            tx_root_scheme: RootScheme::Sha256,
            last_committed_height: 99,
            last_committed_hash: [0x99; 32],
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
            genesis_state_root: [0u8; 32],
        };
        state
            .settlement
            .domains
            .restore_persisted(dom)
            .expect("register domain");
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
        state.settlement.domains.record_observed(42, &facts);
        state
            .settlement
            .commitments
            .insert(DomainCommitment {
                domain_id: 42,
                domain_height: 99,
                domain_block_hash: [0x99; 32],
                parent_domain_block_hash: [0x98; 32],
                state_root: [0x55; 32],
                tx_root: [0x56; 32],
                event_root: [0x57; 32],
                finality_proof_hash: [0x58; 32],
                consensus_kind: ConsensusKind::Bft,
                validator_set_hash: [0xB2; 32],
                timestamp_ms: 1_000,
                sequence: 1,
                producer: None,
                state_updates: std::collections::BTreeMap::new(),
            })
            .expect("insert commitment");

        let cert = state
            .settlement
            .universal_finality_certificate(10)
            .expect("certificate derived from consensus state");
        let proof = cert.prove_domain(42).expect("proof for domain 42");

        let header = GlobalBlockHeader {
            version: 2,
            global_height: 0,
            previous_global_hash: [0u8; 32],
            chain_id: TEST_CHAIN_ID,
            timestamp_ms: 1,
            domain_registry_root: [1u8; 32],
            domain_commitment_root: [2u8; 32],
            message_root: [3u8; 32],
            bridge_state_root: [4u8; 32],
            replay_nonce_root: [5u8; 32],
            proposer: None,
            settlement_finality_root: [6u8; 32],
            storage_root: None,
            ai_root: None,
            identity_root: None,
            checkpoint_height: 10,
            external_intake_root: None,
            app_binding_root: None,
            delegation_root: None,
            object_layer_root: None,
            proof_root: None,
            proven_height: 0,
            ulp_domains_root: state.settlement.ulp_domains_root(),
            finality_certificate_root: Some(cert.certificate_digest),
        };
        state.global_header_summary = header.calculate_hash_bytes();
        let body = state.state_root_body();
        let checkpoint = VerifiedCheckpoint {
            height: 10,
            block_hash: "aa".repeat(32),
            set_hash: "bb".repeat(32),
            epoch: 1,
            state_root: state.calculate_state_root(),
        };
        let mut lc = LightClient::new(TEST_CHAIN_ID);
        lc.anchor_trusted_checkpoint(checkpoint.clone())
            .expect("anchor checkpoint");

        let verified = lc
            .verify_finality_certificate_domain(&checkpoint, &body, &header, &cert, &proof)
            .expect("certified domain inclusion must verify");
        assert_eq!(verified.domain_id, 42);
        assert_eq!(verified.bucket, FinalityBucket::Established);
        assert_eq!(verified.height, 99);
        assert_eq!(verified.state_root, [0x55; 32]);
        assert_eq!(
            verified.guarantee_label,
            "deterministic-quorum|lattice|slashable|ft=3333bps"
        );

        let mut bad_cert = cert.clone();
        bad_cert.certificate_digest[0] ^= 0xFF;
        assert!(lc
            .verify_finality_certificate_domain(&checkpoint, &body, &header, &bad_cert, &proof)
            .is_err());

        let mut bad_proof = proof;
        bad_proof.entry.state_root[0] ^= 0xFF;
        assert!(lc
            .verify_finality_certificate_domain(&checkpoint, &body, &header, &cert, &bad_proof)
            .is_err());
    }
}
