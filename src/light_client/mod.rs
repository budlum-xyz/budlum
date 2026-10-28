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
//!   checkpoint`), the same attestation layer full nodes import.
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

/// A 64-character lowercase hex digest.
/// A 64-character lowercase hex digest. `const fn` so the trust-anchor check
/// can run in constant contexts; `u8::is_ascii_hexdigit` is const since Rust
/// 1.87, which this crate's MSRV (1.97) satisfies.
fn is_canonical_hash(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_hexdigit() {
            return false;
        }
        i += 1;
    }
    true
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
    /// against it (AR-GE-6 / F-12). Carried here so the verified finality fact
    /// survives past the verification call.
    pub state_root: String,
}

impl VerifiedCheckpoint {
    /// The external chain's state root at [`Self::height`], as a 32-byte digest
    /// ready to anchor via `AccountState::anchor_external_root` (AR-GE-6 / F-12).
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
}

/// What a light client's verified checkpoints rest on (Section 6.2 of the PQ
///). Shown to the user beside every answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: light-client surface - the sync doors that read it land with their wiring wave.
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

    /// The trust this client's checkpoints rest on: the validator committee.
    #[must_use]
    pub const fn trust_mode(&self) -> TrustMode {
        TrustMode::Committee
    }

    /// Whether this client refuses BLS-only checkpoints.
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
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
        crate::domain::finality_adapter::verify_pq_quorum(
            &crate::crypto::scheme::SchemeStatusRegistry::genesis(),
            cert,
            snapshot,
            blob,
        )
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
    /// unique signers must carry the same stake and count quorum the BLS path
    /// enforces.
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
            .verify_against_snapshot(snapshot, None, None)
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
        if headers.is_empty() {
            return Err(LightClientError::HeaderChain(
                "no headers supplied".to_string(),
            ));
        }
        let first = &headers[0];
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
            if pair[1].index != pair[0].index.saturating_add(1)
                || pair[1].previous_hash != pair[0].hash
            {
                return Err(LightClientError::HeaderChain(format!(
                    "headers {} and {} are not contiguous and parent-linked",
                    pair[0].index, pair[1].index
                )));
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
    /// WIRING: light-client surface - the sync doors that read it land with their wiring wave.
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
        for (cert, snapshot) in steps {
            snapshot
                .validate_metadata()
                .map_err(LightClientError::TrustBinding)?;
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
        self.trusted.set_hash = last.set_hash.clone();
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

    fn make_bls_key(seed: u8) -> BlsKeypair {
        let mut sk_bytes = [0u8; 64];
        sk_bytes[0] = seed + 1;
        BlsKeypair::from_seed(&sk_bytes)
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

    /// AR-GE-6 / F-12: a verified checkpoint exposes the external state root
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
    /// anchor is refused, even with a valid certificate (audit P18-F07).
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

    /// The next checkpoint height is computed in closed form (audit P18-F08):
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

    ///: a global header binds to a verified checkpoint through the state
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
            graft_root: None,
            delegation_root: None,
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
}
