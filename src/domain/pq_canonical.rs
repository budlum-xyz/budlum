//! The post-quantum canonical source of regeneration.
//!
//! WIRING: wired - `Blockchain` keeps one [`PqCanonicalSource`] and feeds it
//! with the anchors and Root Seals its emission pipeline built and verified
//! (`Blockchain::emit_anchor_for`) and with the finality checkpoints that
//! carry a verified ML-DSA QC blob; the node runtime's health tick
//! (`src/network/regen_health_tick.rs`) reads canonical commitments and seal
//! ids only from it. Rules are pinned by this file's tests.
//!
//! # What counts as canonical
//!
//! A regeneration stage is trusted through a seal, and a seal is trusted only
//! when a post-quantum signature family stands behind it:
//!
//! - **Polyp**: the latest Root Seal (SLH-DSA-SHAKE-256s, hash based). The
//!   commitment is the seal digest, which chains to every earlier seal. The
//!   Handoff chain joins this stage with; until then Root Seals are the
//!   only Polyp source.
//! - **Ephyra**: a verified Anchor V2 (two of three ML-DSA-87 keys of the
//!   ledger). The commitment is the aggregate root the anchor signs.
//! - **Medusa**: the finality checkpoint with its ML-DSA-65 QC. The BLS
//!   certificate may be part of the seal, but a seal whose scheme set holds no
//!   post-quantum family is refused ([`SourceError::NotPostQuantum`]).
//!
//! A source that is signed only classically, or not signed, is never counted:
//! there is no entry, so `canonical` answers `None` and the health layer
//! alarms instead of reverting to it. Every `accept_*` call verifies its input
//! again; the source trusts no caller's word for a seal.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::regeneration_stage::Stage;
use crate::crypto::scheme::{SchemeFamily, SchemeId};
use crate::settlement::anchor_ledger::AnchorKeyLedger;
use crate::settlement::pq_anchor::{verify_anchor_full, PqAnchor};
use crate::settlement::root_seal::{verify_root_seal, RootSeal};

/// Anchors the source keeps: a few days of six minute anchors is more than a
/// regeneration ever looks back, and the bound keeps memory fixed.
pub const MAX_ANCHOR_ENTRIES: usize = 512;

/// Finality checkpoints the source keeps.
pub const MAX_FINALITY_ENTRIES: usize = 1_024;

/// Which kind of seal stands behind a stage commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SealKind {
    /// The hourly Root Seal (Polyp).
    RootSeal,
    /// A verified Anchor V2 (Ephyra).
    Anchor,
    /// The finality checkpoint with its post-quantum QC (Medusa).
    FinalityQc,
}

impl SealKind {
    /// The stage a seal of this kind can anchor.
    #[must_use]
    pub const fn stage(self) -> Stage {
        match self {
            Self::RootSeal => Stage::Polyp,
            Self::Anchor => Stage::Ephyra,
            Self::FinalityQc => Stage::Medusa,
        }
    }
}

/// The identity of the seal behind a stage commitment: its kind, the height it
/// seals and the signature schemes that signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealId {
    /// The kind of seal.
    pub kind: SealKind,
    /// The height the seal commits.
    pub height: u64,
    /// The wire identifiers of the schemes behind it, sorted and distinct
    /// (`SchemeId` carries no serde impl; the code is its wire form).
    pub schemes: Vec<u16>,
}

impl SealId {
    /// A seal id with the scheme set sorted and deduplicated.
    #[must_use]
    pub fn new(kind: SealKind, height: u64, schemes: &[SchemeId]) -> Self {
        let mut schemes: Vec<u16> = schemes.iter().map(|scheme| scheme.0).collect();
        schemes.sort_unstable();
        schemes.dedup();
        Self {
            kind,
            height,
            schemes,
        }
    }

    /// Whether a post-quantum signature family (lattice or hash based) is part
    /// of the seal. A classical component may sit next to it (the BLS half of
    /// finality), never alone.
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        self.schemes.iter().any(|code| {
            matches!(
                SchemeId(*code).info().map(|info| info.family),
                Some(SchemeFamily::Lattice | SchemeFamily::Hash)
            )
        })
    }

    /// Whether a post-quantum family of the seal still verifies under the
    /// scheme statuses of the chain. A quantum alarm that takes a
    /// family to `Disabled` kills every seal that only that family stood
    /// behind, and regeneration then descends to the next safe seal.
    #[must_use]
    pub fn is_live(&self, registry: &crate::crypto::scheme::SchemeStatusRegistry) -> bool {
        self.schemes.iter().any(|code| {
            let scheme = SchemeId(*code);
            matches!(
                scheme.info().map(|info| info.family),
                Some(SchemeFamily::Lattice | SchemeFamily::Hash)
            ) && registry.scheme_verifies(scheme)
        })
    }

    /// Whether the seal is one a reversion or growth into `stage` at `height`
    /// may rest on: the kind belongs to the stage, the height is the stage
    /// height and a post-quantum family stands behind it.
    #[must_use]
    pub fn anchors(&self, stage: Stage, height: u64) -> bool {
        self.kind.stage() == stage && self.height == height && self.is_post_quantum()
    }
}

/// Why the source refused a seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// No post-quantum family stands behind the seal.
    NotPostQuantum,
    /// The Root Seal failed verification against the ledger.
    RootSeal(&'static str),
    /// The anchor failed verification against the ledger.
    Anchor(&'static str),
    /// The seal is not newer than the one held.
    NotNewer { height: u64, held: u64 },
    /// The seal belongs to another chain.
    WrongChain { expected: u64, got: u64 },
    /// The reseal certificate was refused.
    Reseal(crate::settlement::reseal::ResealError),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPostQuantum => {
                write!(f, "no post-quantum signature family stands behind the seal")
            }
            Self::RootSeal(kind) => write!(f, "root seal refused: {kind}"),
            Self::Anchor(kind) => write!(f, "anchor refused: {kind}"),
            Self::NotNewer { height, held } => {
                write!(f, "seal at height {height} is not newer than {held}")
            }
            Self::WrongChain { expected, got } => {
                write!(f, "seal is for chain {got}, this is chain {expected}")
            }
            Self::Reseal(error) => write!(f, "reseal refused: {error:?}"),
        }
    }
}

impl std::error::Error for SourceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    commitment: [u8; 32],
    seal: SealId,
}

/// The seals regeneration may trust, keyed by stage and height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqCanonicalSource {
    chain_id: u64,
    root_seal: Option<(u64, Entry)>,
    anchors: BTreeMap<u64, Entry>,
    finality: BTreeMap<u64, Entry>,
}

impl PqCanonicalSource {
    /// An empty source for `chain_id`: nothing is canonical yet.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            root_seal: None,
            anchors: BTreeMap::new(),
            finality: BTreeMap::new(),
        }
    }

    /// Take a Root Seal after verifying it against the ledger's seal keys. The
    /// seal must be newer than the one held; its digest becomes the Polyp
    /// commitment.
    ///
    /// # Errors
    ///
    /// [`SourceError::RootSeal`] with the refusal label, or
    /// [`SourceError::NotNewer`].
    pub fn accept_root_seal(
        &mut self,
        seal: &RootSeal,
        ledger: &AnchorKeyLedger,
    ) -> Result<(), SourceError> {
        verify_root_seal(seal, self.chain_id, ledger, ledger.key_epoch, None)
            .map_err(|e| SourceError::RootSeal(e.kind()))?;
        if let Some((held, _)) = &self.root_seal {
            if seal.seal_height <= *held {
                return Err(SourceError::NotNewer {
                    height: seal.seal_height,
                    held: *held,
                });
            }
        }
        self.root_seal = Some((
            seal.seal_height,
            Entry {
                commitment: seal.digest(),
                seal: SealId::new(
                    SealKind::RootSeal,
                    seal.seal_height,
                    &[SchemeId::SLH_DSA_SHAKE_256S],
                ),
            },
        ));
        Ok(())
    }

    /// Take an Anchor V2 after verifying it (two of three live ledger keys).
    /// The aggregate root it signs becomes the Ephyra commitment of its
    /// height.
    ///
    /// # Errors
    ///
    /// [`SourceError::Anchor`] with the refusal label.
    pub fn accept_anchor(
        &mut self,
        anchor: &PqAnchor,
        ledger: &AnchorKeyLedger,
    ) -> Result<(), SourceError> {
        if anchor.chain_id != self.chain_id {
            return Err(SourceError::WrongChain {
                expected: self.chain_id,
                got: anchor.chain_id,
            });
        }
        verify_anchor_full(anchor, ledger).map_err(|e| SourceError::Anchor(e.kind()))?;
        self.anchors.insert(
            anchor.height,
            Entry {
                commitment: anchor.aggregate_root,
                seal: SealId::new(SealKind::Anchor, anchor.height, &[SchemeId::ML_DSA_87]),
            },
        );
        while self.anchors.len() > MAX_ANCHOR_ENTRIES {
            self.anchors.pop_first();
        }
        Ok(())
    }

    /// Take a finality checkpoint. `schemes` are the signature schemes the
    /// chain verified for it: the ML-DSA-65 QC and, when it was required, the
    /// BLS certificate. A set with no post-quantum family (a BLS-only
    /// certificate) is refused: the checkpoint is then not canonical for
    /// regeneration.
    ///
    /// The caller passes a checkpoint whose QC blob went through
    /// `Blockchain::import_qc_blob`; the source cannot re-verify a blob
    /// without the validator snapshot.
    ///
    /// # Errors
    ///
    /// [`SourceError::NotPostQuantum`].
    pub fn accept_finality(
        &mut self,
        height: u64,
        checkpoint_hash: [u8; 32],
        schemes: &[SchemeId],
    ) -> Result<(), SourceError> {
        let seal = SealId::new(SealKind::FinalityQc, height, schemes);
        if !seal.is_post_quantum() {
            return Err(SourceError::NotPostQuantum);
        }
        self.finality.insert(
            height,
            Entry {
                commitment: checkpoint_hash,
                seal,
            },
        );
        while self.finality.len() > MAX_FINALITY_ENTRIES {
            self.finality.pop_first();
        }
        Ok(())
    }

    /// The anchors that are Unsealed under `registry`: their seal has
    /// no live post-quantum family any more. Height and aggregate root, in
    /// height order.
    #[must_use]
    pub fn unsealed_anchors(
        &self,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
    ) -> Vec<(u64, [u8; 32])> {
        self.anchors
            .iter()
            .filter(|(_, entry)| !entry.seal.is_live(registry))
            .map(|(height, entry)| (*height, entry.commitment))
            .collect()
    }

    /// Take a reseal certificate: it must cover exactly the Unsealed anchors of
    /// its height range and be signed by a family that is still live. The
    /// covered anchors are then sealed by that family. Returns how many.
    ///
    /// # Errors
    ///
    /// [`SourceError::Reseal`] with the refusal.
    pub fn accept_reseal(
        &mut self,
        cert: &crate::settlement::reseal::ResealCertificate,
        ledger: &AnchorKeyLedger,
        registry: &crate::crypto::scheme::SchemeStatusRegistry,
    ) -> Result<usize, SourceError> {
        let covered: Vec<(u64, [u8; 32])> = self
            .unsealed_anchors(registry)
            .into_iter()
            .filter(|(height, _)| *height >= cert.from_height && *height <= cert.to_height)
            .collect();
        crate::settlement::reseal::verify_reseal(cert, self.chain_id, ledger, registry, &covered)
            .map_err(SourceError::Reseal)?;
        let scheme = cert.authority.scheme();
        for (height, _) in &covered {
            if let Some(entry) = self.anchors.get_mut(height) {
                entry.seal = SealId::new(SealKind::Anchor, *height, &[scheme]);
            }
        }
        Ok(covered.len())
    }

    /// Forget the finality checkpoints above `height` (a reorg dropped them).
    pub fn forget_finality_above(&mut self, height: u64) {
        self.finality.split_off(&height.saturating_add(1));
    }

    fn entry(&self, stage: Stage, height: u64) -> Option<&Entry> {
        match stage {
            Stage::Polyp => self
                .root_seal
                .as_ref()
                .filter(|(held, _)| *held == height)
                .map(|(_, entry)| entry),
            Stage::Ephyra => self.anchors.get(&height),
            Stage::Medusa => self.finality.get(&height),
        }
    }

    /// The canonical commitment of `stage` at `height`, `None` when no
    /// post-quantum seal stands behind it.
    #[must_use]
    pub fn canonical(&self, stage: Stage, height: u64) -> Option<[u8; 32]> {
        self.entry(stage, height).map(|entry| entry.commitment)
    }

    /// The seal behind the commitment of `stage` at `height`.
    #[must_use]
    pub fn seal(&self, stage: Stage, height: u64) -> Option<SealId> {
        self.entry(stage, height).map(|entry| entry.seal.clone())
    }

    /// The greatest height `stage` has a seal for.
    #[must_use]
    pub fn latest_height(&self, stage: Stage) -> Option<u64> {
        match stage {
            Stage::Polyp => self.root_seal.as_ref().map(|(height, _)| *height),
            Stage::Ephyra => self.anchors.keys().next_back().copied(),
            Stage::Medusa => self.finality.keys().next_back().copied(),
        }
    }

    /// The greatest height at or below `limit` that `stage` has a seal for.
    #[must_use]
    pub fn latest_at_or_below(&self, stage: Stage, limit: u64) -> Option<u64> {
        match stage {
            Stage::Polyp => self
                .root_seal
                .as_ref()
                .map(|(height, _)| *height)
                .filter(|height| *height <= limit),
            Stage::Ephyra => self.anchors.range(..=limit).next_back().map(|(h, _)| *h),
            Stage::Medusa => self.finality.range(..=limit).next_back().map(|(h, _)| *h),
        }
    }
}

/// A post-quantum seal id for the stage at `height`, for tests that need a
/// snapshot the ledger accepts.
#[cfg(test)]
pub(crate) fn test_seal(stage: Stage, height: u64) -> SealId {
    let (kind, scheme) = match stage {
        Stage::Polyp => (SealKind::RootSeal, SchemeId::SLH_DSA_SHAKE_256S),
        Stage::Ephyra => (SealKind::Anchor, SchemeId::ML_DSA_87),
        Stage::Medusa => (SealKind::FinalityQc, SchemeId::ML_DSA_65),
    };
    SealId::new(kind, height, &[scheme])
}

/// `snapshot` with the post-quantum seal of its stage and height.
#[cfg(test)]
pub(crate) fn sealed(
    mut snapshot: super::regeneration_stage::StageSnapshot,
) -> super::regeneration_stage::StageSnapshot {
    snapshot.seal = Some(test_seal(snapshot.stage, snapshot.height));
    snapshot
}

#[cfg(all(test, feature = "wallet-ml-dsa"))]
mod tests {
    use super::*;
    use crate::settlement::anchor_ledger::test_support::{seal_signer, signer, software_ledger};
    use crate::settlement::pq_anchor::{assemble_anchor, AnchorSigner};
    use crate::settlement::root_seal::build_root_seal;

    const CHAIN: u64 = 45262;

    #[allow(clippy::expect_used)] // a test fixture: a refused assembly is a broken test
    fn anchor(height: u64, ledger: &AnchorKeyLedger, signers: &[u8]) -> PqAnchor {
        let owned: Vec<_> = signers.iter().map(|i| signer(*i)).collect();
        let mut refs: Vec<&dyn AnchorSigner> = Vec::new();
        for s in &owned {
            refs.push(s);
        }
        assemble_anchor(
            CHAIN,
            height,
            &[[height as u8; 32]],
            (None, None),
            ledger.key_epoch,
            &refs,
        )
        .expect("an anchor over one leaf")
    }

    #[allow(clippy::expect_used)] // a test fixture, as above
    fn root_seal(ledger: &AnchorKeyLedger, anchors: &[PqAnchor], height: u64) -> RootSeal {
        build_root_seal(
            CHAIN,
            height,
            anchors,
            None,
            ledger.key_epoch,
            0,
            &seal_signer(),
        )
        .expect("a root seal over its period")
    }

    #[test]
    fn the_seal_id_needs_a_post_quantum_family() {
        let bls = SealId::new(SealKind::FinalityQc, 10, &[SchemeId::BLS12381_MINSIG]);
        assert!(!bls.is_post_quantum());
        assert!(!bls.anchors(Stage::Medusa, 10));
        let ed = SealId::new(SealKind::FinalityQc, 10, &[SchemeId::ED25519]);
        assert!(!ed.is_post_quantum());
        let both = SealId::new(
            SealKind::FinalityQc,
            10,
            &[
                SchemeId::BLS12381_MINSIG,
                SchemeId::ML_DSA_65,
                SchemeId::ML_DSA_65,
            ],
        );
        assert!(both.is_post_quantum());
        assert_eq!(both.schemes.len(), 2, "the set is sorted and distinct");
        assert!(both.anchors(Stage::Medusa, 10));
        // Wrong stage or wrong height never anchors.
        assert!(!both.anchors(Stage::Ephyra, 10));
        assert!(!both.anchors(Stage::Medusa, 11));
        assert!(!SealId::new(SealKind::RootSeal, 3_600, &[]).is_post_quantum());
    }

    /// after a lattice break the anchors are Unsealed; a seal key
    /// reseals them and they count again, now behind the hash-based family.
    #[test]
    fn a_reseal_turns_unsealed_anchors_back_into_a_source() {
        use crate::crypto::scheme::{SchemeStatus, SchemeStatusRegistry, TransitionSource};
        use crate::settlement::reseal::{sign_with_seal_key, unsigned_certificate};
        let ledger = software_ledger(CHAIN, 1);
        let mut source = PqCanonicalSource::new(CHAIN);
        let a = anchor(360, &ledger, &[0, 1]);
        let b = anchor(720, &ledger, &[1, 2]);
        source.accept_anchor(&a, &ledger).expect("anchor");
        source.accept_anchor(&b, &ledger).expect("anchor");
        let mut registry = SchemeStatusRegistry::genesis();
        assert!(source.unsealed_anchors(&registry).is_empty());
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .expect("one rung forward");
        }
        let unsealed = source.unsealed_anchors(&registry);
        assert_eq!(unsealed.len(), 2, "the lattice break unsealed both anchors");
        // Reseal only the first: the certificate must cover exactly the
        // unsealed anchors of its range.
        let cert = unsigned_certificate(CHAIN, 1, &unsealed[..1]).expect("coverage");
        let key = crate::crypto::pq::slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, &[0x5E; 96])
            .expect("public key");
        struct SealKey(Vec<u8>);
        impl crate::crypto::pkcs11::HsmPqKey for SealKey {
            fn public_key(&self) -> Vec<u8> {
                self.0.clone()
            }
            fn sign(
                &self,
                ctx: &[u8],
                payload: &[u8],
            ) -> Result<Vec<u8>, crate::crypto::primitives::CryptoError> {
                crate::crypto::pq::slh_dsa_sign(
                    SchemeId::SLH_DSA_SHAKE_256S,
                    &[0x5E; 96],
                    payload,
                    ctx,
                    Some(&[7u8; 32]),
                )
                .map_err(|_| crate::crypto::primitives::CryptoError::Signing("slh".into()))
            }
        }
        // A certificate whose range reaches past the anchors it hashes is
        // refused: the range must be fully covered, or the tail of the range
        // would pass as resealed on one anchor's proof.
        let lying = crate::settlement::reseal::ResealCertificate {
            to_height: unsealed[1].0,
            ..cert
        };
        let signed = sign_with_seal_key(lying, 0, &SealKey(key)).expect("signs");
        assert_eq!(
            source.accept_reseal(&signed, &ledger, &registry),
            Err(SourceError::Reseal(
                crate::settlement::reseal::ResealError::CoveredMismatch,
            )),
            "the range holds both anchors, the certificate covers one"
        );
        // Covering both works, and the anchors are a live source again.
        let full = sign_with_seal_key(
            unsigned_certificate(CHAIN, 1, &unsealed).expect("coverage"),
            0,
            &SealKey(
                crate::crypto::pq::slh_dsa_public_key(SchemeId::SLH_DSA_SHAKE_256S, &[0x5E; 96])
                    .expect("public key"),
            ),
        )
        .expect("signs");
        assert_eq!(source.accept_reseal(&full, &ledger, &registry), Ok(2));
        assert!(source.unsealed_anchors(&registry).is_empty());
        let seal = source.seal(Stage::Ephyra, 360).expect("a seal");
        assert!(seal.is_live(&registry));
        assert!(seal.anchors(Stage::Ephyra, 360));
    }

    #[test]
    fn a_seal_dies_with_its_only_family() {
        use crate::crypto::scheme::{SchemeStatus, SchemeStatusRegistry, TransitionSource};
        let mut registry = SchemeStatusRegistry::genesis();
        let lattice = SealId::new(SealKind::Anchor, 360, &[SchemeId::ML_DSA_87]);
        let hash = SealId::new(SealKind::RootSeal, 3_600, &[SchemeId::SLH_DSA_SHAKE_256S]);
        let both = SealId::new(
            SealKind::FinalityQc,
            10,
            &[SchemeId::BLS12381_MINSIG, SchemeId::ML_DSA_65],
        );
        assert!(lattice.is_live(&registry) && hash.is_live(&registry) && both.is_live(&registry));
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_87, to, TransitionSource::CanaryAlarm)
                .expect("one rung forward");
        }
        assert!(
            !lattice.is_live(&registry),
            "the anchor seal needs ML-DSA-87"
        );
        assert!(hash.is_live(&registry), "the root seal does not");
        assert!(
            both.is_live(&registry),
            "ML-DSA-65 still stands behind the QC"
        );
        for to in [SchemeStatus::Deprecated, SchemeStatus::Disabled] {
            registry
                .transition_scheme(SchemeId::ML_DSA_65, to, TransitionSource::CanaryAlarm)
                .expect("one rung forward");
        }
        assert!(!both.is_live(&registry), "BLS alone is never a live seal");
    }

    #[test]
    fn a_bls_only_checkpoint_is_not_canonical() {
        let mut source = PqCanonicalSource::new(CHAIN);
        assert_eq!(
            source.accept_finality(10, [1; 32], &[SchemeId::BLS12381_MINSIG]),
            Err(SourceError::NotPostQuantum)
        );
        assert_eq!(
            source.accept_finality(10, [1; 32], &[]),
            Err(SourceError::NotPostQuantum)
        );
        assert_eq!(source.canonical(Stage::Medusa, 10), None);
        assert_eq!(source.seal(Stage::Medusa, 10), None);
        // With the ML-DSA-65 QC it is.
        source
            .accept_finality(
                10,
                [1; 32],
                &[SchemeId::BLS12381_MINSIG, SchemeId::ML_DSA_65],
            )
            .expect("a QC backed checkpoint");
        assert_eq!(source.canonical(Stage::Medusa, 10), Some([1; 32]));
        assert_eq!(
            source.seal(Stage::Medusa, 10).map(|s| s.kind),
            Some(SealKind::FinalityQc)
        );
        // An isolate alarm drops BLS: the QC alone suffices.
        source
            .accept_finality(20, [2; 32], &[SchemeId::ML_DSA_65])
            .expect("the QC alone is canonical");
        assert_eq!(source.latest_height(Stage::Medusa), Some(20));
        assert_eq!(source.latest_at_or_below(Stage::Medusa, 19), Some(10));
        source.forget_finality_above(10);
        assert_eq!(source.latest_height(Stage::Medusa), Some(10));
    }

    #[test]
    fn a_verified_anchor_is_the_ephyra_source_and_a_forged_one_is_not() {
        let ledger = software_ledger(CHAIN, 1);
        let mut source = PqCanonicalSource::new(CHAIN);
        let good = anchor(360, &ledger, &[0, 1]);
        source
            .accept_anchor(&good, &ledger)
            .expect("two of three keys");
        assert_eq!(
            source.canonical(Stage::Ephyra, 360),
            Some(good.aggregate_root)
        );
        assert_eq!(source.canonical(Stage::Ephyra, 720), None);

        // One signature is no anchor.
        let one = PqAnchor {
            signatures: vec![good.signatures[0].clone()],
            height: 720,
            ..good.clone()
        };
        assert!(source.accept_anchor(&one, &ledger).is_err());
        // A root edited after signing no longer verifies.
        let forged = PqAnchor {
            aggregate_root: [0xEE; 32],
            height: 360,
            ..good.clone()
        };
        assert!(matches!(
            source.accept_anchor(&forged, &ledger),
            Err(SourceError::Anchor("anchor-invalid-signature"))
        ));
        assert_eq!(
            source.canonical(Stage::Ephyra, 360),
            Some(good.aggregate_root)
        );
        // Another chain's anchor.
        let other_chain = PqAnchor {
            chain_id: CHAIN + 1,
            ..good.clone()
        };
        assert!(matches!(
            source.accept_anchor(&other_chain, &ledger),
            Err(SourceError::WrongChain { .. })
        ));
        // An anchor of the wrong key epoch.
        let stale = PqAnchor {
            key_epoch: 9,
            ..good
        };
        assert!(source.accept_anchor(&stale, &ledger).is_err());
    }

    #[test]
    fn a_verified_root_seal_is_the_polyp_source_and_only_the_newest() {
        let ledger = software_ledger(CHAIN, 1);
        let mut source = PqCanonicalSource::new(CHAIN);
        let anchors = [anchor(3_600, &ledger, &[0, 2])];
        let seal = root_seal(&ledger, &anchors, 3_600);
        source
            .accept_root_seal(&seal, &ledger)
            .expect("a signed seal");
        assert_eq!(source.canonical(Stage::Polyp, 3_600), Some(seal.digest()));
        assert_eq!(
            source.canonical(Stage::Polyp, 0),
            None,
            "genesis is no longer an answer"
        );
        assert_eq!(
            source.seal(Stage::Polyp, 3_600),
            Some(SealId::new(
                SealKind::RootSeal,
                3_600,
                &[SchemeId::SLH_DSA_SHAKE_256S]
            ))
        );
        assert_eq!(
            source.accept_root_seal(&seal, &ledger),
            Err(SourceError::NotNewer {
                height: 3_600,
                held: 3_600
            })
        );
        // A seal with a flipped signature byte is refused and changes nothing.
        let mut forged = seal;
        forged.seal_height = 7_200;
        assert!(matches!(
            source.accept_root_seal(&forged, &ledger),
            Err(SourceError::RootSeal(_))
        ));
        assert_eq!(source.latest_height(Stage::Polyp), Some(3_600));
    }
}
