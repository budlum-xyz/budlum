//! Name resolution behind a verified header (B14, `A4`).
//!
//! The gateway's answer is only worth what the proof behind it is worth, and
//! the proof is only worth what the root it is checked against is worth. The
//! chain of trust is therefore fixed here, in one function, and nothing in this
//! module takes a root, a height or a record from the same answer that carries
//! the proof:
//!
//! ```text
//! light client  ->  verified state root at a height      (A4 step 3)
//! RPC answer    ->  proof for that name
//! verify        ->  proof folds to the root the light client already trusts
//! record        ->  read only from the proof, never from a second RPC field
//! ```
//!
//! # Why the traits, not the RPC types
//!
//! The rules above are what must be tested. An `RpcClient` that speaks HTTP is
//! the part that has to be right about TLS, timeouts and retries, and none of
//! that changes the trust argument. So the trust argument lives in
//! [`resolve_verified`] against two small traits, and the HTTP client is one
//! implementation of them.
//!
//! # Failure is a status, never a substitute
//!
//! A proof that does not verify is a 502 and no content. The gateway never
//! falls back to an unverified answer, a cached body from another name, or the
//! record the RPC sent next to the proof: each of those would turn a
//! verification failure into a page.

use std::collections::BTreeMap;

use crate::bns::registry::BnsRegistry;
use crate::bns::types::BnsMerkleBranch;
use crate::storage::bud3::content_ref::ContentRef;

use super::host::Target;
use super::manifest::{Route, RouteError, SiteManifest};

/// The HTTP status the gateway answers with when a proof does not verify.
const PROOF_FAILED_STATUS: u16 = 502;

/// Verified headers, as the light client knows them.
pub trait StateRoots {
    /// The state root of the header at `height`, already verified by the light
    /// client. `None` means the client has not seen that height.
    fn verified_state_root(&self, height: u64) -> Option<[u8; 32]>;

    /// The epoch of the header at `height`, from the same verified header.
    ///
    /// Expiry is decided against this epoch and never against one the
    /// answering node supplies. The root does not commit to the epoch, so an
    /// answer that carries its own can date an expired record to before its
    /// term ended. `None` means there is no verified epoch for that height, so
    /// no expiry verdict can be made.
    fn verified_epoch(&self, height: u64) -> Option<u64>;
}

/// One RPC answer: a height, the proof it claims for a name, and the epoch.
///
/// The record is deliberately absent. The record is whatever the verified
/// branch says it is; a separate `record` field would be a second source for
/// the same fact, and the second source is the one an attacker writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameProof {
    /// The height the answering node claims the proof belongs to.
    pub height: u64,
    /// The epoch the answering node says it is. It is a claim. Only the
    /// consistency check against the proof's own epoch reads it. Expiry is
    /// judged against the epoch of the verified header.
    pub epoch: u64,
    /// The Merkle proof itself, checked against the root of `height`.
    pub proof: crate::bns::types::BnsStateProof,
}

/// A BNS proof source, normally one of several RPC nodes.
pub trait NameProver {
    /// Ask `name` for a proof.
    ///
    /// # Errors
    ///
    /// An opaque message. The gateway treats every error as a 502 unless every
    /// configured node agrees, in which case the name is a 404.
    fn proof_for(&self, name: &str) -> Result<NameProof, String>;
}

/// A site body source: the B.U.D. 3.0 object the manifest route names.
pub trait ContentSource {
    /// The bytes of `content`.
    ///
    /// # Errors
    ///
    /// An opaque message, answered as a 502. There is no fallback body.
    fn fetch(&self, content: &ContentRef) -> Result<Vec<u8>, String>;
    /// The manifest stored in `content`.
    ///
    /// # Errors
    ///
    /// An opaque message, answered as a 502.
    fn fetch_manifest(&self, content: &ContentRef) -> Result<SiteManifest, String>;
}

/// A resolved name: the branch that proved it and the height it was proved at.
///
/// exposed for: the gateway binary, which receives it from
/// [`resolve_verified`] and reads both fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The verified branch. Every field the gateway serves comes from here.
    pub branch: BnsMerkleBranch,
    /// The height whose header root the branch folded to.
    pub height: u64,
}

/// Why a name did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    /// The host parsed, but the registry has no such name.
    NotFound,
    /// The name exists and its term has ended.
    Expired,
    /// The name exists and carries no content, or the subdomain has none.
    NoContent,
    /// The name exists, but no such subdomain is registered.
    NoSuchSubdomain(String),
    /// The proof did not fold to the root the light client trusts.
    ProofFailed(String),
    /// The node answered with a height the light client has not seen.
    UnknownHeight(u64),
    /// Every configured node failed, so there is nothing to compare.
    NoProverAnswered,
    /// The nodes disagree. Serving either answer would pick a side.
    ProversDisagree,
    /// The manifest could not be read or the path is not in it.
    Site(RouteError),
    /// The content store refused.
    ContentUnavailable(String),
}

impl GatewayError {
    /// The status a caller answers with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound | Self::Expired | Self::NoContent | Self::NoSuchSubdomain(_) => 404,
            Self::ProofFailed(_) | Self::NoProverAnswered | Self::ProversDisagree => {
                PROOF_FAILED_STATUS
            }
            Self::UnknownHeight(_) => PROOF_FAILED_STATUS,
            Self::Site(RouteError::Malformed) => 400,
            Self::Site(RouteError::DisallowedMime) => 415,
            Self::Site(_) => 404,
            Self::ContentUnavailable(_) => PROOF_FAILED_STATUS,
        }
    }
}

/// Ask every prover for `name` and require them to agree.
///
/// One prover answering is enough, because the proof is checked against a root
/// the light client verified: agreement is a second opinion about *which
/// height* answered, not about whether the answer is true. Disagreement is
/// still a refusal rather than a majority vote, because a gateway that picked
/// the answer with the most votes would be a consensus of nodes instead of a
/// consensus of chain.
///
/// # Errors
///
/// [`GatewayError::NoProverAnswered`] when no prover produced a proof, and
/// [`GatewayError::ProversDisagree`] when two produced different ones.
fn agreed_proof<P: NameProver>(provers: &[P], name: &str) -> Result<NameProof, GatewayError> {
    let mut agreed: Option<NameProof> = None;
    for prover in provers {
        let Ok(answer) = prover.proof_for(name) else {
            continue;
        };
        match &agreed {
            None => agreed = Some(answer),
            Some(first) => {
                if *first != answer {
                    return Err(GatewayError::ProversDisagree);
                }
            }
        }
    }
    agreed.ok_or(GatewayError::NoProverAnswered)
}

/// Check `answer` against `root` and return the live branch it proves.
///
/// `epoch` is the epoch of the verified header at `answer.height`, never the
/// epoch the answer claims.
///
/// An expired record is told apart from a bad proof. The proof of an expired
/// record is first checked one epoch before its expiry, so only a record that
/// really folds to `root` is answered as expired. Anything else is a failed
/// proof.
///
/// # Errors
///
/// [`GatewayError::ProofFailed`], [`GatewayError::NotFound`] or
/// [`GatewayError::Expired`].
fn verified_branch<'a>(
    answer: &'a NameProof,
    root: &[u8; 32],
    epoch: u64,
) -> Result<&'a BnsMerkleBranch, GatewayError> {
    if answer.epoch != answer.proof.epoch {
        return Err(GatewayError::ProofFailed(
            "answer epoch differs from proof epoch".into(),
        ));
    }
    let lapsed = answer
        .proof
        .entry
        .as_ref()
        .filter(|entry| answer.proof.included && entry.expires_at <= epoch)
        .map(|entry| entry.expires_at);
    if let Some(expires_at) = lapsed {
        let before = expires_at
            .checked_sub(1)
            .ok_or_else(|| GatewayError::ProofFailed("record expires at epoch zero".into()))?;
        BnsRegistry::verify_state_proof(&answer.proof, root, before)
            .map_err(GatewayError::ProofFailed)?;
        return Err(GatewayError::Expired);
    }
    BnsRegistry::verify_state_proof(&answer.proof, root, epoch)
        .map_err(GatewayError::ProofFailed)?
        .ok_or(GatewayError::NotFound)
}

/// Resolve `target` through a proof the light client has already checked.
///
/// Steps, in order: agree a proof across the configured nodes, take the state
/// root and the epoch of the proof's height from the light client (never from
/// the answer), require the proof to fold to that root, read the record from
/// the folded branch, refuse a record that is expired at that epoch, then take
/// the subdomain's content when a subdomain was asked for and the name's own
/// content otherwise.
///
/// # Errors
///
/// [`GatewayError::UnknownHeight`], [`GatewayError::ProofFailed`],
/// [`GatewayError::NotFound`], [`GatewayError::Expired`],
/// [`GatewayError::NoSuchSubdomain`] or [`GatewayError::NoContent`], in that
/// order of precedence.
pub fn resolve_verified<P: NameProver, R: StateRoots + ?Sized>(
    provers: &[P],
    roots: &R,
    target: &Target,
) -> Result<Resolved, GatewayError> {
    let answer = agreed_proof(provers, &target.name)?;
    let root = roots
        .verified_state_root(answer.height)
        .ok_or(GatewayError::UnknownHeight(answer.height))?;
    let epoch = roots
        .verified_epoch(answer.height)
        .ok_or(GatewayError::UnknownHeight(answer.height))?;
    let branch = verified_branch(&answer, &root, epoch)?;
    if let Some(sub) = &target.sub {
        let extras = branch
            .extras
            .as_ref()
            .ok_or_else(|| GatewayError::ProofFailed("branch carries no extras".into()))?;
        // A subdomain is an owner pointer under the name. It has no content
        // of its own, so it serves the name's manifest once it is proven to
        // exist.
        if !extras.subdomains.contains_key(sub) {
            return Err(GatewayError::NoSuchSubdomain(sub.clone()));
        }
    }
    Ok(Resolved {
        branch: branch.clone(),
        height: answer.height,
    })
}

/// The proved B.U.D. 3.0 `ContentRef` a name record points at.
///
/// The legacy `content_id` and `storage_root` fields are unrelated to the
/// B.U.D. 3.0 identifier and object commitment. `set_bud3_content` writes
/// only `bud3_content`; requiring those legacy fields would make a valid,
/// independently verified B.U.D. 3.0 site look empty. A public gateway
/// serves only public content and validates the complete reference again.
#[must_use]
pub fn content_ref_of(branch: &BnsMerkleBranch) -> Option<ContentRef> {
    let content = branch.extras.as_ref()?.bud3_content?;
    if content.content_id.kind != crate::storage::bud3::content_id::ContentIdKind::Public {
        return None;
    }
    ContentRef::new(
        content.content_id,
        content.object_commitment,
        content.nft_id,
    )
    .ok()
}

/// Resolve a request path against a site.
///
/// # Errors
///
/// [`GatewayError::Site`] carrying the manifest's own reason.
pub fn route_of<'a>(manifest: &'a SiteManifest, path: &str) -> Result<&'a Route, GatewayError> {
    manifest.resolve(path).map_err(GatewayError::Site)
}

/// The cache key for a site request: the object commitment, not the path.
///
/// Content is addressed by its bytes, so one object has one key regardless of
/// which name or path reached it. A path-keyed cache would store the same
/// bytes once per name.
#[must_use]
pub fn cache_key(content: &ContentRef) -> [u8; 32] {
    content.object_commitment
}

/// A verified-answer cache, keyed by object commitment.
///
/// Bounded by total bytes, not by entry count, because one entry can be a
/// 10 MB page and a thousand entries can be a thousand favicons. Every byte is
/// checked against the `ContentId` digest before it is stored, and again when
/// it is served, so a cache that was written by a buggy or hostile source can
/// still not serve a body that does not hash to the id the manifest named.
#[derive(Debug, Default)]
pub struct ContentCache {
    entries: BTreeMap<[u8; 32], Vec<u8>>,
    max_bytes: usize,
    held_bytes: usize,
}

/// Why a cache insert was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMiss {
    /// The bytes do not hash to the `ContentId` the reference named.
    DigestMismatch,
    /// The object does not fit the budget, so caching it would evict
    /// everything else for one page.
    TooLarge,
}

impl ContentCache {
    /// An empty cache holding at most `max_bytes`.
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_bytes,
            held_bytes: 0,
        }
    }

    /// Insert `bytes` for `content` after checking them against its id.
    ///
    /// # Errors
    ///
    /// [`CacheMiss::DigestMismatch`] when the bytes do not hash to the id, and
    /// [`CacheMiss::TooLarge`] when the object alone exceeds the budget.
    pub fn insert(&mut self, content: &ContentRef, bytes: Vec<u8>) -> Result<(), CacheMiss> {
        let public = crate::storage::bud3::content_id::ContentId::public(&bytes);
        if public != content.content_id {
            return Err(CacheMiss::DigestMismatch);
        }
        if bytes.len() > self.max_bytes {
            return Err(CacheMiss::TooLarge);
        }
        let key = content.object_commitment;
        if let Some(old) = self.entries.remove(&key) {
            self.held_bytes = self.held_bytes.saturating_sub(old.len());
        }
        while self.held_bytes + bytes.len() > self.max_bytes {
            let Some(victim) = self.entries.keys().next().copied() else {
                break;
            };
            if let Some(dropped) = self.entries.remove(&victim) {
                self.held_bytes = self.held_bytes.saturating_sub(dropped.len());
            }
        }
        self.held_bytes += bytes.len();
        self.entries.insert(key, bytes);
        Ok(())
    }

    /// The cached bytes for `content`, re-checked against its id.
    ///
    /// A poisoned entry answers `None` and is dropped, so a bad write cannot
    /// become a bad page.
    pub fn get(&mut self, content: &ContentRef) -> Option<&[u8]> {
        let key = content.object_commitment;
        let valid = self.entries.get(&key).is_some_and(|bytes| {
            crate::storage::bud3::content_id::ContentId::public(bytes) == content.content_id
        });
        if !valid {
            if let Some(dropped) = self.entries.remove(&key) {
                self.held_bytes = self.held_bytes.saturating_sub(dropped.len());
            }
            return None;
        }
        self.entries.get(&key).map(Vec::as_slice)
    }

    /// Bytes currently held.
    #[must_use]
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bns::registry::BnsRegistry;
    use crate::core::address::Address;
    use crate::storage::bud3::content_id::{ContentId, ContentIdKind};

    struct FakeProver {
        answer: Result<NameProof, String>,
    }

    impl NameProver for FakeProver {
        fn proof_for(&self, _name: &str) -> Result<NameProof, String> {
            self.answer.clone()
        }
    }

    /// Verified headers: height to (root, epoch).
    struct Roots(BTreeMap<u64, ([u8; 32], u64)>);

    impl StateRoots for Roots {
        fn verified_state_root(&self, height: u64) -> Option<[u8; 32]> {
            self.0.get(&height).map(|(root, _)| *root)
        }

        fn verified_epoch(&self, height: u64) -> Option<u64> {
            self.0.get(&height).map(|(_, epoch)| *epoch)
        }
    }

    fn registry_with(content: Option<(ContentId, [u8; 32])>) -> BnsRegistry {
        let owner = Address::from([0x11; 32]);
        let mut reg = BnsRegistry::new();
        reg.register("ayaz.bud".to_string(), owner, 10, 100)
            .unwrap();
        if let Some((content_id, object_commitment)) = content {
            let bud3_content = ContentRef::new(content_id, object_commitment, None)
                .expect("non-zero B.U.D. 3.0 reference");
            // B.U.D. 3.0 registration writes this field, not the unrelated
            // legacy `content_id` and `storage_root` fields.
            reg.names
                .get_mut("ayaz.bud")
                .expect("registered above")
                .bud3_content = Some(bud3_content);
        }
        reg
    }

    fn proof_from(reg: &BnsRegistry, name: &str, height: u64, epoch: u64) -> NameProof {
        NameProof {
            height,
            epoch,
            proof: reg.prove_name(name, epoch),
        }
    }

    fn target(sub: Option<&str>) -> Target {
        Target {
            name: "ayaz.bud".into(),
            sub: sub.map(str::to_string),
        }
    }

    #[test]
    fn a_proof_that_folds_to_the_verified_root_resolves() {
        let reg = registry_with(None);
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 100)),
        };
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));
        let resolved = resolve_verified(&[prover], &roots, &target(None)).unwrap();
        assert_eq!(resolved.height, 7);
        assert_eq!(resolved.branch.name, "ayaz.bud");
        assert_eq!(resolved.branch.expires_at, 110);
    }

    #[test]
    fn a_proof_checked_against_a_root_the_node_chose_would_be_no_proof() {
        // The node answers with a height the light client never verified. The
        // gateway must not accept the root from the answer, so there is no
        // root to check against and the request fails closed.
        let reg = registry_with(None);
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 9, 100)),
        };
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));
        assert_eq!(
            resolve_verified(&[prover], &roots, &target(None)),
            Err(GatewayError::UnknownHeight(9))
        );
    }

    #[test]
    fn a_tampered_proof_is_a_502_and_never_a_page() {
        let reg = registry_with(None);
        let mut answer = proof_from(&reg, "ayaz.bud", 7, 100);
        answer.proof.entry.as_mut().unwrap().owner = Address::from([0x99; 32]);
        let prover = FakeProver { answer: Ok(answer) };
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));
        let err = resolve_verified(&[prover], &roots, &target(None)).unwrap_err();
        assert_eq!(err.status(), PROOF_FAILED_STATUS);
        assert!(matches!(err, GatewayError::ProofFailed(_)));

        let mut inconsistent = proof_from(&reg, "ayaz.bud", 7, 100);
        inconsistent.epoch = 99;
        let err = resolve_verified(
            &[FakeProver {
                answer: Ok(inconsistent),
            }],
            &roots,
            &target(None),
        )
        .unwrap_err();
        assert!(matches!(err, GatewayError::ProofFailed(_)));
    }

    #[test]
    fn an_expired_record_is_a_404_even_with_a_perfect_proof() {
        let reg = registry_with(None);
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 200)),
        };
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 200))]));
        // The proof's own expiry check runs *after* the Merkle check. A
        // verified expired record is a 404, not an invalid-proof 502.
        let err = resolve_verified(&[prover], &roots, &target(None)).unwrap_err();
        assert_eq!(err, GatewayError::Expired);
        assert_eq!(err.status(), 404);

        let mut tampered = proof_from(&reg, "ayaz.bud", 7, 200);
        tampered.proof.entry.as_mut().unwrap().owner = Address::from([0x99; 32]);
        let err = resolve_verified(
            &[FakeProver {
                answer: Ok(tampered),
            }],
            &roots,
            &target(None),
        )
        .unwrap_err();
        assert!(matches!(err, GatewayError::ProofFailed(_)));
        assert_eq!(err.status(), PROOF_FAILED_STATUS);
    }

    /// The root does not commit to the epoch. A node that reports an epoch
    /// inside the term must not keep an expired record resolving.
    #[test]
    fn a_node_cannot_date_an_expired_record_to_before_its_term() {
        // The record expires at 110. The verified header is at epoch 200.
        let reg = registry_with(None);
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 200))]));
        // The node claims epoch 100 and builds its proof for it.
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 100)),
        };
        let err = resolve_verified(&[prover], &roots, &target(None)).unwrap_err();
        assert_eq!(err, GatewayError::Expired);
        assert_eq!(err.status(), 404);
    }

    /// The same lie the other way: a node that reports a late epoch must not
    /// turn a live record into a 404.
    #[test]
    fn a_node_cannot_expire_a_live_record_by_reporting_a_late_epoch() {
        let reg = registry_with(None);
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 200)),
        };
        let resolved = resolve_verified(&[prover], &roots, &target(None)).unwrap();
        assert_eq!(resolved.branch.name, "ayaz.bud");
        assert_eq!(resolved.branch.expires_at, 110);
    }

    /// A header with a root and no epoch is a header the gateway cannot judge
    /// expiry against, so the height is unknown.
    #[test]
    fn a_height_with_a_root_and_no_verified_epoch_is_unknown() {
        struct RootOnly([u8; 32]);

        impl StateRoots for RootOnly {
            fn verified_state_root(&self, _height: u64) -> Option<[u8; 32]> {
                Some(self.0)
            }

            fn verified_epoch(&self, _height: u64) -> Option<u64> {
                None
            }
        }

        let reg = registry_with(None);
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 100)),
        };
        assert_eq!(
            resolve_verified(&[prover], &RootOnly(reg.root()), &target(None)),
            Err(GatewayError::UnknownHeight(7))
        );
    }

    #[test]
    fn provers_must_agree_and_an_empty_set_is_not_agreement() {
        let reg = registry_with(None);
        let honest = proof_from(&reg, "ayaz.bud", 7, 100);
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));

        let one = FakeProver {
            answer: Ok(honest.clone()),
        };
        let same = FakeProver {
            answer: Ok(honest.clone()),
        };
        // The Merkle branch can be byte-for-byte identical at two heights;
        // the nodes still disagree on which verified header anchors it.
        let differing = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 8, 100)),
        };

        assert!(resolve_verified(&[one], &roots, &target(None)).is_ok());
        // Two agreeing provers are fine.
        let one = FakeProver {
            answer: Ok(honest.clone()),
        };
        assert!(resolve_verified(&[one, same], &roots, &target(None)).is_ok());
        // A silent prover is skipped, not fatal.
        let one = FakeProver {
            answer: Ok(honest.clone()),
        };
        let silent_again = FakeProver {
            answer: Err("timeout".into()),
        };
        assert!(resolve_verified(&[one, silent_again], &roots, &target(None)).is_ok());
        // Disagreement is a refusal.
        let one = FakeProver {
            answer: Ok(honest.clone()),
        };
        assert_eq!(
            resolve_verified(&[one, differing], &roots, &target(None)),
            Err(GatewayError::ProversDisagree)
        );
        // No answer at all is not a "no such name".
        let silent = FakeProver {
            answer: Err("timeout".into()),
        };
        assert_eq!(
            resolve_verified(&[silent], &roots, &target(None)),
            Err(GatewayError::NoProverAnswered)
        );
    }

    #[test]
    fn a_name_between_two_names_proves_absent_and_is_a_404() {
        let owner = Address::from([0x11; 32]);
        let mut reg = BnsRegistry::new();
        reg.register("alpha.bud".to_string(), owner, 10, 100)
            .unwrap();
        reg.register("gamma.bud".to_string(), owner, 10, 100)
            .unwrap();
        let missing = Target {
            name: "beta.bud".into(),
            sub: None,
        };
        let prover = FakeProver {
            answer: Ok(NameProof {
                height: 7,
                epoch: 100,
                proof: reg.prove_name("beta.bud", 100),
            }),
        };
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));
        assert_eq!(
            resolve_verified(&[prover], &roots, &missing),
            Err(GatewayError::NotFound)
        );
    }

    #[test]
    fn a_subdomain_is_answered_from_the_verified_branch_only() {
        let owner = Address::from([0x11; 32]);
        let mut reg = BnsRegistry::new();
        reg.register("ayaz.bud".to_string(), owner, 10, 100)
            .unwrap();
        reg.register_subdomain("ayaz.bud", "shop".to_string(), owner, &owner, 101)
            .unwrap();
        let roots = Roots(BTreeMap::from([(7u64, (reg.root(), 100))]));

        // The registered subdomain resolves.
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 100)),
        };
        assert!(resolve_verified(&[prover], &roots, &target(Some("shop"))).is_ok());

        // An unregistered one is a 404, not the name's own site: serving the
        // parent would let a typo in a subdomain load someone else's page.
        let prover = FakeProver {
            answer: Ok(proof_from(&reg, "ayaz.bud", 7, 100)),
        };
        assert_eq!(
            resolve_verified(&[prover], &roots, &target(Some("blog"))),
            Err(GatewayError::NoSuchSubdomain("blog".into()))
        );
    }

    #[test]
    fn only_a_proven_public_bud3_reference_resolves_even_without_legacy_fields() {
        let mut reg = registry_with(None);
        let proof = reg.prove_name("ayaz.bud", 100);
        let branch = BnsRegistry::verify_state_proof(&proof, &reg.root(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(content_ref_of(branch), None);

        // Legacy fields alone cannot manufacture a B.U.D. 3.0 reference.
        let owner = Address::from([0x11; 32]);
        reg.set_content(
            "ayaz.bud",
            &owner,
            crate::storage::content_id::ContentId::of(b"legacy content"),
            101,
        )
        .unwrap();
        reg.set_storage("ayaz.bud", owner, [0x44; 32], 0, 101)
            .unwrap();
        let proof = reg.prove_name("ayaz.bud", 100);
        let branch = BnsRegistry::verify_state_proof(&proof, &reg.root(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(content_ref_of(branch), None);

        // A B.U.D. 3.0-only record is a complete site reference, without
        // populating either legacy field (as the production setter does).
        let reg = registry_with(Some((
            ContentId {
                kind: ContentIdKind::Public,
                digest: [0x22; 32],
                len: 4,
            },
            [0x33; 32],
        )));
        let proof = reg.prove_name("ayaz.bud", 100);
        let branch = BnsRegistry::verify_state_proof(&proof, &reg.root(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(branch.content_id, None);
        assert_eq!(branch.storage_root, None);
        let content = content_ref_of(branch).expect("authenticated B.U.D. 3.0 reference");
        assert_eq!(content.content_id.digest, [0x22; 32]);
        assert_eq!(content.object_commitment, [0x33; 32]);

        let reg = registry_with(Some((
            ContentId {
                kind: ContentIdKind::Sealed,
                digest: [0x55; 32],
                len: 4,
            },
            [0x66; 32],
        )));
        let proof = reg.prove_name("ayaz.bud", 100);
        let branch = BnsRegistry::verify_state_proof(&proof, &reg.root(), 100)
            .unwrap()
            .unwrap();
        assert_eq!(
            content_ref_of(branch),
            None,
            "public gateway refuses sealed data"
        );
    }

    #[test]
    fn the_cache_checks_every_byte_against_the_id_before_and_after_storing() {
        let bytes = b"site bytes".to_vec();
        let id = crate::storage::bud3::content_id::ContentId::public(&bytes);
        let content = ContentRef::new(id, [0x44; 32], None).unwrap();
        let mut cache = ContentCache::new(1024);
        cache.insert(&content, bytes.clone()).unwrap();
        assert_eq!(cache.get(&content), Some(bytes.as_slice()));

        // Bytes that do not hash to the id are refused at the door.
        let wrong = ContentRef::new(
            ContentId {
                kind: ContentIdKind::Public,
                digest: [0x99; 32],
                len: 4,
            },
            [0x55; 32],
            None,
        )
        .unwrap();
        assert_eq!(
            cache.insert(&wrong, b"tampered".to_vec()),
            Err(CacheMiss::DigestMismatch)
        );
        // The length is part of a B.U.D. 3.0 ContentId, not a hint. A
        // matching digest with a forged length cannot pass the cache door.
        let wrong_len = ContentRef::new(
            ContentId {
                len: content.content_id.len + 1,
                ..content.content_id
            },
            [0xAA; 32],
            None,
        )
        .unwrap();
        assert_eq!(
            cache.insert(&wrong_len, bytes.clone()),
            Err(CacheMiss::DigestMismatch)
        );
        let wrong_lookup =
            ContentRef::new(wrong_len.content_id, content.object_commitment, None).unwrap();
        assert_eq!(cache.get(&wrong_lookup), None);

        // An object larger than the budget is refused rather than evicting
        // everything else for one page.
        let mut small = ContentCache::new(4);
        assert_eq!(small.insert(&content, bytes), Err(CacheMiss::TooLarge));
    }

    #[test]
    fn the_cache_is_bounded_by_bytes_and_keyed_by_the_object() {
        let mut cache = ContentCache::new(10);
        let first_bytes = b"123456".to_vec();
        let first = ContentRef::new(
            crate::storage::bud3::content_id::ContentId::public(&first_bytes),
            [0x01; 32],
            None,
        )
        .unwrap();
        let second_bytes = b"abcdef".to_vec();
        let second = ContentRef::new(
            crate::storage::bud3::content_id::ContentId::public(&second_bytes),
            [0x02; 32],
            None,
        )
        .unwrap();
        cache.insert(&first, first_bytes).unwrap();
        assert_eq!(cache.held_bytes(), 6);
        cache.insert(&second, second_bytes).unwrap();
        // Six plus six exceeds ten, so the older entry made room.
        assert_eq!(cache.held_bytes(), 6);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&first).is_none());
        assert!(cache.get(&second).is_some());
    }
}
