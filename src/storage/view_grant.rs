//! View grants: who may open content that is not public.
//!
//! # Product placement
//!
//! - **B.U.D. 3.0 (Three / R1):** the durable object is a recipe. A view-key
//!   unlocks *production* (or decryption of an encrypted recipe blob), not a
//!   stored body. QR frames stay derivative-only.
//! - **B.U.D. 2.0 (Classic body / R2-R3 cost regimes):** the durable object is
//!   held bytes. Privacy is **client-side encryption**
//!   ([`crate::storage::ContentEncryption::ClientSide`]) plus this grant layer
//!   for key delivery. Operators hold ciphertext; they do not hold the key.
//!
//! R2/R3 in the cost tables are **not** a third edition. They are body-cost
//! regimes on the Classic path. If it has a body, it is 2.0 (Classic). If it
//! is recipe-only with zero held bytes, it is 3.0 (Three). Calling a stored
//! JPEG "3.0 because we wrapped it in QR" is a category error (K13).
//!
//! # What a grant is
//!
//! A grant is an on-chain record: `(content, grantee, key_id, policy)` with an
//! open epoch and optional revoke epoch. The **key material is never stored
//! here** - putting a key in a public commitment publishes the key. Delivery
//! is out of band (DM, device keystore, sealed channel). This registry only
//! answers: "does grantee G still have permission to use `key_id` K on content C?"
//!
//! # Revocation honesty
//!
//! Revoke means **no new opens**. Bytes or frames already on a device are not
//! clawed back. Product copy that says otherwise is a lie (threat model T3).
//!
//! # ZKVM / TEE (research pin, not implemented here)
//!
//! - **ZK** proves a statement about committed data without revealing it
//!   (Filecoin PoRep/PoSt compress storage proofs; they do not make plaintext
//!   private if the client uploaded plaintext). Confidentiality of *content*
//!   still requires client encryption first.
//! - **TEE** can decrypt or evaluate inside an enclave (attestation). Trust is
//!   the chip vendor + side-channel history (SGX breaks are real). Our
//!   `tee_attestation` module signs quotes; vendor chain verify is unwired
//!   (no trust root).
//! - **Hybrid (industry default 2025-26):** chain holds commitments + grants;
//!   ZK for public verifiability of proofs; TEE optional for private compute.
//!   Validity of a proof ≠ authorization to view (Aleo/snarkVM lesson).

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How wide a grant is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewPolicy {
    /// Only the owner (implicit; usually no row needed).
    OwnerOnly,
    /// A single grantee address (DM-style).
    NamedGrantee,
    /// Anyone who presents the matching `key_id` (public link).
    PublicKeyId,
}

/// On-chain grant row. No key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewGrant {
    pub grant_id: u64,
    pub content_id: ContentId,
    /// Owner who issued the grant (revoker).
    pub issuer: Address,
    /// `None` only with [`ViewPolicy::PublicKeyId`].
    pub grantee: Option<Address>,
    /// Handle the off-chain keystore uses; not the key.
    pub key_id: [u8; 32],
    pub policy: ViewPolicy,
    pub opened_epoch: u64,
    /// `None` = still live.
    pub revoked_epoch: Option<u64>,
}

impl ViewGrant {
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.revoked_epoch.is_none()
    }

    /// Binding commitment over the grant fields (no secrets).
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let grant_id = self.grant_id.to_le_bytes();
        let opened = self.opened_epoch.to_le_bytes();
        let policy = [match self.policy {
            ViewPolicy::OwnerOnly => 1u8,
            ViewPolicy::NamedGrantee => 2u8,
            ViewPolicy::PublicKeyId => 3u8,
        }];
        let grantee = self.grantee.map(|a| *a.as_bytes()).unwrap_or([0u8; 32]);
        let revoked = self
            .revoked_epoch
            .map(|e| e.to_le_bytes())
            .unwrap_or([0u8; 8]);
        hash_fields_bytes(&[
            b"BDLM_VIEW_GRANT_V1",
            &grant_id,
            &self.content_id.0,
            issuer_bytes(&self.issuer),
            &grantee,
            &self.key_id,
            &policy,
            &opened,
            &revoked,
        ])
    }
}

fn issuer_bytes(a: &Address) -> &[u8; 32] {
    a.as_bytes()
}

/// Refusal of a signed authorisation over a grant mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAuthError {
    /// The signature does not verify under the supplied key.
    BadSignature,
    /// The key speaks for an address that is not the owner named in the request.
    WrongOwner,
    /// The signature cannot be checked at all, because this binary was built
    /// without the ML-DSA-87 wallet verifier.
    VerifierUnavailable,
}

impl std::fmt::Display for GrantAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "grant authorization signature does not verify"),
            Self::WrongOwner => write!(f, "grant authorization key is not the content owner"),
            Self::VerifierUnavailable => {
                write!(f, "grant signatures need the wallet-ml-dsa verifier")
            }
        }
    }
}

impl std::error::Error for GrantAuthError {}

/// Signed authorisation for a view-grant mutation.
///
/// The registry knows which address owns content; it does not know who is
/// calling. This closes that gap: the caller supplies the owner's FIPS 204
/// ML-DSA-87 public key and a signature over the domain-tagged digest of the
/// mutation, and the address the key derives to is the only identity the
/// registry believes. Before this existed, `issuer` and `caller` were strings a
/// caller typed into an RPC field, so any caller could hand out view grants for
/// content it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAuthorization {
    /// Account public key whose word this is.
    pub owner_key: [u8; crate::crypto::primitives::ML_DSA_87_PUBLIC_KEY_LEN],
    /// ML-DSA-87 signature over the mutation digest.
    pub signature: Vec<u8>,
}

impl GrantAuthorization {
    /// The address this authorisation speaks for: derived from the key, never
    /// read from a field.
    ///
    /// The derivation is
    /// [`wallet_address_from_ml_dsa_87_public_key`](crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key),
    /// the one the chain already uses to bind a transaction signature to the
    /// spend authority that produced it. Choosing it is what makes a grant mean
    /// "the wallet holding this key allowed this": a key cannot sign its way to
    /// an address the wallet itself does not own, and a grant could not be issued
    /// under one derivation and spent under another. A binary without the
    /// `wallet-ml-dsa` feature derives nothing and refuses everything.
    ///
    /// # Errors
    ///
    /// Returns [`GrantAuthError::VerifierUnavailable`] when this build cannot
    /// check ML-DSA-87 keys.
    pub fn derived_owner(&self) -> Result<Address, GrantAuthError> {
        crate::crypto::primitives::wallet_address_from_ml_dsa_87_public_key(&self.owner_key)
            .map_err(|_| GrantAuthError::VerifierUnavailable)
    }

    /// Whether `digest` is signed by `owner`'s key.
    ///
    /// # Errors
    ///
    /// [`GrantAuthError::WrongOwner`] when the key derives to another address,
    /// [`GrantAuthError::BadSignature`] when the signature does not verify, which
    /// includes a binary built without the `wallet-ml-dsa` feature.
    pub fn verify(&self, digest: &[u8; 32], owner: &Address) -> Result<(), GrantAuthError> {
        if &self.derived_owner()? != owner {
            return Err(GrantAuthError::WrongOwner);
        }
        crate::crypto::primitives::verify_ml_dsa_87_signature(
            digest,
            &self.signature,
            &self.owner_key,
        )
        .map_err(|_| GrantAuthError::BadSignature)
    }
}

/// Digest a grant issuance is signed over. The content, the derived `issuer`,
/// the grantee, the key handle, the policy and the opening epoch all enter: a
/// signature cannot be moved to another object, another key or another grant.
#[must_use]
pub fn grant_issue_digest(
    content_id: &ContentId,
    issuer: &Address,
    grantee: Option<&Address>,
    key_id: &[u8; 32],
    policy: ViewPolicy,
    opened_epoch: u64,
) -> [u8; 32] {
    let policy_byte = [match policy {
        ViewPolicy::OwnerOnly => 1u8,
        ViewPolicy::NamedGrantee => 2u8,
        ViewPolicy::PublicKeyId => 3u8,
    }];
    let absent_grantee = [0u8; 32];
    hash_fields_bytes(&[
        b"BDLM_GRANT_ISSUE_V1",
        content_id.as_bytes(),
        issuer.as_bytes(),
        grantee.map_or(absent_grantee.as_slice(), |g| g.as_bytes()),
        key_id,
        &policy_byte,
        &opened_epoch.to_le_bytes(),
    ])
}

/// Digest a grant revocation is signed over.
#[must_use]
pub fn grant_revoke_digest(grant_id: u64, caller: &Address, at_epoch: u64) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_GRANT_REVOKE_V1",
        &grant_id.to_le_bytes(),
        caller.as_bytes(),
        &at_epoch.to_le_bytes(),
    ])
}

/// Digest a social/DM delete authorisation is signed over. Separate domain
/// from issue and revoke: a delete is not a revoke of one grant, it is the
/// owner retiring every grant of one content and its key id with them.
#[must_use]
pub fn social_delete_digest(content_id: &ContentId, caller: &Address, at_epoch: u64) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_SOCIAL_DELETE_V1",
        content_id.as_bytes(),
        caller.as_bytes(),
        &at_epoch.to_le_bytes(),
    ])
}

/// Digest a viewer signs to open a reveal session for one object.
///
/// The registry decides `may_view(content, viewer, key_id, owner)`, and until
/// this existed `viewer` was a string the RPC caller typed: anyone could name
/// a grantee and have the node build frames for content the caller holds no
/// grant on. The claim binds the viewer address (derived from the signing key,
/// never read from a field), the object, the key handle, the owner whose
/// grant is authoritative, and the payload the frames will be built from, so
/// a claim signed for one object, one key or one payload cannot open another.
/// `issued_at` (unix seconds) enters so a captured claim expires with
/// [`VIEW_CLAIM_MAX_AGE_SECS`] instead of living as long as the grant.
#[must_use]
pub fn view_claim_digest(
    content_id: &ContentId,
    viewer: &Address,
    key_id: &[u8; 32],
    owner: &Address,
    payload_commitment: &[u8; 32],
    issued_at: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_VIEW_CLAIM_V1",
        content_id.as_bytes(),
        viewer.as_bytes(),
        key_id,
        owner.as_bytes(),
        payload_commitment,
        &issued_at.to_le_bytes(),
    ])
}

/// How long a signed view claim stays usable, in seconds.
///
/// A claim is a bearer credential for one session open; a captured one must
/// not stay valid for the life of the grant. Five minutes matches the reveal
/// session TTL: a client that opens a session and streams it never needs a
/// claim older than the session it opened.
pub const VIEW_CLAIM_MAX_AGE_SECS: u64 = 300;

/// Digest a confidential body commit is signed over.
///
/// The object, the owner deriving from the signing key, the cipher, the
/// ciphertext root and the proof kind all enter: without this binding a
/// signature could be lifted from one commit and replayed under another body,
/// another cipher or another object.
#[must_use]
pub fn confidential_commit_digest(commit: &ConfidentialBodyCommit, owner: &Address) -> [u8; 32] {
    let enc_byte: u8 = match commit.encryption {
        crate::storage::ContentEncryption::Plaintext => 0,
        crate::storage::ContentEncryption::ClientSide(cipher) => match cipher {
            crate::storage::ContentCipher::Aes256Gcm => 1,
            crate::storage::ContentCipher::ChaCha20Poly1305 => 2,
            crate::storage::ContentCipher::XChaCha20Poly1305 => 3,
        },
    };
    let proof_byte: u8 = match commit.proof_kind {
        ConfidentialProofKind::RetrievalChallenge => 1,
        ConfidentialProofKind::ZkStorageProof => 2,
        ConfidentialProofKind::TeeAttested => 3,
        ConfidentialProofKind::HybridZkTee => 4,
    };
    hash_fields_bytes(&[
        b"BDLM_CONFIDENTIAL_COMMIT_V1",
        commit.content_id.as_bytes(),
        owner.as_bytes(),
        &[enc_byte],
        &commit.ciphertext_root,
        &[proof_byte],
    ])
}

/// Errors for the grant registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewGrantError {
    UnknownGrant(u64),
    AlreadyRevoked(u64),
    NotIssuer,
    PublicPolicyMustNotNameGrantee,
    NamedPolicyNeedsGrantee,
    OwnerOnlyMustNotNameGrantee,
    DuplicateLiveGrant,
    /// The address named as issuer is not the owner of the content, so it has
    /// no word to give about who may view it.
    NotOwner {
        /// Address the caller claimed as issuer.
        issuer: Address,
        /// Address the content belongs to.
        owner: Address,
    },
    /// No manifest describes the content, so there is no owner to authorise.
    UnknownContent,
    /// The signed authorisation is not the owner's word over this mutation.
    Authorization(GrantAuthError),
}

impl std::fmt::Display for ViewGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownGrant(id) => write!(f, "unknown view grant {id}"),
            Self::AlreadyRevoked(id) => write!(f, "view grant {id} already revoked"),
            Self::NotIssuer => write!(f, "only the issuer may revoke a view grant"),
            Self::PublicPolicyMustNotNameGrantee => {
                write!(f, "PublicKeyId grants must not name a grantee")
            }
            Self::NamedPolicyNeedsGrantee => {
                write!(f, "NamedGrantee grants need a grantee address")
            }
            Self::OwnerOnlyMustNotNameGrantee => {
                write!(f, "OwnerOnly grants must not name a grantee")
            }
            Self::NotOwner { issuer, owner } => write!(
                f,
                "view grants belong to the content owner {owner}, not {issuer}"
            ),
            Self::UnknownContent => write!(f, "no manifest describes this content"),
            Self::Authorization(e) => write!(f, "grant authorization refused: {e}"),
            Self::DuplicateLiveGrant => {
                write!(
                    f,
                    "a live grant already exists for this content/grantee/key"
                )
            }
        }
    }
}

/// In-memory grant book. Deterministic `BTreeMap` for state root hashing later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViewGrantRegistry {
    next_id: u64,
    grants: BTreeMap<u64, ViewGrant>,
    /// Live index: content → grant ids (includes revoked; filter at read).
    by_content: BTreeMap<ContentId, Vec<u64>>,
}

impl ViewGrantRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    ///
    /// Policy/grantee shape errors or a duplicate live row.
    pub fn issue(
        &mut self,
        content_id: ContentId,
        issuer: Address,
        grantee: Option<Address>,
        key_id: [u8; 32],
        policy: ViewPolicy,
        opened_epoch: u64,
    ) -> Result<u64, ViewGrantError> {
        match policy {
            ViewPolicy::NamedGrantee if grantee.is_none() => {
                return Err(ViewGrantError::NamedPolicyNeedsGrantee);
            }
            ViewPolicy::PublicKeyId if grantee.is_some() => {
                return Err(ViewGrantError::PublicPolicyMustNotNameGrantee);
            }
            ViewPolicy::OwnerOnly if grantee.is_some() => {
                return Err(ViewGrantError::OwnerOnlyMustNotNameGrantee);
            }
            _ => {}
        }
        let dup = self.grants.values().any(|g| {
            g.is_live()
                && g.content_id == content_id
                && g.key_id == key_id
                && g.grantee == grantee
                && g.policy == policy
        });
        if dup {
            return Err(ViewGrantError::DuplicateLiveGrant);
        }
        let grant_id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let grant = ViewGrant {
            grant_id,
            content_id,
            issuer,
            grantee,
            key_id,
            policy,
            opened_epoch,
            revoked_epoch: None,
        };
        self.by_content
            .entry(content_id)
            .or_default()
            .push(grant_id);
        self.grants.insert(grant_id, grant);
        Ok(grant_id)
    }

    /// # Errors
    ///
    /// Unknown id, not issuer, or already revoked.
    pub fn revoke(
        &mut self,
        grant_id: u64,
        caller: Address,
        at_epoch: u64,
    ) -> Result<(), ViewGrantError> {
        let grant = self
            .grants
            .get_mut(&grant_id)
            .ok_or(ViewGrantError::UnknownGrant(grant_id))?;
        if grant.issuer != caller {
            return Err(ViewGrantError::NotIssuer);
        }
        if grant.revoked_epoch.is_some() {
            return Err(ViewGrantError::AlreadyRevoked(grant_id));
        }
        grant.revoked_epoch = Some(at_epoch);
        Ok(())
    }

    /// Revoke a grant and deliver the resulting social event to a hook.
    ///
    /// This is the product-facing wrapper: a DM-delete or social-revoke path
    /// calls this so the local side learns not just that the row is gone but
    /// *which* content and *when*, so it can drop session keys and stop serving
    /// new reveal sessions. The revoke behaviour is exactly
    /// [`Self::revoke`], unchanged and re-used; only the event emission is new.
    ///
    /// The event is delivered only after the revoke succeeds, so a refused
    /// revoke (unknown id, wrong issuer, already revoked) produces no event and
    /// the caller sees the same errors it always did.
    ///
    /// # Errors
    ///
    /// [`ViewGrantError`] exactly as [`Self::revoke`]: `UnknownGrant`,
    /// `NotIssuer`, or `AlreadyRevoked`.
    pub fn revoke_with_hook(
        &mut self,
        grant_id: u64,
        caller: Address,
        at_epoch: u64,
        hook: &mut dyn crate::storage::three_hooks::ThreeEventHook,
    ) -> Result<(), ViewGrantError> {
        // Read the content id from the live row before revoking, so the event
        // names the content even though the row is revoked right after.
        let content_id = self
            .grants
            .get(&grant_id)
            .ok_or(ViewGrantError::UnknownGrant(grant_id))?
            .content_id;
        self.revoke(grant_id, caller, at_epoch)?;
        crate::storage::three_hooks::emit_hook(
            hook,
            crate::storage::three_hooks::ThreeHookEvent {
                kind: crate::storage::three_hooks::ThreeHookKind::GrantRevoked,
                content_id,
                actor: caller,
                epoch: at_epoch,
                grant_id: Some(grant_id),
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn get(&self, grant_id: u64) -> Option<&ViewGrant> {
        self.grants.get(&grant_id)
    }

    /// Every row this content has, revoked ones included: what an owner reads
    /// when auditing who was ever let in, as opposed to who can open it now.
    #[must_use]
    pub fn rows_for_content(&self, content_id: &ContentId) -> Vec<&ViewGrant> {
        self.by_content
            .get(content_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.grants.get(id))
            .collect()
    }

    /// Live grants for content (revoked excluded).
    #[must_use]
    pub fn live_for_content(&self, content_id: &ContentId) -> Vec<&ViewGrant> {
        self.by_content
            .get(content_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.grants.get(id))
            .filter(|g| g.is_live())
            .collect()
    }

    /// Whether `viewer` may use `key_id` on `content` at this moment.
    ///
    /// Owner is always allowed (root). `PublicKeyId` live rows allow anyone with
    /// the key handle. `NamedGrantee` requires address match. A row counts only
    /// when its issuer is that owner: a grant is the owner's word, so a row
    /// minted by anybody else is inert here even if it reached the book, and the
    /// `StorageRegistry` decides who the owner is from the manifest.
    #[must_use]
    pub fn may_view(
        &self,
        content_id: &ContentId,
        viewer: &Address,
        key_id: &[u8; 32],
        owner: &Address,
    ) -> bool {
        if viewer == owner {
            return true;
        }
        self.live_for_content(content_id).into_iter().any(|g| {
            if g.issuer != *owner {
                return false;
            }
            if &g.key_id != key_id {
                return false;
            }
            match g.policy {
                ViewPolicy::OwnerOnly => false,
                ViewPolicy::PublicKeyId => true,
                ViewPolicy::NamedGrantee => g.grantee.as_ref() == Some(viewer),
            }
        })
    }

    /// How many grant ids this book has handed out, including the revoked ones.
    ///
    /// The storage registry folds the book into its own root only after the first
    /// id exists, so this is what decides whether a fold contributes bytes: an
    /// issue-then-revoke sequence must still move the root, while a book nobody
    /// ever wrote to must not.
    #[must_use]
    pub fn issued(&self) -> u64 {
        self.next_id
    }

    /// Domain-tagged digest of the whole book: the next id and every row's
    /// commitment. The storage registry folds this into `StorageRegistry::root`
    /// once an id has been issued, so the grant set is state-root committed.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut fields: Vec<Vec<u8>> = vec![b"BDLM_VIEW_GRANT_REG_V1".to_vec()];
        fields.push(self.next_id.to_le_bytes().to_vec());
        for g in self.grants.values() {
            fields.push(g.commitment().to_vec());
        }
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        hash_fields_bytes(&refs)
    }
}

/// Confidential body commit: what Classic/2.0 puts on chain when the payload
/// must stay private from operators and chain observers.
///
/// This is **not** a 3.0 recipe. It is the honest shape for R2/R3 cost regimes:
/// ciphertext commitment + encryption claim + optional proof kind. Operators
/// prove custody of ciphertext (retrieval/PoSt-class); they never see plaintext
/// without a view-key path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBodyCommit {
    pub content_id: ContentId,
    pub encryption: crate::storage::ContentEncryption,
    /// Commitment to ciphertext (or Merkle root over encrypted shards).
    pub ciphertext_root: [u8; 32],
    /// How custody/correctness will be proven later. Pin only; no verifier here.
    pub proof_kind: ConfidentialProofKind,
}

/// Research-selected proof surface for confidential bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidentialProofKind {
    /// Challenge/response over ciphertext bytes (today's retrieval path).
    RetrievalChallenge,
    /// ZK storage proof (Filecoin-class): proves unique storage of sealed
    /// bytes without putting plaintext on chain. Still requires client
    /// encryption for content privacy.
    ZkStorageProof,
    /// TEE attestation that an enclave held/processed the object. Trusts
    /// hardware; vendor chain not wired in-tree yet.
    TeeAttested,
    /// ZK validity of a statement + TEE for private eval (industry hybrid).
    HybridZkTee,
}

impl ConfidentialBodyCommit {
    /// # Errors
    ///
    /// Plaintext encryption claim is refused: a "confidential" commit that
    /// advertises plaintext is the T1 threat (on-chain clear body).
    pub const fn new(
        content_id: ContentId,
        encryption: crate::storage::ContentEncryption,
        ciphertext_root: [u8; 32],
        proof_kind: ConfidentialProofKind,
    ) -> Result<Self, &'static str> {
        if !encryption.is_encrypted() {
            return Err(
                "confidential body commit requires ClientSide encryption; plaintext is not confidential",
            );
        }
        Ok(Self {
            content_id,
            encryption,
            ciphertext_root,
            proof_kind,
        })
    }

    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let enc = [self.encryption.commitment_tag()];
        let kind = [match self.proof_kind {
            ConfidentialProofKind::RetrievalChallenge => 1u8,
            ConfidentialProofKind::ZkStorageProof => 2u8,
            ConfidentialProofKind::TeeAttested => 3u8,
            ConfidentialProofKind::HybridZkTee => 4u8,
        }];
        hash_fields_bytes(&[
            b"BDLM_CONFIDENTIAL_BODY_V1",
            &self.content_id.0,
            &enc,
            &self.ciphertext_root,
            &kind,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ContentCipher;
    use crate::storage::ContentEncryption;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn cid(b: u8) -> ContentId {
        ContentId([b; 32])
    }

    /// Every field of a view claim moves the digest.
    ///
    /// The claim is what stops a caller from naming somebody else as the
    /// viewer; if any field failed to enter, a signature made for one object,
    /// key, owner, payload or moment could be replayed under another.
    #[test]
    fn view_claim_digest_binds_every_field() {
        let base = view_claim_digest(&cid(1), &addr(2), &[3u8; 32], &addr(4), &[5u8; 32], 6);
        let variants = [
            view_claim_digest(&cid(9), &addr(2), &[3u8; 32], &addr(4), &[5u8; 32], 6),
            view_claim_digest(&cid(1), &addr(9), &[3u8; 32], &addr(4), &[5u8; 32], 6),
            view_claim_digest(&cid(1), &addr(2), &[9u8; 32], &addr(4), &[5u8; 32], 6),
            view_claim_digest(&cid(1), &addr(2), &[3u8; 32], &addr(9), &[5u8; 32], 6),
            view_claim_digest(&cid(1), &addr(2), &[3u8; 32], &addr(4), &[9u8; 32], 6),
            view_claim_digest(&cid(1), &addr(2), &[3u8; 32], &addr(4), &[5u8; 32], 7),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(
                &base, v,
                "field {i} of the view claim did not enter the digest"
            );
        }
        assert_ne!(
            base,
            grant_issue_digest(
                &cid(1),
                &addr(2),
                None,
                &[3u8; 32],
                ViewPolicy::PublicKeyId,
                6
            ),
            "a view claim must not collide with a grant issue over the same fields"
        );
    }

    /// The claim's lifetime matches the session it opens.
    #[test]
    fn view_claim_max_age_matches_the_reveal_session_ttl() {
        assert_eq!(
            VIEW_CLAIM_MAX_AGE_SECS,
            crate::storage::REVEAL_SESSION_TTL_SECS,
            "a claim older than the session it could open is a captured credential"
        );
    }

    #[test]
    fn named_grant_issues_and_authorizes_only_grantee() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let bob = addr(2);
        let eve = addr(3);
        let content = cid(9);
        let key = [7u8; 32];
        let id = reg
            .issue(content, owner, Some(bob), key, ViewPolicy::NamedGrantee, 10)
            .unwrap();
        assert!(reg.may_view(&content, &bob, &key, &owner));
        assert!(reg.may_view(&content, &owner, &key, &owner));
        assert!(!reg.may_view(&content, &eve, &key, &owner));
        reg.revoke(id, owner, 20).unwrap();
        assert!(
            !reg.may_view(&content, &bob, &key, &owner),
            "revoke ends new opens for the grantee"
        );
        assert!(
            reg.may_view(&content, &owner, &key, &owner),
            "owner root remains"
        );
    }

    #[test]
    fn public_key_grant_allows_any_viewer_with_key_handle() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let content = cid(9);
        let key = [8u8; 32];
        reg.issue(content, owner, None, key, ViewPolicy::PublicKeyId, 1)
            .unwrap();
        assert!(reg.may_view(&content, &addr(99), &key, &owner));
        assert!(!reg.may_view(&content, &addr(99), &[0u8; 32], &owner));
    }

    /// A grant minted by somebody else opens nothing.
    ///
    /// The `issuer` field is not a claim the book waves through: without this
    /// rule any caller could hand out public view access to content it does not
    /// own, and the access model would be decoration.
    #[test]
    fn a_grant_from_a_stranger_opens_nothing() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let stranger = addr(7);
        let bob = addr(2);
        let content = cid(9);
        let key = [6u8; 32];
        reg.issue(content, stranger, None, key, ViewPolicy::PublicKeyId, 1)
            .expect("the book records rows by shape");
        assert!(
            !reg.may_view(&content, &bob, &key, &owner),
            "a row issued by a stranger must not open the owner's content"
        );
        // The same row does open when the query names the stranger as owner: the
        // rule binds a grant to an owner, it is `StorageRegistry` that decides
        // which owner is real.
        assert!(reg.may_view(&content, &bob, &key, &stranger));
    }

    #[test]
    fn revoke_is_issuer_only_and_once() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let id = reg
            .issue(
                cid(1),
                owner,
                Some(addr(2)),
                [1u8; 32],
                ViewPolicy::NamedGrantee,
                0,
            )
            .unwrap();
        assert_eq!(reg.revoke(id, addr(2), 5), Err(ViewGrantError::NotIssuer));
        reg.revoke(id, owner, 5).unwrap();
        assert_eq!(
            reg.revoke(id, owner, 6),
            Err(ViewGrantError::AlreadyRevoked(id))
        );
    }

    #[test]
    fn confidential_commit_refuses_plaintext() {
        let err = ConfidentialBodyCommit::new(
            cid(1),
            ContentEncryption::Plaintext,
            [2u8; 32],
            ConfidentialProofKind::ZkStorageProof,
        )
        .unwrap_err();
        assert!(err.contains("ClientSide"));
    }

    #[test]
    fn confidential_commit_accepts_client_side_and_binds_fields() {
        let c = ConfidentialBodyCommit::new(
            cid(1),
            ContentEncryption::ClientSide(ContentCipher::XChaCha20Poly1305),
            [3u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        let again = ConfidentialBodyCommit::new(
            cid(1),
            ContentEncryption::ClientSide(ContentCipher::XChaCha20Poly1305),
            [3u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        assert_eq!(c.commitment(), again.commitment());
        let other = ConfidentialBodyCommit::new(
            cid(1),
            ContentEncryption::ClientSide(ContentCipher::Aes256Gcm),
            [3u8; 32],
            ConfidentialProofKind::HybridZkTee,
        )
        .unwrap();
        assert_ne!(c.commitment(), other.commitment());
    }

    #[test]
    fn grant_commitment_moves_on_revoke() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let id = reg
            .issue(
                cid(4),
                owner,
                Some(addr(5)),
                [9u8; 32],
                ViewPolicy::NamedGrantee,
                1,
            )
            .unwrap();
        let before = reg.get(id).unwrap().commitment();
        let root_before = reg.root();
        reg.revoke(id, owner, 9).unwrap();
        let after = reg.get(id).unwrap().commitment();
        assert_ne!(before, after);
        assert_ne!(root_before, reg.root());
    }

    #[test]
    fn revoke_with_hook_emits_social_event() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let grantee = addr(5);
        let id = reg
            .issue(
                cid(4),
                owner,
                Some(grantee),
                [9u8; 32],
                ViewPolicy::NamedGrantee,
                1,
            )
            .unwrap();
        let mut hook = crate::storage::three_hooks::RecordingThreeHook::default();

        reg.revoke_with_hook(id, owner, 9, &mut hook).unwrap();

        assert_eq!(hook.events.len(), 1);
        let ev = &hook.events[0];
        assert_eq!(
            ev.kind,
            crate::storage::three_hooks::ThreeHookKind::GrantRevoked
        );
        assert_eq!(ev.content_id, cid(4));
        assert_eq!(ev.actor, owner);
        assert_eq!(ev.epoch, 9);
        assert_eq!(ev.grant_id, Some(id));
    }

    #[test]
    fn revoke_with_hook_no_event_when_revoke_refused() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let id = reg
            .issue(
                cid(4),
                owner,
                Some(addr(5)),
                [9u8; 32],
                ViewPolicy::NamedGrantee,
                1,
            )
            .unwrap();
        let mut hook = crate::storage::three_hooks::RecordingThreeHook::default();

        // A wrong revoker refusals and emits nothing.
        assert!(reg.revoke_with_hook(id, addr(9), 3, &mut hook).is_err());
        assert!(hook.events.is_empty());
    }

    #[test]
    fn r2_r3_body_is_classic_not_three_in_docs() {
        let doc = include_str!("view_grant.rs");
        // A claim pinned to the whole file is not a claim: the assertion below
        // writes the same string it looks for, so it stays green after the
        // module doc is deleted. Bound the search to the module-doc block and
        // assemble the needle so its text lives in exactly one place.
        let doc_block = doc.split("\n\n").next().unwrap_or(doc);
        let needle = format!("{} in the cost tables", "R2/R3");
        let second = "If it has a body".to_string() + ", it is 2.0 (Classic)";
        assert!(doc_block.contains(&needle));
        assert!(doc_block.contains(second.as_str()));
    }
}
