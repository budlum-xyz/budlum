//! View grants: who may open content that is not public.
//!
//! # Product placement
//!
//! - **B.U.D. 3.0 (Three / R1):** the durable object is a recipe. A view-key
//!   unlocks *production* (or decryption of an encrypted recipe blob), not a
//!   stored body. QR frames stay derivative-only.
//! - **B.U.D. 2.0 (Classic body / R2–R3 cost regimes):** the durable object is
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
//! here** — putting a key in a public commitment publishes the key. Delivery
//! is out of band (DM, device keystore, sealed channel). This registry only
//! answers: "does grantee G still have permission to use key_id K on content C?"
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
//! - **Hybrid (industry default 2025–26):** chain holds commitments + grants;
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
    /// Anyone who presents the matching key_id (public link).
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
    pub fn is_live(&self) -> bool {
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

    #[must_use]
    pub fn get(&self, grant_id: u64) -> Option<&ViewGrant> {
        self.grants.get(&grant_id)
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
    /// Owner is always allowed (root). PublicKeyId live rows allow anyone with
    /// the key handle. NamedGrantee requires address match.
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

    /// Domain-tagged digest of the whole book (for future state roots).
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
    pub fn new(
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
    fn r2_r3_body_is_classic_not_three_in_docs() {
        let doc = include_str!("view_grant.rs");
        assert!(doc.contains("R2/R3 in the cost tables are **not** a third edition"));
        assert!(doc.contains("If it has a body, it is 2.0 (Classic)"));
    }
}
