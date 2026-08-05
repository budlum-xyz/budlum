//! The bridge between a Pollen data asset and the bytes behind it.
//!
//! Pollen governs *permission*: a `DataAsset` is registered, an `AccessGrant`
//! is issued against a payment, and `validate_ai_read_ref` refuses an AI
//! request whose grant is missing, expired, exhausted or held by someone
//! else. B.U.D. governs *bytes*: a `ContentManifest` names shards, operators
//! hold them, and a reader assembles `k` of them into the object.
//!
//! Those two were complete on their own and had no connection, which is the
//! hole this module closes. Measured: nothing in `src/storage/` mentions
//! Pollen, and nothing in `src/pollen/` mentions a manifest. So the same
//! bytes could be sold through Pollen and simultaneously be fetched from
//! B.U.D. by anyone who knew the `manifest_id`, and the second path asked no
//! questions. Paying was optional in the only sense that matters.
//!
//! # What this adds
//!
//! One registry, `ProtectedContent`, mapping `manifest_id -> asset_id`. Once
//! a manifest is bound to an asset:
//!
//! * reading it requires a live grant, checked through Pollen's own
//!   `validate_ai_read_ref` rules rather than a second copy of them;
//! * it can never be declared public, so the deduplication path cannot see
//!   it. That matters more than it looks: deduplication keys on content, so
//!   an attacker who can guess an asset's contents could confirm its
//!   existence, or brute-force a missing field, without ever buying it.
//!   Those are the confirmation-of-a-file and learn-the-remaining-information
//!   attacks, and paid content is exactly the target they are written for.
//!
//! # Why the binding is one-way
//!
//! A manifest can be bound to an asset. It can never be unbound. Unbinding
//! would let an owner take payment, then release the bytes into the public
//! path where they are free and deduplicated, which is the same as not
//! having sold anything. Content that should stop being protected is
//! withdrawn by revoking the `DataAsset`, which stops new grants and leaves
//! the binding intact.
//!
//! # What this deliberately does not do
//!
//! It does not encrypt anything and does not hold keys. An operator holding
//! a shard still holds those bytes; what changes is whether the chain will
//! *authorise* a read and let an AI request consume it. Byte-level secrecy
//! is the client-side encryption layer's job, and the two compose: encrypted
//! content plus a grant means the operator holds ciphertext and the chain
//! decides who may ask for it.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::pollen::AssetId;
use crate::storage::content_id::ContentId;
use std::collections::BTreeMap;

/// Why a read of protected content was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentGateError {
    /// The manifest is bound to an asset and the caller presented no grant.
    ///
    /// Separate from an invalid grant so a caller can tell "you need to buy
    /// this" from "what you bought does not apply".
    GrantRequired {
        manifest_id: ContentId,
        asset_id: AssetId,
    },
    /// A grant was presented but it is for a different asset.
    ///
    /// The attack this closes: buy the cheapest asset in the marketplace,
    /// then present its grant when reading an expensive one.
    GrantForDifferentAsset {
        presented: AssetId,
        required: AssetId,
    },
    /// The manifest is already bound to a different asset.
    ///
    /// Rebinding would let a second owner claim bytes a first owner is
    /// already selling.
    AlreadyBound {
        manifest_id: ContentId,
        bound_to: AssetId,
    },
    /// Someone tried to declare protected content public.
    ///
    /// Refused because the public class is the one deduplication reads, and
    /// deduplicating paid content lets it be confirmed, or partially
    /// recovered, without payment.
    ProtectedCannotBePublic {
        manifest_id: ContentId,
        asset_id: AssetId,
    },
    /// A binding was attempted by an address that does not own the asset.
    NotTheAssetOwner {
        expected: Address,
        provided: Address,
    },
}

impl std::fmt::Display for ContentGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentGateError::GrantRequired {
                manifest_id,
                asset_id,
            } => write!(
                f,
                "content {manifest_id} is sold as Pollen asset {} and needs a live access grant",
                hex::encode(asset_id.0)
            ),
            ContentGateError::GrantForDifferentAsset {
                presented,
                required,
            } => write!(
                f,
                "grant covers asset {} but the content belongs to {}",
                hex::encode(presented.0),
                hex::encode(required.0)
            ),
            ContentGateError::AlreadyBound {
                manifest_id,
                bound_to,
            } => write!(
                f,
                "content {manifest_id} is already sold as asset {}",
                hex::encode(bound_to.0)
            ),
            ContentGateError::ProtectedCannotBePublic {
                manifest_id,
                asset_id,
            } => write!(
                f,
                "content {manifest_id} is sold as asset {} and cannot be declared public; \
                 the public class is deduplicated, which would let the content be \
                 confirmed without payment",
                hex::encode(asset_id.0)
            ),
            ContentGateError::NotTheAssetOwner { expected, provided } => write!(
                f,
                "asset is owned by {expected} but the binding was signed by {provided}"
            ),
        }
    }
}

impl std::error::Error for ContentGateError {}

/// Which stored objects are sold through Pollen.
///
/// Deliberately a plain map rather than a field on `ContentManifest`. A
/// manifest is content-addressed: its id is the hash of its own contents, so
/// two uploaders sharding the same bytes get one id. Whether those bytes are
/// *for sale* is not a property of the bytes, it is a property of an
/// agreement, and folding it into the id would give the same content two
/// identities depending on whether someone had listed it.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProtectedContent {
    /// `manifest_id -> asset_id`. Append-only by construction: there is no
    /// removal method, for the reason in the module doc.
    bindings: BTreeMap<ContentId, AssetId>,
}

impl ProtectedContent {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind stored content to a Pollen asset.
    ///
    /// `asset_owner` is the owner recorded on the `DataAsset`, and
    /// `caller` is whoever signed the binding; they have to match, or one
    /// account could put another account's content behind its own paywall.
    ///
    /// # Errors
    ///
    /// [`ContentGateError::NotTheAssetOwner`] when the caller does not own
    /// the asset, and [`ContentGateError::AlreadyBound`] when the content is
    /// already sold under a different asset. Rebinding to the *same* asset is
    /// accepted and does nothing, so a retried transaction is not an error.
    pub fn bind(
        &mut self,
        manifest_id: ContentId,
        asset_id: AssetId,
        asset_owner: Address,
        caller: Address,
    ) -> Result<(), ContentGateError> {
        if asset_owner != caller {
            return Err(ContentGateError::NotTheAssetOwner {
                expected: asset_owner,
                provided: caller,
            });
        }
        match self.bindings.get(&manifest_id) {
            Some(existing) if *existing == asset_id => Ok(()),
            Some(existing) => Err(ContentGateError::AlreadyBound {
                manifest_id,
                bound_to: *existing,
            }),
            None => {
                self.bindings.insert(manifest_id, asset_id);
                Ok(())
            }
        }
    }

    /// Which asset sells this content, if any.
    #[must_use]
    pub fn asset_for(&self, manifest_id: &ContentId) -> Option<AssetId> {
        self.bindings.get(manifest_id).copied()
    }

    /// Whether this content is sold through Pollen.
    #[must_use]
    pub fn is_protected(&self, manifest_id: &ContentId) -> bool {
        self.bindings.contains_key(manifest_id)
    }

    /// How many objects are behind a paywall. Used by the state root and by
    /// operators reporting what they hold.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Decide whether a read may proceed.
    ///
    /// `grant_asset` is the asset covered by whatever grant the caller
    /// presented, already validated by Pollen. Passing `None` means no grant
    /// was presented at all.
    ///
    /// Unprotected content returns `Ok(())` with no grant, because content
    /// nobody listed for sale is content nobody restricted. That is the
    /// common case and it stays free.
    ///
    /// # Errors
    ///
    /// [`ContentGateError::GrantRequired`] when protected content is read
    /// with no grant, and [`ContentGateError::GrantForDifferentAsset`] when
    /// the grant covers something else.
    pub fn authorize_read(
        &self,
        manifest_id: &ContentId,
        grant_asset: Option<AssetId>,
    ) -> Result<(), ContentGateError> {
        let Some(required) = self.asset_for(manifest_id) else {
            return Ok(());
        };
        match grant_asset {
            None => Err(ContentGateError::GrantRequired {
                manifest_id: *manifest_id,
                asset_id: required,
            }),
            Some(presented) if presented != required => {
                Err(ContentGateError::GrantForDifferentAsset {
                    presented,
                    required,
                })
            }
            Some(_) => Ok(()),
        }
    }

    /// Refuse to let protected content enter the public, deduplicated class.
    ///
    /// Called on the declaration path rather than the read path, because the
    /// damage from deduplicating paid content happens at registration: once
    /// the id is a hash of plaintext that anyone can recompute, the leak is
    /// already available and revoking the listing does not take it back.
    ///
    /// # Errors
    ///
    /// [`ContentGateError::ProtectedCannotBePublic`] when the content is
    /// bound to an asset.
    pub fn check_may_be_public(&self, manifest_id: &ContentId) -> Result<(), ContentGateError> {
        match self.asset_for(manifest_id) {
            None => Ok(()),
            Some(asset_id) => Err(ContentGateError::ProtectedCannotBePublic {
                manifest_id: *manifest_id,
                asset_id,
            }),
        }
    }

    /// Domain-tagged digest for the state root.
    ///
    /// Ordered by construction: `BTreeMap` iterates by key, so every node
    /// hashes the same bytes. An unordered map here would give two honest
    /// nodes two different roots.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(8 + self.bindings.len() * 64);
        buf.extend_from_slice(&(self.bindings.len() as u64).to_le_bytes());
        for (manifest, asset) in &self.bindings {
            buf.extend_from_slice(&manifest.0);
            buf.extend_from_slice(&asset.0);
        }
        hash_fields_bytes(&[b"BDLM_POLLEN_PROTECTED_CONTENT_V1", &buf])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(b: u8) -> ContentId {
        ContentId([b; 32])
    }
    fn aid(b: u8) -> AssetId {
        AssetId([b; 32])
    }
    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    #[test]
    fn unlisted_content_reads_without_a_grant() {
        // The canary for the whole module. Most content is not for sale, and
        // a gate that demanded a grant for everything would be a gate that
        // passes its own tests by refusing the network.
        let gate = ProtectedContent::new();
        assert!(gate.authorize_read(&mid(1), None).is_ok());
        assert!(!gate.is_protected(&mid(1)));
    }

    #[test]
    fn listed_content_refuses_a_read_with_no_grant() {
        // The finding, stated as a test: before this, knowing the manifest id
        // was enough to fetch bytes someone was selling.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();

        let err = gate
            .authorize_read(&mid(1), None)
            .expect_err("sold content needs a grant");
        match err {
            ContentGateError::GrantRequired { asset_id, .. } => assert_eq!(asset_id, aid(9)),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_grant_for_the_right_asset_opens_the_read() {
        // The second canary: paying has to actually work, or the gate is
        // just an outage.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();
        assert!(gate.authorize_read(&mid(1), Some(aid(9))).is_ok());
    }

    #[test]
    fn a_grant_for_a_different_asset_is_refused() {
        // Buy the cheapest listing, read the most expensive one. Closed by
        // comparing the asset the grant covers against the asset the content
        // belongs to.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();

        let err = gate
            .authorize_read(&mid(1), Some(aid(3)))
            .expect_err("a grant for another asset must not open this one");
        assert!(
            matches!(err, ContentGateError::GrantForDifferentAsset { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn protected_content_cannot_be_declared_public() {
        // The deduplication leak. The public class keys on content, so a
        // listed asset in that class could be confirmed, or partially
        // brute-forced, without buying it.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();

        let err = gate
            .check_may_be_public(&mid(1))
            .expect_err("sold content must stay out of the deduplicated class");
        assert!(
            matches!(err, ContentGateError::ProtectedCannotBePublic { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unlisted_content_may_be_public() {
        // Third canary. If this failed, the rule above would be blocking
        // deduplication for the entire network rather than for paid content.
        let gate = ProtectedContent::new();
        assert!(gate.check_may_be_public(&mid(1)).is_ok());
    }

    #[test]
    fn content_cannot_be_rebound_to_a_second_asset() {
        // Otherwise a second seller lists bytes the first seller is already
        // selling, and a grant from either would open it.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();

        let err = gate
            .bind(mid(1), aid(8), addr(6), addr(6))
            .expect_err("already sold under another asset");
        match err {
            ContentGateError::AlreadyBound { bound_to, .. } => assert_eq!(bound_to, aid(9)),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rebinding_to_the_same_asset_is_not_an_error() {
        // A retried or replayed transaction must not fail, or an owner sees
        // an error for a state that is already what they asked for.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();
        gate.bind(mid(1), aid(9), addr(5), addr(5))
            .expect("idempotent");
        assert_eq!(gate.len(), 1);
    }

    #[test]
    fn only_the_asset_owner_may_put_content_behind_its_paywall() {
        // Without this, any account could list someone else's content and
        // collect for reads of it.
        let mut gate = ProtectedContent::new();
        let err = gate
            .bind(mid(1), aid(9), addr(5), addr(7))
            .expect_err("caller does not own the asset");
        assert!(
            matches!(err, ContentGateError::NotTheAssetOwner { .. }),
            "got {err:?}"
        );
        assert!(
            !gate.is_protected(&mid(1)),
            "a refused bind must write nothing"
        );
    }

    #[test]
    fn a_refused_bind_leaves_no_trace() {
        // `bind` takes `&mut self`, so a matching error type only proves half
        // the property. The other half is that nothing was written.
        let mut gate = ProtectedContent::new();
        gate.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();
        let before = gate.root();

        let _ = gate.bind(mid(1), aid(8), addr(6), addr(6));
        assert_eq!(
            gate.root(),
            before,
            "a refused rebind must not change state"
        );
    }

    #[test]
    fn the_root_is_order_independent() {
        // Two nodes inserting the same bindings in different orders have to
        // reach the same root, or they accept different blocks.
        let mut a = ProtectedContent::new();
        let mut b = ProtectedContent::new();
        for i in [3u8, 1, 2] {
            a.bind(mid(i), aid(i), addr(1), addr(1)).unwrap();
        }
        for i in [1u8, 2, 3] {
            b.bind(mid(i), aid(i), addr(1), addr(1)).unwrap();
        }
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn the_root_changes_when_a_binding_is_added() {
        // The canary for the test above: a root that never changed would
        // also be order independent, and useless.
        let mut g = ProtectedContent::new();
        let empty = g.root();
        g.bind(mid(1), aid(9), addr(5), addr(5)).unwrap();
        assert_ne!(g.root(), empty);
    }
}
