//! B.U.D. 3.0 content binding and `bud3::view` resolution for BNS (Section 5.6, WP-23).
//!
//! exposed for: BNS RPC handlers, `bud` CLI, and explorer resolution.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::registry::BnsRegistry;
use super::types::BnsError;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::{ContentId, ContentIdKind, ContentKey};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey};
use crate::storage::bud3::view::{
    view_from_network, PaidViewReceipt, SymbolSource, ViewBud3Error,
};

/// Domain tag committing a BNS B.U.D. 3.0 content binding.
pub const DOMAIN_BNS_BINDING: &[u8] = b"BDLM_BUD3_BNS_BINDING_V1";

/// Errors returned by BNS B.U.D. 3.0 content binding and resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsBud3Error {
    Bns(BnsError),
    UnknownObject,
    ContentIdMismatch,
    SealedRequiresNftGrant,
    InvalidContentRef(ContentRefError),
    NoContentBound,
    View(ViewBud3Error),
}

impl std::fmt::Display for BnsBud3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bns(e) => write!(f, "bns error: {e}"),
            Self::UnknownObject => f.write_str("unknown B.U.D. 3.0 object commitment"),
            Self::ContentIdMismatch => {
                f.write_str("BNS ContentRef mismatches registered object ContentId")
            }
            Self::SealedRequiresNftGrant => {
                f.write_str("sealed BNS target requires an NFT binding and grant")
            }
            Self::InvalidContentRef(e) => write!(f, "invalid BNS ContentRef: {e:?}"),
            Self::NoContentBound => f.write_str("no B.U.D. 3.0 content bound to BNS name"),
            Self::View(e) => write!(f, "bud3 view error: {e:?}"),
        }
    }
}

impl std::error::Error for BnsBud3Error {}

/// Canonical B.U.D. 3.0 content record attached to a `.bud` BNS name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3NameBinding {
    pub name: String,
    pub owner: Address,
    pub content_ref: ContentRef,
    pub updated_at_epoch: u64,
}

impl Bud3NameBinding {
    /// Deterministic commitment digest over this BNS binding.
    ///
    /// exposed for: BNS receipt signing and state commitment checks (`WP-23`).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let kind_byte = match self.content_ref.content_id.kind {
            ContentIdKind::Public => [0u8],
            ContentIdKind::Sealed => [1u8],
        };
        let nft_flag = match self.content_ref.nft_id {
            Some(_) => [1u8],
            None => [0u8],
        };
        let nft_bytes = self.content_ref.nft_id.unwrap_or([0u8; 32]);
        hash_fields_bytes(&[
            DOMAIN_BNS_BINDING,
            self.name.as_bytes(),
            self.owner.as_bytes(),
            &kind_byte,
            &self.content_ref.content_id.digest,
            &self.content_ref.content_id.len.to_le_bytes(),
            &self.content_ref.object_commitment,
            &nft_flag,
            &nft_bytes,
            &self.updated_at_epoch.to_le_bytes(),
        ])
    }
}

/// Optional view credentials supplied when resolving a `.bud` name.
#[derive(Debug, Clone, Default)]
pub struct BnsViewAccess {
    pub content_key: Option<ContentKey>,
    pub grant_tag: Option<[u8; 32]>,
    pub paid_receipt: Option<PaidViewReceipt>,
}

/// BNS B.U.D. 3.0 binding table and `bud3::view` content resolver.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bud3BnsResolver {
    bindings: BTreeMap<String, Bud3NameBinding>,
}

impl Bud3BnsResolver {
    /// Create an empty BNS B.U.D. 3.0 resolver.
    ///
    /// exposed for: BNS state initialization (`WP-23`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `name` to a B.U.D. 3.0 [`ContentRef`].
    ///
    /// exposed for: BNS content-binding transactions (`WP-23`).
    pub fn set_bud3_content(
        &mut self,
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        owner_claim: (&str, &Address),
        target: (ContentId, ObjectKey, Option<NftId>),
        current_epoch: u64,
    ) -> Result<Bud3NameBinding, BnsBud3Error> {
        let (name, caller) = owner_claim;
        let canonical = name.trim().to_ascii_lowercase();
        let owner = bns
            .resolve(&canonical, current_epoch)
            .ok_or(BnsBud3Error::Bns(BnsError::InvalidName))?;
        if &owner != caller {
            return Err(BnsBud3Error::Bns(BnsError::NotOwner));
        }

        let (content_id, object_commitment, nft_id) = target;
        let obj = bud3
            .object(&object_commitment)
            .ok_or(BnsBud3Error::UnknownObject)?;
        if obj.record.content_id != content_id {
            return Err(BnsBud3Error::ContentIdMismatch);
        }
        if content_id.kind == ContentIdKind::Sealed && nft_id.is_none() {
            return Err(BnsBud3Error::SealedRequiresNftGrant);
        }

        let content_ref = ContentRef::new(content_id, object_commitment, nft_id)
            .map_err(BnsBud3Error::InvalidContentRef)?;
        let binding = Bud3NameBinding {
            name: canonical.clone(),
            owner,
            content_ref,
            updated_at_epoch: current_epoch,
        };
        self.bindings.insert(canonical, binding.clone());
        Ok(binding)
    }

    /// Look up the bound [`Bud3NameBinding`] for `name` if still active in `bns`.
    ///
    /// exposed for: BNS RPC and explorer queries (`WP-23`).
    #[must_use]
    pub fn binding(&self, bns: &BnsRegistry, name: &str, epoch: u64) -> Option<&Bud3NameBinding> {
        let canonical = name.trim().to_ascii_lowercase();
        let live_owner = bns.resolve(&canonical, epoch)?;
        let b = self.bindings.get(&canonical)?;
        if b.owner != live_owner {
            return None;
        }
        Some(b)
    }

    /// Resolve `.bud` content directly through `bud3::view` (`WP-23` item 1).
    ///
    /// exposed for: BNS `bud3::view` content resolution (`WP-23`).
    pub fn resolve_via_bud3_view(
        &self,
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        name: &str,
        source: &dyn SymbolSource,
        access: &BnsViewAccess,
        current_epoch: u64,
    ) -> Result<Vec<u8>, BnsBud3Error> {
        let b = self
            .binding(bns, name, current_epoch)
            .ok_or(BnsBud3Error::NoContentBound)?;
        view_from_network(
            bud3,
            &b.content_ref.object_commitment,
            source,
            current_epoch,
            access.grant_tag.as_ref(),
            access.content_key.as_ref(),
            access.paid_receipt.as_ref(),
        )
        .map_err(BnsBud3Error::View)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};
    use crate::storage::bud3::view::InMemorySymbolSource;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn bns_resolves_bud3_content() {
        let alice = Address([0x11; 32]);
        let intruder = Address([0x22; 32]);
        let mut bns = BnsRegistry::new();
        bns.register("portal.bud", alice, 1, 100).expect("register");

        let mut bud3 = Bud3Registry::default();
        let body = b"welcome to portal.bud on B.U.D. 3.0!".repeat(8);
        let up = prepare_public_upload(&body, &P, &Bud3Limits::default(), 8).expect("upload");
        let cid = up.record.content_id;
        let obj_key = up.record.commitment;
        bud3.register_object(
            alice.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: [7u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            50,
        )
        .expect("register object");

        let mut net = InMemorySymbolSource::new();
        net.insert_segment(obj_key, 0, up.segments[0].clone());

        let mut resolver = Bud3BnsResolver::new();
        assert!(resolver
            .set_bud3_content(&bns, &bud3, ("portal.bud", &intruder), (cid, obj_key, None), 2)
            .is_err());

        let binding = resolver
            .set_bud3_content(&bns, &bud3, ("portal.bud", &alice), (cid, obj_key, None), 2)
            .expect("bind");
        assert_eq!(binding.content_ref.content_id, cid);

        let resolved = resolver
            .resolve_via_bud3_view(&bns, &bud3, "portal.bud", &net, &BnsViewAccess::default(), 3)
            .expect("resolve via bud3::view");
        assert_eq!(resolved, body);
    }
}
