//! B.U.D. 3.0 content binding and view resolution for BNS (Section 5.6, WP-23).
//! exposed for BNS RPC handlers, `Bud3ContentGateway`, and dApp resolution.
//!
//! Each BNS name binding carries a B.U.D. 3.0 [`ContentRef`] (`ContentId`,
//! `object_commitment`, optional `NftId`) and resolves content strictly through
//! `bud3::view` / [`Bud3ContentGateway`] rather than any 2.0 manifest lookup.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::registry::BnsRegistry;
use super::types::BnsError;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_gateway::{Bud3ContentGateway, ContentGatewayError};
use crate::storage::bud3::content_id::{ContentId, ContentIdKind, ContentKey};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey};
use crate::storage::bud3::view::{
    view_from_network, NetworkSymbolSource, PaidViewReceipt, ViewBud3Error,
};

/// Domain tag committing a BNS B.U.D. 3.0 content binding.
pub const DOMAIN_BNS_BINDING: &[u8] = b"BDLM_BUD3_BNS_BINDING_V1";

/// Errors returned by BNS B.U.D. 3.0 content binding and resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsBud3Error {
    /// Underlying BNS registry error (expired, unregistered, or unauthorized).
    Bns(BnsError),
    /// Referenced `ObjectKey` does not exist in [`Bud3Registry`].
    UnknownObject,
    /// Supplied `ContentId` does not match the registered object's `ContentId`.
    ContentIdMismatch,
    /// Sealed object resolution requires an `NftId` and matching grant/key.
    SealedRequiresNftGrant,
    /// `ContentRef` structural validation failed.
    InvalidContentRef(ContentRefError),
    /// No B.U.D. 3.0 content binding is set for this BNS name.
    NoContentBound,
    /// `Bud3ContentGateway` resolution failed.
    Gateway(ContentGatewayError),
    /// `bud3::view` network reconstruction failed.
    View(ViewBud3Error),
}

impl std::fmt::Display for BnsBud3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bns(e) => write!(f, "bns error: {e}"),
            Self::UnknownObject => f.write_str("unknown B.U.D. 3.0 object commitment"),
            Self::ContentIdMismatch => {
                f.write_str("BNS ContentRef does not match registered object ContentId")
            }
            Self::SealedRequiresNftGrant => {
                f.write_str("sealed BNS target requires an NFT binding and active view grant")
            }
            Self::InvalidContentRef(e) => write!(f, "invalid BNS ContentRef: {e:?}"),
            Self::NoContentBound => f.write_str("no B.U.D. 3.0 content bound to BNS name"),
            Self::Gateway(e) => write!(f, "bud3 gateway error: {e:?}"),
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
    /// exposed for BNS receipt signing and state commitment checks.
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
    /// Optional content key opened locally by an NFT owner or grant holder.
    pub content_key: Option<ContentKey>,
    /// Optional unlinkable grant tag checked against `Bud3Registry`.
    pub grant_tag: Option<[u8; 32]>,
    /// Optional paid G8 fallback receipt for public content when the viewer holds no NFT.
    pub paid_receipt: Option<PaidViewReceipt>,
}

/// BNS B.U.D. 3.0 binding table and `bud3::view` content resolver.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bud3BnsResolver {
    bindings: BTreeMap<String, Bud3NameBinding>,
}

impl Bud3BnsResolver {
    /// Create an empty BNS B.U.D. 3.0 resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `name` to a B.U.D. 3.0 [`ContentRef`] (`ContentId`, `ObjectKey`, optional `NftId`).
    /// exposed for BNS RPC handlers and name-binding transactions.
    ///
    /// Verifies that `caller` owns the active `name` in `bns`, and that
    /// `content_ref.object_commitment` exists in `bud3` with the exact `ContentId`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsBud3Error`] if ownership, expiry, or object binding fails.
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
            owner: *caller,
            content_ref,
            updated_at_epoch: current_epoch,
        };
        self.bindings.insert(canonical, binding.clone());
        Ok(binding)
    }

    /// Inspect the current B.U.D. 3.0 binding for `name`.
    #[must_use]
    pub fn binding(&self, name: &str) -> Option<&Bud3NameBinding> {
        self.bindings.get(&name.trim().to_ascii_lowercase())
    }

    /// Resolve a `.bud` BNS name through `bud3::view` / [`Bud3ContentGateway`].
    /// exposed for BNS content gateway and `.bud` browser resolution.
    ///
    /// * When `access.paid_receipt` is supplied, serves public content through
    ///   [`Bud3ContentGateway::serve_paid_public_fallback`].
    /// * Otherwise reconstructs and verifies content from network symbol holders
    ///   via [`view_from_network`], requiring an active `grant_row` when `grant_tag`
    ///   is specified.
    ///
    /// # Errors
    ///
    /// Returns [`BnsBud3Error`] if the name is unbound/expired or view fails.
    pub fn resolve_via_bud3_view<N: NetworkSymbolSource>(
        &self,
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        network: &N,
        name: &str,
        current_epoch: u64,
        access: &BnsViewAccess,
    ) -> Result<Vec<u8>, BnsBud3Error> {
        let canonical = name.trim().to_ascii_lowercase();
        let active_owner = bns
            .resolve(&canonical, current_epoch)
            .ok_or(BnsBud3Error::Bns(BnsError::Expired))?;
        let binding = self.binding(&canonical).ok_or(BnsBud3Error::NoContentBound)?;
        if binding.owner != active_owner {
            return Err(BnsBud3Error::Bns(BnsError::NotOwner));
        }

        if let Some(tag) = access.grant_tag {
            let row = bud3
                .grant_row(&tag)
                .ok_or(BnsBud3Error::SealedRequiresNftGrant)?;
            if row.expires_at_epoch <= current_epoch {
                return Err(BnsBud3Error::SealedRequiresNftGrant);
            }
        }

        if let Some(receipt) = &access.paid_receipt {
            return Bud3ContentGateway::serve_paid_public_fallback(
                bud3,
                &binding.content_ref,
                receipt,
                network,
            )
            .map_err(BnsBud3Error::Gateway);
        }

        let _bundle =
            Bud3ContentGateway::fetch_symbol_bundle(bud3, &binding.content_ref, network)
                .map_err(BnsBud3Error::Gateway)?;
        view_from_network(
            bud3,
            &binding.content_ref.object_commitment,
            access.content_key.as_ref(),
            network,
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
    use crate::storage::bud3::view::MemorySymbolNetwork;

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
        let mut bns = BnsRegistry::new();
        bns.register(String::from("budlum.bud"), alice, 1, 20)
            .unwrap();

        let mut bud3 = Bud3Registry::default();
        let html = b"<html><body>BNS on B.U.D. 3.0</body></html>".repeat(6);
        let up = prepare_public_upload(&html, &P, &Bud3Limits::default(), 8).unwrap();
        let key = up.record.commitment;
        let cid = up.record.content_id;
        let nft_id = [0x44; 32];
        let holder = [1u8; 32];

        let mut net = MemorySymbolNetwork::default();
        for (_, syms) in &up.segments {
            for sym in syms {
                net.insert(holder, key, sym.clone());
            }
        }

        bud3.register_object(
            alice.0,
            up.record,
            vec![(
                0,
                Share {
                    validator: holder,
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            20,
        )
        .unwrap();
        bud3.bind_nft(nft_id, alice.0, &key).unwrap();

        let mut resolver = Bud3BnsResolver::new();
        let binding = resolver
            .set_bud3_content(
                &bns,
                &bud3,
                ("budlum.bud", &alice),
                (cid, key, Some(nft_id)),
                2,
            )
            .unwrap();
        assert_eq!(binding.content_ref.content_id, cid);
        assert_ne!(binding.digest(), [0u8; 32]);

        let body = resolver
            .resolve_via_bud3_view(&bns, &bud3, &net, "budlum.bud", 2, &BnsViewAccess::default())
            .unwrap();
        assert_eq!(body, html);

        let new_owner = Address([0x33; 32]);
        bns.transfer("budlum.bud", &alice, new_owner, 3)
            .unwrap();
        assert!(matches!(
            resolver.resolve_via_bud3_view(
                &bns,
                &bud3,
                &net,
                "budlum.bud",
                3,
                &BnsViewAccess::default(),
            ),
            Err(BnsBud3Error::Bns(BnsError::NotOwner))
        ));
    }
}
