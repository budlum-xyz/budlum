//! B.U.D. 3.0 content binding and view resolution for BNS (Section 5.6, WP-23).
//! exposed for BNS RPC handlers, `Bud3ContentGateway`, and dApp resolution.
//!
//! Each BNS name binding carries a B.U.D. 3.0 [`ContentRef`] (`ContentId`) and
//! an optional [`NftId`], resolving content strictly through `bud3::view` /
//! [`Bud3ContentGateway`] rather than any 2.0 manifest lookup.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::registry::BnsRegistry;
use super::types::BnsError;
use crate::core::address::Address;
use crate::storage::bud3::content_gateway::{Bud3ContentGateway, GatewayError, GatewayResponse};
use crate::storage::bud3::content_ref::ContentRef;
use crate::storage::bud3::registry::{Bud3Registry, NftId, ObjectKey};
use crate::storage::bud3::ContentId;

/// Domain tag committing a BNS B.U.D. 3.0 content binding.
pub const DOMAIN_BNS_BINDING: &[u8] = b"BDLM_BUD3_BNS_BINDING_V1";

/// Errors returned by BNS B.U.D. 3.0 content binding and resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsBud3Error {
    /// Underlying BNS registry error (expired, unregistered, or unauthorized).
    Bns(BnsError),
    /// Referenced `ObjectKey` does not exist in [`Bud3Registry`].
    UnknownObject,
    /// Supplied `ContentRef` does not match the registered object's `ContentId`.
    ContentIdMismatch,
    /// Sealed object resolution requires an `NftId` and matching grant tag.
    SealedRequiresNftGrant,
    /// No B.U.D. 3.0 content binding is set for this BNS name.
    NoContentBound,
    /// Gateway / `bud3::view` resolution failed.
    Gateway(GatewayError),
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
            Self::NoContentBound => f.write_str("no B.U.D. 3.0 content bound to BNS name"),
            Self::Gateway(e) => write!(f, "bud3 gateway error: {e}"),
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
    pub object_commitment: ObjectKey,
    pub nft_id: Option<NftId>,
    pub updated_at_epoch: u64,
}

impl Bud3NameBinding {
    /// Deterministic commitment digest over this BNS binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN_BNS_BINDING);
        h.update((self.name.len() as u64).to_le_bytes());
        h.update(self.name.as_bytes());
        h.update(self.owner.as_bytes());
        h.update(self.content_ref.content_id.0);
        h.update(self.object_commitment);
        match self.nft_id {
            Some(nft) => {
                h.update([1u8]);
                h.update(nft);
            }
            None => h.update([0u8]),
        }
        h.update(self.updated_at_epoch.to_le_bytes());
        h.finalize().into()
    }
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

    /// Bind `name` to a B.U.D. 3.0 [`ContentId`] and optional [`NftId`].
    /// exposed for BNS RPC handlers and name-binding transactions.
    ///
    /// Verifies that `caller` owns the active `name` in `bns`, and that
    /// `object_commitment` exists in `bud3` with the exact `content_id`.
    ///
    /// # Errors
    ///
    /// Returns [`BnsBud3Error`] if ownership, expiry, or object binding fails.
    pub fn set_bud3_content(
        &mut self,
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        name: &str,
        caller: &Address,
        content_id: ContentId,
        object_commitment: ObjectKey,
        nft_id: Option<NftId>,
        current_epoch: u64,
    ) -> Result<Bud3NameBinding, BnsBud3Error> {
        let record = bns
            .resolve(name, current_epoch)
            .ok_or(BnsBud3Error::Bns(BnsError::NotFound))?;
        if &record.owner != caller {
            return Err(BnsBud3Error::Bns(BnsError::NotOwner));
        }
        let obj = bud3
            .object(&object_commitment)
            .ok_or(BnsBud3Error::UnknownObject)?;
        if obj.record.content_id != content_id {
            return Err(BnsBud3Error::ContentIdMismatch);
        }
        if obj.record.visibility == crate::storage::bud3::visibility::Visibility::Sealed
            && nft_id.is_none()
        {
            return Err(BnsBud3Error::SealedRequiresNftGrant);
        }

        let canonical = name.trim().to_ascii_lowercase();
        let binding = Bud3NameBinding {
            name: canonical.clone(),
            owner: *caller,
            content_ref: ContentRef::new(content_id),
            object_commitment,
            nft_id,
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
    /// * When the viewer holds an NFT or unlinkable grant (`grant_tag`), serves
    ///   via the network-backed reveal session path (`get_object`).
    /// * When the viewer holds no NFT on a public object and supplies
    ///   `paid_fallback_bud`, runs the paid G8 fallback decode (`BLG-212`).
    ///
    /// # Errors
    ///
    /// Returns [`BnsBud3Error`] if the name is unbound/expired or view fails.
    pub fn resolve_via_bud3_view(
        &self,
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        gateway: &mut Bud3ContentGateway,
        name: &str,
        current_epoch: u64,
        current_height: u64,
        grant_tag: Option<[u8; 32]>,
        paid_fallback_bud: Option<u64>,
    ) -> Result<GatewayResponse, BnsBud3Error> {
        let _active = bns
            .resolve(name, current_epoch)
            .ok_or(BnsBud3Error::Bns(BnsError::NotFound))?;
        let binding = self.binding(name).ok_or(BnsBud3Error::NoContentBound)?;

        if binding.nft_id.is_some() || grant_tag.is_some() {
            return gateway
                .get_object(
                    bud3,
                    &binding.object_commitment,
                    binding.nft_id,
                    grant_tag,
                    current_height,
                )
                .map_err(BnsBud3Error::Gateway);
        }

        if let Some(paid) = paid_fallback_bud {
            return gateway
                .get_public_paid(bud3, &binding.object_commitment, paid)
                .map_err(BnsBud3Error::Gateway);
        }

        gateway
            .get_object(bud3, &binding.object_commitment, None, None, current_height)
            .map_err(BnsBud3Error::Gateway)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 1024,
        fps: 10,
        k_max: 64,
    };

    #[test]
    fn bns_resolves_bud3_content() {
        let alice = Address::from([0x11; 32]);
        let mut bns = BnsRegistry::new(1_000);
        bns.register("budlum.bud", alice, 10, 1, 10_000).unwrap();

        let mut bud3 = Bud3Registry::new();
        let mut gateway = Bud3ContentGateway::new();
        let html = b"<html><body>BNS on B.U.D. 3.0</body></html>".repeat(40);
        let up = prepare_public_upload(&html, &P, &Bud3Limits::default()).unwrap();
        let key = up.record.commitment;
        let cid = up.record.content_id;
        let nft_id = [0x44; 32];

        bud3.register_object(
            up.record.clone(),
            vec![(
                0,
                Share {
                    validator: [1u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbol_count: up.record.symbols_per_segment,
                },
            )],
            1,
            20,
            10_000,
        )
        .unwrap();
        bud3.bind_nft(nft_id, key).unwrap();
        gateway.stage_object(&up.record, &up.object_bytes).unwrap();

        let mut resolver = Bud3BnsResolver::new();
        let binding = resolver
            .set_bud3_content(&bns, &bud3, "budlum.bud", &alice, cid, key, Some(nft_id), 2)
            .unwrap();
        assert_eq!(binding.content_ref.content_id, cid);
        assert_ne!(binding.digest(), [0u8; 32]);

        let resp = resolver
            .resolve_via_bud3_view(&bns, &bud3, &mut gateway, "budlum.bud", 2, 10, None, None)
            .unwrap();
        assert_eq!(resp.body, html);
        assert_eq!(resp.content_id, cid);
    }
}
