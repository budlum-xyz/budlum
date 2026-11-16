//! B.U.D. 3.0 content binding and view resolution for BNS (Section 5.6).
//! exposed for BNS RPC handlers, `Bud3ContentGateway`, and dApp resolution.
//!
//! Each BNS name binding carries a B.U.D. 3.0 [`ContentRef`] (`ContentId`,
//! `object_commitment`, optional `NftId`) and resolves content strictly through
//! `bud3::view` / [`Bud3ContentGateway`] rather than any 2.0 manifest lookup.

use serde::{Deserialize, Serialize};

use super::registry::BnsRegistry;
use super::types::BnsError;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_gateway::{Bud3ContentGateway, ContentGatewayError};
use crate::storage::bud3::content_id::{ContentIdKind, ContentKey};
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::registry::Bud3Registry;
use crate::storage::bud3::view::{
    view_from_network, NetworkSymbolSource, PaidViewReceipt, ViewBud3Error,
};

/// Domain tag committing a BNS B.U.D. 3.0 content binding.
pub const DOMAIN_BNS_BINDING: &[u8] = b"BDLM_BUD3_BNS_BINDING_V2";

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

/// The content of one `.bud` name, as the name registry root commits to it.
///
/// The record stores the [`ContentRef`]; the name and the owner come from
/// the same record. The digest binds the three together, so content cannot
/// be replayed under another name or survive a change of owner unnoticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3NameBinding {
    pub name: String,
    pub owner: Address,
    pub content_ref: ContentRef,
}

impl Bud3NameBinding {
    /// The commitment the name leaf carries (`BDLM_BUD3_BNS_BINDING_V2`).
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
        ])
    }
}

/// Check a content reference against the object registry before a record
/// may point at it.
///
/// # Errors
///
/// [`BnsBud3Error`] if the reference is malformed, names an object the chain
/// does not hold, carries another content id than the object, or is sealed
/// without an NFT.
pub fn checked_content_ref(
    bud3: &Bud3Registry,
    content_ref: ContentRef,
) -> Result<ContentRef, BnsBud3Error> {
    let checked = ContentRef::new(
        content_ref.content_id,
        content_ref.object_commitment,
        content_ref.nft_id,
    )
    .map_err(BnsBud3Error::InvalidContentRef)?;
    let obj = bud3
        .object(&checked.object_commitment)
        .ok_or(BnsBud3Error::UnknownObject)?;
    if obj.record.content_id != checked.content_id {
        return Err(BnsBud3Error::ContentIdMismatch);
    }
    match checked.nft_id {
        // An NFT the reference names has to be one bound to this object.
        Some(nft) if !obj.references.contains(&nft) => {
            return Err(BnsBud3Error::SealedRequiresNftGrant);
        }
        None if checked.content_id.kind == ContentIdKind::Sealed => {
            return Err(BnsBud3Error::SealedRequiresNftGrant);
        }
        _ => {}
    }
    Ok(checked)
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

/// Reads the content of a `.bud` name out of chain state and through
/// `bud3::view`. It holds no table of its own: the name registry record is
/// the only place a binding lives.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bud3BnsResolver;

impl Bud3BnsResolver {
    /// Bind or clear the content of `name` in chain state. The name registry
    /// checks the owner and the expiry; the object registry checks the
    /// reference.
    ///
    /// # Errors
    ///
    /// Returns [`BnsBud3Error`] if ownership, expiry, or object binding fails.
    pub fn set_bud3_content(
        bns: &mut BnsRegistry,
        bud3: &Bud3Registry,
        owner_claim: (&str, &Address),
        content_ref: Option<ContentRef>,
        current_epoch: u64,
    ) -> Result<(), BnsBud3Error> {
        let (name, caller) = owner_claim;
        bns.set_content(name, caller, bud3, content_ref, current_epoch)
    }

    /// The live binding of `name`, read from chain state.
    #[must_use]
    pub fn binding(bns: &BnsRegistry, name: &str, current_epoch: u64) -> Option<Bud3NameBinding> {
        let owner = bns.resolve_owner(name, current_epoch)?;
        let content_ref = bns.resolve_content(name, current_epoch)?;
        Some(Bud3NameBinding {
            name: name.to_string(),
            owner,
            content_ref,
        })
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
        bns: &BnsRegistry,
        bud3: &Bud3Registry,
        network: &N,
        name: &str,
        current_epoch: u64,
        access: &BnsViewAccess,
    ) -> Result<Vec<u8>, BnsBud3Error> {
        if bns.resolve_owner(name, current_epoch).is_none() {
            return Err(BnsBud3Error::Bns(BnsError::Expired));
        }
        let content_ref = bns
            .resolve_content(name, current_epoch)
            .ok_or(BnsBud3Error::NoContentBound)?;

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
                &content_ref,
                receipt,
                network,
            )
            .map_err(BnsBud3Error::Gateway);
        }

        let _bundle = Bud3ContentGateway::fetch_symbol_bundle(bud3, &content_ref, network)
            .map_err(BnsBud3Error::Gateway)?;
        view_from_network(
            bud3,
            &content_ref.object_commitment,
            access.content_key.as_ref(),
            network,
        )
        .map_err(BnsBud3Error::View)
    }
}

/// Test fixtures shared by the name registry tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{Bud3Registry, ContentRef};
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::{Class, Share};

    /// Register `bytes` as a public object owned by `owner` and return the
    /// reference a name record may point at.
    pub(crate) fn public_object(
        bud3: &mut Bud3Registry,
        owner: [u8; 32],
        bytes: &[u8],
    ) -> ContentRef {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let up = prepare_public_upload(bytes, &profile, &Bud3Limits::default(), 8).unwrap();
        let commitment = up.record.commitment;
        let content_id = up.record.content_id;
        bud3.register_object(
            owner,
            up.record,
            vec![(
                0,
                Share {
                    validator: [1u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 8,
                },
            )],
            1,
            20,
        )
        .unwrap();
        bud3.ack(&commitment, &[1u8; 32]).unwrap();
        ContentRef::new(content_id, commitment, None).unwrap()
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
        bns.register(String::from("portal.bud"), alice, 1, 20)
            .unwrap();

        let mut bud3 = Bud3Registry::default();
        let html = b"<html><body>BNS on B.U.D. 3.0</body></html>".repeat(6);
        let up = prepare_public_upload(&html, &P, &Bud3Limits::default(), 8).unwrap();
        let key = up.record.commitment;
        let cid = up.record.content_id;
        let nft_id = [0x44; 32];
        let holder = [1u8; 32];

        let mut net = MemorySymbolNetwork::default();
        for (seg_idx, syms) in up.segments.iter().enumerate() {
            net.store_holder_share(holder, key, seg_idx as u64, syms.clone());
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
        bud3.bind_nft(nft_id, alice.0, Some(alice.0), &key).unwrap();

        let cref = ContentRef::new(cid, key, Some(nft_id)).unwrap();
        Bud3BnsResolver::set_bud3_content(&mut bns, &bud3, ("portal.bud", &alice), Some(cref), 2)
            .unwrap();
        let binding = Bud3BnsResolver::binding(&bns, "portal.bud", 2).unwrap();
        assert_eq!(binding.content_ref.content_id, cid);
        assert_eq!(binding.owner, alice);

        // The binding lives in the record, so it is part of the name root.
        let root_bound = bns.root();
        let body = Bud3BnsResolver::resolve_via_bud3_view(
            &bns,
            &bud3,
            &net,
            "portal.bud",
            2,
            &BnsViewAccess::default(),
        )
        .unwrap();
        assert_eq!(body, html);

        // A stranger cannot bind, and the refusal changes nothing.
        let stranger = Address([0x77; 32]);
        assert!(matches!(
            Bud3BnsResolver::set_bud3_content(&mut bns, &bud3, ("portal.bud", &stranger), None, 2),
            Err(BnsBud3Error::Bns(BnsError::NotOwner))
        ));
        assert_eq!(bns.root(), root_bound);

        // A transfer clears the content with the rest of the record, so the
        // new owner starts from nothing and the binding digest is gone.
        let new_owner = Address([0x33; 32]);
        bns.transfer("portal.bud", &alice, new_owner, 3).unwrap();
        assert_ne!(bns.root(), root_bound);
        assert!(Bud3BnsResolver::binding(&bns, "portal.bud", 3).is_none());
        assert!(matches!(
            Bud3BnsResolver::resolve_via_bud3_view(
                &bns,
                &bud3,
                &net,
                "portal.bud",
                3,
                &BnsViewAccess::default(),
            ),
            Err(BnsBud3Error::NoContentBound)
        ));

        // Clearing as the owner removes the binding from the root too.
        Bud3BnsResolver::set_bud3_content(
            &mut bns,
            &bud3,
            ("portal.bud", &new_owner),
            Some(cref),
            3,
        )
        .unwrap();
        let root_rebound = bns.root();
        assert_ne!(root_rebound, root_bound, "the owner is part of the binding");
        Bud3BnsResolver::set_bud3_content(&mut bns, &bud3, ("portal.bud", &new_owner), None, 3)
            .unwrap();
        assert_ne!(bns.root(), root_rebound);
    }

    // The explorer and the wallets compute this digest on their own; the
    // vector is pinned on both sides so the two cannot drift apart.
    #[test]
    fn the_binding_digest_matches_the_pinned_vector() {
        let binding = Bud3NameBinding {
            name: "ayaz.bud".to_string(),
            owner: Address::from([1u8; 32]),
            content_ref: ContentRef {
                content_id: crate::storage::bud3::content_id::ContentId {
                    kind: ContentIdKind::Public,
                    digest: [2u8; 32],
                    len: 1024,
                },
                object_commitment: [3u8; 32],
                nft_id: None,
            },
        };
        assert_eq!(
            hex::encode(binding.digest()),
            "1f64b4ce979f1864d4ab5d6784d32094a6085e6adef0fcd5410fc0261516560c"
        );
    }
}
