//! B.U.D. 3.0 content gateway (`bud3::content_gateway`,  item 8).
//! exposed for HTTP/RPC content gateway endpoints and symbol exchange handlers.
//!
//! Replaces legacy gateway serving with B.U.D. 3.0's two-mode delivery:
//! 1. **Default client-decoded delivery (G3/G4)**: collects `>= k + 2` verified
//!    RFC 6330 symbols per segment from placement holders (Full class first,
//!    Mobile class second) and returns [`GatewaySymbolBundle`] so the viewer's
//!    own device decodes and verifies the BOF-1 object (and decrypts sealed
//!    objects locally with its grant key).
//! 2. **Optional G8 fallback decode (`serve_paid_public_fallback`)**: runs
//!    server-side decoding ONLY for `ContentIdKind::Public` when accompanied by
//!    a valid [`PaidViewReceipt`]; sealed objects are unconditionally refused.

use super::content_id::{ContentIdKind, ContentKey};
use super::content_ref::ContentRef;
use super::fountain::Symbol;
use super::pipeline::{view_public, view_sealed, ObjectRecord};
use super::registry::Bud3Registry;
use super::symbol_protocol::{
    verify_symbol_range_response, LinkMetering, MobileServePolicy, SymbolPeerLimiter,
    SymbolProtocolError, SymbolRangeRequest, SymbolRangeResponse,
};
use super::view::{
    collect_symbols_full_then_mobile, fallback_decode_public, NetworkSymbolSource, PaidViewReceipt,
    ViewBud3Error,
};

/// Alias for [`ViewBud3Error`] returned by [`Bud3ContentGateway`] operations.
pub type ContentGatewayError = ViewBud3Error;

/// Bundle of `>= k + 2` symbols per segment returned by [`Bud3ContentGateway`]
/// for client-side verification and decoding.
#[derive(Debug, Clone)]
pub struct GatewaySymbolBundle {
    /// On-chain record binding `content_id`, `commitment`, and `symbol_roots`.
    pub record: ObjectRecord,
    /// Collected symbols ordered Full-first, Mobile-second per segment.
    pub symbols: Vec<Symbol>,
}

/// Stateless B.U.D. 3.0 content gateway facade over [`Bud3Registry`] and [`NetworkSymbolSource`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Bud3ContentGateway;

impl Bud3ContentGateway {
    /// Collect `>= k + 2` symbols per segment for `content_ref` so the client
    /// decodes locally (works for both public and sealed objects; the gateway
    /// never sees sealed keys or plaintext).
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error`] if the object is unknown/tombstoned or `content_id` mismatches.
    pub fn fetch_symbol_bundle<N: NetworkSymbolSource>(
        registry: &Bud3Registry,
        content_ref: &ContentRef,
        network: &N,
    ) -> Result<GatewaySymbolBundle, ViewBud3Error> {
        let _ = registry
            .resolve_live_object(&content_ref.object_commitment)
            .ok_or(ViewBud3Error::UnknownObject)?;
        if let Some(nft) = content_ref.nft_id {
            let Some((bound_key, _)) = registry.nft_binding(&nft) else {
                return Err(ViewBud3Error::AccessDenied);
            };
            if bound_key != content_ref.object_commitment
                && !registry.nft_matches_object(&nft, &content_ref.object_commitment)
            {
                return Err(ViewBud3Error::AccessDenied);
            }
        }
        let (record, symbols) =
            collect_symbols_full_then_mobile(registry, &content_ref.object_commitment, network)?;
        if record.content_id != content_ref.content_id {
            return Err(ViewBud3Error::AccessDenied);
        }
        Ok(GatewaySymbolBundle { record, symbols })
    }

    /// Decode and verify content from an already-fetched [`GatewaySymbolBundle`]
    /// without repeating network symbol fetches.
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error`] if a sealed object lacks `grant_key` or object/content
    /// verification fails.
    pub fn decode_symbol_bundle(
        bundle: &GatewaySymbolBundle,
        grant_key: Option<&ContentKey>,
    ) -> Result<Vec<u8>, ViewBud3Error> {
        match bundle.record.content_id.kind {
            ContentIdKind::Public => {
                Ok(view_public(&bundle.record, bundle.symbols.iter().cloned())?)
            }
            ContentIdKind::Sealed => {
                let key = grant_key.ok_or(ViewBud3Error::AccessDenied)?;
                Ok(view_sealed(
                    &bundle.record,
                    key,
                    bundle.symbols.iter().cloned(),
                )?)
            }
        }
    }

    /// G8 Validator Fallback Decode: decode and return public content bytes on
    /// behalf of a thin client that paid `receipt`. Sealed content is always refused.
    ///
    /// # Errors
    ///
    /// [`ViewBud3Error::SealedFallbackForbidden`], [`ViewBud3Error::UnpaidFallbackView`],
    /// or [`ViewBud3Error::Pipeline`].
    pub fn serve_paid_public_fallback<N: NetworkSymbolSource>(
        registry: &Bud3Registry,
        content_ref: &ContentRef,
        receipt: &PaidViewReceipt,
        network: &N,
    ) -> Result<Vec<u8>, ViewBud3Error> {
        let (_, entry) = registry
            .resolve_live_object(&content_ref.object_commitment)
            .ok_or(ViewBud3Error::UnknownObject)?;
        if let Some(nft) = content_ref.nft_id {
            if !registry.nft_matches_object(&nft, &content_ref.object_commitment) {
                return Err(ViewBud3Error::AccessDenied);
            }
        }
        if entry.record.content_id != content_ref.content_id {
            return Err(ViewBud3Error::AccessDenied);
        }
        fallback_decode_public(registry, &content_ref.object_commitment, receipt, network)
    }

    /// Enforce peer symbol-request rate limits, Mobile Wi-Fi/cellular link policy,
    /// and Merkle range verification on `/budlum/bud3/symbols/1`.
    /// Convenience: exposed for symbol request-response handler and RPC symbol serving.
    ///
    /// # Errors
    ///
    /// Returns `SymbolExchangeError` if rate limits, link policy, or Merkle verification fail.
    pub fn serve_verified_symbol_exchange(
        limiter: &mut SymbolPeerLimiter,
        mobile_policy: &mut MobileServePolicy,
        peer_link: (&[u8; 32], LinkMetering, u64),
        req: &SymbolRangeRequest,
        resp: &SymbolRangeResponse,
        root_meta: ([u8; 32], u64, u16),
    ) -> Result<bool, SymbolProtocolError> {
        let (peer, link, now_sec) = peer_link;
        let (symbol_root, symbol_count, symbol_size) = root_meta;
        limiter.check_symbol_request(peer, req, now_sec)?;
        let bytes = u64::from(req.count).saturating_mul(u64::from(symbol_size));
        if !mobile_policy.admit_serve(link, bytes) {
            return Ok(false);
        }
        verify_symbol_range_response(req.segment, symbol_root, symbol_count, symbol_size, resp)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::limits::{Bud3Limits, Profile};
    use super::super::pipeline::{prepare_public_upload, view_public};
    use super::super::placement::{Class, Share};
    use super::super::view::{MemorySymbolNetwork, MIN_PAID_VIEW_FEE_ATOMS};
    use super::*;

    #[test]
    fn gateway_serves_symbol_bundle_and_enforces_paid_public_fallback() {
        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let up = prepare_public_upload(
            b"gateway delivered bud3 content",
            &profile,
            &Bud3Limits::default(),
            6,
        )
        .unwrap();
        let key = up.record.commitment;
        let cref = ContentRef::new(up.record.content_id, key, None).unwrap();

        let mut reg = Bud3Registry::default();
        let holder = [21u8; 32];
        let holder2 = [22u8; 32];
        reg.register_object(
            [1; 32],
            up.record,
            vec![
                (
                    0,
                    Share {
                        validator: holder,
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 3,
                    },
                ),
                (
                    0,
                    Share {
                        validator: holder2,
                        class: Class::Full,
                        first_esi: 3,
                        symbols: 3,
                    },
                ),
            ],
            0,
            10,
        )
        .unwrap();
        let mut net = MemorySymbolNetwork::default();
        net.store_holder_share(holder, key, 0, up.segments[0][..3].to_vec());
        net.store_holder_share(holder2, key, 0, up.segments[0][3..].to_vec());

        let bundle = Bud3ContentGateway::fetch_symbol_bundle(&reg, &cref, &net).unwrap();
        assert_eq!(
            view_public(&bundle.record, bundle.symbols).unwrap(),
            b"gateway delivered bud3 content"
        );

        let receipt_id = [0x99; 32];
        reg.record_paid_view([9; 32], key, receipt_id, MIN_PAID_VIEW_FEE_ATOMS, 1)
            .unwrap();
        let fallback = Bud3ContentGateway::serve_paid_public_fallback(
            &reg,
            &cref,
            &PaidViewReceipt {
                payer: [9; 32],
                object: key,
                receipt_id,
                fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
            },
            &net,
        )
        .unwrap();
        assert_eq!(fallback, b"gateway delivered bud3 content");
    }

    #[test]
    fn gateway_follows_finalized_replacement_with_nft_ref() {
        use super::super::bof1::Object;
        use super::super::custody::{symbol_leaf, symbol_root};
        use super::super::fountain::SegmentEncoder;
        use super::super::pipeline::ObjectRecord;
        use super::super::registry::Address;
        use super::super::replace::sign_replace_attestation;
        use super::super::segment::commit_object;
        use crate::crypto::pq::ml_dsa_public_key;
        use crate::crypto::scheme::SchemeId;
        use std::collections::BTreeMap;

        let profile = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 128,
            fps: 10,
            k_max: 16,
        };
        let payload = b"gateway redirect payload for nft ".repeat(6);
        let up_old = prepare_public_upload(&payload, &profile, &Bud3Limits::default(), 16).unwrap();
        let old_key = up_old.record.commitment;
        let nft = [0x88; 32];

        let raw_obj = Object::raw_public(&payload);
        let raw_bytes = raw_obj.encode();
        let new_commit = commit_object(&raw_bytes, &profile).unwrap();
        let enc_raw = SegmentEncoder::new(0, &raw_bytes, &profile).unwrap();
        let k_raw = enc_raw.k();
        let mut syms_new = enc_raw.source_symbols();
        syms_new.extend(enc_raw.repair_symbols(0, 16 - k_raw).unwrap());
        let leaves_new: Vec<(u32, [u8; 32])> = syms_new
            .iter()
            .map(|s| (s.esi, symbol_leaf(&s.data)))
            .collect();
        let new_record = ObjectRecord {
            content_id: up_old.record.content_id,
            object_len: raw_bytes.len() as u64,
            commitment: new_commit,
            profile,
            codec: raw_obj.header.codec,
            symbols_per_segment: 16,
            symbol_roots: vec![symbol_root(&leaves_new)],
        };

        let validators = [[61u8; 32], [62u8; 32], [63u8; 32]];
        let shares = vec![
            (
                0,
                Share {
                    validator: validators[0],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 6,
                },
            ),
            (
                0,
                Share {
                    validator: validators[1],
                    class: Class::Full,
                    first_esi: 6,
                    symbols: 6,
                },
            ),
            (
                0,
                Share {
                    validator: validators[2],
                    class: Class::Full,
                    first_esi: 12,
                    symbols: 4,
                },
            ),
        ];

        let mut reg = Bud3Registry::default();
        reg.register_object([1; 32], up_old.record.clone(), shares.clone(), 0, 40)
            .unwrap();
        for v in &validators {
            reg.ack(&old_key, v).unwrap();
        }
        reg.bind_nft(nft, [1; 32], Some([1; 32]), &old_key).unwrap();
        let cref_old = ContentRef::new(up_old.record.content_id, old_key, Some(nft)).unwrap();

        let validator_keys: BTreeMap<Address, Vec<u8>> = [61u8, 62, 63]
            .into_iter()
            .map(|v| {
                (
                    [v; 32],
                    ml_dsa_public_key(SchemeId::ML_DSA_65, &[v; 32]).unwrap(),
                )
            })
            .collect();
        let attestations: Vec<_> = [61u8, 62, 63]
            .into_iter()
            .map(|v| {
                sign_replace_attestation([v; 32], &[v; 32], &old_key, &new_record, &shares).unwrap()
            })
            .collect();
        let new_key = reg
            .replace_object(
                (validators[0], 10_000),
                &old_key,
                new_record,
                shares,
                &attestations,
                (
                    crate::core::transaction::DEFAULT_CHAIN_ID,
                    1,
                    &validator_keys,
                ),
            )
            .unwrap();

        // While the replacement is pending (unfinalized), `nfts[nft]` already moved
        // to `new_key`, whereas `old_key` still holds the live confirmed shares.
        // Reading via `cref_old` must still authorize and recover from `old_key`,
        // while an unbound/wrong NFT id is denied.
        let mut net_pending = MemorySymbolNetwork::default();
        let old_syms = &up_old.segments[0];
        net_pending.store_holder_share(validators[0], old_key, 0, old_syms[0..6].to_vec());
        net_pending.store_holder_share(validators[1], old_key, 0, old_syms[6..12].to_vec());
        net_pending.store_holder_share(validators[2], old_key, 0, old_syms[12..16].to_vec());
        let pending_bundle =
            Bud3ContentGateway::fetch_symbol_bundle(&reg, &cref_old, &net_pending).unwrap();
        assert_eq!(
            Bud3ContentGateway::decode_symbol_bundle(&pending_bundle, None).unwrap(),
            payload
        );
        let wrong_ref =
            ContentRef::new(up_old.record.content_id, old_key, Some([0x77; 32])).unwrap();
        assert!(matches!(
            Bud3ContentGateway::fetch_symbol_bundle(&reg, &wrong_ref, &net_pending),
            Err(ViewBud3Error::AccessDenied)
        ));

        for v in &validators {
            reg.ack(&new_key, v).unwrap();
        }

        let mut net = MemorySymbolNetwork::default();
        net.store_holder_share(validators[0], new_key, 0, syms_new[0..6].to_vec());
        net.store_holder_share(validators[1], new_key, 0, syms_new[6..12].to_vec());
        net.store_holder_share(validators[2], new_key, 0, syms_new[12..16].to_vec());

        let bundle = Bud3ContentGateway::fetch_symbol_bundle(&reg, &cref_old, &net).unwrap();
        assert_eq!(
            Bud3ContentGateway::decode_symbol_bundle(&bundle, None).unwrap(),
            payload
        );
    }
}
