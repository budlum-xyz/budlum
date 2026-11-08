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

use super::content_ref::ContentRef;
use super::fountain::Symbol;
use super::pipeline::ObjectRecord;
use super::registry::Bud3Registry;
use super::symbol_protocol::{
    verify_symbol_range_response, LinkMetering, MobileServePolicy, SymbolPeerLimiter,
    SymbolProtocolError, SymbolRangeRequest, SymbolRangeResponse,
};
use super::view::{
    collect_symbols_full_then_mobile, fallback_decode_public, NetworkSymbolSource, PaidViewReceipt,
    ViewBud3Error,
};

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
        let (record, symbols) =
            collect_symbols_full_then_mobile(registry, &content_ref.object_commitment, network)?;
        if record.content_id != content_ref.content_id {
            return Err(ViewBud3Error::AccessDenied);
        }
        Ok(GatewaySymbolBundle { record, symbols })
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
        let entry = registry
            .object(&content_ref.object_commitment)
            .ok_or(ViewBud3Error::UnknownObject)?;
        if entry.record.content_id != content_ref.content_id {
            return Err(ViewBud3Error::AccessDenied);
        }
        fallback_decode_public(registry, &content_ref.object_commitment, receipt, network)
    }

    /// Enforce peer symbol-request rate limits, Mobile Wi-Fi/cellular link policy,
    /// and Merkle range verification on `/budlum/bud3/symbols/1`.
    /// Convenience: exposed for symbol request-response handler and RPC symbol serving.
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
        let up = prepare_public_upload(b"gateway delivered bud3 content", &profile, &Bud3Limits::default(), 6)
            .unwrap();
        let key = up.record.commitment;
        let cref = ContentRef::new(up.record.content_id, key, None).unwrap();

        let mut reg = Bud3Registry::default();
        let holder = [21u8; 32];
        reg.register_object(
            [1; 32],
            up.record,
            vec![(
                0,
                Share {
                    validator: holder,
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 6,
                },
            )],
            0,
            10,
        )
        .unwrap();
        let mut net = MemorySymbolNetwork::default();
        net.store_holder_share(holder, key, 0, up.segments[0].clone());

        let bundle = Bud3ContentGateway::fetch_symbol_bundle(&reg, &cref, &net).unwrap();
        assert_eq!(
            view_public(&bundle.record, bundle.symbols).unwrap(),
            b"gateway delivered bud3 content"
        );

        let fallback = Bud3ContentGateway::serve_paid_public_fallback(
            &reg,
            &cref,
            &PaidViewReceipt {
                payer: [9; 32],
                object: key,
                fee_paid_atoms: MIN_PAID_VIEW_FEE_ATOMS,
            },
            &net,
        )
        .unwrap();
        assert_eq!(fallback, b"gateway delivered bud3 content");
    }
}
