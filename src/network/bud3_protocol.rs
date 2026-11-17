//! Wire codecs and cryptographic response verification for B.U.D. 3.0 P2P
//! symbol transfer (`/budlum/bud3/symbols/1`) and custody share delivery
//! (`/budlum/bud3/custody/1`).

use std::collections::BTreeSet;
use std::io;

use futures::prelude::*;
use libp2p::{identity, request_response, PeerId, StreamProtocol};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::core::hash::hash_fields_bytes;
use crate::network::bounded_bincode::decode_bounded_bincode;
use crate::storage::bud3::registry::{Address, ObjectKey, SymbolRoot};
use crate::storage::bud3::symbol_protocol::{
    verify_symbol_range_response, SymbolRangeRequest, SymbolRangeResponse, VerifiedSymbolItem,
    MAX_SYMBOLS_PER_REQUEST,
};

/// Maximum serialized byte size of one `/budlum/bud3/symbols/1` request.
const MAX_BUD3_SYMBOL_REQUEST_BYTES: usize = 1_024;
/// Maximum serialized byte size of one `/budlum/bud3/symbols/1` response (up to 64 P0 symbols + proofs).
const MAX_BUD3_SYMBOL_RESPONSE_BYTES: usize = 512 * 1024;
/// Maximum serialized byte size of one `/budlum/bud3/custody/1` share push request.
const MAX_BUD3_CUSTODY_REQUEST_BYTES: usize = 512 * 1024;
/// Maximum serialized byte size of one `/budlum/bud3/custody/1` receipt response.
const MAX_BUD3_CUSTODY_RESPONSE_BYTES: usize = 1_024;

/// Request payload on `/budlum/bud3/symbols/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3SymbolsRequest {
    /// Validator address expected to hold the requested share.
    pub holder: Address,
    /// Object, segment, and bounded ESI range (`1..=64`).
    pub range: SymbolRangeRequest,
}

/// Response payload on `/budlum/bud3/symbols/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bud3SymbolsResponse {
    /// Merkle-authenticated symbols held for the requested range.
    Symbols(SymbolRangeResponse),
    /// Peer refused, was rate-limited, or does not hold the requested symbols.
    Unavailable(String),
}

/// Request payload on `/budlum/bud3/custody/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bud3CustodyRequest {
    /// Target validator holder whose custody slot receives the symbols.
    pub holder: Address,
    /// Object commitment registered on-chain.
    pub object: ObjectKey,
    /// Segment index within `object`.
    pub segment: u64,
    /// Bounded batch (`1..=64`) of symbols with custody Merkle proofs.
    pub items: Vec<VerifiedSymbolItem>,
}

/// Response payload on `/budlum/bud3/custody/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bud3CustodyResponse {
    /// Holder verified the symbols against consensus roots and persisted them locally.
    Accepted {
        /// Number of verified symbol items admitted.
        stored: usize,
        /// Domain-separated receipt digest binding `(holder, object, segment, stored)`.
        receipt_digest: [u8; 32],
    },
    /// Holder rejected the custody push (unregistered object, invalid proof, or capacity limit).
    Rejected(String),
}

/// Domain-separated digest binding a custody push acknowledgement to `(holder, object, segment, stored)`.
#[must_use]
pub fn custody_receipt_digest(
    holder: &Address,
    object: &ObjectKey,
    segment: u64,
    stored: usize,
) -> [u8; 32] {
    let stored_u64 = u64::try_from(stored).unwrap_or(u64::MAX);
    hash_fields_bytes(&[
        b"BDLM_BUD3_CUSTODY_RECEIPT_V1",
        holder,
        object,
        &segment.to_le_bytes(),
        &stored_u64.to_le_bytes(),
    ])
}

/// Convert a validator's 32-byte Ed25519 transport public key (`ValidatorRecord::peer_id`)
/// into its libp2p [`PeerId`].
///
/// # Errors
///
/// Returns an error if `key` is zero or not a valid Ed25519 public key.
pub fn ed25519_key_to_peer_id(key: &[u8; 32]) -> Result<PeerId, String> {
    if *key == [0u8; 32] {
        return Err(String::from("validator peer_id is zero"));
    }
    let pk = identity::ed25519::PublicKey::try_from_bytes(key)
        .map_err(|e| format!("invalid validator Ed25519 peer key: {e}"))?;
    Ok(PeerId::from(identity::PublicKey::from(pk)))
}

/// Verify a `/budlum/bud3/symbols/1` response against the original request and
/// consensus-registered `(symbol_size, roots)` before accepting any symbol bytes.
///
/// # Errors
///
/// Returns an error string if the peer reported unavailability, exceeded the
/// requested ESI window or symbol cap, duplicated ESIs, returned wrong symbol
/// lengths, or failed Merkle/sub-block verification against consensus roots.
pub fn verify_bud3_symbols_response(
    req: &Bud3SymbolsRequest,
    resp: &Bud3SymbolsResponse,
    symbol_size: u16,
    roots: &[SymbolRoot],
) -> Result<Vec<VerifiedSymbolItem>, String> {
    let Bud3SymbolsResponse::Symbols(range_resp) = resp else {
        let Bud3SymbolsResponse::Unavailable(reason) = resp else {
            return Err(String::from("B.U.D. 3.0 symbols unavailable"));
        };
        return Err(format!("peer refused B.U.D. 3.0 symbols: {reason}"));
    };
    if symbol_size == 0 || req.range.count == 0 || req.range.count > MAX_SYMBOLS_PER_REQUEST {
        return Err(String::from("invalid B.U.D. 3.0 symbol request metadata"));
    }
    let max_requested = usize::try_from(req.range.count).unwrap_or(64);
    if range_resp.items.len() > max_requested {
        return Err(format!(
            "peer returned {} symbols exceeding requested count {}",
            range_resp.items.len(),
            req.range.count
        ));
    }
    let Some(end_esi) = req.range.first_esi.checked_add(req.range.count) else {
        return Err(String::from("B.U.D. 3.0 symbol request ESI range overflow"));
    };
    let mut seen_esis = BTreeSet::new();
    for item in &range_resp.items {
        if item.symbol.segment != req.range.segment
            || item.symbol.esi < req.range.first_esi
            || item.symbol.esi >= end_esi
            || !seen_esis.insert(item.symbol.esi)
        {
            return Err(String::from(
                "peer returned out-of-range or duplicate B.U.D. 3.0 ESI",
            ));
        }
        let Some(sym_root) = roots.iter().find(|r| {
            r.segment == req.range.segment
                && r.count > 0
                && item.symbol.esi >= r.first_esi
                && item.symbol.esi < r.first_esi.saturating_add(r.count)
        }) else {
            return Err(String::from(
                "missing consensus SymbolRoot covering returned ESI",
            ));
        };
        let expected_pos = u64::from(item.symbol.esi - sym_root.first_esi);
        if item.proof.position != expected_pos {
            return Err(String::from(
                "B.U.D. 3.0 custody proof position mismatches consensus root",
            ));
        }
        let single = SymbolRangeResponse {
            items: vec![item.clone()],
        };
        verify_symbol_range_response(
            req.range.segment,
            sym_root.root,
            u64::from(sym_root.count),
            symbol_size,
            &single,
        )
        .map_err(|e| format!("B.U.D. 3.0 symbol Merkle proof rejected: {e:?}"))?;
    }
    Ok(range_resp.items.clone())
}

/// Verify a `/budlum/bud3/custody/1` response against the original custody push request.
///
/// # Errors
///
/// Returns an error if the remote holder rejected the push, stored fewer items
/// than pushed, or returned a mismatched receipt digest.
pub fn verify_bud3_custody_response(
    req: &Bud3CustodyRequest,
    resp: &Bud3CustodyResponse,
) -> Result<usize, String> {
    match resp {
        Bud3CustodyResponse::Accepted {
            stored,
            receipt_digest,
        } => {
            if *stored != req.items.len() {
                return Err(format!(
                    "custody holder stored {stored} of {} pushed symbols",
                    req.items.len()
                ));
            }
            let expected = custody_receipt_digest(&req.holder, &req.object, req.segment, *stored);
            if *receipt_digest != expected {
                return Err(String::from(
                    "custody receipt digest mismatch from remote holder",
                ));
            }
            Ok(*stored)
        }
        Bud3CustodyResponse::Rejected(reason) => Err(format!(
            "remote holder rejected B.U.D. 3.0 custody push: {reason}"
        )),
    }
}

async fn read_bounded_bytes<T>(io: &mut T, limit: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut limited = io.take(cap);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("B.U.D. 3.0 frame exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

fn decode_bounded_frame<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> io::Result<T> {
    decode_bounded_bincode(bytes, limit).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn encode_bounded_frame<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    let bytes = bincode::serialize(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("B.U.D. 3.0 outbound frame exceeds {limit} bytes"),
        ));
    }
    Ok(bytes)
}

/// libp2p codec for `/budlum/bud3/symbols/1`.
#[derive(Debug, Clone, Default)]
pub struct Bud3SymbolsCodec;

impl request_response::Codec for Bud3SymbolsCodec {
    type Protocol = StreamProtocol;
    type Request = Bud3SymbolsRequest;
    type Response = Bud3SymbolsResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded_bytes(io, MAX_BUD3_SYMBOL_REQUEST_BYTES).await?;
        let req: Bud3SymbolsRequest = decode_bounded_frame(&bytes, MAX_BUD3_SYMBOL_REQUEST_BYTES)?;
        if req.range.count == 0
            || req.range.count > MAX_SYMBOLS_PER_REQUEST
            || req.range.first_esi.checked_add(req.range.count).is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid B.U.D. 3.0 symbol request count or ESI range",
            ));
        }
        Ok(req)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded_bytes(io, MAX_BUD3_SYMBOL_RESPONSE_BYTES).await?;
        let resp: Bud3SymbolsResponse =
            decode_bounded_frame(&bytes, MAX_BUD3_SYMBOL_RESPONSE_BYTES)?;
        if let Bud3SymbolsResponse::Symbols(ref r) = resp {
            if usize::try_from(MAX_SYMBOLS_PER_REQUEST).is_ok_and(|max| r.items.len() > max) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "B.U.D. 3.0 symbol response exceeds 64 symbols",
                ));
            }
        }
        Ok(resp)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_bounded_frame(&req, MAX_BUD3_SYMBOL_REQUEST_BYTES)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_bounded_frame(&resp, MAX_BUD3_SYMBOL_RESPONSE_BYTES)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

/// libp2p codec for `/budlum/bud3/custody/1`.
#[derive(Debug, Clone, Default)]
pub struct Bud3CustodyCodec;

impl request_response::Codec for Bud3CustodyCodec {
    type Protocol = StreamProtocol;
    type Request = Bud3CustodyRequest;
    type Response = Bud3CustodyResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded_bytes(io, MAX_BUD3_CUSTODY_REQUEST_BYTES).await?;
        let req: Bud3CustodyRequest = decode_bounded_frame(&bytes, MAX_BUD3_CUSTODY_REQUEST_BYTES)?;
        let max_items = usize::try_from(MAX_SYMBOLS_PER_REQUEST).unwrap_or(64);
        if req.items.is_empty() || req.items.len() > max_items {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "B.U.D. 3.0 custody push item count outside 1..=64",
            ));
        }
        Ok(req)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_bounded_bytes(io, MAX_BUD3_CUSTODY_RESPONSE_BYTES).await?;
        decode_bounded_frame(&bytes, MAX_BUD3_CUSTODY_RESPONSE_BYTES)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_bounded_frame(&req, MAX_BUD3_CUSTODY_REQUEST_BYTES)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_bounded_frame(&resp, MAX_BUD3_CUSTODY_RESPONSE_BYTES)?;
        io.write_all(&bytes).await?;
        io.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec;

    use super::*;
    use crate::storage::bud3::custody::{symbol_leaf, symbol_root};
    use crate::storage::bud3::fountain::Symbol;
    use crate::storage::bud3::symbol_protocol::{
        build_symbol_range_response, CUSTODY_PROTOCOL_ID, SYMBOLS_PROTOCOL_ID,
    };

    type SampleSymbols = (Vec<Symbol>, Vec<(u32, [u8; 32])>, SymbolRoot);

    fn sample_symbols() -> SampleSymbols {
        let syms: Vec<Symbol> = (0..4u32)
            .map(|esi| Symbol {
                segment: 0,
                esi,
                data: vec![0x30u8.wrapping_add(u8::try_from(esi).unwrap_or(0)); 128],
            })
            .collect();
        let leaves: Vec<(u32, [u8; 32])> =
            syms.iter().map(|s| (s.esi, symbol_leaf(&s.data))).collect();
        let root = SymbolRoot {
            segment: 0,
            root: symbol_root(&leaves),
            first_esi: 0,
            count: 4,
        };
        (syms, leaves, root)
    }

    #[tokio::test]
    async fn bud3_symbols_codec_roundtrips_and_rejects_oversize_or_malformed_frames() {
        let (syms, leaves, root) = sample_symbols();
        let req = Bud3SymbolsRequest {
            holder: [11; 32],
            range: SymbolRangeRequest {
                object: [22; 32],
                segment: 0,
                first_esi: 1,
                count: 2,
            },
        };
        let mut codec = Bud3SymbolsCodec;
        let proto = StreamProtocol::new(SYMBOLS_PROTOCOL_ID);
        let mut wire = Vec::new();
        codec
            .write_request(&proto, &mut wire, req.clone())
            .await
            .unwrap();
        let decoded_req = codec
            .read_request(&proto, &mut Cursor::new(wire))
            .await
            .unwrap();
        assert_eq!(decoded_req, req);

        // Zero-count request must be rejected on read.
        let bad_req = Bud3SymbolsRequest {
            holder: [11; 32],
            range: SymbolRangeRequest {
                object: [22; 32],
                segment: 0,
                first_esi: 0,
                count: 0,
            },
        };
        let mut bad_wire = Vec::new();
        codec
            .write_request(&proto, &mut bad_wire, bad_req)
            .await
            .unwrap();
        assert!(codec
            .read_request(&proto, &mut Cursor::new(bad_wire))
            .await
            .is_err());

        let range_resp = build_symbol_range_response(&req.range, &leaves, &syms).unwrap();
        let resp = Bud3SymbolsResponse::Symbols(range_resp);
        let mut resp_wire = Vec::new();
        codec
            .write_response(&proto, &mut resp_wire, resp.clone())
            .await
            .unwrap();
        let decoded_resp = codec
            .read_response(&proto, &mut Cursor::new(resp_wire))
            .await
            .unwrap();
        let verified = verify_bud3_symbols_response(&req, &decoded_resp, 128, &[root]).unwrap();
        assert_eq!(verified.len(), 2);

        // Forged bincode count header must fail without allocating.
        let mut forged = vec![0x00u8; 16];
        forged[4..12].copy_from_slice(&0x00FF_FFFF_FFFFu64.to_le_bytes());
        assert!(codec
            .read_response(&proto, &mut Cursor::new(forged))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn bud3_symbols_verifier_rejects_tampered_bytes_and_custody_receipt_verifies() {
        let (syms, leaves, root) = sample_symbols();
        let req = Bud3SymbolsRequest {
            holder: [5; 32],
            range: SymbolRangeRequest {
                object: [6; 32],
                segment: 0,
                first_esi: 0,
                count: 2,
            },
        };
        let mut range_resp = build_symbol_range_response(&req.range, &leaves, &syms).unwrap();
        range_resp.items[0].symbol.data[90] ^= 0xFF;
        let err = verify_bud3_symbols_response(
            &req,
            &Bud3SymbolsResponse::Symbols(range_resp.clone()),
            128,
            &[root],
        )
        .unwrap_err();
        assert!(err.contains("Merkle"), "{err}");

        // Valid custody push codec + receipt verification.
        let valid_resp = build_symbol_range_response(&req.range, &leaves, &syms).unwrap();
        let push_req = Bud3CustodyRequest {
            holder: [5; 32],
            object: [6; 32],
            segment: 0,
            items: valid_resp.items,
        };
        let mut ccodec = Bud3CustodyCodec;
        let cproto = StreamProtocol::new(CUSTODY_PROTOCOL_ID);
        let mut cwire = Vec::new();
        ccodec
            .write_request(&cproto, &mut cwire, push_req.clone())
            .await
            .unwrap();
        let back_req = ccodec
            .read_request(&cproto, &mut Cursor::new(cwire))
            .await
            .unwrap();
        assert_eq!(back_req, push_req);

        let digest = custody_receipt_digest(&push_req.holder, &push_req.object, 0, 2);
        let ok_ack = Bud3CustodyResponse::Accepted {
            stored: 2,
            receipt_digest: digest,
        };
        assert_eq!(verify_bud3_custody_response(&push_req, &ok_ack), Ok(2));

        let bad_ack = Bud3CustodyResponse::Accepted {
            stored: 2,
            receipt_digest: [0x99; 32],
        };
        assert!(verify_bud3_custody_response(&push_req, &bad_ack)
            .unwrap_err()
            .contains("digest mismatch"));
    }

    #[test]
    fn ed25519_key_to_peer_id_accepts_valid_key_and_refuses_zero() {
        assert!(ed25519_key_to_peer_id(&[0u8; 32])
            .unwrap_err()
            .contains("zero"));
        let seed = [0x42u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let raw = signing.verifying_key().to_bytes();
        let kp = identity::Keypair::ed25519_from_bytes(seed).unwrap();
        assert_eq!(
            ed25519_key_to_peer_id(&raw).unwrap(),
            kp.public().to_peer_id()
        );
    }

    #[tokio::test]
    async fn repaired_root_nonzero_first_esi_and_empty_custody_rejected() {
        let repaired_syms: Vec<Symbol> = (10..14u32)
            .map(|esi| Symbol {
                segment: 0,
                esi,
                data: vec![0x50u8.wrapping_add(u8::try_from(esi).unwrap_or(0)); 128],
            })
            .collect();
        let leaves: Vec<(u32, [u8; 32])> = repaired_syms
            .iter()
            .map(|s| (s.esi, symbol_leaf(&s.data)))
            .collect();
        let repaired_root = SymbolRoot {
            segment: 0,
            root: symbol_root(&leaves),
            first_esi: 10,
            count: 4,
        };
        let req = Bud3SymbolsRequest {
            holder: [7; 32],
            range: SymbolRangeRequest {
                object: [8; 32],
                segment: 0,
                first_esi: 11,
                count: 2,
            },
        };
        let resp = build_symbol_range_response(&req.range, &leaves, &repaired_syms).unwrap();
        let verified = verify_bud3_symbols_response(
            &req,
            &Bud3SymbolsResponse::Symbols(resp),
            128,
            &[repaired_root],
        )
        .unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].symbol.esi, 11);
        assert_eq!(verified[1].proof.position, 2);

        // Empty custody push batch must be rejected by the codec on read.
        let mut ccodec = Bud3CustodyCodec;
        let cproto = StreamProtocol::new(CUSTODY_PROTOCOL_ID);
        let empty_req = Bud3CustodyRequest {
            holder: [7; 32],
            object: [8; 32],
            segment: 0,
            items: Vec::new(),
        };
        let mut wire = Vec::new();
        ccodec
            .write_request(&cproto, &mut wire, empty_req)
            .await
            .unwrap();
        assert!(ccodec
            .read_request(&cproto, &mut Cursor::new(wire))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn bud3_symbols_rejects_overflowing_esi_range() {
        let (_, _, root) = sample_symbols();
        let req = Bud3SymbolsRequest {
            holder: [7; 32],
            range: SymbolRangeRequest {
                object: [8; 32],
                segment: 0,
                first_esi: u32::MAX,
                count: 2,
            },
        };
        let mut codec = Bud3SymbolsCodec;
        let proto = StreamProtocol::new(SYMBOLS_PROTOCOL_ID);
        let mut wire = Vec::new();
        codec
            .write_request(&proto, &mut wire, req.clone())
            .await
            .unwrap();
        assert!(codec
            .read_request(&proto, &mut Cursor::new(wire))
            .await
            .is_err());
        let empty = Bud3SymbolsResponse::Symbols(SymbolRangeResponse { items: Vec::new() });
        assert!(verify_bud3_symbols_response(&req, &empty, 128, &[root])
            .unwrap_err()
            .contains("overflow"));
    }
}
