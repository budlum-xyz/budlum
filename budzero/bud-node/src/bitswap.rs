//! B.U.D. Bitswap — Bitswap-like block exchange protocol.
//!
//! Implements a simplified Bitswap protocol using libp2p's
//! `request-response` codec. Peers can request content chunks by
//! `ContentId` and respond with the raw data (if available in their
//! local store).
//!
//! # Protocol
//!
//! ```text
//! Request:  { want_cid: ContentId }
//! Response: { cid: ContentId, data: Vec<u8> }  — on success
//!           { cid: ContentId, not_found: true } — on miss
//! ```
//!
//! # Security
//!
//! - Response data is verified against the requested CID before
//!   being stored locally (integrity check via `ContentId::of`).
//! - Rate limiting is handled by the libp2p swarm layer.
//! - No authentication is required — the protocol is permissionless
//!   (anyone can request or serve content).

use crate::store::{ContentId, ContentStore, StoreError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Protocol name for the Bitswap-like exchange.
pub const BITSWAP_PROTOCOL_NAME: &str = "/bud/bitswap/1.0.0";

/// A Bitswap request — "I want this CID".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapRequest {
    /// The content identifier being requested.
    pub want_cid: ContentId,
}

/// A Bitswap response — "here's the data" or "I don't have it".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitswapResponse {
    /// The CID this response is for.
    pub cid: ContentId,
    /// The raw chunk data. Empty if `not_found` is true.
    pub data: Vec<u8>,
    /// Whether the content was not found in the responder's store.
    pub not_found: bool,
}

/// Codec for serializing/deserializing Bitswap messages.
///
/// Uses `bincode` for compact binary encoding. Maximum message size
/// is 16 MiB (matching `MAX_CHUNK_SIZE` in `storage_params.rs`).
#[derive(Debug, Clone, Default)]
pub struct BitswapCodec;

/// Maximum message size: 16 MiB + overhead for CID and metadata.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024 + 256;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("message too large: {size} bytes (max {max})")]
    TooLarge { size: usize, max: usize },
    #[error("io error: {0}")]
    Io(String),
}

/// The Bitswap behaviour — wraps `request_response::Behaviour` with
/// a content store for automatic request handling.
pub struct BudBitswap {
    /// The content store used to serve and cache chunks.
    store: Arc<dyn ContentStore>,
}

impl BudBitswap {
    /// Create a new Bitswap instance backed by the given store.
    pub fn new(store: Arc<dyn ContentStore>) -> Self {
        Self { store }
    }

    /// Handle an incoming Bitswap request. Looks up the CID in the
    /// local store and returns the appropriate response.
    pub fn handle_request(&self, request: BitswapRequest) -> BitswapResponse {
        let cid = request.want_cid;
        match self.store.get(&cid) {
            Ok(data) => {
                tracing::debug!(%cid, size = data.len(), "serving chunk from local store");
                BitswapResponse {
                    cid,
                    data,
                    not_found: false,
                }
            }
            Err(StoreError::NotFound(_)) => {
                tracing::debug!(%cid, "chunk not found in local store");
                BitswapResponse {
                    cid,
                    data: Vec::new(),
                    not_found: true,
                }
            }
            Err(e) => {
                tracing::warn!(%cid, error = %e, "error reading from store");
                BitswapResponse {
                    cid,
                    data: Vec::new(),
                    not_found: true,
                }
            }
        }
    }

    /// Handle an incoming Bitswap response. Verifies integrity and
    /// stores the chunk if valid.
    pub fn handle_response(&self, response: BitswapResponse) -> Result<(), StoreError> {
        if response.not_found || response.data.is_empty() {
            return Ok(()); // Nothing to store.
        }

        // Integrity check: verify the data matches the claimed CID.
        let computed = ContentId::of(&response.data);
        if computed != response.cid {
            tracing::warn!(
                expected = %response.cid,
                actual = %computed,
                "received chunk with integrity mismatch — rejecting"
            );
            return Err(StoreError::IntegrityMismatch {
                expected: response.cid,
                actual: computed,
            });
        }

        self.store.put(response.cid, response.data)?;
        tracing::debug!(cid = %response.cid, "stored received chunk");
        Ok(())
    }

    /// Get a reference to the underlying content store.
    pub fn store(&self) -> &Arc<dyn ContentStore> {
        &self.store
    }
}

/// Encode a Bitswap request to bytes.
pub fn encode_request(req: &BitswapRequest) -> Result<Vec<u8>, CodecError> {
    let bytes = bincode::serialize(req).map_err(|e| CodecError::Serialize(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    Ok(bytes)
}

/// Decode a Bitswap request from bytes.
pub fn decode_request(bytes: &[u8]) -> Result<BitswapRequest, CodecError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    bincode::deserialize(bytes).map_err(|e| CodecError::Deserialize(e.to_string()))
}

/// Encode a Bitswap response to bytes.
pub fn encode_response(resp: &BitswapResponse) -> Result<Vec<u8>, CodecError> {
    let bytes = bincode::serialize(resp).map_err(|e| CodecError::Serialize(e.to_string()))?;
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    Ok(bytes)
}

/// Decode a Bitswap response from bytes.
pub fn decode_response(bytes: &[u8]) -> Result<BitswapResponse, CodecError> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        return Err(CodecError::TooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }
    bincode::deserialize(bytes).map_err(|e| CodecError::Deserialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryContentStore;

    #[test]
    fn request_encode_decode_roundtrip() {
        let req = BitswapRequest {
            want_cid: ContentId::of(b"test chunk"),
        };
        let bytes = encode_request(&req).unwrap();
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.want_cid, req.want_cid);
    }

    #[test]
    fn response_encode_decode_roundtrip() {
        let data = b"hello B.U.D. world".to_vec();
        let cid = ContentId::of(&data);
        let resp = BitswapResponse {
            cid,
            data: data.clone(),
            not_found: false,
        };
        let bytes = encode_response(&resp).unwrap();
        let decoded = decode_response(&bytes).unwrap();
        assert_eq!(decoded.cid, cid);
        assert_eq!(decoded.data, data);
        assert!(!decoded.not_found);
    }

    #[test]
    fn not_found_response_roundtrip() {
        let cid = ContentId::of(b"missing");
        let resp = BitswapResponse {
            cid,
            data: Vec::new(),
            not_found: true,
        };
        let bytes = encode_response(&resp).unwrap();
        let decoded = decode_response(&bytes).unwrap();
        assert!(decoded.not_found);
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn handle_request_returns_data_when_present() {
        let store = Arc::new(MemoryContentStore::with_default_capacity());
        let data = b"chunk data for bitswap".to_vec();
        let cid = ContentId::of(&data);
        store.put(cid, data.clone()).unwrap();

        let bitswap = BudBitswap::new(store);
        let resp = bitswap.handle_request(BitswapRequest { want_cid: cid });

        assert!(!resp.not_found);
        assert_eq!(resp.data, data);
        assert_eq!(resp.cid, cid);
    }

    #[test]
    fn handle_request_returns_not_found_when_missing() {
        let store = Arc::new(MemoryContentStore::with_default_capacity());
        let cid = ContentId::of(b"nonexistent chunk");

        let bitswap = BudBitswap::new(store);
        let resp = bitswap.handle_request(BitswapRequest { want_cid: cid });

        assert!(resp.not_found);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn handle_response_stores_valid_chunk() {
        let store = Arc::new(MemoryContentStore::with_default_capacity());
        let bitswap = BudBitswap::new(store.clone());

        let data = b"received chunk data".to_vec();
        let cid = ContentId::of(&data);
        let resp = BitswapResponse {
            cid,
            data,
            not_found: false,
        };

        bitswap.handle_response(resp).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn handle_response_rejects_integrity_mismatch() {
        let store = Arc::new(MemoryContentStore::with_default_capacity());
        let bitswap = BudBitswap::new(store.clone());

        let data = b"tampered data".to_vec();
        let wrong_cid = ContentId::of(b"original data");
        let resp = BitswapResponse {
            cid: wrong_cid,
            data,
            not_found: false,
        };

        let result = bitswap.handle_response(resp);
        assert!(matches!(result, Err(StoreError::IntegrityMismatch { .. })));
        assert!(!store.has(&wrong_cid));
    }

    #[test]
    fn handle_response_ignores_not_found() {
        let store = Arc::new(MemoryContentStore::with_default_capacity());
        let bitswap = BudBitswap::new(store);

        let cid = ContentId::of(b"missing");
        let resp = BitswapResponse {
            cid,
            data: Vec::new(),
            not_found: true,
        };

        // Should not error, just return Ok.
        bitswap.handle_response(resp).unwrap();
    }
}
