//! The `/budlum/witness/1.0.0` protocol.
//!
//! WIRING: wired - `BudlumBehaviour::witness` in `src/network/node.rs` serves
//! and receives it. The serving side answers [`WitnessResponse::NotAvailable`]
//! until the Phase 4 witness storage exists; the receiving side
//! admits witnesses only through [`check_witnesses`], which recomputes the
//! `witness_root` the block header commits. Rules are pinned by this file's
//! tests.
//!
//! A regenerating node holds blocks without their witnesses (a normal node
//! prunes them,). To validate the blocks it grows back through it asks an
//! archive node for the witnesses of one block. A witness is not trusted
//! because a peer sent it: the set must hash to the `witness_root` of the
//! block, so a peer that withholds, swaps or adds a witness is caught and
//! reported.
//!
//! The wire types are plain length-prefixed bytes, bounded on both ends. The
//! root below is the provisional rule of this protocol (`witness_root`);
//! replaces [`witness_root`] with the block header's own function.

use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;
use sha3::{Digest, Sha3_256};

use crate::consensus::merkle_tree::{combine_sha3, merkle_root, promote_sha3};

/// The protocol name.
pub const WITNESS_PROTOCOL: &str = "/budlum/witness/1.0.0";
/// Transactions one request may ask the witnesses of.
pub const MAX_WITNESS_REQUEST_IDS: usize = 1_024;
/// Largest request frame: a height, a count and the ids.
pub const MAX_WITNESS_REQUEST_BYTES: usize = 8 + 4 + MAX_WITNESS_REQUEST_IDS * 32;
/// Largest response frame (the witness budget of a block is 2,000,000 bytes).
pub const MAX_WITNESS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Largest single witness.
pub const MAX_WITNESS_BYTES: usize = 160 * 1024;

/// Ask for the witnesses of some transactions of one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRequest {
    /// The block the transactions are in.
    pub block_height: u64,
    /// The transaction ids, in block order.
    pub tx_ids: Vec<[u8; 32]>,
}

impl WitnessRequest {
    /// The wire form: height, count, ids.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.tx_ids.len() * 32);
        out.extend_from_slice(&self.block_height.to_le_bytes());
        out.extend_from_slice(&(self.tx_ids.len() as u32).to_le_bytes());
        for id in &self.tx_ids {
            out.extend_from_slice(id);
        }
        out
    }

    /// Decode a request; anything malformed or over a bound is `None`.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let block_height = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        let count = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
        if count > MAX_WITNESS_REQUEST_IDS || bytes.len() != 12 + count * 32 {
            return None;
        }
        let tx_ids = bytes[12..]
            .chunks_exact(32)
            .map(|chunk| <[u8; 32]>::try_from(chunk).ok())
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            block_height,
            tx_ids,
        })
    }
}

/// The answer to a [`WitnessRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessResponse {
    /// This node does not hold the witnesses (not an archive node, or no
    /// witness storage yet).
    NotAvailable,
    /// One witness per requested id, in request order.
    Witnesses(Vec<Vec<u8>>),
}

impl WitnessResponse {
    /// The wire form: tag 0, or tag 1 with a count and length-prefixed witnesses.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::NotAvailable => vec![0],
            Self::Witnesses(witnesses) => {
                let mut out = vec![1];
                out.extend_from_slice(&(witnesses.len() as u32).to_le_bytes());
                for witness in witnesses {
                    out.extend_from_slice(&(witness.len() as u32).to_le_bytes());
                    out.extend_from_slice(witness);
                }
                out
            }
        }
    }

    /// Decode a response; anything malformed or over a bound is `None`.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.first()? {
            0 if bytes.len() == 1 => Some(Self::NotAvailable),
            1 => {
                let count = u32::from_le_bytes(bytes.get(1..5)?.try_into().ok()?) as usize;
                if count > MAX_WITNESS_REQUEST_IDS {
                    return None;
                }
                let mut at = 5usize;
                let mut witnesses = Vec::with_capacity(count);
                for _ in 0..count {
                    let len = u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize;
                    at += 4;
                    if len > MAX_WITNESS_BYTES {
                        return None;
                    }
                    witnesses.push(bytes.get(at..at.checked_add(len)?)?.to_vec());
                    at += len;
                }
                (at == bytes.len()).then_some(Self::Witnesses(witnesses))
            }
            _ => None,
        }
    }
}

/// The leaf of one witness: its transaction id and its bytes.
#[must_use]
pub fn witness_leaf(tx_id: &[u8; 32], witness: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_WITNESS_LEAF_V1");
    hasher.update(tx_id);
    hasher.update((witness.len() as u64).to_le_bytes());
    hasher.update(witness);
    hasher.finalize().into()
}

/// The `witness_root` over the witnesses of a block, in block order. An empty
/// block has the root of the empty list, bound under its own tag.
#[must_use]
pub fn witness_root(tx_ids: &[[u8; 32]], witnesses: &[Vec<u8>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = tx_ids
        .iter()
        .zip(witnesses)
        .map(|(id, witness)| witness_leaf(id, witness))
        .collect();
    let root = merkle_root(&leaves, combine_sha3, promote_sha3);
    let mut hasher = Sha3_256::new();
    hasher.update(b"BDLM_WITNESS_ROOT_V1");
    hasher.update((leaves.len() as u64).to_le_bytes());
    hasher.update(root);
    hasher.finalize().into()
}

/// Why a witness response was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessError {
    /// The peer holds no witnesses.
    NotAvailable,
    /// The count differs from the number of ids asked for.
    CountMismatch { asked: usize, got: usize },
    /// The witnesses do not hash to the root the block commits.
    RootMismatch,
}

/// Admit a response only when the witnesses, in request order, hash to the
/// `witness_root` of the block. A short, long, reordered or edited set fails
/// the root.
///
/// # Errors
///
/// [`WitnessError`] naming the refusal.
pub fn check_witnesses(
    request: &WitnessRequest,
    response: &WitnessResponse,
    expected_root: &[u8; 32],
) -> Result<(), WitnessError> {
    let WitnessResponse::Witnesses(witnesses) = response else {
        return Err(WitnessError::NotAvailable);
    };
    if witnesses.len() != request.tx_ids.len() {
        return Err(WitnessError::CountMismatch {
            asked: request.tx_ids.len(),
            got: witnesses.len(),
        });
    }
    if &witness_root(&request.tx_ids, witnesses) != expected_root {
        return Err(WitnessError::RootMismatch);
    }
    Ok(())
}

/// The libp2p codec of the protocol: bounded frames, no more.
#[derive(Debug, Clone, Default)]
pub struct WitnessCodec;

async fn read_bounded<T>(io: &mut T, limit: usize) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(limit as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("witness frame exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

impl request_response::Codec for WitnessCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded(io, MAX_WITNESS_REQUEST_BYTES).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_bounded(io, MAX_WITNESS_RESPONSE_BYTES).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&resp).await?;
        io.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i; 32]).collect()
    }

    fn witnesses(n: u8) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i; 40]).collect()
    }

    #[test]
    fn request_and_response_roundtrip_and_refuse_malformed_frames() {
        let request = WitnessRequest {
            block_height: 77,
            tx_ids: ids(3),
        };
        assert_eq!(
            WitnessRequest::decode(&request.encode()),
            Some(request.clone())
        );
        let mut short = request.encode();
        short.pop();
        assert_eq!(WitnessRequest::decode(&short), None);
        let mut over = vec![0u8; 12];
        over[8..12].copy_from_slice(&((MAX_WITNESS_REQUEST_IDS as u32) + 1).to_le_bytes());
        assert_eq!(WitnessRequest::decode(&over), None);

        let response = WitnessResponse::Witnesses(witnesses(3));
        assert_eq!(
            WitnessResponse::decode(&response.encode()),
            Some(response.clone())
        );
        assert_eq!(
            WitnessResponse::decode(&WitnessResponse::NotAvailable.encode()),
            Some(WitnessResponse::NotAvailable)
        );
        let mut trailing = response.encode();
        trailing.push(0);
        assert_eq!(WitnessResponse::decode(&trailing), None);
        let mut oversize = vec![1u8];
        oversize.extend_from_slice(&1u32.to_le_bytes());
        oversize.extend_from_slice(&((MAX_WITNESS_BYTES as u32) + 1).to_le_bytes());
        assert_eq!(WitnessResponse::decode(&oversize), None);
        assert_eq!(WitnessResponse::decode(&[]), None);
        assert_eq!(WitnessResponse::decode(&[9]), None);
    }

    #[test]
    fn the_witnesses_must_hash_to_the_block_witness_root() {
        let request = WitnessRequest {
            block_height: 5,
            tx_ids: ids(4),
        };
        let honest = witnesses(4);
        let root = witness_root(&request.tx_ids, &honest);
        assert_eq!(
            check_witnesses(&request, &WitnessResponse::Witnesses(honest.clone()), &root),
            Ok(())
        );
        // An edited witness.
        let mut edited = honest.clone();
        edited[2][0] ^= 1;
        assert_eq!(
            check_witnesses(&request, &WitnessResponse::Witnesses(edited), &root),
            Err(WitnessError::RootMismatch)
        );
        // Reordered witnesses.
        let mut swapped = honest.clone();
        swapped.swap(0, 1);
        assert_eq!(
            check_witnesses(&request, &WitnessResponse::Witnesses(swapped), &root),
            Err(WitnessError::RootMismatch)
        );
        // Withheld witness.
        let mut short = honest;
        short.pop();
        assert_eq!(
            check_witnesses(&request, &WitnessResponse::Witnesses(short), &root),
            Err(WitnessError::CountMismatch { asked: 4, got: 3 })
        );
        assert_eq!(
            check_witnesses(&request, &WitnessResponse::NotAvailable, &root),
            Err(WitnessError::NotAvailable)
        );
    }

    #[test]
    fn the_root_binds_the_transaction_ids_and_the_count() {
        let a = witness_root(&ids(2), &witnesses(2));
        let mut other_ids = ids(2);
        other_ids[1] = [9; 32];
        assert_ne!(a, witness_root(&other_ids, &witnesses(2)));
        assert_ne!(a, witness_root(&ids(3), &witnesses(3)));
        assert_ne!(witness_root(&[], &[]), a);
    }
}
