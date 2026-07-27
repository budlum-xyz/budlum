use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;
pub const MAX_TX_SIZE: usize = 100 * 1024;
/// Maximum number of full blocks returned in one range-sync response.
///
/// This is derived from the transport frame ceiling instead of being an
/// Independent large number: a peer can request worst-case `MAX_BLOCK_SIZE`
/// Blocks, and the response still must fit under `MAX_MESSAGE_SIZE` with
/// Headroom for protobuf framing.
pub const MAX_CHAIN_SYNC_BLOCKS: usize = (MAX_MESSAGE_SIZE / MAX_BLOCK_SIZE).saturating_sub(1);
pub const MAX_HEADERS_PER_REQUEST: u32 = 2000;
pub const MAX_HEADER_LOCATOR_HASHES: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum MessageError {
    TooLarge(usize),
    ParseError(String),
    VersionMismatch { expected: u32, got: u32 },
}

/// Snapshot block batches share the same `BlocksByHeight` transport envelope,
/// So keep them no larger than range-sync block batches.
pub const MAX_SNAP_BATCH: u64 = MAX_CHAIN_SYNC_BLOCKS as u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Handshake {
        version_major: u32,
        version_minor: u32,
        chain_id: u64,
        best_height: u64,
        validator_set_hash: String,
        supported_schemes: Vec<String>,
    },
    HandshakeAck {
        version_major: u32,
        version_minor: u32,
        chain_id: u64,
        best_height: u64,
        validator_set_hash: String,
        supported_schemes: Vec<String>,
    },

    Block(Block),
    Transaction(Transaction),

    GetHeaders {
        locator: Vec<String>,
        limit: u32,
    },

    Headers(Vec<BlockHeader>),

    GetBlocksRange {
        from: u64,
        to: u64,
    },

    Blocks(Vec<Block>),

    GetBlocksByHeight {
        from_height: u64,
        to_height: u64,
    },

    BlocksByHeight(Vec<Block>),

    StateSnapshotResponse {
        height: u64,
        state_root: String,
        ok: bool,
    },

    NewTip {
        height: u64,
        hash: String,
    },

    GetStateSnapshot {
        height: u64,
    },

    SnapshotChunk {
        height: u64,
        index: u32,
        total: u32,
        data: Vec<u8>,
        session_id: u64,
    },

    Prevote {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: String,
        sig_bls: Vec<u8>,
    },

    Precommit {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: String,
        sig_bls: Vec<u8>,
    },

    FinalityCert {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        agg_sig_bls: Vec<u8>,
        bitmap: Vec<u8>,
        set_hash: String,
        scheme_id: String,
    },

    GetQcBlob {
        epoch: u64,
        checkpoint_height: u64,
    },

    QcBlobResponse {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        blob_data: Vec<u8>,
        found: bool,
    },

    QcFaultProof {
        proof_data: Vec<u8>,
    },

    DomainCommitment(crate::domain::DomainCommitment),
    VerifiedDomainCommitment(crate::domain::VerifiedDomainCommitment),
    SlashingEvidence(crate::consensus::pos::SlashingEvidence),
    GlobalHeader(crate::settlement::GlobalBlockHeader),
    CrossDomainMessage(crate::cross_domain::CrossDomainMessage),
}
impl NetworkMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        use prost::Message;
        let proto_msg = crate::network::proto_conversions::pb::ProtoNetworkMessage::from(self);
        proto_msg.encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        use prost::Message;
        let proto_msg = crate::network::proto_conversions::pb::ProtoNetworkMessage::decode(bytes)
            .map_err(|e| format!("Protobuf decode error: {e}"))?;
        Self::try_from(proto_msg)
    }

    pub fn from_bytes_validated(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(MessageError::TooLarge(bytes.len()));
        }
        Self::from_bytes(bytes).map_err(MessageError::ParseError)
    }

    pub fn validate_block_size(block: &Block) -> Result<(), MessageError> {
        use prost::Message;
        let proto_block = crate::network::proto_conversions::pb::ProtoBlock::from(block);
        let size = proto_block.encoded_len();
        if size > MAX_BLOCK_SIZE {
            return Err(MessageError::TooLarge(size));
        }
        Ok(())
    }

    pub fn validate_tx_size(tx: &Transaction) -> Result<(), MessageError> {
        use prost::Message;
        let proto_tx = crate::network::proto_conversions::pb::ProtoTransaction::from(tx);
        let size = proto_tx.encoded_len();
        if size > MAX_TX_SIZE {
            return Err(MessageError::TooLarge(size));
        }
        Ok(())
    }

    pub fn validate_header_request(locator: &[String], limit: u32) -> Result<(), MessageError> {
        if limit == 0 || limit > MAX_HEADERS_PER_REQUEST {
            return Err(MessageError::ParseError(format!(
                "header request limit must be within 1..={MAX_HEADERS_PER_REQUEST}, got {limit}"
            )));
        }
        if locator.len() > MAX_HEADER_LOCATOR_HASHES {
            return Err(MessageError::ParseError(format!(
                "header locator count exceeds {MAX_HEADER_LOCATOR_HASHES}"
            )));
        }
        if locator.iter().any(|hash| !is_canonical_hash(hash)) {
            return Err(MessageError::ParseError(
                "header locator contains a non-canonical hash".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_header_batch(
        headers: &[BlockHeader],
        expected_chain_id: u64,
    ) -> Result<(), MessageError> {
        if headers.len() > MAX_HEADERS_PER_REQUEST as usize {
            return Err(MessageError::ParseError(format!(
                "header batch exceeds {MAX_HEADERS_PER_REQUEST}"
            )));
        }
        for header in headers {
            if header.chain_id != expected_chain_id {
                return Err(MessageError::ParseError(
                    "header batch chain_id mismatch".into(),
                ));
            }
            if !is_canonical_hash(&header.hash)
                || !is_canonical_hash(&header.previous_hash)
                || header.hash != header.calculate_hash()
            {
                return Err(MessageError::ParseError(
                    "header batch contains an invalid hash".into(),
                ));
            }
        }
        for pair in headers.windows(2) {
            if pair[1].index != pair[0].index.saturating_add(1)
                || pair[1].previous_hash != pair[0].hash
            {
                return Err(MessageError::ParseError(
                    "header batch is not contiguous and parent-linked".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn is_canonical_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_sync_batch_fits_one_transport_frame_at_worst_case_block_size() {
        // Compile-time guards: these are consts, so a runtime assert! would be a
        // Tautology clippy rejects. const blocks keep the regression guard and
        // Fail the build (not the test run) if the constants ever drift.
        const _: () = assert!(MAX_CHAIN_SYNC_BLOCKS > 0);
        const _: () = assert!(
            MAX_CHAIN_SYNC_BLOCKS * MAX_BLOCK_SIZE < MAX_MESSAGE_SIZE,
            "range-sync worst-case payload must stay below one transport frame"
        );
        assert_eq!(MAX_SNAP_BATCH, MAX_CHAIN_SYNC_BLOCKS as u64);
    }

    #[test]
    fn header_request_rejects_unbounded_or_malformed_input() {
        assert!(NetworkMessage::validate_header_request(&[], 1).is_ok());
        assert!(NetworkMessage::validate_header_request(&[], 0).is_err());
        assert!(NetworkMessage::validate_header_request(&[], MAX_HEADERS_PER_REQUEST + 1).is_err());
        assert!(NetworkMessage::validate_header_request(&["short".into()], 1).is_err());
        assert!(NetworkMessage::validate_header_request(
            &vec!["00".repeat(32); MAX_HEADER_LOCATOR_HASHES + 1],
            1,
        )
        .is_err());
    }

    #[test]
    fn header_batch_must_be_hash_valid_parent_linked_and_same_chain() {
        let first = Block::new_with_chain_id(1, "00".repeat(32), Vec::new(), 1337);
        let second = Block::new_with_chain_id(2, first.hash.clone(), Vec::new(), 1337);
        let headers = vec![
            BlockHeader::from_block(&first),
            BlockHeader::from_block(&second),
        ];
        assert!(NetworkMessage::validate_header_batch(&headers, 1337).is_ok());

        let mut wrong_chain = headers.clone();
        wrong_chain[1].chain_id = 42;
        assert!(NetworkMessage::validate_header_batch(&wrong_chain, 1337).is_err());

        let mut disconnected = headers;
        disconnected[1].previous_hash = "11".repeat(32);
        disconnected[1].hash = disconnected[1].calculate_hash();
        assert!(NetworkMessage::validate_header_batch(&disconnected, 1337).is_err());
    }
}
