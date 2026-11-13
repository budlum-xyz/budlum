use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
/// Transport block-size ceiling, measured over the **protobuf** encoding.
///
/// Not the same bound as `consensus::MAX_BLOCK_SIZE` (1_000_000 over JSON),
/// which is stricter in both value and encoding. See that constant for the
/// comparison and for why this one must stay the looser of the two.
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;
pub const MAX_TX_SIZE: usize = crate::consensus::budget::MAX_TX_BYTES;
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
        auth_sig: Vec<u8>,
    },

    Precommit {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        voter_id: String,
        sig_bls: Vec<u8>,
        auth_sig: Vec<u8>,
        /// The signer's ML-DSA attestation of the same checkpoint; see
        /// [`crate::chain::finality::Precommit::pq_sig`].
        pq_sig: Vec<u8>,
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

    GetFinalityCert {
        checkpoint_height: u64,
    },

    FinalityCertResponse {
        found: bool,
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
        /// Zero denotes the first chunk (and the legacy two-field request).
        chunk_index: u32,
    },

    QcBlobResponse {
        epoch: u64,
        checkpoint_height: u64,
        checkpoint_hash: String,
        /// One chunk of the binary QC V2 blob. A blob of a thousand
        /// validators is several megabytes and travels as numbered chunks.
        blob_data: Vec<u8>,
        found: bool,
        chunk_index: u32,
        chunk_count: u32,
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
        validate_wire_frame_caps(bytes)?;
        // Only the canonical encoding is accepted. Dedup keys and
        // gossipsub ids hash the raw bytes, but prost skips unknown fields and
        // accepts any field order and overlong varints, so one signed object
        // could be re-wrapped into unlimited byte strings that each look new.
        // The honest encoder is `to_bytes`, which is what the bytes must equal
        // after a decode and a re-encode.
        use prost::Message;
        let proto_msg =
            crate::network::proto_conversions::pb::ProtoNetworkMessage::decode(bytes)
                .map_err(|e| MessageError::ParseError(format!("Protobuf decode error: {e}")))?;
        if proto_msg.encoded_len() != bytes.len() || proto_msg.encode_to_vec() != bytes {
            return Err(MessageError::ParseError(
                "non-canonical protobuf encoding".into(),
            ));
        }
        let message = Self::try_from(proto_msg).map_err(MessageError::ParseError)?;
        // The protobuf can be canonical while its string-valued address is
        // not. Raw gossip IDs hash the bytes; accepting hex case or a 0x
        // prefix lets a single signed vote bypass deduplication and repeatedly
        // trigger expensive BLS checks. Do not count replays as fresh offences:
        // a third party can replay another validator's authenticated vote.
        if let Self::Prevote { voter_id, .. } | Self::Precommit { voter_id, .. } = &message {
            let address = crate::core::address::Address::from_hex(voter_id)
                .map_err(MessageError::ParseError)?;
            if address.to_hex() != voter_id.as_str() {
                return Err(MessageError::ParseError(
                    "non-canonical finality voter address".into(),
                ));
            }
        }
        Ok(message)
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

const MAX_SLASHING_ITEMS_PER_CONTAINER: usize = 64;
const MAX_SLASHING_REPORT_BYTES: usize = 65_536;
const MAX_FRAME_SLASHING_EVIDENCE: usize = 256;
const MAX_SLASHING_EVIDENCE_NESTING: usize = 2;
const MAX_HANDSHAKE_SCHEMES: usize = 64;
const MAX_MULTISIG_ITEMS_WIRE: usize = 64;
const MAX_PRIVATE_TRANSFER_ITEMS_WIRE: usize = 256;
const MAX_EXECUTION_DIMS_WIRE: usize = 64;

fn skip_wire_field(
    buf: &mut &[u8],
    wire_type: prost::encoding::WireType,
) -> Result<(), MessageError> {
    use prost::encoding::{decode_varint, WireType};
    match wire_type {
        WireType::Varint => {
            decode_varint(buf)
                .map_err(|e| MessageError::ParseError(format!("Protobuf varint error: {e}")))?;
            Ok(())
        }
        WireType::SixtyFourBit => {
            *buf = buf.get(8..).ok_or_else(|| {
                MessageError::ParseError("Truncated 64-bit protobuf field".into())
            })?;
            Ok(())
        }
        WireType::ThirtyTwoBit => {
            *buf = buf.get(4..).ok_or_else(|| {
                MessageError::ParseError("Truncated 32-bit protobuf field".into())
            })?;
            Ok(())
        }
        WireType::LengthDelimited => {
            let _ = take_len_delimited(buf, wire_type)?;
            Ok(())
        }
        WireType::StartGroup | WireType::EndGroup => Err(MessageError::ParseError(
            "Deprecated protobuf group wire type refused".into(),
        )),
    }
}

fn take_len_delimited<'a>(
    buf: &mut &'a [u8],
    wire_type: prost::encoding::WireType,
) -> Result<&'a [u8], MessageError> {
    use prost::encoding::{decode_varint, WireType};
    if wire_type != WireType::LengthDelimited {
        return Err(MessageError::ParseError(
            "Expected length-delimited protobuf field".into(),
        ));
    }
    let raw_len = decode_varint(buf)
        .map_err(|e| MessageError::ParseError(format!("Protobuf length varint error: {e}")))?;
    let len = usize::try_from(raw_len)
        .map_err(|_| MessageError::ParseError("Protobuf field length overflow".into()))?;
    if buf.len() < len {
        return Err(MessageError::ParseError(
            "Truncated length-delimited protobuf field".into(),
        ));
    }
    let (head, tail) = buf.split_at(len);
    *buf = tail;
    Ok(head)
}

fn scan_proto_slashing_evidence(
    mut slice: &[u8],
    depth: usize,
    frame_evidence_total: &mut usize,
) -> Result<(), MessageError> {
    if depth > MAX_SLASHING_EVIDENCE_NESTING {
        return Err(MessageError::ParseError(
            "Nested slashing evidence exceeds depth limit".into(),
        ));
    }
    *frame_evidence_total = frame_evidence_total.saturating_add(1);
    if *frame_evidence_total > MAX_FRAME_SLASHING_EVIDENCE {
        return Err(MessageError::ParseError(
            "Frame slashing evidence count exceeds limit".into(),
        ));
    }
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        match tag {
            1 | 2 => {
                let header_bytes = take_len_delimited(&mut slice, wire_type)?;
                if header_bytes.len() > MAX_BLOCK_SIZE {
                    return Err(MessageError::TooLarge(header_bytes.len()));
                }
                scan_proto_block_header(header_bytes, depth, frame_evidence_total)?;
            }
            _ => skip_wire_field(&mut slice, wire_type)?,
        }
    }
    Ok(())
}

fn scan_proto_block_header(
    mut slice: &[u8],
    depth: usize,
    frame_evidence_total: &mut usize,
) -> Result<(), MessageError> {
    let mut evidence_count = 0usize;
    let mut report_count = 0usize;
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        match tag {
            9 => {
                evidence_count = evidence_count.saturating_add(1);
                if evidence_count > MAX_SLASHING_ITEMS_PER_CONTAINER {
                    return Err(MessageError::ParseError(
                        "Too many slashing evidence entries in block header".into(),
                    ));
                }
                let evidence_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_proto_slashing_evidence(
                    evidence_bytes,
                    depth.saturating_add(1),
                    frame_evidence_total,
                )?;
            }
            18 => {
                report_count = report_count.saturating_add(1);
                if report_count > MAX_SLASHING_ITEMS_PER_CONTAINER {
                    return Err(MessageError::ParseError(
                        "Too many slashing reports in block header".into(),
                    ));
                }
                let report_bytes = take_len_delimited(&mut slice, wire_type)?;
                if report_bytes.len() > MAX_SLASHING_REPORT_BYTES {
                    return Err(MessageError::ParseError(
                        "Slashing report entry exceeds size limit".into(),
                    ));
                }
            }
            _ => skip_wire_field(&mut slice, wire_type)?,
        }
    }
    Ok(())
}

fn scan_bounded_repeated_fields(
    mut slice: &[u8],
    watched_tag: u32,
    cap: usize,
    err_msg: &'static str,
) -> Result<(), MessageError> {
    let mut count = 0usize;
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        if tag == watched_tag {
            if watched_tag == 13 && wire_type == prost::encoding::WireType::LengthDelimited {
                let mut packed = take_len_delimited(&mut slice, wire_type)?;
                while !packed.is_empty() {
                    prost::encoding::decode_varint(&mut packed).map_err(|e| {
                        MessageError::ParseError(format!("Protobuf varint error: {e}"))
                    })?;
                    count = count.saturating_add(1);
                    if count > cap {
                        return Err(MessageError::ParseError(err_msg.into()));
                    }
                }
                continue;
            }
            count = count.saturating_add(1);
            if count > cap {
                return Err(MessageError::ParseError(err_msg.into()));
            }
        }
        skip_wire_field(&mut slice, wire_type)?;
    }
    Ok(())
}

fn scan_proto_transaction(mut slice: &[u8]) -> Result<(), MessageError> {
    if slice.len() > MAX_TX_SIZE {
        return Err(MessageError::TooLarge(slice.len()));
    }
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        match tag {
            28 => {
                let sub = take_len_delimited(&mut slice, wire_type)?;
                scan_bounded_repeated_fields(
                    sub,
                    13,
                    MAX_EXECUTION_DIMS_WIRE,
                    "Too many execution_dims in model registration",
                )?;
            }
            44 => {
                let mut sub = take_len_delimited(&mut slice, wire_type)?;
                let mut spent_count = 0usize;
                let mut nullifier_count = 0usize;
                let mut output_count = 0usize;
                let mut proof_count = 0usize;
                while !sub.is_empty() {
                    let (inner_tag, inner_wire) =
                        prost::encoding::decode_key(&mut sub).map_err(|e| {
                            MessageError::ParseError(format!("Protobuf key error: {e}"))
                        })?;
                    let bucket = match inner_tag {
                        1 => Some(&mut spent_count),
                        2 => Some(&mut nullifier_count),
                        3 => Some(&mut output_count),
                        6 => Some(&mut proof_count),
                        _ => None,
                    };
                    if let Some(counter) = bucket {
                        *counter = counter.saturating_add(1);
                        if *counter > MAX_PRIVATE_TRANSFER_ITEMS_WIRE {
                            return Err(MessageError::ParseError(
                                "Too many entries in private transfer payload".into(),
                            ));
                        }
                    }
                    skip_wire_field(&mut sub, inner_wire)?;
                }
            }
            50 => {
                let mut sub = take_len_delimited(&mut slice, wire_type)?;
                let mut owner_count = 0usize;
                let mut sig_count = 0usize;
                while !sub.is_empty() {
                    let (inner_tag, inner_wire) =
                        prost::encoding::decode_key(&mut sub).map_err(|e| {
                            MessageError::ParseError(format!("Protobuf key error: {e}"))
                        })?;
                    match inner_tag {
                        1 => {
                            owner_count = owner_count.saturating_add(1);
                            if owner_count > MAX_MULTISIG_ITEMS_WIRE {
                                return Err(MessageError::ParseError(
                                    "Too many multisig owners in authorization".into(),
                                ));
                            }
                        }
                        3 => {
                            sig_count = sig_count.saturating_add(1);
                            if sig_count > MAX_MULTISIG_ITEMS_WIRE {
                                return Err(MessageError::ParseError(
                                    "Too many multisig signatures in authorization".into(),
                                ));
                            }
                        }
                        _ => {}
                    }
                    skip_wire_field(&mut sub, inner_wire)?;
                }
            }
            51 => {
                let sub = take_len_delimited(&mut slice, wire_type)?;
                scan_bounded_repeated_fields(
                    sub,
                    3,
                    crate::consensus::MAX_TRANSACTIONS_PER_BLOCK,
                    "Too many state_updates in settlement transaction",
                )?;
            }
            _ => skip_wire_field(&mut slice, wire_type)?,
        }
    }
    Ok(())
}

fn scan_proto_block(
    mut slice: &[u8],
    frame_evidence_total: &mut usize,
) -> Result<(), MessageError> {
    if slice.len() > MAX_BLOCK_SIZE {
        return Err(MessageError::TooLarge(slice.len()));
    }
    let mut evidence_count = 0usize;
    let mut report_count = 0usize;
    let mut tx_count = 0usize;
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        match tag {
            5 => {
                tx_count = tx_count.saturating_add(1);
                if tx_count > crate::consensus::MAX_TRANSACTIONS_PER_BLOCK {
                    return Err(MessageError::ParseError(
                        "Too many transactions in block".into(),
                    ));
                }
                let tx_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_proto_transaction(tx_bytes)?;
            }
            11 => {
                evidence_count = evidence_count.saturating_add(1);
                if evidence_count > MAX_SLASHING_ITEMS_PER_CONTAINER {
                    return Err(MessageError::ParseError(
                        "Too many slashing evidence entries in block".into(),
                    ));
                }
                let evidence_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_proto_slashing_evidence(evidence_bytes, 1, frame_evidence_total)?;
            }
            22 => {
                report_count = report_count.saturating_add(1);
                if report_count > MAX_SLASHING_ITEMS_PER_CONTAINER {
                    return Err(MessageError::ParseError(
                        "Too many slashing reports in block".into(),
                    ));
                }
                let report_bytes = take_len_delimited(&mut slice, wire_type)?;
                if report_bytes.len() > MAX_SLASHING_REPORT_BYTES {
                    return Err(MessageError::ParseError(
                        "Slashing report entry exceeds size limit".into(),
                    ));
                }
            }
            _ => skip_wire_field(&mut slice, wire_type)?,
        }
    }
    Ok(())
}

fn validate_wire_frame_caps(mut slice: &[u8]) -> Result<(), MessageError> {
    let mut frame_evidence_total = 0usize;
    while !slice.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut slice)
            .map_err(|e| MessageError::ParseError(format!("Protobuf key error: {e}")))?;
        match tag {
            1 | 2 => {
                let hs_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_bounded_repeated_fields(
                    hs_bytes,
                    6,
                    MAX_HANDSHAKE_SCHEMES,
                    "Handshake supported_schemes exceeds limit",
                )?;
            }
            3 => {
                let block_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_proto_block(block_bytes, &mut frame_evidence_total)?;
            }
            4 => {
                let tx_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_proto_transaction(tx_bytes)?;
            }
            5 => {
                let req_bytes = take_len_delimited(&mut slice, wire_type)?;
                scan_bounded_repeated_fields(
                    req_bytes,
                    1,
                    MAX_HEADER_LOCATOR_HASHES,
                    "GetHeaders locator exceeds the limit",
                )?;
            }
            6 => {
                let mut batch_payload = take_len_delimited(&mut slice, wire_type)?;
                let mut header_count = 0usize;
                while !batch_payload.is_empty() {
                    let (inner_tag, inner_wire) = prost::encoding::decode_key(&mut batch_payload)
                        .map_err(|e| {
                        MessageError::ParseError(format!("Protobuf key error: {e}"))
                    })?;
                    if inner_tag == 1 {
                        header_count = header_count.saturating_add(1);
                        if header_count > MAX_HEADERS_PER_REQUEST as usize {
                            return Err(MessageError::ParseError(format!(
                                "header batch exceeds {MAX_HEADERS_PER_REQUEST}"
                            )));
                        }
                        let header_bytes = take_len_delimited(&mut batch_payload, inner_wire)?;
                        if header_bytes.len() > MAX_BLOCK_SIZE {
                            return Err(MessageError::TooLarge(header_bytes.len()));
                        }
                        scan_proto_block_header(header_bytes, 0, &mut frame_evidence_total)?;
                    } else {
                        skip_wire_field(&mut batch_payload, inner_wire)?;
                    }
                }
            }
            8 | 10 => {
                let mut batch_payload = take_len_delimited(&mut slice, wire_type)?;
                let mut block_count = 0usize;
                while !batch_payload.is_empty() {
                    let (inner_tag, inner_wire) = prost::encoding::decode_key(&mut batch_payload)
                        .map_err(|e| {
                        MessageError::ParseError(format!("Protobuf key error: {e}"))
                    })?;
                    if inner_tag == 1 {
                        block_count = block_count.saturating_add(1);
                        if block_count > MAX_CHAIN_SYNC_BLOCKS {
                            return Err(MessageError::ParseError(format!(
                                "block batch exceeds {MAX_CHAIN_SYNC_BLOCKS}"
                            )));
                        }
                        let block_bytes = take_len_delimited(&mut batch_payload, inner_wire)?;
                        scan_proto_block(block_bytes, &mut frame_evidence_total)?;
                    } else {
                        skip_wire_field(&mut batch_payload, inner_wire)?;
                    }
                }
            }
            25 => {
                let evidence_bytes = take_len_delimited(&mut slice, wire_type)?;
                if evidence_bytes.len() > MAX_BLOCK_SIZE {
                    return Err(MessageError::TooLarge(evidence_bytes.len()));
                }
                scan_proto_slashing_evidence(evidence_bytes, 1, &mut frame_evidence_total)?;
            }
            _ => skip_wire_field(&mut slice, wire_type)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An appended unknown field decodes to the same message but is
    /// not the canonical encoding, so the validated entry point refuses it.
    #[test]
    fn a_non_canonical_encoding_of_a_valid_message_is_refused() {
        let msg = NetworkMessage::GetHeaders {
            locator: vec!["00".repeat(32)],
            limit: 10,
        };
        let bytes = msg.to_bytes();
        assert!(NetworkMessage::from_bytes_validated(&bytes).is_ok());
        let mut padded = bytes.clone();
        // field 99, varint 1: unknown to the schema, skipped by prost.
        // (Field 15, the old choice, became `prevote` - a known
        // length-delimited field - so it no longer decodes leniently.)
        padded.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(NetworkMessage::from_bytes(&padded).is_ok());
        assert!(NetworkMessage::from_bytes_validated(&padded).is_err());
    }

    #[test]
    fn finality_votes_require_canonical_voter_ids_before_verification() {
        let canonical = "ab".repeat(32);
        for voter_id in [
            canonical.clone(),
            canonical.to_uppercase(),
            format!("0x{canonical}"),
        ] {
            for is_precommit in [false, true] {
                let message = if is_precommit {
                    NetworkMessage::Precommit {
                        epoch: 1,
                        checkpoint_height: 10,
                        checkpoint_hash: "cd".repeat(32),
                        voter_id: voter_id.clone(),
                        sig_bls: vec![1; 48],
                        auth_sig: vec![2; 48],
                        pq_sig: vec![3; 16],
                    }
                } else {
                    NetworkMessage::Prevote {
                        epoch: 1,
                        checkpoint_height: 10,
                        checkpoint_hash: "cd".repeat(32),
                        voter_id: voter_id.clone(),
                        sig_bls: vec![1; 48],
                        auth_sig: vec![2; 48],
                    }
                };
                let bytes = message.to_bytes();
                assert!(NetworkMessage::from_bytes(&bytes).is_ok());
                assert_eq!(
                    NetworkMessage::from_bytes_validated(&bytes).is_ok(),
                    voter_id == canonical
                );
            }
        }
    }

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

    /// The transport bound must stay looser than the consensus bound.
    ///
    /// Two constants share the name `MAX_BLOCK_SIZE` and measure different
    /// things: this one is protobuf `encoded_len`, `consensus::MAX_BLOCK_SIZE`
    /// is `serde_json::to_vec`. JSON is the fatter encoding and carries the
    /// smaller ceiling, so consensus is always the binding check, a block that
    /// clears gossip can still be refused by validation, and never the reverse.
    ///
    /// That ordering is what keeps the network from admitting blocks every
    /// validator then rejects, wasting bandwidth on gossip that cannot be
    /// applied. It holds because of the current numbers, not because of
    /// anything in the design, so it is asserted here.
    ///
    /// Canary: lower this constant below 1_000_000 and the assertion fails.
    #[test]
    fn transport_block_ceiling_is_not_stricter_than_consensus() {
        // Both sides are `const`, so this is decidable at compile time. In a
        // `const` block it fails the build rather than a test run, the
        // strictly better place for an invariant over two literals, and what
        // `clippy::assertions_on_constants` is pointing at.
        const {
            assert!(
                MAX_BLOCK_SIZE >= crate::consensus::MAX_BLOCK_SIZE,
                "transport ceiling is below the consensus ceiling: gossip would \
                 refuse blocks that validation accepts, and honest producers \
                 could not propagate them"
            );
        }
        // And they are genuinely different bounds, not an accidental
        // duplicate: if someone unifies them, the encodings have to be
        // reconciled first.
        const {
            assert!(
                MAX_BLOCK_SIZE != crate::consensus::MAX_BLOCK_SIZE,
                "the two ceilings became equal; they measure different \
                 encodings (protobuf here, JSON in consensus), so equal values \
                 mean one of the two checks is now the wrong shape"
            );
        }
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
        let first = Block::new_with_chain_id(1, "00".repeat(32), Vec::new(), 45262);
        let second = Block::new_with_chain_id(2, first.hash.clone(), Vec::new(), 45262);
        let headers = vec![
            BlockHeader::from_block(&first),
            BlockHeader::from_block(&second),
        ];
        assert!(NetworkMessage::validate_header_batch(&headers, 45262).is_ok());

        let mut wrong_chain = headers.clone();
        wrong_chain[1].chain_id = 42;
        assert!(NetworkMessage::validate_header_batch(&wrong_chain, 45262).is_err());

        let mut disconnected = headers;
        disconnected[1].previous_hash = "11".repeat(32);
        disconnected[1].hash = disconnected[1].calculate_hash();
        assert!(NetworkMessage::validate_header_batch(&disconnected, 45262).is_err());
    }

    #[test]
    fn unbounded_slashing_evidence_wire_frame_is_refused() {
        // Build a raw ProtoNetworkMessage (field 3 = ProtoBlock, wire type 2)
        // carrying 65 minimal ProtoSlashingEvidence entries (field 11, 2 wire bytes each).
        let mut proto_block = Vec::with_capacity(65 * 2);
        for _ in 0..65 {
            // tag 11 (11 << 3 | 2 = 0x5a), length 0
            proto_block.extend_from_slice(&[0x5a, 0x00]);
        }
        let mut frame = Vec::new();
        // outer tag 3 (3 << 3 | 2 = 0x1a)
        frame.push(0x1a);
        prost::encoding::encode_varint(proto_block.len() as u64, &mut frame);
        frame.extend_from_slice(&proto_block);

        assert!(matches!(
            NetworkMessage::from_bytes_validated(&frame),
            Err(MessageError::ParseError(msg)) if msg.contains("Too many slashing evidence")
        ));

        // Nested recursive ProtoSlashingEvidence exceeding MAX_SLASHING_EVIDENCE_NESTING is also refused.
        // Inner ProtoSlashingEvidence: empty (0 bytes) -> wrapped in header1 (field 9 = 0x4a, len 0) -> ...
        let mut inner_payload = Vec::new();
        for _ in 0..4 {
            // Wrap current evidence inside a ProtoBlockHeader's field 9 (0x4a)
            let mut wrapped_header = Vec::new();
            wrapped_header.push(0x4a);
            prost::encoding::encode_varint(inner_payload.len() as u64, &mut wrapped_header);
            wrapped_header.extend_from_slice(&inner_payload);
            // Wrap header inside a ProtoSlashingEvidence's field 1 (0x0a)
            let mut wrapped_evidence = Vec::new();
            wrapped_evidence.push(0x0a);
            prost::encoding::encode_varint(wrapped_header.len() as u64, &mut wrapped_evidence);
            wrapped_evidence.extend_from_slice(&wrapped_header);
            inner_payload = wrapped_evidence;
        }
        let mut nested_frame = Vec::new();
        // outer tag 25 (25 << 3 | 2 = 0xca, 0x01)
        prost::encoding::encode_key(
            25,
            prost::encoding::WireType::LengthDelimited,
            &mut nested_frame,
        );
        prost::encoding::encode_varint(inner_payload.len() as u64, &mut nested_frame);
        nested_frame.extend_from_slice(&inner_payload);

        assert!(matches!(
            NetworkMessage::from_bytes_validated(&nested_frame),
            Err(MessageError::ParseError(msg)) if msg.contains("depth limit")
        ));
    }

    #[test]
    fn unbounded_block_transactions_and_batch_wire_frames_are_refused() {
        let cap = crate::consensus::MAX_TRANSACTIONS_PER_BLOCK;

        // A block at the exact MAX_TRANSACTIONS_PER_BLOCK wire budget passes pre-decode scanning.
        let mut at_budget_block = Vec::with_capacity(cap * 2);
        for _ in 0..cap {
            // ProtoBlock field 5 (transactions): 5 << 3 | 2 = 0x2a, len 0
            at_budget_block.extend_from_slice(&[0x2a, 0x00]);
        }
        let mut at_budget_frame = Vec::new();
        at_budget_frame.push(0x1a);
        prost::encoding::encode_varint(at_budget_block.len() as u64, &mut at_budget_frame);
        at_budget_frame.extend_from_slice(&at_budget_block);
        assert!(validate_wire_frame_caps(&at_budget_frame).is_ok());

        // One extra empty transaction entry (cap + 1) is refused before prost allocates.
        let mut over_budget_block = at_budget_block;
        over_budget_block.extend_from_slice(&[0x2a, 0x00]);
        let mut over_budget_frame = Vec::new();
        over_budget_frame.push(0x1a);
        prost::encoding::encode_varint(over_budget_block.len() as u64, &mut over_budget_frame);
        over_budget_frame.extend_from_slice(&over_budget_block);
        assert!(matches!(
            NetworkMessage::from_bytes_validated(&over_budget_frame),
            Err(MessageError::ParseError(msg)) if msg.contains("Too many transactions in block")
        ));

        // A ProtoBlocks batch (outer tag 8 = 0x42) exceeding MAX_CHAIN_SYNC_BLOCKS is also refused.
        let mut batch_payload = Vec::new();
        for _ in 0..=MAX_CHAIN_SYNC_BLOCKS {
            // ProtoBlocks field 1 (blocks): 1 << 3 | 2 = 0x0a, len 0
            batch_payload.extend_from_slice(&[0x0a, 0x00]);
        }
        let mut batch_frame = Vec::new();
        batch_frame.push(0x42);
        prost::encoding::encode_varint(batch_payload.len() as u64, &mut batch_frame);
        batch_frame.extend_from_slice(&batch_payload);
        assert!(matches!(
            NetworkMessage::from_bytes_validated(&batch_frame),
            Err(MessageError::ParseError(msg)) if msg.contains("block batch exceeds")
        ));
    }
}
