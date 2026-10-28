//! The one EVM log shape a contract uses to speak to Budlum, and its
//! translation into a cross-domain message (,,
//!).
//!
//! `contracts/lib/BudlumOutbound.sol` declares
//!
//! ```text
//! event BudlumOutbound(bytes kind, bytes32 indexed recipient,
//!                      bytes32 indexed correlationId, bytes32 payloadHash)
//! ```
//!
//! and `GraftExecutor`, `BudlumGraftClaimer` and `BudlumRegistrar` emit it.
//! A domain reporter puts the message built here into the domain's event
//! tree; Budlum accepts it only once that tree's root reaches the external
//! root it anchored for the domain. The emitter becomes the message sender,
//! right-aligned in a 32-byte word (`settlement::graft::origin_emitter`), so
//! a contract can only ever speak as itself.

use crate::core::address::Address;
use crate::cross_domain::evm::receipt::EthLog;
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};
use sha3::{Digest, Keccak256};

/// The event signature.
/// WIRING: cross-domain surface - the relayer/bridge doors that read it land with their wiring wave.
pub const OUTBOUND_EVENT_SIGNATURE: &str = "BudlumOutbound(bytes,bytes32,bytes32,bytes32)";
/// Longest `kind` a log may carry.
/// WIRING: cross-domain surface - the relayer/bridge doors that read it land with their wiring wave.
pub const MAX_OUTBOUND_KIND_BYTES: usize = 128;

/// `topic0` of the outbound event.
#[must_use]
/// WIRING: cross-domain surface - the relayer/bridge doors that read it land with their wiring wave.
pub fn outbound_topic0() -> [u8; 32] {
    Keccak256::digest(OUTBOUND_EVENT_SIGNATURE.as_bytes()).into()
}

/// Where a message built from a log sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: cross-domain surface - the relayer/bridge doors that read it land with their wiring wave.
pub struct OutboundPosition {
    /// The Budlum domain id of the EVM chain.
    pub source_domain: u32,
    /// The Budlum domain the message is for (the settlement chain).
    pub target_domain: u32,
    /// The EVM block height of the log.
    pub source_height: u64,
    /// The log's index among the domain's events at that height.
    pub event_index: u32,
    /// The message nonce the reporter assigns.
    pub nonce: u64,
    /// Zero for no expiry.
    pub expiry_height: u64,
}

/// Why a log is not an outbound message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
/// WIRING: cross-domain surface - the relayer/bridge doors that read it land with their wiring wave.
pub enum OutboundError {
    #[error("the log is not a BudlumOutbound event")]
    NotOutbound,
    #[error("the emitter is not a 20-byte address")]
    Emitter,
    #[error("the log data is not abi.encode(bytes, bytes32): {0}")]
    Data(&'static str),
    #[error("the kind is empty or longer than {MAX_OUTBOUND_KIND_BYTES} bytes")]
    Kind,
}

fn word(data: &[u8], index: usize) -> Result<[u8; 32], OutboundError> {
    let start = index.checked_mul(32).ok_or(OutboundError::Data("offset"))?;
    data.get(start..start + 32)
        .and_then(|w| <[u8; 32]>::try_from(w).ok())
        .ok_or(OutboundError::Data("short"))
}

fn word_as_usize(w: &[u8; 32]) -> Result<usize, OutboundError> {
    if w[..24].iter().any(|b| *b != 0) {
        return Err(OutboundError::Data("number too large"));
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&w[24..]);
    usize::try_from(u64::from_be_bytes(low)).map_err(|_| OutboundError::Data("number too large"))
}

/// Build the cross-domain message of one outbound log.
///
/// # Errors
///
/// [`OutboundError`] when the log is not exactly the outbound event.
/// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
pub fn message_from_log(
    log: &EthLog,
    position: OutboundPosition,
) -> Result<CrossDomainMessage, OutboundError> {
    if log.topics.len() != 3 || log.topics[0] != outbound_topic0() {
        return Err(OutboundError::NotOutbound);
    }
    let emitter: [u8; 20] = log
        .address
        .as_slice()
        .try_into()
        .map_err(|_| OutboundError::Emitter)?;
    // abi.encode(bytes kind, bytes32 payloadHash): head [offset, hash],
    // tail [len, kind padded to 32].
    let data = &log.data;
    let offset = word_as_usize(&word(data, 0)?)?;
    if offset != 64 {
        return Err(OutboundError::Data("kind offset"));
    }
    let payload_hash = word(data, 1)?;
    let len = word_as_usize(&word(data, 2)?)?;
    if len == 0 || len > MAX_OUTBOUND_KIND_BYTES {
        return Err(OutboundError::Kind);
    }
    let padded = len.div_ceil(32) * 32;
    if data.len() != 96 + padded {
        return Err(OutboundError::Data("length"));
    }
    let kind = data[96..96 + len].to_vec();
    if data[96 + len..].iter().any(|b| *b != 0) {
        return Err(OutboundError::Data("padding"));
    }
    let correlation = log.topics[2];
    let params = CrossDomainMessageParams {
        source_domain: position.source_domain,
        target_domain: position.target_domain,
        source_height: position.source_height,
        event_index: position.event_index,
        nonce: position.nonce,
        sender: crate::settlement::graft::origin_emitter(&emitter),
        recipient: Address::from(log.topics[1]),
        payload_hash,
        kind: MessageKind::Custom(kind),
        expiry_height: position.expiry_height,
    };
    Ok(if correlation == [0u8; 32] {
        CrossDomainMessage::new(params)
    } else {
        CrossDomainMessage::new_correlated(params, correlation)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position() -> OutboundPosition {
        OutboundPosition {
            source_domain: 11,
            target_domain: 1,
            source_height: 100,
            event_index: 0,
            nonce: 0,
            expiry_height: 0,
        }
    }

    fn encoded(kind: &[u8], payload: [u8; 32]) -> Vec<u8> {
        let mut data = vec![0u8; 32];
        data[31] = 64;
        data.extend_from_slice(&payload);
        let mut len = [0u8; 32];
        len[31] = u8::try_from(kind.len()).expect("short kind");
        data.extend_from_slice(&len);
        let mut tail = kind.to_vec();
        tail.resize(kind.len().div_ceil(32) * 32, 0);
        data.extend_from_slice(&tail);
        data
    }

    fn log(kind: &[u8]) -> EthLog {
        EthLog {
            address: vec![0xEE; 20],
            topics: vec![outbound_topic0(), [0x02; 32], [0x03; 32]],
            data: encoded(kind, [0x04; 32]),
        }
    }

    #[test]
    fn an_outbound_log_becomes_the_message_the_doors_check() {
        let message =
            message_from_log(&log(b"budlum/mikoriza/allocation/v1"), position()).expect("decodes");
        assert_eq!(
            message.sender,
            crate::settlement::graft::origin_emitter(&[0xEE; 20])
        );
        assert_eq!(message.recipient, Address::from([0x02; 32]));
        assert_eq!(message.correlation_id, Some([0x03; 32]));
        assert_eq!(message.payload_hash, [0x04; 32]);
        assert_eq!(
            message.kind,
            MessageKind::Custom(b"budlum/mikoriza/allocation/v1".to_vec())
        );
        assert!(message.verify_id());
    }

    #[test]
    fn another_event_or_a_malformed_body_is_refused() {
        let mut other = log(b"k");
        other.topics[0] = [0x09; 32];
        assert_eq!(
            message_from_log(&other, position()),
            Err(OutboundError::NotOutbound)
        );
        let mut trailing = log(b"k");
        trailing.data.push(0);
        assert!(message_from_log(&trailing, position()).is_err());
        let mut dirty = log(b"k");
        let last = dirty.data.len() - 1;
        dirty.data[last] = 1;
        assert!(message_from_log(&dirty, position()).is_err());
    }
}
