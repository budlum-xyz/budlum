//! Ethereum receipt decode + deposit-log matching (F10.2).
//!
//! Receipt envelope types (EIP-658/2481/2930/1559/4844):
//! - **Legacy** (`envelope[0] >= 0xc0`): whole bytes = `rlp([status_or_postState,
//!   cumulativeGasUsed, logsBloom(256), logs])`.
//! - **Typed** (`envelope[0] in 0x00..=0x7f`): `[type_byte] ++ rlp([status,
//!   cumulativeGasUsed, logsBloom(256), logs [, accessList]])`. Types: 0x01
//!   (EIP-2930), 0x02 (EIP-1559), 0x03 (EIP-4844).
//!
//! Bridge doğrulaması için yalnızca `status` (success) ve `logs` (deposit event)
//! gerekir; `logsBloom`/`cumulativeGasUsed`/`accessList` doğrulamada kullanılmaz
//! (decode edilir ama yok sayılır).

use crate::cross_domain::evm::rlp::{self, Item, RlpError};

/// Decode edilen bir Ethereum log girdisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthLog {
    /// Emitter contract address (20 bytes).
    pub address: Vec<u8>,
    /// Indexed topics (her biri 32 byte).
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed data payload.
    pub data: Vec<u8>,
}

/// Decode edilen Ethereum receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthReceipt {
    /// `true` = işlem başarılı (status=1 post-Byzantium; pre-Byzantium varsayılan success).
    pub status: bool,
    /// İşlem log'ları (deposit event aranır).
    pub logs: Vec<EthLog>,
}

/// Receipt decode hatası.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Rlp(RlpError),
    /// Geçersiz envelope yapısı (bilinmeyen tip / yanlış alan sayısı).
    InvalidEnvelope,
    /// Geçersiz log yapısı (alan sayısı / topic boyutu).
    InvalidLog,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::Rlp(e) => write!(f, "receipt rlp error: {e}"),
            ReceiptError::InvalidEnvelope => write!(f, "receipt: invalid envelope"),
            ReceiptError::InvalidLog => write!(f, "receipt: invalid log"),
        }
    }
}

impl std::error::Error for ReceiptError {}

impl From<RlpError> for ReceiptError {
    fn from(e: RlpError) -> Self {
        ReceiptError::Rlp(e)
    }
}

/// Ham envelope byte'larını receipt'e decode eder (typed + legacy destek).
pub fn decode_receipt(envelope: &[u8]) -> Result<EthReceipt, ReceiptError> {
    if envelope.is_empty() {
        return Err(ReceiptError::InvalidEnvelope);
    }
    let first = envelope[0];
    // Legacy receipt: ilk byte >= 0xc0 (RLP list prefix). Typed: 0x01/0x02/0x03.
    let payload = if first >= 0xc0 {
        envelope
    } else {
        &envelope[1..]
    };

    let item = rlp::decode(payload)?;
    let list = match item {
        Item::List(ref l) => l,
        _ => return Err(ReceiptError::InvalidEnvelope),
    };
    // [status/postState, cumulativeGasUsed, logsBloom, logs [, accessList]]
    if list.len() < 4 {
        return Err(ReceiptError::InvalidEnvelope);
    }

    let status = decode_status(rlp::as_bytes(&list[0])?)?;
    let logs = decode_logs(&list[3])?;

    Ok(EthReceipt { status, logs })
}

/// Status alanını yorumlar: boş → fail (post-Byzantium 0x00); [0x01] → success;
/// 32-byte → pre-Byzantium postState root (varsayılan success).
fn decode_status(b: &[u8]) -> Result<bool, ReceiptError> {
    match b.len() {
        0 => Ok(false),     // status 0 (fail)
        1 => Ok(b[0] != 0), // 0x01 success, 0x00 fail
        32 => Ok(true),     // pre-Byzantium postState root
        _ => Err(ReceiptError::InvalidEnvelope),
    }
}

/// `logs` RLP listesini decode eder. Her log = `[address(20), topics([32]*), data]`.
fn decode_logs(item: &Item) -> Result<Vec<EthLog>, ReceiptError> {
    let logs = match item {
        Item::List(l) => l,
        _ => return Err(ReceiptError::InvalidLog),
    };
    let mut out = Vec::with_capacity(logs.len());
    for log_item in logs {
        let fields = match log_item {
            Item::List(l) => l,
            _ => return Err(ReceiptError::InvalidLog),
        };
        if fields.len() != 3 {
            return Err(ReceiptError::InvalidLog);
        }
        let address = rlp::as_bytes(&fields[0])?.to_vec();
        let mut topics = Vec::new();
        match &fields[1] {
            Item::List(tl) => {
                for t in tl {
                    let tb = rlp::as_bytes(t)?;
                    if tb.len() != 32 {
                        return Err(ReceiptError::InvalidLog);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(tb);
                    topics.push(arr);
                }
            }
            _ => return Err(ReceiptError::InvalidLog),
        }
        let data = rlp::as_bytes(&fields[2])?.to_vec();
        out.push(EthLog {
            address,
            topics,
            data,
        });
    }
    Ok(out)
}

impl EthReceipt {
    /// Verilen `(emitter_address, topic0)` ile eşleşen ilk log'u döner.
    /// Bridge: `topic0` = keccak256("Deposit(address,uint256,bytes32,uint256)") gibi
    /// event signature; `emitter_address` = bridge kontrat adresi.
    pub fn find_log<'a>(&'a self, emitter: &[u8], topic0: &[u8; 32]) -> Option<&'a EthLog> {
        self.logs.iter().find(|log| {
            log.address == emitter && log.topics.first().map(|t| t == topic0).unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{encode, Item};

    fn rlp_status(success: bool) -> Item {
        // post-Byzantium: success → [0x01], fail → [] (empty)
        if success {
            Item::String(vec![0x01])
        } else {
            Item::String(vec![])
        }
    }

    fn rlp_log(address: &[u8], topics: &[[u8; 32]], data: &[u8]) -> Item {
        Item::List(vec![
            Item::String(address.to_vec()),
            Item::List(topics.iter().map(|t| Item::String(t.to_vec())).collect()),
            Item::String(data.to_vec()),
        ])
    }

    fn build_legacy_receipt(success: bool, logs: Vec<Item>) -> Vec<u8> {
        // [status, cumulativeGasUsed, logsBloom(256 zero), logs]
        let bloom = Item::String(vec![0u8; 256]);
        let item = Item::List(vec![
            rlp_status(success),
            Item::String(vec![]), // cumulativeGasUsed = 0
            bloom,
            Item::List(logs),
        ]);
        encode(&item)
    }

    fn build_typed_receipt(tx_type: u8, success: bool, logs: Vec<Item>) -> Vec<u8> {
        let bloom = Item::String(vec![0u8; 256]);
        let item = Item::List(vec![
            rlp_status(success),
            Item::String(vec![]),
            bloom,
            Item::List(logs),
        ]);
        let mut out = vec![tx_type];
        out.extend_from_slice(&encode(&item));
        out
    }

    #[test]
    fn decode_legacy_success_no_logs() {
        let bytes = build_legacy_receipt(true, vec![]);
        let r = decode_receipt(&bytes).unwrap();
        assert!(r.status);
        assert!(r.logs.is_empty());
    }

    #[test]
    fn decode_legacy_failure_status() {
        let bytes = build_legacy_receipt(false, vec![]);
        let r = decode_receipt(&bytes).unwrap();
        assert!(!r.status);
    }

    #[test]
    fn decode_typed_1559_with_log() {
        let addr = vec![0xaa; 20];
        let topic0 = [0x42u8; 32];
        let log = rlp_log(&addr, &[topic0], b"deposit-data");
        let bytes = build_typed_receipt(0x02, true, vec![log]);
        let r = decode_receipt(&bytes).unwrap();
        assert!(r.status);
        assert_eq!(r.logs.len(), 1);
        assert_eq!(r.logs[0].address, addr);
        assert_eq!(r.logs[0].topics.len(), 1);
        assert_eq!(r.logs[0].topics[0], topic0);
        assert_eq!(r.logs[0].data, b"deposit-data");
    }

    #[test]
    fn decode_typed_2930_access_list_ignored() {
        // Type 1 has an extra accessList field; our decoder reads first 4, ignores rest.
        let addr = vec![0xbb; 20];
        let log = rlp_log(&addr, &[], b"");
        let bloom = Item::String(vec![0u8; 256]);
        let item = Item::List(vec![
            rlp_status(true),
            Item::String(vec![]),
            bloom,
            Item::List(vec![log]),
            Item::List(vec![]), // accessList (ignored)
        ]);
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&encode(&item));
        let r = decode_receipt(&bytes).unwrap();
        assert!(r.status);
        assert_eq!(r.logs.len(), 1);
        assert_eq!(r.logs[0].address, addr);
    }

    #[test]
    fn find_log_matches_deposit() {
        let bridge = vec![0xcc; 20];
        let sig = [0xabu8; 32];
        let other_addr = vec![0xdd; 20];
        let log_bridge = rlp_log(&bridge, &[sig], b"x");
        let log_other = rlp_log(&other_addr, &[sig], b"y");
        let bytes = build_legacy_receipt(true, vec![log_other, log_bridge]);
        let r = decode_receipt(&bytes).unwrap();
        let found = r.find_log(&bridge, &sig).unwrap();
        assert_eq!(found.data, b"x".to_vec()); // bridge log = first match by emitter
    }

    #[test]
    fn find_log_no_match_returns_none() {
        let bytes = build_legacy_receipt(true, vec![]);
        let r = decode_receipt(&bytes).unwrap();
        assert!(r.find_log(&[0xcc; 20], &[0xab; 32]).is_none());
    }

    #[test]
    fn decode_pre_byzantium_poststate_root_treated_success() {
        // 32-byte postState root → pre-Byzantium success convention
        let bloom = Item::String(vec![0u8; 256]);
        let item = Item::List(vec![
            Item::String(vec![0x77; 32]), // postState root
            Item::String(vec![]),
            bloom,
            Item::List(vec![]),
        ]);
        let bytes = encode(&item);
        let r = decode_receipt(&bytes).unwrap();
        assert!(r.status);
    }

    #[test]
    fn decode_invalid_status_length_rejected() {
        let bloom = Item::String(vec![0u8; 256]);
        let item = Item::List(vec![
            Item::String(vec![0x01, 0x02]), // invalid status length (2 bytes)
            Item::String(vec![]),
            bloom,
            Item::List(vec![]),
        ]);
        let bytes = encode(&item);
        assert_eq!(
            decode_receipt(&bytes).unwrap_err(),
            ReceiptError::InvalidEnvelope
        );
    }

    #[test]
    fn decode_empty_envelope_rejected() {
        assert_eq!(
            decode_receipt(&[]).unwrap_err(),
            ReceiptError::InvalidEnvelope
        );
    }

    #[test]
    fn decode_log_wrong_topic_length_rejected() {
        let bad_log = Item::List(vec![
            Item::String(vec![0xaa; 20]),
            Item::List(vec![Item::String(vec![0x00; 31])]), // 31-byte topic (invalid)
            Item::String(vec![]),
        ]);
        let bytes = build_legacy_receipt(true, vec![bad_log]);
        assert_eq!(
            decode_receipt(&bytes).unwrap_err(),
            ReceiptError::InvalidLog
        );
    }
}
