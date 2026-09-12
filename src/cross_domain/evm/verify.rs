//! F10.2 security core: `verify_evm_receipt`, the deterministic orchestrator.
//!
//! Combines the steps of RFC section 4.1 (the ETH -> Budlum mint flow) into a
//! single verification surface. It **runs on-chain, inside Budlum consensus**,
//! so it is deterministic and touches no network. The relayer produces the
//! proof; Budlum verifies it here.
//!
//! # Verification flow
//!
//! 1. `header_chain`: target plus confirmations, N-confirmation finality
//!    (RFC Q2, N-conf).
//! 2. `proof_nodes` plus `target_header.receipts_root`: MPT verify yields the
//!    receipt bytes.
//! 3. `receipt` RLP decode (F10.2 `receipt.rs`) yields `{status, logs}`.
//! 4. `status == true`, meaning the transaction succeeded.
//! 5. Deposit log match: `find_log(emitter, topic0)` against the expected
//!    payload.
//! 6. Replay protection, in the caller's domain, keyed by the proven
//!    identity of the receipt: the target block's hash and the receipt's
//!    trie key (`RLP(tx_index)`). The transaction hash is not part of what
//!    the proof proves (a receipt does not contain it), so it is carried for
//!    logging and for matching the relayer's own broadcast, not as a key.
//!
//! On success the result is a `VerifiedDeposit`, carrying every proven field
//! the mint needs.
//!
//! The relayer carries the proof to the adapter as a [`DepositProofPackage`]
//! inside `RelayerExternalResult::receipt_proof`; the adapter borrows it as an
//! [`EvmDepositProof`], adding its own bridge address, deposit topic and
//! confirmation window, and runs it through here before the result is signed.

use crate::cross_domain::evm::header::{verify_chain, EthHeader};
use crate::cross_domain::evm::mpt::{self, MptError};
use crate::cross_domain::evm::receipt::{self, EthReceipt, ReceiptError};
use crate::cross_domain::evm::sync_committee::{
    verify_execution_block_finality, BeaconBinding, BeaconChainParams, SyncAggregate,
    SyncCommitteeError, SyncCommitteeState,
};
use serde::{Deserialize, Serialize};
/// A `verify_evm_receipt` failure; every sub-step's error is wrapped here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Header chain verification failed: too few confirmations, or a broken
    /// chain link.
    Header(String),
    /// The MPT proof is invalid against the receipt trie.
    Mpt(MptError),
    /// Receipt decoding failed.
    Receipt(ReceiptError),
    /// The transaction itself failed (`status == false`).
    TxFailed,
    /// The transaction identifier is metadata rather than a receipt proof,
    /// but an empty identifier cannot be correlated with the relayer request.
    EmptyTransactionHash,
    /// No deposit log was found: the emitter or topic0 did not match.
    LogNotFound,
    /// The deposit payload did not match what was expected: amount, asset or
    /// recipient.
    PayloadMismatch,
    /// Sync-committee attestation over the target header failed.
    ///
    /// Only produced when the proof carries one. A proof that carries none is
    /// accepted on N-confirmation alone, which is what every proof did before
    /// this variant existed.
    SyncCommittee(SyncCommitteeError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Header(m) => write!(f, "evm verify: header chain: {m}"),
            VerifyError::Mpt(e) => write!(f, "evm verify: mpt: {e}"),
            VerifyError::Receipt(e) => write!(f, "evm verify: receipt: {e}"),
            VerifyError::TxFailed => write!(f, "evm verify: transaction status=false"),
            VerifyError::EmptyTransactionHash => {
                write!(f, "evm verify: transaction hash is empty")
            }
            VerifyError::LogNotFound => write!(f, "evm verify: deposit log not found"),
            VerifyError::PayloadMismatch => write!(f, "evm verify: deposit payload mismatch"),
            VerifyError::SyncCommittee(e) => write!(f, "evm verify: sync-committee: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<MptError> for VerifyError {
    fn from(e: MptError) -> Self {
        VerifyError::Mpt(e)
    }
}
impl From<ReceiptError> for VerifyError {
    fn from(e: ReceiptError) -> Self {
        VerifyError::Receipt(e)
    }
}
impl From<SyncCommitteeError> for VerifyError {
    fn from(e: SyncCommitteeError) -> Self {
        VerifyError::SyncCommittee(e)
    }
}

/// A proven Ethereum deposit: every field the mint needs has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeposit {
    /// Ethereum transaction hash as the relayer reported it. Not proven:
    /// the MPT proof commits to the receipt's position, not to the
    /// transaction hash, so the same proof would verify under any string
    /// here. Kept for logging and for the worker's broadcast match; a
    /// replay key built from it could be rotated by the relayer.
    pub tx_hash: String,
    /// The proven identity of the receipt, first half: the hash of the
    /// target block, which the confirmation chain links to.
    pub block_hash: [u8; 32],
    /// The proven identity of the receipt, second half: its key in the
    /// receipts trie, `RLP(tx_index)`. `(block_hash, receipt_key)` names one
    /// receipt on one chain; it is the replay key.
    pub receipt_key: Vec<u8>,
    /// The log extracted from the bridge contract; its data field is the
    /// deposit payload.
    pub deposit_log_data: Vec<u8>,
    /// Number of the block holding the proven receipt.
    pub block_number: u64,
    /// `receiptsRoot` of the target header, the root the MPT proof was
    /// checked against. Returned so a caller holding a separately declared
    /// root (`RelayerExternalResult::external_state_root`) can compare the
    /// two instead of decoding the header a second time.
    pub receipts_root: [u8; 32],
}

/// The Ethereum deposit proof the relayer produces, in wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmDepositProof<'a> {
    /// RLP-encoded header of the target block, the one holding the deposit.
    pub target_header: &'a [u8],
    /// Confirmation headers stacked above the target: at least
    /// `confirmations` of them, each with `parent_hash` equal to the previous
    /// header's hash and `number` one higher. RFC Q2, N-conf.
    pub confirmation_headers: &'a [&'a [u8]],
    /// Required confirmation count, the reorg window. Mainnet uses roughly
    /// 64, and governance tunes it. Zero is refused by `verify_chain`, and
    /// `EvmChainAdapter::verify_deposit` refuses a value below the adapter's
    /// configured floor: the relayer writes this field, so on its own it is
    /// the relayer's choice of window, not the operator's.
    pub required_confirmations: u32,
    /// MPT proof nodes, from `receiptsRoot` down to the target receipt.
    pub proof_nodes: &'a [Vec<u8>],
    /// Key in the trie: `RLP(tx_index)`, the receipt's position. With the
    /// target block hash it is the proven identity of the receipt.
    pub receipt_key: &'a [u8],
    /// Ethereum transaction hash, relayer-supplied and not verified against
    /// the receipt. Informative only; not a replay key.
    pub tx_hash: &'a str,
    /// Bridge contract address, the deposit event emitter.
    pub emitter_address: &'a [u8],
    /// Deposit event signature: `topic0 = keccak256("Deposit(...)")`.
    pub deposit_topic0: &'a [u8; 32],
    /// Ethereum PoS attestation over the target header, when the relayer has
    /// one.
    ///
    /// `None` keeps the previous behaviour exactly: finality rests on
    /// `required_confirmations` alone, which is a bet that no reorg is that
    /// deep rather than proof that none can be. Every existing caller passes
    /// `None`, so nothing that verified before stops verifying now.
    ///
    /// `Some` is the stronger claim, and it is checked. This module's header
    /// and `adapter.rs` have both said "F10.3 (sync-committee) is used"
    /// since they were written, and neither did: `verify_sync_aggregate`
    /// existed, was tested six ways, and no production path reached it. A
    /// bridge whose documentation claims PoS finality and whose code counts
    /// confirmations is claiming a guarantee it does not have.
    ///
    /// The signed message is not the caller's. It is rebuilt from the beacon
    /// header the attestation names and the adapter's chain parameters, and
    /// that header must commit to `target_header`'s hash; see
    /// [`SyncAttestation`].
    pub sync_attestation: Option<SyncAttestation<'a>>,
}

/// The wire form of an Ethereum deposit proof: what the relayer's RPC side
/// assembles and `EvmChainAdapter::verify_observation` reads back out of
/// `RelayerExternalResult::receipt_proof` before the result is signed.
///
/// Owned, because it crosses a byte field. Deliberately without the emitter
/// address, the deposit topic and the confirmation window: those three are
/// the adapter's configuration, and a package that named its own would be
/// choosing which contract's log to match and how deep a reorg to survive.
/// The adapter supplies them when it borrows the package as an
/// [`EvmDepositProof`]. No sync-committee attestation either: the committee
/// state it needs is around 100 KB of light-client state that the node
/// holds, not something a proof carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositProofPackage {
    /// RLP-encoded header of the block holding the deposit.
    pub target_header: Vec<u8>,
    /// Confirmation headers stacked above the target, oldest first.
    pub confirmation_headers: Vec<Vec<u8>>,
    /// MPT proof nodes from `receiptsRoot` down to the receipt.
    pub proof_nodes: Vec<Vec<u8>>,
    /// Trie key of the receipt: `RLP(tx_index)`.
    pub receipt_key: Vec<u8>,
    /// Ethereum transaction hash the receipt belongs to.
    pub tx_hash: String,
}

/// A sync-committee attestation bundled with the state that validates it.
///
/// Grouped rather than added as loose `Option` fields, so it is impossible
/// to supply an aggregate without the committee it must verify against, or
/// a beacon header without either.
///
/// An earlier shape carried a caller-supplied `signing_message`. That
/// verified only that the committee had signed *some* bytes the relayer
/// chose, which is not a statement about the deposit's block at all: a
/// genuine attestation over any beacon header would have passed for any
/// target header. The message is now derived. The relayer supplies the
/// beacon header fields and the SSZ branch from the execution block hash to
/// that header's `body_root`; the verifier rebuilds the signing root from
/// those fields and the adapter's fork parameters, and refuses the
/// attestation unless the branch lands `keccak256(target_header)` inside
/// the signed header and the header's slot inside the committee's period.
///
/// `PartialEq`/`Eq` because `EvmDepositProof` derives them and an
/// `Option<SyncAttestation>` field makes that requirement transitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAttestation<'a> {
    /// Light-client state holding the 512 pubkeys for this period.
    pub state: &'a SyncCommitteeState,
    /// The bitmap and aggregate signature the relayer observed.
    pub aggregate: &'a SyncAggregate,
    /// The beacon header the committee signed and the branch that places
    /// the target execution block inside it.
    pub beacon: &'a BeaconBinding,
    /// Fork version and genesis validators root. The adapter's, never the
    /// proof's: a proof choosing its own domain chooses which chain it is
    /// finalized on.
    pub chain: &'a BeaconChainParams,
}

/// Verifies an Ethereum deposit proof end to end. Deterministic, no network.
///
/// On success the caller gets a `VerifiedDeposit` holding every proven field
/// the mint needs. On failure it gets a `VerifyError` naming the step at which
/// the proof turned out to be invalid.
pub fn verify_evm_receipt(proof: &EvmDepositProof<'_>) -> Result<VerifiedDeposit, VerifyError> {
    // The receipt proof cannot prove a transaction hash, but the relay result
    // still needs a non-empty identifier to correlate the proof with the
    // external action it claims to observe. Refuse the ambiguous value before
    // doing expensive header/MPT work.
    if proof.tx_hash.is_empty() {
        return Err(VerifyError::EmptyTransactionHash);
    }

    // 1. Header decode + N-confirmation finality.
    let target = decode_header_or_err(proof.target_header)?;
    let confs: Result<Vec<EthHeader>, VerifyError> = proof
        .confirmation_headers
        .iter()
        .map(|raw| decode_header_or_err(raw))
        .collect();
    let confs = confs?;
    verify_chain(&target, &confs, proof.required_confirmations)
        .map_err(|e| VerifyError::Header(e.to_string()))?;

    // 2. MPT verify: receiptsRoot → receipt bytes.
    let receipt_bytes = mpt::verify(proof.proof_nodes, &target.receipts_root, proof.receipt_key)?;

    // 3. Receipt RLP decode.
    let receipt: EthReceipt = receipt::decode_receipt(&receipt_bytes)?;

    // 4. Status check.
    if !receipt.status {
        return Err(VerifyError::TxFailed);
    }

    // 5. Deposit log match.
    let log = receipt
        .find_log(proof.emitter_address, proof.deposit_topic0)
        .ok_or(VerifyError::LogNotFound)?;

    // 5b. PoS attestation, when the relayer supplied one.
    //
    // Runs after the cheap structural checks and before the caller is handed
    // anything it could mint against. Verifying 342 BLS signatures is the
    // most expensive step here by a wide margin, so a proof that is malformed
    // in some cheaper way should not pay for it.
    //
    // Deliberately not mandatory. Making it so would refuse every proof the
    // current relayer produces, and a bridge that refuses everything is
    // indistinguishable from one that is switched off. What it does buy is
    // that a proof which *claims* PoS finality has that claim checked rather
    // than trusted.
    if let Some(ref attestation) = proof.sync_attestation {
        verify_execution_block_finality(
            attestation.state,
            attestation.aggregate,
            attestation.beacon,
            attestation.chain,
            &target.hash,
        )?;
    }

    // 6. Replay protection lives in the caller's domain. What is returned
    //    for it is the proven identity, block hash plus receipt key; the tx
    //    hash rides along unverified.
    Ok(VerifiedDeposit {
        tx_hash: proof.tx_hash.to_string(),
        block_hash: target.hash,
        receipt_key: proof.receipt_key.to_vec(),
        deposit_log_data: log.data.clone(),
        block_number: target.number,
        receipts_root: target.receipts_root,
    })
}

fn decode_header_or_err(raw: &[u8]) -> Result<EthHeader, VerifyError> {
    crate::cross_domain::evm::header::decode_header(raw)
        .map_err(|e| VerifyError::Header(e.to_string()))
}

/// Proof fixtures shared by this module's tests and the adapter's: one
/// receipt in a single-leaf trie under a header chain of `n_conf`
/// confirmations. Test-only, and crate-visible so the adapter tests can hand
/// the relayer a package that really verifies instead of one that is
/// accepted for being well-formed.
#[cfg(test)]
pub(crate) mod fixtures {
    use crate::cross_domain::evm::mpt::{keccak256, to_nibbles};
    use crate::cross_domain::evm::rlp::{encode, Item};

    fn trim_u64(n: u64) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }
        let be = n.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        be[start..].to_vec()
    }

    pub(crate) fn header_rlp(parent: [u8; 32], number: u64, receipts_root: [u8; 32]) -> Vec<u8> {
        encode(&Item::List(vec![
            Item::String(parent.to_vec()),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 20]),
            Item::String(vec![0u8; 32]),
            Item::String(vec![0u8; 32]),
            Item::String(receipts_root.to_vec()),
            Item::String(vec![0u8; 256]),
            Item::String(vec![]),
            Item::String(trim_u64(number)),
        ]))
    }

    fn receipt_rlp(success: bool, logs: Vec<Item>) -> Vec<u8> {
        encode(&Item::List(vec![
            if success {
                Item::String(vec![0x01])
            } else {
                Item::String(vec![])
            },
            Item::String(vec![]),
            Item::String(vec![0u8; 256]),
            Item::List(logs),
        ]))
    }

    fn log_item(addr: &[u8], topic0: [u8; 32], data: &[u8]) -> Item {
        Item::List(vec![
            Item::String(addr.to_vec()),
            Item::List(vec![Item::String(topic0.to_vec())]),
            Item::String(data.to_vec()),
        ])
    }

    /// Builds a complete proof fixture: target header, N confirmations,
    /// receipt proof and deposit log, from
    /// `(emitter, topic0, log_data, success, n_conf)`.
    pub(crate) struct Fixture {
        pub(crate) target_header: Vec<u8>,
        pub(crate) conf_headers: Vec<Vec<u8>>,
        pub(crate) receipts_root: [u8; 32],
        pub(crate) proof_nodes: Vec<Vec<u8>>,
        pub(crate) receipt_key: Vec<u8>,
    }

    pub(crate) fn build_fixture(
        emitter: &[u8],
        topic0: [u8; 32],
        log_data: &[u8],
        success: bool,
        n_conf: u32,
    ) -> Fixture {
        // Single-leaf trie: the key is RLP(tx_index=0), the leaf value is the
        // receipt.
        let receipt_bytes = receipt_rlp(success, vec![log_item(emitter, topic0, log_data)]);
        // MPT key = keccak256(rlp(0)) nibbles; leaf path = full 64 nibbles.
        let key_bytes = encode(&Item::String(vec![])); // rlp(0) = 0x80
        let nibbles = to_nibbles(&keccak256(&key_bytes));

        // Leaf node RLP.
        let leaf_node = Item::List(vec![
            Item::String(crate::cross_domain::evm::mpt::hp_encode(&nibbles, true)),
            Item::String(receipt_bytes.clone()),
        ]);
        let leaf_bytes = encode(&leaf_node);
        let receipts_root = keccak256(&leaf_bytes);

        // Target header at number=100.
        let target_hdr = header_rlp([9u8; 32], 100, receipts_root);
        let target_hash = keccak256(&target_hdr);

        // N confirmation headers (chain: parent = prev hash, number+1).
        let mut conf_headers = Vec::new();
        let mut prev_hash = target_hash;
        for offset in 1..=n_conf {
            let h = header_rlp(prev_hash, 100 + offset as u64, receipts_root);
            prev_hash = keccak256(&h);
            conf_headers.push(h);
        }

        Fixture {
            target_header: target_hdr,
            conf_headers,
            receipts_root,
            proof_nodes: vec![leaf_bytes],
            receipt_key: key_bytes,
        }
    }

    pub(crate) fn conf_refs(f: &Fixture) -> Vec<&[u8]> {
        f.conf_headers.iter().map(|v| v.as_slice()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{build_fixture, conf_refs, header_rlp, Fixture};
    use super::*;
    use crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;

    // ---- Pozitif: tam happy-path ----

    #[test]
    fn an_empty_transaction_hash_is_refused_before_proof_work() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"deposit-payload", true, 3);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof),
            Err(VerifyError::EmptyTransactionHash)
        );
    }

    #[test]
    fn verify_full_happy_path() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let data = b"deposit-payload";
        let f = build_fixture(&emitter, topic0, data, true, 3);

        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xabc123",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let verified = verify_evm_receipt(&proof).unwrap();
        assert_eq!(verified.tx_hash, "0xabc123");
        assert_eq!(verified.deposit_log_data, data);
        assert_eq!(verified.block_number, 100);
        assert_eq!(verified.receipts_root, f.receipts_root);
        assert_eq!(verified.receipt_key, f.receipt_key);
        assert_eq!(
            verified.block_hash,
            crate::cross_domain::evm::mpt::keccak256(&f.target_header)
        );
    }

    /// The transaction hash is not proven: the same proof verifies under
    /// any string, which is why the proven identity `(block_hash,
    /// receipt_key)` is what a replay set must key on. Two proofs that
    /// differ only in the reported hash name the same receipt.
    #[test]
    fn the_tx_hash_is_not_bound_and_the_receipt_identity_is() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"deposit-payload", true, 3);
        let confs = conf_refs(&f);
        let under = |tx_hash: &'static str| EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &confs,
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash,
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let first = verify_evm_receipt(&under("0xaaaa")).unwrap();
        let second = verify_evm_receipt(&under("0xbbbb")).unwrap();
        assert_ne!(first.tx_hash, second.tx_hash);
        assert_eq!(
            (first.block_hash, first.receipt_key.clone()),
            (second.block_hash, second.receipt_key.clone()),
            "the proven identity does not move with the reported hash"
        );
    }

    // ---- Negative: the transaction failed ----

    #[test]
    fn verify_rejects_failed_tx_status() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", false, 3);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xdead",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::TxFailed
        );
    }

    // ---- Negative: too few confirmations ----

    #[test]
    fn verify_rejects_insufficient_confirmations() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 2);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: DEFAULT_CONFIRMATIONS, // 64 > 2
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Header(_)));
    }

    // ---- Negative: broken chain ----

    #[test]
    fn verify_rejects_broken_chain() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        // Broken confirmation: wrong parent.
        let bad_conf = header_rlp([0xff; 32], 101, f.receipts_root);
        let conf_refs = vec![bad_conf.as_slice()];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs,
            required_confirmations: 1,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Header(_)));
    }

    // ---- Negative: no deposit log, because the emitter is wrong ----

    #[test]
    fn verify_rejects_wrong_emitter() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let wrong_emitter = vec![0xdd; 20];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &wrong_emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::LogNotFound
        );
    }

    // ---- Negative: the deposit topic0 does not match ----

    #[test]
    fn verify_rejects_wrong_topic0() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let wrong_topic = [0x99; 32];
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &wrong_topic,
            sync_attestation: None,
        };
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::LogNotFound
        );
    }

    // ---- Negative: the MPT proof is broken, a node is missing ----

    #[test]
    fn verify_rejects_missing_mpt_node() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"data", true, 3);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &conf_refs(&f),
            required_confirmations: 3,
            proof_nodes: &[], // empty, so the root node is missing
            receipt_key: &f.receipt_key,
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let err = verify_evm_receipt(&proof).unwrap_err();
        assert!(matches!(err, VerifyError::Mpt(_)));
    }

    // ---- Negative: wrong root, the target header's receiptsRoot differs
    // from the proof's ----
    // This lands on the MPT verifier's `MissingNode`, because the proof's root
    // node cannot be found.

    #[test]
    fn verify_does_not_panic_on_garbage() {
        // DoS safety: a wholly garbage proof yields an Err, never a panic.
        let garbage = vec![vec![0xff; 50]; 3];
        let proof = EvmDepositProof {
            target_header: &garbage[0],
            confirmation_headers: &[&garbage[1][..], &garbage[2][..]],
            required_confirmations: 1,
            proof_nodes: &garbage,
            receipt_key: &garbage[0],
            tx_hash: "garbage",
            emitter_address: &garbage[0],
            deposit_topic0: &[0u8; 32],
            sync_attestation: None,
        };
        let _ = verify_evm_receipt(&proof); // Err beklenir, panic YOK.
    }

    // ---- Sync-committee attestation ----

    use crate::cross_domain::evm::sync_committee::{
        BLS_PUBKEY_LEN, BLS_SIGNATURE_LEN, PARTICIPATION_THRESHOLD, SYNC_COMMITTEE_SIZE,
    };

    use crate::cross_domain::evm::sync_committee::fixtures::{
        binding_committing_to as beacon_for, first_slot_of_period,
    };

    const TEST_CHAIN: BeaconChainParams = BeaconChainParams {
        fork_version: [0x04, 0, 0, 0],
        genesis_validators_root: [0x42; 32],
    };

    fn empty_committee() -> SyncCommitteeState {
        SyncCommitteeState {
            current_period: 0,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        }
    }

    fn aggregate_with_participation(bits_set: bool) -> SyncAggregate {
        SyncAggregate {
            sync_committee_bits: if bits_set {
                [0xFFu8; SYNC_COMMITTEE_SIZE / 8]
            } else {
                [0u8; SYNC_COMMITTEE_SIZE / 8]
            },
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        }
    }

    fn proof_with_attestation<'a>(
        f: &'a Fixture,
        confs: &'a [&'a [u8]],
        emitter: &'a [u8],
        topic0: &'a [u8; 32],
        attestation: Option<SyncAttestation<'a>>,
    ) -> EvmDepositProof<'a> {
        EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: confs,
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xabc123",
            emitter_address: emitter,
            deposit_topic0: topic0,
            sync_attestation: attestation,
        }
    }

    /// A proof carrying no attestation verifies exactly as it did before.
    ///
    /// The narrow half. Every relayer in the tree produces `None`, and making
    /// the attestation mandatory would refuse all of them; a bridge that
    /// refuses everything is indistinguishable from one switched off.
    #[test]
    fn a_proof_without_an_attestation_still_verifies_on_confirmations_alone() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let proof = proof_with_attestation(&f, &confs, &emitter, &topic0, None);
        assert!(
            verify_evm_receipt(&proof).is_ok(),
            "N-confirmation finality must keep working; this is what every \
             existing caller relies on"
        );
    }

    /// A proof that claims PoS finality has the claim checked.
    ///
    /// This is the defect. `sync_committee.rs` implements Altair verification
    /// and is tested six ways; `adapter.rs` said "F10.3 (sync-committee)
    /// is used" in two places, and no production path called
    /// `verify_sync_aggregate`. A bridge whose documentation claims proof of
    /// stake finality and whose code counts confirmations is claiming a
    /// guarantee it does not have: confirmations are a bet that no reorg goes
    /// that deep, not evidence that none can.
    #[test]
    fn an_attestation_below_the_participation_threshold_is_rejected() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(false);
        let beacon = beacon_for(
            crate::cross_domain::evm::mpt::keccak256(&f.target_header),
            0,
        );
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &beacon,
                chain: &TEST_CHAIN,
            }),
        );

        let err = verify_evm_receipt(&proof)
            .expect_err("an attestation nobody signed must not pass as finality");
        assert!(
            matches!(
                err,
                VerifyError::SyncCommittee(SyncCommitteeError::InsufficientParticipation {
                    participating: 0,
                    threshold: PARTICIPATION_THRESHOLD,
                })
            ),
            "the refusal must name the participation shortfall, got: {err}"
        );
    }

    /// Participation alone is not enough; the signatures must verify.
    ///
    /// The bitmap is attacker-supplied. A committee of zero pubkeys with
    /// every bit set claims full participation and verifies nothing, and the
    /// count of *valid* signatures is what the threshold applies to.
    #[test]
    fn a_full_bitmap_over_unverifiable_signatures_is_rejected() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(true);
        assert_eq!(
            aggregate.participation_count(),
            SYNC_COMMITTEE_SIZE,
            "the fixture only means something if the bitmap claims everyone signed"
        );

        let beacon = beacon_for(
            crate::cross_domain::evm::mpt::keccak256(&f.target_header),
            0,
        );
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &beacon,
                chain: &TEST_CHAIN,
            }),
        );

        let err = verify_evm_receipt(&proof)
            .expect_err("a bitmap claiming 512 signers over 512 zero keys must not pass");
        assert!(
            matches!(err, VerifyError::SyncCommittee(_)),
            "the refusal must come from the attestation, got: {err}"
        );
    }

    /// The attestation runs after the cheap checks, not before them.
    ///
    /// Verifying 342 BLS signatures is by far the most expensive step here. A
    /// proof that is malformed in some cheaper way must be refused for that
    /// reason, both because the message is more useful and because an
    /// attacker must not be able to spend a node's CPU with a proof that a
    /// byte comparison would have rejected.
    #[test]
    fn a_failed_transaction_is_refused_before_the_signatures_are_checked() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        // success = false: the receipt says the transaction reverted.
        let f = build_fixture(&emitter, topic0, b"payload", false, 3);
        let confs = conf_refs(&f);

        let state = empty_committee();
        let aggregate = aggregate_with_participation(false);
        let beacon = beacon_for(
            crate::cross_domain::evm::mpt::keccak256(&f.target_header),
            0,
        );
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &beacon,
                chain: &TEST_CHAIN,
            }),
        );

        let err = verify_evm_receipt(&proof).expect_err("a reverted transaction must be refused");
        assert_eq!(
            err,
            VerifyError::TxFailed,
            "the cheap structural refusal must win, so a malformed proof cannot \
             make a node verify 342 BLS signatures before saying no"
        );
    }

    /// The attestation is about the deposit's block or it is nothing. A
    /// beacon header that commits to some other execution block is refused
    /// before any signature is looked at, and a header from another period
    /// than the committee state's is refused too. A header that does commit
    /// to the target gets as far as the signature check, which is where an
    /// unsigned fixture fails.
    #[test]
    fn an_attestation_over_another_block_is_rejected_before_the_signatures() {
        let emitter = vec![0xcc; 20];
        let topic0 = [0xab; 32];
        let f = build_fixture(&emitter, topic0, b"payload", true, 3);
        let confs = conf_refs(&f);
        let state = empty_committee();
        // Full participation, so the only thing standing between this
        // aggregate and the pairing is the binding.
        let aggregate = aggregate_with_participation(true);

        let other_block = beacon_for([0xEE; 32], 0);
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &other_block,
                chain: &TEST_CHAIN,
            }),
        );
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::SyncCommittee(SyncCommitteeError::ExecutionBlockNotInBeaconBody),
            "a committee signature over a header that does not contain the \
             target block says nothing about the target block"
        );

        let target_hash = crate::cross_domain::evm::mpt::keccak256(&f.target_header);
        let wrong_period = beacon_for(target_hash, first_slot_of_period(3));
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &wrong_period,
                chain: &TEST_CHAIN,
            }),
        );
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::SyncCommittee(SyncCommitteeError::PeriodMismatch {
                slot_period: 3,
                state_period: 0,
            }),
            "the 512 keys in the state are the period's committee, not another's"
        );

        let bound = beacon_for(target_hash, 0);
        let proof = proof_with_attestation(
            &f,
            &confs,
            &emitter,
            &topic0,
            Some(SyncAttestation {
                state: &state,
                aggregate: &aggregate,
                beacon: &bound,
                chain: &TEST_CHAIN,
            }),
        );
        assert_eq!(
            verify_evm_receipt(&proof).unwrap_err(),
            VerifyError::SyncCommittee(SyncCommitteeError::InvalidPubkey),
            "a header that does commit to the target reaches the key checks"
        );
    }
}
