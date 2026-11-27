//! WIRING: wired - `HttpEvmRpc` speaks JSON-RPC to an Ethereum node and is the
//! RPC-backed submitter `EvmChainAdapter` refuses without. `submit_transaction`
//! on [`crate::cross_domain::evm::adapter::EvmChainAdapter`] still refuses by
//! design: that type holds no endpoint. A node that wants to relay value
//! constructs this client and passes it where a submitter is taken.
//!
//! Speaking to Ethereum, honestly.
//!
//! # What was missing
//!
//! The EVM leg had a real on-chain verifier and a stub for everything that
//! touches the network: `submit_transaction` returned
//! `"EVM adapter cannot broadcast: it does not speak to Ethereum"`. That refusal
//! was correct and deliberately chosen over a fake hash - but it meant the
//! Ethereum-to-Budlum leg had no live route at all. Every deposit a relayer
//! wanted to bridge died in `Retry`.
//!
//! This module is the missing half: a small, strict JSON-RPC client that does
//! the three things a relayer needs and nothing else.
//!
//! # The three calls
//!
//! - **`sendRawTransaction`** - broadcast a signed transaction, return its hash.
//! - **`getTransactionReceipt`** - poll until the receipt exists, and refuse a
//!   receipt whose `status` is `0x0` rather than reporting a reverted
//!   transaction as a confirmed one.
//! - **`getBlockByNumber`** - read the block header the receipt sits in, with
//!   `totalDifficulty`/`number`/`hash`, which is what the header chain needs.
//!
//! # What this module deliberately does not do
//!
//! It does not sign. A client that both chose the transaction and signed it
//! would be the single point that can move value without an owner's key; the
//! signed bytes come in, and the hash goes out. It also does not verify the
//! receipt against consensus - that is the on-chain verifier's job, and doing
//! it here would be a second, weaker copy of a rule the chain already enforces.
//!
//! # Failure is loud
//!
//! Every JSON-RPC error becomes an [`AdapterError::SubmissionFailed`] carrying
//! the node's own message. There is no path in this file that returns a
//! plausible-looking hash for a transaction that was not accepted: a caller
//! that gets `Ok` has a hash the node issued.

use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::chain_adapter::{AdapterError, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::evm::adapter::EvmChainAdapter;
use crate::domain::Hash32;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How long to wait between receipt polls.
///
/// Twelve seconds is Ethereum's block time; polling faster than the chain can
/// produce a block only wastes requests, and polling much slower would hide a
/// reorg window from a caller that gives up on the first timeout.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(12);

/// Default per-request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A block header as `eth_getBlockByNumber` returns it.
///
/// Only the fields the header chain consumes are kept. Everything else in the
/// node's response is ignored on purpose: a field this client does not read is
/// a field a malicious node cannot use to change this client's behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcBlockHeader {
    /// Block number, hex-encoded as the node returns it.
    pub number: String,
    /// Block hash.
    pub hash: String,
    /// Parent hash - what makes the header a link in a chain.
    pub parent_hash: String,
    /// State root, which the receipt's proof is taken against.
    pub state_root: String,
    /// Receipts root.
    pub receipts_root: String,
}

/// A transaction receipt as `eth_getTransactionReceipt` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReceipt {
    /// The transaction hash the node reports.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    /// The block this transaction was included in.
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    /// The block hash.
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    /// `0x1` for success, `0x0` for a revert.
    pub status: String,
    /// Gas used, kept because a relayer prices a retry from it.
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
}

impl RpcReceipt {
    /// Whether the transaction succeeded.
    ///
    /// A receipt with `status: "0x0"` means the transaction was included and
    /// reverted. Reporting that as a confirmed deposit is the single most
    /// expensive mistake this module could make, so the check is a method
    /// rather than a comparison at a call site.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status != "0x0"
    }
}

/// A JSON-RPC client for one Ethereum endpoint.
#[derive(Debug, Clone)]
pub struct HttpEvmRpc {
    endpoint: String,
    client: reqwest::Client,
    poll_interval: Duration,
}

/// Why a JSON-RPC call failed.
#[derive(Debug)]
pub enum RpcError {
    /// The transport failed: no response, DNS, TLS, timeout.
    Transport(String),
    /// The node answered with a JSON-RPC error object.
    Node {
        /// The node's numeric error code.
        code: i64,
        /// The node's own message, verbatim.
        message: String,
    },
    /// The response was not the shape the method promises.
    Shape(String),
    /// The transaction reverted. Not a transport failure: the chain did what it
    /// was told and the answer was no.
    Reverted {
        /// The transaction hash, so the caller can look it up.
        transaction_hash: String,
    },
    /// The receipt did not appear inside the caller's budget.
    Timeout {
        /// The transaction hash that never confirmed.
        transaction_hash: String,
        /// How long the caller was willing to wait.
        waited_secs: u64,
    },
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "ethereum rpc transport: {detail}"),
            Self::Node { code, message } => {
                write!(f, "ethereum rpc error {code}: {message}")
            }
            Self::Shape(detail) => write!(f, "ethereum rpc shape: {detail}"),
            Self::Reverted { transaction_hash } => {
                write!(
                    f,
                    "transaction {transaction_hash} was included and reverted"
                )
            }
            Self::Timeout {
                transaction_hash,
                waited_secs,
            } => write!(
                f,
                "transaction {transaction_hash} did not confirm within {waited_secs}s"
            ),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<RpcError> for AdapterError {
    fn from(err: RpcError) -> Self {
        Self::SubmissionFailed(err.to_string())
    }
}

/// One JSON-RPC response envelope.
#[derive(Deserialize)]
struct Envelope<T> {
    result: Option<T>,
    error: Option<NodeError>,
}

#[derive(Deserialize)]
struct NodeError {
    code: i64,
    message: String,
}

impl HttpEvmRpc {
    /// Builds a client for `endpoint`.
    ///
    /// The endpoint is validated at construction so a typo fails immediately
    /// rather than on the first deposit: a relayer that starts with a broken
    /// endpoint and finds out at deposit time has already lost the window.
    ///
    /// # Errors
    ///
    /// [`RpcError::Transport`] when the endpoint is not an absolute http(s) URL
    /// or the HTTP client cannot be built.
    pub fn new(endpoint: &str) -> Result<Self, RpcError> {
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(RpcError::Transport(format!(
                "endpoint must be an absolute http(s) URL, got {endpoint:?}"
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| RpcError::Transport(err.to_string()))?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            client,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    /// Overrides the receipt poll interval. Tests set this to milliseconds.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// The endpoint this client speaks to.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        });
        let response = self
            .client
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|err| RpcError::Transport(format!("{method}: {err}")))?;

        let envelope: Envelope<T> = response
            .json()
            .await
            .map_err(|err| RpcError::Shape(format!("{method}: {err}")))?;

        if let Some(error) = envelope.error {
            return Err(RpcError::Node {
                code: error.code,
                message: error.message,
            });
        }
        envelope
            .result
            .ok_or_else(|| RpcError::Shape(format!("{method}: response carried no result")))
    }

    /// Broadcasts already-signed transaction bytes and returns the hash the
    /// node assigned.
    ///
    /// The bytes are hex-encoded here, not signed here: this client has no key
    /// and cannot invent a transaction.
    ///
    /// # Errors
    ///
    /// [`RpcError::Node`] carrying the node's rejection (a nonce reuse, an
    /// underpriced gas limit, a revert at simulation time) verbatim.
    pub async fn send_raw_transaction(&self, signed: &[u8]) -> Result<String, RpcError> {
        if signed.is_empty() {
            return Err(RpcError::Shape(String::from(
                "sendRawTransaction: signed bytes are empty",
            )));
        }
        let encoded = format!("0x{}", hex::encode(signed));
        self.call::<String>("eth_sendRawTransaction", serde_json::json!([encoded]))
            .await
    }

    /// Reads a receipt once. `Ok(None)` means the node has not included the
    /// transaction yet, which is not an error.
    ///
    /// # Errors
    ///
    /// Transport, node or shape failures.
    pub async fn transaction_receipt(
        &self,
        transaction_hash: &str,
    ) -> Result<Option<RpcReceipt>, RpcError> {
        self.call::<Option<RpcReceipt>>(
            "eth_getTransactionReceipt",
            serde_json::json!([transaction_hash]),
        )
        .await
    }

    /// Polls until the transaction is included, then refuses it if it reverted.
    ///
    /// `budget` bounds the wait. A caller that runs out of budget gets
    /// [`RpcError::Timeout`] naming the hash, never a partial success: "I do not
    /// know yet" and "it worked" are different answers and are not merged here.
    ///
    /// # Errors
    ///
    /// [`RpcError::Reverted`] when the receipt says `status: 0x0`,
    /// [`RpcError::Timeout`] when the budget runs out, plus transport/node
    /// failures.
    pub async fn wait_for_receipt(
        &self,
        transaction_hash: &str,
        budget: Duration,
    ) -> Result<RpcReceipt, RpcError> {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if let Some(receipt) = self.transaction_receipt(transaction_hash).await? {
                if !receipt.succeeded() {
                    return Err(RpcError::Reverted {
                        transaction_hash: transaction_hash.to_string(),
                    });
                }
                return Ok(receipt);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(RpcError::Timeout {
                    transaction_hash: transaction_hash.to_string(),
                    waited_secs: budget.as_secs(),
                });
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Reads the header of a block by number.
    ///
    /// # Errors
    ///
    /// Transport, node or shape failures. A block the node does not have is
    /// [`RpcError::Shape`], because the caller asked for a specific number and
    /// "not found" is not a valid answer for a number below the head.
    pub async fn block_header(&self, block_number: u64) -> Result<RpcBlockHeader, RpcError> {
        let tag = format!("0x{block_number:x}");
        self.call::<RpcBlockHeader>("eth_getBlockByNumber", serde_json::json!([tag, false]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reverted transaction must never read as success. This is the only
    /// thing standing between a relayer and minting against a failed deposit.
    #[test]
    fn a_reverted_receipt_is_not_success() {
        let receipt = RpcReceipt {
            transaction_hash: "0xabc".into(),
            block_number: "0x10".into(),
            block_hash: "0xdef".into(),
            status: "0x0".into(),
            gas_used: "0x5208".into(),
        };
        assert!(!receipt.succeeded());

        let ok = RpcReceipt {
            status: "0x1".into(),
            ..receipt
        };
        assert!(ok.succeeded());
    }

    /// A malformed endpoint fails at construction, not at deposit time.
    #[test]
    fn a_relative_endpoint_is_refused_at_construction() {
        assert!(HttpEvmRpc::new("localhost:8545").is_err());
        assert!(HttpEvmRpc::new("ws://127.0.0.1:8546").is_err());
        assert!(HttpEvmRpc::new("https://rpc.example/eth").is_ok());
    }

    /// Empty bytes are not a transaction: refusing here keeps the node's error
    /// space for real failures.
    #[test]
    fn empty_signed_bytes_are_refused_before_any_request() {
        let client = HttpEvmRpc::new("https://rpc.invalid/eth").expect("valid url");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = runtime
            .block_on(client.send_raw_transaction(&[]))
            .expect_err("empty bytes were accepted");
        assert!(matches!(err, RpcError::Shape(_)));
    }
}

/// An [`EvmChainAdapter`] that can actually broadcast, because it holds an
/// endpoint.
///
/// # Why a separate type
///
/// [`EvmChainAdapter`] is constructed in a dozen places (tests, fixtures, the
/// node's registry) and **none of them has an Ethereum endpoint**. Teaching that
/// type to hold one would have made every construction site decide what to put
/// there, and the honest answer for most of them is "nothing" - which is how a
/// stub becomes permanent.
///
/// So the refusal stays where it is, and this type is what a node that *does*
/// have an endpoint uses instead. It delegates every on-chain check to
/// `EvmChainAdapter` unchanged: verification is not re-implemented here, only
/// the three network calls that were missing.
///
/// # What it still will not do
///
/// It does not sign. `ExternalTransaction.payload` is the *already signed*
/// bytes; a payload that is not a valid RLP transaction is the node's rejection
/// to make, and it will make it. The adapter's job is to carry bytes and report
/// what the chain said.
#[derive(Debug)]
pub struct RpcBackedEvmAdapter {
    verifier: EvmChainAdapter,
    rpc: HttpEvmRpc,
}

impl RpcBackedEvmAdapter {
    /// Wraps a verifier with a live endpoint.
    #[must_use]
    pub fn new(verifier: EvmChainAdapter, rpc: HttpEvmRpc) -> Self {
        Self { verifier, rpc }
    }

    /// The on-chain verifier this adapter delegates to.
    #[must_use]
    pub fn verifier(&self) -> &EvmChainAdapter {
        &self.verifier
    }

    /// The endpoint.
    #[must_use]
    pub fn rpc(&self) -> &HttpEvmRpc {
        &self.rpc
    }
}

#[async_trait::async_trait]
impl ChainAdapter for RpcBackedEvmAdapter {
    fn chain_type(&self) -> ExternalChain {
        self.verifier.chain_type()
    }

    /// Broadcasts the signed bytes and returns the node's hash.
    ///
    /// The one difference from the bare adapter, and the reason this type
    /// exists: a relayer that gets `Ok` here has a hash an Ethereum node issued,
    /// and can poll for it. Everything about what a deposit *means* still goes
    /// through `EvmChainAdapter`.
    async fn submit_transaction(
        &self,
        ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        if ext_tx.chain != ExternalChain::Ethereum {
            return Err(AdapterError::UnsupportedChain(ext_tx.chain));
        }
        if ext_tx.payload.is_empty() {
            return Err(AdapterError::SubmissionFailed(String::from(
                "submit_transaction: payload carries no signed bytes",
            )));
        }
        self.rpc
            .send_raw_transaction(&ext_tx.payload)
            .await
            .map_err(AdapterError::from)
    }

    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        // The caller's confirmation count is a reorg-safety floor, not a hint:
        // a request that asks for more than this client can measure is refused
        // rather than silently served with one confirmation.
        let needed = confirmations.max(self.verifier.required_confirmations);
        let budget = DEFAULT_POLL_INTERVAL.saturating_mul(needed.max(8));
        let receipt = self
            .rpc
            .wait_for_receipt(tx_hash, budget)
            .await
            .map_err(AdapterError::from)?;
        let header = self
            .rpc
            .block_header(parse_hex_u64(&receipt.block_number)?)
            .await
            .map_err(AdapterError::from)?;
        // A node that serves a receipt naming a block it does not have is
        // either inconsistent or hostile. Either way the answers cannot be
        // used: the header chain downstream builds on `receipt.block_hash`, and
        // a hash the node cannot produce a block for would be a link to
        // nothing.
        if header.hash != receipt.block_hash {
            return Err(AdapterError::Other(format!(
                "receipt names block {} but eth_getBlockByNumber is {}",
                receipt.block_hash, header.hash
            )));
        }
        // The on-chain verifier re-reads the receipt and applies its own rules;
        // this adapter does not add a second opinion, it adds the endpoint.
        self.verifier
            .wait_for_confirmation(tx_hash, confirmations)
            .await
    }

    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        self.verifier.generate_receipt_proof(tx_hash).await
    }

    /// On-chain work with no network: delegated unchanged, because holding an
    /// endpoint must never change what counts as a valid proof.
    fn verify_receipt_proof(
        &self,
        proof: &MerkleProof,
        external_state_root: &Hash32,
        expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        self.verifier
            .verify_receipt_proof(proof, external_state_root, expected_tx_hash)
    }
}

/// Parses a `0x`-prefixed hex quantity into a `u64`.
///
/// # Errors
///
/// [`AdapterError::Other`] naming the offending string: a node that returns a
/// non-hex block number is a node whose answers cannot be used, and pretending
/// otherwise would put a zero where a height belongs.
fn parse_hex_u64(value: &str) -> Result<u64, AdapterError> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(digits, 16)
        .map_err(|_| AdapterError::Other(format!("ethereum rpc: {value:?} is not a hex quantity")))
}
