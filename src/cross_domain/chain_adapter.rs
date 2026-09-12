//! Multi-chain adapter trait for the Universal Relayer.
//!
//! Each supported external chain (Ethereum, Solana, Bitcoin, etc.) implements
//! This trait to provide:
//! - Proof generation (Merkle proof of transaction receipt)
//! - Proof verification (against the chain's state root)
//! - Transaction submission (broadcast signed tx to external chain)
//!
//! The relayer is chain-agnostic at the orchestrator level, it delegates
//! Chain-specific logic to the adapter.

use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::event_tree::MerkleProof;
use crate::domain::types::Hash32;
use bincode::Options;

/// The most bytes the default `verify_observation` reads as a `MerkleProof`.
///
/// The proof is relayer-provided input and its `siblings` is a
/// length-prefixed vector, so an unbounded decode lets a length word ask for
/// memory before any verification. A path is one sibling per tree level and
/// the leaf index is a `usize`, so a valid proof has at most 64 siblings:
/// 32 bytes of leaf, 8 of index, 8 of length and 64 * 32 of siblings is
/// 2096 bytes. Four KiB holds every valid proof with room and nothing an
/// attacker would want.
const MAX_RECEIPT_PROOF_BYTES: u64 = 4 * 1024;

/// Errors from chain adapter operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// The chain is not supported by this adapter.
    UnsupportedChain(ExternalChain),
    /// Failed to connect to the external chain's RPC/provider.
    ConnectionFailed(String),
    /// The transaction was not found on the external chain.
    TransactionNotFound(String),
    /// Proof generation failed.
    ProofGenerationFailed(String),
    /// Proof verification failed.
    ProofVerificationFailed(String),
    /// Transaction submission failed.
    SubmissionFailed(String),
    /// Timeout waiting for confirmation.
    ConfirmationTimeout,
    /// Generic adapter error.
    Other(String),
    /// A registry may expose at most one authoritative adapter per chain.
    DuplicateChainAdapter(ExternalChain),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::UnsupportedChain(chain) => {
                write!(f, "unsupported chain: {:?}", chain)
            }
            AdapterError::ConnectionFailed(msg) => {
                write!(f, "connection failed: {}", msg)
            }
            AdapterError::TransactionNotFound(hash) => {
                write!(f, "transaction not found: {}", hash)
            }
            AdapterError::ProofGenerationFailed(msg) => {
                write!(f, "proof generation failed: {}", msg)
            }
            AdapterError::ProofVerificationFailed(msg) => {
                write!(f, "proof verification failed: {}", msg)
            }
            AdapterError::SubmissionFailed(msg) => {
                write!(f, "submission failed: {}", msg)
            }
            AdapterError::ConfirmationTimeout => {
                write!(f, "confirmation timeout")
            }
            AdapterError::Other(msg) => write!(f, "adapter error: {}", msg),
            AdapterError::DuplicateChainAdapter(chain) => {
                write!(f, "duplicate adapter for chain: {:?}", chain)
            }
        }
    }
}

impl std::error::Error for AdapterError {}

/// Trait for external chain adapters.
///
/// Each chain (Ethereum, Solana, Bitcoin, etc.) provides an implementation.
/// The Universal Relayer delegates chain-specific operations to the adapter.
#[async_trait::async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Which external chain this adapter supports.
    fn chain_type(&self) -> ExternalChain;

    /// Generate a Merkle proof for a transaction receipt on the external chain.
    ///
    /// Returns the proof, the external state root that anchors it, and the
    /// Transaction hash on the external chain.
    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError>;

    /// Verify a receipt proof against the external chain's state root.
    ///
    /// This is used for on-chain verification when the relayer submits
    /// A RelayerResult back to Budlum.
    fn verify_receipt_proof(
        &self,
        proof: &MerkleProof,
        external_state_root: &Hash32,
        expected_tx_hash: &str,
    ) -> Result<(), AdapterError>;

    /// Verify the whole observation this adapter handed back, before the
    /// relayer signs it.
    ///
    /// The default reads `receipt_proof` as a bincode `MerkleProof` and runs
    /// `verify_receipt_proof` over it, which is what every adapter's
    /// observation held until the EVM one grew a stronger check. An adapter
    /// whose observation carries more than a Merkle path overrides this and
    /// verifies all of it: the EVM adapter refuses the bare path here and
    /// demands the full deposit package, header chain and receipt included.
    ///
    /// # Errors
    ///
    /// `ProofVerificationFailed` when the proof does not decode within
    /// `MAX_RECEIPT_PROOF_BYTES` or does not verify against the declared
    /// root and transaction hash. The decoder is the fixed-integer one that
    /// `bincode::serialize` writes, with a byte limit, so a length word in
    /// the input cannot ask for memory before the proof is checked.
    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        let proof: MerkleProof = bincode::options()
            .with_fixint_encoding()
            .with_limit(MAX_RECEIPT_PROOF_BYTES)
            .deserialize(&result.receipt_proof)
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!(
                    "adapter returned a receipt proof that does not decode within \
                     {MAX_RECEIPT_PROOF_BYTES} bytes: {e}"
                ))
            })?;
        self.verify_receipt_proof(&proof, &result.external_state_root, &result.tx_hash)
    }

    /// Is this adapter configured well enough to be trusted with real value?
    ///
    /// Asked once, when the adapter is registered, rather than at each
    /// deposit. An adapter that answers no is refused registration, so a
    /// misconfigured one cannot sit in the registry advertising support for a
    /// chain it cannot verify.
    ///
    /// The default answers yes, because most adapters carry no configuration
    /// that can be wrong. An adapter that does carry some, like the EVM one
    /// with its bridge address and confirmation depth, overrides this.
    ///
    /// # Errors
    ///
    /// A message naming what is misconfigured.
    fn check_fit_for_relay(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    /// Submit a transaction to the external chain.
    ///
    /// Returns the transaction hash on the external chain.
    async fn submit_transaction(
        &self,
        ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError>;

    /// Wait for a transaction to be confirmed on the external chain.
    ///
    /// Returns the receipt proof once confirmed.
    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError>;
}

/// Registry of chain adapters. The relayer looks up the appropriate adapter
/// By chain type.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn ChainAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Register a chain adapter that is fit to relay.
    ///
    /// The fitness check runs here rather than at deposit time, so a
    /// misconfigured adapter never reaches the registry. Doing it the other
    /// way round means the node starts, advertises support for a chain, and
    /// only refuses once a user has already paid to bridge.
    ///
    /// # Errors
    ///
    /// Whatever [`ChainAdapter::check_fit_for_relay`] reports.
    pub fn register(&mut self, adapter: Box<dyn ChainAdapter>) -> Result<(), AdapterError> {
        let chain = adapter.chain_type();
        if self.adapters.iter().any(|existing| existing.chain_type() == chain) {
            return Err(AdapterError::DuplicateChainAdapter(chain));
        }
        adapter.check_fit_for_relay()?;
        self.adapters.push(adapter);
        Ok(())
    }

    /// Find the adapter for a given chain type.
    pub fn get(&self, chain: &ExternalChain) -> Option<&dyn ChainAdapter> {
        self.adapters
            .iter()
            .find(|a| &a.chain_type() == chain)
            .map(|a| a.as_ref())
    }

    /// Check if a chain is supported.
    pub fn supports(&self, chain: &ExternalChain) -> bool {
        self.get(chain).is_some()
    }

    /// List all supported chains.
    pub fn supported_chains(&self) -> Vec<ExternalChain> {
        self.adapters.iter().map(|a| a.chain_type()).collect()
    }
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Stub adapter for testing and development.
/// Generates deterministic proofs that pass verification.
#[cfg(test)]
pub mod test_adapter {
    use super::*;
    use crate::core::hash::hash_fields_bytes;

    pub struct StubAdapter {
        chain: ExternalChain,
    }

    impl StubAdapter {
        pub fn new(chain: ExternalChain) -> Self {
            Self { chain }
        }
    }

    #[async_trait::async_trait]
    impl ChainAdapter for StubAdapter {
        fn chain_type(&self) -> ExternalChain {
            self.chain
        }

        async fn generate_receipt_proof(
            &self,
            tx_hash: &str,
        ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
            let leaf = hash_fields_bytes(&[b"BDLM_STUB_RECEIPT_V1", tx_hash.as_bytes()]);
            let proof = MerkleProof {
                leaf,
                index: 0,
                siblings: Vec::new(),
            };
            Ok((proof, leaf, tx_hash.to_string()))
        }

        fn verify_receipt_proof(
            &self,
            proof: &MerkleProof,
            external_state_root: &Hash32,
            _expected_tx_hash: &str,
        ) -> Result<(), AdapterError> {
            if proof.verify(*external_state_root) {
                Ok(())
            } else {
                Err(AdapterError::ProofVerificationFailed(
                    "stub verification failed".into(),
                ))
            }
        }

        async fn submit_transaction(
            &self,
            _ext_tx: &ExternalTransaction,
        ) -> Result<String, AdapterError> {
            Ok(format!("0x{}", hex::encode([0xEE; 32])))
        }

        async fn wait_for_confirmation(
            &self,
            tx_hash: &str,
            _confirmations: u32,
        ) -> Result<RelayerExternalResult, AdapterError> {
            let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
            Ok(RelayerExternalResult {
                chain: self.chain,
                tx_hash: hash,
                success: true,
                message: None,
                receipt_proof: bincode::serialize(&proof).unwrap_or_default(),
                external_state_root: root,
            })
        }
    }

    #[tokio::test]
    async fn stub_adapter_round_trip() {
        let adapter = StubAdapter::new(ExternalChain::Ethereum);
        assert_eq!(adapter.chain_type(), ExternalChain::Ethereum);

        let (proof, root, hash) = adapter.generate_receipt_proof("0xabc123").await.unwrap();
        assert!(adapter.verify_receipt_proof(&proof, &root, &hash).is_ok());

        let result = adapter.wait_for_confirmation("0xabc123", 1).await.unwrap();
        assert!(result.success);
        assert_eq!(result.chain, ExternalChain::Ethereum);
        assert!(adapter.verify_observation(&result).is_ok());
    }

    /// The default observation check decodes the proof under a byte limit.
    /// A proof at the ceiling of a valid path still decodes; a `siblings`
    /// length word asking for more than the limit is refused as a decode
    /// error before any allocation, and so is a proof padded past the limit.
    #[tokio::test]
    async fn the_default_observation_decode_is_bounded() {
        let adapter = StubAdapter::new(ExternalChain::Ethereum);
        let mut result = adapter.wait_for_confirmation("0xabc123", 1).await.unwrap();

        let deep = MerkleProof {
            leaf: [7u8; 32],
            index: 0,
            siblings: vec![[9u8; 32]; 64],
        };
        let encoded = bincode::serialize(&deep).unwrap();
        assert!(
            (encoded.len() as u64) < MAX_RECEIPT_PROOF_BYTES,
            "a 64-level path ({} bytes) must fit under the ceiling",
            encoded.len()
        );
        result.receipt_proof = encoded;
        let err = adapter.verify_observation(&result).unwrap_err();
        assert!(
            !err.to_string().contains("does not decode"),
            "a deep but valid encoding is refused by verification, not by the decoder: {err}"
        );

        // 32-byte leaf, 8-byte index, then a length word claiming 2^40 siblings.
        let mut hostile = vec![7u8; 40];
        hostile.extend_from_slice(&(1u64 << 40).to_le_bytes());
        result.receipt_proof = hostile;
        let err = adapter.verify_observation(&result).unwrap_err();
        assert!(err.to_string().contains("does not decode"), "{err}");

        let mut padded = bincode::serialize(&deep).unwrap();
        padded.resize(MAX_RECEIPT_PROOF_BYTES as usize + 1, 0);
        result.receipt_proof = padded;
        let err = adapter.verify_observation(&result).unwrap_err();
        assert!(err.to_string().contains("does not decode"), "{err}");
    }

    #[test]
    fn adapter_registry_basic() {
        let mut registry = AdapterRegistry::new();
        assert!(!registry.supports(&ExternalChain::Ethereum));

        registry
            .register(Box::new(StubAdapter::new(ExternalChain::Ethereum)))
            .expect("stub adapter must be fit to relay");
        assert!(registry.supports(&ExternalChain::Ethereum));
        assert!(!registry.supports(&ExternalChain::Solana));

        let chains = registry.supported_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0], ExternalChain::Ethereum);
    }

    #[test]
    fn duplicate_chain_adapters_are_refused_instead_of_shadowed() {
        let mut registry = AdapterRegistry::new();
        registry
            .register(Box::new(StubAdapter::new(ExternalChain::Ethereum)))
            .expect("first adapter must register");
        let err = registry
            .register(Box::new(StubAdapter::new(ExternalChain::Ethereum)))
            .expect_err("a second adapter must not become an unreachable shadow");
        assert_eq!(
            err,
            AdapterError::DuplicateChainAdapter(ExternalChain::Ethereum)
        );
        assert_eq!(registry.supported_chains().len(), 1);
    }
}

#[test]
fn adapter_registry_empty_supported_chains() {
    let registry = AdapterRegistry::new();
    assert!(registry.supported_chains().is_empty());
    assert!(!registry.supports(&ExternalChain::Ethereum));
    assert!(!registry.supports(&ExternalChain::Solana));
}

#[test]
fn adapter_registry_multiple_adapters() {
    use self::test_adapter::StubAdapter;

    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(StubAdapter::new(ExternalChain::Ethereum)))
        .expect("stub adapter must be fit to relay");
    registry
        .register(Box::new(StubAdapter::new(ExternalChain::Solana)))
        .expect("stub adapter must be fit to relay");

    assert!(registry.supports(&ExternalChain::Ethereum));
    assert!(registry.supports(&ExternalChain::Solana));
    assert!(!registry.supports(&ExternalChain::Bitcoin));

    let chains = registry.supported_chains();
    assert_eq!(chains.len(), 2);
}

#[test]
fn adapter_error_display() {
    let err = AdapterError::UnsupportedChain(ExternalChain::Bitcoin);
    assert!(err.to_string().contains("Bitcoin"));

    let err = AdapterError::ConnectionFailed("timeout".into());
    assert!(err.to_string().contains("timeout"));

    let err = AdapterError::ConfirmationTimeout;
    assert!(err.to_string().contains("timeout"));
}
