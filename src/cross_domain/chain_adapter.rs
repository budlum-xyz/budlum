//! Multi-chain adapter trait for the Universal Relayer.
//!
//! Each supported external chain (Ethereum, Solana, Bitcoin, etc.) implements
//! this trait to provide:
//! - Proof generation (Merkle proof of transaction receipt)
//! - Proof verification (against the chain's state root)
//! - Transaction submission (broadcast signed tx to external chain)
//!
//! The relayer is chain-agnostic at the orchestrator level — it delegates
//! chain-specific logic to the adapter.

use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::event_tree::MerkleProof;
use crate::domain::types::Hash32;

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
    /// transaction hash on the external chain.
    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError>;

    /// Verify a receipt proof against the external chain's state root.
    ///
    /// This is used for on-chain verification when the relayer submits
    /// a RelayerResult back to Budlum.
    fn verify_receipt_proof(
        &self,
        proof: &MerkleProof,
        external_state_root: &Hash32,
        expected_tx_hash: &str,
    ) -> Result<(), AdapterError>;

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
/// by chain type.
pub struct AdapterRegistry {
    adapters: Vec<Box<dyn ChainAdapter>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    /// Register a chain adapter.
    pub fn register(&mut self, adapter: Box<dyn ChainAdapter>) {
        self.adapters.push(adapter);
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
            ext_tx: &ExternalTransaction,
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
    }

    #[test]
    fn adapter_registry_basic() {
        let mut registry = AdapterRegistry::new();
        assert!(!registry.supports(&ExternalChain::Ethereum));

        registry.register(Box::new(StubAdapter::new(ExternalChain::Ethereum)));
        assert!(registry.supports(&ExternalChain::Ethereum));
        assert!(!registry.supports(&ExternalChain::Solana));

        let chains = registry.supported_chains();
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0], ExternalChain::Ethereum);
    }
}
