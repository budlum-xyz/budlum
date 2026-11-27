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

/// Test adapters have no external anchor to give, so the default
/// `verify_observation` refuses them. This is the self-check they
/// stand in with: decode the proof and verify it against the root the result
/// itself carries. Valid for a stub only - it proves the result is
/// self-consistent, nothing about the external chain.
#[cfg(test)]
pub(crate) fn self_checked_observation<A: ChainAdapter + ?Sized>(
    adapter: &A,
    result: &RelayerExternalResult,
) -> Result<(), AdapterError> {
    if result.chain != adapter.chain_type() {
        return Err(AdapterError::UnsupportedChain(result.chain));
    }
    if !result.success {
        return Err(AdapterError::ProofVerificationFailed(
            "external transaction execution reported failure".into(),
        ));
    }
    let proof: MerkleProof = bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_PROOF_BYTES)
        .reject_trailing_bytes()
        .deserialize(&result.receipt_proof)
        .map_err(|e| {
            AdapterError::ProofVerificationFailed(format!(
                "adapter returned a receipt proof that does not decode within \
                 {MAX_RECEIPT_PROOF_BYTES} bytes: {e}"
            ))
        })?;
    adapter.verify_receipt_proof(&proof, &result.external_state_root, &result.tx_hash)
}

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
            Self::UnsupportedChain(chain) => {
                write!(f, "unsupported chain: {chain:?}")
            }
            Self::ConnectionFailed(msg) => {
                write!(f, "connection failed: {msg}")
            }
            Self::TransactionNotFound(hash) => {
                write!(f, "transaction not found: {hash}")
            }
            Self::ProofGenerationFailed(msg) => {
                write!(f, "proof generation failed: {msg}")
            }
            Self::ProofVerificationFailed(msg) => {
                write!(f, "proof verification failed: {msg}")
            }
            Self::SubmissionFailed(msg) => {
                write!(f, "submission failed: {msg}")
            }
            Self::ConfirmationTimeout => {
                write!(f, "confirmation timeout")
            }
            Self::Other(msg) => write!(f, "adapter error: {msg}"),
            Self::DuplicateChainAdapter(chain) => {
                write!(f, "duplicate adapter for chain: {chain:?}")
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
    /// A `RelayerResult` back to Budlum.
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
    /// The root an observation must agree with, from a source the adapter
    /// TRUSTS (a checkpoint, a light client), never from the observation
    /// itself. `None` (the default) means the adapter has no anchor; the
    /// default [`Self::verify_observation`] then refuses the observation.
    fn trusted_observation_root(&self) -> Option<Hash32> {
        None
    }

    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        if result.chain != self.chain_type() {
            return Err(AdapterError::UnsupportedChain(result.chain));
        }
        if !result.success {
            return Err(AdapterError::ProofVerificationFailed(
                "external transaction execution reported failure".into(),
            ));
        }
        // The root must NOT come from the same result
        // being verified - that only proved the result is self-consistent.
        // The default fails closed: an adapter without a trusted anchor
        // overrides this method with a real check.
        let trusted = self.trusted_observation_root().ok_or_else(|| {
            AdapterError::ProofVerificationFailed(
                "no trusted observation root: refusing to check an observation \
                 against a root the same result supplies"
                    .into(),
            )
        })?;
        if result.external_state_root != trusted {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "observation root {} does not match the trusted root {}",
                hex::encode(result.external_state_root),
                hex::encode(trusted)
            )));
        }
        let proof: MerkleProof = bincode::options()
            .with_fixint_encoding()
            .with_limit(MAX_RECEIPT_PROOF_BYTES)
            .reject_trailing_bytes()
            .deserialize(&result.receipt_proof)
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!(
                    "adapter returned a receipt proof that does not decode within \
                     {MAX_RECEIPT_PROOF_BYTES} bytes: {e}"
                ))
            })?;
        self.verify_receipt_proof(&proof, &trusted, &result.tx_hash)
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
    #[must_use]
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
        if self
            .adapters
            .iter()
            .any(|existing| existing.chain_type() == chain)
        {
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
            .map(std::convert::AsRef::as_ref)
    }

    /// Verify an external observation through the registered adapter for `result.chain`.
    ///
    /// # Errors
    ///
    /// Fails closed with [`AdapterError::UnsupportedChain`] if no adapter is
    /// registered for `result.chain`, or propagates the adapter's verification error.
    pub fn verify_observation_for_chain(
        &self,
        result: &RelayerExternalResult,
    ) -> Result<(), AdapterError> {
        let adapter = self
            .get(&result.chain)
            .ok_or(AdapterError::UnsupportedChain(result.chain))?;
        adapter.verify_observation(result)
    }

    /// Register an anchored Bitcoin SPV adapter (`min_confirmations >= 6`).
    ///
    /// # Errors
    ///
    /// Propagates [`AdapterRegistry::register`] and adapter fitness failures.
    pub fn register_bitcoin_spv(
        &mut self,
        trusted_merkle_root: Hash32,
        min_confirmations: u32,
    ) -> Result<(), AdapterError> {
        let min_conf = min_confirmations
            .max(crate::cross_domain::multi_chain_adapters::MIN_BITCOIN_SPV_CONFIRMATIONS);
        if min_confirmations < min_conf {
            return Err(AdapterError::Other(format!(
                "Bitcoin SPV min_confirmations {min_confirmations} below {min_conf}"
            )));
        }
        let adapter = crate::cross_domain::multi_chain_adapters::BitcoinSpvChainAdapter::new(
            Some(trusted_merkle_root),
            min_confirmations,
        );
        self.register(Box::new(adapter))
    }

    /// Register an anchored Cosmos ICS-23 adapter bound to `store_prefix`.
    ///
    /// # Errors
    ///
    /// Propagates [`AdapterRegistry::register`] and adapter fitness failures.
    pub fn register_cosmos_ics23(
        &mut self,
        chain_domain_id: u32,
        store_prefix: Vec<u8>,
        trusted_app_hash: Hash32,
    ) -> Result<(), AdapterError> {
        let domain_id = if chain_domain_id == 0 {
            crate::cross_domain::multi_chain_adapters::COSMOS_DEFAULT_CHAIN_DOMAIN_ID
        } else {
            chain_domain_id
        };
        let adapter = crate::cross_domain::multi_chain_adapters::CosmosIcs23ChainAdapter::new(
            domain_id,
            store_prefix,
            Some(trusted_app_hash),
        );
        self.register(Box::new(adapter))
    }

    /// Register an anchored Solana bank-hash + account/tx inclusion adapter.
    ///
    /// # Errors
    ///
    /// Propagates [`AdapterRegistry::register`] and adapter fitness failures.
    pub fn register_solana_bank(
        &mut self,
        trusted_bank_hash: Hash32,
        trusted_accounts_delta_root: Hash32,
        trusted_tx_root: Hash32,
        min_confirmed_slot: u64,
    ) -> Result<(), AdapterError> {
        let adapter = crate::cross_domain::multi_chain_adapters::SolanaBankChainAdapter::new(
            Some(trusted_bank_hash),
            Some(trusted_accounts_delta_root),
            Some(trusted_tx_root),
            min_confirmed_slot,
        );
        self.register(Box::new(adapter))
    }

    /// Assemble and verify a Bitcoin SPV observation against the registered Bitcoin adapter.
    ///
    /// # Errors
    ///
    /// Fails closed on zero root, encoding errors, unregistered adapter, or proof failure.
    pub fn verify_bitcoin_spv_proof(
        &self,
        proof: &crate::cross_domain::multi_chain_adapters::BitcoinSpvReceiptProof,
        merkle_root: Hash32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let obs = crate::cross_domain::multi_chain_adapters::assemble_bitcoin_spv_observation(
            proof,
            merkle_root,
        )?;
        self.verify_observation_for_chain(&obs)?;
        Ok(obs)
    }

    /// Assemble and verify a Cosmos ICS-23 existence observation against the registered adapter.
    ///
    /// # Errors
    ///
    /// Fails closed on zero root, prefix mismatch, ICS-23 mismatch, or unregistered adapter.
    pub fn verify_cosmos_ics23_proof(
        &self,
        chain_domain_id: u32,
        proof: &crate::cross_domain::multi_chain_adapters::CosmosIcs23ReceiptProof,
        app_hash: Hash32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let _ops: &[crate::cross_domain::multi_chain_adapters::Ics23InnerOp] = &proof.inner_ops;
        let computed =
            crate::cross_domain::multi_chain_adapters::compute_ics23_existence_root(proof)?;
        if computed != app_hash {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos ICS-23 existence root mismatch".into(),
            ));
        }
        let expected_digest =
            crate::cross_domain::multi_chain_adapters::compute_cosmos_receipt_tx_hash(proof);
        let obs = crate::cross_domain::multi_chain_adapters::assemble_cosmos_ics23_observation(
            chain_domain_id,
            proof,
            app_hash,
        )?;
        if obs.tx_hash != hex::encode(expected_digest) {
            return Err(AdapterError::ProofVerificationFailed(
                "Cosmos observation tx_hash mismatch".into(),
            ));
        }
        self.verify_observation_for_chain(&obs)?;
        Ok(obs)
    }

    /// Assemble and verify a Solana bank-hash + account/tx observation against the registered adapter.
    ///
    /// # Errors
    ///
    /// Fails closed on bank-commitment mismatch, account/tx branch failure, or unregistered adapter.
    pub fn verify_solana_bank_proof(
        &self,
        proof: &crate::cross_domain::multi_chain_adapters::SolanaAccountReceiptProof,
        bank_hash: Hash32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let acct_leaf = crate::cross_domain::multi_chain_adapters::compute_solana_account_leaf(
            &proof.account_pubkey,
            &proof.account_data_hash,
            proof.lamports,
        );
        let acct_root = crate::cross_domain::multi_chain_adapters::compute_solana_merkle_root(
            &acct_leaf,
            &proof.account_branch,
        );
        let tx_leaf = crate::cross_domain::multi_chain_adapters::compute_solana_tx_leaf(
            &proof.tx_signature_hash,
            proof.slot,
        );
        let tx_root = crate::cross_domain::multi_chain_adapters::compute_solana_merkle_root(
            &tx_leaf,
            &proof.tx_branch,
        );
        let expected_bank =
            crate::cross_domain::multi_chain_adapters::compute_solana_bank_commitment(
                &proof.parent_bank_hash,
                &acct_root,
                &tx_root,
                proof.slot,
            );
        if expected_bank != bank_hash {
            return Err(AdapterError::ProofVerificationFailed(
                "Solana bank commitment mismatch".into(),
            ));
        }
        let obs = crate::cross_domain::multi_chain_adapters::assemble_solana_bank_observation(
            proof, bank_hash,
        )?;
        self.verify_observation_for_chain(&obs)?;
        Ok(obs)
    }

    /// Check if a chain is supported.
    #[must_use]
    pub fn supports(&self, chain: &ExternalChain) -> bool {
        self.get(chain).is_some()
    }

    /// List all supported chains.
    #[must_use]
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
        #[must_use]
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

        // A STUB: it stands in for plumbing, so it self-checks on purpose.
        // The default now fails closed, and the stub has no
        // anchor to give.
        fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
            if result.chain != self.chain {
                return Err(AdapterError::UnsupportedChain(result.chain));
            }
            if !result.success {
                return Err(AdapterError::ProofVerificationFailed(
                    "observation indicates failure".into(),
                ));
            }
            let proof: MerkleProof = bincode::options()
                .with_fixint_encoding()
                .with_limit(MAX_RECEIPT_PROOF_BYTES)
                .reject_trailing_bytes()
                .deserialize(&result.receipt_proof)
                .map_err(|e| {
                    AdapterError::ProofVerificationFailed(format!(
                        "stub proof does not decode: {e}"
                    ))
                })?;
            self.verify_receipt_proof(&proof, &result.external_state_root, &result.tx_hash)
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

    #[tokio::test]
    async fn verify_observation_refuses_failed_and_cross_chain_results() {
        let adapter = StubAdapter::new(ExternalChain::Ethereum);
        let valid = adapter.wait_for_confirmation("0xabc123", 1).await.unwrap();
        assert!(adapter.verify_observation(&valid).is_ok());

        let mut failed = valid.clone();
        failed.success = false;
        assert!(matches!(
            adapter.verify_observation(&failed),
            Err(AdapterError::ProofVerificationFailed(_))
        ));

        let mut wrong_chain = valid;
        wrong_chain.chain = ExternalChain::Solana;
        assert_eq!(
            adapter.verify_observation(&wrong_chain),
            Err(AdapterError::UnsupportedChain(ExternalChain::Solana))
        );
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

#[cfg(test)]
#[tokio::test]
async fn verify_observation_refuses_trailing_bytes_after_valid_proof() {
    use self::test_adapter::StubAdapter;
    let adapter = StubAdapter::new(ExternalChain::Ethereum);
    let mut result = adapter.wait_for_confirmation("0xabc123", 1).await.unwrap();
    adapter
        .verify_observation(&result)
        .expect("canonical receipt proof verifies");
    result
        .receipt_proof
        .extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let err = adapter
        .verify_observation(&result)
        .expect_err("trailing garbage after canonical receipt proof must be refused");
    assert!(err.to_string().contains("decode"), "got: {err}");
}
