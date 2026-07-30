use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::cross_domain::chain_adapter::{AdapterError, AdapterRegistry};
use crate::crypto::primitives::KeyPair;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Universal Relayer Worker.
/// Watches the Budlum chain for UniversalRelay transactions and
/// relays them to external chains (EVM, Solana, etc.).
///
/// # What this worker is allowed to assert
///
/// A `RelayerResult` transaction is a *claim about another chain*. Budlum's
/// consensus can only check that claim against a finalized light-client
/// anchor, so the worker must never manufacture one. Concretely:
///
/// - the external transaction hash comes from an adapter that actually
///   broadcast it, never from a constant;
/// - the receipt proof comes from an adapter that read the external chain,
///   never from a locally invented single-leaf tree;
/// - the adapter re-verifies its own proof (`verify_receipt_proof`) before
///   the result is signed, so a broken or dishonest adapter is caught here
///   rather than by consensus after the signature exists.
///
/// If any of those cannot be satisfied, the worker submits nothing. A relayer
/// that stays silent stalls a transfer; a relayer that signs an unverified
/// success is indistinguishable from an attacker, because the signature makes
/// the lie authentic. That asymmetry is why every failure path below is a
/// refusal and not a fallback.
pub struct RelayerWorker {
    chain: ChainHandle,
    /// Rewards for the relayer are minted in $BUD (Decision 9).
    relayer_address: Address,
    /// Relayer must sign result TXs.
    /// Without a signing key, the worker refuses to submit results
    /// (fail-closed).
    relayer_keypair: Option<Arc<KeyPair>>,
    /// Chain adapters that can actually reach the external chains.
    ///
    /// Empty by default: a worker with no adapter can observe relay requests
    /// but cannot produce a result for any of them.
    adapters: Arc<AdapterRegistry>,
}

impl RelayerWorker {
    pub fn new(chain: ChainHandle, relayer_address: Address) -> Self {
        Self {
            chain,
            relayer_address,
            relayer_keypair: None,
            adapters: Arc::new(AdapterRegistry::new()),
        }
    }

    /// Bind a signing key so result TXs are
    /// cryptographically signed before injection into the chain.
    #[must_use]
    pub fn with_signing_key(mut self, keypair: Arc<KeyPair>) -> Self {
        self.relayer_keypair = Some(keypair);
        self
    }

    /// Bind the chain adapters this worker may relay through.
    ///
    /// Without this, [`Self::build_verified_result`] refuses every chain: the
    /// worker has no way to observe an external chain, so it has nothing
    /// truthful to report.
    #[must_use]
    pub fn with_adapters(mut self, adapters: Arc<AdapterRegistry>) -> Self {
        self.adapters = adapters;
        self
    }

    pub async fn run(self) {
        info!(
            "Universal Relayer Worker started for {}",
            self.relayer_address
        );
        if self.adapters.supported_chains().is_empty() {
            warn!(
                "Relayer worker started with no chain adapters registered. It will observe \
                 relay requests but refuse to submit results for any chain. Use \
                 RelayerWorker::with_adapters() to bind real adapters."
            );
        }

        let mut last_height = self.chain.get_height().await;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let current_height = self.chain.get_height().await;
            if current_height <= last_height {
                continue;
            }

            for h in (last_height + 1)..=current_height {
                if let Some(block) = self.chain.get_block(h).await {
                    for tx in block.transactions {
                        if let TransactionType::UniversalRelay(ext_tx) = tx.tx_type {
                            info!(
                                chain = ?ext_tx.chain,
                                target = %ext_tx.target_address,
                                "Relayer: Detected external transaction request"
                            );

                            self.process_relay(tx.from, ext_tx).await;
                        }
                    }
                }
            }
            last_height = current_height;
        }
    }

    /// Produce a result that is backed by an adapter observation, or an error.
    ///
    /// Separated from [`Self::process_relay`] so the refusal behaviour is
    /// directly testable without a running chain actor: the interesting
    /// property is that no input can make this return a `success: true`
    /// result the adapter did not verify.
    pub async fn build_verified_result(
        adapters: &AdapterRegistry,
        ext_tx: &crate::core::transaction::ExternalTransaction,
    ) -> Result<crate::core::transaction::RelayerExternalResult, AdapterError> {
        let adapter = adapters
            .get(&ext_tx.chain)
            .ok_or(AdapterError::UnsupportedChain(ext_tx.chain))?;

        // Broadcast, then read the result back off the external chain. Both
        // steps are the adapter's job precisely because only the adapter is
        // allowed to talk to that chain.
        let tx_hash = adapter.submit_transaction(ext_tx).await?;
        let result = adapter
            .wait_for_confirmation(&tx_hash, CONFIRMATION_DEPTH)
            .await?;

        // An adapter is not trusted to be correct, only to be the source. Its
        // own verifier runs against its own output before anything is signed.
        let proof: crate::cross_domain::event_tree::MerkleProof =
            bincode::deserialize(&result.receipt_proof).map_err(|e| {
                AdapterError::ProofVerificationFailed(format!(
                    "adapter returned a receipt proof that does not decode: {e}"
                ))
            })?;
        adapter.verify_receipt_proof(&proof, &result.external_state_root, &result.tx_hash)?;

        if result.chain != ext_tx.chain {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "adapter for {:?} returned a result tagged {:?}",
                ext_tx.chain, result.chain
            )));
        }
        if result.external_state_root == [0u8; 32] {
            return Err(AdapterError::ProofVerificationFailed(
                "adapter returned a zero external state root, which anchors nothing".into(),
            ));
        }

        Ok(result)
    }

    async fn process_relay(
        &self,
        user: Address,
        ext_tx: crate::core::transaction::ExternalTransaction,
    ) {
        let result = match Self::build_verified_result(&self.adapters, &ext_tx).await {
            Ok(result) => result,
            Err(e) => {
                // Refuse, loudly. Submitting an unverified success here would
                // be worse than submitting nothing: the relayer's signature
                // would make a fabricated external outcome look authentic.
                warn!(
                    chain = ?ext_tx.chain,
                    target = %ext_tx.target_address,
                    error = %e,
                    "Relayer: refusing to submit a relay result that is not backed by a \
                     verified adapter observation"
                );
                return;
            }
        };

        // Submit result back to Budlum. The relayer signs with its own key
        // via the Node's signer; the transaction is injected through the
        // chain handle for inclusion in the next block.
        let mut result_tx = Transaction::new_with_chain_id(
            self.relayer_address,
            user, // to: original UniversalRelay caller
            0,
            100, // Fee
            self.chain.get_nonce(&self.relayer_address).await,
            Vec::new(),
            self.chain.get_chain_id().await,
            TransactionType::RelayerResult(result),
        );

        // Relayer MUST sign result TXs.
        // Fail-closed: if no signing key is configured, refuse to submit.
        // Unsigned TXs in the chain would allow forged relay results.
        match &self.relayer_keypair {
            Some(kp) => {
                result_tx.sign(kp);
                let _ = self.chain.add_transaction(result_tx).await;
            }
            None => {
                error!(
                    "CRITICAL: Relayer worker has no signing key configured. \
                     Refusing to submit unsigned relay result (P8-01 fail-closed). \
                     Use RelayerWorker::with_signing_key() to bind a key."
                );
            }
        }
    }
}

/// Confirmation depth required before a result is considered readable.
///
/// Reuses the EVM reorg window rather than defining a second number, so the
/// worker cannot drift into accepting a shallower confirmation than the
/// verifier was calibrated for. A one-block confirmation is not a
/// confirmation on any chain this bridge targets.
const CONFIRMATION_DEPTH: u32 = crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;
