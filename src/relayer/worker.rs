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
    /// Where the relay cursor is persisted between runs.
    ///
    /// `None` keeps the previous in-memory behaviour, which is what the tests
    /// and any embedded use rely on; a deployed relayer sets this.
    cursor_path: Option<std::path::PathBuf>,
}

impl RelayerWorker {
    pub fn new(chain: ChainHandle, relayer_address: Address) -> Self {
        Self {
            chain,
            relayer_address,
            relayer_keypair: None,
            adapters: Arc::new(AdapterRegistry::new()),
            cursor_path: None,
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

    /// Persist the relay cursor to `path` so a restart resumes where it left
    /// off.
    ///
    /// Without this the cursor starts at whatever `get_finalized_height()`
    /// returns at boot, and every relay request finalized while the worker was
    /// down is skipped. The user has already paid the fee and the request sits
    /// on chain forever with nothing acting on it — a silent service failure,
    /// not a loud one.
    #[must_use]
    pub fn with_cursor_path(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.cursor_path = path;
        self
    }

    /// Read the persisted cursor, or `None` when there is nothing to resume.
    ///
    /// A malformed or unreadable file is treated as absent and logged rather
    /// than fatal: refusing to start would turn a corrupt cursor into an
    /// outage, and resuming from the chain tip is the behaviour this had
    /// before the file existed.
    fn load_cursor(&self) -> Option<u64> {
        let path = self.cursor_path.as_ref()?;
        match std::fs::read_to_string(path) {
            Ok(text) => match text.trim().parse::<u64>() {
                Ok(height) => {
                    info!(height, path = %path.display(), "Relayer: resuming from persisted cursor");
                    Some(height)
                }
                Err(e) => {
                    warn!(error = %e, path = %path.display(),
                          "Relayer: cursor file is not a height; resuming from the chain tip");
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!(error = %e, path = %path.display(),
                      "Relayer: cursor unreadable; resuming from the chain tip");
                None
            }
        }
    }

    /// Write the cursor after a batch of heights has been relayed.
    ///
    /// Written *after* the relays, never before: a cursor ahead of the work is
    /// how requests get skipped, which is the bug this exists to prevent. The
    /// cost of the opposite ordering is a repeated relay attempt after a crash,
    /// which the chain-side replay protection already refuses.
    fn save_cursor(&self, height: u64) {
        let Some(path) = self.cursor_path.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(error = %e, path = %path.display(), "Relayer: cannot create cursor directory");
                return;
            }
        }
        if let Err(e) = std::fs::write(path, height.to_string()) {
            warn!(error = %e, path = %path.display(), height,
                  "Relayer: failed to persist cursor; a restart will skip relayed heights");
        }
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

        // The cursor follows finalized height, not chain height.
        //
        // Relaying is an external side effect: once a transaction has been
        // submitted to another chain it cannot be recalled. Following
        // `get_height()` meant relaying blocks that a reorg could still
        // remove, so a request that ended up off the canonical chain had
        // already been sent. Finalized height never moves backwards, so a
        // relayed block is one that cannot be reorged away.
        //
        // The old loop also stalled permanently after a reorg. `last_height`
        // was set from chain height, and `if current_height <= last_height {
        // continue; }` then held forever on the shorter fork — the relayer
        // went quiet with nothing in the logs. Tracking a monotonic value
        // removes that state entirely.
        // Resume from the persisted cursor when there is one. Starting from the
        // current finalized height means every request finalized while this
        // worker was down is skipped silently.
        let mut relayed_through = match self.load_cursor() {
            Some(persisted) => persisted,
            None => self.chain.get_finalized_height().await,
        };

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let finalized = self.chain.get_finalized_height().await;
            if finalized <= relayed_through {
                continue;
            }

            for h in (relayed_through + 1)..=finalized {
                if let Some(block) = self.chain.get_block(h).await {
                    for tx in block.transactions {
                        if let TransactionType::UniversalRelay(ext_tx) = tx.tx_type {
                            info!(
                                chain = ?ext_tx.chain,
                                target = %ext_tx.target_address,
                                height = h,
                                "Relayer: Detected external transaction request"
                            );

                            self.process_relay(tx.from, ext_tx).await;
                        }
                    }
                }
            }
            relayed_through = finalized;
            self.save_cursor(relayed_through);
        }
    }

    /// Produce a result that is backed by an adapter observation, or an error.
    ///
    /// Separated from the private relay loop so the refusal behaviour is
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
