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
    /// Requests of the block under the cursor whose attempt is over, by
    /// transaction hash. Cleared when the cursor moves past the block. Kept
    /// so that a block held back by one retried request does not have its
    /// other requests relayed again on the next pass.
    settled: std::collections::HashSet<String>,
    /// Verified external observations whose result has not yet been seen
    /// in a finalized Budlum block, by request hash. A retry submits the
    /// stored result again instead of repeating the external action: the
    /// chain's replay guard refuses a second result, it does not undo a
    /// second transfer on the other chain.
    ///
    /// An entry outlives the block cursor. `add_transaction` confirms local
    /// acceptance into the mempool, not execution: the mempool can still
    /// drop the result (expiry, eviction, a restart before the next block),
    /// and a result dropped there is a paid request nobody acts on again.
    /// The entry is removed only when [`Self::reap_finalized`] finds the
    /// result transaction in a block at or below the finalized height, and
    /// the map is written to disk next to the cursor so a restart between
    /// the external action and that finality resumes the same submission.
    observed: std::collections::HashMap<String, PendingResult>,
}

/// A verified external result together with the hash of the result
/// transaction last submitted for it, when one has been accepted locally.
///
/// The transaction hash is what the finality check asks the chain about. A
/// resubmission after the mempool dropped the first copy signs a fresh
/// transaction (new nonce, new hash), and the hash is replaced with it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct PendingResult {
    /// The observation the adapter verified.
    result: crate::core::transaction::RelayerExternalResult,
    /// The hash of the signed result transaction the chain handle took last,
    /// or `None` when no submission has been accepted yet.
    submitted_tx: Option<String>,
}

/// The file name of the pending-result store, next to the cursor file.
const PENDING_FILE_NAME: &str = "relayer-pending.json";

impl RelayerWorker {
    pub fn new(chain: ChainHandle, relayer_address: Address) -> Self {
        Self {
            chain,
            relayer_address,
            relayer_keypair: None,
            adapters: Arc::new(AdapterRegistry::new()),
            cursor_path: None,
            settled: std::collections::HashSet::new(),
            observed: std::collections::HashMap::new(),
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
    ///
    /// # Off unless the operator says what to point at
    ///
    /// This had no caller for a long time, and the reason was configuration:
    /// `EvmChainAdapter::new` needs the bridge contract address and the
    /// `Deposit` topic0, and the node carried a field for neither. The
    /// registry was therefore empty on every deployed node, and
    /// `build_verified_result` answered `AdapterError::UnsupportedChain` for
    /// all eight `ExternalChain` variants, Ethereum included.
    ///
    /// `--evm-bridge-address` and `--evm-deposit-topic0` now exist, and
    /// `main.rs` calls this with whatever `NodeConfig::evm_adapter` assembles
    /// from them. A node that supplies neither still registers nothing and
    /// still refuses every chain, which is deliberate: there is nothing safe
    /// to default to. `test_default()` supplies a zero address, and every
    /// receipt leaf binds to `bridge_address`, so a node defaulting to it
    /// would advertise Ethereum support while pointing at no contract.
    ///
    /// `AdapterRegistry::register` asks each adapter whether it is fit to
    /// relay before accepting it, so the zero-address and zero-confirmation
    /// cases are refused at startup rather than discovered as a mint against
    /// a transaction that never happened.
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
    /// on chain forever with nothing acting on it, a silent service failure,
    /// not a loud one.
    #[must_use]
    pub fn with_cursor_path(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.cursor_path = path;
        self
    }

    /// Where the pending results live: next to the cursor, under the same
    /// directory, so the operator's choice of a durable path covers both.
    fn pending_path(&self) -> Option<std::path::PathBuf> {
        let cursor = self.cursor_path.as_ref()?;
        Some(cursor.with_file_name(PENDING_FILE_NAME))
    }

    /// Read the pending results persisted by an earlier run.
    ///
    /// A malformed file is logged and treated as empty, like the cursor:
    /// the requests it named are still under or behind the cursor, and the
    /// worst case is a repeated external action for them, which is the same
    /// state a worker without persistence was always in. An unreadable file
    /// must not turn into an outage.
    fn load_pending(&self) -> std::collections::HashMap<String, PendingResult> {
        let Some(path) = self.pending_path() else {
            return std::collections::HashMap::new();
        };
        match crate::core::bounded_read::read_to_string_bounded(
            &path,
            crate::core::bounded_read::MAX_RELAY_PENDING_BYTES,
        ) {
            Ok(text) => {
                match serde_json::from_str::<std::collections::HashMap<String, PendingResult>>(
                    &text,
                ) {
                    Ok(map) => {
                        if !map.is_empty() {
                            info!(
                                pending = map.len(),
                                path = %path.display(),
                                "Relayer: resuming pending relay results"
                            );
                        }
                        map
                    }
                    Err(e) => {
                        warn!(error = %e, path = %path.display(),
                          "Relayer: pending-result file is unreadable; starting with none");
                        std::collections::HashMap::new()
                    }
                }
            }
            Err(e) if e.is_not_found() => std::collections::HashMap::new(),
            Err(e) => {
                warn!(error = %e, path = %path.display(),
                      "Relayer: pending-result file unreadable; starting with none");
                std::collections::HashMap::new()
            }
        }
    }

    /// Write the pending results after every change to them.
    ///
    /// Written before the cursor moves past the block that holds the
    /// request, so a crash between the two leaves either the request under
    /// the cursor (relayed again from the stored observation) or the stored
    /// observation itself; never a request nothing knows about.
    fn save_pending(&self) {
        let Some(path) = self.pending_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(error = %e, path = %path.display(), "Relayer: cannot create pending directory");
                return;
            }
        }
        let body = match serde_json::to_string(&self.observed) {
            Ok(body) => body,
            Err(e) => {
                warn!(error = %e, "Relayer: cannot encode pending results");
                return;
            }
        };
        if let Err(e) = std::fs::write(&path, body) {
            warn!(error = %e, path = %path.display(),
                  "Relayer: failed to persist pending results; a restart may repeat an external action");
        }
    }

    /// Drop every pending result whose transaction sits in a finalized block,
    /// and put back on the submission path every one the mempool lost.
    ///
    /// A result transaction the chain handle accepted can still vanish: the
    /// mempool expires it after `tx_ttl_secs`, evicts it under pressure, or
    /// forgets it across a restart. Finality is the only state that cannot
    /// be undone, so it is the only state that releases the observation. A
    /// submitted result that is neither in the mempool nor in a block has
    /// its transaction hash forgotten, and the next pass signs and submits
    /// the stored observation again; the external action is not repeated.
    async fn reap_finalized(&mut self, finalized: u64) {
        let submitted: Vec<(String, String)> = self
            .observed
            .iter()
            .filter_map(|(request, p)| p.submitted_tx.clone().map(|h| (request.clone(), h)))
            .collect();
        let mut changed = false;
        for (request, tx_hash) in submitted {
            match self.included_height(&tx_hash).await {
                Some(height) if height <= finalized => {
                    info!(request, tx = %tx_hash, height, "Relayer: relay result finalized");
                    self.observed.remove(&request);
                    changed = true;
                }
                Some(_) => {}
                None => {
                    if !self.chain.mempool_contains(tx_hash.clone()).await {
                        warn!(
                            request,
                            tx = %tx_hash,
                            "Relayer: the chain lost the submitted relay result before a block \
                             took it; the stored observation will be submitted again"
                        );
                        if let Some(pending) = self.observed.get_mut(&request) {
                            pending.submitted_tx = None;
                        }
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.save_pending();
        }
    }

    /// The height of the block that holds `tx_hash`, if any block does.
    async fn included_height(&self, tx_hash: &str) -> Option<u64> {
        let receipt = self.chain.get_tx_receipt(tx_hash.to_string()).await?;
        let hex = receipt.get("blockNumber")?.as_str()?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    }

    /// Submit the stored observation of every pending request whose
    /// submission the chain lost. Only the local signing and submission run
    /// again; the external action does not.
    async fn resubmit_lost(&mut self) {
        let lost: Vec<String> = self
            .observed
            .iter()
            .filter(|(_, p)| p.submitted_tx.is_none())
            .map(|(request, _)| request.clone())
            .collect();
        if lost.is_empty() {
            return;
        }
        let Some(kp) = self.relayer_keypair.clone() else {
            return;
        };
        for request in lost {
            let Some(result) = self.observed.get(&request).map(|p| p.result.clone()) else {
                continue;
            };
            let Some(user) = self.requester_of(&request).await else {
                warn!(
                    request,
                    "Relayer: cannot find the requester of a pending result"
                );
                continue;
            };
            let _ = self.submit_result(&request, user, &result, &kp).await;
        }
    }

    /// The account that paid for a relay request, read back from its
    /// transaction on chain.
    async fn requester_of(&self, request: &str) -> Option<Address> {
        self.chain
            .get_transaction_by_hash(request.to_string())
            .await
            .map(|tx| tx.from)
    }

    /// Sign the verified result and hand it to the chain. On acceptance the
    /// transaction hash is recorded against the request; the observation
    /// itself stays until [`Self::reap_finalized`] sees the result in a
    /// finalized block.
    async fn submit_result(
        &mut self,
        request: &str,
        user: Address,
        result: &crate::core::transaction::RelayerExternalResult,
        kp: &KeyPair,
    ) -> RelayOutcome {
        let mut result_tx = Transaction::new_with_chain_id(
            self.relayer_address,
            user, // to: original UniversalRelay caller
            0,
            100, // Fee
            self.chain.get_nonce(&self.relayer_address).await,
            Vec::new(),
            self.chain.get_chain_id().await,
            TransactionType::RelayerResult(result.clone()),
        );
        result_tx.sign(kp);
        let tx_hash = result_tx.hash.clone();
        match self.chain.add_transaction(result_tx).await {
            Ok(()) => {
                if let Some(pending) = self.observed.get_mut(request) {
                    pending.submitted_tx = Some(tx_hash);
                }
                self.save_pending();
                RelayOutcome::Submitted
            }
            Err(e) => {
                // Not accepted by the chain handle: mempool full, actor
                // gone, nonce raced. The external action has happened and
                // its result is kept under the request hash, so the retry
                // signs and submits that result again; the chain's replay
                // protection refuses a second result if one did land.
                warn!(
                    error = %e,
                    "Relayer: chain did not accept the signed relay result; \
                     holding the request for retry"
                );
                RelayOutcome::Retry
            }
        }
    }

    /// Read the persisted cursor, or `None` when there is nothing to resume.
    ///
    /// A malformed or unreadable file is treated as absent and logged rather
    /// than fatal: refusing to start would turn a corrupt cursor into an
    /// outage, and resuming from the chain tip is the behaviour this had
    /// before the file existed.
    fn load_cursor(&self) -> Option<u64> {
        let path = self.cursor_path.as_ref()?;
        // Bounded: the cursor is a single decimal height.
        match crate::core::bounded_read::read_to_string_bounded(
            path,
            crate::core::bounded_read::MAX_CONTROL_FILE_BYTES,
        ) {
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
            Err(e) if e.is_not_found() => None,
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

    pub async fn run(mut self) {
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
        // continue; }` then held forever on the shorter fork - the relayer
        // went quiet with nothing in the logs. Tracking a monotonic value
        // removes that state entirely.
        // Resume from the persisted cursor when there is one. Starting from the
        // current finalized height means every request finalized while this
        // worker was down is skipped silently.
        let mut relayed_through = match self.load_cursor() {
            Some(persisted) => persisted,
            None => self.chain.get_finalized_height().await,
        };
        self.observed = self.load_pending();

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let finalized = self.chain.get_finalized_height().await;
            // Results submitted on earlier passes are released only once a
            // finalized block holds them; ones the mempool lost go back out.
            self.reap_finalized(finalized).await;
            self.resubmit_lost().await;
            if finalized <= relayed_through {
                continue;
            }

            'heights: for h in (relayed_through + 1)..=finalized {
                // The cursor only moves past a height that was actually
                // read. A block that storage cannot hand over is retried on
                // the next pass instead of being skipped with its relay
                // requests, which the user has already paid for.
                let Some(block) = self.chain.get_block(h).await else {
                    warn!(
                        height = h,
                        "Relayer: finalized block unavailable; holding the cursor and retrying"
                    );
                    break;
                };
                for tx in block.transactions {
                    if let TransactionType::UniversalRelay(ext_tx) = tx.tx_type {
                        // A request whose result already reached the chain
                        // on an earlier pass over this held block is not
                        // relayed twice: the external action is not
                        // idempotent, and the chain refuses the second result
                        // anyway.
                        if self.settled.contains(&tx.hash) {
                            continue;
                        }
                        info!(
                            chain = ?ext_tx.chain,
                            target = %ext_tx.target_address,
                            height = h,
                            "Relayer: Detected external transaction request"
                        );

                        match self.process_relay(&tx.hash, tx.from, ext_tx).await {
                            RelayOutcome::Submitted => {
                                self.settled.insert(tx.hash.clone());
                            }
                            RelayOutcome::Refused => {
                                // A refusal at the adapter is a fact about
                                // the request: retrying it changes nothing
                                // and the chain-side deadline reclaims it.
                                self.settled.insert(tx.hash.clone());
                            }
                            RelayOutcome::Retry => {
                                // The block stays under the cursor; the
                                // next pass comes back to this request.
                                warn!(
                                    height = h,
                                    request = %tx.hash,
                                    "Relayer: result not accepted yet; holding the cursor and retrying"
                                );
                                break 'heights;
                            }
                        }
                    }
                }
                relayed_through = h;
                self.save_cursor(relayed_through);
                // Everything in this block is behind the cursor now. The
                // pending results are not: they stay until finality.
                self.settled.clear();
            }
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

    /// Relay one request and say what became of it.
    ///
    /// The block cursor used to move past a request whatever happened here:
    /// a connection failure, a missing signing key and a full mempool all
    /// left a paid request behind for good. The caller now holds the cursor
    /// on [`RelayOutcome::Retry`] and comes back to the request.
    ///
    /// The external action runs once per request. Its verified result is
    /// kept under the request hash until the chain takes the signed result
    /// transaction, so a retry after a full mempool or a raced nonce repeats
    /// the local submission and not the transfer on the other chain.
    async fn process_relay(
        &mut self,
        request: &str,
        user: Address,
        ext_tx: crate::core::transaction::ExternalTransaction,
    ) -> RelayOutcome {
        // Relayer MUST sign result TXs.
        // Fail-closed: if no signing key is configured, refuse to submit.
        // Unsigned TXs in the chain would allow forged relay results. The
        // check comes before the external action: without a key the result
        // could never be delivered, so nothing external is done in its name.
        let Some(kp) = self.relayer_keypair.clone() else {
            error!(
                "CRITICAL: Relayer worker has no signing key configured. \
                 Refusing to submit unsigned relay result (P8-01 fail-closed). \
                 Use RelayerWorker::with_signing_key() to bind a key."
            );
            return RelayOutcome::Retry;
        };

        let result = if let Some(kept) = self.observed.get(request) {
            if kept.submitted_tx.is_some() {
                // Accepted on an earlier pass and not yet finalized: nothing
                // to do until `reap_finalized` says otherwise.
                return RelayOutcome::Submitted;
            }
            info!(
                request,
                "Relayer: resubmitting the verified result of an earlier pass; the external \
                 action is not repeated"
            );
            kept.result.clone()
        } else {
            match Self::build_verified_result(&self.adapters, &ext_tx).await {
                Ok(result) => {
                    self.observed.insert(
                        request.to_string(),
                        PendingResult {
                            result: result.clone(),
                            submitted_tx: None,
                        },
                    );
                    self.save_pending();
                    result
                }
                Err(e) => {
                    // Refuse, loudly. Submitting an unverified success here
                    // would be worse than submitting nothing: the relayer's
                    // signature would make a fabricated external outcome
                    // look authentic.
                    warn!(
                        chain = ?ext_tx.chain,
                        target = %ext_tx.target_address,
                        error = %e,
                        "Relayer: refusing to submit a relay result that is not backed by a \
                         verified adapter observation"
                    );
                    return relay_outcome_for(&e);
                }
            }
        };

        // Submit result back to Budlum. The relayer signs with its own key
        // via the Node's signer; the transaction is injected through the
        // chain handle for inclusion in the next block.
        self.submit_result(request, user, &result, &kp).await
    }
}

/// What the relay loop does with a request after one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayOutcome {
    /// The signed result was accepted by the chain handle.
    Submitted,
    /// The request itself cannot be relayed (no adapter for its chain, or
    /// the adapter's own proof did not verify). Retrying changes nothing;
    /// the request is left to the chain-side deadline.
    Refused,
    /// A transient failure: the external chain could not be reached, the
    /// confirmation timed out, the signing key is missing, or the chain
    /// handle did not take the result. The cursor is held and the request is
    /// attempted again on the next pass.
    Retry,
}

/// Sort an adapter failure into "try again" and "never".
///
/// Only failures that name the request as the problem are final. A chain
/// without an adapter stays without one until the operator restarts with a
/// different configuration, and a proof the adapter itself rejects is not
/// going to verify on the next pass either. Everything else is the network
/// or the remote node having a bad minute.
fn relay_outcome_for(error: &AdapterError) -> RelayOutcome {
    match error {
        AdapterError::UnsupportedChain(_) | AdapterError::ProofVerificationFailed(_) => {
            RelayOutcome::Refused
        }
        AdapterError::ConnectionFailed(_)
        | AdapterError::TransactionNotFound(_)
        | AdapterError::ProofGenerationFailed(_)
        | AdapterError::SubmissionFailed(_)
        | AdapterError::ConfirmationTimeout
        | AdapterError::Other(_) => RelayOutcome::Retry,
    }
}

/// Confirmation depth required before a result is considered readable.
///
/// Reuses the EVM reorg window rather than defining a second number, so the
/// worker cannot drift into accepting a shallower confirmation than the
/// verifier was calibrated for. A one-block confirmation is not a
/// confirmation on any chain this bridge targets.
const CONFIRMATION_DEPTH: u32 = crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;

#[cfg(test)]
mod cursor_persistence {
    use super::*;

    fn worker_with(path: Option<std::path::PathBuf>) -> RelayerWorker {
        // The cursor helpers touch only `cursor_path`, so a worker built
        // without a live chain actor is enough to exercise them.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        RelayerWorker::new(ChainHandle::new(tx), Address::from([7u8; 32])).with_cursor_path(path)
    }

    /// A cursor written by one run must be read by the next.
    ///
    /// Without this the worker resumes from the chain tip, and every relay
    /// request finalized while it was down is skipped, the user has paid and
    /// nothing acts on the request.
    #[test]
    fn a_persisted_cursor_is_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay-cursor");
        let w = worker_with(Some(path));

        assert_eq!(w.load_cursor(), None, "nothing persisted yet");
        w.save_cursor(4_211);
        assert_eq!(
            w.load_cursor(),
            Some(4_211),
            "a restart must resume from the persisted height"
        );
    }

    /// The cursor only ever moves forward as work completes.
    #[test]
    fn a_later_cursor_replaces_an_earlier_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay-cursor");
        let w = worker_with(Some(path));

        w.save_cursor(10);
        w.save_cursor(20);
        assert_eq!(w.load_cursor(), Some(20));
    }

    /// A corrupt cursor falls back to the chain tip instead of refusing to
    /// start.
    ///
    /// Turning an unreadable file into an outage would be a worse failure than
    /// the one this fixes.
    #[test]
    fn a_corrupt_cursor_is_ignored_rather_than_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relay-cursor");
        std::fs::write(&path, "not-a-height").expect("write");

        let w = worker_with(Some(path));
        assert_eq!(
            w.load_cursor(),
            None,
            "a malformed cursor must read as absent, not panic"
        );
    }

    /// Without a configured path the worker keeps its previous in-memory
    /// behaviour, so tests and embedded uses are unaffected.
    #[test]
    fn no_path_means_no_persistence() {
        let w = worker_with(None);
        w.save_cursor(99);
        assert_eq!(w.load_cursor(), None);
    }
}

#[cfg(test)]
mod relay_outcomes {
    use super::*;
    use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
    use crate::cross_domain::chain_adapter::ChainAdapter;
    use crate::cross_domain::event_tree::MerkleProof;

    /// The smallest adapter whose proof its own verifier accepts, so the
    /// relay reaches the signing step.
    struct ConsistentAdapter;

    fn leaf_for(tx_hash: &str) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[b"RELAY_OUTCOME_TEST_LEAF", tx_hash.as_bytes()])
    }

    #[async_trait::async_trait]
    impl ChainAdapter for ConsistentAdapter {
        fn chain_type(&self) -> ExternalChain {
            ExternalChain::Ethereum
        }

        async fn generate_receipt_proof(
            &self,
            tx_hash: &str,
        ) -> Result<(MerkleProof, [u8; 32], String), AdapterError> {
            let leaf = leaf_for(tx_hash);
            Ok((
                MerkleProof {
                    leaf,
                    index: 0,
                    siblings: Vec::new(),
                },
                leaf,
                tx_hash.to_string(),
            ))
        }

        fn verify_receipt_proof(
            &self,
            proof: &MerkleProof,
            external_state_root: &[u8; 32],
            expected_tx_hash: &str,
        ) -> Result<(), AdapterError> {
            if proof.leaf != leaf_for(expected_tx_hash) || !proof.verify(*external_state_root) {
                return Err(AdapterError::ProofVerificationFailed("leaf".into()));
            }
            Ok(())
        }

        async fn submit_transaction(
            &self,
            _ext_tx: &ExternalTransaction,
        ) -> Result<String, AdapterError> {
            Ok("0xconsistent".to_string())
        }

        async fn wait_for_confirmation(
            &self,
            tx_hash: &str,
            _confirmations: u32,
        ) -> Result<RelayerExternalResult, AdapterError> {
            let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
            // The outcome is what the proof says about the root, the way a
            // real adapter reads it off the receipt; nothing here asserts
            // success on its own.
            let observed = proof.verify(root);
            Ok(RelayerExternalResult {
                chain: ExternalChain::Ethereum,
                tx_hash: hash,
                success: observed,
                message: None,
                receipt_proof: bincode::serialize(&proof).expect("proof serialize"),
                external_state_root: root,
            })
        }
    }

    /// A chain without an adapter, or a proof the adapter itself rejects,
    /// is final: the cursor must not be held forever on a request that can
    /// never succeed.
    #[test]
    fn failures_that_name_the_request_are_final() {
        assert_eq!(
            relay_outcome_for(&AdapterError::UnsupportedChain(ExternalChain::Solana)),
            RelayOutcome::Refused
        );
        assert_eq!(
            relay_outcome_for(&AdapterError::ProofVerificationFailed("leaf".into())),
            RelayOutcome::Refused
        );
    }

    /// Everything that is the network's or the remote node's fault is
    /// retried: the request is paid for, and the next pass may succeed.
    #[test]
    fn transient_failures_hold_the_cursor() {
        for error in [
            AdapterError::ConnectionFailed("rpc down".into()),
            AdapterError::TransactionNotFound("0x1".into()),
            AdapterError::ProofGenerationFailed("no receipt yet".into()),
            AdapterError::SubmissionFailed("nonce too low".into()),
            AdapterError::ConfirmationTimeout,
            AdapterError::Other("?".into()),
        ] {
            assert_eq!(relay_outcome_for(&error), RelayOutcome::Retry, "{error}");
        }
    }

    /// A worker without a signing key cannot finish a relay; the request is
    /// held rather than recorded as done, so binding a key later lets the
    /// worker pick it up instead of skipping past it.
    #[tokio::test]
    async fn a_missing_signing_key_holds_the_request() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let handle = ChainHandle::new(tx);
        // Answer the nonce and chain id lookups the worker makes before
        // it notices there is no key to sign with.
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    crate::chain::chain_actor::ChainCommand::GetNonce(_, reply) => {
                        let _ = reply.send(0);
                    }
                    crate::chain::chain_actor::ChainCommand::GetChainId(reply) => {
                        let _ = reply.send(1);
                    }
                    _ => {}
                }
            }
        });
        let mut registry = AdapterRegistry::new();
        registry
            .register(Box::new(ConsistentAdapter))
            .expect("a consistent adapter registers");
        let mut worker =
            RelayerWorker::new(handle, Address::from([7u8; 32])).with_adapters(Arc::new(registry));
        let request = ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000aa".to_string(),
            payload: vec![1, 2, 3],
            external_nonce: 7,
        };
        let outcome = worker
            .process_relay("req-1", Address::from([8u8; 32]), request)
            .await;
        assert_eq!(outcome, RelayOutcome::Retry);
        assert!(
            worker.observed.is_empty(),
            "without a key nothing external is done, so there is nothing to keep"
        );
    }

    /// An adapter that counts its submissions: the external action is the
    /// thing a retry must not repeat.
    struct CountingAdapter(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait::async_trait]
    impl ChainAdapter for CountingAdapter {
        fn chain_type(&self) -> ExternalChain {
            ExternalChain::Ethereum
        }

        async fn generate_receipt_proof(
            &self,
            tx_hash: &str,
        ) -> Result<(MerkleProof, [u8; 32], String), AdapterError> {
            ConsistentAdapter.generate_receipt_proof(tx_hash).await
        }

        fn verify_receipt_proof(
            &self,
            proof: &MerkleProof,
            external_state_root: &[u8; 32],
            expected_tx_hash: &str,
        ) -> Result<(), AdapterError> {
            ConsistentAdapter.verify_receipt_proof(proof, external_state_root, expected_tx_hash)
        }

        async fn submit_transaction(
            &self,
            ext_tx: &ExternalTransaction,
        ) -> Result<String, AdapterError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ConsistentAdapter.submit_transaction(ext_tx).await
        }

        async fn wait_for_confirmation(
            &self,
            tx_hash: &str,
            confirmations: u32,
        ) -> Result<RelayerExternalResult, AdapterError> {
            ConsistentAdapter
                .wait_for_confirmation(tx_hash, confirmations)
                .await
        }
    }

    /// The chain refusing the signed result is a local failure. The retry
    /// signs and submits the kept result again; the external transaction
    /// is not sent a second time.
    #[tokio::test]
    async fn a_rejected_result_is_resubmitted_without_a_second_external_action() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let handle = ChainHandle::new(tx);
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_in_actor = accepted.clone();
        // The first result is refused (a full mempool), the second is taken.
        tokio::spawn(async move {
            let mut seen = 0usize;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    crate::chain::chain_actor::ChainCommand::GetNonce(_, reply) => {
                        let _ = reply.send(0);
                    }
                    crate::chain::chain_actor::ChainCommand::GetChainId(reply) => {
                        let _ = reply.send(1);
                    }
                    crate::chain::chain_actor::ChainCommand::AddTransaction(_, reply) => {
                        seen += 1;
                        if seen == 1 {
                            let _ = reply.send(Err("mempool full".to_string()));
                        } else {
                            accepted_in_actor.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let _ = reply.send(Ok(()));
                        }
                    }
                    _ => {}
                }
            }
        });
        let submissions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = AdapterRegistry::new();
        registry
            .register(Box::new(CountingAdapter(submissions.clone())))
            .expect("a counting adapter registers");
        let key = Arc::new(KeyPair::generate().expect("keypair"));
        let mut worker = RelayerWorker::new(handle, Address::from([7u8; 32]))
            .with_adapters(Arc::new(registry))
            .with_signing_key(key);
        let request = ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000aa".to_string(),
            payload: vec![1, 2, 3],
            external_nonce: 7,
        };

        let first = worker
            .process_relay("req-2", Address::from([8u8; 32]), request.clone())
            .await;
        assert_eq!(first, RelayOutcome::Retry);
        assert_eq!(submissions.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            worker.observed.contains_key("req-2"),
            "the verified result is kept for the retry"
        );

        let second = worker
            .process_relay("req-2", Address::from([8u8; 32]), request)
            .await;
        assert_eq!(second, RelayOutcome::Submitted);
        assert_eq!(
            submissions.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the external transaction must not be sent twice"
        );
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            worker
                .observed
                .get("req-2")
                .is_some_and(|p| p.submitted_tx.is_some()),
            "an accepted result stays pending, with its transaction hash, until finality"
        );
    }
}

#[cfg(test)]
mod pending_results {
    use super::*;
    use crate::core::transaction::{ExternalChain, RelayerExternalResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn observation(tag: u8) -> RelayerExternalResult {
        RelayerExternalResult {
            chain: ExternalChain::Ethereum,
            tx_hash: format!("0x{tag:02x}"),
            success: true,
            message: None,
            receipt_proof: vec![tag; 4],
            external_state_root: [tag; 32],
        }
    }

    /// An actor stub that answers the relay loop's finality questions from
    /// two tables: which hashes sit in which block, and which hashes the
    /// mempool still holds. Every `AddTransaction` is accepted and counted.
    fn actor(
        included: std::collections::HashMap<String, u64>,
        queued: std::collections::HashSet<String>,
        accepted: Arc<AtomicUsize>,
    ) -> ChainHandle {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    crate::chain::chain_actor::ChainCommand::GetNonce(_, reply) => {
                        let _ = reply.send(0);
                    }
                    crate::chain::chain_actor::ChainCommand::GetChainId(reply) => {
                        let _ = reply.send(1);
                    }
                    crate::chain::chain_actor::ChainCommand::GetTxReceipt(hash, reply) => {
                        let _ = reply.send(
                            included
                                .get(&hash)
                                .map(|h| serde_json::json!({ "blockNumber": format!("0x{h:x}") })),
                        );
                    }
                    crate::chain::chain_actor::ChainCommand::MempoolContains(hash, reply) => {
                        let _ = reply.send(queued.contains(&hash));
                    }
                    crate::chain::chain_actor::ChainCommand::GetTransactionByHash(_, reply) => {
                        let _ = reply.send(None);
                    }
                    crate::chain::chain_actor::ChainCommand::AddTransaction(_, reply) => {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    _ => {}
                }
            }
        });
        ChainHandle::new(tx)
    }

    /// The pending map survives a restart: what one worker wrote, the next
    /// reads back, so an external action done before a crash is not done
    /// again and its result is still delivered.
    #[test]
    fn pending_results_are_read_back_by_the_next_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("relayer-cursor");
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut w = RelayerWorker::new(ChainHandle::new(tx), Address::from([7u8; 32]))
            .with_cursor_path(Some(path.clone()));
        w.observed.insert(
            "req-a".to_string(),
            PendingResult {
                result: observation(1),
                submitted_tx: Some("tx-a".to_string()),
            },
        );
        w.observed.insert(
            "req-b".to_string(),
            PendingResult {
                result: observation(2),
                submitted_tx: None,
            },
        );
        w.save_pending();

        let (tx2, _rx2) = tokio::sync::mpsc::channel(1);
        let again = RelayerWorker::new(ChainHandle::new(tx2), Address::from([7u8; 32]))
            .with_cursor_path(Some(path));
        assert_eq!(again.load_pending(), w.observed);
    }

    /// A worker without a cursor path keeps everything in memory, as before.
    #[test]
    fn no_path_means_no_pending_file() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut w = RelayerWorker::new(ChainHandle::new(tx), Address::from([7u8; 32]));
        w.observed.insert(
            "req".to_string(),
            PendingResult {
                result: observation(3),
                submitted_tx: None,
            },
        );
        w.save_pending();
        assert!(w.load_pending().is_empty());
    }

    /// A result whose transaction sits in a finalized block is released; one
    /// in a block above the finalized height is kept; one that is in neither
    /// a block nor the mempool loses its hash and goes back to submission.
    #[tokio::test]
    async fn only_finality_releases_a_pending_result() {
        let included = std::collections::HashMap::from([
            ("tx-final".to_string(), 10u64),
            ("tx-young".to_string(), 12u64),
        ]);
        let queued = std::collections::HashSet::from(["tx-queued".to_string()]);
        let accepted = Arc::new(AtomicUsize::new(0));
        let handle = actor(included, queued, accepted);
        let mut w = RelayerWorker::new(handle, Address::from([7u8; 32]));
        for (request, hash) in [
            ("req-final", "tx-final"),
            ("req-young", "tx-young"),
            ("req-queued", "tx-queued"),
            ("req-lost", "tx-lost"),
        ] {
            w.observed.insert(
                request.to_string(),
                PendingResult {
                    result: observation(9),
                    submitted_tx: Some(hash.to_string()),
                },
            );
        }

        w.reap_finalized(11).await;

        assert!(
            !w.observed.contains_key("req-final"),
            "a result in a finalized block is done"
        );
        assert_eq!(
            w.observed["req-young"].submitted_tx.as_deref(),
            Some("tx-young"),
            "a result in a block above the finalized height waits"
        );
        assert_eq!(
            w.observed["req-queued"].submitted_tx.as_deref(),
            Some("tx-queued"),
            "a result still in the mempool waits"
        );
        assert!(
            w.observed["req-lost"].submitted_tx.is_none(),
            "a result the mempool lost goes back to submission"
        );
    }

    /// A lost submission is signed and submitted again from the stored
    /// observation; the adapter is not consulted, so the external action
    /// cannot run twice.
    #[tokio::test]
    async fn a_lost_submission_is_resubmitted_without_the_adapter() {
        let accepted = Arc::new(AtomicUsize::new(0));
        let handle = actor(
            std::collections::HashMap::new(),
            std::collections::HashSet::new(),
            accepted.clone(),
        );
        let key = Arc::new(KeyPair::generate().expect("keypair"));
        let mut w = RelayerWorker::new(handle, Address::from([7u8; 32])).with_signing_key(key);
        w.observed.insert(
            "req-lost".to_string(),
            PendingResult {
                result: observation(5),
                submitted_tx: None,
            },
        );

        let user = Address::from([8u8; 32]);
        let kp = w.relayer_keypair.clone().expect("key bound");
        let result = observation(5);
        let outcome = w.submit_result("req-lost", user, &result, &kp).await;

        assert_eq!(outcome, RelayOutcome::Submitted);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert!(
            w.observed["req-lost"].submitted_tx.is_some(),
            "the fresh transaction hash is recorded for the finality check"
        );
        assert!(
            w.adapters.supported_chains().is_empty(),
            "no adapter was needed: the stored observation is what gets signed"
        );
    }
}
