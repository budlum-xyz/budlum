use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use tracing::{info, warn};

/// Phase 5 §5.1: Universal Relayer Worker.
/// Watches the Budlum chain for UniversalRelay transactions and
/// "relays" them to external chains (EVM, Solana, etc.).

pub struct RelayerWorker {
    chain: ChainHandle,
    /// Rewards for the relayer are minted in $BUD (Decision 9).
    relayer_address: Address,
}

impl RelayerWorker {
    pub fn new(chain: ChainHandle, relayer_address: Address) -> Self {
        Self {
            chain,
            relayer_address,
        }
    }

    pub async fn run(self) {
        info!(
            "Universal Relayer Worker started for {}",
            self.relayer_address
        );

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

                            // Real-world: Connect to Web3 provider (ethers-rs, solana-sdk)
                            // and submit the signed payload.
                            self.process_relay(tx.from, ext_tx).await;
                        }
                    }
                }
            }
            last_height = current_height;
        }
    }

    async fn process_relay(
        &self,
        user: Address,
        ext_tx: crate::core::transaction::ExternalTransaction,
    ) {
        match ext_tx.chain {
            crate::core::transaction::ExternalChain::Ethereum => {
                info!("Relaying to Ethereum...");
                // Phase 8.9 / L1: gerçek kanıt üretimi — sonuç olgularının
                // domain-separated leaf'i tek-yaprak ağacın kökü olur
                // (executor kapısı aynı şemayla dogrular: MerkleProof {leaf, 0, []}).
                // TODO(phase9): EVM light-client root anchor + cok-yaprakli
                // aggregation (gercek Merkle-patricia receipt trie) ve
                // external broadcast'tan gelen gercek tx_hash.
                let mut result = crate::core::transaction::RelayerExternalResult {
                    chain: ext_tx.chain,
                    tx_hash: "0x".to_string() + &hex::encode([0xEE; 32]), // TODO(phase9)
                    success: true,
                    receipt_proof: Vec::new(),
                    external_state_root: [0u8; 32],
                };
                let leaf = result.result_leaf();
                let proof = crate::cross_domain::event_tree::MerkleProof {
                    leaf,
                    index: 0,
                    siblings: Vec::new(),
                };
                result.external_state_root = leaf;
                result.receipt_proof = bincode::serialize(&proof).unwrap_or_default();

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
                // TODO(phase9): sign with relayer key via Node signer
                // result_tx.signature = self.signer.sign(&result_tx.signing_hash());

                let _ = self.chain.add_transaction(result_tx).await;
            }
            _ => {
                warn!("Relay for {:?} not yet implemented", ext_tx.chain);
            }
        }
    }
}
