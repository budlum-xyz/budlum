#![allow(clippy::pedantic, clippy::nursery)]

//! F10.4 EvmChainAdapter - gerçek ChainAdapter impl (H4 tam canlı yol).
//!
//! İki taraf:
//!
//! - **On-chain (verify_receipt_proof):** Budlum konsensüsünde deterministik.
//!   F10.1 (MPT) + F10.2 (receipt/header/verify) kullanır. Sync-committee
//!   (F10.3) yalnızca `EvmDepositProof.sync_attestation` doluysa çalışır;
//!   bu satır uzun süre "kullanır" diyordu ve hiçbir yol çağırmıyordu.
//!   Network'süz - relayer proof üretir, Budlum verify eder.
//!
//! - **Off-chain (generate/submit/wait):** Relayer binary'sinde (`src/bin/
//!   Budlum-relayer.rs`). Ethereum RPC'ye bağlanır. Bu modül yapı + minimal
//!   Impl sağlar; production RPC client ayrı (reqwest/alloy - mainnet sonrası).
//!
//! **Güvenlik sabiti:** `verify_receipt_proof` ASLA network'e bağlanmaz.
//!
//! ## - receipt ↔ tx_hash kriptografik bağı
//!
//! `proof.leaf` artık `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`
//! Formülüyle türetilmiş olmalı. Saldırgan farklı bir tx_hash ile aynı
//! Merkle proof'u kopyalayıp ileri süremez: leaf yeniden hesaplanır ve
//! Uyuşmazlık `ProofVerificationFailed` ile sonuçlanır. Aynı bağ
//! Cross-bridge proof kullanımını da engeller (leaf bridge_address'e
//! Bağlı).
//!
//! **Güvenlik sınırı:** Wire format değişti - relayer off-chain tool
//! Aynı formülle leaf üretmeli. `verify_deposit` (gerçek güvenli yol)
//! Etkilenmedi: zaten tam `EvmDepositProof` üzerinden MPT + header
//! Chain + status + log match yapıyor.

use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::chain_adapter::{AdapterError, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::evm::header::{verify_chain, EthHeader, DEFAULT_CONFIRMATIONS};
use crate::cross_domain::evm::mpt;
use crate::cross_domain::evm::receipt::{decode_receipt, EthReceipt};
use crate::cross_domain::evm::verify::{verify_evm_receipt, EvmDepositProof, VerifyError};
use crate::domain::types::Hash32;

/// Ethereum bridge kontrat deposit event imzas (topic0).
/// Keccak256("Deposit(address,uint256,bytes32,uint256)") - gerçek değer
/// Ceremony'de chain config ile set edilir. Burada placeholder (CI test).
pub const DEFAULT_DEPOSIT_TOPIC0: [u8; 32] = [0u8; 32];

/// EvmChainAdapter - Ethereum için gerçek ChainAdapter.
///
/// `verify_receipt_proof` on-chain deterministik. Off-chain metodlar
/// (`generate_receipt_proof`/`submit_transaction`/`wait_for_confirmation`)
/// Relayer binary'sinde Ethereum RPC'ye bağlanır; bu impl'de offline-test
/// Modu (StubAdapter deseni) - production RPC ayrı.
///
/// `Debug` so a caller can `expect` on a `Result` carrying one. All three
/// fields are public configuration already: a contract address, an event
/// topic and a confirmation count. There is no key material here to leak
/// into a log line.
#[derive(Debug)]
pub struct EvmChainAdapter {
    /// Ethereum bridge kontrat adresi (deposit event emitter).
    pub bridge_address: Vec<u8>,
    /// Deposit event topic0 = keccak256("Deposit(...)").
    pub deposit_topic0: [u8; 32],
    /// N-confirmation eşiği (reorg penceresi; mainnet ≈64).
    pub required_confirmations: u32,
}

impl EvmChainAdapter {
    pub fn new(bridge_address: Vec<u8>, deposit_topic0: [u8; 32]) -> Self {
        Self {
            bridge_address,
            deposit_topic0,
            required_confirmations: DEFAULT_CONFIRMATIONS,
        }
    }

    /// Is this adapter configured well enough to be trusted with deposits?
    ///
    /// Two ways an adapter can exist and be useless, both of which look fine
    /// at the call site:
    ///
    /// * a zero bridge address, which `test_default` supplies. Every receipt
    ///   leaf binds to `bridge_address`, so a zero address binds to nothing
    ///   in particular and the node advertises Ethereum support while
    ///   pointing at no contract.
    /// * zero required confirmations, which accepts a deposit from a block
    ///   that can still be reorged away. The bridge would mint against a
    ///   transaction that later did not happen.
    ///
    /// Kept separate from the constructor because a test adapter is a
    /// legitimate thing to build; what is not legitimate is relaying with
    /// one. The registry wiring calls this, so the refusal happens once at
    /// setup rather than being re-derived at each deposit.
    ///
    /// # Errors
    ///
    /// A message naming which of the two is wrong.
    pub fn check_fit_for_relay(&self) -> Result<(), String> {
        if self.bridge_address.iter().all(|b| *b == 0) {
            return Err(
                "EVM adapter has a zero bridge address: every receipt leaf binds to this \
                 address, so the node would advertise Ethereum support while pointing at no \
                 contract"
                    .into(),
            );
        }
        if self.required_confirmations == 0 {
            return Err(
                "EVM adapter requires zero confirmations: a deposit from a block that can \
                 still be reorged away would be minted against a transaction that did not \
                 happen"
                    .into(),
            );
        }
        Ok(())
    }

    /// Default (test/devnet) - placeholder bridge address + topic0.
    pub fn test_default() -> Self {
        Self::new(vec![0u8; 20], DEFAULT_DEPOSIT_TOPIC0)
    }
}

#[async_trait::async_trait]
impl ChainAdapter for EvmChainAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Ethereum
    }

    /// Off-chain (relayer binary): Ethereum RPC'den receipt + MPT proof üret.
    ///
    /// Bu impl offline-test stub'ı (StubAdapter deseni). Production RPC client
    /// `src/bin/budlum-relayer.rs`'te (mainnet sonrası, reqwest/alloy).
    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        // Offline-test: dummy proof (F10.1 verify ile tutarsız → RED test).
        let leaf = crate::core::hash::hash_fields_bytes(&[b"BDLM_EVM_STUB", tx_hash.as_bytes()]);
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

    /// ON-CHAIN (Budlum konsensüsü): EVM receipt proof doğrula.
    ///
    /// Deterministik + network'süz. F10.1 (MPT) + F10.2 (receipt/header) +
    /// Relayer proof üretir. Sync-committee bu trait yolunda hiç çalışmaz:
    /// bu metot yalnızca Merkle proof + leaf bağı kontrol eder, tam paket
    /// (`EvmDepositProof`) `verify_deposit`'e gider.
    ///
    /// **Wire format (sonrası):** `proof.leaf` =
    /// `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`;
    /// `external_state_root` = header.receiptsRoot; `expected_tx_hash` = tx_hash.
    /// Header chain + sync-committee doğrulaması bu metotta DEĞİL,
    /// `verify_evm_receipt` içindedir ve oraya yalnızca `verify_deposit`
    /// gider.
    ///
    /// **** İki görevlı doğrulama -
    /// 1) `proof.verify(external_state_root)` - Merkle self-consistency.
    /// 2) `proof.leaf == derive_receipt_leaf(tx_hash, bridge_address)` -
    ///    Kriptografik leaf bağı. Saldırgan farklı bir tx_hash ile aynı
    ///    Proof'u ileri süremez; cross-bridge proof da reddedilir.
    /// Refuse registration for an adapter that cannot bind a receipt.
    ///
    /// Delegates to the inherent check so there is one definition of "fit",
    /// not two that can drift.
    fn check_fit_for_relay(&self) -> Result<(), AdapterError> {
        EvmChainAdapter::check_fit_for_relay(self).map_err(AdapterError::ProofVerificationFailed)
    }

    fn verify_receipt_proof(
        &self,
        proof: &MerkleProof,
        external_state_root: &Hash32,
        expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        // Merkle proof self-consistency (kısmi fix).
        if !proof.verify(*external_state_root) {
            return Err(AdapterError::ProofVerificationFailed(
                "EVM receipt Merkle proof does not verify against declared receipts root".into(),
            ));
        }
        // Tam fix - leaf ↔ tx_hash + bridge_address kriptografik bağı.
        if expected_tx_hash.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "EVM receipt proof requires non-empty tx_hash for receipt binding".into(),
            ));
        }
        let expected_leaf = derive_receipt_leaf(expected_tx_hash, &self.bridge_address);
        if proof.leaf != expected_leaf {
            return Err(AdapterError::ProofVerificationFailed(
                "EVM receipt leaf does not match tx_hash + bridge binding (forgery reject)".into(),
            ));
        }
        Ok(())
    }

    /// Off-chain (relayer binary): signed EVM tx → Ethereum RPC broadcast.
    ///
    /// Offline-test stub. Production: RLP encode signed tx + eth_sendRawTransaction.
    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Ok(format!("0x{}", hex::encode([0xEE; 32])))
    }

    /// Off-chain (relayer binary): k confirmation poll → receipt proof.
    ///
    /// Offline-test stub. Production: eth_getTransactionReceipt + block header
    /// Chain + MPT proof assemble.
    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
        Ok(RelayerExternalResult {
            chain: self.chain_type(),
            tx_hash: hash,
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&proof).unwrap_or_default(),
            external_state_root: root,
        })
    }
}

impl EvmChainAdapter {
    /// Tam on-chain EVM receipt verify (F10.2 verify.rs orchestrator).
    /// Bu, ChainAdapter::verify_receipt_proof'un zenginleştirilmiş hali -
    /// Relayer tam proof paketi (header chain + MPT nodes + receipt) sağlar.
    pub fn verify_deposit(&self, proof: &EvmDepositProof<'_>) -> Result<EthReceipt, VerifyError> {
        // Verify_evm_receipt: header N-conf → MPT → receipt → status → deposit log.
        let _verified = verify_evm_receipt(proof)?;
        // Receipt decode (verify_evm_receipt içinde zaten var, burada accessor için).
        // Verify_evm_receipt VerifiedDeposit döner; caller'a EthReceipt gerekirse
        // Ayrı decode. Minimal: header chain teyit.
        let target = decode_header_or_err(proof.target_header)?;
        let confs: Vec<EthHeader> = proof
            .confirmation_headers
            .iter()
            .map(|h| decode_header_or_err(h))
            .collect::<Result<_, _>>()?;
        verify_chain(&target, &confs, proof.required_confirmations)
            .map_err(|e| VerifyError::Header(e.to_string()))?;
        // MPT + receipt decode (verify_evm_receipt içinde çağrılır).
        let receipt_bytes =
            mpt::verify(proof.proof_nodes, &target.receipts_root, proof.receipt_key)?;
        decode_receipt(&receipt_bytes).map_err(VerifyError::from)
    }
}

fn decode_header_or_err(raw: &[u8]) -> Result<EthHeader, VerifyError> {
    crate::cross_domain::evm::header::decode_header(raw)
        .map_err(|e| VerifyError::Header(e.to_string()))
}

/// Receipt proof leaf'ini `tx_hash + bridge_address`'ten türetir.
/// Domain-tagged (collision-resistant, length-prefixed) SHA-256.
/// Saldırgan başka bir tx için geçerli proof'u kopyalayıp farklı tx_hash
/// Ileri süremez: leaf bağımsız olarak yeniden hesaplanır ve uyuşmazlık
/// `ProofVerificationFailed` ile sonuçlanır. Aynı bağ cross-bridge proof
/// Kullanımını da engeller.
fn derive_receipt_leaf(tx_hash: &str, bridge_address: &[u8]) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_EVM_RECEIPT_LEAF_V1",
        tx_hash.as_bytes(),
        bridge_address,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_chain_type_ethereum() {
        let adapter = EvmChainAdapter::test_default();
        assert_eq!(adapter.chain_type(), ExternalChain::Ethereum);
    }

    #[test]
    fn adapter_default_confirmations() {
        let adapter = EvmChainAdapter::test_default();
        assert_eq!(adapter.required_confirmations, DEFAULT_CONFIRMATIONS);
    }

    #[tokio::test]
    async fn offline_stub_generate_proof() {
        let adapter = EvmChainAdapter::test_default();
        let (proof, root, hash) = adapter.generate_receipt_proof("0xabc").await.unwrap();
        assert_eq!(hash, "0xabc");
        assert_eq!(proof.leaf, root);
    }

    #[tokio::test]
    async fn offline_stub_submit_transaction() {
        let adapter = EvmChainAdapter::test_default();
        let tx = ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x0".to_string(),
            payload: vec![],
            external_nonce: 0,
        };
        let hash = adapter.submit_transaction(&tx).await.unwrap();
        assert!(hash.starts_with("0x"));
    }

    #[tokio::test]
    async fn offline_stub_wait_confirmation() {
        let adapter = EvmChainAdapter::test_default();
        let result = adapter.wait_for_confirmation("0xabc", 1).await.unwrap();
        assert_eq!(result.chain, ExternalChain::Ethereum);
        assert!(result.success);
    }

    #[test]
    fn a_zero_bridge_address_cannot_be_registered() {
        // `test_default` builds an adapter with a zero bridge address, which
        // is a legitimate thing for a test to do and not a legitimate thing
        // to relay with: every receipt leaf binds to `bridge_address`, so a
        // zero address binds to nothing in particular.
        let adapter = EvmChainAdapter::test_default();
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("zero bridge address"), "got: {err}");

        let mut registry = crate::cross_domain::chain_adapter::AdapterRegistry::new();
        assert!(
            registry
                .register(Box::new(EvmChainAdapter::test_default()))
                .is_err(),
            "a zero-address adapter must not reach the registry: the node would \
             advertise Ethereum support while pointing at no contract"
        );
    }

    #[test]
    fn zero_confirmations_cannot_be_registered() {
        // A deposit from a block that can still be reorged away would be
        // minted against a transaction that did not happen.
        let mut adapter = EvmChainAdapter::new(vec![7u8; 20], DEFAULT_DEPOSIT_TOPIC0);
        assert!(EvmChainAdapter::check_fit_for_relay(&adapter).is_ok());

        adapter.required_confirmations = 0;
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("zero confirmations"), "got: {err}");
    }

    #[test]
    fn a_configured_adapter_registers() {
        // The refusal has to stay narrow, or it is just a ban on Ethereum.
        let adapter = EvmChainAdapter::new(vec![7u8; 20], DEFAULT_DEPOSIT_TOPIC0);
        assert!(EvmChainAdapter::check_fit_for_relay(&adapter).is_ok());

        let mut registry = crate::cross_domain::chain_adapter::AdapterRegistry::new();
        registry
            .register(Box::new(EvmChainAdapter::new(
                vec![7u8; 20],
                DEFAULT_DEPOSIT_TOPIC0,
            )))
            .expect("a configured adapter must register");
    }

    #[test]
    fn verify_receipt_proof_minimal_ok() {
        // Tam fix: leaf = hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address).
        let adapter = EvmChainAdapter::test_default();
        let tx_hash = "0xabc";
        let leaf = derive_receipt_leaf(tx_hash, &adapter.bridge_address);
        let proof = MerkleProof {
            leaf,
            index: 0,
            siblings: vec![],
        };
        assert!(adapter.verify_receipt_proof(&proof, &leaf, tx_hash).is_ok());
        // Forged root must fail.
        assert!(adapter
            .verify_receipt_proof(&proof, &[0u8; 32], tx_hash)
            .is_err());
    }

    #[test]
    fn verify_receipt_proof_v30_tx_hash_forgery_rejected() {
        // Farklı tx_hash ile aynı Merkle proof'u ileri sürmek
        // Kriptografik leaf bağı nedeniyle reddedilir.
        let adapter = EvmChainAdapter::test_default();
        let real_tx = "0xabc";
        let forged_tx = "0xdeadbeef";
        let leaf = derive_receipt_leaf(real_tx, &adapter.bridge_address);
        let proof = MerkleProof {
            leaf,
            index: 0,
            siblings: vec![],
        };
        // Real tx ile geçer.
        assert!(adapter.verify_receipt_proof(&proof, &leaf, real_tx).is_ok());
        // Forged tx ile RED.
        let err = adapter
            .verify_receipt_proof(&proof, &leaf, forged_tx)
            .expect_err("forged tx_hash must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("forgery"), "msg: {msg}");
    }

    #[test]
    fn verify_receipt_proof_v30_empty_tx_hash_rejected() {
        // Empty tx_hash kabul edilmez (binding anlamsız olur).
        let adapter = EvmChainAdapter::test_default();
        let leaf = derive_receipt_leaf("0xabc", &adapter.bridge_address);
        let proof = MerkleProof {
            leaf,
            index: 0,
            siblings: vec![],
        };
        let err = adapter
            .verify_receipt_proof(&proof, &leaf, "")
            .expect_err("empty tx_hash must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("tx_hash") || msg.contains("empty"),
            "msg: {msg}"
        );
    }

    #[test]
    fn verify_receipt_proof_v30_bridge_address_isolation() {
        // Bridge_address farklı olsa aynı tx_hash için leaf farklı
        // Olur → cross-bridge proof kullanımı reddedilir.
        let bridge_a = vec![0xaa; 20];
        let bridge_b = vec![0xbb; 20];
        let tx_hash = "0xabc";
        let leaf_a = derive_receipt_leaf(tx_hash, &bridge_a);
        let leaf_b = derive_receipt_leaf(tx_hash, &bridge_b);
        assert_ne!(leaf_a, leaf_b);
        let adapter_a = EvmChainAdapter::new(bridge_a.clone(), DEFAULT_DEPOSIT_TOPIC0);
        let proof = MerkleProof {
            leaf: leaf_a,
            index: 0,
            siblings: vec![],
        };
        // Bridge A → leaf_a bağlamı doğru; adapter_a ile geçer.
        assert!(adapter_a
            .verify_receipt_proof(&proof, &leaf_a, tx_hash)
            .is_ok());
        // Bridge A'nın proof'unu Bridge B'nin adapter'ı ile kullanırsak RED.
        let adapter_b = EvmChainAdapter::new(bridge_b, DEFAULT_DEPOSIT_TOPIC0);
        let err = adapter_b
            .verify_receipt_proof(&proof, &leaf_a, tx_hash)
            .expect_err("cross-bridge proof must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("forgery"), "msg: {msg}");
    }

    #[test]
    fn derive_receipt_leaf_is_deterministic_and_collision_resistant() {
        let bridge = vec![0xcc; 20];
        // Determinism: aynı input → aynı leaf.
        assert_eq!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xabc", &bridge)
        );
        // Farklı tx_hash → farklı leaf.
        assert_ne!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xdef", &bridge)
        );
        // Farklı bridge → farklı leaf.
        assert_ne!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xabc", &[0xdd; 20])
        );
    }

    /// The stronger of the two verification paths has no caller.
    ///
    /// This file documents `verify_deposit` as "gerçek güvenli yol", the real
    /// safe path - and it is: it runs the full `verify_evm_receipt`
    /// orchestrator (header chain with N confirmations, MPT inclusion, receipt
    /// status, deposit-log match). The trait method `verify_receipt_proof`
    /// checks a Merkle proof against a declared root plus a leaf binding, and
    /// takes the receipts root on the relayer's word.
    ///
    /// Production calls the second one. `relayer/worker.rs:263` invokes
    /// `adapter.verify_receipt_proof(...)`; nothing anywhere invokes
    /// `verify_deposit`, and until this test existed nothing referenced it
    /// outside its own definition - not even a test.
    ///
    /// That was survivable while the adapter registry was empty in production,
    /// because every chain answered `UnsupportedChain` and the outbound path
    /// refused rather than accepting a weakly-verified deposit. It is no
    /// longer empty by construction: `--evm-bridge-address` and
    /// `--evm-deposit-topic0` let an operator register this adapter, and then
    /// the trait path is what runs. The gap below is now reachable on a node
    /// whose operator configured the bridge, which is exactly the ordering
    /// this test warned about. `relayer_worker_locks.rs` pins the
    /// configuration half.
    ///
    /// The danger is the order of events when someone wires the registry up:
    /// the code compiles, the tests pass, the comment says the safe path
    /// exists, and the weak path is what actually runs. This test makes the
    /// gap explicit and breaks when either half of it changes.
    ///
    /// What has since been added is not a fix for that gap but a floor under
    /// it. `AdapterRegistry::register` now asks each adapter whether it is
    /// fit to relay, and the EVM one refuses a zero bridge address or zero
    /// confirmations. That stops the worst version of the wiring mistake, an
    /// adapter that verifies nothing because it points nowhere, without
    /// pretending the trait path checks what `verify_deposit` checks. It
    /// still does not.
    #[test]
    fn the_full_receipt_verification_path_is_still_unreachable_from_production() {
        let adapter_src = include_str!("adapter.rs");
        let worker_src = include_str!("../../relayer/worker.rs");

        // `verify_deposit` exists and still wraps the full orchestrator.
        assert!(
            adapter_src.contains("pub fn verify_deposit("),
            "verify_deposit was removed or renamed; update this pin"
        );
        assert!(
            adapter_src.contains("verify_evm_receipt(proof)?"),
            "verify_deposit no longer runs the full verify_evm_receipt \
             orchestrator - the 'real safe path' claim in this file's header \
             needs rewriting"
        );

        // The relayer reaches the adapter through the trait method only.
        assert!(
            worker_src.contains("verify_receipt_proof("),
            "the relayer no longer calls verify_receipt_proof; re-derive which \
             verification actually runs before touching this test"
        );
        assert!(
            !worker_src.contains("verify_deposit"),
            "the relayer now calls verify_deposit - the stronger path is live. \
             Delete this test and pin the new behaviour instead"
        );
    }
}
