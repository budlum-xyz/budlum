#![allow(clippy::pedantic, clippy::nursery)]

//! F10.4 EvmChainAdapter - the real ChainAdapter impl (the H4 fully live path).
//!
//! Two sides:
//!
//! - **On-chain (verify_receipt_proof):** deterministic in Budlum consensus.
//!   It uses F10.1 (MPT) + F10.2 (receipt/header/verify). The sync committee
//!   (F10.3) runs only if `EvmDepositProof.sync_attestation` is populated;
//!   this line said "uses" for a long time while no path called it.
//!   Network-free - the relayer produces the proof, Budlum verifies it.
//!
//! - **Off-chain (generate/submit/wait):** in the relayer binary (`src/bin/
//!   budlum-relayer.rs`). It connects to Ethereum RPC. This module provides the
//!   structure + a minimal impl; the production RPC client is separate (reqwest/alloy - after mainnet).
//!
//! **Security invariant:** `verify_receipt_proof` NEVER connects to the network.
//!
//! ## The cryptographic binding between receipt and tx_hash
//!
//! `proof.leaf` must now be derived with the formula
//! `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`. An attacker
//! cannot copy the same Merkle proof and present it with a different tx_hash:
//! the leaf is recomputed and a mismatch ends in `ProofVerificationFailed`. The
//! same binding also prevents cross-bridge proof reuse (the leaf is bound to
//! bridge_address).
//!
//! **Security boundary:** the wire format changed - the off-chain relayer tool
//! must produce the leaf with the same formula. `verify_deposit` (the real safe
//! path) is unaffected: it already does MPT + header chain + status + log match
//! over the full `EvmDepositProof`.

use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::chain_adapter::{AdapterError, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;
use crate::cross_domain::evm::verify::{
    verify_evm_receipt, EvmDepositProof, VerifiedDeposit, VerifyError,
};
use crate::domain::types::Hash32;

/// The Ethereum bridge contract deposit event signature (topic0).
/// Keccak256("Deposit(address,uint256,bytes32,uint256)") - the real value is
/// set with the chain config during the ceremony. A placeholder here (CI test).
pub const DEFAULT_DEPOSIT_TOPIC0: [u8; 32] = [0u8; 32];

/// EvmChainAdapter - the real ChainAdapter for Ethereum.
///
/// `verify_receipt_proof` on-chain deterministik. Off-chain metodlar
/// (`generate_receipt_proof`/`submit_transaction`/`wait_for_confirmation`)
/// connect to Ethereum RPC in the relayer binary; in this impl they are in
/// offline-test mode (the StubAdapter pattern) - production RPC is separate.
///
/// `Debug` so a caller can `expect` on a `Result` carrying one. All three
/// fields are public configuration already: a contract address, an event
/// topic and a confirmation count. There is no key material here to leak
/// into a log line.
#[derive(Debug)]
pub struct EvmChainAdapter {
    /// The Ethereum bridge contract address (the deposit event emitter).
    pub bridge_address: Vec<u8>,
    /// Deposit event topic0 = keccak256("Deposit(...)").
    pub deposit_topic0: [u8; 32],
    /// The N-confirmation threshold (the reorg window; mainnet is about 64).
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

    /// Off-chain (the relayer binary): produce a receipt + MPT proof from Ethereum RPC.
    ///
    /// This impl is an offline-test stub (the StubAdapter pattern). The production
    /// RPC client lives in `src/bin/budlum-relayer.rs` (after mainnet, reqwest/alloy).
    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        // This adapter does not read Ethereum, so it cannot produce a receipt
        // proof. It used to return a single-leaf tree: the leaf and the root were
        // the same value, so the Merkle check inside `verify_receipt_proof`
        // passed without measuring anything. The most dangerous form of a stub is
        // one that produces output which looks valid.
        //
        // Refusing is the correct behaviour. The relayer sees this error and signs
        // nothing; a silent relayer delays a transfer, but a relayer signing an
        // unverified success turns a lie into truth.
        let _ = tx_hash;
        Err(AdapterError::ProofVerificationFailed(
            "EVM adapter cannot assemble a receipt proof: it does not read Ethereum. \
             Wire an RPC-backed proof assembler before relaying value"
                .into(),
        ))
    }

    /// ON-CHAIN (Budlum consensus): verify an EVM receipt proof.
    ///
    /// Deterministic + network-free. F10.1 (MPT) + F10.2 (receipt/header). The
    /// relayer produces the proof. The sync committee never runs on this trait
    /// path: this method only checks the Merkle proof + leaf binding, while the
    /// full package (`EvmDepositProof`) goes to `verify_deposit`.
    ///
    /// **Wire format:** `proof.leaf` =
    /// `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`;
    /// `external_state_root` = header.receiptsRoot; `expected_tx_hash` = tx_hash.
    /// Header chain + sync-committee verification is NOT in this method, it is
    /// inside `verify_evm_receipt`, and only `verify_deposit` goes there.
    ///
    ///
    /// **Two-part verification:**
    /// 1) `proof.verify(external_state_root)` - Merkle self-consistency.
    /// 2) `proof.leaf == derive_receipt_leaf(tx_hash, bridge_address)` -
    ///    The cryptographic leaf binding. An attacker cannot present the same
    ///    proof with a different tx_hash; a cross-bridge proof is rejected too.
    ///
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
        // A leaf is not verified against its own root.
        //
        // When `MerkleProof::verify` is called with an empty `siblings` list it
        // takes no hash step and falls through to the `leaf == expected_root`
        // comparison. So if the party producing the proof gives the same value as
        // both leaf and root, the check passes. That is the adapter having a tree
        // it invented approved by itself; the offline stub of
        // `generate_receipt_proof` produces exactly that.
        //
        // The check is here, before `verify`. Placed after, the call would already
        // have passed.
        if proof.siblings.is_empty() {
            return Err(AdapterError::ProofVerificationFailed(
                "EVM receipt proof has no sibling path: a single-leaf tree proves only that \
                 the prover can repeat itself, because leaf and root are then the same value"
                    .into(),
            ));
        }
        // Merkle proof self-consistency (the partial fix).
        if !proof.verify(*external_state_root) {
            return Err(AdapterError::ProofVerificationFailed(
                "EVM receipt Merkle proof does not verify against declared receipts root".into(),
            ));
        }
        // The full fix - the cryptographic binding of leaf to tx_hash + bridge_address.
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
    /// Full on-chain EVM deposit verification (the F10.2 `verify.rs` orchestrator).
    ///
    /// This is the enriched form of `ChainAdapter::verify_receipt_proof`: the
    /// relayer supplies the full proof package (header chain + MPT nodes +
    /// receipt), and what comes back is a **proven deposit**.
    ///
    /// This function used to throw away the result of `verify_evm_receipt` as
    /// `_verified`, resolve the header chain and the MPT a second time and hand
    /// the caller a raw `EthReceipt`. It had two defects. First: the same check
    /// was written in two places, and when a check has two copies the attacker
    /// picks which one applies (see `docs/ARCHITECTURE.md` section 65).
    /// Second and worse: `EthReceipt` is a type that does not carry the two
    /// checks `verify_evm_receipt` actually *does* (is `status` correct, does the
    /// deposit log really exist). The caller received, from a function named
    /// "verify", a receipt whose status appeared unchecked.
    ///
    /// Now there is a single verification and the returned type is what it proves.
    pub fn verify_deposit(
        &self,
        proof: &EvmDepositProof<'_>,
    ) -> Result<VerifiedDeposit, VerifyError> {
        verify_evm_receipt(proof)
    }
}

/// Derives the receipt proof leaf from `tx_hash + bridge_address`.
/// Domain-tagged (collision-resistant, length-prefixed) SHA-256.
/// An attacker cannot copy a proof valid for another tx and present it with a
/// different tx_hash: the leaf is recomputed independently and a mismatch ends
/// in `ProofVerificationFailed`. The same binding also prevents cross-bridge
/// proof reuse.
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

    /// It refuses to produce a proof for a chain it does not read.
    ///
    /// It used to return a single-leaf tree and its test **pinned** the equality
    /// `proof.leaf == root`. That equality was precisely the defect:
    /// `MerkleProof::verify` takes no hash step with an empty sibling list, falls
    /// through to the `leaf == root` comparison and passes. So the proof produced
    /// by the adapter always passed the adapter's own check.
    ///
    #[tokio::test]
    async fn the_offline_adapter_refuses_to_invent_a_proof() {
        let adapter = EvmChainAdapter::test_default();
        let err = adapter
            .generate_receipt_proof("0xabc")
            .await
            .expect_err("a receipt proof cannot be produced without reading Ethereum");
        assert!(
            format!("{err:?}").contains("does not read Ethereum"),
            "the reason must say what is missing: {err:?}"
        );
    }

    /// And a single-leaf tree is not accepted even when built by hand.
    #[test]
    fn a_single_leaf_tree_is_refused() {
        let adapter = EvmChainAdapter::new(vec![7u8; 20], DEFAULT_DEPOSIT_TOPIC0);
        let leaf = derive_receipt_leaf("0xabc", &adapter.bridge_address);
        let proof = MerkleProof {
            leaf,
            index: 0,
            siblings: Vec::new(),
        };
        // Leaf and root are the same: `verify` would pass without taking a step.
        let err = adapter
            .verify_receipt_proof(&proof, &leaf, "0xabc")
            .expect_err("a path without siblings proves nothing");
        assert!(
            format!("{err:?}").contains("no sibling path"),
            "the reason must say the sibling path is missing: {err:?}"
        );
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

    /// Waiting for confirmation also refuses, because it cannot produce a proof.
    ///
    /// It used to return `success: true`. The relayer would read that as a result
    /// it could sign, while there is no Ethereum read underneath it at all.
    #[tokio::test]
    async fn waiting_for_confirmation_refuses_without_a_proof() {
        let adapter = EvmChainAdapter::test_default();
        assert!(
            adapter.wait_for_confirmation("0xabc", 1).await.is_err(),
            "an adapter that cannot produce a proof must not report a successful result"
        );
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

    /// Builds a proof with a real sibling path.
    ///
    /// What the tests below measure is the leaf binding, not the tree. But a
    /// single-leaf tree is now rejected (ARCHITECTURE.md section 69): on a path
    /// without siblings `verify` takes no hash step and falls through to the
    /// `leaf == root` comparison, so the prover approves its own output. This
    /// helper adds a single sibling and computes the root with it, so the tests
    /// keep measuring what they mean to measure.
    fn proof_with_sibling(leaf: Hash32) -> (MerkleProof, Hash32) {
        let sibling = [0x5au8; 32];
        let root = crate::core::hash::hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", &leaf, &sibling]);
        (
            MerkleProof {
                leaf,
                index: 0,
                siblings: vec![sibling],
            },
            root,
        )
    }

    #[test]
    fn verify_receipt_proof_minimal_ok() {
        // Tam fix: leaf = hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address).
        let adapter = EvmChainAdapter::test_default();
        let tx_hash = "0xabc";
        let leaf = derive_receipt_leaf(tx_hash, &adapter.bridge_address);
        let (proof, root) = proof_with_sibling(leaf);
        assert!(adapter.verify_receipt_proof(&proof, &root, tx_hash).is_ok());
        // Forged root must fail.
        assert!(adapter
            .verify_receipt_proof(&proof, &[0u8; 32], tx_hash)
            .is_err());
    }

    #[test]
    fn verify_receipt_proof_v30_tx_hash_forgery_rejected() {
        // Presenting the same Merkle proof with a different tx_hash is rejected
        // because of the cryptographic leaf binding.
        let adapter = EvmChainAdapter::test_default();
        let real_tx = "0xabc";
        let forged_tx = "0xdeadbeef";
        let leaf = derive_receipt_leaf(real_tx, &adapter.bridge_address);
        let (proof, root) = proof_with_sibling(leaf);
        // It passes with the real tx.
        assert!(adapter.verify_receipt_proof(&proof, &root, real_tx).is_ok());
        // REJECTED with the forged tx.
        let err = adapter
            .verify_receipt_proof(&proof, &root, forged_tx)
            .expect_err("forged tx_hash must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("forgery"), "msg: {msg}");
    }

    #[test]
    fn verify_receipt_proof_v30_empty_tx_hash_rejected() {
        // An empty tx_hash is not accepted (the binding would be meaningless).
        let adapter = EvmChainAdapter::test_default();
        let leaf = derive_receipt_leaf("0xabc", &adapter.bridge_address);
        let (proof, root) = proof_with_sibling(leaf);
        let err = adapter
            .verify_receipt_proof(&proof, &root, "")
            .expect_err("empty tx_hash must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("tx_hash") || msg.contains("empty"),
            "msg: {msg}"
        );
    }

    #[test]
    fn verify_receipt_proof_v30_bridge_address_isolation() {
        // With a different bridge_address the leaf differs for the same tx_hash,
        // so cross-bridge proof reuse is rejected.
        let bridge_a = vec![0xaa; 20];
        let bridge_b = vec![0xbb; 20];
        let tx_hash = "0xabc";
        let leaf_a = derive_receipt_leaf(tx_hash, &bridge_a);
        let leaf_b = derive_receipt_leaf(tx_hash, &bridge_b);
        assert_ne!(leaf_a, leaf_b);
        let adapter_a = EvmChainAdapter::new(bridge_a.clone(), DEFAULT_DEPOSIT_TOPIC0);
        let (proof, root) = proof_with_sibling(leaf_a);
        // Bridge A -> the leaf_a context is correct; it passes with adapter_a.
        assert!(adapter_a
            .verify_receipt_proof(&proof, &root, tx_hash)
            .is_ok());
        // Using bridge A's proof with bridge B's adapter is REJECTED.
        let adapter_b = EvmChainAdapter::new(bridge_b, DEFAULT_DEPOSIT_TOPIC0);
        let err = adapter_b
            .verify_receipt_proof(&proof, &root, tx_hash)
            .expect_err("cross-bridge proof must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("forgery"), "msg: {msg}");
    }

    #[test]
    fn derive_receipt_leaf_is_deterministic_and_collision_resistant() {
        let bridge = vec![0xcc; 20];
        // Determinism: the same input gives the same leaf.
        assert_eq!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xabc", &bridge)
        );
        // A different tx_hash gives a different leaf.
        assert_ne!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xdef", &bridge)
        );
        // A different bridge gives a different leaf.
        assert_ne!(
            derive_receipt_leaf("0xabc", &bridge),
            derive_receipt_leaf("0xabc", &[0xdd; 20])
        );
    }

    /// The stronger of the two verification paths has no caller.
    ///
    /// This file documents `verify_deposit` as the real
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

        // Measure the production half only.
        //
        // `include_str!` reads this test module too, and both strings below
        // appear once in production and once in the assertion that searches
        // for them. Searched whole-file, deleting `verify_deposit` outright
        // would leave these assertions passing on the strength of their own
        // text: the pin would survive the very change it exists to catch.
        let adapter_prod = adapter_src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("this file keeps its tests behind #[cfg(test)]");
        assert!(
            adapter_prod.len() < adapter_src.len(),
            "the #[cfg(test)] split matched nothing, so the assertions below \
             are reading their own source again"
        );

        // `verify_deposit` exists and still wraps the full orchestrator.
        assert!(
            adapter_prod.contains("pub fn verify_deposit("),
            "verify_deposit was removed or renamed; update this pin"
        );
        assert!(
            adapter_prod.contains("verify_evm_receipt(proof)"),
            "verify_deposit no longer runs the full verify_evm_receipt \
             orchestrator - the 'real safe path' claim in this file's header \
             needs rewriting"
        );
        // And it returns what that orchestrator proved. Returning a bare
        // `EthReceipt` would hand the caller a value that does not carry the
        // status check or the deposit-log match `verify_evm_receipt` made,
        // from a function named `verify`. See ARCHITECTURE.md section 68.
        assert!(
            adapter_prod.contains("Result<VerifiedDeposit, VerifyError>"),
            "verify_deposit must return the proven deposit, not a raw receipt"
        );
        // One verification, not two. A second header/MPT decode in this file
        // would be a second copy of the same check, and an attacker picks
        // which copy applies (section 65).
        assert!(
            !adapter_prod.contains("mpt::verify("),
            "verify_deposit is decoding the MPT again instead of delegating"
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
