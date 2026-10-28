//! WIRING: unwired - verify_deposit_observed is reached only from the adapter fixture tests in this tree; the live relayer observation runs the adapter's verify_observation instead.
//! F10.4 EvmChainAdapter - the ChainAdapter impl for the EVM leg. NOT a
//! fully live path (BLG-0135/P06-F06): the off-chain half is a stub that
//! refuses at broadcast, so the Ethereum-to-Budlum leg has no live end-to-end
//! route. The on-chain verification below is real and deterministic; what it
//! verifies today is produced only in tests.
//!
//! Two sides:
//!
//! - On-chain (verify_receipt_proof): deterministic in Budlum consensus.
//!   It uses F10.1 (MPT) + F10.2 (receipt/header/verify). The sync committee
//!   (F10.3) runs only if `EvmDepositProof.sync_attestation` is populated;
//!   this line said "uses" for a long time while no path called it.
//!   Network-free - the relayer produces the proof, Budlum verifies it.
//!
//! - Off-chain (generate/submit/wait): in the relayer binary (`src/bin/
//!   budlum-relayer.rs`). It connects to Ethereum RPC. This module provides the
//!   structure + a minimal impl; the production RPC client is separate (reqwest/alloy - after mainnet).
//!
//! Security invariant: `verify_receipt_proof` NEVER connects to the network.
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
//! Security boundary: the wire format changed - the off-chain relayer tool
//! must produce the leaf with the same formula. `verify_deposit` does MPT +
//! header chain + status + log match over the full `EvmDepositProof`, but it
//! is UNREACHABLE today (BLG-0135): no production path calls it.

use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::{ExternalChain, ExternalTransaction, RelayerExternalResult};
use crate::cross_domain::chain_adapter::{AdapterError, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::cross_domain::evm::header::DEFAULT_CONFIRMATIONS;
use crate::cross_domain::evm::verify::{
    verify_evm_receipt, DepositProofPackage, EvmDepositProof, VerifiedDeposit, VerifyError,
};
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use bincode::Options;

/// Ceiling on a serialised [`DepositProofPackage`]: sixty-four confirmation
/// headers of a few hundred bytes plus an MPT path of a dozen nodes fit in a
/// small fraction of this; an observation larger than it is not a proof.
const MAX_DEPOSIT_PACKAGE_BYTES: u64 = 1024 * 1024;

/// The Ethereum bridge contract deposit event signature (topic0).
/// Keccak256("Deposit(address,uint256,bytes32,uint256)") - the real value is
/// set with the chain config during the ceremony. A placeholder here (CI test).
pub const DEFAULT_DEPOSIT_TOPIC0: [u8; 32] = [0u8; 32];

/// EvmChainAdapter - the ChainAdapter for Ethereum.
///
/// `verify_receipt_proof` is deterministic in Budlum consensus. The off-chain
/// methods (`generate_receipt_proof`/`submit_transaction`/
/// `wait_for_confirmation`) are an offline-test stub (the StubAdapter
/// pattern) that REFUSES at broadcast - there is no live Ethereum RPC route
/// (BLG-0135/P06-F06).
///
/// `Debug` so a caller can `expect` on a `Result` carrying one. All three
/// fields are public configuration already: a contract address, an event
/// topic and a confirmation count. There is no key material here to leak
/// into a log line.
#[derive(Debug)]
///
/// WIRING: the EVM deposit adapter for the relayer's adapter
/// registry; no production relayer registers an EVM adapter yet
/// (a lock test holds that line), so deposit verification is
/// pinned by this module's tests.
pub struct EvmChainAdapter {
    /// The Ethereum bridge contract address (the deposit event emitter).
    pub bridge_address: Vec<u8>,
    /// Deposit event topic0 = keccak256("Deposit(...)").
    pub deposit_topic0: [u8; 32],
    /// The N-confirmation threshold (the reorg window; mainnet is about 64).
    pub required_confirmations: u32,
    /// BLG-0111 (P05-F04): the operator's trusted checkpoint `(number,
    /// hash)` - the interim anchor the header chain must touch.
    pub trusted_checkpoint: Option<(u64, [u8; 32])>,
}

impl EvmChainAdapter {
    pub fn new(bridge_address: Vec<u8>, deposit_topic0: [u8; 32]) -> Self {
        Self {
            bridge_address,
            deposit_topic0,
            required_confirmations: DEFAULT_CONFIRMATIONS,
            trusted_checkpoint: None,
        }
    }

    /// Pins the operator's trusted checkpoint - BLG-0111 (P05-F04) interim
    /// form A of the finality rule: until relayers ship sync-committee
    /// attestations (form B), the deposit's header chain must touch this
    /// anchor or the deposit refuses.
    #[must_use]
    ///
    /// WIRING: the operator configuration for the interim finality rule
    /// above; it is set when an operator actually registers this
    /// adapter, which no production relayer does yet.
    pub fn with_trusted_checkpoint(mut self, number: u64, hash: [u8; 32]) -> Self {
        self.trusted_checkpoint = Some((number, hash));
        self
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
        // BLG-0111 (P05-F04): without finality evidence every deposit would
        // refuse at verify time anyway - say it once, at setup. Form B
        // (sync-committee attestation) supersedes the anchor when relayers
        // ship it.
        if self.trusted_checkpoint.is_none() {
            return Err(
                "EVM adapter has no trusted checkpoint: deposits need finality \
                 evidence (a sync-committee attestation or the interim anchor)"
                    .to_string(),
            );
        }
        if self.bridge_address.len() != 20 {
            return Err(format!(
                "EVM adapter bridge address must be exactly 20 bytes, got {}",
                self.bridge_address.len()
            ));
        }
        if self.bridge_address.iter().all(|b| *b == 0) {
            return Err(
                "EVM adapter has a zero bridge address: every receipt leaf binds to this \
                 address, so the node would advertise Ethereum support while pointing at no \
                 contract"
                    .into(),
            );
        }
        if self.deposit_topic0 == [0u8; 32] {
            return Err(
                "EVM adapter has a zero deposit topic: placeholder event configuration cannot relay value"
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
    /// This impl is an offline-test stub (the StubAdapter pattern) and
    /// REFUSES - there is no live Ethereum RPC route (BLG-0135/P06-F06).
    /// A production RPC client does not exist in this tree.
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
    /// Wire format: `proof.leaf` =
    /// `hash(BDLM_EVM_RECEIPT_LEAF_V1 || tx_hash || bridge_address)`;
    /// `external_state_root` = header.receiptsRoot; `expected_tx_hash` = tx_hash.
    /// Header chain + sync-committee verification is NOT in this method, it is
    /// inside `verify_evm_receipt`, and only `verify_deposit` goes there.
    ///
    ///
    /// Two-part verification:
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

    /// The observation the relayer signs must carry the full deposit
    /// package, and the package must pass `verify_deposit`.
    ///
    /// The trait default reads a bare `MerkleProof` and runs
    /// `verify_receipt_proof`, which takes the receipts root on the
    /// relayer's word and never walks a header chain. That was the only
    /// check on the production path while `verify_deposit`, the one this
    /// file has always called the real safe path, had no caller. An
    /// operator who registered this adapter got the weaker check without
    /// being told.
    ///
    /// The override refuses a bare `MerkleProof` outright, decodes the
    /// `receipt_proof` bytes as a [`DepositProofPackage`], borrows it with
    /// this adapter's bridge address, deposit topic and confirmation floor,
    /// and runs the full verifier. Three bindings on top of that: the
    /// package's transaction hash is the result's, the proven receipts root
    /// is the root the result declares, and the result's `success` is the
    /// receipt's status, which `verify_evm_receipt` has already required to
    /// be true.
    fn verify_observation(&self, result: &RelayerExternalResult) -> Result<(), AdapterError> {
        let package: DepositProofPackage = bincode::options()
            .with_fixint_encoding()
            .with_limit(MAX_DEPOSIT_PACKAGE_BYTES)
            .deserialize(&result.receipt_proof)
            .map_err(|e| {
                AdapterError::ProofVerificationFailed(format!(
                    "EVM observation does not carry a deposit package (header chain, MPT \
                     nodes, receipt key): {e}. A bare Merkle path is not accepted on this \
                     chain"
                ))
            })?;
        if package.tx_hash != result.tx_hash {
            return Err(AdapterError::ProofVerificationFailed(format!(
                "deposit package is for {} but the observation names {}",
                package.tx_hash, result.tx_hash
            )));
        }
        let confirmation_headers: Vec<&[u8]> = package
            .confirmation_headers
            .iter()
            .map(Vec::as_slice)
            .collect();
        let proof = EvmDepositProof {
            target_header: &package.target_header,
            confirmation_headers: &confirmation_headers,
            required_confirmations: self.required_confirmations,
            proof_nodes: &package.proof_nodes,
            receipt_key: &package.receipt_key,
            tx_hash: &package.tx_hash,
            emitter_address: &self.bridge_address,
            deposit_topic0: &self.deposit_topic0,
            sync_attestation: None,
        };
        let verified = self
            .verify_deposit(&proof)
            .map_err(|e| AdapterError::ProofVerificationFailed(e.to_string()))?;
        if verified.receipts_root != result.external_state_root {
            return Err(AdapterError::ProofVerificationFailed(
                "the receipts root the header chain proves is not the external state root \
                 the observation declares"
                    .into(),
            ));
        }
        if !result.success {
            return Err(AdapterError::ProofVerificationFailed(
                "the receipt proves a successful deposit but the observation reports failure"
                    .into(),
            ));
        }
        // BLG-0136 (P06-F07, decision B interim): no sync attestation, no
        // accepted observation. `DepositProofPackage` cannot yet carry the
        // attestation and finality branch (decision A lands with the
        // committee work), and this seam built its proof with
        // `sync_attestation: None`, which let fabricated header chains read
        // as final behind the confirmation count. The verification above
        // still runs (so its specific refusals fire first); the seam itself
        // refuses to ACCEPT the result until the package can carry the
        // evidence.
        Err(AdapterError::ProofVerificationFailed(
            "the deposit package carries no sync attestation; BLG-0136 interim: this \
             observation seam refuses until the package can carry the attestation and \
             finality branch"
                .into(),
        ))
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
    /// This adapter does not speak to Ethereum, so it refuses, the same way
    /// `generate_receipt_proof` and `wait_for_confirmation` do. It used to
    /// answer with a constant hash, so a caller recorded a broadcast that
    /// never happened under a transaction hash that identified nothing; the
    /// worker then reserved a nonce and waited for a confirmation that could
    /// not come. A refusal keeps the request in `Retry` until an RPC-backed
    /// adapter is wired.
    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Err(AdapterError::SubmissionFailed(
            "EVM adapter cannot broadcast: it does not speak to Ethereum. Wire an \
             RPC-backed submitter before relaying value"
                .into(),
        ))
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
            receipt_proof: bincode::serialize(&proof)
                .map_err(|e| AdapterError::ProofGenerationFailed(e.to_string()))?,
            external_state_root: root,
        })
    }
}

impl EvmChainAdapter {
    /// Full on-chain EVM deposit verification (the F10.2 `verify.rs` orchestrator).
    ///
    /// This is the enriched form of `ChainAdapter::verify_receipt_proof`: the
    /// relayer supplies the full proof package (header chain + MPT nodes +
    /// receipt), and what comes back is a proven deposit.
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
    ///
    /// The proof names its own `required_confirmations`, and the relayer
    /// writes that field. The adapter's `required_confirmations` is the
    /// operator's floor (`DEFAULT_CONFIRMATIONS` unless configured), so a
    /// proof that demands less than the floor is refused here, before the
    /// header chain is walked against the smaller number. Without this the
    /// configured window was a default the relayer could lower to one in the
    /// proof it sent.
    ///
    /// # Errors
    ///
    /// `VerifyError::Header` when the proof demands fewer confirmations than
    /// this adapter requires; otherwise whatever `verify_evm_receipt` returns.
    pub fn verify_deposit(
        &self,
        proof: &EvmDepositProof<'_>,
    ) -> Result<VerifiedDeposit, VerifyError> {
        if proof.required_confirmations < self.required_confirmations {
            return Err(VerifyError::Header(format!(
                "proof demands {} confirmations, adapter floor is {}",
                proof.required_confirmations, self.required_confirmations
            )));
        }
        // BLG-0111 (P05-F04): the operator's trusted checkpoint is the
        // interim finality anchor when the proof carries no sync attestation.
        verify_evm_receipt(proof, self.trusted_checkpoint.as_ref())
    }

    /// [`Self::verify_deposit`], naming the schemes the proven deposit rests
    /// on.
    ///
    /// A deposit that verified is a receipt in a chain whose transactions are
    /// authorised by secp256k1 account signatures, so that scheme is a fact of
    /// the claim even though this adapter never checks one signature itself.
    /// BLS12-381 is named only when the proof carried a sync-committee
    /// attestation, which is the one place a BLS aggregate was verified. A
    /// proof finalised by the operator's trusted checkpoint alone has no BLS
    /// fact, and the profile shows that too.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::verify_deposit`] refuses with; nothing is observed
    /// then.
    pub fn verify_deposit_observed(
        &self,
        proof: &EvmDepositProof<'_>,
        observer: &mut dyn CryptoObserver,
    ) -> Result<VerifiedDeposit, VerifyError> {
        let verified = self.verify_deposit(proof)?;
        for scheme in deposit_schemes(proof.sync_attestation.is_some()) {
            observer.observe(scheme);
        }
        Ok(verified)
    }
}

/// The schemes a verified EVM deposit rests on: secp256k1 always, BLS12-381
/// when a sync-committee attestation finalised the block.
fn deposit_schemes(attested: bool) -> Vec<ObservedScheme> {
    let mut schemes = vec![ObservedScheme::Secp256k1];
    if attested {
        schemes.push(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG));
    }
    schemes
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
    const TEST_DEPOSIT_TOPIC0: [u8; 32] = [0x11; 32];

    use super::*;
    use crate::cross_domain::evm::verify::fixtures;

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
    /// It used to return a single-leaf tree and its test pinned the equality
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
        let adapter = EvmChainAdapter::new(vec![7u8; 20], TEST_DEPOSIT_TOPIC0);
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

    /// Broadcasting refuses too: an adapter with no Ethereum connection must
    /// not hand back a transaction hash, because the worker treats a hash as
    /// a broadcast that happened.
    #[tokio::test]
    async fn submitting_a_transaction_refuses_without_a_connection() {
        let adapter = EvmChainAdapter::test_default();
        let tx = ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x0".to_string(),
            payload: vec![],
            external_nonce: 0,
        };
        let err = adapter
            .submit_transaction(&tx)
            .await
            .expect_err("no connection, no broadcast");
        assert!(
            matches!(err, AdapterError::SubmissionFailed(_)),
            "the refusal names the broadcast, got {err:?}"
        );
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
    fn a_bridge_address_with_the_wrong_shape_cannot_be_registered() {
        let adapter = EvmChainAdapter::new(vec![7u8; 19], TEST_DEPOSIT_TOPIC0)
            .with_trusted_checkpoint(1, [1; 32]);
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("exactly 20 bytes"), "got: {err}");
    }

    #[test]
    fn a_zero_deposit_topic_cannot_be_registered() {
        let adapter = EvmChainAdapter::new(vec![7u8; 20], DEFAULT_DEPOSIT_TOPIC0)
            .with_trusted_checkpoint(1, [1; 32]);
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("zero deposit topic"), "got: {err}");
    }

    #[test]
    fn a_zero_bridge_address_cannot_be_registered() {
        // `test_default` builds an adapter with a zero bridge address, which
        // is a legitimate thing for a test to do and not a legitimate thing
        // to relay with: every receipt leaf binds to `bridge_address`, so a
        // zero address binds to nothing in particular.
        let adapter = EvmChainAdapter::test_default().with_trusted_checkpoint(1, [1; 32]);
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("zero bridge address"), "got: {err}");

        let mut registry = crate::cross_domain::chain_adapter::AdapterRegistry::new();
        assert!(
            registry
                .register(Box::new(
                    EvmChainAdapter::test_default().with_trusted_checkpoint(1, [1; 32])
                ))
                .is_err(),
            "a zero-address adapter must not reach the registry: the node would \
             advertise Ethereum support while pointing at no contract"
        );
    }

    #[test]
    fn zero_confirmations_cannot_be_registered() {
        // A deposit from a block that can still be reorged away would be
        // minted against a transaction that did not happen.
        let mut adapter = EvmChainAdapter::new(vec![7u8; 20], TEST_DEPOSIT_TOPIC0)
            .with_trusted_checkpoint(1, [1; 32]);
        assert!(EvmChainAdapter::check_fit_for_relay(&adapter).is_ok());

        adapter.required_confirmations = 0;
        let err = EvmChainAdapter::check_fit_for_relay(&adapter).unwrap_err();
        assert!(err.contains("zero confirmations"), "got: {err}");
    }

    /// The confirmation window is the adapter's, not the proof's. A proof
    /// that names one confirmation against a 64-confirmation adapter is
    /// refused before any header is decoded; a proof at or above the floor
    /// goes on to the orchestrator, which then fails on the empty header
    /// list rather than on the floor.
    #[test]
    fn verify_deposit_holds_the_configured_confirmation_floor() {
        let adapter = EvmChainAdapter::new(vec![7u8; 20], TEST_DEPOSIT_TOPIC0);
        let topic0 = TEST_DEPOSIT_TOPIC0;
        let emitter = vec![7u8; 20];
        let proof_with = |required: u32| EvmDepositProof {
            target_header: &[],
            confirmation_headers: &[],
            required_confirmations: required,
            proof_nodes: &[],
            receipt_key: &[],
            tx_hash: "0x1",
            emitter_address: &emitter,
            deposit_topic0: &topic0,
            sync_attestation: None,
        };
        let below = adapter.verify_deposit(&proof_with(1)).unwrap_err();
        match below {
            VerifyError::Header(m) => assert!(m.contains("adapter floor is 64"), "got: {m}"),
            other => panic!("expected the floor refusal, got {other:?}"),
        }
        let zero = adapter.verify_deposit(&proof_with(0)).unwrap_err();
        assert!(matches!(zero, VerifyError::Header(_)));
        // at the floor the refusal comes from the empty target header, not the floor
        let at_floor = adapter
            .verify_deposit(&proof_with(DEFAULT_CONFIRMATIONS))
            .unwrap_err();
        match at_floor {
            VerifyError::Header(m) => assert!(!m.contains("adapter floor"), "got: {m}"),
            other => panic!("expected a header decode error, got {other:?}"),
        }
    }

    ///: a verified EVM deposit names secp256k1; BLS12-381 joins it when
    /// a sync-committee attestation finalised the block. A refused proof
    /// names nothing.
    #[test]
    fn a_verified_deposit_reports_secp256k1_and_bls_when_attested() {
        use crate::crypto::facts::{CryptoFacts, QuantumClass};
        let adapter = floor_three();
        let f = fixtures::build_fixture(
            &adapter.bridge_address,
            adapter.deposit_topic0,
            b"deposit-payload",
            true,
            3,
        );
        let confirmations = fixtures::conf_refs(&f);
        let proof = EvmDepositProof {
            target_header: &f.target_header,
            confirmation_headers: &confirmations,
            required_confirmations: 3,
            proof_nodes: &f.proof_nodes,
            receipt_key: &f.receipt_key,
            tx_hash: "0xabc123",
            emitter_address: &adapter.bridge_address,
            deposit_topic0: &adapter.deposit_topic0,
            sync_attestation: None,
        };
        let mut facts = CryptoFacts::new();
        adapter
            .verify_deposit_observed(&proof, &mut facts)
            .expect("the anchored fixture verifies");
        assert_eq!(facts.count(ObservedScheme::Secp256k1), 1);
        assert_eq!(
            facts.count(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)),
            0,
            "no attestation, no BLS fact"
        );
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Classical));

        let mut attested = CryptoFacts::new();
        for scheme in deposit_schemes(true) {
            crate::crypto::facts::CryptoObserver::observe(&mut attested, scheme);
        }
        assert_eq!(attested.count(ObservedScheme::Secp256k1), 1);
        assert_eq!(
            attested.count(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)),
            1
        );

        let mut refused = CryptoFacts::new();
        let below_floor = EvmDepositProof {
            required_confirmations: 1,
            ..proof
        };
        assert!(adapter
            .verify_deposit_observed(&below_floor, &mut refused)
            .is_err());
        assert!(refused.is_empty(), "a refused proof observes nothing");
    }

    #[test]
    fn a_configured_adapter_registers() {
        // The refusal has to stay narrow, or it is just a ban on Ethereum.
        let adapter = EvmChainAdapter::new(vec![7u8; 20], TEST_DEPOSIT_TOPIC0)
            .with_trusted_checkpoint(1, [1; 32]);
        assert!(EvmChainAdapter::check_fit_for_relay(&adapter).is_ok());

        let mut registry = crate::cross_domain::chain_adapter::AdapterRegistry::new();
        registry
            .register(Box::new(
                EvmChainAdapter::new(vec![7u8; 20], TEST_DEPOSIT_TOPIC0)
                    .with_trusted_checkpoint(1, [1; 32]),
            ))
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
        let adapter_a = EvmChainAdapter::new(bridge_a.clone(), TEST_DEPOSIT_TOPIC0);
        let (proof, root) = proof_with_sibling(leaf_a);
        // Bridge A -> the leaf_a context is correct; it passes with adapter_a.
        assert!(adapter_a
            .verify_receipt_proof(&proof, &root, tx_hash)
            .is_ok());
        // Using bridge A's proof with bridge B's adapter is REJECTED.
        let adapter_b = EvmChainAdapter::new(bridge_b, TEST_DEPOSIT_TOPIC0);
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

    /// The full deposit verification is the production path.
    ///
    /// This file used to carry a test named
    /// `the_full_receipt_verification_path_is_still_unreachable_from_production`,
    /// pinning that the relayer called `verify_receipt_proof` and nothing
    /// called `verify_deposit`. That was true from the day both were
    /// written until this override: `--evm-bridge-address` let an operator
    /// register this adapter, and then the weaker check was what ran on a
    /// deposit.
    ///
    /// The worker now calls `verify_observation` on every observation, and
    /// this adapter's override runs `verify_deposit`. The pin is inverted:
    /// the worker must not go back to reading a bare `MerkleProof` itself,
    /// and the override must keep delegating to the one verifier.
    #[test]
    fn the_relayer_reaches_verify_deposit() {
        let adapter_src = include_str!("adapter.rs");
        let worker_src = include_str!("../../relayer/worker.rs");
        let adapter_prod = adapter_src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("this file keeps its tests behind #[cfg(test)]");
        let worker_prod = worker_src
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .expect("worker.rs keeps its tests behind #[cfg(test)]");
        let worker_code: Vec<&str> = worker_prod
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//"))
            .collect();

        assert!(
            worker_code
                .iter()
                .any(|l| l.contains("verify_observation(&result)")),
            "the worker must hand the whole observation to the adapter"
        );
        assert!(
            !worker_code
                .iter()
                .any(|l| l.contains("verify_receipt_proof(")),
            "the worker is verifying a Merkle path itself again, which bypasses the \
             EVM adapter's full deposit check"
        );
        assert!(
            adapter_prod.contains("fn verify_observation(")
                && adapter_prod.contains(".verify_deposit(&proof)"),
            "the EVM override must run verify_deposit over the decoded package"
        );
        assert!(
            adapter_prod.contains("Result<VerifiedDeposit, VerifyError>"),
            "verify_deposit must return the proven deposit, not a raw receipt"
        );
        assert!(
            !adapter_prod.contains("mpt::verify("),
            "verify_deposit is decoding the MPT again instead of delegating"
        );
    }

    /// One observation the relayer would sign: a real header chain, a real
    /// receipt proof, the root it declares equal to the proven receiptsRoot.
    fn observation_for(adapter: &EvmChainAdapter, n_conf: u32) -> RelayerExternalResult {
        let f = fixtures::build_fixture(
            &adapter.bridge_address,
            adapter.deposit_topic0,
            b"deposit-payload",
            true,
            n_conf,
        );
        let package = DepositProofPackage {
            target_header: f.target_header.clone(),
            confirmation_headers: f.conf_headers.clone(),
            proof_nodes: f.proof_nodes.clone(),
            receipt_key: f.receipt_key.clone(),
            tx_hash: "0xabc123".to_string(),
        };
        RelayerExternalResult {
            chain: ExternalChain::Ethereum,
            tx_hash: "0xabc123".to_string(),
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&package).expect("package serialises"),
            external_state_root: f.receipts_root,
        }
    }

    /// `adapter` anchored at the target header of `source`'s fixture chain -
    /// the interim finality anchor (BLG-0111) the chain must touch for the
    /// later, more specific refusals to be reachable.
    fn anchored_to(adapter: EvmChainAdapter, source: &EvmChainAdapter) -> EvmChainAdapter {
        let f = fixtures::build_fixture(
            &source.bridge_address,
            source.deposit_topic0,
            b"deposit-payload",
            true,
            3,
        );
        let target = crate::cross_domain::evm::header::decode_header(&f.target_header)
            .expect("the fixture target header decodes");
        adapter.with_trusted_checkpoint(target.number, target.hash)
    }

    fn unanchored_floor_three() -> EvmChainAdapter {
        let mut adapter = EvmChainAdapter::new(vec![0xcc; 20], [0xab; 32]);
        adapter.required_confirmations = 3;
        adapter
    }

    fn floor_three() -> EvmChainAdapter {
        let base = unanchored_floor_three();
        anchored_to(unanchored_floor_three(), &base)
    }

    /// BLG-0136 (P06-F07, decision B interim): even a fully proven package
    /// is REFUSED at this seam while it cannot carry a sync attestation. The
    /// old positive pinned the missing rule: an attestation-less package
    /// verified as final. Until the package gains the attestation and
    /// finality branch (decision A), acceptance is impossible here.
    #[test]
    fn a_full_deposit_package_without_an_attestation_is_refused() {
        let adapter = floor_three();
        let observation = observation_for(&adapter, 3);
        let err = adapter
            .verify_observation(&observation)
            .expect_err("no sync attestation, no accepted observation (BLG-0136 interim)");
        // Either refusal is the contract: the 0111 finality rule (no
        // attestation and no checkpoint) or this seam's own attestation
        // gate. What is pinned is that attestation-less is not accepted.
        assert!(format!("{err}").contains("attestation"), "got: {err}");
    }

    /// A bare Merkle path, the shape the trait default accepts and the
    /// worker used to verify by itself, is refused on this chain.
    #[test]
    fn a_bare_merkle_path_is_refused_as_an_observation() {
        let adapter = floor_three();
        let leaf = derive_receipt_leaf("0xabc", &adapter.bridge_address);
        let (proof, root) = proof_with_sibling(leaf);
        let observation = RelayerExternalResult {
            chain: ExternalChain::Ethereum,
            tx_hash: "0xabc".to_string(),
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&proof).expect("proof serialises"),
            external_state_root: root,
        };
        let err = adapter
            .verify_observation(&observation)
            .expect_err("a Merkle path without header chain and receipt proves no deposit");
        assert!(
            format!("{err}").contains("deposit package"),
            "the refusal must say what is missing: {err}"
        );
    }

    /// The confirmation window is the operator's. A package with fewer
    /// confirmation headers than the floor is refused by the header chain
    /// walk, whatever the relayer would have liked to declare.
    #[test]
    fn an_observation_below_the_confirmation_floor_is_refused() {
        let adapter = floor_three();
        let observation = observation_for(&adapter, 2);
        let err = adapter
            .verify_observation(&observation)
            .expect_err("two confirmations under a floor of three");
        assert!(format!("{err}").contains("header chain"), "got: {err}");
    }

    /// The root the observation declares has to be the root the header
    /// chain proves, or the executor would anchor the wrong value.
    #[test]
    fn an_observation_declaring_another_root_is_refused() {
        let adapter = floor_three();
        let mut observation = observation_for(&adapter, 3);
        observation.external_state_root = [0x77; 32];
        let err = adapter
            .verify_observation(&observation)
            .expect_err("declared root differs from the proven receiptsRoot");
        assert!(format!("{err}").contains("receipts root"), "got: {err}");
    }

    /// The package is bound to the transaction the observation names.
    #[test]
    fn an_observation_naming_another_transaction_is_refused() {
        let adapter = floor_three();
        let mut observation = observation_for(&adapter, 3);
        observation.tx_hash = "0xother".to_string();
        let err = adapter
            .verify_observation(&observation)
            .expect_err("package tx_hash and observation tx_hash differ");
        assert!(format!("{err}").contains("0xother"), "got: {err}");
    }

    /// A bridge address other than this adapter's finds no deposit log.
    #[test]
    fn an_observation_from_another_bridge_is_refused() {
        let mut other = EvmChainAdapter::new(vec![0xdd; 20], [0xab; 32]);
        other.required_confirmations = 3;
        // Anchored at the other chain's header: the refusal under test is the
        // emitter, not the checkpoint.
        let adapter = anchored_to(unanchored_floor_three(), &other);
        let observation = observation_for(&other, 3);
        let err = adapter
            .verify_observation(&observation)
            .expect_err("the log was emitted by another contract");
        assert!(
            format!("{err}").contains("deposit log not found"),
            "got: {err}"
        );
    }

    /// Reported failure over a receipt that proves success is a
    /// contradiction, and a contradiction is not signed.
    #[test]
    fn an_observation_contradicting_its_receipt_is_refused() {
        let adapter = floor_three();
        let mut observation = observation_for(&adapter, 3);
        observation.success = false;
        let err = adapter
            .verify_observation(&observation)
            .expect_err("success=false over a status=true receipt");
        assert!(format!("{err}").contains("reports failure"), "got: {err}");
    }
}
