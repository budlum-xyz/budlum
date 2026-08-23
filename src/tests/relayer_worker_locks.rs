//! A relayer may stay silent. It may not lie.
//!
//! `RelayerWorker` signs the `RelayerResult` transactions it submits. That
//! signature is what makes the claim credible to the rest of the network, so
//! the worker is the last place where an unverified external outcome can still
//! be stopped cheaply. Once it is signed and gossiped, the only remaining
//! defence is the consensus gate - and a gate is a worse place to discover
//! that your own relayer fabricates receipts.
//!
//! These tests pin the refusal behaviour on the paths that used to fabricate:
//! no adapter, a broken adapter, an adapter that contradicts itself, and an
//! adapter that reports a root anchoring nothing. They also pin the schema
//! boundary between adapter proofs and the executor's result-fact leaf, so a
//! future change cannot quietly make one look like the other.

use crate::core::transaction::{
    ExternalChain, ExternalTransaction, RelayerExternalResult, Transaction, TransactionType,
};
use crate::cross_domain::chain_adapter::{AdapterError, AdapterRegistry, ChainAdapter};
use crate::cross_domain::event_tree::MerkleProof;
use crate::domain::types::Hash32;
use crate::relayer::RelayerWorker;

fn relay_request(chain: ExternalChain) -> ExternalTransaction {
    ExternalTransaction {
        chain,
        target_address: "0x00000000000000000000000000000000000000aa".to_string(),
        payload: vec![1, 2, 3],
        external_nonce: 7,
    }
}

/// An adapter whose observation is internally consistent: the proof it hands
/// back is the proof its own verifier accepts. This is the shape a real
/// adapter must have, reduced to the minimum.
struct HonestAdapter {
    chain: ExternalChain,
}

#[async_trait::async_trait]
impl ChainAdapter for HonestAdapter {
    fn chain_type(&self) -> ExternalChain {
        self.chain
    }

    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        let leaf = crate::core::hash::hash_fields_bytes(&[
            b"RELAYER_WORKER_TEST_HONEST_LEAF",
            tx_hash.as_bytes(),
        ]);
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
        external_state_root: &Hash32,
        expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        let expected = crate::core::hash::hash_fields_bytes(&[
            b"RELAYER_WORKER_TEST_HONEST_LEAF",
            expected_tx_hash.as_bytes(),
        ]);
        if proof.leaf != expected {
            return Err(AdapterError::ProofVerificationFailed("leaf".into()));
        }
        if !proof.verify(*external_state_root) {
            return Err(AdapterError::ProofVerificationFailed("root".into()));
        }
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Ok("0xhonest".to_string())
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
            receipt_proof: bincode::serialize(&proof).expect("proof serialize"),
            external_state_root: root,
        })
    }
}

/// An adapter that reports success while handing back a proof its own verifier
/// rejects. This is the exact failure the worker must not launder into a
/// signed transaction - a real adapter can reach this state through an RPC
/// bug, a reorg between read and proof assembly, or a hostile endpoint.
struct ContradictoryAdapter;

#[async_trait::async_trait]
impl ChainAdapter for ContradictoryAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Ethereum
    }

    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        let leaf = crate::core::hash::hash_fields_bytes(&[
            b"RELAYER_WORKER_TEST_BAD_LEAF",
            tx_hash.as_bytes(),
        ]);
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
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ProofVerificationFailed(
            "receipt is not in the declared receipts root".into(),
        ))
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Ok("0xbad".to_string())
    }

    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
        Ok(RelayerExternalResult {
            chain: ExternalChain::Ethereum,
            tx_hash: hash,
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&proof).expect("proof serialize"),
            external_state_root: root,
        })
    }
}

/// An adapter that confirms a result whose root is all zeroes. A zero root
/// anchors nothing, so a "verified" result carrying one is a success claim
/// with no commitment behind it.
struct ZeroRootAdapter;

#[async_trait::async_trait]
impl ChainAdapter for ZeroRootAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Ethereum
    }

    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        Ok((
            MerkleProof {
                leaf: [0u8; 32],
                index: 0,
                siblings: Vec::new(),
            },
            [0u8; 32],
            tx_hash.to_string(),
        ))
    }

    fn verify_receipt_proof(
        &self,
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        // Deliberately permissive: the zero-root refusal must come from the
        // worker, not from the adapter being well-behaved.
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Ok("0xzero".to_string())
    }

    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
        Ok(RelayerExternalResult {
            chain: ExternalChain::Ethereum,
            tx_hash: hash,
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&proof).expect("proof serialize"),
            external_state_root: root,
        })
    }
}

/// An adapter registered for one chain that returns a result tagged as
/// another. The tag decides which `external_roots` domain the executor checks,
/// so a mismatched tag would send the proof to the wrong anchor registry.
struct ChainSwappingAdapter;

#[async_trait::async_trait]
impl ChainAdapter for ChainSwappingAdapter {
    fn chain_type(&self) -> ExternalChain {
        ExternalChain::Ethereum
    }

    async fn generate_receipt_proof(
        &self,
        tx_hash: &str,
    ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
        let leaf = crate::core::hash::hash_fields_bytes(&[
            b"RELAYER_WORKER_TEST_SWAP_LEAF",
            tx_hash.as_bytes(),
        ]);
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
        _proof: &MerkleProof,
        _external_state_root: &Hash32,
        _expected_tx_hash: &str,
    ) -> Result<(), AdapterError> {
        Ok(())
    }

    async fn submit_transaction(
        &self,
        _ext_tx: &ExternalTransaction,
    ) -> Result<String, AdapterError> {
        Ok("0xswap".to_string())
    }

    async fn wait_for_confirmation(
        &self,
        tx_hash: &str,
        _confirmations: u32,
    ) -> Result<RelayerExternalResult, AdapterError> {
        let (proof, root, hash) = self.generate_receipt_proof(tx_hash).await?;
        Ok(RelayerExternalResult {
            // Registered as Ethereum, reports Polygon.
            chain: ExternalChain::Polygon,
            tx_hash: hash,
            success: true,
            message: None,
            receipt_proof: bincode::serialize(&proof).expect("proof serialize"),
            external_state_root: root,
        })
    }
}

#[tokio::test]
async fn a_worker_without_adapters_produces_no_result() {
    // The default worker cannot reach any external chain. Before this lock it
    // still emitted `success: true` with a constant `0xEE..` hash for every
    // Ethereum relay request, which meant a validator running the default
    // configuration was attesting to Ethereum transactions it had never seen.
    let registry = AdapterRegistry::new();
    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err("a worker with no adapter must not produce a result");
    assert!(
        matches!(err, AdapterError::UnsupportedChain(ExternalChain::Ethereum)),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn every_chain_is_refused_when_no_adapter_is_registered() {
    // Not just Ethereum: the old code fell through to a warning for other
    // chains, so the asymmetry is worth pinning explicitly.
    let registry = AdapterRegistry::new();
    for chain in [
        ExternalChain::Ethereum,
        ExternalChain::Solana,
        ExternalChain::Bitcoin,
        ExternalChain::Avalanche,
        ExternalChain::Polygon,
        ExternalChain::Arbitrum,
        ExternalChain::Optimism,
        ExternalChain::Custom(99),
    ] {
        let err = RelayerWorker::build_verified_result(&registry, &relay_request(chain))
            .await
            .expect_err("no adapter means no result");
        assert!(
            matches!(err, AdapterError::UnsupportedChain(_)),
            "chain {chain:?} produced {err}"
        );
    }
}

#[tokio::test]
async fn an_adapter_that_fails_its_own_verifier_produces_no_result() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(ContradictoryAdapter))
        .expect("test adapter must be fit to relay");
    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err("a self-contradicting adapter must not yield a signed result");
    assert!(
        matches!(err, AdapterError::ProofVerificationFailed(_)),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn a_zero_external_root_is_refused_before_signing() {
    // The executor rejects a zero root too, but only after the relayer has
    // already signed and broadcast. Catching it here keeps a provably
    // worthless claim off the wire and out of the relayer's own history.
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(ZeroRootAdapter))
        .expect("test adapter must be fit to relay");
    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err("a zero root anchors nothing");
    let msg = format!("{err}");
    assert!(msg.contains("zero external state root"), "msg: {msg}");
}

#[tokio::test]
async fn a_result_tagged_for_a_different_chain_is_refused() {
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(ChainSwappingAdapter))
        .expect("test adapter must be fit to relay");
    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err("chain tag must match the adapter that produced the result");
    let msg = format!("{err}");
    assert!(msg.contains("tagged"), "msg: {msg}");
}

#[tokio::test]
async fn a_malformed_receipt_proof_from_an_adapter_is_refused() {
    struct GarbageProofAdapter;

    #[async_trait::async_trait]
    impl ChainAdapter for GarbageProofAdapter {
        fn chain_type(&self) -> ExternalChain {
            ExternalChain::Ethereum
        }
        async fn generate_receipt_proof(
            &self,
            tx_hash: &str,
        ) -> Result<(MerkleProof, Hash32, String), AdapterError> {
            Ok((
                MerkleProof {
                    leaf: [1u8; 32],
                    index: 0,
                    siblings: Vec::new(),
                },
                [1u8; 32],
                tx_hash.to_string(),
            ))
        }
        fn verify_receipt_proof(
            &self,
            _p: &MerkleProof,
            _r: &Hash32,
            _t: &str,
        ) -> Result<(), AdapterError> {
            Ok(())
        }
        async fn submit_transaction(
            &self,
            _e: &ExternalTransaction,
        ) -> Result<String, AdapterError> {
            Ok("0xg".to_string())
        }
        async fn wait_for_confirmation(
            &self,
            _tx_hash: &str,
            _c: u32,
        ) -> Result<RelayerExternalResult, AdapterError> {
            Ok(RelayerExternalResult {
                chain: ExternalChain::Ethereum,
                tx_hash: "0xg".to_string(),
                success: true,
                message: None,
                // Not a bincode-encoded MerkleProof.
                receipt_proof: vec![0xde, 0xad, 0xbe, 0xef],
                external_state_root: [1u8; 32],
            })
        }
    }

    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(GarbageProofAdapter))
        .expect("test adapter must be fit to relay");
    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err("an undecodable proof cannot be verified, so it cannot be signed");
    let msg = format!("{err}");
    assert!(msg.contains("does not decode"), "msg: {msg}");
}

#[tokio::test]
async fn an_internally_consistent_adapter_observation_is_accepted() {
    // The refusals above are only meaningful if the accepting path still
    // works - otherwise this would be a gate that rejects everything and
    // proves nothing.
    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(HonestAdapter {
            chain: ExternalChain::Ethereum,
        }))
        .expect("test adapter must be fit to relay");
    let result =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect("a verified observation must be usable");
    assert_eq!(result.chain, ExternalChain::Ethereum);
    assert_eq!(result.tx_hash, "0xhonest");
    assert_ne!(result.external_state_root, [0u8; 32]);
    assert!(!result.receipt_proof.is_empty());
}

#[tokio::test]
async fn the_placeholder_transaction_hash_is_no_longer_reachable() {
    // `0xEE` repeated 32 times was the fabricated hash. It is still returned
    // by the offline `submit_transaction` stubs, which is fine, those are
    // inputs, not results. What must not happen is that hash reaching a
    // signed `RelayerResult` without a verified receipt behind it.
    let placeholder = format!("0x{}", hex::encode([0xEEu8; 32]));
    let registry = AdapterRegistry::new();
    let outcome =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await;
    match outcome {
        Err(_) => {}
        Ok(result) => panic!(
            "an adapterless worker produced a result: tx_hash={} (placeholder={})",
            result.tx_hash, placeholder
        ),
    }
}

/// The adapter proof and the executor's result-fact leaf commit to different
/// things, and neither side can satisfy the other.
///
/// - an adapter proves *"this receipt is under this external receipts root"*;
/// - the executor requires *"this proof's leaf is `result_leaf()` of the
///   declared Budlum-side facts, under a root present in `external_roots`"*.
///
/// A real Ethereum receipts root does not commit to Budlum's
/// `BDLM_RELAYER_RESULT_V2` leaf, so an honest adapter observation is rejected
/// by the executor. That is the correct direction to fail, but it means the
/// bridge acceptance path is not merely unfinished, it is unsatisfiable as
/// specified. This test pins that so the gap is closed by designing the
/// anchor, not by loosening the executor until adapter output slips through.
#[tokio::test]
async fn an_adapter_observation_does_not_satisfy_the_executor_result_leaf() {
    use crate::core::account::AccountState;
    use crate::execution::executor::Executor;

    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(HonestAdapter {
            chain: ExternalChain::Ethereum,
        }))
        .expect("test adapter must be fit to relay");
    let result =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect("adapter observation");

    // Give the result the most favourable treatment possible: anchor its root
    // as if a light client had finalized it.
    let mut state = AccountState::new();
    let relayer = crate::core::address::Address::from([0x0A; 32]);
    state.add_balance(&relayer, 1_000);
    state.external_roots.insert(
        ExternalChain::Ethereum.domain_id(),
        result.external_state_root,
    );

    let decoded: MerkleProof =
        bincode::deserialize(&result.receipt_proof).expect("adapter proof decodes");
    assert_ne!(
        decoded.leaf,
        result.result_leaf(),
        "adapter leaf and executor result-fact leaf must remain distinct commitments"
    );

    let tx = Transaction::new_with_chain_id(
        relayer,
        crate::core::address::Address::zero(),
        0,
        1,
        0,
        Vec::new(),
        45262,
        TransactionType::RelayerResult(result),
    );
    let err = Executor::apply_transaction(&mut state, &tx)
        .expect_err("adapter proof must not satisfy the result-fact gate");
    assert!(
        err.contains("does not match the declared result facts"),
        "err: {err}"
    );
    assert_eq!(
        state.get_balance(&relayer),
        1_000,
        "a rejected relay result must not move balance"
    );
}

/// Source-level canary: the worker must not carry a hardcoded success literal.
///
/// A behavioural test can be satisfied by a code path that is bypassed
/// elsewhere in the same file. Reading the source keeps the specific
/// regression - "construct a `RelayerExternalResult` with `success: true`
/// inline" - from coming back through a different function.
#[test]
fn the_worker_source_contains_no_fabricated_success_literal() {
    let src = include_str!("../relayer/worker.rs");
    // Comments are allowed to name the thing they forbid, that is how the
    // next reader learns why the branch is missing. Only executable lines are
    // measured.
    let code: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect();

    let fabricated: Vec<&&str> = code
        .iter()
        .filter(|line| line.contains("success: true"))
        .collect();
    assert!(
        fabricated.is_empty(),
        "src/relayer/worker.rs must not construct a result with a literal `success: true`; \
         the value has to come from an adapter observation. Offending lines: {fabricated:?}"
    );

    let placeholder: Vec<&&str> = code.iter().filter(|line| line.contains("0xEE")).collect();
    assert!(
        placeholder.is_empty(),
        "src/relayer/worker.rs must not carry a placeholder transaction hash. \
         Offending lines: {placeholder:?}"
    );

    // And the refusal path has to still be there, otherwise the checks above
    // would pass on an empty file.
    assert!(
        src.contains("refusing to submit a relay result"),
        "the refusal branch is the whole point of this module"
    );

    // Canary: the filter must still be able to see a violation. If the
    // comment-stripping ever swallowed real code, the assertions above would
    // silently pass forever.
    let planted = ["    let x = RelayerExternalResult { success: true };"];
    assert!(
        planted
            .iter()
            .map(|l| l.trim())
            .filter(|line| !line.starts_with("//"))
            .any(|line| line.contains("success: true")),
        "the source scan cannot detect a planted violation, so it proves nothing"
    );
}

/// The relay cursor must follow finalized height, not chain height.
///
/// Relaying is an external side effect: once a transaction is submitted to
/// another chain it cannot be recalled. Following `get_height()` meant
/// relaying blocks a reorg could still remove, so a request that ended up off
/// the canonical chain had already been sent to the other side.
///
/// The old loop also stalled permanently after a reorg. `last_height` came
/// from chain height and the guard was `if current_height <= last_height {
/// continue; }`, so on a shorter fork the condition held forever and the
/// relayer went silent with nothing in the logs.
///
/// A source check rather than a behavioural one, because reproducing a reorg
/// needs a running chain actor; what matters is that the cursor cannot be
/// wired back to the reorg-able value.
#[test]
fn the_relay_cursor_reads_finalized_height() {
    let src = include_str!("../relayer/worker.rs");
    let code: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//") && !line.starts_with("///"))
        .collect();

    assert!(
        code.iter().any(|l| l.contains("get_finalized_height()")),
        "the relay loop must take its cursor from finalized height"
    );
    let reorgable: Vec<&&str> = code
        .iter()
        .filter(|l| l.contains("self.chain.get_height()"))
        .collect();
    assert!(
        reorgable.is_empty(),
        "the relay loop reads chain height, which moves backwards on a reorg \
         and has already caused a permanent stall: {reorgable:?}"
    );
}

/// The scan must be able to see the shape it forbids.
#[test]
fn the_relay_cursor_scan_can_detect_a_violation() {
    let planted = [
        "        let mut last_height = self.chain.get_height().await;",
        "/// followed self.chain.get_height() before the fix",
    ];
    let caught = planted
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("//") && !l.starts_with("///"))
        .filter(|l| l.contains("self.chain.get_height()"))
        .count();
    assert_eq!(
        caught, 1,
        "the scan must catch the code line and ignore the doc-comment one"
    );
}

/// An unconfigured worker refuses every external chain, and configuring one is
/// now possible.
///
/// Previously pinned the stronger claim that `main.rs` never calls
/// `with_adapters` at all, and asked whoever wired it to confirm the config
/// plumbing landed first. It has: `--evm-bridge-address`,
/// `--evm-deposit-topic0` and `--evm-confirmations` exist, `evm_adapter()`
/// assembles them or refuses, and `main.rs` registers the result.
///
/// What stays pinned is the part that still matters. A node given no bridge
/// configuration keeps refusing all eight chains rather than defaulting to
/// something, because there is nothing safe to default to: a zero address
/// binds every receipt leaf to no contract, and `test_default()` supplies
/// exactly that. Off remains the behaviour you get by not asking.
#[tokio::test]
async fn an_unconfigured_worker_refuses_every_external_chain() {
    let empty = AdapterRegistry::new();

    for chain in [
        ExternalChain::Ethereum,
        ExternalChain::Solana,
        ExternalChain::Bitcoin,
        ExternalChain::Avalanche,
        ExternalChain::Polygon,
        ExternalChain::Arbitrum,
        ExternalChain::Optimism,
        ExternalChain::Custom(99),
    ] {
        let err = RelayerWorker::build_verified_result(&empty, &relay_request(chain))
            .await
            .expect_err("an empty registry must refuse, never fabricate a result");
        assert!(
            matches!(err, AdapterError::UnsupportedChain(_)),
            "{chain:?} must be refused as unsupported, got {err:?}"
        );
    }

    // Production registers adapters only when told what to point at, and the
    // configuration it needs exists.
    let main_src = include_str!("../main.rs");
    assert!(
        main_src.contains("with_adapters"),
        "main.rs no longer registers adapters; outbound relay is off again and \
         the config plumbing below is unreachable"
    );

    let cli_src = include_str!("../cli/commands.rs");
    for flag in [
        "evm_bridge_address",
        "evm_deposit_topic0",
        "evm_confirmations",
    ] {
        assert!(
            cli_src.contains(flag),
            "{flag} is gone, so an operator cannot say what the adapter points \
             at and registering one would mean guessing"
        );
    }

    // The default is still off. A node that was not told a bridge address
    // must not acquire one.
    let default_config = crate::cli::commands::NodeConfig::default();
    assert!(
        default_config
            .evm_adapter()
            .expect("an unconfigured node is not a misconfigured one")
            .is_none(),
        "a node given no bridge configuration must build no adapter, not a \
         zero-address one that advertises Ethereum while pointing nowhere"
    );
}

/// A node configuration carrying exactly the bridge settings a test needs.
///
/// Built with struct-update syntax rather than `default()` followed by field
/// assignments: clippy refuses the latter, and it is right to, because a
/// half-assigned config is the same shape as the bug these tests are about.
fn config_with(
    bridge: Option<&str>,
    topic0: Option<&str>,
    confirmations: Option<u32>,
) -> crate::cli::commands::NodeConfig {
    crate::cli::commands::NodeConfig {
        evm_bridge_address: bridge.map(str::to_string),
        evm_deposit_topic0: topic0.map(str::to_string),
        evm_confirmations: confirmations,
        ..Default::default()
    }
}

fn bridge_address() -> String {
    "0x".to_string() + &"aa".repeat(20)
}

fn deposit_topic0() -> String {
    "0x".to_string() + &"bb".repeat(32)
}

/// Half a bridge configuration is refused, not completed by guessing.
///
/// A deposit log is matched on emitter address and topic0 together. Given one
/// without the other, the only way to proceed is to invent the missing half,
/// and both zero values are actively dangerous: a zero address binds every
/// receipt leaf to no contract, and a zero topic0 matches the first log the
/// contract ever emitted.
#[test]
fn a_half_configured_bridge_is_refused() {
    let err = config_with(Some(&bridge_address()), None, None)
        .evm_adapter()
        .expect_err("an address with no topic must be refused");
    assert!(
        err.contains("evm-deposit-topic0"),
        "the refusal must name the missing half, got: {err}"
    );

    let err = config_with(None, Some(&deposit_topic0()), None)
        .evm_adapter()
        .expect_err("a topic with no address must be refused");
    assert!(
        err.contains("evm-bridge-address"),
        "the refusal must name the missing half, got: {err}"
    );

    // Both together, and it builds.
    assert!(
        config_with(Some(&bridge_address()), Some(&deposit_topic0()), None)
            .evm_adapter()
            .expect("a complete configuration must build")
            .is_some(),
        "the refusal has to stay narrow, or it is a ban on bridging"
    );
}

/// Zero confirmations is refused at configuration time.
///
/// `check_fit_for_relay` already says why: a deposit from a block that can
/// still be reorged away would be minted against a transaction that did not
/// happen. This pins that the configuration path asks it, rather than
/// re-deriving the rule and drifting from it.
#[test]
fn zero_confirmations_cannot_be_configured() {
    let err = config_with(Some(&bridge_address()), Some(&deposit_topic0()), Some(0))
        .evm_adapter()
        .expect_err("zero confirmations must be refused before the registry");
    assert!(
        err.contains("confirmations"),
        "the refusal must say which setting is wrong, got: {err}"
    );

    assert!(
        config_with(Some(&bridge_address()), Some(&deposit_topic0()), Some(1))
            .evm_adapter()
            .is_ok(),
        "one confirmation is a policy choice, not a malformed configuration"
    );
}

/// A malformed address is refused rather than truncated or padded.
#[test]
fn a_bridge_address_of_the_wrong_length_is_refused() {
    // 19 bytes: one short of an Ethereum address.
    let short = "0x".to_string() + &"aa".repeat(19);
    let err = config_with(Some(&short), Some(&deposit_topic0()), None)
        .evm_adapter()
        .expect_err("a 19-byte address is not an Ethereum address");
    assert!(
        err.contains("20 bytes"),
        "the refusal must state the expected length, got: {err}"
    );

    assert!(
        config_with(Some("nothex"), Some(&deposit_topic0()), None)
            .evm_adapter()
            .is_err(),
        "a non-hex address must be refused, not silently decoded"
    );
}

/// Registering the EVM adapter cannot manufacture a successful relay.
///
/// This is the question the configuration flags raise. `with_adapters` was
/// unreachable, so the stubbed off-chain half of `EvmChainAdapter` was
/// unreachable too; now an operator can register it, and the stub is what
/// `build_verified_result` will call.
///
/// It must still refuse, and it now refuses one step earlier and for a
/// better reason. `generate_receipt_proof` used to return a placeholder
/// single-leaf tree that happened to fail the leaf binding; the refusal was
/// real but incidental, and the same stub passed the Merkle check itself
/// because a tree with no siblings verifies `leaf == root` (see
/// ARCHITECTURE.md section 69). The assembler now returns an error outright:
/// this adapter does not read Ethereum, so it cannot produce a receipt
/// proof. The worker submits nothing.
///
/// That is the property worth pinning: turning the bridge on gets a stalled
/// transfer, never a signed claim about an Ethereum transaction that was
/// never observed. If the stub is ever replaced with a real RPC client, this
/// test fails and whoever replaced it has to say what now makes the result
/// truthful.
#[tokio::test]
async fn a_configured_evm_adapter_still_refuses_its_own_stubbed_result() {
    use crate::cross_domain::evm::adapter::{EvmChainAdapter, DEFAULT_DEPOSIT_TOPIC0};

    let mut registry = AdapterRegistry::new();
    registry
        .register(Box::new(EvmChainAdapter::new(
            vec![0xaa; 20],
            DEFAULT_DEPOSIT_TOPIC0,
        )))
        .expect("a properly configured adapter must register");

    let err =
        RelayerWorker::build_verified_result(&registry, &relay_request(ExternalChain::Ethereum))
            .await
            .expect_err(
                "the off-chain half is still a stub; it must not produce a result the \
             adapter is willing to verify",
            );

    assert!(
        matches!(err, AdapterError::ProofVerificationFailed(_)),
        "the refusal must come from verification, not from the chain being \
         unsupported: got {err:?}"
    );

    // And the reason has to be the leaf binding, which is the check standing
    // between a stub and a signed claim.
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Merkle") || msg.contains("leaf") || msg.contains("forgery"),
        "the refusal must name the binding that failed, got: {msg}"
    );
}
