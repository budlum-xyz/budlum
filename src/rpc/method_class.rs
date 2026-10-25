//! The class of every JSON-RPC method.
//!
//! Each method answers two questions, and the answers live in one table so a
//! reader (and a test) can see the whole surface at once instead of
//! reconstructing it from 156 handler bodies:
//!
//! * **Listener.** Which listener serves it. `Operator` methods call
//!   `require_operator` and are refused on the public listener; every other
//!   method is `Public`. The test below holds the table and the handlers to
//!   the same answer.
//! * **Effect.** What a successful call does to state. The only acceptable
//!   effects are a read, a signed transaction handed to the mempool (or an
//!   unsigned one prepared for the caller to sign), and node-local work that
//!   no other node has to agree on. `ConsensusWrite` is the fourth: a method
//!   that changes consensus state outside block execution. That is forbidden
//!   (the node that serves the call computes a state, a finality view or a
//!   registry its peers do not share). Every row still marked
//!   `ConsensusWrite` is an open finding in
//!   `docs/audit/testnet/FINDINGS.md` (B-02 and the rows after it), and the
//!   test pins the set so it can shrink and cannot grow.
//!
//! `RpcServer::run` checks at startup that the methods it registers are
//! exactly the rows of this table, so a new method cannot be served before
//! it is classified. A public listener that runs without an API key refuses
//! to start while any public row is a `ConsensusWrite`: an unauthenticated
//! network caller must not be able to change one node's consensus state.

use Effect::{ConsensusWrite, LocalAdmin, Read, Refused, TxSubmit};
use Listener::{Operator, Public};

/// Which listener serves a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listener {
    /// Served on the public listener (and the operator listener).
    Public,
    /// Refused on the public listener: the handler calls `require_operator`.
    Operator,
}

/// What a successful call does to state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Reads state, or computes from its arguments. Changes nothing.
    Read,
    /// Hands a signed transaction to the mempool, or returns an unsigned
    /// transaction template for the caller to sign. State changes only when
    /// a block carries the transaction.
    TxSubmit,
    /// Changes node-local state that is not consensus state: peer bans,
    /// pruning of this node's own history, reveal sessions.
    LocalAdmin,
    /// Changes consensus state outside block execution. Forbidden; each row
    /// is an open finding until it becomes a transaction door.
    ConsensusWrite,
    /// The method exists and refuses every call, saying which door to use.
    Refused,
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MethodClass {
    name: &'static str,
    listener: Listener,
    effect: Effect,
}

const fn row(name: &'static str, listener: Listener, effect: Effect) -> MethodClass {
    MethodClass {
        name,
        listener,
        effect,
    }
}

/// Every method `src/rpc/api.rs` declares, in declaration order.
const METHOD_CLASSES: &[MethodClass] = &[
    row("bud_chainId", Public, Read),
    row("bud_blockNumber", Public, Read),
    row("bud_getBlockByNumber", Public, Read),
    row("bud_getBlockByHash", Public, Read),
    row("bud_getBalance", Public, Read),
    row("bud_getNonce", Public, Read),
    row("bud_getAccountProof", Public, Read),
    row("bud_sendRawTransaction", Public, TxSubmit),
    row("bud_getTransactionByHash", Public, Read),
    row("bud_getTransactionReceipt", Public, Read),
    row("bud_gasPrice", Public, Read),
    row("bud_estimateGas", Public, Read),
    row("bud_txPrecheck", Public, Read),
    row("bud_syncing", Public, Read),
    row("bud_netVersion", Public, Read),
    row("bud_netListening", Public, Read),
    row("bud_netPeerCount", Public, Read),
    row("bud_getSettlementInfo", Public, Read),
    row("bud_getGlobalHeader", Public, Read),
    row("bud_getDomainCommitments", Public, Read),
    row("bud_getConsensusDomains", Public, Read),
    // B-03: refused outside block execution; the in-block entry has no door.
    row("bud_registerExternalDomain", Operator, Refused),
    // B-02: writes `external_intake` (refusal counters included).
    row("bud_submitExternalEvidence", Operator, ConsensusWrite),
    row("bud_getExternalDomainProfile", Public, Read),
    row("bud_getExternalDomains", Public, Read),
    row("bud_getExternalIntakeDigest", Public, Read),
    // B-02: writes the external registry's admission record.
    row("bud_readmitExternalDomain", Operator, ConsensusWrite),
    // B-02: writes the external domain's version policy.
    row("bud_scheduleExternalFork", Operator, ConsensusWrite),
    // B-03: refused outside block execution.
    row("bud_slashExternalProver", Operator, Refused),
    // B-03: refused outside block execution.
    row("bud_bondExternalProver", Operator, Refused),
    // B-02: writes the external domain's quorum policy.
    row("bud_setExternalQuorumPolicy", Operator, ConsensusWrite),
    row("bud_getExternalQuorumRound", Public, Read),
    row("bud_getExternalQuorumRounds", Public, Read),
    row("bud_encodeExternalEvidence", Public, Read),
    row("bud_getExternalDomainStatus", Public, Read),
    row("bud_replayExternalProbes", Public, Read),
    row("bud_inspectEthereumUpdate", Public, Read),
    row("bud_planEvmVerification", Public, Read),
    // B-02: writes the consensus domain registry.
    row("bud_registerConsensusDomain", Operator, ConsensusWrite),
    // B-02: writes the sovereign template registry.
    row("bud_registerSovereignTemplate", Operator, ConsensusWrite),
    row("bud_validateSovereignAuditExport", Public, Read),
    row("bud_submitDomainCommitment", Public, Refused),
    // B-02: writes the domain registry and `external_roots`, then gossips.
    row(
        "bud_submitVerifiedDomainCommitment",
        Operator,
        ConsensusWrite,
    ),
    // N-12: refused; a relayed message is a `RelayCrossDomainMessage`
    // transaction now.
    row("bud_submitCrossDomainMessage", Public, Refused),
    // B-02: writes `bridge_state`.
    row("bud_registerBridgeAsset", Operator, ConsensusWrite),
    // B-02: writes `bridge_state` and balances.
    row("bud_mintBridgeTransfer", Operator, ConsensusWrite),
    row("bud_burnBridgeTransfer", Operator, Refused),
    // B-02: writes `bridge_state` and `message_registry`.
    row("bud_burnBridgeTransferWithEvent", Operator, ConsensusWrite),
    row("bud_unlockBridgeTransfer", Operator, Refused),
    // B-02: writes `bridge_state` and balances.
    row("bud_unlockBridgeTransferVerified", Operator, ConsensusWrite),
    // B-02: writes the relayer ledger, `bridge_state` and balances.
    row("bud_submitRelayProof", Operator, ConsensusWrite),
    // B-01: appends to the node-local global header sequence.
    row("bud_sealGlobalHeader", Operator, ConsensusWrite),
    row("bud_registryRegister", Public, TxSubmit),
    // WP-1: refused; a role bond is a `RoleBond` transaction now.
    row("bud_registryBondRelayer", Operator, Refused),
    row("bud_registryBondProver", Operator, Refused),
    // WP-1: refused; the exits are `RoleUnbond` and `RoleWithdraw`.
    row("bud_registryBeginRoleBondUnbonding", Operator, Refused),
    row("bud_registryWithdrawRoleBond", Operator, Refused),
    // B-02: writes the proof claim book.
    row("bud_submitZkProof", Operator, ConsensusWrite),
    row("bud_registryQuery", Public, Read),
    row("bud_registryActiveMembers", Public, Read),
    // The RPC marks every report `Unverified`, and unverified reports are
    // refused before any fee is charged.
    row("bud_submitSlashingReport", Public, Refused),
    // Both proof kinds refuse in `QcFaultProof::verify_against_blob` (a
    // signature that fails is not evidence, and the ZK verifier is not
    // integrated), so the finality invalidation behind it is unreachable.
    row("bud_submitQcFaultProof", Public, Refused),
    row("bud_health", Public, Read),
    row("bud_nodeInfo", Public, Read),
    row("bud_adminBanPeer", Operator, LocalAdmin),
    row("bud_adminUnbanPeer", Operator, LocalAdmin),
    row("bud_adminListBannedPeers", Operator, Read),
    // B-02: writes the storage registry (state-root bearing).
    row("bud_storageRegisterManifest", Operator, ConsensusWrite),
    row("bud_storageVerifyEncoding", Public, Read),
    row("bud_storageQrFeedPreview", Public, Read),
    row("bud_storageQrFeedFrames", Public, Read),
    // Refused on every chain until grants ride a block transaction (P30-F01).
    row("bud_storageIssueViewGrant", Public, Refused),
    row("bud_storageRevokeViewGrant", Public, Refused),
    row("bud_storageSocialDelete", Public, Refused),
    row("bud_storageListViewGrants", Public, Read),
    row("bud_storageMayView", Public, Read),
    row("bud_storageOpenReveal", Public, LocalAdmin),
    row("bud_storageRevealFrames", Public, LocalAdmin),
    row("bud_storageCloseReveal", Public, LocalAdmin),
    row("bud_storageRegisterConfidentialCommit", Operator, Refused),
    row("bud_storageGetConfidentialCommit", Public, Read),
    // B-02: opens a deal and moves escrow outside a block.
    row("bud_storageOpenDeal", Operator, ConsensusWrite),
    // B-02: reallocates a deal and moves escrow outside a block.
    row("bud_storageAcceptReallocation", Operator, ConsensusWrite),
    row("bud_storageGetManifest", Public, Read),
    row("bud_storageGetDealsByManifest", Public, Read),
    row("bud_storageGetDealsByShard", Public, Read),
    // B-02: opens a challenge and debits the opener bond outside a block.
    row("bud_storageOpenChallenge", Operator, ConsensusWrite),
    // B-02: settles a challenge (and its slash) outside a block.
    row("bud_storageAnswerChallenge", Operator, ConsensusWrite),
    row("bud_storageGetEconomicsSummary", Public, Read),
    row("bud_storageGetEconomicsEvents", Public, Read),
    row("bud_storageGetOperatorEconomics", Public, Read),
    row("bud_storageGetOutcome", Public, Read),
    row("bud_storageRepairBand", Public, Read),
    row("bud_storageActiveOperators", Public, Read),
    row("bud_bnsResolve", Public, Read),
    row("bud_bnsResolveFull", Public, Read),
    row("bud_bnsResolveContent", Public, Read),
    row("bud_bnsResolveSubdomain", Public, Read),
    row("bud_bnsPrepareRegister", Public, TxSubmit),
    row("bud_bnsPrepareRegisterSubdomain", Public, TxSubmit),
    row("bud_bnsPrepareSetContent", Public, TxSubmit),
    row("bud_socialGetPost", Public, Read),
    row("bud_socialGetProfile", Public, Read),
    row("bud_socialGetFeed", Public, Read),
    row("bud_socialPreparePost", Public, TxSubmit),
    row("bud_gatewayFetchContent", Public, Read),
    row("bud_gatewayRenderContent", Public, Read),
    row("bud_passportGetProfile", Public, Read),
    row("bud_passportGetProofBundle", Public, Read),
    row("bud_atlasGetWalletContext", Public, Read),
    row("bud_socialPrepareBurn", Public, TxSubmit),
    row("bud_socialPrepareBoost", Public, TxSubmit),
    row("bud_marketGetOffers", Public, Read),
    row("bud_marketPrepareOffer", Public, TxSubmit),
    row("bud_marketPreparePurchase", Public, TxSubmit),
    row("bud_pollenGetDataAssets", Public, Read),
    row("bud_pollenGetAccessGrants", Public, Read),
    row("bud_pollenGetSaleAuthorizations", Public, Read),
    row("bud_pollenGetPurchaseReceipts", Public, Read),
    row("bud_pollenBuildAiInputRef", Public, Read),
    row("bud_pollenPrepareSaleAuthorization", Public, TxSubmit),
    row("bud_pollenPreparePurchase", Public, TxSubmit),
    row("bud_hubGetApps", Public, Read),
    row("bud_hubPrepareRegister", Public, TxSubmit),
    row("bud_relayerPrepareExternalTx", Public, TxSubmit),
    row("bud_pruneStatus", Public, Read),
    row("bud_requestPrune", Operator, LocalAdmin),
    row("bud_aiGetModel", Public, Read),
    row("bud_aiRegisterModel", Public, TxSubmit),
    row("bud_aiSubmitRequest", Public, TxSubmit),
    row("bud_aiSubmitResult", Public, TxSubmit),
    row("bud_aiGetOutcome", Public, Read),
    row("bud_aiGetActiveVerifiers", Public, Read),
    row("bud_aiReclaimFee", Public, Read),
    row("bud_aiEquivocationStatus", Public, Read),
    row("bud_aiCancelStatus", Public, Read),
    row("bud_aiDisputeSlash", Public, TxSubmit),
    row("bud_aiSlashingStatus", Public, Read),
    row("bud_aiVerifierStake", Public, Read),
    row("bud_aiCallbackQueue", Public, Read),
    row("bud_aiExecutionProof", Public, Read),
    row("bud_aiVerifierQos", Public, Read),
    row("bud_aiVerifierRanking", Public, Read),
    row("bud_aiAgentPayment", Public, Read),
    row("bud_aiAgentPayments", Public, Read),
    row("bud_aiVerifierWhitelist", Public, Read),
    row("bud_aiAgentReputation", Public, Read),
    row("bud_aiAgentRanking", Public, Read),
    row("bud_getStatus", Public, Read),
    row("bud_getValidatorSet", Public, Read),
    row("bud_getDomainInfo", Public, Read),
    row("bud_getSlashingHistory", Public, Read),
    row("bud_aiInferenceStats", Public, Read),
    row("bud_identityResolve", Public, Read),
    row("bud_identityCredential", Public, Read),
    row("bud_identityVerifyPresentation", Public, Read),
];

/// Public methods that still write consensus state outside a block.
fn public_consensus_writes() -> impl Iterator<Item = &'static MethodClass> {
    METHOD_CLASSES
        .iter()
        .filter(|row| row.listener == Listener::Public && row.effect == Effect::ConsensusWrite)
}

/// Check that the methods a server registers are exactly the classified
/// ones, and that a keyless public listener exposes no consensus write.
///
/// # Errors
///
/// Names every registered method without a row, every row without a
/// registered method, and, when `keyless_public` is set, every public row
/// that is a `ConsensusWrite`.
pub fn check_served_methods<'a>(
    registered: impl IntoIterator<Item = &'a str>,
    keyless_public: bool,
) -> Result<(), String> {
    let registered: std::collections::BTreeSet<&str> = registered.into_iter().collect();
    let classified: std::collections::BTreeSet<&str> =
        METHOD_CLASSES.iter().map(|row| row.name).collect();
    let mut problems = Vec::new();
    for name in registered.difference(&classified) {
        problems.push(format!("{name} is served but has no row in METHOD_CLASSES"));
    }
    for name in classified.difference(&registered) {
        problems.push(format!(
            "{name} has a row in METHOD_CLASSES but is not served"
        ));
    }
    if keyless_public {
        for row in public_consensus_writes() {
            problems.push(format!(
                "{} writes consensus state outside a block and would be reachable without an \
                 API key on the public listener",
                row.name
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{check_served_methods, public_consensus_writes, Effect, Listener, METHOD_CLASSES};
    use std::collections::BTreeSet;

    /// The method names `api.rs` declares, read from its source.
    fn declared_methods() -> Vec<String> {
        let api = include_str!("api.rs");
        let needle = "#[method(name = \"";
        api.match_indices(needle)
            .map(|(at, _)| {
                let rest = &api[at + needle.len()..];
                rest[..rest.find('"').expect("closing quote")].to_string()
            })
            .collect()
    }

    /// The method names whose handlers call `require_operator`, read from
    /// the production part of `server.rs` (cut at its first test module,
    /// comment lines dropped).
    fn operator_gated_methods() -> BTreeSet<String> {
        let src = include_str!("server.rs");
        let cut = src.find("#[cfg(test)]").unwrap_or(src.len());
        assert!(
            cut * 2 > src.len(),
            "the production slice of server.rs is {cut} of {} bytes; the cut is wrong",
            src.len()
        );
        let code: String = src[..cut]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let needle = "self.require_operator(\"";
        code.match_indices(needle)
            .map(|(at, _)| {
                let rest = &code[at + needle.len()..];
                rest[..rest.find('"').expect("closing quote")].to_string()
            })
            .collect()
    }

    #[test]
    fn every_declared_method_has_exactly_one_row() {
        let declared = declared_methods();
        assert!(
            declared.len() > 100,
            "the scan found {} methods in api.rs; it is reading the wrong text",
            declared.len()
        );
        let rows: Vec<&str> = METHOD_CLASSES.iter().map(|row| row.name).collect();
        let unique: BTreeSet<&str> = rows.iter().copied().collect();
        assert_eq!(unique.len(), rows.len(), "a method has two rows");
        let declared_set: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
        assert_eq!(
            declared_set, unique,
            "the table and api.rs disagree on which methods exist"
        );
        // Declaration order, so a reader can walk both files side by side.
        assert_eq!(declared, rows, "rows are not in api.rs declaration order");
    }

    #[test]
    fn the_listener_column_matches_the_handlers() {
        let gated = operator_gated_methods();
        assert!(
            gated.len() > 10,
            "the scan found {} operator gates; it is reading the wrong text",
            gated.len()
        );
        let marked: BTreeSet<String> = METHOD_CLASSES
            .iter()
            .filter(|row| row.listener == Listener::Operator)
            .map(|row| row.name.to_string())
            .collect();
        assert_eq!(
            gated, marked,
            "a handler calls require_operator without an Operator row, or the reverse"
        );
    }

    /// The open consensus writes, with the finding that tracks each. The set
    /// may only shrink: a method that becomes a transaction door changes its
    /// row and leaves this list in the same change, and a new consensus
    /// write cannot be added without adding it here in review.
    const OPEN_CONSENSUS_WRITES: &[(&str, &str)] = &[
        ("bud_submitExternalEvidence", "B-02"),
        ("bud_readmitExternalDomain", "B-02"),
        ("bud_scheduleExternalFork", "B-02"),
        ("bud_setExternalQuorumPolicy", "B-02"),
        ("bud_registerConsensusDomain", "B-02"),
        ("bud_registerSovereignTemplate", "B-02"),
        ("bud_submitVerifiedDomainCommitment", "B-02"),
        ("bud_registerBridgeAsset", "B-02"),
        ("bud_mintBridgeTransfer", "B-02"),
        ("bud_burnBridgeTransferWithEvent", "B-02"),
        ("bud_unlockBridgeTransferVerified", "B-02"),
        ("bud_submitRelayProof", "B-02"),
        ("bud_sealGlobalHeader", "B-01"),
        ("bud_submitZkProof", "B-02"),
        ("bud_storageRegisterManifest", "B-02"),
        ("bud_storageOpenDeal", "B-02"),
        ("bud_storageAcceptReallocation", "B-02"),
        ("bud_storageOpenChallenge", "B-02"),
        ("bud_storageAnswerChallenge", "B-02"),
    ];

    #[test]
    fn the_open_consensus_writes_are_exactly_the_pinned_list() {
        let open: BTreeSet<&str> = METHOD_CLASSES
            .iter()
            .filter(|row| row.effect == Effect::ConsensusWrite)
            .map(|row| row.name)
            .collect();
        let pinned: BTreeSet<&str> = OPEN_CONSENSUS_WRITES.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            open, pinned,
            "the ConsensusWrite rows and the pinned list disagree: a fixed method must leave \
             the list, and a new consensus write is not accepted"
        );
    }

    #[test]
    fn the_startup_check_refuses_a_gap_in_either_direction() {
        let all: Vec<&str> = METHOD_CLASSES.iter().map(|row| row.name).collect();
        assert!(check_served_methods(all.iter().copied(), false).is_ok());

        let mut extra = all.clone();
        extra.push("bud_unclassified");
        let err = check_served_methods(extra, false).unwrap_err();
        assert!(err.contains("bud_unclassified is served but has no row"));

        let missing = &all[1..];
        let err = check_served_methods(missing.iter().copied(), false).unwrap_err();
        assert!(err.contains(&format!("{} has a row", all[0])));
    }

    #[test]
    fn a_keyless_public_listener_refuses_while_a_public_consensus_write_exists() {
        let all: Vec<&str> = METHOD_CLASSES.iter().map(|row| row.name).collect();
        let public_writes: Vec<&str> = public_consensus_writes().map(|r| r.name).collect();
        let outcome = check_served_methods(all.iter().copied(), true);
        if public_writes.is_empty() {
            assert!(outcome.is_ok());
        } else {
            let err = outcome.unwrap_err();
            for name in public_writes {
                assert!(err.contains(name), "{name} missing from: {err}");
            }
        }
    }

    /// Today no public method writes consensus state, so a keyless public
    /// listener is allowed to start. A new public consensus write would
    /// have to pass the pinned list above first.
    #[test]
    fn no_public_method_writes_consensus_state() {
        let public_writes: Vec<&str> = public_consensus_writes().map(|r| r.name).collect();
        assert!(public_writes.is_empty(), "{public_writes:?}");
        let send = METHOD_CLASSES
            .iter()
            .find(|row| row.name == "bud_sendRawTransaction")
            .expect("a known method");
        assert_eq!(send.listener, Listener::Public);
        assert_eq!(send.effect, Effect::TxSubmit);
    }
}
