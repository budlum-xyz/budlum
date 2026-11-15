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
//!   no other node has to agree on, or a refusal that names the door. A
//!   method that changes consensus state outside block execution has no
//!   class: the node that served it would hold a state, a finality view or a
//!   registry its peers do not share. The last such
//!   rows became transaction doors or in-block work in and, and the
//!   class was removed with them, so a new one cannot be classified at all.
//!
//! `RpcServer::run` checks at startup that the methods it registers are
//! exactly the rows of this table, so a new method cannot be served before
//! it is classified.

use Effect::{LocalAdmin, Read, Refused, TxSubmit};
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
    // A bundle is one composite witness over several V7 bodies: it is the
    // same door as `bud_sendRawTransaction`, admitting members instead of one
    // transaction, and it changes state only when a block carries them.
    row("bud_sendTxBundle", Public, TxSubmit),
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
    row("bud_getGlobalHeaderProof", Public, Read),
    row("bud_getDomainCommitments", Public, Read),
    row("bud_getConsensusDomains", Public, Read),
    row("bud_getGraftApplication", Public, Read),
    row("bud_getRestakedValidators", Public, Read),
    row("bud_graftPaymentProof", Public, Read),
    // /: refused; the door is `ExternalDomainTx::Register`.
    row("bud_registerExternalDomain", Operator, Refused),
    // refused; the door is `ExternalDomainTx::SubmitEvidence`.
    row("bud_submitExternalEvidence", Operator, Refused),
    row("bud_getExternalDomainProfile", Public, Read),
    row("bud_getExternalDomains", Public, Read),
    row("bud_getExternalIntakeDigest", Public, Read),
    // refused; the doors are `ExternalDomainTx::Readmit` and
    // `ExternalDomainTx::ScheduleFork`.
    row("bud_readmitExternalDomain", Operator, Refused),
    row("bud_scheduleExternalFork", Operator, Refused),
    // Closed: no proof that an attestation was false is defined yet.
    row("bud_slashExternalProver", Operator, Refused),
    // refused; the doors are `ExternalDomainTx::BondProver` and
    // `ExternalDomainTx::SetQuorumPolicy`.
    row("bud_bondExternalProver", Operator, Refused),
    row("bud_setExternalQuorumPolicy", Operator, Refused),
    row("bud_getExternalQuorumRound", Public, Read),
    row("bud_getExternalQuorumRounds", Public, Read),
    row("bud_encodeExternalEvidence", Public, Read),
    row("bud_getExternalDomainStatus", Public, Read),
    row("bud_replayExternalProbes", Public, Read),
    row("bud_inspectEthereumUpdate", Public, Read),
    row("bud_planEvmVerification", Public, Read),
    // /: refused; the doors are `SettlementTx::RegisterDomain` and
    // `SettlementTx::RegisterSovereignTemplate`.
    row("bud_registerConsensusDomain", Operator, Refused),
    row("bud_registerSovereignTemplate", Operator, Refused),
    row("bud_getSovereignTemplate", Public, Read),
    row("bud_validateSovereignAuditExport", Public, Read),
    row("bud_submitDomainCommitment", Public, Refused),
    // /: refused; the door is `SettlementTx::SubmitCommitment`.
    row("bud_submitVerifiedDomainCommitment", Operator, Refused),
    // refused; a relayed message is a `RelayCrossDomainMessage`
    // transaction now.
    row("bud_submitCrossDomainMessage", Public, Refused),
    row("bud_getCrossDomainMessage", Public, Read),
    row("bud_getBridgeTransfer", Public, Read),
    row("bud_getRelayerStatus", Public, Read),
    row("bud_getRelayerIntent", Public, Read),
    // /: refused; the doors are the `BridgeTx` variants
    // (`RegisterAsset`, `Mint`, `BurnWithEvent`, `Unlock`, `RelayProof`).
    row("bud_registerBridgeAsset", Operator, Refused),
    row("bud_mintBridgeTransfer", Operator, Refused),
    row("bud_burnBridgeTransfer", Operator, Refused),
    row("bud_burnBridgeTransferWithEvent", Operator, Refused),
    row("bud_unlockBridgeTransfer", Operator, Refused),
    row("bud_unlockBridgeTransferVerified", Operator, Refused),
    row("bud_submitRelayProof", Operator, Refused),
    // /: refused; headers are built in block at every checkpoint.
    row("bud_sealGlobalHeader", Operator, Refused),
    row("bud_registryRegister", Public, TxSubmit),
    // refused; a role bond is a `RoleBond` transaction now.
    row("bud_registryBondRelayer", Operator, Refused),
    row("bud_registryBondProver", Operator, Refused),
    // refused; the exits are `RoleUnbond` and `RoleWithdraw`.
    row("bud_registryBeginRoleBondUnbonding", Operator, Refused),
    row("bud_registryWithdrawRoleBond", Operator, Refused),
    // /: refused; the door is `SettlementTx::SubmitZkProof`.
    row("bud_submitZkProof", Operator, Refused),
    row("bud_registryQuery", Public, Read),
    row("bud_registryActiveMembers", Public, Read),
    row("bud_validatorProfile", Public, Read),
    row("bud_validatorList", Public, Read),
    row("bud_getValidatorDelegations", Public, Read),
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
    // refused; manifest registration is `StorageTx::RegisterManifest`.
    row("bud_storageRegisterManifest", Operator, Refused),
    row("bud_storageVerifyEncoding", Public, Read),
    row("bud_storageQrFeedPreview", Public, Read),
    row("bud_storageQrFeedFrames", Public, Read),
    // Refused on every chain until grants ride a block transaction.
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
    // refused; the doors are `StorageTx::OpenDeal` and
    // `StorageTx::AcceptReallocation`.
    row("bud_storageOpenDeal", Operator, Refused),
    row("bud_storageAcceptReallocation", Operator, Refused),
    row("bud_storageGetManifest", Public, Read),
    row("bud_storageGetDealsByManifest", Public, Read),
    row("bud_storageGetDealsByShard", Public, Read),
    row("bud_storageGetChallenges", Public, Read),
    // refused; the doors are `StorageTx::OpenChallenge` and
    // `StorageTx::AnswerChallenge`.
    row("bud_storageOpenChallenge", Operator, Refused),
    row("bud_storageAnswerChallenge", Operator, Refused),
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
    row("bud_bnsPrepareRenew", Public, TxSubmit),
    row("bud_bnsPrepareTransfer", Public, TxSubmit),
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
    row("bud_hubGetGraftApps", Public, Read),
    row("bud_hubPrepareRegister", Public, TxSubmit),
    row("bud_relayerPrepareExternalTx", Public, TxSubmit),
    row("bud_pruneStatus", Public, Read),
    row("bud_getStateSnapshot", Operator, Read),
    row("bud_requestPrune", Operator, LocalAdmin),
    row("bud_aiGetModel", Public, Read),
    row("bud_aiRegisterModel", Public, TxSubmit),
    row("bud_aiSubmitRequest", Public, TxSubmit),
    row("bud_aiSubmitResult", Public, TxSubmit),
    row("bud_aiOpenRequests", Public, Read),
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
    row("bud_getQuantumAlarm", Public, Read),
    row("bud_getSlashingHistory", Public, Read),
    row("bud_aiInferenceStats", Public, Read),
    row("bud_identityResolve", Public, Read),
    row("bud_identityCredential", Public, Read),
    row("bud_identityVerifyPresentation", Public, Read),
    // WebSocket subscriptions: read-only feeds (src/rpc/subscriptions.rs).
    row("bud_subscribe", Public, Read),
    row("bud_unsubscribe", Public, Read),
];

/// Check that the methods a server registers are exactly the classified
/// ones.
///
/// # Errors
///
/// Names every registered method without a row and every row without a
/// registered method.
pub fn check_served_methods<'a>(
    registered: impl IntoIterator<Item = &'a str>,
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
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::{check_served_methods, Listener, METHOD_CLASSES};
    use std::collections::BTreeSet;

    /// The method names `api.rs` declares, read from its source: each
    /// `#[method]`, and each `#[subscription]` with its unsubscribe method.
    fn declared_methods() -> Vec<String> {
        let api = include_str!("api.rs");
        let mut found: Vec<(usize, String)> = Vec::new();
        for needle in [
            "#[method(name = \"",
            "#[subscription(name = \"",
            "unsubscribe = \"",
        ] {
            for (at, _) in api.match_indices(needle) {
                let rest = &api[at + needle.len()..];
                found.push((
                    at,
                    rest[..rest.find('"').expect("closing quote")].to_string(),
                ));
            }
        }
        found.sort();
        found.into_iter().map(|(_, name)| name).collect()
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

    #[test]
    fn the_startup_check_refuses_a_gap_in_either_direction() {
        let all: Vec<&str> = METHOD_CLASSES.iter().map(|row| row.name).collect();
        assert!(check_served_methods(all.iter().copied()).is_ok());

        let mut extra = all.clone();
        extra.push("bud_unclassified");
        let err = check_served_methods(extra).unwrap_err();
        assert!(err.contains("bud_unclassified is served but has no row"));

        let missing = &all[1..];
        let err = check_served_methods(missing.iter().copied()).unwrap_err();
        assert!(err.contains(&format!("{} has a row", all[0])));
    }
}
