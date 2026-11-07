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

/// The ratchet file that records the coverage gaps  cannot close yet.
#[cfg(test)]
const COVERAGE_BASELINE_PATH: &str = ".github/rpc-method-coverage-baseline.txt";

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
    row("bud_dataMarketGetDataAssets", Public, Read),
    row("bud_dataMarketGetAccessGrants", Public, Read),
    row("bud_dataMarketGetSaleAuthorizations", Public, Read),
    row("bud_dataMarketGetPurchaseReceipts", Public, Read),
    row("bud_dataMarketBuildAiInputRef", Public, Read),
    row("bud_dataMarketPrepareSaleAuthorization", Public, TxSubmit),
    row("bud_dataMarketPreparePurchase", Public, TxSubmit),
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
    row("bud_getValidator", Public, Read),
    row("bud_storageGetObject", Public, Read),
    row("bud_storageGetCustody", Public, Read),
    row("bud_listRelays", Public, Read),
    row("bud_listGateways", Public, Read),
    row("bud_getDomainInfo", Public, Read),
    row("bud_getQuantumAlarm", Public, Read),
    row("bud_getSlashingHistory", Public, Read),
    row("bud_aiInferenceStats", Public, Read),
    row("bud_identityResolve", Public, Read),
    row("bud_identityCredential", Public, Read),
    row("bud_identityVerifyPresentation", Public, Read),
    row("bud_getCharter", Public, Read),
    row("bud_getAssetClass", Public, Read),
    row("bud_getAsset", Public, Read),
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
    use super::{check_served_methods, Effect, Listener, METHOD_CLASSES};
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

    /// no method may change consensus state outside block execution.
    ///
    /// The finding is that the public listener could change consensus state:
    /// an RPC call wrote a registry row, a finality view or a state root that
    /// the node's peers did not share, and the two nodes then disagreed about
    /// the tip without either of them having produced a block. The class table
    /// is the fix - `Effect` has no variant for such a write, and every writer
    /// that remains is either a signed transaction handed to the mempool
    /// (`TxSubmit`), a node-local action (`LocalAdmin`), a read (`Read`) or a
    /// refusal that names a transaction door (`Refused`).
    ///
    /// Canary: add an `Effect` variant that mutates consensus state directly,
    /// or classify a `bud_lockBridgeTransfer`-shaped name as `Read`, and the
    /// assertions here fail.
    #[test]
    fn no_effect_can_change_consensus_state_outside_a_block() {
        // The whole variant set, spelled out. A new variant is added here
        // first, and the comment on it must say which of the four legitimate
        // effects it is. There is deliberately no `StateWrite` to add.
        let legitimate_effects = [Effect::Read, Effect::TxSubmit, Effect::Refused, Effect::LocalAdmin];
        for effect in legitimate_effects {
            match effect {
                // Reads change nothing.
                Effect::Read => {}
                // A write reaches consensus only by being executed in a block.
                Effect::TxSubmit => {}
                // The call is refused and names the door that does the write.
                Effect::Refused => {}
                // Node-local state no peer has to agree on.
                Effect::LocalAdmin => {}
            }
        }
        // Every row's effect must be one the match above knows. The comparison
        // is by `Debug` name so the test names the offending class instead of
        // pointing at a line number.
        let known: Vec<String> = legitimate_effects
            .iter()
            .map(|effect| format!("{effect:?}"))
            .collect();
        for row in METHOD_CLASSES {
            let used = format!("{:?}", row.effect);
            assert!(
                known.contains(&used),
                "{} uses the effect {used}, which is outside the four legitimate ones",
                row.name
            );
        }
        // And each of the four is actually used, so the table is not
        // degenerate: a surface with no TxSubmit row would mean the mempool is
        // unreachable, and one with no Refused row would mean no writer was
        // moved to a door.
        for effect in legitimate_effects {
            let name = format!("{effect:?}");
            assert!(
                METHOD_CLASSES.iter().any(|row| format!("{:?}", row.effect) == name),
                "no row is classified as {name}"
            );
        }

        // Rows whose name says they write are `Refused`, `TxSubmit` or
        // `LocalAdmin` - never `Read`: a handler named `bud_lock*` that reads
        // would be a name that lies about its effect.
        const WRITE_VERBS: &[&str] = &[
            "bud_lock", "bud_mint", "bud_burn", "bud_unlock", "bud_register", "bud_submit",
            "bud_bond", "bud_slash", "bud_set", "bud_schedule",
        ];
        for row in METHOD_CLASSES {
            if WRITE_VERBS.iter().any(|verb| row.name.starts_with(verb)) {
                assert_ne!(
                    row.effect,
                    Effect::Read,
                    "{} names a write but is classified as a read",
                    row.name
                );
            }
        }
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

    /// The rows the coverage ratchet reads: the method name, and whether a
    /// success answer exists at all. A `Refused` row answers every call with a
    /// refusal, so it has no success test to have.
    fn coverage_targets() -> Vec<(&'static str, bool, bool)> {
        use super::Effect;
        METHOD_CLASSES
            .iter()
            .map(|row| {
                // A `Refused` row is asked for the refusal only: every call to
                // it is a refusal, so a success test would assert the row was
                // misclassified.
                let refused_row = row.effect == Effect::Refused;
                (row.name, !refused_row, wants_refusal(row.name))
            })
            .collect()
    }

    /// Whether a row is asked for a refusal test, which the trait declaration of
    /// `src/rpc/api.rs` decides. A method the trait declares with `&self` alone
    /// has no invalid call at this layer, so asking for a refusal test would ask
    /// for an invented one; the answer test is the whole requirement. A name the
    /// trait does not declare (a subscription, a method that arrives through an
    /// alias) is asked for both, because the rule cannot see its shape.
    fn wants_refusal(method: &str) -> bool {
        // `get_charter` is total over its `u32` domain id: every value is a
        // well-formed lookup and an absent charter answers `null`. There is
        // no invalid call at this layer to invent a refusal test for.
        if method == "bud_getCharter" {
            return false;
        }
        match declared_arguments(method) {
            Some(count) => count > 0,
            None => true,
        }
    }

    /// The number of parameters a method takes, as the trait declares them, with
    /// the receiver excluded. `None` says the declaration was not found.
    fn declared_arguments(method: &str) -> Option<usize> {
        let api = include_str!("api.rs");
        let marker = format!("#[method(name = \"{method}\")]");
        let at = api.find(&marker)? + marker.len();
        let rest = &api[at..];
        let fn_at = rest.find("fn ")? + 3;
        let open = rest[fn_at..].find('(')? + fn_at;
        let close = rest[open..].find(')')? + open;
        Some(
            rest[open + 1..close]
                .split(',')
                .map(str::trim)
                .filter(|param| !param.is_empty() && !param.starts_with('&') && *param != "self")
                .count(),
        )
    }

    /// The RPC behaviour corpus: the test functions that answer and refuse
    /// methods. Both files of the RPC test surface are read, so a coverage claim
    /// is a claim about a test a reader can open.
    fn coverage_corpus() -> Vec<(String, String)> {
        let mut files = vec![(
            "src/rpc/tests.rs".to_string(),
            include_str!("tests.rs").to_string(),
        )];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("src/tests is the second half of the coverage corpus")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".rs"))
            .collect();
        names.sort();
        for name in names {
            let shown = format!("src/tests/{name}");
            let text = std::fs::read_to_string(dir.join(&name))
                .unwrap_or_else(|e| panic!("{shown} is unreadable: {e}"));
            files.push((format!("src/tests/{name}"), text));
        }
        files
    }

    /// The `#[test]` and `#[tokio::test]` functions of one file: the name, and
    /// the text from the `fn` line to the brace that closes the function.
    fn test_functions(text: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let head = lines[i].trim();
            if head == "#[test]" || head == "#[tokio::test]" {
                let mut j = i + 1;
                while j < lines.len()
                    && !lines[j].trim().starts_with("fn ")
                    && !lines[j].trim().starts_with("async fn ")
                {
                    j += 1;
                }
                if j < lines.len() {
                    let decl = lines[j].trim();
                    let name: String = decl[decl.find("fn ").map_or(0, |at| at + 3)..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    let mut body = Vec::new();
                    let mut depth: i32 = 0;
                    let mut opened = false;
                    let mut k = j;
                    while k < lines.len() {
                        body.push(lines[k]);
                        for ch in lines[k].chars() {
                            match ch {
                                '{' => {
                                    depth += 1;
                                    opened = true;
                                }
                                '}' => depth -= 1,
                                _ => {}
                            }
                        }
                        if opened && depth <= 0 {
                            break;
                        }
                        k += 1;
                    }
                    out.push((name, body.join("\n")));
                    i = k + 1;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// `bud_estimateGas` to `estimate_gas`: the handler name a test calls.
    fn handler_name(method: &str) -> String {
        let tail = method.strip_prefix("bud_").unwrap_or(method);
        let mut out = String::with_capacity(tail.len() + 4);
        for ch in tail.chars() {
            if ch.is_ascii_uppercase() {
                if !out.is_empty() {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// The handler named by this method's trait declaration. RPC names and
    /// Rust handler names need not be generated from one another: the Data
    /// Market methods, for example, deliberately use `pollen_*` handlers.
    fn declared_handler(method: &str) -> Option<String> {
        let api = include_str!("api.rs");
        let marker = format!("#[method(name = \"{method}\")]");
        let rest = &api[api.find(&marker)? + marker.len()..];
        let declaration = &rest[rest.find("fn ")? + 3..];
        let name: String = declaration
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// Where a test names a method: the JSON-RPC name in quotes, which a
    /// dispatch test uses, or a call to either its derived or declared handler.
    fn mention_offsets(body: &str, method: &str) -> Vec<usize> {
        let quoted = format!("\"{method}\"");
        let mut handlers = vec![handler_name(method)];
        if let Some(declared) = declared_handler(method) {
            if !handlers.contains(&declared) {
                handlers.push(declared);
            }
        }
        let mut hits: Vec<usize> = body
            .match_indices(quoted.as_str())
            .chain(handlers.iter().flat_map(|handler| {
                body.match_indices(format!(".{handler}(").as_str())
            }))
            .map(|(at, _)| at)
            .collect();
        hits.sort_unstable();
        hits.dedup();
        hits
    }

    /// The statement that starts at `from`, to and including its next `;`. The
    /// 400 byte cap keeps a call in a loop head from swallowing the loop body,
    /// so a mark found here is a mark on this method's own answer.
    fn statement_at(body: &str, from: usize) -> &str {
        let bytes = body.as_bytes();
        let start = from.min(bytes.len());
        let limit = (start + 400).min(bytes.len());
        let mut end = limit;
        if let Some(at) = bytes[start..limit].iter().position(|b| *b == b';') {
            end = start + at + 1;
        }
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        &body[start..end]
    }

    /// What proves that a method was answered.
    const SUCCESS_MARKS: [&str; 3] = [".unwrap()", ".expect(", ".is_ok()"];
    /// What proves that a method refused a call.
    const REFUSAL_MARKS: [&str; 4] = [".is_err()", ".unwrap_err()", ".expect_err(", ".code()"];

    /// The rows whose required kind of test is missing, one
    /// `"<method> missing=<kind>"` line each, sorted so the output is stable.
    fn missing_coverage(
        targets: &[(&str, bool, bool)],
        tests: &[(String, String)],
    ) -> Vec<String> {
        let mut missing = Vec::new();
        for (name, needs_success, needs_refusal) in targets {
            let mut saw_success = false;
            let mut saw_refusal = false;
            for (_, body) in tests {
                for at in mention_offsets(body, name) {
                    let statement = statement_at(body, at);
                    saw_success |= SUCCESS_MARKS.iter().any(|mark| statement.contains(mark));
                    saw_refusal |= REFUSAL_MARKS.iter().any(|mark| statement.contains(mark));
                }
            }
            if *needs_refusal && !saw_refusal {
                missing.push(format!("{name} missing=refusal"));
            }
            if *needs_success && !saw_success {
                missing.push(format!("{name} missing=success"));
            }
        }
        missing.sort();
        missing
    }

    /// The recorded gaps, one line each. Comments and blanks are dropped.
    fn read_coverage_baseline() -> Vec<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_BASELINE_PATH);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)
            .collect()
    }

    /// . Every row of the table has a test that answers it and a test
    /// that refuses it, except a `Refused` row, which has no success answer to
    /// give. The gaps this delivery cannot close are recorded in the baseline
    /// file, and that file is a ratchet in the same shape as the concept-name
    /// counter: a row that gains its test must leave the file in the same change,
    /// so the only way to keep this green is to write tests.
    ///
    /// The rule is a coverage rule, not a proof. It reads whether a test calls
    /// the method and asserts on the answer; what each assertion establishes is
    /// the review of the test itself, and the directive's closure protocol
    /// (section 14.1 item 5) is where a finding is argued.
    #[test]
    fn rpc_every_method_has_success_and_refusal_test() {
        let corpus = coverage_corpus();
        let tests: Vec<(String, String)> = corpus
            .iter()
            .map(|(_, text)| text.as_str())
            .flat_map(test_functions)
            .collect();
        assert!(
            tests.len() > 400,
            "the corpus scan found {} test functions; it is reading the wrong text",
            tests.len()
        );
        let missing = missing_coverage(&coverage_targets(), &tests);
        let baseline = read_coverage_baseline();
        let missing_set: BTreeSet<&str> = missing.iter().map(String::as_str).collect();
        let baseline_set: BTreeSet<&str> = baseline.iter().map(String::as_str).collect();
        let path = COVERAGE_BASELINE_PATH;
        for line in &baseline {
            assert!(
                missing_set.contains(line.as_str()),
                "{line} is recorded as a gap but is covered now: delete the line from {path} \
                 in the same change"
            );
        }
        for line in &missing {
            assert!(
                !baseline_set.contains(line.as_str()),
                "{line} has neither a test nor a recorded gap: write the test, or record the \
                 gap in {path} with a reason"
            );
        }
    }

    /// The ratchet's own canary. A row that loses its refusal test is reported,
    /// a `Refused` row is not asked for a success test, and a mark sitting on a
    /// different statement covers nothing.
    #[test]
    fn rpc_method_coverage_catches_an_injected_gap() {
        let tests = vec![
            (
                "both_kinds".to_string(),
                "let ok = server.bns_resolve(name).await.unwrap();\n\
                 let bad = server.bns_resolve(bad_name).await.unwrap_err();"
                    .to_string(),
            ),
            (
                "success_only".to_string(),
                "let v = server.bns_resolve_full(n).await.unwrap();".to_string(),
            ),
            (
                "wrong_statement".to_string(),
                "let other = server.node_info().await.unwrap();\n\
                 let refused = server.bns_resolve_content(n).await;"
                    .to_string(),
            ),
        ];
        let targets = [
            ("bud_bnsResolve", true, true),
            ("bud_bnsResolveFull", true, true),
            ("bud_bnsResolveContent", true, true),
            ("bud_registerBridgeAsset", false, true),
            // The shape a `Read` row with no argument takes: the answer test is
            // required, the refusal test is not, and a missing answer is still
            // reported.
            ("bud_gasPrice", true, false),
        ];
        assert!(
            !mention_offsets(
                "server.pollen_get_data_assets().await.unwrap();",
                "bud_dataMarketGetDataAssets"
            )
            .is_empty(),
            "the trait's declared alias handler must count"
        );
        assert_eq!(
            missing_coverage(&targets, &tests),
            vec![
                "bud_bnsResolveContent missing=refusal".to_string(),
                "bud_bnsResolveContent missing=success".to_string(),
                "bud_bnsResolveFull missing=refusal".to_string(),
                "bud_gasPrice missing=success".to_string(),
                "bud_registerBridgeAsset missing=refusal".to_string(),
            ]
        );
    }
}
