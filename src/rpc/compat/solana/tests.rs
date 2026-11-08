//! Locks the Solana wire names, class table and native refusal doors together.
use super::{
    check_served, ee_unavailable, faucet_unavailable, is_unsubscribe, native_door, not_exposed,
    owns_method, SOLANA_METHOD_CLASSES,
};
use crate::rpc::compat::CompatEffect;

const EXPECTED: &[&str] = &[
    "getHealth", "getVersion", "getGenesisHash", "getSlot",
    "getBlockHeight", "getEpochInfo", "getLatestBlockhash", "isBlockhashValid",
    "getBalance", "getAccountInfo", "getMultipleAccounts", "getProgramAccounts",
    "getTokenAccountsByOwner", "getTokenAccountBalance", "getTokenSupply", "getMinimumBalanceForRentExemption",
    "getFeeForMessage", "getRecentPrioritizationFees", "sendTransaction", "simulateTransaction",
    "getSignatureStatuses", "getSignaturesForAddress", "getTransaction", "getBlock",
    "requestAirdrop", "accountSubscribe", "accountUnsubscribe", "signatureSubscribe",
    "signatureUnsubscribe", "slotSubscribe", "slotUnsubscribe", "logsSubscribe",
    "logsUnsubscribe", "programSubscribe", "programUnsubscribe",
];

fn declared_names() -> Vec<String> {
    let api = include_str!("../../api.rs");
    let mut names = Vec::new();
    for needle in ["#[method(name = \"", "#[subscription(name = \"", "unsubscribe = \""] {
        for (at, _) in api.match_indices(needle) {
            let rest = &api[at + needle.len()..];
            names.push(rest[..rest.find('"').expect("wire name closes")].to_string());
        }
    }
    names
}

fn class_rows() -> Vec<(String, String, String)> {
    let source = include_str!("../../method_class.rs");
    let start = source.find("const METHOD_CLASSES").expect("class table");
    let source = &source[start..];
    let cut = source.find("#[cfg(test)]").unwrap_or(source.len());
    let source = &source[..cut];
    let mut rows = Vec::new();
    for (at, _) in source.match_indices("row(\"") {
        let rest = &source[at + 5..];
        let name = &rest[..rest.find('"').expect("class name closes")];
        let inner = &rest[name.len() + 1..];
        let inner = &inner[..inner.find(')').expect("class row closes")];
        let mut parts = inner.split(',').map(str::trim).filter(|part| !part.is_empty());
        rows.push((name.to_string(), parts.next().unwrap().to_string(), parts.next().unwrap().to_string()));
    }
    rows
}

#[test]
fn solana_method_table_is_exact_and_declared() {
    let actual: Vec<&str> = SOLANA_METHOD_CLASSES.iter().map(|row| row.name).collect();
    assert_eq!(actual, EXPECTED);
    let declared = declared_names();
    for name in EXPECTED { assert!(declared.iter().any(|candidate| candidate == name), "{name} is not declared"); }
}

#[test]
fn solana_class_rows_match_the_compat_table() {
    let rows = class_rows();
    let mut previous = None;
    for entry in SOLANA_METHOD_CLASSES {
        let at = rows.iter().position(|(name, _, _)| name == entry.name).expect("class row");
        assert!(previous.is_none_or(|old| at > old), "{} is out of order", entry.name);
        previous = Some(at);
        let (_, listener, effect) = &rows[at];
        assert_eq!(listener, "Public", "{}", entry.name);
        assert_eq!(effect, &format!("{:?}", entry.effect), "{}", entry.name);
    }
}

#[test]
fn solana_refusals_name_existing_native_doors() {
    let declared = declared_names();
    for entry in SOLANA_METHOD_CLASSES {
        if entry.effect == CompatEffect::Refused {
            let door = native_door(entry.name).unwrap_or_else(|| panic!("{} has no door", entry.name));
            assert!(declared.iter().any(|name| name == door), "{} names missing {door}", entry.name);
        }
    }
    assert_eq!(native_door("slotSubscribe"), None);
}

#[test]
fn solana_subscription_doors_are_exact() {
    for name in ["account", "signature", "slot", "logs", "program"] {
        assert!(owns_method(&format!("{name}Subscribe")));
        assert!(is_unsubscribe(&format!("{name}Unsubscribe")));
        assert!(!is_unsubscribe(&format!("{name}Subscribe")));
    }
    assert!(!is_unsubscribe("bud_unsubscribe"));
}

#[test]
fn solana_check_served_rejects_unclassified_foreign_names() {
    check_served(["getHealth", "getBalance", "slotSubscribe"]).expect("classified methods");
    let error = check_served(["solana_notAThing"]).expect_err("unknown foreign method");
    assert!(error.contains("solana_notAThing"), "{error}");
}

#[test]
fn solana_error_payloads_name_the_native_door() {
    let error = ee_unavailable("getBalance", "bud_getBalance");
    assert_eq!(error.code(), -32004);
    assert!(error.message().contains("bud_getBalance"));
    assert_eq!(not_exposed("getEpochInfo", "bud_getStatus").code(), -32004);
    assert!(faucet_unavailable("requestAirdrop").message().contains("no grant was queued"));
}
