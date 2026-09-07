//! The training-data grant has a real on-chain issuance path.
//!
//! AÇIK-2 closure: `TrainingDataGrant` used to be a type with no caller -
//! nobody could issue one, so the fail-closed epoch ledger on the training
//! side had nothing to enforce against. This gate is the source-level lock
//! that the issuance path exists end to end: registry map, creation rule
//! (owner must match the DataAsset owner, DAO duration ceiling applies),
//! transaction variant + executor arm, RPC prepare + list, and the wire
//! mapping in the protocol schema.

use std::path::Path;

pub fn run(root: &Path) -> Result<String, String> {
    let offers = std::fs::read_to_string(root.join("src/pollen/offers.rs"))
        .map_err(|e| format!("cannot read offers.rs: {e}"))?;
    for marker in [
        "pub training_grants: BTreeMap<GrantId",
        "pub fn create_training_grant",
        "TrainingDataGrant owner must match DataAsset owner",
        "check_dao_grant_duration_ceiling",
    ] {
        if !offers.contains(marker) {
            return Err(format!("offers.rs lost the training-grant issuance rule: {marker}"));
        }
    }

    let executor = std::fs::read_to_string(root.join("src/execution/executor.rs"))
        .map_err(|e| format!("cannot read executor.rs: {e}"))?;
    for marker in [
        "TransactionType::PollenGrantTrainingData",
        "pollen_training_grant_owner_mismatch",
        "create_training_grant(grant)",
    ] {
        if !executor.contains(marker) {
            return Err(format!("executor.rs lost the training-grant arm: {marker}"));
        }
    }

    let tx = std::fs::read_to_string(root.join("src/core/transaction.rs"))
        .map_err(|e| format!("cannot read transaction.rs: {e}"))?;
    if !tx.contains("PollenGrantTrainingData(crate::ai_inference::TrainingDataGrant)") {
        return Err("transaction.rs lost the PollenGrantTrainingData variant".into());
    }

    let api = std::fs::read_to_string(root.join("src/rpc/api.rs"))
        .map_err(|e| format!("cannot read api.rs: {e}"))?;
    for marker in ["bud_marketPrepareTrainingGrant", "bud_pollenGetTrainingGrants"] {
        if !api.contains(marker) {
            return Err(format!("rpc/api.rs lost the RPC surface: {marker}"));
        }
    }

    let proto = std::fs::read_to_string(root.join("proto/budlum/network/protocol.proto"))
        .map_err(|e| format!("cannot read protocol.proto: {e}"))?;
    for marker in ["POLLEN_GRANT_TRAINING_DATA", "ProtoPollenTrainingDataGrant"] {
        if !proto.contains(marker) {
            return Err(format!("protocol.proto lost the training-grant wire type: {marker}"));
        }
    }

    Ok("training-data grants are issued on chain end to end".into())
}

pub fn self_test() -> Result<String, String> {
    let good_offers = "pub training_grants: BTreeMap<GrantId, crate::ai_inference::TrainingDataGrant>\npub fn create_training_grant(\nTrainingDataGrant owner must match DataAsset owner\ncheck_dao_grant_duration_ceiling";
    let thin_offers = "pub fn create_training_grant(&mut self) {}";
    assert!(!run_offers_like(good_offers), "full rule set must pass");
    assert!(run_offers_like(thin_offers), "rule-less issuance must fail");

    let good_executor = "TransactionType::PollenGrantTrainingData(grant) => {\npollen_training_grant_owner_mismatch\ncreate_training_grant(grant)";
    let thin_executor = "TransactionType::PollenGrantTrainingData(grant) => { create_training_grant(grant) }";
    assert!(!run_executor_like(good_executor), "full arm must pass");
    assert!(run_executor_like(thin_executor), "owner check omission must fail");
    Ok("self-test OK".into())
}

fn run_offers_like(text: &str) -> bool {
    for marker in [
        "pub training_grants: BTreeMap<GrantId",
        "pub fn create_training_grant",
        "TrainingDataGrant owner must match DataAsset owner",
        "check_dao_grant_duration_ceiling",
    ] {
        if !text.contains(marker) {
            return true;
        }
    }
    false
}

fn run_executor_like(text: &str) -> bool {
    !(text.contains("TransactionType::PollenGrantTrainingData")
        && text.contains("pollen_training_grant_owner_mismatch")
        && text.contains("create_training_grant(grant)"))
}
