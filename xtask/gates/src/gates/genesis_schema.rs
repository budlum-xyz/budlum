//! The genesis file has the shape the node expects, field by field.
//!
//! Ported from `ops/scripts/check_genesis_schema.py`.
//!
//! # The failure this closes
//!
//! `config/mainnet-genesis.json` is read by `mainnet_genesis()`'s lock test,
//! but a lock compares two copies of the same numbers; it does not say
//! whether the numbers are usable. A schedule value of zero (an epoch of zero
//! slots, a slot of zero seconds, zero epochs in a year) divides the
//! tokenomics by nothing and passed the python gate, whose `POSITIVE_KEYS`
//! set was declared and never applied.
//!
//! # What is checked
//!
//! * The required top-level fields are present.
//! * Integer fields are JSON integers, not booleans or strings.
//! * Every gas and tokenomics entry is a non-negative integer.
//! * The scheduling keys (`chain_id`, `epochs_per_year`,
//!   `slot_duration_secs`, `epoch_length_slots`) are strictly positive.
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

const REQUIRED_TOP: &[&str] = &[
    "chain_id",
    "allocations",
    "validators",
    "block_reward",
    "base_fee",
    "gas_schedule",
    "timestamp",
    "bud_tokenomics",
];

const INT_TOP: &[&str] = &["chain_id", "block_reward", "base_fee", "timestamp"];

const GAS_KEYS: &[&str] = &[
    "base_fee",
    "gas_per_byte",
    "gas_per_signature",
    "transfer_gas",
    "stake_gas",
    "vote_gas",
    "contract_call_gas",
];

const TOKENOMICS_KEYS: &[&str] = &[
    "community",
    "liquidity",
    "ecosystem",
    "team",
    "burn_reserve",
    "epochs_per_year",
    "annual_burn_ratio_fixed",
    "team_cliff_epochs",
    "team_vesting_epochs",
    "tx_fee_burn_ratio_fixed",
    "block_reward",
    "validator_annual_yield_ratio_fixed",
    "slot_duration_secs",
    "epoch_length_slots",
];

/// Keys that must be strictly positive: a zero here is a division by zero
/// or a chain with no identity, not a configuration.
const POSITIVE_KEYS: &[&str] = &[
    "chain_id",
    "epochs_per_year",
    "slot_duration_secs",
    "epoch_length_slots",
];

/// A JSON integer that fits `u64`; booleans and strings are not integers.
fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64()
}

fn check_int_table(table: &Value, table_name: &str, keys: &[&str], errs: &mut Vec<String>) {
    let Some(map) = table.as_object() else {
        errs.push(format!("{table_name}: must be an object"));
        return;
    };
    for key in keys {
        match map.get(*key) {
            None => errs.push(format!("{table_name}.{key} is missing")),
            Some(v) => match as_u64(v) {
                None => errs.push(format!("{table_name}.{key}: must be an integer >= 0")),
                Some(0) if POSITIVE_KEYS.contains(key) => {
                    errs.push(format!("{table_name}.{key}: must be > 0"));
                }
                Some(_) => {}
            },
        }
    }
}

/// Every problem with the genesis document; empty when it is well formed.
fn validate(g: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    let Some(map) = g.as_object() else {
        return vec![String::from("the root must be a JSON object")];
    };
    for key in REQUIRED_TOP {
        if !map.contains_key(*key) {
            errs.push(format!("missing required field: {key}"));
        }
    }
    if !errs.is_empty() {
        // A deep check is meaningless when the fields are absent.
        return errs;
    }
    for key in INT_TOP {
        match map.get(*key).and_then(as_u64) {
            None => errs.push(format!("{key}: must be an integer, not a bool or a string")),
            Some(0) if POSITIVE_KEYS.contains(key) => errs.push(format!("{key}: must be > 0")),
            Some(_) => {}
        }
    }
    for key in ["allocations", "validators"] {
        if !map.get(key).is_some_and(Value::is_array) {
            errs.push(format!("{key}: must be a list"));
        }
    }
    check_int_table(&map["gas_schedule"], "gas_schedule", GAS_KEYS, &mut errs);
    check_int_table(
        &map["bud_tokenomics"],
        "bud_tokenomics",
        TOKENOMICS_KEYS,
        &mut errs,
    );
    errs
}

fn load(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))
}

/// Which genesis files the gate reads from the repository root.
const GENESIS_FILES: &[&str] = &["config/mainnet-genesis.json"];

/// # Errors
///
/// Returns every schema problem in every genesis file.
pub fn run(root: &Path) -> Result<String, String> {
    let mut msg = String::new();
    for rel in GENESIS_FILES {
        let errs = validate(&load(&root.join(rel))?);
        for e in errs {
            let _ = writeln!(msg, "FAIL: {rel}: {e}");
        }
    }
    if !msg.is_empty() {
        return Err(msg);
    }
    Ok(format!(
        "genesis schema OK: {} file(s), {} top-level, {} gas and {} tokenomics fields typed, {} scheduling fields positive",
        GENESIS_FILES.len(),
        REQUIRED_TOP.len(),
        GAS_KEYS.len(),
        TOKENOMICS_KEYS.len(),
        POSITIVE_KEYS.len()
    ))
}

/// One way of breaking a well-formed genesis document.
type Mutation = fn(&mut Value);

/// # Errors
///
/// Returns a finding when the current genesis is refused or a broken variant
/// passes.
pub fn self_test() -> Result<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let good = load(&root.join(GENESIS_FILES[0]))?;
    if !validate(&good).is_empty() {
        return Err(String::from("canary: the current genesis was refused"));
    }
    let variants: &[(&str, Mutation)] = &[
        ("chain_id = 0", |g| g["chain_id"] = Value::from(0)),
        ("a missing table", |g| {
            g.as_object_mut().map(|m| m.remove("gas_schedule"));
        }),
        ("a string block_reward", |g| {
            g["block_reward"] = Value::from("50");
        }),
        ("a boolean chain_id", |g| g["chain_id"] = Value::from(true)),
        ("a negative gas entry", |g| {
            g["gas_schedule"]["transfer_gas"] = Value::from(-5);
        }),
        ("epochs_per_year = 0", |g| {
            g["bud_tokenomics"]["epochs_per_year"] = Value::from(0);
        }),
        ("slot_duration_secs = 0", |g| {
            g["bud_tokenomics"]["slot_duration_secs"] = Value::from(0);
        }),
        ("epoch_length_slots = 0", |g| {
            g["bud_tokenomics"]["epoch_length_slots"] = Value::from(0);
        }),
    ];
    for (name, mutate) in variants {
        let mut bad = good.clone();
        mutate(&mut bad);
        if validate(&bad).is_empty() {
            return Err(format!("canary: the '{name}' variant was not refused"));
        }
    }
    Ok(format!(
        "genesis schema canary OK: {} broken variants refused, the current genesis passes",
        variants.len()
    ))
}
