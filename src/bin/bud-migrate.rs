//! Offline EVM Migration Kit verifier and bundle tool (directive 8.12).
//!
//! Commands:
//! - `bud-migrate digest --contract 0x... --chain-id <id> --source-block <n> --state-root 0x... --code-hash 0x...`
//! - `bud-migrate analyze --code-file <path> [--json]`
//! - `bud-migrate verify <bundle.json> <chain-fee-schedule.json> --chain-id <id>`

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::ExitCode;

use budlum_core::cross_domain::evm::account_proof;
use budlum_core::execution::coordinator::migration::{
    begin_import, dependency_report, verify_deployment, DependencyReport, DeploymentProof,
    ImportEvmStorageChunk, MigrationAuthorization, MigrationFeeSchedule, MigrationRecord,
    MigrationRequest, StorageEntry,
};
use serde::{Deserialize, Serialize};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(usage());
    };
    let tail = args.get(1..).unwrap_or_default();
    match command {
        "--help" | "-h" | "help" => Ok(usage()),
        "digest" => run_digest(tail),
        "analyze" => run_analyze(tail),
        "verify" => run_verify(tail),
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "bud-migrate <command> [options]",
        "",
        "Commands:",
        "  digest   --contract 0x<20-bytes> --chain-id <u64> --source-block <u64>",
        "           --state-root 0x<32-bytes> --code-hash 0x<32-bytes>",
        "  analyze  --code-file <path> [--json]",
        "  verify   <bundle.json> <chain-fee-schedule.json> --chain-id <u64>",
    ]
    .join("\n")
}

fn run_digest(args: &[String]) -> Result<String, String> {
    let mut contract = None;
    let mut chain_id = None;
    let mut source_block = None;
    let mut state_root = None;
    let mut code_hash = None;
    let mut idx = 0usize;
    while let Some(flag) = args.get(idx) {
        let val = args
            .get(idx + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--contract" => contract = Some(parse_hex_array::<20>(val)?),
            "--chain-id" => chain_id = Some(parse_u64(val, "--chain-id")?),
            "--source-block" => source_block = Some(parse_u64(val, "--source-block")?),
            "--state-root" => state_root = Some(parse_hex_array::<32>(val)?),
            "--code-hash" => code_hash = Some(parse_hex_array::<32>(val)?),
            other => return Err(format!("unknown digest option `{other}`")),
        }
        idx += 2;
    }
    let auth = MigrationAuthorization {
        contract: contract.ok_or_else(|| String::from("--contract is required"))?,
        budlum_chain_id: chain_id.ok_or_else(|| String::from("--chain-id is required"))?,
        source_block: source_block.ok_or_else(|| String::from("--source-block is required"))?,
        state_root: state_root.ok_or_else(|| String::from("--state-root is required"))?,
        code_hash: code_hash.ok_or_else(|| String::from("--code-hash is required"))?,
        signature: Vec::new(),
    };
    Ok(format!("0x{}", hex::encode(auth.digest())))
}

fn run_analyze(args: &[String]) -> Result<String, String> {
    let mut code_file = None;
    let mut json = false;
    let mut idx = 0usize;
    while let Some(arg) = args.get(idx) {
        match arg.as_str() {
            "--json" => {
                json = true;
                idx += 1;
            }
            "--code-file" => {
                let path = args
                    .get(idx + 1)
                    .ok_or_else(|| String::from("--code-file requires a path"))?;
                code_file = Some(path.clone());
                idx += 2;
            }
            other => return Err(format!("unknown analyze option `{other}`")),
        }
    }
    let path = code_file.ok_or_else(|| String::from("--code-file is required"))?;
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let code = parse_hex_bytes(raw.trim())?;
    let scanned_bytes = code.len();
    let report = dependency_report([0u8; 20], &code, &[]);
    if json {
        serde_json::to_string_pretty(&JsonDependencyReport::from_report(&report, scanned_bytes))
            .map_err(|e| format!("encode report: {e}"))
    } else {
        Ok(format_dependency_report(&report, scanned_bytes))
    }
}

fn format_dependency_report(report: &DependencyReport, scanned_bytes: usize) -> String {
    let mut lines = vec![
        format!("scanned_bytes: {scanned_bytes}"),
        format!("static_targets: {}", report.static_targets.len()),
    ];
    if report.static_targets.is_empty() {
        lines.push(String::from("hardcoded_addresses: none"));
    } else {
        lines.push(String::from("hardcoded_addresses:"));
        for address in &report.static_targets {
            lines.push(format!("  0x{}", hex::encode(address)));
        }
    }
    lines.join("\n")
}

fn run_verify(args: &[String]) -> Result<String, String> {
    let usage = "verify expects <bundle.json> <chain-fee-schedule.json> --chain-id <u64>";
    let (path, fee_path, flag, value) = match args {
        [path, fee_path, flag, value] => (path, fee_path, flag, value),
        _ => return Err(String::from(usage)),
    };
    // The chain id is node configuration, like the fee schedule: a bundle that
    // named its own chain would let one deployer signature replay anywhere.
    if flag != "--chain-id" {
        return Err(String::from(usage));
    }
    let chain_id = parse_u64(value, "--chain-id")?;
    let raw = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let bundle: MigrationBundleFile =
        serde_json::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))?;
    // This is node configuration, never a field supplied by the migrator.
    let fee_raw = fs::read_to_string(fee_path).map_err(|e| format!("read {fee_path}: {e}"))?;
    let fee_schedule: MigrationFeeSchedule =
        serde_json::from_str(&fee_raw).map_err(|e| format!("parse {fee_path}: {e}"))?;
    let output = verify_bundle(bundle, &fee_schedule, chain_id)?;
    serde_json::to_string_pretty(&output).map_err(|e| format!("encode output: {e}"))
}

fn verify_bundle(
    bundle: MigrationBundleFile,
    fee_schedule: &MigrationFeeSchedule,
    chain_id: u64,
) -> Result<VerifiedMigrationOutput, String> {
    let deployment = bundle.deployment.into_proof()?;
    let evidence = verify_deployment(&deployment, bundle.source_chain_id)
        .map_err(|e| format!("deployment proof: {e}"))?;
    let state_root = parse_hex_array::<32>(&bundle.state_root)?;
    let account_proof = parse_hex_list(&bundle.account_proof)?;
    let code = parse_hex_bytes(&bundle.code)?;
    let source_account =
        account_proof::verify_account(&account_proof, &state_root, &evidence.contract)
            .map_err(|e| format!("account proof: {e}"))?;
    account_proof::check_code(&code, &source_account.code_hash)
        .map_err(|e| format!("bytecode: {e}"))?;
    let authorization = MigrationAuthorization {
        contract: parse_hex_array::<20>(&bundle.authorization.contract)?,
        budlum_chain_id: bundle.authorization.budlum_chain_id,
        source_block: bundle.authorization.source_block,
        state_root: parse_hex_array::<32>(&bundle.authorization.state_root)?,
        code_hash: parse_hex_array::<32>(&bundle.authorization.code_hash)?,
        signature: parse_hex_bytes(&bundle.authorization.signature)?,
    };
    let request = MigrationRequest {
        source_chain_id: bundle.source_chain_id,
        source_domain: bundle.source_domain,
        source_block: bundle.source_block,
        deployment,
        authorization,
        state_root,
        account_proof,
        code,
        occupied: bundle.occupied,
    };
    let mut plan = begin_import(request, chain_id).map_err(|e| e.to_string())?;
    for chunk in bundle.chunks {
        let decoded = chunk.into_chunk()?;
        plan.import_chunk(&decoded).map_err(|e| e.to_string())?;
    }
    let raw_code = parse_hex_bytes(&bundle.code)?;
    let deps = dependency_report(evidence.contract, &raw_code, &[]);
    let record = plan.finalize(fee_schedule).map_err(|e| e.to_string())?;
    Ok(VerifiedMigrationOutput::from_record(
        record,
        evidence.deployer,
        source_account.balance_u128(),
        &deps,
        raw_code.len(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationBundleFile {
    source_chain_id: u64,
    source_domain: String,
    source_block: u64,
    #[serde(default)]
    occupied: bool,
    state_root: String,
    account_proof: Vec<String>,
    code: String,
    deployment: DeploymentProofFile,
    authorization: AuthorizationFile,
    #[serde(default)]
    chunks: Vec<StorageChunkFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentProofFile {
    deployment_block: u64,
    transaction_index: u64,
    transaction: String,
    transaction_proof: Vec<String>,
    transactions_root: String,
    receipt_proof: Vec<String>,
    receipts_root: String,
}

impl DeploymentProofFile {
    fn into_proof(self) -> Result<DeploymentProof, String> {
        Ok(DeploymentProof {
            deployment_block: self.deployment_block,
            transaction_index: self.transaction_index,
            transaction: parse_hex_bytes(&self.transaction)?,
            transaction_proof: parse_hex_list(&self.transaction_proof)?,
            transactions_root: parse_hex_array::<32>(&self.transactions_root)?,
            receipt_proof: parse_hex_list(&self.receipt_proof)?,
            receipts_root: parse_hex_array::<32>(&self.receipts_root)?,
        })
    }
}

#[derive(Deserialize)]
struct AuthorizationFile {
    contract: String,
    budlum_chain_id: u64,
    source_block: u64,
    state_root: String,
    code_hash: String,
    signature: String,
}

#[derive(Deserialize)]
struct StorageChunkFile {
    contract: String,
    source_block: u64,
    slots: Vec<StorageEntryFile>,
}

impl StorageChunkFile {
    fn into_chunk(self) -> Result<ImportEvmStorageChunk, String> {
        let mut slots = Vec::with_capacity(self.slots.len());
        for entry in self.slots {
            slots.push(StorageEntry {
                slot: parse_hex_array::<32>(&entry.slot)?,
                value: parse_hex_array::<32>(&entry.value)?,
                proof_nodes: parse_hex_list(&entry.proof_nodes)?,
            });
        }
        Ok(ImportEvmStorageChunk {
            contract: parse_hex_array::<20>(&self.contract)?,
            source_block: self.source_block,
            slots,
        })
    }
}

#[derive(Deserialize)]
struct StorageEntryFile {
    slot: String,
    value: String,
    proof_nodes: Vec<String>,
}

#[derive(Serialize)]
struct JsonDependencyReport {
    scanned_bytes: usize,
    external_call_opcodes: usize,
    addresses: Vec<String>,
}

impl JsonDependencyReport {
    fn from_report(report: &DependencyReport, scanned_bytes: usize) -> Self {
        Self {
            scanned_bytes,
            external_call_opcodes: report.static_targets.len(),
            addresses: report
                .static_targets
                .iter()
                .map(|addr| format!("0x{}", hex::encode(addr)))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct VerifiedMigrationOutput {
    address: String,
    deployer: String,
    nonce: u64,
    source_eth_balance_not_migrated: Option<String>,
    installed_bud_balance_attos: &'static str,
    code_hash: String,
    storage_root: String,
    imported_from: ImportedFromOutput,
    storage: BTreeMap<String, String>,
    dependencies: JsonDependencyReport,
    fee: FeeOutput,
}

#[derive(Serialize)]
struct ImportedFromOutput {
    domain: String,
    block: u64,
    address: String,
}

#[derive(Serialize)]
struct FeeOutput {
    proof_nodes: u64,
    code_bytes: u64,
    storage_slots: u64,
    verification_bgu: u64,
    storage_bytes: u64,
    verification_attos: String,
    storage_deposit_attos: String,
    total_attos: String,
}

impl VerifiedMigrationOutput {
    fn from_record(
        record: MigrationRecord,
        deployer: [u8; 20],
        source_eth_balance: Option<u128>,
        deps: &DependencyReport,
        scanned_bytes: usize,
    ) -> Self {
        let mut storage = BTreeMap::new();
        for (slot, value) in record.storage {
            storage.insert(
                format!("0x{}", hex::encode(slot)),
                format!("0x{}", hex::encode(value)),
            );
        }
        Self {
            address: format!("0x{}", hex::encode(record.address)),
            deployer: format!("0x{}", hex::encode(deployer)),
            nonce: record.nonce,
            source_eth_balance_not_migrated: source_eth_balance.map(|v| v.to_string()),
            installed_bud_balance_attos: "0",
            code_hash: format!("0x{}", hex::encode(record.code_hash)),
            storage_root: format!("0x{}", hex::encode(record.storage_root)),
            imported_from: ImportedFromOutput {
                domain: record.imported_from.domain,
                block: record.imported_from.block,
                address: format!("0x{}", hex::encode(record.imported_from.address)),
            },
            storage,
            dependencies: JsonDependencyReport::from_report(deps, scanned_bytes),
            fee: FeeOutput {
                proof_nodes: record.usage.proof_nodes,
                code_bytes: record.usage.code_bytes,
                storage_slots: record.usage.storage_slots,
                verification_bgu: record.fee.verification_bgu,
                storage_bytes: record.fee.storage_bytes,
                verification_attos: record.fee.verification_attos.to_string(),
                storage_deposit_attos: record.fee.storage_deposit_attos.to_string(),
                total_attos: record.fee.total_attos.to_string(),
            },
        }
    }
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|e| format!("invalid {flag} `{value}`: {e}"))
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    hex::decode(trimmed).map_err(|e| format!("invalid hex `{value}`: {e}"))
}

fn parse_hex_list(values: &[String]) -> Result<Vec<Vec<u8>>, String> {
    values.iter().map(|v| parse_hex_bytes(v)).collect()
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = parse_hex_bytes(value)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} hex bytes, got {len}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = "0xa3183498b579bd228aa2b62101c40cc1da978f24";
    /// The same known answer the library pins in
    /// `the_authorization_digest_matches_the_known_answer`, reached through the CLI.
    const KNOWN_ANSWER: &str = "0xa270d0a4b367237f543fc31799b0483e5739224c286716cecdfe7acc14da9df8";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    fn digest_args(with_root: bool, with_code: bool) -> Vec<String> {
        let state_root = format!("0x{}", "11".repeat(32));
        let code_hash = format!("0x{}", "22".repeat(32));
        let mut out = args(&[
            "--contract",
            CONTRACT,
            "--chain-id",
            "45261",
            "--source-block",
            "19000000",
        ]);
        if with_root {
            out.extend(args(&["--state-root", &state_root]));
        }
        if with_code {
            out.extend(args(&["--code-hash", &code_hash]));
        }
        out
    }

    #[test]
    fn the_digest_command_prints_the_known_answer() {
        assert_eq!(
            run_digest(&digest_args(true, true)),
            Ok(KNOWN_ANSWER.to_string())
        );
    }

    #[test]
    fn the_digest_command_refuses_a_signature_that_names_no_payload() {
        assert_eq!(
            run_digest(&digest_args(false, false)),
            Err(String::from("--state-root is required"))
        );
        assert_eq!(
            run_digest(&digest_args(true, false)),
            Err(String::from("--code-hash is required"))
        );
    }

    #[test]
    fn verify_takes_the_chain_id_from_the_node_and_nowhere_else() {
        for bad in [
            args(&["bundle.json", "fees.json"]),
            args(&["bundle.json", "fees.json", "--chain", "45261"]),
            args(&["bundle.json", "fees.json", "--chain-id"]),
        ] {
            let error = run_verify(&bad).expect_err("the chain id flag is required");
            assert!(error.contains("--chain-id <u64>"), "{error}");
        }
        let error = run_verify(&args(&["bundle.json", "fees.json", "--chain-id", "x"]))
            .expect_err("a chain id is a number");
        assert!(error.contains("--chain-id"), "{error}");
    }

    #[test]
    fn a_bundle_that_names_its_own_chain_is_refused() {
        let error = match serde_json::from_str::<MigrationBundleFile>(r#"{"chain_id": 45261}"#) {
            Ok(_) => panic!("a bundle with a chain_id field must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("unknown field `chain_id`"), "{error}");
    }
}
