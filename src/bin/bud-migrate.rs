//! `bud-migrate`: the EVM migration kit's tool (directive 8.12, WP-34).
//!
//! `bud-migrate verify <request.json> <chain-fee-schedule.json>` runs the
//! verification core (`budlum_core::execution::coordinator::migration`) and
//! prints the record the account door installs, or the refusal. The two files
//! are separate because the migrator must not choose the node's fee schedule.
//! `bud-migrate report <input.json>`
//! prints the dependency report: the contracts that must migrate for this one
//! to keep working. Neither command touches the network or signs anything; the
//! transaction that installs the account comes from the migration door the node
//! owns. Every byte string in an input file is `0x`-prefixed hex.

use std::process::ExitCode;

use budlum_core::execution::coordinator::migration::{
    begin_import, dependency_report, DependencyReport, DeploymentProof, ImportError,
    ImportEvmStorageChunk, ImportSource, MigrationAuthorization,
    MigrationFeeSchedule, MigrationPlan, MigrationRecord, MigrationRequest, StorageEntry,
};
use serde::Deserialize;

/// One migration request as it is written on disk.
#[derive(Debug, Deserialize)]
struct RequestJson {
    chain_id: u64,
    source_chain_id: u64,
    domain: String,
    contract: String,
    source_block: u64,
    deployment: DeploymentJson,
    state_root: String,
    account_proof: Vec<String>,
    code: String,
    signature: String,
    #[serde(default)]
    occupied: bool,
    #[serde(default)]
    chunks: Vec<ChunkJson>,
}

/// The source transaction and receipt proofs, with every byte string in hex.
#[derive(Debug, Deserialize)]
struct DeploymentJson {
    deployment_block: u64,
    transaction_index: u64,
    transaction: String,
    transaction_proof: Vec<String>,
    transactions_root: String,
    receipt_proof: Vec<String>,
    receipts_root: String,
}

/// One storage chunk as it is written on disk.
#[derive(Debug, Deserialize)]
struct ChunkJson {
    #[serde(default)]
    slots: Vec<SlotJson>,
}

/// One proven slot as it is written on disk.
#[derive(Debug, Deserialize)]
struct SlotJson {
    slot: String,
    value: String,
    #[serde(default)]
    proof: Vec<String>,
}

/// One dependency-report input as it is written on disk.
#[derive(Debug, Deserialize)]
struct ReportJson {
    contract: String,
    code: String,
    #[serde(default)]
    trace: Vec<String>,
}

impl RequestJson {
    /// Splits the on-disk shape into the request and its chunks.
    fn into_parts(self) -> Result<(MigrationRequest, Vec<ImportEvmStorageChunk>), String> {
        let contract = decode_address(&self.contract)?;
        let deployment = DeploymentProof {
            deployment_block: self.deployment.deployment_block,
            transaction_index: self.deployment.transaction_index,
            transaction: decode_hex(&self.deployment.transaction)?,
            transaction_proof: decode_nodes(&self.deployment.transaction_proof)?,
            transactions_root: decode_word(&self.deployment.transactions_root)?,
            receipt_proof: decode_nodes(&self.deployment.receipt_proof)?,
            receipts_root: decode_word(&self.deployment.receipts_root)?,
        };
        let mut account_proof = Vec::with_capacity(self.account_proof.len());
        for node in &self.account_proof {
            account_proof.push(decode_hex(node)?);
        }
        let mut chunks = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            let mut slots = Vec::with_capacity(chunk.slots.len());
            for slot in &chunk.slots {
                let mut proof_nodes = Vec::with_capacity(slot.proof.len());
                for node in &slot.proof {
                    proof_nodes.push(decode_hex(node)?);
                }
                slots.push(StorageEntry {
                    slot: decode_word(&slot.slot)?,
                    value: decode_word(&slot.value)?,
                    proof_nodes,
                });
            }
            chunks.push(ImportEvmStorageChunk {
                contract,
                source_block: self.source_block,
                slots,
            });
        }
        let request = MigrationRequest {
            chain_id: self.chain_id,
            source_chain_id: self.source_chain_id,
            source_domain: self.domain,
            source_block: self.source_block,
            deployment,
            authorization: MigrationAuthorization {
                contract,
                budlum_chain_id: self.chain_id,
                source_block: self.source_block,
                signature: decode_hex(&self.signature)?,
            },
            state_root: decode_word(&self.state_root)?,
            account_proof,
            code: decode_hex(&self.code)?,
            occupied: self.occupied,
        };
        Ok((request, chunks))
    }
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        eprintln!("usage: bud-migrate verify <request.json> <chain-fee-schedule.json>");
        eprintln!("       bud-migrate report <input.json>");
        return ExitCode::from(2);
    };
    let input = arguments.next();
    match command.as_str() {
        "verify" => verify(input, arguments.next()),
        "report" => report(input),
        other => {
            eprintln!("bud-migrate: unknown command `{other}`");
            ExitCode::from(2)
        }
    }
}

/// Runs the verification core over one request and prints the record.
fn verify(input: Option<String>, fee_schedule_input: Option<String>) -> ExitCode {
    let (Some(path), Some(fee_schedule_path)) = (input, fee_schedule_input) else {
        eprintln!("usage: bud-migrate verify <request.json> <chain-fee-schedule.json>");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return fail(&format!("read {path}: {error}")),
    };
    let input: RequestJson = match serde_json::from_str(&text) {
        Ok(input) => input,
        Err(error) => return fail(&format!("parse {path}: {error}")),
    };
    // This file is node configuration, never a field in the migrator's request.
    let fee_schedule_text = match std::fs::read_to_string(&fee_schedule_path) {
        Ok(text) => text,
        Err(error) => return fail(&format!("read {fee_schedule_path}: {error}")),
    };
    let fee_schedule: MigrationFeeSchedule = match serde_json::from_str(&fee_schedule_text) {
        Ok(schedule) => schedule,
        Err(error) => return fail(&format!("parse {fee_schedule_path}: {error}")),
    };
    let (request, chunks) = match input.into_parts() {
        Ok(parts) => parts,
        Err(error) => return fail(&error),
    };
    let digest = hex_bytes(&request.authorization.digest());
    let mut plan: MigrationPlan = match begin_import(request) {
        Ok(plan) => plan,
        Err(error) => return refuse(&error),
    };
    for chunk in &chunks {
        if let Err(error) = plan.import_chunk(chunk) {
            return refuse(&error);
        }
    }
    let nonce = plan.account().nonce;
    let balance = plan.account().balance;
    let record: MigrationRecord = match plan.finalize(&fee_schedule) {
        Ok(record) => record,
        Err(error) => return refuse(&error),
    };
    println!("{}", pretty(&record_json(&record, nonce, balance, &digest)));
    ExitCode::SUCCESS
}

/// Builds the dependency report of one contract and prints it.
fn report(input: Option<String>) -> ExitCode {
    let Some(path) = input else {
        eprintln!("usage: bud-migrate report <report-input.json>");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => return fail(&format!("read {path}: {error}")),
    };
    let input: ReportJson = match serde_json::from_str(&text) {
        Ok(input) => input,
        Err(error) => return fail(&format!("parse {path}: {error}")),
    };
    let contract = match decode_address(&input.contract) {
        Ok(address) => address,
        Err(error) => return fail(&error),
    };
    let code = match decode_hex(&input.code) {
        Ok(code) => code,
        Err(error) => return fail(&error),
    };
    let mut trace = Vec::with_capacity(input.trace.len());
    for target in &input.trace {
        match decode_address(target) {
            Ok(address) => trace.push(address),
            Err(error) => return fail(&error),
        }
    }
    let report: DependencyReport = dependency_report(contract, &code, &trace);
    let required = report.required_migrations();
    let document = serde_json::json!({
        "contract": hex_bytes(&report.contract),
        "static_targets": report
            .static_targets
            .iter()
            .map(|address| hex_bytes(address))
            .collect::<Vec<String>>(),
        "trace_targets": report
            .trace_targets
            .iter()
            .map(|address| hex_bytes(address))
            .collect::<Vec<String>>(),
        "required_migrations": required
            .iter()
            .map(|address| hex_bytes(address))
            .collect::<Vec<String>>(),
    });
    println!("{}", pretty(&document));
    ExitCode::SUCCESS
}

/// The record as the operator reads it, with every byte string in hex.
fn record_json(
    record: &MigrationRecord,
    nonce: u64,
    balance: u128,
    digest: &str,
) -> serde_json::Value {
    let slots: &[([u8; 32], [u8; 32])] = &record.storage;
    let source: &ImportSource = &record.imported_from;
    serde_json::json!({
        "address": hex_bytes(&record.address),
        "code_hash": hex_bytes(&record.code_hash),
        "code_bytes": record.code.len(),
        "storage_root": hex_bytes(&record.storage_root),
        "storage": slots
            .iter()
            .map(|(slot, value)| serde_json::json!({
                "slot": hex_bytes(slot),
                "value": hex_bytes(value),
            }))
            .collect::<Vec<serde_json::Value>>(),
        "authorization_digest": digest,
        "migration_fee": {
            "proof_nodes": record.usage.proof_nodes,
            "verification_bgu": record.fee.verification_bgu,
            "storage_bytes": record.fee.storage_bytes,
            "total_attos": record.fee.total_attos.to_string(),
        },
        "imported_from": {
            "domain": source.domain.as_str(),
            "block": source.block,
            "address": hex_bytes(&source.address),
        },
        "source_account": {
            "nonce": nonce,
            "balance_wei": balance.to_string(),
        },
    })
}

/// Prints a JSON document, or the reason it could not be printed.
fn pretty(document: &serde_json::Value) -> String {
    match serde_json::to_string_pretty(document) {
        Ok(text) => text,
        Err(error) => format!("{{\"error\":\"{error}\"}}"),
    }
}

/// Reports a refusal from the verification core.
fn refuse(error: &ImportError) -> ExitCode {
    eprintln!("bud-migrate: refused: {error}");
    ExitCode::FAILURE
}

/// Reports an input or tool failure.
fn fail(message: &str) -> ExitCode {
    eprintln!("bud-migrate: {message}");
    ExitCode::FAILURE
}

/// Decodes `0x`-prefixed or bare hex.
fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let body = text.strip_prefix("0x").unwrap_or(text);
    hex::decode(body).map_err(|error| format!("hex `{text}`: {error}"))
}

/// Decodes a 20-byte address.
fn decode_address(text: &str) -> Result<[u8; 20], String> {
    let bytes = decode_hex(text)?;
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| format!("address `{text}` is not 20 bytes"))?;
    Ok(address)
}

/// Decodes a list of RLP proof nodes.
fn decode_nodes(nodes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    nodes.iter().map(|node| decode_hex(node)).collect()
}

/// Decodes a 32-byte word.
fn decode_word(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(text)?;
    let word: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("word `{text}` is not 32 bytes"))?;
    Ok(word)
}

/// Encodes bytes as `0x`-prefixed hex.
fn hex_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
