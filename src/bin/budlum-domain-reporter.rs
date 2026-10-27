//! Submit a cryptographically checked proof-market receipt.
//!
//! The reporter is the prover-facing companion to `budlum-domain-producer`.
//! It reads a `VerifiedDomainCommitment`, wraps it in the signed
//! `ProofMarketTx::SubmitReceipt` door, and sends it to the public transaction
//! RPC. Finality verification and the task-specific binding happen again in
//! every block, so a reporter cannot create a receipt by writing local state.
//!
//! The payload file is JSON so an adapter can be implemented in another
//! process without linking node internals. The signer is a V5 wallet key
//! file sealed with a password (`bud wallet create`); neither the key nor the
//! password is ever taken on the command line.

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::settlement::domains::SettlementTx;
use budlum_core::settlement::proof_market::ProofMarketTx;
use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "budlum-domain-reporter",
    about = "Submit a proof-market receipt"
)]
struct Cli {
    /// Public node JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// JSON file containing a VerifiedDomainCommitment.
    #[arg(long)]
    payload: PathBuf,
    /// 32-byte proof-market task id, with an optional 0x prefix.
    #[arg(long)]
    task_id: String,
    /// The V5 wallet key file (`bud wallet create`), sealed with a password.
    #[arg(long)]
    key_file: PathBuf,
    /// A mode-0600 file holding the wallet password; else
    /// `BUD_WALLET_PASSWORD`.
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// Transaction fee in atoms.
    #[arg(long, default_value_t = 1_000)]
    fee: u64,
}

fn task_id(text: &str) -> Result<[u8; 32], String> {
    let clean = text.trim().strip_prefix("0x").unwrap_or(text.trim());
    hex::decode(clean)
        .map_err(|e| format!("task id is not hex: {e}"))?
        .try_into()
        .map_err(|_| "the task id must be exactly 32 bytes".to_string())
}

fn quantity(value: &Value, field: &str) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{field} did not return a quantity string"))?;
    text.strip_prefix("0x").map_or_else(
        || text.parse::<u64>().map_err(|e| format!("{field}: {e}")),
        |hex| u64::from_str_radix(hex, 16).map_err(|e| format!("{field}: {e}")),
    )
}

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let answer: Value = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("{method}: request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("{method}: response was not JSON: {e}"))?;
    if let Some(error) = answer.get("error") {
        return Err(format!("{method}: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: response has no result"))
}

async fn run(cli: Cli) -> Result<(), String> {
    let payload: budlum_core::domain::VerifiedDomainCommitment = serde_json::from_slice(
        &std::fs::read(&cli.payload)
            .map_err(|e| format!("cannot read payload {}: {e}", cli.payload.display()))?,
    )
    .map_err(|e| format!("payload is not a VerifiedDomainCommitment: {e}"))?;
    let key = budlum_core::wallet::open_key_file(&cli.key_file, cli.password_file.as_deref())?;
    let client = reqwest::Client::new();
    let chain_id = quantity(
        &rpc_call(&client, &cli.rpc_url, "bud_chainId", serde_json::json!([])).await?,
        "bud_chainId",
    )?;
    let sender = key.address();
    let nonce = quantity(
        &rpc_call(
            &client,
            &cli.rpc_url,
            "bud_getNonce",
            serde_json::json!([sender.to_hex()]),
        )
        .await?,
        "bud_getNonce",
    )?;
    let market = ProofMarketTx::SubmitReceipt {
        task_id: task_id(&cli.task_id)?,
        proof: Box::new(payload),
    };
    let mut transaction = Transaction::new_with_chain_id(
        sender,
        Address::zero(),
        0,
        cli.fee,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Settlement(SettlementTx::ProofMarket(Box::new(market))),
    );
    key.sign(&mut transaction)?;
    let hash = transaction.hash.clone();
    let result = rpc_call(
        &client,
        &cli.rpc_url,
        "bud_sendRawTransaction",
        serde_json::json!([transaction]),
    )
    .await?;
    println!("submitted proof-market receipt transaction {hash}: {result}");
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("budlum-domain-reporter: {error}");
            std::process::ExitCode::from(1)
        }
    }
}
