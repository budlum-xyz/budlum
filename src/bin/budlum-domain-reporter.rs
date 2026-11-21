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
use budlum_core::wallet::bind_signing_chain_id;
use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;

#[cfg(test)]
#[path = "test_support/domain_clients.rs"]
mod domain_client_test_support;

#[derive(Debug, Parser)]
#[command(
    name = "budlum-domain-reporter",
    about = "Submit a proof-market receipt"
)]
struct Cli {
    /// Public node JSON-RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// JSON file containing a `VerifiedDomainCommitment`.
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
    /// The Budlum chain this invocation signs for: `45260` mainnet, `45261`
    /// testnet, `45262` devnet.
    ///
    /// Required and never defaulted. The RPC node's answer is checked against
    /// this operator-named replay domain before signing.
    #[arg(long)]
    signing_chain_id: u64,
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

const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

async fn read_json_bounded(mut response: reqwest::Response, method: &str) -> Result<Value, String> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RPC_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "{method}: response exceeds {MAX_RPC_RESPONSE_BYTES}-byte limit"
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("{method}: failed reading response body: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
            return Err(format!(
                "{method}: response exceeds {MAX_RPC_RESPONSE_BYTES}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| format!("{method}: response was not JSON: {e}"))
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
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("{method}: request failed: {e}"))?;
    let answer = read_json_bounded(response, method).await?;
    if let Some(error) = answer.get("error") {
        return Err(format!("{method}: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: response has no result"))
}

/// A client whose TLS stack is ready to use.
///
/// reqwest is built against `rustls-tls-webpki-roots-no-provider`, so
/// `Client::new()` panics unless a process-wide provider is installed first.
/// The install is idempotent and keeps an existing default, and doing it here
/// rather than only in `main` covers every entry point - including a test that
/// calls `run` directly, which is the path a `main`-only install leaves open.
fn http_client() -> Result<reqwest::Client, String> {
    budlum_core::crypto::tls::install_default_provider();
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

async fn run(cli: Cli) -> Result<(), String> {
    let payload: budlum_core::domain::VerifiedDomainCommitment = serde_json::from_slice(
        &std::fs::read(&cli.payload)
            .map_err(|e| format!("cannot read payload {}: {e}", cli.payload.display()))?,
    )
    .map_err(|e| format!("payload is not a VerifiedDomainCommitment: {e}"))?;
    let key = budlum_core::wallet::open_key_file(&cli.key_file, cli.password_file.as_deref())?;
    let client = http_client()?;
    let chain_id = bind_signing_chain_id(
        quantity(
            &rpc_call(&client, &cli.rpc_url, "bud_chainId", serde_json::json!([])).await?,
            "bud_chainId",
        )?,
        cli.signing_chain_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_cannot_choose_the_reporters_signing_network() {
        assert_eq!(
            bind_signing_chain_id(45_261, 45_261).expect("named network agrees"),
            45_261
        );
        let error = bind_signing_chain_id(45_262, 45_261)
            .expect_err("another network's RPC answer must be refused");
        assert!(error.contains("refusing to sign"), "{error}");
    }

    #[tokio::test]
    async fn submission_checks_the_network_before_signing_or_sending() {
        use super::domain_client_test_support::{rpc, Files};
        use budlum_core::core::transaction::TransactionType;
        use budlum_core::settlement::proof_market::ProofMarketTx;

        let files = Files::new();
        let cli = |url| Cli {
            rpc_url: url,
            payload: files.payload.clone(),
            task_id: format!("0x{}", "11".repeat(32)),
            key_file: files.key.clone(),
            password_file: Some(files.password.clone()),
            signing_chain_id: 45262,
            fee: 1_000,
        };
        let (url, calls, server) = rpc(45260).await;
        let error = super::run(cli(url))
            .await
            .expect_err("a node on another network must not sign");
        assert!(error.contains("refusing to sign"), "{error}");
        assert_eq!(*calls.methods.lock().unwrap(), ["bud_chainId"]);
        assert!(calls.transactions.lock().unwrap().is_empty());
        server.stop().unwrap();

        let (url, calls, server) = rpc(45262).await;
        super::run(cli(url))
            .await
            .expect("the named network submits");
        let transactions = calls.transactions.lock().unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].chain_id, 45262);
        // The proof-market door is boxed inside the settlement variant; the
        // deref is what makes the payload pattern reachable on stable Rust.
        assert!(matches!(
            &transactions[0].tx_type,
            TransactionType::Settlement(SettlementTx::ProofMarket(market))
                if matches!(market.as_ref(), ProofMarketTx::SubmitReceipt { .. })
        ));
        assert!(
            transactions[0].verify(),
            "the submitted transaction is signed"
        );
        server.stop().unwrap();
    }
}
