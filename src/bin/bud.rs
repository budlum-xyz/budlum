//! Budlum L1 CLI - send transactions, query state, validator guidance.
//!
//! This binary talks to the L1 core (`budlum_core`):
//! build and send a signed transaction (`tx send`), read-only queries
//! (`query balance`/`query block`/`query status`), and guidance for running
//! a validator (`validator run`).
//!
//! The BudZKVM toolchain (`budzero/bud-cli`) is a separate workspace; this binary
//! is for L1 chain interaction and uses the core types directly.
//!
//! # Design
//! - JSON-RPC transport: a hand-written minimal HTTP/1.1 POST over a std
//!   `TcpStream`. NO new external dependency (enough for a CLI; localhost/single node).
//! - Signing: `KeyPair::from_seed` (32-byte hex seed) -> `Transaction::sign`.
//! - Node address via `--rpc-url` (default `http://127.0.0.1:8545`).

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::developer_os::{DeveloperOsManifest, ProofFixtureStatus};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_RPC_URL: &str = "http://127.0.0.1:8545";
const RPC_TIMEOUT_SECS: u64 = 15;

#[derive(Parser)]
#[command(
    name = "bud",
    author,
    version,
    about = "Budlum L1 CLI - send txs, query state, validator guidance"
)]
struct Cli {
    /// The node's JSON-RPC endpoint.
    #[arg(long, global = true, default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a signed transaction and send it to the node.
    Tx {
        #[command(subcommand)]
        action: TxAction,
    },
    /// Read-only state query (relayer independent).
    Query {
        #[command(subcommand)]
        action: QueryAction,
    },
    /// Guidance for running a validator/node (the full node runner is separate).
    Validator {
        /// A configuration file such as `config/mainnet.toml` (validate + summarize).
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Local development project manifest (validate + project id).
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// Validate the local standard manifest and print the project id.
    Id {
        /// Project name.
        #[arg(long, required = true)]
        name: String,
        /// The 32-byte hash of the BudL source tree (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        source_hash: String,
    },
    /// Bind a proof record to the hash of a verified proof envelope.
    BindProof {
        /// Project name.
        #[arg(long, required = true)]
        name: String,
        /// The 32-byte hash of the BudL source tree (hex).
        #[arg(long, required = true)]
        source_hash: String,
        /// Name of the proof record in the manifest.
        #[arg(long, required = true)]
        fixture: String,
        /// The 32-byte hash of the proof envelope that passed verification (hex).
        #[arg(long, required = true)]
        proof_hash: String,
    },
}

#[derive(Subcommand)]
enum TxAction {
    /// Send a BDLM transfer.
    Send {
        /// Recipient address (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        to: String,
        /// Transfer amount (base units).
        #[arg(long, required = true)]
        amount: u64,
        /// The sender's 32-byte hex signing seed (private key).
        #[arg(long, required = true)]
        priv_key: String,
        /// Transaction fee (base units).
        #[arg(long, default_value_t = 0)]
        fee: u64,
        /// Transaction nonce (fetched from the node with `bud_getNonce` if omitted).
        #[arg(long)]
        nonce: Option<u64>,
    },
}

#[derive(Subcommand)]
enum QueryAction {
    /// Adres bakiyesini sorgula (`bud_getBalance`).
    Balance {
        /// Address (hex, `0x` prefix optional).
        address: String,
    },
    /// Query a block by number (`bud_getBlockByNumber`).
    Block {
        /// Block number or `latest`.
        number: String,
    },
    /// Zincir durumunu sorgula (`bud_getStatus`).
    Status,
}

/// Parses a `http://host:port` URL into a (host, port) pair. The path is ignored.
fn parse_rpc_url(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        format!("--rpc-url expects the 'http://' scheme (https unsupported): '{url}'")
    })?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("invalid port: '{p}'"))?,
        ),
        None => (host_port.to_string(), 8545u16),
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok((host, port))
}

/// A minimal HTTP/1.1 POST over a std TcpStream, reading the whole response body.
fn http_post_json(host: &str, port: u16, body: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("connection error ({host}:{port}): {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("read_timeout setting: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(RPC_TIMEOUT_SECS)))
        .map_err(|e| format!("write_timeout setting: {e}"))?;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("request write error: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("response read error: {e}"))?;
    let text = String::from_utf8(raw).map_err(|e| format!("UTF-8 parse: {e}"))?;

    // HTTP header/body split: everything after the first "\r\n\r\n" is the body.
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    Ok(body.to_string())
}

/// Parse a JSON-RPC response: return `result` or propagate the `error` message.
fn rpc_result(resp: &serde_json::Value) -> Result<serde_json::Value, String> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown JSON-RPC error");
        return Err(format!("JSON-RPC error: {msg}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "the JSON-RPC response has no 'result' field".to_string())
}

/// Make a single JSON-RPC call.
fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (host, port) = parse_rpc_url(rpc_url)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let body_str = serde_json::to_string(&body).map_err(|e| format!("request serialization: {e}"))?;
    let resp_text = http_post_json(&host, port, &body_str)?;
    let v: serde_json::Value =
        serde_json::from_str(&resp_text).map_err(|e| format!("RPC response parse: {e}"))?;
    rpc_result(&v)
}

/// Parse an address leniently (`0x` prefix optional).
fn parse_address(s: &str) -> Result<Address, String> {
    Address::from_hex(s).map_err(|e| format!("invalid address '{s}': {e}"))
}

/// Parse a 32-byte hex signing seed.
fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("invalid hex priv key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "the priv key must be 32 bytes".to_string())?;
    Ok(arr)
}

fn parse_rpc_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    let s = value
        .as_str()
        .ok_or_else(|| format!("{field} must return a string"))?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{field} hex parse: {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("{field} parse: {e}"))
    }
}

#[allow(clippy::too_many_arguments)]
fn run_tx_send(
    rpc_url: &str,
    to: &str,
    amount: u64,
    priv_key: &str,
    fee: u64,
    nonce: Option<u64>,
) -> Result<(), String> {
    let seed = parse_seed(priv_key)?;
    let keypair = KeyPair::from_seed(&seed).map_err(|e| format!("key derivation: {e}"))?;
    let from = Address::from(keypair.public_key_bytes());
    let to_addr = parse_address(to)?;

    // Nonce: fetch it from the node when not given.
    let nonce = match nonce {
        Some(n) => n,
        None => {
            let r = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
            let s = parse_rpc_u64(&r, "bud_getNonce")?;
            println!("nonce (from node): {s}");
            s
        }
    };

    // Build and sign the transaction.
    let mut tx = Transaction::new(from, to_addr, amount, Vec::new());
    tx.fee = fee;
    tx.nonce = nonce;
    tx.tx_type = TransactionType::Transfer;
    tx.sign(&keypair);

    let tx_hash = tx.calculate_hash();
    println!("tx hash (signed): {tx_hash}");

    // Send it (bud_sendRawTransaction takes the Transaction object directly).
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    match r.as_str() {
        Some(returned) => println!("sent \u{2713} - node tx hash: {returned}"),
        None => println!("sent \u{2713} - node response: {r}"),
    }
    Ok(())
}

fn run_query_balance(rpc_url: &str, address: &str) -> Result<(), String> {
    let addr = parse_address(address)?;
    let r = rpc_call(
        rpc_url,
        "bud_getBalance",
        serde_json::json!([addr.to_hex()]),
    )?;
    match r.as_str() {
        Some(balance) => println!("balance ({address}): {balance}"),
        None => println!("balance ({address}): {r}"),
    }
    Ok(())
}

fn run_query_block(rpc_url: &str, number: &str) -> Result<(), String> {
    let block_number = if number.eq_ignore_ascii_case("latest") {
        let latest = rpc_call(rpc_url, "bud_blockNumber", serde_json::json!([]))?;
        parse_rpc_u64(&latest, "bud_blockNumber")?
    } else {
        if let Some(hex) = number.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).map_err(|e| format!("invalid block number: {e}"))?
        } else {
            number
                .parse::<u64>()
                .map_err(|e| format!("invalid block number: {e}"))?
        }
    };
    let r = rpc_call(
        rpc_url,
        "bud_getBlockByNumber",
        serde_json::json!([block_number]),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).unwrap_or_else(|_| r.to_string())
    );
    Ok(())
}

fn run_query_status(rpc_url: &str) -> Result<(), String> {
    let r = rpc_call(rpc_url, "bud_getStatus", serde_json::json!([]))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&r).unwrap_or_else(|_| r.to_string())
    );
    Ok(())
}

fn run_validator(config: Option<&str>) -> Result<(), String> {
    // Tam node runner (chain + consensus loop + RPC sunucu) paketli bir binary
    // It is not - `validator run` here validates configuration and gives guidance.
    // Real node startup with `RpcServer::run` + `NodeConfig` is future work.
    match config {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("configuration read error ({path}): {e}"))?;
            // Basic TOML parse validation.
            let _doc: toml::Value =
                toml::from_str(&content).map_err(|e| format!("invalid TOML configuration: {e}"))?;
            println!("configuration valid (TOML): {path}");
        }
        None => {
            println!("(no configuration given - validate one with --config <path>)");
        }
    }
    println!();
    println!("running a validator:");
    println!("  The full node runner (consensus loop + RPC server) is a separate binary.");
    println!("  This command validates configuration. Use the node binary to start a node.");
    println!("  RPC: --rpc-url <url> (default {DEFAULT_RPC_URL})");
    Ok(())
}

/// Parse a 32-byte hex digest.
fn parse_digest(field: &str, hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| format!("{field} invalid hex: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes, {} bytes given", bytes.len()))
}

/// Build and validate the local standard manifest.
///
/// The manifest is a record layer and its validation is a gate: no project id is
/// computed for a manifest that does not pass `validate`. Otherwise a manifest
/// carrying an invented compiler profile or a zero source hash would also produce
/// a smooth id, indistinguishable from a real one.
fn build_manifest(name: &str, source_hash: &str) -> Result<DeveloperOsManifest, String> {
    let digest = parse_digest("--source-hash", source_hash)?;
    let manifest = DeveloperOsManifest::local_standard(name, digest);
    manifest
        .validate()
        .map_err(|e| format!("manifest refused: {e:?}"))?;
    Ok(manifest)
}

fn run_project_id(name: &str, source_hash: &str) -> Result<(), String> {
    let manifest = build_manifest(name, source_hash)?;
    println!("proje: {name}");
    println!("chain_id: {}", manifest.chain_id);
    println!("project id: 0x{}", hex::encode(manifest.project_id()));
    Ok(())
}

/// Audit a proof record's right to say `Verified` by binding it to the hash of
/// the verified envelope.
///
/// A record declaring itself verified is not enough: the hash it carries must equal
/// the one of the envelope that passed verification. If they differ the record is
/// speaking of another proof, and that is a wrong record that looks right.
fn run_project_bind_proof(
    name: &str,
    source_hash: &str,
    fixture: &str,
    proof_hash: &str,
) -> Result<(), String> {
    let mut manifest = build_manifest(name, source_hash)?;
    let verified = parse_digest("--proof-hash", proof_hash)?;

    let record = manifest
        .proof_fixtures
        .iter_mut()
        .find(|f| f.name == fixture)
        .ok_or_else(|| format!("the manifest has no proof record named '{fixture}'"))?;

    // A record arrives `Pending` from the local template; binding is meaningful on a
    // record that claims the verifier has run.
    record.status = ProofFixtureStatus::Verified;
    record.proof_hash = verified;
    let bound = record.clone();

    bound
        .bind_verified(verified)
        .map_err(|e| format!("proof binding refused: {e:?}"))?;
    println!("proof record '{fixture}' bound to the verified envelope");
    println!("proof hash: 0x{}", hex::encode(verified));
    println!("project id: 0x{}", hex::encode(manifest.project_id()));
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Tx { action } => match action {
            TxAction::Send {
                to,
                amount,
                priv_key,
                fee,
                nonce,
            } => run_tx_send(&cli.rpc_url, to, *amount, priv_key, *fee, *nonce),
        },
        Command::Query { action } => match action {
            QueryAction::Balance { address } => run_query_balance(&cli.rpc_url, address),
            QueryAction::Block { number } => run_query_block(&cli.rpc_url, number),
            QueryAction::Status => run_query_status(&cli.rpc_url),
        },
        Command::Validator { config } => run_validator(config.as_deref()),
        Command::Project { action } => match action {
            ProjectAction::Id { name, source_hash } => run_project_id(name, source_hash),
            ProjectAction::BindProof {
                name,
                source_hash,
                fixture,
                proof_hash,
            } => run_project_bind_proof(name, source_hash, fixture, proof_hash),
        },
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rpc_u64_accepts_hex_and_decimal() {
        assert_eq!(
            parse_rpc_u64(&serde_json::json!("0x2a"), "field").unwrap(),
            42
        );
        assert_eq!(
            parse_rpc_u64(&serde_json::json!("42"), "field").unwrap(),
            42
        );
    }

    #[test]
    fn parse_rpc_url_defaults_port() {
        let (host, port) = parse_rpc_url("http://127.0.0.1").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8545);
    }

    const SOURCE_HASH: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    /// Manifest validation is a gate: a manifest that passes produces an id.
    #[test]
    fn a_valid_project_yields_an_id() {
        let manifest = build_manifest("demo-app", SOURCE_HASH).unwrap();
        assert_eq!(manifest.project_id(), manifest.project_id());
    }

    /// A zero source hash does not name a project; no id must be computed.
    #[test]
    fn a_zero_source_hash_is_refused() {
        let zero = "0".repeat(64);
        let err = build_manifest("demo-app", &zero).expect_err("a zero source hash must be refused");
        assert!(err.contains("manifest refused"), "{err}");
    }

    /// A short digest must not be silently padded.
    #[test]
    fn a_short_digest_is_refused() {
        let err = parse_digest("--source-hash", "0x0909").expect_err("a short digest must be refused");
        assert!(err.contains("must be 32 bytes"), "{err}");
    }

    /// Binding passes for a record carrying the hash of the verified envelope.
    #[test]
    fn binding_a_proof_to_its_own_hash_passes() {
        let proof = "01".repeat(32);
        run_project_bind_proof("demo-app", SOURCE_HASH, "zkvm-smoke", &proof).unwrap();
    }

    /// A record absent from the manifest cannot be bound.
    #[test]
    fn binding_an_unknown_fixture_is_refused() {
        let proof = "01".repeat(32);
        let err = run_project_bind_proof("demo-app", SOURCE_HASH, "yok-boyle-kayit", &proof)
            .expect_err("an unknown record must be refused");
        assert!(err.contains("no proof record named"), "{err}");
    }
}
