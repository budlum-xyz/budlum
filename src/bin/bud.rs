//! Budlum CLI - send transactions, query state, validator guidance.
//!
//! This binary talks to the Universal Settlement Layer core (`budlum_core`):
//! build and send a signed transaction (`tx send`), read-only queries
//! (`query balance`/`query block`/`query status`), and guidance for running
//! a validator (`validator run`).
//!
//! The BudZKVM toolchain (`budzero/bud-cli`) is a separate workspace; this binary
//! is for chain interaction and uses the core types directly.
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

/// Ceiling for one RPC response body. CLI answers are kilobytes; a hostile
/// or broken endpoint that streams forever must hit a wall, not the heap.
const MAX_RPC_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "bud",
    author,
    version,
    about = "Budlum CLI - send txs, query state, validator guidance"
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
    /// Validator keys, ceremony record and joining (without a subcommand:
    /// guidance for running a node).
    Validator {
        /// A configuration file such as `config/mainnet.toml` (validate + summarize).
        #[arg(short, long)]
        config: Option<String>,
        #[command(subcommand)]
        action: Option<ValidatorAction>,
    },
    /// The genesis ceremony.
    Genesis {
        #[command(subcommand)]
        action: GenesisAction,
    },
    /// Node identity and seed records.
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// The V5 (ML-DSA-87) wallet: 24-word mnemonic, password-sealed key file.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Bond stake from a V5 wallet (`Stake`).
    Stake {
        #[command(flatten)]
        signer: V5Signer,
        /// Stake to bond, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Start unbonding stake of a V5 wallet (`Unstake`).
    Unstake {
        #[command(flatten)]
        signer: V5Signer,
        /// Stake to unbond, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Delegate stake from a V5 wallet to a validator (`Delegate`). The
    /// delegated stake carries the validator's slashing risk and earns only
    /// the rewards the chain actually pays; there is no fixed yield.
    Delegate {
        #[command(flatten)]
        signer: V5Signer,
        /// The validator's address (hex, `0x` prefix optional).
        #[arg(long, required = true)]
        validator: String,
        /// Stake to delegate, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Answer an open AI request as an AI verifier (`AiInferenceResult`).
    /// The testnet harness (`budlum-tools ai-test-verifier`) drives this;
    /// its answers are attestation only.
    AiAnswer {
        #[command(flatten)]
        signer: V5Signer,
        /// The request id (32 bytes hex).
        #[arg(long, required = true)]
        request_id: String,
        /// The output commitment (32 bytes hex).
        #[arg(long, required = true)]
        output_commitment: String,
    },
    /// Start unbonding a delegation (`Undelegate`); it stays slashable until
    /// the exit matures.
    Undelegate {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
        /// Stake to undelegate, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Withdraw matured delegation exits back to the wallet
    /// (`WithdrawDelegation`).
    WithdrawDelegation {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
    },
    /// Move a delegation from one validator to another (`Redelegate`); no
    /// unbonding round trip, the voting weight follows the position.
    Redelegate {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        from_validator: String,
        #[arg(long, required = true)]
        to_validator: String,
        /// Stake to move, in whole BUD.
        #[arg(long, required = true)]
        amount_bud: u64,
    },
    /// Claim the delegator rewards an epoch close credited
    /// (`ClaimRewards`).
    ClaimRewards {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        validator: String,
    },
    /// Consensus domains: register one in a block.
    Domain {
        #[command(subcommand)]
        action: DomainAction,
    },
    /// A Budlum project (`budlum.toml`): scaffold it, read it, check it
    /// against a node.
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Graft: use an application of another network from Budlum, in BUD.
    Graft {
        #[command(subcommand)]
        action: GraftAction,
    },
    /// `.bud` names.
    Bns {
        #[command(subcommand)]
        action: BnsAction,
    },
    /// Local development project manifest (validate + project id).
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
}

#[derive(Subcommand)]
enum ValidatorAction {
    /// Generate a validator key set and write the public ceremony record.
    ///
    /// The key file holds plaintext key material (mode 0600); mainnet
    /// refuses it. The record holds only public keys and the proof of
    /// possession bound to `--chain-id` and the validator address.
    Init {
        /// Where to write the new key set. An existing file is never overwritten.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Where to write the public operator record (JSON).
        #[arg(long, required = true)]
        record_out: std::path::PathBuf,
        /// The chain the proof of possession is bound to (testnet: 45261).
        #[arg(long, default_value_t = 45_261)]
        chain_id: u64,
        /// A display name for the record.
        #[arg(long, default_value = "")]
        moniker: String,
    },
    /// Bond stake and register the consensus keys: the validator becomes
    /// active at the next epoch.
    Join {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Stake to bond, in whole BUD (the network's minimum at least).
        #[arg(long, required = true)]
        stake_bud: u64,
        /// Fee for each of the two transactions (base units).
        #[arg(long, default_value_t = 1_000)]
        fee: u64,
    },
    /// Register this validator's Filiz Chain (`RegisterFiliz`). The node
    /// must run with the same seed file in `BUDLUM_FILIZ_SEED_FILE`; the
    /// chain becomes its leader-election proof three epochs later.
    Filiz {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// The Filiz seed: 64 hex characters, mode 0600.
        #[arg(long, required = true)]
        seed_file: std::path::PathBuf,
        /// Fee (base units).
        #[arg(long, default_value_t = 1_000)]
        fee: u64,
    },
    /// Set the commission this validator takes from its delegators'
    /// rewards (`SetValidatorCommission`), in parts per million. The chain
    /// caps it and limits how fast it may change per epoch.
    Commission {
        /// The key set `bud validator init` wrote.
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        /// Commission in parts per million (100000 = 10 percent).
        #[arg(long, required = true)]
        rate_ppm: u32,
        #[arg(long, default_value_t = 1_000)]
        fee: u64,
    },
}

#[derive(Subcommand)]
enum GenesisAction {
    /// Assemble a ceremony genesis from the operators' public records.
    Assemble {
        /// `testnet`, `mainnet` or `devnet`.
        #[arg(long, default_value = "testnet")]
        network: String,
        /// A directory of operator records (`*.json`, from `bud validator init`).
        #[arg(long, required = true)]
        operators: std::path::PathBuf,
        /// Community destination; on the testnet this is the faucet account.
        #[arg(long, required = true)]
        community: String,
        #[arg(long, required = true)]
        liquidity: String,
        /// Ecosystem destination; the genesis validator stake is drawn from it.
        #[arg(long, required = true)]
        ecosystem: String,
        #[arg(long, required = true)]
        team: String,
        #[arg(long, required = true)]
        burn_reserve: String,
        /// Genesis timestamp in milliseconds (the template's when absent).
        #[arg(long)]
        timestamp_ms: Option<u128>,
        /// An extra genesis balance, `<address>:<base units>`; repeatable.
        /// A tokenomics genesis has no room for one (fixed supply).
        #[arg(long)]
        fund: Vec<String>,
        /// Where to write the genesis file.
        #[arg(long, required = true)]
        out: std::path::PathBuf,
    },
}

/// Where a V5 command finds its key and its password.
#[derive(clap::Args)]
struct V5Signer {
    /// The wallet key file (`bud wallet create` or `import`).
    #[arg(long, required = true)]
    key_file: std::path::PathBuf,
    /// A file holding the wallet password; else `BUD_WALLET_PASSWORD`.
    #[arg(long)]
    password_file: Option<std::path::PathBuf>,
    /// Fee (base units).
    #[arg(long, default_value_t = 1_000)]
    fee: u64,
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a wallet: print its 24 words once and seal it in a key file.
    Create {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        password_file: Option<std::path::PathBuf>,
    },
    /// Import a 24-word mnemonic read from standard input (never from argv).
    Import {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        password_file: Option<std::path::PathBuf>,
    },
    /// Print the address a key file holds (no password needed).
    Address {
        #[arg(long, required = true)]
        key_file: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum DomainAction {
    /// Register a proof-of-work domain (header-chain finality) with the
    /// wallet as its operator; the operator bond is escrowed from it.
    RegisterPow {
        #[command(flatten)]
        signer: V5Signer,
        /// The domain id to claim.
        #[arg(long, required = true)]
        id: u32,
        /// The domain's own chain id.
        #[arg(long, required = true)]
        chain_id: u64,
        /// Confirmations the header chain must carry.
        #[arg(long, default_value_t = 6)]
        min_confirmations: u64,
    },
    /// Run an adapter's admission self-test offline: the golden sample must
    /// verify and every fault probe must be refused. Exits non-zero when
    /// the adapter would not be admitted.
    Selftest {
        /// Adapter family. `zkvm` is the BudZKVM proof adapter.
        #[arg(long, default_value = "zkvm")]
        adapter: String,
        /// The external network label the adapter serves.
        #[arg(long, required = true)]
        network: String,
        /// The golden evidence sample (JSON `RawConsensusEvidence`).
        #[arg(long, required = true)]
        golden: std::path::PathBuf,
        /// Program hash the proof must commit to (hex, 32 bytes).
        #[arg(long)]
        program_hash: Option<String>,
        /// Chain id the proof must commit to.
        #[arg(long)]
        chain_id: Option<u64>,
        /// The target's current time for the verification policy.
        #[arg(long, default_value_t = 0)]
        now: u64,
    },
}

#[derive(Subcommand)]
enum GraftAction {
    /// Print the Graft id and the mirror account of an application.
    Id {
        #[arg(long, required = true)]
        domain: u32,
        /// The application's identifier on its own network (hex).
        #[arg(long, required = true)]
        origin_app: String,
    },
    /// Register an origin application (permissionless; names no owner).
    Register {
        #[command(flatten)]
        signer: V5Signer,
        /// The origin domain id.
        #[arg(long, required = true)]
        domain: u32,
        /// The application's identifier on its own network (hex).
        #[arg(long, required = true)]
        origin_app: String,
        /// The B.U.D. content id of the application's metadata (hex).
        #[arg(long, required = true)]
        manifest: String,
    },
    /// Pay an application in BUD.
    Pay {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        /// Amount in base units.
        #[arg(long, required = true)]
        amount: u64,
        /// The recipient on the origin network (hex).
        #[arg(long, required = true)]
        origin_recipient: String,
        /// A 32-byte memo hash (hex); zero when absent.
        #[arg(long)]
        memo_hash: Option<String>,
    },
    /// Ask a solver to make a call on the origin network; escrows
    /// `--max-payment`.
    Intent {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        /// Hash of the call data (hex).
        #[arg(long, required = true)]
        call_hash: String,
        /// Origin-chain value the call carries.
        #[arg(long, default_value_t = 0)]
        value: u64,
        /// The most BUD (base units) the call may cost in total.
        #[arg(long, required = true)]
        max_payment: u64,
        #[arg(long, required = true)]
        solver_fee_cap: u64,
        /// The application's price for the service.
        #[arg(long, default_value_t = 0)]
        service_price: u64,
        /// The beneficiary on the origin network (hex).
        #[arg(long, required = true)]
        beneficiary: String,
        /// Deadline block; the genesis default when absent.
        #[arg(long, default_value_t = 0)]
        deadline_block: u64,
    },
    /// Refund an expired intent.
    Refund {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
    },
    /// Bid on an intent (needs an active RELAYER bond).
    Bid {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
        #[arg(long, required = true)]
        cost: u64,
        #[arg(long, required = true)]
        fee: u64,
    },
    /// Award the cheapest bid; only the intent owner can do this.
    Award {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
    },
    /// Claim an application for a payout with an anchored claim event
    /// (a `RelayerExternalResult` JSON file).
    Claim {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        #[arg(long, required = true)]
        payout: String,
        #[arg(long, required = true)]
        evidence: std::path::PathBuf,
    },
    /// Claim an externally owned application with its EIP-191 signature
    /// over `eoa_claim_hash` (docs/GRAFT.md, section 4).
    ClaimSigned {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        graft_id: String,
        #[arg(long, required = true)]
        payout: String,
        /// Last block the signature is valid at.
        #[arg(long, required = true)]
        valid_until_block: u64,
        /// The 65-byte r || s || v signature (hex).
        #[arg(long, required = true)]
        signature: String,
    },
    /// Collect a bid with an anchored fulfilment event (JSON file).
    Fulfill {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        intent_id: String,
        #[arg(long, required = true)]
        evidence: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum BnsAction {
    /// Register a `.bud` name to the wallet's address.
    Register {
        #[command(flatten)]
        signer: V5Signer,
        /// The name, e.g. `alice.bud`.
        #[arg(long, required = true)]
        name: String,
        /// Registration length in blocks.
        #[arg(long, required = true)]
        duration: u64,
    },
    /// Extend a live `.bud` name from its existing expiry.
    Renew {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// Additional registration length in blocks.
        #[arg(long, required = true)]
        duration: u64,
    },
    /// Transfer a live `.bud` name to another address.
    Transfer {
        #[command(flatten)]
        signer: V5Signer,
        #[arg(long, required = true)]
        name: String,
        /// New owner's 32-byte address, with or without a 0x prefix.
        #[arg(long, required = true)]
        new_owner: String,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Create (or read) a P2P identity file and print the node's peer id,
    /// its bootnode multiaddr and the DNS seed record that names it.
    Identity {
        /// The identity file the node is started with (`p2p.identity_file`).
        #[arg(long, required = true)]
        identity_file: std::path::PathBuf,
        /// The public IPv4 address or DNS name peers dial.
        #[arg(long, required = true)]
        host: String,
        /// The P2P port (testnet: 5001).
        #[arg(long, default_value_t = 5001)]
        port: u16,
        /// The DNS seed name (`p2p.dns_seeds`) this node answers under.
        #[arg(long)]
        seed_domain: Option<String>,
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
enum DevAction {
    /// Write a `budlum.toml` for a new project (refuses to overwrite).
    Init {
        /// The project name.
        #[arg(long, required = true)]
        name: String,
        /// Where to write the file.
        #[arg(long, default_value = "budlum.toml")]
        path: std::path::PathBuf,
    },
    /// Read a `budlum.toml` and show what it says; with a reachable node,
    /// show the node's chain id and version beside it.
    Info {
        #[arg(long, default_value = "budlum.toml")]
        path: std::path::PathBuf,
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
        /// Path to a file holding the sender's 32-byte hex signing seed.
        ///
        /// The seed is never taken on the command line: `argv` is visible in
        /// the process list, shell history and any log that captures the
        /// invocation. Either this flag or the `BUD_PRIV_KEY` environment
        /// variable must supply it.
        #[arg(long)]
        priv_key_file: Option<std::path::PathBuf>,
        /// Transaction fee (base units).
        #[arg(long, default_value_t = 0)]
        fee: u64,
        /// Transaction nonce (fetched from the node with `bud_getNonce` if omitted).
        #[arg(long)]
        nonce: Option<u64>,
        /// A V5 wallet key file. With it the transfer is signed ML-DSA-87
        /// (V5, the default for new wallets); without it the retired V4
        /// Ed25519 seed (`--priv-key-file`) signs.
        #[arg(long, conflicts_with = "priv_key_file")]
        key_file: Option<std::path::PathBuf>,
        /// A file holding the wallet password; else `BUD_WALLET_PASSWORD`.
        #[arg(long, requires = "key_file")]
        password_file: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum QueryAction {
    /// Query an address balance (`bud_getBalance`).
    Balance {
        /// Address (hex, `0x` prefix optional).
        address: String,
    },
    /// Query a block by number (`bud_getBlockByNumber`).
    Block {
        /// Block number or `latest`.
        number: String,
    },
    /// Queries the chain status (`bud_getStatus`).
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
    let mut limited = stream.take(MAX_RPC_RESPONSE_BYTES + 1);
    limited
        .read_to_end(&mut raw)
        .map_err(|e| format!("response read error: {e}"))?;
    if raw.len() as u64 > MAX_RPC_RESPONSE_BYTES {
        return Err(format!(
            "response over {MAX_RPC_RESPONSE_BYTES} bytes refused"
        ));
    }
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
    let body_str =
        serde_json::to_string(&body).map_err(|e| format!("request serialization: {e}"))?;
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
/// The signing seed comes from a file (`--priv-key-file`) or from the
/// `BUD_PRIV_KEY` environment variable, in that order, never from `argv`.
fn load_priv_key(path: Option<&std::path::Path>) -> Result<String, String> {
    if let Some(path) = path {
        check_key_file_mode(path)?;
        return std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("cannot read priv key file {}: {e}", path.display()));
    }
    std::env::var("BUD_PRIV_KEY").map_err(|_| {
        String::from(
            "no signing seed: pass --priv-key-file <path> or set BUD_PRIV_KEY \
             (the seed is not accepted as a command-line argument)",
        )
    })
}

/// Refuse a seed file that group or others can read (Unix only).
///
/// A world-readable seed file is a leaked key; the user must `chmod 600` it.
#[cfg(unix)]
fn check_key_file_mode(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("cannot read priv key file {}: {e}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "priv key file {} has mode {:03o}; group and others must have no access \
             (chmod 600)",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_mode(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

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
        s.parse::<u64>().map_err(|e| format!("{field} parse: {e}"))
    }
}

/// Build an unsigned transfer bound to `chain_id`.
fn build_transfer(
    from: Address,
    to: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        to,
        amount,
        fee,
        nonce,
        Vec::new(),
        chain_id,
        TransactionType::Transfer,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_tx_send(
    rpc_url: &str,
    to: &str,
    amount: u64,
    priv_key_file: Option<&std::path::Path>,
    fee: u64,
    nonce: Option<u64>,
) -> Result<(), String> {
    let seed = parse_seed(&load_priv_key(priv_key_file)?)?;
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

    // The chain id comes from the node, so the signature is bound to the
    // network the node serves and never to a compiled-in default.
    let chain_id_value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    let chain_id = parse_rpc_u64(&chain_id_value, "bud_chainId")?;
    println!("chain id (from node): {chain_id}");

    // V4 is refused on mainnet: say so before a signature is spent.
    if chain_id
        == budlum_core::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
    {
        return Err(
            "the node serves mainnet, which refuses V4 Ed25519 transactions; sign with a \
             wallet key file (--key-file) instead"
                .into(),
        );
    }

    // Build and sign the transaction.
    let mut tx = build_transfer(from, to_addr, amount, fee, nonce, chain_id);
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
    // This is not a packaged full-node runner (chain + consensus loop + RPC
    // server) - `validator run` here validates configuration and gives guidance.
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
    println!("project: {name}");
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
    // record that claims the verifier has run. The hash the record already
    // carries is what gets compared with the verified envelope; it is not
    // overwritten first, since a record rewritten to the supplied hash would
    // pass the comparison whatever it said before, and the mismatch check
    // would never fire.
    let mut candidate = record.clone();
    candidate.status = ProofFixtureStatus::Verified;
    candidate
        .bind_verified(verified)
        .map_err(|e| format!("proof binding refused: {e:?}"))?;
    *record = candidate;
    println!("proof record '{fixture}' bound to the verified envelope");
    println!("proof hash: 0x{}", hex::encode(verified));
    println!("project id: 0x{}", hex::encode(manifest.project_id()));
    Ok(())
}

/// `bud validator init`: generate keys, write them, write the record.
fn run_validator_init(
    key_file: &std::path::Path,
    record_out: &std::path::Path,
    chain_id: u64,
    moniker: &str,
) -> Result<(), String> {
    use budlum_core::core::chain_config::Network;
    if Network::from_chain_id(chain_id) == Some(Network::Mainnet) {
        return Err(
            "mainnet validator keys live in an HSM; this command writes a plaintext key file"
                .into(),
        );
    }
    if key_file.exists() {
        return Err(format!(
            "{} exists; a key file is never overwritten",
            key_file.display()
        ));
    }
    let keys = budlum_core::crypto::primitives::ValidatorKeys::generate()
        .map_err(|e| format!("key generation: {e}"))?;
    let record = budlum_core::chain::genesis_ceremony::OperatorRecord {
        validator: keys.address(),
        registration: keys
            .consensus_key_registration(chain_id)
            .map_err(|e| format!("consensus keys: {e}"))?,
        moniker: moniker.to_string(),
    };
    keys.save(key_file)
        .map_err(|e| format!("cannot write {}: {e}", key_file.display()))?;
    let json = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    std::fs::write(record_out, json + "\n")
        .map_err(|e| format!("cannot write {}: {e}", record_out.display()))?;
    println!("validator address: {}", record.validator.to_hex());
    println!("key file (secret, mode 0600): {}", key_file.display());
    println!("ceremony record (public): {}", record_out.display());
    println!("An Ethereum validator key is never reused here: these are new, Budlum-only keys.");
    Ok(())
}

/// Sign `tx_type` from `keys` against the node at `rpc_url` and send it.
/// How `send_signed` signs a validator transaction.
///
/// `Auto` picks V7 when the key set carries an ML-DSA-65 key - the form a
/// mainnet node admits from a validator registered with that key. `Enrol`
/// always signs the Ed25519-authorised legacy form: enrolment happens before
/// any ML-DSA-65 key is registered, and a V7 validator transaction from an
/// unregistered sender is refused at the binding gate (both halves of an
/// unregistered pair are chosen by whoever presents them).
#[derive(Clone, Copy)]
enum ValidatorSigning {
    Auto,
    Enrol,
}

fn send_signed(
    rpc_url: &str,
    keys: &budlum_core::crypto::primitives::ValidatorKeys,
    amount: u64,
    fee: u64,
    tx_type: TransactionType,
    signing: ValidatorSigning,
) -> Result<String, String> {
    let from = keys.address();
    let nonce_value = rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
    let nonce = parse_rpc_u64(&nonce_value, "bud_getNonce")?;
    let chain_id_value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    let chain_id = parse_rpc_u64(&chain_id_value, "bud_chainId")?;
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        amount,
        fee,
        nonce,
        Vec::new(),
        chain_id,
        tx_type,
    );
    // A key set with an ML-DSA-65 key signs the V7 validator form,
    // the only one a mainnet node admits; a legacy set signs V4. Enrolment
    // always signs V4: the V7 binding gate refuses a validator transaction
    // from a sender with no registered ML-DSA-65 key, which is exactly the
    // state `bud validator join` starts from.
    if keys.pq_key.is_some() && matches!(signing, ValidatorSigning::Auto) {
        use rand::Rng;
        let keypair = keys.composite_keypair().map_err(|e| e.to_string())?;
        let mut rnd = [0u8; 32];
        rand::rng().fill_bytes(&mut rnd);
        tx.sign_v7_validator(
            &budlum_core::crypto::scheme::SchemeStatusRegistry::genesis(),
            &keypair,
            &rnd,
        )?;
    } else {
        tx.sign(&keys.sig_key);
    }
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    Ok(r.as_str().map_or_else(|| r.to_string(), str::to_string))
}

/// `bud validator join`: `Stake`, then `RegisterConsensusKeys`.
fn run_validator_join(
    rpc_url: &str,
    key_file: &std::path::Path,
    stake_bud: u64,
    fee: u64,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let stake = stake_bud
        .checked_mul(budlum_core::tokenomics::BUD_UNIT)
        .ok_or("stake overflows the base unit")?;
    let chain_id_value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    let chain_id = parse_rpc_u64(&chain_id_value, "bud_chainId")?;
    let registration = keys
        .consensus_key_registration(chain_id)
        .map_err(|e| format!("consensus keys: {e}"))?;
    let staked = send_signed(
        rpc_url,
        &keys,
        stake,
        fee,
        TransactionType::Stake,
        ValidatorSigning::Enrol,
    )?;
    println!("stake sent: {staked}");
    let registered = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::RegisterConsensusKeys(registration),
        ValidatorSigning::Enrol,
    )?;
    println!("consensus keys sent: {registered}");
    println!(
        "validator {} is active from the next epoch once both are in a block",
        keys.address().to_hex()
    );
    Ok(())
}

/// `bud validator filiz`: build the chain the node will open and register
/// its top link.
fn run_validator_filiz(
    rpc_url: &str,
    key_file: &std::path::Path,
    seed_file: &std::path::Path,
    fee: u64,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    check_key_file_mode(seed_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let seed = budlum_core::consensus::filiz::read_seed_file(seed_file)?;
    let chain_id_value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    let chain_id = parse_rpc_u64(&chain_id_value, "bud_chainId")?;
    let chain = budlum_core::consensus::filiz::chain_for_network(keys.address().0, seed, chain_id)
        .map_err(|e| format!("Filiz chain: {e:?}"))?;
    let sent = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::RegisterFiliz {
            commitment: chain.commitment(),
            length: chain.length(),
        },
        ValidatorSigning::Auto,
    )?;
    println!("Filiz registration sent: {sent}");
    println!(
        "the chain ({} links) is the leader-election proof three epochs after it lands",
        chain.length()
    );
    Ok(())
}

/// `bud validator commission`: sign `SetValidatorCommission` with the
/// validator's own key set.
fn run_validator_commission(
    rpc_url: &str,
    key_file: &std::path::Path,
    rate_ppm: u32,
    fee: u64,
) -> Result<(), String> {
    check_key_file_mode(key_file)?;
    let keys = budlum_core::crypto::primitives::ValidatorKeys::load(key_file)
        .map_err(|e| format!("cannot load {}: {e}", key_file.display()))?;
    let sent = send_signed(
        rpc_url,
        &keys,
        0,
        fee,
        TransactionType::SetValidatorCommission {
            commission_ppm: rate_ppm,
        },
        ValidatorSigning::Auto,
    )?;
    println!("commission sent: {sent}");
    Ok(())
}

/// `bud delegate`, `bud undelegate` (with an amount) and
/// `bud withdraw-delegation` (without one).
fn run_delegation(
    rpc_url: &str,
    signer: &V5Signer,
    validator: &str,
    amount_bud: Option<u64>,
    bond: bool,
) -> Result<(), String> {
    let validator = parse_address(validator.strip_prefix("0x").unwrap_or(validator))?;
    let key = open_wallet(signer)?;
    let (tx_type, amount) = match amount_bud {
        Some(bud) => {
            let amount = bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the amount overflows the base unit")?;
            let tx_type = if bond {
                TransactionType::Delegate { validator }
            } else {
                TransactionType::Undelegate { validator }
            };
            (tx_type, amount)
        }
        None => (TransactionType::WithdrawDelegation { validator }, 0),
    };
    send_v5(
        rpc_url,
        &key,
        v5_template(tx_type, amount, signer.fee),
        None,
    )
}

/// `bud redelegate`: move a position to another validator.
fn run_redelegate(
    rpc_url: &str,
    signer: &V5Signer,
    from_validator: &str,
    to_validator: &str,
    amount_bud: u64,
) -> Result<(), String> {
    let from = parse_address(from_validator.strip_prefix("0x").unwrap_or(from_validator))?;
    let to = parse_address(to_validator.strip_prefix("0x").unwrap_or(to_validator))?;
    let amount = amount_bud
        .checked_mul(budlum_core::tokenomics::BUD_UNIT)
        .ok_or("the amount overflows the base unit")?;
    let key = open_wallet(signer)?;
    send_v5(
        rpc_url,
        &key,
        v5_template(
            TransactionType::Redelegate {
                from_validator: from,
                to_validator: to,
            },
            amount,
            signer.fee,
        ),
        None,
    )
}

/// `bud claim-rewards`: take the claimable delegator reward of one validator.
fn run_claim_rewards(rpc_url: &str, signer: &V5Signer, validator: &str) -> Result<(), String> {
    let validator = parse_address(validator.strip_prefix("0x").unwrap_or(validator))?;
    let key = open_wallet(signer)?;
    send_v5(
        rpc_url,
        &key,
        v5_template(TransactionType::ClaimRewards { validator }, 0, signer.fee),
        None,
    )
}

/// `bud ai-answer`: sign one AI verifier result.
fn run_ai_answer(
    rpc_url: &str,
    signer: &V5Signer,
    request_id: &str,
    output_commitment: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let latest = rpc_call(rpc_url, "bud_blockNumber", serde_json::json!([]))?;
    let height = parse_rpc_u64(&latest, "bud_blockNumber")?;
    let result = budlum_core::ai::types::AiInferenceResult {
        request_id: budlum_core::ai::types::AiRequestId(hex32(request_id, "request id")?),
        verifier: key.address(),
        output_commitment: hex32(output_commitment, "output commitment")?,
        output_ref: budlum_core::ai::types::BoundedBytes::try_new(Vec::new())?,
        result_nonce: height,
        signature: Vec::new(),
        submitted_at_block: height,
    };
    send_v5(
        rpc_url,
        &key,
        v5_template(TransactionType::AiInferenceResult(result), 0, signer.fee),
        None,
    )
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what} must be 32 bytes of hex"))
}

fn hex_bytes(text: &str, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
        .map_err(|e| format!("{what} is not hex: {e}"))
}

fn evidence_file(
    path: &std::path::Path,
) -> Result<Box<budlum_core::core::transaction::RelayerExternalResult>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&raw)
        .map(Box::new)
        .map_err(|e| format!("{} is not an external result: {e}", path.display()))
}

/// `bud domain register-pow`: a PoW domain with the header-chain adapter,
/// the wallet as operator.
fn run_domain_register_pow(
    rpc_url: &str,
    signer: &V5Signer,
    id: u32,
    chain_id: u64,
    min_confirmations: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let mut domain = budlum_core::domain::plugin::default_domain(
        id,
        budlum_core::domain::ConsensusKind::PoW,
        chain_id,
        budlum_core::domain::POW_HEADER_CHAIN_ADAPTER,
        min_confirmations,
    );
    domain.operator = Some(key.address());
    let tx_type = TransactionType::Settlement(
        budlum_core::settlement::domains::SettlementTx::RegisterDomain(Box::new(domain)),
    );
    send_v5(rpc_url, &key, v5_template(tx_type, 0, signer.fee), None)
}

/// `bud domain selftest`: the admission harness
/// (`cross_domain::external::admit`) run locally, so an adapter author sees
/// the report before bonding anything.
fn run_domain_selftest(
    adapter: &str,
    network: &str,
    golden: &std::path::Path,
    program_hash: Option<&str>,
    chain_id: Option<u64>,
    now: u64,
) -> Result<(), String> {
    use budlum_core::cross_domain::external::{
        admit, RawConsensusEvidence, VerificationPolicy, ZkVmFinalityAdapter,
    };
    let text = std::fs::read_to_string(golden)
        .map_err(|e| format!("cannot read {}: {e}", golden.display()))?;
    let sample: RawConsensusEvidence =
        serde_json::from_str(&text).map_err(|e| format!("golden sample: {e}"))?;
    let report = match adapter {
        "zkvm" => {
            let program_hash = match program_hash {
                Some(hex) => {
                    let bytes = hex_bytes(hex, "--program-hash")?;
                    Some(
                        <[u8; 32]>::try_from(bytes.as_slice())
                            .map_err(|_| "--program-hash must be 32 bytes".to_string())?,
                    )
                }
                None => None,
            };
            let adapter =
                ZkVmFinalityAdapter::new(network, program_hash, chain_id).with_golden(sample);
            admit(&adapter, &VerificationPolicy::proven(now))
        }
        other => return Err(format!("unknown adapter family: {other} (known: zkvm)")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| format!("report: {e}"))?
    );
    if report.admitted {
        Ok(())
    } else {
        Err(format!(
            "not admitted: golden sample verified = {}, {} of {} probes refused as required",
            report.golden_verified,
            report.passed(),
            report.probes.len()
        ))
    }
}

/// `bud graft ...`: build the Graft settlement transaction here and sign it
/// with the V5 wallet.
fn run_graft(rpc_url: &str, action: &GraftAction) -> Result<(), String> {
    use budlum_core::settlement::graft::GraftTx;
    let (signer, graft_tx) = match action {
        GraftAction::Id { domain, origin_app } => {
            let origin = hex_bytes(origin_app, "--origin-app")?;
            let id = budlum_core::settlement::graft::graft_id(*domain, &origin);
            println!("graft id: 0x{}", hex::encode(id));
            println!(
                "mirror account: 0x{}",
                budlum_core::settlement::graft::mirror_account(id).to_hex()
            );
            return Ok(());
        }
        GraftAction::Register {
            signer,
            domain,
            origin_app,
            manifest,
        } => (
            signer,
            GraftTx::Register {
                domain_key: *domain,
                origin_app: hex_bytes(origin_app, "--origin-app")?,
                manifest_hash: hex32(manifest, "--manifest")?,
            },
        ),
        GraftAction::Pay {
            signer,
            graft_id,
            amount,
            origin_recipient,
            memo_hash,
        } => (
            signer,
            GraftTx::Pay {
                graft_id: hex32(graft_id, "--graft-id")?,
                amount: *amount,
                memo_hash: memo_hash
                    .as_deref()
                    .map_or(Ok([0u8; 32]), |memo| hex32(memo, "--memo-hash"))?,
                origin_recipient: hex_bytes(origin_recipient, "--origin-recipient")?,
            },
        ),
        GraftAction::Intent {
            signer,
            graft_id,
            call_hash,
            value,
            max_payment,
            solver_fee_cap,
            service_price,
            beneficiary,
            deadline_block,
        } => (
            signer,
            GraftTx::OpenIntent {
                graft_id: hex32(graft_id, "--graft-id")?,
                call_hash: hex32(call_hash, "--call-hash")?,
                value: *value,
                max_payment: *max_payment,
                solver_fee_cap: *solver_fee_cap,
                service_price: *service_price,
                origin_beneficiary: hex_bytes(beneficiary, "--beneficiary")?,
                deadline_block: *deadline_block,
            },
        ),
        GraftAction::Refund { signer, intent_id } => (
            signer,
            GraftTx::Refund {
                intent_id: hex32(intent_id, "--intent-id")?,
            },
        ),
        GraftAction::Bid {
            signer,
            intent_id,
            cost,
            fee,
        } => (
            signer,
            GraftTx::Bid {
                intent_id: hex32(intent_id, "--intent-id")?,
                cost: *cost,
                fee: *fee,
            },
        ),
        GraftAction::Award { signer, intent_id } => (
            signer,
            GraftTx::Award {
                intent_id: hex32(intent_id, "--intent-id")?,
            },
        ),
        GraftAction::Claim {
            signer,
            graft_id,
            payout,
            evidence,
        } => (
            signer,
            GraftTx::Claim {
                graft_id: hex32(graft_id, "--graft-id")?,
                payout: parse_address(payout.strip_prefix("0x").unwrap_or(payout))?,
                evidence: evidence_file(evidence)?,
            },
        ),
        GraftAction::ClaimSigned {
            signer,
            graft_id,
            payout,
            valid_until_block,
            signature,
        } => (
            signer,
            GraftTx::ClaimBySignature {
                graft_id: hex32(graft_id, "--graft-id")?,
                payout: parse_address(payout.strip_prefix("0x").unwrap_or(payout))?,
                valid_until_block: *valid_until_block,
                signature: hex_bytes(signature, "--signature")?,
            },
        ),
        GraftAction::Fulfill {
            signer,
            intent_id,
            evidence,
        } => (
            signer,
            GraftTx::Fulfill {
                intent_id: hex32(intent_id, "--intent-id")?,
                evidence: evidence_file(evidence)?,
            },
        ),
    };
    let key = open_wallet(signer)?;
    let tx_type = TransactionType::Settlement(
        budlum_core::settlement::domains::SettlementTx::Graft(Box::new(graft_tx)),
    );
    send_v5(rpc_url, &key, v5_template(tx_type, 0, signer.fee), None)
}

/// `bud dev`: the project file is the schema `budlum_core::sdk` defines.
fn run_dev(rpc_url: &str, action: &DevAction) -> Result<(), String> {
    use budlum_core::sdk::BudlumToml;
    match action {
        DevAction::Init { name, path } => {
            if path.exists() {
                return Err(format!("{} exists; not overwriting it", path.display()));
            }
            let mut project = BudlumToml::default_template(name);
            project.project.budlum_version = Some(env!("CARGO_PKG_VERSION").to_string());
            project.save(path).map_err(|e| e.to_string())?;
            println!("wrote {}", path.display());
            Ok(())
        }
        DevAction::Info { path } => {
            let project = BudlumToml::load(path).map_err(|e| e.to_string())?;
            println!(
                "project: {} {}",
                project.project.name, project.project.version
            );
            match &project.project.budlum_version {
                Some(v) if v != env!("CARGO_PKG_VERSION") => println!(
                    "targets budlum {v}; this CLI is {}",
                    env!("CARGO_PKG_VERSION")
                ),
                Some(v) => println!("targets budlum {v}"),
                None => println!("names no budlum version"),
            }
            match rpc_call(rpc_url, "bud_chainId", serde_json::json!([])) {
                Ok(chain_id) => println!("node at {rpc_url}: chain id {chain_id}"),
                Err(e) => println!("node at {rpc_url} not reachable: {e}"),
            }
            Ok(())
        }
    }
}

/// `<address>:<amount>` of `--fund`.
fn parse_fund(entry: &str) -> Result<(Address, u64), String> {
    let (address, amount) = entry
        .split_once(':')
        .ok_or_else(|| format!("--fund '{entry}' is not <address>:<amount>"))?;
    let amount = amount
        .parse::<u64>()
        .map_err(|e| format!("--fund '{entry}': amount: {e}"))?;
    Ok((parse_address(address)?, amount))
}

/// `bud genesis assemble`: read the records, assemble, check, write.
fn run_genesis_assemble(
    network: &str,
    operators: &std::path::Path,
    destinations: [&str; 5],
    timestamp_ms: Option<u128>,
    fund: &[String],
    out: &std::path::Path,
) -> Result<(), String> {
    use budlum_core::chain::genesis_ceremony::{assemble, genesis_hash, CeremonyInputs};
    use budlum_core::core::chain_config::Network;
    let network = match network {
        "testnet" => Network::Testnet,
        "mainnet" => Network::Mainnet,
        // The local rehearsal (ops/docker-compose.yml) runs the same
        // ceremony on the devnet profile.
        "devnet" => Network::Devnet,
        other => {
            return Err(format!(
                "unknown network '{other}' (testnet, mainnet or devnet)"
            ))
        }
    };
    let mut paths: Vec<_> = std::fs::read_dir(operators)
        .map_err(|e| format!("cannot read {}: {e}", operators.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    let mut records = Vec::with_capacity(paths.len());
    for path in &paths {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        records.push(
            serde_json::from_str(&raw)
                .map_err(|e| format!("{} is not an operator record: {e}", path.display()))?,
        );
    }
    let [community, liquidity, ecosystem, team, burn_reserve] = destinations;
    let inputs = CeremonyInputs {
        operators: records,
        tokenomics_addresses: budlum_core::tokenomics::TokenomicsAddresses {
            community: parse_address(community)?,
            liquidity: parse_address(liquidity)?,
            ecosystem: parse_address(ecosystem)?,
            team: parse_address(team)?,
            burn_reserve: parse_address(burn_reserve)?,
        },
        timestamp_ms,
        allocations: fund
            .iter()
            .map(|entry| parse_fund(entry))
            .collect::<Result<_, _>>()?,
    };
    let genesis = assemble(network, inputs)?;
    let json = serde_json::to_string_pretty(&genesis).map_err(|e| e.to_string())?;
    std::fs::write(out, json + "\n").map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    println!("validators: {}", genesis.validators.len());
    println!("genesis file: {}", out.display());
    println!("genesis hash: {}", genesis_hash(&genesis));
    Ok(())
}

/// The wallet password: the first line of `--password-file`, else the
/// `BUD_WALLET_PASSWORD` environment variable. Never an argument.
fn wallet_password(file: Option<&std::path::Path>) -> Result<String, String> {
    let password = match file {
        Some(path) => {
            check_key_file_mode(path)?;
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        }
        None => std::env::var("BUD_WALLET_PASSWORD").map_err(|_| {
            String::from(
                "no wallet password: pass --password-file <path> or set BUD_WALLET_PASSWORD",
            )
        })?,
    };
    if password.chars().count() < 8 {
        return Err("the wallet password must have at least 8 characters".into());
    }
    Ok(password)
}

/// Write a key file that did not exist, owner-only.
fn write_new_key_file(
    path: &std::path::Path,
    file: &budlum_core::wallet::KeyFile,
) -> Result<(), String> {
    use std::io::Write as _;
    let json = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut handle = options.open(path).map_err(|e| {
        format!(
            "cannot create {} (a key file is never overwritten): {e}",
            path.display()
        )
    })?;
    handle
        .write_all(json.as_bytes())
        .and_then(|()| handle.write_all(b"\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn read_key_file(path: &std::path::Path) -> Result<budlum_core::wallet::KeyFile, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not a wallet key file: {e}", path.display()))
}

fn run_wallet_create(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<(), String> {
    use budlum_core::wallet::{
        generate_entropy, mnemonic_from_entropy, KeyFile, DEFAULT_KDF_ITERATIONS,
    };
    let password = wallet_password(password_file)?;
    let entropy = generate_entropy();
    let file =
        KeyFile::seal(&entropy, &password, DEFAULT_KDF_ITERATIONS).map_err(|e| e.to_string())?;
    write_new_key_file(key_file, &file)?;
    println!("address: 0x{}", file.address);
    println!(
        "key file (sealed with your password): {}",
        key_file.display()
    );
    println!();
    println!("Write these 24 words down, offline, in order. They are shown once and they");
    println!("are the only way to recover the wallet:");
    println!();
    println!("{}", mnemonic_from_entropy(&entropy));
    Ok(())
}

fn run_wallet_import(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<(), String> {
    use budlum_core::wallet::{entropy_from_mnemonic, KeyFile, DEFAULT_KDF_ITERATIONS};
    use std::io::BufRead as _;
    let password = wallet_password(password_file)?;
    eprintln!("Type the 24 words on one line and press enter:");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the mnemonic: {e}"))?;
    let entropy = entropy_from_mnemonic(line.trim()).map_err(|e| e.to_string())?;
    let file =
        KeyFile::seal(&entropy, &password, DEFAULT_KDF_ITERATIONS).map_err(|e| e.to_string())?;
    write_new_key_file(key_file, &file)?;
    println!("address: 0x{}", file.address);
    println!("key file: {}", key_file.display());
    Ok(())
}

use budlum_core::wallet::SigningKey as WalletKey;

/// Open a wallet: its keys.
fn open_wallet(signer: &V5Signer) -> Result<WalletKey, String> {
    open_wallet_file(&signer.key_file, signer.password_file.as_deref())
}

fn open_wallet_file(
    key_file: &std::path::Path,
    password_file: Option<&std::path::Path>,
) -> Result<WalletKey, String> {
    let file = read_key_file(key_file)?;
    let entropy = file
        .open(&wallet_password(password_file)?)
        .map_err(|e| e.to_string())?;
    WalletKey::from_entropy(&entropy, file.is_legacy()).map_err(|e| e.to_string())
}

/// Sign `tx` with the wallet (its sender, nonce and chain id from the node)
/// and send it. A V3 wallet signs V7; a legacy key signs V5.
fn send_v5(
    rpc_url: &str,
    key: &WalletKey,
    mut tx: Transaction,
    nonce: Option<u64>,
) -> Result<(), String> {
    let from = key.address();
    let chain_id_value = rpc_call(rpc_url, "bud_chainId", serde_json::json!([]))?;
    tx.from = from;
    tx.nonce = match nonce {
        Some(n) => n,
        None => {
            let nonce_value =
                rpc_call(rpc_url, "bud_getNonce", serde_json::json!([from.to_hex()]))?;
            parse_rpc_u64(&nonce_value, "bud_getNonce")?
        }
    };
    tx.chain_id = parse_rpc_u64(&chain_id_value, "bud_chainId")?;
    match key {
        WalletKey::V3(account) => {
            use rand::Rng;
            let mut rnd = [0u8; 32];
            rand::rng().fill_bytes(&mut rnd);
            tx.sign_v7(
                &budlum_core::crypto::scheme::SchemeStatusRegistry::genesis(),
                &account.signing,
                &account.recovery_public_key,
                &rnd,
            )?;
            println!("tx hash (signed, V7): {}", tx.hash);
        }
        WalletKey::V5(key) => {
            tx.sign_v5(key);
            println!("tx hash (signed, V5): {}", tx.hash);
        }
    }
    let r = rpc_call(rpc_url, "bud_sendRawTransaction", serde_json::json!([tx]))?;
    match r.as_str() {
        Some(returned) => println!("sent \u{2713} - node tx hash: {returned}"),
        None => println!("sent \u{2713} - node response: {r}"),
    }
    Ok(())
}

/// A header-only transaction of `tx_type` for `send_v5` to complete.
fn v5_template(tx_type: TransactionType, amount: u64, fee: u64) -> Transaction {
    Transaction::new_with_chain_id(
        Address::zero(),
        Address::zero(),
        amount,
        fee,
        0,
        Vec::new(),
        0,
        tx_type,
    )
}

/// The cost a `bud_bnsPrepare*` answer quotes. Only the number is taken from
/// the node: the transaction itself is built here, so a node that answers
/// with a different transaction type, recipient or payload cannot get it
/// signed. Consensus refuses a wrong cost, so a lying node can make the
/// transaction fail but not redirect it.
fn quoted_cost(prepared: &serde_json::Value, method: &str) -> Result<u64, String> {
    prepared
        .get("cost")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{method} returned no cost"))
}

fn send_bns(
    rpc_url: &str,
    signer: &V5Signer,
    key: &WalletKey,
    tx_type: TransactionType,
    amount: u64,
    data: Vec<u8>,
) -> Result<(), String> {
    let mut tx = v5_template(tx_type, amount, signer.fee);
    tx.data = data;
    send_v5(rpc_url, key, tx, None)
}

fn run_bns_register(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    duration: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareRegister",
        serde_json::json!([name, key.address().to_hex(), duration]),
    )?;
    let cost = quoted_cost(&prepared, "bud_bnsPrepareRegister")?;
    let data = bincode::serialize(&(name.to_string(), duration)).map_err(|e| e.to_string())?;
    send_bns(
        rpc_url,
        signer,
        &key,
        TransactionType::BnsRegister,
        cost,
        data,
    )
}

fn run_bns_renew(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    duration: u64,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let prepared = rpc_call(
        rpc_url,
        "bud_bnsPrepareRenew",
        serde_json::json!([name, key.address().to_hex(), duration]),
    )?;
    let cost = quoted_cost(&prepared, "bud_bnsPrepareRenew")?;
    let data = bincode::serialize(&(name.to_string(), duration)).map_err(|e| e.to_string())?;
    send_bns(rpc_url, signer, &key, TransactionType::BnsRenew, cost, data)
}

fn run_bns_transfer(
    rpc_url: &str,
    signer: &V5Signer,
    name: &str,
    new_owner: &str,
) -> Result<(), String> {
    let key = open_wallet(signer)?;
    let new_owner = parse_address(new_owner.strip_prefix("0x").unwrap_or(new_owner))?;
    if new_owner == Address::zero() {
        return Err("the new owner cannot be the zero address".into());
    }
    let data = bincode::serialize(&(name.to_string(), new_owner)).map_err(|e| e.to_string())?;
    send_bns(rpc_url, signer, &key, TransactionType::BnsTransfer, 0, data)
}

/// The multiaddr peers dial: `/ip4/...` for an address, `/dns4/...` for a
/// name.
fn bootnode_multiaddr(host: &str, port: u16, peer_id: &str) -> String {
    let proto = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else {
        "dns4"
    };
    format!("/{proto}/{host}/tcp/{port}/p2p/{peer_id}")
}

/// `bud node identity`: the node's identity and its seed records.
fn run_node_identity(
    identity_file: &std::path::Path,
    host: &str,
    port: u16,
    seed_domain: Option<&str>,
) -> Result<(), String> {
    let path = identity_file
        .to_str()
        .ok_or("the identity file path is not UTF-8")?;
    let keypair = budlum_core::network::node::load_or_generate_identity_key(Some(path));
    let peer_id = keypair.public().to_peer_id().to_string();
    let multiaddr = bootnode_multiaddr(host, port, &peer_id);
    println!("peer id: {peer_id}");
    println!("bootnode (config [p2p] bootnodes): \"{multiaddr}\"");
    if let Some(domain) = seed_domain {
        // `p2p.dns_seeds` names are resolved through their address records
        // (A/AAAA) and each address is dialled at the P2P port; the node does
        // not read libp2p `_dnsaddr` TXT records.
        if host.parse::<std::net::IpAddr>().is_ok() {
            println!(
                "DNS seed record: {domain} A {host}   (config [p2p] dns_seeds = [\"{domain}\"])"
            );
        } else {
            println!("DNS seed record: {domain} CNAME {host}   (config [p2p] dns_seeds = [\"{domain}\"])");
        }
    }
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Tx { action } => match action {
            TxAction::Send {
                to,
                amount,
                priv_key_file: _,
                fee,
                nonce,
                key_file: Some(key_file),
                password_file,
            } => open_wallet_file(key_file, password_file.as_deref()).and_then(|key| {
                let tx = build_transfer(Address::zero(), parse_address(to)?, *amount, *fee, 0, 0);
                send_v5(&cli.rpc_url, &key, tx, *nonce)
            }),
            TxAction::Send {
                to,
                amount,
                priv_key_file,
                fee,
                nonce,
                key_file: None,
                password_file: _,
            } => run_tx_send(
                &cli.rpc_url,
                to,
                *amount,
                priv_key_file.as_deref(),
                *fee,
                *nonce,
            ),
        },
        Command::Query { action } => match action {
            QueryAction::Balance { address } => run_query_balance(&cli.rpc_url, address),
            QueryAction::Block { number } => run_query_block(&cli.rpc_url, number),
            QueryAction::Status => run_query_status(&cli.rpc_url),
        },
        Command::Validator { config, action } => match action {
            None => run_validator(config.as_deref()),
            Some(ValidatorAction::Init {
                key_file,
                record_out,
                chain_id,
                moniker,
            }) => run_validator_init(key_file, record_out, *chain_id, moniker),
            Some(ValidatorAction::Join {
                key_file,
                stake_bud,
                fee,
            }) => run_validator_join(&cli.rpc_url, key_file, *stake_bud, *fee),
            Some(ValidatorAction::Commission {
                key_file,
                rate_ppm,
                fee,
            }) => run_validator_commission(&cli.rpc_url, key_file, *rate_ppm, *fee),
            Some(ValidatorAction::Filiz {
                key_file,
                seed_file,
                fee,
            }) => run_validator_filiz(&cli.rpc_url, key_file, seed_file, *fee),
        },
        Command::Wallet { action } => match action {
            WalletAction::Create {
                key_file,
                password_file,
            } => run_wallet_create(key_file, password_file.as_deref()),
            WalletAction::Import {
                key_file,
                password_file,
            } => run_wallet_import(key_file, password_file.as_deref()),
            WalletAction::Address { key_file } => read_key_file(key_file).map(|file| {
                println!("0x{}", file.address);
            }),
        },
        Command::Stake { signer, amount_bud } => open_wallet(signer).and_then(|key| {
            let amount = amount_bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the stake overflows the base unit")?;
            send_v5(
                &cli.rpc_url,
                &key,
                v5_template(TransactionType::Stake, amount, signer.fee),
                None,
            )
        }),
        Command::Unstake { signer, amount_bud } => open_wallet(signer).and_then(|key| {
            let amount = amount_bud
                .checked_mul(budlum_core::tokenomics::BUD_UNIT)
                .ok_or("the amount overflows the base unit")?;
            send_v5(
                &cli.rpc_url,
                &key,
                v5_template(TransactionType::Unstake, amount, signer.fee),
                None,
            )
        }),
        Command::Delegate {
            signer,
            validator,
            amount_bud,
        } => run_delegation(&cli.rpc_url, signer, validator, Some(*amount_bud), true),
        Command::Undelegate {
            signer,
            validator,
            amount_bud,
        } => run_delegation(&cli.rpc_url, signer, validator, Some(*amount_bud), false),
        Command::AiAnswer {
            signer,
            request_id,
            output_commitment,
        } => run_ai_answer(&cli.rpc_url, signer, request_id, output_commitment),
        Command::WithdrawDelegation { signer, validator } => {
            run_delegation(&cli.rpc_url, signer, validator, None, false)
        }
        Command::Redelegate {
            signer,
            from_validator,
            to_validator,
            amount_bud,
        } => run_redelegate(
            &cli.rpc_url,
            signer,
            from_validator,
            to_validator,
            *amount_bud,
        ),
        Command::ClaimRewards { signer, validator } => {
            run_claim_rewards(&cli.rpc_url, signer, validator)
        }
        Command::Domain { action } => match action {
            DomainAction::RegisterPow {
                signer,
                id,
                chain_id,
                min_confirmations,
            } => run_domain_register_pow(&cli.rpc_url, signer, *id, *chain_id, *min_confirmations),
            DomainAction::Selftest {
                adapter,
                network,
                golden,
                program_hash,
                chain_id,
                now,
            } => run_domain_selftest(
                adapter,
                network,
                golden,
                program_hash.as_deref(),
                *chain_id,
                *now,
            ),
        },
        Command::Dev { action } => run_dev(&cli.rpc_url, action),
        Command::Graft { action } => run_graft(&cli.rpc_url, action),
        Command::Bns { action } => match action {
            BnsAction::Register {
                signer,
                name,
                duration,
            } => run_bns_register(&cli.rpc_url, signer, name, *duration),
            BnsAction::Renew {
                signer,
                name,
                duration,
            } => run_bns_renew(&cli.rpc_url, signer, name, *duration),
            BnsAction::Transfer {
                signer,
                name,
                new_owner,
            } => run_bns_transfer(&cli.rpc_url, signer, name, new_owner),
        },
        Command::Node { action } => match action {
            NodeAction::Identity {
                identity_file,
                host,
                port,
                seed_domain,
            } => run_node_identity(identity_file, host, *port, seed_domain.as_deref()),
        },
        Command::Genesis { action } => match action {
            GenesisAction::Assemble {
                network,
                operators,
                community,
                liquidity,
                ecosystem,
                team,
                burn_reserve,
                timestamp_ms,
                fund,
                out,
            } => run_genesis_assemble(
                network,
                operators,
                [community, liquidity, ecosystem, team, burn_reserve],
                *timestamp_ms,
                fund,
                out,
            ),
        },
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
    fn delegation_commands_parse() {
        let validator = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "bud",
            "delegate",
            "--key-file",
            "w.key",
            "--validator",
            &validator,
            "--amount-bud",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Delegate { amount_bud: 5, .. }
        ));
        let cli = Cli::try_parse_from([
            "bud",
            "withdraw-delegation",
            "--key-file",
            "w.key",
            "--validator",
            &validator,
        ])
        .unwrap();
        assert!(matches!(cli.command, Command::WithdrawDelegation { .. }));
        let cli = Cli::try_parse_from([
            "bud",
            "validator",
            "commission",
            "--key-file",
            "v.key",
            "--rate-ppm",
            "100000",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Validator {
                action: Some(ValidatorAction::Commission {
                    rate_ppm: 100_000,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn a_bootnode_multiaddr_names_its_transport() {
        assert_eq!(
            bootnode_multiaddr("203.0.113.7", 5001, "12D3Koo"),
            "/ip4/203.0.113.7/tcp/5001/p2p/12D3Koo"
        );
        assert_eq!(
            bootnode_multiaddr("seed1.example.org", 5001, "12D3Koo"),
            "/dns4/seed1.example.org/tcp/5001/p2p/12D3Koo"
        );
    }

    /// The CLI help names the product by its approved name, not
    /// by the banned layer-one term.
    #[test]
    fn cli_help_does_not_use_the_layer_one_term() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        let banned = ["L", "1"].concat();
        assert!(
            !help
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|w| w == banned),
            "help text uses the banned term: {help}"
        );
        // The ban covers every surface the CLI PRINTS -
        // long help, short help and the subcommand helps - instead of
        // scanning the source file as text.
        let short = Cli::command().render_help().to_string();
        assert!(!short.contains(&banned), "short help uses the banned term");
        for sub in Cli::command().get_subcommands() {
            let sub_help = sub.clone().render_help().to_string();
            assert!(
                !sub_help.contains(&banned),
                "subcommand help uses the banned term: {sub_help}"
            );
        }
    }

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

    /// A seed file readable by group or others is refused.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("bud-key-mode-{}", std::process::id()));
        std::fs::write(&path, "00").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_key_file_mode(&path).expect_err("mode 644 must be refused");
        assert!(err.contains("chmod 600"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_key_file_mode(&path).is_ok());
        std::fs::remove_file(&path).ok();
    }

    /// The transfer carries the chain id it was given, not the devnet default.
    #[test]
    fn a_transfer_is_bound_to_the_given_chain_id() {
        let from = Address::zero();
        let tx = build_transfer(from, from, 1, 2, 3, 45260);
        assert_eq!(tx.chain_id, 45260);
        assert_eq!(tx.fee, 2);
        assert_eq!(tx.nonce, 3);
        assert_eq!(tx.tx_type, TransactionType::Transfer);
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
        let err =
            build_manifest("demo-app", &zero).expect_err("a zero source hash must be refused");
        assert!(err.contains("manifest refused"), "{err}");
    }

    /// A short digest must not be silently padded.
    #[test]
    fn a_short_digest_is_refused() {
        let err =
            parse_digest("--source-hash", "0x0909").expect_err("a short digest must be refused");
        assert!(err.contains("must be 32 bytes"), "{err}");
    }

    /// Binding passes for a record carrying the hash of the verified envelope.
    #[test]
    fn binding_a_proof_to_its_own_hash_passes() {
        let proof = "01".repeat(32);
        run_project_bind_proof("demo-app", SOURCE_HASH, "zkvm-smoke", &proof).unwrap();
    }

    /// A record whose own hash differs from the verified envelope is refused.
    /// The record used to be rewritten to the supplied hash before the
    /// comparison, so this case passed.
    #[test]
    fn binding_a_proof_to_another_hash_is_refused() {
        let other = "02".repeat(32);
        let err = run_project_bind_proof("demo-app", SOURCE_HASH, "zkvm-smoke", &other)
            .expect_err("a record speaking of another proof must be refused");
        assert!(err.contains("ProofFixtureHashMismatch"), "{err}");
    }

    /// A record absent from the manifest cannot be bound.
    #[test]
    fn binding_an_unknown_fixture_is_refused() {
        let proof = "01".repeat(32);
        let err = run_project_bind_proof("demo-app", SOURCE_HASH, "no-such-record", &proof)
            .expect_err("an unknown record must be refused");
        assert!(err.contains("no proof record named"), "{err}");
    }
}
