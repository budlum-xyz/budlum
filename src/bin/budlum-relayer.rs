//! F10.4 plus the Budlum relayer binary: the permissionless cross-chain relay
//! service.
//!
//! ## Design, permissionless
//!
//! - **Permissionless entry:** the only gate is the registry's `min_stake`
//!   floor (`RegistryParams::min_stake`, in atoms; 1 BUD is `1_000_000`
//!   atoms). Anyone can run a relayer.
//! - **Bond and stake:** a relayer stakes through `PermissionlessRegistry`
//!   under the `RELAYER` role, `RoleId` 3.
//! - **Slashing:** for griefing, fronting or a wrong relay,
//!   `SlashingProof::Other { tag: \"relayer_invalid_proof\" }` leads to
//!   `MaliciousBehaviour` and a 100 percent slash.
//!   - The report is produced by the `consensus_invalid_relay_proof` helper.
//!   - The bridge keeps an open relayer set plus a challenge window; see RFC
//!     F10, sections 4 and 5.
//!
//! ## Flows
//!
//! Status: NOT mainnet ready. Neither direction relays anything yet.
//!
//! - **`EthToBud` (design):** the Ethereum RPC `eth_getLogs` gives a deposit
//!   event, which becomes an MPT and header chain proof, submitted to Budlum
//!   through `bud_submitRelayProof`, behind the registry gate and the stake.
//!   Today the deposit log is a placeholder (no topic filter, amount 0) and
//!   proof assembly always refuses, so nothing is submitted.
//! - **`BudToEth` (design):** a Budlum burn event plus a finality proof becomes a
//!   `claimUnlock` transaction to the Ethereum bridge contract. Today burns are
//!   found and reported only; the bridge contract does not exist yet.
//!
//! The binary checks the registry gate before it starts `EthToBud`; the node
//! checks it again on every submission. Slashing reports come from consensus,
//! the relayer files none.
//!
//! ## Running it
//!
//! ```bash
//! Budlum-relayer --eth-rpc https://mainnet.infura.io/v3/... \
//!                --budlum-rpc http://localhost:8545 \
//!                --bridge-address 0x... \
//!                --relayer-address 0xYourBudlumAddressHexOr0x... \
//!                --direction eth-to-bud --confirmations 64
//! ```

use std::env;
use std::process::ExitCode;
use std::time::Duration;

// Reqwest for both Eth and Budlum JSON-RPC
// Added to Cargo.toml: reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

/// The relayer CLI configuration, permissionless.
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    pub eth_rpc_url: String,
    pub budlum_rpc_url: String,
    pub bridge_address: String,
    pub direction: RelayDirection,
    pub required_confirmations: u32,
    /// The relayer's Budlum address, in hex, 32 bytes, optionally 0x-prefixed.
    /// The stake is checked for the RELAYER role in the permissionless registry.
    pub relayer_address: String,
    /// The poll interval, in seconds.
    pub poll_interval_secs: u64,
    /// Used for the minimum stake check; the default is 1000.
    pub min_stake: u64,
    /// A file that keeps the scan cursor across restarts. `None` keeps it in
    /// memory only, and a restart then starts again from the head.
    pub cursor_file: Option<String>,
}

/// The relay direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDirection {
    EthToBud,
    BudToEth,
}

impl RelayDirection {
    /// Parse a `--direction` value.
    ///
    /// # Errors
    ///
    /// Returns an error for any value other than the four spellings below.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "eth-to-bud" | "eth" => Ok(Self::EthToBud),
            "bud-to-eth" | "bud" => Ok(Self::BudToEth),
            _ => Err(format!(
                "Unknown direction '{s}'; expected 'eth-to-bud' or 'bud-to-eth'"
            )),
        }
    }
}

impl Default for RelayerConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "http://localhost:8546".to_string(),
            budlum_rpc_url: "http://localhost:8545".to_string(),
            bridge_address: "0x0".to_string(),
            direction: RelayDirection::EthToBud,
            required_confirmations: 64,
            relayer_address: "0x0".to_string(),
            poll_interval_secs: 10,
            min_stake: 1000,
            cursor_file: None,
        }
    }
}

/// The cursor saved in `path`, if the file holds one block number.
fn read_cursor(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Save the cursor beside `path` and rename it over, so a crash cannot leave
/// a truncated file.
fn write_cursor(path: &str, block: u64) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, block.to_string()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Largest RPC response body the relayer reads.
const MAX_RPC_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Most blocks one `eth_getLogs` scan covers.
const MAX_LOG_SCAN_BLOCKS: u64 = 2_000;

/// Refuse a response body longer than the cap.
fn check_body_len(len: usize) -> Result<(), String> {
    if len > MAX_RPC_BODY_BYTES {
        return Err(format!("response body of {len} bytes is too large"));
    }
    Ok(())
}

/// Read a JSON body but refuse one over the cap, also while it streams in.
async fn read_json_bounded(mut resp: reqwest::Response) -> Result<serde_json::Value, String> {
    if let Some(len) = resp.content_length() {
        check_body_len(usize::try_from(len).unwrap_or(usize::MAX))?;
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        check_body_len(body.len().saturating_add(chunk.len()))?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

/// The block range of the next scan: it starts after the cursor and never
/// spans more than `MAX_LOG_SCAN_BLOCKS` blocks.
fn scan_window(last_block: u64, latest: u64) -> (u64, u64) {
    let from = last_block.saturating_add(1);
    let to = from
        .checked_add(MAX_LOG_SCAN_BLOCKS - 1)
        .map_or(latest, |cap| latest.min(cap));
    (from, to)
}

/// Minimal Ethereum deposit event, parsed from `eth_getLogs`.
#[derive(Debug, Clone)]
pub struct EthDepositEvent {
    pub tx_hash: String,
    pub block_number: u64,
    pub log_index: u64,
    pub depositor: String,
    pub amount: u128,
    pub budlum_recipient: String,
    pub nonce: u64,
}

/// Minimal Budlum burn event, read over Budlum RPC.
#[derive(Debug, Clone)]
pub struct BudlumBurnEvent {
    pub message_id: String,
    pub asset_id: String,
    pub amount: u128,
    pub recipient_eth: String,
    pub burn_height: u64,
}

/// The Budlum JSON-RPC client, the gate onto the permissionless registry.
#[derive(Debug, Clone)]
pub struct BudlumClient {
    pub url: String,
    pub client: reqwest::Client,
}

impl BudlumClient {
    #[must_use]
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { url, client }
    }

    /// Generic JSON-RPC call.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be sent, the body is over
    /// the size cap or not JSON, or the node answers with an `error` field.
    pub async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Budlum RPC send failed ({method}): {e}"))?;
        let json = read_json_bounded(resp)
            .await
            .map_err(|e| format!("Budlum RPC json parse failed: {e}"))?;
        if let Some(err) = json.get("error") {
            return Err(format!("Budlum RPC error ({method}): {err}"));
        }
        Ok(json
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Ask whether the relayer is active, through `bud_registryActiveMembers`
    /// with role 3.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC call fails or the answer has neither a
    /// `members` array nor the shape of one.
    pub async fn is_active_relayer(&self, address: &str) -> Result<bool, String> {
        let params = serde_json::json!([3]); // RELAYER role id
        let val = self.rpc_call("bud_registryActiveMembers", params).await?;

        let members = val
            .get("members")
            .and_then(|m| m.as_array())
            .or_else(|| val.as_array())
            .ok_or_else(|| {
                "bud_registryActiveMembers returned unexpected JSON shape".to_string()
            })?;

        Ok(members_contain(members, address))
    }

    /// Submit a relay proof through `bud_submitRelayProof`.
    ///
    /// Parameters: `message_id` (hex), `relayer_addr` (hex), the proof
    /// object, and `source_domain` (`u32`).
    ///
    /// # Errors
    ///
    /// Returns the RPC error, unchanged.
    pub async fn submit_relay_proof(
        &self,
        message_id: &str,
        relayer_addr: &str,
        proof_json: serde_json::Value,
        source_domain: u32,
    ) -> Result<serde_json::Value, String> {
        let params = serde_json::json!([message_id, relayer_addr, proof_json, source_domain]);
        self.rpc_call("bud_submitRelayProof", params).await
    }
}

/// The Ethereum JSON-RPC client, observing deposits for the permissionless
/// relayer.
#[derive(Debug, Clone)]
pub struct EthClient {
    pub url: String,
    pub bridge_address: String,
    pub client: reqwest::Client,
}

impl EthClient {
    #[must_use]
    pub fn new(url: String, bridge_address: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            url,
            bridge_address,
            client,
        }
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Eth RPC {method} send failed: {e}"))?;
        let json = read_json_bounded(resp)
            .await
            .map_err(|e| format!("Eth RPC json fail: {e}"))?;
        if let Some(err) = json.get("error") {
            return Err(format!("Eth RPC error {method}: {err}"));
        }
        Ok(json
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// The Ethereum head height.
    ///
    /// # Errors
    ///
    /// Returns an error when the call fails or the answer is not a hex
    /// string.
    pub async fn get_block_number(&self) -> Result<u64, String> {
        let val = self
            .rpc_call("eth_blockNumber", serde_json::json!([]))
            .await?;
        if let Some(s) = val.as_str() {
            let n = u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|e| format!("parse blockNumber {s}: {e}"))?;
            Ok(n)
        } else {
            Err("eth_blockNumber not hex string".into())
        }
    }

    /// `eth_getLogs`, for the bridge deposit events.
    ///
    /// Topic0 is a placeholder,
    /// `keccak256("Deposit(address,uint256,bytes32,uint256)")`; it must be set
    /// from the real contract.
    ///
    /// # Errors
    ///
    /// Returns the RPC error, unchanged.
    pub async fn get_deposit_logs(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<EthDepositEvent>, String> {
        // A minimal filter; the real topic0 must come from configuration.
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
            "address": self.bridge_address,
            // "topics": [["0x..."]] is a placeholder; fetch every log
        });
        let logs = self
            .rpc_call("eth_getLogs", serde_json::json!([filter]))
            .await?;
        let mut events = Vec::new();
        if let Some(arr) = logs.as_array() {
            for (idx, log) in arr.iter().enumerate() {
                let tx_hash = log
                    .get("transactionHash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x")
                    .to_string();
                let block_num_str = log
                    .get("blockNumber")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x0");
                let block_number =
                    u64::from_str_radix(block_num_str.trim_start_matches("0x"), 16).unwrap_or(0);
                let log_index_str = log
                    .get("logIndex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0x0");
                let log_index = u64::from_str_radix(log_index_str.trim_start_matches("0x"), 16)
                    .unwrap_or(idx as u64);
                // Parse naive - amount/recipient from data/topics placeholder
                events.push(EthDepositEvent {
                    tx_hash,
                    block_number,
                    log_index,
                    depositor: log
                        .get("address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0x0")
                        .to_string(),
                    // Fail-closed boundary: the configured event ABI/topic and
                    // Indexed-field layout are not wired yet, so `log.data` cannot
                    // Safely be interpreted as an amount. Proof assembly below
                    // Rejects every placeholder event before submission.
                    amount: 0,
                    budlum_recipient:
                        "0x0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    nonce: log_index,
                });
            }
        }
        Ok(events)
    }

    /// Builds the F10.1 and F10.2 proof package: the MPT proof, the header chain
    /// and the receipt.
    ///
    /// A real implementation would use `eth_getTransactionReceipt`,
    /// `eth_getBlockByHash` and `eth_getProof` for the receipts root proof. What
    /// stands here is a placeholder, matching the offline `EvmChainAdapter` stub
    /// and the `verify_evm_receipt` path. It makes no call yet, so it is not
    /// `async`; it becomes `async` with the first RPC it needs.
    ///
    /// # Errors
    ///
    /// Always, until the proof assembly exists: a placeholder proof is never
    /// submitted.
    pub fn build_deposit_proof(
        &self,
        event: &EthDepositEvent,
    ) -> Result<serde_json::Value, String> {
        let _ = event;
        Err(
            "EthToBud deposit proof assembly is not implemented yet; refusing to submit placeholder proofs"
                .into(),
        )
    }
}

/// Parses the CLI arguments.
///
/// # Errors
///
/// Returns an error for an unknown flag, a flag without its value, a value
/// that does not parse, or `--relayer-key`.
pub fn parse_args(args: &[String]) -> Result<RelayerConfig, String> {
    let mut config = RelayerConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--eth-rpc" => {
                i += 1;
                config
                    .eth_rpc_url
                    .clone_from(args.get(i).ok_or("--eth-rpc requires a value")?);
            }
            "--budlum-rpc" => {
                i += 1;
                config
                    .budlum_rpc_url
                    .clone_from(args.get(i).ok_or("--budlum-rpc requires a value")?);
            }
            "--bridge-address" => {
                i += 1;
                config
                    .bridge_address
                    .clone_from(args.get(i).ok_or("--bridge-address requires a value")?);
            }
            "--direction" => {
                i += 1;
                config.direction =
                    RelayDirection::parse(args.get(i).ok_or("--direction requires a value")?)?;
            }
            "--confirmations" => {
                i += 1;
                config.required_confirmations = args
                    .get(i)
                    .ok_or("--confirmations requires a value")?
                    .parse()
                    .map_err(|e| format!("Invalid --confirmations value: {e}"))?;
            }
            "--relayer-address" => {
                i += 1;
                config
                    .relayer_address
                    .clone_from(args.get(i).ok_or("--relayer-address requires a value")?);
            }
            "--relayer-key" => {
                // The flag used to accept a key value on the command line and
                // then never use it. A secret in `argv` is visible in the
                // process list and shell history; the relayer signs nothing
                // today, so the flag is refused rather than silently kept.
                return Err(String::from(
                    "--relayer-key is not accepted: the relayer holds no signing key, and a \
                     key would not be taken from the command line",
                ));
            }
            "--poll-interval" => {
                i += 1;
                config.poll_interval_secs = args
                    .get(i)
                    .ok_or("--poll-interval requires a value")?
                    .parse()
                    .map_err(|e| format!("Invalid --poll-interval: {e}"))?;
            }
            "--cursor-file" => {
                i += 1;
                config.cursor_file =
                    Some(args.get(i).ok_or("--cursor-file requires a value")?.clone());
            }
            "--min-stake" => {
                i += 1;
                config.min_stake = args
                    .get(i)
                    .ok_or("--min-stake requires a value")?
                    .parse()
                    .map_err(|e| format!("Invalid --min-stake: {e}"))?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]));
            }
        }
        i += 1;
    }
    Ok(config)
}

/// What the binary can do today. Shown in the usage text so `--help` does not
/// promise a working relay.
const STATUS_NOTICE: &str = "STATUS: not mainnet ready. No direction relays yet: eth-to-bud \
cannot build deposit proofs, bud-to-eth only reports burns. Nothing is submitted.";

fn print_usage() {
    eprintln!("budlum-relayer - F10 Universal Relayer (D1 permissionless + D4 unified registry)");
    eprintln!("{STATUS_NOTICE}");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  budlum-relayer --eth-rpc <URL> --budlum-rpc <URL> --bridge-address <ADDR>");
    eprintln!(
        "                 --relayer-address <BUDLUM_ADDR> --direction <eth-to-bud|bud-to-eth>"
    );
    eprintln!("                 [--confirmations N] [--poll-interval S] [--min-stake 1000]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --eth-rpc <URL>            Ethereum RPC endpoint");
    eprintln!("  --budlum-rpc <URL>         Budlum RPC endpoint");
    eprintln!("  --bridge-address <ADDR>    Ethereum bridge contract address");
    eprintln!("  --relayer-address <ADDR>   Relayer's Budlum address (hex, for registry check)");
    eprintln!("  --direction <DIR>          eth-to-bud (F10.2) | bud-to-eth (F10.5)");
    eprintln!("  --confirmations <N>        N-confirmation threshold (default: 64)");
    eprintln!("  --poll-interval <S>        Poll interval seconds (default: 10)");
    eprintln!(
        "  --min-stake <AMOUNT>       Min stake floor for permissionless gate (default: 1000)"
    );
    eprintln!("  --cursor-file <PATH>       Keep the scan cursor across restarts");
    eprintln!("  -h, --help                 Show this help");
    eprintln!();
    eprintln!("Permissionless model (D1):");
    eprintln!("  - The only gate: the registry min_stake floor (atoms), PermissionlessRegistry RoleId(3) RELAYER");
    eprintln!("  - Bond: a signed RoleBond transaction with role 3 (RELAYER)");
    eprintln!(
        "  - Slashing: the relayer_invalid_proof tag leads to a 100% MaliciousBehaviour slash"
    );
    eprintln!("  - Challenge: open relayer set + bad relay challenge via bud_submitSlashingReport");
}

/// Validates the config and initialises the Ethereum and Budlum clients.
///
/// # Errors
///
/// Returns an error for a placeholder bridge address, and for a placeholder
/// relayer address in the submitting direction.
pub fn run_relayer(config: &RelayerConfig) -> Result<(), String> {
    eprintln!("budlum-relayer D1 permissionless starting:");
    eprintln!("  direction: {:?}", config.direction);
    eprintln!("  eth-rpc: {}", config.eth_rpc_url);
    eprintln!("  budlum-rpc: {}", config.budlum_rpc_url);
    eprintln!("  bridge: {}", config.bridge_address);
    eprintln!("  relayer: {}", config.relayer_address);
    eprintln!("  confirmations: {}", config.required_confirmations);
    eprintln!(
        "  poll: {}s min_stake: {}",
        config.poll_interval_secs, config.min_stake
    );
    eprintln!();

    if config.bridge_address == "0x0" || config.bridge_address == "0x" {
        return Err(
            "bridge-address is placeholder (0x0); set real Ethereum bridge contract".into(),
        );
    }
    if let Err(e) = validate_relayer_address(&config.relayer_address) {
        // The submitting direction must name a real relayer. BudToEth submits
        // nothing, so it only warns and its registry check reports "not active".
        if config.direction == RelayDirection::EthToBud {
            return Err(e);
        }
        eprintln!("WARN: {e}");
    }

    Ok(())
}

/// Lowercase an address and drop an optional `0x` prefix, so that
/// `0xAB..` and `ab..` name the same account.
fn normalize_address(address: &str) -> String {
    let lower = address.trim().to_lowercase();
    lower
        .strip_prefix("0x")
        .map_or_else(|| lower.clone(), ToString::to_string)
}

/// Is `address` among the registry members? A member is an object with an
/// `address` or `account` field, or a plain string.
fn members_contain(members: &[serde_json::Value], address: &str) -> bool {
    let wanted = normalize_address(address);
    members.iter().any(|entry| {
        let member = entry
            .get("address")
            .and_then(|a| a.as_str())
            .or_else(|| entry.get("account").and_then(|a| a.as_str()))
            .or_else(|| entry.as_str());
        member.is_some_and(|m| normalize_address(m) == wanted)
    })
}

/// A relayer address is 32 bytes in hex, with an optional `0x` prefix.
///
/// The placeholder `0x0` (the default) and short values are refused. There is
/// no devnet or mainnet switch in this binary, so no value may switch the
/// registry check off.
fn validate_relayer_address(address: &str) -> Result<(), String> {
    let clean = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);
    if clean.len() == 64 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "relayer-address '{address}' is not a 32-byte hex Budlum address"
        ))
    }
}

/// Permissionless registration check - is relayer active?
async fn check_relayer_active(budlum_client: &BudlumClient, config: &RelayerConfig) -> bool {
    match budlum_client
        .is_active_relayer(&config.relayer_address)
        .await
    {
        Ok(active) => {
            if active {
                eprintln!(
                    "Relayer {} is ACTIVE (bond >= {}), permissionless gate passed.",
                    config.relayer_address, config.min_stake
                );
            } else {
                eprintln!("Relayer {} is NOT active - need to bond >= {} with a signed RoleBond transaction (RoleId 3 RELAYER).", config.relayer_address, config.min_stake);
                eprintln!("Continuing in observation mode (will fail on submit). Bond first for production.");
            }
            active
        }
        Err(e) => {
            eprintln!("Failed to check relayer active status: {e}");
            false
        }
    }
}

/// Production loop - `EthToBud` direction.
///
/// This is the submitting direction, so the registry gate is enforced here:
/// a relayer that is not bonded (or whose bond cannot be checked) does not
/// start. The node refuses its submissions anyway; starting would only poll
/// Ethereum for deposits nobody can relay.
///
/// The first scan window starts at the Ethereum head. The loop does not
/// begin until the head height is known: with an unknown head the first
/// `eth_getLogs` would span block 1 to the tip without a topic filter, which
/// public providers reject, and the relayer would stall on its first poll.
async fn run_eth_to_bud_loop(config: RelayerConfig) -> Result<(), String> {
    let eth_client = EthClient::new(config.eth_rpc_url.clone(), config.bridge_address.clone());
    let budlum_client = BudlumClient::new(config.budlum_rpc_url.clone());

    if !check_relayer_active(&budlum_client, &config).await {
        return Err(format!(
            "relayer {} is not an active bonded relayer; bond with a signed \
             RoleBond transaction (RoleId 3 RELAYER, >= {} atoms) before relaying",
            config.relayer_address, config.min_stake
        ));
    }

    eprintln!("EthToBud: WARNING {STATUS_NOTICE}");

    let mut interval = tokio::time::interval(Duration::from_secs(config.poll_interval_secs));
    let mut last_block = initial_cursor(&eth_client, &config, &mut interval).await;

    let mut window_attempts: u32 = 0;
    loop {
        interval.tick().await;
        // 1. Get latest finalized block (N-conf)
        let latest = match eth_client.get_block_number().await {
            Ok(bn) => bn.saturating_sub(u64::from(config.required_confirmations)),
            Err(e) => {
                eprintln!("EthToBud poll: get_block_number failed: {e} - retry");
                continue;
            }
        };
        if latest <= last_block {
            continue;
        }
        let (from, to) = scan_window(last_block, latest);
        eprintln!("EthToBud: scanning deposits from {from} to {to}");

        // 2. Get deposit logs
        let deposits = match eth_client.get_deposit_logs(from, to).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("EthToBud: get_deposit_logs failed: {e}");
                continue;
            }
        };
        if deposits.is_empty() {
            last_block = to;
            window_attempts = 0;
            save_cursor(&config, last_block);
            continue;
        }
        eprintln!("EthToBud: found {} deposit event(s)", deposits.len());

        let window_failed = relay_deposits(&eth_client, &budlum_client, &config, deposits).await;
        let (next_last, next_attempts) =
            advance_cursor(last_block, to, window_failed, window_attempts);
        if window_failed && next_last == to {
            eprintln!(
                "EthToBud: window {from}..{to} failed {MAX_WINDOW_ATTEMPTS} times; \
                 skipping it, its deposits are NOT relayed"
            );
        }
        last_block = next_last;
        window_attempts = next_attempts;
        save_cursor(&config, last_block);
    }
}

/// The block the first scan window starts after: the saved cursor when there
/// is one, otherwise the confirmed Ethereum head, waited for one tick at a
/// time until it is known.
async fn initial_cursor(
    eth_client: &EthClient,
    config: &RelayerConfig,
    interval: &mut tokio::time::Interval,
) -> u64 {
    if let Some(saved) = config.cursor_file.as_deref().and_then(read_cursor) {
        eprintln!("EthToBud: resuming from saved block {saved}");
        return saved;
    }
    loop {
        interval.tick().await;
        match eth_client.get_block_number().await {
            Ok(bn) => {
                let start = bn.saturating_sub(u64::from(config.required_confirmations));
                eprintln!(
                    "EthToBud: starting from block {} (current {} - {} conf)",
                    start, bn, config.required_confirmations
                );
                return start;
            }
            Err(e) => {
                eprintln!(
                    "EthToBud: get_block_number failed ({e}), waiting for the head before scanning"
                );
            }
        }
    }
}

/// Build and submit the proof of every deposit in one scan window. Returns
/// whether any deposit failed, so the caller can retry the window.
async fn relay_deposits(
    eth_client: &EthClient,
    budlum_client: &BudlumClient,
    config: &RelayerConfig,
    deposits: Vec<EthDepositEvent>,
) -> bool {
    let mut window_failed = false;
    for dep in deposits {
        // 3. Build proof
        let proof_json = match eth_client.build_deposit_proof(&dep) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "EthToBud: build_deposit_proof failed for {}: {e}",
                    dep.tx_hash
                );
                window_failed = true;
                continue;
            }
        };

        // 4. Submit to Budlum (permissionless gate + stake)
        let message_id = format!("0x{:064x}", dep.nonce); // placeholder mapping: nonce -> message_id
                                                          // For demo, source_domain 1 (Ethereum)
        let source_domain = 1u32;

        // Proof format expected by Budlum: MerkleProof { leaf, index, siblings } + external root
        // Here we pass our proof_json as placeholder, real impl would bincode-serialize MerkleProof
        // And submit via bud_submitRelayProof
        match budlum_client
            .submit_relay_proof(
                &message_id,
                &config.relayer_address,
                proof_json,
                source_domain,
            )
            .await
        {
            Ok(res) => {
                eprintln!(
                    "EthToBud: relay proof submitted for tx {} -> Budlum result: {:?}",
                    dep.tx_hash, res
                );
            }
            Err(e) => {
                // The node decides whether a proof was invalid and the
                // consensus helper produces the slashing report. The
                // relayer never files a report against itself: a
                // transport error or a node-side failure used to match
                // a substring test here and send a self-report that
                // would burn the relayer's own bond.
                eprintln!(
                    "EthToBud: submit_relay_proof failed for {}: {e}",
                    dep.tx_hash
                );
                window_failed = true;
            }
        }
    }
    window_failed
}

/// Persist the cursor when a cursor file is configured. A failed write is
/// logged and the loop goes on: the cursor is still held in memory.
fn save_cursor(config: &RelayerConfig, block: u64) {
    if let Some(path) = config.cursor_file.as_deref() {
        if let Err(e) = write_cursor(path, block) {
            eprintln!("EthToBud: cursor file could not be written: {e}");
        }
    }
}

/// How many times one scan window is retried before it is skipped.
const MAX_WINDOW_ATTEMPTS: u32 = 5;

/// The scan cursor after one window.
///
/// A window with a failed deposit is scanned again on the next tick, so a
/// transient proof or submit error does not drop the deposit for good. After
/// `MAX_WINDOW_ATTEMPTS` failures the window is skipped, so one permanently
/// bad deposit cannot stall the loop. Returns the new cursor and the failed
/// attempts so far on the current window.
const fn advance_cursor(
    last_block: u64,
    to: u64,
    window_failed: bool,
    attempts: u32,
) -> (u64, u32) {
    if !window_failed {
        return (to, 0);
    }
    let attempts = attempts.saturating_add(1);
    if attempts >= MAX_WINDOW_ATTEMPTS {
        (to, 0)
    } else {
        (last_block, attempts)
    }
}

/// `BudToEth` direction: scan finalized Budlum blocks for burn events.
///
/// # What this used to be
///
/// A timer. It polled at an interval, incremented a local counter and printed
/// "poll tick"; it never read a burn event, never built a proof and never
/// submitted anything. An operator running `--direction bud-to-eth` saw
/// healthy-looking ticks while nothing was relayed. The opposite direction
/// already refused rather than pretending, so the two halves of the same
/// binary disagreed about what an unimplemented path should do.
///
/// # What it does now
///
/// Scans blocks over Budlum RPC and finds real burn transactions
/// (`BurnBridgeTransferWithEvent`). There is no `bud_getBridgeBurnEvents`
/// method, so the scan walks `bud_getBlockByNumber` and filters on the
/// transaction type the node already exposes.
///
/// # What it deliberately does not do
///
/// It does not submit to Ethereum. The claim needs a Budlum finality proof
/// (BLS aggregate / QC) and an Ethereum bridge contract to verify it; the
/// Solidity side does not exist yet (RFC F10.5b). So a discovered burn is
/// reported and counted, and the submit step **refuses loudly** instead of
/// sending a placeholder. That is the same contract the `EthToBud` direction
/// keeps: refuse, do not pretend.
///
/// The difference from before is that the refusal is now about a real burn
/// that was really found, not a counter that was never connected to anything.
async fn run_bud_to_eth_loop(config: RelayerConfig) {
    let budlum_client = BudlumClient::new(config.budlum_rpc_url.clone());

    // No `EthClient` is built for this direction. One used to be, kept alive at
    // the end of the loop with `let _ = &eth_client;`; since it made no call, it
    // only produced the appearance that "the Ethereum side is wired". Holding a
    // client when there is no submission path implies a capability that does not
    // exist.
    //
    // Nothing is submitted in this direction, so the registry gate is
    // advisory here: the check reports the bond state and the scan runs
    // either way. The submitting direction enforces it.
    let _ = check_relayer_active(&budlum_client, &config).await;

    eprintln!(
        "BudToEth: scanning for burn events. Submission to Ethereum is NOT available \
         (no bridge contract, RFC F10.5b) - discovered burns are reported, never \
         submitted with a placeholder proof."
    );

    let mut interval = tokio::time::interval(Duration::from_secs(config.poll_interval_secs));
    // `None` until the first head is read, then the next height to scan.
    let mut next_height: Option<u64> = None;
    let mut total_burns: u64 = 0;

    loop {
        interval.tick().await;

        let head = match budlum_head_height(&budlum_client).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("BudToEth: cannot read head height: {e}");
                continue;
            }
        };

        // First pass starts at the head: replaying the whole chain on every
        // restart would hammer the node and re-report burns already seen.
        let from = *next_height.get_or_insert(head);
        if from > head {
            continue; // no new block
        }

        // The cursor advances only past heights that were really scanned. A
        // failed block ends the pass and the next tick retries from that
        // height, so one RPC failure cannot drop a burn from the report
        // forever.
        for height in from..=head {
            match burn_events_in_block(&budlum_client, height).await {
                Ok(burns) => {
                    for tx_hash in burns {
                        total_burns += 1;
                        eprintln!(
                            "BudToEth: burn found at height {height} (tx {tx_hash}) - \
                             NOT submitted: finality proof + Ethereum bridge contract \
                             missing (RFC F10.5b). Total seen: {total_burns}"
                        );
                    }
                    next_height = Some(height + 1);
                }
                Err(e) => {
                    eprintln!(
                        "BudToEth: block {height} scan failed: {e}; retrying from it next tick"
                    );
                    break;
                }
            }
        }
    }
}

/// Current Budlum head height over RPC.
async fn budlum_head_height(client: &BudlumClient) -> Result<u64, String> {
    let val = client
        .rpc_call("bud_blockNumber", serde_json::json!([]))
        .await?;
    parse_hex_height(&val)
}

/// Hashes of burn transactions in one block.
///
/// The node renders the transaction type with `{:?}`, so the wire value is the
/// variant name. Matching on a prefix keeps a variant that carries fields
/// (`BurnBridgeTransferWithEvent { .. }`) from being missed.
async fn burn_events_in_block(client: &BudlumClient, height: u64) -> Result<Vec<String>, String> {
    let block = client
        .rpc_call("bud_getBlockByNumber", block_by_number_params(height))
        .await?;
    Ok(burn_hashes_from_block(&block))
}

/// Positional parameters of `bud_getBlockByNumber`: exactly one `u64`.
///
/// The node declares `number: u64` (src/rpc/api.rs). A hex string or an extra
/// flag is an invalid-params error, so every scan would fail.
fn block_by_number_params(height: u64) -> serde_json::Value {
    serde_json::json!([height])
}

/// Burn transaction hashes in a block payload.
///
/// Split from the RPC call so the filter can be tested without a node: the
/// part that can be wrong here is the matching, not the HTTP.
fn burn_hashes_from_block(block: &serde_json::Value) -> Vec<String> {
    let Some(txs) = block.get("transactions").and_then(|t| t.as_array()) else {
        return Vec::new();
    };
    txs.iter()
        .filter(|tx| {
            tx.get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|ty| ty.starts_with("BurnBridgeTransferWithEvent"))
        })
        .map(|tx| {
            tx.get("hash")
                .and_then(|h| h.as_str())
                .unwrap_or("<no hash>")
                .to_string()
        })
        .collect()
}

/// Parse a hex block height as returned by `bud_blockNumber`.
fn parse_hex_height(val: &serde_json::Value) -> Result<u64, String> {
    let hex = val
        .as_str()
        .ok_or_else(|| "bud_blockNumber did not return a string".to_string())?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("bud_blockNumber is not hex: {e}"))
}

fn main() -> ExitCode {
    // The Semgrep rule `rust.lang.security.args.args` targets argv[0] being used
    // as the basis of a security decision. `parse_args` starts at index 1, see
    // its definition, so argv[0] is never read; the parsed values are only RPC
    // endpoints and bridge parameters, and carry no identity or authorisation
    // decision.
    // Nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = env::args().collect();
    let config = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            print_usage();
            return ExitCode::from(1);
        }
    };
    if let Err(e) = run_relayer(&config) {
        eprintln!("budlum-relayer config error: {e}");
        return ExitCode::from(1);
    }

    eprintln!("budlum-relayer: config valid, starting D1 permissionless relay loop...");

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let outcome = rt.block_on(async {
        match config.direction {
            RelayDirection::EthToBud => run_eth_to_bud_loop(config).await,
            RelayDirection::BudToEth => {
                run_bud_to_eth_loop(config).await;
                Ok(())
            }
        }
    });

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("budlum-relayer: refusing to start: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        advance_cursor, block_by_number_params, burn_hashes_from_block, check_body_len,
        parse_hex_height, scan_window, MAX_LOG_SCAN_BLOCKS, MAX_RPC_BODY_BYTES,
        MAX_WINDOW_ATTEMPTS, STATUS_NOTICE,
    };

    #[test]
    fn a_scan_window_and_a_body_are_bounded() {
        assert_eq!(scan_window(10, 20), (11, 20));
        assert_eq!(scan_window(10, 1_000_000), (11, 10 + MAX_LOG_SCAN_BLOCKS));
        assert_eq!(scan_window(u64::MAX, u64::MAX), (u64::MAX, u64::MAX));
        assert!(check_body_len(MAX_RPC_BODY_BYTES).is_ok());
        assert!(check_body_len(MAX_RPC_BODY_BYTES + 1).is_err());
    }

    /// A failed window is retried and only skipped after the attempt limit.
    #[test]
    fn a_failed_window_is_retried_before_it_is_skipped() {
        assert_eq!(advance_cursor(10, 20, false, 3), (20, 0));
        assert_eq!(advance_cursor(10, 20, true, 0), (10, 1));
        assert_eq!(
            advance_cursor(10, 20, true, MAX_WINDOW_ATTEMPTS - 2),
            (10, MAX_WINDOW_ATTEMPTS - 1)
        );
        assert_eq!(
            advance_cursor(10, 20, true, MAX_WINDOW_ATTEMPTS - 1),
            (20, 0)
        );
    }

    /// The check used to compare lowercased strings, so a prefix difference
    /// made an active relayer look inactive.
    #[test]
    fn membership_ignores_case_and_the_0x_prefix() {
        let members = vec![
            serde_json::json!({"address": "0xAABB"}),
            serde_json::json!({"account": "ccdd"}),
            serde_json::json!("0xEEFF"),
        ];
        assert!(members_contain(&members, "aabb"));
        assert!(members_contain(&members, "0XCCDD"));
        assert!(members_contain(&members, "eeff"));
        assert!(!members_contain(&members, "0xaa"));
        assert!(!members_contain(&[], "aabb"));
    }

    #[test]
    fn a_placeholder_relayer_address_is_refused() {
        assert!(validate_relayer_address("0x0").is_err());
        assert!(validate_relayer_address("0xab").is_err());
        assert!(validate_relayer_address(&"g".repeat(64)).is_err());
        assert!(validate_relayer_address(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(validate_relayer_address(&"AB".repeat(32)).is_ok());
    }

    #[test]
    fn the_cursor_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("relayer-cursor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cursor").to_string_lossy().into_owned();
        assert_eq!(read_cursor(&path), None);
        write_cursor(&path, 1234).unwrap();
        assert_eq!(read_cursor(&path), Some(1234));
        std::fs::write(&path, "not a number").unwrap();
        assert_eq!(read_cursor(&path), None);
        std::fs::remove_dir_all(&dir).unwrap();

        let args = vec![
            "budlum-relayer".to_string(),
            "--cursor-file".to_string(),
            "/tmp/c".to_string(),
        ];
        assert_eq!(
            parse_args(&args).unwrap().cursor_file.as_deref(),
            Some("/tmp/c")
        );
    }

    #[test]
    fn eth_to_bud_does_not_start_with_a_placeholder_relayer_address() {
        let config = RelayerConfig {
            bridge_address: format!("0x{}", "11".repeat(20)),
            direction: RelayDirection::EthToBud,
            ..RelayerConfig::default()
        };
        assert!(run_relayer(&config).is_err());
        let ok = RelayerConfig {
            relayer_address: format!("0x{}", "ab".repeat(32)),
            ..config
        };
        assert!(run_relayer(&ok).is_ok());
    }

    /// The usage text must say that nothing is relayed yet.
    #[test]
    fn the_status_notice_says_nothing_is_relayed() {
        assert!(STATUS_NOTICE.contains("not mainnet ready"));
        assert!(STATUS_NOTICE.contains("Nothing is submitted"));
    }

    fn block_with(types: &[&str]) -> serde_json::Value {
        let txs: Vec<serde_json::Value> = types
            .iter()
            .enumerate()
            .map(|(i, t)| serde_json::json!({ "hash": format!("0x{i:02x}"), "type": t }))
            .collect();
        serde_json::json!({ "transactions": txs })
    }

    /// The node takes one numeric height; a hex string plus a flag is refused.
    #[test]
    fn block_by_number_sends_one_numeric_parameter() {
        assert_eq!(block_by_number_params(42), serde_json::json!([42]));
    }

    /// The loop used to report nothing because it read nothing. A block that
    /// really carries a burn must yield that burn.
    #[test]
    fn a_burn_transaction_is_found() {
        let b = block_with(&["Transfer", "BurnBridgeTransferWithEvent", "Transfer"]);
        assert_eq!(burn_hashes_from_block(&b), vec!["0x01".to_string()]);
    }

    /// A variant rendered with its fields still has to match: `{:?}` prints
    /// `BurnBridgeTransferWithEvent { .. }`, and an equality test would miss it.
    #[test]
    fn a_burn_rendered_with_fields_is_found() {
        let b = block_with(&["BurnBridgeTransferWithEvent { amount: 5 }"]);
        assert_eq!(burn_hashes_from_block(&b).len(), 1);
    }

    /// A near-miss name must not count. Matching too loosely would report
    /// ordinary bridge traffic as burns.
    #[test]
    fn other_bridge_transactions_are_not_burns() {
        let b = block_with(&["BurnBridgeTransfer", "MintBridgeTransfer", "Transfer"]);
        assert!(burn_hashes_from_block(&b).is_empty());
    }

    #[test]
    fn a_block_without_transactions_yields_nothing() {
        assert!(burn_hashes_from_block(&serde_json::json!({})).is_empty());
        assert!(burn_hashes_from_block(&serde_json::Value::Null).is_empty());
        assert!(burn_hashes_from_block(&block_with(&[])).is_empty());
    }

    #[test]
    fn the_head_height_is_parsed_as_hex() {
        assert_eq!(parse_hex_height(&serde_json::json!("0x10")).unwrap(), 16);
        assert_eq!(parse_hex_height(&serde_json::json!("0x0")).unwrap(), 0);
        assert!(parse_hex_height(&serde_json::json!(16)).is_err());
        assert!(parse_hex_height(&serde_json::json!("zzz")).is_err());
    }

    use super::*;

    #[test]
    fn parse_direction() {
        assert_eq!(
            RelayDirection::parse("eth-to-bud").unwrap(),
            RelayDirection::EthToBud
        );
        assert_eq!(
            RelayDirection::parse("bud-to-eth").unwrap(),
            RelayDirection::BudToEth
        );
        assert!(RelayDirection::parse("invalid").is_err());
    }

    #[test]
    fn default_config_min_stake() {
        let cfg = RelayerConfig::default();
        assert_eq!(cfg.min_stake, 1000);
        assert_eq!(cfg.required_confirmations, 64);
    }

    #[test]
    fn parse_args_with_relayer_address() {
        let args = vec![
            "budlum-relayer".to_string(),
            "--eth-rpc".to_string(),
            "http://eth".to_string(),
            "--budlum-rpc".to_string(),
            "http://bud".to_string(),
            "--bridge-address".to_string(),
            "0x1234".to_string(),
            "--relayer-address".to_string(),
            "0xabcd".to_string(),
            "--direction".to_string(),
            "eth-to-bud".to_string(),
        ];
        let cfg = parse_args(&args).unwrap();
        assert_eq!(cfg.relayer_address, "0xabcd");
        assert_eq!(cfg.direction, RelayDirection::EthToBud);
    }

    #[test]
    fn relayer_config_permissionless_gate() {
        // Permissionless gate = min_stake floor (1000)
        let cfg = RelayerConfig::default();
        assert!(cfg.min_stake >= 1000);
        // RoleId 3 = RELAYER
        assert_eq!(cfg.min_stake, 1000);
    }

    #[test]
    fn registry_active_members_object_shape_parses_exact_address_only() {
        let payload = serde_json::json!({
            "roleId": 3,
            "count": 1,
            "members": [
                {"address": "0xaaaaaaaa"}
            ]
        });
        let members = payload.get("members").and_then(|m| m.as_array()).unwrap();
        let normalized = "0xaaaaaaaa".to_string();
        assert!(members.iter().any(|entry| {
            entry
                .get("address")
                .and_then(|a| a.as_str())
                .map(str::to_lowercase)
                == Some(normalized.clone())
        }));
        assert!(!members.iter().any(|entry| {
            entry
                .get("address")
                .and_then(|a| a.as_str())
                .map(str::to_lowercase)
                == Some("0xaa".to_string())
        }));
    }

    #[test]
    fn deposit_proof_builder_is_fail_closed_until_real_impl_exists() {
        let client = EthClient::new("http://eth".into(), "0x1234".into());
        let event = EthDepositEvent {
            tx_hash: "0xabc".into(),
            block_number: 1,
            log_index: 0,
            depositor: "0xdep".into(),
            amount: 1,
            budlum_recipient: "0xrecip".into(),
            nonce: 1,
        };
        let err = client.build_deposit_proof(&event).unwrap_err();
        assert!(err.contains("not implemented"));
    }
}
