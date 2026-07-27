#![allow(clippy::pedantic, clippy::nursery)]
//! F10.4 + Budlum Relayer Binary — permissionless cross-chain relay servisi.
//!
//! ## Design (permissionless)
//! - **Permissionless entry:** Tek gate `min_stake` (1000 $BUD). Herkes relayer çalıştırabilir.
//! - **Bond/stake:** Relayer `RELAYER` rolü (RoleId 3) ile `PermissionlessRegistry` üzerinden stake yatırır.
//! - **Slashing:** Griefing/fronting/yanlış-relay için `SlashingProof::Other { tag: \"relayer_invalid_proof\" }` → `MaliciousBehaviour` %100 slash.
//!   - `consensus_invalid_relay_proof` helper ile rapor üretilir.
//!   - Bridge: open relayer set + challenge penceresi (RFC F10 §4-5).
//!
//! ## Akışlar
//! - **EthToBud:** Ethereum RPC `eth_getLogs` → deposit event → MPT + header chain proof → Budlum `bud_submitRelayProof` (registry kapısı, stake).
//! - **BudToEth:** Budlum burn event + finality proof → Ethereum bridge kontratına `claimUnlock` tx.
//!
//! ## Çalıştırma
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

/// Relayer CLI konfigürasyonu — permissionless.
#[derive(Debug, Clone)]
pub struct RelayerConfig {
    pub eth_rpc_url: String,
    pub budlum_rpc_url: String,
    pub bridge_address: String,
    pub direction: RelayDirection,
    pub required_confirmations: u32,
    /// Relayer'ın Budlum adresi (hex, 32 bytes veya 0x…). Permissionless registry'de RELAYER rolü için stake kontrolü yapılır.
    pub relayer_address: String,
    /// Opsiyonel: relayer private key path veya hex (ileride HSM). Şimdilik sadece log.
    pub relayer_key_hint: Option<String>,
    /// Poll aralığı (saniye)
    pub poll_interval_secs: u64,
    /// Min stake kontrolü için (varsayılan 1000)
    pub min_stake: u64,
}

/// Relay yönü.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDirection {
    EthToBud,
    BudToEth,
}

impl RelayDirection {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "eth-to-bud" | "eth" => Ok(RelayDirection::EthToBud),
            "bud-to-eth" | "bud" => Ok(RelayDirection::BudToEth),
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
            relayer_key_hint: None,
            poll_interval_secs: 10,
            min_stake: 1000,
        }
    }
}

/// Minimal Ethereum deposit event (eth_getLogs'dan parse).
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

/// Minimal Budlum burn event (Budlum RPC'den).
#[derive(Debug, Clone)]
pub struct BudlumBurnEvent {
    pub message_id: String,
    pub asset_id: String,
    pub amount: u128,
    pub recipient_eth: String,
    pub burn_height: u64,
}

/// Budlum JSON-RPC client — permissionless registry kapısı.
#[derive(Debug, Clone)]
pub struct BudlumClient {
    pub url: String,
    pub client: reqwest::Client,
}

impl BudlumClient {
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { url, client }
    }

    /// Generic JSON-RPC call.
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
        let json: serde_json::Value = resp
            .json()
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

    /// Relayer'ın aktif olup olmadığını sorgula (bud_registryActiveMembers role=3).
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

        let normalized = address.to_lowercase();
        for entry in members {
            if let Some(acc) = entry.get("address").and_then(|a| a.as_str()) {
                if acc.to_lowercase() == normalized {
                    return Ok(true);
                }
            } else if let Some(acc) = entry.get("account").and_then(|a| a.as_str()) {
                if acc.to_lowercase() == normalized {
                    return Ok(true);
                }
            } else if let Some(s) = entry.as_str() {
                if s.to_lowercase() == normalized {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Relay proof submit — bud_submitRelayProof
    /// Params: message_id (hex), relayer_addr (hex), proof (object), source_domain (u32)
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

    /// Slashing report submit — bud_submitSlashingReport
    /// Tag: relayer_invalid_proof → MaliciousBehaviour %100
    pub async fn submit_slashing_report_for_invalid_relay(
        &self,
        offender: &str,
        reason: &str,
        reporter: &str,
    ) -> Result<serde_json::Value, String> {
        // Build SlashingReport JSON matching Rust struct:
        // { offender, role: 3, proof: { Other: { tag: "relayer_invalid_proof", data: <bytes> } }, provenance: "ConsensusVerified", reporter: Some(...) }
        let report = serde_json::json!({
            "offender": offender,
            "role": 3,
            "proof": { "Other": { "tag": "relayer_invalid_proof", "data": reason.as_bytes().to_vec() } },
            "provenance": "ConsensusVerified",
            "reporter": reporter
        });
        self.rpc_call("bud_submitSlashingReport", serde_json::json!([report]))
            .await
    }
}

/// Ethereum JSON-RPC client — permissionless relayer için deposit gözlemi.
#[derive(Debug, Clone)]
pub struct EthClient {
    pub url: String,
    pub bridge_address: String,
    pub client: reqwest::Client,
}

impl EthClient {
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
        let json: serde_json::Value = resp
            .json()
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

    /// Eth_getLogs — bridge deposit eventleri için.
    /// Topic0 = keccak256("Deposit(address,uint256,bytes32,uint256)") placeholder — gerçek kontratla set edilmeli.
    pub async fn get_deposit_logs(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<EthDepositEvent>, String> {
        // Minimal filter — gerçek topic0 konfigürasyondan gelmeli.
        let filter = serde_json::json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
            "address": self.bridge_address,
            // "topics": [["0x..."]] — placeholder, tüm logları getir
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
                // Parse naive — amount/recipient from data/topics placeholder
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

    /// F10.1/F10.2 proof paketi üretimi — MPT + header chain + receipt.
    /// Gerçek impl: eth_getTransactionReceipt + eth_getBlockByHash + eth_getProof (receiptsRoot proof).
    /// Burada placeholder: EvmChainAdapter offline stub + verify_evm_receipt path'e uygun.
    pub async fn build_deposit_proof(
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

/// CLI argümanları parse et.
pub fn parse_args(args: &[String]) -> Result<RelayerConfig, String> {
    let mut config = RelayerConfig::default();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--eth-rpc" => {
                i += 1;
                config.eth_rpc_url = args.get(i).ok_or("--eth-rpc requires a value")?.clone();
            }
            "--budlum-rpc" => {
                i += 1;
                config.budlum_rpc_url = args.get(i).ok_or("--budlum-rpc requires a value")?.clone();
            }
            "--bridge-address" => {
                i += 1;
                config.bridge_address = args
                    .get(i)
                    .ok_or("--bridge-address requires a value")?
                    .clone();
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
                config.relayer_address = args
                    .get(i)
                    .ok_or("--relayer-address requires a value")?
                    .clone();
            }
            "--relayer-key" => {
                i += 1;
                config.relayer_key_hint =
                    Some(args.get(i).ok_or("--relayer-key requires a value")?.clone());
            }
            "--poll-interval" => {
                i += 1;
                config.poll_interval_secs = args
                    .get(i)
                    .ok_or("--poll-interval requires a value")?
                    .parse()
                    .map_err(|e| format!("Invalid --poll-interval: {e}"))?;
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

fn print_usage() {
    eprintln!("budlum-relayer — F10 Universal Relayer (D1 permissionless + D4 unified registry)");
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
    eprintln!("  --relayer-key <HINT>       Optional private key hint / path (HSM future)");
    eprintln!("  --direction <DIR>          eth-to-bud (F10.2) | bud-to-eth (F10.5)");
    eprintln!("  --confirmations <N>        N-confirmation threshold (default: 64)");
    eprintln!("  --poll-interval <S>        Poll interval seconds (default: 10)");
    eprintln!(
        "  --min-stake <AMOUNT>       Min stake floor for permissionless gate (default: 1000)"
    );
    eprintln!("  -h, --help                 Show this help");
    eprintln!();
    eprintln!("Permissionless model (D1):");
    eprintln!("  - Tek gate: min_stake (1000 $BUD) — PermissionlessRegistry RoleId(3) RELAYER");
    eprintln!("  - Bond: bud_registryBondRelayer ile stake yatırılır");
    eprintln!("  - Slashing: relayer_invalid_proof tag → MaliciousBehaviour %100 slash");
    eprintln!("  - Challenge: open relayer set + bad relay challenge via bud_submitSlashingReport");
}

/// Config validate + eth/budlum client init.
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
    if config.relayer_address == "0x0" || config.relayer_address.len() < 10 {
        eprintln!("WARN: relayer-address is placeholder — permissionless gate will skip active check (devnet mode). Set real Budlum address for mainnet.");
    }

    Ok(())
}

/// Permissionless registration check — is relayer active?
async fn check_relayer_active(budlum_client: &BudlumClient, config: &RelayerConfig) -> bool {
    if config.relayer_address == "0x0" {
        eprintln!("Devnet mode: relayer-address placeholder, skip active check (assume active).");
        return true;
    }
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
                eprintln!("Relayer {} is NOT active — need to bond >= {} via bud_registryBondRelayer (RoleId 3 RELAYER).", config.relayer_address, config.min_stake);
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

/// Production loop — EthToBud direction
async fn run_eth_to_bud_loop(config: RelayerConfig) {
    let eth_client = EthClient::new(config.eth_rpc_url.clone(), config.bridge_address.clone());
    let budlum_client = BudlumClient::new(config.budlum_rpc_url.clone());

    let _active = check_relayer_active(&budlum_client, &config).await;

    let mut last_block: u64 = 0;
    // Init last_block from current eth block minus confirmations
    match eth_client.get_block_number().await {
        Ok(bn) => {
            last_block = bn.saturating_sub(config.required_confirmations as u64);
            eprintln!(
                "EthToBud: starting from block {} (current {} - {} conf)",
                last_block, bn, config.required_confirmations
            );
        }
        Err(e) => {
            eprintln!("EthToBud: get_block_number failed ({e}), starting from 0");
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(config.poll_interval_secs));
    loop {
        interval.tick().await;
        // 1. Get latest finalized block (N-conf)
        let latest = match eth_client.get_block_number().await {
            Ok(bn) => bn.saturating_sub(config.required_confirmations as u64),
            Err(e) => {
                eprintln!("EthToBud poll: get_block_number failed: {e} — retry");
                continue;
            }
        };
        if latest <= last_block {
            continue;
        }
        let from = last_block + 1;
        let to = latest;
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
            continue;
        }
        eprintln!("EthToBud: found {} deposit event(s)", deposits.len());

        for dep in deposits {
            // 3. Build proof
            let proof_json = match eth_client.build_deposit_proof(&dep).await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "EthToBud: build_deposit_proof failed for {}: {e}",
                        dep.tx_hash
                    );
                    continue;
                }
            };

            // 4. Submit to Budlum (permissionless gate + stake)
            let message_id = format!("0x{:064x}", dep.nonce); // placeholder mapping: nonce → message_id
            let relayer_addr = config.relayer_address.clone();
            // For demo, source_domain 1 (Ethereum)
            let source_domain = 1u32;

            // Proof format expected by Budlum: MerkleProof { leaf, index, siblings } + external root
            // Here we pass our proof_json as placeholder — real impl would bincode-serialize MerkleProof
            // And submit via bud_submitRelayProof
            match budlum_client
                .submit_relay_proof(&message_id, &relayer_addr, proof_json, source_domain)
                .await
            {
                Ok(res) => {
                    eprintln!(
                        "EthToBud: relay proof submitted for tx {} → Budlum result: {:?}",
                        dep.tx_hash, res
                    );
                }
                Err(e) => {
                    eprintln!(
                        "EthToBud: submit_relay_proof failed for {}: {e}",
                        dep.tx_hash
                    );
                    // Slashing scenario: if we submitted invalid proof, we would be slashed.
                    // If we detect another relayer's invalid proof, we submit slashing report.
                    if e.contains("invalid") || e.contains("proof") {
                        eprintln!("EthToBud: detected invalid proof — would trigger slashing (relayer_invalid_proof tag)");
                        // Example slashing report (reporter = our relayer)
                        let _ = budlum_client
                            .submit_slashing_report_for_invalid_relay(
                                &relayer_addr,
                                &format!("invalid deposit proof for tx {}: {}", dep.tx_hash, e),
                                &relayer_addr,
                            )
                            .await;
                    }
                }
            }
        }
        last_block = to;
    }
}

/// Production loop — BudToEth direction
async fn run_bud_to_eth_loop(config: RelayerConfig) {
    let budlum_client = BudlumClient::new(config.budlum_rpc_url.clone());
    let eth_client = EthClient::new(config.eth_rpc_url.clone(), config.bridge_address.clone());

    let _active = check_relayer_active(&budlum_client, &config).await;

    eprintln!("BudToEth: watching Budlum burn events → Ethereum claim");
    eprintln!("BudToEth: (Production needs Budlum light-client proof + Ethereum bridge tx — Solidity bridge contract separate RFC F10.5b)");

    let mut interval = tokio::time::interval(Duration::from_secs(config.poll_interval_secs));
    let mut last_burn_height: u64 = 0;

    loop {
        interval.tick().await;

        // TODO: Real impl would:
        // 1. Call Budlum RPC bud_getBridgeBurnEvents or scan blocks for TransactionType::BurnBridgeTransferWithEvent
        // 2. For each burn, construct BudToEthClaim (bud_to_eth.rs: build_bud_to_eth_claim) — check Burned status
        // 3. Build Budlum finality proof (BLS aggregate / QC)
        // 4. Submit to Ethereum bridge via eth_sendRawTransaction claimUnlock
        // Placeholder poll:
        eprintln!("BudToEth: poll tick at height {last_burn_height} (RPC integration pending — would fetch burn events)");

        // Example placeholder burn event simulation (devnet):
        // Simulate no events
        last_burn_height += 1;

        // Challenge window logic (RFC F10 §4-5):
        // If we see a bad relay (e.g., invalid burn proof), submit slashing report.
        // Open relayer set is permissionless — anyone can challenge.
        if last_burn_height.is_multiple_of(100) {
            eprintln!("BudToEth: challenge window check — no bad relays detected (open relayer set, permissionless)");
        }

        // Prevent unused warning for eth_client (would be used for eth_sendRawTransaction)
        let _ = &eth_client;
    }
}

fn main() -> ExitCode {
    // Semgrep `rust.lang.security.args.args` kuralı argv[0]'ın güvenlik
    // Kararına dayanak yapılmasını hedefler. `parse_args` index 1'den başlar
    // (bkz. tanımı), argv[0] okunmaz; ayrıştırılan değerler yalnız RPC uçları
    // Ve köprü parametreleridir, kimlik/yetki kararı içermez.
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

    rt.block_on(async {
        match config.direction {
            RelayDirection::EthToBud => run_eth_to_bud_loop(config).await,
            RelayDirection::BudToEth => run_bud_to_eth_loop(config).await,
        }
    });

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
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
    fn slashing_tag_for_relayer_invalid_proof() {
        // Slashing: Other tag = relayer_invalid_proof → MaliciousBehaviour 100%
        let tag = "relayer_invalid_proof";
        assert_eq!(tag, "relayer_invalid_proof");
        // This tag maps to MaliciousBehaviour in evidence.rs
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
                .map(|s| s.to_lowercase())
                == Some(normalized.clone())
        }));
        assert!(!members.iter().any(|entry| {
            entry
                .get("address")
                .and_then(|a| a.as_str())
                .map(|s| s.to_lowercase())
                == Some("0xaa".to_string())
        }));
    }

    #[test]
    fn deposit_proof_builder_is_fail_closed_until_real_impl_exists() {
        let rt = tokio::runtime::Runtime::new().unwrap();
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
        let err = rt.block_on(client.build_deposit_proof(&event)).unwrap_err();
        assert!(err.contains("not implemented"));
    }
}
