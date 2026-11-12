//! `budlum-faucet`: testnet BUD for people who have none.
//!
//! The faucet holds one funded account (allocated in the testnet genesis)
//! and answers a request by sending an ordinary V5 transfer from it,
//! signed with ML-DSA-87 and submitted through the node's public RPC. It
//! writes no state of its own into the chain: the transfer is a transaction
//! like any other, so every node applies it inside a block. That is the
//! difference from the development credit paths on `Blockchain`, which
//! credit outside consensus and refuse every chain id except devnet.
//!
//! # Limits
//!
//! Each request is checked against three limits before anything is signed
//!
//!
//! * one grant per recipient address per cooldown window,
//! * one grant per client IP per cooldown window,
//! * a daily cap on the total sent.
//!
//! The limits are persisted before submission. An unreadable or unwritable
//! state file stops the faucet rather than silently resetting its allowances.
//!
//! # Chains
//!
//! The faucet asks the node for its chain id at startup and refuses to run
//! unless it is the testnet or the devnet id. A faucet pointed at a mainnet
//! node by mistake stops before it signs anything.
//!
//! # Usage
//!
//! ```text
//! budlum-faucet keygen --out ./secrets/faucet.seed
//! budlum-faucet serve --rpc-url http://127.0.0.1:18545 \
//!     --key-file ./secrets/faucet.seed --state-file ./data/faucet-state.json \
//!     --listen 127.0.0.1:18600 --allow-direct
//! budlum-faucet request --url http://127.0.0.1:18600 --address 0x<64 hex digits>
//! ```
//!
//! The key file holds the 32-byte ML-DSA-87 seed as hex. It is read from a
//! path, never from the command line or the environment, and `keygen`
//! creates it with owner-only permissions.

use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::WalletKeyPair;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};

#[path = "support/faucet_client.rs"]
mod faucet_client;
#[path = "support/http.rs"]
mod http_support;
use faucet_client::{meets_difficulty, parse_address, pow_hash, request_funds, DEFAULT_AMOUNT_BUD};

/// TESTNET-DEFAULT: one grant per address and per IP every 24 hours.
const DEFAULT_COOLDOWN_SECS: u64 = 24 * 60 * 60;
/// TESTNET-DEFAULT: at most 100000 BUD per UTC day.
const DEFAULT_DAILY_CAP_BUD: u64 = 100_000;
/// Largest request body read. A request carries one address.
const MAX_REQUEST_BYTES: usize = 1024;
/// A body that stops arriving cannot occupy a connection indefinitely.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most rows each cooldown table keeps. Rows older than the cooldown are
/// dropped first; at the ceiling new requests are refused rather than
/// letting the table grow without bound.
/// One caller may make this many requests per window whether or not they are
/// granted: the address and IP cooldowns alone let a client with fresh
/// addresses and a source range spend the whole daily allowance in one burst.
const CLIENT_REQUESTS_PER_WINDOW: u32 = 10;
const REQUEST_WINDOW_SECS: u64 = 60;
const MAX_TRACKED_KEYS: usize = 200_000;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const CHALLENGE_LIFETIME_SECS: u64 = 120;

#[derive(Parser, Debug)]
#[command(name = "budlum-faucet", about = "Testnet BUD faucet")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new faucet key file and print its address.
    Keygen {
        /// Where to write the seed. An existing file is never overwritten.
        #[arg(long)]
        out: String,
    },
    /// Request testnet funds after solving the faucet's work challenge.
    Request {
        /// Faucet base URL (HTTPS except loopback development hosts).
        #[arg(long)]
        url: String,
        /// Externally owned 32-byte recipient address.
        #[arg(long)]
        address: String,
    },
    /// Serve faucet requests.
    Serve {
        /// The node's public JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:18545")]
        rpc_url: String,
        /// The faucet key file written by `keygen`.
        #[arg(long)]
        key_file: String,
        /// Persistent allowances; keep on durable storage, never delete on restart.
        #[arg(long)]
        state_file: PathBuf,
        /// Address the faucet's HTTP endpoint binds.
        #[arg(long, default_value = "127.0.0.1:18600")]
        listen: String,
        /// BUD sent per request (whole BUD).
        #[arg(long, default_value_t = DEFAULT_AMOUNT_BUD)]
        amount_bud: u64,
        /// Seconds between two grants to one address or one IP.
        #[arg(long, default_value_t = DEFAULT_COOLDOWN_SECS)]
        cooldown_secs: u64,
        /// Total BUD sent per UTC day.
        #[arg(long, default_value_t = DEFAULT_DAILY_CAP_BUD)]
        daily_cap_bud: u64,
        /// Serve only these reverse proxies and trust their X-Forwarded-For. Repeatable.
        #[arg(long = "trusted-proxy")]
        trusted_proxies: Vec<IpAddr>,
        /// Serve direct clients; ignore every X-Forwarded-For header.
        #[arg(long)]
        allow_direct: bool,
    },
}

/// The limits one faucet enforces, in atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Policy {
    amount: u64,
    cooldown_secs: u64,
    daily_cap: u64,
}

impl Policy {
    fn from_bud(amount_bud: u64, cooldown_secs: u64, daily_cap_bud: u64) -> Result<Self, String> {
        let amount = amount_bud
            .checked_mul(budlum_core::tokenomics::BUD_UNIT)
            .ok_or("--amount-bud overflows")?;
        let daily_cap = daily_cap_bud
            .checked_mul(budlum_core::tokenomics::BUD_UNIT)
            .ok_or("--daily-cap-bud overflows")?;
        if amount == 0 {
            return Err("--amount-bud must be at least 1".into());
        }
        if daily_cap < amount {
            return Err("--daily-cap-bud is below one grant".into());
        }
        Ok(Self {
            amount,
            cooldown_secs,
            daily_cap,
        })
    }
}

/// Why a request was refused before anything was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    AddressCooldown { retry_after: u64 },
    IpCooldown { retry_after: u64 },
    DailyCap,
    Busy,
}

impl Refusal {
    fn message(&self) -> String {
        match self {
            Self::AddressCooldown { retry_after } => {
                format!("this address was funded recently; retry in {retry_after} s")
            }
            Self::IpCooldown { retry_after } => {
                format!("a request from this IP was funded recently; retry in {retry_after} s")
            }
            Self::DailyCap => "the faucet's daily cap is reached; retry after 00:00 UTC".into(),
            Self::Busy => "the faucet is tracking too many requests; retry later".into(),
        }
    }
}

/// The cooldown and cap bookkeeping, separate from I/O so it can be tested.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Ledger {
    by_address: BTreeMap<Address, u64>,
    #[serde(with = "budlum_core::core::map_keys")]
    by_ip: BTreeMap<IpAddr, u64>,
    day: u64,
    sent_today: u64,
    #[serde(default)]
    grants_total: u64,
}

impl Ledger {
    /// Refuse the request if a limit stands in the way; change nothing.
    fn check(
        &mut self,
        policy: &Policy,
        to: &Address,
        ip: IpAddr,
        now: u64,
    ) -> Result<(), Refusal> {
        self.roll_day(now);
        self.forget_expired(policy, now);
        if let Some(last) = self.by_address.get(to) {
            let open_at = last.saturating_add(policy.cooldown_secs);
            if now < open_at {
                return Err(Refusal::AddressCooldown {
                    retry_after: open_at - now,
                });
            }
        }
        if let Some(last) = self.by_ip.get(&ip) {
            let open_at = last.saturating_add(policy.cooldown_secs);
            if now < open_at {
                return Err(Refusal::IpCooldown {
                    retry_after: open_at - now,
                });
            }
        }
        if self.sent_today.saturating_add(policy.amount) > policy.daily_cap {
            return Err(Refusal::DailyCap);
        }
        if self.by_address.len() >= MAX_TRACKED_KEYS || self.by_ip.len() >= MAX_TRACKED_KEYS {
            return Err(Refusal::Busy);
        }
        Ok(())
    }

    /// Reserve an allowance before submission, even if the RPC response is lost.
    fn record(&mut self, policy: &Policy, to: Address, ip: IpAddr, now: u64) {
        self.roll_day(now);
        self.by_address.insert(to, now);
        self.by_ip.insert(ip, now);
        self.sent_today = self.sent_today.saturating_add(policy.amount);
    }

    fn roll_day(&mut self, now: u64) {
        let day = now / SECONDS_PER_DAY;
        if day != self.day {
            self.day = day;
            self.sent_today = 0;
        }
    }

    fn forget_expired(&mut self, policy: &Policy, now: u64) {
        let live = |last: &u64| last.saturating_add(policy.cooldown_secs) > now;
        self.by_address.retain(|_, last| live(last));
        self.by_ip.retain(|_, last| live(last));
    }
}

/// Each reservation is durable before the node sees a signed transaction.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredState {
    version: u8,
    chain_id: u64,
    faucet_address: Address,
    ledger: Ledger,
    next_nonce: u64,
}

impl StoredState {
    fn lock(path: &Path) -> Result<std::fs::File, String> {
        let lock_path = path.with_extension("lock");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options
            .open(&lock_path)
            .map_err(|e| format!("cannot open faucet lock {}: {e}", lock_path.display()))?;
        lock.try_lock().map_err(|e| {
            format!(
                "faucet state is already in use ({}): {e}",
                lock_path.display()
            )
        })?;
        Ok(lock)
    }

    fn new(chain_id: u64, faucet_address: Address) -> Self {
        Self {
            version: 1,
            chain_id,
            faucet_address,
            ledger: Ledger::default(),
            next_nonce: 0,
        }
    }

    fn load(
        path: &Path,
        chain_id: u64,
        faucet_address: Address,
        chain_nonce: u64,
    ) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let state: Self = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("invalid faucet state {}: {e}", path.display()))?;
                if state.version != 1
                    || state.chain_id != chain_id
                    || state.faucet_address != faucet_address
                {
                    return Err("faucet state belongs to another version, chain or key".into());
                }
                Ok(state)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if chain_nonce != 0 {
                    return Err("faucet state is missing for an account with previous transactions; restore the original state instead of resetting limits".into());
                }
                let state = Self::new(chain_id, faucet_address);
                state.save(path)?;
                Ok(state)
            }
            Err(e) => Err(format!("cannot read faucet state {}: {e}", path.display())),
        }
    }

    fn verify_chain_nonce(&self, chain_nonce: u64) -> Result<(), String> {
        if self.next_nonce != chain_nonce {
            return Err(format!(
                "faucet state next nonce {} differs from the confirmed chain nonce {chain_nonce}; wait for a pending submission or investigate other uses of the funding key before restarting",
                self.next_nonce
            ));
        }
        Ok(())
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        use std::io::Write as _;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let bytes = serde_json::to_vec(self).map_err(|e| format!("encode faucet state: {e}"))?;
        // A fresh name per write avoids following an attacker-supplied symlink.
        let mut suffix = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut suffix);
        let temporary = parent.join(format!(".faucet-{}.tmp", hex::encode(suffix)));
        let write = (|| -> Result<(), std::io::Error> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if write.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        write.map_err(|e| format!("cannot persist faucet state {}: {e}", path.display()))
    }
}

/// The two chains a faucet may serve.
fn faucet_allowed_on(chain_id: u64) -> bool {
    chain_id == Network::Testnet.chain_id().value()
        || chain_id == Network::Devnet.chain_id().value()
}

/// The `address` field of a request body.
fn parse_request(body: &[u8]) -> Result<Address, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("request is not JSON: {e}"))?;
    let raw = value
        .get("address")
        .and_then(serde_json::Value::as_str)
        .ok_or("request needs an \"address\" string")?;
    parse_address(raw)
}

#[derive(Clone)]
struct Challenge {
    address: Address,
    token: [u8; 16],
    expires_at: u64,
    difficulty_bits: u8,
}

/// Read a node RPC answer that is a decimal or `0x` hex number.
fn rpc_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{field} did not return a string"))?;
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| format!("{field}: {e}")),
        None => text.parse().map_err(|e| format!("{field}: {e}")),
    }
}

struct Node {
    url: String,
    http: reqwest::Client,
    /// The operator key, when the node this faucet funds from runs with the RPC
    /// gate on - which is its default. Read once from the file named by
    /// `BUDLUM_RPC_API_KEY_FILE`; the environment carries a path, never the
    /// secret (RT-002: without this header every call to an `auth_required`
    /// node answered `401 Unauthorized`).
    api_key: Option<String>,
}

impl Node {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut request = self.http.post(&self.url).json(&body);
        if let Some(key) = self.api_key.as_deref() {
            request = request.header("x-api-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("{method}: node unreachable: {e}"))?;
        // An unauthorised answer carries no JSON-RPC error object, so name the
        // cause here instead of reporting "answer is not JSON".
        let status = response.status();
        if matches!(status.as_u16(), 401 | 403) {
            return Err(format!(
                "{method}: node refused the call with HTTP {status}: it requires the operator \
                 key; point {} at a 0600 file holding it",
                budlum_core::rpc::client_auth::API_KEY_FILE_ENV
            ));
        }
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("{method}: answer is not JSON: {e}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("{method}: {error}"));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: answer has no result"))
    }
}

struct Faucet {
    node: Node,
    key: WalletKeyPair,
    address: Address,
    chain_id: u64,
    policy: Policy,
    identity: http_support::ClientIdentity,
    /// Do not queue an unbounded number of grants behind the nonce lock.
    grant_slots: Arc<Semaphore>,
    /// Per-client request arrivals, charged before a request may queue for a
    /// grant so one caller cannot hold the permit or spend the daily cap.
    request_window: Mutex<BTreeMap<IpAddr, (u64, u32)>>,
    /// At most one expiring challenge per peer; never persisted or reused.
    challenges: Mutex<BTreeMap<IpAddr, Challenge>>,
    /// The ledger and nonce are locked together to serialize grants.
    state: Mutex<StoredState>,
    state_file: PathBuf,
    /// Hold an exclusive process lock across the entire serving lifetime.
    _state_lock: std::fs::File,
    /// Stop on a failed write or an ambiguous submission until reconciled.
    halted: std::sync::atomic::AtomicBool,
}

impl Faucet {
    async fn limit_requests(&self, ip: IpAddr, now: u64) -> Result<(), String> {
        let mut window = self.request_window.lock().await;
        if window.len() >= MAX_TRACKED_KEYS {
            window.retain(|_, (start, _)| now.saturating_sub(*start) < REQUEST_WINDOW_SECS);
        }
        if window.len() >= MAX_TRACKED_KEYS && !window.contains_key(&ip) {
            return Err("faucet rate-limit table full; retry in a minute".into());
        }
        let entry = window.entry(ip).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= REQUEST_WINDOW_SECS {
            *entry = (now, 0);
        }
        if entry.1 >= CLIENT_REQUESTS_PER_WINDOW {
            return Err("too many faucet requests from this client; retry in a minute".into());
        }
        entry.1 += 1;
        Ok(())
    }

    async fn issue_challenge(
        &self,
        ip: IpAddr,
        address: Address,
        now: u64,
    ) -> Result<serde_json::Value, String> {
        let state = self.state.lock().await;
        let grants = if state.ledger.day == now / SECONDS_PER_DAY {
            state.ledger.sent_today / self.policy.amount
        } else {
            0
        };
        let difficulty_bits = (12 + (grants / 100).min(8)) as u8;
        drop(state);
        let mut token = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut token);
        let expires_at = now.saturating_add(CHALLENGE_LIFETIME_SECS);
        let mut challenges = self.challenges.lock().await;
        if challenges.len() >= MAX_TRACKED_KEYS {
            challenges.retain(|_, challenge| challenge.expires_at > now);
        }
        if challenges.len() >= MAX_TRACKED_KEYS && !challenges.contains_key(&ip) {
            return Err("challenge capacity reached; retry later".into());
        }
        challenges.insert(
            ip,
            Challenge {
                address,
                token,
                expires_at,
                difficulty_bits,
            },
        );
        Ok(serde_json::json!({
            "challenge": hex::encode(token),
            "difficulty_bits": difficulty_bits,
            "expires_at": expires_at,
            "chain_id": self.chain_id,
        }))
    }

    async fn verify_challenge(
        &self,
        ip: IpAddr,
        to: Address,
        value: &serde_json::Value,
        now: u64,
    ) -> Result<(), String> {
        let challenge = value
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or("request needs a challenge string")?;
        let nonce = value
            .get("nonce")
            .and_then(|v| v.as_u64())
            .ok_or("request needs an unsigned nonce")?;
        let mut challenges = self.challenges.lock().await;
        // Take before checking: one challenge yields at most one submission,
        // including when a client retries after an ambiguous node response.
        let issued = challenges
            .remove(&ip)
            .ok_or("request a fresh work challenge")?;
        if now >= issued.expires_at
            || issued.address != to
            || challenge != hex::encode(issued.token)
            || !meets_difficulty(
                &pow_hash(self.chain_id, &issued.token, &to, nonce),
                issued.difficulty_bits,
            )
        {
            return Err("invalid or expired work challenge".into());
        }
        Ok(())
    }

    async fn grant(
        &self,
        to: Address,
        ip: IpAddr,
    ) -> Result<serde_json::Value, (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut state = self.state.lock().await;
        if self.halted.load(std::sync::atomic::Ordering::Acquire) {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "faucet is halted; reconcile the last submission or state write".into(),
            ));
        }
        state
            .ledger
            .check(&self.policy, &to, ip, now)
            .map_err(|refusal| (StatusCode::TOO_MANY_REQUESTS, refusal.message()))?;

        let chain_nonce = self
            .node
            .call("bud_getNonce", serde_json::json!([self.address.to_hex()]))
            .await
            .and_then(|v| rpc_u64(&v, "bud_getNonce"))
            .map_err(|e| upstream_failure("bud_getNonce", &e))?;
        let nonce = chain_nonce.max(state.next_nonce);
        let mut tx = Transaction::new_with_chain_id(
            self.address,
            to,
            self.policy.amount,
            0,
            nonce,
            Vec::new(),
            self.chain_id,
            TransactionType::Transfer,
        );
        let fee = self
            .node
            .call("bud_estimateGas", serde_json::json!([tx]))
            .await
            .and_then(|v| rpc_u64(&v, "bud_estimateGas"))
            .map_err(|e| upstream_failure("bud_estimateGas", &e))?;
        tx.fee = fee;
        tx.max_fee = fee;
        tx.sign_v5(&self.key);
        // The node can accept a transfer and then lose the reply. Charge the
        // cooldown and daily allowance before sending, so an ambiguous RPC
        // timeout cannot yield unaccounted grants. Definite RPC refusals also
        // consume the allowance; this is safer than assuming no transfer ran.
        state.ledger.record(&self.policy, to, ip, now);
        // The nonce is reserved too: an accepted transaction may lose its RPC
        // reply. Never reuse that nonce for a different recipient on restart.
        state.next_nonce = nonce.saturating_add(1);
        if let Err(e) = state.save(&self.state_file) {
            self.halted
                .store(true, std::sync::atomic::Ordering::Release);
            eprintln!("budlum-faucet: {e}");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "faucet state is not writable".into(),
            ));
        }
        let hash = self
            .node
            .call("bud_sendRawTransaction", serde_json::json!([tx]))
            .await
            .map_err(|e| {
                // The upstream text can carry the node's URL and diagnostics,
                // and this body is served to anonymous callers.
                eprintln!("budlum-faucet: bud_sendRawTransaction failed: {e}");
                // Whether the node accepted the transfer is unknown. Stop all
                // subsequent grants until the reserved nonce is reconciled.
                self.halted
                    .store(true, std::sync::atomic::Ordering::Release);
                (
                    StatusCode::BAD_GATEWAY,
                    "submission failed or its reply was lost; the allowance is reserved"
                        .to_string(),
                )
            })?;
        state.ledger.grants_total = state.ledger.grants_total.saturating_add(1);
        if let Err(e) = state.save(&self.state_file) {
            self.halted
                .store(true, std::sync::atomic::Ordering::Release);
            eprintln!("budlum-faucet: {e}");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "submission accepted, but faucet state is not writable".into(),
            ));
        }
        Ok(serde_json::json!({
            "to": format!("0x{}", to.to_hex()),
            "amount_atoms": self.policy.amount,
            "fee_atoms": fee,
            "nonce": nonce,
            "tx_hash": hash,
        }))
    }

    async fn health(&self) -> serde_json::Value {
        let state = self.state.lock().await;
        serde_json::json!({
            "chain_id": self.chain_id,
            "faucet_address": format!("0x{}", self.address.to_hex()),
            "amount_atoms": self.policy.amount,
            "cooldown_secs": self.policy.cooldown_secs,
            "daily_cap_atoms": self.policy.daily_cap,
            "sent_today_atoms": state.ledger.sent_today,
            "accepting_requests": !self.halted.load(std::sync::atomic::Ordering::Acquire),
        })
    }

    async fn metrics(&self) -> String {
        let state = self.state.lock().await;
        format_faucet_metrics(state.ledger.grants_total)
    }
}

fn format_faucet_metrics(total: u64) -> String {
    format!(
        "# HELP budlum_faucet_grants_total Acknowledged signed transfers.\n\
         # TYPE budlum_faucet_grants_total counter\n\
         budlum_faucet_grants_total {total}\n"
    )
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    if let Ok(value) = hyper::header::HeaderValue::from_str("application/json") {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_TYPE, value);
    }
    response
}

/// A caller-facing refusal for a failed node call: the detail is logged, the
/// body is the generic one the faucet's contract documents.
///
/// The upstream text is not a public interface. It carries the node's URL,
/// host and port and its own diagnostics, and anyone can read the response.
fn upstream_failure(method: &str, error: &str) -> (StatusCode, String) {
    eprintln!("budlum-faucet: {method} failed: {error}");
    (
        StatusCode::BAD_GATEWAY,
        "the node could not answer this request".to_string(),
    )
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, &serde_json::json!({ "error": message }))
}

async fn read_request_body(body: Incoming, deadline: Duration) -> Result<Bytes, StatusCode> {
    match tokio::time::timeout(deadline, Limited::new(body, MAX_REQUEST_BYTES).collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(_)) => Err(StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
    }
}

async fn handle(
    faucet: Arc<Faucet>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    if method == Method::GET && path == "/health" {
        return Ok(json_response(StatusCode::OK, &faucet.health().await));
    }
    if method == Method::GET && path == "/metrics" {
        let mut response = Response::new(Full::new(Bytes::from(faucet.metrics().await)));
        response.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        );
        return Ok(response);
    }
    if (method != Method::POST || path != "/request")
        && (method != Method::GET || path != "/challenge")
    {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "GET /challenge or POST /request",
        ));
    }
    let ip = match faucet.identity.client_ip(peer.ip(), request.headers()) {
        Ok(ip) => ip,
        Err(message) => return Ok(error_response(StatusCode::BAD_REQUEST, message)),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Err(message) = faucet.limit_requests(ip, now).await {
        return Ok(error_response(StatusCode::TOO_MANY_REQUESTS, &message));
    }
    if method == Method::GET {
        let raw = request
            .uri()
            .query()
            .and_then(|query| query.strip_prefix("address="))
            .filter(|address| !address.contains('&'));
        let to = match raw
            .ok_or_else(|| "challenge needs an address".to_string())
            .and_then(parse_address)
        {
            Ok(to) => to,
            Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, &e)),
        };
        return Ok(match faucet.issue_challenge(ip, to, now).await {
            Ok(challenge) => json_response(StatusCode::OK, &challenge),
            Err(e) => error_response(StatusCode::TOO_MANY_REQUESTS, &e),
        });
    }
    let body = match read_request_body(request.into_body(), BODY_TIMEOUT).await {
        Ok(body) => body,
        Err(status) => {
            return Ok(error_response(
                status,
                "request body is too large or timed out",
            ))
        }
    };
    let to = match parse_request(&body) {
        Ok(to) => to,
        Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, &e)),
    };
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "invalid request JSON",
            ))
        }
    };
    if let Err(e) = faucet.verify_challenge(ip, to, &value, now).await {
        return Ok(error_response(StatusCode::BAD_REQUEST, &e));
    }
    let Ok(permit) = faucet.grant_slots.clone().try_acquire_owned() else {
        return Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "faucet busy; retry later",
        ));
    };
    // A client can disappear after the node accepted its transfer. Detach the
    // bounded grant from the HTTP connection so cancellation or timeout cannot
    // discard the nonce/cooldown update after an accepted transaction.
    let grant = tokio::spawn(async move {
        let _permit = permit;
        faucet.grant(to, ip).await
    });
    Ok(match grant.await {
        Ok(Ok(receipt)) => json_response(StatusCode::OK, &receipt),
        Ok(Err((status, message))) => error_response(status, &message),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "faucet worker failed"),
    })
}

fn read_seed(path: &str) -> Result<[u8; 32], String> {
    use std::io::Read as _;
    // Check and read the SAME descriptor: replacing a pathname between a
    // permission check and read must not swap in a different signing seed.
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open {path}: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {path}: {e}"))?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err("faucet seed must be a regular file of at most 128 bytes".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("faucet seed must be an owner-only file (mode 0600)".into());
        }
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    file.take(129)
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {path}: {e}"))?;
    let bytes = zeroize::Zeroizing::new(
        hex::decode(text.trim()).map_err(|e| format!("{path} is not hex: {e}"))?,
    );
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{path} must hold 32 bytes"))
}

fn keygen(out: &str) -> Result<(), String> {
    use std::io::Write as _;
    // The seed is wiped when it goes out of scope.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut_slice());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(out)
        .map_err(|e| format!("cannot create {out} (it is never overwritten): {e}"))?;
    file.write_all(hex::encode(*seed).as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| format!("cannot write {out}: {e}"))?;
    let address = WalletKeyPair::from_seed(&seed).address();
    println!("faucet address: 0x{}", address.to_hex());
    println!("allocate this address in the testnet genesis; keep {out} off every repository");
    Ok(())
}

async fn serve(
    rpc_url: String,
    key_file: &str,
    state_file: PathBuf,
    listen: &str,
    policy: Policy,
    trusted_proxies: Vec<IpAddr>,
    allow_direct: bool,
) -> Result<(), String> {
    let identity = http_support::ClientIdentity::new(allow_direct, trusted_proxies)?;
    let seed = zeroize::Zeroizing::new(read_seed(key_file)?);
    let key = WalletKeyPair::from_seed(&seed);
    drop(seed);
    let address = key.address();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let api_key = budlum_core::rpc::client_auth::api_key_from_env()
        .map_err(|e| format!("RPC operator key: {e}"))?;
    let node = Node {
        url: rpc_url,
        http,
        api_key,
    };
    let chain_id = node
        .call("bud_chainId", serde_json::json!([]))
        .await
        .and_then(|v| rpc_u64(&v, "bud_chainId"))?;
    if !faucet_allowed_on(chain_id) {
        return Err(format!(
            "the node serves chain id {chain_id}; a faucet runs on the testnet ({}) or devnet ({}) only",
            Network::Testnet.chain_id().value(),
            Network::Devnet.chain_id().value()
        ));
    }
    if chain_id == Network::Testnet.chain_id().value()
        && policy
            != Policy::from_bud(
                DEFAULT_AMOUNT_BUD,
                DEFAULT_COOLDOWN_SECS,
                DEFAULT_DAILY_CAP_BUD,
            )?
    {
        return Err("testnet faucet limits are fixed at 100 BUD per address and IP per 24h and 100000 BUD per day".into());
    }
    let state_lock = StoredState::lock(&state_file)?;
    let chain_nonce = node
        .call("bud_getNonce", serde_json::json!([address.to_hex()]))
        .await
        .and_then(|v| rpc_u64(&v, "bud_getNonce"))?;
    let stored = StoredState::load(&state_file, chain_id, address, chain_nonce)?;
    stored.verify_chain_nonce(chain_nonce)?;
    let faucet = Arc::new(Faucet {
        node,
        key,
        address,
        chain_id,
        policy,
        identity,
        grant_slots: Arc::new(Semaphore::new(1)),
        request_window: Mutex::new(BTreeMap::new()),
        challenges: Mutex::new(BTreeMap::new()),
        state: Mutex::new(stored),
        state_file,
        _state_lock: state_lock,
        halted: std::sync::atomic::AtomicBool::new(false),
    });
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("cannot bind {listen}: {e}"))?;
    eprintln!(
        "budlum-faucet: chain {chain_id}, address 0x{}, {} atoms per request, listening on {listen}",
        address.to_hex(),
        policy.amount
    );
    let connections = Arc::new(Semaphore::new(http_support::MAX_CONNECTIONS));
    /// The peer address as one log token. The address is the one part of a
    /// connection a remote host chooses the shape of, so the line breaks that
    /// would forge a second log entry - and any other control character - are
    /// removed before it reaches a log sink.
    fn loggable_peer(peer: SocketAddr) -> String {
        // `is_control` covers the line break and the carriage return as well
        // as every other character that could move the cursor or start a new
        // entry, in one pass.
        peer.to_string()
            .chars()
            .filter(|c| !c.is_control())
            .collect()
    }
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("budlum-faucet: accept failed: {e}");
                continue;
            }
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            // Drop excess sockets without spawning another task.
            continue;
        };
        let faucet = faucet.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service =
                hyper::service::service_fn(move |request| handle(faucet.clone(), peer, request));
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(http_support::HEADER_TIMEOUT)
                .max_buf_size(http_support::MAX_HEADER_BYTES)
                .keep_alive(false);
            let connection =
                builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            match tokio::time::timeout(http_support::CONNECTION_LIFETIME, connection).await {
                Ok(Err(e)) => eprintln!(
                    "budlum-faucet: connection from {} ended: {e}",
                    loggable_peer(peer)
                ),
                Err(_) => eprintln!(
                    "budlum-faucet: connection from {} timed out",
                    loggable_peer(peer)
                ),
                Ok(Ok(())) => {}
            }
        });
    }
}

fn main() -> ExitCode {
    budlum_core::crypto::tls::install_default_provider();
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Keygen { out } => keygen(&out),
        Command::Request { url, address } => tokio::runtime::Runtime::new()
            .map_err(|e| format!("tokio runtime: {e}"))
            .and_then(|runtime| runtime.block_on(request_funds(&url, &address))),
        Command::Serve {
            rpc_url,
            key_file,
            state_file,
            listen,
            amount_bud,
            cooldown_secs,
            daily_cap_bud,
            trusted_proxies,
            allow_direct,
        } => Policy::from_bud(amount_bud, cooldown_secs, daily_cap_bud).and_then(|policy| {
            tokio::runtime::Runtime::new()
                .map_err(|e| format!("tokio runtime: {e}"))
                .and_then(|runtime| {
                    runtime.block_on(serve(
                        rpc_url,
                        &key_file,
                        state_file,
                        &listen,
                        policy,
                        trusted_proxies,
                        allow_direct,
                    ))
                })
        }),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("budlum-faucet: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        faucet_allowed_on, format_faucet_metrics, meets_difficulty, parse_request, pow_hash,
        rpc_u64, Faucet, Ledger, Node, Policy, Refusal, StoredState, DEFAULT_AMOUNT_BUD,
        DEFAULT_COOLDOWN_SECS, DEFAULT_DAILY_CAP_BUD,
    };
    use budlum_core::core::address::Address;
    use budlum_core::core::chain_config::Network;
    use std::net::IpAddr;

    fn policy() -> Policy {
        Policy::from_bud(
            DEFAULT_AMOUNT_BUD,
            DEFAULT_COOLDOWN_SECS,
            DEFAULT_DAILY_CAP_BUD,
        )
        .unwrap()
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[tokio::test]
    async fn faucet_pow_difficulty_adjusts_and_replay_is_refused() {
        let _ = budlum_core::crypto::tls::install_default_provider();
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join("faucet-state.json");
        let key = budlum_core::crypto::primitives::WalletKeyPair::from_seed(&[5u8; 32]);
        let mut state = StoredState::new(Network::Testnet.chain_id().value(), key.address());
        state.ledger.day = 1;
        state.ledger.sent_today = policy().amount * 100;
        let faucet = Faucet {
            node: Node {
                url: String::new(),
                api_key: None,
                http: reqwest::Client::new(),
            },
            address: key.address(),
            key,
            chain_id: Network::Testnet.chain_id().value(),
            policy: policy(),
            identity: super::http_support::ClientIdentity::new(true, vec![]).unwrap(),
            grant_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            request_window: tokio::sync::Mutex::new(Default::default()),
            challenges: tokio::sync::Mutex::new(Default::default()),
            state: tokio::sync::Mutex::new(state),
            state_file,
            _state_lock: StoredState::lock(&dir.path().join("faucet-state.json")).unwrap(),
            halted: std::sync::atomic::AtomicBool::new(false),
        };
        let to = Address::from([9u8; 32]);
        let now = super::SECONDS_PER_DAY + 1;
        let challenge = faucet.issue_challenge(ip(1), to, now).await.unwrap();
        assert_eq!(challenge["difficulty_bits"], 13);
        let token = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
        let token: [u8; 16] = token.try_into().unwrap();
        let nonce = (0u64..8_000_000)
            .find(|n| meets_difficulty(&pow_hash(faucet.chain_id, &token, &to, *n), 13))
            .unwrap();
        let solution = serde_json::json!({
            "challenge": challenge["challenge"], "nonce": nonce,
        });
        assert!(faucet
            .verify_challenge(ip(1), to, &solution, now)
            .await
            .is_ok());
        assert!(
            faucet
                .verify_challenge(ip(1), to, &solution, now)
                .await
                .is_err(),
            "proofs cannot be replayed"
        );
        let challenge = faucet.issue_challenge(ip(1), to, now).await.unwrap();
        let wrong = serde_json::json!({"challenge": challenge["challenge"], "nonce": nonce});
        assert!(faucet
            .verify_challenge(ip(1), Address::from([8u8; 32]), &wrong, now)
            .await
            .is_err());
        let expired = faucet.issue_challenge(ip(1), to, now).await.unwrap();
        let expired_solution =
            serde_json::json!({"challenge": expired["challenge"], "nonce": nonce});
        assert!(faucet
            .verify_challenge(
                ip(1),
                to,
                &expired_solution,
                now + super::CHALLENGE_LIFETIME_SECS
            )
            .await
            .is_err());
    }

    #[test]
    fn faucet_limits_hold_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("faucet-state.json");
        let chain = Network::Testnet.chain_id().value();
        let address = Address::from([7u8; 32]);
        let recipient = Address::from([8u8; 32]);
        let lock = StoredState::lock(&path).unwrap();
        assert!(
            StoredState::lock(&path).is_err(),
            "two faucet instances must not share a ledger"
        );
        drop(lock);
        assert!(
            StoredState::load(&path, chain, address, 1).is_err(),
            "a lost ledger must not reset a spent account"
        );
        let mut state = StoredState::load(&path, chain, address, 0).unwrap();
        state.ledger.record(&policy(), recipient, ip(1), 1_000);
        state.next_nonce = 4;
        state.ledger.grants_total = 1;
        state.save(&path).unwrap();
        let mut restored = StoredState::load(&path, chain, address, 4).unwrap();
        assert_eq!(restored.next_nonce, 4);
        assert!(restored.verify_chain_nonce(4).is_ok());
        assert!(restored.verify_chain_nonce(3).is_err());
        assert!(restored.verify_chain_nonce(5).is_err());
        assert_eq!(restored.ledger.grants_total, 1);
        assert_eq!(restored.ledger.sent_today, policy().amount);
        assert!(matches!(
            restored.ledger.check(&policy(), &recipient, ip(2), 1_001),
            Err(Refusal::AddressCooldown { .. })
        ));
        assert!(matches!(
            restored
                .ledger
                .check(&policy(), &Address::from([9u8; 32]), ip(1), 1_001),
            Err(Refusal::IpCooldown { .. })
        ));
        assert!(StoredState::load(&path, chain + 1, address, 4).is_err());
        assert!(StoredState::load(&path, chain, recipient, 4).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn faucet_metrics_export_acknowledged_submissions() {
        let metrics = format_faucet_metrics(42);
        assert!(metrics.contains("# TYPE budlum_faucet_grants_total counter\n"));
        assert!(metrics.ends_with("budlum_faucet_grants_total 42\n"));
    }

    #[test]
    fn faucet_refuses_corrupt_or_unwritable_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"{broken").unwrap();
        assert!(StoredState::load(&path, 45261, Address::from([1; 32]), 0).is_err());
        assert!(StoredState::load(
            &dir.path().join("missing/state.json"),
            45261,
            Address::from([1; 32]),
            0,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn faucet_seed_must_be_owner_only_before_signing() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("faucet.seed");
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(super::read_seed(path.to_str().unwrap()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            super::read_seed(path.to_str().unwrap()).unwrap(),
            [0xAB; 32]
        );
        std::fs::write(&path, "aa".repeat(65)).unwrap();
        assert!(
            super::read_seed(path.to_str().unwrap()).is_err(),
            "oversize seed is refused before allocation"
        );
    }

    #[test]
    fn the_defaults_are_the_published_values_in_atoms() {
        let p = policy();
        assert_eq!(p.amount, budlum_core::tokenomics::bud(100));
        assert_eq!(p.cooldown_secs, 86_400);
        assert_eq!(p.daily_cap, budlum_core::tokenomics::bud(100_000));
        assert!(Policy::from_bud(0, 1, 1).is_err());
        assert!(
            Policy::from_bud(10, 1, 5).is_err(),
            "a cap below one grant is refused"
        );
    }

    #[test]
    fn only_testnet_and_devnet_are_served() {
        assert!(faucet_allowed_on(Network::Testnet.chain_id().value()));
        assert!(faucet_allowed_on(Network::Devnet.chain_id().value()));
        assert!(!faucet_allowed_on(Network::Mainnet.chain_id().value()));
        assert!(!faucet_allowed_on(1));
    }

    #[test]
    fn an_address_is_funded_once_per_cooldown() {
        let p = policy();
        let mut ledger = Ledger::default();
        let to = Address::from([7u8; 32]);
        ledger.check(&p, &to, ip(1), 1_000).unwrap();
        ledger.record(&p, to, ip(1), 1_000);
        let refusal = ledger.check(&p, &to, ip(2), 1_010).unwrap_err();
        assert_eq!(
            refusal,
            Refusal::AddressCooldown {
                retry_after: p.cooldown_secs - 10
            }
        );
        ledger
            .check(&p, &to, ip(2), 1_000 + p.cooldown_secs)
            .unwrap();
    }

    #[test]
    fn an_ip_is_funded_once_per_cooldown_whatever_the_address() {
        let p = policy();
        let mut ledger = Ledger::default();
        ledger.record(&p, Address::from([1u8; 32]), ip(9), 5_000);
        let refusal = ledger
            .check(&p, &Address::from([2u8; 32]), ip(9), 5_001)
            .unwrap_err();
        assert!(matches!(refusal, Refusal::IpCooldown { .. }));
    }

    #[test]
    fn the_daily_cap_stops_grants_and_resets_the_next_day() {
        let p = Policy::from_bud(100, 1, 250).unwrap();
        let mut ledger = Ledger::default();
        let day = 10 * super::SECONDS_PER_DAY;
        for i in 0..2u8 {
            let to = Address::from([i + 1; 32]);
            ledger.check(&p, &to, ip(i), day).unwrap();
            ledger.record(&p, to, ip(i), day);
        }
        assert_eq!(
            ledger
                .check(&p, &Address::from([9u8; 32]), ip(9), day + 5)
                .unwrap_err(),
            Refusal::DailyCap
        );
        ledger
            .check(
                &p,
                &Address::from([9u8; 32]),
                ip(9),
                day + super::SECONDS_PER_DAY,
            )
            .unwrap();
    }

    #[test]
    fn a_refused_check_records_nothing() {
        let p = policy();
        let mut ledger = Ledger::default();
        let to = Address::from([3u8; 32]);
        ledger.record(&p, to, ip(3), 100);
        let sent = ledger.sent_today;
        assert!(ledger.check(&p, &to, ip(4), 101).is_err());
        assert_eq!(ledger.sent_today, sent);
        assert!(!ledger.by_ip.contains_key(&ip(4)));
    }

    #[tokio::test]
    async fn a_partial_request_body_times_out() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let status = super::read_request_body(
                        request.into_body(),
                        std::time::Duration::from_millis(30),
                    )
                    .await
                    .unwrap_err();
                    Ok::<_, std::convert::Infallible>(super::error_response(
                        status,
                        "body timed out",
                    ))
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(b"POST /request HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{").await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        // The status line, not the body: the response text is built from the
        // half-sent request, and putting it in a panic message makes the test
        // log depend on remote bytes (the CodeQL log-injection rule reads a
        // panic message as a log sink). The length is a number and carries
        // no user text.
        assert!(
            response.starts_with("HTTP/1.1 408"),
            "the half-sent body was not refused with 408 ({} bytes received)",
            response.len()
        );
        server.await.unwrap();
    }

    #[test]
    fn a_request_names_one_valid_non_zero_address() {
        let hex = "ab".repeat(32);
        let ok = format!("{{\"address\":\"0x{hex}\"}}");
        assert_eq!(
            parse_request(ok.as_bytes()).unwrap(),
            Address::from_hex(&hex).unwrap()
        );
        assert!(parse_request(b"{}").is_err());
        assert!(parse_request(b"not json").is_err());
        assert!(parse_request(b"{\"address\":\"0x1234\"}").is_err());
        let zero = format!("{{\"address\":\"{}\"}}", "00".repeat(32));
        assert!(parse_request(zero.as_bytes()).is_err());
    }

    #[test]
    fn node_numbers_parse_as_hex_or_decimal() {
        assert_eq!(rpc_u64(&serde_json::json!("0x2a"), "x").unwrap(), 42);
        assert_eq!(rpc_u64(&serde_json::json!("42"), "x").unwrap(), 42);
        assert!(rpc_u64(&serde_json::json!(42), "x").is_err());
    }

    /// The faucet signs a V5 transfer the node's own verifier accepts, from
    /// the address its seed derives.
    #[test]
    fn a_grant_is_a_v5_transfer_the_node_verifies() {
        let key = budlum_core::crypto::primitives::WalletKeyPair::from_seed(&[5u8; 32]);
        let again = budlum_core::crypto::primitives::WalletKeyPair::from_seed(&[5u8; 32]);
        assert_eq!(key.address(), again.address(), "the seed fixes the address");
        let mut tx = budlum_core::core::transaction::Transaction::new_with_chain_id(
            key.address(),
            Address::from([8u8; 32]),
            policy().amount,
            1,
            0,
            Vec::new(),
            Network::Testnet.chain_id().value(),
            budlum_core::core::transaction::TransactionType::Transfer,
        );
        tx.sign_v5(&key);
        assert_eq!(
            tx.signature_version,
            budlum_core::core::transaction::SIGNATURE_VERSION_V5
        );
        assert!(tx.verify());
    }
}
