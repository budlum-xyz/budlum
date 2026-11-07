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
//! A request also carries a small proof of work (section 11.9 item 3). The
//! caller fetches a challenge bound to its address and to the current
//! difficulty, then submits the challenge and a nonce. Difficulty rises one
//! bit for each doubling of the target daily demand, capped at twenty bits,
//! so a busy day costs a bot more work without pricing out a phone.
//!
//! The limits live in memory. A restart forgets cooldowns, the daily cap and
//! the demand count, and it also rotates the challenge secret; only the
//! faucet balance is an absolute bound across restarts.
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
//!     --key-file ./secrets/faucet.seed --listen 127.0.0.1:18600 --allow-direct
//! curl -X POST http://127.0.0.1:18600/challenge -d '{"address":"0x..."}'
//! # solve the returned challenge at the returned difficulty, then:
//! curl -X POST http://127.0.0.1:18600/request \
//!     -d '{"address":"0x...","pow":{"challenge":"...","issued_at":0,\
//!          "difficulty":8,"nonce":1234}}'
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
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};

#[path = "support/http.rs"]
mod http_support;

/// TESTNET-DEFAULT: 100 BUD per request.
const DEFAULT_AMOUNT_BUD: u64 = 100;
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
const MAX_TRACKED_KEYS: usize = 200_000;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
/// TESTNET-DEFAULT: one request costs eight leading zero bits at the target
/// daily demand and never more than twenty (section 11.9 item 3).
const BASE_POW_BITS: u32 = 8;
const MAX_POW_BITS: u32 = 20;
/// TESTNET-DEFAULT: demand above 1 000 requests per UTC day raises the
/// difficulty one bit per doubling of that demand (R-15).
const POW_TARGET_REQUESTS_PER_DAY: u64 = 1_000;
/// A solved challenge cannot be saved for a quieter day.
const CHALLENGE_TTL_SECS: u64 = 300;
const CHALLENGE_TAG: &[u8] = b"BDLM_FAUCET_POW_CHALLENGE_V1";
const WORK_TAG: &[u8] = b"BDLM_FAUCET_POW_WORK_V1";

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
    /// Serve faucet requests.
    Serve {
        /// The node's public JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:18545")]
        rpc_url: String,
        /// The faucet key file written by `keygen`.
        #[arg(long)]
        key_file: String,
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
#[derive(Debug, Default)]
struct Ledger {
    by_address: BTreeMap<Address, u64>,
    by_ip: BTreeMap<IpAddr, u64>,
    day: u64,
    sent_today: u64,
    /// Every `/request` attempt, granted or refused. Difficulty follows
    /// demand, not the number of successful grants.
    requests_today: u64,
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

    /// Count one request attempt toward the current day's demand.
    fn note_request(&mut self, now: u64) {
        self.roll_day(now);
        self.requests_today = self.requests_today.saturating_add(1);
    }

    fn roll_day(&mut self, now: u64) {
        let day = now / SECONDS_PER_DAY;
        // Ported from open PR #34, which found this bug: a wall-clock
        // correction backwards must not reset the daily cap (or the demand
        // counter) a second time. Keep the newest day seen until the clock
        // catches up again.
        if day > self.day {
            self.day = day;
            self.sent_today = 0;
            self.requests_today = 0;
        }
    }

    fn forget_expired(&mut self, policy: &Policy, now: u64) {
        let live = |last: &u64| last.saturating_add(policy.cooldown_secs) > now;
        self.by_address.retain(|_, last| live(last));
        self.by_ip.retain(|_, last| live(last));
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
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err("address must be 32 bytes of hex".into());
    }
    let address = Address::from_hex(hex).map_err(|e| format!("invalid address: {e}"))?;
    if address == Address::zero() {
        return Err("the zero address cannot receive".into());
    }
    Ok(address)
}

/// The proof-of-work fields of a `/request` body, issued by `/challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PowSolution {
    challenge: [u8; 32],
    issued_at: u64,
    difficulty: u32,
    nonce: u64,
}

/// Read the proof-of-work fields. A body without them is refused with the
/// name of the endpoint that issues them, never with a silent free grant.
fn parse_pow(body: &[u8]) -> Result<PowSolution, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("request is not JSON: {e}"))?;
    let pow = value
        .get("pow")
        .ok_or("request needs a \"pow\" object; fetch one from POST /challenge")?;
    let raw = pow
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .ok_or("pow needs a \"challenge\" hex string")?;
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err("pow challenge must be 32 bytes of hex".into());
    }
    let bytes = hex::decode(hex).map_err(|e| format!("pow challenge is not hex: {e}"))?;
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&bytes);
    let issued_at = pow
        .get("issued_at")
        .and_then(serde_json::Value::as_u64)
        .ok_or("pow needs an \"issued_at\" timestamp")?;
    let bits = pow
        .get("difficulty")
        .and_then(serde_json::Value::as_u64)
        .ok_or("pow needs a \"difficulty\"")?;
    let difficulty = u32::try_from(bits).map_err(|_| "pow difficulty is out of range")?;
    let nonce = pow
        .get("nonce")
        .and_then(serde_json::Value::as_u64)
        .ok_or("pow needs a \"nonce\"")?;
    Ok(PowSolution {
        challenge,
        issued_at,
        difficulty,
        nonce,
    })
}

/// The challenge is bound to one address, one issuing second and one
/// difficulty by a per-process secret. A caller cannot mint a challenge with
/// a lower difficulty, or for another address, without that secret. Every
/// preimage field is fixed width, so the concatenation is unambiguous.
fn pow_challenge(secret: &[u8; 32], to: &Address, issued_at: u64, difficulty: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_TAG);
    hasher.update(secret);
    hasher.update(to.as_bytes());
    hasher.update(issued_at.to_le_bytes());
    hasher.update(difficulty.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest
}

/// Leading zero bits of a digest, counted over whole bytes first.
const fn pow_leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0u32;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// Does `nonce` solve `challenge` at `difficulty`?
fn pow_work_meets(challenge: &[u8; 32], nonce: u64, difficulty: u32) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(WORK_TAG);
    hasher.update(challenge);
    hasher.update(nonce.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    pow_leading_zero_bits(&digest) >= difficulty
}

/// Verify a solution against the current difficulty and the wall clock.
fn verify_pow(
    secret: &[u8; 32],
    to: &Address,
    solution: &PowSolution,
    now: u64,
    min_difficulty: u32,
) -> Result<(), String> {
    if solution.difficulty > MAX_POW_BITS {
        return Err("pow difficulty is above the ceiling".into());
    }
    if solution.difficulty < min_difficulty {
        return Err("pow difficulty is older than the current one; fetch a new challenge".into());
    }
    if solution.issued_at > now || now.saturating_sub(solution.issued_at) > CHALLENGE_TTL_SECS {
        return Err("pow challenge expired or is dated in the future".into());
    }
    if pow_challenge(secret, to, solution.issued_at, solution.difficulty) != solution.challenge {
        return Err("pow challenge was not issued for this address".into());
    }
    if !pow_work_meets(&solution.challenge, solution.nonce, solution.difficulty) {
        return Err("pow work does not meet the required difficulty".into());
    }
    Ok(())
}

/// Demand-based difficulty: one extra bit per doubling of the target daily
/// demand, capped so a busy day never makes the work unbounded (R-15).
const fn difficulty_for(requests_today: u64) -> u32 {
    let ceiling = MAX_POW_BITS - BASE_POW_BITS;
    let mut level = 0u32;
    let mut threshold = POW_TARGET_REQUESTS_PER_DAY;
    while requests_today >= threshold && level < ceiling {
        level += 1;
        threshold = threshold.saturating_mul(2);
    }
    BASE_POW_BITS + level
}

/// Seconds since the Unix epoch. The faucet uses this only for cooldowns and
/// challenge freshness; it never enters consensus state.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
}

impl Node {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{method}: node unreachable: {e}"))?;
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
    /// Per-process secret binding a challenge to its address, issuing second
    /// and difficulty. Generated at startup, never persisted or logged.
    pow_secret: [u8; 32],
    /// Do not queue an unbounded number of grants behind the nonce lock.
    grant_slots: Arc<Semaphore>,
    /// The ledger and the next nonce to use, under one lock so two requests
    /// cannot pass the same cooldown or sign with the same nonce.
    state: Mutex<(Ledger, u64)>,
}

impl Faucet {
    /// Issue a fresh challenge for `to` at the demand-based difficulty now in
    /// force. The challenge is address bound, so it cannot be solved once and
    /// replayed for a different recipient.
    async fn challenge(&self, to: Address, now: u64) -> serde_json::Value {
        let mut state = self.state.lock().await;
        state.0.roll_day(now);
        let difficulty = difficulty_for(state.0.requests_today);
        let challenge = pow_challenge(&self.pow_secret, &to, now, difficulty);
        serde_json::json!({
            "address": format!("0x{}", to.to_hex()),
            "challenge": hex::encode(challenge),
            "issued_at": now,
            "difficulty": difficulty,
            "expires_at": now.saturating_add(CHALLENGE_TTL_SECS),
        })
    }

    /// Count one request attempt and return the difficulty a solution must
    /// meet from this moment on.
    async fn note_request_and_difficulty(&self, now: u64) -> u32 {
        let mut state = self.state.lock().await;
        state.0.note_request(now);
        difficulty_for(state.0.requests_today)
    }

    async fn grant(
        &self,
        to: Address,
        ip: IpAddr,
    ) -> Result<serde_json::Value, (StatusCode, String)> {
        let now = unix_now();
        let mut state = self.state.lock().await;
        let (ledger, next_nonce) = &mut *state;
        ledger
            .check(&self.policy, &to, ip, now)
            .map_err(|refusal| (StatusCode::TOO_MANY_REQUESTS, refusal.message()))?;

        let chain_nonce = self
            .node
            .call("bud_getNonce", serde_json::json!([self.address.to_hex()]))
            .await
            .and_then(|v| rpc_u64(&v, "bud_getNonce"))
            .map_err(|e| upstream_failure("bud_getNonce", &e))?;
        let nonce = chain_nonce.max(*next_nonce);
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
        ledger.record(&self.policy, to, ip, now);
        let hash = self
            .node
            .call("bud_sendRawTransaction", serde_json::json!([tx]))
            .await
            .map_err(|e| {
                // The upstream text can carry the node's URL and diagnostics,
                // and this body is served to anonymous callers.
                eprintln!("budlum-faucet: bud_sendRawTransaction failed: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    "submission failed or its reply was lost; the allowance is reserved"
                        .to_string(),
                )
            })?;

        *next_nonce = nonce.saturating_add(1);
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
            "sent_today_atoms": state.0.sent_today,
            "requests_today": state.0.requests_today,
            "pow_difficulty": difficulty_for(state.0.requests_today),
        })
    }
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
    if method == Method::POST && path == "/challenge" {
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
        let challenge = faucet.challenge(to, unix_now()).await;
        return Ok(json_response(StatusCode::OK, &challenge));
    }
    if method != Method::POST || path != "/request" {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "POST /request, POST /challenge or GET /health",
        ));
    }
    let ip = match faucet.identity.client_ip(peer.ip(), request.headers()) {
        Ok(ip) => ip,
        Err(message) => return Ok(error_response(StatusCode::BAD_REQUEST, message)),
    };
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
    let pow = match parse_pow(&body) {
        Ok(pow) => pow,
        Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, &e)),
    };
    let now = unix_now();
    let min_difficulty = faucet.note_request_and_difficulty(now).await;
    if let Err(e) = verify_pow(&faucet.pow_secret, &to, &pow, now, min_difficulty) {
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
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|e| format!("{path} is not hex: {e}"))?;
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
    listen: &str,
    policy: Policy,
    trusted_proxies: Vec<IpAddr>,
    allow_direct: bool,
) -> Result<(), String> {
    let identity = http_support::ClientIdentity::new(allow_direct, trusted_proxies)?;
    let key = WalletKeyPair::from_seed(&read_seed(key_file)?);
    let address = key.address();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;
    let node = Node { url: rpc_url, http };
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
    // Challenges die with the process: a restart cannot reuse a solved
    // challenge, and no key material is written for the work check.
    let mut pow_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pow_secret);
    let faucet = Arc::new(Faucet {
        node,
        key,
        address,
        chain_id,
        policy,
        identity,
        pow_secret,
        grant_slots: Arc::new(Semaphore::new(1)),
        state: Mutex::new((Ledger::default(), 0)),
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
        Command::Serve {
            rpc_url,
            key_file,
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
        difficulty_for, faucet_allowed_on, parse_pow, parse_request, pow_challenge,
        pow_work_meets, rpc_u64, verify_pow, Ledger, Policy, PowSolution, Refusal, BASE_POW_BITS,
        CHALLENGE_TTL_SECS, DEFAULT_AMOUNT_BUD, DEFAULT_COOLDOWN_SECS, DEFAULT_DAILY_CAP_BUD,
        MAX_POW_BITS, POW_TARGET_REQUESTS_PER_DAY,
    };
    use budlum_core::core::address::Address;
    use budlum_core::core::chain_config::Network;
    use std::net::{IpAddr, Ipv6Addr};

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

    /// WP-41: the three published limits hold at once, with distinct
    /// addresses and client IPs so only the daily cap can stop the third
    /// grant.
    #[test]
    fn faucet_limits_hold() {
        let p = Policy::from_bud(100, 1, 250).unwrap();
        assert_eq!(p.amount, budlum_core::tokenomics::bud(100));
        let mut ledger = Ledger::default();
        let day = 7 * super::SECONDS_PER_DAY;
        for i in 0u8..2 {
            let mut bytes = [9u8; 32];
            bytes[0] = i + 1;
            let to = Address::from(bytes);
            let client = IpAddr::V6(Ipv6Addr::from(u128::from(i)));
            ledger.check(&p, &to, client, day).unwrap();
            ledger.record(&p, to, client, day);
        }
        let mut bytes = [9u8; 32];
        bytes[0] = 3;
        let refusal = ledger
            .check(
                &p,
                &Address::from(bytes),
                IpAddr::V6(Ipv6Addr::from(3u128)),
                day,
            )
            .unwrap_err();
        assert_eq!(refusal, Refusal::DailyCap);
    }

    /// Ported from open PR #34: a backwards clock correction must not give
    /// the caller another daily cap, and must not lower the work difficulty
    /// by resetting the demand count either.
    #[test]
    fn faucet_limits_hold_when_the_clock_moves_backwards() {
        let p = Policy::from_bud(100, 1, 100).unwrap();
        let mut ledger = Ledger::default();
        let today = 10 * super::SECONDS_PER_DAY;
        ledger.note_request(today);
        ledger
            .check(&p, &Address::from([1u8; 32]), ip(1), today)
            .unwrap();
        ledger.record(&p, Address::from([1u8; 32]), ip(1), today);
        ledger.note_request(today - super::SECONDS_PER_DAY);
        assert_eq!(ledger.requests_today, 2, "demand survives a clock rollback");
        assert_eq!(
            ledger.check(&p, &Address::from([2u8; 32]), ip(2), today),
            Err(Refusal::DailyCap)
        );
        ledger
            .check(
                &p,
                &Address::from([2u8; 32]),
                ip(2),
                today + super::SECONDS_PER_DAY,
            )
            .unwrap();
    }

    /// WP-41: difficulty rises with demand and resets on a new UTC day.
    #[test]
    fn faucet_pow_difficulty_adjusts() {
        assert_eq!(difficulty_for(0), BASE_POW_BITS);
        assert_eq!(
            difficulty_for(POW_TARGET_REQUESTS_PER_DAY - 1),
            BASE_POW_BITS
        );
        assert_eq!(
            difficulty_for(POW_TARGET_REQUESTS_PER_DAY),
            BASE_POW_BITS + 1
        );
        assert_eq!(
            difficulty_for(POW_TARGET_REQUESTS_PER_DAY * 2),
            BASE_POW_BITS + 2
        );
        assert_eq!(difficulty_for(u64::MAX), MAX_POW_BITS);
        let mut ledger = Ledger::default();
        let day = 4 * super::SECONDS_PER_DAY;
        for _ in 0..POW_TARGET_REQUESTS_PER_DAY {
            ledger.note_request(day);
        }
        assert_eq!(difficulty_for(ledger.requests_today), BASE_POW_BITS + 1);
        ledger.note_request(day + super::SECONDS_PER_DAY);
        assert_eq!(ledger.requests_today, 1);
        assert_eq!(difficulty_for(ledger.requests_today), BASE_POW_BITS);
    }

    /// WP-41: a solution is bound to one address, one issuing second, the
    /// current difficulty and the work itself.
    #[test]
    fn faucet_pow_accepts_only_fresh_bound_work() {
        let secret = [7u8; 32];
        let to = Address::from([1u8; 32]);
        let issued_at = 1_800_000_000u64;
        let difficulty = BASE_POW_BITS;
        let challenge = pow_challenge(&secret, &to, issued_at, difficulty);
        let mut nonce = 0u64;
        while !pow_work_meets(&challenge, nonce, difficulty) {
            nonce += 1;
            assert!(nonce < 200_000, "no nonce met the base difficulty");
        }
        let ok = PowSolution {
            challenge,
            issued_at,
            difficulty,
            nonce,
        };
        assert!(verify_pow(&secret, &to, &ok, issued_at + 10, difficulty).is_ok());
        assert!(
            verify_pow(
                &secret,
                &Address::from([2u8; 32]),
                &ok,
                issued_at + 10,
                difficulty
            )
            .is_err(),
            "a challenge solved for one address must not fund another"
        );
        assert!(
            verify_pow(
                &secret,
                &to,
                &ok,
                issued_at + CHALLENGE_TTL_SECS + 1,
                difficulty
            )
            .is_err(),
            "an expired challenge must be refused"
        );
        assert!(verify_pow(&secret, &to, &ok, issued_at - 1, difficulty).is_err());
        assert!(
            verify_pow(&secret, &to, &ok, issued_at + 10, difficulty + 1).is_err(),
            "a difficulty that has risen must retire older challenges"
        );
        let mut bad_nonce = ok;
        bad_nonce.nonce = nonce.wrapping_add(1);
        assert!(verify_pow(&secret, &to, &bad_nonce, issued_at + 10, difficulty).is_err());
        let forged = PowSolution {
            challenge: pow_challenge(&[0u8; 32], &to, issued_at, 0),
            difficulty: 0,
            ..ok
        };
        assert!(
            verify_pow(&secret, &to, &forged, issued_at + 10, 0).is_err(),
            "a challenge minted with another secret must be refused"
        );
    }

    /// WP-41: the request parser refuses a body with no work and malformed
    /// work, rather than granting for free.
    #[test]
    fn faucet_pow_request_parsing_is_strict() {
        let hex = "ab".repeat(32);
        let good = format!(
            "{{\"address\":\"0x{hex}\",\"pow\":{{\"challenge\":\"{hex}\",\
             \"issued_at\":10,\"difficulty\":8,\"nonce\":42}}}}"
        );
        let solution = parse_pow(good.as_bytes()).unwrap();
        assert_eq!(solution.challenge, [0xabu8; 32]);
        assert_eq!(solution.issued_at, 10);
        assert_eq!(solution.difficulty, 8);
        assert_eq!(solution.nonce, 42);
        assert!(parse_pow(format!("{{\"address\":\"0x{hex}\"}}").as_bytes()).is_err());
        let short = "{\"pow\":{\"challenge\":\"00\",\"issued_at\":10,\"difficulty\":8,\"nonce\":42}}";
        assert!(parse_pow(short.as_bytes()).is_err());
        let invalid = format!(
            "{{\"pow\":{{\"challenge\":\"{}\",\"issued_at\":10,\"difficulty\":8,\"nonce\":42}}}}",
            "zz".repeat(32)
        );
        assert!(parse_pow(invalid.as_bytes()).is_err());
        let huge = format!(
            "{{\"pow\":{{\"challenge\":\"{hex}\",\"issued_at\":10,\
             \"difficulty\":4294967296,\"nonce\":42}}}}"
        );
        assert!(parse_pow(huge.as_bytes()).is_err(), "difficulty overflow");
    }

    /// WP-41: the grant remains an ordinary signed V5 transfer. No credit
    /// RPC, no direct balance write and no minting path is involved.
    #[test]
    fn faucet_sends_signed_transfer_only() {
        use budlum_core::core::transaction::{Transaction, TransactionType, SIGNATURE_VERSION_V5};
        let key = budlum_core::crypto::primitives::WalletKeyPair::from_seed(&[5u8; 32]);
        let mut tx = Transaction::new_with_chain_id(
            key.address(),
            Address::from([8u8; 32]),
            policy().amount,
            1,
            0,
            Vec::new(),
            Network::Testnet.chain_id().value(),
            TransactionType::Transfer,
        );
        tx.sign_v5(&key);
        assert!(matches!(tx.tx_type, TransactionType::Transfer));
        assert!(tx.data.is_empty());
        assert_eq!(tx.signature_version, SIGNATURE_VERSION_V5);
        assert!(tx.verify());
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
