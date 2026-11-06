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
//! The limits live in memory. A restart forgets cooldowns and the daily cap,
//! so operators must protect restarts as well as the funding key; only the
//! faucet balance is an absolute bound across restarts.
//!
//! # Proof of work
//!
//! Every grant also carries a small proof of work (section 11.9). `POST
//! /challenge` issues a challenge bound to the UTC day, the client IP and the
//! recipient address. The number of leading zero bits the proof needs rises
//! with the previous UTC day's demand and falls back when demand falls. A
//! refusal costs the caller its work but reserves no allowance.
//!
//! # Request shapes
//!
//! `POST /request` is the native shape. `POST /mobile/request` is the mobile
//! client shape and names `client = "mobile"`. `POST /requestAirdrop` is the
//! Solana JSON-RPC shape routed here by the compatibility gateway; the gateway
//! translates the base58 public key to the 32-byte address the node uses and
//! attaches its proof of work in a `budlum` object. All three lead to the same
//! ordinary signed transfer and the same three limits.
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
//! curl -X POST http://127.0.0.1:18600/request -d '{"address":"0x..."}'
//! ```
//!
//! The key file holds the 32-byte ML-DSA-87 seed as hex. It is read from a
//! path, never from the command line or the environment, and `keygen`
//! creates it with owner-only permissions.

use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::hash::hash_fields_bytes;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::WalletKeyPair;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use prometheus::{IntCounter, Registry, TextEncoder};
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
/// TESTNET-DEFAULT: leading zero bits a proof carries on a quiet day.
const POW_BASE_BITS: u8 = 8;
/// TESTNET-DEFAULT: the ceiling. One grant must stay cheap on a phone.
const POW_MAX_BITS: u8 = 24;
/// TESTNET-DEFAULT: requests per UTC day that leave the difficulty at the base.
const POW_DEMAND_TARGET: u64 = 1_000;
/// TESTNET-DEFAULT: the largest amount a routed `requestAirdrop` may name.
/// The amount never changes the grant: the faucet always sends its fixed sum.
const MAX_AIRDROP_REQUEST: u64 = 1_000_000_000;
/// Domain tags keep a challenge from being replayed as a proof and back.
const POW_CHALLENGE_DOMAIN: &[u8] = b"BDLM/FAUCET/POW/V1/CHALLENGE";
const POW_PROOF_DOMAIN: &[u8] = b"BDLM/FAUCET/POW/V1/PROOF";
const CHALLENGE_HEX_LEN: usize = 64;

/// Which HTTP shape carried a request. All three lead to the same grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestShape {
    Native,
    Mobile,
    SolanaAirdrop,
}

/// The fields the faucet needs before it will sign anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GrantRequest {
    to: Address,
    challenge: [u8; 32],
    nonce: u64,
}

/// One extra bit of work for every doubling of the previous day's demand.
/// The arithmetic is integer only: a floating factor would make the difficulty
/// depend on the toolchain instead of on a rule.
fn pow_difficulty_for(previous_day_requests: u64) -> u8 {
    let mut demand = previous_day_requests;
    let mut extra = 0u8;
    while demand > POW_DEMAND_TARGET && extra < POW_MAX_BITS - POW_BASE_BITS {
        demand /= 2;
        extra = extra.saturating_add(1);
    }
    POW_BASE_BITS.saturating_add(extra)
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// A challenge is bound to the server secret, the UTC day, the client IP and
/// the recipient. Nobody can precompute work for another address or reuse a
/// proof from another proxy address.
fn pow_challenge(secret: &[u8; 32], day: u64, ip: IpAddr, to: &Address) -> [u8; 32] {
    let day_bytes = day.to_le_bytes();
    let ip = ip_bytes(ip);
    hash_fields_bytes(&[
        POW_CHALLENGE_DOMAIN,
        secret.as_slice(),
        &day_bytes[..],
        ip.as_slice(),
        &to.as_bytes()[..],
    ])
}

fn pow_digest(challenge: &[u8; 32], to: &Address, nonce: u64) -> [u8; 32] {
    let nonce_bytes = nonce.to_le_bytes();
    hash_fields_bytes(&[
        POW_PROOF_DOMAIN,
        challenge.as_slice(),
        &to.as_bytes()[..],
        &nonce_bytes[..],
    ])
}

/// Leading zero bits of a digest, without a cast. An all-zero digest reports
/// 255: the difficulty ceiling is far below that, so the saturation is safe.
fn leading_zero_bits(digest: &[u8; 32]) -> u8 {
    let mut bits = 0u8;
    for byte in digest {
        if *byte == 0 {
            bits = bits.saturating_add(8);
        } else {
            let mut mask = 0x80u8;
            while mask != 0 && mask & *byte == 0 {
                bits = bits.saturating_add(1);
                mask >>= 1;
            }
            break;
        }
    }
    bits
}

fn proof_is_valid(challenge: &[u8; 32], to: &Address, nonce: u64, difficulty: u8) -> bool {
    leading_zero_bits(&pow_digest(challenge, to, nonce)) >= difficulty
}

fn parse_challenge(raw: &str) -> Result<[u8; 32], String> {
    let raw = raw.strip_prefix("0x").unwrap_or(raw);
    if raw.len() != CHALLENGE_HEX_LEN {
        return Err("the proof-of-work challenge must be 32 bytes of hex".into());
    }
    let bytes = hex::decode(raw).map_err(|e| format!("invalid challenge: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Native, mobile and routed Solana bodies all carry the same address and the
/// same proof of work. `serde_json` is the only decoder: no new parser enters
/// the tree, so the fuzz-target rule for a new parser is not engaged.
fn parse_grant_request(shape: RequestShape, body: &[u8]) -> Result<GrantRequest, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("request is not JSON: {e}"))?;
    let (address_raw, proof) = match shape {
        RequestShape::Native => (
            value
                .get("address")
                .and_then(serde_json::Value::as_str)
                .ok_or("request needs an \"address\" string")?,
            &value,
        ),
        RequestShape::Mobile => {
            let client = value
                .get("client")
                .and_then(serde_json::Value::as_str)
                .ok_or("a mobile request needs a \"client\" string")?;
            if client != "mobile" {
                return Err("a mobile request must name client \"mobile\"".into());
            }
            (
                value
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("request needs an \"address\" string")?,
                &value,
            )
        }
        RequestShape::SolanaAirdrop => {
            let rpc = value
                .get("jsonrpc")
                .and_then(serde_json::Value::as_str)
                .ok_or("requestAirdrop needs \"jsonrpc\": \"2.0\"")?;
            if rpc != "2.0" {
                return Err("requestAirdrop needs JSON-RPC 2.0".into());
            }
            let method = value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .ok_or("requestAirdrop needs a \"method\" string")?;
            if method != "requestAirdrop" {
                return Err("only requestAirdrop is routed to the faucet".into());
            }
            let params = value
                .get("params")
                .and_then(serde_json::Value::as_array)
                .ok_or("requestAirdrop needs a \"params\" array")?;
            let address_raw = params
                .first()
                .and_then(serde_json::Value::as_str)
                .ok_or("requestAirdrop params[0] is the translated 32-byte address")?;
            let amount = params
                .get(1)
                .and_then(serde_json::Value::as_u64)
                .ok_or("requestAirdrop params[1] is a positive amount")?;
            if amount == 0 || amount > MAX_AIRDROP_REQUEST {
                return Err("requestAirdrop amount is out of range; the grant is fixed".into());
            }
            let proof = value
                .get("budlum")
                .ok_or("requestAirdrop needs a \"budlum\" proof-of-work object")?;
            (address_raw, proof)
        }
    };
    let to = address_from_str(address_raw)?;
    let challenge_raw = proof
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        .ok_or("request needs a \"challenge\" string")?;
    let nonce = proof
        .get("nonce")
        .and_then(serde_json::Value::as_u64)
        .ok_or("request needs a \"nonce\" integer")?;
    Ok(GrantRequest {
        to,
        challenge: parse_challenge(challenge_raw)?,
        nonce,
    })
}

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
    InvalidProofOfWork,
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
            Self::InvalidProofOfWork => {
                "the proof of work is missing, expired or below the current difficulty".into()
            }
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
    /// Every request that reaches the faucet, including refused ones. The next
    /// day's proof-of-work difficulty comes from this count.
    requests_today: u64,
    requests_previous_day: u64,
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

    /// Count a request for demand without granting anything.
    fn note_request(&mut self, now: u64) {
        self.roll_day(now);
        self.requests_today = self.requests_today.saturating_add(1);
    }

    /// The difficulty for the current day, from the previous day's demand.
    fn difficulty(&self) -> u8 {
        pow_difficulty_for(self.requests_previous_day)
    }

    fn roll_day(&mut self, now: u64) {
        let day = now / SECONDS_PER_DAY;
        // A wall-clock correction must not reset the cap a second time.
        // Keep the newest day seen until the clock catches up again.
        if day > self.day {
            self.day = day;
            self.sent_today = 0;
            self.requests_previous_day = self.requests_today;
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

fn address_from_str(raw: &str) -> Result<Address, String> {
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

/// The `address` field of a challenge request body.
fn parse_request(body: &[u8]) -> Result<Address, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("request is not JSON: {e}"))?;
    let raw = value
        .get("address")
        .and_then(serde_json::Value::as_str)
        .ok_or("request needs an \"address\" string")?;
    address_from_str(raw)
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
    /// Per-process secret for proof-of-work challenges. A restart issues new
    /// challenges; in-flight proofs must be fetched again, which is safe.
    pow_secret: [u8; 32],
    /// R-15 grant counter and the registry it is exposed through.
    grant_metric: IntCounter,
    metric_registry: Registry,
    identity: http_support::ClientIdentity,
    /// Do not queue an unbounded number of grants behind the nonce lock.
    grant_slots: Arc<Semaphore>,
    /// The ledger and the next nonce to use, under one lock so two requests
    /// cannot pass the same cooldown or sign with the same nonce.
    state: Mutex<(Ledger, u64)>,
}

impl Faucet {
    async fn grant(
        &self,
        request: GrantRequest,
        ip: IpAddr,
    ) -> Result<serde_json::Value, (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut state = self.state.lock().await;
        let (ledger, next_nonce) = &mut *state;
        ledger.note_request(now);
        let expected = pow_challenge(&self.pow_secret, now / SECONDS_PER_DAY, ip, &request.to);
        if request.challenge != expected
            || !proof_is_valid(&expected, &request.to, request.nonce, ledger.difficulty())
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Refusal::InvalidProofOfWork.message(),
            ));
        }
        ledger
            .check(&self.policy, &request.to, ip, now)
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
            request.to,
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
        ledger.record(&self.policy, request.to, ip, now);
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
        self.grant_metric.inc();
        Ok(serde_json::json!({
            "to": format!("0x{}", request.to.to_hex()),
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
            "pow_difficulty": state.0.difficulty(),
            "requests_today": state.0.requests_today,
            "requests_previous_day": state.0.requests_previous_day,
        })
    }

    /// Issue the challenge a client must solve. It stays valid until 00:00 UTC.
    async fn challenge_for(&self, ip: IpAddr, to: Address) -> serde_json::Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let day = now / SECONDS_PER_DAY;
        let difficulty = {
            let mut state = self.state.lock().await;
            state.0.roll_day(now);
            state.0.difficulty()
        };
        let challenge = pow_challenge(&self.pow_secret, day, ip, &to);
        serde_json::json!({
            "address": format!("0x{}", to.to_hex()),
            "challenge": hex::encode(challenge),
            "difficulty": difficulty,
            "expires_at": (day + 1) * SECONDS_PER_DAY,
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

/// The four write routes and the two read routes, in one place so the refusal
/// text cannot drift away from the dispatcher.
const ROUTE_HELP: &str =
    "POST /challenge, /request, /mobile/request, /requestAirdrop or GET /health, /metrics";

/// R-15: the faucet exports its own grant counter. It is a separate process
/// from the node, so it owns a separate registry instead of reporting a zero
/// next to the node's metrics.
fn metrics_response(registry: &Registry) -> Response<Full<Bytes>> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if prometheus::Encoder::encode(&encoder, &registry.gather(), &mut buffer).is_err() {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the faucet metrics could not be encoded",
        );
    }
    let mut response = Response::new(Full::new(Bytes::from(buffer)));
    *response.status_mut() = StatusCode::OK;
    if let Ok(value) = hyper::header::HeaderValue::from_str("text/plain; version=0.0.4") {
        response
            .headers_mut()
            .insert(hyper::header::CONTENT_TYPE, value);
    }
    response
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
        return Ok(metrics_response(&faucet.metric_registry));
    }
    if method != Method::POST {
        return Ok(error_response(StatusCode::NOT_FOUND, ROUTE_HELP));
    }
    let shape = match path.as_str() {
        "/challenge" => None,
        "/request" => Some(RequestShape::Native),
        "/mobile/request" => Some(RequestShape::Mobile),
        "/requestAirdrop" => Some(RequestShape::SolanaAirdrop),
        _ => return Ok(error_response(StatusCode::NOT_FOUND, ROUTE_HELP)),
    };
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
    let grant_request = match shape {
        None => {
            let to = match parse_request(&body) {
                Ok(to) => to,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, &e)),
            };
            return Ok(json_response(
                StatusCode::OK,
                &faucet.challenge_for(ip, to).await,
            ));
        }
        Some(shape) => match parse_grant_request(shape, &body) {
            Ok(grant_request) => grant_request,
            Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, &e)),
        },
    };
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
        faucet.grant(grant_request, ip).await
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
    let mut pow_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pow_secret);
    let metric_registry = Registry::new();
    let grant_metric = IntCounter::new(
        "budlum_faucet_grants_total",
        "Ordinary signed transfers the testnet faucet submitted",
    )
    .map_err(|e| format!("faucet grant metric: {e}"))?;
    metric_registry
        .register(Box::new(grant_metric.clone()))
        .map_err(|e| format!("faucet metric registry: {e}"))?;
    let faucet = Arc::new(Faucet {
        node,
        key,
        address,
        chain_id,
        policy,
        pow_secret,
        grant_metric,
        metric_registry,
        identity,
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
        faucet_allowed_on, leading_zero_bits, parse_challenge, parse_grant_request, parse_request,
        pow_challenge, pow_difficulty_for, pow_digest, proof_is_valid, rpc_u64, Ledger, Policy,
        Refusal, RequestShape, DEFAULT_AMOUNT_BUD, DEFAULT_COOLDOWN_SECS, DEFAULT_DAILY_CAP_BUD,
        MAX_AIRDROP_REQUEST, POW_BASE_BITS, POW_DEMAND_TARGET, POW_MAX_BITS, SECONDS_PER_DAY,
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
    fn faucet_limits_hold_when_the_clock_moves_backwards() {
        let p = Policy::from_bud(100, 1, 100).unwrap();
        let mut ledger = Ledger::default();
        let today = 10 * super::SECONDS_PER_DAY;
        let to = Address::from([1u8; 32]);
        ledger.check(&p, &to, ip(1), today).unwrap();
        ledger.record(&p, to, ip(1), today);

        // A backwards correction, then a return to the same day, must not
        // create either a second cap or a second daily reset.
        for now in [today - super::SECONDS_PER_DAY, today + 2] {
            assert_eq!(
                ledger.check(&p, &Address::from([2u8; 32]), ip(2), now),
                Err(Refusal::DailyCap)
            );
        }
        ledger
            .check(
                &p,
                &Address::from([2u8; 32]),
                ip(2),
                today + super::SECONDS_PER_DAY,
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

    /// Section 11.9: the three limits hold, and a request that is refused for
    /// missing work counts as demand but reserves no allowance.
    #[test]
    fn faucet_limits_hold() {
        let p = policy();
        let mut ledger = Ledger::default();
        let to = Address::from([11u8; 32]);
        let day = 12 * SECONDS_PER_DAY;
        ledger.check(&p, &to, ip(1), day).unwrap();
        ledger.record(&p, to, ip(1), day);
        assert!(matches!(
            ledger.check(&p, &to, ip(2), day + 1),
            Err(Refusal::AddressCooldown { .. })
        ));
        assert!(matches!(
            ledger.check(&p, &Address::from([12u8; 32]), ip(1), day + 1),
            Err(Refusal::IpCooldown { .. })
        ));
        let before = ledger.sent_today;
        ledger.note_request(day + 2);
        assert_eq!(ledger.sent_today, before, "demand is not a grant");
        assert_eq!(ledger.requests_today, 1);
        assert_eq!(ledger.difficulty(), POW_BASE_BITS);
    }

    /// Section 11.9 item 3: one extra bit per doubling of daily demand, with
    /// a ceiling, and a fall back when demand falls.
    #[test]
    fn faucet_pow_difficulty_adjusts() {
        assert_eq!(pow_difficulty_for(0), POW_BASE_BITS);
        assert_eq!(pow_difficulty_for(POW_DEMAND_TARGET), POW_BASE_BITS);
        assert_eq!(pow_difficulty_for(POW_DEMAND_TARGET + 1), POW_BASE_BITS + 1);
        assert_eq!(pow_difficulty_for(4 * POW_DEMAND_TARGET), POW_BASE_BITS + 2);
        assert_eq!(pow_difficulty_for(u64::MAX), POW_MAX_BITS);

        let mut ledger = Ledger::default();
        let day = 20 * SECONDS_PER_DAY;
        for _ in 0..(8 * POW_DEMAND_TARGET) {
            ledger.note_request(day);
        }
        ledger.note_request(day + SECONDS_PER_DAY);
        assert!(
            ledger.difficulty() > POW_BASE_BITS,
            "a busy previous day raises the difficulty"
        );
        assert_eq!(ledger.requests_today, 1, "the new day starts a new count");
        let busy = ledger.difficulty();
        ledger.note_request(day + 2 * SECONDS_PER_DAY);
        assert!(
            ledger.difficulty() <= busy,
            "a quiet previous day cannot raise the difficulty"
        );
    }

    /// The faucet signs an ordinary V5 transfer. It never credits outside a
    /// block and never serves a mainnet node.
    #[test]
    fn faucet_sends_signed_transfer_only() {
        let key = budlum_core::crypto::primitives::WalletKeyPair::from_seed(&[9u8; 32]);
        let mut tx = budlum_core::core::transaction::Transaction::new_with_chain_id(
            key.address(),
            Address::from([6u8; 32]),
            policy().amount,
            0,
            7,
            Vec::new(),
            Network::Testnet.chain_id().value(),
            budlum_core::core::transaction::TransactionType::Transfer,
        );
        tx.sign_v5(&key);
        assert!(tx.verify(), "the node's own verifier accepts the grant");
        assert_eq!(
            tx.tx_type,
            budlum_core::core::transaction::TransactionType::Transfer
        );
        assert_eq!(
            tx.signature_version,
            budlum_core::core::transaction::SIGNATURE_VERSION_V5
        );
        assert!(!faucet_allowed_on(Network::Mainnet.chain_id().value()));
    }

    #[test]
    fn pow_challenge_is_bound_to_address_ip_and_day() {
        let secret = [3u8; 32];
        let to = Address::from([4u8; 32]);
        let other = Address::from([5u8; 32]);
        let day = 30;
        let a = pow_challenge(&secret, day, ip(1), &to);
        assert_eq!(a, pow_challenge(&secret, day, ip(1), &to));
        assert_ne!(a, pow_challenge(&secret, day + 1, ip(1), &to));
        assert_ne!(a, pow_challenge(&secret, day, ip(2), &to));
        assert_ne!(a, pow_challenge(&secret, day, ip(1), &other));
        assert_ne!(a, pow_challenge(&[4u8; 32], day, ip(1), &to));
    }

    #[test]
    fn pow_proof_is_domain_separated_and_enforces_difficulty() {
        let challenge = [7u8; 32];
        let to = Address::from([8u8; 32]);
        let mut digest = [0xffu8; 32];
        digest[0] = 0;
        digest[1] = 0x0f;
        assert_eq!(leading_zero_bits(&digest), 12);
        assert!(leading_zero_bits(&[0u8; 32]) >= POW_MAX_BITS);
        let mut solved = None;
        for nonce in 0..200_000u64 {
            if proof_is_valid(&challenge, &to, nonce, POW_BASE_BITS) {
                solved = Some(nonce);
                break;
            }
        }
        let nonce = solved.expect("a base-difficulty proof exists in the sampled range");
        assert!(proof_is_valid(&challenge, &to, nonce, POW_BASE_BITS));
        assert!(!proof_is_valid(&challenge, &to, nonce, POW_BASE_BITS + 8));
        assert!(!proof_is_valid(
            &challenge,
            &Address::from([9u8; 32]),
            nonce,
            POW_BASE_BITS
        ));
        assert_ne!(
            pow_digest(&challenge, &to, nonce),
            pow_digest(&challenge, &to, nonce + 1)
        );
        assert_ne!(
            pow_digest(&challenge, &to, nonce),
            pow_challenge(&challenge, 0, ip(1), &to),
            "the proof and challenge domains stay apart"
        );
    }

    #[test]
    fn request_shapes_are_accepted_with_a_proof_of_work() {
        let secret = [1u8; 32];
        let to = Address::from([2u8; 32]);
        let expected = pow_challenge(&secret, 40, ip(7), &to);
        let challenge = hex::encode(expected);
        let native = format!(
            "{{\"address\":\"0x{}\",\"challenge\":\"{challenge}\",\"nonce\":5}}",
            to.to_hex()
        );
        let parsed = parse_grant_request(RequestShape::Native, native.as_bytes()).unwrap();
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.nonce, 5);
        assert_eq!(parsed.challenge, expected);

        let mobile = format!(
            "{{\"client\":\"mobile\",\"address\":\"0x{}\",\"challenge\":\"{challenge}\",\"nonce\":6}}",
            to.to_hex()
        );
        assert_eq!(
            parse_grant_request(RequestShape::Mobile, mobile.as_bytes())
                .unwrap()
                .nonce,
            6
        );

        let airdrop = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"0x{}\",100000000],\"budlum\":{{\"challenge\":\"{challenge}\",\"nonce\":7}}}}",
            to.to_hex()
        );
        let parsed = parse_grant_request(RequestShape::SolanaAirdrop, airdrop.as_bytes()).unwrap();
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.nonce, 7);
        assert_eq!(parsed.challenge, expected);
    }

    #[test]
    fn request_shapes_refuse_bad_bodies() {
        let to = Address::from([2u8; 32]);
        let challenge = "ab".repeat(32);
        let good = format!(
            "{{\"address\":\"0x{}\",\"challenge\":\"{challenge}\",\"nonce\":1}}",
            to.to_hex()
        );
        assert!(parse_grant_request(RequestShape::Native, b"not json").is_err());
        assert!(parse_grant_request(RequestShape::Native, b"{}").is_err());
        assert!(
            parse_grant_request(
                RequestShape::Native,
                good.replace("\"nonce\":1", "\"nonce\":-1").as_bytes()
            )
            .is_err(),
            "a negative nonce is not a u64"
        );
        assert!(
            parse_grant_request(
                RequestShape::Native,
                good.replace(&challenge, "abcd").as_bytes()
            )
            .is_err(),
            "a short challenge is refused"
        );
        assert!(parse_grant_request(RequestShape::Mobile, good.as_bytes()).is_err());
        let mobile = format!(
            "{{\"client\":\"mobile\",\"address\":\"0x{}\",\"challenge\":\"{challenge}\",\"nonce\":1}}",
            to.to_hex()
        );
        assert!(parse_grant_request(RequestShape::Mobile, mobile.as_bytes()).is_ok());
        assert!(
            parse_grant_request(
                RequestShape::Mobile,
                mobile.replace("\"mobile\"", "\"desktop\"").as_bytes()
            )
            .is_err(),
            "another client name cannot use the mobile shape"
        );
        for amount in [0, MAX_AIRDROP_REQUEST + 1] {
            let body = format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"requestAirdrop\",\"params\":[\"0x{}\",{amount}],\"budlum\":{{\"challenge\":\"{challenge}\",\"nonce\":1}}}}",
                to.to_hex()
            );
            assert!(
                parse_grant_request(RequestShape::SolanaAirdrop, body.as_bytes()).is_err(),
                "an out-of-range airdrop amount is refused"
            );
        }
        let no_proof = format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"requestAirdrop\",\"params\":[\"0x{}\",1]}}",
            to.to_hex()
        );
        assert!(
            parse_grant_request(RequestShape::SolanaAirdrop, no_proof.as_bytes()).is_err(),
            "a routed airdrop still carries its proof of work"
        );
        assert!(parse_challenge("abcd").is_err());
        assert!(parse_challenge(&challenge).is_ok());
        // The only decoder is serde_json. Arbitrary bytes are refused, never
        // interpreted, and never panic.
        for body in [
            b"".as_slice(),
            b"\xff\xfe".as_slice(),
            b"[]".as_slice(),
            b"null".as_slice(),
        ] {
            for shape in [
                RequestShape::Native,
                RequestShape::Mobile,
                RequestShape::SolanaAirdrop,
            ] {
                assert!(parse_grant_request(shape, body).is_err());
            }
        }
    }

    /// The required launch-boundary alerts exist and every Budlum metric an
    /// expression names is a metric the node really registers.
    #[test]
    fn alert_rules_reference_existing_metrics() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let metrics = std::fs::read_to_string(root.join("src/core/metrics.rs")).unwrap();
        let mut registered = std::collections::BTreeSet::new();
        for metric in metrics
            .split('"')
            .filter(|part| part.starts_with("budlum_"))
        {
            registered.insert(metric.to_string());
        }
        // The faucet is a separate process and exports its own counter.
        let faucet = std::fs::read_to_string(root.join("src/bin/budlum-faucet.rs")).unwrap();
        assert!(faucet.contains("\"budlum_faucet_grants_total\""));
        assert!(faucet.contains("path == \"/metrics\""));
        registered.insert("budlum_faucet_grants_total".to_string());
        assert!(
            registered.len() > 100,
            "the metric scan found too few registered metrics"
        );

        let alerts = std::fs::read_to_string(root.join("ops/monitoring/alerts.yml")).unwrap();
        let mut names = std::collections::BTreeSet::new();
        for line in alerts.lines() {
            let line = line.trim_start();
            if let Some(name) = line.strip_prefix("- alert:") {
                names.insert(name.trim().to_string());
            }
            if let Some(expr) = line.strip_prefix("expr:") {
                let mut s = expr;
                while let Some(pos) = s.find("budlum_") {
                    s = &s[pos..];
                    let metric: String = s
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    assert!(
                        registered.contains(&metric),
                        "an alert expression names a metric the node does not export: {metric}"
                    );
                    s = &s[metric.len()..];
                }
            }
        }
        for required in [
            "budlum_finality_stalled",
            "budlum_finality_lag_checkpoints",
            "budlum_bud3_segments_at_risk",
            "budlum_bud3_repair_backlog",
            "budlum_relay_reservations",
            "budlum_ee_fault_total",
            "budlum_state_root_mismatch_total",
            "budlum_rpc_rate_limited_total",
        ] {
            assert!(
                names.contains(required),
                "a required launch-boundary alert is missing: {required}"
            );
        }
    }

    /// DOC-GAP-01 and DOC-GAP-04: the shipped testnet profile names a usable
    /// SoftHSM configuration, and the systemd unit carries its context.
    #[test]
    fn testnet_first_run_has_softhsm_context() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config = std::fs::read_to_string(root.join("config/testnet.toml")).unwrap();
        assert!(config.contains("[validator.signer.pkcs11]"));
        assert!(config.contains("module_path ="));
        assert!(config.contains("token_pin_env ="));
        let softhsm = std::fs::read_to_string(root.join("ops/softhsm2.conf")).unwrap();
        assert!(softhsm.contains("directories.tokendir"));
        let unit = std::fs::read_to_string(root.join("ops/budlum-core.service")).unwrap();
        assert!(unit.contains("SOFTHSM2_CONF"));
        assert!(unit.contains("/etc/budlum/hsm.env"));
        assert!(unit.contains("github.com/lubothebook/budlum"));
        assert!(!unit.contains("github.com/rade/"));
    }

    /// WP-41 job 4: the three compose profiles are present and the rehearsal
    /// profile loads the alert rules. A CI host cannot boot Docker, so the
    /// test locks the wiring instead of claiming a live boot.
    #[test]
    fn ops_compose_testnet_profile_boots() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let compose = std::fs::read_to_string(root.join("ops/docker-compose.testnet.yml")).unwrap();
        for profile in ["single", "four-node", "rehearsal"] {
            assert!(
                compose.contains(&format!("profiles: [\"{profile}\"]"))
                    || compose.contains(&format!("\"{profile}\"")),
                "the {profile} profile is missing"
            );
        }
        for service in [
            "seed",
            "relay",
            "gateway",
            "rpc",
            "faucet",
            "prometheus",
            "grafana",
        ] {
            assert!(
                compose.contains(&format!("  {service}:\n")),
                "the {service} service is missing"
            );
        }
        assert!(compose.contains("monitoring/alerts.yml"));
        let alerts = std::fs::read_to_string(root.join("ops/monitoring/alerts.yml")).unwrap();
        assert!(alerts.contains("budlum-launch-boundary"));
        assert!(root
            .join("ops/monitoring/grafana/budlum-launch-boundary.json")
            .is_file());
        assert!(root.join("ops/runbooks/seed-node.md").is_file());
        assert!(root.join("ops/runbooks/relay-node.md").is_file());
        assert!(root.join("ops/runbooks/upload-gateway.md").is_file());
        assert!(root.join("ops/runbooks/rpc-node.md").is_file());
        assert!(root.join("ops/BACKUP_DRILL.md").is_file());
    }
}
