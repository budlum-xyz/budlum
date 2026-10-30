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
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::crypto::primitives::WalletKeyPair;
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
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
    /// Do not queue an unbounded number of grants behind the nonce lock.
    grant_slots: Arc<Semaphore>,
    /// The ledger and the next nonce to use, under one lock so two requests
    /// cannot pass the same cooldown or sign with the same nonce.
    state: Mutex<(Ledger, u64)>,
}

impl Faucet {
    async fn grant(
        &self,
        to: Address,
        ip: IpAddr,
    ) -> Result<serde_json::Value, (StatusCode, String)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
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
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
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
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
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
                (
                    StatusCode::BAD_GATEWAY,
                    format!("submission failed or reply was lost; allowance reserved: {e}"),
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
    if method != Method::POST || path != "/request" {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "POST /request or GET /health",
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
    let faucet = Arc::new(Faucet {
        node,
        key,
        address,
        chain_id,
        policy,
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
        let text = peer.to_string().replace('\n', "").replace('\r', "");
        text.chars().filter(|c| !c.is_control()).collect()
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
        faucet_allowed_on, parse_request, rpc_u64, Ledger, Policy, Refusal, DEFAULT_AMOUNT_BUD,
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
        assert!(response.starts_with("HTTP/1.1 408"), "{response}");
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
