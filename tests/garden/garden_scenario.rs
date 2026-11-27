//! Garden acceptance tests.
//!
//! Every test here drives real `budlum-core` nodes, each in its own process,
//! through their operator JSON-RPC listener. Nothing is mocked: the Garden
//! swarm, the Garden chain, the content store and the Budlum domain registry
//! are the ones the node runs in production.
//!
//! The eleven acceptance steps share one network. The first step test that
//! runs drives the whole scenario; every step test then reports the result
//! of its own step.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Only one Garden network runs at a time, so the tests fit a small CI box.
static NETWORK: Mutex<()> = Mutex::new(());

const ROUND_MS: u64 = 400;
const STEP_TIMEOUT: Duration = Duration::from_secs(90);

/// A `budlum-core` node in its own process.
struct Node {
    name: String,
    child: Child,
    dir: tempfile::TempDir,
    operator_port: u16,
    public_port: u16,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Four distinct free ports.
///
/// The listeners are held until all four are known. Asking for them one at a
/// time hands the same port out twice: the kernel is free to reuse a port the
/// previous `TcpListener` released, and when it did, the node started with two
/// of its four listeners on one port - the public RPC lost the race to the
/// operator listener and the test failed with "timed out waiting for the
/// operator listener" after two minutes. It failed roughly once in three runs.
fn free_ports() -> Result<[u16; 4], String> {
    let listeners = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<Result<Vec<TcpListener>, _>>()
        .map_err(|e| e.to_string())?;
    let mut ports = [0u16; 4];
    for (port, listener) in ports.iter_mut().zip(&listeners) {
        *port = listener.local_addr().map_err(|e| e.to_string())?.port();
    }
    Ok(ports)
}

/// The operator listener serves 120 requests a minute to one address. The
/// scenario stays under that limit instead of lifting it: every listener
/// gets its calls this far apart.
const CALL_SPACING: Duration = Duration::from_millis(550);
static LAST_CALL: Mutex<BTreeMap<u16, Instant>> = Mutex::new(BTreeMap::new());

/// Wait until `port` may be called again and book the call.
fn pace(port: u16) {
    let wait = {
        let mut last = LAST_CALL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let at = last
            .get(&port)
            .map_or(now, |previous| (*previous + CALL_SPACING).max(now));
        last.insert(port, at);
        at.saturating_duration_since(now)
    };
    std::thread::sleep(wait);
}

/// One JSON-RPC call over a fresh HTTP connection.
fn call(port: u16, method: &str, params: &Value) -> Result<Value, String> {
    pace(port);
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_mins(2)))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (_, payload) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{method}: no HTTP body in {text:?}"))?;
    let start = payload
        .find('{')
        .ok_or_else(|| format!("{method}: no JSON in {payload:?}"))?;
    let end = payload
        .rfind('}')
        .ok_or_else(|| format!("{method}: no JSON in {payload:?}"))?;
    let json_text = payload
        .get(start..=end)
        .ok_or_else(|| format!("{method}: bad JSON bounds"))?;
    let answer: Value = serde_json::from_str(json_text).map_err(|e| format!("{method}: {e}"))?;
    if let Some(error) = answer.get("error") {
        return Err(format!("{method}: {error}"));
    }
    answer
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: answer has no result: {answer}"))
}

/// Poll `probe` until it yields a value or `timeout` passes.
fn wait_for<T>(
    what: &str,
    timeout: Duration,
    mut probe: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let started = Instant::now();
    let mut last = String::from("condition not met");
    loop {
        match probe() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(e) => last = e,
        }
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {what}: {last}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn text(value: &Value, pointer: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no text at {pointer} in {value}"))
}

fn number(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("no number at {pointer} in {value}"))
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

impl Node {
    /// Start a devnet node with an operator listener and wait until it
    /// answers.
    fn start(name: &str) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let [operator_port, public_port, p2p_port, metrics_port] = free_ports()?;
        let db = dir.path().join("db");
        let log = std::fs::File::create(dir.path().join("node.log")).map_err(|e| e.to_string())?;
        let errors = log.try_clone().map_err(|e| e.to_string())?;
        let child = Command::new(env!("CARGO_BIN_EXE_budlum-core"))
            .arg("--network=devnet")
            .arg(format!("--db-path={}", db.display()))
            .arg(format!("--port={p2p_port}"))
            .arg("--rpc-host=127.0.0.1")
            .arg(format!("--rpc-port={public_port}"))
            .arg(format!("--rpc-public-listener=127.0.0.1:{public_port}"))
            .arg(format!("--rpc-operator-listener=127.0.0.1:{operator_port}"))
            .arg(format!("--metrics-port={metrics_port}"))
            .arg(format!("--metrics-listener=127.0.0.1:{metrics_port}"))
            .arg("--mdns-enabled=false")
            // The public listener of a test node needs no API key; the
            // Garden surface is refused there whatever the auth setting is.
            .env("BUDLUM_RPC_AUTH_REQUIRED", "0")
            .env("BUDLUM_APTOS_LISTENER", "none")
            .env("BUDLUM_SOLANA_LISTENER", "none")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .spawn()
            .map_err(|e| format!("budlum-core did not start: {e}"))?;
        let node = Self {
            name: name.to_string(),
            child,
            dir,
            operator_port,
            public_port,
        };
        wait_for("the operator listener", Duration::from_mins(2), || {
            node.rpc("bud_gardenStatus", &json!([])).map(Some)
        })
        .map_err(|e| format!("{e}\n{}", node.log_tail()))?;
        Ok(node)
    }

    /// Stop the node process where it stands (`STOP`) or let it go on
    /// (`CONT`). A stopped process keeps its sockets and its memory and
    /// answers nobody, which is what a sleeping device looks like.
    fn signal(&self, name: &str) -> Result<(), String> {
        let status = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.child.id().to_string())
            .status()
            .map_err(|e| format!("kill did not start: {e}"))?;
        ensure(
            status.success(),
            format!("[{}] kill -{name} failed", self.name),
        )
    }

    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(self.dir.path().join("node.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let from = lines.len().saturating_sub(30);
        lines
            .get(from..)
            .map(|tail| tail.join("\n"))
            .unwrap_or_default()
    }

    fn rpc(&self, method: &str, params: &Value) -> Result<Value, String> {
        call(self.operator_port, method, params).map_err(|e| format!("[{}] {e}", self.name))
    }

    fn garden(&self) -> Result<Value, String> {
        let status = self.rpc("bud_gardenStatus", &json!([]))?;
        status
            .get("garden")
            .filter(|garden| !garden.is_null())
            .cloned()
            .ok_or_else(|| format!("[{}] node runs no Garden: {status}", self.name))
    }

    fn create(&self, title: &str) -> Result<Value, String> {
        self.rpc(
            "bud_gardenCreate",
            &json!([title, self.name, {
                "listen": "/ip4/127.0.0.1/tcp/0",
                "round_ms": ROUND_MS,
                "presence_interval_ms": 200,
                "host_timeout_ms": 1500,
                "suspend_after_ms": 3000,
            }]),
        )
    }

    fn join(&self, invite: &str, reachable: bool) -> Result<Value, String> {
        let options = if reachable {
            json!({ "listen": "/ip4/127.0.0.1/tcp/0" })
        } else {
            json!({ "listen": "/ip4/0.0.0.0/tcp/0" })
        };
        self.rpc("bud_gardenJoin", &json!([invite, self.name, options]))
    }

    fn publish_text(&self, kind: &str, body: &str) -> Result<(String, String), String> {
        let answer = self.rpc("bud_gardenPublish", &json!([kind, body]))?;
        Ok((text(&answer, "/tx_id")?, text(&answer, "/content_id")?))
    }

    /// Wait until this node sees `tx_id` in a finalized block.
    fn wait_final(&self, tx_id: &str) -> Result<Value, String> {
        wait_for(
            &format!("[{}] finality of {tx_id}", self.name),
            STEP_TIMEOUT,
            || {
                let trace = self.rpc("bud_gardenTrace", &json!([tx_id]))?;
                Ok((text(&trace, "/stage")? == "final").then_some(trace))
            },
        )
    }

    fn wait_status(&self, wanted: &str) -> Result<Value, String> {
        wait_for(
            &format!("[{}] Garden status {wanted}", self.name),
            STEP_TIMEOUT,
            || {
                let garden = self.garden()?;
                Ok((text(&garden, "/status")? == wanted).then_some(garden))
            },
        )
    }

    /// The Garden domain as this node's Budlum chain records it on the
    /// operator listener. Also asserts that the public RPC listener never
    /// discloses this node-local Garden domain.
    fn budlum_domain(&self, chain_id: u64) -> Result<Value, String> {
        let wanted = json!(format!("0x{chain_id:x}"));
        let public_domains = call(self.public_port, "bud_getConsensusDomains", &json!([]))?;
        let leaked = public_domains.as_array().is_some_and(|list| {
            list.iter()
                .any(|domain| domain.get("domainChainId") == Some(&wanted))
        });
        ensure(
            !leaked,
            format!(
                "[{}] public RPC disclosed node-local Garden chain {chain_id:x}",
                self.name
            ),
        )?;
        let domains = self.rpc("bud_getConsensusDomains", &json!([]))?;
        domains
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|domain| domain.get("domainChainId") == Some(&wanted))
            })
            .cloned()
            .ok_or_else(|| {
                format!(
                    "[{}] Budlum has no domain for chain {chain_id:x}",
                    self.name
                )
            })
    }

    /// True when this node's Budlum chain holds the commitment of the
    /// Garden block `hash` at `height` for `domain` on the operator listener.
    /// Also asserts that the public RPC listener never discloses it.
    fn budlum_holds_block(&self, domain: &Value, height: u64, hash: &str) -> Result<bool, String> {
        let id = domain.get("domainId").cloned().unwrap_or(Value::Null);
        let public_commitments = call(self.public_port, "bud_getDomainCommitments", &json!([]))?;
        let leaked = public_commitments
            .as_array()
            .is_some_and(|list| list.iter().any(|c| c.get("domainId") == Some(&id)));
        ensure(
            !leaked,
            format!(
                "[{}] public RPC disclosed node-local Garden commitments for {id}",
                self.name
            ),
        )?;
        let commitments = self.rpc("bud_getDomainCommitments", &json!([]))?;
        let wanted_height = json!(format!("0x{height:x}"));
        let wanted_hash = json!(format!("0x{hash}"));
        Ok(commitments.as_array().is_some_and(|list| {
            list.iter().any(|c| {
                c.get("domainId") == Some(&id)
                    && c.get("domainHeight") == Some(&wanted_height)
                    && c.get("domainBlockHash") == Some(&wanted_hash)
            })
        }))
    }

    fn wait_budlum_status(&self, chain_id: u64, wanted: &str) -> Result<Value, String> {
        wait_for(
            &format!("[{}] Budlum domain status {wanted}", self.name),
            STEP_TIMEOUT,
            || {
                let domain = self.budlum_domain(chain_id)?;
                let status = text(&domain, "/status")?;
                if status == wanted {
                    Ok(Some(domain))
                } else {
                    Err(format!("Budlum holds the domain as {status}"))
                }
            },
        )
        .map_err(|e| {
            // What the node itself says about its Budlum record, with the
            // refusal the chain gave it, if any.
            let own = self
                .rpc("bud_gardenStatus", &json!([]))
                .map_or_else(|e| e, |status| status["garden"]["budlum"].to_string());
            format!("{e}; the node reports {own}")
        })
    }

    /// Files left under this node's Garden content directory.
    fn garden_files(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![self.dir.path().join("db").join("garden")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    found.push(path);
                }
            }
        }
        found
    }
}

fn chain_id_of(garden: &Value) -> Result<u64, String> {
    u64::from_str_radix(&text(garden, "/chain_id")?, 16).map_err(|e| e.to_string())
}

/// Deterministic bytes that stand for an image.
fn image_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// What the scenario carries from one step to the next.
struct Scenario {
    host: Node,
    validators: Vec<Node>,
    invite: String,
    chain_id: u64,
    message_tx: String,
    image_id: String,
    image_hex: String,
}

fn step_01(host: Node) -> Result<Scenario, String> {
    let created = host.create("Acceptance Room")?;
    let invite = text(&created, "/invite")?;
    ensure(
        invite.starts_with("budlum-garden:1?chain="),
        format!("bad invite {invite}"),
    )?;
    ensure(
        text(&created, "/qr")? == invite,
        "QR content differs from the invite",
    )?;
    ensure(
        invite.contains("&peer=/ip4/127.0.0.1/tcp/"),
        "invite has no host address",
    )?;
    let garden = host.garden()?;
    ensure(
        text(&garden, "/status")? == "Active",
        "new Garden is not Active",
    )?;
    ensure(
        garden.pointer("/me/host") == Some(&json!(true)),
        "creator is not the host",
    )?;
    ensure(
        number(&garden, "/active_validators")? == 1,
        "host is not the only validator",
    )?;
    let again = text(&host.rpc("bud_gardenInvite", &json!([]))?, "/invite")?;
    ensure(
        again == invite,
        "bud_gardenInvite differs from the creation invite",
    )?;
    let chain_id = chain_id_of(&garden)?;
    Ok(Scenario {
        host,
        validators: Vec::new(),
        invite,
        chain_id,
        message_tx: String::new(),
        image_id: String::new(),
        image_hex: String::new(),
    })
}

fn step_02(s: &mut Scenario) -> Result<(), String> {
    for index in 1..=5 {
        let node = Node::start(&format!("validator-{index}"))?;
        let joined = node.join(&s.invite, true)?;
        ensure(
            text(&joined, "/garden/me/member")? == "Active",
            format!("validator-{index} is not active after joining"),
        )?;
        s.validators.push(node);
    }
    // Every validator can be dialed here, so each one ends up with a direct
    // connection to the other five and none leans on the host to forward.
    for node in std::iter::once(&s.host).chain(&s.validators) {
        wait_for("six active validators in a full mesh", STEP_TIMEOUT, || {
            let garden = node.garden()?;
            let complete = number(&garden, "/active_validators")? == 6
                && number(&garden, "/connected_peers")? == 5;
            Ok(complete.then_some(()))
        })?;
    }
    Ok(())
}

fn step_03(s: &mut Scenario) -> Result<(), String> {
    let first = s.validators.first().ok_or("no validator")?;
    let second = s.validators.get(1).ok_or("no second validator")?;
    let (message_tx, message_id) = first.publish_text("message", "hello from validator one")?;
    let (post_tx, _) = second.publish_text("post", "a post from validator two")?;
    let (host_tx, _) = s.host.publish_text("post", "the host posts too")?;
    for node in std::iter::once(&s.host).chain(&s.validators) {
        for tx in [&message_tx, &post_tx, &host_tx] {
            node.wait_final(tx)?;
        }
        let feed = node.rpc("bud_gardenFeed", &json!([10]))?;
        ensure(
            number(&feed, "/total")? == 3,
            format!("[{}] feed is not complete", node.name),
        )?;
    }
    let reader = s.validators.get(2).ok_or("no third validator")?;
    let resolved = reader.rpc("bud_gardenResolve", &json!([message_id]))?;
    ensure(
        text(&resolved, "/text")? == "hello from validator one",
        "message text differs on another node",
    )?;
    s.message_tx = message_tx;
    Ok(())
}

fn step_04(s: &mut Scenario) -> Result<(), String> {
    let uploader = s.validators.first().ok_or("no validator")?;
    let image = image_bytes(200_000);
    s.image_hex = hex::encode(&image);
    let answer = uploader.rpc(
        "bud_gardenPublish",
        &json!(["image", s.image_hex, "hex", "image/png", "a picture"]),
    )?;
    s.image_id = text(&answer, "/content_id")?;
    let tx = text(&answer, "/tx_id")?;
    for node in &s.validators {
        node.wait_final(&tx)?;
    }
    for node in s.validators.iter().skip(1) {
        let resolved = node.rpc("bud_gardenResolve", &json!([s.image_id]))?;
        ensure(
            text(&resolved, "/content_id")? == s.image_id,
            format!("[{}] content id differs", node.name),
        )?;
        ensure(
            text(&resolved, "/hex")? == s.image_hex,
            format!("[{}] image bytes differ", node.name),
        )?;
        ensure(number(&resolved, "/size")? == 200_000, "image size differs")?;
    }
    Ok(())
}

fn step_05(s: &mut Scenario) -> Result<(), String> {
    let asker = s.validators.get(3).ok_or("no fourth validator")?;
    let trace = asker.rpc("bud_gardenTrace", &json!([s.message_tx]))?;
    ensure(text(&trace, "/stage")? == "final", "message is not final")?;
    ensure(
        text(&trace, "/transaction/kind")? == "message",
        "trace names another kind",
    )?;
    ensure(
        text(&trace, "/transaction/sender_name")? == "validator-1",
        "trace names another sender",
    )?;
    ensure(
        number(&trace, "/block/height")? >= 6,
        "message block is below the joins",
    )?;
    ensure(
        text(&trace, "/block/hash")?.len() == 64,
        "block hash is not 32 bytes",
    )?;
    let signers = trace
        .pointer("/finality/signers")
        .and_then(Value::as_array)
        .ok_or("trace has no signers")?;
    let needed = number(&trace, "/finality/needed")?;
    ensure(
        signers.len() as u64 >= needed && needed == 5,
        format!("trace shows {} signers, needs {needed}", signers.len()),
    )?;
    let host_key = text(&s.host.garden()?, "/me/key")?;
    let host_signed = signers
        .iter()
        .any(|signer| signer.get("validator").and_then(Value::as_str) == Some(host_key.as_str()));
    ensure(host_signed, "the host is not among the signers")?;
    let by_content = asker.rpc("bud_gardenTrace", &json!([s.image_id]))?;
    ensure(
        text(&by_content, "/transaction/kind")? == "image",
        "content id trace failed",
    )
}

fn step_06(s: &mut Scenario) -> Result<(), String> {
    // The uploader of the image disappears without a word.
    let gone = s.validators.remove(0);
    drop(gone);
    let writer = s.validators.first().ok_or("no validator left")?;
    let (tx, _) = writer.publish_text("message", "still here after a sudden departure")?;
    for node in std::iter::once(&s.host).chain(&s.validators) {
        node.wait_final(&tx)?;
    }
    let reader = s.validators.last().ok_or("no validator left")?;
    let resolved = reader.rpc("bud_gardenResolve", &json!([s.image_id]))?;
    ensure(
        text(&resolved, "/hex")? == s.image_hex,
        "image was lost with its uploader",
    )?;
    // The silent validator is suspended, with nothing taken from it.
    let mut counter = 0u32;
    wait_for("the silent validator to be suspended", STEP_TIMEOUT, || {
        counter += 1;
        writer.publish_text("message", &format!("tick {counter}"))?;
        std::thread::sleep(Duration::from_millis(ROUND_MS));
        let garden = s.host.garden()?;
        let suspended = garden
            .pointer("/validators")
            .and_then(Value::as_array)
            .is_some_and(|list| {
                list.iter().any(|v| {
                    v.get("name").and_then(Value::as_str) == Some("validator-1")
                        && v.get("status").and_then(Value::as_str) == Some("Suspended")
                })
            });
        Ok(suspended.then_some(()))
    })?;
    ensure(
        number(&s.host.garden()?, "/active_validators")? == 5,
        "active set did not shrink to five",
    )
}

fn step_07(s: &mut Scenario) -> Result<(), String> {
    for node in std::iter::once(&s.host).chain(&s.validators) {
        wait_for(
            &format!("[{}] Budlum to show Garden finality", node.name),
            STEP_TIMEOUT,
            || {
                let garden = node.garden()?;
                let domain = node.budlum_domain(s.chain_id)?;
                let height = number(&garden, "/height")?;
                let last_hash = text(&garden, "/last_hash")?;
                let same = node.budlum_holds_block(&domain, height, &last_hash)?
                    && number(&garden, "/budlum/finalized_height")? == height
                    && text(&garden, "/budlum/finalized_hash")? == last_hash;
                Ok(same.then_some(()))
            },
        )?;
        let domain = node.budlum_domain(s.chain_id)?;
        ensure(
            text(&domain, "/status")? == "Active",
            "Budlum domain is not Active",
        )?;
        ensure(
            text(&domain, "/consensusKind")? == "PoA",
            "Garden domain is not PoA",
        )?;
        ensure(
            domain.get("bridgeEnabled") == Some(&json!(false)),
            "Garden domain has a bridge",
        )?;
        ensure(
            text(&domain, "/finalityAdapter")? == "poa-authority-quorum",
            "Garden domain uses another adapter",
        )?;
    }
    Ok(())
}

fn step_08(s: &mut Scenario) -> Result<(), String> {
    let left = s.host.rpc("bud_gardenLeave", &json!([]))?;
    ensure(
        left.get("retired") == Some(&json!(false)),
        "Garden retired when the host left",
    )?;
    ensure(
        s.host.garden_files().is_empty(),
        "host kept Garden files after leaving",
    )?;
    for node in &s.validators {
        let garden = node.wait_status("Frozen")?;
        let height = number(&garden, "/height")?;
        node.wait_budlum_status(s.chain_id, "Frozen")?;
        let refusal = node
            .publish_text("message", "into the frozen Garden")
            .err()
            .ok_or("a frozen Garden accepted a transaction")?;
        ensure(
            refusal.contains("frozen"),
            format!("unexpected refusal: {refusal}"),
        )?;
        let resolved = node.rpc("bud_gardenResolve", &json!([s.image_id]))?;
        ensure(
            text(&resolved, "/hex")? == s.image_hex,
            "data is not readable while frozen",
        )?;
        ensure(
            number(&node.rpc("bud_gardenFeed", &json!([5]))?, "/total")? >= 4,
            "feed is not readable while frozen",
        )?;
        std::thread::sleep(Duration::from_millis(ROUND_MS * 3));
        ensure(
            number(&node.garden()?, "/height")? == height,
            "a block was made while the host was away",
        )?;
    }
    Ok(())
}

fn step_09(s: &mut Scenario) -> Result<(), String> {
    let back = s.host.rpc("bud_gardenReturn", &json!([]))?;
    ensure(
        text(&back, "/garden/me/member")? == "Active",
        "host is not active after returning",
    )?;
    for node in std::iter::once(&s.host).chain(&s.validators) {
        node.wait_status("Active")?;
        node.wait_budlum_status(s.chain_id, "Active")?;
    }
    let writer = s.validators.first().ok_or("no validator left")?;
    let (tx, _) = writer.publish_text("message", "the host is back")?;
    for node in std::iter::once(&s.host).chain(&s.validators) {
        node.wait_final(&tx)?;
    }
    let resolved = s.host.rpc("bud_gardenResolve", &json!([s.image_id]))?;
    ensure(
        text(&resolved, "/hex")? == s.image_hex,
        "returned host cannot read old data",
    )
}

fn step_10(s: &mut Scenario) -> Result<(), String> {
    for node in &s.validators {
        let left = node.rpc("bud_gardenLeave", &json!([]))?;
        ensure(
            left.get("left") == Some(&json!(true)),
            "validator did not leave",
        )?;
        ensure(
            left.get("retired") == Some(&json!(false)),
            "Garden retired too early",
        )?;
    }
    let last = s.host.rpc("bud_gardenLeave", &json!([]))?;
    ensure(
        last.get("retired") == Some(&json!(true)),
        "last departure did not retire the Garden",
    )?;
    s.host.wait_budlum_status(s.chain_id, "Retired")?;
    for node in &s.validators {
        // A validator that left may still return, so its record waits as
        // Frozen. Leaving again forgets the Garden for good.
        node.wait_budlum_status(s.chain_id, "Frozen")?;
        node.rpc("bud_gardenLeave", &json!([]))?;
        node.wait_budlum_status(s.chain_id, "Retired")?;
    }
    for node in std::iter::once(&s.host).chain(&s.validators) {
        let files = node.garden_files();
        ensure(
            files.is_empty(),
            format!("[{}] Garden data left on disk: {files:?}", node.name),
        )?;
        let status = node.rpc("bud_gardenStatus", &json!([]))?;
        ensure(
            status.get("garden") == Some(&Value::Null),
            format!("[{}] node still reports a Garden", node.name),
        )?;
    }
    Ok(())
}

fn step_11(s: &mut Scenario) -> Result<(), String> {
    let founder = s.validators.first().ok_or("no validator left")?;
    let created = founder.create("Second Room")?;
    let invite = text(&created, "/invite")?;
    let garden = founder.garden()?;
    let chain_id = chain_id_of(&garden)?;
    ensure(chain_id != s.chain_id, "new Garden reuses the old chain id")?;
    ensure(
        text(&garden, "/status")? == "Active",
        "new Garden is not Active",
    )?;
    ensure(
        number(&garden, "/height")? == 0,
        "new Garden does not start at genesis",
    )?;
    ensure(
        number(&garden, "/objects")? == 0,
        "new Garden carries old content",
    )?;
    s.host.join(&invite, true)?;
    let (tx, _) = s
        .host
        .publish_text("message", "first words in the new Garden")?;
    founder.wait_final(&tx)?;
    founder.wait_budlum_status(chain_id, "Active")?;
    ensure(
        text(&founder.budlum_domain(s.chain_id)?, "/status")? == "Retired",
        "the old Garden is not Retired any more",
    )
}

const STEPS: usize = 11;

/// One acceptance step: it works on the shared scenario and reports.
type Step = fn(&mut Scenario) -> Result<(), String>;

fn run_scenario() -> Vec<Result<(), String>> {
    let mut results: Vec<Result<(), String>> = Vec::new();
    let mut scenario = match Node::start("host").and_then(step_01) {
        Ok(scenario) => {
            results.push(Ok(()));
            Some(scenario)
        }
        Err(e) => {
            results.push(Err(e));
            None
        }
    };
    let steps: [Step; STEPS - 1] = [
        step_02, step_03, step_04, step_05, step_06, step_07, step_08, step_09, step_10, step_11,
    ];
    for step in steps {
        let failed_at = results.iter().position(Result::is_err);
        let outcome = match (scenario.as_mut(), failed_at) {
            (Some(scenario), None) => step(scenario).map_err(|e| {
                let logs: Vec<String> = std::iter::once(&scenario.host)
                    .chain(&scenario.validators)
                    .map(|node| format!("--- {} ---\n{}", node.name, node.log_tail()))
                    .collect();
                format!("{e}\n{}", logs.join("\n"))
            }),
            (_, at) => Err(format!(
                "not reached: step {} failed first",
                at.map_or(1, |index| index + 1)
            )),
        };
        results.push(outcome);
    }
    results
}

/// The result of acceptance step `number` (1 based).
fn step(number: usize) -> Result<(), String> {
    static RESULTS: OnceLock<Vec<Result<(), String>>> = OnceLock::new();
    // Serialize the shared scenario even when invoked without --test-threads=1
    // so parallel Gardens do not compete for the same host timing budget.
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    RESULTS
        .get_or_init(run_scenario)
        .get(number.saturating_sub(1))
        .cloned()
        .unwrap_or_else(|| Err(format!("step {number} does not exist")))
}

#[test]
fn garden_step_01_host_creates_a_garden_with_invite_and_qr() -> Result<(), String> {
    step(1)
}

#[test]
fn garden_step_02_five_validators_join_with_the_invite() -> Result<(), String> {
    step(2)
}

#[test]
fn garden_step_03_validators_share_messages_and_posts() -> Result<(), String> {
    step(3)
}

#[test]
fn garden_step_04_image_resolves_on_another_node_with_equal_content_id() -> Result<(), String> {
    step(4)
}

#[test]
fn garden_step_05_participant_queries_the_path_of_a_message() -> Result<(), String> {
    step(5)
}

#[test]
fn garden_step_06_sudden_departure_keeps_chain_and_content() -> Result<(), String> {
    step(6)
}

#[test]
fn garden_step_07_finality_is_visible_on_budlum_as_active() -> Result<(), String> {
    step(7)
}

#[test]
fn garden_step_08_host_leaves_and_the_garden_freezes_readable() -> Result<(), String> {
    step(8)
}

#[test]
fn garden_step_09_host_returns_and_the_garden_runs_again() -> Result<(), String> {
    step(9)
}

#[test]
fn garden_step_10_everyone_leaves_and_no_data_stays_on_disk() -> Result<(), String> {
    step(10)
}

#[test]
fn garden_step_11_a_new_garden_is_created() -> Result<(), String> {
    step(11)
}

/// Garden transaction types are closed on the primary Budlum chains: a node
/// refuses, with the name of the network, an invite that points a Garden at
/// the testnet chain id, and it starts nothing.
#[test]
fn garden_is_closed_on_testnet() -> Result<(), String> {
    use budlum_core::core::chain_config::Network;

    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let node = Node::start("closed")?;
    for (network, label) in [
        (Network::Testnet, "closed on Budlum Testnet"),
        (Network::Mainnet, "closed on Budlum Mainnet"),
        (Network::Devnet, "closed on Budlum Devnet"),
    ] {
        let invite = format!(
            "budlum-garden:1?chain={:016x}&genesis={}&token={}&peer=/ip4/127.0.0.1/tcp/9",
            network.chain_id().value(),
            "11".repeat(32),
            "22".repeat(32),
        );
        let refusal = match node.rpc("bud_gardenJoin", &json!([invite, "Mallory"])) {
            Ok(answer) => return Err(format!("a primary chain invite was accepted: {answer}")),
            Err(refusal) => refusal,
        };
        ensure(refusal.contains(label), refusal)?;
    }
    ensure(
        node.rpc("bud_gardenStatus", &json!([]))?
            .get("garden")
            .is_some_and(Value::is_null),
        "a refused invite left a Garden behind",
    )
}

/// Two validators that nobody can dial join through the host and still
/// reach each other's content: the host forwards for them.
#[test]
fn garden_join_behind_nat() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let host = Node::start("host")?;
    let invite = text(&host.create("Relay Room")?, "/invite")?;
    let first = Node::start("hidden-1")?;
    let second = Node::start("hidden-2")?;
    for node in [&first, &second] {
        let joined = node.join(&invite, false)?;
        ensure(
            text(&joined, "/garden/me/address")?.is_empty(),
            "a hidden validator announced an address",
        )?;
    }
    wait_for("three active validators", STEP_TIMEOUT, || {
        Ok((number(&second.garden()?, "/active_validators")? == 3).then_some(()))
    })?;
    ensure(
        number(&first.garden()?, "/connected_peers")? == 1,
        "a hidden validator has a peer besides the host",
    )?;
    let fresh = text(&second.rpc("bud_gardenInvite", &json!([]))?, "/invite")?;
    ensure(
        fresh.matches("&peer=").count() == 1,
        "the invite lists a validator nobody can dial",
    )?;
    let image = hex::encode(image_bytes(50_000));
    let answer = first.rpc(
        "bud_gardenPublish",
        &json!(["image", image, "hex", "image/png"]),
    )?;
    let tx = text(&answer, "/tx_id")?;
    let content_id = text(&answer, "/content_id")?;
    second.wait_final(&tx)?;
    let resolved = second.rpc("bud_gardenResolve", &json!([content_id]))?;
    ensure(
        text(&resolved, "/hex")? == image,
        "content did not cross the relay",
    )?;
    let trace = second.wait_final(&tx)?;
    ensure(
        number(&trace, "/finality/needed")? == 3,
        "three validators need three signatures",
    )
}

/// Anyone leaves a running Garden and comes back when they like. The one
/// who left keeps nothing on disk, the Garden goes on without it, and when
/// it returns it takes its own seat again and reads what it missed.
#[test]
fn garden_validator_leaves_and_returns_while_the_garden_runs() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let host = Node::start("host")?;
    let invite = text(&host.create("Open Door")?, "/invite")?;
    let first = Node::start("validator-1")?;
    let second = Node::start("validator-2")?;
    for node in [&first, &second] {
        node.join(&invite, true)?;
    }
    let active = |wanted: u64| {
        wait_for(&format!("{wanted} active validators"), STEP_TIMEOUT, || {
            Ok((number(&host.garden()?, "/active_validators")? == wanted).then_some(()))
        })
    };
    active(3)?;
    let (before, content_id) = first.publish_text("message", "before the door")?;
    for node in [&host, &first, &second] {
        node.wait_final(&before)?;
    }
    let seat = text(&second.garden()?, "/me/key")?;

    let left = second.rpc("bud_gardenLeave", &json!([]))?;
    ensure(
        left.get("left") == Some(&json!(true)) && left.get("retired") == Some(&json!(false)),
        format!("unexpected departure: {left}"),
    )?;
    let files = second.garden_files();
    ensure(
        files.is_empty(),
        format!("the one who left kept Garden data: {files:?}"),
    )?;
    active(2)?;
    let (during, _) = first.publish_text("message", "while one is out")?;
    for node in [&host, &first] {
        node.wait_final(&during)?;
    }

    let back = second.rpc("bud_gardenReturn", &json!([]))?;
    ensure(
        text(&back, "/garden/me/member")? == "Active",
        "the validator is not active after returning",
    )?;
    ensure(
        text(&back, "/garden/me/key")? == seat,
        "the validator returned under another key",
    )?;
    active(3)?;
    second.wait_final(&during)?;
    second.rpc("bud_gardenResolve", &json!([content_id]))?;
    let (after, _) = second.publish_text("message", "back again")?;
    for node in [&host, &first, &second] {
        node.wait_final(&after)?;
    }
    let seats = host
        .garden()?
        .get("validators")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    ensure(
        seats == 3,
        format!("returning made a new seat: {seats} validators on record"),
    )
}

/// The host goes silent without a departure block, the way a sleeping device
/// does. No block says so, and the others still stop: they see the Garden
/// as Frozen, show it Frozen on Budlum, take no transaction and make no
/// block, and keep the data readable. When the host answers again the same
/// chain goes on with every validator still in it.
#[test]
fn garden_host_silence_freezes_and_its_return_resumes() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let host = Node::start("host")?;
    let invite = text(&host.create("Quiet Room")?, "/invite")?;
    let chain_id = chain_id_of(&host.garden()?)?;
    let first = Node::start("validator-1")?;
    let second = Node::start("validator-2")?;
    for node in [&first, &second] {
        node.join(&invite, true)?;
    }
    wait_for("three active validators", STEP_TIMEOUT, || {
        Ok((number(&second.garden()?, "/active_validators")? == 3).then_some(()))
    })?;
    let (before, content_id) = first.publish_text("message", "before the silence")?;
    for node in [&host, &first, &second] {
        node.wait_final(&before)?;
    }
    for node in [&first, &second] {
        node.wait_budlum_status(chain_id, "Active")?;
    }

    host.signal("STOP")?;
    let silent = (|| {
        for node in [&first, &second] {
            let garden = node.wait_status("Frozen")?;
            let height = number(&garden, "/height")?;
            node.wait_budlum_status(chain_id, "Frozen")?;
            let refusal = node
                .publish_text("message", "into the silent Garden")
                .err()
                .ok_or("a Garden without its host accepted a transaction")?;
            ensure(
                refusal.contains("frozen"),
                format!("unexpected refusal: {refusal}"),
            )?;
            node.rpc("bud_gardenResolve", &json!([content_id]))?;
            std::thread::sleep(Duration::from_millis(ROUND_MS * 3));
            ensure(
                number(&node.garden()?, "/height")? == height,
                "a block was made while the host was silent",
            )?;
        }
        // Long enough for the host to hold every validator as silent when
        // it wakes up, if it counted its own standstill against them.
        std::thread::sleep(Duration::from_secs(4));
        Ok::<(), String>(())
    })();
    // The host goes on whatever the checks said, so its process can end.
    host.signal("CONT")?;
    silent?;

    for node in [&host, &first, &second] {
        node.wait_status("Active")?;
    }
    for node in [&first, &second] {
        node.wait_budlum_status(chain_id, "Active")?;
    }
    let (after, _) = second.publish_text("message", "the host answers again")?;
    for node in [&host, &first, &second] {
        node.wait_final(&after)?;
    }
    for node in [&host, &first, &second] {
        ensure(
            number(&node.garden()?, "/active_validators")? == 3,
            format!("[{}] a validator was lost to the silence", node.name),
        )?;
    }
    Ok(())
}

/// What one validator publishes over the life of a Garden has a ceiling the
/// host sets at the founding, and an address the others would not dial is
/// not announced.
#[test]
fn garden_validator_share_bounds_what_it_publishes() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let node = Node::start("solo")?;
    let low_port = node.rpc(
        "bud_gardenCreate",
        &json!(["Room", "solo", {
            "listen": "/ip4/0.0.0.0/tcp/0",
            "announce": "/ip4/127.0.0.1/tcp/22",
        }]),
    );
    let refusal = low_port
        .err()
        .ok_or("a Garden was founded on an address nobody would dial")?;
    ensure(refusal.contains("cannot be announced"), refusal)?;

    node.rpc(
        "bud_gardenCreate",
        &json!(["Room", "solo", {
            "listen": "/ip4/127.0.0.1/tcp/0",
            "round_ms": ROUND_MS,
            "max_object_bytes": 4096,
            "max_published_bytes_per_validator": 8192,
        }]),
    )?;
    for body in ["one", "two"] {
        let (tx_id, _) = node.publish_text("message", body)?;
        node.wait_final(&tx_id)?;
    }
    let refusal = node
        .publish_text("message", "three")
        .err()
        .ok_or("a validator published past its share")?;
    ensure(refusal.contains("share"), refusal)?;
    let garden = node.garden()?;
    ensure(
        garden.pointer("/limits/max_published_bytes_per_validator") == Some(&json!(8192))
            && garden.pointer("/validators/0/published_bytes") == Some(&json!(8192))
            && garden.pointer("/objects") == Some(&json!(2)),
        format!("the share is not what the Garden reports: {garden}"),
    )
}

/// A Garden founded with host approval. The invite link or QR content lets a
/// node ask; it becomes a validator when the host admits it and not before,
/// and a node the host turns away stays outside.
#[test]
fn garden_host_approval_admits_only_whom_the_host_accepts() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let host = Node::start("host")?;
    let created = host.rpc(
        "bud_gardenCreate",
        &json!(["Closed Door", "host", {
            "listen": "/ip4/127.0.0.1/tcp/0",
            "round_ms": ROUND_MS,
            "presence_interval_ms": 200,
            "host_timeout_ms": 1500,
            "suspend_after_ms": 3000,
            "admission": "host_approval",
        }]),
    )?;
    let invite = text(&created, "/invite")?;
    ensure(
        text(&created, "/garden/admission")? == "host_approval",
        format!("the Garden does not report its admission mode: {created}"),
    )?;
    let unknown = host.rpc(
        "bud_gardenCreate",
        &json!(["Other", "host", { "admission": "anyone" }]),
    );
    ensure(unknown.is_err(), "an unknown admission mode was accepted")?;

    let welcome = Node::start("welcome")?;
    let unwelcome = Node::start("unwelcome")?;
    for node in [&welcome, &unwelcome] {
        let asked = node.join(&invite, true)?;
        ensure(
            text(&asked, "/garden/me/member")? == "Waiting",
            format!(
                "[{}] the invite alone gave more than a request: {asked}",
                node.name
            ),
        )?;
    }
    let seen = wait_for("two requests waiting for the host", STEP_TIMEOUT, || {
        let garden = host.garden()?;
        Ok((number(&garden, "/waiting_for_host")? == 2).then_some(garden))
    })?;
    ensure(
        number(&seen, "/active_validators")? == 1,
        format!("a node that only holds the invite is a validator: {seen}"),
    )?;
    let welcome_key = text(&welcome.garden()?, "/me/key")?;
    let unwelcome_key = text(&unwelcome.garden()?, "/me/key")?;

    // A node that waits publishes nothing and does not answer for the host.
    let refusal = welcome
        .publish_text("message", "early")
        .err()
        .ok_or("a node that waits for the host published")?;
    ensure(refusal.contains("not an active validator"), refusal)?;
    let refusal = unwelcome
        .rpc("bud_gardenAdmit", &json!([unwelcome_key, true]))
        .err()
        .ok_or("a node that waits admitted itself")?;
    ensure(refusal.contains("only the host"), refusal)?;
    // The host goes on alone meanwhile: a key that waits has no vote.
    let (alone, _) = host.publish_text("message", "before anybody is in")?;
    host.wait_final(&alone)?;

    let yes = host.rpc("bud_gardenAdmit", &json!([welcome_key, true]))?;
    host.wait_final(&text(&yes, "/tx_id")?)?;
    let no = host.rpc("bud_gardenAdmit", &json!([unwelcome_key, false]))?;
    host.wait_final(&text(&no, "/tx_id")?)?;
    wait_for("the admitted node to be active", STEP_TIMEOUT, || {
        let garden = welcome.garden()?;
        Ok((garden.pointer("/me/member") == Some(&json!("Active"))).then_some(()))
    })?;
    wait_for(
        "the other node to learn it was turned away",
        STEP_TIMEOUT,
        || {
            let garden = unwelcome.garden()?;
            Ok((garden.pointer("/me/turned_away") == Some(&json!(true))
                && garden.pointer("/me/member") == Some(&Value::Null))
            .then_some(()))
        },
    )?;

    // The admitted validator is heard: two validators need two signatures.
    let (inside, content_id) = welcome.publish_text("message", "inside")?;
    for node in [&host, &welcome] {
        node.wait_final(&inside)?;
    }
    host.rpc("bud_gardenResolve", &json!([content_id]))?;
    // The node that was turned away has no seat and does not ask again.
    std::thread::sleep(Duration::from_millis(ROUND_MS * 5));
    let garden = host.garden()?;
    let on_record = garden
        .get("validators")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    ensure(
        number(&garden, "/waiting_for_host")? == 0
            && number(&garden, "/active_validators")? == 2
            && on_record == 2,
        format!("the Garden holds more than the host admitted: {garden}"),
    )?;
    let again = host
        .rpc("bud_gardenAdmit", &json!([unwelcome_key, true]))
        .err()
        .ok_or("the host admitted a key that no longer waits")?;
    ensure(again.contains("not waiting"), again)
}

/// The Garden surface is an operator surface: the public listener refuses
/// every `bud_garden*` method, and no method takes a key to act for.
#[test]
fn garden_rpc_is_refused_on_the_public_listener() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let node = Node::start("solo")?;
    let calls = [
        ("bud_gardenCreate", json!(["Room", "mallory"])),
        ("bud_gardenInvite", json!([])),
        (
            "bud_gardenJoin",
            json!(["budlum-garden:1?chain=0", "mallory"]),
        ),
        ("bud_gardenLeave", json!([])),
        ("bud_gardenAdmit", json!(["00", true])),
        ("bud_gardenReturn", json!([])),
        ("bud_gardenStatus", json!([])),
        ("bud_gardenPublish", json!(["message", "hi"])),
        ("bud_gardenResolve", json!(["00"])),
        ("bud_gardenTrace", json!(["00"])),
        ("bud_gardenFeed", json!([1])),
    ];
    for (method, params) in calls {
        let refusal = call(node.public_port, method, &params)
            .err()
            .ok_or_else(|| format!("{method} was answered on the public listener"))?;
        ensure(
            refusal.contains("-32004") && refusal.contains("operator RPC listener"),
            format!("{method}: unexpected refusal {refusal}"),
        )?;
    }
    for removed in [
        "bud_gardenPeerStatus",
        "bud_gardenAdvanceRound",
        "bud_gardenResolveContent",
    ] {
        let refusal = node
            .rpc(removed, &json!([]))
            .err()
            .ok_or_else(|| format!("{removed} still exists"))?;
        ensure(refusal.contains("-32601"), format!("{removed}: {refusal}"))?;
    }
    // A caller cannot name the key a method acts for: the old signature with
    // a pubkey parameter is not accepted any more.
    let with_key = node.rpc("bud_gardenLeave", &json!([null, "00".repeat(32)]));
    ensure(
        with_key.is_err(),
        "bud_gardenLeave accepted a caller-chosen key",
    )?;
    let unknown = node.rpc(
        "bud_gardenCreate",
        &json!(["Room", "solo", { "peer": "10.0.0.1:22" }]),
    );
    ensure(
        unknown.is_err(),
        "bud_gardenCreate accepted an unknown option",
    )?;
    ensure(
        node.rpc("bud_gardenStatus", &json!([]))?.get("garden") == Some(&Value::Null),
        "a refused call left a Garden behind",
    )
}

/// A Garden that loses seven of its eight validators, one at a time, and
/// still holds everything it was given.
///
/// This is the shape a real Garden ends in. People do not resign from a
/// room; their phone dies, they walk out of range, they close the lid. Each
/// of those is a validator that stops answering with no departure block, and
/// after each one the placement table names fewer holders for every object,
/// so the nodes left have to fetch what they are now responsible for. If
/// repair lagged behind departures the Garden would look healthy right up to
/// the moment the last copy of something walked out of the door.
///
/// The test insists on three things after every single departure: the chain
/// still makes blocks, repair finishes (nothing is left wanted), and every
/// object published by anyone - including the ones published by validators
/// that are already gone - still reads back byte for byte. At the end the
/// host is alone with all eight objects, and when the host leaves too there
/// is nothing left on its disk.
#[test]
fn garden_eight_validator_storage_shrink() -> Result<(), String> {
    let _guard = NETWORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let host = Node::start("host")?;
    let invite = text(&host.create("Shrinking Room")?, "/invite")?;
    let mut validators = Vec::new();
    for index in 1..=7 {
        let node = Node::start(&format!("validator-{index}"))?;
        node.join(&invite, true)?;
        validators.push(node);
    }
    let active = |wanted: u64| {
        wait_for(&format!("{wanted} active validators"), STEP_TIMEOUT, || {
            Ok((number(&host.garden()?, "/active_validators")? == wanted).then_some(()))
        })
    };
    active(8)?;

    // Eight uploads, one from each validator, so no single departure can
    // take every author with it.
    let mut objects: Vec<(String, String)> = Vec::new();
    let (tx, id) = host.publish_text("message", "object from the host")?;
    objects.push((tx, id));
    for (index, node) in validators.iter().enumerate() {
        let (tx, id) = node.publish_text("message", &format!("object from validator {index}"))?;
        objects.push((tx, id));
    }
    for (tx, _) in &objects {
        host.wait_final(tx)?;
        for node in &validators {
            node.wait_final(tx)?;
        }
    }

    // One by one, without a word. `drop` kills the process.
    while !validators.is_empty() {
        let gone = validators.remove(0);
        let gone_name = gone.name.clone();
        drop(gone);
        let left = u64::try_from(validators.len()).map_err(|e| e.to_string())? + 1;

        // A silent validator still counts in the active set until the
        // others agree to suspend it, and the chain needs those blocks to
        // get there, so the host keeps writing while it waits.
        let mut tick = 0u32;
        wait_for(
            &format!("the Garden to settle after {gone_name} vanished"),
            STEP_TIMEOUT,
            || {
                tick += 1;
                host.publish_text("message", &format!("tick after {gone_name} {tick}"))?;
                std::thread::sleep(Duration::from_millis(ROUND_MS));
                Ok((number(&host.garden()?, "/active_validators")? == left).then_some(()))
            },
        )?;

        // Repair finishes: nobody is still waiting for bytes it is now
        // supposed to hold.
        for node in std::iter::once(&host).chain(validators.iter()) {
            wait_for(
                &format!("[{}] repair to finish after {gone_name}", node.name),
                STEP_TIMEOUT,
                || Ok((number(&node.garden()?, "/objects_wanted_here")? == 0).then_some(())),
            )?;
        }

        // And everything ever published still reads back, on every node
        // that is left.
        for node in std::iter::once(&host).chain(validators.iter()) {
            for (_, content_id) in &objects {
                let resolved = node.rpc("bud_gardenResolve", &json!([content_id]))?;
                ensure(
                    text(&resolved, "/content_id")? == *content_id,
                    format!("[{}] lost {content_id} after {gone_name} left", node.name),
                )?;
            }
        }
    }

    // The host is the Garden now, and it still has all eight.
    active(1)?;
    for (_, content_id) in &objects {
        host.rpc("bud_gardenResolve", &json!([content_id]))?;
    }

    // The last one out takes nothing with it.
    let left = host.rpc("bud_gardenLeave", &json!([]))?;
    ensure(
        left.get("retired") == Some(&json!(true)),
        format!("the last validator out did not retire the Garden: {left}"),
    )?;
    let files = host.garden_files();
    ensure(
        files.is_empty(),
        format!("Garden data stayed on the host's disk: {files:?}"),
    )
}
