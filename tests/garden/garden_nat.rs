//! Garden behind address translation that is real.
//!
//! `garden_join_behind_nat` in the scenario target runs validators that
//! announce no address. Here the network itself hides them: every hidden
//! validator sits in its own network namespace on a private network, behind
//! a router namespace that translates addresses, and the host sits on the
//! public side. The host has no route to a hidden validator, and one private
//! network has no route to the other, so the only path between the two
//! hidden validators is the host.
//!
//! ```text
//!  gdn-val1 10.1.0.2 -- 10.1.0.1 gdn-nat1 198.51.100.2 -- 198.51.100.1
//!                                                          gdn-host 203.0.113.1
//!  gdn-val2 10.2.0.2 -- 10.2.0.1 gdn-nat2 198.51.100.6 -- 198.51.100.5
//! ```
//!
//! Namespaces need root, so every privileged step goes through `sudo -n`.
//! The target runs in the nightly workflow `garden-nat-nightly.yml`.

use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HOST_NS: &str = "gdn-host";
const NATS: [&str; 2] = ["gdn-nat1", "gdn-nat2"];
const VALS: [&str; 2] = ["gdn-val1", "gdn-val2"];
/// The address of the host on the public side.
const HOST_IP: &str = "203.0.113.1";
/// Every node has its own namespace, so every node uses the same ports.
const P2P_PORT: u16 = 4701;
const PUBLIC_PORT: u16 = 4702;
const OPERATOR_PORT: u16 = 4703;
const METRICS_PORT: u16 = 4704;
const GARDEN_PORT: u16 = 4800;
const ROUND_MS: u64 = 400;
const STEP_TIMEOUT: Duration = Duration::from_secs(90);
/// The operator listener serves 120 requests a minute to one address.
const CALL_SPACING: Duration = Duration::from_millis(550);

/// Run a command as root and return what it printed.
fn root(args: &[&str]) -> Result<String, String> {
    let output = Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .map_err(|e| format!("sudo did not start: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "{}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn wait_for<T>(
    what: &str,
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
        if started.elapsed() >= STEP_TIMEOUT {
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

/// The namespaces and the links between them. Dropping the lab stops what
/// still runs inside and removes every namespace.
struct Lab;

impl Lab {
    fn build() -> Result<Self, String> {
        Self::clear();
        let lab = Self;
        for ns in std::iter::once(HOST_NS).chain(NATS).chain(VALS) {
            root(&["ip", "netns", "add", ns])?;
            root(&["ip", "-n", ns, "link", "set", "lo", "up"])?;
        }
        let public = format!("{HOST_IP}/32");
        root(&["ip", "-n", HOST_NS, "addr", "add", &public, "dev", "lo"])?;
        for (index, (nat, val)) in NATS.into_iter().zip(VALS).enumerate() {
            let n = index + 1;
            let (host_if, nat_out) = (format!("gh{n}"), format!("gn{n}o"));
            let (nat_in, val_if) = (format!("gn{n}i"), format!("gv{n}"));
            let host_side = format!("198.51.100.{}", 4 * index + 1);
            let nat_side = format!("198.51.100.{}", 4 * index + 2);
            let gateway = format!("10.{n}.0.1");
            root(&[
                "ip", "link", "add", &host_if, "netns", HOST_NS, "type", "veth", "peer", "name",
                &nat_out, "netns", nat,
            ])?;
            root(&[
                "ip", "link", "add", &nat_in, "netns", nat, "type", "veth", "peer", "name",
                &val_if, "netns", val,
            ])?;
            Self::address(HOST_NS, &host_if, &format!("{host_side}/30"))?;
            Self::address(nat, &nat_out, &format!("{nat_side}/30"))?;
            Self::address(nat, &nat_in, &format!("{gateway}/24"))?;
            Self::address(val, &val_if, &format!("10.{n}.0.2/24"))?;
            root(&["ip", "-n", val, "route", "add", "default", "via", &gateway])?;
            root(&["ip", "-n", nat, "route", "add", &public, "via", &host_side])?;
            root(&[
                "ip",
                "netns",
                "exec",
                nat,
                "sysctl",
                "-qw",
                "net.ipv4.ip_forward=1",
            ])?;
            root(&[
                "ip",
                "netns",
                "exec",
                nat,
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                &nat_out,
                "-j",
                "MASQUERADE",
            ])?;
        }
        Ok(lab)
    }

    fn address(ns: &str, link: &str, address: &str) -> Result<(), String> {
        root(&["ip", "-n", ns, "addr", "add", address, "dev", link])?;
        root(&["ip", "-n", ns, "link", "set", link, "up"]).map(|_| ())
    }

    fn clear() {
        for ns in std::iter::once(HOST_NS).chain(NATS).chain(VALS) {
            if let Ok(pids) = root(&["ip", "netns", "pids", ns]) {
                for pid in pids.split_whitespace() {
                    let _ = root(&["kill", "-9", pid]);
                }
            }
            let _ = root(&["ip", "netns", "del", ns]);
        }
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        Self::clear();
    }
}

/// A `budlum-core` node inside a namespace.
struct Node {
    name: String,
    ns: &'static str,
    child: Child,
    dir: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        // The child is `sudo`; the node itself is stopped with the lab. The
        // node ran as root, so its files are removed as root.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(path) = self.dir.path().join("db").to_str() {
            let _ = root(&["rm", "-rf", path]);
        }
    }
}

impl Node {
    fn start(name: &str, ns: &'static str) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let log = std::fs::File::create(dir.path().join("node.log")).map_err(|e| e.to_string())?;
        let errors = log.try_clone().map_err(|e| e.to_string())?;
        let child = Command::new("sudo")
            .args(["-n", "ip", "netns", "exec", ns, "env"])
            .arg("BUDLUM_RPC_AUTH_REQUIRED=0")
            .arg(env!("CARGO_BIN_EXE_budlum-core"))
            .arg("--network=devnet")
            .arg(format!("--db-path={}", dir.path().join("db").display()))
            .arg(format!("--port={P2P_PORT}"))
            .arg("--rpc-host=127.0.0.1")
            .arg(format!("--rpc-port={PUBLIC_PORT}"))
            .arg(format!("--rpc-public-listener=127.0.0.1:{PUBLIC_PORT}"))
            .arg(format!("--rpc-operator-listener=127.0.0.1:{OPERATOR_PORT}"))
            .arg(format!("--metrics-port={METRICS_PORT}"))
            .arg(format!("--metrics-listener=127.0.0.1:{METRICS_PORT}"))
            .arg("--mdns-enabled=false")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(errors))
            .spawn()
            .map_err(|e| format!("budlum-core did not start: {e}"))?;
        let node = Self {
            name: name.to_string(),
            ns,
            child,
            dir,
        };
        wait_for("the operator listener", || {
            node.rpc("bud_gardenStatus", &json!([])).map(Some)
        })
        .map_err(|e| format!("{e}\n{}", node.log_tail()))?;
        Ok(node)
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

    /// Call the operator listener from inside the node's namespace: it
    /// binds loopback only, and the loopback of a namespace is its own.
    fn rpc(&self, method: &str, params: &Value) -> Result<Value, String> {
        std::thread::sleep(CALL_SPACING);
        let body =
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        let url = format!("http://127.0.0.1:{OPERATOR_PORT}/");
        let answer = root(&[
            "ip",
            "netns",
            "exec",
            self.ns,
            "curl",
            "-sS",
            "--max-time",
            "120",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ])
        .map_err(|e| format!("[{}] {method}: {e}", self.name))?;
        let answer: Value = serde_json::from_str(&answer)
            .map_err(|e| format!("[{}] {method}: {e} in {answer:?}", self.name))?;
        match answer.get("error") {
            Some(error) => Err(format!("[{}] {method}: {error}", self.name)),
            None => Ok(answer.get("result").cloned().unwrap_or(Value::Null)),
        }
    }

    fn garden(&self) -> Result<Value, String> {
        let status = self.rpc("bud_gardenStatus", &json!([]))?;
        status
            .get("garden")
            .filter(|garden| !garden.is_null())
            .cloned()
            .ok_or_else(|| format!("[{}] node runs no Garden: {status}", self.name))
    }

    /// Wait until this node sees `tx_id` in a finalized block.
    fn wait_final(&self, tx_id: &str) -> Result<Value, String> {
        wait_for(&format!("[{}] finality of {tx_id}", self.name), || {
            self.rpc("bud_gardenTrace", &json!([tx_id])).map(Some)
        })
    }
}

/// Two validators behind two different address translators join through
/// the host, become validators, and read each other's content. Nothing but
/// the host can carry it: the test first shows that the host cannot reach
/// them and that their networks cannot reach each other.
#[test]
fn garden_join_behind_real_nat() -> Result<(), String> {
    let _lab = Lab::build()?;
    for (index, nat) in NATS.into_iter().enumerate() {
        let hidden = format!("10.{}.0.2", index + 1);
        let other = format!("10.{}.0.2", 2 - index);
        ensure(
            root(&["ip", "-n", HOST_NS, "route", "get", &hidden]).is_err(),
            format!("the host has a route to {hidden}"),
        )?;
        ensure(
            root(&["ip", "-n", nat, "route", "get", &other]).is_err(),
            format!("{nat} has a route to the other private network"),
        )?;
    }

    let host = Node::start("host", HOST_NS)?;
    let created = host.rpc(
        "bud_gardenCreate",
        &json!(["Relay Room", "host", {
            "listen": format!("/ip4/{HOST_IP}/tcp/{GARDEN_PORT}"),
            "round_ms": ROUND_MS,
            "presence_interval_ms": 200,
            "host_timeout_ms": 1500,
            "suspend_after_ms": 3000,
        }]),
    )?;
    let invite = text(&created, "/invite")?;
    let first = Node::start("hidden-1", VALS[0])?;
    let second = Node::start("hidden-2", VALS[1])?;
    for node in [&first, &second] {
        let joined = node.rpc(
            "bud_gardenJoin",
            &json!([invite, node.name, { "listen": "/ip4/0.0.0.0/tcp/0" }]),
        )?;
        ensure(
            text(&joined, "/garden/me/address")?.is_empty(),
            "a hidden validator announced an address",
        )?;
    }
    wait_for("three active validators", || {
        Ok((number(&second.garden()?, "/active_validators")? == 3).then_some(()))
    })?;
    for node in [&first, &second] {
        ensure(
            number(&node.garden()?, "/connected_peers")? == 1,
            "a hidden validator has a peer besides the host",
        )?;
    }

    let image: Vec<u8> = (0..50_000u32)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let image = hex::encode(image);
    let answer = first.rpc(
        "bud_gardenPublish",
        &json!(["image", image, "hex", "image/png"]),
    )?;
    let tx = text(&answer, "/tx_id")?;
    let content_id = text(&answer, "/content_id")?;
    let trace = second.wait_final(&tx)?;
    ensure(
        number(&trace, "/finality/needed")? == 3,
        "three validators need three signatures",
    )?;
    let resolved = second.rpc("bud_gardenResolve", &json!([content_id]))?;
    ensure(
        text(&resolved, "/hex")? == image,
        "content did not cross the relay",
    )
}
