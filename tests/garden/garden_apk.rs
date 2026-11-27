//! The ten APK acceptance checks of `direktifler/GARDEN_OPTIMIZASYON.md`
//! section 9.1, run against the phone's real Garden library.
//!
//! Section 9.1 requires that the APK is exercised rather than only built: a
//! Garden created on the phone, an invite shared out of it, a second phone
//! joining over that invite, content following, and the phone surviving a
//! restart, a wipe and a leave. The phone's library is `budlum_garden_ffi`,
//! the exact type the Android app reaches through UniFFI, so every check here
//! runs the code the APK ships.
//!
//! Where a check needs the phone to be a process rather than a call (a status
//! door, a restart, a second device), the `garden-phone` binary is started as
//! a child and read from outside, which is the only way to show that a seat
//! survives its process.
//!
//! `garden_apk_permissions_denied` is the one check that cannot run on a
//! desktop in full: it needs an Android sandbox that refuses a write. The half
//! that can be proven here is proven - a directory the process cannot write to
//! must fail the storage step instead of passing - and the Android half is
//! reported as the documented device-only gap rather than silently dropped, so
//! the count stays honest at nine of ten.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long a node, a join or a status change may take.
const PATIENCE: Duration = Duration::from_secs(90);
/// The round the nodes run with, in milliseconds.
const ROUND_MS: u64 = 200;

// ---------------------------------------------------------------------------
// The binaries
// ---------------------------------------------------------------------------

/// Resolve a binary the checks drive.
///
/// `CARGO_BIN_EXE_*` only names binaries of the current package, and both
/// `garden-phone` (in `mobile/garden-ffi`) and `budlum-core` live elsewhere,
/// so the search runs in order over:
///
/// 1. the profile directory of this test executable (`target/debug`), which
///    is where `cargo build --bin budlum-core` puts the node;
/// 2. `<workspace>/target/<profile>` as this file's own crate sees it;
/// 3. every directory named on `BUDLUM_BIN_PATH`, for a workspace whose
///    crates were built into separate target directories. The phone and the
///    node have different dependency graphs and are routinely built apart, so
///    the environment variable is the supported way to point at them.
fn profile_bin(name: &str) -> Result<PathBuf, String> {
    static CACHE: OnceLock<PathBuf> = OnceLock::new();
    let profile_dir = CACHE.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().and_then(Path::parent).map(Path::to_path_buf))
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(
                    if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    },
                )
            })
    });
    let mut candidates: Vec<PathBuf> = vec![profile_dir.join(name)];
    if let Ok(extra) = std::env::var("BUDLUM_BIN_PATH") {
        for dir in extra.split(':').filter(|dir| !dir.is_empty()) {
            candidates.push(Path::new(dir).join(name));
        }
    }
    let candidate = candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| profile_dir.join(name));
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!(
            "{name} is not built: looked in {candidates:?}. Build it and, if it landed in \
             another target directory, name that directory in BUDLUM_BIN_PATH \
             (for example BUDLUM_BIN_PATH=/path/to/target/debug)"
        ))
    }
}

fn phone_bin() -> Result<PathBuf, String> {
    profile_bin("garden-phone")
}

fn node_bin() -> Result<PathBuf, String> {
    profile_bin("budlum-core")
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

/// Wait until `probe` succeeds, or fail with `what` after `PATIENCE`.
fn wait_for<T>(
    what: &str,
    mut probe: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < PATIENCE {
        match probe() {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => {}
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err(if last.is_empty() {
        format!("{what} did not happen within {PATIENCE:?}")
    } else {
        format!("{what} did not happen within {PATIENCE:?}: {last}")
    })
}

// ---------------------------------------------------------------------------
// A Garden node from the core, started the way the scenario starts one
// ---------------------------------------------------------------------------

struct Node {
    operator: u16,
    child: Option<Child>,
    dir: tempfile::TempDir,
}

impl Node {
    fn start() -> Result<Self, String> {
        let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
        let operator = free_port()?;
        let public = free_port()?;
        let p2p = free_port()?;
        let metrics = free_port()?;
        let db = dir.path().join("db");
        let log = std::fs::File::create(dir.path().join("node.log")).map_err(|e| e.to_string())?;
        let errors = log.try_clone().map_err(|e| e.to_string())?;
        let child = Command::new(node_bin()?)
            .arg("--network=devnet")
            .arg(format!("--db-path={}", db.display()))
            .arg(format!("--port={p2p}"))
            .arg("--rpc-host=127.0.0.1")
            .arg(format!("--rpc-port={public}"))
            .arg(format!("--rpc-public-listener=127.0.0.1:{public}"))
            .arg(format!("--rpc-operator-listener=127.0.0.1:{operator}"))
            .arg(format!("--metrics-port={metrics}"))
            .arg(format!("--metrics-listener=127.0.0.1:{metrics}"))
            .arg("--mdns-enabled=false")
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
            operator,
            child: Some(child),
            dir,
        };
        wait_for("the operator listener", || {
            node.rpc("bud_gardenStatus", &json!([])).map(Some)
        })?;
        Ok(node)
    }

    fn rpc(&self, method: &str, params: &Value) -> Result<Value, String> {
        rpc_call(self.operator, method, params)
    }

    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(self.dir.path().join("node.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines
            .get(lines.len().saturating_sub(30)..)
            .map(|slice| slice.join("\n"))
            .unwrap_or_default()
    }

    /// Create the Garden on this node.
    ///
    /// Returns the invite line (what `join` takes) and the signed record
    /// (what `read` takes). They are two different strings: the line is
    /// `budlum-garden:1?...` and the record is `budlum://garden/join#...`.
    fn create(&self, title: &str) -> Result<Invite, String> {
        let answer = self
            .rpc(
                "bud_gardenCreate",
                &json!([title, "Host", {
                    "listen": "/ip4/127.0.0.1/tcp/0",
                    "round_ms": ROUND_MS,
                    "presence_interval_ms": 200,
                    "host_timeout_ms": 1500,
                    "suspend_after_ms": 3000,
                }]),
            )
            .map_err(|e| format!("{e}\n{}", self.log_tail()))?;
        let line = text(&answer, "/invite")?;
        let record = self
            .rpc("bud_gardenInvite", &json!([]))
            .map_err(|e| format!("{e}\n{}", self.log_tail()))?;
        let record = text(&record, "/record")?;
        Ok(Invite { line, record })
    }
}

/// The two strings a Garden creation hands out.
struct Invite {
    /// The invite line, `budlum-garden:1?...`, which `join` parses.
    line: String,
    /// The signed record, `budlum://garden/join#...`, which `read` parses
    /// and which is what a phone's QR code carries.
    record: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn text(answer: &Value, pointer: &str) -> Result<String, String> {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no {pointer} in the answer: {answer}"))
}

fn rpc_call(port: u16, method: &str, params: &Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("{method}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((_, payload)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("no body in the answer to {method}: {raw}"));
    };
    let value: Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    if let Some(error) = value.get("error") {
        return Err(format!("{method} refused: {error}"));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// The phone, as a child process
// ---------------------------------------------------------------------------

/// Run `garden-phone <args...>` to completion and return (ok, stdout+stderr).
fn phone(dir: &Path, args: &[&str]) -> Result<(bool, String), String> {
    // The command line is `<verb> <dir> <rest...>`: the verb comes first and
    // the app directory second, before any positional the verb takes. Putting
    // the directory last made `join` read the record as the directory and
    // build a path out of it.
    let (verb, rest) = args.split_first().ok_or("a phone command is needed")?;
    let output = Command::new(phone_bin()?)
        .arg(verb)
        .arg(dir)
        .args(rest)
        .output()
        .map_err(|e| format!("the phone did not run: {e}"))?;
    let mut joined = String::from_utf8_lossy(&output.stdout).into_owned();
    joined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), joined))
}

/// Run a phone verb whose positional order is `<verb> <dir> <rest...>`.
fn phone_verb(dir: &Path, verb: &str, rest: &[&str]) -> Result<(bool, String), String> {
    let mut args: Vec<&str> = vec![verb];
    args.extend_from_slice(rest);
    phone(dir, &args)
}

fn files_under(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            for inner in files_under(&path) {
                found.push(format!("{name}/{inner}"));
            }
        } else {
            found.push(name);
        }
    }
    found.sort();
    found
}

struct Serving {
    child: Child,
    port: u16,
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `garden-phone serve <dir> <port> [record]` and wait for its door.
fn serve(dir: &Path, record: Option<&str>) -> Result<(Serving, Value), String> {
    let port = free_port()?;
    let mut command = Command::new(phone_bin()?);
    command.arg("serve").arg(dir).arg(port.to_string());
    if let Some(record) = record {
        command.arg(record).arg("Phone");
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the phone did not start: {e}"))?;
    let mut serving = Serving { child, port };
    let status = wait_for("the phone's status door", || {
        status_over(serving.port).map(Some)
    })?;
    // Keep the child handle alive for the caller's scope.
    serving.port = port;
    Ok((serving, status))
}

/// Start `garden-phone host <dir> <port> <title> <name> [listen]` and wait for its door.
fn host_phone(
    dir: &Path,
    title: &str,
    name: &str,
    listen: Option<&str>,
) -> Result<(Serving, Value), String> {
    let port = free_port()?;
    let mut command = Command::new(phone_bin()?);
    command
        .arg("host")
        .arg(dir)
        .arg(port.to_string())
        .arg(title)
        .arg(name);
    if let Some(listen) = listen {
        command.arg(listen);
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("the founding phone did not start: {e}"))?;
    let mut serving = Serving { child, port };
    let status = wait_for("the founding phone's status door", || {
        if let Ok(Some(exit)) = serving.child.try_wait() {
            return Err(format!("the founding phone exited early with {exit}"));
        }
        status_over(serving.port).map(Some)
    })?;
    Ok((serving, status))
}

/// Send a JSON `POST` to a live `garden-phone` control door.
fn post_json(port: u16, path: &str, body: &Value) -> Result<(u16, Value), String> {
    let payload = body.to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((head, resp_body)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("no body from POST {path}: {raw}"));
    };
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("no status code from POST {path}: {head}"))?;
    let parsed = serde_json::from_str(resp_body).map_err(|e| e.to_string())?;
    Ok((code, parsed))
}

/// Send a raw HTTP request line and return `(status_code, raw_headers, json_body)`.
fn raw_http(port: u16, method: &str, path: &str) -> Result<(u16, String, Value), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((head, resp_body)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("no body from {method} {path}: {raw}"));
    };
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("no status code from {method} {path}: {head}"))?;
    let parsed = serde_json::from_str(resp_body).unwrap_or(Value::Null);
    Ok((code, head.to_string(), parsed))
}

/// Ask a `serve` door one path and read its JSON answer.
fn get_path(port: u16, path: &str) -> Result<Value, String> {
    get_with_status(port, path).map(|(_, body)| body)
}

/// The same read, keeping the status line.
///
/// A door that answers a refusal with `200` and an `{"error":...}` body is
/// indistinguishable from an answer to a caller that reads the status first,
/// which is what most do. The checks that care ask for the status.
fn get_with_status(port: u16, path: &str) -> Result<(u16, Value), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((head, payload)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("no body from {path}: {raw}"));
    };
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("no status line from {path}: {head}"))?;
    let body = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    Ok((status, body))
}

fn status_over(port: u16) -> Result<Value, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: phone\r\nConnection: close\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((_, payload)) = raw.split_once("\r\n\r\n") else {
        return Err(format!("no body from the status door: {raw}"));
    };
    serde_json::from_str(payload).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// The ten checks
// ---------------------------------------------------------------------------

/// 9.1 item 1: the APK carries the core, so the phone can run its own checks
/// before it is allowed to join anything.
#[test]
fn garden_apk_single_file() -> Result<(), String> {
    let bin = phone_bin()?;
    let size = std::fs::metadata(&bin).map_err(|e| e.to_string())?.len();
    assert!(size > 0, "{} is empty", bin.display());
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "self-test", &[])?;
    assert!(ok, "the four-step self test failed: {log}");
    assert!(
        log.contains("all four passed"),
        "the self test did not report all four steps: {log}"
    );
    for step in ["write to private storage", "key", "listen"] {
        assert!(log.contains(step), "the self test skipped {step}: {log}");
    }
    Ok(())
}

/// 9.1 item 2: a fresh install has no Garden and no seat.
#[test]
fn garden_apk_clean_install() -> Result<(), String> {
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "status", &[])?;
    assert!(ok, "status failed on a fresh install: {log}");
    assert!(
        log.contains("\"garden\":null"),
        "a fresh install already runs a Garden: {log}"
    );
    assert!(
        !files_under(dir.path()).iter().any(|f| f == "seat.json"),
        "a fresh install already carries a seat: {:?}",
        files_under(dir.path())
    );
    Ok(())
}

/// 9.1 item 3: the first run gets through its own gate within the time ceiling,
/// founds a Garden with no manual setup, produces both the invite record and
/// local QR content within their byte bounds, and decodes the QR content back.
#[test]
fn garden_apk_first_run() -> Result<(), String> {
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let (ok, log) = phone_verb(dir.path(), "self-test", &[])?;
    assert!(ok, "the first run refused to get past its gate: {log}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "first-run self test exceeded the 15s ceiling: {:?}",
        started.elapsed()
    );
    let (ok, status) = phone_verb(dir.path(), "status", &[])?;
    assert!(
        ok,
        "the first run left the app directory unusable: {status}"
    );
    assert!(
        status.contains("\"garden\":null"),
        "the first run already joined something: {status}"
    );

    // Found an isolated Garden on this phone and inspect its invite + QR record.
    let (founder, founded_status) = host_phone(
        dir.path(),
        "First Run Room",
        "Founder",
        Some("/ip4/127.0.0.1/tcp/0"),
    )?;
    assert_eq!(
        founded_status
            .pointer("/garden/status")
            .and_then(Value::as_str),
        Some("Active"),
        "the founded Garden is not Active: {founded_status}"
    );
    let chain_id = text(&founded_status, "/garden/chain_id")?;
    let host_key = text(&founded_status, "/garden/me/key")?;

    let (code, invite_json) = get_with_status(founder.port, "/invite")?;
    assert_eq!(code, 200, "/invite refused: {invite_json}");
    let record = text(&invite_json, "/record")?;
    let record_qr = text(&invite_json, "/record_qr")?;
    assert!(
        record.starts_with("budlum://garden/join#") && record.len() <= 512,
        "record outside format/512B ceiling ({}B): {record}",
        record.len()
    );
    assert!(
        record_qr.starts_with("http://") && record_qr.contains("/g#") && record_qr.len() <= 640,
        "local QR outside http://<addr>/g# format or 640B ceiling ({}B): {record_qr}",
        record_qr.len()
    );

    // The phone's own decoder reads the QR content back to the same Garden.
    let reader_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, decoded_raw) = phone_verb(reader_dir.path(), "read", &[&record_qr])?;
    assert!(
        ok,
        "phone decoder rejected local HTTP QR content: {decoded_raw}"
    );
    let decoded: Value = serde_json::from_str(&decoded_raw).map_err(|e| e.to_string())?;
    assert_eq!(text(&decoded, "/chain_id")?, chain_id);
    assert_eq!(text(&decoded, "/host")?, host_key);
    drop(founder);
    Ok(())
}

/// 9.1 item 4: the phone itself founds and hosts an isolated Garden, at least
/// five Linux validators plus a second phone validator (via local HTTP QR)
/// join its network, tampered/uninvited joins are refused, the host phone
/// uploads an image, and peers resolve and chain-verify it with equal content id.
#[test]
fn garden_apk_host_scenario() -> Result<(), String> {
    let founder_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (founder, founded) = host_phone(
        founder_dir.path(),
        "Phone Founded Isolated Network",
        "FounderPhone",
        Some("/ip4/127.0.0.1/tcp/0"),
    )?;
    assert_eq!(
        founded.pointer("/garden/status").and_then(Value::as_str),
        Some("Active"),
        "founder phone is not Active: {founded}"
    );
    assert_eq!(
        founded.pointer("/garden/me/host").and_then(Value::as_bool),
        Some(true),
        "founder phone is not recorded as the host: {founded}"
    );

    let invite_json = get_path(founder.port, "/invite")?;
    let record = text(&invite_json, "/record")?;
    let record_qr = text(&invite_json, "/record_qr")?;
    let invite_line = text(&invite_json, "/invite")?;

    // Five real Linux validator nodes join the phone's isolated Garden.
    let mut linux_validators = Vec::new();
    for idx in 1..=5 {
        let peer = Node::start()?;
        let join_target = if idx % 2 == 0 { &record } else { &record_qr };
        let joined = peer.rpc(
            "bud_gardenJoin",
            &json!([join_target, format!("LinuxVal{idx}"), { "listen": "/ip4/127.0.0.1/tcp/0" }]),
        )?;
        assert_eq!(
            joined.pointer("/garden/me/member").and_then(Value::as_str),
            Some("Active"),
            "Linux validator {idx} did not become Active: {joined}"
        );
        linux_validators.push(peer);
    }

    // A second phone validator joins directly from the local HTTP QR string.
    let second_phone_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (second_phone, second_status) = serve(second_phone_dir.path(), Some(&record_qr))?;
    assert_eq!(
        second_status
            .pointer("/garden/status")
            .and_then(Value::as_str),
        Some("Active"),
        "second phone did not join over local HTTP QR: {second_status}"
    );

    // Wait until the founder phone sees all 7 active validators (founder + 5 Linux + 1 peer phone).
    wait_for("seven active validators on the phone-hosted Garden", || {
        let st = get_path(founder.port, "/")?;
        let count = st
            .pointer("/garden/active_validators")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Ok((count == 7).then_some(()))
    })?;

    // Adversarial check: an uninvited / wrong-genesis invite is refused fail-closed.
    let rogue_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let tampered_invite = invite_line.replacen("genesis=", "genesis=ff", 1);
    let (rogue_ok, _rogue_log) =
        phone_verb(rogue_dir.path(), "read", &["budlum://garden/join#AAAA"])?;
    assert!(!rogue_ok, "malformed invite record was accepted");
    let rogue_node = Node::start()?;
    assert!(
        rogue_node
            .rpc(
                "bud_gardenJoin",
                &json!([tampered_invite, "Rogue", { "listen": "/ip4/127.0.0.1/tcp/0" }]),
            )
            .is_err(),
        "wrong-genesis invite was admitted into the isolated Garden"
    );
    drop(rogue_node);

    // The founder phone uploads a 32 KiB PNG-like image into its isolated Garden.
    let mut image_bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    for i in 0..32_760u32 {
        image_bytes.push(((i.wrapping_mul(31) ^ (i >> 3)) & 0xff) as u8);
    }
    let image_hex = hex::encode(&image_bytes);
    let (post_code, published) = post_json(
        founder.port,
        "/send-image",
        &json!({
            "hex": image_hex,
            "mime": "image/png",
            "caption": "founder-phone-camera-frame"
        }),
    )?;
    assert_eq!(
        post_code, 200,
        "founder phone image upload failed: {published}"
    );
    let content_id = text(&published, "/content_id")?;
    let tx_id = text(&published, "/tx_id")?;

    // A Linux validator waits for finality across the 7-validator PoA quorum and resolves the image.
    let verifier_node = linux_validators
        .first()
        .ok_or_else(|| "missing Linux validator".to_string())?;
    wait_for("phone-uploaded image transaction to finalize", || {
        let trace = verifier_node.rpc("bud_gardenTrace", &json!([tx_id]))?;
        Ok((text(&trace, "/stage")? == "final").then_some(()))
    })?;
    let resolved_on_linux = verifier_node.rpc("bud_gardenResolve", &json!([content_id]))?;
    assert_eq!(text(&resolved_on_linux, "/content_id")?, content_id);
    assert_eq!(text(&resolved_on_linux, "/hex")?, image_hex);
    assert_eq!(
        resolved_on_linux.get("verified").and_then(Value::as_bool),
        Some(true)
    );

    // The second phone validator also fetches and chain-verifies the exact image bytes.
    let resolved_on_phone = wait_for("second phone to fetch and verify the image", || {
        let (st, body) = get_with_status(second_phone.port, &format!("/fetch/{content_id}"))?;
        if st == 200 {
            Ok(Some(body))
        } else {
            Ok(None)
        }
    })?;
    assert_eq!(text(&resolved_on_phone, "/content_id")?, content_id);
    assert_eq!(text(&resolved_on_phone, "/hex")?, image_hex);
    assert_eq!(
        resolved_on_phone.get("verified").and_then(Value::as_bool),
        Some(true)
    );

    // Sudden departure of one non-host Linux validator keeps the isolated chain and content alive.
    let dropped = linux_validators.pop();
    drop(dropped);
    let (msg_code, msg_pub) = post_json(
        founder.port,
        "/send",
        &json!({ "text": "isolated network continues after peer drop", "caption": "after-drop" }),
    )?;
    assert_eq!(msg_code, 200, "post-drop send failed: {msg_pub}");
    let msg_tx = text(&msg_pub, "/tx_id")?;
    let remaining = linux_validators
        .last()
        .ok_or_else(|| "missing remaining Linux validator".to_string())?;
    wait_for("post-drop message finality", || {
        let trace = remaining.rpc("bud_gardenTrace", &json!([msg_tx]))?;
        Ok((text(&trace, "/stage")? == "final").then_some(()))
    })?;

    // HTTP control door rejects unsafe methods, unknown routes, and carries no wildcard CORS.
    let (bad_method, headers, _) = raw_http(founder.port, "DELETE", "/")?;
    assert_eq!(
        bad_method, 405,
        "unexpected status for DELETE /: {bad_method}"
    );
    assert!(
        !headers
            .to_ascii_lowercase()
            .contains("access-control-allow-origin: *"),
        "control door exposed wildcard CORS: {headers}"
    );
    let (not_found, _, _) = raw_http(founder.port, "GET", "/unknown-route")?;
    assert_eq!(
        not_found, 404,
        "unexpected status for unknown route: {not_found}"
    );
    let (bad_feed, _, _) = raw_http(founder.port, "GET", "/feed/0")?;
    assert_eq!(bad_feed, 400, "unexpected status for /feed/0: {bad_feed}");

    drop(second_phone);
    drop(linux_validators);
    drop(founder);
    Ok(())
}

/// 9.1 item 5: a second phone joins over the invite link alone.
#[test]
fn garden_apk_join_by_link() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk join by link")?;
    let record = invite.line.clone();
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "join", &[&record, "Second"])?;
    assert!(ok, "the second phone did not join over the link: {log}");
    assert!(
        log.contains("joined") || log.contains("Active"),
        "the join answered without a Garden: {log}"
    );
    // A join that ends when the command ends is not a validator, so the
    // status after the join names the place and the way back, not a live
    // seat. What a link has to prove is that it was enough to get in: the
    // seat it left behind can return to the Garden without the link again.
    let (ok, status) = phone_verb(dir.path(), "status", &[])?;
    assert!(ok, "the second phone cannot report its status: {status}");
    assert!(
        status.contains("Away") || status.contains("Active"),
        "the second phone kept no seat from the link: {status}"
    );
    // The way back is the seat, not the link: a process started with no
    // record at all returns through `rejoin`, which is what the Status
    // screen calls on the way up.
    let (serving, back) = serve(dir.path(), None)?;
    assert_eq!(
        back.pointer("/garden/status").and_then(Value::as_str),
        Some("Active"),
        "the seat the link bought is not a way back: {back}"
    );
    drop(serving);
    Ok(())
}

/// 9.1 item 6: the invite is a shareable link a joining phone can read before
/// acting on it, with QR content beside it.
#[test]
fn garden_apk_share() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk share")?;
    let record = invite.record.clone();
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "read", &[&record])?;
    assert!(ok, "the share link could not be read: {log}");
    // The record a phone's QR carries names the Garden it opens: the chain it
    // belongs to, who holds the door, when the door closes, and how many may
    // come through. A title is the host's label and travels in the invite
    // line, not in the signed record.
    for field in ["chain_id", "host", "expires_at_ms", "uses"] {
        assert!(
            log.contains(&format!("\"{field}\"")),
            "the record does not carry {field}: {log}"
        );
    }
    Ok(())
}

/// 9.1 item 7: what one member sends into the Garden comes back out of the
/// Garden on another member, byte for byte.
///
/// The earlier draft had the host publish and the host read the answer back,
/// which proves a node can talk to itself. Here the phone is the reader: it
/// joins over the invite, the host puts an object into the Garden, and the
/// phone lists it and fetches the bytes back by content id - from the
/// Garden's copies, verified against the chain, not from the sender.
///
/// Reading needs a phone that is still *live*, so the phone is held open by
/// `serve` and asked through its own door (`/feed`, `/fetch/<id>`). A command
/// that joins keeps its seat and ends, and a second process would only get as
/// far as returning through that seat.
#[test]
fn garden_apk_clipboard_join() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk clipboard")?;
    let record = invite.line.clone();
    let phone = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (serving, status) = serve(phone.path(), Some(&record))?;
    assert_eq!(
        status.pointer("/garden/status").and_then(Value::as_str),
        Some("Active"),
        "the phone is not an active validator: {status}"
    );

    // Something goes into the Garden that the phone did not write. Both the
    // text and its caption carry a token unique to this run, so a Garden this
    // check meets with an object already in it cannot satisfy the read with
    // the wrong bytes - and the feed, which lists captions, can be matched
    // without depending on how a body is rendered in a listing.
    let token = format!("clipboard-{}-{}", invite.line.len(), node.operator);
    let sent = format!("the clipboard of {token}");
    let caption = format!("caption of {token}");
    let published = node.rpc(
        "bud_gardenPublish",
        &json!(["message", sent, "utf8", "text/plain", caption]),
    )?;
    let content_id = text(&published, "/content_id")?;
    let tx = text(&published, "/tx_id")?;
    wait_for("the publication to finalise", || {
        let trace = node.rpc("bud_gardenTrace", &json!([tx]))?;
        match text(&trace, "/stage")?.as_str() {
            "final" => Ok(Some(())),
            _ => Ok(None),
        }
    })?;

    // The live phone lists it...
    let feed = wait_for("the publication to reach the phone's feed", || {
        let feed = get_path(serving.port, "/feed/10")?;
        Ok(feed.to_string().contains(&caption).then_some(feed))
    })?;
    assert!(
        feed.to_string().contains(&caption),
        "the phone's feed does not carry what the Garden holds: {feed}"
    );

    // ...and fetches the bytes back out by content id.
    let fetched = get_path(serving.port, &format!("/fetch/{content_id}"))?;
    assert_eq!(
        fetched.get("text").and_then(Value::as_str),
        Some(sent.as_str()),
        "the phone got different content back: {fetched}"
    );
    assert_eq!(
        fetched.get("verified").and_then(Value::as_bool),
        Some(true),
        "the phone did not verify what it fetched: {fetched}"
    );

    // ...and what it does with a content id no Garden holds. A door that
    // answers "200, and here is an error inside" is a door a caller cannot
    // tell from success without reading the body, which most callers do not.
    let missing = "0".repeat(64);
    let (status, body) = get_with_status(serving.port, &format!("/fetch/{missing}"))?;
    assert_ne!(
        status, 200,
        "the phone answered 200 for a content id it does not hold: {body}"
    );
    assert!(
        body.get("error").is_some(),
        "the refusal does not say what was refused: {body}"
    );
    drop(serving);
    Ok(())
}

/// 9.1 item 8: a phone that is closed and opened again keeps its seat, and
/// the seat outlives the process that wrote it.
#[test]
fn garden_apk_background() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk background")?;
    let record = invite.line.clone();
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;

    // Hold the Garden open in one process, as the app does while the screen
    // is up, then kill it and check the seat that is left on disk.
    let (serving, before) = serve(dir.path(), Some(&record))?;
    assert_eq!(
        before.pointer("/garden/status").and_then(Value::as_str),
        Some("Active"),
        "the first process is not an active validator: {before}"
    );
    drop(serving);
    assert!(
        dir.path().join("seat.json").exists(),
        "the join left no seat on disk: {:?}",
        files_under(dir.path())
    );

    // A second process reads what the first one wrote and is still in the
    // Garden, without being handed the invite again.
    let (serving, after) = serve(dir.path(), None)?;
    assert_eq!(
        after.pointer("/garden/status").and_then(Value::as_str),
        Some("Active"),
        "the second process lost the seat: {after}"
    );
    drop(serving);
    // Leave and return, as the Status screen's two taps do them: join, leave
    // and come back in one process. That needs a phone with no seat yet - a
    // phone that already holds one is told to use the return door, which is
    // the second half of this check above - so the round trip runs on a
    // second device against the same Garden, whose host is still standing.
    let other = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(other.path(), "return-check", &[&record, "Second"])?;
    assert!(ok, "leave-and-return is broken: {log}");
    assert!(
        log.contains("the phone left and came back"),
        "the round trip did not report a return: {log}"
    );
    Ok(())
}

/// 9.1 item 9: leaving wipes the Garden from the phone.
///
/// The Status screen offers two different leaves and the phone tells them
/// apart. Stepping out of a Garden that still stands keeps the seat, so the
/// way back is one tap; the phone here is the only member, so its leave
/// retires the Garden and nothing is kept - not the content, not the seat.
#[test]
fn garden_apk_cleanup() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk cleanup")?;
    let record = invite.line.clone();
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "join", &[&record, "Phone"])?;
    assert!(ok, "the phone did not join: {log}");
    // What a leave touches is the Garden's own data: the content tree under
    // `<app dir>/garden/<chain id>` and the seat at the top. A file put at the
    // top of the app directory is not Garden data and is not the leave's to
    // remove, so the check is made on the Garden's own paths. A phone that
    // only joined published nothing, so the content tree may be empty here -
    // that is not a failure, and the seat is what a join certainly leaves.
    let before = files_under(dir.path());
    assert!(
        before.iter().any(|path| path == "seat.json"),
        "the join left no seat to clean up: {before:?}"
    );

    let (ok, left) = phone_verb(dir.path(), "leave", &[])?;
    assert!(ok, "the leave failed: {left}");
    assert!(
        left.contains("\"left\":true"),
        "the leave did not answer: {left}"
    );
    // The answer has to be one of the two honest outcomes, and the disk has
    // to agree with it: a promise of a way back is a seat that is kept, and a
    // retired Garden keeps nothing.
    let keeps_seat = left.contains("\"can_return\":true");
    let retires = left.contains("\"retired\":true");
    assert!(
        keeps_seat || retires,
        "the leave answered neither a seat nor a retirement: {left}"
    );
    assert!(
        !(keeps_seat && retires),
        "the leave promised a way back to a Garden it retired: {left}"
    );
    let kept = files_under(dir.path());
    assert!(
        !kept.iter().any(|path| path.starts_with("garden/")),
        "Garden content survived the leave: {kept:?}"
    );
    let seat_kept = kept.iter().any(|path| path == "seat.json");
    assert_eq!(
        seat_kept, keeps_seat,
        "the disk disagrees with the answer about the way back: answer {left}, files {kept:?}"
    );
    // There is nothing to return to, and the phone says so instead of
    // quietly rejoining a Garden that no longer exists.
    let (ok, back) = phone_verb(dir.path(), "status", &[])?;
    assert!(ok, "status failed after the leave: {back}");
    assert!(
        !back.contains("\"Active\""),
        "the phone is still in a Garden it left: {back}"
    );
    Ok(())
}

/// 9.1 item 10: the app runs with Android's storage permission refused.
///
/// Android refuses a write by failing it inside the app sandbox. A desktop
/// cannot produce that refusal, so the Android half is reported missing. The
/// half that can be proven here is proven: a directory the process cannot
/// write to must fail the self test instead of passing it.
#[test]
fn garden_apk_permissions_denied() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let bin = phone_bin().expect("the phone binary is built");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let read_only = dir.path().join("read-only");
        std::fs::create_dir(&read_only).expect("a directory");
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o555))
            .expect("a read-only directory");
        let output = Command::new(bin)
            .arg("self-test")
            .arg(&read_only)
            .output()
            .expect("the self test runs");
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o755))
            .expect("the directory is writable again");
        // Root can write anywhere, so the refusal only means something when
        // the process is not root. Either way, a passing self test on an
        // unwritable directory would be the bug this check exists to catch.
        if !dir
            .path()
            .metadata()
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
        {
            eprintln!("note: running as root, so the storage refusal cannot be produced here");
        }
        assert!(
            !log.contains("all four passed") || is_root(),
            "a directory the phone cannot write passed the self test: {log}"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = bin;
    }
    eprintln!(
        "garden_apk_permissions_denied: the Android sandbox half is device-only; \
         the refusal half was exercised above"
    );
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|uid| uid.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Airgapped multi-device isolated LAN proof: three separate `garden-phone`
/// device validator processes inside isolated Linux network namespaces with
/// zero default gateway (`0.0.0.0/0`) and zero internet access discover their
/// LAN interface automatically, form a 3-validator PoA chain over a virtual
/// L2 bridge, exchange and chain-verify content, and clean up completely.
#[test]
fn garden_apk_isolated_airgap_lan() -> Result<(), String> {
    let can_netns = Command::new("sudo")
        .args(["-n", "ip", "netns", "list"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !can_netns {
        eprintln!("garden_apk_isolated_airgap_lan: skipped (sudo ip netns unavailable)");
        return Ok(());
    }

    struct AirgapLan;
    impl AirgapLan {
        fn run_root(args: &[&str]) -> Result<String, String> {
            let out = Command::new("sudo")
                .arg("-n")
                .args(args)
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            } else {
                Err(format!(
                    "sudo {}: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        }

        fn clear() {
            for ns in ["gdn-air-sw", "gdn-air-1", "gdn-air-2", "gdn-air-3"] {
                if let Ok(pids) = Self::run_root(&["ip", "netns", "pids", ns]) {
                    for pid in pids.split_whitespace() {
                        let _ = Self::run_root(&["kill", "-9", pid]);
                    }
                }
                let _ = Self::run_root(&["ip", "netns", "del", ns]);
            }
        }

        fn setup() -> Result<Self, String> {
            Self::clear();
            let guard = Self;
            Self::run_root(&["ip", "netns", "add", "gdn-air-sw"])?;
            Self::run_root(&["ip", "-n", "gdn-air-sw", "link", "set", "lo", "up"])?;
            Self::run_root(&[
                "ip",
                "-n",
                "gdn-air-sw",
                "link",
                "add",
                "br0",
                "type",
                "bridge",
            ])?;
            Self::run_root(&["ip", "-n", "gdn-air-sw", "link", "set", "br0", "up"])?;

            for n in 1..=3 {
                let ns = format!("gdn-air-{n}");
                let v_dev = format!("ga{n}d");
                let v_sw = format!("ga{n}s");
                let ip = format!("10.77.0.1{n}/24");
                Self::run_root(&["ip", "netns", "add", &ns])?;
                Self::run_root(&["ip", "-n", &ns, "link", "set", "lo", "up"])?;
                Self::run_root(&[
                    "ip",
                    "link",
                    "add",
                    &v_dev,
                    "netns",
                    &ns,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &v_sw,
                    "netns",
                    "gdn-air-sw",
                ])?;
                Self::run_root(&[
                    "ip",
                    "-n",
                    "gdn-air-sw",
                    "link",
                    "set",
                    &v_sw,
                    "master",
                    "br0",
                ])?;
                Self::run_root(&["ip", "-n", "gdn-air-sw", "link", "set", &v_sw, "up"])?;
                Self::run_root(&["ip", "-n", &ns, "addr", "add", &ip, "dev", &v_dev])?;
                Self::run_root(&["ip", "-n", &ns, "link", "set", &v_dev, "up"])?;
                // Deliberately add NO default gateway (`0.0.0.0/0`): pure isolated L2 LAN.
            }
            Ok(guard)
        }
    }
    impl Drop for AirgapLan {
        fn drop(&mut self) {
            AirgapLan::clear();
        }
    }

    fn ns_http(
        ns: &str,
        port: u16,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        let payload = body.map_or_else(String::new, Value::to_string);
        let req = if body.is_some() {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            )
        } else {
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        };
        let py = "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 10); s.sendall(sys.argv[2].encode()); chunks=[]; \nwhile True:\n d=s.recv(65536)\n if not d: break\n chunks.append(d)\nsys.stdout.buffer.write(b''.join(chunks))";
        let out = Command::new("sudo")
            .args([
                "-n",
                "ip",
                "netns",
                "exec",
                ns,
                "python3",
                "-c",
                py,
                &port.to_string(),
                &req,
            ])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        let raw = String::from_utf8_lossy(&out.stdout);
        let Some((head, resp_body)) = raw.split_once("\r\n\r\n") else {
            return Err(format!("short HTTP answer in {ns}: {raw}"));
        };
        let code = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if code != 200 {
            return Err(format!("HTTP {code} in {ns}: {resp_body}"));
        }
        serde_json::from_str(resp_body).map_err(|e| e.to_string())
    }

    let _lan = AirgapLan::setup()?;
    let bin = phone_bin()?;
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "1000".to_string(), |s| s.trim().to_string());
    let dir1 = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let dir2 = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let dir3 = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let door_port: u16 = 19480;

    // Device 1 starts in `gdn-air-1` (`10.77.0.11/24`, ZERO default gateway) with NO explicit address!
    let mut dev1 = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            "gdn-air-1",
            "sudo",
            "-u",
            &format!("#{uid}"),
        ])
        .arg(&bin)
        .args([
            "host",
            &dir1.path().to_string_lossy(),
            &door_port.to_string(),
            "AirgapLAN",
            "DeviceOne",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let dev1_status = wait_for(
        "DeviceOne founding validator on zero-gateway airgap LAN",
        || ns_http("gdn-air-1", door_port, "GET", "/", None).map(Some),
    );
    if let Err(e) = &dev1_status {
        let _ = dev1.kill();
        let out = dev1.wait_with_output().ok();
        let diag = out
            .map(|o| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            })
            .unwrap_or_default();
        return Err(format!("{e}\nDeviceOne output:\n{diag}"));
    }
    let invite_json = ns_http("gdn-air-1", door_port, "GET", "/invite", None)?;
    let record = text(&invite_json, "/record")?;
    let record_qr = text(&invite_json, "/record_qr")?;
    assert!(
        record_qr.starts_with("http://10.77.0.11") && record_qr.contains("/g#"),
        "zero-gateway LAN auto-discovery did not bind 10.77.0.11: {invite_json}"
    );

    // Device 2 (`10.77.0.12`) joins via the local HTTP QR record; Device 3 (`10.77.0.13`) joins via the record link.
    let mut dev2 = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            "gdn-air-2",
            "sudo",
            "-u",
            &format!("#{uid}"),
        ])
        .arg(&bin)
        .args([
            "serve",
            &dir2.path().to_string_lossy(),
            &door_port.to_string(),
            &record_qr,
            "DeviceTwo",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let mut dev3 = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            "gdn-air-3",
            "sudo",
            "-u",
            &format!("#{uid}"),
        ])
        .arg(&bin)
        .args([
            "serve",
            &dir3.path().to_string_lossy(),
            &door_port.to_string(),
            &record,
            "DeviceThree",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let res = (|| -> Result<(), String> {
        wait_for(
            "three airgapped device validators in active consensus",
            || {
                for (label, child) in [
                    ("dev1", &mut dev1),
                    ("dev2", &mut dev2),
                    ("dev3", &mut dev3),
                ] {
                    if let Ok(Some(st)) = child.try_wait() {
                        let mut out = String::new();
                        if let Some(mut s) = child.stdout.take() {
                            let _ = s.read_to_string(&mut out);
                        }
                        if let Some(mut e) = child.stderr.take() {
                            let _ = e.read_to_string(&mut out);
                        }
                        return Err(format!("{label} exited early ({st}): {out}"));
                    }
                }
                let s1 = ns_http("gdn-air-1", door_port, "GET", "/", None)?;
                let s2 = ns_http("gdn-air-2", door_port, "GET", "/", None)?;
                let s3 = ns_http("gdn-air-3", door_port, "GET", "/", None)?;
                let ok = s1.pointer("/garden/active_validators") == Some(&json!(3))
                    && s2.pointer("/garden/active_validators") == Some(&json!(3))
                    && s3.pointer("/garden/active_validators") == Some(&json!(3))
                    && s1
                        .pointer("/garden/connected_peers")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        >= 2
                    && s2
                        .pointer("/garden/connected_peers")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        >= 1
                    && s3
                        .pointer("/garden/connected_peers")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        >= 1;
                Ok(ok.then_some(()))
            },
        )?;

        // Device 2 publishes a message on the airgapped LAN; Device 3 and Device 1 verify it!
        let payload_msg = "hello across pure zero-internet airgap LAN";
        let sent = ns_http(
            "gdn-air-2",
            door_port,
            "POST",
            "/send",
            Some(&json!({ "text": payload_msg, "caption": "airgap-note" })),
        )?;
        let cid = text(&sent, "/content_id")?;

        for reader_ns in ["gdn-air-1", "gdn-air-3"] {
            let fetched = wait_for(&format!("{reader_ns} fetching airgapped object"), || {
                ns_http(reader_ns, door_port, "GET", &format!("/fetch/{cid}"), None)
                    .ok()
                    .map(Ok)
                    .transpose()
            })?;
            assert_eq!(text(&fetched, "/content_id")?, cid);
            assert_eq!(
                fetched.get("text").and_then(Value::as_str),
                Some(payload_msg)
            );
            assert_eq!(fetched.get("verified").and_then(Value::as_bool), Some(true));
        }
        Ok(())
    })();

    let _ = dev3.kill();
    let _ = dev2.kill();
    let _ = dev1.kill();
    let _ = dev3.wait();
    let _ = dev2.wait();
    let _ = dev1.wait();
    res
}

/// Direct `GardenService` proof:
/// `service.invite()` emits a local HTTP QR (`http://<addr>/g#<record>`) when
/// the validator has a dialable address, `service.join()` accepts both
/// `budlum://garden/join#...` and `http://<addr>/g#...` records, and
/// authority/fragment-injected `http://` URLs are rejected fail-closed.
#[tokio::test]
async fn garden_apk_service_qr_join_and_ended_seat_cleanup() -> Result<(), String> {
    use budlum_core::garden::{GardenOptions, GardenService};

    let opts = || GardenOptions {
        listen: Some("/ip4/127.0.0.1/tcp/0".into()),
        round_ms: Some(200),
        presence_interval_ms: Some(200),
        host_timeout_ms: Some(1500),
        suspend_after_ms: Some(3000),
        ..GardenOptions::default()
    };

    let host_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let qr_guest_dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let host = GardenService::new(None, Some(host_dir.path().to_path_buf()));
    let qr_guest = GardenService::new(None, Some(qr_guest_dir.path().to_path_buf()));

    host.create("QR Service Room".into(), "Host".into(), opts())
        .await?;
    let invite_val = host.invite().await?;
    let record_link = text(&invite_val, "/record")?;
    let local_qr = text(&invite_val, "/record_qr")?;
    assert!(
        local_qr.starts_with("http://127.0.0.1:") && local_qr.contains("/g#"),
        "service.invite() did not emit http://<local>/g# record_qr: {local_qr}"
    );
    let fragment = record_link
        .strip_prefix("budlum://garden/join#")
        .ok_or_else(|| format!("unexpected record prefix: {record_link}"))?;

    // Reject URL authority/query/fragment injection in local HTTP QR strings.
    for injected in [
        format!("http://127.0.0.1:8080@evil.example/g#{fragment}"),
        format!("http://127.0.0.1:8080?x=1/g#{fragment}"),
        format!("http://127.0.0.1:8080#x/g#{fragment}"),
        format!("http://127.0.0.1:8080/g#{fragment}#extra"),
    ] {
        assert!(
            GardenService::read_record(&injected).is_err(),
            "injected QR URL was accepted: {injected}"
        );
    }

    // Joining directly with the local HTTP QR string succeeds.
    let joined = qr_guest.join(local_qr, "QrGuest".into(), opts()).await?;
    assert_eq!(
        joined.pointer("/garden/me/member").and_then(Value::as_str),
        Some("Active")
    );
    let _ = qr_guest.leave().await?;
    let _ = qr_guest.leave().await?;
    let _ = host.leave().await?;
    Ok(())
}
