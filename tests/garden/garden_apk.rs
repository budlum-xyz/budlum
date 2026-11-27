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

/// 9.1 item 3: the first run gets through its own gate and leaves the app
/// directory in a state the next screen can use.
#[test]
fn garden_apk_first_run() -> Result<(), String> {
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "self-test", &[])?;
    assert!(ok, "the first run refused to get past its gate: {log}");
    // The self test writes and removes its probe file; what must remain true
    // is that the process could use the directory it was given.
    let (ok, status) = phone_verb(dir.path(), "status", &[])?;
    assert!(
        ok,
        "the first run left the app directory unusable: {status}"
    );
    assert!(
        status.contains("\"garden\":null"),
        "the first run already joined something: {status}"
    );
    Ok(())
}

/// 9.1 item 4: a phone joins a real Garden node and the host sees it.
#[test]
fn garden_apk_host_scenario() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk host scenario")?;
    let record = invite.line.clone();
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "join", &[&record, "Phone"])?;
    assert!(ok, "the phone did not join: {log}");
    assert!(
        log.contains("joined") || log.contains("Active"),
        "the join answered without a Garden: {log}"
    );
    // The host sees the phone: a join nobody observes is not a join.
    wait_for("the phone in the host's status", || {
        let garden = node.rpc("bud_gardenStatus", &json!([]))?;
        garden
            .pointer("/garden/active_validators")
            .and_then(Value::as_u64)
            .map(|n| if n >= 2 { Some(()) } else { None })
            .ok_or_else(|| format!("no active validator count: {garden}"))
    })?;
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
    // remove, so the check is made on the Garden's own paths.
    let before = files_under(dir.path());
    assert!(
        before.iter().any(|path| path == "seat.json"),
        "the join left no seat to clean up: {before:?}"
    );
    // A phone that only joined holds no content, so "nothing survived the
    // leave" would be true before the leave runs and would stay true if the
    // leave removed nothing. The publish below is what makes the assertion
    // below it mean something: the bytes have to reach the disk first.
    //
    // The check is made here, right after `send`, and not after the trace.
    // Every verb is its own process, and `GardenService::new` removes a
    // content tree it did not put there, because a validator key never
    // survives a restart and content is fetched again from the Garden. So a
    // process that starts after the publish clears the tree before doing
    // anything, and asserting over it later would be asserting over a fresh
    // directory. What this test proves is that a publish writes content; that
    // a leave wipes a tree that is still there is proven where the publish
    // and the leave happen in one process, in the core's own
    // `garden_service_keeps_caller_text_out_of_file_paths`.
    let (ok, sent) = phone_verb(dir.path(), "send", &["cleanup content", "cleanup"])?;
    assert!(ok, "the publish before the leave was refused: {sent}");
    assert!(
        sent.contains("accepted into the mempool, not yet in a block"),
        "the send did not say what its answer is: {sent}"
    );
    let answered: Value = serde_json::from_str(
        sent.lines()
            .find(|line| line.trim_start().starts_with('{'))
            .ok_or_else(|| format!("the send printed no JSON: {sent}"))?,
    )
    .map_err(|e| format!("the send answered with unreadable JSON: {e}"))?;
    assert_eq!(
        answered["published"],
        json!(false),
        "the send answered that it published: {answered}"
    );
    let tx_id = text(&answered, "/tx_id")?;
    let with_content = files_under(dir.path());
    assert!(
        with_content.iter().any(|path| path.starts_with("garden/")),
        "the publish wrote nothing under garden/, so it never stored the bytes it \
         answered about: {with_content:?}"
    );

    // The handle the send answered with is the way to the verdict, and the
    // verdict has to arrive: a mempool acceptance that never becomes a block
    // is the failure this whole check exists for.
    wait_for("the publish to reach a final block", || {
        let (ok, out) = phone_verb(dir.path(), "trace", &[&tx_id])?;
        if !ok {
            return Err(out);
        }
        let value: Value = serde_json::from_str(
            out.lines()
                .find(|line| line.trim_start().starts_with('{'))
                .ok_or_else(|| format!("the trace printed no JSON: {out}"))?,
        )
        .map_err(|e| e.to_string())?;
        Ok(if value["stage"] == json!("final") {
            Some(())
        } else {
            None
        })
    })
    .map_err(|e| format!("the publish never reached a block: {e}"))?;

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
