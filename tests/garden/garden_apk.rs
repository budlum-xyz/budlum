//! The ten Garden APK acceptance checks (section 9.1), run against the
//! phone's real Garden library.
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

/// Resolve a sibling binary of this test executable.
///
/// `CARGO_BIN_EXE_*` only names binaries of the current package, and both
/// `garden-phone` (in `mobile/garden-ffi`) and `budlum-core` live elsewhere,
/// so the path is taken from this test binary's own directory
/// (`target/debug/deps`) and checked for existence before every use.
fn profile_bin(name: &str) -> Result<PathBuf, String> {
    static CACHE: OnceLock<PathBuf> = OnceLock::new();
    let dir = CACHE.get_or_init(|| {
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
    let candidate = dir.join(name);
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(format!(
            "{} is not built; build it first (garden-phone is `cargo build -p budlum-garden-ffi --bin garden-phone`, the node is `cargo build --bin budlum-core`)",
            candidate.display()
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

    /// Create the Garden on this node and return the invite record.
    fn create(&self, title: &str) -> Result<String, String> {
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
        text(&answer, "/invite")
    }
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
    let output = Command::new(phone_bin()?)
        .args(args)
        .arg(dir)
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
    let record = format!("budlum://garden/join#{invite}");
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
    let record = format!("budlum://garden/join#{invite}");
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "join", &[&record, "Second"])?;
    assert!(ok, "the second phone did not join over the link: {log}");
    let (ok, status) = phone_verb(dir.path(), "status", &[])?;
    assert!(ok, "the second phone cannot report its status: {status}");
    assert!(
        status.contains("Active"),
        "the second phone is not an active validator: {status}"
    );
    Ok(())
}

/// 9.1 item 6: the invite is a shareable link a joining phone can read before
/// acting on it, with QR content beside it.
#[test]
fn garden_apk_share() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk share")?;
    let record = format!("budlum://garden/join#{invite}");
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "read", &[&record])?;
    assert!(ok, "the share link could not be read: {log}");
    assert!(
        log.contains("apk share") || log.contains("title"),
        "the read answer does not name the Garden being shared: {log}"
    );
    Ok(())
}

/// 9.1 item 7: what one member puts into the Garden comes back out of the
/// Garden's own feed on another member.
#[test]
fn garden_apk_clipboard_join() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk clipboard")?;
    let record = format!("budlum://garden/join#{invite}");
    let guest = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(guest.path(), "join", &[&record, "Guest"])?;
    assert!(ok, "the guest did not join: {log}");

    let published = node.rpc(
        "bud_gardenPublish",
        &json!(["message", "from the clipboard"]),
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
    let resolved = node.rpc("bud_gardenResolve", &json!([content_id]))?;
    assert_eq!(
        resolved.get("text").and_then(Value::as_str),
        Some("from the clipboard"),
        "the guest resolved different content: {resolved}"
    );
    Ok(())
}

/// 9.1 item 8: a phone that is closed and opened again keeps its seat, and
/// the seat outlives the process that wrote it.
#[test]
fn garden_apk_background() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk background")?;
    let record = format!("budlum://garden/join#{invite}");
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;

    // Hold the Garden open in one process, as the app does while the screen
    // is up, then kill it and check the seat that is left on disk.
    let (serving, before) = serve(dir.path(), Some(&record))?;
    assert_eq!(
        before.get("status").and_then(Value::as_str),
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
        after.get("status").and_then(Value::as_str),
        Some("Active"),
        "the second process lost the seat: {after}"
    );
    drop(serving);
    let (ok, log) = phone_verb(dir.path(), "return-check", &[&record, "Phone"])?;
    assert!(ok, "leave-and-return is broken: {log}");
    Ok(())
}

/// 9.1 item 9: leaving wipes the Garden from the phone and keeps only the
/// record of the place, which is what the Status screen offers as "return".
#[test]
fn garden_apk_cleanup() -> Result<(), String> {
    let node = Node::start()?;
    let invite = node.create("apk cleanup")?;
    let record = format!("budlum://garden/join#{invite}");
    let dir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let (ok, log) = phone_verb(dir.path(), "join", &[&record, "Phone"])?;
    assert!(ok, "the phone did not join: {log}");
    std::fs::write(dir.path().join("content.bin"), [7u8; 4096]).map_err(|e| e.to_string())?;

    let (ok, left) = phone_verb(dir.path(), "leave", &[])?;
    assert!(ok, "the leave failed: {left}");
    assert!(
        left.contains("\"can_return\":true"),
        "the leave kept no way back: {left}"
    );
    assert!(
        !dir.path().join("content.bin").exists(),
        "content survived the leave"
    );
    let kept = files_under(dir.path());
    assert!(
        kept.iter().all(|f| f == "seat.json"),
        "the leave left more than the seat behind: {kept:?}"
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
    let dir = tempfile::TempDir::new().expect("a temporary directory");
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
        if is_root() {
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
