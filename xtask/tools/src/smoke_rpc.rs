//! The RPC smoke test.
//!
//! It replaces `ops/scripts/smoke_rpc.sh`. It starts a short-lived node and
//! probes the JSON-RPC method `bud_chainId` on the operator listener. That
//! listener is used on purpose: the smoke test then does not depend on the
//! public-RPC auth policy or the allow-list. It validates node boot, not
//! public exposure.
//!
//! Environment, all optional: `SMOKE_NETWORK` (default `devnet`),
//! `SMOKE_RPC_PORT` (default 18546, the operator listener),
//! `SMOKE_PUBLIC_RPC_PORT` (default 18545), `SMOKE_DB_PATH`, `SMOKE_BIN`,
//! `RUST_LOG` (default `warn`) and `BUDLUM_RPC_AUTH_REQUIRED` (default `0`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::support::{make_temp_dir, tail_lines};
use crate::{has_program, rpc};

const TRIES: u32 = 60;
const POLL_PAUSE: Duration = Duration::from_millis(500);
const REQUEST_TIME: Duration = Duration::from_secs(5);

/// The settings of one run.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub network: String,
    pub rpc_port: u16,
    pub public_port: u16,
    pub db_path: Option<PathBuf>,
    pub bin: Option<PathBuf>,
}

impl Config {
    /// Read the settings from the environment.
    ///
    /// # Errors
    ///
    /// If a port is not a number.
    pub fn from_env() -> Result<Self, String> {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let port = |name: &str, default: u16| -> Result<u16, String> {
            get(name).map_or(Ok(default), |v| {
                v.parse()
                    .map_err(|_| format!("{name} is not a port: {v:?}"))
            })
        };
        let rpc_port = port("SMOKE_RPC_PORT", 18546)?;
        let public_port = port("SMOKE_PUBLIC_RPC_PORT", 18545)?;
        Ok(Self {
            network: get("SMOKE_NETWORK").unwrap_or_else(|| "devnet".to_string()),
            rpc_port,
            public_port,
            db_path: get("SMOKE_DB_PATH").map(PathBuf::from),
            bin: get("SMOKE_BIN").map(PathBuf::from),
        })
    }
}

/// The two listeners must never share a port, or the second bind fails with
/// `EADDRINUSE` and the probe loop times out. Returns the operator port to
/// use, and a note when it had to move.
///
/// # Errors
///
/// If the shifted port would not fit in a `u16`.
pub fn operator_port(rpc_port: u16, public_port: u16) -> Result<(u16, Option<String>), String> {
    if rpc_port != public_port {
        return Ok((rpc_port, None));
    }
    let shifted = public_port
        .checked_add(1)
        .ok_or_else(|| format!("no port above the public port {public_port}"))?;
    Ok((
        shifted,
        Some(format!(
            "operator port {rpc_port} equals public port {public_port}; shifting operator to {shifted}"
        )),
    ))
}

/// The node command line.
#[must_use]
pub fn node_args(cfg: &Config, operator: u16, db: &Path) -> Vec<String> {
    vec![
        "--network".to_string(),
        cfg.network.clone(),
        "--port".to_string(),
        "0".to_string(),
        "--rpc-public-listener".to_string(),
        format!("127.0.0.1:{}", cfg.public_port),
        "--rpc-operator-listener".to_string(),
        format!("127.0.0.1:{operator}"),
        "--db-path".to_string(),
        db.join("chain").display().to_string(),
        "--snapshot-dir".to_string(),
        db.join("snapshots").display().to_string(),
        "--p2p-identity-file".to_string(),
        db.join("secrets/node-id.key").display().to_string(),
    ]
}

/// A reply passes when it carries a `"result"` member. This is the same
/// substring test the shell version made.
#[must_use]
pub fn reply_has_result(body: &str) -> bool {
    body.contains("\"result\"")
}

/// Kills and reaps the node when the run ends, however it ends.
struct NodeGuard(Child);

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run the smoke test.
///
/// # Errors
///
/// If no binary can be found or built, the node cannot start or exits early,
/// the RPC never answers, or the answer has no result.
pub fn run(root: &Path, cfg: &Config) -> Result<String, String> {
    let (operator, note) = operator_port(cfg.rpc_port, cfg.public_port)?;
    if let Some(note) = note {
        eprintln!("[smoke] {note}");
    }
    let db = match &cfg.db_path {
        Some(p) => p.clone(),
        None => make_temp_dir("budlum-smoke-db")?,
    };
    let bin = match &cfg.bin {
        Some(b) => b.clone(),
        None => find_binary(root)?,
    };

    reset_dir(&db)?;
    std::fs::create_dir_all(db.join("secrets"))
        .map_err(|e| format!("{} could not be created: {e}", db.display()))?;
    let log_path = db.join("node.log");
    let log = std::fs::File::create(&log_path)
        .map_err(|e| format!("{} could not be created: {e}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("could not share the log file: {e}"))?;

    let args = node_args(cfg, operator, &db);
    println!("[smoke] starting {} {}", bin.display(), args.join(" "));
    let env_or = |name: &str, default: &str| {
        std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| default.to_string())
    };
    let rust_log = env_or("RUST_LOG", "warn");
    let auth = env_or("BUDLUM_RPC_AUTH_REQUIRED", "0");
    let child = Command::new(&bin)
        .args(&args)
        .env("RUST_LOG", rust_log)
        .env("BUDLUM_RPC_AUTH_REQUIRED", auth)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("{} could not be started: {e}", bin.display()))?;
    let mut guard = NodeGuard(child);

    let mut body = None;
    for attempt in 1..=TRIES {
        if let Ok(reply) = rpc::call(operator, "bud_chainId", "[]", REQUEST_TIME) {
            body = Some(reply);
            break;
        }
        std::thread::sleep(POLL_PAUSE);
        if matches!(guard.0.try_wait(), Ok(Some(_))) {
            return Err(format!("node exited early; log:\n{}", log_tail(&log_path)));
        }
        if attempt == TRIES {
            return Err(format!(
                "timeout waiting for RPC; log:\n{}",
                log_tail(&log_path)
            ));
        }
    }
    let body = body.ok_or_else(|| "no RPC reply".to_string())?;

    println!("[smoke] RPC response: {body}");
    if !reply_has_result(&body) {
        return Err("the reply carries no \"result\"".to_string());
    }
    Ok(format!(
        "[smoke] OK - bud_chainId responded on {}",
        cfg.network
    ))
}

fn log_tail(path: &Path) -> String {
    std::fs::read_to_string(path).map_or_else(|_| String::new(), |t| tail_lines(&t, 80))
}

/// `rm -rf` then `mkdir -p`, with a guard the shell version lacked: an empty
/// or root path is refused, because `rm -rf ""` style slips are exactly what
/// this crate exists to prevent.
fn reset_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.parent().is_none() {
        return Err(format!("refusing to wipe {:?}", path.display().to_string()));
    }
    if path.exists() {
        std::fs::remove_dir_all(path)
            .map_err(|e| format!("{} could not be wiped: {e}", path.display()))?;
    }
    std::fs::create_dir_all(path)
        .map_err(|e| format!("{} could not be created: {e}", path.display()))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn docker_image_exists(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Pick the node binary: the debug build, the release build, the one inside
/// the `budlum-core:devnet` image, or a fresh debug build, in that order.
fn find_binary(root: &Path) -> Result<PathBuf, String> {
    let debug = root.join("target/debug/budlum-core");
    let release = root.join("target/release/budlum-core");
    if is_executable(&debug) {
        return Ok(debug);
    }
    if is_executable(&release) {
        return Ok(release);
    }
    if docker_image_exists("budlum-core:devnet") {
        // The docker-smoke workflow builds budlum-core:devnet with compose build.
        println!("[smoke] extracting binary from Docker image...");
        return extract_from_image(root);
    }
    if has_program("cargo") {
        println!("[smoke] building budlum-core (debug)...");
        crate::run_checked("cargo", &["build", "-q", "--bin", "budlum-core"], root)?;
        return Ok(debug);
    }
    Err("no budlum-core binary and no cargo".to_string())
}

fn extract_from_image(root: &Path) -> Result<PathBuf, String> {
    let out = Command::new("docker")
        .args(["create", "budlum-core:devnet"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("`docker create` could not be run: {e}"))?;
    if !out.status.success() {
        return Err("`docker create budlum-core:devnet` failed".to_string());
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let dir = make_temp_dir("budlum-smoke-bin")?;
    let bin = dir.join("budlum-core");
    let source = format!("{id}:/usr/local/bin/budlum-core");
    let copied = crate::run_checked("docker", &["cp", &source, &bin.display().to_string()], root);
    let _ = Command::new("docker")
        .args(["rm", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    copied?;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("{} could not be made executable: {e}", bin.display()))?;
    Ok(bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clash_of_ports_shifts_the_operator() {
        assert_eq!(operator_port(18546, 18545).expect("ok"), (18546, None));
        let (port, note) = operator_port(18545, 18545).expect("ok");
        assert_eq!(port, 18546);
        assert!(note.expect("a note").contains("shifting operator to 18546"));
        assert!(operator_port(65535, 65535).is_err());
    }

    #[test]
    fn the_node_command_line_has_every_flag() {
        let cfg = Config {
            network: "devnet".to_string(),
            rpc_port: 18546,
            public_port: 18545,
            db_path: None,
            bin: None,
        };
        let args = node_args(&cfg, 18546, Path::new("/tmp/db"));
        let line = args.join(" ");
        assert!(line.starts_with("--network devnet --port 0 "));
        assert!(line.contains("--rpc-public-listener 127.0.0.1:18545"));
        assert!(line.contains("--rpc-operator-listener 127.0.0.1:18546"));
        assert!(line.contains("--db-path /tmp/db/chain"));
        assert!(line.contains("--snapshot-dir /tmp/db/snapshots"));
        assert!(line.contains("--p2p-identity-file /tmp/db/secrets/node-id.key"));
    }

    #[test]
    fn a_reply_needs_a_result_member() {
        assert!(reply_has_result(
            r#"{"jsonrpc":"2.0","result":"0xb0ce","id":1}"#
        ));
        assert!(!reply_has_result(
            r#"{"jsonrpc":"2.0","error":{"code":-32601},"id":1}"#
        ));
    }

    #[test]
    fn the_wipe_refuses_an_empty_or_root_path() {
        assert!(reset_dir(Path::new("")).is_err());
        assert!(reset_dir(Path::new("/")).is_err());
    }

    #[test]
    fn the_wipe_recreates_a_directory() {
        let dir = make_temp_dir("budlum-smoke-test").expect("dir");
        std::fs::write(dir.join("old"), b"x").expect("file");
        reset_dir(&dir).expect("reset");
        assert!(dir.is_dir());
        assert!(!dir.join("old").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
