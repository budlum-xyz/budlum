//! The Docker smoke test for the node image.
//!
//! It replaces `ops/scripts/docker-smoke-mainnet.sh`. Two halves, asserting
//! two different things:
//!
//! 1. Mainnet refuses. The image carries no mainnet configuration: no
//!    bootnodes, no genesis file, no HSM signer. Started with `--network
//!    mainnet` it must exit non-zero with a `CRITICAL SECURITY FAILURE` line
//!    and never answer RPC.
//! 2. Devnet boots. The same image started with `--network devnet` must answer
//!    `bud_chainId` with the devnet id and serve a genesis block whose hash is
//!    the pinned devnet genesis. Any other chain id or hash fails: a fallback
//!    that answers is not a pass, it is a different network.
//!
//! The genesis pin is the devnet genesis built from `devnet_genesis()`. When
//! that genesis changes on purpose, the new hash goes into
//! [`DEVNET_GENESIS_HASH`] in the same change. The test
//! `devnet_genesis_hash_matches_the_docker_smoke_pin` in the main crate fails
//! first and prints the new value.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::json::{self, Value};
use crate::rpc;

const IMAGE_NAME: &str = "budlum-mainnet-smoke";
const MAINNET_CONTAINER: &str = "budlum-smoke-mainnet";
const DEVNET_CONTAINER: &str = "budlum-smoke-devnet";
const RPC_PORT: u16 = 8545;
pub const DEVNET_CHAIN_ID: &str = "0xb0ce";
pub const DEVNET_GENESIS_HASH: &str =
    "0x87d93624975213bbdf7879ba8af973935e21f52d3436cc736b8df586774879ba";
const WAIT_SECONDS: u32 = 60;
const REFUSAL_MARKER: &str = "CRITICAL SECURITY FAILURE";

/// Run the smoke test. The containers are removed on every exit path, and
/// their logs are printed first when the run failed.
///
/// # Errors
///
/// The first failed assertion.
pub fn run(root: &Path) -> Result<String, String> {
    let result = steps(root);
    cleanup(result.is_err());
    result
}

fn docker_ok(args: &[&str], root: &Path) -> bool {
    Command::new("docker")
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn cleanup(failed: bool) {
    if failed {
        for c in [MAINNET_CONTAINER, DEVNET_CONTAINER] {
            if docker_ok(&["inspect", c], Path::new(".")) {
                eprintln!("[docker-smoke] --- logs of {c} ---");
                if let Ok(out) = Command::new("docker")
                    .args(["logs", "--tail", "80", c])
                    .output()
                {
                    eprint!("{}", String::from_utf8_lossy(&out.stdout));
                    eprint!("{}", String::from_utf8_lossy(&out.stderr));
                }
            }
        }
    }
    println!("[docker-smoke] Cleaning up containers...");
    let _ = docker_ok(
        &["rm", "-f", MAINNET_CONTAINER, DEVNET_CONTAINER],
        Path::new("."),
    );
}

fn steps(root: &Path) -> Result<String, String> {
    println!("[docker-smoke] Building Docker image: {IMAGE_NAME}");
    crate::run_checked(
        "docker",
        &["build", "-t", IMAGE_NAME, "-f", "ops/Dockerfile", "."],
        root,
    )?;

    mainnet_refuses(root)?;
    devnet_boots(root)
}

/// Half one: an unconfigured mainnet must refuse to start.
fn mainnet_refuses(root: &Path) -> Result<(), String> {
    println!("[docker-smoke] Starting {MAINNET_CONTAINER} with --network mainnet (must refuse)");
    let port = RPC_PORT.to_string();
    crate::run_checked(
        "docker",
        &[
            "run",
            "-d",
            "--name",
            MAINNET_CONTAINER,
            IMAGE_NAME,
            "--network",
            "mainnet",
            "--port",
            &port,
        ],
        root,
    )?;
    let exit = wait_for_exit(MAINNET_CONTAINER, Duration::from_mins(1));
    // The log is captured once, whole, so there is no pipe to break.
    let log = Command::new("docker")
        .args(["logs", MAINNET_CONTAINER])
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default();
    let refusal = judge_mainnet(&exit, &log)?;
    println!("[docker-smoke] OK: mainnet refused to start without a configuration (exit {exit}):");
    println!("[docker-smoke]   {refusal}");
    Ok(())
}

/// `timeout 60 docker wait NAME || echo running`: the exit code text, or
/// `running` when the container is still up after the budget or the wait
/// itself failed.
fn wait_for_exit(container: &str, budget: Duration) -> String {
    let Ok(mut child) = Command::new("docker")
        .args(["wait", container])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return "running".to_string();
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut out, &mut text);
                }
                return if status.success() {
                    text.trim().to_string()
                } else {
                    "running".to_string()
                };
            }
            Ok(None) if start.elapsed() < budget => {
                std::thread::sleep(Duration::from_millis(200));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return "running".to_string();
            }
        }
    }
}

/// Decide whether the mainnet container behaved. Returns the refusal line.
///
/// # Errors
///
/// If the container is still running, exited 0, or exited without the
/// `CRITICAL SECURITY FAILURE` line.
pub fn judge_mainnet(exit: &str, log: &str) -> Result<String, String> {
    if exit == "running" {
        return Err(
            "the mainnet container is still running after 60s; mainnet must refuse to start \
             without bootnodes, a genesis file and an HSM signer."
                .to_string(),
        );
    }
    if exit == "0" {
        return Err("the mainnet container exited 0; a refusal exits non-zero.".to_string());
    }
    log.lines()
        .find(|l| l.contains(REFUSAL_MARKER))
        .map(str::to_string)
        .ok_or_else(|| {
            format!("the mainnet container exited {exit} without a {REFUSAL_MARKER} line.")
        })
}

/// Half two: devnet must boot and identify itself.
fn devnet_boots(root: &Path) -> Result<String, String> {
    println!("[docker-smoke] Starting {DEVNET_CONTAINER} with --network devnet");
    let publish = format!("127.0.0.1:{RPC_PORT}:{RPC_PORT}");
    let listener = format!("0.0.0.0:{RPC_PORT}");
    crate::run_checked(
        "docker",
        &[
            "run",
            "-d",
            "--name",
            DEVNET_CONTAINER,
            "-p",
            &publish,
            "-e",
            "BUDLUM_RPC_AUTH_REQUIRED=0",
            "-e",
            "BUDLUM_RPC_ALLOWED_IPS=",
            IMAGE_NAME,
            "--network",
            "devnet",
            "--port",
            "0",
            "--rpc-public-listener",
            &listener,
        ],
        root,
    )?;

    println!("[docker-smoke] Waiting for devnet RPC (max {WAIT_SECONDS}s)...");
    let mut body = None;
    for attempt in 1..=WAIT_SECONDS {
        if let Ok(reply) = bounded_call("bud_chainId", "[]") {
            body = Some(reply);
            break;
        }
        if !container_running(DEVNET_CONTAINER) {
            return Err("the devnet container exited before answering RPC.".to_string());
        }
        if attempt == WAIT_SECONDS {
            return Err("timeout waiting for the devnet RPC.".to_string());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let chain_body = body.ok_or_else(|| "no RPC reply".to_string())?;

    let chain_id = jq_string(&chain_body, &["result"]);
    println!("[docker-smoke] Chain ID: {chain_id}");
    check_chain_id(&chain_id)?;

    let block_body = bounded_call("bud_getBlockByNumber", "[0]")
        .map_err(|e| format!("bud_getBlockByNumber [0] failed: {e}"))?;
    let hash = jq_string(&block_body, &["result", "hash"]);
    let number = jq_string(&block_body, &["result", "number"]);
    println!("[docker-smoke] Genesis block {number} hash: {hash}");
    check_genesis(&number, &hash)?;

    Ok(format!(
        "[docker-smoke] SUCCESS: the image refuses an unconfigured mainnet and boots devnet \
         ({DEVNET_CHAIN_ID}, genesis {DEVNET_GENESIS_HASH})."
    ))
}

/// Each request is bounded: a listener that accepts the connection but never
/// finishes the response must not block past the polling budget.
fn bounded_call(method: &str, params: &str) -> Result<String, String> {
    rpc::call(RPC_PORT, method, params, Duration::from_secs(5))
}

fn container_running(container: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", container])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
}

/// `jq -r` over a path of object keys: the string, or the text `null` when
/// the path is missing. A non-string value is printed as its JSON kind would
/// be by `jq`, which no check here can match anyway.
#[must_use]
pub fn jq_string(body: &str, path: &[&str]) -> String {
    let Ok(mut value) = json::parse(body) else {
        return "null".to_string();
    };
    for key in path {
        match value.get(key) {
            Some(next) => value = next.clone(),
            None => return "null".to_string(),
        }
    }
    match value {
        Value::String(s) => s,
        Value::Number(n) => n,
        Value::Bool(b) => b.to_string(),
        _ => "null".to_string(),
    }
}

/// The chain id must be the devnet one.
///
/// # Errors
///
/// If it is anything else.
pub fn check_chain_id(chain_id: &str) -> Result<(), String> {
    if chain_id == DEVNET_CHAIN_ID {
        Ok(())
    } else {
        Err(format!(
            "expected the devnet chain id {DEVNET_CHAIN_ID}, got {chain_id}."
        ))
    }
}

/// Block 0 must be number `0x0` with the pinned hash.
///
/// # Errors
///
/// If the number or the hash differs.
pub fn check_genesis(number: &str, hash: &str) -> Result<(), String> {
    if number != "0x0" {
        return Err(format!("block 0 reported number {number}."));
    }
    if hash != DEVNET_GENESIS_HASH {
        return Err(format!(
            "expected the pinned devnet genesis {DEVNET_GENESIS_HASH}, got {hash}.\n\
             If devnet_genesis() changed on purpose, update DEVNET_GENESIS_HASH in \
             xtask/tools/src/docker_smoke.rs in the same change."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_mainnet_container_fails() {
        let err = judge_mainnet("running", "").expect_err("must fail");
        assert!(err.contains("still running"));
    }

    #[test]
    fn a_clean_exit_is_not_a_refusal() {
        let err = judge_mainnet("0", "CRITICAL SECURITY FAILURE").expect_err("must fail");
        assert!(err.contains("exited 0"));
    }

    #[test]
    fn a_refusal_needs_the_marker_line() {
        let err = judge_mainnet("1", "some other crash\n").expect_err("must fail");
        assert!(err.contains("without a CRITICAL SECURITY FAILURE line"));
        let log = "boot\nCRITICAL SECURITY FAILURE: no bootnodes\nmore\nCRITICAL SECURITY FAILURE: second\n";
        assert_eq!(
            judge_mainnet("1", log).expect("refused"),
            "CRITICAL SECURITY FAILURE: no bootnodes"
        );
    }

    #[test]
    fn the_chain_id_must_be_the_devnet_one() {
        assert!(check_chain_id("0xb0ce").is_ok());
        assert!(check_chain_id("0x1").is_err());
        assert!(check_chain_id("null").is_err());
    }

    #[test]
    fn genesis_needs_number_zero_and_the_pinned_hash() {
        assert!(check_genesis("0x0", DEVNET_GENESIS_HASH).is_ok());
        assert!(check_genesis("0x1", DEVNET_GENESIS_HASH).is_err());
        let err = check_genesis("0x0", "0xdead").expect_err("wrong hash");
        assert!(err.contains("0xdead") && err.contains("DEVNET_GENESIS_HASH"));
    }

    #[test]
    fn jq_string_follows_a_path() {
        let body = r#"{"jsonrpc":"2.0","result":{"hash":"0xab","number":"0x0"},"id":1}"#;
        assert_eq!(jq_string(body, &["result", "hash"]), "0xab");
        assert_eq!(jq_string(body, &["result", "number"]), "0x0");
        assert_eq!(jq_string(body, &["result", "missing"]), "null");
        assert_eq!(jq_string("not json", &["result"]), "null");
        assert_eq!(jq_string(r#"{"result":"0xb0ce"}"#, &["result"]), "0xb0ce");
    }

    #[test]
    fn the_pin_is_a_32_byte_hex_hash() {
        assert_eq!(DEVNET_GENESIS_HASH.len(), 66);
        assert!(DEVNET_GENESIS_HASH.starts_with("0x"));
        assert!(DEVNET_GENESIS_HASH[2..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));
    }
}
