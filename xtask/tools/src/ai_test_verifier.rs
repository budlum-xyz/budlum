//! `ai-test-verifier`: the testnet AI verifier harness (
//!). It does not use the Lubot crate and runs no model.
//!
//! It reads `bud_aiOpenRequests` from a node and answers each open request
//! once through `bud ai-answer`, with a fixed test transform of the input
//! commitment as the output commitment. The answers are attestation only:
//! they prove the request, result, k-of-n agreement and fee paths work, not
//! that any inference happened.
//!
//! ```text
//! ai-test-verifier --port 8545 --key-file v.key [--password-file p] [--rounds N]
//! ```
//!
//! The wallet password comes from the file or `BUD_WALLET_PASSWORD`; the
//! tool never prints or stores it (K7).

use crate::json::{self, Value};
use crate::rpc;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// The test transform: every byte of the input commitment XOR `0xA5`. Any
/// fixed function serves; this one is visible to a reader of the chain.
#[must_use]
pub fn test_output(input_commitment_hex: &str) -> Option<String> {
    let text = input_commitment_hex.trim_start_matches("0x");
    if text.len() != 64 {
        return None;
    }
    let mut out = String::with_capacity(64);
    for i in 0..32 {
        let byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
        let _ = write!(out, "{:02x}", byte ^ 0xA5);
    }
    Some(out)
}

fn open_requests(port: u16) -> Result<Vec<(String, String)>, String> {
    let body = rpc::call(port, "bud_aiOpenRequests", "[]", Duration::from_secs(10))?;
    let doc = json::parse(&body)?;
    let list = doc
        .get("result")
        .and_then(Value::as_array)
        .ok_or("bud_aiOpenRequests returned no list")?;
    Ok(list
        .iter()
        .filter_map(|item| {
            Some((
                item.get("request_id")?.as_str()?.to_string(),
                item.get("input_commitment")?.as_str()?.to_string(),
            ))
        })
        .collect())
}

/// Run the harness.
///
/// # Errors
///
/// Bad arguments, an unreachable node, or a `bud` invocation that fails.
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    let mut port = 8545u16;
    let mut key_file = None;
    let mut password_file = None;
    let mut rounds = 1u32;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--port" => {
                port = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--port needs a number")?;
            }
            "--key-file" => key_file = it.next().copied(),
            "--password-file" => password_file = it.next().copied(),
            "--rounds" => {
                rounds = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--rounds needs a number")?;
            }
            other => return Err(format!("ai-test-verifier: unknown argument `{other}`")),
        }
    }
    let key_file = key_file.ok_or("ai-test-verifier: --key-file is required")?;
    let mut answered = BTreeSet::new();
    for round in 0..rounds {
        if round > 0 {
            std::thread::sleep(Duration::from_secs(5));
        }
        for (request_id, input) in open_requests(port)? {
            if answered.contains(&request_id) {
                continue;
            }
            let Some(output) = test_output(&input) else {
                continue;
            };
            let mut command = Command::new("cargo");
            command
                .current_dir(root)
                .args(["run", "-q", "--bin", "bud", "--", "--rpc-url"])
                .arg(format!("http://127.0.0.1:{port}"))
                .args(["ai-answer", "--key-file", key_file]);
            if let Some(file) = password_file {
                command.args(["--password-file", file]);
            }
            let status = command
                .args(["--request-id", &request_id, "--output-commitment", &output])
                .status()
                .map_err(|e| format!("cannot run bud: {e}"))?;
            if !status.success() {
                return Err(format!("bud ai-answer failed for {request_id}: {status}"));
            }
            answered.insert(request_id);
        }
    }
    Ok(format!(
        "ai-test-verifier: answered {} request(s), attestation only",
        answered.len()
    ))
}

/// The canary: the transform is total on 32-byte input and fixed.
///
/// # Errors
///
/// The first property that does not hold.
pub fn self_test() -> Result<String, String> {
    let zero = "00".repeat(32);
    if test_output(&zero).as_deref() != Some("a5".repeat(32).as_str()) {
        return Err("the test transform changed".into());
    }
    if test_output("abcd").is_some() {
        return Err("a short commitment was accepted".into());
    }
    Ok("ai-test-verifier: test transform fixed, short input refused".into())
}
