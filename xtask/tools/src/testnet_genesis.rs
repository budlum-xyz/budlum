//! `testnet-genesis`: the testnet genesis ceremony.
//!
//! The ceremony logic lives in the node crate
//! (`budlum_core::chain::genesis_ceremony`), the one place that builds and
//! checks a genesis. This tool runs it through the `bud` CLI, so the
//! coordinator has one command:
//!
//! ```text
//! cargo run --manifest-path xtask/tools/Cargo.toml -- testnet-genesis \
//!     --operators <dir of operator records> \
//!     --community <faucet account> --liquidity <addr> --ecosystem <addr> \
//!     --team <addr> --burn-reserve <addr> \
//!     --out config/testnet-genesis.json
//! ```
//!
//! Each operator writes its record with `bud validator init`; the records
//! hold public keys only. The tool prints the genesis hash every operator
//! compares before starting its node.

use std::path::Path;
use std::process::Command;

/// The arguments the tool fixes itself and refuses from the caller.
fn check_args(args: &[&str]) -> Result<(), String> {
    if args.contains(&"--network") {
        return Err("testnet-genesis fixes --network testnet; drop the flag".into());
    }
    if !args.contains(&"--operators") || !args.contains(&"--out") {
        return Err(
            "usage: testnet-genesis --operators <dir> --community <faucet> --liquidity <addr> \
             --ecosystem <addr> --team <addr> --burn-reserve <addr> --out <file>"
                .into(),
        );
    }
    Ok(())
}

/// Assemble and check the testnet genesis.
///
/// # Errors
///
/// A refused argument list, a `cargo` that cannot start, or the ceremony's
/// own refusal (printed by `bud`).
pub fn run(root: &Path, args: &[&str]) -> Result<String, String> {
    check_args(args)?;
    let status = Command::new("cargo")
        .current_dir(root)
        .args([
            "run",
            "--quiet",
            "--release",
            "--bin",
            "bud",
            "--",
            "genesis",
            "assemble",
            "--network",
            "testnet",
        ])
        .args(args)
        .status()
        .map_err(|e| format!("cargo could not start: {e}"))?;
    if status.success() {
        Ok(String::from(
            "testnet genesis assembled and checked; publish the file and the hash above",
        ))
    } else {
        Err(format!("bud genesis assemble exited with {status}"))
    }
}

/// The argument check refuses what it must and passes a full list.
///
/// # Errors
///
/// When a refused or a complete argument list is judged wrongly.
pub fn self_test() -> Result<String, String> {
    if check_args(&["--operators", "d", "--out", "f", "--network", "mainnet"]).is_ok() {
        return Err("a caller-chosen network passed".into());
    }
    if check_args(&["--operators", "d"]).is_ok() {
        return Err("a list without --out passed".into());
    }
    check_args(&["--operators", "d", "--out", "f"])?;
    Ok(String::from(
        "testnet-genesis canary OK: the network is fixed and the required flags are checked.",
    ))
}
