//! Every `budlum-ee-*` worker binary must build with `panic = "unwind"`, while
//! the node binary builds with `panic = "abort"`.
//!
//! # Why both profiles are pinned in opposite directions
//!
//! In the node process (`Cargo.toml`), `panic = "abort"` and
//! `overflow-checks = true` close silent wrapping and unwinding gadgets inside
//! consensus and networking.
//!
//! An execution-environment worker (`execution/*`, `budlum-ee-*`) runs third-party
//! guest bytecode inside a third-party engine in a separate OS process. When an
//! engine hits an internal invariant panic on a deterministic input, every honest
//! validator hits the same panic. Under `panic = "abort"`, `catch_unwind` in
//! `budlum_uel_abi::transport::serve_connection` is compiled into a no-op and the
//! worker dies with `SIGABRT`, looking indistinguishable from an out-of-memory
//! kill (`BLG-250`). Under `panic = "unwind"`, `serve_connection` catches the
//! unwind, hashes the domain-separated message into `EeFault`, transmits a
//! deterministic fault receipt over the socket, and exits cleanly so the
//! coordinator charges `gas_limit` and restarts the worker.
//!
//! This gate checks both halves together:
//! 1. Root `Cargo.toml` pins `[profile.release]` `panic = "abort"`.
//! 2. `execution/Cargo.toml` declares a `[workspace]` with at least one member
//!    and pins `[profile.release]` `panic = "unwind"` and `overflow-checks = true`.
//! 3. Every member listed in `execution/Cargo.toml` exists on disk, declares a
//!    `budlum-ee-*` package or `[[bin]]` target, and never overrides `[profile.*]`
//!    back to `panic = "abort"`.

use std::fs;
use std::path::{Path, PathBuf};

/// Checks a root `Cargo.toml` text for `[profile.release] panic = "abort"`.
fn check_node_manifest(manifest: &str) -> Result<(), String> {
    let doc: toml::Value = toml::from_str(manifest)
        .map_err(|e| format!("root Cargo.toml is not valid TOML: {e}"))?;
    let panic_val = doc
        .get("profile")
        .and_then(|p| p.get("release"))
        .and_then(|r| r.get("panic"))
        .and_then(toml::Value::as_str);
    match panic_val {
        Some("abort") => Ok(()),
        Some(other) => Err(format!(
            "root Cargo.toml pins [profile.release] panic = \"{other}\"; \
             the node binary must keep panic = \"abort\"."
        )),
        None => Err(String::from(
            "root Cargo.toml does not pin [profile.release] panic = \"abort\".",
        )),
    }
}

/// Checks `execution/Cargo.toml` and returns its declared workspace member paths.
fn check_execution_workspace(manifest: &str) -> Result<Vec<String>, String> {
    let doc: toml::Value = toml::from_str(manifest)
        .map_err(|e| format!("execution/Cargo.toml is not valid TOML: {e}"))?;
    let members_arr = doc
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            String::from("execution/Cargo.toml must declare [workspace] members = [...].")
        })?;
    let mut members = Vec::with_capacity(members_arr.len());
    for item in members_arr {
        let s = item.as_str().ok_or_else(|| {
            String::from("execution/Cargo.toml [workspace].members entries must be strings.")
        })?;
        members.push(s.to_string());
    }
    if members.is_empty() {
        return Err(String::from(
            "execution/Cargo.toml [workspace].members is empty; at least one worker is required.",
        ));
    }

    let release = doc
        .get("profile")
        .and_then(|p| p.get("release"))
        .ok_or_else(|| {
            String::from("execution/Cargo.toml carries no [profile.release] table.")
        })?;
    match release.get("panic").and_then(toml::Value::as_str) {
        Some("unwind") => {}
        Some(other) => {
            return Err(format!(
                "execution/Cargo.toml pins [profile.release] panic = \"{other}\"; \
                 EE workers require panic = \"unwind\" so catch_unwind produces EeFault receipts."
            ));
        }
        None => {
            return Err(String::from(
                "execution/Cargo.toml must pin [profile.release] panic = \"unwind\".",
            ));
        }
    }
    if release.get("overflow-checks").and_then(toml::Value::as_bool) != Some(true) {
        return Err(String::from(
            "execution/Cargo.toml must pin [profile.release] overflow-checks = true.",
        ));
    }
    Ok(members)
}

/// Checks one member `execution/<member>/Cargo.toml` for a `budlum-ee-*` target
/// and ensures no profile table overrides `panic` away from `"unwind"`.
fn check_worker_member(member_rel: &str, manifest: &str) -> Result<String, String> {
    let doc: toml::Value = toml::from_str(manifest)
        .map_err(|e| format!("execution/{member_rel}/Cargo.toml is invalid TOML: {e}"))?;

    if let Some(profiles) = doc.get("profile").and_then(toml::Value::as_table) {
        for (prof_name, table) in profiles {
            if let Some(p) = table.get("panic").and_then(toml::Value::as_str) {
                if p != "unwind" {
                    return Err(format!(
                        "execution/{member_rel}/Cargo.toml overrides [profile.{prof_name}] \
                         panic = \"{p}\"; worker crates must keep panic = \"unwind\"."
                    ));
                }
            }
        }
    }

    let pkg_name = doc
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    let bin_names: Vec<&str> = doc
        .get("bin")
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| b.get("name").and_then(toml::Value::as_str))
                .collect()
        })
        .unwrap_or_default();

    let worker_bin = bin_names
        .iter()
        .copied()
        .find(|n| n.starts_with("budlum-ee-"))
        .or_else(|| pkg_name.starts_with("budlum-ee-").then_some(pkg_name));

    let Some(found) = worker_bin else {
        return Err(format!(
            "execution/{member_rel}/Cargo.toml declares no `budlum-ee-*` package or [[bin]] target."
        ));
    };
    Ok(found.to_string())
}

/// Runs the gate against the repository at `root`.
///
/// # Errors
///
/// Returns `Err` when either root `Cargo.toml` or `execution/Cargo.toml` is
/// missing or mispins `panic`, or when a declared worker member is absent or
/// overrides `panic` away from `"unwind"`.
pub fn run(root: &Path) -> Result<String, String> {
    let node_toml = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("cannot read root Cargo.toml: {e}"))?;
    check_node_manifest(&node_toml)?;

    let exec_manifest_path = root.join("execution/Cargo.toml");
    let exec_toml = fs::read_to_string(&exec_manifest_path)
        .map_err(|e| format!("cannot read execution/Cargo.toml: {e}"))?;
    let members = check_execution_workspace(&exec_toml)?;

    let mut verified_bins = Vec::with_capacity(members.len());
    for member in &members {
        let member_toml_path = root.join("execution").join(member).join("Cargo.toml");
        let member_toml = fs::read_to_string(&member_toml_path)
            .map_err(|e| format!("cannot read execution/{member}/Cargo.toml: {e}"))?;
        let bin_name = check_worker_member(member, &member_toml)?;
        verified_bins.push(bin_name);
    }

    Ok(format!(
        "EE worker unwind profile held: node = abort; {} worker(s) ({}) = unwind.",
        verified_bins.len(),
        verified_bins.join(", ")
    ))
}

fn staged_dir() -> Result<PathBuf, String> {
    crate::gates::rust_literals::exclusive_scratch_dir("ee-workers-build-with-unwind")
}

/// Staged-copy self-test exercising passing and tampered manifests.
///
/// # Errors
///
/// Returns `Err` if the valid layout fails or any tampered layout passes.
pub fn self_test() -> Result<String, String> {
    let tmp = staged_dir()?;
    let exec_dir = tmp.join("execution");
    let mock_dir = exec_dir.join("mock");
    fs::create_dir_all(&mock_dir).map_err(|e| format!("cannot create scratch dirs: {e}"))?;

    let good_node = "[package]\nname = \"budlum-core\"\nversion = \"0.1.0\"\n\n\
                     [profile.release]\noverflow-checks = true\npanic = \"abort\"\n";
    let good_exec = "[workspace]\nmembers = [\"mock\"]\nresolver = \"2\"\n\n\
                     [profile.release]\noverflow-checks = true\npanic = \"unwind\"\n";
    let good_mock = "[package]\nname = \"budlum-ee-mock\"\nversion = \"0.1.0\"\n\n\
                     [[bin]]\nname = \"budlum-ee-mock\"\npath = \"src/main.rs\"\n";

    fs::write(tmp.join("Cargo.toml"), good_node).map_err(|e| e.to_string())?;
    fs::write(exec_dir.join("Cargo.toml"), good_exec).map_err(|e| e.to_string())?;
    fs::write(mock_dir.join("Cargo.toml"), good_mock).map_err(|e| e.to_string())?;

    if let Err(e) = run(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("canary: valid node+worker layout must pass, got: {e}"));
    }

    // Tamper 1: node binary set to unwind must fail.
    let bad_node = good_node.replace("panic = \"abort\"", "panic = \"unwind\"");
    if check_node_manifest(&bad_node).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from("canary: node panic = \"unwind\" must be refused"));
    }

    // Tamper 2: execution workspace set to abort must fail.
    let bad_exec = good_exec.replace("panic = \"unwind\"", "panic = \"abort\"");
    if check_execution_workspace(&bad_exec).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: execution workspace panic = \"abort\" must be refused",
        ));
    }

    // Tamper 3: execution workspace without overflow-checks must fail.
    let no_overflow = good_exec.replace("overflow-checks = true\n", "");
    if check_execution_workspace(&no_overflow).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: execution workspace missing overflow-checks must be refused",
        ));
    }

    // Tamper 4: member overriding panic = "abort" must fail.
    let bad_member = format!("{good_mock}\n[profile.release]\npanic = \"abort\"\n");
    if check_worker_member("mock", &bad_member).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: member overriding panic = \"abort\" must be refused",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Self-test OK: node abort + worker unwind verified; tampered profiles refused.",
    ))
}

#[cfg(test)]
mod tests {
    use super::{check_execution_workspace, check_node_manifest, check_worker_member, self_test};

    #[test]
    fn canary_suite_passes() {
        assert!(self_test().is_ok());
    }

    #[test]
    fn empty_workspace_members_refused() {
        let empty = "[workspace]\nmembers = []\n[profile.release]\n\
                     overflow-checks = true\npanic = \"unwind\"\n";
        assert!(check_execution_workspace(empty).is_err());
        assert!(check_node_manifest("[package]\nname = \"x\"\n").is_err());
        assert!(check_worker_member("x", "[package]\nname = \"not-a-worker\"\n").is_err());
    }
}
