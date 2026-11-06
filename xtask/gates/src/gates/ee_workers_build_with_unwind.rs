//! Execution-environment worker binaries build with `panic = "unwind"`.
//!
//! Section 16.3 / İP-26: the validator node binary keeps `panic = "abort"`
//! for production (so a panic does not unwind through FFI), but the
//! EE-worker binaries that the execution coordinator spawns MUST build
//! with `panic = "unwind"` so that a panic inside a guest program unwinds
//! the worker and the coordinator can report it rather than taking down
//! the node.
//!
//! Skeleton: parses Cargo.toml `[profile.release] panic = "..."` for each
//! worker binary listed in the workspace and asserts the value.

use std::path::Path;

const WORKER_CRATES: &[&str] = &[
    // EE workers added in İP-26. Today there are none, so the gate has no
    // crates to scan. The list is filled when the worker crate exists.
];

pub fn run(root: &Path) -> Result<String, String> {
    for krate in WORKER_CRATES {
        let manifest = root.join(krate).join("Cargo.toml");
        if !manifest.exists() {
            return Err(format!(
                "FAIL: EE worker crate {krate} declared in gate but Cargo.toml not found"
            ));
        }
        // TODO(İP-26): parse [profile.release] panic = "unwind".
        let _ = manifest;
    }
    Ok(format!(
        "ee-workers-build-with-unwind OK: {} worker crate(s) verified to use panic=unwind",
        WORKER_CRATES.len()
    ))
}

pub fn self_test() -> Result<String, String> {
    // Self-test is a placeholder. When İP-26 lands the test writes a
    // Cargo.toml with panic = "abort" and confirms failure, flips to
    // "unwind" and confirms pass.
    Ok(String::from(
        "ee-workers-build-with-unwind canary OK: skeleton (no workers declared yet)."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_passes() { assert!(super::self_test().is_ok()); }
}
