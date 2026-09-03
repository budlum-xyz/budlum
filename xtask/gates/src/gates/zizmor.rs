//! zizmor GitHub Actions static security analysis gate.
//!
//! Ported from `scripts/check-zizmor.sh`. Runs `zizmor` over the workflow
//! tree and fails on any finding. `ZIZMOR_BIN` overrides the binary path;
//! without it the pinned version is downloaded (version + sha256 enforced),
//! mirroring the shell gate's pin policy.

use std::path::{Path, PathBuf};

const VERSION: &str = "1.27.0";
const SHA256: &str = "277f2bd8fd37cf60c42ab7afca6faa884e65440fa31e02b44bdaae60f62a358f";

/// Resolve the zizmor binary, downloading the pinned release when needed.
///
/// Fail-closed by construction (CWE-426): every failure - download,
/// checksum, extraction, missing binary - returns `Err`, never a bare
/// command name. A bare `zizmor` fallback would resolve through PATH, and
/// in `repo-lint` a malicious PR can place a fake `zizmor` in a writable
/// PATH directory, so executing from PATH would run attacker-controlled
/// code.
fn bin_path() -> Result<PathBuf, String> {
    if let Ok(b) = std::env::var("ZIZMOR_BIN") {
        return Ok(PathBuf::from(b));
    }
    // No unverified cache. This gate runs inside `repo-lint`, where earlier
    // steps execute PR-controlled Rust code from xtask/gates via `cargo run`;
    // a malicious PR could plant a binary at a fixed `/tmp/zizmor-<ver>`
    // path and have the gate execute it, bypassing the workflow-security
    // scan. Every run therefore downloads the pinned release and verifies
    // its sha256 before the binary is ever invoked (CWE-494).
    // A private directory, created exclusively for this run: a fixed
    // `/tmp/zizmor-<ver>.tar.gz` and a fixed `/tmp/zizmor` were paths
    // another process on the runner could write between the checksum and
    // the extraction, or between the extraction and the run (CWE-377).
    let work = private_work_dir()?;
    let tgz = work.join(format!("zizmor-{VERSION}.tar.gz"));
    let url = format!(
        "https://github.com/zizmorcore/zizmor/releases/download/v{VERSION}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
    );
    let ok = std::process::Command::new("curl")
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "--retry",
            "5",
            "--retry-all-errors",
            "--retry-delay",
            "2",
            "-sSfL",
            "-o",
        ])
        .arg(&tgz)
        .arg(&url)
        .status()
        .map_err(|e| format!("zizmor indirilemedi (curl): {e}"))?;
    if !ok.success() {
        return Err(String::from("zizmor indirilemedi (curl exit != 0)"));
    }
    // Verify the pinned sha256 before extracting; a tampered download is
    // refused the same way the shell gate refused it.
    let sum = std::process::Command::new("sha256sum")
        .arg(&tgz)
        .output()
        .map_err(|e| format!("zizmor sha256sum did not run: {e}"))?
        .stdout;
    let sum = String::from_utf8_lossy(&sum);
    if !sum.starts_with(SHA256) {
        return Err(format!(
            "the zizmor sha256 did not match (expected {SHA256}, got {}); the download was refused",
            sum.split_whitespace().next().unwrap_or("?")
        ));
    }
    let extract_ok = std::process::Command::new("tar")
        .args(["-xzf"])
        .arg(&tgz)
        .arg("-C")
        .arg(&work)
        .status()
        .map_err(|e| format!("zizmor could not be extracted (tar): {e}"))?
        .success();
    if !extract_ok {
        return Err(String::from(
            "zizmor could not be extracted (tar exit != 0)",
        ));
    }
    // The archive contains the binary at the root of the extract dir; look
    // for it next to the tgz, inside the directory only this run knows.
    let extracted = work.join("zizmor");
    if extracted.is_file() {
        return Ok(extracted);
    }
    Err(format!(
        "no binary was found in the zizmor archive: {}",
        extracted.display()
    ))
}

/// A fresh directory under the temp root that did not exist before this
/// call, owner-only on Unix. `create_dir` (not `create_dir_all`) fails if
/// the path already exists, so a pre-planted directory is refused rather
/// than reused.
fn private_work_dir() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-zizmor-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).map_err(|e| {
        format!(
            "cannot create a private work directory {}: {e}",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot restrict {}: {e}", dir.display()))?;
    }
    Ok(dir)
}

/// # Errors
///
/// Returns zizmor's findings when it reports any, or a bootstrap/run failure.
pub fn run(root: &Path) -> Result<String, String> {
    let bin = bin_path()?;
    let out = std::process::Command::new(&bin)
        .arg(".")
        .current_dir(root)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from("zizmor clean (0 findings).")),
        Ok(o) => Err(format!(
            "zizmor findings:\n{}",
            String::from_utf8_lossy(&o.stdout)
        )),
        Err(e) => Err(format!("zizmor did not run ({}): {e}", bin.display())),
    }
}

/// # Errors
///
/// Returns a finding when the gate cannot fail (zizmor unavailable or the
/// canary workflow passes).
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-zizmor-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let wf = dir.join("bad.yml");
    std::fs::write(
        &wf,
        "name: badan\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    .map_err(|e| e.to_string())?;
    let bin = bin_path()?;
    let out = std::process::Command::new(&bin)
        .arg(".")
        .current_dir(&dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) if o.status.success() => {
            Err(String::from("canary: zizmor ran but that is not evidence"))
        }
        Ok(_) => Ok(String::from(
            "canary OK: zizmor refused the broken/suspicious workflow.",
        )),
        Err(e) => Err(format!("zizmor did not run ({}): {e}", bin.display())),
    }
}
