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
/// The resolved binary and, when this run downloaded it, the private
/// directory holding it. The directory is removed when the value drops, so
/// a run leaves nothing behind in the temp root: each run used to leave its
/// own copy of the archive and the binary there, and a runner that hosts
/// many gate runs filled its temp file system with them.
struct ZizmorBin {
    path: PathBuf,
    work: Option<PathBuf>,
}

impl Drop for ZizmorBin {
    fn drop(&mut self) {
        if let Some(work) = self.work.take() {
            let _ = std::fs::remove_dir_all(work);
        }
    }
}

fn bin_path() -> Result<ZizmorBin, String> {
    if let Ok(b) = std::env::var("ZIZMOR_BIN") {
        return Ok(ZizmorBin {
            path: PathBuf::from(b),
            work: None,
        });
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
    // Owned from here on: every early return below drops it, and with it
    // the directory, the archive and whatever was extracted.
    let owned = ZizmorBin {
        path: work.join("zizmor"),
        work: Some(work.clone()),
    };
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
    if owned.path.is_file() {
        return Ok(owned);
    }
    Err(format!(
        "no binary was found in the zizmor archive: {}",
        owned.path.display()
    ))
}

/// A fresh directory under the temp root that did not exist before this
/// call, owner-only on Unix. The exclusive create refuses a pre-planted
/// path rather than reusing it; the mode keeps the extracted binary from
/// being read or swapped by another local user before it runs.
fn private_work_dir() -> Result<PathBuf, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-zizmor")?;
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
    let out = std::process::Command::new(&bin.path)
        .arg(".")
        .current_dir(root)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from("zizmor clean (0 findings).")),
        Ok(o) => Err(format!(
            "zizmor findings:\n{}",
            String::from_utf8_lossy(&o.stdout)
        )),
        Err(e) => Err(format!("zizmor did not run ({}): {e}", bin.path.display())),
    }
}

/// # Errors
///
/// Returns a finding when the gate cannot fail (zizmor unavailable or the
/// canary workflow passes).
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-zizmor")?;
    // A workflow carrying a documented finding, at the path zizmor collects
    // from. The previous fixture was a harmless `run: echo hi` at the top of
    // the scratch directory: zizmor collected no inputs there, exited 3 with
    // "no audit was performed", and the non-zero status passed as a refusal.
    // The canary was proving that zizmor fails on nothing, not that it sees
    // anything. Now the fixture expands attacker-controlled event data
    // inside `run:`, and the audit's own identifier must appear in the
    // report, so an exit code from any other cause cannot stand in for it.
    let workflows = dir.join(".github/workflows");
    std::fs::create_dir_all(&workflows).map_err(|e| e.to_string())?;
    std::fs::write(
        workflows.join("bad.yml"),
        "name: bad\non:\n  pull_request_target:\njobs:\n  x:\n    runs-on: ubuntu-latest\n    \
         steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n",
    )
    .map_err(|e| e.to_string())?;
    let bin = bin_path()?;
    let out = std::process::Command::new(&bin.path)
        .arg(".")
        .current_dir(&dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let bin_shown = bin.path.display().to_string();
    let work = bin.work.clone();
    drop(bin);
    if let Some(work) = work {
        if work.exists() {
            return Err(format!(
                "canary: the private zizmor directory {} survived the run",
                work.display()
            ));
        }
    }
    match out {
        Ok(o) if o.status.success() => Err(String::from(
            "canary: zizmor passed a workflow that expands pull-request data into a shell",
        )),
        Ok(o) => {
            let report = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if report.contains("template-injection") {
                Ok(String::from(
                    "canary OK: zizmor reported template-injection on the injected workflow.",
                ))
            } else {
                Err(format!(
                    "canary: zizmor exited non-zero without the template-injection finding, \
                     so it did not audit the fixture:\n{report}"
                ))
            }
        }
        Err(e) => Err(format!("zizmor did not run ({bin_shown}): {e}")),
    }
}
