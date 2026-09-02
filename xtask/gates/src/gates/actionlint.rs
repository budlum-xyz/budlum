//! actionlint workflow lint gate.
//!
//! Ported from `scripts/check-actionlint.sh`. Runs `actionlint` over every
//! workflow file and fails when it reports anything. The self-test proves the
//! gate can fail by linting a deliberately broken workflow.

use std::path::Path;

fn bin() -> String {
    std::env::var("ACTIONLINT_BIN").unwrap_or_else(|_| "actionlint".to_string())
}

/// # Errors
///
/// Returns actionlint's report when it finds problems, or when it cannot run.
pub fn run(root: &Path) -> Result<String, String> {
    let workflows = root.join(".github/workflows");
    let Ok(rd) = std::fs::read_dir(&workflows) else {
        return Err(format!("no workflow directory: {}", workflows.display()));
    };
    let mut files: Vec<String> = Vec::new();
    for e in rd.filter_map(Result::ok) {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext == "yml" || ext == "yaml" {
            files.push(p.to_string_lossy().into_owned());
        }
    }
    let out = std::process::Command::new(bin())
        .args(&files)
        .current_dir(root)
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(String::from("actionlint temiz.")),
        Ok(o) => Err(format!(
            "actionlint findings:\n{}",
            String::from_utf8_lossy(&o.stdout)
        )),
        Err(e) => Err(format!("actionlint did not run: {e}")),
    }
}

/// # Errors
///
/// Returns a finding when a deliberately broken workflow passes actionlint.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-actionlint-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let wf = dir.join("bad.yml");
    std::fs::write(
        &wf,
        "name: deliberately-broken\non: [pushh]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.no_such_field_xyz }}\"\n",
    )
    .map_err(|e| e.to_string())?;
    let out = std::process::Command::new(bin())
        .arg(&wf)
        .current_dir(&dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    match out {
        Ok(o) if o.status.success() => Err(String::from(
            "VACUOUS GATE: a broken workflow passed actionlint!",
        )),
        Ok(_) => Ok(String::from(
            "canary OK: the broken workflow was refused (the gate is not vacuous).",
        )),
        Err(e) => Err(format!("actionlint did not run: {e}")),
    }
}
