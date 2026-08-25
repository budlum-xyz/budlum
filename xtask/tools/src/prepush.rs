//! Local verification before a push.
//!
//! Replaces `scripts/pre-push-check.sh`.
//!
//! # Two problems with the shell version
//!
//! 1. Under `set -e` the first error stopped the script, so when `cargo fmt`
//!    fell clippy **never ran**. The developer fixed one error,
//!    ran again, saw the second, ran again. Here
//!    every check runs and all of them are reported at once.
//! 2. The script did not say which toolchain it ran with. `rust-toolchain.toml`
//!    pins 1.97.1 but the developer's default may be another; then
//!    the local `cargo fmt` passes and CI comes back red. This is the
//!    "toolchain drift" class recorded in past notes. Here the version is printed first.

use std::path::Path;

use crate::{run_capturing_status, run_checked};

/// The result of one check.
struct Outcome {
    name: &'static str,
    code: i32,
}

/// Push oncesi kontrolleri kosur.
///
/// `cargo fmt --check` ve `cargo clippy -D warnings`. Ikisi de kosar; ilki
/// dustu diye ikincisi atlanmaz.
///
/// # Errors
///
/// When a check fails, an error saying which ones failed.
pub fn run(root: &Path) -> Result<String, String> {
    let mut lines = Vec::new();

    // Toolchain first: if local and CI differ, fmt/clippy decide differently
    // and that was seen in the past as green locally plus red in CI.
    match std::process::Command::new("cargo")
        .arg("--version")
        .current_dir(root)
        .output()
    {
        Ok(out) => lines.push(format!(
            "toolchain: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        )),
        Err(e) => return Err(format!("`cargo` bulunamadi: {e}")),
    }

    let checks = [
        (
            "cargo fmt --all -- --check",
            vec!["fmt", "--all", "--", "--check"],
        ),
        (
            "cargo clippy --all-targets --all-features -- -D warnings",
            vec![
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ];

    let mut outcomes: Vec<Outcome> = Vec::new();
    for (label, args) in checks {
        lines.push(format!("--- {label}"));
        let code = run_capturing_status("cargo", &args, root)?;
        outcomes.push(Outcome {
            name: if args[0] == "fmt" { "fmt" } else { "clippy" },
            code,
        });
    }

    let failed: Vec<&str> = outcomes
        .iter()
        .filter(|o| o.code != 0)
        .map(|o| o.name)
        .collect();

    if failed.is_empty() {
        lines.push("All checks passed; the push is safe.".to_string());
        Ok(lines.join("\n"))
    } else {
        Err(format!(
            "{}\nFailing check(s): {}. \
             Both were run, so everything on the list is a real finding.",
            lines.join("\n"),
            failed.join(", ")
        ))
    }
}

/// Canary: proves that `cargo fmt` really refuses a badly formatted file.
///
///
/// This is not empty pedantry. A check that "ran and returned 0" and one that "never ran and
/// returned 0" look the same from outside; the shell version carried exactly this
/// risk. Here a deliberately broken file is produced and shown to be refused.
///
/// # Errors
///
/// If `cargo fmt` accepts a broken file.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-prepush-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("src")).map_err(|e| format!("canary directory: {e}"))?;

    std::fs::write(
        tmp.join("Cargo.toml"),
        "[package]\nname = \"fmt-canary\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .map_err(|e| format!("canary manifest: {e}"))?;

    // Deliberately broken formatting: rustfmt will certainly change this.
    std::fs::write(
        tmp.join("src").join("main.rs"),
        "fn main(){let x=1;let y=2;println!(\"{}\",x+y);}\n",
    )
    .map_err(|e| format!("canary source: {e}"))?;

    let code = run_capturing_status("cargo", &["fmt", "--", "--check"], &tmp)?;
    let _ = std::fs::remove_dir_all(&tmp);

    if code == 0 {
        return Err(
            "CANARY FELL: `cargo fmt --check` accepted a deliberately broken file; \
             this check is looking at nothing."
                .to_string(),
        );
    }
    Ok("pre-push canary OK: a broken format was refused, so the check really runs".to_string())
}

/// Install the git `pre-push` hook.
///
/// The shell version had no such step: the script existed but nobody called it,
/// so it was the counterpart of a suggestion, not a gate.
///
/// # Errors
///
/// If `.git/hooks` is absent or the hook cannot be written.
pub fn install_hook(root: &Path) -> Result<String, String> {
    let hooks = root.join(".git").join("hooks");
    if !hooks.is_dir() {
        return Err(format!(
            "{} is absent; this is not a git working tree",
            hooks.display()
        ));
    }
    let hook = hooks.join("pre-push");
    let body = "#!/bin/sh\n\
                # budlum-tools tarafindan kuruldu.\n\
                exec cargo run --quiet --manifest-path xtask/tools/Cargo.toml \\\n\
                \x20    --bin budlum-tools -- pre-push\n";
    std::fs::write(&hook, body).map_err(|e| format!("{} yazilamadi: {e}", hook.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&hook)
            .map_err(|e| format!("izin okunamadi: {e}"))?
            .permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&hook, perm).map_err(|e| format!("izin yazilamadi: {e}"))?;
    }

    Ok(format!("pre-push kancasi kuruldu: {}", hook.display()))
}

/// `cargo fmt` ve `cargo clippy` mevcut mu.
///
/// # Errors
///
/// Ikisinden biri yoksa.
pub fn ensure_components(root: &Path) -> Result<(), String> {
    run_checked("cargo", &["fmt", "--version"], root)
        .map_err(|e| format!("`cargo fmt` yok: {e}. `rustup component add rustfmt`"))?;
    run_checked("cargo", &["clippy", "--version"], root)
        .map_err(|e| format!("`cargo clippy` yok: {e}. `rustup component add clippy`"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_hook_refuses_a_non_git_tree() {
        let tmp = std::env::temp_dir().join("budlum-prepush-nogit");
        let _ = std::fs::create_dir_all(&tmp);
        let err = install_hook(&tmp).expect_err("a non-git tree must be refused");
        assert!(err.contains("not a git working tree"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn install_hook_writes_an_executable_hook() {
        let tmp = std::env::temp_dir().join("budlum-prepush-git");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".git").join("hooks")).expect("dizin");
        let msg = install_hook(&tmp).expect("kanca kurulmali");
        assert!(msg.contains("pre-push"), "{msg}");

        let hook = tmp.join(".git").join("hooks").join("pre-push");
        assert!(hook.is_file(), "the hook file must exist");
        let body = std::fs::read_to_string(&hook).expect("the hook has to be readable");
        assert!(
            body.contains("budlum-tools"),
            "the hook has to call the tool: {body}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&hook)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "the hook must be executable");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
