// Unsafe lock: this crate currently has 0 unsafe. The moment an `unsafe` block
// enters, the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
//! Repository tools, in Rust.
//!
//! # Why this crate exists
//!
//! `xtask/gates` moved the gates from shell to Rust and states its reasoning in
//! its own header. The same reasoning holds for scripts that are **not gates**,
//! and at one point it holds more strongly: when a gate falls CI turns red and
//! somebody looks; a tool silently doing the wrong thing is visible to nobody.
//!
//! Three shell failures measured in this tree:
//!
//!   * `set -u` catches an **unassigned** variable, it does not catch an
//!     **empty** one. With `VAR=""`, `rm -rf "$VAR/"` runs. `ShellCheck`
//!     carries an open feature request for this class and it was not closed.
//!   * `grep -q` asks "does this text occur"; the right question is usually
//!     "what is this value". In this tree a wrongly scaled ratio and a stale
//!     factor passed two separate gates for exactly this reason.
//!   * There is no type between a path, a number and a label; a script that
//!     compares the wrong two things compiles and runs.
//!
//! # Shape
//!
//! Every tool is a module, every module has a `run` function returning
//! `Result<String, String>`. The `Ok` side is the successful output itself,
//! the `Err` side is the finding. No tool calls `process::exit` from inside,
//! so each of them can be called from a test.
//!
//! # Migration order
//!
//! The scripts are moved one by one, not in a single step. In the first round
//! the four that **no workflow calls** go over: `run_nodes.sh`,
//! `pre-push-check.sh`, `generate_zkvm_seed_corpus.sh` and
//! `backup_restore_drill.sh`. Converting these cannot break CI, because CI
//! does not call them anyway.
//!
//! To be moved in the second round: the five scripts called from workflows
//! (`audit-deps`, `generate-sbom`, `smoke_rpc`, `docker-smoke-mainnet`,
//! `devnet-multinode-smoke`), each together with its own workflow change; and
//! `coverage-report.sh`, which is not called but parses `cargo llvm-cov`
//! output, so its counterpart is not a tool but a parser.

use std::path::{Path, PathBuf};
use std::process::Command;

pub mod backup_drill;
pub mod devnet;
pub mod prepush;
pub mod seed_corpus;

/// Find the repository root.
///
/// The working directory decides: the tools walk up from it to the first
/// directory holding both a `Cargo.toml` and a `src/` tree. Only when that
/// walk finds nothing does the path compiled into the binary count, and it
/// is checked the same way before it is trusted.
///
/// The order matters. `option_env!("CARGO_MANIFEST_DIR")` is the checkout the
/// binary was *built* in, and it used to be consulted first. A tool built in
/// one checkout and run in another then pointed `prepush`, `devnet` and
/// `backup_drill` at the stale tree for as long as it still had a manifest,
/// and ran commands or wrote files there rather than where the operator
/// stood.
///
/// # Panics
///
/// Panics if the working directory cannot be read. A tool that cannot read its
/// working directory has no work to do anyway.
#[must_use]
pub fn repo_root() -> PathBuf {
    let cwd = std::env::current_dir().expect("the working directory could not be read");
    root_above(&cwd).unwrap_or_else(|| {
        option_env!("CARGO_MANIFEST_DIR")
            .and_then(|dir| Path::new(dir).parent().and_then(Path::parent))
            .filter(|root| is_repo_root(root))
            .map_or(cwd, Path::to_path_buf)
    })
}

/// The nearest repository root at or above `start`, if there is one.
fn root_above(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| is_repo_root(dir))
        .map(Path::to_path_buf)
}

/// A repository root carries the workspace manifest and the source tree.
fn is_repo_root(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() && dir.join("src").is_dir()
}

/// Run a command and return **without losing** the exit code.
///
/// The shell equivalent was `cmd || true` or `cmd; RC=$?`, and both are easily
/// written wrongly: the first swallows the error, and the second loses `$?` the
/// moment another command slips in between. Here the exit code is a return
/// value, not an effect.
///
/// # Errors
///
/// Returns an error if the process cannot be started (including `ENOENT`). If
/// the process runs and returns non-zero that is **not an error**: the exit
/// code is returned inside `Ok` and the caller makes the decision.
pub fn run_capturing_status(program: &str, args: &[&str], cwd: &Path) -> Result<i32, String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("`{program}` could not be run: {e}"))?;
    // 128+signal is the shell's convention for a process killed by a signal.
    // If there is no code, a signal killed the process, and counting that as 0
    // would be wrong.
    Ok(status.code().unwrap_or(-1))
}

/// Run a command; a non-zero exit is an error.
///
/// # Errors
///
/// If the process cannot be started or returns non-zero.
pub fn run_checked(program: &str, args: &[&str], cwd: &Path) -> Result<(), String> {
    let code = run_capturing_status(program, args, cwd)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "`{program} {}` exited with code {code}",
            args.join(" ")
        ))
    }
}

/// Say whether a program is on `PATH`.
///
/// Shell'deki `command -v X >/dev/null 2>&1` karsiligi.
#[must_use]
pub fn has_program(program: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file() || candidate.with_extension("exe").is_file()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_root_has_a_manifest_and_a_source_tree() {
        let root = repo_root();
        assert!(
            root.join("Cargo.toml").is_file(),
            "the root has to carry a manifest: {}",
            root.display()
        );
        assert!(
            root.join("src").is_dir(),
            "the root has to carry the source tree: {}",
            root.display()
        );
    }

    /// The directory the tool is run from wins over the path compiled into
    /// the binary: a checkout with a manifest and a source tree above the
    /// working directory is the root, whatever `CARGO_MANIFEST_DIR` said at
    /// build time.
    #[test]
    fn repo_root_follows_the_working_directory() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let fake =
            std::env::temp_dir().join(format!("budlum-tools-root-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(fake.join("src/deeper")).expect("scratch tree");
        std::fs::write(fake.join("Cargo.toml"), "[workspace]\n").expect("scratch manifest");
        let found = root_above(&fake.join("src/deeper"));
        let _ = std::fs::remove_dir_all(&fake);
        assert_eq!(
            found.as_deref(),
            Some(fake.as_path()),
            "the tools must act on the checkout the operator stands in"
        );
        assert!(
            root_above(Path::new("/")).is_none(),
            "no root above `/` is an honest None, so the fallback runs only then"
        );
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_silent_zero() {
        let err = run_capturing_status("budlum-no-such-program", &[], Path::new("."))
            .expect_err("a missing program has to return an error");
        assert!(
            err.contains("could not be run"),
            "it has to say the reason for the error: {err}"
        );
    }

    #[test]
    fn a_nonzero_exit_is_returned_not_swallowed() {
        // `false` returns 1 on every POSIX system. Writing `false || true` in
        // shell used to lose that information.
        let code =
            run_capturing_status("false", &[], Path::new(".")).expect("`false` has to be runnable");
        assert_eq!(code, 1, "the exit code has to be preserved");
    }

    #[test]
    fn run_checked_refuses_a_nonzero_exit() {
        let err = run_checked("false", &[], Path::new(".")).expect_err("1 must not be accepted");
        assert!(
            err.contains("exited with code 1"),
            "it has to say the code: {err}"
        );
    }

    #[test]
    fn has_program_finds_a_shell_builtin_binary() {
        assert!(has_program("sh"), "`sh` her POSIX sisteminde PATH'te");
        assert!(!has_program("budlum-no-such-program"));
    }
}
