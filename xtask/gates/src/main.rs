//! Repository gates, in Rust.
//!
//! # Why this crate exists
//!
//! The gates were shell. Eighteen thousand lines of it across seventy-four
//! `scripts/check-*.sh`, each one deciding whether a commit is allowed onto
//! `main`. That places them inside the trust boundary, and shell is a poor
//! language to put there:
//!
//!   * A misspelt variable is an empty string, not an error, so a check can
//!     silently examine nothing and report OK. `set -u` catches the unset
//!     case and not the misspelt-but-assigned one.
//!   * `grep -q` answers "does this text appear", which is the wrong question
//!     often enough that it let a wrongly scaled rate and a stale factor
//!     through two separate gates on this branch alone. Both were found by
//!     recomputing outside the gate, not by the gate.
//!   * There is no type between a path, a count and a label, so a gate that
//!     compares the wrong two things compiles and runs.
//!   * The canaries were themselves shell, so a broken canary and a working
//!     one look the same from the outside.
//!
//! Rust removes the first and third by construction, and makes the second a
//! matter of writing the arithmetic out rather than grepping for its answer.
//!
//! # Shape
//!
//! One binary, one gate per module, each exposing `run` and `self_test`.
//! Both return `Result<String, String>`: the `Ok` side is what a passing gate
//! prints, the `Err` side is the finding. Nothing calls `process::exit` from
//! inside a gate, so a gate can be called from a test.
//!
//! # Migration
//!
//! The shell gates are being replaced one at a time, not in a single sweep. A
//! gate moves when its Rust version reproduces every canary the shell version
//! had, which is checked by `--self-test`. Until a gate has moved, its shell
//! script stays wired and authoritative; a half-ported gate that runs in
//! neither language would be worse than the shell it replaced.

use std::path::{Path, PathBuf};

mod gates {
    pub mod bns_names_are_safe_in_an_address_bar;
    pub mod capability_modules_are_wired;
    pub mod every_fuzz_target_is_run;
    pub mod mermaid;
    pub mod no_new_shell_gates;
    pub mod security_scans_can_fail;
    pub mod suppressions_are_justified;
    pub mod the_image_builds_what_the_manifest_declares;
    pub mod workflows_produce_jobs;
}

/// One gate, as the runner sees it.
struct Gate {
    /// Name used on the command line and in CI job names.
    name: &'static str,
    /// The shell script this replaced, so the two can be compared during the
    /// migration and the old one deleted with evidence rather than hope.
    replaces: Option<&'static str>,
    run: fn(&Path) -> Result<String, String>,
    self_test: fn() -> Result<String, String>,
}

const GATES: &[Gate] = &[
    Gate {
        name: "capability-wiring",
        replaces: Some("check-capability-modules-are-wired.sh"),
        run: gates::capability_modules_are_wired::run,
        self_test: gates::capability_modules_are_wired::self_test,
    },
    Gate {
        name: "mermaid",
        replaces: None,
        run: gates::mermaid::run,
        self_test: gates::mermaid::self_test,
    },
    Gate {
        name: "bns-names",
        replaces: None,
        run: gates::bns_names_are_safe_in_an_address_bar::run,
        self_test: gates::bns_names_are_safe_in_an_address_bar::self_test,
    },
    Gate {
        name: "security-scans-can-fail",
        replaces: None,
        run: gates::security_scans_can_fail::run,
        self_test: gates::security_scans_can_fail::self_test,
    },
    Gate {
        name: "suppressions-are-justified",
        replaces: None,
        run: gates::suppressions_are_justified::run,
        self_test: gates::suppressions_are_justified::self_test,
    },
    Gate {
        name: "workflows-produce-jobs",
        replaces: None,
        run: gates::workflows_produce_jobs::run,
        self_test: gates::workflows_produce_jobs::self_test,
    },
    Gate {
        name: "image-builds-the-manifest",
        replaces: None,
        run: gates::the_image_builds_what_the_manifest_declares::run,
        self_test: gates::the_image_builds_what_the_manifest_declares::self_test,
    },
    Gate {
        name: "every-fuzz-target-is-run",
        replaces: None,
        run: gates::every_fuzz_target_is_run::run,
        self_test: gates::every_fuzz_target_is_run::self_test,
    },
    Gate {
        name: "no-new-shell-gates",
        replaces: None,
        run: gates::no_new_shell_gates::run,
        self_test: gates::no_new_shell_gates::self_test,
    },
];

fn usage() -> String {
    let mut s = String::from(
        "usage:\n  \
         budlum-gates <gate>              run one gate\n  \
         budlum-gates <gate> --self-test  run one gate's canaries\n  \
         budlum-gates --all               run every gate\n  \
         budlum-gates --all --self-test   run every canary\n  \
         budlum-gates --list              name every gate\n\n\
         gates:\n",
    );
    for g in GATES {
        s.push_str("  ");
        s.push_str(g.name);
        if let Some(r) = g.replaces {
            s.push_str("  (replaces ");
            s.push_str(r);
            s.push(')');
        }
        s.push('\n');
    }
    s
}

/// Where the repository root is.
///
/// `BUDLUM_ROOT` wins so a canary can point the gate at a staged copy. The
/// fallback walks up from the binary's own directory rather than trusting the
/// current directory, because CI does not always run from the root.
fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("BUDLUM_ROOT") {
        return PathBuf::from(r);
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        if dir.join("ARCHITECTURE.md").is_file() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
        if !dir.pop() {
            return PathBuf::from(".");
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let self_test = refs.contains(&"--self-test");
    let root = repo_root();

    let selected: Vec<&Gate> = match refs.first() {
        None => {
            eprint!("{}", usage());
            std::process::exit(2);
        }
        Some(&"--list") => {
            for g in GATES {
                println!("{}", g.name);
            }
            return;
        }
        // `--all` and a bare `--self-test` both mean every gate; the flag was
        // already read above, so the two arms are one.
        Some(&"--all" | &"--self-test") => GATES.iter().collect(),
        Some(name) => {
            if let Some(g) = GATES.iter().find(|g| g.name == *name) {
                vec![g]
            } else {
                eprintln!("FAIL: no gate named `{name}`.\n");
                eprint!("{}", usage());
                std::process::exit(2);
            }
        }
    };

    let mut failed = 0usize;
    for g in selected {
        let outcome = if self_test {
            (g.self_test)()
        } else {
            (g.run)(&root)
        };
        match outcome {
            Ok(msg) => println!("{msg}"),
            Err(msg) => {
                eprintln!("FAIL [{}]: {msg}", g.name);
                failed += 1;
            }
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
}
