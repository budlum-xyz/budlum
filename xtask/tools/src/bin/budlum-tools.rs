//! The entry point for the repository tools.
//!
//! Usage:
//!
//! ```text
//! cargo run --manifest-path xtask/tools/Cargo.toml -- <arac> [arg...]
//! ```
//!
//! Araclar:
//!
//! | Tool | The script it replaces |
//! |---|---|
//! | `pre-push` | `scripts/pre-push-check.sh` |
//! | `install-hook` | (new: nobody was calling the script) |
//! | `devnet` | `run_nodes.sh` |
//! | `seed-corpus [dir]` | `scripts/generate_zkvm_seed_corpus.sh` |
//! | `backup-drill` | `ops/backup_restore_drill.sh` |
//! | `audit-deps` | `ops/scripts/audit-deps.sh` |
//! | `generate-sbom` | `ops/scripts/generate-sbom.sh` |
//! | `smoke-rpc` | `ops/scripts/smoke_rpc.sh` |
//! | `docker-smoke-mainnet` | `ops/scripts/docker-smoke-mainnet.sh` |
//! | `devnet-multinode-smoke` | `ops/scripts/devnet-multinode-smoke.sh` |
//! | `audit-guard [--self-test]` | `.github/scripts/audit_guard.py` |
//! | `step-reachability [--self-test] [--fail JOB:STEP] [file...]` | `ops/scripts/check-step-reachability.py` |
//! | `clippy-extra-report <json> [n]` | `ops/scripts/clippy-extra-report.py` |
//! | `fsf-project-fit [--write] [--check] [--self-test]` | `tools/fsf_project_fit.py` |
//! | `--self-test` | (new: the canary of every tool) |

use budlum_tools::{
    audit_deps, backup_drill, devnet, docker_smoke, multinode_smoke, prepush, repo_root, sbom,
    seed_corpus, smoke_rpc,
};
use budlum_tools::{audit_guard, clippy_extra_report, fsf_fit, step_reachability};

fn usage() -> String {
    "budlum-tools <arac> [arg...]\n\
     \n\
     Tools:\n\
     \x20 pre-push              cargo fmt + clippy (both run)\n\
     \x20 install-hook          install the .git/hooks/pre-push hook\n\
     \x20 devnet                prepare a local two-node devnet\n\
     \x20 seed-corpus [dir]     write the ZKVM fuzz seeds\n\
     \x20 backup-drill          take a backup, restore it, verify integrity\n\
     \x20 audit-deps            cargo audit over both lockfiles, plus the report
     \x20 generate-sbom         CycloneDX SBOM (pinned cargo-cyclonedx)
     \x20 smoke-rpc             start a node and probe bud_chainId
     \x20 docker-smoke-mainnet  image smoke: mainnet refuses, devnet boots
     \x20 devnet-multinode-smoke  4-node compose smoke (needs docker)
     \x20 audit-guard           review boundary audit of workflows and history\n\
     \x20 step-reachability     which workflow steps can run (guards that point nowhere)\n\
     \x20 clippy-extra-report   per-lint tally and addresses from clippy JSON\n\
     \x20 fsf-project-fit       generate or check docs/FSF_PROJECT_FIT.md\n\
     \x20 --self-test           run every tool's canary\n\
     \x20 --list                print the tool names\n"
        .to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let root = repo_root();

    // The tools ported from scripts keep the exact stdout, stderr and exit
    // code of the script, so they return a full report.
    if let Some((name, rest)) = refs.split_first() {
        let ported = match *name {
            "audit-guard" => Some(audit_guard::cli(rest, &root)),
            "step-reachability" => Some(step_reachability::cli(rest, &root)),
            "clippy-extra-report" => Some(clippy_extra_report::cli(rest, &root)),
            "fsf-project-fit" => Some(fsf_fit::cli(rest, &root)),
            _ => None,
        };
        if let Some(report) = ported {
            print!("{}", report.stdout);
            eprint!("{}", report.stderr);
            std::process::exit(report.code);
        }
    }

    let outcome: Result<String, String> = match refs.first() {
        None => {
            eprint!("{}", usage());
            std::process::exit(2);
        }
        Some(&"--list") => {
            for name in [
                "pre-push",
                "install-hook",
                "devnet",
                "seed-corpus",
                "backup-drill",
                "audit-deps",
                "generate-sbom",
                "smoke-rpc",
                "docker-smoke-mainnet",
                "devnet-multinode-smoke",
                "audit-guard",
                "step-reachability",
                "clippy-extra-report",
                "fsf-project-fit",
            ] {
                println!("{name}");
            }
            return;
        }
        // Every tool's canary. A tool must show from outside the difference
        // between "returned 0" and "never ran"; the `--self-test` pattern of the
        // gates crate holds here too.
        Some(&"--self-test") => {
            let mut failed = 0usize;
            for (name, result) in [
                ("seed-corpus", seed_corpus::self_test()),
                ("devnet", devnet::self_test()),
                ("backup-drill", backup_drill::self_test()),
                ("pre-push", prepush::self_test()),
            ] {
                match result {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => {
                        eprintln!("FAIL [{name}]: {e}");
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                eprintln!("\n{failed} canaries fell.");
                std::process::exit(1);
            }
            return;
        }
        Some(&"pre-push") => prepush::ensure_components(&root).and_then(|()| prepush::run(&root)),
        Some(&"install-hook") => prepush::install_hook(&root),
        Some(&"devnet") => devnet::prepare(&root),
        Some(&"seed-corpus") => {
            let dir = refs
                .get(1)
                .map_or_else(|| seed_corpus::default_out_dir(&root), Into::into);
            seed_corpus::generate(&dir)
        }
        Some(&"backup-drill") => backup_drill::DrillConfig::from_env(&root)
            .and_then(|cfg| backup_drill::run(&cfg, &root)),
        Some(&"audit-deps") => audit_deps::run(&root),
        Some(&"generate-sbom") => sbom::run(&root),
        Some(&"smoke-rpc") => {
            smoke_rpc::Config::from_env().and_then(|cfg| smoke_rpc::run(&root, &cfg))
        }
        Some(&"docker-smoke-mainnet") => docker_smoke::run(&root),
        Some(&"devnet-multinode-smoke") => multinode_smoke::run(&root),
        Some(name) => {
            eprintln!("FAIL: there is no tool named `{name}`.\n");
            eprint!("{}", usage());
            std::process::exit(2);
        }
    };

    match outcome {
        Ok(msg) => println!("{msg}"),
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
