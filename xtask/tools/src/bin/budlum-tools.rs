//! Depo araclarinin giris noktasi.
//!
//! Kullanim:
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
//! | `--self-test` | (new: the canary of every tool) |

use budlum_tools::{backup_drill, devnet, prepush, repo_root, seed_corpus};

fn usage() -> String {
    "budlum-tools <arac> [arg...]\n\
     \n\
     Tools:\n\
     \x20 pre-push              cargo fmt + clippy (both run)\n\
     \x20 install-hook          install the .git/hooks/pre-push hook\n\
     \x20 devnet                prepare a local two-node devnet\n\
     \x20 seed-corpus [dir]     write the ZKVM fuzz seeds\n\
     \x20 backup-drill          take a backup, restore it, verify integrity\n\
     \x20 --self-test           run every tool's canary\n\
     \x20 --list                print the tool names\n"
        .to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let root = repo_root();

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
        Some(name) => {
            eprintln!("FAIL: `{name}` diye bir arac yok.\n");
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
