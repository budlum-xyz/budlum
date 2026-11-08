//! The backup drill covers the paths the node actually persists.
//!
//! The drill was written when the node kept one database directory. It now
//! keeps more: the sled database, the vote high-water marks
//! (`vote-history.json`, on by default on every network), the ban list
//! (`banned-peers.json`, on where the network asks for it), the snapshot
//! directory and the backup directory itself. A drill that restores the
//! database and calls the node recovered leaves a restarted validator without
//! its vote marks, which is the double-sign window the marks exist to close
//! (`src/network/node.rs::save_vote_history`).
//!
//! What is checked here, none of it a measurement:
//!
//! * the **list** of persisted paths is the node's own list, read out of the
//!   source that writes them, so the drill cannot lose a file the node gained;
//! * the restore really does refuse a target that is not empty, so the drill's
//!   "restore into an empty directory" step is a check rather than a hope;
//! * the check runs after the write it is a check on.
//!
//! A tampered-backup case is a source lock rather than a run: minting a valid
//! backup needs the node's own bincode and hash framing, and a fixture that
//! reproduced it here would be a second implementation of the format proving
//! itself. The runbook says so instead of implying the drill covers it.

use crate::storage::Storage;
use std::path::{Path, PathBuf};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// Everything the node writes outside the database directory, as
/// `(file, who writes it)`.
///
/// These defaults are not literals in a config file: they are formatted from
/// the network name at runtime, which is why they are easy to miss when a
/// drill is written against `config/testnet.toml` alone.
const PERSISTED_OUTSIDE_THE_DB: &[(&str, &str)] = &[
    ("vote-history.json", "src/network/node.rs"),
    ("banned-peers.json", "src/network/node.rs"),
    ("--state-file", "src/bin/budlum-faucet.rs"),
    ("relayer-pending.json", "src/relayer/worker.rs"),
];

/// The drill's own list of paths has to match the node's.
///
/// This is the check that would have caught the gap: a name in
/// `PERSISTED_OUTSIDE_THE_DB` and a line in the runbook, or the list is stale.
#[test]
fn the_drill_covers_every_persisted_path() {
    let runbook = read("ops/BACKUP_AND_RESTORE.md");
    for (file, writer) in PERSISTED_OUTSIDE_THE_DB {
        let source = read(writer);
        assert!(
            source.contains(file),
            "{writer} no longer names {file}; update PERSISTED_OUTSIDE_THE_DB \
             rather than deleting the check"
        );
        assert!(
            runbook.contains(file),
            "ops/BACKUP_AND_RESTORE.md does not cover {file}, which {writer} persists"
        );
    }
    // The drill drives the operator-facing flags, not a shortcut of its own:
    // a drill that passed through a code path no operator can run would prove
    // nothing about the runbook.
    let drill = read("xtask/tools/src/backup_drill.rs");
    for flag in ["--backup-now", "--restore-backup", "--check-db"] {
        assert!(
            drill.contains(flag),
            "the drill must drive the operator-facing flag {flag}"
        );
        assert!(
            runbook.contains(flag),
            "the runbook must document the flag the drill drives: {flag}"
        );
    }
}

/// `restore_snapshot` refuses a non-empty target.
///
/// A restore that overwrote a live database would be the one operation an
/// operator must never be able to run by accident; the drill depends on this
/// refusal to know its restore went into a fresh directory.
#[test]
fn restore_refuses_a_target_that_is_not_empty() {
    let root = std::env::temp_dir().join(format!("budlum-restore-refusal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let target: PathBuf = root.join("occupied");
    std::fs::create_dir_all(&target).expect("fixture");
    std::fs::write(target.join("keeper"), b"not a database").expect("fixture");
    let snapshot = root.join("missing.budbak");

    let refusal = Storage::restore_snapshot(&snapshot, &target)
        .expect_err("a non-empty target must be refused before the snapshot is even read");
    assert_eq!(
        refusal.kind(),
        std::io::ErrorKind::AlreadyExists,
        "the refusal names the reason: {refusal}"
    );
    assert!(
        target.join("keeper").is_file(),
        "the refused restore must not touch what was already there"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The restore is checked after it is written, and the runbook's order is the
/// code's order. A check that runs before the write proves nothing about what
/// was written.
#[test]
fn the_restore_is_checked_after_it_is_written() {
    let main = read("src/main.rs");
    let restore = main
        .find("config.restore_backup")
        .expect("the restore path exists in main.rs");
    let check = main[restore..]
        .find("restored and integrity-checked")
        .expect("the restore path reports an integrity check");
    assert!(
        main[restore..restore + check].contains("Storage::restore_snapshot"),
        "the restore must run before the check that reports it"
    );
    let runbook = read("docs/OPERATIONS.md");
    let restore_step = runbook
        .find("--restore-backup")
        .expect("the runbook documents the restore");
    let check_step = runbook[restore_step..]
        .find("--check-db")
        .expect("the runbook checks a restored database");
    assert!(
        check_step > 0,
        "the runbook must check a database after it restores one"
    );
}
