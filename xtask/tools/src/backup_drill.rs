//! The backup and restore drill.
//!
//! It replaces `ops/backup_restore_drill.sh`.
//!
//! # The three problems of the shell version
//!
//! 1. `find ... -printf '%T@ %p\n' | sort -nr | head -n1` is **specific to GNU
//!    find**. `-printf` is not POSIX; BSD find (macOS) does not know it and the
//!    drill never runs there. Here the newest backup is found through
//!    `std::fs`'s `modified()` value.
//! 2. The same pipeline breaks when the file name contains a **space**: `cut
//!    -d' ' -f2-` takes everything after the first space, which looks right but
//!    assumes the timestamp itself contains no space. In Rust the name is a
//!    `PathBuf`, not a string to be parsed.
//! 3. `grep -q 'Integrity Audit PASSED'` looked for a **substring**. The output
//!    could read "Integrity Audit PASSED: 3 warnings" instead of "Integrity
//!    Audit PASSED", or carry the same words in another context.
//!    Here the same string is sought but the result is **line based** and the
//!    matching line is reported, so what matched becomes visible.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The inputs to the drill.
pub struct DrillConfig {
    pub binary: PathBuf,
    pub source_db: PathBuf,
    pub backup_dir: PathBuf,
    pub retention: u32,
}

impl DrillConfig {
    /// Read from the environment variables.
    ///
    /// The shell version required it with `: "${SOURCE_DB:?...}"`; that was a
    /// correct pattern and it is kept here, except the error message lives in
    /// one place.
    ///
    /// # Errors
    ///
    /// When a required variable is missing **or empty**. The shell's `:?`
    /// operator catches the empty string too; `set -u` on its own does not.
    pub fn from_env(root: &Path) -> Result<Self, String> {
        let binary = env_or(root, "BUDLUM_BIN", "target/release/budlum-core");
        let source_db = required("SOURCE_DB", "the database directory of a stopped node")?;
        let backup_dir = required("BACKUP_DIR", "the backup destination")?;
        Ok(Self {
            binary,
            source_db: PathBuf::from(source_db),
            backup_dir: PathBuf::from(backup_dir),
            retention: 168,
        })
    }
}

fn required(name: &str, what: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        // An empty string counts as missing too. In shell, `set -u` MISSES
        // this, and an empty path turns into a disaster in expressions like
        // `rm -rf "$VAR/"`.
        Ok(_) => Err(format!("{name} is empty; give a path as {what}")),
        Err(_) => Err(format!("{name} is not defined; give a path as {what}")),
    }
}

fn env_or(root: &Path, name: &str, default_rel: &str) -> PathBuf {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => root.join(default_rel),
    }
}

/// Find the newest `budlum-*.budbak` file in a directory.
///
/// `std::fs` instead of GNU `find -printf`. A space, newline or dash in the
/// file name does not matter: there is no string being parsed.
///
/// # Errors
///
/// If the directory cannot be read or there is no backup at all.
pub fn newest_backup(dir: &Path) -> Result<PathBuf, String> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("{} could not be read: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("a directory entry: {e}"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if !name.starts_with("budlum-") || !name.ends_with(".budbak") {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .map_err(|e| format!("the time of {} could not be read: {e}", path.display()))?;
        if best.as_ref().is_none_or(|(t, _)| modified > *t) {
            best = Some((modified, path));
        }
    }
    best.map(|(_, p)| p).ok_or_else(|| {
        format!(
            "there is no `budlum-*.budbak` inside {}; no backup was produced",
            dir.display()
        )
    })
}

/// Say whether the integrity check output passed.
///
/// The shell looked for a substring with `grep -q` and did not say what
/// matched. Here the matching **line** is returned, so the log stays
/// readable.
///
/// # Errors
///
/// If the expected line is absent.
pub fn integrity_line(output: &str) -> Result<&str, String> {
    output
        .lines()
        .find(|l| l.contains("Integrity Audit PASSED"))
        .ok_or_else(|| {
            let tail: Vec<&str> = output.lines().rev().take(10).collect();
            format!(
                "the integrity check did not pass; the last lines of the output:\n  {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n  ")
            )
        })
}

/// Run the drill.
///
/// # Errors
///
/// If the binary cannot be run, no backup is produced, or the restored database
/// does not pass the integrity check.
pub fn run(cfg: &DrillConfig, root: &Path) -> Result<String, String> {
    if !cfg.binary.is_file() {
        return Err(format!(
            "the Budlum binary was not found: {}",
            cfg.binary.display()
        ));
    }
    std::fs::create_dir_all(&cfg.backup_dir)
        .map_err(|e| format!("{} could not be created: {e}", cfg.backup_dir.display()))?;

    let retention = cfg.retention.to_string();
    let status = Command::new(&cfg.binary)
        .args([
            "--db-path",
            &cfg.source_db.to_string_lossy(),
            "--backup-dir",
            &cfg.backup_dir.to_string_lossy(),
            "--backup-retention-count",
            &retention,
            "--backup-now",
        ])
        .current_dir(root)
        .status()
        .map_err(|e| format!("the backup could not be run: {e}"))?;
    if !status.success() {
        return Err(format!("the backup exited with code {:?}", status.code()));
    }

    let backup = newest_backup(&cfg.backup_dir)?;

    let restore_parent =
        std::env::temp_dir().join(format!("budlum-restore-drill-{}", std::process::id()));
    std::fs::create_dir_all(&restore_parent)
        .map_err(|e| format!("{} could not be created: {e}", restore_parent.display()))?;
    let restore_db = restore_parent.join("restored.db");

    let restore = Command::new(&cfg.binary)
        .args([
            "--db-path",
            &restore_db.to_string_lossy(),
            "--restore-backup",
            &backup.to_string_lossy(),
        ])
        .current_dir(root)
        .status()
        .map_err(|e| format!("the restore could not be run: {e}"))?;
    if !restore.success() {
        let _ = std::fs::remove_dir_all(&restore_parent);
        return Err(format!("the restore exited with code {:?}", restore.code()));
    }

    let check = Command::new(&cfg.binary)
        .args(["--db-path", &restore_db.to_string_lossy(), "--check-db"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("the integrity check could not be run: {e}"))?;
    let stdout = String::from_utf8_lossy(&check.stdout).into_owned();

    let verdict = integrity_line(&stdout).map(ToString::to_string);
    let _ = std::fs::remove_dir_all(&restore_parent);
    let line = verdict?;

    Ok(format!(
        "the drill passed: {} -> {}\n{}",
        backup.display(),
        restore_db.display(),
        line.trim()
    ))
}

/// The canary: it proves that both checks really do refuse.
///
/// # Errors
///
/// If an empty directory returns a backup, or invalid output passes the
/// integrity check.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-drill-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("canary directory: {e}"))?;

    // 1. An empty directory: it has to say there is no backup.
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("THE CANARY FELL: a backup was found in an empty directory".to_string());
    }

    // 2. A file with the wrong extension must not count.
    std::fs::write(tmp.join("budlum-1.txt"), b"x").map_err(|e| format!("canary: {e}"))?;
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("THE CANARY FELL: a `.txt` counted as a backup".to_string());
    }

    // 3. The right file has to be found, even with a space in its name. The
    //    shell's `cut -d' '` pipeline broke exactly here.
    let spaced = tmp.join("budlum-2026 08 14.budbak");
    std::fs::write(&spaced, b"x").map_err(|e| format!("canary: {e}"))?;
    let found = newest_backup(&tmp)?;
    if found != spaced {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!(
            "THE CANARY FELL: the spaced name was not found, {} was returned",
            found.display()
        ));
    }

    // 4. Output without an integrity line has to be refused.
    if integrity_line("everything looks fine\ndone").is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("THE CANARY FELL: it passed without an integrity line".to_string());
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok("backup drill canary OK: an empty directory, a wrong extension and a missing integrity line were refused; a name with a space was found".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_backup_dir_is_an_error() {
        let tmp = std::env::temp_dir().join("budlum-drill-empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("directory");
        let err = newest_backup(&tmp).expect_err("an empty directory must be an error");
        assert!(err.contains("budbak"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_name_with_spaces_is_found() {
        let tmp = std::env::temp_dir().join("budlum-drill-spaces");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("directory");
        let p = tmp.join("budlum-2026 08 14 12:00.budbak");
        std::fs::write(&p, b"x").expect("file");
        assert_eq!(newest_backup(&tmp).expect("bulunmali"), p);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn integrity_line_reports_what_matched() {
        let line = integrity_line("a\nIntegrity Audit PASSED (3 tables)\nb").expect("must pass");
        assert!(
            line.contains("3 tables"),
            "the matching line must be returned: {line}"
        );
    }

    #[test]
    fn integrity_line_shows_the_tail_when_it_fails() {
        let err = integrity_line("line1\nline2").expect_err("must not pass");
        assert!(err.contains("line2"), "it must show the last lines: {err}");
    }

    #[test]
    fn an_empty_env_var_counts_as_missing() {
        // In shell `set -u` MISSES this; an empty string counts as assigned.
        std::env::set_var("BUDLUM_DRILL_TEST_EMPTY", "");
        let err = required("BUDLUM_DRILL_TEST_EMPTY", "a path").expect_err("empty must be refused");
        assert!(err.contains("is empty"), "{err}");
        std::env::remove_var("BUDLUM_DRILL_TEST_EMPTY");
    }

    #[test]
    fn self_test_passes() {
        let msg = self_test().expect("the canary must pass");
        assert!(msg.contains("OK"), "{msg}");
    }
}
