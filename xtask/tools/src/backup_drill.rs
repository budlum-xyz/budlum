//! The backup and restore drill.
//!
//! `ops/backup_restore_drill.sh` yerine gecer.
//!
//! # Shell surumunun uc sorunu
//!
//! 1. `find ... -printf '%T@ %p\n' | sort -nr | head -n1` **GNU find'a
//!    specific**. `-printf` is not POSIX; BSD find (macOS) does not know it and
//!    tatbikat orada hic kosmaz. Burada en yeni yedek `std::fs`'in
//!    `modified()` degeriyle bulunuyor.
//! 2. Ayni boru hatti dosya adinda **bosluk** varsa bozulur: `cut -d' '
//!    -f2-` takes everything after the first space, which looks right but
//!    assumes the timestamp itself contains no space. In Rust the name is a
//!    `PathBuf`, not a string to be parsed.
//! 3. `grep -q 'Integrity Audit PASSED'` bir **alt dizgi** ariyordu. Cikti
//!    "Integrity Audit PASSED" yerine "Integrity Audit PASSED: 3 warnings"
//!    or carried the same words in another context.
//!    Here the same string is sought but the result is **line based** and the matching
//!    line is reported, so what matched becomes visible.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Tatbikatin girdileri.
pub struct DrillConfig {
    pub binary: PathBuf,
    pub source_db: PathBuf,
    pub backup_dir: PathBuf,
    pub retention: u32,
}

impl DrillConfig {
    /// Ortam degiskenlerinden oku.
    ///
    /// The shell version required it with `: "${SOURCE_DB:?...}"`; that is correct
    /// bir desendi ve burada da korunuyor, ama hata mesaji tek yerde.
    ///
    /// # Errors
    ///
    /// Zorunlu bir degisken yoksa **ya da bos ise**. Shell'in `:?` operatoru
    /// bos dizgiyi de yakalar; `set -u` tek basina yakalamaz.
    pub fn from_env(root: &Path) -> Result<Self, String> {
        let binary = env_or(root, "BUDLUM_BIN", "target/release/budlum-core");
        let source_db = required("SOURCE_DB", "the database directory of a stopped node")?;
        let backup_dir = required("BACKUP_DIR", "yedek hedefi")?;
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
        // Bos dizgi de eksik sayilir. Shell'de `set -u` bunu KACIRIR ve
        // bos bir yol `rm -rf "$VAR/"` gibi ifadelerde felakete doner.
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

/// Bir dizindeki en yeni `budlum-*.budbak` dosyasini bul.
///
/// `std::fs` instead of GNU `find -printf`. A space, newline or dash in the file name
/// does not matter: there is no string being parsed.
///
/// # Errors
///
/// If the directory cannot be read or there is no backup at all.
pub fn newest_backup(dir: &Path) -> Result<PathBuf, String> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{} okunamadi: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("dizin girdisi: {e}"))?;
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
            .map_err(|e| format!("{} zamani okunamadi: {e}", path.display()))?;
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

/// Butunluk denetimi ciktisinin gectigini soyle.
///
/// Shell `grep -q` ile bir alt dizgi ariyordu ve neyin eslestigini
/// did not say so. Here the matching **line** is returned, so the log stays readable.
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
                "butunluk denetimi gecmedi; ciktinin son satirlari:\n  {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n  ")
            )
        })
}

/// Tatbikati kos.
///
/// # Errors
///
/// If the binary cannot be run, no backup is produced, or the restored database
/// butunluk denetiminden gecmezse.
pub fn run(cfg: &DrillConfig, root: &Path) -> Result<String, String> {
    if !cfg.binary.is_file() {
        return Err(format!(
            "Budlum ikilisi bulunamadi: {}",
            cfg.binary.display()
        ));
    }
    std::fs::create_dir_all(&cfg.backup_dir)
        .map_err(|e| format!("{} olusturulamadi: {e}", cfg.backup_dir.display()))?;

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
        .map_err(|e| format!("yedek alma calistirilamadi: {e}"))?;
    if !status.success() {
        return Err(format!("yedek alma cikis kodu {:?}", status.code()));
    }

    let backup = newest_backup(&cfg.backup_dir)?;

    let restore_parent =
        std::env::temp_dir().join(format!("budlum-restore-drill-{}", std::process::id()));
    std::fs::create_dir_all(&restore_parent)
        .map_err(|e| format!("{} olusturulamadi: {e}", restore_parent.display()))?;
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
        .map_err(|e| format!("butunluk denetimi calistirilamadi: {e}"))?;
    let stdout = String::from_utf8_lossy(&check.stdout).into_owned();

    let verdict = integrity_line(&stdout).map(ToString::to_string);
    let _ = std::fs::remove_dir_all(&restore_parent);
    let line = verdict?;

    Ok(format!(
        "tatbikat gecti: {} -> {}\n{}",
        backup.display(),
        restore_db.display(),
        line.trim()
    ))
}

/// Kanarya: iki kontrolun de gercekten reddettigini kanitlar.
///
/// # Errors
///
/// If an empty directory returns a backup, or invalid output passes the integrity
/// gecerse.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-drill-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("canary directory: {e}"))?;

    // 1. Bos dizin: yedek yok denmeli.
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: bos dizinde yedek bulundu".to_string());
    }

    // 2. Yanlis uzantili dosya sayilmamali.
    std::fs::write(tmp.join("budlum-1.txt"), b"x").map_err(|e| format!("canary: {e}"))?;
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: `.txt` bir yedek sayildi".to_string());
    }

    // 3. Dogru dosya bulunmali, adinda bosluk olsa bile. Shell'in
    //    `cut -d' '` boru hatti tam burada bozuluyordu.
    let spaced = tmp.join("budlum-2026 08 14.budbak");
    std::fs::write(&spaced, b"x").map_err(|e| format!("canary: {e}"))?;
    let found = newest_backup(&tmp)?;
    if found != spaced {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(format!(
            "KANARYA DUSTU: bosluklu ad bulunamadi, {} donduruldu",
            found.display()
        ));
    }

    // 4. Butunluk satiri olmayan cikti reddedilmeli.
    if integrity_line("her sey yolunda gibi\nbitti").is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: butunluk satiri olmadan gecti".to_string());
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
        std::fs::create_dir_all(&tmp).expect("dizin");
        let err = newest_backup(&tmp).expect_err("bos dizin hata vermeli");
        assert!(err.contains("budbak"), "{err}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_name_with_spaces_is_found() {
        let tmp = std::env::temp_dir().join("budlum-drill-spaces");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("dizin");
        let p = tmp.join("budlum-2026 08 14 12:00.budbak");
        std::fs::write(&p, b"x").expect("dosya");
        assert_eq!(newest_backup(&tmp).expect("bulunmali"), p);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn integrity_line_reports_what_matched() {
        let line = integrity_line("a\nIntegrity Audit PASSED (3 tables)\nb").expect("gecmeli");
        assert!(
            line.contains("3 tables"),
            "the matching line must be returned: {line}"
        );
    }

    #[test]
    fn integrity_line_shows_the_tail_when_it_fails() {
        let err = integrity_line("satir1\nsatir2").expect_err("gecmemeli");
        assert!(err.contains("satir2"), "son satirlari gostermeli: {err}");
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
