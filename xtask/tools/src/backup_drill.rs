//! Yedek alma ve geri yukleme tatbikati.
//!
//! `ops/backup_restore_drill.sh` yerine gecer.
//!
//! # Shell surumunun uc sorunu
//!
//! 1. `find ... -printf '%T@ %p\n' | sort -nr | head -n1` **GNU find'a
//!    ozgu**. `-printf` POSIX degil; BSD find (macOS) bunu tanimaz ve
//!    tatbikat orada hic kosmaz. Burada en yeni yedek `std::fs`'in
//!    `modified()` degeriyle bulunuyor.
//! 2. Ayni boru hatti dosya adinda **bosluk** varsa bozulur: `cut -d' '
//!    -f2-` ilk bosluktan sonrasini alir, ki bu dogru gibi gorunur ama
//!    zaman damgasinin kendisi bosluk icermez diye varsayar. Rust'ta ad bir
//!    `PathBuf`, ayristirilacak bir dizgi degil.
//! 3. `grep -q 'Integrity Audit PASSED'` bir **alt dizgi** ariyordu. Cikti
//!    "Integrity Audit PASSED" yerine "Integrity Audit PASSED: 3 warnings"
//!    ya da baska bir baglamda ayni kelimeleri tasisaydi da gecerdi.
//!    Burada ayni dizgi araniyor ama sonuc **satir bazinda** ve eslesen
//!    satir raporlaniyor, yani ne eslesitigi gorunur oluyor.

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
    /// Shell surumu `: "${SOURCE_DB:?...}"` ile zorunlu tutuyordu; bu dogru
    /// bir desendi ve burada da korunuyor, ama hata mesaji tek yerde.
    ///
    /// # Errors
    ///
    /// Zorunlu bir degisken yoksa **ya da bos ise**. Shell'in `:?` operatoru
    /// bos dizgiyi de yakalar; `set -u` tek basina yakalamaz.
    pub fn from_env(root: &Path) -> Result<Self, String> {
        let binary = env_or(root, "BUDLUM_BIN", "target/release/budlum-core");
        let source_db = required("SOURCE_DB", "durdurulmus dugum veritabani dizini")?;
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
        Ok(_) => Err(format!("{name} bos; {what} olarak bir yol verin")),
        Err(_) => Err(format!("{name} tanimli degil; {what} olarak bir yol verin")),
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
/// GNU `find -printf` yerine `std::fs`. Dosya adindaki bosluk, yeni satir ya
/// da tire onemli degil: ayristirilan bir dizgi yok.
///
/// # Errors
///
/// Dizin okunamazsa ya da hicbir yedek yoksa.
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
            "{} icinde `budlum-*.budbak` yok; yedek uretilmedi",
            dir.display()
        )
    })
}

/// Butunluk denetimi ciktisinin gectigini soyle.
///
/// Shell `grep -q` ile bir alt dizgi ariyordu ve neyin eslestigini
/// soylemiyordu. Burada eslesen **satir** doner, yani log okunabilir.
///
/// # Errors
///
/// Beklenen satir yoksa.
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
/// Ikili calistirilamazsa, yedek uretilmezse ya da geri yuklenen veritabani
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
        .map_err(|e| format!("geri yukleme calistirilamadi: {e}"))?;
    if !restore.success() {
        let _ = std::fs::remove_dir_all(&restore_parent);
        return Err(format!("geri yukleme cikis kodu {:?}", restore.code()));
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
/// Bos bir dizin yedek dondurur ya da gecersiz cikti butunluk denetiminden
/// gecerse.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-drill-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("kanarya dizini: {e}"))?;

    // 1. Bos dizin: yedek yok denmeli.
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: bos dizinde yedek bulundu".to_string());
    }

    // 2. Yanlis uzantili dosya sayilmamali.
    std::fs::write(tmp.join("budlum-1.txt"), b"x").map_err(|e| format!("kanarya: {e}"))?;
    if newest_backup(&tmp).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: `.txt` bir yedek sayildi".to_string());
    }

    // 3. Dogru dosya bulunmali, adinda bosluk olsa bile. Shell'in
    //    `cut -d' '` boru hatti tam burada bozuluyordu.
    let spaced = tmp.join("budlum-2026 08 14.budbak");
    std::fs::write(&spaced, b"x").map_err(|e| format!("kanarya: {e}"))?;
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
    Ok("yedek tatbikati kanaryasi OK: bos dizin, yanlis uzanti ve eksik butunluk satiri reddedildi; bosluklu ad bulundu".to_string())
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
        assert!(line.contains("3 tables"), "eslesen satir donmeli: {line}");
    }

    #[test]
    fn integrity_line_shows_the_tail_when_it_fails() {
        let err = integrity_line("satir1\nsatir2").expect_err("gecmemeli");
        assert!(err.contains("satir2"), "son satirlari gostermeli: {err}");
    }

    #[test]
    fn an_empty_env_var_counts_as_missing() {
        // Shell'de `set -u` bunu KACIRIR; bos dizgi atanmis sayilir.
        std::env::set_var("BUDLUM_DRILL_TEST_EMPTY", "");
        let err = required("BUDLUM_DRILL_TEST_EMPTY", "bir yol").expect_err("bos reddedilmeli");
        assert!(err.contains("bos"), "{err}");
        std::env::remove_var("BUDLUM_DRILL_TEST_EMPTY");
    }

    #[test]
    fn self_test_passes() {
        let msg = self_test().expect("kanarya gecmeli");
        assert!(msg.contains("OK"), "{msg}");
    }
}
