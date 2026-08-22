// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// derleme FAIL eder (regresyon kapisi). Ana crate ile ayni politika.
#![forbid(unsafe_code)]
//! Depo araclari, Rust'ta.
//!
//! # Bu crate neden var
//!
//! `xtask/gates` kapilari shell'den Rust'a tasidi ve gerekcesini kendi
//! basliginda yaziyor. Ayni gerekce **kapi olmayan** betikler icin de
//! gecerli, hatta bir noktada daha guclu: bir kapi dustugunde CI kirmizi
//! olur ve birisi bakar; bir aracin sessizce yanlis is yapmasi kimseye
//! gorunmez.
//!
//! Shell'in bu agacta olculmus uc hatasi:
//!
//!   * `set -u` **atanmamis** degiskeni yakalar, **bos** degiskeni
//!     yakalamaz. `VAR=""` iken `rm -rf "$VAR/"` calisir. `ShellCheck` bu
//!     sinif icin acik bir ozellik istegi tasiyor ve kapatilmadi.
//!   * `grep -q` "bu metin geciyor mu" diye sorar; dogru soru cogu zaman
//!     "bu deger ne" olur. Bu agacta iki ayri kapiyi yanlis olceklenmis bir
//!     oran ve bayat bir carpan tam bu yuzden gecti.
//!   * Bir yol, bir sayi ve bir etiket arasinda tur yoktur; yanlis iki seyi
//!     karsilastiran bir betik derlenir ve calisir.
//!
//! # Bicim
//!
//! Her arac bir modul, her modul bir `run` fonksiyonu ve
//! `Result<String, String>` donuyor. `Ok` tarafi basarili ciktinin
//! kendisi, `Err` tarafi bulgu. Hicbir arac icinden `process::exit`
//! cagrilmiyor, boylece her biri bir testten cagrilabilir.
//!
//! # Tasima sirasi
//!
//! Betikler tek seferde degil, teker teker tasiniyor. Ilk turda **hicbir
//! workflow'un cagirmadigi** dordu geciyor: `run_nodes.sh`,
//! `pre-push-check.sh`, `generate_zkvm_seed_corpus.sh` ve
//! `backup_restore_drill.sh`. Bunlarin donusumu CI'i kiramaz, cunku CI
//! onlari zaten cagirmiyor.
//!
//! Ikinci turda tasinacaklar: workflow'lardan cagrilan bes betik
//! (`audit-deps`, `generate-sbom`, `smoke_rpc`, `docker-smoke-mainnet`,
//! `devnet-multinode-smoke`), her biri kendi workflow degisikligiyle
//! birlikte; ve `coverage-report.sh`, ki o cagrilmiyor ama `cargo llvm-cov`
//! ciktisini ayristirdigi icin karsiligi bir arac degil bir cozumleyici.

use std::path::{Path, PathBuf};
use std::process::Command;

pub mod backup_drill;
pub mod devnet;
pub mod prepush;
pub mod seed_corpus;

/// Depo kokunu bul.
///
/// `CARGO_MANIFEST_DIR` bu crate'i (`xtask/tools`) gosterir; kok iki ust
/// dizin. Ortam degiskeni yoksa calisma dizininden yukari yurunur.
///
/// # Panics
///
/// Calisma dizini okunamazsa panikler. Bir arac calisma dizinini
/// okuyamiyorsa yapacak isi zaten yoktur.
#[must_use]
pub fn repo_root() -> PathBuf {
    if let Some(dir) = option_env!("CARGO_MANIFEST_DIR") {
        let manifest = Path::new(dir);
        if let Some(root) = manifest.parent().and_then(Path::parent) {
            if root.join("Cargo.toml").is_file() {
                return root.to_path_buf();
            }
        }
    }
    let mut cur = std::env::current_dir().expect("calisma dizini okunamadi");
    loop {
        if cur.join("Cargo.toml").is_file() && cur.join("src").is_dir() {
            return cur;
        }
        if !cur.pop() {
            return std::env::current_dir().expect("calisma dizini okunamadi");
        }
    }
}

/// Bir komutu calistir, cikis kodunu **kaybetmeden** don.
///
/// Shell'de bunun karsiligi `cmd || true` ya da `cmd; RC=$?` idi ve ikisi de
/// kolayca yanlis yaziliyor: ilki hatayi yutar, ikincisi araya bir komut
/// girdiginde `$?`'i kaybeder. Burada cikis kodu bir donus degeri, bir yan
/// etki degil.
///
/// # Errors
///
/// Surec baslatilamazsa (`ENOENT` dahil) hata doner. Sureç calisip sifirdan
/// farkli donerse bu **hata degildir**: cikis kodu `Ok` icinde doner ve
/// karari cagiran verir.
pub fn run_capturing_status(program: &str, args: &[&str], cwd: &Path) -> Result<i32, String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .map_err(|e| format!("`{program}` calistirilamadi: {e}"))?;
    // 128+signal, bir sinyalle olen surecin kabuk karsiligi. Kod yoksa
    // sureci bir sinyal oldurmustur ve bunu 0 saymak yanlis olur.
    Ok(status.code().unwrap_or(-1))
}

/// Bir komutu calistir; sifirdan farkli cikis bir hatadir.
///
/// # Errors
///
/// Surec baslatilamazsa ya da sifirdan farkli donerse.
pub fn run_checked(program: &str, args: &[&str], cwd: &Path) -> Result<(), String> {
    let code = run_capturing_status(program, args, cwd)?;
    if code == 0 {
        Ok(())
    } else {
        Err(format!("`{program} {}` cikis kodu {code}", args.join(" ")))
    }
}

/// Bir programin `PATH`'te olup olmadigini soyle.
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
            "kok bir manifest tasimali: {}",
            root.display()
        );
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_silent_zero() {
        let err = run_capturing_status("budlum-bu-program-yok", &[], Path::new("."))
            .expect_err("olmayan bir program hata dondurmeli");
        assert!(
            err.contains("calistirilamadi"),
            "hata sebebini soylemeli: {err}"
        );
    }

    #[test]
    fn a_nonzero_exit_is_returned_not_swallowed() {
        // `false` her POSIX sisteminde 1 doner. Shell'de `false || true`
        // yazmak bu bilgiyi kaybettiriyordu.
        let code =
            run_capturing_status("false", &[], Path::new(".")).expect("`false` calistirilabilmeli");
        assert_eq!(code, 1, "cikis kodu korunmali");
    }

    #[test]
    fn run_checked_refuses_a_nonzero_exit() {
        let err = run_checked("false", &[], Path::new(".")).expect_err("1 kabul edilmemeli");
        assert!(err.contains("cikis kodu 1"), "kodu soylemeli: {err}");
    }

    #[test]
    fn has_program_finds_a_shell_builtin_binary() {
        assert!(has_program("sh"), "`sh` her POSIX sisteminde PATH'te");
        assert!(!has_program("budlum-bu-program-yok"));
    }
}
