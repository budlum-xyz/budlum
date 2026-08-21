//! Push oncesi yerel dogrulama.
//!
//! `scripts/pre-push-check.sh` yerine gecer.
//!
//! # Shell surumunun iki sorunu
//!
//! 1. `set -e` altinda ilk hata betigi durduruyordu, yani `cargo fmt`
//!    dustugunde clippy **hic kosmuyordu**. Gelistirici bir hatayi
//!    duzeltip tekrar kosuyor, ikinciyi goruyor, tekrar kosuyordu. Burada
//!    her kontrol kosuyor ve hepsi birden raporlaniyor.
//! 2. Betik hangi toolchain'le kostugunu soylemiyordu. `rust-toolchain.toml`
//!    1.97.0'i pinliyor ama gelistiricinin varsayilani baska olabilir; o
//!    zaman yerel `cargo fmt` gecer, CI kirmizi doner. Bu, gecmis notlarda
//!    kayitli "toolchain drift" sinifi. Burada surum once yazdiriliyor.

use std::path::Path;

use crate::{run_capturing_status, run_checked};

/// Bir kontrolun sonucu.
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
/// Bir kontrol dustugunde, hangilerinin dustugunu soyleyen bir hata doner.
pub fn run(root: &Path) -> Result<String, String> {
    let mut lines = Vec::new();

    // Once toolchain: yerel ile CI ayni degilse fmt/clippy farkli karar
    // verir ve bu, gecmiste yesil yerel + kirmizi CI olarak goruldu.
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
        lines.push("Tum kontroller gecti; push guvenli.".to_string());
        Ok(lines.join("\n"))
    } else {
        Err(format!(
            "{}\nDusen kontrol(ler): {}. \
             Ikisi de kosuldu, yani listedeki her sey gercek bir bulgu.",
            lines.join("\n"),
            failed.join(", ")
        ))
    }
}

/// Kanarya: `cargo fmt`'in bozuk bicimli bir dosyayi gercekten reddettigini
/// kanitlar.
///
/// Bu bos bir titizlik degil. Kontrol "kostu ve 0 dondu" ile "hic kosmadi ve
/// 0 dondu" disaridan ayni gorunur; shell surumunde tam olarak bu risk
/// vardi. Burada bilerek bozuk bir dosya uretilip reddedildigi gosteriliyor.
///
/// # Errors
///
/// `cargo fmt` bozuk bir dosyayi kabul ederse.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-prepush-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("src")).map_err(|e| format!("kanarya dizini: {e}"))?;

    std::fs::write(
        tmp.join("Cargo.toml"),
        "[package]\nname = \"fmt-canary\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .map_err(|e| format!("kanarya manifesti: {e}"))?;

    // Bilerek bozuk bicim: rustfmt bunu kesin degistirir.
    std::fs::write(
        tmp.join("src").join("main.rs"),
        "fn main(){let x=1;let y=2;println!(\"{}\",x+y);}\n",
    )
    .map_err(|e| format!("kanarya kaynagi: {e}"))?;

    let code = run_capturing_status("cargo", &["fmt", "--", "--check"], &tmp)?;
    let _ = std::fs::remove_dir_all(&tmp);

    if code == 0 {
        return Err(
            "KANARYA DUSTU: `cargo fmt --check` bilerek bozulmus bir dosyayi kabul etti; \
             bu kontrol hicbir seye bakmiyor."
                .to_string(),
        );
    }
    Ok("pre-push kanaryasi OK: bozuk bicim reddedildi, kontrol gercekten kosuyor".to_string())
}

/// Git `pre-push` kancasini kur.
///
/// Shell surumunde bu adim yoktu: betik vardi ama onu kimse cagirmiyordu,
/// yani bir kapinin degil bir onerinin karsiligiydi.
///
/// # Errors
///
/// `.git/hooks` yoksa ya da kanca yazilamazsa.
pub fn install_hook(root: &Path) -> Result<String, String> {
    let hooks = root.join(".git").join("hooks");
    if !hooks.is_dir() {
        return Err(format!(
            "{} yok; bu bir git calisma agaci degil",
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
        let err = install_hook(&tmp).expect_err("git olmayan agac reddedilmeli");
        assert!(err.contains("git calisma agaci degil"), "{err}");
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
        assert!(hook.is_file(), "kanca dosyasi olmali");
        let body = std::fs::read_to_string(&hook).expect("kanca okunmali");
        assert!(
            body.contains("budlum-tools"),
            "kanca araci cagirmali: {body}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&hook)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o111, "kanca calistirilabilir olmali");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
