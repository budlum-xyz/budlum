//! cargo-vet unvetted-dependency count ratchet.
//!
//! Ported from `scripts/check-cargo-vet.sh`. Runs `cargo vet check`, reads the
//! `<N> unvetted dependencies` count from its output, and fails when the
//! count exceeds `.github/cargo-vet-baseline.txt`. The count may fall (the
//! baseline is tightened in a deliberate PR), never rise.

use std::path::Path;

fn baseline(root: &Path) -> Result<u64, String> {
    let f = root.join(".github/cargo-vet-baseline.txt");
    let text = std::fs::read_to_string(&f)
        .map_err(|e| format!("baseline okunamadı ({}): {e}", f.display()))?;
    text.lines()
        .find(|l| l.chars().all(|c| c.is_ascii_digit()) && !l.is_empty())
        .ok_or_else(|| format!("baseline okunamadı ({})", f.display()))?
        .parse::<u64>()
        .map_err(|e| format!("baseline sayı değil: {e}"))
}

fn count_from_output(out: &str) -> Option<u64> {
    out.lines().find_map(|l| {
        let t = l.trim_start();
        // The count is the leading run of digits.
        let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let rest = &t[digits.len()..];
        if rest.starts_with(" unvetted dependencies") {
            digits.parse().ok()
        } else {
            None
        }
    })
}

/// `cargo vet` prints this exact line when nothing is unvetted, and prints no
/// count at all. That is the only shape allowed to mean zero: any other
/// countless output is an unfinished scan, not a clean one.
fn is_clean_report(out: &str) -> bool {
    out.lines().any(|l| l.trim() == "Vetting Succeeded!")
}

/// Run `cargo vet check` in the repo root and return its stdout/stderr.
///
/// A spawn failure is an error, not text. The previous shape turned
/// "cargo vet çalışmadı: ..." into a normal report string, which then parsed
/// as zero unvetted dependencies and passed the gate. A gate that reports
/// clean when its scanner never ran proves nothing.
fn run_vet(root: &Path) -> Result<String, String> {
    let out = std::process::Command::new("cargo")
        .args(["vet", "check"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo vet çalışmadı: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

/// `cargo-vet` is a separate binary, and Repo Lint does not install it.
///
/// Cargo answers a missing subcommand with "no such command: vet". That is
/// not an unfinished scan, it is *no* scan: the gate has nothing to judge and
/// no evidence that anything is wrong. Treating it as a finding made the
/// dedicated Cargo Vet job the second place this gate ran, and the only place
/// it could pass - so Repo Lint failed on every push for a tool it never
/// installs.
///
/// The distinction that matters: a *missing tool* is skipped, a tool that
/// *ran and produced an unreadable report* is still a hard failure. The
/// second case is the fail-open hole this gate exists to close.
fn tool_is_absent(out: &str) -> bool {
    out.lines()
        .any(|l| l.contains("no such command") && l.contains("vet"))
}

/// # Errors
///
/// Returns a finding when the unvetted count exceeds the baseline.
pub fn run(root: &Path) -> Result<String, String> {
    let base = baseline(root)?;
    let output = run_vet(root)?;
    if tool_is_absent(&output) {
        return Ok(String::from(
            "ATLANDI: cargo-vet bu işte kurulu değil; ratchet kararını\n\
             ayrılmış `Cargo Vet` işi veriyor (cargo-vet.yml). Aracın\n\
             yokluğu bulgu değildir - çalışıp okunamayan rapor üretmesi\n\
             hâlâ sert hatadır.",
        ));
    }
    let n = match count_from_output(&output) {
        Some(n) => n,
        None if is_clean_report(&output) => 0,
        None => {
            return Err(format!(
                "cargo-vet çıktısı ne denetimsiz bağımlılık sayısı ne de\n\
                 'Vetting Succeeded!' satırı içeriyor; tarama tamamlanmamış\n\
                 sayılır ve kapı bu çıktıyı temiz kabul etmez:\n{output}"
            ));
        }
    };
    let msg = format!("cargo-vet denetimsiz bağımlılık: {n} | baseline: {base}");
    if n > base {
        return Err(format!(
            "{msg}\nFAIL: denetimsiz bağımlılık sayısı baseline'ı aştı (+{}).\n      Yeni bir bağımlılık eklendiyse: ya güvenilir bir import kaynağı\n      onu kapsamalı, ya `cargo vet certify` ile gerekçeli denetim\n      kaydı girilmeli. Baseline'ı YÜKSELTMEK bir çözüm değildir.",
            n - base
        ));
    }
    if n < base {
        return Ok(format!(
            "{msg}\nİYİLEŞME: baseline {base} -> {n} düşürülebilir.\n          .github/cargo-vet-baseline.txt dosyasını {n} yapın (ratchet sıkılır).\n\nOK: denetimsiz bağımlılık baseline altında/eşit (ratchet sağlam)."
        ));
    }
    Ok(format!(
        "{msg}\nOK: denetimsiz bağımlılık baseline altında/eşit (ratchet sağlam)."
    ))
}

/// # Errors
///
/// Returns a finding when the output parser misreads a known shape.
pub fn self_test() -> Result<String, String> {
    let got = count_from_output(
        "Vetting Failed!\n\n123 unvetted dependencies:\n  aead:0.5.2 missing [\"safe-to-deploy\"]",
    );
    if got != Some(123) {
        return Err(format!(
            "canary: sayaç 123 yerine '{got:?}' okudu (parse bozuk)"
        ));
    }
    // Eksik araç ile okunamayan rapor birbirine karışmamalı: ilki atlanır,
    // ikincisi kapıyı kırar. Kanarya bu ayrımı sabitliyor.
    if !tool_is_absent("error: no such command: `vet`") {
        return Err(String::from(
            "canary: eksik cargo-vet ikilisi tanınmadı (atlama kolu ölü)",
        ));
    }
    if tool_is_absent("Vetting Failed!\n\n7 unvetted dependencies:") {
        return Err(String::from(
            "canary: gerçek bir vet raporu 'araç yok' sanıldı (kapı fail-open)",
        ));
    }
    let clean = "Vetting Succeeded!";
    if count_from_output(clean).is_some() || !is_clean_report(clean) {
        return Err(String::from(
            "canary: 'Vetting Succeeded!' temiz rapor olarak tanınmadı",
        ));
    }
    // A scanner that died before saying anything must not read as zero. This
    // is the shape the gate used to accept.
    let broken = "error: no such subcommand: `vet`";
    if count_from_output(broken).is_some() || is_clean_report(broken) {
        return Err(String::from(
            "canary: bozuk tarayıcı çıktısı temiz/0 olarak okundu (fail-open)",
        ));
    }
    Ok(String::from(
        "Kanarya OK: 123 sayıldı, temiz rapor tanındı, bozuk çıktı reddedildi.",
    ))
}
