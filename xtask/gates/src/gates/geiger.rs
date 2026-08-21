//! First-party crates must show zero unsafe usage in cargo-geiger output.
//!
//! Ported from `scripts/check-geiger.sh`. The gate reads a `cargo geiger
//! --all-targets` report: lines whose crate name starts with `budlum-core` or
//! `bud-` must show a `0/N` unsafe column (the crate roots already
//! `#![forbid(unsafe_code)]`; this is the second, independent evidence
//! layer). Third-party dependencies are informational only.

use std::path::Path;

/// # Errors
///
/// Returns a finding when a first-party crate shows non-zero unsafe usage, or
/// when the report file is missing/empty.
/// The five `used/total` counters at the head of a cargo-geiger row.
fn counters(line: &str) -> impl Iterator<Item = &str> {
    line.split_whitespace()
        .take_while(|t| t.contains('/') && t.split('/').all(|p| p.parse::<u64>().is_ok()))
}

/// The first-party crate name on a cargo-geiger row, if the row names one.
///
/// A row is first-party when the token immediately before the version is
/// `budlum-core` or starts with `bud-`. Matching the version too is what keeps
/// build chatter (`Checking bud-isa v0.1.0 (/path)`) out: there the name is
/// followed by `v0.1.0`, not `0.1.0`, and it is not preceded by counters.
fn first_party_name(line: &str) -> Option<&str> {
    if counters(line).count() == 0 {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let version_at = tokens.iter().rposition(|t| {
        t.split('.').count() == 3 && t.split('.').all(|p| p.parse::<u64>().is_ok())
    })?;
    let name = tokens.get(version_at.checked_sub(1)?)?;
    // `verifier-registry` budzero'nun sekizinci uyesi ve isim kalibina
    // uymuyor; adiyla listelenmezse taranmis olmasina ragmen ucuncu taraf
    // sayilirdi.
    (*name == "budlum-core" || *name == "verifier-registry" || name.starts_with("bud-"))
        .then_some(*name)
}

pub fn run(_root: &Path, out: &Path) -> Result<String, String> {
    if !out.is_file() {
        return Err(format!("geiger çıktısı yok/boş: {}", out.display()));
    }
    let text =
        std::fs::read_to_string(out).map_err(|e| format!("cannot read {}: {e}", out.display()))?;
    let mut fp_bad = String::new();
    let mut total = 0usize;
    let mut fp_seen = 0usize;
    for line in text.lines() {
        // A cargo-geiger row leads with five unsafe counters and ends with the
        // crate name and version:
        //
        //   0/0  0/0  0/0  0/0  0/0   ?  budlum-core 0.1.0
        //
        // The ported shell gate matched on `starts_with`, which is where the
        // crate name sits in `cargo tree` output but not here - so no line
        // ever counted as first-party and the `fp_seen == 0` arm reported a
        // complete scan as a dead one. The crate name is the token before the
        // version, so that is what is read.
        let Some(crate_name) = first_party_name(line) else {
            if line
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            {
                total += 1;
            }
            continue;
        };
        let _ = crate_name;
        fp_seen += 1;
        // Counters are `used/total`; anything other than a `0/` numerator on
        // every one of them means unsafe was reached.
        if !counters(line).all(|c| c.starts_with("0/")) {
            fp_bad.push_str(line);
            fp_bad.push('\n');
        }
    }
    // A report with no first-party row is not a clean report, it is a report
    // about nothing: cargo-geiger died, or the crate names moved. The old
    // shape passed such a file, so a broken scan and a zero-unsafe scan were
    // indistinguishable at the gate.
    if fp_seen == 0 {
        return Err(format!(
            "cargo-geiger çıktısı first-party crate satırı içermiyor; tarama\n\
             tamamlanmamış sayılır ve temiz kabul edilmez:\n{text}"
        ));
    }
    if !fp_bad.is_empty() {
        return Err(format!(
            "FAIL: first-party crate'te sıfır-olmayan unsafe kullanımı (forbid(unsafe_code) ile çelişir - sahte rapor olabilir!):\n{fp_bad}"
        ));
    }
    Ok(format!(
        "OK: first-party unsafe kullanımı = 0 (forbid(unsafe_code) ile tutarlı). {total} satır inceleme (deps bilgi amaçlı):"
    ))
}

/// # Errors
///
/// Returns a finding when the canary report does not behave: a first-party
/// `2/N` line must fail, a clean report must pass.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let dir = std::env::temp_dir().join(format!(
        "budlum-gates-geiger-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let clean = dir.join("temiz.txt");
    let dirty = dir.join("kirli.txt");
    // Kanarya, cargo-geiger'in GERÇEK satır biçimini kullanır: beş sayaç,
    // sonra bir işaret sütunu, en sonda crate adı ve sürümü. Eski kanarya
    // "budlum-core 0/120" gibi uydurma bir biçim yazıyordu ve kapının
    // `starts_with` hatası tam da bu yüzden görünmüyordu - kanarya, kapının
    // sahada okuyacağı şeyi hiç sınamamıştı.
    std::fs::write(
        &clean,
        "0/0        0/0          0/0    0/0     0/0      ?  budlum-core 0.1.0\n\
         0/0        0/0          0/0    0/0     0/0      ?  bud-proof 0.1.0\n\
         26/30      2387/3011    110/119 3/3     109/139  !  tokio 1.53.1\n\
         0/46       0/500        0/0    0/0     0/0       ?  winapi 0.3.9\n",
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        &dirty,
        "2/4        7/120        0/0    0/0     0/0      !  budlum-core 0.1.0\n\
         26/30      2387/3011    110/119 3/3     109/139  !  tokio 1.53.1\n",
    )
    .map_err(|e| e.to_string())?;

    let empty = dir.join("bos.txt");
    // Sayaçsız bir satır: tarama ölmüş demektir. Crate adının metinde geçiyor
    // Olması yetmez, satırın rapor satırı olması gerekir.
    std::fs::write(&empty, "error: could not compile budlum-core\n").map_err(|e| e.to_string())?;

    let dirty_failed = run(&dir, &dirty).is_err();
    let clean_passed = run(&dir, &clean).is_ok();
    let empty_failed = run(&dir, &empty).is_err();
    let _ = std::fs::remove_dir_all(&dir);

    if !dirty_failed {
        return Err(String::from("canary: first-party unsafe (2) geçti"));
    }
    if !clean_passed {
        return Err(String::from("canary: temiz çıktı reddedildi"));
    }
    if !empty_failed {
        return Err(String::from(
            "canary: first-party satırı olmayan çıktı temiz sayıldı (fail-open)",
        ));
    }
    Ok(String::from(
        "kanarya OK: first-party unsafe FAIL, temiz PASS, satırsız çıktı FAIL.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report() {
        let dir = std::env::temp_dir().join(format!("budlum-geiger-t-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("r.txt");
        std::fs::write(
            &f,
            "0/0        0/0          0/0    0/0     0/0      ?  budlum-core 0.1.0\n\
             26/30      2387/3011    110/119 3/3     109/139  !  tokio 1.53.1\n",
        )
        .unwrap();
        assert!(run(&dir, &f).is_ok());
        std::fs::write(
            &f,
            "3/9        12/120       0/0    0/0     0/0      !  budlum-core 0.1.0\n",
        )
        .unwrap();
        assert!(run(&dir, &f).is_err());
        // Derleme gürültüsü first-party satırı sayılmaz: `Checking bud-isa
        // v0.1.0 (...)` satırında crate adı geçer ama sayaç yoktur.
        std::fs::write(
            &f,
            "    Checking bud-isa v0.1.0 (/w/budzero/bud-isa)\n    Checking bud-vm v0.1.0 (/w)\n",
        )
        .unwrap();
        assert!(
            run(&dir, &f).is_err(),
            "derleme çıktısı tamamlanmış tarama sayılmamalı"
        );
        // No first-party row at all: an unfinished scan, not a clean one.
        std::fs::write(&f, "error: linking with cc failed\n").unwrap();
        assert!(run(&dir, &f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
