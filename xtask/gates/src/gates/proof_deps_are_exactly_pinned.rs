//! Kanit sisteminin bagimliliklari tam surumle sabitlenir.
//!
//! `p3-*` crate'leri kanitin **soundness'ini** tasir: meydan okuma turetimi,
//! FRI, taahhut semasi. Bu ailede bir yama surumu, "hata duzeltmesi" degil
//! cogu zaman bir **guvenlik sinirinin** yeri degismesi demektir. Somut ornek:
//! CVE-2026-46654, `MultiField32Challenger`'da transcript malleability -
//! `< 0.4.3` ve `>= 0.5.0, < 0.5.3` etkilenmis, yama 0.4.3 ve 0.5.3.
//!
//! Caret (`"0.6"`) yazmak, "0.6.x ailesinden herhangi biri" demektir. Lock
//! dosyasi bugun 0.6.3'u tutuyor, ama lock'un yenilendigi her an - bir
//! `cargo update`, bir bagimlilik cakismasi, CI'da lock'suz bir kurulum -
//! secilen surum **sessizce** kayar. Kaydigi yer daha yeni bir surumdur ve
//! genelde iyidir; sorun "genelde"nin bir guvenlik sinirinda yeterli
//! olmamasi. Kanit sisteminin surumu, kanitin ne kanitladiginin parcasidir:
//! hangi kodun uretip dogruladigini bilmeden, dogrulanan seyi bilmiyoruz.
//!
//! Kapi `=x.y.z` biciminde tam pin arar. Yukseltme yasak degil - yukseltmenin
//! **gorunur** olmasi sart: manifestte tek satirlik bir degisiklik, code
//! review'da okunan bir satir.

use std::fmt::Write as _;
use std::path::Path;

/// Kanit sisteminin surumune bagli oldugu manifestler.
const MANIFESTS: &[&str] = &["budzero/bud-proof/Cargo.toml"];

/// Tam pin gerektiren bagimlilik onekleri.
///
/// `p3-*`: Plonky3 ailesi, yukaridaki gerekce. Liste onek olarak tutuluyor ki
/// aileye yeni bir crate eklendiginde kapi onu kendiliginden kapsasin -
/// muafiyet eklemek icin bilincli bir edit gerekir, unutmak yeterli olmaz.
const PINNED_PREFIXES: &[(&str, &str)] = &[(
    "p3-",
    "kanitin soundness'ini tasiyan Plonky3 crate'i (CVE-2026-46654 bu ailede)",
)];

/// Bir manifest satirindan `(ad, surum-ifadesi)` cikar.
///
/// Yalnizca `ad = "surum"` bicimindeki kisa yazim ele alinir; tablo bicimi
/// (`ad = { version = "..." }`) da yakalanir cunku aranan sey satirdaki
/// surum dizgisidir.
fn dependency(line: &str) -> Option<(&str, &str)> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    let (name, rest) = t.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    let rest = rest.trim();
    // Kisa yazim: ad = "0.6"
    let version = if let Some(v) = rest.strip_prefix('"') {
        v.split('"').next()?
    } else if rest.starts_with('{') {
        // Tablo yazimi: ad = { version = "0.6", ... }
        let v = rest.split("version").nth(1)?;
        v.split('"').nth(1)?
    } else {
        return None;
    };
    Some((name, version))
}

/// # Errors
///
/// Kapsanan bir bagimlilik tam surumle sabitlenmemisse.
pub fn run(root: &Path) -> Result<String, String> {
    let mut checked = 0usize;
    let mut problems = String::new();

    for manifest in MANIFESTS {
        let path = root.join(manifest);
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{manifest} okunamadi: {e}"))?;
        for line in text.lines() {
            let Some((name, version)) = dependency(line) else {
                continue;
            };
            let Some((_, why)) = PINNED_PREFIXES
                .iter()
                .find(|(prefix, _)| name.starts_with(prefix))
            else {
                continue;
            };
            checked += 1;
            if !version.starts_with('=') {
                let _ = write!(
                    problems,
                    "\n  {manifest}: `{name} = \"{version}\"` tam pin degil. \
                     {why}; caret bir yama surumunun sessizce degismesine izin verir \
                     ve kanit sisteminin surumu kanitin ne kanitladiginin parcasidir. \
                     `=` ile yazin (ornek: `{name} = \"={}\"`)",
                    version.trim_start_matches(['^', '~', '=']),
                );
            }
        }
    }

    if !problems.is_empty() {
        return Err(format!("proof-deps-are-exactly-pinned:{problems}"));
    }
    if checked == 0 {
        return Err(
            "proof-deps-are-exactly-pinned: kapsanan bagimlilik bulunamadi. \
             Kapi korlesmis - manifest tasindiysa MANIFESTS guncellenmeli."
                .into(),
        );
    }
    Ok(format!(
        "proof-deps-are-exactly-pinned OK: {checked} kanit bagimliligi tam surumle sabit"
    ))
}

/// # Errors
///
/// Kapi caret veya tilde yazimini tam pinden ayirt edemezse.
pub fn self_test() -> Result<String, String> {
    let cases = [
        ("p3-fri = \"=0.6.3\"", Some(("p3-fri", "=0.6.3"))),
        ("p3-fri = \"0.6\"", Some(("p3-fri", "0.6"))),
        ("p3-fri = \"^0.6\"", Some(("p3-fri", "^0.6"))),
        (
            "p3-air = { version = \"0.6\", features = [] }",
            Some(("p3-air", "0.6")),
        ),
        ("# p3-fri = \"0.6\"", None),
        ("[dependencies]", None),
    ];
    for (line, want) in cases {
        if dependency(line) != want {
            return Err(format!(
                "self_test: `{line}` icin {want:?} beklenirdi, {:?} cikti",
                dependency(line)
            ));
        }
    }
    let pinned = dependency("p3-fri = \"=0.6.3\"").ok_or("self_test: pin ayristirilamadi")?;
    if !pinned.1.starts_with('=') {
        return Err("self_test: tam pin `=` ile baslamiyor sayildi".into());
    }
    let loose = dependency("p3-fri = \"0.6\"").ok_or("self_test: caret ayristirilamadi")?;
    if loose.1.starts_with('=') {
        return Err("self_test: caret yazimi tam pin sayildi".into());
    }
    Ok("proof-deps-are-exactly-pinned self-test OK: caret, tilde, tablo yazimi ve yorum ayirt ediliyor".into())
}
