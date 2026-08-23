//! Kanitlayici ve dogrulayici ayni transcript'i kurar mi.
//!
//! Fiat-Shamir'da meydan okumalar, o ana kadar emilmis her seyden turetilir.
//! Iki taraf ayni seyleri **ayni sirada** emmezse ayni meydan okumalari
//! uretmezler; ya hicbir gecerli kanit dogrulanmaz (fark eden bir ariza) ya da
//! -tehlikeli olani- bir taraf otekinin bagladigi bir seyi **atlar** ve o alan
//! meydan okumaya bagli olmaktan cikar. Atlanan alan uzerinde saldirgan
//! serbesttir: CVE-2026-46654 ve gnark'in Last Challenge Attack'i bu sinifin
//! iki ornegi.
//!
//! Bugun bu aynalama iki dosyanin yorumlarinda anlatiliyor ("the verifier
//! absorbs the same slice at the same point") ve **hicbir sey zorlamiyor**.
//! Bir tarafa emilim eklemek, otekine eklemeyi unutmak sessiz bir
//! degisikliktir: kod derlenir, testler kosar, transcript ayrisir.
//!
//! Kapi iki dosyadaki emilim dizisini cikarir ve karsilastirir. Karsilastirdigi
//! sey **sira ve tur**, degisken adlari degil: ayni sirada ayni tur emilim.
//!
//! # Neden kaynak okuyarak
//!
//! Calisma zamaninda olcmek icin iki tarafi da kosturmak, yani tam bir kanit
//! uretip dogrulamak gerekir; o zaten testlerin isi ve pahali. Buradaki soru
//! daha dar: **iki listenin sekli ayni mi.** Bu soru kaynakta cevaplanabilir ve
//! saniyeler surer.
//!
//! # Ne yakalamaz
//!
//! Emilen **degerin** dogrulugunu denetlemez - iki taraf ayni sirada yanlis
//! seyi emiyorsa kapi susar. Yakaladigi sey ayrisma, ve ayrisma bu ailenin
//! bilinen giris kapisi.

use std::path::Path;

const PROVER: &str = "budzero/bud-proof/src/bud_stark/prover.rs";
const VERIFIER: &str = "budzero/bud-proof/src/bud_stark/verifier.rs";

/// Bir emilim cagrisinin turu.
///
/// Ad degil **sekil** tutulur: `observe` mi `observe_slice` mi, ve neyin
/// uzerinde. Iki tarafta ayni deger farkli yerel adlarla tutulabilir
/// (`trace_commit` vs `commitments.trace`), ama emilim sirasi ve turu ayni
/// olmak zorunda.
#[derive(Debug, PartialEq, Eq)]
struct Absorb {
    /// `observe` veya `observe_slice`.
    call: String,
    /// Kaba bir sinif: skaler mi, taahhut mu, dilim mi.
    shape: &'static str,
}

fn classify(arg: &str) -> &'static str {
    let a = arg.trim();
    if a.contains("from_u8") || a.contains("from_usize") || a.contains("from_canonical") {
        "scalar"
    } else if a.contains("security_parameters") {
        "security-params"
    } else if a.contains("public_values") {
        "public-values"
    } else {
        // Geri kalan her sey bir taahhut (Merkle koku): trace, preprocessed,
        // aux, quotient, random.
        "commitment"
    }
}

/// Bir dosyadan emilim dizisini cikar.
///
/// Yalnizca `challenger.observe...` cagrilari sayilir ve **yorum satirlari
/// atlanir**: bir yorumda gecen `challenger.observe(...)` ornegi diziyi
/// kaydirirdi.
fn absorptions(text: &str) -> Vec<Absorb> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") || t.starts_with("///") {
            continue;
        }
        let Some(idx) = t.find("challenger.observe") else {
            continue;
        };
        let rest = &t[idx + "challenger.".len()..];
        let call = if rest.starts_with("observe_slice") {
            "observe_slice"
        } else if rest.starts_with("observe(") {
            "observe"
        } else {
            continue;
        };
        let arg = rest
            .split_once('(')
            .map(|(_, a)| a)
            .unwrap_or_default()
            .trim_end_matches(");")
            .trim_end_matches(')');
        out.push(Absorb {
            call: call.to_string(),
            shape: classify(arg),
        });
    }
    out
}

/// # Errors
///
/// Iki dosyanin emilim dizileri uzunlukta veya sirada ayrisirsa.
pub fn run(root: &Path) -> Result<String, String> {
    let p = std::fs::read_to_string(root.join(PROVER))
        .map_err(|e| format!("{PROVER} okunamadi: {e}"))?;
    let v = std::fs::read_to_string(root.join(VERIFIER))
        .map_err(|e| format!("{VERIFIER} okunamadi: {e}"))?;

    let pa = absorptions(&p);
    let va = absorptions(&v);

    if pa.is_empty() || va.is_empty() {
        return Err(format!(
            "transcript-mirrors: emilim bulunamadi (kanitlayici {}, dogrulayici {}). \
             Kapi korlesmis olabilir - cagri sekli degistiyse kapi da guncellenmeli.",
            pa.len(),
            va.len()
        ));
    }

    if pa.len() != va.len() {
        return Err(format!(
            "transcript-mirrors: kanitlayici {} emilim yapiyor, dogrulayici {}. \
             Bir tarafta olup otekinde olmayan her emilim, o alani meydan \
             okumadan cozer ve uzerinde saldirgani serbest birakir.\n  \
             prover:   {pa:?}\n  verifier: {va:?}",
            pa.len(),
            va.len()
        ));
    }

    for (i, (a, b)) in pa.iter().zip(va.iter()).enumerate() {
        if a != b {
            return Err(format!(
                "transcript-mirrors: {i}. emilim ayrisiyor.\n  \
                 prover:   {a:?}\n  verifier: {b:?}\n  \
                 Sira Fiat-Shamir'in kendisidir: ayni seyleri farkli sirada \
                 emmek, farkli meydan okumalar uretmektir."
            ));
        }
    }

    Ok(format!(
        "transcript-mirrors OK: kanitlayici ve dogrulayici {} emilimi ayni sirada ve ayni turde yapiyor",
        pa.len()
    ))
}

/// # Errors
///
/// Kapinin kendisi ayrismis bir dizi uzerinde susarsa.
pub fn self_test() -> Result<String, String> {
    let good = r"
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe_slice(&config.security_parameters());
        challenger.observe(trace_commit.clone());
    ";
    // Bir emilim eksik: kapi bunu gormeli.
    let short = r"
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe(trace_commit.clone());
    ";
    // Sira degismis: kapi bunu da gormeli.
    let swapped = r"
        challenger.observe_slice(&config.security_parameters());
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe(trace_commit.clone());
    ";
    // Yorumdaki bir ornek diziyi kaydirmamali.
    let commented = r"
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        // challenger.observe(bir_ornek);
        challenger.observe_slice(&config.security_parameters());
        challenger.observe(trace_commit.clone());
    ";

    let g = absorptions(good);
    if g.len() != 3 {
        return Err(format!(
            "self_test: 3 emilim beklenirdi, {} bulundu",
            g.len()
        ));
    }
    if absorptions(short).len() == g.len() {
        return Err("self_test: eksik emilim fark edilmedi".into());
    }
    if absorptions(swapped) == g {
        return Err("self_test: sira degisikligi fark edilmedi".into());
    }
    if absorptions(commented) != g {
        return Err("self_test: yorumdaki ornek diziyi kaydirdi".into());
    }
    Ok("transcript-mirrors self-test OK: eksik emilim, sira degisikligi ve yorum ornegi ayirt ediliyor".into())
}
