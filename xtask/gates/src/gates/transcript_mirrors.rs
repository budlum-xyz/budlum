//! Do the prover and the verifier build the same transcript?
//!
//! In Fiat-Shamir the challenges are derived from everything absorbed so far.
//! If the two sides do not absorb the same things **in the same order** they do not produce the
//! same challenges; either no valid proof verifies (a noticeable failure) or
//! -tehlikeli olani- bir taraf otekinin bagladigi bir seyi **atlar** ve o alan
//! it stops being bound to the challenge. Over the skipped field an attacker
//! serbesttir: CVE-2026-46654 ve gnark'in Last Challenge Attack'i bu sinifin
//! iki ornegi.
//!
//! Bugun bu aynalama iki dosyanin yorumlarinda anlatiliyor ("the verifier
//! absorbs the same slice at the same point") and **nothing enforces it**.
//! Adding an absorption on one side and forgetting the other is a silent
//! degisikliktir: kod derlenir, testler kosar, transcript ayrisir.
//!
//! Kapi iki dosyadaki emilim dizisini cikarir ve karsilastirir. Karsilastirdigi
//! is **order and kind**, not variable names: the same kind of absorption in the same order.
//!
//! # Neden kaynak okuyarak
//!
//! Measuring at run time means running both sides, that is producing and verifying a full
//! proof; that is already the job of the tests and it is expensive. The question here is
//! narrower: **do the two lists have the same shape?** That question can be answered in the source and
//! saniyeler surer.
//!
//! # Ne yakalamaz
//!
//! It does not check the correctness of the absorbed **value** - if both sides absorb the wrong
//! thing in the same order the gate stays silent. What it catches is divergence, and divergence is this family's
//! bilinen giris kapisi.

use std::path::Path;

const PROVER: &str = "budzero/bud-proof/src/bud_stark/prover.rs";
const VERIFIER: &str = "budzero/bud-proof/src/bud_stark/verifier.rs";

/// Bir emilim cagrisinin turu.
///
/// The **shape** is kept, not the name: `observe` or `observe_slice`, and over
/// what. The same value may be held under different local names on the two sides
/// (`trace_commit` versus `commitments.trace`), but the order and kind of absorption must be the
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

/// Extract the absorption sequence from a file.
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
             The gate may have gone blind - if the call shape changed the gate must be updated too.",
            pa.len(),
            va.len()
        ));
    }

    if pa.len() != va.len() {
        return Err(format!(
            "transcript-mirrors: kanitlayici {} emilim yapiyor, dogrulayici {}. \
             Bir tarafta olup otekinde olmayan her emilim, o alani meydan \
             resolves without reading and leaves an attacker free over it.\n  \
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
                 Order is Fiat-Shamir itself: absorbing the same things in a different \
                 order means producing different challenges."
            ));
        }
    }

    Ok(format!(
        "transcript-mirrors OK: the prover and the verifier perform {} absorptions in the same order and of the same kind",
        pa.len()
    ))
}

/// # Errors
///
/// If the gate itself stays silent over a diverged sequence.
pub fn self_test() -> Result<String, String> {
    let good = r"
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe_slice(&config.security_parameters());
        challenger.observe(trace_commit.clone());
    ";
    // One absorption is missing: the gate must see it.
    let short = r"
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe(trace_commit.clone());
    ";
    // The order changed: the gate must see that too.
    let swapped = r"
        challenger.observe_slice(&config.security_parameters());
        challenger.observe(Val::<SC>::from_u8(log_degree as u8));
        challenger.observe(trace_commit.clone());
    ";
    // An example in a comment must not shift the sequence.
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
        return Err("self_test: an example in a comment shifted the sequence".into());
    }
    Ok("transcript-mirrors self-test OK: eksik emilim, sira degisikligi ve yorum ornegi ayirt ediliyor".into())
}
