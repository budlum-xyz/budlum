//! Do the prover and the verifier build the same transcript?
//!
//! In Fiat-Shamir the challenges are derived from everything absorbed so far.
//! If the two sides do not absorb the same things **in the same order** they do not produce the
//! same challenges; either no valid proof verifies (a noticeable failure) or,
//! the dangerous one, one side **skips** something the other binds, and that
//! field stops being bound to the challenge. Over the skipped field an attacker
//! is free: CVE-2026-46654 and gnark's Last Challenge Attack are two examples
//! of this class.
//!
//! Today that mirroring is described in the comments of two files ("the verifier
//! absorbs the same slice at the same point") and **nothing enforces it**.
//! Adding an absorption on one side and forgetting the other is a silent
//! change: the code compiles, the tests pass, and the transcripts drift
//! apart.
//!
//! The gate extracts the absorption sequence from both files and compares
//! them. What it compares is **order and kind**, not variable names: the same
//! kind of absorption in the same order.
//!
//! # Why by reading the source
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
//! a known entry point.

use std::path::Path;

const PROVER: &str = "budzero/bud-proof/src/bud_stark/prover.rs";
const VERIFIER: &str = "budzero/bud-proof/src/bud_stark/verifier.rs";

/// The kind of an absorption call.
///
/// The **shape** is kept, not the name: `observe` or `observe_slice`, and over
/// what. The same value may be held under different local names on the two sides
/// (`trace_commit` versus `commitments.trace`), but the order and kind of the
/// absorptions have to be identical.
#[derive(Debug, PartialEq, Eq)]
struct Absorb {
    /// `observe` or `observe_slice`.
    call: String,
    /// A coarse class: scalar, commitment or slice.
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
        // Everything else is a commitment (a Merkle root): trace, preprocessed,
        // aux, quotient, random.
        "commitment"
    }
}

/// Extract the absorption sequence from a file.
///
/// Only `challenger.observe...` calls are counted, and **comment lines are
/// skipped**: a `challenger.observe(...)` example inside a comment would shift
/// the sequence.
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
/// When the two files' absorption sequences differ in length or order.
pub fn run(root: &Path) -> Result<String, String> {
    let p = std::fs::read_to_string(root.join(PROVER))
        .map_err(|e| format!("could not read {PROVER}: {e}"))?;
    let v = std::fs::read_to_string(root.join(VERIFIER))
        .map_err(|e| format!("could not read {VERIFIER}: {e}"))?;

    let pa = absorptions(&p);
    let va = absorptions(&v);

    if pa.is_empty() || va.is_empty() {
        return Err(format!(
            "transcript-mirrors: no absorption was found (prover {}, verifier {}). \
             The gate may have gone blind - if the call shape changed the gate must be updated too.",
            pa.len(),
            va.len()
        ));
    }

    if pa.len() != va.len() {
        return Err(format!(
            "transcript-mirrors: the prover makes {} absorptions and the verifier {}. \
             Every absorption present on one side and missing on the other is a field the \
             challenge resolves without reading, and leaves an attacker free over it.\n  \
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
        // challenger.observe(an_example);
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
        return Err("self_test: a missing absorption went unnoticed".into());
    }
    if absorptions(swapped) == g {
        return Err("self_test: a change of order went unnoticed".into());
    }
    if absorptions(commented) != g {
        return Err("self_test: an example in a comment shifted the sequence".into());
    }
    Ok(
        "transcript-mirrors self-test OK: a missing absorption, a change of order and an example \
         in a comment are all told apart"
            .into(),
    )
}
