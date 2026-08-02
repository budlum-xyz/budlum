//! Fiat-Shamir binding order in the in-tree STARK.
//!
//! Six zkVMs were found in March 2026 to share one root cause: a
//! prover-controlled value that affects a verification equation was not
//! absorbed into the transcript before the challenges were derived. With the
//! challenges fixed independently of that value, a malicious prover picks the
//! value *after* seeing them and solves for one that satisfies the check. The
//! fix in every case was one or two lines; finding it meant asking, of each
//! input, "what if the prover chose this after the challenge?"
//!
//! `bud_stark` is our own verifier, not a dependency, so that question applies
//! here directly. It is currently answered correctly:
//!
//!   prover.rs:184    challenger.observe_slice(public_values);
//!   prover.rs:223    let alpha = challenger.sample_algebra_element();
//!
//!   verifier.rs:352  challenger.observe_slice(public_values);
//!   verifier.rs:356  let rand_1 = challenger.sample_algebra_element();
//!
//! Public values go in before any challenge comes out, on both sides, and the
//! instance data and commitments precede them in the same order.
//!
//! Nothing was pinning that. These tests read both files and fail if the
//! observe/sample order changes, because the change that breaks soundness here
//! is a *reordering* - it compiles, every existing test passes, and proofs
//! still verify against an honest prover. Only a malicious prover notices.
//!
//! The permutation challenges (rand_1..3) are also derived after the public
//! values, and alpha and zeta after their respective commitments; a
//! source-level check is the only thing that can catch those moving without a
//! full adversarial prover harness.

const PROVER: &str = include_str!("../src/bud_stark/prover.rs");
const VERIFIER: &str = include_str!("../src/bud_stark/verifier.rs");

/// Strip line comments so prose describing an ordering cannot satisfy a check
/// about the ordering.
fn code(body: &str) -> Vec<&str> {
    body.lines()
        .map(|l| match l.find("//") {
            Some(at) => &l[..at],
            None => l,
        })
        .collect()
}

/// Index of the first line containing `needle`, ignoring comments.
fn first(body: &str, needle: &str) -> usize {
    code(body)
        .iter()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| {
            panic!(
                "expected to find `{needle}` in the source; it was removed or \
                 renamed, which is itself the thing this test guards"
            )
        })
}

#[test]
fn prover_absorbs_public_values_before_sampling_any_challenge() {
    let observed = first(PROVER, "observe_slice(public_values)");
    let first_sample = first(PROVER, "sample_algebra_element()");
    assert!(
        observed < first_sample,
        "the prover samples a challenge at line {} before absorbing the public \
         values at line {}. That is the exact shape of the soundness bug found \
         in six zkVMs in March 2026: a challenge independent of a value the \
         prover controls lets the prover choose the value afterwards",
        first_sample + 1,
        observed + 1
    );
}

#[test]
fn verifier_absorbs_public_values_before_sampling_any_challenge() {
    let observed = first(VERIFIER, "observe_slice(public_values)");
    let first_sample = first(VERIFIER, "sample_algebra_element()");
    assert!(
        observed < first_sample,
        "the verifier samples a challenge at line {} before absorbing the \
         public values at line {}",
        first_sample + 1,
        observed + 1
    );
}

/// Prover and verifier must absorb the same things in the same order, or they
/// derive different challenges and an honest proof stops verifying, the
/// failure is loud. The dangerous case is the reverse: an item dropped from
/// *both* sides stays quiet and stops binding anything.
#[test]
fn both_sides_absorb_the_same_items_before_the_first_challenge() {
    // Classifying each observe line and comparing the two lists position by
    // position was the first attempt, and it does not survive contact with the
    // source: the verifier wraps one call across two lines, and joining lines
    // to compensate double-counts the neighbours. The property that actually
    // matters is not the formatting - it is that each item is absorbed on both
    // sides, and that public_values is absorbed last of them, immediately
    // before the challenges.
    let absorbed_before_first_challenge = |body: &str, needle: &str| -> bool {
        let lines = code(body);
        let stop = lines
            .iter()
            .position(|l| l.contains("sample_algebra_element()"))
            .expect("a challenge must be sampled somewhere");
        lines[..stop]
            .iter()
            .any(|l| l.contains("challenger.observe") && l.contains(needle))
            // A wrapped call: `observe(` on one line, the argument on the next.
            || lines[..stop].windows(2).any(|w| {
                w[0].contains("challenger.observe") && w[1].contains(needle)
            })
    };

    // `security_parameters` is in this list for the same reason the others
    // are, and it was the last one missing. The FRI parameters decide the
    // soundness error and the grinding cost: measured, the current set is
    // roughly 316 bits, and `num_queries = 1` with `log_blowup = 1` and no
    // grinding is one bit and produces a proof of the same shape. Least
    // Authority's Plonky3 audit found exactly this, a challenger that absorbed
    // neither the FRI config nor the degree. Our degrees were already here.
    for item in [
        "degree",
        "preprocessed_width",
        "security_parameters",
        "trace",
        "public_values",
    ] {
        for (name, body) in [("prover", PROVER), ("verifier", VERIFIER)] {
            assert!(
                absorbed_before_first_challenge(body, item),
                "{name} no longer absorbs `{item}` before the first challenge. \
                 A value the prover controls that is not in the transcript when \
                 the challenge is drawn can be chosen afterwards to satisfy it"
            );
        }
    }

    // public_values must be the *last* thing absorbed before the challenges.
    // Anything absorbed after it would be outside the binding that the six-zkVM
    // findings were all about.
    for (name, body) in [("prover", PROVER), ("verifier", VERIFIER)] {
        let lines = code(body);
        let stop = lines
            .iter()
            .position(|l| l.contains("sample_algebra_element()"))
            .expect("a challenge must be sampled somewhere");
        let pv = lines[..stop]
            .iter()
            .position(|l| l.contains("observe_slice(public_values)"))
            .expect("public_values must be absorbed");
        let later_observe = lines[pv + 1..stop]
            .iter()
            .position(|l| l.contains("challenger.observe"));
        assert!(
            later_observe.is_none(),
            "{name} absorbs something at line {} after public_values and before \
             the first challenge; keep public_values last so the transcript \
             order is the same on both sides by construction",
            pv + 2 + later_observe.unwrap()
        );
    }
}

/// alpha folds the constraints; it must come after the commitments it folds
/// over are fixed. zeta is the out-of-domain point; it must come after the
/// quotient commitment, or the prover picks a quotient that matches the point.
#[test]
fn alpha_and_zeta_follow_their_commitments() {
    for (name, body) in [("prover", PROVER), ("verifier", VERIFIER)] {
        // Must be the *observe* of the quotient commitment, not the first
        // textual mention: both files name `quotient_chunks` in a `use` line
        // near the top, and matching that would make the ordering assertion
        // trivially true.
        let quotient = code(body)
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                l.contains("challenger.observe")
                    && (l.contains("quotient_chunks") || l.contains("quotient_commit"))
            })
            .map(|(i, _)| i)
            .next()
            .unwrap_or_else(|| {
                panic!("{name}: the quotient commitment is no longer absorbed into the transcript")
            });
        let zeta = code(body)
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("zeta") && l.contains("sample_algebra_element()"))
            .map(|(i, _)| i)
            .next()
            .unwrap_or_else(|| panic!("{name}: zeta is no longer sampled"));
        assert!(
            quotient < zeta,
            "{name}: zeta is sampled at line {} before the quotient commitment \
             is absorbed at line {}. The out-of-domain point must not be \
             predictable to whoever builds the quotient",
            zeta + 1,
            quotient + 1
        );
    }
}
