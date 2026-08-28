//! Behavior evaluation: a model-agnostic correctness harness for Lubot.
//!
//! The "success" of the Lubot module must be measurable
//! ([`crate::plan`] decides *how* to train; this module decides *whether the
//! result is correct*). A [`Check`] grades a model response against golden
//! behavior; [`run_eval`] batches a set of [`EvalCase`]s through a responder
//! and returns a scored [`EvalReport`].
//!
//! It is deliberately model-agnostic: `respond` is any `Fn(&str) -> String`,
//! so the harness can grade a live model, a LoRA-adapted model, or a canned
//! fixture without owning an inference engine. The "correctness at the moment
//! of ingestion" guarantee (zkVM execution proof) is a *separate, orthogonal*
//! concern (see the BudZero/BudZKVM proof path); this module measures the
//! *behavior semantics* the proof backend cannot.

/// A single grading rule applied to a model response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The response must equal `0` exact.
    Exact(String),
    /// The response must contain every one of these substrings.
    ContainsAll(Vec<String>),
    /// The response must contain none of these substrings.
    Excludes(Vec<String>),
    /// Same as [`Check::Exact`] after trimming + collapsing whitespace.
    ExactTrimmed(String),
}

/// One evaluation example: a prompt and how to grade its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalCase {
    pub name: String,
    pub prompt: String,
    pub check: Check,
}

impl EvalCase {
    /// Build an [`EvalCase`] that grades a golden answer exactly.
    #[must_use]
    pub fn exact(name: impl Into<String>, prompt: impl Into<String>, golden: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            prompt: prompt.into(),
            check: Check::Exact(golden.into()),
        }
    }
}

/// The outcome of grading a single response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Pass,
    Fail { reason: String },
}

impl Check {
    /// Grade `response`.
    #[must_use]
    pub fn apply(&self, response: &str) -> CheckOutcome {
        match self {
            Check::Exact(expected) => {
                if response == expected {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail {
                        reason: format!("expected exact {:?}, got {:?}", expected, response),
                    }
                }
            }
            Check::ExactTrimmed(expected) => {
                let norm: String = response.split_whitespace().collect::<Vec<_>>().join(" ");
                let exp: String = expected.split_whitespace().collect::<Vec<_>>().join(" ");
                if norm == exp {
                    CheckOutcome::Pass
                } else {
                    CheckOutcome::Fail {
                        reason: format!("expected trimmed {:?}, got {:?}", exp, norm),
                    }
                }
            }
            Check::ContainsAll(needles) => {
                for n in needles {
                    if !response.contains(n) {
                        return CheckOutcome::Fail {
                            reason: format!("response is missing {:?}", n),
                        };
                    }
                }
                CheckOutcome::Pass
            }
            Check::Excludes(banned) => {
                for b in banned {
                    if response.contains(b) {
                        return CheckOutcome::Fail {
                            reason: format!("response contains forbidden {:?}", b),
                        };
                    }
                }
                CheckOutcome::Pass
            }
        }
    }
}

/// A per-case outcome carrying a pass/fail flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseReport {
    pub name: String,
    pub passed: bool,
    /// Populated only on failure.
    pub reason: Option<String>,
}

/// Aggregate result of an eval run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalReport {
    pub cases: Vec<CaseReport>,
}

impl EvalReport {
    #[must_use]
    pub fn total(&self) -> usize {
        self.cases.len()
    }

    #[must_use]
    pub fn passed(&self) -> usize {
        self.cases.iter().filter(|c| c.passed).count()
    }

    /// Fraction of cases that passed, in `0.0..=1.0`.
    #[must_use]
    pub fn score(&self) -> f64 {
        if self.cases.is_empty() {
            return 0.0;
        }
        self.passed() as f64 / self.cases.len() as f64
    }

    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.passed() == self.total()
    }
}

/// Run every [`EvalCase`] through `respond` and score the results.
/// `respond` takes the prompt and returns the model's answer.
#[must_use]
pub fn run_eval<F>(cases: &[EvalCase], respond: F) -> EvalReport
where
    F: Fn(&str) -> String,
{
    let mut reports = Vec::with_capacity(cases.len());
    for case in cases {
        let answer = respond(&case.prompt);
        let (passed, reason) = match case.check.apply(&answer) {
            CheckOutcome::Pass => (true, None),
            CheckOutcome::Fail { reason } => (false, Some(reason)),
        };
        reports.push(CaseReport {
            name: case.name.clone(),
            passed,
            reason,
        });
    }
    EvalReport { cases: reports }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_grades_a_correct_answer_as_pass() {
        let c = EvalCase::exact("capital", "Başkent neresi?", "Ankara");
        assert_eq!(c.check.apply("Ankara"), CheckOutcome::Pass);
    }

    #[test]
    fn exact_grades_a_different_answer_as_fail_with_surrounding() {
        let c = EvalCase::exact("capital", "Başkent neresi?", "Ankara");
        assert!(matches!(
            c.check.apply("İstanbul"),
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn contains_all_requires_every_needle() {
        let c = EvalCase {
            name: "parts".into(),
            prompt: "Lubot hangi katmanlardan oluşur?".into(),
            check: Check::ContainsAll(vec!["core".into(), "knowledge".into(), "serve".into()]),
        };
        assert_eq!(c.check.apply("core knowledge serve"), CheckOutcome::Pass);
        assert!(matches!(c.check.apply("core serve"), CheckOutcome::Fail { .. }));
    }

    #[test]
    fn excludes_rejects_forbidden_substrings() {
        let c = EvalCase {
            name: "no_halluc".into(),
            prompt: "x".into(),
            check: Check::Excludes(vec!["bilinmiyor".into(), "emin değilim".into()]),
        };
        assert_eq!(c.check.apply("cevap 42."), CheckOutcome::Pass);
        assert!(matches!(c.check.apply("emin değilim ama 42."), CheckOutcome::Fail { .. }));
    }

    #[test]
    fn exact_trimmed_ignores_whitespace_padding() {
        let c = EvalCase::exact("t", "soru", "cevap bu");
        assert!(matches!(c.check.apply("  cevap   bu  "), CheckOutcome::Fail { .. }));
        let trimmed = EvalCase {
            name: "t".into(),
            prompt: "soru".into(),
            check: Check::ExactTrimmed("cevap bu".into()),
        };
        assert_eq!(trimmed.check.apply("  cevap   bu  "), CheckOutcome::Pass);
    }

    #[test]
    fn run_eval_scores_a_fixture_responder() {
        let cases = vec![
            EvalCase::exact("a", "2+2?", "4"),
            EvalCase::exact("b", "1+1?", "3"),
            EvalCase {
                name: "c".into(),
                prompt: "? ".into(),
                check: Check::ContainsAll(vec!["ok".into()]),
            },
        ];
        // A responder that is right on a and c, wrong on b.
        let report = run_eval(&cases, |p| {
            if p == "2+2?" {
                "4".into()
            } else if p == "?" {
                "ok".into()
            } else {
                "3".into()
            }
        });
        assert_eq!(report.total(), 3);
        assert_eq!(report.passed(), 2);
        assert!((report.score() - 2.0 / 3.0).abs() < f64::EPSILON);
        assert!(!report.all_passed());
    }

    #[test]
    fn empty_eval_reports_zero_score() {
        let report = run_eval(&[], |_: &str| "x".into());
        assert_eq!(report.total(), 0);
        assert_eq!(report.score(), 0.0);
    }
}
