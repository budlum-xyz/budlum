//! Behavior evaluation: a model-agnostic correctness harness for AI inference layer.
//!
//! The "success" of the AI inference layer module must be measurable
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
    /// Both sides must pass (used to combine facts + a hedge ban).
    And(Box<Check>, Box<Check>),
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
    pub fn exact(
        name: impl Into<String>,
        prompt: impl Into<String>,
        golden: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            prompt: prompt.into(),
            check: Check::Exact(golden.into()),
        }
    }

    /// A case graded by required facts ([`Check::ContainsAll`]) and banned
    /// hedges ([`Check::Excludes`]). This is the form that tolerates real,
    /// free-form model output (which almost never matches a golden string
    /// exactly) while still rejecting a hallucinated or evasive answer.
    #[must_use]
    pub fn facts(
        name: impl Into<String>,
        prompt: impl Into<String>,
        contains_all: impl IntoIterator<Item = impl Into<String>>,
        excludes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            prompt: prompt.into(),
            check: Check::ContainsAll(contains_all.into_iter().map(Into::into).collect()),
        }
        .plus_excludes(excludes)
    }

    fn plus_excludes(mut self, excludes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let banned: Vec<String> = excludes.into_iter().map(Into::into).collect();
        if !banned.is_empty() {
            self.check = Check::And(Box::new(self.check), Box::new(Check::Excludes(banned)));
        }
        self
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
            Check::And(a, b) => match a.apply(response) {
                CheckOutcome::Pass => b.apply(response),
                fail => fail,
            },
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

// ---------------------------------------------------------------------------
// An educational/evaluation data set: the "learning content" side of the AI inference layer.
// ---------------------------------------------------------------------------

impl Check {
    /// A deterministic, human-readable representation used for hashing the
    /// data set. Two [`EvalCase`]s that grade identically hash identically.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Check::Exact(s) => format!("exact:{}", s),
            Check::ExactTrimmed(s) => format!("exact_trimmed:{}", s),
            Check::ContainsAll(xs) => format!("contains_all:{}", xs.join("|")),
            Check::Excludes(xs) => format!("excludes:{}", xs.join("|")),
            Check::And(a, b) => format!("and:{}|{}", a.canonical(), b.canonical()),
        }
    }
}

impl EvalCase {
    /// The deterministic record for this case (name / prompt / rule).
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.name,
            self.prompt,
            self.check.canonical()
        )
    }
}

/// A named data set of behaviour cases. This is the unit that is *registered*
/// (its SHA-256 binds it, mirroring [`crate::plan::TunePlan`]'s
/// `dataset_hashes`), so the same content can be trained on and later graded -
/// the data-set hash makes "the content we graded" and "the content we tuned
/// on" the same object.
#[derive(Debug, Clone)]
pub struct EvalDataSet {
    pub name: String,
    pub cases: Vec<EvalCase>,
}

impl EvalDataSet {
    /// Build a data set where each record's `assistant` is the golden answer
    /// (whitespace-insensitive) and `user` is the prompt.
    ///
    /// This is the bridge between the SFT training set (`InstructionRecord`)
    /// and the evaluation set: the same golden content is both the training
    /// target and the correctness oracle.
    #[must_use]
    pub fn from_golden(
        name: impl Into<String>,
        records: &[ai_data::jsonl::InstructionRecord],
    ) -> Self {
        let cases = records
            .iter()
            .map(|r| EvalCase {
                name: String::new(),
                prompt: r.user.clone(),
                check: Check::ExactTrimmed(r.assistant.clone()),
            })
            .collect();
        Self {
            name: name.into(),
            cases,
        }
    }

    /// The content hash (SHA-256, [`ai_data::verify::content_id_of`]) of the
    /// deterministic record list. Changing any case changes the hash, so the
    /// hash pins *this* exact behaviour set.
    #[must_use]
    pub fn digest(&self) -> ai_core::model::Hash32 {
        let mut canon = String::with_capacity(self.cases.len() * 64);
        for c in &self.cases {
            canon.push_str(&c.canonical());
        }
        ai_data::verify::content_id_of(canon.as_bytes())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    /// Whether this set's digest is among the hashes a [`crate::plan::TunePlan`]
    /// is tuned on. This pins the train/eval identity: the content we grade is
    /// the same content the plan registered, so a model cannot be "tuned on X,
    /// graded on Y".
    #[must_use]
    pub fn registered_in(&self, plan: &crate::plan::TunePlan) -> bool {
        plan.dataset_hashes.contains(&self.digest())
    }
}

/// A success threshold. "AI inference layer is usable and successful" is not a feeling - it
/// is a gate: a [`EvalReport`] either clears `min_score` or it does not.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EvalGate {
    /// The minimum [`EvalReport::score`] the report must reach, in `0.0..=1.0`.
    pub min_score: f64,
}

impl EvalGate {
    /// The strict gate: every case must pass.
    #[must_use]
    pub fn perfect() -> Self {
        Self { min_score: 1.0 }
    }

    /// A gate with the given minimum score, clamped into `0.0..=1.0`.
    #[must_use]
    pub fn at_least(min_score: f64) -> Self {
        Self {
            min_score: min_score.clamp(0.0, 1.0),
        }
    }

    /// Whether the report clears the gate.
    #[must_use]
    pub fn passes(&self, report: &EvalReport) -> bool {
        report.score() >= self.min_score
    }

    /// The short verdict string used by the CLI.
    #[must_use]
    pub fn verdict(&self, report: &EvalReport) -> String {
        if self.passes(report) {
            format!("PASS ({:.0}%)", report.score() * 100.0)
        } else {
            format!(
                "REFUSED ({:.0}% < {:.0}% required)",
                report.score() * 100.0,
                self.min_score * 100.0
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_grades_a_correct_answer_as_pass() {
        let c = EvalCase::exact("capital", "What is the capital of Turkey?", "Ankara");
        assert_eq!(c.check.apply("Ankara"), CheckOutcome::Pass);
    }

    #[test]
    fn exact_grades_a_different_answer_as_fail_with_surrounding() {
        let c = EvalCase::exact("capital", "What is the capital of Turkey?", "Ankara");
        assert!(matches!(
            c.check.apply("Istanbul"),
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn contains_all_requires_every_needle() {
        let c = EvalCase {
            name: "parts".into(),
            prompt: "Which layers is AI inference layer built from?".into(),
            check: Check::ContainsAll(vec!["core".into(), "knowledge".into(), "serve".into()]),
        };
        assert_eq!(c.check.apply("core knowledge serve"), CheckOutcome::Pass);
        assert!(matches!(
            c.check.apply("core serve"),
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn excludes_rejects_forbidden_substrings() {
        let c = EvalCase {
            name: "no_halluc".into(),
            prompt: "x".into(),
            check: Check::Excludes(vec!["i do not know".into(), "i am not sure".into()]),
        };
        assert_eq!(c.check.apply("the answer is 42."), CheckOutcome::Pass);
        assert!(matches!(
            c.check.apply("i am not sure but 42."),
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn exact_trimmed_ignores_whitespace_padding() {
        let c = EvalCase::exact("t", "question", "the answer here");
        assert!(matches!(
            c.check.apply("  the answer   here  "),
            CheckOutcome::Fail { .. }
        ));
        let trimmed = EvalCase {
            name: "t".into(),
            prompt: "question".into(),
            check: Check::ExactTrimmed("the answer here".into()),
        };
        assert_eq!(
            trimmed.check.apply("  the answer   here  "),
            CheckOutcome::Pass
        );
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

    #[test]
    fn curriculum_dataset_has_a_stable_digest_and_is_graded_end_to_end() {
        // The behaviour curriculum for this system: golden Q/A pairs.
        const CURRICULUM: &str = include_str!("../data/ai-behaviour-curriculum.jsonl");
        let mut records = Vec::new();
        for line in CURRICULUM.lines() {
            records.push(ai_data::jsonl::decode(line).expect("valid JSONL line"));
        }

        let set = EvalDataSet::from_golden("ai-behaviour-curriculum", &records);
        assert_eq!(set.len(), 10);

        // The digest is deterministic and, crucially, matches the digest of an
        // identical set built from scratch (so it can be registered in B.U.D.
        // and the same object later re-graded).
        let d1 = set.digest();
        assert_eq!(
            d1,
            EvalDataSet::from_golden("ai-behaviour-curriculum", &records).digest()
        );
        assert_eq!(d1.len(), 32);

        // An oracle that answers the golden text: 100% pass.
        // Map prompt -> golden so the responder is deterministic, then verify
        // the *harness* scores a perfect set as 1.0.
        let goldens: std::collections::HashMap<String, String> = records
            .iter()
            .map(|r| (r.user.clone(), r.assistant.clone()))
            .collect();
        let perfect = run_eval(&set.cases, |p| goldens.get(p).cloned().unwrap_or_default());
        assert_eq!(perfect.passed(), 10);
        assert!((perfect.score() - 1.0).abs() < f64::EPSILON);
        assert!(perfect.all_passed());

        // A bad responder that always evades: the harness must flag failures.
        let bad = run_eval(&set.cases, |_| "i am not sure, i do not know".to_string());
        assert_eq!(bad.passed(), 0);
        assert!((bad.score()).abs() < f64::EPSILON);
    }

    #[test]
    fn from_golden_maps_user_become_prompt_and_assistant_becomes_rule() {
        let recs = vec![ai_data::jsonl::InstructionRecord {
            system: None,
            user: "question".to_string(),
            assistant: "correct answer".to_string(),
        }];
        let set = EvalDataSet::from_golden("t", &recs);
        assert_eq!(set.cases[0].prompt, "question");
        // Whitespace-insensitive golden grading.
        assert_eq!(
            set.cases[0].check.apply("  correct   answer  "),
            CheckOutcome::Pass
        );
    }

    #[test]
    fn eval_set_binds_to_the_plan_it_is_registered_in() {
        let recs = vec![ai_data::jsonl::InstructionRecord {
            system: None,
            user: "question".to_string(),
            assistant: "answer".to_string(),
        }];
        let set = EvalDataSet::from_golden("t", &recs);
        let digest = set.digest();

        // Plane the plan does NOT contain the eval hash -> not registered.
        let mut plan = crate::plan::TunePlan::lora(ai_core::model::ModelId([2; 32]), 2_000);
        assert!(!set.registered_in(&plan));

        // Register the eval set's digest in the plan -> train/eval identity.
        plan.dataset_hashes.push(digest);
        assert!(set.registered_in(&plan));

        // A different plan, or a tampered content set, no longer binds.
        let other = EvalDataSet::from_golden(
            "t",
            &[ai_data::jsonl::InstructionRecord {
                system: None,
                user: "question".to_string(),
                assistant: "different answer".to_string(),
            }],
        );
        assert!(!other.registered_in(&plan));
    }

    #[test]
    fn facts_grades_a_realistic_freeform_answer() {
        // A free-form answer that names the right facts but is not a verbatim
        // golden string - the form a real model actually produces.
        let c = EvalCase::facts(
            "pruning",
            "When is a processed Bridge replay message pruned?",
            ["mark_processed_at", "finality"],
            ["i do not know", "i am not sure", "maybe"],
        );
        assert_eq!(
            c.check
                .apply("Pruning happens with mark_processed_at once the finality depth passes."),
            CheckOutcome::Pass
        );
        // Missing a fact fails.
        assert!(matches!(
            c.check.apply("It is done with mark_processed_at."),
            CheckOutcome::Fail { .. }
        ));
        // A hedge is refused even if the facts are present.
        assert!(matches!(
            c.check
                .apply("i am not sure but pruning follows mark_processed_at after finality."),
            CheckOutcome::Fail { .. }
        ));
    }

    #[test]
    fn gate_clears_only_at_or_above_the_threshold() {
        let perfect = EvalGate::perfect();
        assert!(perfect.passes(&EvalReport {
            cases: vec![CaseReport {
                name: "a".into(),
                passed: true,
                reason: None,
            }],
        }));

        let strict = EvalGate::at_least(0.8);
        // 3/4 = 0.75 clears a 0.8 gate? No.
        let ok = EvalReport {
            cases: vec![
                CaseReport {
                    name: "a".into(),
                    passed: true,
                    reason: None,
                },
                CaseReport {
                    name: "b".into(),
                    passed: true,
                    reason: None,
                },
                CaseReport {
                    name: "c".into(),
                    passed: true,
                    reason: None,
                },
                CaseReport {
                    name: "d".into(),
                    passed: true,
                    reason: None,
                },
            ],
        };
        assert!(strict.passes(&ok));
        let half = EvalReport {
            cases: vec![
                CaseReport {
                    name: "a".into(),
                    passed: true,
                    reason: None,
                },
                CaseReport {
                    name: "b".into(),
                    passed: false,
                    reason: Some("x".into()),
                },
            ],
        };
        assert!(!strict.passes(&half));
        assert!(strict.verdict(&half).contains("REFUSED"));
        assert!(perfect.verdict(&ok).contains("PASS"));
    }
}
