// Unsafe lock: the whole ai_inference workspace is at 0 unsafe. This binary joins
// the other crates in refusing unsafe from the first line, so a raw-pointer
// regression cannot enter through the operator tooling. Same policy as the
// serving bridge and the main crate.
#![forbid(unsafe_code)]
//! The ai-ops entry point. A skeleton: it parses commands and prints
//! drafts.

mod cli;
mod logparse;

use ai_core::dataset::DatasetError;
use ai_core::model::{FineTuneSource, ModelId, ModelLicense, ModelSpec};
use ai_core::tier::ModelTier;
use ai_serve::config::ServeConfig;
use ai_tune::eval::{
    run_eval, CaseReport, CheckOutcome, EvalCase, EvalDataSet, EvalGate, EvalReport,
};
use ai_tune::plan::TunePlan;
use cli::{parse, Command, HELP};
use std::fmt::Write as _;

/// Decode a JSONL file of instruction records. A broken line is a hard stop:
/// a grader that silently skipped unreadable records would grade a different
/// set than the one the operator meant to submit.
fn load_records(path: &str) -> Vec<ai_data::jsonl::InstructionRecord> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("the dataset could not be read ({path}): {e}");
            std::process::exit(2);
        }
    };
    let mut records = Vec::new();
    for line in text.lines() {
        match ai_data::jsonl::decode(line) {
            Ok(r) => records.push(r),
            Err(e) => {
                eprintln!("the dataset line is not a valid record: {e}");
                std::process::exit(1);
            }
        }
    }
    records
}

/// Print the failing cases of a scored report, one line each.
fn print_failures(report: &EvalReport) {
    for CaseReport {
        name,
        passed,
        reason,
    } in &report.cases
    {
        if !*passed {
            println!(
                "  FAIL {name}: {}",
                reason.as_deref().unwrap_or("no reason recorded")
            );
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse(&argv) {
        Command::Register { model_id_hex } => {
            println!("AI inference layer model registration (a draft)");
            println!(
                "model_id: {}",
                model_id_hex.unwrap_or_else(|| "<not given>".into())
            );
            let spec = ModelSpec::new(
                ModelId([0; 32]),
                "example-org/base-checkpoint-light",
                ModelLicense::Mit,
                FineTuneSource::BaseModel,
                ModelTier::Light,
            );
            println!(
                "tier: {} - production registration requires SHA-256; ready now: {}",
                spec.tier.as_str(),
                spec.is_production_ready()
            );
        }
        Command::Bond { amount } => match amount {
            Some(a) if a >= 1_000 => {
                println!("draft bond: {a} (above MIN_OPERATOR_BOND=1_000)")
            }
            Some(a) => println!("the draft bond is refused: {a} < MIN_OPERATOR_BOND (1_000)"),
            None => println!("bond: <no amount given>"),
        },
        Command::Serve => {
            let light = ServeConfig::for_tier(ModelTier::Light, "v0.1");
            let normal = ServeConfig::for_tier(ModelTier::Normal, "v0.1");
            println!("the serving bridge (a draft)");
            println!(
                "tier light:  served name {} | weight source {}",
                light.served_model_name, light.weight_source
            );
            println!(
                "tier normal: served name {} | weight source {}",
                normal.served_model_name, normal.weight_source
            );
            println!(
                "the REST transport doubles its backoff per attempt, capped at {} s",
                ai_integrations::rest::MAX_BACKOFF_SECS
            );
        }
        Command::Tune { dataset } => {
            let mut plan = TunePlan::lora(ModelId([0; 32]), 2_000);
            println!("the training plan (a draft)");
            println!("method: {:?}, dtype: {:?}", plan.method, plan.adapter_dtype);
            println!("the example ceiling: {}", plan.max_examples);
            if let Some(dp) = dataset {
                let records = load_records(&dp);
                // The dataset is first a claim about the closed circuit: it
                // must name the model it feeds and must not be empty. The
                // label gate is `ai-core`'s, run here before the digest.
                let meta =
                    ai_core::dataset::DatasetMetadata::training(plan.base.0, records.len() as u64);
                match meta.validate() {
                    Err(DatasetError::EmptyTrainingCorpus) => {
                        eprintln!("the dataset holds zero samples; a corpus that trains nothing is not attached");
                        std::process::exit(1);
                    }
                    Err(DatasetError::MissingModelTarget) => {
                        eprintln!("the dataset does not name the model it feeds");
                        std::process::exit(1);
                    }
                    Ok(()) => {}
                }
                let set = EvalDataSet::from_golden(dp.clone(), &records);
                plan.dataset_hashes.push(set.digest());
                // train/eval identity: the plan carries the eval-set digest
                // it will be graded under, and the binding survives the push.
                if !set.registered_in(&plan) {
                    eprintln!("the eval set did not bind to the plan draft");
                    std::process::exit(1);
                }
                println!(
                    "eval set attached: {} records, digest {}",
                    set.len(),
                    digest_hex(&set.digest())
                );
            }
            println!("is a dataset attached: {}", plan.has_datasets());
        }
        Command::Status => {
            println!(
                "ai-ops status: a skeleton - the chain connection is fail-closed (NotConnected)"
            );
        }
        Command::Eval {
            dataset,
            responses,
            min_score,
        } => {
            let Some(d) = dataset else {
                eprintln!("eval: no dataset file given");
                std::process::exit(2);
            };
            let records = load_records(&d);
            let set = EvalDataSet::from_golden(d.clone(), &records);
            println!("eval set: {}", set.name);
            println!("records: {}", set.len());
            println!(
                "content digest (B.U.D. hash): {}",
                digest_hex(&set.digest())
            );
            // A golden rule that passes on an empty answer grades nothing.
            // Refusing here keeps a vacuous curriculum from reporting success.
            let vacuous: Vec<&EvalCase> = set
                .cases
                .iter()
                .filter(|c| matches!(c.check.apply(""), CheckOutcome::Pass))
                .collect();
            if !vacuous.is_empty() {
                for c in &vacuous {
                    eprintln!("vacuous golden case: {}", c.name);
                }
                eprintln!(
                    "eval: {} case(s) pass on an empty answer; refusing",
                    vacuous.len()
                );
                std::process::exit(1);
            }
            let gate = match min_score.as_deref() {
                Some(v) => match v.parse::<f64>() {
                    Ok(f) => EvalGate::at_least(f),
                    Err(e) => {
                        eprintln!("the minimum score does not parse: {e}");
                        std::process::exit(2);
                    }
                },
                None => EvalGate::perfect(),
            };
            match responses {
                None => println!("no responses given: the set identity is reported, but it\ncannot be graded without produced answers."),
                Some(rp) => {
                    let rtext = match std::fs::read_to_string(&rp) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("the responses could not be read ({rp}): {e}");
                            std::process::exit(2);
                        }
                    };
                    let mut answers = std::collections::HashMap::new();
                    for line in rtext.lines() {
                        match ai_data::jsonl::decode(line) {
                            Ok(r) => {
                                answers.insert(r.user, r.assistant);
                            }
                            Err(e) => {
                                eprintln!("the responses line is not a valid record: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    let missing = set
                        .cases
                        .iter()
                        .filter(|c| !answers.contains_key(&c.prompt))
                        .count();
                    if missing > 0 {
                        eprintln!("{missing} prompt(s) have no recorded answer; they grade as failures");
                    }
                    let report = run_eval(&set.cases, |p| answers.get(p).cloned().unwrap_or_default());
                    print_failures(&report);
                    println!("\nscored: {}/{}", report.passed(), report.total());
                    if report.all_passed() {
                        println!("gate: all {} cases passed", report.total());
                    } else {
                        println!("gate: {}", gate.verdict(&report));
                    }
                    if !gate.passes(&report) {
                        std::process::exit(1);
                    }
                }
            }
        }
        Command::Prompt => match ai_serve::config::checked_system_prompt() {
            // The prompt is served unaltered: the bridge serves exactly this
            // text, so printing it here is printing what the model sees.
            Ok(text) => {
                println!(
                    "ai_inference system prompt (verified): {}\n{}\n---",
                    text.len(),
                    text
                )
            }
            // A start-up refusal would catch the same thing later; surfacing it
            // here lets the operator fix the prompt (or understand a bad state)
            // before they attempt to bring a bridge up.
            Err(e) => {
                eprintln!("THE PROMPT CHECK REFUSED: {e}");
                std::process::exit(1);
            }
        },
        Command::Validate { path } => match path {
            None => println!("validate: <no jsonl file given>"),
            Some(p) => match std::fs::read_to_string(&p) {
                Err(e) => {
                    eprintln!("the file could not be read ({p}): {e}");
                    std::process::exit(2);
                }
                Ok(text) => {
                    let lines: Vec<String> = text.lines().map(str::to_string).collect();
                    match ai_tune::schema::validate_records(&lines) {
                        Err(e) => {
                            eprintln!("THE SCHEMA GATE REFUSED: {e:?}");
                            std::process::exit(1);
                        }
                        Ok(records) => {
                            let ratio = ai_tune::schema::tr_ratio_estimate(&records);
                            println!(
                                "the schema gate PASSED: {} records; the estimated TR ratio is {:.2}",
                                records.len(),
                                ratio
                            );
                        }
                    }
                }
            },
        },
        Command::Help => print!("{HELP}"),
    }
}

/// A 64-char lowercase hex rendering of a 32-byte content hash.
fn digest_hex(hash: &[u8; 32]) -> String {
    hash.iter()
        .fold(String::with_capacity(hash.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}
