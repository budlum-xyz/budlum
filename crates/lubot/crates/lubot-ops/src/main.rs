//! The lubot-ops entry point. A skeleton: it parses commands and prints
//! drafts.

mod cli;
mod logparse;

use cli::{parse, Command, HELP};
use lubot_core::model::{FineTuneSource, ModelId, ModelLicense, ModelSpec};
use lubot_core::tier::ModelTier;
use lubot_serve::config::ServeConfig;
use lubot_tune::plan::TunePlan;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse(&argv) {
        Command::Register { model_id_hex } => {
            println!("Lubot model registration (a draft)");
            println!(
                "model_id: {}",
                model_id_hex.unwrap_or_else(|| "<not given>".into())
            );
            let spec = ModelSpec::new(
                ModelId([0; 32]),
                "deepseek-ai/DeepSeek-V4-Flash-Base",
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
        }
        Command::Tune => {
            let plan = TunePlan::lora(ModelId([0; 32]), 2_000);
            println!("the training plan (a draft)");
            println!("method: {:?}, dtype: {:?}", plan.method, plan.adapter_dtype);
            println!("the example ceiling: {}", plan.max_examples);
            println!("is a dataset attached: {}", plan.has_datasets());
        }
        Command::Status => {
            println!(
                "lubot-ops status: a skeleton - the chain connection is fail-closed (NotConnected)"
            );
        }
        Command::Prompt => match lubot_serve::config::checked_system_prompt() {
            // The prompt is served unaltered: the bridge serves exactly this
            // text, so printing it here is printing what the model sees.
            Ok(text) => {
                println!(
                    "lubot system prompt (verified): {}\n{}\n---",
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
                    match lubot_tune::schema::validate_records(&lines) {
                        Err(e) => {
                            eprintln!("THE SCHEMA GATE REFUSED: {e:?}");
                            std::process::exit(1);
                        }
                        Ok(records) => {
                            let ratio = lubot_tune::schema::tr_ratio_estimate(&records);
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
