//! lubot-ops giriş noktası. İskelet: komutları ayrıştırır, taslakları yazar.

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
            println!("Lubot model kaydı (taslak)");
            println!(
                "model_id: {}",
                model_id_hex.unwrap_or_else(|| "<belirtilmedi>".into())
            );
            let spec = ModelSpec::new(
                ModelId([0; 32]),
                "example-org/base-checkpoint-light",
                ModelLicense::Mit,
                FineTuneSource::BaseModel,
                ModelTier::Light,
            );
            println!(
                "kademe: {} - üretim kaydı için SHA-256 zorunlu; şu an hazır: {}",
                spec.tier.as_str(),
                spec.is_production_ready()
            );
        }
        Command::Bond { amount } => match amount {
            Some(a) if a >= 1_000 => println!("bond taslağı: {a} (MIN_OPERATOR_BOND=1_000 üzeri)"),
            Some(a) => println!("bond taslağı reddedilir: {a} < MIN_OPERATOR_BOND (1_000)"),
            None => println!("bond: <miktar belirtilmedi>"),
        },
        Command::Serve => {
            let light = ServeConfig::for_tier(ModelTier::Light, "v0.1");
            let normal = ServeConfig::for_tier(ModelTier::Normal, "v0.1");
            println!("serving köprüsü (taslak)");
            println!(
                "kademe light:  sunulan ad {} | ağırlık kaynağı {}",
                light.served_model_name, light.weight_source
            );
            println!(
                "kademe normal: sunulan ad {} | ağırlık kaynağı {}",
                normal.served_model_name, normal.weight_source
            );
        }
        Command::Tune => {
            let plan = TunePlan::lora(ModelId([0; 32]), 2_000);
            println!("eğitim planı (taslak)");
            println!("yöntem: {:?}, dtype: {:?}", plan.method, plan.adapter_dtype);
            println!("örnek üst sınırı: {}", plan.max_examples);
            println!("veri seti bağlı mı: {}", plan.has_datasets());
        }
        Command::Status => {
            println!("lubot-ops durumu: iskelet - zincir bağlantısı fail-closed (NotConnected)");
        }
        Command::Validate { path } => match path {
            None => println!("validate: <jsonl dosyası belirtilmedi>"),
            Some(p) => match std::fs::read_to_string(&p) {
                Err(e) => {
                    eprintln!("dosya okunamadı ({p}): {e}");
                    std::process::exit(2);
                }
                Ok(text) => {
                    let lines: Vec<String> = text.lines().map(str::to_string).collect();
                    match lubot_tune::schema::validate_records(&lines) {
                        Err(e) => {
                            eprintln!("ŞEMA KAPISI RED: {e:?}");
                            std::process::exit(1);
                        }
                        Ok(records) => {
                            let ratio = lubot_tune::schema::tr_ratio_estimate(&records);
                            println!(
                                "şema kapısı GEÇTİ: {} kayıt; TR oranı tahmini {:.2}",
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
