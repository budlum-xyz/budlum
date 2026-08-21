//! Komut ayrıştırma (std::env tabanlı; clap üretim fazında girer).
//! Yardım metinleri Türkçe, kimlikler İngilizce (repo kuralı).

/// CLI komutları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Model kaydı taslağı (32 bayt hex).
    Register { model_id_hex: Option<String> },
    /// Operator compute-bond taslağı (zincir üstü `MIN_OPERATOR_BOND` ile karşılaştırılır).
    Bond { amount: Option<u64> },
    /// Serving köprüsü yapılandırma özeti.
    Serve,
    /// Varsayılan eğitim planı taslağı.
    Tune,
    /// Sağlık özeti.
    Status,
    /// JSONL veri dosyasını şema kapısından geçir (lubot-tune::schema).
    Validate { path: Option<String> },
    /// Yardım metni.
    Help,
}

/// Komut satırını ayrıştır. `argv` program adını içermez.
#[must_use]
pub fn parse(argv: &[String]) -> Command {
    let cmd = argv.first().map(String::as_str).unwrap_or("");
    match cmd {
        "register" => Command::Register {
            model_id_hex: argv.get(1).cloned(),
        },
        "bond" => Command::Bond {
            amount: argv.get(1).and_then(|a| a.parse::<u64>().ok()),
        },
        "serve" => Command::Serve,
        "tune" => Command::Tune,
        "status" => Command::Status,
        "validate" => Command::Validate {
            path: argv.get(1).cloned(),
        },
        _ => Command::Help,
    }
}

/// Yardım metni (Türkçe).
pub const HELP: &str = "\
lubot-ops - Lubot off-chain operatör CLI (iskelet)

Kullanım:
  lubot-ops register [MODEL_ID_HEX]   model kaydı taslağı
  lubot-ops bond [MIKTAR]             operator compute-bond taslağı
  lubot-ops serve                     serving köprüsü özeti
  lubot-ops tune                      eğitim planı taslağı
  lubot-ops status                    sağlık özeti
  lubot-ops validate [JSONL_DOSYASI]  veri seti şema kapısı (boş alan, bayt
                                      tavanı, satır numaralı hata, TR oranı)
  lubot-ops help                      bu metin

Not: Zincir üstü işlemler (kayıt, bond) budlum düğüm RPC'si üzerinden
yapılır; bu CLI yalnızca iskelet taslaklarını gösterir.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_subcommands() {
        assert_eq!(parse(&[]), Command::Help);
        assert_eq!(
            parse(&["register".into()]),
            Command::Register { model_id_hex: None }
        );
        assert_eq!(
            parse(&["register".into(), "ab".repeat(32)]),
            Command::Register {
                model_id_hex: Some("ab".repeat(32))
            }
        );
        assert_eq!(
            parse(&["bond".into(), "1000".into()]),
            Command::Bond { amount: Some(1000) }
        );
        assert_eq!(
            parse(&["bond".into(), "abc".into()]),
            Command::Bond { amount: None }
        );
        assert_eq!(parse(&["serve".into()]), Command::Serve);
        assert_eq!(parse(&["tune".into()]), Command::Tune);
        assert_eq!(parse(&["status".into()]), Command::Status);
        assert_eq!(
            parse(&["validate".into(), "veri.jsonl".into()]),
            Command::Validate {
                path: Some("veri.jsonl".into())
            }
        );
    }
}
