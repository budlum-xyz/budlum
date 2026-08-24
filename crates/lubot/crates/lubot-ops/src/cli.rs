//! Command parsing (built on std::env; clap arrives in the production phase).
//!
//! Help text and identifiers are both English: the tree is written in English,
//! so the earlier split between Turkish help text and English identifiers no
//! longer holds.

/// The CLI commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Model registration draft (32-byte hex).
    Register { model_id_hex: Option<String> },
    /// Operator compute-bond draft (compared against the on-chain
    /// `MIN_OPERATOR_BOND`).
    Bond { amount: Option<u64> },
    /// Serving-bridge configuration summary.
    Serve,
    /// Default training plan draft.
    Tune,
    /// Health summary.
    Status,
    /// Run a JSONL data file through the schema gate (lubot-tune::schema).
    Validate { path: Option<String> },
    /// The help text.
    Help,
}

/// Parse the command line. `argv` does not include the program name.
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

/// The help text.
pub const HELP: &str = "\
lubot-ops - the Lubot off-chain operator CLI (skeleton)

Usage:
  lubot-ops register [MODEL_ID_HEX]   model registration draft
  lubot-ops bond [AMOUNT]             operator compute-bond draft
  lubot-ops serve                     serving-bridge summary
  lubot-ops tune                      training plan draft
  lubot-ops status                    health summary
  lubot-ops validate [JSONL_FILE]     data set schema gate (empty field, byte
                                      ceiling, line-numbered error, TR ratio)
  lubot-ops help                      this text

Note: on-chain operations (registration, bond) go through the budlum node RPC;
this CLI only prints the skeleton drafts.
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
            parse(&["validate".into(), "data.jsonl".into()]),
            Command::Validate {
                path: Some("data.jsonl".into())
            }
        );
    }
}
