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
    /// Default training plan draft. When a dataset JSONL is given, its
    /// eval-set digest is attached to the plan and the binding is checked
    /// (train/eval identity, `lubot-tune::eval`); an empty corpus or a
    /// dataset that names no model is refused.
    Tune { dataset: Option<String> },
    /// Health summary.
    Status,
    /// Run a JSONL data file through the schema gate (lubot-tune::schema).
    Validate { path: Option<String> },
    /// Grade a golden dataset against produced responses and report the score,
    /// the gate verdict and the dataset digest (lubot-tune::eval).
    ///
    /// `dataset` is a JSONL of `InstructionRecord`s (the golden answers are the
    /// grading rule). `responses` is a JSONL of the produced prompt/answer
    /// pairs; when omitted the command reports the dataset identity only (it
    /// cannot grade without model output). `min_score` (0.0-1.0) replaces the
    /// perfect gate; a report that does not clear it exits non-zero.
    Eval {
        dataset: Option<String>,
        responses: Option<String>,
        min_score: Option<String>,
    },
    /// Print the verified system prompt this bridge will serve.
    ///
    /// The prompt is a `const`; an operator serves the same text every other
    /// operator serves. This command runs the same startup check
    /// (`lubot_serve::config::checked_system_prompt`) and prints the verified
    /// text, or a refusal, so an operator can audit what they are about to
    /// serve before they commit, rather than discovering a refusal only at
    /// `Bridge::start`.
    Prompt,
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
        "tune" => Command::Tune {
            dataset: argv.get(1).cloned(),
        },
        "status" => Command::Status,
        "validate" => Command::Validate {
            path: argv.get(1).cloned(),
        },
        "eval" => Command::Eval {
            dataset: argv.get(1).cloned(),
            responses: argv.get(2).cloned(),
            min_score: argv.get(3).cloned(),
        },
        "prompt" => Command::Prompt,
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
  lubot-ops tune [DATASET]            training plan draft (with a dataset:
                                      attach its eval-set digest to the plan)
  lubot-ops status                    health summary
  lubot-ops validate [JSONL_FILE]     data set schema gate (empty field, byte
                                      ceiling, line-numbered error, TR ratio)
  lubot-ops eval [DATASET] [RESPONSES] [MIN_SCORE]
                                      grade a golden set against produced
                                      responses (score, gate verdict, digest;
                                      a non-clearing report exits non-zero)
  lubot-ops prompt                    print the verified serving system prompt
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
        assert_eq!(parse(&["tune".into()]), Command::Tune { dataset: None });
        assert_eq!(
            parse(&["tune".into(), "d.jsonl".into()]),
            Command::Tune {
                dataset: Some("d.jsonl".into())
            }
        );
        assert_eq!(
            parse(&["eval".into(), "d".into(), "r".into(), "0.8".into()]),
            Command::Eval {
                dataset: Some("d".into()),
                responses: Some("r".into()),
                min_score: Some("0.8".into()),
            }
        );
        assert_eq!(parse(&["status".into()]), Command::Status);
        assert_eq!(
            parse(&["validate".into(), "data.jsonl".into()]),
            Command::Validate {
                path: Some("data.jsonl".into())
            }
        );
        assert_eq!(parse(&["prompt".into()]), Command::Prompt);
    }
}
