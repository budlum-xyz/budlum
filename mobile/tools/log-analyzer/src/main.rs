//! CLI entry point for `budlum-mobile-log-analyzer` (WP-37).

use std::env;
use std::fs;
use std::process::ExitCode;

use budlum_mobile_log_analyzer::{evaluate_bundle, parse_field_log, render_markdown_report};

fn run() -> Result<bool, String> {
    let mut args = env::args().skip(1);
    let mut input_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut strict = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--input" => {
                input_path = Some(
                    args.next()
                        .ok_or_else(|| "--input requires a file path".to_string())?,
                );
            }
            "--output" => {
                output_path = Some(
                    args.next()
                        .ok_or_else(|| "--output requires a file path".to_string())?,
                );
            }
            "--strict" => {
                strict = true;
            }
            other => {
                return Err(format!("unknown argument `{other}`"));
            }
        }
    }

    let in_file = input_path.ok_or_else(|| "--input <path> is required".to_string())?;
    let raw = fs::read_to_string(&in_file).map_err(|e| format!("cannot read `{in_file}`: {e}"))?;
    let bundle = parse_field_log(&raw)?;
    let summary = evaluate_bundle(&bundle);
    let report = render_markdown_report(&bundle, &summary);

    if let Some(out_file) = output_path {
        fs::write(&out_file, &report).map_err(|e| format!("cannot write `{out_file}`: {e}"))?;
    } else {
        print!("{report}");
    }

    Ok(!strict || summary.overall_passed())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("budlum-mobile-log-analyzer: matrix verdict is FAIL under --strict");
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("budlum-mobile-log-analyzer: {err}");
            ExitCode::from(1)
        }
    }
}
