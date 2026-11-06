//! Analyze field telemetry supplied as a JSONL file.

use std::env;
use std::fs;
use std::process::ExitCode;

use budlum_core::registry::rehearsal::analyze_mobile_field_logs;

fn run() -> Result<(), String> {
    let mut args = env::args_os();
    let _program = args.next();
    let path = args
        .next()
        .ok_or_else(|| "usage: budlum-mobile-log-analyzer <samples.jsonl>".to_owned())?;
    if args.next().is_some() {
        return Err("usage: budlum-mobile-log-analyzer <samples.jsonl>".to_owned());
    }
    let input = fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {err}", path.to_string_lossy()))?;
    let summary = analyze_mobile_field_logs(&input).map_err(|err| err.to_string())?;
    let output = serde_json::to_string_pretty(&summary)
        .map_err(|err| format!("cannot serialize report: {err}"))?;
    println!("{output}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
