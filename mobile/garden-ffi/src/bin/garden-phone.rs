//! The phone's own Garden library, driven from a terminal.
//!
//! This is not a second implementation of anything. It calls `GardenPhone`,
//! the exact type the Android app reaches through UniFFI, so a Garden the
//! app would join can be joined here and watched. It exists because an
//! emulator cannot be run where this is developed, and a claim that the
//! phone joins a real chain is worth no more than the run that shows it.
//!
//! Usage:
//!   garden-phone self-test <dir>
//!   garden-phone read <dir> <record>
//!   garden-phone join <dir> <record> <name>
//!   garden-phone status <dir>
//!   garden-phone leave <dir>

use std::process::ExitCode;

use budlum_garden_ffi::GardenPhone;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let dir = args.get(2).cloned().unwrap_or_default();
    if command.is_empty() || dir.is_empty() {
        eprintln!("usage: garden-phone <self-test|read|join|status|leave> <dir> [...]");
        return ExitCode::from(2);
    }

    let phone = match GardenPhone::new(dir) {
        Ok(phone) => phone,
        Err(e) => {
            eprintln!("the phone did not start: {e}");
            return ExitCode::FAILURE;
        }
    };

    match command {
        "self-test" => {
            let report = phone.self_test();
            for step in &report.steps {
                println!(
                    "{} {}{}",
                    if step.passed { "pass" } else { "FAIL" },
                    step.name,
                    if step.detail.is_empty() {
                        String::new()
                    } else {
                        format!("  ({})", step.detail)
                    }
                );
            }
            println!("{} in {} ms", if report.passed { "all four passed" } else { "a step failed" }, report.elapsed_ms);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "read" => say(args.get(3).map_or_else(
            || Err("a record is needed".to_string()),
            |record| phone.read_record(record.clone()).map_err(|e| e.to_string()),
        )),
        "join" => {
            let record = args.get(3).cloned().unwrap_or_default();
            let name = args.get(4).cloned().unwrap_or_else(|| "Phone".to_string());
            if record.is_empty() {
                eprintln!("a record is needed");
                return ExitCode::from(2);
            }
            // The self test is the gate the app puts in front of joining, so
            // it is the gate here too.
            let report = phone.self_test();
            if !report.passed {
                for step in report.steps.iter().filter(|s| !s.passed) {
                    eprintln!("self test failed: {} - {}", step.name, step.detail);
                }
                return ExitCode::FAILURE;
            }
            say(phone.join(record, name).map_err(|e| e.to_string()))
        }
        "status" => say(phone.status().map_err(|e| e.to_string())),
        "leave" => say(phone.leave().map_err(|e| e.to_string())),
        other => {
            eprintln!("no such command: {other}");
            ExitCode::from(2)
        }
    }
}

fn say(result: Result<budlum_garden_ffi::GardenAnswer, String>) -> ExitCode {
    match result {
        Ok(answer) => {
            println!("{}", answer.json);
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("refused: {reason}");
            ExitCode::FAILURE
        }
    }
}
