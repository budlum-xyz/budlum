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
//!   garden-phone create <dir> <title> [name]
//!   garden-phone join <dir> <record> <name>
//!   garden-phone serve <dir> <port> [record] [name]
//!   garden-phone return-check <dir> <record> [name]
//!   garden-phone status <dir>
//!   garden-phone send <dir> <text> [caption]
//!   garden-phone feed <dir> [limit]
//!   garden-phone fetch <dir> <content id>
//!   garden-phone leave <dir>

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;

use budlum_garden_ffi::GardenPhone;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let dir = args.get(2).cloned().unwrap_or_default();
    if command.is_empty() || dir.is_empty() {
        eprintln!(
            "usage: garden-phone \
<self-test|read|create|join|serve|return-check|status|send|feed|fetch|leave> <dir> [...]"
        );
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
            println!(
                "{} in {} ms",
                if report.passed {
                    "all four passed"
                } else {
                    "a step failed"
                },
                report.elapsed_ms
            );
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
        // Founding a Garden from the phone's own library. The app runs
        // this when somebody taps "Start my own network", and nothing
        // outside the app had ever run it, so a person reporting that
        // starting a network does not work could not be answered with
        // anything but a guess.
        "create" => {
            let title = args.get(3).cloned().unwrap_or_default();
            let name = args.get(4).cloned().unwrap_or_else(|| "Phone".to_string());
            if title.is_empty() {
                eprintln!("usage: garden-phone create <dir> <title> [name]");
                return ExitCode::from(2);
            }
            if !gate(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone.create(title, name).map_err(|e| e.to_string()))
        }
        "join" => {
            let record = args.get(3).cloned().unwrap_or_default();
            let name = args.get(4).cloned().unwrap_or_else(|| "Phone".to_string());
            if record.is_empty() {
                eprintln!("a record is needed");
                return ExitCode::from(2);
            }
            if !gate(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone.join(record, name).map_err(|e| e.to_string()))
        }
        // A join that ends when the command ends is not a validator. The
        // app holds the Garden open for as long as the screen is up, so
        // this holds it open for as long as the process lives, and answers
        // the same status over HTTP so a watcher can see it from outside.
        "serve" => {
            let port = args.get(3).and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
            if port == 0 {
                eprintln!("a port is needed: garden-phone serve <dir> <port> [record] [name]");
                return ExitCode::from(2);
            }
            let record = args.get(4).cloned().unwrap_or_default();
            let name = args.get(5).cloned().unwrap_or_else(|| "Phone".to_string());
            if !gate(&phone) {
                return ExitCode::FAILURE;
            }
            // Returning is tried first: a phone that already has a seat
            // keeps it, and only a phone with none needs the record.
            match phone.rejoin() {
                Ok(answer) => println!("returned to the Garden: {}", answer.json),
                Err(back) => {
                    if record.is_empty() {
                        eprintln!("no Garden to return to ({back}), and no record was given");
                        return ExitCode::FAILURE;
                    }
                    match phone.join(record, name) {
                        Ok(answer) => println!("joined: {}", answer.json),
                        Err(e) => {
                            eprintln!("refused: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            serve(&phone, port)
        }
        // The Status screen offers Leave, and then a way back. Both are
        // one tap on the phone, so both are run here in one process -
        // against the real Garden, in the order a person would tap them.
        "return-check" => {
            let record = args.get(3).cloned().unwrap_or_default();
            let name = args.get(4).cloned().unwrap_or_else(|| "Phone".to_string());
            if record.is_empty() {
                eprintln!("a record is needed");
                return ExitCode::from(2);
            }
            if !gate(&phone) {
                return ExitCode::FAILURE;
            }
            match round_trip(&phone, record, name) {
                Ok(()) => {
                    println!("the phone left and came back");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    eprintln!("the way back is broken: {reason}");
                    ExitCode::FAILURE
                }
            }
        }
        "status" => say(phone.status().map_err(|e| e.to_string())),
        // The Data screen's three taps. A Garden is a group that sends
        // data over its own chain and reads it back verified, so the phone
        // has to be able to do all three from the command line the app's
        // own library answers.
        // Each of these is one command in one process, and a phone that
        // closed its process has stepped out of its Garden with its seat
        // kept. So the door does what the Status screen does on the way up:
        // it returns first, then acts. A phone with no seat is told so.
        "send" => {
            let text = match args.get(3) {
                Some(text) => text.clone(),
                None => {
                    eprintln!("usage: garden-phone send <dir> <text> [caption]");
                    return ExitCode::from(2);
                }
            };
            let caption = args.get(4).cloned().unwrap_or_default();
            if !gate(&phone) || !return_first(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone.send(text, caption).map_err(|e| e.to_string()))
        }
        "feed" => {
            let limit = args
                .get(3)
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(20);
            if !return_first(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone.feed(limit).map_err(|e| e.to_string()))
        }
        "fetch" => {
            let content_id = match args.get(3) {
                Some(id) => id.clone(),
                None => {
                    eprintln!("usage: garden-phone fetch <dir> <content id>");
                    return ExitCode::from(2);
                }
            };
            if !return_first(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone.fetch(content_id).map_err(|e| e.to_string()))
        }
        "leave" => say(phone.leave().map_err(|e| e.to_string())),
        other => {
            eprintln!("no such command: {other}");
            ExitCode::from(2)
        }
    }
}

/// The self test is the gate the app puts in front of joining, so it is the
/// gate here too.
fn gate(phone: &Arc<GardenPhone>) -> bool {
    let report = phone.self_test();
    if !report.passed {
        for step in report.steps.iter().filter(|s| !s.passed) {
            eprintln!("self test failed: {} - {}", step.name, step.detail);
        }
    }
    report.passed
}

/// Put a phone that stepped out back into its Garden, and say plainly when
/// there is no Garden to return to.
///
/// A phone command is one process. The process that joined kept a seat and
/// ended, so the seat is "away" until something returns it; the app does this
/// on the way up, and a data command has to do the same. A phone that never
/// joined is refused rather than left to fail deeper in with a less useful
/// message.
fn return_first(phone: &Arc<GardenPhone>) -> bool {
    match phone.rejoin() {
        Ok(answer) => {
            println!(
                "returned to the Garden: {}",
                one_line(&answer.json, "status")
            );
            true
        }
        Err(back) => {
            eprintln!("no Garden to return to: {back}");
            false
        }
    }
}

/// Join, leave, and return - the three taps the Status screen allows.
fn round_trip(phone: &Arc<GardenPhone>, record: String, name: String) -> Result<(), String> {
    let joined = phone.join(record, name).map_err(|e| e.to_string())?;
    println!("joined:   {}", one_line(&joined.json, "status"));
    let left = phone.leave().map_err(|e| e.to_string())?;
    println!("left:     {}", left.json);
    if !left.json.contains("\"can_return\":true") {
        return Err("the seat was not kept, so there is nothing to return to".into());
    }
    let back = phone.rejoin().map_err(|e| e.to_string())?;
    println!("returned: {}", one_line(&back.json, "status"));
    let now = phone.status().map_err(|e| e.to_string())?;
    if !now.json.contains("\"status\":\"Active\"") {
        return Err("the phone came back to something that is not an active Garden".into());
    }
    Ok(())
}

/// The one field worth printing out of a long status answer.
fn one_line(json: &str, field: &str) -> String {
    let needle = format!("\"{field}\":");
    json.find(&needle).map_or_else(
        || format!("{} bytes", json.len()),
        |at| {
            let rest = &json[at + needle.len()..];
            let end = rest.find(',').unwrap_or(rest.len());
            format!("{field} {}", rest[..end].trim_matches('"'))
        },
    )
}

/// Hold the Garden open and answer the phone's own status on `port`.
///
/// Only the phone's view is served, exactly as `status` prints it. Nothing
/// can be changed through this door: it reads, and that is all.
fn serve(phone: &Arc<GardenPhone>, port: u16) -> ExitCode {
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("the status door would not open on {port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("the phone is in the Garden; its status is on port {port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => answer_one(phone, stream),
            Err(e) => eprintln!("a status reader dropped: {e}"),
        }
    }
    ExitCode::SUCCESS
}

fn answer_one(phone: &Arc<GardenPhone>, mut stream: TcpStream) {
    // The first line names what is being asked for. Nothing here writes to
    // the Garden: `status` is the phone's view, `feed` is what the Garden
    // holds and `fetch` reads one object back out by content id. A path this
    // door does not know answers the status, which is what it always did.
    let mut first = String::new();
    if BufReader::new(&stream).read_line(&mut first).is_err() {
        return;
    }
    let path = first.split_whitespace().nth(1).unwrap_or("/");
    let answer = if let Some(rest) = path.strip_prefix("/feed/") {
        rest.parse::<u32>()
            .map_or_else(|_| phone.feed(50), |limit| phone.feed(limit))
    } else if let Some(content_id) = path.strip_prefix("/fetch/") {
        phone.fetch(content_id.to_string())
    } else if path.starts_with("/feed") {
        phone.feed(50)
    } else {
        phone.status()
    };
    let body = match answer {
        Ok(answer) => answer.json,
        Err(e) => format!("{{\"error\":{}}}", json_string(&e.to_string())),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
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
