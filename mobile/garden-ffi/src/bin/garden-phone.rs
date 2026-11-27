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
//!   garden-phone create <dir> <title> [name] [listen multiaddr]
//!   garden-phone host <dir> <port> <title> [name] [listen multiaddr]
//!   garden-phone join <dir> <record> <name>
//!   garden-phone serve <dir> <port> [record] [name]
//!   garden-phone return-check <dir> <record> [name]
//!   garden-phone status <dir>
//!   garden-phone send <dir> <text> [caption]
//!   garden-phone feed <dir> [limit]
//!   garden-phone fetch <dir> <content id>
//!   garden-phone leave <dir>

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use budlum_garden_ffi::{GardenAnswer, GardenPhone};
use serde_json::Value;

/// Loopback bind address so a phone control door is never exposed to LAN peers.
const STATUS_BIND_ADDR: &str = "127.0.0.1";
/// Per-connection read and write deadline on the local control door.
const STATUS_IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum bytes read for the HTTP request line + headers.
const MAX_HTTP_HEAD_BYTES: u64 = 4_096;
/// Maximum JSON body bytes accepted on local `POST` commands.
const MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let dir = args.get(2).cloned().unwrap_or_default();
    if command.is_empty() || dir.is_empty() {
        eprintln!(
            "usage: garden-phone \
<self-test|read|create|host|join|serve|return-check|status|send|feed|fetch|leave> <dir> [...]"
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
            let address = args.get(5).cloned();
            say(phone
                .create(title, name, address)
                .map_err(|e| e.to_string()))
        }
        // Found an isolated Garden on this device and keep the validator swarm
        // alive for peers to dial while exposing the local loopback control door.
        "host" => {
            let port = args.get(3).and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
            let title = args.get(4).cloned().unwrap_or_default();
            let name = args.get(5).cloned().unwrap_or_else(|| "Phone".to_string());
            let address = args.get(6).cloned();
            if port == 0 || title.is_empty() {
                eprintln!(
                    "usage: garden-phone host <dir> <port> <title> [name] [listen multiaddr]"
                );
                return ExitCode::from(2);
            }
            if !gate(&phone) {
                return ExitCode::FAILURE;
            }
            match phone.create(title, name, address) {
                Ok(answer) => println!("founded: {}", answer.json),
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::FAILURE;
                }
            }
            serve(&phone, port)
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

/// Hold the Garden open and answer local operator queries on loopback `port`.
fn serve(phone: &Arc<GardenPhone>, port: u16) -> ExitCode {
    let listener = match TcpListener::bind((STATUS_BIND_ADDR, port)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("the status door would not open on {STATUS_BIND_ADDR}:{port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("the phone is in the Garden; its status is on {STATUS_BIND_ADDR}:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => answer_one(phone, stream),
            Err(e) => eprintln!("a status reader dropped: {e}"),
        }
    }
    ExitCode::SUCCESS
}

fn write_http_json(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn error_body(reason: &str) -> String {
    format!("{{\"error\":{}}}", json_string(reason))
}

fn answer_result(
    stream: &mut TcpStream,
    result: Result<GardenAnswer, budlum_garden_ffi::GardenError>,
) {
    match result {
        Ok(answer) => write_http_json(stream, "200 OK", &answer.json),
        Err(e) => write_http_json(stream, "409 CONFLICT", &error_body(&e.to_string())),
    }
}

fn answer_one(phone: &Arc<GardenPhone>, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(STATUS_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(STATUS_IO_TIMEOUT));

    let mut reader = BufReader::new((&mut stream).take(MAX_HTTP_HEAD_BYTES));
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() || first.trim().is_empty() {
        return;
    }
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if path.is_empty() || !path.starts_with('/') {
        write_http_json(
            &mut stream,
            "400 BAD REQUEST",
            &error_body("malformed request line"),
        );
        return;
    }

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some(val) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                    match val.trim().parse::<usize>() {
                        Ok(n) if n <= MAX_HTTP_BODY_BYTES => content_length = n,
                        _ => {
                            write_http_json(
                                &mut stream,
                                "400 BAD REQUEST",
                                &error_body("invalid or oversized content-length"),
                            );
                            return;
                        }
                    }
                }
            }
            Err(_) => {
                write_http_json(
                    &mut stream,
                    "400 BAD REQUEST",
                    &error_body("header read failed"),
                );
                return;
            }
        }
    }
    let buffered = reader.buffer().to_vec();
    drop(reader);

    match method {
        "GET" => {
            if path == "/" || path == "/status" {
                answer_result(&mut stream, phone.status());
            } else if path == "/invite" {
                answer_result(&mut stream, phone.invite());
            } else if path == "/feed" {
                answer_result(&mut stream, phone.feed(50));
            } else if let Some(rest) = path.strip_prefix("/feed/") {
                match rest.parse::<u32>() {
                    Ok(limit) if (1..=200).contains(&limit) => {
                        answer_result(&mut stream, phone.feed(limit));
                    }
                    _ => write_http_json(
                        &mut stream,
                        "400 BAD REQUEST",
                        &error_body("feed limit must be an integer in 1..=200"),
                    ),
                }
            } else if let Some(content_id) = path.strip_prefix("/fetch/") {
                if content_id.len() != 64 || !content_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    write_http_json(
                        &mut stream,
                        "400 BAD REQUEST",
                        &error_body("content id must be 64 hex digits"),
                    );
                } else {
                    answer_result(&mut stream, phone.fetch(content_id.to_string()));
                }
            } else {
                write_http_json(&mut stream, "404 NOT FOUND", &error_body("unknown route"));
            }
        }
        "POST" => {
            let mut body_bytes = Vec::with_capacity(content_length);
            let take_buf = buffered.len().min(content_length);
            if let Some(prefix) = buffered.get(..take_buf) {
                body_bytes.extend_from_slice(prefix);
            }
            if body_bytes.len() < content_length {
                let remaining = content_length.saturating_sub(body_bytes.len());
                let mut tail = vec![0u8; remaining];
                if stream.read_exact(&mut tail).is_err() {
                    write_http_json(
                        &mut stream,
                        "400 BAD REQUEST",
                        &error_body("incomplete body"),
                    );
                    return;
                }
                body_bytes.extend_from_slice(&tail);
            }
            let payload: Value = match serde_json::from_slice(&body_bytes) {
                Ok(v) => v,
                Err(_) => {
                    write_http_json(&mut stream, "400 BAD REQUEST", &error_body("invalid json"));
                    return;
                }
            };
            if path == "/send" {
                let Some(text) = payload.get("text").and_then(Value::as_str) else {
                    write_http_json(&mut stream, "400 BAD REQUEST", &error_body("missing text"));
                    return;
                };
                let caption = payload
                    .get("caption")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                answer_result(&mut stream, phone.send(text.to_string(), caption));
            } else if path == "/send-image" {
                let Some(hex_bytes) = payload.get("hex").and_then(Value::as_str) else {
                    write_http_json(&mut stream, "400 BAD REQUEST", &error_body("missing hex"));
                    return;
                };
                let mime = payload
                    .get("mime")
                    .and_then(Value::as_str)
                    .unwrap_or("image/png")
                    .to_string();
                let caption = payload
                    .get("caption")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                answer_result(
                    &mut stream,
                    phone.send_image(hex_bytes.to_string(), mime, caption),
                );
            } else {
                write_http_json(&mut stream, "404 NOT FOUND", &error_body("unknown route"));
            }
        }
        _ => write_http_json(
            &mut stream,
            "405 METHOD NOT ALLOWED",
            &error_body("method not allowed"),
        ),
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string())
}

fn say(result: Result<GardenAnswer, String>) -> ExitCode {
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
