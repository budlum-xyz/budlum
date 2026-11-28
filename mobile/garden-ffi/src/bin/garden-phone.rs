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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use budlum_garden_ffi::{GardenAnswer, GardenPhone};
use serde_json::Value;

/// Loopback bind address so a phone control door is never exposed to LAN peers.
const STATUS_BIND_ADDR: &str = "127.0.0.1";
/// Per-connection read and write deadline on the local control door.
const STATUS_IO_TIMEOUT: Duration = Duration::from_secs(3);
/// End-to-end header read deadline to protect worker slots against slowloris peers.
const STATUS_REQUEST_DEADLINE: Duration = Duration::from_secs(3);
/// Maximum concurrent worker threads answering status-door requests.
const MAX_DOOR_WORKERS: usize = 8;
/// Maximum bytes read for the HTTP request line + headers.
const MAX_HTTP_HEAD_BYTES: usize = 4_096;
/// Named `u64` ceiling for `Read::take` on HTTP request heads.
const MAX_HTTP_HEAD_READ_BYTES: u64 = (MAX_HTTP_HEAD_BYTES + 1) as u64;
/// Maximum HTTP header lines accepted before rejecting with `431`.
const MAX_HTTP_HEADER_LINES: usize = 64;
/// Maximum JSON body bytes accepted on local `POST` commands.
const MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Default and upper-bound feed limit for CLI & HTTP read endpoints.
const DEFAULT_FEED_LIMIT: u32 = 50;
const MAX_FEED_LIMIT: u32 = 200;

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
                .unwrap_or(20)
                .clamp(1, MAX_FEED_LIMIT);
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

/// Extract a top-level JSON boolean field without fragile substring matching.
fn json_bool_field(json: &str, field: &str) -> Option<bool> {
    let value: Value = serde_json::from_str(json).ok()?;
    value.get(field)?.as_bool()
}

/// Extract the validator status label cleanly from either `/garden/status`
/// or a top-level `status` field without spoofable substring scans.
fn garden_status_field(json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json).ok()?;
    value
        .pointer("/garden/status")
        .or_else(|| value.get("status"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Join, leave, and return - the three taps the Status screen allows.
fn round_trip(phone: &Arc<GardenPhone>, record: String, name: String) -> Result<(), String> {
    let joined = phone.join(record, name).map_err(|e| e.to_string())?;
    println!("joined:   {}", one_line(&joined.json, "status"));
    let left = phone.leave().map_err(|e| e.to_string())?;
    println!("left:     {}", left.json);
    if json_bool_field(&left.json, "can_return") != Some(true) {
        return Err("the seat was not kept, so there is nothing to return to".into());
    }
    let back = phone.rejoin().map_err(|e| e.to_string())?;
    println!("returned: {}", one_line(&back.json, "status"));
    let now = phone.status().map_err(|e| e.to_string())?;
    if garden_status_field(&now.json).as_deref() != Some("Active") {
        return Err("the phone came back to something that is not an active Garden".into());
    }
    Ok(())
}

/// The one field worth printing out of a long status answer, parsed structurally
/// so nested objects, trailing braces, or non-ASCII bytes never corrupt or panic.
fn one_line(json: &str, field: &str) -> String {
    serde_json::from_str::<Value>(json)
        .ok()
        .and_then(|v| {
            v.get(field)
                .cloned()
                .or_else(|| v.get("garden").and_then(|g| g.get(field)).cloned())
        })
        .map_or_else(
            || format!("{} bytes", json.len()),
            |val| match val {
                Value::String(s) => format!("{field} {s}"),
                other => format!("{field} {other}"),
            },
        )
}

struct WorkerSlotGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for WorkerSlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
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
    let active_workers = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if active_workers
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                        (n < MAX_DOOR_WORKERS).then_some(n + 1)
                    })
                    .is_err()
                {
                    let _ = stream.set_write_timeout(Some(STATUS_IO_TIMEOUT));
                    write_http_json(
                        &mut stream,
                        "503 SERVICE UNAVAILABLE",
                        &error_body("door busy"),
                    );
                    continue;
                }
                let phone = Arc::clone(phone);
                let active = Arc::clone(&active_workers);
                if std::thread::Builder::new()
                    .name("garden-phone-door".into())
                    .spawn(move || {
                        let _guard = WorkerSlotGuard { active };
                        answer_one(&phone, stream);
                    })
                    .is_err()
                {
                    active_workers.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(e) => eprintln!("a status reader dropped: {e}"),
        }
    }
    ExitCode::SUCCESS
}

fn format_http_head(status: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    )
}

fn write_http_json(stream: &mut TcpStream, status: &str, body: &str) {
    let head = format_http_head(status, body.len());
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

#[derive(Debug, PartialEq, Eq)]
enum DoorRoute {
    Status,
    Invite,
    Feed(u32),
    Fetch(String),
    Send,
    SendImage,
}

#[derive(Debug, PartialEq, Eq)]
enum RouteRejection {
    BadRequest(&'static str),
    NotFound(&'static str),
    MethodNotAllowed(&'static str),
}

impl RouteRejection {
    fn http_status(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "400 BAD REQUEST",
            Self::NotFound(_) => "404 NOT FOUND",
            Self::MethodNotAllowed(_) => "405 METHOD NOT ALLOWED",
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::BadRequest(r) | Self::NotFound(r) | Self::MethodNotAllowed(r) => r,
        }
    }
}

fn route_http_request(first_line: &str) -> Result<DoorRoute, RouteRejection> {
    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(RouteRejection::BadRequest("malformed request line"))?;
    let raw_target = parts
        .next()
        .ok_or(RouteRejection::BadRequest("malformed request line"))?;
    let version = parts
        .next()
        .ok_or(RouteRejection::BadRequest("malformed request line"))?;
    if parts.next().is_some()
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || !raw_target.starts_with('/')
    {
        return Err(RouteRejection::BadRequest("malformed request line"));
    }
    let path = raw_target.split('?').next().unwrap_or(raw_target);
    if path.contains('\\')
        || path.contains("..")
        || path
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(RouteRejection::NotFound("unknown route"));
    }
    match method {
        "GET" => {
            if path == "/" || path == "/status" {
                Ok(DoorRoute::Status)
            } else if path == "/invite" {
                Ok(DoorRoute::Invite)
            } else if path == "/feed" {
                Ok(DoorRoute::Feed(DEFAULT_FEED_LIMIT))
            } else if let Some(rest) = path.strip_prefix("/feed/") {
                match rest.parse::<u32>() {
                    Ok(limit) if (1..=MAX_FEED_LIMIT).contains(&limit) => {
                        Ok(DoorRoute::Feed(limit))
                    }
                    _ => Err(RouteRejection::BadRequest(
                        "feed limit must be an integer in 1..=200",
                    )),
                }
            } else if let Some(content_id) = path.strip_prefix("/fetch/") {
                if content_id.len() != 64 || !content_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    Err(RouteRejection::BadRequest(
                        "content id must be 64 hex digits",
                    ))
                } else {
                    Ok(DoorRoute::Fetch(content_id.to_ascii_lowercase()))
                }
            } else {
                Err(RouteRejection::NotFound("unknown route"))
            }
        }
        "POST" => match path {
            "/send" => Ok(DoorRoute::Send),
            "/send-image" => Ok(DoorRoute::SendImage),
            _ => Err(RouteRejection::NotFound("unknown route")),
        },
        _ => Err(RouteRejection::MethodNotAllowed("method not allowed")),
    }
}

enum HeadReadError {
    SilentClose,
    Rejected(&'static str, &'static str),
}

struct ParsedHead {
    first_line: String,
    content_length: usize,
    buffered_body_prefix: Vec<u8>,
}

/// Read the HTTP request line and headers with strict aggregate byte/line limits
/// and a bounded wall-clock deadline so split or non-terminated headers fail
/// closed (`400` / `431`) instead of truncating into partial dispatch.
fn read_http_head<R: Read>(input: R, deadline: Instant) -> Result<ParsedHead, HeadReadError> {
    let mut reader = BufReader::new(input.take(MAX_HTTP_HEAD_READ_BYTES));
    let mut first = String::new();
    match reader.read_line(&mut first) {
        Ok(0) => return Err(HeadReadError::SilentClose),
        Ok(_) if first.len() > MAX_HTTP_HEAD_BYTES => {
            return Err(HeadReadError::Rejected(
                "431 REQUEST HEADER FIELDS TOO LARGE",
                "request head exceeds byte limit",
            ));
        }
        Ok(_) if !first.ends_with('\n') => {
            return Err(HeadReadError::Rejected(
                "400 BAD REQUEST",
                "malformed or unterminated request line",
            ));
        }
        Ok(_) if first.trim().is_empty() => return Err(HeadReadError::SilentClose),
        Ok(_) => {}
        Err(_) => {
            return Err(HeadReadError::Rejected(
                "400 BAD REQUEST",
                "request line read failed",
            ));
        }
    }

    let mut total_bytes = first.len();
    let mut header_lines = 0usize;
    let mut content_length: Option<usize> = None;

    loop {
        if Instant::now() > deadline {
            return Err(HeadReadError::Rejected(
                "408 REQUEST TIMEOUT",
                "request header deadline exceeded",
            ));
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Err(HeadReadError::Rejected(
                    "400 BAD REQUEST",
                    "unterminated HTTP header block",
                ));
            }
            Ok(_) => {
                total_bytes = total_bytes.saturating_add(line.len());
                if total_bytes > MAX_HTTP_HEAD_BYTES {
                    return Err(HeadReadError::Rejected(
                        "431 REQUEST HEADER FIELDS TOO LARGE",
                        "request headers exceed byte limit",
                    ));
                }
                if !line.ends_with('\n') {
                    return Err(HeadReadError::Rejected(
                        "400 BAD REQUEST",
                        "unterminated HTTP header line",
                    ));
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                header_lines += 1;
                if header_lines > MAX_HTTP_HEADER_LINES {
                    return Err(HeadReadError::Rejected(
                        "431 REQUEST HEADER FIELDS TOO LARGE",
                        "too many request headers",
                    ));
                }
                let Some((name, val)) = trimmed.split_once(':') else {
                    return Err(HeadReadError::Rejected(
                        "400 BAD REQUEST",
                        "malformed header line",
                    ));
                };
                let lower = name.trim().to_ascii_lowercase();
                if lower == "transfer-encoding" {
                    return Err(HeadReadError::Rejected(
                        "400 BAD REQUEST",
                        "transfer-encoding is not supported",
                    ));
                }
                if lower == "content-length" {
                    let parsed = val
                        .trim()
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n <= MAX_HTTP_BODY_BYTES);
                    let Some(n) = parsed else {
                        return Err(HeadReadError::Rejected(
                            "400 BAD REQUEST",
                            "invalid or oversized content-length",
                        ));
                    };
                    if let Some(prev) = content_length {
                        if prev != n {
                            return Err(HeadReadError::Rejected(
                                "400 BAD REQUEST",
                                "conflicting content-length headers",
                            ));
                        }
                    } else {
                        content_length = Some(n);
                    }
                }
            }
            Err(_) => {
                return Err(HeadReadError::Rejected(
                    "400 BAD REQUEST",
                    "header read failed",
                ));
            }
        }
    }

    Ok(ParsedHead {
        first_line: first,
        content_length: content_length.unwrap_or(0),
        buffered_body_prefix: reader.buffer().to_vec(),
    })
}

fn answer_one(phone: &Arc<GardenPhone>, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(STATUS_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(STATUS_IO_TIMEOUT));
    let deadline = Instant::now() + STATUS_REQUEST_DEADLINE;

    let head = {
        match read_http_head(&mut stream, deadline) {
            Ok(head) => head,
            Err(HeadReadError::SilentClose) => return,
            Err(HeadReadError::Rejected(status, reason)) => {
                write_http_json(&mut stream, status, &error_body(reason));
                return;
            }
        }
    };

    let route = match route_http_request(&head.first_line) {
        Ok(route) => route,
        Err(rej) => {
            write_http_json(&mut stream, rej.http_status(), &error_body(rej.reason()));
            return;
        }
    };

    match route {
        DoorRoute::Status => answer_result(&mut stream, phone.status()),
        DoorRoute::Invite => answer_result(&mut stream, phone.invite()),
        DoorRoute::Feed(limit) => answer_result(&mut stream, phone.feed(limit)),
        DoorRoute::Fetch(content_id) => answer_result(&mut stream, phone.fetch(content_id)),
        DoorRoute::Send | DoorRoute::SendImage => {
            let mut body_bytes = Vec::with_capacity(head.content_length);
            let take_buf = head.buffered_body_prefix.len().min(head.content_length);
            if let Some(prefix) = head.buffered_body_prefix.get(..take_buf) {
                body_bytes.extend_from_slice(prefix);
            }
            if body_bytes.len() < head.content_length {
                let remaining = head.content_length.saturating_sub(body_bytes.len());
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
            if route == DoorRoute::Send {
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
            } else {
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
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn status_listener_binds_loopback_only_with_bounded_limits() {
        assert_eq!(STATUS_BIND_ADDR, "127.0.0.1");
        assert!(STATUS_IO_TIMEOUT >= Duration::from_secs(1));
        assert!(STATUS_IO_TIMEOUT <= Duration::from_secs(5));
        const {
            assert!(MAX_DOOR_WORKERS <= 16);
        }
    }

    #[test]
    fn status_response_omits_wildcard_cors_and_sets_nosniff_and_no_store() {
        let head = format_http_head("200 OK", 11);
        assert!(head.contains("X-Content-Type-Options: nosniff"));
        assert!(head.contains("Cache-Control: no-store"));
        assert!(!head
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"));
    }

    #[test]
    fn router_enforces_strict_routes_methods_and_rejects_traversal() {
        assert_eq!(
            route_http_request("GET / HTTP/1.1\r\n"),
            Ok(DoorRoute::Status)
        );
        assert_eq!(
            route_http_request("GET /status HTTP/1.1\r\n"),
            Ok(DoorRoute::Status)
        );
        assert_eq!(
            route_http_request("GET /invite HTTP/1.1\r\n"),
            Ok(DoorRoute::Invite)
        );
        assert_eq!(
            route_http_request("GET /feed HTTP/1.1\r\n"),
            Ok(DoorRoute::Feed(DEFAULT_FEED_LIMIT))
        );
        assert_eq!(
            route_http_request("GET /feed/3 HTTP/1.1\r\n"),
            Ok(DoorRoute::Feed(3))
        );
        assert!(matches!(
            route_http_request("GET /feed/0 HTTP/1.1\r\n"),
            Err(RouteRejection::BadRequest(_))
        ));
        assert!(matches!(
            route_http_request("GET /feed/201 HTTP/1.1\r\n"),
            Err(RouteRejection::BadRequest(_))
        ));
        assert!(matches!(
            route_http_request("GET /feed/two HTTP/1.1\r\n"),
            Err(RouteRejection::BadRequest(_))
        ));
        let valid_hex = "ab".repeat(32);
        assert_eq!(
            route_http_request(&format!(
                "GET /fetch/{} HTTP/1.1\r\n",
                valid_hex.to_uppercase()
            )),
            Ok(DoorRoute::Fetch(valid_hex))
        );
        assert!(matches!(
            route_http_request("GET /fetch/abc HTTP/1.1\r\n"),
            Err(RouteRejection::BadRequest(_))
        ));
        assert!(matches!(
            route_http_request("GET /../etc/passwd HTTP/1.1\r\n"),
            Err(RouteRejection::NotFound(_))
        ));
        assert!(matches!(
            route_http_request("GET /unknown-route HTTP/1.1\r\n"),
            Err(RouteRejection::NotFound(_))
        ));
        assert_eq!(
            route_http_request("POST /send HTTP/1.1\r\n"),
            Ok(DoorRoute::Send)
        );
        assert_eq!(
            route_http_request("POST /send-image HTTP/1.1\r\n"),
            Ok(DoorRoute::SendImage)
        );
        assert!(matches!(
            route_http_request("DELETE / HTTP/1.1\r\n"),
            Err(RouteRejection::MethodNotAllowed(_))
        ));
    }

    #[test]
    fn header_reader_rejects_oversized_split_unterminated_and_smuggled_headers() {
        let deadline = Instant::now() + Duration::from_secs(10);
        // Oversized header > MAX_HTTP_HEAD_BYTES must return 431 instead of truncating.
        let big = format!(
            "GET /status HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_HEAD_BYTES)
        );
        assert!(matches!(
            read_http_head(Cursor::new(big.as_bytes()), deadline),
            Err(HeadReadError::Rejected(
                "431 REQUEST HEADER FIELDS TOO LARGE",
                _
            ))
        ));

        // Single huge line with NO newline must also return 431 without OOM.
        let huge_no_nl = "GET /status ".to_string() + &"a".repeat(MAX_HTTP_HEAD_BYTES + 128);
        assert!(matches!(
            read_http_head(Cursor::new(huge_no_nl.as_bytes()), deadline),
            Err(HeadReadError::Rejected(
                "431 REQUEST HEADER FIELDS TOO LARGE",
                _
            ))
        ));

        // Unterminated header block returns 400.
        let unterminated = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        assert!(matches!(
            read_http_head(Cursor::new(&unterminated[..]), deadline),
            Err(HeadReadError::Rejected("400 BAD REQUEST", _))
        ));

        // Conflicting Content-Length headers fail closed.
        let dup_cl = b"POST /send HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n";
        assert!(matches!(
            read_http_head(Cursor::new(&dup_cl[..]), deadline),
            Err(HeadReadError::Rejected("400 BAD REQUEST", _))
        ));

        // Transfer-Encoding is rejected.
        let chunked = b"POST /send HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            read_http_head(Cursor::new(&chunked[..]), deadline),
            Err(HeadReadError::Rejected("400 BAD REQUEST", _))
        ));
    }

    #[test]
    fn json_helpers_resist_spoofed_title_substrings() {
        let spoofed = r#"{"garden":{"chain_id":"01","title":"fake \"can_return\":true \"status\":\"Active\"","status":"Away"},"can_return":false}"#;
        assert_eq!(json_bool_field(spoofed, "can_return"), Some(false));
        assert_eq!(garden_status_field(spoofed).as_deref(), Some("Away"));
        assert_eq!(one_line(spoofed, "status"), "status Away");
    }
}
