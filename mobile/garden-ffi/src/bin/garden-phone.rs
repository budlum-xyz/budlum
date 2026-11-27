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

use budlum_garden_ffi::GardenPhone;

/// The address the status door opens on.
///
/// Loopback, and not a configurable value: this door answers with the phone's
/// own Garden view and it has no caller authentication, so the only thing that
/// keeps it closed is the address it is bound to. A flag that widened it would
/// be an admin key by another name, and a host that could reach the port could
/// read the Garden without ever holding an invite.
const STATUS_DOOR_ADDRESS: &str = "127.0.0.1";

/// Bytes read from one caller before the door gives up on the request line.
///
/// The listener answers one caller at a time, so a caller that never sends a
/// newline would otherwise hold the door forever.
const STATUS_REQUEST_LINE_LIMIT: u64 = 1024;

/// Socket read and write timeout, for the same reason: a stalled reader must
/// not become the next caller's outage.
const STATUS_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// How many records `/feed` answers with when the caller names no limit, and
/// the ceiling a caller cannot raise.
const FEED_LIMIT_DEFAULT: u32 = 50;
const FEED_LIMIT_MAX: u32 = 500;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let dir = args.get(2).cloned().unwrap_or_default();
    if command.is_empty() || dir.is_empty() {
        eprintln!(
            "usage: garden-phone <self-test|read|join|serve|return-check|status|send|feed|fetch|leave> <dir> [...]"
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
/// can be changed through this door: it reads, and that is all. It is bound to
/// [`STATUS_DOOR_ADDRESS`], not to every interface, because it asks the caller
/// for nothing.
fn serve(phone: &Arc<GardenPhone>, port: u16) -> ExitCode {
    let listener = match open_status_door(port) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("the status door would not open on {STATUS_DOOR_ADDRESS}:{port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("the phone is in the Garden; its status is on {STATUS_DOOR_ADDRESS}:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => answer_one(phone, stream),
            Err(e) => eprintln!("a status reader dropped: {e}"),
        }
    }
    ExitCode::SUCCESS
}

/// Open the status door on loopback only.
///
/// A separate function so the address policy is one thing to read and one
/// thing to test, rather than a literal buried in `serve`.
fn open_status_door(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((STATUS_DOOR_ADDRESS, port))
}

/// What one request line asks the door for.
#[derive(Debug, PartialEq, Eq)]
enum DoorRoute {
    Status,
    Feed(u32),
    Fetch(String),
}

/// The method and target of a request line, or why the door refuses it.
///
/// Only `GET` is answered. The door reads, so a write method is refused with a
/// status of its own instead of being served the status answer, which is what
/// an unrecognised path does.
fn parse_request_line(line: &str) -> Result<(&str, &str), &'static str> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("the request line is empty")?;
    let target = parts.next().ok_or("the request line names no path")?;
    if method != "GET" {
        return Err("only GET is answered");
    }
    Ok((method, target))
}

/// Which answer a path asks for.
///
/// `/feed` and `/fetch/<id>` are the two the Data screen reads; anything else
/// is the status, which is what this door always answered. A `/fetch/` with an
/// empty id is not a read of content id `""`, so it falls back to status the
/// same way an unknown path does.
fn route_for_path(path: &str) -> DoorRoute {
    match path {
        "/feed" => DoorRoute::Feed(FEED_LIMIT_DEFAULT),
        _ => {
            if let Some(rest) = path.strip_prefix("/feed/") {
                return rest
                    .parse::<u32>()
                    .map_or(DoorRoute::Feed(FEED_LIMIT_DEFAULT), |limit| {
                        DoorRoute::Feed(limit.min(FEED_LIMIT_MAX))
                    });
            }
            if let Some(content_id) = path.strip_prefix("/fetch/") {
                if !content_id.is_empty() {
                    return DoorRoute::Fetch(content_id.to_string());
                }
            }
            DoorRoute::Status
        }
    }
}

/// The response head, with no wildcard origin grant.
///
/// `Access-Control-Allow-Origin: *` let any page a person had open read the
/// Garden through their own browser. The door has no cross-origin caller that
/// needs it, so the grant is gone; `nosniff` and `no-store` are here because
/// the body is a live view of a private group and must not be cached or
/// reinterpreted as another content type.
fn response_head(status: &str, body_len: usize) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
    )
}

/// Read the first request line, bounded in size and in time.
///
/// A stream that ends, errors, or sends [`STATUS_REQUEST_LINE_LIMIT`] bytes
/// without a newline is not a request and gets no answer.
fn read_request_line<R: Read>(input: R) -> Option<String> {
    let mut first = String::new();
    let mut reader = BufReader::new(input.take(STATUS_REQUEST_LINE_LIMIT));
    match reader.read_line(&mut first) {
        Ok(0) | Err(_) => None,
        Ok(_) if !first.ends_with('\n') => None,
        Ok(_) => Some(first),
    }
}

fn answer_one(phone: &Arc<GardenPhone>, mut stream: TcpStream) {
    // Both timeouts are set before a byte is read, so a caller cannot hold the
    // single-threaded accept loop by opening a connection and saying nothing.
    let _ = stream.set_read_timeout(Some(STATUS_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(STATUS_IO_TIMEOUT));
    // The first line names what is being asked for. Nothing here writes to
    // the Garden: `status` is the phone's view, `feed` is what the Garden
    // holds and `fetch` reads one object back out by content id. A path this
    // door does not know answers the status, which is what it always did.
    let first = match read_request_line(&stream) {
        Some(first) => first,
        None => return,
    };
    let (status, body) = match parse_request_line(&first) {
        Err(reason) => (
            "405 METHOD NOT ALLOWED",
            format!("{{\"error\":{}}}", json_string(reason)),
        ),
        Ok((_method, path)) => {
            let answer = match route_for_path(path) {
                DoorRoute::Feed(limit) => phone.feed(limit),
                DoorRoute::Fetch(content_id) => phone.fetch(content_id),
                DoorRoute::Status => phone.status(),
            };
            // A refusal is not a success with a sad body. A caller that only
            // reads the status line - which is most of them - would take
            // `{"error":...}` for an answer and go on to parse a Garden that
            // was never read. The status says which it was, and the body says
            // why.
            match answer {
                Ok(answer) => ("200 OK", answer.json),
                Err(e) => (
                    "409 CONFLICT",
                    format!("{{\"error\":{}}}", json_string(&e.to_string())),
                ),
            }
        }
    };
    let head = response_head(status, body.len());
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod status_door_tests {
    use super::*;

    /// The door must not be reachable from another host: the address it binds
    /// is the whole of its access control.
    #[test]
    fn the_status_door_opens_on_loopback_and_nothing_else() {
        assert_eq!(STATUS_DOOR_ADDRESS, "127.0.0.1");
        let bound = open_status_door(0).map(|listener| listener.local_addr().map(|a| a.ip()));
        assert!(
            matches!(bound, Ok(Ok(ip)) if ip.is_loopback()),
            "the status door bound to {bound:?}, not to loopback"
        );
    }

    /// The wildcard grant is what let a page read the Garden; it must not come
    /// back through another spelling of the same header.
    #[test]
    fn the_response_head_grants_no_cross_origin_reader() {
        let head = response_head("200 OK", 7);
        assert!(
            !head.to_ascii_lowercase().contains("access-control"),
            "the head still carries a CORS grant: {head:?}"
        );
        assert!(
            head.to_ascii_lowercase().contains("x-content-type-options: nosniff"),
            "the head does not refuse a sniffed content type: {head:?}"
        );
        assert!(
            head.to_ascii_lowercase().contains("cache-control: no-store"),
            "the head does not refuse a cached Garden view: {head:?}"
        );
    }

    /// The declared length is the body a caller reads; an off-by-one here is a
    /// truncated or hung reader.
    #[test]
    fn the_response_head_declares_the_exact_body_length() {
        let head = response_head("200 OK", 11);
        assert!(
            head.contains("Content-Length: 11\r\n"),
            "the head declares another length: {head:?}"
        );
    }

    /// A caller that writes a write method is refused, and the door says so
    /// with a status: serving it the status answer would report success for a
    /// request that was never allowed.
    #[test]
    fn a_write_method_is_refused_with_its_own_status() {
        assert!(parse_request_line("POST /feed HTTP/1.1\r\n").is_err());
        assert!(parse_request_line("DELETE / HTTP/1.1\r\n").is_err());
        assert!(parse_request_line("GET /feed/3 HTTP/1.1\r\n").is_ok());
        assert!(parse_request_line("\r\n").is_err());
    }

    /// The three reads the Data screen makes, and the fallback for everything
    /// else that has always answered the status.
    #[test]
    fn the_route_splits_the_three_reads_from_everything_else() {
        assert_eq!(route_for_path("/"), DoorRoute::Status);
        assert_eq!(route_for_path("/status"), DoorRoute::Status);
        assert_eq!(route_for_path("/feed"), DoorRoute::Feed(FEED_LIMIT_DEFAULT));
        assert_eq!(route_for_path("/feed/3"), DoorRoute::Feed(3));
        assert_eq!(route_for_path("/feed/999999"), DoorRoute::Feed(FEED_LIMIT_MAX));
        assert_eq!(route_for_path("/feed/two"), DoorRoute::Feed(FEED_LIMIT_DEFAULT));
        assert_eq!(route_for_path("/fetch/abc"), DoorRoute::Fetch("abc".into()));
        assert_eq!(route_for_path("/fetch/"), DoorRoute::Status);
        assert_eq!(route_for_path("/../etc/passwd"), DoorRoute::Status);
    }

    /// A request line that never ends must not hold the door: the limit is the
    /// reason the accept loop cannot be stalled by one silent caller.
    #[test]
    fn an_unterminated_request_line_is_refused() {
        assert!(read_request_line(&b"GET / HTTP/1.1\r\n"[..]).is_some());
        assert!(read_request_line(&[b'A'; 4096][..]).is_none());
        assert!(read_request_line(&b""[..]).is_none());
    }
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
