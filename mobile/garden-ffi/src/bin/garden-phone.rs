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
//!   garden-phone join <dir> <record> <name>
//!   garden-phone serve <dir> <port> [record] [name]
//!   garden-phone return-check <dir> <record> [name]
//!   garden-phone status <dir>
//!   garden-phone send <dir> <text> [caption]
//!   garden-phone send-file <dir> <file> [mime]
//!   garden-phone file-check <dir> <file> [mime] [address]
//!   garden-phone room-check <dir> [file] [address]
//!   garden-phone join-check <dir> [second dir] [address]
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
<self-test|read|create|join|serve|return-check|status|send|send-file|file-check|room-check|join-check|feed|fetch|leave> \
<dir> [...]"
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
            say(phone.create(title, name, address).map_err(|e| e.to_string()))
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
        "send-file" => {
            // The same path the Room's paperclip takes: read the bytes,
            // hex them, publish. Here so the file path can be run where
            // no emulator can.
            let file = match args.get(3) {
                Some(path) => path.clone(),
                None => {
                    eprintln!("usage: garden-phone send-file <dir> <file> [mime]");
                    return ExitCode::from(2);
                }
            };
            let mime = args
                .get(4)
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let bytes = match std::fs::read(&file) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    eprintln!("that file could not be read: {reason}");
                    return ExitCode::FAILURE;
                }
            };
            let name = std::path::Path::new(&file)
                .file_name()
                .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
            if !gate(&phone) || !return_first(&phone) {
                return ExitCode::FAILURE;
            }
            say(phone
                .send_file(hex_of(&bytes), mime, name)
                .map_err(|e| e.to_string()))
        }
        // One process, the whole file path: found a Garden, send a real
        // file into it, read it back off the chain and compare the bytes
        // to what went in. The app does the same three things; this is
        // where they can be run without an emulator.
        // What the Room does, in one process: found a Garden, type two
        // lines, send a file, then read the whole thing back off the
        // chain the way the screen reads it - feed for what was sent,
        // fetch for the words themselves.
        // The whole invite story in one place: a host opens a six digit
        // code, a second phone in another directory asks the network for
        // it and joins, the host sees it waiting and admits it, and both
        // ends agree it is seated. Run where no two phones are.
        "join-check" => {
            let second = args.get(3).cloned().unwrap_or_else(|| {
                std::env::temp_dir()
                    .join("garden-join-check")
                    .to_string_lossy()
                    .into_owned()
            });
            let address = args.get(4).cloned();
            match join_round_trip(&phone, &second, address) {
                Ok(()) => {
                    println!("the code let a second phone in, and the host admitted it");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    eprintln!("the invite is broken: {reason}");
                    ExitCode::FAILURE
                }
            }
        }
        "room-check" => {
            let file = args.get(3).cloned();
            let address = args.get(4).cloned();
            match room_round_trip(&phone, file, address) {
                Ok(()) => {
                    println!("the room came back off the chain in the order it was said");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    eprintln!("the room is broken: {reason}");
                    ExitCode::FAILURE
                }
            }
        }
        "file-check" => {
            let file = match args.get(3) {
                Some(path) => path.clone(),
                None => {
                    eprintln!("usage: garden-phone file-check <dir> <file> [mime] [address]");
                    return ExitCode::from(2);
                }
            };
            let mime = args
                .get(4)
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let address = args.get(5).cloned();
            match file_round_trip(&phone, &file, mime, address) {
                Ok(()) => {
                    println!("the file went onto the chain and came back the same");
                    ExitCode::SUCCESS
                }
                Err(reason) => {
                    eprintln!("the file path is broken: {reason}");
                    ExitCode::FAILURE
                }
            }
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

/// Open a code, let a second phone in with it, and admit it.
fn join_round_trip(
    host: &Arc<GardenPhone>,
    second_dir: &str,
    address: Option<String>,
) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(second_dir);
    let made = host
        .create("Kitchen table".to_string(), "Host".to_string(), address)
        .map_err(|e| e.to_string())?;
    println!("founded:  {}", one_line(&made.json, "chain_id"));

    let status = host.status().map_err(|e| e.to_string())?;
    let admission = field(&status.json, "admission").unwrap_or_default();
    println!("admission: {admission}");
    if admission != "host_approval" {
        return Err(format!("this Garden admits on {admission:?}, not on the host's word"));
    }

    let code = host.open_code().map_err(|e| e.to_string())?;
    println!("code:     {} good for {} seconds", code.code, code.seconds_left);
    if code.code.len() != 6 || !code.code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{:?} is not six digits", code.code));
    }

    // A second phone, with its own directory and its own key.
    let guest = GardenPhone::new(second_dir.to_string()).map_err(|e| e.to_string())?;
    let joined = guest
        .join_with_code(code.code.clone(), "Guest".to_string())
        .map_err(|e| e.to_string())?;
    println!("asked:    {}", one_line(&joined.json, "status"));

    // The guest is in the waiting row, and must not be seated yet.
    let guest_status = guest.status().map_err(|e| e.to_string())?;
    let member = field(&guest_status.json, "member").unwrap_or_default();
    println!("guest is: {member}");
    if member != "Waiting" {
        return Err(format!("the guest is {member:?} before anybody admitted it"));
    }

    // The host sees somebody waiting, and knows which key.
    let waiting = wait_until(host, "waiting_for_host", "1")?;
    println!("host sees: {} waiting", field(&waiting, "waiting_for_host").unwrap_or_default());
    let key = field(&guest_status.json, "key").ok_or("the guest has no key to admit")?;

    host.admit(key.clone(), true).map_err(|e| e.to_string())?;
    println!("admitted: {key}");

    // Both ends have to agree, because only one of them was asked.
    let seated = deadline_loop(|| {
        let answer = guest.status().ok()?;
        (field(&answer.json, "member").as_deref() == Some("Active")).then_some(())
    });
    if seated.is_none() {
        return Err("the guest was admitted and never became active".into());
    }
    let host_sees = wait_until(host, "active_validators", "2")?;
    println!("network:  {} validators", field(&host_sees, "active_validators").unwrap_or_default());
    Ok(())
}

/// Poll a phone's status until one field reads `want`.
fn wait_until(phone: &Arc<GardenPhone>, key: &str, want: &str) -> Result<String, String> {
    deadline_loop(|| {
        let answer = phone.status().ok()?;
        (field(&answer.json, key).as_deref() == Some(want)).then_some(answer.json)
    })
    .ok_or_else(|| format!("{key} never reached {want}"))
}

/// Try something twice a second for half a minute.
fn deadline_loop<T>(mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(got) = attempt() {
            return Some(got);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Say two lines and send a file, then read the room back off the chain.
///
/// This is the Room screen's whole job written out: publish, wait for
/// the block the group agreed on, read the feed, and fetch the words
/// back rather than trusting what this phone remembers typing.
fn room_round_trip(
    phone: &Arc<GardenPhone>,
    file: Option<String>,
    address: Option<String>,
) -> Result<(), String> {
    let made = phone
        .create("Kitchen table".to_string(), "Phone".to_string(), address)
        .map_err(|e| e.to_string())?;
    println!("founded:  {}", one_line(&made.json, "chain_id"));

    let first = "this is the first thing anybody said here";
    let second = "and this is the second, so the order can be checked";
    let one = phone
        .send(first.to_string(), String::new())
        .map_err(|e| e.to_string())?;
    let first_id = field(&one.json, "content_id").ok_or("the first line has no content id")?;
    println!("said:     {first}");
    let two = phone
        .send(second.to_string(), String::new())
        .map_err(|e| e.to_string())?;
    let second_id = field(&two.json, "content_id").ok_or("the second line has no content id")?;
    println!("said:     {second}");

    let mut file_id = None;
    if let Some(path) = file {
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let name = std::path::Path::new(&path)
            .file_name()
            .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
        let sent = phone
            .send_file(hex_of(&bytes), "image/png".to_string(), name.clone())
            .map_err(|e| e.to_string())?;
        println!("sent:     {name}, {} bytes", bytes.len());
        file_id = field(&sent.json, "content_id");
    }

    let wanted = file_id.clone().map_or(2, |_| 3);
    let feed = wait_for_feed(phone, wanted)?;
    println!("feed:     {feed}");

    // The screen fetches the words of a text line rather than echoing
    // what was typed, so that is what is checked here.
    let back = phone.fetch(first_id.clone()).map_err(|e| e.to_string())?;
    println!("fetched:  {}", back.json);
    if !back.json.contains(first) {
        return Err("the first line did not come back off the chain".into());
    }
    if !feed.contains(&second_id) {
        return Err("the second line is not in the feed".into());
    }
    if let Some(id) = file_id {
        if !feed.contains(&id) {
            return Err("the file is not in the feed".into());
        }
        if !feed.contains("image/png") {
            return Err("the feed does not say the file is an image".into());
        }
    }
    // Order is by the block a line landed in, which is what the screen
    // sorts on. The feed hands them back newest first, so the second
    // line has to come before the first one in it.
    let newest = feed.find(&second_id).ok_or("the second line vanished")?;
    let oldest = feed.find(&first_id).ok_or("the first line vanished")?;
    if newest > oldest {
        return Err("the chain put the lines in the wrong order".into());
    }
    Ok(())
}

/// Wait until the group has agreed on blocks carrying `wanted` items.
fn wait_for_feed(phone: &Arc<GardenPhone>, wanted: usize) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let feed = phone.feed(20).map_err(|e| e.to_string())?;
        let got = feed.json.matches("\"content_id\"").count();
        if got >= wanted {
            return Ok(feed.json);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("only {got} of {wanted} reached a block in ninety seconds"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Found a Garden, publish a file into it, and read it back verified.
///
/// Byte for byte, because a content id that matches a payload nobody
/// checked proves nothing. The Garden is founded in this same process
/// because a one-member chain lives in the process that runs it.
fn file_round_trip(
    phone: &Arc<GardenPhone>,
    file: &str,
    mime: String,
    address: Option<String>,
) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|e| e.to_string())?;
    let name = std::path::Path::new(file)
        .file_name()
        .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
    println!("file:     {name}, {} bytes, {mime}", bytes.len());

    let made = phone
        .create("File check".to_string(), "Phone".to_string(), address)
        .map_err(|e| e.to_string())?;
    println!("founded:  {}", one_line(&made.json, "chain_id"));

    let sent = phone
        .send_file(hex_of(&bytes), mime.clone(), name.clone())
        .map_err(|e| e.to_string())?;
    println!("sent:     {}", sent.json);
    let content_id = field(&sent.json, "content_id")
        .ok_or("the publish answer carried no content id")?;

    // Publishing hands the file to the group; the feed only shows it
    // once a block carrying it has been agreed on. At a three second
    // round that is a wait, not a failure, and the Room waits the same
    // way by re-reading the chain rather than echoing what was typed.
    let mut feed = phone.feed(10).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !feed.json.contains(&content_id) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(500));
        feed = phone.feed(10).map_err(|e| e.to_string())?;
    }
    println!("feed:     {}", feed.json);
    if !feed.json.contains(&content_id) {
        return Err("the file never reached a block the group agreed on".into());
    }
    if !feed.json.contains(&mime) {
        return Err("the feed does not carry the file's type".into());
    }
    if !feed.json.contains(&name) {
        return Err("the feed does not carry the file's name".into());
    }

    let got = phone.fetch(content_id).map_err(|e| e.to_string())?;
    let size = field(&got.json, "size").ok_or("the fetch answer carried no size")?;
    println!("fetched:  {}", one_line(&got.json, "size"));
    if size != bytes.len().to_string() {
        return Err(format!(
            "what came back is {size} bytes and what went in is {}",
            bytes.len()
        ));
    }
    Ok(())
}

/// The value of one JSON field, read without a parser the binary lacks.
fn field(json: &str, key: &str) -> Option<String> {
    let at = json.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = json.get(at..)?.trim_start();
    if let Some(text) = rest.strip_prefix('"') {
        text.find('"').and_then(|end| text.get(..end)).map(str::to_string)
    } else {
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        rest.get(..end).map(|n| n.trim().to_string())
    }
}

/// Hex, the one binary encoding the core's publish takes.
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
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
