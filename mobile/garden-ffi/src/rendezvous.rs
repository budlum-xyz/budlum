//! Six digits instead of a link.
//!
//! An invite record carries a chain id, a genesis hash, a token and a
//! multiaddr. That is far more than a person can read out loud, and the
//! link form of it did not survive being pasted around. Six digits do
//! survive: they can be said across a table, typed with a thumb, and
//! they expire.
//!
//! Six digits are about twenty bits, so the code cannot *be* the invite.
//! It is a meeting point. The phone that started the network answers to
//! the code on the local network and hands back the real record; the
//! phone joining broadcasts the code and takes what comes back. That
//! only works between phones on one Wi-Fi, which is the same condition
//! the Garden already has - a phone with no address the others can dial
//! cannot host one either.
//!
//! Nothing here is a secret channel. The code is short-lived and single
//! purpose: it gets the record across the room. What the record buys is
//! a seat in the waiting row, not a seat at the table - the host still
//! has to admit the key.
//!
//! Two things make it behave like the code an e-mail sends you rather
//! than a walkie-talkie channel. It is written down, so closing the app
//! and opening it again an hour later finds the same code with the time
//! it has left, instead of a dead desk and a number the other person is
//! still holding. And it burns: the first phone to redeem it gets the
//! record, and the digits stop meaning anything from that moment, so a
//! code said out loud in a room cannot be used twice.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The port both sides agree on. Chosen high and fixed so neither phone
/// has to tell the other anything except the six digits.
pub const PORT: u16 = 45678;

/// How long a code is good for.
pub const LIFETIME: Duration = Duration::from_secs(60 * 60);

/// What a joining phone shouts, with the code appended.
const ASK: &str = "BUDLUM-GARDEN-ASK ";

/// What the hosting phone shouts back, with the record appended.
const TELL: &str = "BUDLUM-GARDEN-TELL ";

/// Longest datagram either side will read. An invite record is a few
/// hundred bytes; this leaves room without inviting a flood.
const MAX_DATAGRAM: usize = 4096;

/// Longest invite record accepted from a local-network reply.
const MAX_RECORD_LEN: usize = 2048;

/// Number of six-digit codes (`000000` through `999999`).
const CODE_SPACE: u32 = 1_000_000;

/// Largest multiple of `CODE_SPACE` that fits in `u32`, for rejection sampling
/// without modulo bias.
const UNIFORM_BOUND: u32 = (u32::MAX / CODE_SPACE) * CODE_SPACE;

/// A code being answered on this network, and the record it stands for.
pub struct Desk {
    code: String,
    record: String,
    port: u16,
    /// Wall clock, not a monotonic instant: the hour has to keep running
    /// while the app is closed, and an `Instant` does not survive that.
    born: u64,
    /// Set by the answering thread the moment it hands the record over.
    /// Read by everything else to know the code is spent.
    burnt: Arc<AtomicBool>,
    /// Where the code is written down, if it is written down at all.
    note: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

/// Seconds since the epoch, or zero if the clock is before it.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Desk {
    /// Start answering `code` with `record` on [`PORT`] until the code expires.
    ///
    /// The socket is bound before the thread starts so that a port
    /// already taken is reported to the caller rather than swallowed by
    /// a background thread nobody is watching.
    pub fn open(code: String, record: String) -> Result<Self, String> {
        Self::open_on(PORT, code, record)
    }

    /// Open a code and write it down in `dir`, so it survives a restart.
    pub fn open_noted(dir: &Path, code: String, record: String) -> Result<Self, String> {
        let born = now_secs();
        let path = note_path(dir);
        // Written down before the desk starts answering. The other order
        // leaves a note behind for a code that was already redeemed, and
        // a restart would then put a spent code back on the air.
        write_note(&path, &code, born, &record)?;
        match Self::start(PORT, code, record, born, Some(path.clone())) {
            Ok(desk) => Ok(desk),
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                Err(e)
            }
        }
    }

    /// Pick up a code written down earlier, if it is still good.
    ///
    /// A code outlives the process that opened it. Without this the
    /// first thing a restart did was forget a number somebody else was
    /// holding, and the only cure was to read out a new one.
    pub fn resume(dir: &Path) -> Option<Self> {
        let path = note_path(dir);
        let text = std::fs::read_to_string(&path).ok()?;
        let mut lines = text.lines();
        let code = lines.next()?.trim().to_owned();
        let born: u64 = lines.next()?.trim().parse().ok()?;
        let record = lines.collect::<Vec<_>>().join("\n");
        if !is_valid_code(&code) || !is_valid_record(&record) {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        if now_secs().saturating_sub(born) >= LIFETIME.as_secs() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        match Self::start(PORT, code, record, born, Some(path.clone())) {
            Ok(desk) => Some(desk),
            Err(_) => None,
        }
    }

    /// Start answering `code` with `record` on `port` until the code expires.
    pub fn open_on(port: u16, code: String, record: String) -> Result<Self, String> {
        Self::start(port, code, record, now_secs(), None)
    }

    fn start(
        port: u16,
        code: String,
        record: String,
        born: u64,
        note: Option<PathBuf>,
    ) -> Result<Self, String> {
        if !is_valid_code(&code) {
            return Err("a code is six digits".into());
        }
        if !is_valid_record(&record) {
            return Err("the invite record is empty or malformed".into());
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
            .map_err(|e| format!("the code desk could not open on {port}: {e}"))?;
        let bound_port = socket
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(port);
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|e| e.to_string())?;

        let stop = Arc::new(AtomicBool::new(false));
        let burnt = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let burnt_flag = Arc::clone(&burnt);
        let note_for_thread = note.clone();
        let match_code = code.clone();
        let reply_record = record.clone();

        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; MAX_DATAGRAM];
            while !stop_flag.load(Ordering::Acquire) {
                if now_secs().saturating_sub(born) >= LIFETIME.as_secs() {
                    break;
                }
                if burnt_flag.load(Ordering::Acquire) {
                    break;
                }
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(got) => got,
                    // A read timeout is the loop breathing, not a fault.
                    Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                    Err(_) => continue,
                };
                if stop_flag.load(Ordering::Acquire) {
                    break;
                }
                let Ok(text) = std::str::from_utf8(&buffer[..read]) else {
                    continue;
                };
                let Some(asked) = text.trim().strip_prefix(ASK) else {
                    continue;
                };
                if asked.trim() != match_code {
                    continue;
                }
                let reply = format!("{TELL}{reply_record}");
                if socket.send_to(reply.as_bytes(), from).is_ok() {
                    // Spent. One redemption is the whole contract: the
                    // next phone to try these digits finds nothing,
                    // whoever they are and however they got them.
                    burnt_flag.store(true, Ordering::Release);
                    if let Some(path) = note_for_thread.as_ref() {
                        let _ = std::fs::remove_file(path);
                    }
                    break;
                }
            }
        });

        Ok(Self {
            code,
            record,
            port: bound_port,
            born,
            burnt,
            note,
            stop,
            handle: Some(handle),
        })
    }

    /// True once somebody has redeemed the code.
    pub fn burnt(&self) -> bool {
        self.burnt.load(Ordering::Acquire)
    }

    /// Put the code out by hand, and rub out what was written down.
    pub fn burn(&self) {
        self.burnt.store(true, Ordering::Release);
        if let Some(path) = self.note.as_ref() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// The six digits a person reads out.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The record the code stands for.
    pub fn record(&self) -> &str {
        &self.record
    }

    /// The UDP port this desk is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Seconds left before the code stops working.
    pub fn seconds_left(&self) -> u64 {
        if self.burnt() {
            return 0;
        }
        LIFETIME
            .as_secs()
            .saturating_sub(now_secs().saturating_sub(self.born))
    }

    /// True once the code has run out or been used.
    pub fn expired(&self) -> bool {
        self.burnt() || now_secs().saturating_sub(self.born) >= LIFETIME.as_secs()
    }
}

impl Drop for Desk {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Nudge the blocked recv_from on loopback so the thread exits and
        // releases the UDP port immediately rather than waiting for timeout.
        if let Ok(wake) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
            let _ = wake.send_to(b"", (Ipv4Addr::LOCALHOST, self.port));
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Where an open code is written down inside the app's own directory.
fn note_path(dir: &Path) -> PathBuf {
    dir.join("open-code.txt")
}

/// Write the code, the hour it started and the record it stands for.
fn write_note(path: &Path, code: &str, born: u64, record: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("the code could not be written down: {e}"))?;
    }
    std::fs::write(path, format!("{code}\n{born}\n{record}"))
        .map_err(|e| format!("the code could not be written down: {e}"))
}

/// Shout `code` on the local network and wait for the record.
///
/// `extra` is an address to ask directly as well as by broadcast. It is
/// how this path is tested where broadcast does not reach - two
/// processes on one machine - and how a phone could be pointed at a
/// known address later.
pub fn ask(code: &str, timeout: Duration, extra: Option<SocketAddr>) -> Result<String, String> {
    if !is_valid_code(code) {
        return Err("a code is six digits".into());
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("this phone could not open a socket to ask: {e}"))?;
    socket.set_broadcast(true).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| e.to_string())?;

    let question = format!("{ASK}{code}");
    let mut targets: Vec<SocketAddr> = vec![
        SocketAddr::from((Ipv4Addr::BROADCAST, PORT)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, PORT)),
    ];
    targets.extend(broadcast_addresses());
    if let Some(one) = extra {
        targets.push(one);
    }

    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; MAX_DATAGRAM];
    let mut last_error = String::new();
    while Instant::now() < deadline {
        let mut reached = false;
        for target in &targets {
            match socket.send_to(question.as_bytes(), target) {
                Ok(_) => reached = true,
                Err(e) => last_error = e.to_string(),
            }
        }
        if !reached {
            return Err(format!(
                "this phone could not reach the network to ask: {last_error}"
            ));
        }
        // Several answers can arrive; the first well-formed one wins.
        while let Ok((read, _)) = socket.recv_from(&mut buffer) {
            let Ok(text) = std::str::from_utf8(&buffer[..read]) else {
                continue;
            };
            if let Some(record) = text.trim().strip_prefix(TELL) {
                let candidate = record.trim();
                if is_valid_record(candidate) {
                    return Ok(candidate.to_string());
                }
            }
        }
    }
    Err("nobody on this Wi-Fi answered that code".into())
}

/// True when `code` is exactly six ASCII digits.
fn is_valid_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

/// True when a local-network reply carries a bounded, printable invite record
/// with no control characters.
fn is_valid_record(record: &str) -> bool {
    let trimmed = record.trim();
    !trimmed.is_empty()
        && trimmed.len() <= MAX_RECORD_LEN
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ')
}

/// Broadcast addresses worth shouting at besides 255.255.255.255.
///
/// Some Android builds drop the all-ones broadcast but pass a subnet
/// one, so the /24 of every address this phone holds is tried too. It
/// is a guess at the mask, and a wrong guess costs one stray datagram.
fn broadcast_addresses() -> Vec<SocketAddr> {
    let mut found = Vec::new();
    for ip in local_addresses() {
        let octets = ip.octets();
        let subnet = Ipv4Addr::new(octets[0], octets[1], octets[2], 255);
        found.push(SocketAddr::from((subnet, PORT)));
    }
    found
}

/// The IPv4 addresses this machine answers on, learned by asking the
/// routing table rather than by listing interfaces, which needs a crate.
fn local_addresses() -> Vec<Ipv4Addr> {
    let mut found = Vec::new();
    for probe in ["198.51.100.1:9", "192.168.1.1:9", "10.0.0.1:9"] {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect(probe).is_err() {
            continue;
        }
        if let Ok(SocketAddr::V4(local)) = socket.local_addr() {
            let ip = *local.ip();
            if !ip.is_loopback() && !ip.is_unspecified() && !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

/// Six digits from the operating system's randomness.
///
/// Read straight from the kernel because this crate has no random
/// number dependency and a code guessed from the clock is not a code.
/// If the kernel cannot be read the call fails rather than quietly
/// handing back something predictable.
///
/// Rejection sampling keeps all one million six-digit codes strictly
/// uniform. Leading zeros are kept: a code is a string of six digits,
/// not a number, so 000123 is a code and not 123.
pub fn fresh_code() -> Result<String, String> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("this phone would not give out randomness: {e}"))?;
    let mut bytes = [0u8; 4];
    for _ in 0..64 {
        file.read_exact(&mut bytes)
            .map_err(|e| format!("this phone would not give out randomness: {e}"))?;
        let value = u32::from_be_bytes(bytes);
        if value < UNIFORM_BOUND {
            return Ok(format!("{:06}", value % CODE_SPACE));
        }
    }
    Err("this phone would not give out unbiased randomness".into())
}

/// The address a caller can hand to [`ask`] to reach a desk on this
/// same machine, used by the checks that cannot rely on broadcast.
pub fn loopback_desk() -> SocketAddr {
    SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), PORT))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A code is a one-time password, not a channel. The second phone to
    /// try the same digits must come away with nothing, or a code read
    /// out in a room full of people lets in everyone who overheard it.
    #[test]
    fn a_redeemed_code_cannot_be_redeemed_again() {
        let desk = Desk::open_on(0, "314159".into(), "budlum://garden/join#once".into())
            .expect("desk opens");
        let addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), desk.port()));

        let first = ask("314159", Duration::from_secs(2), Some(addr))
            .expect("the first redemption is answered");
        assert_eq!(first, "budlum://garden/join#once");

        let second = ask("314159", Duration::from_millis(600), Some(addr));
        assert!(second.is_err(), "a spent code must not answer twice");
        assert!(desk.burnt(), "the desk knows the code is spent");
        assert_eq!(desk.seconds_left(), 0, "a spent code has no time left");
        assert!(desk.expired(), "a spent code counts as over");
    }

    /// The hour belongs to the code, not to the process. Closing the app
    /// used to cancel a number the other person was still holding.
    #[test]
    fn a_written_down_code_survives_the_process_that_opened_it() {
        let dir = std::env::temp_dir().join(format!("budlum-code-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let _ = std::fs::remove_file(note_path(&dir));

        let opened = Desk::open_noted(&dir, "271828".into(), "budlum://garden/join#kept".into())
            .expect("desk opens and is written down");
        let left = opened.seconds_left();
        assert!(left > LIFETIME.as_secs() - 5, "a fresh code has its hour");
        drop(opened);

        let resumed = Desk::resume(&dir).expect("the code is picked back up");
        assert_eq!(resumed.code(), "271828");
        assert_eq!(resumed.record(), "budlum://garden/join#kept");
        assert!(
            resumed.seconds_left() + 5 >= left,
            "the hour continues where it was"
        );
        resumed.burn();
        drop(resumed);

        assert!(
            Desk::resume(&dir).is_none(),
            "a burnt code is not picked back up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_desk_immediately_after_drop_releases_port() {
        let first = Desk::open_on(0, "123456".into(), "budlum://garden/join#first".into())
            .expect("first desk opens");
        let port = first.port();
        drop(first);

        let second = Desk::open_on(port, "654321".into(), "budlum://garden/join#second".into())
            .expect("second desk rebinds immediately after drop");
        let addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        let got = ask("654321", Duration::from_secs(2), Some(addr))
            .expect("ask receives refreshed record");
        assert_eq!(got, "budlum://garden/join#second");
        drop(second);
    }

    #[test]
    fn wrong_code_is_not_answered() {
        let desk = Desk::open_on(0, "004219".into(), "budlum://garden/join#secret".into())
            .expect("desk opens");
        let addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), desk.port()));
        let err = ask("999999", Duration::from_millis(500), Some(addr))
            .expect_err("wrong code must time out");
        assert!(err.contains("answered"));
        drop(desk);
    }

    #[test]
    fn invalid_codes_are_refused_fail_closed() {
        for bad in ["", "12345", "1234567", "12a456", " 12345"] {
            assert!(ask(bad, Duration::from_millis(50), None).is_err());
            assert!(Desk::open_on(0, bad.into(), "budlum://garden/join#x".into()).is_err());
        }
    }

    #[test]
    fn spoofed_control_char_or_oversized_tell_is_ignored() {
        assert!(!is_valid_record(""));
        assert!(!is_valid_record("   "));
        assert!(!is_valid_record("budlum://garden/join#a\nInjected: 1"));
        assert!(!is_valid_record(&"a".repeat(MAX_RECORD_LEN + 1)));
        assert!(is_valid_record("budlum://garden/join#abc123"));
    }

    #[test]
    fn fresh_code_is_always_six_ascii_digits() {
        for _ in 0..32 {
            let code = fresh_code().expect("fresh code");
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
