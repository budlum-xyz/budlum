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

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// A code being answered on this network, and the record it stands for.
pub struct Desk {
    code: String,
    record: String,
    born: Instant,
    stop: Arc<AtomicBool>,
}

impl Desk {
    /// Start answering `code` with `record` until the code expires.
    ///
    /// The socket is bound before the thread starts so that a port
    /// already taken is reported to the caller rather than swallowed by
    /// a background thread nobody is watching.
    pub fn open(code: String, record: String) -> Result<Self, String> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT))
            .map_err(|e| format!("the code desk could not open on {PORT}: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|e| e.to_string())?;

        let stop = Arc::new(AtomicBool::new(false));
        let desk = Self {
            code: code.clone(),
            record: record.clone(),
            born: Instant::now(),
            stop: Arc::clone(&stop),
        };
        let born = desk.born;

        std::thread::spawn(move || {
            let mut buffer = [0u8; MAX_DATAGRAM];
            while !stop.load(Ordering::Relaxed) {
                if born.elapsed() >= LIFETIME {
                    break;
                }
                let (read, from) = match socket.recv_from(&mut buffer) {
                    Ok(got) => got,
                    // A read timeout is the loop breathing, not a fault.
                    Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                    Err(_) => continue,
                };
                let Ok(text) = std::str::from_utf8(&buffer[..read]) else {
                    continue;
                };
                let Some(asked) = text.trim().strip_prefix(ASK) else {
                    continue;
                };
                if asked.trim() != code {
                    continue;
                }
                let reply = format!("{TELL}{record}");
                let _ = socket.send_to(reply.as_bytes(), from);
            }
        });

        Ok(desk)
    }

    /// The six digits a person reads out.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The record the code stands for.
    pub fn record(&self) -> &str {
        &self.record
    }

    /// Seconds left before the code stops working.
    pub fn seconds_left(&self) -> u64 {
        LIFETIME.saturating_sub(self.born.elapsed()).as_secs()
    }

    /// True once the code has run out.
    pub fn expired(&self) -> bool {
        self.born.elapsed() >= LIFETIME
    }
}

impl Drop for Desk {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Shout `code` on the local network and wait for the record.
///
/// `extra` is an address to ask directly as well as by broadcast. It is
/// how this path is tested where broadcast does not reach - two
/// processes on one machine - and how a phone could be pointed at a
/// known address later.
pub fn ask(code: &str, timeout: Duration, extra: Option<SocketAddr>) -> Result<String, String> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
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
                if !record.trim().is_empty() {
                    return Ok(record.trim().to_string());
                }
            }
        }
    }
    Err("nobody on this Wi-Fi answered that code".into())
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
/// Leading zeros are kept: a code is a string of six digits, not a
/// number, so 000123 is a code and not 123.
pub fn fresh_code() -> Result<String, String> {
    // Four bytes, read exactly. /dev/urandom never ends, so reading the
    // whole file would never return.
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("this phone would not give out randomness: {e}"))?;
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("this phone would not give out randomness: {e}"))?;
    let value = u32::from_be_bytes(bytes);
    Ok(format!("{:06}", value % 1_000_000))
}

/// The address a caller can hand to [`ask`] to reach a desk on this
/// same machine, used by the checks that cannot rely on broadcast.
pub fn loopback_desk() -> SocketAddr {
    SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), PORT))
}
