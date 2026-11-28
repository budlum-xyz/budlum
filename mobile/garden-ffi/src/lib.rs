//! The Garden a phone runs, as the app calls it.
//!
//! Section 9.1 of the optimisation directive says the APK carries the same
//! core the testnet node carries, and that no separate Garden node, demo or
//! simulation is written for it. So this crate holds no Garden logic at
//! all: every call below hands straight over to `budlum_core::garden`,
//! which is the code the Linux validators run. What it does add is the two
//! things a phone needs and a server does not: somewhere to run async code
//! from a synchronous Kotlin call, and the self test of section 4.
//!
//! `GardenService::new` takes the Budlum chain handle as an `Option`. A
//! Garden is a sovereign PoA domain with no bridge, so the phone passes
//! `None` and still runs a complete validator: it proposes, it votes, it
//! holds parts and it executes blocks. The chain handle only adds the
//! domain registry and the finality adapter, neither of which a Garden
//! needs in order to be a Garden. That is what lets the phone be a full
//! validator (sections 1.2 and 6.1) rather than a viewer.
//!
//! Section 2.8 keeps message, post and trace queries out of the app, so
//! they are not exported here even though the core has them.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use budlum_core::garden::{GardenOptions, GardenService};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// What the screens get back: the JSON the Garden RPC already answers
/// with, as text.
///
/// The shapes are the ones `bud_garden*` returns, so the app and a Linux
/// operator read the same fields and nothing is redefined on the phone.
#[derive(uniffi::Record)]
pub struct GardenAnswer {
    /// The JSON body, verbatim from the core.
    pub json: String,
}

/// One check of the first run self test.
#[derive(uniffi::Record)]
pub struct SelfTestStep {
    /// What was tried, in words a person can read.
    pub name: String,
    /// Whether it worked.
    pub passed: bool,
    /// What went wrong, when something did.
    pub detail: String,
}

/// The whole self test of section 4.
#[derive(uniffi::Record)]
pub struct SelfTestReport {
    /// Every step, in the order they ran.
    pub steps: Vec<SelfTestStep>,
    /// True only when every step passed.
    pub passed: bool,
    /// How long the whole thing took.
    pub elapsed_ms: u64,
}

/// What a Garden call can refuse with.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GardenError {
    /// The core refused, and this is what it said.
    #[error("{reason}")]
    Refused {
        /// The refusal, passed through unchanged.
        reason: String,
    },
}

impl GardenError {
    fn of(reason: impl Into<String>) -> Self {
        Self::Refused {
            reason: reason.into(),
        }
    }
}

/// The phone's Garden validator.
#[derive(uniffi::Object)]
pub struct GardenPhone {
    runtime: Runtime,
    service: GardenService,
    data_dir: PathBuf,
    local_http_address: Mutex<Option<String>>,
}

#[uniffi::export]
impl GardenPhone {
    /// Open the validator against a directory the app owns.
    ///
    /// Nothing is asked of the person: section 4 puts the identity and the
    /// seed in the hands of the APK, and the core makes its own validator
    /// key when a Garden is created or joined.
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, GardenError> {
        if data_dir.trim().is_empty() || data_dir.contains('\0') {
            return Err(GardenError::of(
                "the app directory path is empty or invalid",
            ));
        }
        let dir = PathBuf::from(&data_dir);
        if !Path::new(&data_dir).is_absolute() {
            return Err(GardenError::of("the app directory path must be absolute"));
        }
        std::fs::create_dir_all(&dir)
            .map_err(|e| GardenError::of(format!("the app directory is not writable: {e}")))?;
        // A phone has few cores and a battery. The core's own round timing
        // does the pacing, so the runtime only has to not fight it.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| GardenError::of(format!("no async runtime: {e}")))?;
        let service = GardenService::new(None, Some(dir.clone()));
        Ok(Arc::new(Self {
            runtime,
            service,
            data_dir: dir,
            local_http_address: Mutex::new(None),
        }))
    }

    /// Register or clear the phone's local HTTP `host:port` share address so
    /// [`Self::invite`] formats `record_qr` as `http://<addr>/g#<record>`.
    pub fn set_local_http_address(&self, address: Option<String>) -> Result<(), GardenError> {
        let cleaned = match address {
            Some(raw) => {
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else if !is_valid_http_host_port(&trimmed) {
                    return Err(GardenError::of(
                        "local HTTP address must be bare host or host:port without URL delimiters",
                    ));
                } else {
                    Some(trimmed)
                }
            }
            None => None,
        };
        let mut guard = self
            .local_http_address
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = cleaned;
        Ok(())
    }

    /// Start a Garden and become its host.
    ///
    /// A host is dialled by everyone it invites, so unlike a joiner it
    /// cannot leave its address unsaid. Listening on every interface is
    /// right for a phone - it moves between networks - but "every
    /// interface" is not an address anybody can dial, and founding a
    /// Garden with only that was refused outright: the invite would have
    /// carried nowhere to go. So the address of the network this phone is
    /// actually on is found first and announced alongside the binding.
    pub fn create(
        &self,
        title: String,
        name: String,
        address: Option<String>,
    ) -> Result<GardenAnswer, GardenError> {
        let mut options = Self::options();
        if let Some(given) = address.filter(|a| !a.trim().is_empty()) {
            // A caller that already knows where it answers says so. The
            // app never does - it is the phone, and the phone asks the
            // network it is on - but a terminal driving this library can
            // name a address, which is how the founding path is exercised
            // somewhere other than a handset.
            options.listen = Some(validate_host_listen_multiaddr(&given)?);
            return answer(
                self.runtime
                    .block_on(self.service.create(title, name, options)),
            );
        }
        // Bound to that one interface rather than announced on top of a
        // binding to all of them: the port is picked by the system, and
        // only the binding knows which one it got. An announcement would
        // have had to name the port before it existed.
        options.listen = Some(Self::address_on_this_network().ok_or_else(|| {
            GardenError::of(
                "this phone is on no network the others could reach it on. \
                 Join the Wi-Fi the others are on, then start the network."
                    .to_owned(),
            )
        })?);
        answer(
            self.runtime
                .block_on(self.service.create(title, name, options)),
        )
    }

    /// The invite record to hand out, with its QR content.
    ///
    /// This is the Invite screen of section 2.5: the link, the QR and
    /// something to share. Uses any registered local HTTP share address.
    pub fn invite(&self) -> Result<GardenAnswer, GardenError> {
        let local = self
            .local_http_address
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        self.invite_for(local)
    }

    /// The invite record with an explicit optional local HTTP `host:port`
    /// override for `record_qr`.
    pub fn invite_for(&self, local_address: Option<String>) -> Result<GardenAnswer, GardenError> {
        let cleaned = match local_address {
            Some(raw) if !raw.trim().is_empty() => {
                let trimmed = raw.trim().to_string();
                if !is_valid_http_host_port(&trimmed) {
                    return Err(GardenError::of(
                        "local HTTP address must be bare host or host:port without URL delimiters",
                    ));
                }
                Some(trimmed)
            }
            _ => None,
        };
        answer(
            self.runtime
                .block_on(self.service.invite_for(cleaned.as_deref())),
        )
    }

    /// Read an invite record without acting on it, so the Join screen can
    /// show who is inviting and until when before anybody taps yes.
    pub fn read_record(&self, record: String) -> Result<GardenAnswer, GardenError> {
        answer(GardenService::read_record(&record))
    }

    /// Join the Garden an invite record names.
    pub fn join(&self, record: String, name: String) -> Result<GardenAnswer, GardenError> {
        let options = Self::join_options();
        answer(
            self.runtime
                .block_on(self.service.join(record, name, options)),
        )
    }

    /// Return to the Garden this phone already belongs to.
    ///
    /// An app is closed and opened again, a phone is carried out of range
    /// and back. The seat is kept in either case, so the Status screen
    /// calls this on the way up rather than asking for the invite a
    /// second time. The core keeps the key and the Garden on disk; this
    /// only puts the validator back on the network.
    pub fn rejoin(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.rejoin()))
    }

    /// The Garden as this phone sees it: its status and its validators.
    pub fn status(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.status()))
    }

    /// Leave, and wipe the Garden from this phone.
    pub fn leave(&self) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.leave()))
    }

    /// Send data into the Garden.
    ///
    /// This is what the Garden is for. The group is not a currency and
    /// there is nothing to pay: a validator's work is checking blocks and
    /// holding a share of what the group stores, and what the group
    /// stores is this - a note, a file, a reading from something. The
    /// bytes go down the B.U.D. 3.0 path, so what comes back out is
    /// verified against the chain rather than trusted.
    pub fn send(&self, text: String, caption: String) -> Result<GardenAnswer, GardenError> {
        let caption = if caption.trim().is_empty() {
            None
        } else {
            Some(caption)
        };
        answer(self.runtime.block_on(self.service.publish(
            "message".to_owned(),
            text,
            Some("utf8".to_owned()),
            None,
            caption,
        )))
    }

    /// Publish binary content (an image or file encoded in hex) into the
    /// Garden through B.U.D. 3.0.
    pub fn send_image(
        &self,
        hex_bytes: String,
        mime: String,
        caption: String,
    ) -> Result<GardenAnswer, GardenError> {
        let kind = if mime.trim().starts_with("image/") {
            "image"
        } else {
            "post"
        };
        let mime_opt = if mime.trim().is_empty() {
            None
        } else {
            Some(mime)
        };
        let caption_opt = if caption.trim().is_empty() {
            None
        } else {
            Some(caption)
        };
        answer(self.runtime.block_on(self.service.publish(
            kind.to_owned(),
            hex_bytes,
            Some("hex".to_owned()),
            mime_opt,
            caption_opt,
        )))
    }

    /// What the Garden has been sent, newest first.
    pub fn feed(&self, limit: u32) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.feed(Some(limit))))
    }

    /// Fetch one piece of data back out by its content id, rebuilt from
    /// the parts the validators hold and checked against the chain.
    pub fn fetch(&self, content_id: String) -> Result<GardenAnswer, GardenError> {
        answer(self.runtime.block_on(self.service.resolve(content_id)))
    }

    /// The section 4 self test, run before a Garden is created or joined.
    ///
    /// It tries the four things the phone has to be able to do, and it
    /// tries them for real: a file is written and read back, a key is made
    /// and used to sign, a socket is bound, and an object goes down the
    /// B.U.D. 3.0 path and comes back. None of it touches the network.
    pub fn self_test(&self) -> SelfTestReport {
        let started = std::time::Instant::now();
        let steps = vec![
            self.check_private_storage(),
            check_key_generation(),
            check_network_listen(),
            check_object_round_trip(),
        ];
        let passed = steps.iter().all(|step| step.passed);
        SelfTestReport {
            steps,
            passed,
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        }
    }
}

impl GardenPhone {
    /// The address this phone answers at on the network it is on.
    ///
    /// Asked of the routing table rather than of a list of interfaces: a
    /// phone has several, most of them useless here, and the one that
    /// would carry a packet to a neighbour is the one an invite should
    /// name. Nothing is sent - a connected UDP socket only fixes the
    /// route, which is all that is being asked.
    fn address_on_this_network() -> Option<String> {
        use std::net::{IpAddr, Ipv4Addr, UdpSocket};
        let usable = |ip: Ipv4Addr| {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        };
        // Probe both routed destinations and common private RFC1918 ranges so
        // a LAN without an internet gateway still resolves its interface when
        // the phone sits in one of those ranges.
        for target in [
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 42, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 20, 10, 1),
        ] {
            let Ok(probe) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
                continue;
            };
            if probe.connect((target, 9)).is_err() {
                continue;
            }
            if let Ok(IpAddr::V4(ip)) = probe.local_addr().map(|local| local.ip()) {
                if usable(ip) {
                    return Some(format!("/ip4/{ip}/tcp/0"));
                }
            }
        }
        // Pure airgapped L2 LAN fallback (e.g. 10.77.0.0/24 with zero default
        // gateway): read the kernel's local IPv4 FIB table (`fib_trie`) and
        // pick the first active non-loopback host address.
        local_ipv4_from_fib_trie()
            .filter(|ip| usable(*ip))
            .map(|ip| format!("/ip4/{ip}/tcp/0"))
    }

    /// Joiner listen options: bind every interface behind NAT on an ephemeral port.
    fn join_options() -> GardenOptions {
        Self::options()
    }

    /// The listen address a phone uses: every interface, a port the system
    /// picks. A phone moves between networks and cannot be told a port.
    /// Founding a Garden overrides this, because a host must be dialable.
    fn options() -> GardenOptions {
        serde_json::from_value(serde_json::json!({ "listen": "/ip4/0.0.0.0/tcp/0" }))
            .unwrap_or_default()
    }

    fn check_private_storage(&self) -> SelfTestStep {
        let path = self.data_dir.join("self-test.tmp");
        let written = std::fs::write(&path, b"garden")
            .and_then(|()| std::fs::read(&path))
            .inspect(|_| {
                let _ = std::fs::remove_file(&path);
            });
        match written {
            Ok(read) if read == b"garden" => step("write to private storage", true, String::new()),
            Ok(_) => step(
                "write to private storage",
                false,
                "the file read back as something else".into(),
            ),
            Err(e) => step("write to private storage", false, e.to_string()),
        }
    }
}

fn is_valid_http_host_port(address: &str) -> bool {
    !address.is_empty()
        && !address.bytes().any(|b| {
            b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%')
        })
}

fn step(name: &str, passed: bool, detail: String) -> SelfTestStep {
    SelfTestStep {
        name: name.to_string(),
        passed,
        detail,
    }
}

fn answer(result: Result<serde_json::Value, String>) -> Result<GardenAnswer, GardenError> {
    match result {
        Ok(value) => Ok(GardenAnswer {
            json: value.to_string(),
        }),
        Err(reason) => Err(GardenError::of(reason)),
    }
}

fn check_key_generation() -> SelfTestStep {
    // Making a key proves nothing on its own: it has to sign, and the
    // signature has to verify, or the phone cannot be a validator.
    let name = "make a key and sign with it";
    match budlum_core::crypto::primitives::KeyPair::generate() {
        Ok(key) => {
            let signature = key.sign(b"garden self test");
            match budlum_core::crypto::primitives::verify_signature(
                b"garden self test",
                &signature,
                &key.public_key_bytes(),
            ) {
                Ok(()) => step(name, true, String::new()),
                Err(e) => step(name, false, format!("the signature did not verify: {e:?}")),
            }
        }
        Err(e) => step(name, false, format!("{e:?}")),
    }
}

fn check_network_listen() -> SelfTestStep {
    let name = "listen on the network";
    match std::net::TcpListener::bind("0.0.0.0:0") {
        Ok(listener) => match listener.local_addr() {
            Ok(address) => step(name, true, format!("port {}", address.port())),
            Err(e) => step(name, false, e.to_string()),
        },
        Err(e) => step(name, false, e.to_string()),
    }
}

fn check_object_round_trip() -> SelfTestStep {
    let name = "code and rebuild a small object";
    match budlum_core::garden::self_test_object_round_trip() {
        Ok(()) => step(name, true, String::new()),
        Err(e) => step(name, false, e),
    }
}

fn ipv4_listen_is_dialable(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_link_local())
}

fn ipv6_listen_is_dialable(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_listen_is_dialable(v4);
    }
    true
}

fn validate_host_listen_multiaddr(raw: &str) -> Result<String, GardenError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.chars().any(char::is_control)
    {
        return Err(GardenError::of(
            "garden listen address must be a single /ip4 or /ip6 TCP multiaddr without whitespace or control characters",
        ));
    }
    let Some(rest) = trimmed.strip_prefix('/') else {
        return Err(GardenError::of(
            "garden listen address must start with /ip4/ or /ip6/",
        ));
    };
    let parts: Vec<&str> = rest.split('/').collect();
    let port_str = match parts.as_slice() {
        ["ip4", ip_str, "tcp", port_str] => {
            let ip: Ipv4Addr = ip_str
                .parse()
                .map_err(|_| GardenError::of("garden listen address has an invalid IPv4 host"))?;
            if !ipv4_listen_is_dialable(ip) {
                return Err(GardenError::of(
                    "garden listen address IPv4 host is not dialable (unspecified, multicast, broadcast, or link-local)",
                ));
            }
            *port_str
        }
        ["ip6", ip_str, "tcp", port_str] => {
            let ip: Ipv6Addr = ip_str
                .parse()
                .map_err(|_| GardenError::of("garden listen address has an invalid IPv6 host"))?;
            if !ipv6_listen_is_dialable(ip) {
                return Err(GardenError::of(
                    "garden listen address IPv6 host is not dialable (unspecified, multicast, or link-local)",
                ));
            }
            *port_str
        }
        _ => {
            return Err(GardenError::of(
                "garden listen address must be /ip4/<addr>/tcp/<port> or /ip6/<addr>/tcp/<port>",
            ));
        }
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| GardenError::of("garden listen address has an invalid TCP port"))?;
    if port != 0 && port < 1024 {
        return Err(GardenError::of(
            "garden listen address TCP port must be 0 or >= 1024",
        ));
    }
    Ok(trimmed.to_string())
}

/// Inspect `/proc/net/fib_trie` (`Local:` table) on Linux to find an assigned
/// non-loopback IPv4 interface address when the device has no default gateway.
fn local_ipv4_from_fib_trie() -> Option<std::net::Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/fib_trie").ok()?;
    let mut in_local = false;
    let mut candidate: Option<std::net::Ipv4Addr> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "Local:" {
            in_local = true;
            candidate = None;
            continue;
        }
        if !in_local {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("|-- ") {
            candidate = rest.split_whitespace().next().and_then(|w| w.parse().ok());
        } else if trimmed == "/32 host LOCAL" {
            if let Some(ip) = candidate {
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(label: &str) -> TempDirGuard {
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("budlum_garden_ffi_{label}_{seq}"));
        std::fs::create_dir_all(&dir).unwrap();
        TempDirGuard(dir)
    }

    #[test]
    fn phone_create_http_qr_join_status_leave_and_rejoin_round_trip() {
        let host_dir = temp_dir("host");
        let guest_dir = temp_dir("guest");
        let host = GardenPhone::new(host_dir.0.to_string_lossy().into_owned()).unwrap();
        let guest = GardenPhone::new(guest_dir.0.to_string_lossy().into_owned()).unwrap();

        let self_test = host.self_test();
        assert!(
            self_test.passed,
            "self_test must pass: {:?}",
            self_test
                .steps
                .iter()
                .map(|s| (&s.name, s.passed, &s.detail))
                .collect::<Vec<_>>()
        );

        let created = host
            .create(
                "Phone Garden".into(),
                "HostPhone".into(),
                Some("/ip4/127.0.0.1/tcp/0".into()),
            )
            .unwrap();
        let created_json: serde_json::Value = serde_json::from_str(&created.json).unwrap();
        assert_eq!(
            created_json
                .pointer("/garden/me/member")
                .and_then(|v| v.as_str()),
            Some("Active")
        );

        let invite = host.invite().unwrap();
        let invite_json: serde_json::Value = serde_json::from_str(&invite.json).unwrap();
        let record_link = invite_json
            .get("record")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert!(record_link.starts_with("budlum://garden/join#"));

        let read = guest.read_record(record_link.clone()).unwrap();
        let read_json: serde_json::Value = serde_json::from_str(&read.json).unwrap();
        assert!(read_json.get("host").and_then(|v| v.as_str()).is_some());

        let joined = guest.join(record_link, "GuestPhone".into()).unwrap();
        let joined_json: serde_json::Value = serde_json::from_str(&joined.json).unwrap();
        assert_eq!(
            joined_json
                .pointer("/garden/me/member")
                .and_then(|v| v.as_str()),
            Some("Active")
        );

        let status = guest.status().unwrap();
        let status_json: serde_json::Value = serde_json::from_str(&status.json).unwrap();
        assert_eq!(
            status_json
                .pointer("/garden/active_validators")
                .and_then(|v| v.as_u64()),
            Some(2)
        );

        let left = guest.leave().unwrap();
        let left_json: serde_json::Value = serde_json::from_str(&left.json).unwrap();
        assert_eq!(
            left_json.get("can_return").and_then(|v| v.as_bool()),
            Some(true)
        );

        let returned = guest.rejoin().unwrap();
        let returned_json: serde_json::Value = serde_json::from_str(&returned.json).unwrap();
        assert_eq!(
            returned_json
                .pointer("/garden/me/member")
                .and_then(|v| v.as_str()),
            Some("Active")
        );

        let _ = guest.leave();
        let _ = host.leave();
    }

    #[test]
    fn phone_new_rejects_empty_relative_and_nul_data_dir() {
        for bad in ["", "   ", "relative/garden", "/tmp/bad\0dir"] {
            assert!(
                GardenPhone::new(bad.to_string()).is_err(),
                "invalid data_dir {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn phone_local_http_qr_and_invite_for_round_trip() {
        let host_dir = temp_dir("http_host");
        let guest_dir = temp_dir("http_guest");
        let host = GardenPhone::new(host_dir.0.to_string_lossy().into_owned()).unwrap();
        let guest = GardenPhone::new(guest_dir.0.to_string_lossy().into_owned()).unwrap();

        host.create(
            "LAN Room".into(),
            "HostPhone".into(),
            Some("/ip4/127.0.0.1/tcp/0".into()),
        )
        .unwrap();
        assert!(host
            .set_local_http_address(Some("bad/path#x".into()))
            .is_err());
        assert!(host.invite_for(Some("bad@host".into())).is_err());

        host.set_local_http_address(Some("127.0.0.1:43210".into()))
            .unwrap();
        let inv = host.invite().unwrap();
        let inv_json: serde_json::Value = serde_json::from_str(&inv.json).unwrap();
        let http_qr = inv_json
            .get("record_qr")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert!(
            http_qr.starts_with("http://127.0.0.1:43210/g#"),
            "unexpected local QR format: {http_qr}"
        );

        let preview = guest.read_record(http_qr.clone()).unwrap();
        let preview_json: serde_json::Value = serde_json::from_str(&preview.json).unwrap();
        assert!(preview_json.get("host").and_then(|v| v.as_str()).is_some());

        let joined = guest.join(http_qr, "GuestPhone".into()).unwrap();
        let joined_json: serde_json::Value = serde_json::from_str(&joined.json).unwrap();
        assert_eq!(
            joined_json
                .pointer("/garden/me/member")
                .and_then(|v| v.as_str()),
            Some("Active")
        );

        host.set_local_http_address(None).unwrap();
        let cleared = host.invite().unwrap();
        let cleared_json: serde_json::Value = serde_json::from_str(&cleared.json).unwrap();
        let plain_qr = cleared_json
            .get("record_qr")
            .and_then(|v| v.as_str())
            .unwrap();
        // Loopback host address may still advertise http://127.0.0.1:<port>/g#
        // or fall back to budlum://garden/join# when no override is set.
        assert!(
            plain_qr.starts_with("budlum://garden/join#")
                || plain_qr.starts_with("http://127.0.0.1:"),
            "unexpected cleared QR: {plain_qr}"
        );

        let _ = guest.leave();
        let _ = host.leave();
    }

    #[test]
    fn phone_create_rejects_malformed_and_nondialable_addresses_and_trims_valid_one() {
        let dir = temp_dir("create_addr");
        let phone = GardenPhone::new(dir.0.to_string_lossy().into_owned()).unwrap();

        for bad in [
            "not-a-multiaddr",
            "/ip4/0.0.0.0/tcp/0",
            "/ip6/::/tcp/0",
            "/ip4/224.0.0.1/tcp/0",
            "/ip4/255.255.255.255/tcp/0",
            "/ip4/169.254.1.2/tcp/0",
            "/ip6/::ffff:0.0.0.0/tcp/0",
            "/ip6/fe80::1/tcp/0",
            "/ip4/127.0.0.1/tcp/80",
            "/ip4/127.0.0.1/tcp/notaport",
            "/ip4/127.0.0.1/udp/1234",
            "/ip4/127.0.0.1/tcp/0/p2p/12D3KooWtest",
            "/ip4/127.0.0.1\n/tcp/0",
            "/ip4/127.0.0.1 /tcp/0",
        ] {
            let err = match phone.create("Room".into(), "Host".into(), Some(bad.into())) {
                Ok(_) => panic!("bad listen address {bad:?} must be refused"),
                Err(err) => err,
            };
            assert!(
                matches!(err, GardenError::Refused { .. }),
                "expected GardenError::Refused for {bad:?}"
            );
        }

        let created = phone
            .create(
                "Trimmed Room".into(),
                "Host".into(),
                Some("  /ip4/127.0.0.1/tcp/0  ".into()),
            )
            .expect("whitespace-padded valid loopback multiaddr must succeed once trimmed");
        let created_json: serde_json::Value = serde_json::from_str(&created.json).unwrap();
        assert_eq!(
            created_json
                .pointer("/garden/me/member")
                .and_then(|v| v.as_str()),
            Some("Active")
        );
        let _ = phone.leave();
    }
}
