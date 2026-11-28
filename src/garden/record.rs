//! The invite record a Garden validator hands out.
//!
//! The older invite line names a Garden and carries the secret that opens
//! it. That is enough to join, but it says nothing about who opened the
//! door, until when, or for how many people. This record says all of it in
//! one string:
//!
//! ```text
//! budlum://garden/join#<base64url>
//! ```
//!
//! The part after `#` is the record itself, packed as bytes and written in
//! base64url. Packing is not decoration: the fields below do not fit the
//! ceiling a person can carry if each one is spelled out in hex.
//!
//! What the record carries, and why each field is in it:
//!
//! * `version` so a Garden running older code refuses a record it would
//!   otherwise half understand.
//! * `chain_id` and `genesis_hash` name the Garden. A joiner fetches the
//!   genesis from a peer and refuses it unless it hashes to this.
//! * `token` is the secret that opens the door. Genesis carries the public
//!   key derived from it and a join request must be signed by the matching
//!   secret key.
//! * `owner` is the validator that handed this record out. Inviting is not
//!   a host privilege, so the record has to say who it came from rather
//!   than assume the host.
//! * `host` is the host's identity, not its address. An address goes stale
//!   the moment the host moves; an identity does not, and a host is found
//!   through a relay by identity.
//! * `expires_at_ms` and `uses` bound the record in time and in people. A
//!   door that never closes is not a door.
//! * `peers` lists where to knock: the host first, then relays.
//! * `proof` is the owner's signature over everything above. Any validator
//!   can check it against the owner's key, which the chain already knows,
//!   and nothing secret is written down to make that possible.

use super::types::{verify_garden_execution_chain, GardenKey};
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::Hash32;

/// The record version this code writes and the only one it reads.
const RECORD_VERSION: u8 = 1;

/// The scheme and path an invite record is written under.
const RECORD_LINK_PREFIX: &str = "budlum://garden/join#";

/// How long a record is good for when the caller does not say.
///
/// A day is long enough that a Garden opened in the morning still admits
/// someone that evening, and short enough that a link left in a group chat
/// stops working before it is forgotten about.
pub(super) const DEFAULT_RECORD_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Longest record link, in bytes.
///
/// The same ceiling the older invite line is held to: a record is carried
/// by hand, read off one screen and typed into another, and those carriers
/// set the limit rather than the parser.
///
/// WIRING: read directly by `fuzz/fuzz_targets/garden_invite_record_decode.rs`
/// to enforce the canonical link byte ceiling on every fuzzed record.
pub const MAX_RECORD_LINK_BYTES: usize = 512;

/// Longest QR content, in bytes.
///
/// The QR may carry a local address in front of the record, so it is given
/// more room than the link. Past this a QR stops scanning reliably off a
/// screen held in front of another screen.
const MAX_RECORD_QR_BYTES: usize = 640;

/// Most peer addresses one record names.
const MAX_RECORD_PEERS: usize = 8;

/// Most validators a Garden can hold, and so the largest count a record can
/// carry. This is the Garden's own limit, not a limit of the link: the count
/// is outside the signed body and would otherwise be unbounded text.
const MAX_RECORD_PEERS_TOTAL: u16 = 4096;

/// Longest single peer address inside a record, in bytes.
const MAX_RECORD_PEER_BYTES: usize = 255;

/// The bytes a record spends before its first peer address:
/// version 1, chain id 8, genesis 32, token 32, owner 32, host 32,
/// expiry 8, uses 2, peer count 1, and the 64 byte proof.
const FIXED_RECORD_BYTES: usize = 1 + 8 + 32 + 32 + 32 + 32 + 8 + 2 + 1 + PROOF_BYTES;

/// The length of the signature that proves a record.
const PROOF_BYTES: usize = 64;

/// An invite record, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenRecord {
    /// Protocol version of the record itself.
    pub version: u8,
    /// The Garden this record opens.
    pub chain_id: u64,
    /// Hash of that Garden's genesis.
    pub genesis_hash: Hash32,
    /// The secret that opens the door.
    pub token: Hash32,
    /// The validator that handed this record out.
    pub owner: GardenKey,
    /// The host's identity. Not an address: a host that moves keeps it.
    pub host: GardenKey,
    /// Wall clock milliseconds after which the record is refused.
    pub expires_at_ms: u64,
    /// How many keys this record may still admit.
    pub uses: u16,
    /// Host address first, relay addresses after it.
    pub peers: Vec<String>,
    /// How many validators the Garden has, when that is more than `peers`.
    ///
    /// A record carries at most `MAX_RECORD_PEERS` addresses so the link stays
    /// something a person can hold in a QR, and a Garden of thirty would
    /// otherwise hand out a record that reads like a Garden of three. Zero
    /// means "`peers` is the whole Garden", which is what every record written
    /// before this field says. It is not covered by the proof: it is a count
    /// for the person reading the card, and the addresses it counts stay
    /// signed, so a wrong count can mislead nobody about where to knock.
    pub peers_total: u16,
    /// The owner's signature over every field above.
    pub proof: Vec<u8>,
}

impl GardenRecord {
    /// Build a record and sign it with the key of the validator handing it
    /// out. The owner is taken from the key rather than passed in, so a
    /// record can never name somebody else as the one who opened the door.
    // A record carries exactly these fields (section 5), so the argument list
    // is the record's shape: folding any two into a struct would invent a type
    // the wire format does not have.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        chain_id: u64,
        genesis_hash: Hash32,
        token: Hash32,
        host: GardenKey,
        peers: Vec<String>,
        now_ms: u64,
        ttl_ms: u64,
        uses: u16,
        key: &KeyPair,
    ) -> Result<Self, String> {
        let mut record = Self {
            version: RECORD_VERSION,
            chain_id,
            genesis_hash,
            token,
            owner: key.public_key_bytes(),
            host,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            uses,
            peers: fit_record_peers(peers),
            peers_total: 0,
            proof: Vec::new(),
        };
        record.proof = key.sign(&record.preimage()).to_vec();
        record.check(now_ms)?;
        Ok(record)
    }

    /// Everything the proof covers: the record without the proof.
    fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_RECORD_BYTES);
        out.push(self.version);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.host);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.uses.to_be_bytes());
        let count = u8::try_from(self.peers.len()).unwrap_or(u8::MAX);
        out.push(count);
        for peer in self.peers.iter().take(usize::from(count)) {
            let len = u8::try_from(peer.len()).unwrap_or(u8::MAX);
            out.push(len);
            // `len` was clamped to the byte length above, but the gate wants
            // the absence decided rather than indexed: a peer shorter than its
            // own length prefix writes what it has, never a panic.
            let bytes = peer.as_bytes();
            let take = usize::from(len).min(bytes.len());
            if let Some(prefix) = bytes.get(..take) {
                out.extend_from_slice(prefix);
            }
        }
        out
    }

    /// The packed record: the preimage with the proof behind it.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.preimage();
        out.extend_from_slice(&self.proof);
        out
    }

    /// Every rule a record has to pass before it is handed out or acted on.
    ///
    /// `now_ms` is wall clock time. A record that has run out of time or
    /// out of people is refused here, so a caller never has to remember to
    /// check those separately.
    /// The invite line this record stands for.
    ///
    /// Section 5.8 lets a QR carry either form, and section 5.12 says a
    /// record that arrived by a deliberate act joins on one tap. A record
    /// holds everything an invite line holds - the Garden, its genesis,
    /// the token and the peers - so a reader that was handed the signed
    /// form does not have to go asking for the other one.
    ///
    /// A line is produced rather than a `GardenInvite` built field by
    /// field: the line goes back through `GardenInvite::parse`, so the
    /// checks that guard every other invite guard this one too.
    pub fn to_invite_link(&self) -> String {
        let mut link = format!(
            "budlum-garden:1?chain={:016x}&genesis={}&token={}",
            self.chain_id,
            hex::encode(self.genesis_hash),
            hex::encode(self.token)
        );
        for peer in &self.peers {
            link.push_str("&peer=");
            link.push_str(peer);
        }
        link
    }

    pub fn check(&self, now_ms: u64) -> Result<(), String> {
        if self.version != RECORD_VERSION {
            return Err(format!(
                "invite record is version {}, this Garden speaks version {RECORD_VERSION}",
                self.version
            ));
        }
        // A Garden runs on its own chain id. A record naming a primary
        // Budlum chain is refused with the name of that network.
        verify_garden_execution_chain(self.chain_id)?;
        if self.peers.is_empty() {
            return Err("invite record names nowhere to knock".into());
        }
        if self.peers.len() > MAX_RECORD_PEERS {
            return Err(format!(
                "invite record names {} peers, more than the {MAX_RECORD_PEERS} it may carry",
                self.peers.len()
            ));
        }
        for peer in &self.peers {
            if peer.is_empty() || peer.len() > MAX_RECORD_PEER_BYTES {
                return Err("invite record carries a peer address of an impossible length".into());
            }
        }
        self.check_peer_count()?;
        if self.uses == 0 {
            return Err("invite record has admitted everyone it was good for".into());
        }
        if now_ms >= self.expires_at_ms {
            return Err("invite record has expired".into());
        }
        if self.proof.len() != PROOF_BYTES {
            return Err("invite record carries no usable proof".into());
        }
        verify_signature(&self.preimage(), &self.proof, &self.owner)
            .map_err(|_| "invite record is not signed by the validator it names".to_string())?;
        let suffix = if self.peers_total > self.peers.len() as u16 {
            "&peers_total=".len() + digits(self.peers_total)
        } else {
            0
        };
        let length = RECORD_LINK_PREFIX.len() + base64url_len(self.to_bytes().len()) + suffix;
        if length > MAX_RECORD_LINK_BYTES {
            return Err(format!(
                "invite record is {length} bytes, over the {MAX_RECORD_LINK_BYTES} byte ceiling"
            ));
        }
        Ok(())
    }

    /// The count on the card may only be a number somebody could mean: at
    /// least the addresses the record names, and no larger than a Garden.
    fn check_peer_count(&self) -> Result<(), String> {
        let named = u16::try_from(self.peers.len()).unwrap_or(u16::MAX);
        if self.peers_total != 0 && self.peers_total < named {
            return Err("invite record counts fewer validators than it names".into());
        }
        if self.peers_total > MAX_RECORD_PEERS_TOTAL {
            return Err("invite record counts more validators than a Garden holds".into());
        }
        Ok(())
    }

    /// The link. It is also the QR content.
    ///
    /// `&peers_total=` is appended after the record body when the Garden is
    /// larger than the peer list, so the card a person reads can say "2 of
    /// 30" instead of "2". A record that holds its whole Garden writes no
    /// parameter, so its link is byte for byte what it was before.
    #[must_use]
    pub fn to_link(&self) -> String {
        let body = base64url_encode(&self.to_bytes());
        if self.peers_total > self.peers.len() as u16 {
            format!(
                "{RECORD_LINK_PREFIX}{body}&peers_total={}",
                self.peers_total
            )
        } else {
            format!("{RECORD_LINK_PREFIX}{body}")
        }
    }

    /// What a QR code for this record holds.
    ///
    /// A phone that is on the same wall of the house as the Garden reaches
    /// it without any network at all, so when this node has a local
    /// address the QR points there and the record rides in the fragment.
    /// The scanner reads both shapes, and when there is no local address
    /// the QR is simply the link.
    pub fn to_qr(&self, local_address: Option<&str>) -> Result<String, String> {
        let content = match local_address {
            Some(address) if !address.is_empty() => {
                if !is_safe_qr_authority(address) {
                    return Err("local qr address contains disallowed URL characters".into());
                }
                let body = self.to_link();
                let fragment = body
                    .strip_prefix(RECORD_LINK_PREFIX)
                    .ok_or_else(|| "invite record link is malformed".to_string())?;
                format!("http://{address}/g#{fragment}")
            }
            _ => self.to_link(),
        };
        if content.len() > MAX_RECORD_QR_BYTES {
            return Err(format!(
                "qr content is {} bytes, over the {MAX_RECORD_QR_BYTES} byte ceiling",
                content.len()
            ));
        }
        Ok(content)
    }

    /// True when `link` is shaped as either a direct `budlum://garden/join#...`
    /// record link or a local `http://<address>/g#<record>` QR payload.
    #[must_use]
    pub(super) fn looks_like_record(link: &str) -> bool {
        let trimmed = link.trim();
        trimmed.starts_with(RECORD_LINK_PREFIX) || local_qr_body(trimmed).is_some()
    }

    /// Read a link back. This does not judge the record: it only turns the
    /// text into fields. `check` is what refuses one.
    /// Both shapes are read: the link itself, and the local address form a
    /// QR carries. They differ only in what sits in front of the `#`.
    pub fn parse(link: &str) -> Result<Self, String> {
        let trimmed = link.trim();
        if trimmed.len() > MAX_RECORD_QR_BYTES {
            return Err("invite record is too long".into());
        }
        let body = if let Some(rest) = trimmed.strip_prefix(RECORD_LINK_PREFIX) {
            if trimmed.len() > MAX_RECORD_LINK_BYTES {
                return Err("invite record is too long".into());
            }
            rest
        } else if let Some(rest) = local_qr_body(trimmed) {
            rest
        } else {
            return Err(format!(
                "invite record must start with '{RECORD_LINK_PREFIX}'"
            ));
        };
        // The count rides outside the signed body (see `to_link`), so it is
        // read off the link and placed on the record after it is unpacked.
        let (body, total) = match body.split_once("&peers_total=") {
            Some((body, value)) => {
                let total: u16 = value
                    .parse()
                    .map_err(|_| "invite record carries an unreadable peer count".to_string())?;
                (body, total)
            }
            None => (body, 0u16),
        };
        if body.contains('#') {
            return Err("invite record carries a second fragment".into());
        }
        let bytes = base64url_decode(body)?;
        let mut record = Self::from_bytes(&bytes)?;
        record.peers_total = total;
        record.check_peer_count()?;
        Ok(record)
    }

    /// Unpack a record. Every field is read at a fixed place, so a record
    /// that is one byte short is refused rather than read into the next
    /// field along.
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut at = 0usize;
        let version = one(bytes, &mut at)?;
        let chain_id = u64::from_be_bytes(array8(take(bytes, &mut at, 8)?)?);
        let genesis_hash = array32(take(bytes, &mut at, 32)?)?;
        let token = array32(take(bytes, &mut at, 32)?)?;
        let owner = array32(take(bytes, &mut at, 32)?)?;
        let host = array32(take(bytes, &mut at, 32)?)?;
        let expires_at_ms = u64::from_be_bytes(array8(take(bytes, &mut at, 8)?)?);
        let uses = u16::from_be_bytes(array2(take(bytes, &mut at, 2)?)?);
        let count = usize::from(one(bytes, &mut at)?);
        if count > MAX_RECORD_PEERS {
            return Err(format!(
                "invite record names {count} peers, more than the {MAX_RECORD_PEERS} it may carry"
            ));
        }
        let mut peers = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(one(bytes, &mut at)?);
            let raw = take(bytes, &mut at, len)?;
            let peer = core::str::from_utf8(raw)
                .map_err(|_| "invite record carries a peer address that is not text".to_string())?;
            peers.push(peer.to_string());
        }
        let proof = take(bytes, &mut at, PROOF_BYTES)?.to_vec();
        if at != bytes.len() {
            return Err("invite record carries bytes after its proof".into());
        }
        Ok(Self {
            version,
            chain_id,
            genesis_hash,
            token,
            owner,
            host,
            expires_at_ms,
            uses,
            peers,
            peers_total: 0,
            proof,
        })
    }
}

/// The record inside `http://<address>/g#<record>`, when that is the shape.
///
/// Only the path this code writes is accepted. A stray `http` link that
/// happens to carry a `#` is not an invite and is not read as one.
fn is_safe_qr_authority(address: &str) -> bool {
    !address.is_empty()
        && address
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#'))
}

fn local_qr_body(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("http://")?;
    let (address, fragment) = rest.split_once("/g#")?;
    if !is_safe_qr_authority(address) || fragment.is_empty() || fragment.contains('#') {
        return None;
    }
    Some(fragment)
}

/// How many decimal digits `value` needs, so a link's real length is counted.
fn digits(value: u16) -> usize {
    let mut left = value;
    let mut count = 1;
    while left >= 10 {
        left /= 10;
        count += 1;
    }
    count
}

fn short() -> String {
    "invite record ends in the middle of a field".to_string()
}

/// Read `n` bytes from `at` and walk the cursor past them.
fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = at.checked_add(n).ok_or_else(short)?;
    let slice = bytes.get(*at..end).ok_or_else(short)?;
    *at = end;
    Ok(slice)
}

/// Read a single byte and walk the cursor past it.
fn one(bytes: &[u8], at: &mut usize) -> Result<u8, String> {
    take(bytes, at, 1).map(|slice| slice[0])
}

fn array2(slice: &[u8]) -> Result<[u8; 2], String> {
    <[u8; 2]>::try_from(slice).map_err(|_| short())
}

fn array8(slice: &[u8]) -> Result<[u8; 8], String> {
    <[u8; 8]>::try_from(slice).map_err(|_| short())
}

fn array32(slice: &[u8]) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(slice).map_err(|_| short())
}

/// Keep the peer addresses that fit the record, in the order given.
///
/// The caller orders the list by usefulness: the host first, then the
/// relays that reach it. A Garden with more validators than the record can
/// name is ordinary, so running past the ceiling stops the list rather
/// than failing: refusing would mean a Garden cannot invite anyone the
/// moment it grows.
#[must_use]
fn fit_record_peers(peers: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut packed = FIXED_RECORD_BYTES;
    for peer in peers {
        if kept.len() == MAX_RECORD_PEERS || peer.is_empty() || peer.len() > MAX_RECORD_PEER_BYTES {
            continue;
        }
        let cost = 1 + peer.len();
        let length = RECORD_LINK_PREFIX.len() + base64url_len(packed + cost);
        if length > MAX_RECORD_LINK_BYTES {
            break;
        }
        packed += cost;
        kept.push(peer);
    }
    kept
}

/// How many characters `n` bytes take in base64url without padding.
const fn base64url_len(n: usize) -> usize {
    n / 3 * 4
        + match n % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding, as the link format asks for.
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(base64url_len(bytes.len()));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let packed = b0 << 16 | b1 << 8 | b2;
        let width = chunk.len() + 1;
        for i in 0..width {
            let shift = 18 - i * 6;
            let index = usize::try_from((packed >> shift) & 0x3f).unwrap_or(0);
            // The mask keeps `index` inside `0..64`, but the gate wants the
            // absence decided rather than indexed: a letter that is not there
            // writes nothing instead of aborting a release build.
            if let Some(letter) = ALPHABET.get(index) {
                out.push(char::from(*letter));
            }
        }
    }
    out
}

/// One byte out of a packed group, counted from the given shift.
fn byte_at(packed: u32, shift: u32) -> u8 {
    u8::try_from((packed >> shift) & 0xff).unwrap_or(0)
}

/// Read base64url back. Padding, whitespace and the characters of the
/// other base64 alphabet are all refused, so one record has one spelling.
fn base64url_decode(text: &str) -> Result<Vec<u8>, String> {
    let bad = || "invite record is not base64url".to_string();
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return Err(bad());
        }
        let mut packed = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let value = ALPHABET.iter().position(|a| a == c).ok_or_else(bad)?;
            let value = u32::try_from(value).map_err(|_| bad())?;
            packed |= value << (18 - i * 6);
        }
        out.push(byte_at(packed, 16));
        if chunk.len() >= 3 {
            out.push(byte_at(packed, 8));
        }
        if chunk.len() == 4 {
            out.push(byte_at(packed, 0));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::KeyPair;

    /// A wall clock reading the tests measure from.
    const NOW: u64 = 1_700_000_000_000;

    /// A Garden chain id, which is never a primary Budlum chain id.
    // A Garden chain id carries the Garden prefix (types.rs), or the record
    // refuses to issue: the tests use a real one rather than a made-up number.
    const CHAIN: u64 = 0x4741_0000_0000_0007;

    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32]).unwrap()
    }

    /// A peer address the way a validator announces it, with the peer id
    /// that makes a real one long.
    fn peer(last: u8) -> String {
        let key = KeyPair::generate().unwrap().public_key_bytes();
        let id = super::super::net::peer_id_of(&key).unwrap();
        format!("/ip4/192.168.1.{last}/tcp/30333/p2p/{id}")
    }

    /// A short address, used where the test is about a field and not about
    /// how many addresses fit.
    fn short_peer(last: u8) -> String {
        format!("/ip4/10.0.0.{last}/tcp/30333")
    }

    fn issued(peers: Vec<String>) -> GardenRecord {
        GardenRecord::issue(
            CHAIN,
            [0xab; 32],
            [0xcd; 32],
            key(9).public_key_bytes(),
            peers,
            NOW,
            DEFAULT_RECORD_TTL_MS,
            5,
            &key(1),
        )
        .unwrap()
    }

    #[test]
    fn a_record_survives_the_trip_through_its_link() {
        let record = issued(vec![short_peer(1), short_peer(2), short_peer(3)]);
        let link = record.to_link();
        assert!(
            link.starts_with(RECORD_LINK_PREFIX),
            "a record link must be recognisable: {link}"
        );
        assert_eq!(GardenRecord::parse(&link).unwrap(), record);
        assert!(record.check(NOW).is_ok());
    }

    #[test]
    fn a_record_stays_under_the_ceiling_a_person_can_carry() {
        let record = issued(vec![short_peer(1), short_peer(2), short_peer(3)]);
        let length = record.to_link().len();
        assert!(
            length <= MAX_RECORD_LINK_BYTES,
            "a record link is {length} bytes, over the {MAX_RECORD_LINK_BYTES} byte ceiling"
        );
    }

    /// The record a QR carries says how big the Garden is.
    ///
    /// `peers` is bounded so the link stays a thing a person can carry, so a
    /// Garden of thirty would otherwise hand out a record that looks like a
    /// Garden of three. `peers_total` is the count; it is not covered by the
    /// proof for that reason, and the peer list itself still is.
    #[test]
    fn a_record_says_how_big_the_garden_is_not_only_how_many_peer_lines_fit() {
        let mut peers: Vec<String> = (1..=3).map(short_peer).collect();
        peers.truncate(1);
        let mut record = issued(peers);
        record.peers_total = 30;
        let link = record.to_link();
        let read = GardenRecord::parse(&link).unwrap();
        assert_eq!(
            read.peers.len(),
            1,
            "the line still carries the peers it can"
        );
        assert_eq!(read.peers_total, 30, "the count survives the trip");
        let mut inflated = read.clone();
        inflated.peers_total = 31;
        assert!(
            inflated.check(NOW).is_ok(),
            "the count is not signed, so a record from a newer node still verifies"
        );
        // A count nobody could mean is refused: fewer than the addresses the
        // record names, or more validators than a Garden can hold.
        let mut too_few = read.clone();
        too_few.peers_total = 0;
        assert!(
            too_few.check(NOW).is_ok(),
            "no count is the old, honest shape"
        );
        let mut nonsense = read.clone();
        nonsense.peers_total = MAX_RECORD_PEERS_TOTAL + 1;
        assert!(
            nonsense.check(NOW).is_err(),
            "an impossible count was accepted"
        );
        // A record that carries no count writes the link it always wrote.
        let plain = issued(vec![short_peer(1)]);
        assert!(
            !plain.to_link().contains("peers_total"),
            "a record of a small Garden grew a parameter nobody needs"
        );
    }

    #[test]
    fn the_proof_covers_every_field_of_the_record() {
        let record = issued(vec![short_peer(1), short_peer(2)]);
        // Each of these is a field somebody would want to forge: more
        // uses, a longer life, a different Garden, a different door.
        let mut more_uses = record.clone();
        more_uses.uses = u16::MAX;
        let mut longer_life = record.clone();
        longer_life.expires_at_ms = record.expires_at_ms.saturating_add(86_400_000);
        let mut other_garden = record.clone();
        other_garden.chain_id = CHAIN + 1;
        let mut other_genesis = record.clone();
        other_genesis.genesis_hash = [0x11; 32];
        let mut other_token = record.clone();
        other_token.token = [0x22; 32];
        let mut other_host = record.clone();
        other_host.host = key(8).public_key_bytes();
        let mut other_door = record.clone();
        other_door.peers[0] = short_peer(250);
        let mut other_owner = record.clone();
        other_owner.owner = key(2).public_key_bytes();

        for (label, forged) in [
            ("uses", more_uses),
            ("expiry", longer_life),
            ("chain id", other_garden),
            ("genesis", other_genesis),
            ("token", other_token),
            ("host", other_host),
            ("peer address", other_door),
            ("owner", other_owner),
        ] {
            assert!(
                forged.check(NOW).is_err(),
                "a record with a changed {label} passed the proof"
            );
        }
    }

    #[test]
    fn a_record_that_ran_out_of_time_is_refused() {
        let record = issued(vec![short_peer(1)]);
        assert_eq!(record.expires_at_ms, NOW + DEFAULT_RECORD_TTL_MS);
        assert!(record.check(record.expires_at_ms - 1).is_ok());
        let refusal = record.check(record.expires_at_ms).unwrap_err();
        assert!(refusal.contains("expired"), "{refusal}");
    }

    #[test]
    fn a_record_that_ran_out_of_people_is_refused() {
        let spent = GardenRecord::issue(
            CHAIN,
            [0xab; 32],
            [0xcd; 32],
            key(9).public_key_bytes(),
            vec![short_peer(1)],
            NOW,
            DEFAULT_RECORD_TTL_MS,
            0,
            &key(1),
        );
        let refusal = spent.unwrap_err();
        assert!(refusal.contains("admitted everyone"), "{refusal}");
    }

    #[test]
    fn a_record_naming_a_primary_budlum_chain_is_refused() {
        let wrong = GardenRecord::issue(
            crate::core::chain_config::Network::Testnet
                .chain_id()
                .value(),
            [0xab; 32],
            [0xcd; 32],
            key(9).public_key_bytes(),
            vec![short_peer(1)],
            NOW,
            DEFAULT_RECORD_TTL_MS,
            5,
            &key(1),
        );
        assert!(wrong.is_err(), "a record on Budlum Testnet was issued");
    }

    #[test]
    fn the_qr_carries_a_local_address_when_there_is_one() {
        let record = issued(vec![short_peer(1)]);
        assert_eq!(record.to_qr(None).unwrap(), record.to_link());
        let local = record.to_qr(Some("192.168.1.5:8080")).unwrap();
        assert!(local.starts_with("http://192.168.1.5:8080/g#"), "{local}");
        assert!(local.len() <= MAX_RECORD_QR_BYTES, "{}", local.len());
        // The scanner reads both shapes.
        assert_eq!(GardenRecord::parse(&local).unwrap(), record);
    }

    #[test]
    fn a_link_that_is_not_an_invite_is_not_read_as_one() {
        let record = issued(vec![short_peer(1)]);
        let link = record.to_link();
        for wrong in [
            String::new(),
            "budlum-garden:1?chain=7".to_string(),
            "budlum://garden/join#!!!!".to_string(),
            // Padded base64 is a second spelling of one record.
            "budlum://garden/join#QQ==".to_string(),
            // An http link that merely carries a fragment is not a QR.
            "http://evil.example/x#AAAA".to_string(),
            // One byte short, and one byte long.
            link[..link.len() - 4].to_string(),
            format!("{link}AAAA"),
        ] {
            assert!(
                GardenRecord::parse(&wrong).is_err(),
                "this was read as an invite record: {wrong}"
            );
        }
    }

    #[test]
    fn a_garden_that_outgrows_the_record_still_hands_out_a_working_invite() {
        // Real announced addresses carry a peer id and are long. More of
        // them are offered here than the ceiling allows, and the record is
        // expected to keep the first ones rather than refuse to exist: a
        // Garden cannot stop inviting people because it grew.
        let offered: Vec<String> = (1..=8).map(peer).collect();
        let record = issued(offered.clone());
        assert!(!record.peers.is_empty(), "the record kept no address");
        assert_eq!(
            record.peers,
            offered[..record.peers.len()],
            "the record dropped addresses out of order"
        );
        let length = record.to_link().len();
        assert!(
            length <= MAX_RECORD_LINK_BYTES,
            "a record of real addresses is {length} bytes"
        );
        assert_eq!(GardenRecord::parse(&record.to_link()).unwrap(), record);
    }

    #[test]
    fn an_address_too_long_for_the_record_is_refused_not_half_written() {
        // One address can be long enough that nothing is left to put in
        // the record. The record says so instead of handing out a link
        // with no address in it, and the caller keeps the older line.
        let huge = format!("/dns4/{}/tcp/30333", "a".repeat(200));
        let refused = GardenRecord::issue(
            CHAIN,
            [0xab; 32],
            [0xcd; 32],
            key(9).public_key_bytes(),
            vec![huge],
            NOW,
            DEFAULT_RECORD_TTL_MS,
            5,
            &key(1),
        );
        let refusal = refused.unwrap_err();
        assert!(refusal.contains("nowhere to knock"), "{refusal}");
    }

    #[test]
    fn a_record_with_nowhere_to_knock_is_refused() {
        let nowhere = GardenRecord::issue(
            CHAIN,
            [0xab; 32],
            [0xcd; 32],
            key(9).public_key_bytes(),
            Vec::new(),
            NOW,
            DEFAULT_RECORD_TTL_MS,
            5,
            &key(1),
        );
        let refusal = nowhere.unwrap_err();
        assert!(refusal.contains("nowhere to knock"), "{refusal}");
    }

    #[test]
    fn every_validator_can_issue_a_record_of_its_own() {
        // Inviting is not a host privilege. Two validators issue a record
        // for the same Garden and each one proves who signed it.
        let host = key(9).public_key_bytes();
        let mut links = Vec::new();
        for seed in [1u8, 2u8] {
            let signer = key(seed);
            let record = GardenRecord::issue(
                CHAIN,
                [0xab; 32],
                [0xcd; 32],
                host,
                vec![short_peer(1)],
                NOW,
                DEFAULT_RECORD_TTL_MS,
                5,
                &signer,
            )
            .unwrap();
            assert_eq!(record.owner, signer.public_key_bytes());
            assert_eq!(record.host, host);
            assert!(record.check(NOW).is_ok());
            links.push(record.to_link());
        }
        assert_ne!(links[0], links[1], "two owners produced one record");
        let sample = GardenRecord::parse(&links[0]).unwrap();
        let qr = sample.to_qr(Some("192.168.1.5:4800")).unwrap();
        assert!(GardenRecord::looks_like_record(&qr));
        assert_eq!(GardenRecord::parse(&qr).unwrap(), sample);
        assert!(sample.to_qr(Some("evil.example@192.168.1.5:4800")).is_err());
        assert!(!GardenRecord::looks_like_record(
            "http://evil.example@192.168.1.5:4800/g#abc"
        ));
    }
}
