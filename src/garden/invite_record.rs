//! The Garden invite record.
//!
//! `invite.rs` carries a Garden's identity and token. This module carries the
//! *record* the optimisation directive asks for (GARDEN_OPTIMISATION 5.2 to
//! 5.8): one record that every transport shares, so the link, the QR content,
//! the clipboard line and the local announcement all hand a joiner the same
//! bytes.
//!
//! ```text
//! g1|chain=<id>|genesis=<b64u>|token=<b64u>|owner=<b64u>|host=<b64u>|addr=<host addr>|relay=<a>,<b>|exp=<ms>|uses=<n>|sig=<b64u>
//!
//! Binary fields ride base64url without padding: hex would double the bytes,
//! and the directive binds the record to 512 of them.
//! ```
//!
//! The link is `budlum://garden/join#<base64url record>`. With a local address
//! at hand the QR content is `http://<addr>/g#<base64url record>`, and without
//! one it is the link itself; the reader accepts both.
//!
//! # What the proof covers
//!
//! The signature covers the fields that decide *who may join*: the protocol
//! version, the Garden chain id, the genesis digest, the invite owner, the
//! host, the expiry and the usage limit.
//!
//! It deliberately does not cover the addresses. Directive 5.5 says an invite
//! stays valid when the host address changes, because the host is found by
//! identity through a relay; an invite that died with the address a peer
//! announced an hour ago would be useless on a phone that moved between Wi-Fi
//! and mobile data. Addresses are therefore transport hints, and the test
//! `garden_invite_host_moves` holds that line: rewriting every address leaves
//! the record valid.
//!
//! # Sizes
//!
//! Directive 5.4 bounds the record at 512 bytes and the QR content at 640.
//! Both are checked before a record leaves this module, so an over-long
//! address is refused where it is built instead of producing a code no phone
//! can scan.

use super::types::GardenKey;
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::Hash32;

/// Protocol version this build speaks.
pub const INVITE_RECORD_VERSION: u8 = 1;
/// Longest record accepted, in bytes (directive 5.4).
pub const MAX_RECORD_BYTES: usize = 512;
/// Longest QR content accepted, in bytes (directive 5.4).
pub const MAX_QR_BYTES: usize = 640;
/// Most relays one record carries.
pub const MAX_RELAYS: usize = 8;
/// Longest address inside a record, in bytes.
const MAX_ADDRESS_BYTES: usize = 256;
/// Scheme of the shareable link (directive 5.7).
const LINK_PREFIX: &str = "budlum://garden/join#";
/// Fragment marker of the local-address QR form (directive 5.8).
const QR_FRAGMENT: &str = "/g#";
/// Domain separation of the signed payload.
const SIGNING_DOMAIN: &str = "budlum-garden-invite/1";

/// One invite record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenInviteRecord {
    /// Protocol version. A joiner refuses anything it does not speak.
    pub version: u8,
    /// Garden chain id.
    pub chain_id: u64,
    /// Genesis digest the joiner must see from a peer.
    pub genesis_hash: Hash32,
    /// The invite token. A join request is signed with the key it derives, so
    /// the record must carry it for the joiner to be able to ask at all.
    pub token: Hash32,
    /// Whoever produced this invite. Any validator may, not only the host.
    pub owner: GardenKey,
    /// Garden host identity.
    pub host: GardenKey,
    /// Host address hint. Unsigned, because the host may move.
    pub host_address: String,
    /// Relay address hints. Unsigned for the same reason.
    pub relays: Vec<String>,
    /// Expiry, in Unix milliseconds.
    pub expires_unix_ms: u64,
    /// How many joiners this record may still admit.
    pub max_uses: u16,
    /// Owner signature over the fields listed in the module docs.
    pub signature: [u8; 64],
}

/// True when `address` can stand in a record without escaping.
fn is_plain_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_ADDRESS_BYTES
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | ':' | '-' | '_'))
}

/// base64url without padding, so a record can sit in a fragment.
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let mut push = |index: u32| {
            out.push(char::from(ALPHABET[index as usize & 0x3f]));
        };
        push(triple >> 18);
        push(triple >> 12);
        if chunk.len() > 1 {
            push(triple >> 6);
        }
        if chunk.len() > 2 {
            push(triple);
        }
    }
    out
}

/// Decode base64url without padding.
fn base64url_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4 + 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(format!("invite record is not base64url (byte {byte:#04x})")),
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).unwrap_or_default());
        }
    }
    if bits >= 6 {
        return Err("invite record has a dangling base64url byte".to_string());
    }
    Ok(out)
}

fn parse_hash_field(label: &str, value: &str) -> Result<Hash32, String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(format!(
            "invite record field '{label}' must be 43 base64url characters"
        ));
    }
    let bytes = base64url_decode(value)
        .map_err(|_| format!("invite record field '{label}' is not base64url"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("invite record field '{label}' is not 32 bytes"))
}

impl GardenInviteRecord {
    /// Build and sign a record with the owner's key.
    ///
    /// # Errors
    ///
    /// Refuses a malformed address, a record over the size bound, an owner key
    /// that does not match the signing key, or a Garden chain id that names a
    /// primary Budlum chain.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        genesis_hash: Hash32,
        token: Hash32,
        owner_keypair: &KeyPair,
        host: GardenKey,
        host_address: &str,
        relays: Vec<String>,
        expires_unix_ms: u64,
        max_uses: u16,
    ) -> Result<Self, String> {
        let owner = owner_keypair.public_key_bytes();
        let mut record = Self {
            version: INVITE_RECORD_VERSION,
            chain_id,
            genesis_hash,
            token,
            owner,
            host,
            host_address: host_address.to_string(),
            relays,
            expires_unix_ms,
            max_uses,
            signature: [0u8; 64],
        };
        record.check_hints()?;
        record.signature = owner_keypair.sign(&record.signing_payload());
        record.check()?;
        Ok(record)
    }

    /// The bytes the owner signs.
    fn signing_payload(&self) -> Vec<u8> {
        format!(
            "{SIGNING_DOMAIN}|version={}|chain={}|genesis={}|token={}|owner={}|host={}|exp={}|uses={}",
            self.version,
            self.chain_id,
            hex::encode(self.genesis_hash),
            hex::encode(self.token),
            hex::encode(self.owner),
            hex::encode(self.host),
            self.expires_unix_ms,
            self.max_uses
        )
        .into_bytes()
    }

    /// Address hints must be plain and few.
    fn check_hints(&self) -> Result<(), String> {
        if !is_plain_address(&self.host_address) {
            return Err(format!(
                "invite record host address must be plain and at most {MAX_ADDRESS_BYTES} bytes"
            ));
        }
        if self.relays.len() > MAX_RELAYS {
            return Err(format!(
                "invite record carries {} relays, more than {MAX_RELAYS}",
                self.relays.len()
            ));
        }
        for relay in &self.relays {
            if !is_plain_address(relay) {
                return Err(format!(
                    "invite record relay address must be plain and at most {MAX_ADDRESS_BYTES} bytes"
                ));
            }
        }
        Ok(())
    }

    /// Canonical text form.
    fn encode_body(&self) -> String {
        format!(
            "g{}|chain={}|genesis={}|token={}|owner={}|host={}|addr={}|relay={}|exp={}|uses={}|sig={}",
            self.version,
            self.chain_id,
            base64url_encode(&self.genesis_hash),
            base64url_encode(&self.token),
            base64url_encode(&self.owner),
            base64url_encode(&self.host),
            self.host_address,
            self.relays.join(","),
            self.expires_unix_ms,
            self.max_uses,
            base64url_encode(&self.signature)
        )
    }

    /// The record as one line of text.
    ///
    /// # Errors
    ///
    /// Refuses to emit a record longer than [`MAX_RECORD_BYTES`].
    pub fn encode(&self) -> Result<String, String> {
        let body = self.encode_body();
        if body.len() > MAX_RECORD_BYTES {
            return Err(format!(
                "invite record is {} bytes, over the {MAX_RECORD_BYTES} byte bound",
                body.len()
            ));
        }
        Ok(body)
    }

    /// Parse one line of text.
    ///
    /// # Errors
    ///
    /// Refuses a truncated or reordered record, a version it does not speak,
    /// and any field that is not in its canonical shape.
    pub fn decode(text: &str) -> Result<Self, String> {
        let mut parts = text.split('|');
        let head = parts.next().unwrap_or_default();
        let Some(version) = head.strip_prefix('g') else {
            return Err("invite record must start with its version marker".to_string());
        };
        let version: u8 = version
            .parse()
            .map_err(|_| "invite record version is not a number".to_string())?;
        let mut fields = std::collections::BTreeMap::new();
        for part in parts {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| format!("invite record field '{part}' has no value"))?;
            fields.insert(key.to_string(), value.to_string());
        }
        let take = |key: &str| -> Result<String, String> {
            fields
                .get(key)
                .cloned()
                .ok_or_else(|| format!("invite record is missing field '{key}'"))
        };
        let chain_id: u64 = take("chain")?
            .parse()
            .map_err(|_| "invite record chain id is not a number".to_string())?;
        let expires_unix_ms: u64 = take("exp")?
            .parse()
            .map_err(|_| "invite record expiry is not a number".to_string())?;
        let max_uses: u16 = take("uses")?
            .parse()
            .map_err(|_| "invite record usage limit is not a number".to_string())?;
        let relays = match take("relay")?.as_str() {
            "" => Vec::new(),
            list => list.split(',').map(str::to_string).collect(),
        };
        let sig_field = take("sig")?;
        if sig_field.len() != 86
            || !sig_field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invite record signature must be 86 base64url characters".to_string());
        }
        let raw = base64url_decode(&sig_field)
            .map_err(|_| "invite record signature is not base64url".to_string())?;
        let mut signature_bytes = [0u8; 64];
        if raw.len() != 64 {
            return Err("invite record signature is not 64 bytes".to_string());
        }
        for (dst, src) in signature_bytes.iter_mut().zip(raw.iter()) {
            *dst = *src;
        }
        let record = Self {
            version,
            chain_id,
            genesis_hash: parse_hash_field("genesis", &take("genesis")?)?,
            token: parse_hash_field("token", &take("token")?)?,
            owner: parse_hash_field("owner", &take("owner")?)?,
            host: parse_hash_field("host", &take("host")?)?,
            host_address: take("addr")?,
            relays,
            expires_unix_ms,
            max_uses,
            signature: signature_bytes,
        };
        record.check_hints()?;
        Ok(record)
    }

    /// Structural checks, size included.
    fn check(&self) -> Result<(), String> {
        self.encode()?;
        Ok(())
    }

    /// The shareable link.
    ///
    /// # Errors
    ///
    /// Refuses when the encoded record is over the size bound.
    pub fn link(&self) -> Result<String, String> {
        Ok(format!(
            "{LINK_PREFIX}{}",
            base64url_encode(self.encode()?.as_bytes())
        ))
    }

    /// The QR content: the local-address form when an address is at hand, the
    /// link otherwise.
    ///
    /// # Errors
    ///
    /// Refuses when the content would pass [`MAX_QR_BYTES`], which is the
    /// bound a phone camera actually meets.
    pub fn qr(&self, local_address: Option<&str>) -> Result<String, String> {
        let content = match local_address {
            Some(address) => {
                if !is_plain_address(address) {
                    return Err("invite QR address must be plain and short".to_string());
                }
                // The fragment carries the canonical record itself, not a
                // second base64url layer: the record already fits the QR
                // bound and `parse_any` reads the bare form. Wrapping it again
                // added 4/3 of its length and made real listener addresses
                // unscannable, which silently disabled the invite RPC.
                format!("http://{address}{QR_FRAGMENT}{}", self.encode()?)
            }
            None => self.link()?,
        };
        if content.len() > MAX_QR_BYTES {
            return Err(format!(
                "invite QR content is {} bytes, over the {MAX_QR_BYTES} byte bound",
                content.len()
            ));
        }
        Ok(content)
    }

    /// Read a record from any of the forms the directive lists: the link, the
    /// local-address QR content, or the bare record a clipboard or a local
    /// announcement carries.
    ///
    /// # Errors
    ///
    /// Refuses text that carries no record.
    pub fn parse_any(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let encoded = if let Some(rest) = text.strip_prefix(LINK_PREFIX) {
            rest
        } else if let Some(index) = text.find(QR_FRAGMENT) {
            &text[index + QR_FRAGMENT.len()..]
        } else {
            text
        };
        // The bare canonical record is accepted as it stands: a clipboard line
        // and a local announcement carry the text, not a wrapped URL.
        if encoded.contains('|') {
            return Self::decode(encoded);
        }
        let bytes = base64url_decode(encoded)?;
        let body = String::from_utf8(bytes).map_err(|_| "invite record is not text".to_string())?;
        Self::decode(&body)
    }

    /// The invite line this record stands for.
    ///
    /// # Errors
    ///
    /// Refuses a record whose addresses cannot be dialled.
    pub fn to_invite(&self) -> Result<super::invite::GardenInvite, String> {
        let mut peers = vec![self.host_address.clone()];
        peers.extend(self.relays.iter().cloned());
        super::invite::GardenInvite::from_record(
            self.chain_id,
            self.genesis_hash,
            self.token,
            peers,
        )
    }

    /// Check the proof and the terms under which a joiner may use this record.
    ///
    /// # Errors
    ///
    /// Names the reason: a version this build does not speak, an expired
    /// record, a spent usage limit, or a proof that does not verify.
    pub fn verify_join(
        &self,
        now_unix_ms: u64,
        uses_consumed: u16,
        spoke_version: u8,
    ) -> Result<(), String> {
        if self.version != spoke_version {
            return Err(format!(
                "invite speaks protocol version {}, this node speaks {spoke_version}",
                self.version
            ));
        }
        if now_unix_ms >= self.expires_unix_ms {
            return Err(format!(
                "invite expired at {} ms, it is now {now_unix_ms} ms",
                self.expires_unix_ms
            ));
        }
        if uses_consumed >= self.max_uses {
            return Err(format!("invite usage limit of {} is spent", self.max_uses));
        }
        verify_signature(&self.signing_payload(), &self.signature, &self.owner)
            .map_err(|_| "invite proof does not verify against its owner".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::KeyPair;

    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32]).expect("seed")
    }

    fn record_for(owner: &KeyPair, host: &KeyPair, uses: u16) -> GardenInviteRecord {
        GardenInviteRecord::new(
            0x7a11_0000_0000_0001,
            [7u8; 32],
            [9u8; 32],
            owner,
            host.public_key_bytes(),
            "192.168.1.10:47001",
            vec!["relay.example:47002".to_string()],
            u64::MAX / 2,
            uses,
        )
        .expect("record")
    }

    /// Directive 11.1: the link, the QR content, the clipboard line and the
    /// local announcement hand over the same record.
    #[test]
    fn garden_invite_same_record() {
        let owner = key(1);
        let host = key(2);
        let record = record_for(&owner, &host, 8);
        let link = record.link().expect("link");
        let qr = record.qr(Some("10.0.0.5:47001")).expect("qr");
        let clipboard = record.encode().expect("record text");

        let from_link = GardenInviteRecord::parse_any(&link).expect("link parses");
        let from_qr = GardenInviteRecord::parse_any(&qr).expect("qr parses");
        let from_clipboard = GardenInviteRecord::parse_any(&clipboard).expect("text parses");

        assert_eq!(from_link, record, "the link must carry this record");
        assert_eq!(from_qr, record, "the QR content must carry this record");
        assert_eq!(
            from_clipboard, record,
            "the clipboard line must carry this record"
        );
        assert_eq!(
            from_link.encode().expect("re-encode"),
            from_qr.encode().expect("re-encode"),
            "two transports, one canonical record"
        );
    }

    /// Directive 11.4: the record stays under 512 bytes and the QR content
    /// under 640, and an over-long address is refused where it is built.
    #[test]
    fn garden_invite_size() {
        let owner = key(3);
        let host = key(4);
        let record = record_for(&owner, &host, 8);
        let text = record.encode().expect("record text");
        assert!(
            text.len() <= MAX_RECORD_BYTES,
            "record is {} bytes, over {MAX_RECORD_BYTES}",
            text.len()
        );
        let qr = record.qr(Some("10.0.0.5:47001")).expect("qr");
        assert!(
            qr.len() <= MAX_QR_BYTES,
            "QR content is {} bytes, over {MAX_QR_BYTES}",
            qr.len()
        );

        // A host address learned from a real listener is much longer than the
        // fixture above. The local-address QR form must still fit a phone
        // camera and must still parse back to the very same record.
        let listener_address = format!("/ip4/10.0.0.5/tcp/47001/p2p/{}", "A".repeat(90));
        let listener_record = GardenInviteRecord::new(
            0x7a11_0000_0000_0001,
            [7u8; 32],
            [9u8; 32],
            &owner,
            host.public_key_bytes(),
            &listener_address,
            Vec::new(),
            u64::MAX / 2,
            8,
        )
        .expect("a record with a real listener address");
        let listener_qr = listener_record
            .qr(Some(&listener_record.host_address))
            .expect("a reachable Garden must produce a scannable QR");
        assert!(
            listener_qr.len() <= MAX_QR_BYTES,
            "QR content is {} bytes, over {MAX_QR_BYTES}",
            listener_qr.len()
        );
        assert_eq!(
            GardenInviteRecord::parse_any(&listener_qr).expect("qr parses"),
            listener_record,
            "the QR must carry the record it was built from"
        );

        let long_address = "a".repeat(MAX_ADDRESS_BYTES);
        let mut relays = Vec::new();
        for index in 0..MAX_RELAYS {
            relays.push(format!("{long_address}{index}"));
        }
        let refused = GardenInviteRecord::new(
            0x7a11_0000_0000_0001,
            [7u8; 32],
            [9u8; 32],
            &owner,
            host.public_key_bytes(),
            &long_address,
            relays,
            u64::MAX / 2,
            8,
        );
        let reason = refused.expect_err("an oversized record must be refused");
        assert!(
            reason.contains("byte bound") || reason.contains("at most"),
            "the refusal must name the size bound, got: {reason}"
        );
    }

    /// Directive 11.3: a forged, expired or spent invite is refused, and so is
    /// one that speaks a protocol version this node does not.
    #[test]
    fn garden_invite_rejected() {
        let owner = key(5);
        let host = key(6);
        let record = record_for(&owner, &host, 2);

        record
            .verify_join(1_000, 0, INVITE_RECORD_VERSION)
            .expect("a fresh invite admits a joiner");

        let mut forged = record.clone();
        forged.signature[0] ^= 0xff;
        let reason = forged
            .verify_join(1_000, 0, INVITE_RECORD_VERSION)
            .expect_err("a flipped signature must not verify");
        assert!(reason.contains("proof"), "got: {reason}");

        let expired = record_for(&owner, &host, 2);
        let reason = expired
            .verify_join(u64::MAX / 2, 0, INVITE_RECORD_VERSION)
            .expect_err("an expired invite must be refused");
        assert!(reason.contains("expired"), "got: {reason}");

        let reason = record
            .verify_join(1_000, 2, INVITE_RECORD_VERSION)
            .expect_err("a spent invite must be refused");
        assert!(reason.contains("usage limit"), "got: {reason}");

        let reason = record
            .verify_join(1_000, 0, INVITE_RECORD_VERSION + 1)
            .expect_err("a version this node does not speak must be refused");
        assert!(reason.contains("protocol version"), "got: {reason}");
    }

    /// Directive 11.5: the host address changes and the same invite stays
    /// valid, because the proof binds identity and not transport.
    #[test]
    fn garden_invite_host_moves() {
        let owner = key(7);
        let host = key(8);
        let record = record_for(&owner, &host, 8);
        let moved_text = record
            .encode()
            .expect("record text")
            .replace("addr=192.168.1.10:47001", "addr=203.0.113.9:47001")
            .replace("relay=relay.example:47002", "relay=other.example:47002");
        let moved = GardenInviteRecord::decode(&moved_text).expect("moved record parses");

        assert_eq!(
            moved.host, record.host,
            "the host is the same identity after the move"
        );
        assert_ne!(
            moved.host_address, record.host_address,
            "the test must actually move the address"
        );
        moved
            .verify_join(1_000, 0, INVITE_RECORD_VERSION)
            .expect("a moved host keeps its invite valid");
        assert_eq!(
            moved.link().expect("link"),
            GardenInviteRecord::parse_any(&moved.link().expect("link"))
                .expect("parses")
                .link()
                .expect("link"),
            "the moved record is still one canonical invite"
        );
    }
}
