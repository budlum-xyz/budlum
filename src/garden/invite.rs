//! The Garden invite.
//!
//! An invite is one line of text. The same line is the QR content; drawing
//! the QR image belongs to the interface stage.
//!
//! ```text
//! budlum-garden:1?chain=<hex>&genesis=<hex>&token=<hex>&peer=<addr>&peer=<addr>
//! ```
//!
//! * `chain` and `genesis` name the Garden. The joiner fetches the genesis
//!   from a peer and refuses it unless it hashes to `genesis`.
//! * `token` is the invite secret. Genesis carries the public key derived
//!   from it, and a join request must be signed by the matching secret key.
//!   Whoever holds the line can join; nobody else can.
//! * `peer` lists the host address first, then the validators that offered
//!   to relay. A joiner needs no account and no setup: the line is enough.

use super::net::dial_address;
use super::types::{verify_garden_execution_chain, GardenGenesis};
use crate::domain::types::Hash32;
use std::str::FromStr;

/// The scheme and version prefix of an invite line.
const INVITE_PREFIX: &str = "budlum-garden:1?";
/// Longest invite record, in bytes.
///
/// An invite has to survive being carried by hand: read off one screen,
/// typed into another, or drawn as a QR code a camera has to resolve at
/// arm's length. Those carriers set the ceiling, not the parser, so the
/// ceiling is a property of the record and the code holds the record to
/// it at both ends: `to_link` refuses to build a longer one and `parse`
/// refuses to read a longer one.
///
/// The fixed part of a link is 182 bytes (prefix 16, `chain=` and sixteen
/// hex 22, `&genesis=` and sixty-four hex 73, `&token=` and sixty-four hex
/// 71). Each peer costs `&peer=` plus its address, and an IPv4 address with
/// a peer id runs to about 87 bytes, so this ceiling carries a host and two
/// relays. Measured: one peer 269 bytes, three 443, four 530.
const MAX_INVITE_BYTES: usize = 512;
/// Longest QR payload, in bytes.
///
/// A QR carrying this many bytes at error-correction level L is version
/// 20 or below, which still resolves from a phone camera at the distance
/// one person holds a screen out to another.
const MAX_QR_BYTES: usize = 640;
/// Most peer addresses one invite carries.
const MAX_INVITE_PEERS: usize = 8;
/// The bytes an invite spends before its first peer address.
///
/// Prefix 16, `chain=` and sixteen hex 22, `&genesis=` and sixty-four hex
/// 73, `&token=` and sixty-four hex 71.
const FIXED_INVITE_BYTES: usize = INVITE_PREFIX.len() + 6 + 16 + 9 + 64 + 7 + 64;

/// Keep the peer addresses that fit the record, in the order given.
///
/// The caller orders the list by usefulness: the host first, then the
/// relays that reach it. A Garden with more validators than the record can
/// name is normal, so running past the ceiling is not an error here, it is
/// the point at which the list stops. Refusing instead would mean a Garden
/// stops being able to invite anyone the moment it grows, and the whole
/// record would be decided by whichever validator joined last.
///
/// The hard refusal stays in `check`: a record that arrives over the
/// ceiling, from a hand or another implementation, is still refused.
pub fn fit_peers(peers: Vec<String>) -> Vec<String> {
    let mut kept = Vec::new();
    let mut length = FIXED_INVITE_BYTES;
    for peer in peers {
        let cost = "&peer=".len() + peer.len();
        if kept.len() == MAX_INVITE_PEERS || length + cost > MAX_INVITE_BYTES {
            break;
        }
        length += cost;
        kept.push(peer);
    }
    kept
}
/// Longest peer address inside an invite, in bytes.
const MAX_PEER_BYTES: usize = 256;

/// A parsed invite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GardenInvite {
    pub chain_id: u64,
    pub genesis_hash: Hash32,
    pub token: Hash32,
    /// Host address first, relay addresses after it.
    pub peers: Vec<String>,
}

fn parse_hash(label: &str, value: &str) -> Result<Hash32, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "invite field '{label}' must be 64 lowercase hex characters"
        ));
    }
    let bytes = hex::decode(value).map_err(|_| format!("invite field '{label}' is not hex"))?;
    Hash32::try_from(bytes.as_slice())
        .map_err(|_| format!("invite field '{label}' is not 32 bytes"))
}

/// True when the address says how to reach it: a transport and a port.
///
/// `peer_id` alone is a name with no road; `/ip4/.../tcp/` is a road with no
/// number. Both look like a complete invite line and both fail after a person
/// has already agreed to join, which is the worst place to find out.
fn carries_a_door(address: &str) -> bool {
    ["/tcp/", "/udp/"].iter().any(|transport| {
        address
            .split(transport)
            .nth(1)
            .map(|rest| {
                let port = rest.split('/').next().unwrap_or_default();
                !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
            })
            .unwrap_or(false)
    })
}

/// True when `address` can stand in an invite line without escaping.
fn is_plain_peer(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_PEER_BYTES
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | ':' | '-' | '_'))
}

impl GardenInvite {
    /// Build the invite of `genesis` from the invite token and peer list.
    pub fn new(genesis: &GardenGenesis, token: Hash32, peers: Vec<String>) -> Result<Self, String> {
        let invite = Self {
            chain_id: genesis.chain_id,
            genesis_hash: genesis.hash(),
            token,
            peers,
        };
        invite.check()?;
        Ok(invite)
    }

    fn check(&self) -> Result<(), String> {
        // A Garden runs on its own chain id only. An invite that names a
        // primary Budlum chain is refused with the name of that network.
        verify_garden_execution_chain(self.chain_id)?;
        if self.peers.is_empty() || self.peers.len() > MAX_INVITE_PEERS {
            return Err(format!(
                "invite must carry 1..={MAX_INVITE_PEERS} peer addresses"
            ));
        }
        let mut seen_peers = std::collections::BTreeSet::new();
        for peer in &self.peers {
            if !seen_peers.insert(peer.as_str()) {
                return Err(format!("invite repeats peer address {peer}"));
            }
            if !is_plain_peer(peer) {
                return Err("invite carries a peer address that is not a plain multiaddr".into());
            }
            // A peer line is where a node knocks. One that carries only a
            // peer id, or no transport at all, is a door with no address: the
            // record looks complete and the join fails afterwards, which is
            // the worst place to find out.
            if !carries_a_door(peer) {
                return Err(format!(
                    "peer address {peer} carries no transport and port to knock on"
                ));
            }
            // A node dials these before it knows anything else about the
            // Garden, so each one names the validator it leads to and uses a
            // numeric IP host (never a DNS name that would query local
            // resolvers on untrusted pasted text before genesis verification).
            //
            // `dial_address` insists on a plain host/port/peer-id line because
            // that is all a node dials. An invite, though, is where a member
            // announces itself, and `quic-v1` - the transport the Garden
            // network actually announces on - is not a line `dial_address`
            // accepts. So `quic-v1` is not sent through the dial parser: what
            // it must carry is a numeric host, a numeric port and a peer id,
            // which is exactly what `carries_a_door` above and the peer-id
            // parse below check. Anything else still goes through the dial
            // parser, so no line is accepted here that a node could not dial.
            let Some((reachable, peer_id)) = peer.rsplit_once("/p2p/") else {
                return Err(format!("invite peer {peer} names no peer id"));
            };
            if reachable.contains("/p2p/") {
                return Err(format!("invite peer {peer} names more than one peer id"));
            }
            let parsed: libp2p::Multiaddr = if reachable.contains("/quic") {
                let whole = format!("{reachable}/p2p/{peer_id}");
                let parsed: libp2p::Multiaddr = whole
                    .parse()
                    .map_err(|e| format!("invite peer {peer} is not a multiaddr: {e}"))?;
                let host_ok = {
                    let mut parts = parsed.iter();
                    matches!(
                        parts.next(),
                        Some(
                            libp2p::multiaddr::Protocol::Ip4(_)
                                | libp2p::multiaddr::Protocol::Ip6(_)
                                | libp2p::multiaddr::Protocol::Dns4(_)
                        )
                    )
                };
                if !host_ok {
                    return Err(format!(
                        "invite peer {peer} is refused: a dialable host comes first"
                    ));
                }
                parsed
            } else {
                dial_address(&format!("{reachable}/p2p/{peer_id}"))
                    .map_err(|e| format!("invite peer {peer} is refused: {e}"))?
                    .0
            };
            // The line names one validator, and the id must be one libp2p can
            // actually use: a well-formed multihash naming no key type parses
            // happily and then fails at the handshake, after somebody joined.
            libp2p::PeerId::from_str(peer_id).map_err(|_| {
                format!("invite peer {peer} does not end in a peer id a node can hold")
            })?;
            match parsed.iter().next() {
                Some(libp2p::multiaddr::Protocol::Ip4(ip)) => {
                    if ip.is_unspecified()
                        || ip.is_link_local()
                        || ip.is_multicast()
                        || ip.is_broadcast()
                    {
                        return Err(format!(
                            "invite peer {peer} is refused: unroutable or link-local IPv4 target"
                        ));
                    }
                }
                Some(libp2p::multiaddr::Protocol::Ip6(ip)) => {
                    let bad_mapped = ip.to_ipv4_mapped().is_some_and(|v4| {
                        v4.is_unspecified()
                            || v4.is_link_local()
                            || v4.is_multicast()
                            || v4.is_broadcast()
                    });
                    if ip.is_unspecified()
                        || ip.is_unicast_link_local()
                        || ip.is_multicast()
                        || bad_mapped
                    {
                        return Err(format!(
                            "invite peer {peer} is refused: unroutable or link-local IPv6 target"
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "invite peer {peer} is refused: invite peers must use numeric IP addresses, not DNS names"
                    ));
                }
            }
        }
        // The record is held to its ceiling here rather than at the parser,
        // so the same rule covers both directions: a node cannot hand out an
        // invite it would itself refuse to read. Checking it at the end means
        // the length is measured on the record that passed every other rule.
        let length = self.link_bytes();
        if length > MAX_INVITE_BYTES {
            return Err(format!(
                "invite is {length} bytes, over the {MAX_INVITE_BYTES} byte ceiling"
            ));
        }
        Ok(())
    }

    /// The length of the invite line in bytes.
    ///
    /// Counted the way `to_link` writes it, so the ceiling the checker
    /// applies and the record a validator hands out are the same thing.
    fn link_bytes(&self) -> usize {
        let mut length = FIXED_INVITE_BYTES;
        for peer in &self.peers {
            length += "&peer=".len() + peer.len();
        }
        length
    }

    /// The invite line. It is also the QR content.
    pub fn to_link(&self) -> String {
        let mut link = format!(
            "{INVITE_PREFIX}chain={:016x}&genesis={}&token={}",
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

    /// Parse an invite line. Unknown fields and repeated single fields are
    /// refused, so two different lines never mean the same invite.
    pub fn parse(link: &str) -> Result<Self, String> {
        if link.len() > MAX_INVITE_BYTES {
            return Err("invite is too long".into());
        }
        let query = link
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| format!("invite must start with '{INVITE_PREFIX}'"))?;
        let mut chain_id = None;
        let mut genesis_hash = None;
        let mut token = None;
        let mut peers = Vec::new();
        for pair in query.split('&') {
            let (name, value) = pair
                .split_once('=')
                .ok_or_else(|| "invite field has no value".to_string())?;
            match name {
                "chain" if chain_id.is_none() => {
                    if value.len() != 16
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        return Err(
                            "invite field 'chain' must be 16 lowercase hex characters".to_string()
                        );
                    }
                    chain_id = Some(
                        u64::from_str_radix(value, 16)
                            .map_err(|_| "invite field 'chain' is not hex".to_string())?,
                    );
                }
                "genesis" if genesis_hash.is_none() => {
                    genesis_hash = Some(parse_hash("genesis", value)?);
                }
                "token" if token.is_none() => token = Some(parse_hash("token", value)?),
                "peer" => peers.push(value.to_string()),
                other => return Err(format!("invite field '{other}' is unknown or repeated")),
            }
        }
        let invite = Self {
            chain_id: chain_id.ok_or("invite has no 'chain' field")?,
            genesis_hash: genesis_hash.ok_or("invite has no 'genesis' field")?,
            token: token.ok_or("invite has no 'token' field")?,
            peers,
        };
        invite.check()?;
        Ok(invite)
    }

    /// The QR payload of this invite.
    ///
    /// Today it is the invite line itself, so the two are one record and a
    /// person who reads either one reads the same Garden. The payload has
    /// its own ceiling because its carrier is a camera rather than a
    /// parser, and the two ceilings answer to different limits: a record
    /// has to stay small enough to retype, a QR has to stay inside a
    /// version a phone resolves at arm's length.
    ///
    /// # Errors
    ///
    /// Refuses a payload over [`MAX_QR_BYTES`], so a Garden never shows a
    /// QR that a camera on the other side of the room cannot read.
    pub fn qr_content(&self) -> Result<String, String> {
        let content = self.to_link();
        if content.len() > MAX_QR_BYTES {
            return Err(format!(
                "qr content is {} bytes, over the {MAX_QR_BYTES} byte ceiling",
                content.len()
            ));
        }
        Ok(content)
    }

    /// Check a genesis fetched from a peer against this invite.
    pub fn accepts(&self, genesis: &GardenGenesis) -> Result<(), String> {
        genesis.verify()?;
        if genesis.chain_id != self.chain_id || genesis.hash() != self.genesis_hash {
            return Err("peer sent a genesis that is not the one in the invite".into());
        }
        let invite_key = super::types::invite_keypair(&self.token)?.public_key_bytes();
        if genesis.invite_key != invite_key {
            return Err("invite token does not belong to this Garden".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{GardenFounding, GardenLimits};
    use super::*;
    use crate::crypto::primitives::KeyPair;

    /// A peer address the way a validator announces it.
    fn peer(host: &str, port: u16) -> String {
        let key = KeyPair::generate().unwrap().public_key_bytes();
        let id = super::super::net::peer_id_of(&key).unwrap();
        format!("{host}/tcp/{port}/p2p/{id}")
    }

    fn genesis(token: &Hash32) -> GardenGenesis {
        GardenGenesis::new(
            GardenFounding {
                title: "Room".into(),
                host_name: "host".into(),
                host_address: "/ip4/127.0.0.1/tcp/4001".into(),
                limits: GardenLimits::default(),
            },
            KeyPair::generate().unwrap().public_key_bytes(),
            1,
            2,
            token,
        )
        .unwrap()
    }

    #[test]
    fn garden_invite_size() {
        let token = [3u8; 32];
        let g = genesis(&token);

        // The record a host hands out stays inside both ceilings: the one
        // the parser applies and the one a QR has to carry.
        let invite = GardenInvite::new(&g, token, vec![peer("/ip4/192.0.2.10", 4001)]).unwrap();
        let link = invite.to_link();
        assert_eq!(
            link.len(),
            invite.link_bytes(),
            "the counter and the writer disagree"
        );
        assert!(
            link.len() < MAX_INVITE_BYTES,
            "a one peer invite is {} bytes",
            link.len()
        );
        assert!(
            link.len() < MAX_QR_BYTES,
            "the QR content is {} bytes",
            link.len()
        );

        // A record over the ceiling is refused where it is built, not only
        // where it is read. Without this the node would hand out an invite
        // it would itself refuse, and the ceiling would be a wish.
        let many: Vec<String> = (0..MAX_INVITE_PEERS)
            .map(|n| peer(&format!("/ip4/192.0.2.{}", 10 + n), 4001))
            .collect();
        let refusal = GardenInvite::new(&g, token, many).unwrap_err();
        assert!(
            refusal.contains("over the") && refusal.contains("byte ceiling"),
            "{refusal}"
        );

        // And the same record is refused when it arrives from outside, so
        // another implementation cannot hand this node a record this node
        // would never write.
        let mut handmade = invite.to_link();
        while handmade.len() <= MAX_INVITE_BYTES {
            handmade.push_str(&format!("&peer={}", peer("/ip4/192.0.2.99", 4001)));
        }
        assert!(GardenInvite::parse(&handmade).is_err());

        // What the node hands out is built to fit, so a Garden that grows
        // past the record still invites: the list stops, it does not fail.
        let crowd: Vec<String> = (0..MAX_INVITE_PEERS)
            .map(|n| peer(&format!("/ip4/192.0.2.{}", 20 + n), 4001))
            .collect();
        let fitted = fit_peers(crowd.clone());
        assert!(!fitted.is_empty(), "the record kept no peer at all");
        assert!(fitted.len() < crowd.len(), "nothing was dropped");
        assert_eq!(fitted[0], crowd[0], "the first address is not the host");
        let built = GardenInvite::new(&g, token, fitted).unwrap();
        assert!(built.to_link().len() <= MAX_INVITE_BYTES);
    }

    #[test]
    fn garden_invite_same_record() {
        // The link and the QR content are one record, not two that have to
        // be kept in step. A second reading of the same Garden gives the
        // same bytes, so a person who copies either one copies the same
        // invite.
        let token = [3u8; 32];
        let g = genesis(&token);
        let peers = vec![peer("/ip4/192.0.2.10", 4001), peer("/ip4/192.0.2.11", 4002)];
        let first = GardenInvite::new(&g, token, peers.clone()).unwrap();
        let second = GardenInvite::new(&g, token, peers).unwrap();
        assert_eq!(first.to_link(), second.to_link());
        assert_eq!(GardenInvite::parse(&first.to_link()).unwrap(), first);
        // Reading it back and writing it out again is the identity, so the
        // record survives every hop a person puts it through.
        let round = GardenInvite::parse(&first.to_link()).unwrap().to_link();
        assert_eq!(round, first.to_link());
    }

    #[test]
    fn garden_invite_link_round_trips_and_is_the_qr_content() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let invite = GardenInvite::new(
            &g,
            token,
            vec![peer("/ip4/127.0.0.1", 4001), peer("/ip6/::1", 4002)],
        )
        .unwrap();
        let link = invite.to_link();
        assert!(link.starts_with("budlum-garden:1?chain="));
        assert_eq!(GardenInvite::parse(&link).unwrap(), invite);
        invite.accepts(&g).unwrap();
    }

    #[test]
    fn garden_invite_refuses_dns_peer_addresses() {
        let token = [3u8; 32];
        let g = genesis(&token);
        for dns_peer in [
            peer("/dns/relay.example", 4002),
            peer("/dns4/relay.example", 4002),
            peer("/dns6/relay.example", 4002),
        ] {
            let err = GardenInvite::new(&g, token, vec![dns_peer]).unwrap_err();
            assert!(err.contains("numeric IP"), "{err}");
        }
    }

    #[test]
    fn garden_invite_refuses_a_swapped_genesis_and_a_wrong_token() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let invite = GardenInvite::new(&g, token, vec![peer("/ip4/1.2.3.4", 4001)]).unwrap();
        let other = genesis(&token);
        assert!(invite.accepts(&other).is_err());
        let mut wrong_token = invite;
        wrong_token.token = [4u8; 32];
        let refusal = wrong_token.accepts(&g).unwrap_err();
        assert!(refusal.contains("does not belong"), "{refusal}");
    }

    /// A peer of an invite is dialed before anything else is known, so it
    /// names the validator it leads to. A bare host and port is refused.
    #[test]
    fn garden_invite_peer_names_the_validator_it_leads_to() {
        let token = [3u8; 32];
        let g = genesis(&token);
        for bare in ["/ip4/10.0.0.9/tcp/6379", "/dns4/internal.example/tcp/8080"] {
            let refusal = GardenInvite::new(&g, token, vec![bare.into()]).unwrap_err();
            assert!(refusal.contains("peer id"), "{refusal}");
        }
    }

    /// A peer line with no transport, or with a transport and no port, is
    /// refused when the invite is built rather than after a person agreed.
    #[test]
    fn garden_invite_refuses_a_peer_with_no_door_to_knock_on() {
        let token = [4u8; 32];
        let g = genesis(&token);
        let key = KeyPair::generate().unwrap().public_key_bytes();
        let id = super::super::net::peer_id_of(&key).unwrap();
        for address in [format!("/p2p/{id}"), format!("/ip4/10.0.0.9/p2p/{id}")] {
            let refusal = GardenInvite::new(&g, token, vec![address.clone()]).unwrap_err();
            assert!(
                refusal.contains("transport"),
                "{address} was accepted or refused for the wrong reason: {refusal}"
            );
        }
        // The transport spelling the network actually announces still passes.
        assert!(GardenInvite::new(&g, token, vec![peer("/ip4/10.0.0.9", 4001)]).is_ok());
        // A port is part of the address: `/tcp/` with nothing after it is not
        // somewhere to knock either. QUIC is a real transport here and is
        // not refused for this reason.
        let portless = format!("/ip4/10.0.0.9/tcp/p2p/{id}");
        let refusal = GardenInvite::new(&g, token, vec![portless]).unwrap_err();
        assert!(refusal.contains("transport"), "{refusal}");
        let quic = format!("/ip4/10.0.0.9/udp/4001/quic-v1/p2p/{id}");
        assert!(carries_a_door(&quic), "quic carries a transport and a port");
    }

    #[test]
    fn garden_invite_parser_is_bounded_and_strict() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let link = GardenInvite::new(&g, token, vec![peer("/ip4/1.2.3.4", 4001)])
            .unwrap()
            .to_link();
        assert!(GardenInvite::parse(&format!("{link}&extra=1")).is_err());
        assert!(GardenInvite::parse(&format!("{link}&token={}", hex::encode([9u8; 32]))).is_err());
        assert!(GardenInvite::parse(&link.replace("budlum-garden:1?", "http://")).is_err());
        let more = peer("/ip4/1.1.1.1", 4001);
        GardenInvite::parse(&format!("{link}&peer={more}")).unwrap();
        assert!(GardenInvite::parse(&format!("{link}&peer={more}?x")).is_err());
        assert!(
            GardenInvite::parse(&format!("{link}{}", format!("&peer={more}").repeat(8))).is_err()
        );
        assert!(GardenInvite::parse(&"x".repeat(MAX_INVITE_BYTES + 1)).is_err());
        let no_peer = link.split("&peer=").next().unwrap().to_string();
        assert!(GardenInvite::parse(&no_peer).is_err());

        // DNS/dnsaddr and cloud-metadata link-local/unroutable targets are refused.
        for bad in [
            peer("/dns4/relay.example", 4001),
            peer("/ip4/169.254.169.254", 80),
            peer("/ip4/0.0.0.0", 4001),
            peer("/ip4/224.0.0.1", 4001),
            peer("/ip6/fe80::1", 4001),
            peer("/ip6/::ffff:169.254.169.254", 80),
        ] {
            assert!(
                GardenInvite::new(&g, token, vec![bad.clone()]).is_err(),
                "expected invite peer {bad} to be refused"
            );
        }
    }

    #[test]
    fn garden_invite_refuses_non_canonical_hex_and_duplicate_peers() {
        let token = [0xabu8; 32];
        let g = genesis(&token);
        let p = peer("/ip4/1.2.3.4", 4001);
        assert!(GardenInvite::new(&g, token, vec![p.clone(), p.clone()]).is_err());

        let canonical = GardenInvite::new(&g, token, vec![p]).unwrap().to_link();

        // The mutated line has to differ from the canonical one, or the
        // assertion below proves nothing. `chain` is rendered with `{:016x}`
        // and a Garden chain id always carries the `0x4741` prefix, so the id is
        // at least 2^62 and its canonical form is exactly 16 digits. Neither
        // `{:x}` of the id nor `{:x}` of the id shifted right by four bits is
        // shorter: both are 16-digit values, so `replacen` would find nothing to
        // rewrite and this test would check a canonical line against a
        // rejection assertion. Dropping the id's leading (always zero) digit
        // gives a real 15-character field that a canonical parser has to refuse.
        let digits = format!("{:016x}", g.chain_id);
        let short_chain = canonical.replacen(
            &format!("chain={digits}"),
            &format!("chain={}", &digits[1..]),
            1,
        );
        assert_ne!(
            canonical, short_chain,
            "the mutation must change the line, or the assertion below proves nothing"
        );
        assert!(
            GardenInvite::parse(&short_chain).is_err(),
            "a 15-digit chain id is not canonical"
        );
        let signed_chain = canonical.replacen(
            &format!("chain={:016x}", g.chain_id),
            &format!("chain=+{:x}", g.chain_id),
            1,
        );
        assert!(GardenInvite::parse(&signed_chain).is_err());
        let upper_token =
            canonical.replacen(&hex::encode(token), &hex::encode(token).to_uppercase(), 1);
        assert!(GardenInvite::parse(&upper_token).is_err());
    }
}
