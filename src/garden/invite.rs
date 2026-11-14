use crate::core::hash::hash_fields_bytes;
use crate::garden::types::{GardenChainId, GardenGenesis, TAG_GARDEN_INVITE};
use serde::{Deserialize, Serialize};

const INVITE_SCHEME_PREFIX: &str = "budlum://garden/v1?";

/// Shareable invite payload used identically by both deep links and QR codes
/// (Directive 3.5, 4.8). Carries the Garden identity, host endpoint, and
/// relay addresses for NAT traversal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardenInvitePayload {
    pub chain_id: u64,
    pub genesis_hash_hex: String,
    pub title: String,
    pub host_pubkey_hex: String,
    pub host_multiaddr: String,
    pub relay_multiaddrs: Vec<String>,
    pub checksum_hex: String,
}

impl GardenInvitePayload {
    pub fn from_genesis(
        genesis: &GardenGenesis,
        host_multiaddr: String,
        relay_multiaddrs: Vec<String>,
    ) -> Result<Self, String> {
        if host_multiaddr.trim().is_empty() {
            return Err("host_multiaddr must not be empty".into());
        }
        let mut sorted_relays: Vec<String> = relay_multiaddrs
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        sorted_relays.sort();
        sorted_relays.dedup();

        let genesis_hash_hex = hex::encode(genesis.genesis_hash);
        let host_pubkey_hex = hex::encode(genesis.host_pubkey);
        let checksum_hex = compute_invite_checksum(
            genesis.chain_id.value(),
            &genesis_hash_hex,
            &genesis.title,
            &host_pubkey_hex,
            &host_multiaddr,
            &sorted_relays,
        );

        Ok(Self {
            chain_id: genesis.chain_id.value(),
            genesis_hash_hex,
            title: genesis.title.clone(),
            host_pubkey_hex,
            host_multiaddr,
            relay_multiaddrs: sorted_relays,
            checksum_hex,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if !GardenChainId(self.chain_id).is_valid_garden_id() {
            return Err(format!(
                "invalid Garden chain_id in invite: {}",
                self.chain_id
            ));
        }
        let gen_bytes = hex::decode(&self.genesis_hash_hex)
            .map_err(|_| "invalid genesis_hash_hex in invite".to_string())?;
        if gen_bytes.len() != 32 {
            return Err("genesis_hash_hex must decode to 32 bytes".into());
        }
        let host_bytes = hex::decode(&self.host_pubkey_hex)
            .map_err(|_| "invalid host_pubkey_hex in invite".to_string())?;
        if host_bytes.len() != 32 {
            return Err("host_pubkey_hex must decode to 32 bytes".into());
        }
        if self.host_multiaddr.trim().is_empty() {
            return Err("invite missing host_multiaddr".into());
        }
        let expected_checksum = compute_invite_checksum(
            self.chain_id,
            &self.genesis_hash_hex,
            &self.title,
            &self.host_pubkey_hex,
            &self.host_multiaddr,
            &self.relay_multiaddrs,
        );
        if expected_checksum != self.checksum_hex {
            return Err("invite checksum verification failed".into());
        }
        Ok(())
    }

    /// Encode as a clickable `budlum://garden/v1?...` invite URI.
    pub fn to_invite_link(&self) -> Result<String, String> {
        self.validate()?;
        let relays = self.relay_multiaddrs.join(",");
        Ok(format!(
            "{}chain={}&genesis={}&title={}&host={}&addr={}&relays={}&sig={}",
            INVITE_SCHEME_PREFIX,
            self.chain_id,
            self.genesis_hash_hex,
            percent_encode(&self.title),
            self.host_pubkey_hex,
            percent_encode(&self.host_multiaddr),
            percent_encode(&relays),
            self.checksum_hex,
        ))
    }

    /// Encode as the canonical QR payload carrying the exact same information
    /// as the invite link (Directive 3.5).
    pub fn to_qr_payload(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|e| format!("failed to serialize QR payload: {e}"))
    }

    /// Decode either a `budlum://garden/v1?...` URI or a JSON QR payload.
    pub fn decode_any(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if let Some(query) = trimmed.strip_prefix(INVITE_SCHEME_PREFIX) {
            Self::decode_query(query)
        } else {
            let parsed: Self = serde_json::from_str(trimmed)
                .map_err(|e| format!("failed to decode Garden invite/QR payload: {e}"))?;
            parsed.validate()?;
            Ok(parsed)
        }
    }

    fn decode_query(query: &str) -> Result<Self, String> {
        let mut chain_id: Option<u64> = None;
        let mut genesis_hash_hex: Option<String> = None;
        let mut title: Option<String> = None;
        let mut host_pubkey_hex: Option<String> = None;
        let mut host_multiaddr: Option<String> = None;
        let mut relay_multiaddrs: Vec<String> = Vec::new();
        let mut checksum_hex: Option<String> = None;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| "malformed key=value pair in Garden invite URI".to_string())?;
            match k {
                "chain" => {
                    let parsed = v
                        .parse::<u64>()
                        .map_err(|_| "invalid chain id in Garden invite URI".to_string())?;
                    chain_id = Some(parsed);
                }
                "genesis" => genesis_hash_hex = Some(v.to_string()),
                "title" => title = Some(percent_decode(v)?),
                "host" => host_pubkey_hex = Some(v.to_string()),
                "addr" => host_multiaddr = Some(percent_decode(v)?),
                "relays" => {
                    let decoded = percent_decode(v)?;
                    relay_multiaddrs = decoded
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "sig" => checksum_hex = Some(v.to_string()),
                _ => {}
            }
        }

        let payload = Self {
            chain_id: chain_id.ok_or_else(|| "invite missing chain".to_string())?,
            genesis_hash_hex: genesis_hash_hex
                .ok_or_else(|| "invite missing genesis".to_string())?,
            title: title.ok_or_else(|| "invite missing title".to_string())?,
            host_pubkey_hex: host_pubkey_hex.ok_or_else(|| "invite missing host".to_string())?,
            host_multiaddr: host_multiaddr.ok_or_else(|| "invite missing addr".to_string())?,
            relay_multiaddrs,
            checksum_hex: checksum_hex.ok_or_else(|| "invite missing sig".to_string())?,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn host_pubkey_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.host_pubkey_hex)
            .map_err(|_| "invalid host_pubkey_hex".to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "host_pubkey_hex must be 32 bytes".to_string())?;
        Ok(arr)
    }

    pub fn genesis_hash_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.genesis_hash_hex)
            .map_err(|_| "invalid genesis_hash_hex".to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "genesis_hash_hex must be 32 bytes".to_string())?;
        Ok(arr)
    }

    pub fn host_socket_addr(&self) -> Option<std::net::SocketAddr> {
        parse_tcp_multiaddr(&self.host_multiaddr)
    }

    pub fn relay_socket_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.relay_multiaddrs
            .iter()
            .filter_map(|m| parse_tcp_multiaddr(m))
            .collect()
    }
}

/// Parse a `/ip4/<ip>/tcp/<port>[/...]` or `/ip6/<ip>/tcp/<port>[/...]` multiaddr
/// into a `SocketAddr`.
fn parse_tcp_multiaddr(multiaddr: &str) -> Option<std::net::SocketAddr> {
    let parts: Vec<&str> = multiaddr.trim().split('/').collect();
    // Expect leading empty segment from initial '/': ["", "ip4"|"ip6", ip, "tcp", port, ...]
    if parts.len() < 5 || !parts[0].is_empty() {
        return None;
    }
    let ip: std::net::IpAddr = match parts[1] {
        "ip4" => parts[2].parse::<std::net::Ipv4Addr>().ok()?.into(),
        "ip6" => parts[2].parse::<std::net::Ipv6Addr>().ok()?.into(),
        _ => return None,
    };
    if parts[3] != "tcp" {
        return None;
    }
    let port: u16 = parts[4].parse().ok()?;
    Some(std::net::SocketAddr::new(ip, port))
}

fn compute_invite_checksum(
    chain_id: u64,
    genesis_hash_hex: &str,
    title: &str,
    host_pubkey_hex: &str,
    host_multiaddr: &str,
    relay_multiaddrs: &[String],
) -> String {
    let joined_relays = relay_multiaddrs.join("\n");
    let digest = hash_fields_bytes(&[
        TAG_GARDEN_INVITE,
        &chain_id.to_le_bytes(),
        genesis_hash_hex.as_bytes(),
        title.as_bytes(),
        host_pubkey_hex.as_bytes(),
        host_multiaddr.as_bytes(),
        joined_relays.as_bytes(),
    ]);
    hex::encode(&digest[..16])
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        let is_unreserved =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(*byte as char);
        } else {
            out.push('%');
            let hi = char::from_digit((byte >> 4) as u32, 16)
                .map(|c| c.to_ascii_uppercase())
                .unwrap_or('0');
            let lo = char::from_digit((byte & 0x0f) as u32, 16)
                .map(|c| c.to_ascii_uppercase())
                .unwrap_or('0');
            out.push(hi);
            out.push(lo);
        }
    }
    out
}

fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("truncated percent escape in Garden invite URI".into());
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid hex digit in Garden invite URI".to_string())?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid hex digit in Garden invite URI".to_string())?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "invalid UTF-8 in Garden invite URI".into())
}
