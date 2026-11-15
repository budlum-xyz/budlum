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

use super::types::{verify_garden_execution_chain, GardenGenesis};
use crate::domain::types::Hash32;

/// The scheme and version prefix of an invite line.
const INVITE_PREFIX: &str = "budlum-garden:1?";
/// Longest invite line accepted, in bytes.
const MAX_INVITE_BYTES: usize = 4096;
/// Most peer addresses one invite carries.
pub const MAX_INVITE_PEERS: usize = 8;
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
    let bytes = hex::decode(value).map_err(|_| format!("invite field '{label}' is not hex"))?;
    Hash32::try_from(bytes.as_slice())
        .map_err(|_| format!("invite field '{label}' is not 32 bytes"))
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
        if !self.peers.iter().all(|peer| is_plain_peer(peer)) {
            return Err("invite carries a peer address that is not a plain multiaddr".into());
        }
        Ok(())
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
    fn garden_invite_link_round_trips_and_is_the_qr_content() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let invite = GardenInvite::new(
            &g,
            token,
            vec![
                "/ip4/127.0.0.1/tcp/4001".into(),
                "/dns4/relay.example/tcp/4002".into(),
            ],
        )
        .unwrap();
        let link = invite.to_link();
        assert!(link.starts_with("budlum-garden:1?chain="));
        assert_eq!(GardenInvite::parse(&link).unwrap(), invite);
        invite.accepts(&g).unwrap();
    }

    #[test]
    fn garden_invite_refuses_a_swapped_genesis_and_a_wrong_token() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let invite = GardenInvite::new(&g, token, vec!["/ip4/1.2.3.4/tcp/1".into()]).unwrap();
        let other = genesis(&token);
        assert!(invite.accepts(&other).is_err());
        let mut wrong_token = invite;
        wrong_token.token = [4u8; 32];
        let refusal = wrong_token.accepts(&g).unwrap_err();
        assert!(refusal.contains("does not belong"), "{refusal}");
    }

    #[test]
    fn garden_invite_parser_is_bounded_and_strict() {
        let token = [3u8; 32];
        let g = genesis(&token);
        let link = GardenInvite::new(&g, token, vec!["/ip4/1.2.3.4/tcp/1".into()])
            .unwrap()
            .to_link();
        assert!(GardenInvite::parse(&format!("{link}&extra=1")).is_err());
        assert!(GardenInvite::parse(&format!("{link}&token={}", hex::encode([9u8; 32]))).is_err());
        assert!(GardenInvite::parse(&link.replace("budlum-garden:1?", "http://")).is_err());
        assert!(GardenInvite::parse(&format!("{link}&peer=/ip4/1.1.1.1/tcp/1?x")).is_err());
        assert!(
            GardenInvite::parse(&format!("{link}{}", "&peer=/ip4/1.1.1.1/tcp/1".repeat(8)))
                .is_err()
        );
        assert!(GardenInvite::parse(&"x".repeat(MAX_INVITE_BYTES + 1)).is_err());
        let no_peer = link.split("&peer=").next().unwrap().to_string();
        assert!(GardenInvite::parse(&no_peer).is_err());
    }
}
