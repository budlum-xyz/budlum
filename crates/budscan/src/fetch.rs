//! The fetcher layer: four targets, four different verification strengths.
//!
//! Each fetcher **declares its own verification strength**, and the address bar
//! shows exactly that.
//!
//! | target           | fetched over | verification             | in the bar      |
//! |------------------|--------------|--------------------------|-----------------|
//! | Budlum manifest  | B.U.D.       | hash equals `manifest_id`| verified        |
//! | IPFS CID         | IPFS         | hash equals the CID      | verified        |
//! | Arweave tx       | Arweave      | hash equals `data_root`  | verified        |
//! | HTTPS URL        | HTTP         | TLS only                 | transport only  |
//!
//! # Transport is not in this module
//!
//! The [`Transport`] trait is the seam, and the seam is deliberate:
//! verification logic that is bound to something touching a socket becomes
//! untestable, and a verifier that is not verified is not a verifier. In
//! production the transport is `budlum-core`'s `NodeClient` or an HTTP client;
//! in the tests it is a table.

use crate::arweave::{self, ArweaveVerdict};
use crate::cid::{self, CidVerdict};
use crate::content_id::{bytes_match, ContentId};
use crate::evidence::{Claim, Evidence, Strength};

/// A target: the thing a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A Budlum B.U.D. manifest id.
    Bud(ContentId),
    /// An IPFS CID in string form; the fetcher parses it.
    Ipfs(String),
    /// An Arweave `data_root`, as raw bytes.
    Arweave(Vec<u8>),
    /// An ordinary HTTPS address.
    Https(String),
}

impl Target {
    /// The **maximum** verification strength of this target, known before any
    /// byte arrives.
    ///
    /// An HTTPS target has no chance of being verified, and knowing that before
    /// fetching makes it possible to tell the user before they click.
    #[must_use]
    pub fn ceiling(&self) -> Strength {
        match self {
            Self::Bud(_) | Self::Ipfs(_) | Self::Arweave(_) => Strength::Verified,
            Self::Https(_) => Strength::TransportOnly,
        }
    }

    #[must_use]
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Bud(_) => "bud",
            Self::Ipfs(_) => "ipfs",
            Self::Arweave(_) => "arweave",
            Self::Https(_) => "https",
        }
    }
}

/// Where the bytes come from. The network is not in this crate.
pub trait Transport {
    /// Fetch the target's bytes.
    ///
    /// # Errors
    ///
    /// A network error, content that is not found, or the size limit being
    /// exceeded.
    fn fetch(&self, target: &Target) -> Result<Vec<u8>, String>;
}

/// The result of a fetch: the bytes **and** how strongly they were verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub evidence: Evidence,
}

impl Fetched {
    /// May the bytes be displayed?
    #[must_use]
    pub fn is_displayable(&self) -> bool {
        self.evidence.is_displayable()
    }
}

/// The maximum size of a page.
///
/// It is the same as `budlum-core`'s `MAX_GATEWAY_CONTENT_BYTES`, 10 MiB. That
/// sameness is not a coincidence: both carry the same content, and two
/// different limits would open a gap in which one accepts what the other
/// refuses.
pub const MAX_CONTENT_BYTES: usize = 10 * 1024 * 1024;

/// Fetch a target and verify it.
///
/// Verification is **always** performed; when it fails, the bytes are still
/// returned but the `Evidence` becomes `Refused` and `is_displayable()` returns
/// false. Labelling the bytes rather than discarding them leaves the caller able
/// to show what was refused, so an error page can say "3 KB arrived, the hash
/// did not match".
///
/// # Errors
///
/// A transport error, a size overrun, or a target identifier that cannot be
/// parsed.
pub fn fetch_and_verify<T: Transport>(transport: &T, target: &Target) -> Result<Fetched, String> {
    let bytes = transport.fetch(target)?;
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err(format!(
            "{} content is {} bytes; the limit is {MAX_CONTENT_BYTES}",
            target.scheme(),
            bytes.len()
        ));
    }

    let evidence = match target {
        Target::Bud(manifest_id) => {
            if bytes_match(*manifest_id, &bytes) {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Verified,
                    "the ContentId of the bytes equals the manifest_id",
                ))
            } else {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Refused,
                    &format!(
                        "the ContentId of the bytes is {} but the manifest_id is {manifest_id}",
                        ContentId::of(&bytes)
                    ),
                ))
            }
        }
        Target::Ipfs(s) => {
            let parsed = cid::parse(s).map_err(|e| format!("the CID could not be parsed: {e}"))?;
            match cid::verify(&parsed, &bytes) {
                CidVerdict::Verified => Evidence::new().with(Claim::new(
                    "ipfs",
                    Strength::Verified,
                    "the sha2-256 digest of the bytes equals the CID",
                )),
                CidVerdict::DigestMismatch { expected, produced } => {
                    Evidence::new().with(Claim::new(
                        "ipfs",
                        Strength::Refused,
                        &format!("the digest is {produced}, the CID is {expected}"),
                    ))
                }
                CidVerdict::UnsupportedMultiblock => Evidence::new().with(Claim::new(
                    "ipfs",
                    Strength::RpcClaimOnly,
                    "dag-pb: this version does not walk a UnixFS DAG, so the bytes are unverified",
                )),
            }
        }
        Target::Arweave(root) => match arweave::verify(root, &bytes) {
            ArweaveVerdict::Verified => Evidence::new().with(Claim::new(
                "arweave",
                Strength::Verified,
                "the data_root derived from the bytes equals the one in the transaction",
            )),
            ArweaveVerdict::RootMismatch { expected, produced } => {
                Evidence::new().with(Claim::new(
                    "arweave",
                    Strength::Refused,
                    &format!("the data_root is {produced}, expected {expected}"),
                ))
            }
        },
        Target::Https(url) => Evidence::new().with(Claim::new(
            "https",
            Strength::TransportOnly,
            &format!("{url}: TLS says who sent it, not what was sent"),
        )),
    };

    Ok(Fetched { bytes, evidence })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Table(HashMap<String, Vec<u8>>);

    impl Table {
        fn with(key: &str, bytes: &[u8]) -> Self {
            let mut m = HashMap::new();
            m.insert(key.to_string(), bytes.to_vec());
            Table(m)
        }
    }

    impl Transport for Table {
        fn fetch(&self, target: &Target) -> Result<Vec<u8>, String> {
            let key = match target {
                Target::Bud(id) => id.to_string(),
                Target::Ipfs(s) | Target::Https(s) => s.clone(),
                Target::Arweave(r) => hex::encode(r),
            };
            self.0
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("{key} bulunamadi"))
        }
    }

    #[test]
    fn bud_content_that_hashes_correctly_is_verified() {
        let bytes = b"<html>ayaz</html>";
        let id = ContentId::of(bytes);
        let t = Table::with(&id.to_string(), bytes);
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Verified);
        assert!(got.is_displayable());
    }

    #[test]
    fn bud_content_that_does_not_hash_is_refused_and_not_displayed() {
        let id = ContentId::of(b"beklenen");
        let t = Table::with(&id.to_string(), b"something else arrived");
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Refused);
        assert!(!got.is_displayable());
        // The reason must carry both identities, or the user cannot tell what
        // happened.
        assert!(got.evidence.badge().contains(&id.to_string()));
    }

    #[test]
    fn an_ipfs_raw_cid_is_verified_against_its_digest() {
        let s = "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq";
        let t = Table::with(s, b"hello");
        let got = fetch_and_verify(&t, &Target::Ipfs(s.to_string())).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Verified);
    }

    #[test]
    fn an_ipfs_dag_pb_cid_is_not_claimed_verified() {
        let s = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        let t = Table::with(s, b"whatever");
        let got = fetch_and_verify(&t, &Target::Ipfs(s.to_string())).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(got.is_displayable(), "yasaklamiyoruz, etiketliyoruz");
    }

    #[test]
    fn an_arweave_target_verifies_against_its_data_root() {
        let bytes = b"permaweb";
        let root = arweave::data_root(bytes);
        let t = Table::with(&hex::encode(root), bytes);
        let got = fetch_and_verify(&t, &Target::Arweave(root.to_vec())).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Verified);
    }

    #[test]
    fn https_is_transport_only_and_says_why() {
        let url = "https://example.com/";
        let t = Table::with(url, b"<html></html>");
        let got = fetch_and_verify(&t, &Target::Https(url.to_string())).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::TransportOnly);
        assert!(got.evidence.badge().contains("TLS"));
    }

    #[test]
    fn the_ceiling_is_known_before_any_byte_arrives() {
        assert_eq!(
            Target::Https(String::from("https://x")).ceiling(),
            Strength::TransportOnly
        );
        assert_eq!(
            Target::Bud(ContentId::of(b"")).ceiling(),
            Strength::Verified
        );
    }

    #[test]
    fn oversized_content_is_refused_by_size_not_by_hash() {
        let big = vec![0u8; MAX_CONTENT_BYTES + 1];
        let id = ContentId::of(&big);
        let t = Table::with(&id.to_string(), &big);
        let err = fetch_and_verify(&t, &Target::Bud(id)).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }
}
