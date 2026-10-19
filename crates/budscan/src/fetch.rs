//! The fetcher layer: four targets, four different verification strengths.
//!
//! Each fetcher **declares its own verification strength**, and the address bar
//! shows exactly that.
//!
//! | target           | fetched over | verification             | in the bar      |
//! |------------------|--------------|--------------------------|-----------------|
//! | Budlum manifest  | B.U.D.       | manifest hashes to the id, shards to the manifest | verified |
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
use crate::content_id::{hash_fields_bytes, ContentId};
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

    /// Fetch the manifest a `bud://` manifest id names.
    ///
    /// A manifest id is the hash of the manifest preimage, not the hash of the
    /// content, so the bytes alone can never be compared with it. Without the
    /// manifest the fetcher cannot verify, so the default refuses.
    ///
    /// # Errors
    ///
    /// A network error, a manifest that is not found, or a transport that
    /// cannot serve manifests (the default).
    fn fetch_bud_manifest(&self, _manifest_id: &ContentId) -> Result<BudManifest, String> {
        Err(String::from(
            "this transport cannot serve B.U.D. manifests, so a bud:// target cannot be verified",
        ))
    }
}

/// One shard entry of a [`BudManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudShard {
    pub index: u32,
    pub shard_id: ContentId,
    pub size: u32,
    /// Parity shards carry redundancy, not content.
    pub parity: bool,
}

/// The fields of a B.U.D. manifest that its id commits to
/// (`BDLM_MANIFEST_V4`, the same preimage as `budlum-core`'s
/// `manifest_id_from_parts`).
///
/// The source, edition and dictionary commitments are carried as the exact
/// bytes the chain writes into the preimage, so a manifest with a source regime
/// verifies without this crate knowing the regime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudManifest {
    pub shards: Vec<BudShard>,
    pub erasure_k: u32,
    pub erasure_n: u32,
    pub encryption_tag: u8,
    pub content_size: u64,
    pub total_size: u64,
    pub source_commitment: Vec<u8>,
    pub edition_commitment: Vec<u8>,
    pub dictionary_id: Option<ContentId>,
}

impl BudManifest {
    /// A manifest of plain stored content: one data shard, classic edition,
    /// no encryption, no dictionary. This is what a small unsharded upload
    /// registers.
    #[must_use]
    pub fn single_shard(bytes: &[u8]) -> Self {
        let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        Self {
            shards: vec![BudShard {
                index: 0,
                shard_id: ContentId::of(bytes),
                size,
                parity: false,
            }],
            erasure_k: 1,
            erasure_n: 1,
            encryption_tag: 0,
            content_size: bytes.len() as u64,
            total_size: bytes.len() as u64,
            source_commitment: Vec::new(),
            edition_commitment: Vec::new(),
            dictionary_id: None,
        }
    }

    /// The manifest id, recomputed from the fields.
    #[must_use]
    pub fn manifest_id(&self) -> ContentId {
        let mut buf = Vec::with_capacity(32 + self.shards.len() * 41);
        buf.extend_from_slice(b"BDLM_MANIFEST_V4");
        let count = u32::try_from(self.shards.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&count.to_le_bytes());
        for s in &self.shards {
            buf.extend_from_slice(&s.index.to_le_bytes());
            buf.extend_from_slice(&s.shard_id.0);
            buf.extend_from_slice(&s.size.to_le_bytes());
            buf.push(u8::from(s.parity));
        }
        buf.extend_from_slice(&self.erasure_k.to_le_bytes());
        buf.extend_from_slice(&self.erasure_n.to_le_bytes());
        buf.push(self.encryption_tag);
        buf.extend_from_slice(&self.content_size.to_le_bytes());
        buf.extend_from_slice(&self.total_size.to_le_bytes());
        buf.extend_from_slice(&self.source_commitment);
        buf.extend_from_slice(&self.edition_commitment);
        if let Some(dict) = &self.dictionary_id {
            buf.push(1u8);
            buf.extend_from_slice(&dict.0);
        }
        ContentId(hash_fields_bytes(&[b"BDLM_MANIFEST_V4", &buf]))
    }

    /// Whether `bytes` are the object this manifest describes: the data shards
    /// in index order cut `bytes` (the last one zero padded) and every cut has
    /// the shard's `ContentId`, and the object is exactly `content_size` long.
    #[must_use]
    pub fn describes(&self, bytes: &[u8]) -> bool {
        if bytes.len() as u64 != self.content_size {
            return false;
        }
        let mut data: Vec<&BudShard> = self.shards.iter().filter(|s| !s.parity).collect();
        data.sort_by_key(|s| s.index);
        let mut off = 0usize;
        for shard in data {
            let len = shard.size as usize;
            let Some(end) = off.checked_add(len) else {
                return false;
            };
            let id = if end <= bytes.len() {
                ContentId::of(&bytes[off..end])
            } else {
                // Only the final stripe may run past the object, and only with
                // zero padding.
                let mut padded = bytes.get(off..).unwrap_or_default().to_vec();
                padded.resize(len, 0);
                ContentId::of(&padded)
            };
            if id != shard.shard_id {
                return false;
            }
            off = end;
        }
        off >= bytes.len()
    }
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
            // A manifest id names the manifest, not the bytes: the manifest has
            // to hash to the id, and the bytes have to be what the manifest
            // describes. Either step failing is a refusal; a transport that
            // cannot serve the manifest is an error, never "verified".
            let manifest = transport.fetch_bud_manifest(manifest_id)?;
            let recomputed = manifest.manifest_id();
            if recomputed != *manifest_id {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Refused,
                    &format!(
                        "the manifest hashes to {recomputed} but the manifest_id is {manifest_id}"
                    ),
                ))
            } else if manifest.describes(&bytes) {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Verified,
                    "the manifest hashes to the manifest_id and its shards hash to the bytes",
                ))
            } else {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Refused,
                    &format!(
                        "the bytes are not the object manifest {manifest_id} describes (ContentId of the bytes is {})",
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

    struct Table {
        bytes: HashMap<String, Vec<u8>>,
        manifests: HashMap<String, BudManifest>,
    }

    impl Table {
        fn with(key: &str, bytes: &[u8]) -> Self {
            let mut m = HashMap::new();
            m.insert(key.to_string(), bytes.to_vec());
            Table {
                bytes: m,
                manifests: HashMap::new(),
            }
        }

        /// A Budlum object: `served` arrives under the id of `manifest`.
        fn bud(manifest: &BudManifest, served: &[u8]) -> Self {
            let key = manifest.manifest_id().to_string();
            let mut t = Table::with(&key, served);
            t.manifests.insert(key, manifest.clone());
            t
        }
    }

    impl Transport for Table {
        fn fetch(&self, target: &Target) -> Result<Vec<u8>, String> {
            let key = match target {
                Target::Bud(id) => id.to_string(),
                Target::Ipfs(s) | Target::Https(s) => s.clone(),
                Target::Arweave(r) => hex::encode(r),
            };
            self.bytes
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("{key} bulunamadi"))
        }

        fn fetch_bud_manifest(&self, id: &ContentId) -> Result<BudManifest, String> {
            self.manifests
                .get(&id.to_string())
                .cloned()
                .ok_or_else(|| format!("manifest {id} not found"))
        }
    }

    #[test]
    fn bud_content_that_hashes_correctly_is_verified() {
        let bytes = b"<html>ayaz</html>";
        let manifest = BudManifest::single_shard(bytes);
        let id = manifest.manifest_id();
        let t = Table::bud(&manifest, bytes);
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Verified);
        assert!(got.is_displayable());
    }

    #[test]
    fn bud_content_that_does_not_hash_is_refused_and_not_displayed() {
        let manifest = BudManifest::single_shard(b"beklenen");
        let id = manifest.manifest_id();
        let t = Table::bud(&manifest, b"something else arrived");
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Refused);
        assert!(!got.is_displayable());
        // The reason must carry the manifest identity, or the user cannot tell
        // what happened.
        assert!(got.evidence.badge().contains(&id.to_string()));
    }

    /// P43-F01: a manifest id is not the `ContentId` of the bytes. Bytes whose
    /// `ContentId` equals the id (the old, wrong comparison) are refused when no
    /// manifest backs them.
    #[test]
    fn the_content_id_of_the_bytes_is_not_a_manifest_id() {
        let bytes = b"<html>ayaz</html>";
        let wrong_id = ContentId::of(bytes);
        let t = Table::with(&wrong_id.to_string(), bytes);
        // No manifest is served: the fetch fails closed.
        assert!(fetch_and_verify(&t, &Target::Bud(wrong_id)).is_err());
        // A manifest served under that id does not hash to it: refused.
        let mut t = t;
        t.manifests
            .insert(wrong_id.to_string(), BudManifest::single_shard(bytes));
        let got = fetch_and_verify(&t, &Target::Bud(wrong_id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Refused);
        assert!(!got.is_displayable());
    }

    /// The preimage is the chain's `manifest_id_from_parts`: this vector is
    /// pinned on both sides (`src/storage/manifest.rs`, same bytes).
    #[test]
    fn the_single_shard_manifest_id_matches_the_chain_vector() {
        assert_eq!(
            BudManifest::single_shard(b"hello")
                .manifest_id()
                .to_string(),
            "eb4912748b11896901a5ab57022cb8e117554dfb67233933fd3ea2e9fc076ca1"
        );
    }

    /// A sharded object with a zero padded final stripe verifies; a flipped
    /// byte in any shard does not.
    #[test]
    fn a_sharded_object_is_verified_shard_by_shard() {
        let bytes: Vec<u8> = (0u8..10).collect();
        let shard_a = ContentId::of(&bytes[0..4]);
        let shard_b = ContentId::of(&bytes[4..8]);
        let mut tail = bytes[8..10].to_vec();
        tail.resize(4, 0);
        let shard_c = ContentId::of(&tail);
        let manifest = BudManifest {
            shards: vec![
                BudShard {
                    index: 0,
                    shard_id: shard_a,
                    size: 4,
                    parity: false,
                },
                BudShard {
                    index: 1,
                    shard_id: shard_b,
                    size: 4,
                    parity: false,
                },
                BudShard {
                    index: 2,
                    shard_id: shard_c,
                    size: 4,
                    parity: false,
                },
            ],
            erasure_k: 3,
            erasure_n: 3,
            encryption_tag: 0,
            content_size: 10,
            total_size: 12,
            source_commitment: Vec::new(),
            edition_commitment: Vec::new(),
            dictionary_id: None,
        };
        let id = manifest.manifest_id();
        let ok = Table::bud(&manifest, &bytes);
        assert_eq!(
            fetch_and_verify(&ok, &Target::Bud(id))
                .unwrap()
                .evidence
                .weakest(),
            Strength::Verified
        );
        let mut bad = bytes.clone();
        bad[9] ^= 1;
        let t = Table::bud(&manifest, &bad);
        assert_eq!(
            fetch_and_verify(&t, &Target::Bud(id))
                .unwrap()
                .evidence
                .weakest(),
            Strength::Refused
        );
    }

    /// The manifest id commits to every field: a manifest edited after the
    /// fact no longer hashes to the id the target names.
    #[test]
    fn a_tampered_manifest_does_not_hash_to_its_id() {
        let bytes = b"<html>ayaz</html>";
        let honest = BudManifest::single_shard(bytes);
        let id = honest.manifest_id();
        let mut forged = honest.clone();
        forged.encryption_tag = 3;
        let mut t = Table::with(&id.to_string(), bytes);
        t.manifests.insert(id.to_string(), forged);
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Refused);
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
        let manifest = BudManifest::single_shard(&big);
        let id = manifest.manifest_id();
        let t = Table::bud(&manifest, &big);
        let err = fetch_and_verify(&t, &Target::Bud(id)).unwrap_err();
        assert!(err.contains("limit"), "{err}");
    }
}
