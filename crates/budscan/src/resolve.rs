//! From address bar to page: five steps meeting in one place.
//!
//! ```text
//! typed -> classification -> name rule -> resolution (+proof) -> fetch (+hash) -> badge
//! ```
//!
//! Each step adds its own evidence strength, and the **weakest link** decides
//! the badge. Doing that in one place is deliberate: if three layers have three
//! strengths and combining them is left to the caller, a call that forgets the
//! combination writes `verified`.

use crate::bns_proof::{self, BnsInclusionProof, ResolvedName};
use crate::content_id::ContentId;
use crate::ens::{self, ContentHash};
use crate::evidence::{Claim, Evidence, Strength};
use crate::fetch::{self, Fetched, Target, Transport};
use crate::name_rule;
use crate::query::{self, Query};

/// Whatever turns a name into a target.
pub trait NameResolver {
    /// A `.bud` name: resolution from the chain, with its proof when there is
    /// one.
    ///
    /// # Errors
    ///
    /// When the name is not found, or the chain cannot be reached. A
    /// **refusal** is not an error: a record that exists but cannot be verified
    /// is reported through `BnsInclusionProof::None`, not through `Err`.
    fn resolve_bud(&self, name: &str) -> Result<(ResolvedName, BnsInclusionProof), String>;
    /// The `bns_v1` value written into the state root for `.bud`, when known.
    fn bns_root(&self) -> Option<[u8; 32]>;
    /// An `.eth` name: the raw ENS `contenthash` bytes, and whether the MPT
    /// proof was verified.
    ///
    /// # Errors
    ///
    /// When the name is not found, or Ethereum state cannot be reached.
    fn resolve_eth(&self, name: &str) -> Result<(Vec<u8>, bool), String>;
}

/// The result of opening a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub input: String,
    pub target: Option<Target>,
    pub bytes: Option<Vec<u8>>,
    pub evidence: Evidence,
}

impl Page {
    /// May the page be handed to Gecko?
    #[must_use]
    pub fn is_renderable(&self) -> bool {
        self.bytes.is_some() && self.evidence.is_displayable()
    }

    /// The text shown in the address bar.
    ///
    /// Input that does not pass the name rule is shown as punycode. That what
    /// is displayed and what is resolved are the same string is this browser's
    /// rule.
    #[must_use]
    pub fn address_bar(&self) -> String {
        format!(
            "{}  [{}]",
            name_rule::display_form(&self.input),
            self.evidence.badge()
        )
    }
}

fn refusal(input: &str, layer: &str, reason: &str) -> Page {
    Page {
        input: input.to_string(),
        target: None,
        bytes: None,
        evidence: Evidence::new().with(Claim::new(layer, Strength::Refused, reason)),
    }
}

/// Open whatever was typed.
///
/// # Errors
///
/// Whatever the transport or resolution layer returns. A **refusal** is not an
/// error: refused input comes back as a `Page` with the reason in its badge,
/// because telling the user "it did not open" is not enough - they should be
/// told why.
pub fn open<R: NameResolver, T: Transport>(
    resolver: &R,
    transport: &T,
    raw: &str,
) -> Result<Page, String> {
    let (target, mut evidence) = match plan(resolver, raw)? {
        Plan::Fetch { target, evidence } => (target, evidence),
        Plan::Stop(page) => return Ok(*page),
    };

    let Fetched {
        bytes,
        evidence: fetch_evidence,
    } = fetch::fetch_and_verify(transport, &target)?;

    for claim in fetch_evidence.claims {
        evidence.push(claim);
    }

    let displayable = evidence.is_displayable();
    Ok(Page {
        input: raw.to_string(),
        target: Some(target),
        bytes: if displayable { Some(bytes) } else { None },
        evidence,
    })
}

/// The decision taken before fetching.
///
/// It is a type of its own because "fetch" and "stop" are two different
/// outcomes: an `Option<Target>` flattens them into one shape and carries no
/// reason for why the `None` is a `None`.
enum Plan {
    Fetch { target: Target, evidence: Evidence },
    Stop(Box<Page>),
}

impl Plan {
    fn stop(page: Page) -> Self {
        Self::Stop(Box::new(page))
    }
}

fn plan<R: NameResolver>(resolver: &R, raw: &str) -> Result<Plan, String> {
    Ok(match query::classify(raw) {
        Query::RefusedScheme { input, scheme } => Plan::stop(refusal(
            &input,
            "schema",
            &format!("the {scheme} scheme is not opened from the address bar"),
        )),
        Query::RefusedName { input, rejection } => {
            Plan::stop(refusal(&input, "name-rule", &rejection.to_string()))
        }
        Query::Ambiguous { input, candidates } => Plan::stop(refusal(
            &input,
            "classification",
            &format!(
                "ambiguous input is not guessed at; it could be any of: {}",
                candidates.join(", ")
            ),
        )),
        Query::FreeText(text) => Plan::stop(refusal(
            &text,
            "classification",
            "this is not an address; use the search layer to search",
        )),
        Query::Name { name, suffix } => match suffix.as_str() {
            "bud" => plan_bud(resolver, raw, &name)?,
            "eth" => plan_eth(resolver, raw, &name)?,
            other => Plan::stop(refusal(
                raw,
                "name-rule",
                &format!("there is no resolver for .{other}"),
            )),
        },
        Query::ContentId(bytes) => Plan::Fetch {
            target: Target::Bud(ContentId(bytes)),
            evidence: Evidence::new(),
        },
        Query::Cid(s) => Plan::Fetch {
            target: Target::Ipfs(s),
            evidence: Evidence::new(),
        },
        Query::HttpsUrl(url) => Plan::Fetch {
            target: Target::Https(url),
            evidence: Evidence::new(),
        },
        Query::BudAddress(_)
        | Query::EvmAddress(_)
        | Query::NftId(_)
        | Query::BlockHeight(_)
        | Query::TxHash(_) => Plan::stop(refusal(
            raw,
            "classification",
            "this is a record, not a page; the search layer displays it",
        )),
    })
}

/// `.bud`: the resolution is judged against its proof, then a content link is
/// looked for.
fn plan_bud<R: NameResolver>(resolver: &R, raw: &str, name: &str) -> Result<Plan, String> {
    let (record, proof) = resolver.resolve_bud(name)?;
    let evidence = bns_proof::evaluate(&record, &proof, resolver.bns_root());
    if !evidence.is_displayable() {
        return Ok(Plan::stop(Page {
            input: raw.to_string(),
            target: None,
            bytes: None,
            evidence,
        }));
    }
    let Some(id) = record.content_id.or(record.storage_root.map(ContentId)) else {
        return Ok(Plan::stop(refusal(
            raw,
            "bns-resolution",
            "the name is not bound to any content: neither content_id nor storage_root is present",
        )));
    };
    Ok(Plan::Fetch {
        target: Target::Bud(id),
        evidence,
    })
}

/// `.eth`: the contenthash is decoded, then the target is checked for a
/// fetcher.
fn plan_eth<R: NameResolver>(resolver: &R, raw: &str, name: &str) -> Result<Plan, String> {
    let (raw_ch, proof_verified) = resolver.resolve_eth(name)?;
    let ch = ens::decode_contenthash(&raw_ch)
        .map_err(|e| format!("ENS contenthash could not be decoded: {e}"))?;
    let evidence = Evidence::new().with(if proof_verified {
        Claim::new(
            "ens-resolution",
            Strength::Verified,
            "the MPT proof for the namehash slot verified, and the root is in \
             a known Ethereum header",
        )
    } else {
        Claim::new(
            "ens-resolution",
            Strength::RpcClaimOnly,
            "the MPT proof was not verified; the resolution is one node's claim",
        )
    });

    let stop_with = |claim: Claim| {
        Plan::stop(Page {
            input: raw.to_string(),
            target: None,
            bytes: None,
            evidence: evidence.clone().with(claim),
        })
    };

    Ok(match ch {
        ContentHash::Ipfs(body) => Plan::Fetch {
            target: Target::Ipfs(cid_string(&body)?),
            evidence,
        },
        ContentHash::Arweave(root) => Plan::Fetch {
            target: Target::Arweave(root),
            evidence,
        },
        ContentHash::Ipns(_) => stop_with(Claim::new(
            "ipns",
            Strength::Refused,
            "IPNS resolution needs a signature chain, and this version does not verify one",
        )),
        ContentHash::Swarm(_) | ContentHash::Onion3(_) => stop_with(Claim::new(
            "fetcher",
            Strength::Refused,
            "there is no fetcher for this protocol; falling back to HTTPS would \
             present unverified content as verified",
        )),
    })
}

/// Turn an ENS `ipfs-ns` body into a CID string.
///
/// The body is a binary CID. `crate::cid::parse_bytes` decodes it, and rather
/// than converting back to a string we say directly whether it is
/// verifiable.
fn cid_string(body: &[u8]) -> Result<String, String> {
    let cid = crate::cid::parse_bytes(body)?;
    // `Target::Ipfs` wants a string. base16, multibase 'f', is always
    // re-decodable and, unlike base32, needs no converter.
    //
    // The codec is **preserved**: turning a dag-pb CID into a raw one would
    // present an unverifiable target as a verifiable one. The `0x1220`
    // multihash prefix is written in both branches; forget it and the CID still
    // decodes, but the digest is read from the wrong place.
    let mut out = String::from("f");
    if cid.version == 0 {
        out.push_str("1220");
    } else {
        out.push_str("01");
        out.push_str(&hex::encode([u8::try_from(cid.codec).map_err(|_| {
            format!("codec {:#x} is not a single-byte varint", cid.codec)
        })?]));
        out.push_str("1220");
    }
    out.push_str(&hex::encode(cid.digest));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Resolver {
        bud: Option<(ResolvedName, BnsInclusionProof)>,
        root: Option<[u8; 32]>,
        eth: Option<(Vec<u8>, bool)>,
    }

    impl NameResolver for Resolver {
        fn resolve_bud(&self, _name: &str) -> Result<(ResolvedName, BnsInclusionProof), String> {
            self.bud.clone().ok_or_else(|| String::from("no such name"))
        }
        fn bns_root(&self) -> Option<[u8; 32]> {
            self.root
        }
        fn resolve_eth(&self, _name: &str) -> Result<(Vec<u8>, bool), String> {
            self.eth.clone().ok_or_else(|| String::from("no such name"))
        }
    }

    struct Table(HashMap<String, Vec<u8>>);

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
                .ok_or_else(|| format!("{key} not found"))
        }
    }

    fn table(pairs: &[(&str, &[u8])]) -> Table {
        Table(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_vec()))
                .collect(),
        )
    }

    fn bud_resolver(bytes: &[u8], proven: bool) -> Resolver {
        let id = ContentId::of(bytes);
        let resolved = ResolvedName {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            storage_root: None,
            content_id: Some(id),
            is_expired: false,
        };
        if proven {
            let entries = vec![bns_proof::RegistryEntry {
                name: String::from("ayaz.bud"),
                owner: [1u8; 32],
                expires_at: 100,
                content_id: Some(id),
            }];
            let root = bns_proof::partial_registry_root(100, &entries);
            Resolver {
                bud: Some((
                    resolved,
                    BnsInclusionProof::Registry {
                        base_cost: 100,
                        entries,
                    },
                )),
                root: Some(root),
                eth: None,
            }
        } else {
            Resolver {
                bud: Some((resolved, BnsInclusionProof::None)),
                root: None,
                eth: None,
            }
        }
    }

    #[test]
    fn a_proven_name_with_matching_bytes_renders_as_verified() {
        let bytes = b"<html>ayaz</html>";
        let r = bud_resolver(bytes, true);
        let t = table(&[(&ContentId::of(bytes).to_string(), bytes)]);
        let page = open(&r, &t, "ayaz.bud").unwrap();
        assert!(page.is_renderable());
        assert_eq!(page.evidence.weakest(), Strength::Verified);
        assert!(page.address_bar().starts_with("ayaz.bud"));
    }

    #[test]
    fn correct_bytes_under_an_unproven_resolution_are_not_verified() {
        // This is why the browser exists: the hash matches, but the binding
        // was not proven, so the page shown may not belong to the name asked
        // for.
        let bytes = b"<html>ayaz</html>";
        let r = bud_resolver(bytes, false);
        let t = table(&[(&ContentId::of(bytes).to_string(), bytes)]);
        let page = open(&r, &t, "ayaz.bud").unwrap();
        assert!(page.is_renderable());
        assert_eq!(page.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(page.address_bar().contains("claim only"));
    }

    #[test]
    fn bytes_that_do_not_hash_are_not_rendered_at_all() {
        let r = bud_resolver(b"expected", true);
        let t = table(&[(&ContentId::of(b"expected").to_string(), b"other")]);
        let page = open(&r, &t, "ayaz.bud").unwrap();
        assert!(!page.is_renderable());
        assert!(
            page.bytes.is_none(),
            "refused bytes must not reach the page"
        );
        assert_eq!(page.evidence.weakest(), Strength::Refused);
    }

    #[test]
    fn a_scheme_is_refused_before_anything_is_fetched() {
        let r = bud_resolver(b"x", true);
        let t = table(&[]);
        let page = open(&r, &t, "javascript:alert(1)").unwrap();
        assert!(!page.is_renderable());
        assert!(page.evidence.badge().contains("javascript"));
    }

    #[test]
    fn a_mixed_script_name_is_shown_as_punycode_in_the_bar() {
        let r = bud_resolver(b"x", true);
        let t = table(&[]);
        let page = open(&r, &t, "\u{0430}yaz.bud").unwrap();
        assert!(!page.is_renderable());
        assert!(
            page.address_bar().starts_with("xn--yaz-5cd.bud"),
            "{}",
            page.address_bar()
        );
    }

    #[test]
    fn an_eth_name_pointing_at_ipfs_is_only_as_strong_as_its_proof() {
        // contenthash: ipfs-ns + CIDv1 raw sha2-256("hello")
        let digest = {
            use sha2::Digest;
            let d: [u8; 32] = sha2::Sha256::digest(b"hello").into();
            d
        };
        let mut body = vec![0x01, 0x55, 0x12, 0x20];
        body.extend_from_slice(&digest);
        // `ipfs-ns` is 0xe3, and multicodec codes are varints: 0xe3 on its own
        // carries the continuation bit, so it is written `0xe3 0x01`. That is
        // not a formatting detail but the difference that splits the code in
        // two: write a single byte and the decoder folds the next byte's low
        // seven bits into the code, reading a different protocol.
        let mut ch = vec![0xe3, 0x01];
        ch.extend_from_slice(&body);

        let key = format!("f01551220{}", hex::encode(digest));
        let t = table(&[(&key, b"hello")]);

        let unproven = Resolver {
            bud: None,
            root: None,
            eth: Some((ch.clone(), false)),
        };
        let page = open(&unproven, &t, "x1.eth").unwrap();
        assert_eq!(page.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(page.is_renderable());

        let proven = Resolver {
            bud: None,
            root: None,
            eth: Some((ch, true)),
        };
        let page = open(&proven, &t, "x1.eth").unwrap();
        assert_eq!(page.evidence.weakest(), Strength::Verified);
    }

    #[test]
    fn an_eth_name_pointing_at_swarm_is_refused_not_downgraded_to_https() {
        // `swarm-ns` is 0xe4, written `0xe4 0x01` as a varint.
        let mut ch = vec![0xe4, 0x01];
        ch.extend_from_slice(&[0x11; 32]);
        let r = Resolver {
            bud: None,
            root: None,
            eth: Some((ch, true)),
        };
        let page = open(&r, &table(&[]), "x1.eth").unwrap();
        assert!(!page.is_renderable());
        assert!(page.evidence.badge().contains("no fetcher"));
    }

    #[test]
    fn an_https_url_renders_but_is_labelled_transport_only() {
        let url = "https://example.com/";
        let t = table(&[(url, b"<html></html>")]);
        let r = Resolver {
            bud: None,
            root: None,
            eth: None,
        };
        let page = open(&r, &t, url).unwrap();
        assert!(page.is_renderable());
        assert_eq!(page.evidence.weakest(), Strength::TransportOnly);
    }

    #[test]
    fn an_expired_name_never_reaches_the_fetcher() {
        let resolved = ResolvedName {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            storage_root: None,
            content_id: Some(ContentId([3u8; 32])),
            is_expired: true,
        };
        let r = Resolver {
            bud: Some((resolved, BnsInclusionProof::None)),
            root: None,
            eth: None,
        };
        // The transport is empty: had the fetcher been reached, it would have
        // returned an error.
        let page = open(&r, &table(&[]), "ayaz.bud").unwrap();
        assert!(!page.is_renderable());
        assert!(page.evidence.badge().contains("has expired"));
    }
}
