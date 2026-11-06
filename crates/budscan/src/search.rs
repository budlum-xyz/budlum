//! Search: every result arrives with its own evidence strength.
//!
//! The choice made here is "the proven path is the default, RPC is the
//! fallback": when a verified proof stands behind a result it reads `verified`,
//! and otherwise it is labelled **claim only**. Nothing is quietly counted as
//! trusted.
//!
//! # Why a trait, and not a client
//!
//! [`ChainView`] is a read interface. In production it binds to the RPC methods
//! that already exist - `bud_getBalance`, `bud_bnsResolveFull`,
//! `bud_socialGetPost`, `bud_atlasGetWalletContext`, see `src/rpc/api.rs` - and
//! in tests it is an in-memory table. Keeping the search logic off a socket is
//! what makes the evidence label testable.
//!
//! # How it relates to Atlas
//!
//! `src/gateway/atlas.rs` already carries an evidence-card model
//! (`AtlasEvidenceStatus`: `Verified`, `Derived`, `PendingProof`,
//! `Unverified`) and says it "does not label raw, unproven UI data as
//! verified". Budscan draws the same distinction but uses four **different**
//! values ([`crate::evidence::Strength`]), because the browser asks a different
//! question: Atlas asks "where did this card come from", the browser asks
//! "should I show these bytes". Squeezing the two into one enum would mean
//! answering one question with the other's answer.

use crate::content_id::ContentId;
use crate::evidence::{Claim, Evidence, Strength};
use crate::query::Query;

/// A wallet's state, in summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub address: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    /// Whether this read arrived with a state proof.
    pub proven: bool,
}

/// An NFT in summary; the same fields as `src/socialfi/types.rs::Nft`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftView {
    pub id: u64,
    pub owner: [u8; 32],
    pub content_id: ContentId,
    pub minted_at_epoch: u64,
    pub author_name: Option<String>,
    pub luminance: u64,
    pub tags: Vec<String>,
    pub proven: bool,
}

/// What can be read from the chain.
///
/// Every method returns an `Option`: not being found is an answer, not an
/// error.
pub trait ChainView {
    fn account(&self, address: &[u8; 32]) -> Option<AccountView>;
    fn nft(&self, id: u64) -> Option<NftView>;
    /// The content identity bound to a name.
    fn name_content(&self, name: &str) -> Option<ContentId>;
    /// NFTs under a tag. The result order is the chain's order; the browser
    /// does not re-sort, because ordering is an editorial decision and not one
    /// a browser gets to take.
    fn nfts_by_tag(&self, tag: &str) -> Vec<NftView>;
}

/// A single search result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hit {
    Account(Box<AccountView>),
    Nft(Box<NftView>),
    Name {
        name: String,
        content_id: Option<ContentId>,
    },
    /// A target was found, but opening it is a separate step.
    Openable {
        input: String,
        note: String,
    },
    /// The input did not settle into a class, and that is not an error.
    Nothing {
        input: String,
        note: String,
    },
}

/// The search answer: the result **and** how far it was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    pub hit: Hit,
    pub evidence: Evidence,
}

fn proven_claim(layer: &str, proven: bool, what: &str) -> Claim {
    if proven {
        Claim::new(
            layer,
            Strength::Verified,
            &format!(
                "{what} arrived with a state proof, and the proof is bound to a finalised root"
            ),
        )
    } else {
        Claim::new(
            layer,
            Strength::RpcClaimOnly,
            &format!("{what} arrived without a proof; this is one node's claim"),
        )
    }
}

/// Run one query.
///
/// No network, no resolution: [`ChainView`] is asked, and the answer is
/// labelled. Name resolution and content fetching are separate steps, in
/// [`crate::resolve`].
pub fn run<V: ChainView>(view: &V, query: &Query) -> SearchResult {
    match query {
        Query::BudAddress(address) | Query::ContentId(address) => account_hit(view, address),
        Query::EvmAddress(address) => evm_hit(address),
        Query::NftId(id) => nft_hit(view, *id),
        Query::Name { name, suffix } => name_hit(view, name, suffix),
        Query::Cid(s) => openable(
            s.clone(),
            "IPFS CID: once the bytes are fetched the digest is compared, and only then is it verified",
            Claim::new("ipfs", Strength::RpcClaimOnly, "no bytes have been fetched yet"),
        ),
        Query::HttpsUrl(url) => openable(
            url.clone(),
            "the ordinary web: content is not verified, only the transport is protected",
            Claim::new(
                "https",
                Strength::TransportOnly,
                "TLS says who sent it, not what was sent",
            ),
        ),
        Query::BlockHeight(h) => openable(
            format!("block:{h}"),
            "a block view; header finality is shown separately",
            Claim::new(
                "chain",
                Strength::RpcClaimOnly,
                "header finality is not verified in the browser",
            ),
        ),
        Query::TxHash(h) => openable(
            format!("tx:0x{}", hex::encode(h)),
            "a transaction view",
            Claim::new(
                "chain",
                Strength::RpcClaimOnly,
                "the transaction receipt did not arrive with a proof",
            ),
        ),
        Query::FreeText(text) => free_text_hit(view, text),
        Query::Ambiguous { input, candidates } => nothing(
            input.clone(),
            format!(
                "ambiguous; it could be any of: {}",
                candidates.join(", ")
            ),
            Claim::new(
                "classification",
                Strength::Refused,
                "ambiguous input is not guessed at",
            ),
        ),
        Query::RefusedScheme { input, scheme } => nothing(
            input.clone(),
            format!("{scheme}: nothing is opened under this scheme"),
            Claim::new(
                "schema",
                Strength::Refused,
                &format!("the {scheme} scheme is not opened from the address bar"),
            ),
        ),
        Query::RefusedName { input, rejection } => nothing(
            input.clone(),
            rejection.to_string(),
            Claim::new("name-rule", Strength::Refused, &rejection.to_string()),
        ),
    }
}

fn openable(input: String, note: &str, claim: Claim) -> SearchResult {
    SearchResult {
        hit: Hit::Openable {
            input,
            note: note.to_string(),
        },
        evidence: Evidence::new().with(claim),
    }
}

fn nothing(input: String, note: String, claim: Claim) -> SearchResult {
    SearchResult {
        hit: Hit::Nothing { input, note },
        evidence: Evidence::new().with(claim),
    }
}

fn account_hit<V: ChainView>(view: &V, address: &[u8; 32]) -> SearchResult {
    if let Some(account) = view.account(address) {
        let evidence = Evidence::new().with(proven_claim(
            "account",
            account.proven,
            "the balance and nonce",
        ));
        return SearchResult {
            hit: Hit::Account(Box::new(account)),
            evidence,
        };
    }
    nothing(
        hex::encode(address),
        String::from(
            "there is no account record for this address; an address that has seen \
             no transaction is a valid address too",
        ),
        Claim::new(
            "account",
            Strength::RpcClaimOnly,
            "no proof of absence was offered, so 'not there' cannot be told apart \
             from 'I do not know'",
        ),
    )
}

fn evm_hit(address: &[u8; 20]) -> SearchResult {
    nothing(
        format!("0x{}", hex::encode(address)),
        String::from(
            "an EVM address is not looked up in the Budlum account ledger. Its state \
             on Ethereum needs a bridge query, and the browser does not present that \
             as verified",
        ),
        Claim::new(
            "evm",
            Strength::RpcClaimOnly,
            "Ethereum state is not verified in this browser",
        ),
    )
}

fn nft_hit<V: ChainView>(view: &V, id: u64) -> SearchResult {
    if let Some(nft) = view.nft(id) {
        let evidence = Evidence::new()
            .with(proven_claim("nft", nft.proven, "the NFT record"))
            .with(Claim::new(
                "nft-content",
                Strength::RpcClaimOnly,
                "the NFT's content_id is a pointer; until the bytes are fetched and \
                 hashed the content is not verified",
            ));
        return SearchResult {
            hit: Hit::Nft(Box::new(nft)),
            evidence,
        };
    }
    nothing(
        format!("nft:{id}"),
        String::from("there is no NFT under this identity"),
        Claim::new(
            "nft",
            Strength::RpcClaimOnly,
            "no proof of absence was offered",
        ),
    )
}

fn name_hit<V: ChainView>(view: &V, name: &str, suffix: &str) -> SearchResult {
    let content_id = if suffix == "bud" {
        view.name_content(name)
    } else {
        None
    };
    let claim = if suffix == "bud" {
        Claim::new(
            "bns-resolution",
            Strength::RpcClaimOnly,
            "the resolution carries no proof; BnsRegistry::root() does not produce \
             per-name proofs today",
        )
    } else {
        Claim::new(
            "ens-resolution",
            Strength::RpcClaimOnly,
            "ENS resolution needs an MPT proof and this search layer does not verify \
             one; it is verified before opening",
        )
    };
    SearchResult {
        hit: Hit::Name {
            name: name.to_string(),
            content_id,
        },
        evidence: Evidence::new().with(claim),
    }
}

fn free_text_hit<V: ChainView>(view: &V, text: &str) -> SearchResult {
    if let Some(tag) = text.strip_prefix('#') {
        let hits = view.nfts_by_tag(tag);
        return openable(
            text.to_string(),
            &format!("{} NFT(s) under the tag #{tag}", hits.len()),
            Claim::new(
                "tag-search",
                Strength::RpcClaimOnly,
                "a tag index is an ordering produced by a node; it is not proven",
            ),
        );
    }
    nothing(
        text.to_string(),
        String::from(
            "this does not look like an address, a name, an NFT or a CID. Prefix it \
             with # to search tags",
        ),
        Claim::new(
            "classification",
            Strength::RpcClaimOnly,
            "the input did not settle into a class",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query;

    #[derive(Default)]
    struct Fake {
        account: Option<AccountView>,
        nft: Option<NftView>,
        content: Option<ContentId>,
    }

    impl ChainView for Fake {
        fn account(&self, _address: &[u8; 32]) -> Option<AccountView> {
            self.account.clone()
        }
        fn nft(&self, _id: u64) -> Option<NftView> {
            self.nft.clone()
        }
        fn name_content(&self, _name: &str) -> Option<ContentId> {
            self.content
        }
        fn nfts_by_tag(&self, _tag: &str) -> Vec<NftView> {
            self.nft.clone().into_iter().collect()
        }
    }

    fn nft(proven: bool) -> NftView {
        NftView {
            id: 12,
            owner: [1u8; 32],
            content_id: ContentId([2u8; 32]),
            minted_at_epoch: 4,
            author_name: Some(String::from("ayaz.bud")),
            luminance: 1000,
            tags: vec![String::from("education")],
            proven,
        }
    }

    #[test]
    fn a_proven_account_is_verified_and_an_unproven_one_is_not() {
        let proven = Fake {
            account: Some(AccountView {
                address: [1u8; 32],
                balance: 5,
                nonce: 1,
                proven: true,
            }),
            ..Fake::default()
        };
        let q = Query::BudAddress([1u8; 32]);
        assert_eq!(run(&proven, &q).evidence.weakest(), Strength::Verified);

        let unproven = Fake {
            account: Some(AccountView {
                address: [1u8; 32],
                balance: 5,
                nonce: 1,
                proven: false,
            }),
            ..Fake::default()
        };
        assert_eq!(
            run(&unproven, &q).evidence.weakest(),
            Strength::RpcClaimOnly
        );
    }

    #[test]
    fn an_nft_record_can_be_proven_but_its_content_is_not_yet() {
        let view = Fake {
            nft: Some(nft(true)),
            ..Fake::default()
        };
        let r = run(&view, &Query::NftId(12));
        // Even with a proven record the content has not been fetched yet: the
        // weakest link wins and the badge does not say `verified`.
        assert_eq!(r.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(r.evidence.badge().contains("until the bytes are fetched"));
    }

    #[test]
    fn a_missing_account_says_absence_was_not_proven() {
        let r = run(&Fake::default(), &Query::BudAddress([9u8; 32]));
        assert!(matches!(r.hit, Hit::Nothing { .. }));
        assert!(r.evidence.badge().contains("proof of absence"));
    }

    #[test]
    fn https_is_openable_but_transport_only() {
        let r = run(
            &Fake::default(),
            &Query::HttpsUrl(String::from("https://x.example/")),
        );
        assert_eq!(r.evidence.weakest(), Strength::TransportOnly);
    }

    #[test]
    fn a_refused_scheme_stays_refused_through_search() {
        let q = query::classify("javascript:alert(1)");
        let r = run(&Fake::default(), &q);
        assert_eq!(r.evidence.weakest(), Strength::Refused);
    }

    #[test]
    fn an_ambiguous_input_is_refused_with_its_candidates() {
        let q = query::classify("12");
        let r = run(&Fake::default(), &q);
        assert_eq!(r.evidence.weakest(), Strength::Refused);
        match r.hit {
            Hit::Nothing { note, .. } => assert!(note.contains("ambiguous"), "{note}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_tag_search_is_labelled_as_an_index_not_a_proof() {
        let view = Fake {
            nft: Some(nft(true)),
            ..Fake::default()
        };
        let r = run(&view, &query::classify("#education"));
        assert_eq!(r.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(r.evidence.badge().contains("it is not proven"));
    }

    #[test]
    fn a_bud_name_search_returns_its_content_binding() {
        let view = Fake {
            content: Some(ContentId([7u8; 32])),
            ..Fake::default()
        };
        let r = run(&view, &query::classify("ayaz.bud"));
        match r.hit {
            Hit::Name { content_id, .. } => assert_eq!(content_id, Some(ContentId([7u8; 32]))),
            other => panic!("{other:?}"),
        }
        assert_eq!(r.evidence.weakest(), Strength::RpcClaimOnly);
    }
}
