//! Arama: her sonuc kendi kanit gucuyle gelir.
//!
//! Kullanici secimi "kanitli yol varsayilan, RPC yedek": bir sonucun arkasinda
//! dogrulanmis bir kanit varsa `dogrulandi` yazar; yoksa **yaln1z beyan**
//! olarak etiketlenir. Hicbir sey sessizce guvenilir sayilmaz.
//!
//! # Neden bir trait, neden bir istemci degil
//!
//! [`ChainView`] bir okuma arayuzu. Uretimde `bud_getBalance`,
//! `bud_bnsResolveFull`, `bud_socialGetPost`, `bud_atlasGetWalletContext` gibi
//! mevcut RPC metotlarina baglanir (bkz. `src/rpc/api.rs`); testte bellekteki
//! bir tablodur. Arama mantiginin bir sokete baglanmamasi, kanit etiketinin
//! test edilebilir olmasini sagliyor.
//!
//! # Atlas ile iliskisi
//!
//! `src/gateway/atlas.rs` zaten bir kanit karti modeli tasiyor
//! (`AtlasEvidenceStatus`: `Verified` / `Derived` / `PendingProof` /
//! `Unverified`) ve "ham, kanitsiz UI verisini dogrulanmis diye etiketlemez"
//! diyor. Budscan ayni ayrimi tasiyor ama dort degil dort **farkli** deger
//! kullaniyor ([`crate::evidence::Strength`]), cunku tarayicinin sordugu soru
//! farkli: Atlas "bu kart nereden turedi" diye soruyor, tarayici "bu baytlari
//! gostermeli miyim" diye soruyor. Ikisini tek enum'a sikistirmak, birinin
//! cevabini digerinin sorusuna vermek olurdu.

use crate::content_id::ContentId;
use crate::evidence::{Claim, Evidence, Strength};
use crate::query::Query;

/// Bir cuzdanin ozet durumu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    pub address: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    /// Bu okumanin bir durum kanitiyla gelip gelmedigi.
    pub proven: bool,
}

/// Bir NFT'nin ozeti. `src/socialfi/types.rs::Nft` ile ayni alanlar.
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

/// Zincirden okunabilecekler.
///
/// Her metot `Option` doner: bulunamamak bir hata degil, bir cevaptir.
pub trait ChainView {
    fn account(&self, address: &[u8; 32]) -> Option<AccountView>;
    fn nft(&self, id: u64) -> Option<NftView>;
    /// Bir ada bagli icerik kimligi.
    fn name_content(&self, name: &str) -> Option<ContentId>;
    /// Bir etikete gore NFT'ler. Sonuc sirasi zincirin sirasidir; tarayici
    /// yeniden siralamaz, cunku siralama bir editoryal karardir ve bir
    /// tarayicinin alacagi karar degildir.
    fn nfts_by_tag(&self, tag: &str) -> Vec<NftView>;
}

/// Bir arama sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hit {
    Account(Box<AccountView>),
    Nft(Box<NftView>),
    Name {
        name: String,
        content_id: Option<ContentId>,
    },
    /// Bir hedef bulundu ama acilmasi ayri bir adim.
    Openable {
        input: String,
        note: String,
    },
    /// Girdi bir sinifa oturmadi ve bu bir hata degil.
    Nothing {
        input: String,
        note: String,
    },
}

/// Arama cevabi: sonuc **ve** ne kadar dogrulandigi.
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
            &format!("{what} bir durum kanitiyla geldi ve kanit kesinlesmis bir koke bagli"),
        )
    } else {
        Claim::new(
            layer,
            Strength::RpcClaimOnly,
            &format!("{what} kanitsiz geldi; bu bir dugumun beyani"),
        )
    }
}

/// Bir sorguyu calistir.
///
/// Ag yok, cozum yok: yalniz [`ChainView`]'a sorulur ve cevap etiketlenir.
/// Ad cozumu ve icerik getirme ayri adimlardir ([`crate::resolve`]).
pub fn run<V: ChainView>(view: &V, query: &Query) -> SearchResult {
    match query {
        Query::BudAddress(address) | Query::ContentId(address) => account_hit(view, address),
        Query::EvmAddress(address) => evm_hit(address),
        Query::NftId(id) => nft_hit(view, *id),
        Query::Name { name, suffix } => name_hit(view, name, suffix),
        Query::Cid(s) => openable(
            s.clone(),
            "IPFS CID: baytlar getirildiginde ozet karsilastirilir ve o zaman dogrulanir",
            Claim::new("ipfs", Strength::RpcClaimOnly, "henuz bayt getirilmedi"),
        ),
        Query::HttpsUrl(url) => openable(
            url.clone(),
            "siradan web: icerik dogrulanmaz, yalniz tasima korunur",
            Claim::new(
                "https",
                Strength::TransportOnly,
                "TLS kimin gonderdigini soyluyor, neyin gonderildigini degil",
            ),
        ),
        Query::BlockHeight(h) => openable(
            format!("blok:{h}"),
            "blok goruntusu; basligin kesinligi ayrica gosterilir",
            Claim::new(
                "zincir",
                Strength::RpcClaimOnly,
                "baslik kesinligi tarayicida dogrulanmiyor",
            ),
        ),
        Query::TxHash(h) => openable(
            format!("tx:0x{}", hex::encode(h)),
            "islem goruntusu",
            Claim::new(
                "zincir",
                Strength::RpcClaimOnly,
                "islem makbuzu bir kanitla gelmedi",
            ),
        ),
        Query::FreeText(text) => free_text_hit(view, text),
        Query::Ambiguous { input, candidates } => nothing(
            input.clone(),
            format!(
                "belirsiz; sunlardan biri olabilir: {}",
                candidates.join(", ")
            ),
            Claim::new(
                "siniflandirma",
                Strength::Refused,
                "belirsiz bir girdi tahmin edilmez",
            ),
        ),
        Query::RefusedScheme { input, scheme } => nothing(
            input.clone(),
            format!("{scheme}: bu semada bir sey acilmaz"),
            Claim::new(
                "sema",
                Strength::Refused,
                &format!("{scheme} semasi adres cubugundan acilmaz"),
            ),
        ),
        Query::RefusedName { input, rejection } => nothing(
            input.clone(),
            rejection.to_string(),
            Claim::new("ad-kurali", Strength::Refused, &rejection.to_string()),
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
        let evidence = Evidence::new().with(proven_claim("hesap", account.proven, "bakiye/nonce"));
        return SearchResult {
            hit: Hit::Account(Box::new(account)),
            evidence,
        };
    }
    nothing(
        hex::encode(address),
        String::from(
            "bu adres icin bir hesap kaydi yok; hicbir islem gormemis bir adres de \
             gecerli bir adrestir",
        ),
        Claim::new(
            "hesap",
            Strength::RpcClaimOnly,
            "yokluk kaniti sunulmadi; 'yok' ile 'bilmiyorum' ayirt edilemiyor",
        ),
    )
}

fn evm_hit(address: &[u8; 20]) -> SearchResult {
    nothing(
        format!("0x{}", hex::encode(address)),
        String::from(
            "EVM adresi: Budlum hesap defterinde aranmaz. Bu adresin Ethereum'daki \
             durumu icin bir kopru sorgusu gerekir ve tarayici bunu dogrulanmis diye \
             gostermez",
        ),
        Claim::new(
            "evm",
            Strength::RpcClaimOnly,
            "Ethereum durumu bu tarayicida dogrulanmiyor",
        ),
    )
}

fn nft_hit<V: ChainView>(view: &V, id: u64) -> SearchResult {
    if let Some(nft) = view.nft(id) {
        let evidence = Evidence::new()
            .with(proven_claim("nft", nft.proven, "NFT kaydi"))
            .with(Claim::new(
                "nft-icerik",
                Strength::RpcClaimOnly,
                "NFT'nin content_id'si bir isaret; baytlar getirilip hash'lenene kadar \
                 icerik dogrulanmis degil",
            ));
        return SearchResult {
            hit: Hit::Nft(Box::new(nft)),
            evidence,
        };
    }
    nothing(
        format!("nft:{id}"),
        String::from("bu kimlikte bir NFT yok"),
        Claim::new("nft", Strength::RpcClaimOnly, "yokluk kaniti sunulmadi"),
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
            "bns-cozumu",
            Strength::RpcClaimOnly,
            "cozum kanitsiz; BnsRegistry::root() bugun isim basina kanit uretmiyor",
        )
    } else {
        Claim::new(
            "ens-cozumu",
            Strength::RpcClaimOnly,
            "ENS cozumu bir MPT kaniti gerektiriyor ve bu arama katmani onu \
             dogrulamiyor; acmadan once dogrulanir",
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
            &format!("#{tag} etiketinde {} NFT", hits.len()),
            Claim::new(
                "etiket-arama",
                Strength::RpcClaimOnly,
                "etiket dizini bir dugumun urettigi siralamadir; kanitlanmaz",
            ),
        );
    }
    nothing(
        text.to_string(),
        String::from(
            "bir adrese, ada, NFT'ye ya da CID'ye benzemiyor. Etiket aramasi icin \
             basina # koyun",
        ),
        Claim::new(
            "siniflandirma",
            Strength::RpcClaimOnly,
            "girdi bir sinifa oturmadi",
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
        // Kayit kanitli olsa bile icerik henuz getirilmedi: en zayif halka
        // kazanir ve rozet `dogrulandi` demez.
        assert_eq!(r.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(r.evidence.badge().contains("baytlar getirilip"));
    }

    #[test]
    fn a_missing_account_says_absence_was_not_proven() {
        let r = run(&Fake::default(), &Query::BudAddress([9u8; 32]));
        assert!(matches!(r.hit, Hit::Nothing { .. }));
        assert!(r.evidence.badge().contains("yokluk kaniti"));
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
            Hit::Nothing { note, .. } => assert!(note.contains("belirsiz"), "{note}"),
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
        assert!(r.evidence.badge().contains("kanitlanmaz"));
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
