//! Adres cubugundan sayfaya: bes adimin tek yerde birlesmesi.
//!
//! ```text
//! yazilan -> siniflandirma -> ad kurali -> cozum (+kanit) -> getirme (+hash) -> rozet
//! ```
//!
//! Her adim kendi kanit gucunu ekler ve **en zayif halka** rozeti belirler.
//! Bunun tek yerde olmasi kasitli: uc ayri katmanin uc ayri gucu varsa ve
//! birlestirme cagirana birakilirsa, birlestirmeyi unutan bir cagri
//! `dogrulandi` yazar.

use crate::bns_proof::{self, BnsInclusionProof, ResolvedName};
use crate::content_id::ContentId;
use crate::ens::{self, ContentHash};
use crate::evidence::{Claim, Evidence, Strength};
use crate::fetch::{self, Fetched, Target, Transport};
use crate::name_rule;
use crate::query::{self, Query};

/// Bir adi hedefe ceviren sey.
pub trait NameResolver {
    /// `.bud` adi: zincirden cozum ve varsa kaniti.
    ///
    /// # Errors
    ///
    /// Isim bulunamadiginda ya da zincire ulasilamadiginda. Bir **red** hata
    /// degildir: kaydin var olup dogrulanamamasi `BnsInclusionProof::None`
    /// ile bildirilir, `Err` ile degil.
    fn resolve_bud(&self, name: &str) -> Result<(ResolvedName, BnsInclusionProof), String>;
    /// `.bud` icin state root'a yazilan `bns_v1` degeri, biliniyorsa.
    fn bns_root(&self) -> Option<[u8; 32]>;
    /// `.eth` adi: ENS `contenthash` ham baytlari ve MPT kanitinin
    /// dogrulanip dogrulanmadigi.
    ///
    /// # Errors
    ///
    /// Isim bulunamadiginda ya da Ethereum durumuna ulasilamadiginda.
    fn resolve_eth(&self, name: &str) -> Result<(Vec<u8>, bool), String>;
}

/// Bir sayfayi acmanin sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub input: String,
    pub target: Option<Target>,
    pub bytes: Option<Vec<u8>>,
    pub evidence: Evidence,
}

impl Page {
    /// Sayfa Gecko'ya verilebilir mi?
    #[must_use]
    pub fn is_renderable(&self) -> bool {
        self.bytes.is_some() && self.evidence.is_displayable()
    }

    /// Adres cubugunda gosterilecek metin.
    ///
    /// Ad kuralindan gecmeyen bir girdi punycode olarak gosterilir; gosterilen
    /// sey ile cozulen seyin ayni olmasi bu tarayicinin kuralidir.
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

/// Yazilan bir seyi ac.
///
/// # Errors
///
/// Tasima ya da cozum katmaninin dondurdugu hata. Bir **red** hata degildir:
/// reddedilen girdi `Page` olarak doner ve nedeni rozetinde yazar, cunku
/// kullaniciya "acilmadi" demek yetmez, neden acilmadigi soylenmeli.
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

/// Getirmeden once verilen karar.
///
/// Ayri bir tip olmasinin sebebi, "getirme" ile "durma"nin iki ayri sonuc
/// olmasi: bir `Option<Target>` ikisini ayni sekle sokar ve `None`'in neden
/// `None` oldugunu tasimaz.
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
            "sema",
            &format!("{scheme} semasi adres cubugundan acilmaz"),
        )),
        Query::RefusedName { input, rejection } => {
            Plan::stop(refusal(&input, "ad-kurali", &rejection.to_string()))
        }
        Query::Ambiguous { input, candidates } => Plan::stop(refusal(
            &input,
            "siniflandirma",
            &format!(
                "belirsiz girdi tahmin edilmez; sunlardan biri olabilir: {}",
                candidates.join(", ")
            ),
        )),
        Query::FreeText(text) => Plan::stop(refusal(
            &text,
            "siniflandirma",
            "bu bir adres degil; arama icin arama katmanini kullanin",
        )),
        Query::Name { name, suffix } => match suffix.as_str() {
            "bud" => plan_bud(resolver, raw, &name)?,
            "eth" => plan_eth(resolver, raw, &name)?,
            other => Plan::stop(refusal(
                raw,
                "ad-kurali",
                &format!(".{other} icin bir cozumleyici yok"),
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
            "siniflandirma",
            "bu bir sayfa degil, bir kayit; arama katmani gosterir",
        )),
    })
}

/// `.bud`: cozum kanitla degerlendirilir, sonra bir icerik baglantisi aranir.
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
            "bns-cozumu",
            "isim bir icerige bagli degil: ne content_id ne storage_root var",
        )));
    };
    Ok(Plan::Fetch {
        target: Target::Bud(id),
        evidence,
    })
}

/// `.eth`: contenthash cozulur ve hedefin bir getiricisi var mi diye bakilir.
fn plan_eth<R: NameResolver>(resolver: &R, raw: &str, name: &str) -> Result<Plan, String> {
    let (raw_ch, proof_verified) = resolver.resolve_eth(name)?;
    let ch =
        ens::decode_contenthash(&raw_ch).map_err(|e| format!("ENS contenthash cozulemedi: {e}"))?;
    let evidence = Evidence::new().with(if proof_verified {
        Claim::new(
            "ens-cozumu",
            Strength::Verified,
            "namehash slotu icin MPT kaniti dogrulandi ve kok bilinen bir \
             Ethereum basliginda",
        )
    } else {
        Claim::new(
            "ens-cozumu",
            Strength::RpcClaimOnly,
            "MPT kaniti dogrulanmadi; cozum bir dugumun beyani",
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
            "IPNS cozumu bir imza zinciri gerektiriyor ve bu surum onu dogrulamiyor",
        )),
        ContentHash::Swarm(_) | ContentHash::Onion3(_) => stop_with(Claim::new(
            "getirici",
            Strength::Refused,
            "bu protokol icin bir getirici yok; HTTPS'e dusurmek dogrulanmamis \
             icerigi dogrulanmis gibi gosterirdi",
        )),
    })
}

/// ENS `ipfs-ns` govdesini bir CID dizgisine cevir.
///
/// Govde ikili bir CID; `crate::cid::parse_bytes` onu cozer ve tekrar dizgiye
/// cevirmek yerine dogrudan dogrulanabilir olup olmadigini soyleriz.
fn cid_string(body: &[u8]) -> Result<String, String> {
    let cid = crate::cid::parse_bytes(body)?;
    // `Target::Ipfs` bir dizgi bekliyor; base16 (multibase 'f') her zaman
    // yeniden cozulebilir ve base32'ye gore bir cevirici gerektirmiyor.
    //
    // Kodek **korunur**: bir dag-pb CID'sini raw'a cevirmek, dogrulanamayan
    // bir hedefi dogrulanabilir gibi gostermek olurdu. `0x1220` multihash
    // oneki her iki dalda da yaziliyor; unutulursa CID cozulur ama ozet
    // yanlis yerden okunur.
    let mut out = String::from("f");
    if cid.version == 0 {
        out.push_str("1220");
    } else {
        out.push_str("01");
        out.push_str(&hex::encode([u8::try_from(cid.codec).map_err(|_| {
            format!("kodek {:#x} tek baytlik bir varint degil", cid.codec)
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
            self.bud.clone().ok_or_else(|| String::from("isim yok"))
        }
        fn bns_root(&self) -> Option<[u8; 32]> {
            self.root
        }
        fn resolve_eth(&self, _name: &str) -> Result<(Vec<u8>, bool), String> {
            self.eth.clone().ok_or_else(|| String::from("isim yok"))
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
                .ok_or_else(|| format!("{key} bulunamadi"))
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
        // Bu, bu tarayicinin var olma sebebi: hash tutuyor ama esleme
        // kanitlanmadi, yani gosterilen sayfa istenen isme ait olmayabilir.
        let bytes = b"<html>ayaz</html>";
        let r = bud_resolver(bytes, false);
        let t = table(&[(&ContentId::of(bytes).to_string(), bytes)]);
        let page = open(&r, &t, "ayaz.bud").unwrap();
        assert!(page.is_renderable());
        assert_eq!(page.evidence.weakest(), Strength::RpcClaimOnly);
        assert!(page.address_bar().contains("yalniz beyan"));
    }

    #[test]
    fn bytes_that_do_not_hash_are_not_rendered_at_all() {
        let r = bud_resolver(b"beklenen", true);
        let t = table(&[(&ContentId::of(b"beklenen").to_string(), b"baska")]);
        let page = open(&r, &t, "ayaz.bud").unwrap();
        assert!(!page.is_renderable());
        assert!(page.bytes.is_none(), "reddedilen baytlar sayfaya gecmemeli");
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
        // `ipfs-ns` = 0xe3 ve multicodec kodlari varint'tir: 0xe3 tek basina
        // devam biti tasidigi icin `0xe3 0x01` yazilir. Bu bir bicim ayrintisi
        // degil, kodu ikiye bolen fark: tek bayt yazilirsa cozucu bir sonraki
        // baytin ilk yedi bitini koda katar ve baska bir protokol okur.
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
        // `swarm-ns` = 0xe4, varint olarak `0xe4 0x01`.
        let mut ch = vec![0xe4, 0x01];
        ch.extend_from_slice(&[0x11; 32]);
        let r = Resolver {
            bud: None,
            root: None,
            eth: Some((ch, true)),
        };
        let page = open(&r, &table(&[]), "x1.eth").unwrap();
        assert!(!page.is_renderable());
        assert!(page.evidence.badge().contains("getirici yok"));
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
        // Tasima bos: getiriciye ulasilsaydi hata donerdi.
        let page = open(&r, &table(&[]), "ayaz.bud").unwrap();
        assert!(!page.is_renderable());
        assert!(page.evidence.badge().contains("suresi dolmus"));
    }
}
