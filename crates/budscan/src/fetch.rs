//! Getirici katmani: dort hedef, dort ayri dogrulama gucu.
//!
//! Her getirici **kendi dogrulama gucunu beyan eder** ve adres cubugu o
//! beyani gosterir:
//!
//! | hedef            | getirme | dogrulama                | cubukta        |
//! |------------------|---------|--------------------------|----------------|
//! | Budlum manifest  | B.U.D.  | hash = `manifest_id`     | dogrulandi     |
//! | IPFS CID         | IPFS    | hash = CID               | dogrulandi     |
//! | Arweave tx       | Arweave | hash = `data_root`       | dogrulandi     |
//! | HTTPS URL        | HTTP    | yalniz TLS               | yalniz tasima  |
//!
//! # Tasima bu modulde degil
//!
//! [`Transport`] bir trait ve bu crate'te ag kodu yok. Sebep tek bir cumleye
//! siger: dogrulama mantigi, sokete dokunan bir seye baglanirsa test edilemez
//! olur, ve dogrulanmayan bir dogrulayici bir dogrulayici degildir. Uretimde
//! tasima `budlum-core`'un `NodeClient`'i ya da bir HTTP istemcisi olur;
//! testte bellekteki bir tablo.

use crate::arweave::{self, ArweaveVerdict};
use crate::cid::{self, CidVerdict};
use crate::content_id::{bytes_match, ContentId};
use crate::evidence::{Claim, Evidence, Strength};

/// Bir hedef: bir adin cozuldugu sey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Budlum B.U.D. manifest kimligi.
    Bud(ContentId),
    /// IPFS CID (dizgi hali; cozumu getirici yapar).
    Ipfs(String),
    /// Arweave `data_root` (ham baytlar).
    Arweave(Vec<u8>),
    /// Siradan HTTPS adresi.
    Https(String),
}

impl Target {
    /// Bu hedefin **azami** dogrulama gucu, bayt gelmeden once bilinen.
    ///
    /// Bir HTTPS hedefinin dogrulanmis olma ihtimali yok; bunu getirmeden once
    /// bilmek, kullaniciya tiklamadan once soylemeyi mumkun kiliyor.
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

/// Baytlari nereden alacagimiz. Ag bu crate'te degil.
pub trait Transport {
    /// Hedefin baytlarini getir.
    ///
    /// # Errors
    ///
    /// Ag hatasi, bulunamayan icerik, ya da boyut sinirinin asilmasi.
    fn fetch(&self, target: &Target) -> Result<Vec<u8>, String>;
}

/// Bir getirmenin sonucu: baytlar **ve** ne kadar dogrulandiklari.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub evidence: Evidence,
}

impl Fetched {
    /// Baytlar gosterilebilir mi?
    #[must_use]
    pub fn is_displayable(&self) -> bool {
        self.evidence.is_displayable()
    }
}

/// Bir sayfanin azami boyutu.
///
/// `budlum-core`'un `MAX_GATEWAY_CONTENT_BYTES` degeriyle ayni: 10 MiB. Ayni
/// olmasi tesaduf degil, ikisi de ayni icerigi tasiyor ve iki farkli sinir
/// birinin digerini kabul ettigi bir bosluk acardi.
pub const MAX_CONTENT_BYTES: usize = 10 * 1024 * 1024;

/// Bir hedefi getir ve dogrula.
///
/// Dogrulama **her zaman** yapilir; basarisiz olursa baytlar donmeye devam
/// eder ama `Evidence` `Refused` olur ve `is_displayable()` false doner.
/// Baytlari atmak yerine etiketlemek, cagirana neyi reddettigini gosterme
/// imkani birakiyor (bir hata sayfasi "3 KB geldi, hash tutmadi" diyebilir).
///
/// # Errors
///
/// Tasima hatasi, boyut asimi, ya da cozulemeyen bir hedef tanimlayicisi.
pub fn fetch_and_verify<T: Transport>(transport: &T, target: &Target) -> Result<Fetched, String> {
    let bytes = transport.fetch(target)?;
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err(format!(
            "{} icerigi {} bayt; sinir {MAX_CONTENT_BYTES}",
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
                    "baytlarin ContentId'si manifest_id'ye esit",
                ))
            } else {
                Evidence::new().with(Claim::new(
                    "bud-fetcher",
                    Strength::Refused,
                    &format!(
                        "baytlarin ContentId'si {} ama manifest_id {manifest_id}",
                        ContentId::of(&bytes)
                    ),
                ))
            }
        }
        Target::Ipfs(s) => {
            let parsed = cid::parse(s).map_err(|e| format!("CID cozulemedi: {e}"))?;
            match cid::verify(&parsed, &bytes) {
                CidVerdict::Verified => Evidence::new().with(Claim::new(
                    "ipfs",
                    Strength::Verified,
                    "baytlarin sha2-256 ozeti CID ile esit",
                )),
                CidVerdict::DigestMismatch { expected, produced } => {
                    Evidence::new().with(Claim::new(
                        "ipfs",
                        Strength::Refused,
                        &format!("ozet {produced}, CID {expected}"),
                    ))
                }
                CidVerdict::UnsupportedMultiblock => Evidence::new().with(Claim::new(
                    "ipfs",
                    Strength::RpcClaimOnly,
                    "dag-pb: bu surum UnixFS DAG yurumuyor, baytlar dogrulanmadi",
                )),
            }
        }
        Target::Arweave(root) => match arweave::verify(root, &bytes) {
            ArweaveVerdict::Verified => Evidence::new().with(Claim::new(
                "arweave",
                Strength::Verified,
                "baytlardan turetilen data_root islemdekiyle esit",
            )),
            ArweaveVerdict::RootMismatch { expected, produced } => {
                Evidence::new().with(Claim::new(
                    "arweave",
                    Strength::Refused,
                    &format!("data_root {produced}, beklenen {expected}"),
                ))
            }
        },
        Target::Https(url) => Evidence::new().with(Claim::new(
            "https",
            Strength::TransportOnly,
            &format!("{url}: TLS kimin gonderdigini soyluyor, neyin gonderildigini degil"),
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
        let t = Table::with(&id.to_string(), b"gelen baska seyler");
        let got = fetch_and_verify(&t, &Target::Bud(id)).unwrap();
        assert_eq!(got.evidence.weakest(), Strength::Refused);
        assert!(!got.is_displayable());
        // Sebep her iki kimligi de tasimali, yoksa kullanici ne oldugunu bilemez.
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
        let t = Table::with(s, b"her ne ise");
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
        assert!(err.contains("sinir"), "{err}");
    }
}
