//! Arama kutusuna yazilan sey ne?
//!
//! "Cuzdan adresleri, NFT'ler, web siteleri hepsi burada aratilir" tek bir
//! kutu demek, ve tek bir kutu bir **ayristirma sirasi** demek. Tarayici
//! tarihinin en eski hata sinifi tam olarak burada yasiyor: bir dizginin ad mi
//! sema mi sayilacagi, hangi kontrolun once calistigina bakar.
//!
//! # Kural: siniflandirma once, cozum sonra
//!
//! Bu modul **hicbir sey cozmez**. Yalniz yazilan seyin hangi sinifa
//! girdigini soyler ve karar verilemiyorsa [`Query::Ambiguous`] doner.
//! Belirsizligi kendi basina cozmek, kullanicinin yazdigi seyi kullanicinin
//! kastetmedigi bir seye cevirmektir; belirsiz bir girdi kullaniciya sorulur.
//!
//! # Sema hicbir zaman tahmin edilmez
//!
//! `javascript:alert(1)` bir sema gibi gorunuyor ve gercekten oyle. Bu modul
//! onu bir ad diye okumaz; [`Query::RefusedScheme`] doner ve neden
//! reddedildigini soyler. Ad kurali ayrica ayni girdiyi reddeder
//! ([`crate::name_rule`]); iki katmanin da reddetmesi kasitli, cunku birinin
//! gevsemesi digerinin susmasi anlamina gelmemeli.

use crate::name_rule::{self, NameRejection};

/// Yazilan seyin sinifi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Cozulebilir bir ad: `ayaz.bud`, `x1.eth`.
    Name { name: String, suffix: String },
    /// 32 baytlik Budlum adresi (0x + 64 hex).
    BudAddress([u8; 32]),
    /// 20 baytlik EVM adresi (0x + 40 hex).
    EvmAddress([u8; 20]),
    /// B.U.D. icerik kimligi (0x + 64 hex, `bud://` ya da `cid:` onekiyle
    /// acikca isaretlenmis).
    ContentId([u8; 32]),
    /// IPFS CID.
    Cid(String),
    /// NFT kimligi: `nft:12` ya da cikplak bir tam sayi.
    NftId(u64),
    /// Blok yuksekligi: `blok:1200`.
    BlockHeight(u64),
    /// Islem hash'i: `tx:0x...`.
    TxHash([u8; 32]),
    /// Bir HTTPS adresi. Acikca yazilmis olmali; tahmin edilmez.
    HttpsUrl(String),
    /// Serbest metin: hicbir sinifa girmiyor. Bir arama terimi olabilir.
    FreeText(String),
    /// Ayni girdi iki sinifa da uyuyor ve tahmin edilmiyor.
    Ambiguous {
        input: String,
        candidates: Vec<String>,
    },
    /// Bir sema yazilmis ve o sema acilmayacak.
    RefusedScheme { input: String, scheme: String },
    /// Bir ad gibi duruyor ama ad kuralindan gecmiyor.
    RefusedName {
        input: String,
        rejection: NameRejection,
    },
}

/// Adres cubuguna hicbir kosulda ad diye girmeyecek semalar.
///
/// Liste bir **red** listesi, bir izin listesi degil, ve bu bilincli: izin
/// listesi, listede olmayan her yeni semayi sessizce kabul eder. Bu liste
/// bilinen zararlilari isimlendiriyor; geri kalan her sema
/// [`Query::RefusedScheme`] ile zaten reddediliyor cunku `is_scheme_like`
/// iki nokta gorunce durur.
pub const NEVER_OPENED_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "vbscript",
    "file",
    "blob",
    "chrome",
    "resource",
    "about",
];

/// Bir dizgi "sema:" ile mi basliyor?
///
/// `https://` de bir semadir ve o ayrica ele aliniyor. Buradaki soru sadece
/// "iki noktadan once bir sema etiketi var mi".
fn scheme_of(input: &str) -> Option<&str> {
    let idx = input.find(':')?;
    let scheme = &input[..idx];
    if scheme.is_empty() {
        return None;
    }
    let ok = scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
    if ok && scheme.chars().next()?.is_ascii_alphabetic() {
        Some(scheme)
    } else {
        None
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(s).ok()
}

/// Yazilan seyi siniflandir. Hicbir sey cozulmez, hicbir ag cagrisi yapilmaz.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn classify(raw: &str) -> Query {
    let input = raw.trim();

    if input.is_empty() {
        return Query::FreeText(String::new());
    }

    // 1. Acik onekler. Kullanici ne istedigini soylediyse tahmin yok.
    if let Some(rest) = input.strip_prefix("nft:") {
        if let Ok(id) = rest.trim().parse::<u64>() {
            return Query::NftId(id);
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input
        .strip_prefix("blok:")
        .or_else(|| input.strip_prefix("block:"))
    {
        if let Ok(h) = rest.trim().parse::<u64>() {
            return Query::BlockHeight(h);
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input.strip_prefix("tx:") {
        if let Some(bytes) = hex_bytes(rest.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Query::TxHash(arr);
            }
        }
        return Query::FreeText(input.to_string());
    }
    if let Some(rest) = input
        .strip_prefix("bud://")
        .or_else(|| input.strip_prefix("cid:"))
    {
        let rest = rest.trim();
        if let Some(bytes) = hex_bytes(rest) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Query::ContentId(arr);
            }
        }
        // `bud://ayaz.bud` da gecerli bir yazim: sema bir adi isaret ediyor.
        return classify_name(rest);
    }
    if let Some(rest) = input.strip_prefix("ipfs://") {
        return Query::Cid(rest.trim().to_string());
    }

    // 2. HTTPS acikca yazilmis olmali. `evil.com` yazan biri HTTPS istemis
    //    olabilir ama `evil.com` ayni zamanda bir ad gibi durur; tahmin
    //    etmiyoruz, `Ambiguous` donuyoruz (asagida).
    if input.starts_with("https://") {
        return Query::HttpsUrl(input.to_string());
    }
    if input.starts_with("http://") {
        // Duz HTTP: ne icerik dogrulanir ne tasima. Reddedilmiyor ama
        // ne oldugu soyleniyor; karar `Target::Https` degil, cunku o bile
        // TLS varsayar.
        return Query::RefusedScheme {
            input: input.to_string(),
            scheme: String::from("http"),
        };
    }

    // 3. Geri kalan her sema reddedilir. Once bu, cunku `javascript:alert(1)`
    //    ayni zamanda bir "ad gibi" gorunebilir ve sira burada belirleyici.
    if let Some(scheme) = scheme_of(input) {
        return Query::RefusedScheme {
            input: input.to_string(),
            scheme: scheme.to_string(),
        };
    }

    // 4. Hex adresler.
    if let Some(bytes) = hex_bytes(input) {
        if input.starts_with("0x") {
            if let Ok(arr) = <[u8; 20]>::try_from(bytes.as_slice()) {
                return Query::EvmAddress(arr);
            }
            if bytes.len() == 32 {
                // 32 bayt hem bir Budlum adresi hem bir ContentId hem bir tx
                // hash olabilir. Uctur belirsizlik ve tahmin edilmiyor.
                return Query::Ambiguous {
                    input: input.to_string(),
                    candidates: vec![
                        String::from("cuzdan adresi (Address)"),
                        String::from("icerik kimligi (ContentId) - bud:// ile yazin"),
                        String::from("islem hash'i - tx: ile yazin"),
                    ],
                };
            }
        }
    }

    // 5. Cikplak tam sayi: NFT mi blok mu? Tahmin yok.
    if input.parse::<u64>().is_ok() {
        return Query::Ambiguous {
            input: input.to_string(),
            candidates: vec![
                String::from("NFT kimligi - nft: ile yazin"),
                String::from("blok yuksekligi - blok: ile yazin"),
            ],
        };
    }

    // 6. IPFS CID gibi duruyor mu? (`Qm...` ya da `bafy.../bafk...`)
    if (input.len() == 46 && input.starts_with("Qm"))
        || (input.starts_with("baf")
            && input.len() > 20
            && input.chars().all(|c| c.is_ascii_alphanumeric()))
    {
        return Query::Cid(input.to_string());
    }

    // 7. Noktali bir sey: ad mi, alan adi mi?
    if input.contains('.') {
        return classify_name(input);
    }

    Query::FreeText(input.to_string())
}

/// Noktali bir girdiyi ad kuralindan gecir.
fn classify_name(input: &str) -> Query {
    match name_rule::check_name(input) {
        Ok(()) => {
            let suffix = name_rule::suffix_of(input).unwrap_or_default().to_string();
            if name_rule::RESOLVABLE_SUFFIXES.contains(&suffix.as_str()) {
                Query::Name {
                    name: input.to_string(),
                    suffix,
                }
            } else {
                // `evil.com` gecerli bir ad sekli ama cozumleyicisi yok.
                // HTTPS'e dusurmek, kullanicinin yazmadigi bir semayi
                // varsaymaktir; belirsiz diyoruz.
                Query::Ambiguous {
                    input: input.to_string(),
                    candidates: vec![
                        format!(".{suffix} icin bir ad cozumleyicisi yok"),
                        String::from("siradan web sitesi - https:// ile yazin"),
                    ],
                }
            }
        }
        Err(rejection) => Query::RefusedName {
            input: input.to_string(),
            rejection,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bud_name_is_a_name() {
        assert_eq!(
            classify("ayaz.bud"),
            Query::Name {
                name: String::from("ayaz.bud"),
                suffix: String::from("bud")
            }
        );
        assert_eq!(
            classify("  x1.eth  "),
            Query::Name {
                name: String::from("x1.eth"),
                suffix: String::from("eth")
            }
        );
    }

    #[test]
    fn javascript_is_a_refused_scheme_not_a_name() {
        match classify("javascript:alert(1)") {
            Query::RefusedScheme { scheme, .. } => assert_eq!(scheme, "javascript"),
            other => panic!("sema reddi beklendi, {other:?} geldi"),
        }
        for s in NEVER_OPENED_SCHEMES {
            let input = format!("{s}:whatever");
            assert!(
                matches!(classify(&input), Query::RefusedScheme { .. }),
                "{input} kabul edildi"
            );
        }
    }

    #[test]
    fn plain_http_is_refused_by_name() {
        match classify("http://evil.com") {
            Query::RefusedScheme { scheme, .. } => assert_eq!(scheme, "http"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn https_must_be_written_out() {
        assert_eq!(
            classify("https://example.com/x"),
            Query::HttpsUrl(String::from("https://example.com/x"))
        );
        // Cikplak alan adi tahmin edilmez.
        assert!(matches!(classify("example.com"), Query::Ambiguous { .. }));
    }

    #[test]
    fn an_evm_address_is_twenty_bytes() {
        let q = classify("0x0000000000000000000000000000000000000001");
        assert!(matches!(q, Query::EvmAddress(_)), "{q:?}");
    }

    #[test]
    fn thirty_two_bytes_is_ambiguous_and_says_all_three() {
        let q = classify(&format!("0x{}", "11".repeat(32)));
        match q {
            Query::Ambiguous { candidates, .. } => assert_eq!(candidates.len(), 3),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn explicit_prefixes_remove_the_ambiguity() {
        assert!(matches!(
            classify(&format!("bud://0x{}", "11".repeat(32))),
            Query::ContentId(_)
        ));
        assert!(matches!(
            classify(&format!("tx:0x{}", "22".repeat(32))),
            Query::TxHash(_)
        ));
        assert_eq!(classify("nft:12"), Query::NftId(12));
        assert_eq!(classify("blok:1200"), Query::BlockHeight(1200));
    }

    #[test]
    fn a_bare_integer_is_ambiguous_not_guessed() {
        assert!(matches!(classify("12"), Query::Ambiguous { .. }));
    }

    #[test]
    fn a_bad_name_is_refused_with_its_reason() {
        match classify("has space.bud") {
            Query::RefusedName { rejection, .. } => {
                assert!(matches!(
                    rejection,
                    NameRejection::DisallowedCharacter { .. }
                ));
            }
            other => panic!("{other:?}"),
        }
        match classify("UPPER.bud") {
            Query::RefusedName { rejection, .. } => {
                assert_eq!(
                    rejection,
                    NameRejection::DisallowedCharacter {
                        position: 0,
                        ch: 'U'
                    }
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn path_traversal_never_becomes_a_name() {
        assert!(matches!(
            classify("evil.bud/../../etc"),
            Query::RefusedName { .. }
        ));
    }

    #[test]
    fn a_cid_is_recognised_by_shape() {
        assert!(matches!(
            classify("bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"),
            Query::Cid(_)
        ));
        assert!(matches!(
            classify("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            Query::Cid(_)
        ));
        assert!(matches!(classify("ipfs://bafkrei..."), Query::Cid(_)));
    }

    #[test]
    fn free_text_stays_free_text() {
        assert_eq!(
            classify("egitim iceriği"),
            Query::FreeText(String::from("egitim iceriği"))
        );
    }

    #[test]
    fn a_bidi_override_is_refused_not_displayed() {
        assert!(matches!(
            classify("\u{202E}dub.zaya"),
            Query::RefusedName { .. }
        ));
    }
}
