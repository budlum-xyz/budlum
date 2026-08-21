//! Adres cubugu bir guven sinirdir: bir ad once bu kuraldan gecer.
//!
//! # Olculen sorun
//!
//! `src/bns/registry.rs` bir ada tek kural uyguluyor: 3..=32 karakter.
//! Karakter kumesi denetimi yok. Bu, zincir tarafinda cogunlukla zararsiz
//! (kayit bir dizgi, cozum bir arama) ama bir tarayicida degil: Budscan adi
//! bir kaynak tanimlayicisina cevirir, yani dizgi bir ayristiriciya girer.
//! `javascript:alert(1)` bugun kaydedilebilir bir BNS adidir.
//!
//! # Neden iki katman
//!
//! Zincirin kurali yonetisimle gevseyebilir; bir tarayici bunu varsayamaz.
//! Bu yuzden tarayicinin kurali her zaman zincirin kuralindan **dar** olur ve
//! zincir ne kabul ederse etsin burasi kendi kararini verir. Zincirden gelen
//! ama buradan gecmeyen bir ad **gosterilir**, `acilmaz`, ve neden acilmadigi
//! soylenir.
//!
//! # Reddin sebebi eyleme gecirilebilir olmali
//!
//! Her red sinifinin kendi adi var. Genel bir "gecersiz ad" hatasi, cagirani
//! hangi ozelligin basarisiz oldugunu bilmekten mahrum birakir; bir kullanici
//! icin de "acilmadi" ile "iki nokta ust uste bir ad karakteri degil" ayni
//! sey degildir.
//!
//! Bu modul `xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs`
//! icindeki kuralin calisan surumudur. Iki kopya bilerek ayni tabloyu
//! uyguluyor ve `budscan-name-rule-parity` kapisi ikisinin ayrismasini
//! CI'da dusuruyor: ismin ne icerebileceginе karar veren iki yerin birbirinden
//! habersiz ayrismasi, tek bir yerin kotu karar vermesinden kotudur.

use std::fmt;

/// Bir ad neden adres cubuguna konulamaz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRejection {
    /// 3..=32 karakter disinda. Registry'nin kendi siniri.
    WrongLength,
    /// `a-z`, `0-9`, `-` ve `.` disinda bir karakter.
    ///
    /// Buyuk harf kucultulmez, reddedilir. Kucultmek `UPPER.bud` ile
    /// `upper.bud`'u tek kayda getirir ve sahipligi ilk kaydedenin belirledigi
    /// bir yarisa cevirir; reddetmek ikisinden birinin var olmadigini soyler.
    DisallowedCharacter { position: usize, ch: char },
    /// Bos etiket: bastaki, sondaki ya da ciftlenmis nokta.
    EmptyLabel,
    /// Bir etiket tire ile basliyor ya da bitiyor. Sekil ayrilmis, cunku
    /// punycode'un kendi `xn--` oneki taklit edilemesin.
    HyphenAtLabelEdge,
    /// Yazi sistemi karisiyor: bir Latin kelimenin icine bir Kiril harfin
    /// saklanma bicimi budur. Latin olmadigi icin reddedilmez; tamamen Kiril
    /// bir ad kabul edilir ve punycode gosterilir.
    MixedScript,
    /// Nokta yok, yani hangi ad sistemine ait oldugunu soyleyen bir sonek yok.
    NoSuffix,
    /// Sonek taniniyor ama bu tarayicinin bir cozumleyicisi yok.
    UnknownSuffix,
}

impl fmt::Display for NameRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => write!(f, "bir ad 3 ile 32 karakter arasinda olmali"),
            Self::DisallowedCharacter { position, ch } => write!(
                f,
                "{position}. konumdaki {ch:?} karakteri a-z, 0-9, tire ve nokta disinda; \
                 bir ad adres cubuguna ulasir, yani bir URL ayristiricisinin ozel \
                 davrandigi hicbir sey adin parcasi olamaz"
            ),
            Self::EmptyLabel => write!(
                f,
                "bastaki, sondaki ya da ciftlenmis nokta bos bir etiket birakir ve \
                 ayristiricilar bunun ne demek oldugunda anlasmaz"
            ),
            Self::HyphenAtLabelEdge => write!(
                f,
                "bir etiket tire ile baslayamaz ya da bitemez; bu sekil punycode'un \
                 kendi oneki taklit edilemesin diye ayrilmistir"
            ),
            Self::MixedScript => write!(
                f,
                "ad yazi sistemlerini karistiriyor; bir Latin kelimenin icine tek bir \
                 Kiril harfin saklanma bicimi budur. Tek yazi sistemiyle yazilmis bir \
                 ad kabul edilir"
            ),
            Self::NoSuffix => write!(
                f,
                "noktasiz bir ad hicbir sistemi adlandirmaz: .bud Budlum'da, .eth \
                 Ethereum'da cozulur, cikplak bir etiket ikisini de soylemez"
            ),
            Self::UnknownSuffix => write!(
                f,
                "bu sonek icin bir cozumleyici yok; tarayici hangi ad sistemine \
                 soracagini bilmiyor ve tahmin etmiyor"
            ),
        }
    }
}

/// Bir karakterin hangi yazi sistemine ait oldugu, kabaca.
///
/// Yalniz "bu ad tek yazi sistemiyle mi yazilmis" sorusuna cevap verecek
/// kadar. Latin bir kelimedeki Kiril `a`'yi yakalamak icin tam bir Unicode
/// script tablosu gerekmiyor ve bagimliligi olmayan bir crate'e boyle bir
/// tabloyu tasimak bedava degil.
///
/// Noktalama bilerek bir yazi sistemi **degil**. Tanimadigi her karakteri bir
/// kovaya koyup kovalari karsilastiran ilk surum `javascript:alert(1)` icin
/// `MixedScript` donduruyordu: iki nokta bir sistem, harfler baskasi. Red
/// dogru, sebep sacma. Eyleme gecirilemeyen bir sebep, bir reddin var olma
/// sebebinin cogunu bosa cikarir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Arabic,
    Hebrew,
    Han,
}

/// Bir harfin yazi sistemi; harf olmayan icin `None`.
fn script_of(ch: char) -> Option<Script> {
    match ch {
        'a'..='z' | 'A'..='Z' => Some(Script::Latin),
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Some(Script::Greek),
        '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' => Some(Script::Cyrillic),
        '\u{0590}'..='\u{05FF}' => Some(Script::Hebrew),
        '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' => Some(Script::Arabic),
        '\u{4E00}'..='\u{9FFF}' | '\u{3400}'..='\u{4DBF}' => Some(Script::Han),
        _ => None,
    }
}

/// Bu tarayicinin cozumleyicisi olan sonekler.
///
/// Liste bilerek kisa. Bir sonek buraya, o sonek icin bir kanit yolu
/// yazildiktan sonra eklenir: cozumu dogrulanamayan bir ad sistemi, adres
/// cubugunda dogrulanmis gibi duran bir cevap uretir ve bu tarayicinin
/// kacindigi tek sey odur.
pub const RESOLVABLE_SUFFIXES: &[&str] = &["bud", "eth"];

/// Bu ad cozulup gosterilebilir mi?
///
/// # Errors
///
/// Basarisiz olan ilk ozellik, bir [`NameRejection`] olarak.
pub fn check_name(name: &str) -> Result<(), NameRejection> {
    let count = name.chars().count();
    if !(3..=32).contains(&count) {
        return Err(NameRejection::WrongLength);
    }

    // Harfler arasinda tek yazi sistemi. Karakter kumesinden once bakilir ki
    // tamamen Kiril bir ad, ilk harfinin yasak oldugunu duymak yerine dogru
    // reddi alsin. Harf olmayanlar burada atlanir; onlar hakkinda konusacak
    // olan asagidaki karakter kumesi denetimi.
    let mut seen: Option<Script> = None;
    for ch in name.chars() {
        let Some(s) = script_of(ch) else { continue };
        match seen {
            None => seen = Some(s),
            Some(prev) if prev != s => return Err(NameRejection::MixedScript),
            Some(_) => {}
        }
    }

    for (position, ch) in name.chars().enumerate() {
        if !matches!(ch, 'a'..='z' | '0'..='9' | '-' | '.') {
            return Err(NameRejection::DisallowedCharacter { position, ch });
        }
    }

    if !name.contains('.') {
        return Err(NameRejection::NoSuffix);
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(NameRejection::EmptyLabel);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(NameRejection::HyphenAtLabelEdge);
        }
    }

    Ok(())
}

/// Adin sonekini dondurur (noktadan sonraki son etiket).
#[must_use]
pub fn suffix_of(name: &str) -> Option<&str> {
    name.rsplit('.').next().filter(|s| !s.is_empty())
}

/// [`check_name`] arti "bu sonegi cozebiliyor muyuz".
///
/// # Errors
///
/// [`check_name`]'in verdigi red, ya da tanimayan bir sonek icin
/// [`NameRejection::UnknownSuffix`].
pub fn check_resolvable(name: &str) -> Result<(), NameRejection> {
    check_name(name)?;
    let suffix = suffix_of(name).ok_or(NameRejection::NoSuffix)?;
    if RESOLVABLE_SUFFIXES.contains(&suffix) {
        Ok(())
    } else {
        Err(NameRejection::UnknownSuffix)
    }
}

/// Adres cubugunda gosterilecek bicim.
///
/// Kurali gecen bir ad oldugu gibi gosterilir. Gecmeyen bir ad **acilmaz**,
/// ama gosterilmesi gerekebilir (gecmiste, bir baglantinin ustunde, bir hata
/// satirinda). O durumda ASCII disi her etiket punycode'a cevrilir, cunku
/// kullaniciya gosterilen sey ile cozulen sey arasindaki fark tam olarak
/// homograf saldirisinin yasadigi bosluktur.
#[must_use]
pub fn display_form(name: &str) -> String {
    if check_name(name).is_ok() {
        return name.to_string();
    }
    let mut out = String::with_capacity(name.len() + 8);
    for (i, label) in name.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
        } else if let Some(encoded) = crate::punycode::encode_label(label) {
            out.push_str("xn--");
            out.push_str(&encoded);
        } else {
            // Kodlanamayan bir etiket icin ham baytlari gostermek, gosterilen
            // ile cozulen arasinda tam da kapatmaya calistigimiz farki acar.
            out.push_str("[?]");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_named_not_generic() {
        let cases: &[(&str, NameRejection)] = &[
            (
                "javascript:alert(1)",
                NameRejection::DisallowedCharacter {
                    position: 10,
                    ch: ':',
                },
            ),
            (
                "has space.bud",
                NameRejection::DisallowedCharacter {
                    position: 3,
                    ch: ' ',
                },
            ),
            (
                "UPPER.bud",
                NameRejection::DisallowedCharacter {
                    position: 0,
                    ch: 'U',
                },
            ),
            ("ayaz", NameRejection::NoSuffix),
            (".bud", NameRejection::EmptyLabel),
            ("ayaz..bud", NameRejection::EmptyLabel),
            ("ayaz.bud.", NameRejection::EmptyLabel),
            ("-ayaz.bud", NameRejection::HyphenAtLabelEdge),
            ("ayaz-.bud", NameRejection::HyphenAtLabelEdge),
            ("\u{0430}yaz.bud", NameRejection::MixedScript),
            ("ab", NameRejection::WrongLength),
        ];
        for (name, want) in cases {
            assert_eq!(check_name(name), Err(*want), "{name:?}");
        }
    }

    #[test]
    fn path_traversal_and_urls_are_refused() {
        for name in [
            "evil.bud/../../etc",
            "http://evil.com",
            "a/b/c",
            "ayaz.bud\u{0}x",
            "\u{202E}dub.zaya",
        ] {
            assert!(check_name(name).is_err(), "{name:?} kabul edildi");
        }
    }

    #[test]
    fn an_ordinary_name_passes() {
        for name in ["ayaz.bud", "a-b.bud", "x1.eth", "a.b.c.bud"] {
            assert!(check_name(name).is_ok(), "{name:?} reddedildi");
        }
    }

    #[test]
    fn a_wholly_cyrillic_name_is_not_called_mixed_script() {
        // ASCII kumesinden dusmesi dogru; MixedScript demek yanlis teshis olur.
        let name = "\u{0430}\u{0431}\u{0432}.\u{0431}\u{0430}\u{0434}";
        assert_ne!(check_name(name), Err(NameRejection::MixedScript));
        assert!(check_name(name).is_err());
    }

    #[test]
    fn an_unknown_suffix_is_refused_by_the_resolvable_check_only() {
        assert!(check_name("ayaz.sol").is_ok());
        assert_eq!(
            check_resolvable("ayaz.sol"),
            Err(NameRejection::UnknownSuffix)
        );
        assert!(check_resolvable("ayaz.bud").is_ok());
        assert!(check_resolvable("ayaz.eth").is_ok());
    }

    #[test]
    fn display_form_punycodes_what_it_cannot_accept() {
        assert_eq!(display_form("ayaz.bud"), "ayaz.bud");
        // Deger hesaplandi, belgeden kopyalanmadi: bkz. `punycode` testindeki
        // not (mimari belgesi burada `xn--yaz-hlc.bud` yaziyor ve yanlis).
        assert_eq!(display_form("\u{0430}yaz.bud"), "xn--yaz-5cd.bud");
    }
}
