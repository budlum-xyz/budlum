//! Dogrulama gucu: her cevap ne kadar dogrulandigini **beyan eder**.
//!
//! # Sistemin en onemli tasarim karari
//!
//! Dogrulanamayan icerik yasaklanmiyor, **etiketleniyor**. Yasaklamak
//! tarayiciyi kullanilmaz yapar ve kullaniciyi hic dogrulama yapmayan baska
//! bir tarayiciya gonderir. Etiketlemek, kullaniciya ne gordugunu soyler.
//!
//! Bunun bedeli, etiketin durust olmasi zorunlulugudur. Bir cevabin
//! [`Strength::Verified`] olmasi icin bir **esitlik** kurulmus olmali:
//! getirilen baytlarin hash'i beklenen kimlige esit. Baska hicbir sey
//! `Verified` degildir; ozellikle "guvenilir bir RPC boyle dedi" degildir.
//!
//! # Neden tek bir enum
//!
//! Guc, getiricinin, cozumleyicinin ve hafif istemcinin ayri ayri urettigi bir
//! seydir ve **en zayif halka** kazanir. Ucunu ayri alanlarda tutup adres
//! cubugunda birlestirmek, birlestirmeyi unutan bir cagriya izin verir.
//! [`Evidence::weakest`] o birlesmeyi tek yerde yapiyor.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Bir cevabin ne kadar dogrulandigi.
///
/// Siralama kasitli: `Ord`, zayiftan gucluye. `weakest` bunun uzerine kuruyor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Strength {
    /// Dogrulanamadi ve icerik gosterilmemeli. Hash tutmadi, kanit gecersiz,
    /// ya da sifre cozulemedi.
    Refused,
    /// Yalniz birinin beyani. Bir RPC cevap verdi, kanit yok ya da kanit
    /// dogrulanamadi. Gosterilebilir, ama `dogrulandi` degil.
    RpcClaimOnly,
    /// Yalniz tasima guvenligi: TLS kimin gonderdigini soyluyor, neyin
    /// gonderildigini degil. Siradan web bu.
    TransportOnly,
    /// Icerik adresli ve bayt hash'i beklenen kimlige esit.
    Verified,
}

impl fmt::Display for Strength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => write!(f, "reddedildi"),
            Self::RpcClaimOnly => write!(f, "yalniz beyan"),
            Self::TransportOnly => write!(f, "yalniz tasima"),
            Self::Verified => write!(f, "dogrulandi"),
        }
    }
}

/// Bir tek olcum: kim, neyi, ne kadar dogruladi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// Hangi katman: `name-rule`, `bns-resolution`, `bud-fetcher`, `ipfs`, ...
    pub layer: String,
    pub strength: Strength,
    /// Neden bu guc. Bos birakilamaz: sebepsiz bir etiket, bir etiket degil.
    pub reason: String,
}

impl Claim {
    #[must_use]
    pub fn new(layer: &str, strength: Strength, reason: &str) -> Self {
        debug_assert!(!reason.is_empty(), "sebepsiz iddia yazilamaz");
        Self {
            layer: layer.to_string(),
            strength,
            reason: reason.to_string(),
        }
    }
}

/// Bir cevabin butun iddialari.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub claims: Vec<Claim>,
}

impl Evidence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, claim: Claim) -> Self {
        self.claims.push(claim);
        self
    }

    pub fn push(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    /// Zincirin en zayif halkasi.
    ///
    /// Hicbir iddia yoksa `Refused`: olculmemis bir sey dogrulanmis sayilmaz.
    /// Bu, bos bir `Evidence`'in kazara gecmesini engelliyor ve varsayilanin
    /// yonu hakkinda bir karar: sessizlik, `dogrulandi` demez.
    #[must_use]
    pub fn weakest(&self) -> Strength {
        self.claims
            .iter()
            .map(|c| c.strength)
            .min()
            .unwrap_or(Strength::Refused)
    }

    /// Icerik kullaniciya gosterilebilir mi?
    ///
    /// `Refused` disindaki her sey gosterilebilir, cunku etiketleme karari
    /// tam olarak budur: gosterilir ve ne oldugu soylenir.
    #[must_use]
    pub fn is_displayable(&self) -> bool {
        self.weakest() != Strength::Refused
    }

    /// Adres cubugunda gosterilecek tek satir.
    #[must_use]
    pub fn badge(&self) -> String {
        let w = self.weakest();
        let reason = self
            .claims
            .iter()
            .filter(|c| c.strength == w)
            .map(|c| format!("{}: {}", c.layer, c.reason))
            .collect::<Vec<_>>()
            .join("; ");
        if reason.is_empty() {
            format!("{w} (hicbir olcum yapilmadi)")
        } else {
            format!("{w} - {reason}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_measurement_is_not_verified() {
        let e = Evidence::new();
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(!e.is_displayable());
    }

    #[test]
    fn the_weakest_link_wins() {
        let e = Evidence::new()
            .with(Claim::new("bud-fetcher", Strength::Verified, "hash tuttu"))
            .with(Claim::new(
                "bns-resolution",
                Strength::RpcClaimOnly,
                "durum kaniti gelmedi",
            ));
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.is_displayable());
    }

    #[test]
    fn one_refusal_refuses_the_whole_answer() {
        let e = Evidence::new()
            .with(Claim::new(
                "bns-resolution",
                Strength::Verified,
                "kanit gecerli",
            ))
            .with(Claim::new(
                "ipfs",
                Strength::Refused,
                "ozet CID ile tutmadi",
            ));
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(!e.is_displayable());
    }

    #[test]
    fn the_badge_names_the_weakest_layer() {
        let e = Evidence::new()
            .with(Claim::new("bud-fetcher", Strength::Verified, "hash tuttu"))
            .with(Claim::new("https", Strength::TransportOnly, "yalniz TLS"));
        let badge = e.badge();
        assert!(badge.contains("yalniz tasima"), "{badge}");
        assert!(badge.contains("https"), "{badge}");
        assert!(!badge.contains("bud-fetcher"), "{badge}");
    }

    #[test]
    fn strength_ordering_is_weak_to_strong() {
        assert!(Strength::Refused < Strength::RpcClaimOnly);
        assert!(Strength::RpcClaimOnly < Strength::TransportOnly);
        assert!(Strength::TransportOnly < Strength::Verified);
    }
}
