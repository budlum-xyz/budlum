//! B.U.D. - EDITION SEÇİMİ
//!
//! Tasarım: B.U.D. 3.0 ile 2.0 ayrı tutulur; çağıran taraf sürümü seçer;
//! ayrıca B.U.D. 1.0 da seçilebilsin."
//!
//! Üç sürüm aynı kod ağacında yaşar ama kullanıcı TARİFE SEVİYESİNİ seçer:
//! - B.U.D. 1.0 - Kendi sunucun/cihazın depolaması (BYO). B.U.D. kurallarına uymak
//!   zorunda değil; NFT verisi dışarıda, sorumluluk kullanıcıda. Cihaz aktifken
//!   validatör; verisi sosyal medyada görünür.
//! - B.U.D. 2.0 - .bud konteynerli depolama (0.016 hedefi, format transformları).
//! - B.U.D. 3.0 - Tarif-tek-nesne (depolama kavramı yok; QR video türev).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const ED_MAGIC: [u8; 8] = *b"\xB5EDN\0\0\0\0";
pub const ED_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    Bud1, // kendi sunucu/cihaz - kuralsız, BYO
    Bud2, // .bud konteyner depolama
    Bud3, // tarif-tek-nesne
}

impl Edition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bud1 => "B.U.D. 1.0",
            Self::Bud2 => "B.U.D. 2.0",
            Self::Bud3 => "B.U.D. 3.0",
        }
    }

    /// Kullanıcı hangi sürümü seçti? (deterministik; zincirde kayıt)
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Bud1),
            2 => Some(Self::Bud2),
            3 => Some(Self::Bud3),
            _ => None,
        }
    }

    /// Tarife modeli (kira zorunluluğu).
    pub fn tarif_zorunlu(&self) -> bool {
        match self {
            Self::Bud1 => false, // kuralsız: kendi verin, kendi sorumluluğun
            Self::Bud2 => true,  // .bud kaydı zorunlu
            Self::Bud3 => true,  // tarif kaydı zorunlu
        }
    }
}

// ============================ B.U.D. 1.0 ============================

/// B.U.D. 1.0: kendi depolaman (BYO).
/// - Kendi sunucusu/3. parti sunucu ekleyebilir.
/// - B.U.D. kurallarına uymak zorunda değil (merkeziyetsiz olsa bile).
/// - NFT verisi dışarıda (kullanıcının sunucusunda); sorumluluk kullanıcıda.
/// - Cihazda depolarsa: cihaz aktifken validatör; veri sosyal medyada görünür.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bud1Custody {
    External { server: String }, // kendi sunucusu / 3. parti
    Device,                      // kendi cihazı (aktifken validatör)
}

#[derive(Debug, Clone)]
pub struct Bud1Nft {
    pub id: [u8; 32],
    pub content_uri: String, // verinin TUTULDUĞU yer (dışarıda)
    pub custody: Bud1Custody,
    pub social_visible: bool, // veri sosyal medyada görünür mü?
}

impl Bud1Nft {
    /// 1.0: B.U.D. tarifine/kuralına UYMAK ZORUNDA DEĞİL - veri dışarıda.
    pub fn new_external(id: [u8; 32], server: String, uri: String) -> Self {
        Self {
            id,
            content_uri: uri,
            custody: Bud1Custody::External { server },
            social_visible: false,
        }
    }

    /// Cihazda depolama: cihaz aktifken validatör; veri sosyal medyada görünür.
    pub fn new_device(id: [u8; 32], uri: String, social_visible: bool) -> Self {
        Self {
            id,
            content_uri: uri,
            custody: Bud1Custody::Device,
            social_visible,
        }
    }

    /// Sorumluluk: HER ZAMAN kullanıcıda (1.0'ın çekirdeği).
    pub fn liability_user(&self) -> bool {
        true
    }

    /// Cihaz depoluyorsa + aktifse → validatör katkısı.
    pub fn device_validator(&self, device_active: bool) -> bool {
        matches!(self.custody, Bud1Custody::Device) && device_active
    }
}

/// 1.0 kayıt özeti (zincire yazılabilir).
pub fn bud1_digest(nft: &Bud1Nft) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ED_MAGIC);
    h.update([1]); // edition 1
    h.update(nft.id);
    h.update(nft.content_uri.as_bytes());
    match &nft.custody {
        Bud1Custody::External { server } => {
            h.update([0]);
            h.update(server.as_bytes());
        }
        Bud1Custody::Device => h.update([1]),
    }
    h.update([nft.social_visible as u8]);
    h.finalize().into()
}

// ============================ Edition seçim kaydı ============================

/// Kullanıcının seçimi (zincirde sabit; sürüm yükseltme yönetişim kararı).
#[derive(Debug, Clone)]
pub struct EditionChoice {
    pub edition: Edition,
    pub ts_unix: u64,
}

impl EditionChoice {
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(ED_MAGIC);
        h.update([self.edition as u8]);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edition_secim_deterministik() {
        assert_eq!(Edition::from_u8(1).unwrap(), Edition::Bud1);
        assert_eq!(Edition::from_u8(2).unwrap(), Edition::Bud2);
        assert_eq!(Edition::from_u8(3).unwrap(), Edition::Bud3);
        assert!(Edition::from_u8(0).is_none());
        assert!(Edition::from_u8(9).is_none());
    }

    #[test]
    fn bud1_kuralsiz_kendi_depolamasi() {
        let ext = Bud1Nft::new_external(
            [1u8; 32],
            "kendi-sunucum.example".into(),
            "https://kendi-sunucum.example/nft-1".into(),
        );
        assert!(!Edition::Bud1.tarif_zorunlu(), "1.0 kuralsız");
        assert!(ext.liability_user(), "sorumluluk kullanıcıda");
        // cihaz modu: aktifse validatör
        let dev = Bud1Nft::new_device([2u8; 32], "cid://1".into(), true);
        assert!(dev.device_validator(true));
        assert!(!dev.device_validator(false));
        assert!(dev.social_visible, "veri sosyal medyada görünür");
    }

    #[test]
    fn edition_farkli_digest() {
        let e1 = Bud1Nft::new_external([1u8; 32], "s".into(), "u".into());
        let e2 = Bud1Nft::new_device([1u8; 32], "u".into(), true);
        assert_ne!(
            bud1_digest(&e1),
            bud1_digest(&e2),
            "custody farkı digest'e yansır"
        );
        assert_eq!(bud1_digest(&e1), bud1_digest(&e1));
    }

    #[test]
    fn secim_kaydi() {
        let c = EditionChoice {
            edition: Edition::Bud3,
            ts_unix: 1_768_000_000,
        };
        assert_eq!(c.digest(), c.digest());
    }
}
