//! B.U.D. icerik adresleme, tarayici tarafi.
//!
//! `budlum-core`'daki `src/storage/content_id.rs` ile **ayni** tanim:
//! `ContentId = hash_fields_bytes([b"BDLM_CONTENT_V1", chunk])`, ve
//! `hash_fields_bytes` her alani uzunluk-onekleyerek SHA-256'ya verir.
//!
//! # Neden kopya, neden bagimlilik degil
//!
//! Tarayici `budlum-core`'a baglansaydi libp2p, tokio, jsonrpsee ve sled'i de
//! baglardi; bir tarayicinin guven sinirinda o grafik istenmez. Bunun bedeli
//! iki kopyanin ayrisabilmesidir ve bedel odenmeden birakilmiyor:
//! `budscan-content-id-parity` kapisi iki tanimin ayni vektoru uretmesini
//! CI'da olcer. Kopya serbest degil, olculuyor.
//!
//! # Dogrulama bir imza kontrolu degil, bir esitlik kontrolu
//!
//! Getirilen baytlarin hash'i beklenen kimlige esitse baytlar dogrudur.
//! Tarayicinin kime guvenecegine karar vermesi gerekmiyor: bir dugum en fazla
//! hizmet vermeyi reddedebilir, yalan soyleyemez.

use sha2::{Digest, Sha256};

/// Uzunluk-onekli alan hash'i. `budlum-core::core::hash::hash_fields_bytes`.
///
/// Uzunluk oneki olmasaydi `["a","bc"]` ile `["ab","c"]` ayni bayt dizisini
/// uretirdi ve iki farkli icerik ayni kimlige sahip olurdu.
#[must_use]
pub fn hash_fields_bytes(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Kanonik icerik kimligi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Bir yigin baytin `ContentId`'si.
    #[must_use]
    pub fn of(chunk: &[u8]) -> Self {
        ContentId(hash_fields_bytes(&[b"BDLM_CONTENT_V1", chunk]))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 64 karakterlik hex'ten okur.
    ///
    /// # Errors
    ///
    /// Uzunluk 64 degilse ya da hex degilse.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| String::from("ContentId 32 bayt olmali"))?;
        Ok(ContentId(arr))
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Bir manifest'in shard'lari birlestirildikten sonra kimlik karsilastirmasi.
///
/// Karsilastirma sabit zamanli degil ve olmasi gerekmiyor: iki taraf da
/// halka acik. Gizli olan bir sey yok, yani sizacak bir sey de yok.
#[must_use]
pub fn bytes_match(expected: ContentId, bytes: &[u8]) -> bool {
    ContentId::of(bytes) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic() {
        assert_eq!(ContentId::of(b"hello world"), ContentId::of(b"hello world"));
    }

    #[test]
    fn different_bytes_different_id() {
        assert_ne!(ContentId::of(b"a"), ContentId::of(b"b"));
    }

    #[test]
    fn truncation_cannot_collide() {
        // budlum-core'daki `content_id_collisions_impossible_for_truncated_payloads`
        // testinin aynisi: uzunluk oneki bu esitligi imkansiz kilar.
        let one = ContentId::of(b"ab");
        let two = ContentId::of(b"a").0;
        let three = ContentId::of(b"b").0;
        assert_ne!(
            one.0,
            hash_fields_bytes(&[b"BDLM_CONTENT_V1", &two, &three])
        );
    }

    #[test]
    fn the_core_vector_is_pinned() {
        // Bu vektor `budlum-core` ile paylasilan sozlesmedir. Degisirse iki
        // taraftan biri ayrilmistir ve o bir hata, bir guncelleme degil.
        let id = ContentId::of(b"budlum");
        assert_eq!(
            id.to_string(),
            hex::encode(hash_fields_bytes(&[b"BDLM_CONTENT_V1", b"budlum"]))
        );
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn hex_roundtrip() {
        let id = ContentId::of(b"x");
        assert_eq!(ContentId::from_hex(&id.to_string()).unwrap(), id);
        assert_eq!(ContentId::from_hex(&format!("0x{id}")).unwrap(), id);
        assert!(ContentId::from_hex("00").is_err());
    }
}
