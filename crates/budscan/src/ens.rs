//! ENS: namehash (EIP-137) ve `contenthash` (EIP-1577) cozumleme.
//!
//! # Tarayicinin ENS'ten ne istedigi
//!
//! Bir ENS sunucusuna sorup cevabini kabul etmek, bu tarayicinin butun
//! dogrulama iddiasini o sunucunun durustluguna indirger. Istenen sey bir
//! **kanit**: `namehash(name)` anahtariyla resolver sozlesmesinin depolama
//! slotuna baglanan bir Merkle-Patricia kaniti, ve o kanitin bagli oldugu
//! state root'un dogrulanmis bir Ethereum basliginda olmasi.
//!
//! Budlum'un `src/cross_domain/evm/` katmani bu isin yarisini zaten yapiyor:
//! `header.rs`, `mpt.rs`, `sync_committee.rs`, `verify.rs`. Budscan o katmanin
//! **tuketicisidir**, kopyasi degil: burada namehash ve contenthash cozumu
//! var, MPT dogrulamasi yok. Bu modul `MptProofRequest` uretir ve bir
//! `EvmProofVerifier` uygulamasi onu dogrular; kanit dogrulanamiyorsa cevap
//! [`crate::evidence::Strength::RpcClaimOnly`] olarak etiketlenir ve
//! `dogrulandi` denmez.
//!
//! Bu ayrimin silinmesi, "kanitli" ile "birinin soyledigi"ni ayni rozetin
//! altina koymak olurdu.

use sha3::{Digest, Keccak256};

/// EIP-137 namehash.
///
/// ```text
/// namehash([])            = 0x00 * 32
/// namehash([label, ...])  = keccak256(namehash(...) || keccak256(label))
/// ```
#[must_use]
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    for label in name.split('.').rev() {
        let label_hash: [u8; 32] = Keccak256::digest(label.as_bytes()).into();
        let mut h = Keccak256::new();
        h.update(node);
        h.update(label_hash);
        node = h.finalize().into();
    }
    node
}

/// Tek bir etiketin keccak-256'si.
#[must_use]
pub fn labelhash(label: &str) -> [u8; 32] {
    Keccak256::digest(label.as_bytes()).into()
}

/// EIP-1577 `contenthash` alanindan cikan hedef.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentHash {
    /// `ipfs-ns` (0xe3): govde bir CID.
    Ipfs(Vec<u8>),
    /// `ipns-ns` (0xe5): govde bir IPNS anahtari. Cozumu bir imza zinciri
    /// gerektirir ve bu surum onu dogrulamiyor.
    Ipns(Vec<u8>),
    /// `swarm-ns` (0xe4).
    Swarm(Vec<u8>),
    /// `arweave-ns` (0xb29910): govde bir islem kimligi.
    Arweave(Vec<u8>),
    /// `onion3` (0xbd): govde bir onion adresi.
    Onion3(String),
}

/// unsigned-varint oku.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

/// Bir `contenthash` bayt dizisini coz.
///
/// # Errors
///
/// Bos alan, bozuk varint ya da bu tarayicinin bir getiricisi olmayan bir
/// protokol. Taninmayan bir protokol icin **tahmin edilmez**: hangi agdan
/// getirilecegi bilinmeyen bir hedef, HTTPS'e dusurulurse kullanici
/// dogrulanmamis bir sayfayi dogrulanmis sanir.
pub fn decode_contenthash(bytes: &[u8]) -> Result<ContentHash, String> {
    if bytes.is_empty() {
        return Err(String::from(
            "contenthash bos: isim bir icerige baglanmamis",
        ));
    }
    let (proto, n) = read_varint(bytes).ok_or_else(|| String::from("protokol varint'i bozuk"))?;
    let body = &bytes[n..];
    if body.is_empty() {
        return Err(format!("protokol {proto:#x} bildirildi ama govde bos"));
    }
    match proto {
        0xe3 => Ok(ContentHash::Ipfs(body.to_vec())),
        0xe5 => Ok(ContentHash::Ipns(body.to_vec())),
        0xe4 => Ok(ContentHash::Swarm(body.to_vec())),
        0xb2_9910 => Ok(ContentHash::Arweave(body.to_vec())),
        0xbd => String::from_utf8(body.to_vec())
            .map(ContentHash::Onion3)
            .map_err(|_| String::from("onion3 govdesi UTF-8 degil")),
        other => Err(format!(
            "contenthash protokolu {other:#x} icin bir getirici yok; tarayici hangi agdan \
             getirecegini bilmiyor ve tahmin etmiyor"
        )),
    }
}

/// Bir ENS resolver depolama slotu icin istenen MPT kaniti.
///
/// Bu yapi bir **istek**tir, bir cevap degil. Dogrulamayi Budlum'un
/// `cross_domain/evm/mpt.rs` katmani yapar; Budscan sonucu etiketler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MptProofRequest {
    /// `namehash(name)`: resolver'in anahtar olarak kullandigi dugum.
    pub node: [u8; 32],
    /// Sorulan resolver sozlesmesinin adresi (20 bayt).
    pub resolver: [u8; 20],
    /// Kanitin baglanacagi Ethereum state root'u.
    pub state_root: [u8; 32],
}

impl MptProofRequest {
    #[must_use]
    pub fn new(name: &str, resolver: [u8; 20], state_root: [u8; 32]) -> Self {
        Self {
            node: namehash(name),
            resolver,
            state_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namehash_matches_eip_137_vectors() {
        assert_eq!(namehash(""), [0u8; 32]);
        assert_eq!(
            hex::encode(namehash("eth")),
            "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        );
        assert_eq!(
            hex::encode(namehash("foo.eth")),
            "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        );
    }

    #[test]
    fn labelhash_matches_the_documented_value() {
        assert_eq!(
            hex::encode(labelhash("eth")),
            "4f5b812789fc606be1b3b16908db13fc7a9adf7ca72641f84d75b47069d3d7f0"
        );
    }

    #[test]
    fn contenthash_ipfs_decodes_to_a_cid_body() {
        // ensdomains/content-hash README ornegi.
        let raw = hex::decode(
            "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f",
        )
        .unwrap();
        match decode_contenthash(&raw).unwrap() {
            ContentHash::Ipfs(body) => {
                // Govde CIDv1 dag-pb sha2-256: 0x01 0x70 0x12 0x20 ...
                assert_eq!(&body[..4], &[0x01, 0x70, 0x12, 0x20]);
            }
            other => panic!("ipfs beklendi, {other:?} geldi"),
        }
    }

    #[test]
    fn contenthash_swarm_decodes() {
        let raw = hex::decode(
            "e40101701b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162",
        )
        .unwrap();
        assert!(matches!(
            decode_contenthash(&raw).unwrap(),
            ContentHash::Swarm(_)
        ));
    }

    #[test]
    fn an_unknown_protocol_is_refused_not_downgraded() {
        let raw = vec![0x7f, 0x01, 0x02];
        let err = decode_contenthash(&raw).unwrap_err();
        assert!(err.contains("getirici yok"), "{err}");
    }

    #[test]
    fn an_empty_contenthash_says_so() {
        assert!(decode_contenthash(&[]).is_err());
    }
}
