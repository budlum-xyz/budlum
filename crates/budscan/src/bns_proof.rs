//! BNS cozumu: tarayicinin gercek guven problemi.
//!
//! # Icerik adresleme bunu cozmuyor
//!
//! `ayaz.bud` soruldugunda saldirganin manifest kimligini donduren bir dugum,
//! **dogrulanan ama yanlis** bir sayfa gosterir: baytlar hash'iyle tutarli,
//! ama o hash istenen isme ait degil. Bayt dogrulamasi burada hicbir sey
//! soylemiyor, cunku yanlis olan bayt degil, esleme.
//!
//! Karar: BNS cozumu **durum kanitiyla** alinir ve kanitsiz cevap
//! `dogrulandi` sayilmaz.
//!
//! # Bugun neyin dogrulanabildigi, acikca
//!
//! `AccountState::calculate_state_root` (`src/core/account.rs:1966`) BNS
//! kaydini state root'a su sekilde katiyor:
//!
//! ```text
//! if !self.bns_registry.is_empty() {
//!     final_hasher.update(b"bns_v1");
//!     final_hasher.update(self.bns_registry.root());
//! }
//! ```
//!
//! ve `BnsRegistry::root()` (`src/bns/registry.rs:299`) **butun kayit
//! defterini tek bir SHA-256 akisina** yaziyor. Yani bugun zincirde tek bir
//! isim icin kanit uretecek bir yapi **yok**: `bns_v1` kokunu dogrulamak,
//! butun defteri elde tutmayi gerektirir.
//!
//! Bunun uc sonucu var ve ucu de yaziliyor:
//!
//! 1. [`BnsInclusionProof::Registry`] - butun defterle dogrulama. Dogru ama
//!    olceklenmiyor; kucuk bir defterde calisir, yuz bin isimde calismaz.
//! 2. [`BnsInclusionProof::PerName`] - isim basina Merkle kaniti. Zincir bunu
//!    **bugun uretmiyor**; `BnsRegistry::root()`'un bir Merkle agacina
//!    donmesi gerekir ve o bir **konsensus yuzeyi degisikligidir**, bu
//!    tarayicinin tek tarafli alacagi bir karar degil.
//! 3. Kanit yoksa sonuc [`Strength::RpcClaimOnly`]. Sessizce `Verified`
//!    demek, olmayan bir garantiyi satmak olur.
//!
//! Bu, bu dosyanin en onemli cumlesi: **BNS cozumu bugun kanitlanabilir
//! degil, ve tarayici bunu gizlemiyor.**

use crate::content_id::ContentId;
use crate::evidence::{Claim, Evidence, Strength};
use sha2::{Digest, Sha256};

/// Zincirden gelen cozum cevabi.
///
/// Alanlar `BnsResolved` (`src/bns/types.rs`) ile ayni; bu tarayicinin
/// ihtiyaci olmayanlar tasinmiyor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    pub name: String,
    /// 32 baytlik sahip adresi.
    pub owner: [u8; 32],
    pub storage_root: Option<[u8; 32]>,
    pub content_id: Option<ContentId>,
    pub is_expired: bool,
}

/// Bir cozumun kayit defterine ait oldugunun kaniti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsInclusionProof {
    /// Butun kayit defteri. `BnsRegistry::root()`'un bugun urettigi sey bu
    /// akistan hesaplaniyor, yani dogrulama defterin tamamini yeniden
    /// hash'lemektir.
    Registry {
        /// `base_cost`; koke giren ilk alan.
        base_cost: u64,
        /// `(name, owner, expires_at, content_id)` dortlusu, `BTreeMap`
        /// sirasinda. Zincirdeki `root()` daha fazla alan yaziyor; bu surum
        /// yalniz tarayicinin okudugu alanlari tasiyor ve **bu yuzden tam
        /// kok uretemiyor**. Asagidaki `verify` bunu bir basari degil, bir
        /// eksiklik olarak raporluyor.
        entries: Vec<RegistryEntry>,
    },
    /// Isim basina Merkle kaniti. Zincir bunu bugun uretmiyor.
    PerName {
        leaf: [u8; 32],
        siblings: Vec<[u8; 32]>,
        directions: Vec<bool>,
    },
    /// Kanit yok: bir RPC cevap verdi, hepsi bu.
    None,
}

/// Kayit defterinin bir satiri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    pub name: String,
    pub owner: [u8; 32],
    pub expires_at: u64,
    pub content_id: Option<ContentId>,
}

/// Bir BNS cozumunu kanitla birlikte degerlendir.
///
/// `expected_bns_root`, `AccountState`'in `bns_v1` etiketiyle state root'a
/// yazdigi deger.
#[must_use]
pub fn evaluate(
    resolved: &ResolvedName,
    proof: &BnsInclusionProof,
    expected_bns_root: Option<[u8; 32]>,
) -> Evidence {
    let mut evidence = Evidence::new();

    if resolved.is_expired {
        evidence.push(Claim::new(
            "bns-cozumu",
            Strength::Refused,
            "kayit suresi dolmus; suresi dolmus bir isim bir icerige baglanmaz",
        ));
        return evidence;
    }

    match proof {
        BnsInclusionProof::None => {
            evidence.push(Claim::new(
                "bns-cozumu",
                Strength::RpcClaimOnly,
                "durum kaniti gelmedi; bu cevap bir dugumun beyani ve dugum yalan \
                 soyleyebilir. Icerik hash'i tutsa bile gosterilen sayfa istenen \
                 isme ait olmayabilir",
            ));
        }
        BnsInclusionProof::PerName { .. } => {
            evidence.push(Claim::new(
                "bns-cozumu",
                Strength::RpcClaimOnly,
                "isim basina kanit sunuldu ama zincir bugun boyle bir kanit uretmiyor: \
                 BnsRegistry::root() butun defteri tek bir SHA-256 akisina yaziyor, \
                 Merkle agaci degil. Kanitin dogrulanacagi bir kok yok",
            ));
        }
        BnsInclusionProof::Registry { base_cost, entries } => {
            let Some(expected) = expected_bns_root else {
                evidence.push(Claim::new(
                    "bns-cozumu",
                    Strength::RpcClaimOnly,
                    "defter sunuldu ama karsilastirilacak bir bns_v1 koku verilmedi",
                ));
                return evidence;
            };
            let found = entries.iter().any(|e| {
                e.name == resolved.name
                    && e.owner == resolved.owner
                    && e.content_id == resolved.content_id
            });
            if !found {
                evidence.push(Claim::new(
                    "bns-cozumu",
                    Strength::Refused,
                    "cozulen kayit sunulan defterde yok; cevap defterle celisiyor",
                ));
                return evidence;
            }
            let computed = partial_registry_root(*base_cost, entries);
            if computed == expected {
                evidence.push(Claim::new(
                    "bns-cozumu",
                    Strength::Verified,
                    "defter bns_v1 kokunu yeniden uretti ve kayit defterde",
                ));
            } else {
                // Beklenen durum bu: bu surum `root()`'un butun alanlarini
                // tasimiyor. Yanlis olan defter degil, kanit bicimi.
                evidence.push(Claim::new(
                    "bns-cozumu",
                    Strength::RpcClaimOnly,
                    "sunulan defter bns_v1 kokunu uretmedi. Bu tek basina bir yalan \
                     isareti degil: BnsRegistry::root() resolver, address, \
                     consensus_domain_id, storage_root, storage_domain_id, \
                     storage_root_height ve subdomains alanlarini da yaziyor ve bu \
                     kanit bicimi onlari tasimiyor. Kanit bicimi eksik, cevap \
                     dogrulanmadi",
                ));
            }
        }
    }

    evidence
}

/// `BnsRegistry::root()`'un **kismi** yeniden uretimi.
///
/// Kasitli olarak eksik ve adi bunu soyluyor. Tam kok, tarayicinin okumadigi
/// alti alani ve alt alan adlarini da iceriyor; onlari buraya tasimak, bir
/// tarayicinin bir kayit defterinin tamamini indirmesi demek olurdu. Bu
/// fonksiyonun isi, kanit biciminin neden yetmedigini **olculebilir** kilmak.
#[must_use]
pub fn partial_registry_root(base_cost: u64, entries: &[RegistryEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_REGISTRY_V1");
    hasher.update(base_cost.to_le_bytes());
    for e in entries {
        hasher.update(e.name.as_bytes());
        hasher.update(e.owner);
        hasher.update(e.expires_at.to_le_bytes());
        // Zincirdeki `root()` burada resolver/address/domain/storage alanlarini
        // yaziyor. Yazilmiyorlar ve bu yuzden bu kok tutmuyor.
        match e.content_id {
            Some(cid) => {
                hasher.update([1u8]);
                hasher.update(cid.0);
            }
            None => hasher.update([0u8]),
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved() -> ResolvedName {
        ResolvedName {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            storage_root: Some([9u8; 32]),
            content_id: Some(ContentId([9u8; 32])),
            is_expired: false,
        }
    }

    #[test]
    fn an_expired_name_is_refused_before_any_proof_is_read() {
        let mut r = resolved();
        r.is_expired = true;
        let e = evaluate(&r, &BnsInclusionProof::None, None);
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(e.badge().contains("suresi dolmus"));
    }

    #[test]
    fn no_proof_is_a_claim_not_a_verification() {
        let e = evaluate(&resolved(), &BnsInclusionProof::None, None);
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("yalan soyleyebilir"));
    }

    #[test]
    fn a_per_name_proof_says_the_chain_does_not_produce_one() {
        let e = evaluate(
            &resolved(),
            &BnsInclusionProof::PerName {
                leaf: [0u8; 32],
                siblings: vec![],
                directions: vec![],
            },
            Some([0u8; 32]),
        );
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("Merkle agaci degil"));
    }

    #[test]
    fn a_registry_missing_the_record_is_refused_not_downgraded() {
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries: vec![RegistryEntry {
                name: String::from("baska.bud"),
                owner: [2u8; 32],
                expires_at: 10,
                content_id: None,
            }],
        };
        let e = evaluate(&resolved(), &proof, Some([0u8; 32]));
        assert_eq!(e.weakest(), Strength::Refused);
        assert!(e.badge().contains("celisiyor"));
    }

    #[test]
    fn a_registry_that_reproduces_the_root_is_verified() {
        let entries = vec![RegistryEntry {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            expires_at: 10,
            content_id: Some(ContentId([9u8; 32])),
        }];
        let root = partial_registry_root(100, &entries);
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries,
        };
        let e = evaluate(&resolved(), &proof, Some(root));
        assert_eq!(e.weakest(), Strength::Verified);
    }

    #[test]
    fn a_registry_that_does_not_reproduce_the_root_explains_which_fields_are_missing() {
        let entries = vec![RegistryEntry {
            name: String::from("ayaz.bud"),
            owner: [1u8; 32],
            expires_at: 10,
            content_id: Some(ContentId([9u8; 32])),
        }];
        let proof = BnsInclusionProof::Registry {
            base_cost: 100,
            entries,
        };
        let e = evaluate(&resolved(), &proof, Some([0xFFu8; 32]));
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("storage_root_height"), "{}", e.badge());
    }

    #[test]
    fn the_partial_root_is_deterministic() {
        let entries = vec![RegistryEntry {
            name: String::from("a.bud"),
            owner: [3u8; 32],
            expires_at: 1,
            content_id: None,
        }];
        assert_eq!(
            partial_registry_root(100, &entries),
            partial_registry_root(100, &entries)
        );
        assert_ne!(
            partial_registry_root(100, &entries),
            partial_registry_root(101, &entries)
        );
    }
}
