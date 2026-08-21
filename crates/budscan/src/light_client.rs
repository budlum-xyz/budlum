//! Hafif istemci: hangi state root'un gecerli oldugunu bilmek.
//!
//! Bir tarayici bir dugume sorar ve dugum yalan soyleyebilir. Uc ayri sorunun
//! uc ayri cevabi var ve bu modul ucuncusuyle ilgileniyor.
//!
//! * **Icerik baytlari** yalan soyleyemez: hash tutmuyorsa bayt atilir
//!   ([`crate::fetch`]).
//! * **BNS cozumu** yalan soyleyebilir: saldirganin manifest kimligini donduren
//!   bir dugum, *dogrulanan ama yanlis* bir sayfa gosterir. Cozum bir durum
//!   kanitina baglanmali ([`crate::bns_proof`]).
//! * **Zincir basliklari**: hangi state root'un gecerli oldugunu bilmek icin
//!   bir baslik zinciri takip edilir. Burasi orasi.
//!
//! # Olculen: her basligi takip etmek pahali
//!
//! `src/core/block.rs`'deki `BlockHeader` alanlari toplandiginda baslik basina
//! yaklasik 603 bayt. Hash alanlari `String` ve `hex::encode` ile yaziliyor,
//! yani otuz iki baytlik her kok altmis dort karakter tutuyor.
//!
//! | takip              | 1 sn blok | 6 sn blok  | 12 sn blok |
//! |--------------------|-----------|------------|------------|
//! | her baslik         | 1,5 GB/ay | 248 MB/ay  | 124 MB/ay  |
//! | yalniz epoch siniri| 149 MB/ay | 24,8 MB/ay | 12,4 MB/ay |
//!
//! Karar buradan cikiyor: **tarayici her basligi takip etmez, yalniz
//! kesinlesmis epoch sinirlarini takip eder.** `EPOCH_LENGTH = 10`
//! (`src/chain/blockchain.rs:54`), yani onda bir. Bir durum kanitini
//! dogrulamak icin gereken tek sey, kanitin bagli oldugu state root'un
//! kesinlesmis bir baslikta olmasi; aradaki dokuz baslik o soruya cevap
//! vermiyor.
//!
//! # Ne dogrulanmiyor, acikca
//!
//! Bu modul bir basligin **kesinlestigini** kendi basina kanitlamaz. Budlum
//! coklu konsensus tasiyor ve kesinlik `DomainFinalityAdapter` arkasinda yedi
//! ayri bicimde uretiliyor (`PoW` header-chain, `PoS`, `PoA`, BFT, ZK, depolama
//! attestasyonu, AI cikarimi). Bir tarayicinin bu yedisini de dogrulamasi
//! ayri bir istir ve **yapilmadi**. Yapilana kadar baslik takibi bir
//! `FinalitySource`'a soruyor ve o kaynak bir beyanda bulunuyorsa sonuc
//! [`crate::evidence::Strength::RpcClaimOnly`] olarak etiketleniyor.
//!
//! Bunu "hafif istemci var" diye sunmak, olmayan bir garantiyi satmak olurdu.

use crate::evidence::{Claim, Evidence, Strength};
use sha2::{Digest, Sha256};

/// `src/chain/blockchain.rs:54` ile ayni. Ayrisirsa epoch sinirlari kayar.
pub const EPOCH_LENGTH: u64 = 10;

/// Takip edilen bir baslik.
///
/// `state_root` ve `hash` zincirde hex `String`; burada da oyle tutuluyor,
/// cunku karsilastirmanin zincirin yazdigi bicimle yapilmasi gerekiyor.
/// Ham bayta cevirmek basligi 603'ten 443 bayta indirirdi (yuzde 26) ama o
/// bir konsensus yuzeyi degisikligi ve burada yapilmiyor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHeader {
    pub index: u64,
    pub epoch: u64,
    pub state_root: String,
    pub hash: String,
}

impl TrackedHeader {
    /// Bu baslik bir epoch siniri mi?
    #[must_use]
    pub fn is_epoch_boundary(&self) -> bool {
        self.index.is_multiple_of(EPOCH_LENGTH)
    }
}

/// Kesinlik hakkinda kim konusuyor.
pub trait FinalitySource {
    /// Bu baslik kesinlesti mi, ve bunu **nasil** biliyoruz?
    ///
    /// Donen `Claim`, kaynagin kendi gucunu beyan etmesidir. Bir kaynak
    /// `Verified` demek istiyorsa bir kanit dogrulamis olmali; "RPC boyle
    /// dedi" `RpcClaimOnly`'dir.
    fn finality_of(&self, header: &TrackedHeader) -> Claim;
}

/// Kesinlesmis epoch sinirlarinin deposu.
///
/// Yalniz epoch sinirlari saklanir ve depo sinirlidir: bir tarayici sonsuz
/// zincir tutamaz. Sinira ulasildiginda **en eski** baslik dusurulur, cunku
/// bir durum kaniti her zaman yeni bir koke baglanir.
#[derive(Debug, Clone)]
pub struct HeaderStore {
    headers: Vec<TrackedHeader>,
    capacity: usize,
}

impl HeaderStore {
    /// Varsayilan kapasite: 1024 epoch siniri.
    ///
    /// Alti saniyelik blokta epoch basi altmis saniye, yani 1024 epoch
    /// yaklasik on yedi saat. Bir kanitin bagli oldugu kokun bu pencerede
    /// olmasi bekleniyor; olmuyorsa kanit eski ve reddedilmeli.
    pub const DEFAULT_CAPACITY: usize = 1024;

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            headers: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Bir basligi kabul et.
    ///
    /// # Errors
    ///
    /// Epoch siniri olmayan bir baslik, geriye giden bir indeks, ya da ayni
    /// indekste farkli bir hash (bu bir catallanma isaretidir ve sessizce
    /// uzerine yazilmaz).
    pub fn accept(&mut self, header: TrackedHeader) -> Result<(), String> {
        if !header.is_epoch_boundary() {
            return Err(format!(
                "baslik {} bir epoch siniri degil (EPOCH_LENGTH={EPOCH_LENGTH}); \
                 tarayici aradaki basliklari takip etmiyor",
                header.index
            ));
        }
        if let Some(last) = self.headers.last() {
            if header.index == last.index {
                if header.hash != last.hash {
                    return Err(format!(
                        "indeks {} icin iki farkli hash gorundu ({} ve {}); bu bir \
                         catallanma isareti ve sessizce cozulmez",
                        header.index, last.hash, header.hash
                    ));
                }
                return Ok(());
            }
            if header.index < last.index {
                return Err(format!(
                    "baslik {} zaten gorulen {}'den geride; geriye giden bir zincir \
                     kabul edilmez",
                    header.index, last.index
                ));
            }
        }
        self.headers.push(header);
        if self.headers.len() > self.capacity {
            self.headers.remove(0);
        }
        Ok(())
    }

    /// En yeni kesinlesmis kok.
    #[must_use]
    pub fn tip(&self) -> Option<&TrackedHeader> {
        self.headers.last()
    }

    /// Bu state root takip edilen bir baslikta mi?
    #[must_use]
    pub fn knows_state_root(&self, state_root: &str) -> bool {
        self.headers.iter().any(|h| h.state_root == state_root)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Bir state root'a guvenmenin gucu.
    ///
    /// Ucu de gerekli: kok bilinen bir baslikta olmali, o baslik kesinlesmis
    /// olmali, ve kesinligi soyleyen kaynagin kendi gucu ne ise sonuc ondan
    /// guclu olamaz.
    pub fn strength_of<S: FinalitySource>(&self, source: &S, state_root: &str) -> Evidence {
        let Some(header) = self.headers.iter().find(|h| h.state_root == state_root) else {
            return Evidence::new().with(Claim::new(
                "hafif-istemci",
                Strength::Refused,
                "state root takip edilen hicbir kesinlesmis baslikta yok",
            ));
        };
        Evidence::new().with(source.finality_of(header))
    }
}

impl Default for HeaderStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Seyrek Merkle trie kaniti: `src/storage/merkle_trie.rs` ile ayni kural.
// ---------------------------------------------------------------------------

const TRIE_DEPTH: usize = 256;
const DOMAIN_PREFIX: &[u8] = b"BDLM_MERKLE_TRIE_V1";

/// Bir adres icin durum kaniti.
///
/// `src/storage/merkle_trie.rs`'in urettigi kanitla ayni sekil. O modul bugun
/// **bagli degil** (kendi dosyasi soyluyor: hesap durumu hala eski kok
/// uzerinden hash'leniyor), yani bu dogrulayici bugun canli zincire karsi
/// calismiyor. Burada olmasinin sebebi, trie baglandiginda tarayici tarafinin
/// hazir olmasi ve o gun kuralin yeniden icat edilmemesi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub address: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
    pub leaf_hash: [u8; 32],
}

fn get_bit(bytes: &[u8; 32], index: usize) -> bool {
    let byte = bytes[index / 8];
    let bit = 7 - (index % 8);
    (byte >> bit) & 1 == 1
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Iki bos cocuk bosa cokert: `H(0||0)` degil, sifir.
fn combine_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == [0u8; 32] && *right == [0u8; 32] {
        return [0u8; 32];
    }
    hash_internal(left, right)
}

fn finalize_root(raw: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX);
    h.update(raw);
    h.finalize().into()
}

/// Bir yaprak hash'i: `SHA-256(0x01 || address || balance_le || nonce_le)`.
#[must_use]
pub fn hash_leaf(address: &[u8; 32], balance: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(address);
    h.update(balance.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

impl MerkleProof {
    /// Kanit bu koke baglaniyor mu?
    ///
    /// Yon bitleri adresten **turetilir ve karsilastirilir**. Karsilastirma
    /// olmasaydi gecerli bir kanit baska bir adresin kaniti diye
    /// etiketlenebilirdi; bu tam olarak `merkle_trie.rs`'in Strix LOW
    /// (CWE-345) bulgusunda kapatilan sey ve burada da kapali olmali, cunku
    /// dogrulayici tarafi acik birakmak kaniti anlamsiz kilar.
    #[must_use]
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        if self.siblings.len() != TRIE_DEPTH || self.directions.len() != TRIE_DEPTH {
            return false;
        }
        let mut current = self.leaf_hash;
        for i in 0..TRIE_DEPTH {
            let expected_direction = get_bit(&self.address, TRIE_DEPTH - 1 - i);
            if self.directions[i] != expected_direction {
                return false;
            }
            let (left, right) = if self.directions[i] {
                (self.siblings[i], current)
            } else {
                (current, self.siblings[i])
            };
            current = combine_nodes(&left, &right);
        }
        &finalize_root(&current) == expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct HonestChain;
    impl FinalitySource for HonestChain {
        fn finality_of(&self, header: &TrackedHeader) -> Claim {
            Claim::new(
                "kesinlik",
                Strength::RpcClaimOnly,
                &format!(
                    "epoch {} icin kesinlik bir RPC beyani; yedi DomainFinalityAdapter \
                     bicimi tarayicida dogrulanmiyor",
                    header.epoch
                ),
            )
        }
    }

    fn header(index: u64) -> TrackedHeader {
        TrackedHeader {
            index,
            epoch: index / EPOCH_LENGTH,
            state_root: format!("root{index}"),
            hash: format!("hash{index}"),
        }
    }

    #[test]
    fn only_epoch_boundaries_are_accepted() {
        let mut store = HeaderStore::new();
        assert!(store.accept(header(10)).is_ok());
        let err = store.accept(header(13)).unwrap_err();
        assert!(err.contains("epoch siniri degil"), "{err}");
    }

    #[test]
    fn a_second_hash_at_one_index_is_a_fork_not_an_update() {
        let mut store = HeaderStore::new();
        store.accept(header(10)).unwrap();
        let mut twin = header(10);
        twin.hash = String::from("baska");
        let err = store.accept(twin).unwrap_err();
        assert!(err.contains("catallanma"), "{err}");
    }

    #[test]
    fn the_chain_does_not_go_backwards() {
        let mut store = HeaderStore::new();
        store.accept(header(20)).unwrap();
        assert!(store.accept(header(10)).is_err());
    }

    #[test]
    fn capacity_drops_the_oldest_not_the_newest() {
        let mut store = HeaderStore::with_capacity(2);
        store.accept(header(10)).unwrap();
        store.accept(header(20)).unwrap();
        store.accept(header(30)).unwrap();
        assert_eq!(store.len(), 2);
        assert!(!store.knows_state_root("root10"));
        assert!(store.knows_state_root("root30"));
        assert_eq!(store.tip().unwrap().index, 30);
    }

    #[test]
    fn an_unknown_state_root_is_refused_not_assumed() {
        let store = HeaderStore::new();
        let e = store.strength_of(&HonestChain, "root10");
        assert_eq!(e.weakest(), Strength::Refused);
    }

    #[test]
    fn a_known_root_is_only_as_strong_as_the_finality_source() {
        let mut store = HeaderStore::new();
        store.accept(header(10)).unwrap();
        let e = store.strength_of(&HonestChain, "root10");
        assert_eq!(e.weakest(), Strength::RpcClaimOnly);
        assert!(e.badge().contains("DomainFinalityAdapter"));
    }

    #[test]
    fn a_merkle_proof_verifies_only_against_its_own_root() {
        // Tek yaprakli bir trie: kardeslerin hepsi bos.
        let address = [0xAAu8; 32];
        let leaf = hash_leaf(&address, 100, 3);
        let mut current = leaf;
        let mut directions = Vec::with_capacity(TRIE_DEPTH);
        for i in 0..TRIE_DEPTH {
            let bit = get_bit(&address, TRIE_DEPTH - 1 - i);
            directions.push(bit);
            let (l, r) = if bit {
                ([0u8; 32], current)
            } else {
                (current, [0u8; 32])
            };
            current = combine_nodes(&l, &r);
        }
        let root = finalize_root(&current);
        let proof = MerkleProof {
            address,
            siblings: vec![[0u8; 32]; TRIE_DEPTH],
            directions,
            leaf_hash: leaf,
        };
        assert!(proof.verify(&root));
        assert!(!proof.verify(&[0u8; 32]));
    }

    #[test]
    fn a_proof_relabelled_to_another_address_does_not_verify() {
        let address = [0xAAu8; 32];
        let leaf = hash_leaf(&address, 100, 3);
        let mut current = leaf;
        let mut directions = Vec::with_capacity(TRIE_DEPTH);
        for i in 0..TRIE_DEPTH {
            let bit = get_bit(&address, TRIE_DEPTH - 1 - i);
            directions.push(bit);
            let (l, r) = if bit {
                ([0u8; 32], current)
            } else {
                (current, [0u8; 32])
            };
            current = combine_nodes(&l, &r);
        }
        let root = finalize_root(&current);
        let forged = MerkleProof {
            address: [0xBBu8; 32],
            siblings: vec![[0u8; 32]; TRIE_DEPTH],
            directions,
            leaf_hash: leaf,
        };
        assert!(
            !forged.verify(&root),
            "etiketi degistirilen kanit gecmemeli"
        );
    }

    #[test]
    fn a_short_proof_is_refused() {
        let proof = MerkleProof {
            address: [1u8; 32],
            siblings: vec![[0u8; 32]; 4],
            directions: vec![false; 4],
            leaf_hash: [2u8; 32],
        };
        assert!(!proof.verify(&[0u8; 32]));
    }
}
