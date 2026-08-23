//! B.U.D. 2.0 - DAS Parça Tutma (F25 DTDL deseni) (2026-08-16)
//!
//! F25: validatörler 3x aynı veriyi tutmak yerine YALNIZ BİRER PARÇA tutar;
//! erişim/doğrulama verifiable tree + data-availability-sampling (DAS) ile.
//!
//! Bu modül: bir blok/dosya parçalarını (chunk) tek tek doğrulamak için
//! **Merkle kökü** (domain-etiketli, K38) + **DAS örneklemesi**: az sayıda parça
//! çekilip köke karşı doğrulanırsa verinin tamamının mevcut olduğuna yüksek
//! olasılıkla güvenilir (Celestia/Avail deseni).
//!
//! Ayrıca **parça sahipliği kaydı**: her validatör hangi parçayı tuttuğunu
//! imzalanmış kayıtla beyan eder; eksik parça → DAS sınavı RED (itibar).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const DAS_MAGIC: [u8; 8] = *b"\xB5DASS\0\0\0";
pub const DAS_VERSION: u8 = 1;

/// Merkle kökü (parça listesinden - domain-etiketli, K38).
pub fn das_root(chunks: &[Vec<u8>]) -> [u8; 32] {
    // yaprak hash'leri
    let leaves: Vec<[u8; 32]> = chunks
        .iter()
        .map(|c| {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_BUD_DAS_LEAF_V1");
            h.update((c.len() as u64).to_le_bytes());
            h.update(c);
            h.finalize().into()
        })
        .collect();
    // ikili merkle (tek sayıda → son yaprak çoğaltılır)
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = Sha3_256::new();
            h.update(b"BDLM_BUD_DAS_NODE_V1");
            h.update(pair[0]);
            if let Some(r) = pair.get(1) {
                h.update(*r);
            } else {
                h.update(pair[0]); // tek → çoğalt
            }
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

/// Tek parça kanıtı: (yaprak + yol) → köke karşı doğrula.
/// `path`: her seviyede kardeş hash (sağdaki None = solda değil).
#[derive(Debug, Clone)]
pub struct DasProof {
    pub leaf_index: usize,
    pub path: Vec<[u8; 32]>,
}

impl DasProof {
    /// Kanıt üret (deterministik - veriden yeniden hesaplanır).
    pub fn prove(chunks: &[Vec<u8>], leaf_index: usize) -> Option<DasProof> {
        if chunks.is_empty() || leaf_index >= chunks.len() {
            return None;
        }
        // yaprak hash'i
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunks[leaf_index].len() as u64).to_le_bytes());
        h.update(&chunks[leaf_index]);
        let leaf: [u8; 32] = h.finalize().into();
        let mut level: Vec<[u8; 32]> = chunks
            .iter()
            .map(|c| {
                let mut h = Sha3_256::new();
                h.update(b"BDLM_BUD_DAS_LEAF_V1");
                h.update((c.len() as u64).to_le_bytes());
                h.update(c);
                h.finalize().into()
            })
            .collect();
        let mut idx = leaf_index;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sibling = if sibling_idx < level.len() {
                level[sibling_idx]
            } else {
                level[idx]
            };
            path.push(sibling);
            // üst seviyeye geç
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let mut h = Sha3_256::new();
                h.update(b"BDLM_BUD_DAS_NODE_V1");
                h.update(pair[0]);
                if let Some(r) = pair.get(1) {
                    h.update(*r);
                } else {
                    h.update(pair[0]);
                }
                next.push(h.finalize().into());
            }
            level = next;
            idx /= 2;
        }
        let _ = leaf;
        Some(DasProof { leaf_index, path })
    }

    /// Kanıt doğrula: leaf + path → root (panik'siz).
    pub fn verify(&self, leaf: &[u8], root: &[u8; 32]) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((leaf.len() as u64).to_le_bytes());
        h.update(leaf);
        let mut cur: [u8; 32] = h.finalize().into();
        let mut idx = self.leaf_index;
        for sibling in &self.path {
            let mut nh = Sha3_256::new();
            nh.update(b"BDLM_BUD_DAS_NODE_V1");
            if idx.is_multiple_of(2) {
                nh.update(cur);
                nh.update(*sibling);
            } else {
                nh.update(*sibling);
                nh.update(cur);
            }
            cur = nh.finalize().into();
            idx /= 2;
        }
        cur == *root
    }
}

/// DAS örneklemesi: rastgele (deterministik tohumla) k parça çek, hepsi köke
/// doğrulanırsa veri büyük olasılıkla tam mevcut (eksik oran düşükse).
pub struct DasSampler;

impl DasSampler {
    /// Deterministik örnekleme: tohumdan k indeks üret (çakışmasız).
    pub fn sample_indices(count: usize, k: usize, seed: u64) -> Vec<usize> {
        if count == 0 || k == 0 {
            return vec![];
        }
        let mut out = Vec::with_capacity(k);
        let mut x = seed;
        while out.len() < k.min(count) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let idx = (x % count as u64) as usize;
            if !out.contains(&idx) {
                out.push(idx);
            }
            if out.len() == count {
                break;
            }
        }
        out
    }

    /// Örneklenen parçaların hepsi köke doğrulanıyor mu?
    pub fn verify_sample(chunks: &[Vec<u8>], root: &[u8; 32], seed: u64, k: usize) -> bool {
        let root_computed = das_root(chunks);
        if root_computed != *root {
            return false;
        }
        for idx in Self::sample_indices(chunks.len(), k, seed) {
            let proof = match DasProof::prove(chunks, idx) {
                Some(p) => p,
                None => return false,
            };
            if !proof.verify(&chunks[idx], root) {
                return false;
            }
        }
        true
    }
}

/// Parça sahipliği kaydı (validatör beyanı - zincire yazılabilir).
#[derive(Debug, Clone)]
pub struct DasOwnership {
    pub validator_id: String,
    pub chunk_index: usize,
    pub chunk_hash: [u8; 32],
    pub ts_unix: u64,
}

impl DasOwnership {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_DAS_OWNER_V1";

    pub fn new(validator_id: &str, chunk_index: usize, chunk: &[u8], ts_unix: u64) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunk.len() as u64).to_le_bytes());
        h.update(chunk);
        DasOwnership {
            validator_id: validator_id.to_string(),
            chunk_index,
            chunk_hash: h.finalize().into(),
            ts_unix,
        }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.validator_id.len() as u64).to_le_bytes());
        h.update(self.validator_id.as_bytes());
        h.update((self.chunk_index as u32).to_le_bytes());
        h.update(self.chunk_hash);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// Validatör, beyan ettiği parçayı gerçekten tutuyor mu?
    pub fn verify_hold(&self, chunk: &[u8]) -> bool {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_DAS_LEAF_V1");
        h.update((chunk.len() as u64).to_le_bytes());
        h.update(chunk);
        let digest: [u8; 32] = h.finalize().into();
        digest == self.chunk_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_chunks(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 64]).collect()
    }

    #[test]
    fn merkle_root_and_single_proof() {
        let chunks = gen_chunks(8);
        let root = das_root(&chunks);
        assert_ne!(root, [0u8; 32]);
        // her yaprak için kanıt doğrulanır
        for i in 0..8 {
            let proof = DasProof::prove(&chunks, i).expect("kanıt");
            assert!(proof.verify(&chunks[i], &root), "yaprak {i} doğrulanır");
            // yanlış yaprak → RED
            assert!(!proof.verify(&chunks[(i + 1) % 8], &root));
        }
        // tek sayıda yaprak (çoğaltma)
        let chunks5 = gen_chunks(5);
        let root5 = das_root(&chunks5);
        for i in 0..5 {
            let p = DasProof::prove(&chunks5, i).unwrap();
            assert!(p.verify(&chunks5[i], &root5));
        }
    }

    #[test]
    fn das_sampling_verifies_full_data() {
        let chunks = gen_chunks(100);
        let root = das_root(&chunks);
        // 10 örnek yeterli
        assert!(DasSampler::verify_sample(&chunks, &root, 42, 10));
        // kurcalanmış parça → örnekleme RED
        let mut bad = chunks.clone();
        bad[50][0] ^= 0xFF;
        assert!(
            !DasSampler::verify_sample(&bad, &root, 42, 10),
            "bozuk parça yakalanır"
        );
        // farklı kök → RED
        assert!(!DasSampler::verify_sample(&chunks, &[0u8; 32], 42, 10));
        // indeksler deterministik + çakışmasız
        let a = DasSampler::sample_indices(100, 10, 7);
        let b = DasSampler::sample_indices(100, 10, 7);
        assert_eq!(a, b, "deterministik");
        let uniq: std::collections::HashSet<usize> = a.iter().cloned().collect();
        assert_eq!(uniq.len(), a.len(), "çakışmasız");
    }

    #[test]
    fn ownership_record() {
        let chunk = b"parca icerigi 1234";
        let rec = DasOwnership::new("validator-1", 3, chunk, 1_768_000_000);
        assert!(rec.verify_hold(chunk), "beyan edilen parça tutuluyor");
        assert!(!rec.verify_hold(b"farkli"), "farklı parça RED");
        // deterministik kayıt
        let rec2 = DasOwnership::new("validator-1", 3, chunk, 1_768_000_000);
        assert_eq!(rec.record_hash(), rec2.record_hash());
        assert_ne!(rec.record_hash(), [0u8; 32]);
        // blob roundtrip yok (kayıt basit alanlar) - hash doğrulaması yeterli
    }
}
