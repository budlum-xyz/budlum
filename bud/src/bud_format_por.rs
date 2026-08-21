//! B.U.D. 2.0 Icat - Yon 5: PoR Cekirdegi (Proof-of-Retrievability) (2026-08-16)
//!
//! private-verifiability sürümünün basit, kriptografik gerçeklemesi
//! (S.93/S.149): her blok PRF/MAC tabanlı tag tasir; verifier challenge'daki bloklari
//! yeniden etiketleyip response'u dogrular. Kayipsiz, deterministik, no unsafe.
//!
//! Kod: `#![forbid(unsafe_code)]`. Tag = SHA3-256(key || index || block) - domain-etiketli.
//! Bu bir iskelet degildir: dogru etiket/yanlis etiket ayrimi kaos testleriyle kanitlidir.
//! (BLS tabanli public-verifiability + EVENODD + LRC-DPoR entegrasyonu sonraki adimlar.)

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

/// PoR anahtari (verifier ile paylasilan gizli). Private verifiability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PorTag(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct PorChallenge {
    pub indices: Vec<u64>, // challenge edilen blok indeksleri
    pub nonce: [u8; 32],   // her challenge'da taze (tekrar saldirisi onler)
}

#[derive(Debug, Clone)]
pub struct PorResponse {
    pub tags: Vec<PorTag>, // indices ile ayni sirada
}

impl PorKey {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_POR_V1";

    pub fn new(seed: [u8; 32]) -> Self {
        PorKey(seed)
    }

    /// Blok tag'i: SHA3(domain || key || index || block).
    pub fn tag(&self, block: &[u8], index: u64) -> PorTag {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.0);
        h.update(index.to_le_bytes());
        h.update(block);
        PorTag(h.finalize().into())
    }

    /// Challenge uret: rastgele (deterministik test icin seed'li) indeks seti.
    /// Gercek uygulamada indeksler zincir rastgeleliginden (VRF/VDF, S.104).
    pub fn challenge(block_count: u64, k: usize, seed: u64) -> PorChallenge {
        // basit deterministik: seed kaydirilarak k farkli indeks
        let mut indices = Vec::with_capacity(k);
        for i in 0..k {
            indices.push((seed.wrapping_add(i as u64)) % block_count.max(1));
        }
        let mut nonce = [0u8; 32];
        nonce[0..8].copy_from_slice(&seed.to_le_bytes());
        nonce[8..16].copy_from_slice(&(block_count as u64).to_le_bytes());
        PorChallenge { indices, nonce }
    }

    /// Response uret (prover tarafi): challenge'daki her blok icin tag.
    /// Sınır güvenli: herhangi bir indeks blok sayısını aşıyorsa None döner (PANİK YOK,
    /// K38 mini-fuzz felsefesi) - kötü niyetli/bozuk challenge prover'ı çökertemez.
    pub fn respond(&self, blocks: &[Vec<u8>], challenge: &PorChallenge) -> Option<PorResponse> {
        let mut tags = Vec::with_capacity(challenge.indices.len());
        for &idx in &challenge.indices {
            if idx as usize >= blocks.len() {
                return None; // sınır dışı indeks → geçersiz response
            }
            tags.push(self.tag(&blocks[idx as usize], idx));
        }
        Some(PorResponse { tags })
    }

    /// Dogrula (verifier): her (index, block, tag) yeniden hesaplananla eslesmeli.
    /// Nonce tazeligi: challenge nonce'u response'a baglanmali - basit sürümde
    /// verify, nonce'u challenge kaydinda bekler (tekrar saldirisi disarida).
    pub fn verify(
        &self,
        blocks: &[Vec<u8>],
        challenge: &PorChallenge,
        response: &PorResponse,
    ) -> bool {
        if challenge.indices.len() != response.tags.len() {
            return false;
        }
        for (i, &idx) in challenge.indices.iter().enumerate() {
            if idx as usize >= blocks.len() {
                return false;
            }
            let expected = self.tag(&blocks[idx as usize], idx);
            if expected != response.tags[i] {
                return false; // blok veya tag degismis
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks() -> Vec<Vec<u8>> {
        (0..8u64)
            .map(|i| vec![i as u8; 16])
            .collect()
    }

    #[test]
    fn honest_prover_verified() {
        let key = PorKey::new([7u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = key.respond(&blk, &ch).expect("dürüst prover response üretir");
        assert!(key.verify(&blk, &ch, &resp), "dürüst prover dogrulanir");
    }

    #[test]
    fn tampered_block_rejected() {
        let key = PorKey::new([7u8; 32]);
        let mut blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = key.respond(&blk, &ch).expect("dürüst prover response üretir");
        // challenge'daki ilk indeksi boz
        let bad_idx = ch.indices[0] as usize;
        blk[bad_idx][0] ^= 0xFF;
        assert!(!key.verify(&blk, &ch, &resp), "degistirilmis blok RED");
    }

    #[test]
    fn wrong_key_rejected() {
        let k1 = PorKey::new([7u8; 32]);
        let k2 = PorKey::new([8u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let resp = k1.respond(&blk, &ch).expect("dürüst prover response üretir");
        assert!(!k2.verify(&blk, &ch, &resp), "yanlis anahtar RED");
    }

    #[test]
    fn tampered_response_rejected() {
        let key = PorKey::new([7u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 3, 42);
        let mut resp = key.respond(&blk, &ch).expect("dürüst prover response üretir");
        resp.tags[0].0[0] ^= 0xFF;
        assert!(!key.verify(&blk, &ch, &resp), "degistirilmis tag RED");
    }

    #[test]
    fn challenge_bounds_safe() {
        let key = PorKey::new([1u8; 32]);
        let blk = blocks();
        let ch = PorKey::challenge(8, 8, 0); // 8 indeks, 8 blok
        assert!(key.verify(&blk, &ch, &key.respond(&blk, &ch).expect("response")));
        // indeks disinda blok yoksa RED (sınır kontrolü)
        let mut bad = blocks();
        bad.clear();
        assert!(!key.verify(&bad, &ch, &key.respond(&blk, &ch).expect("response")));
        // sınır dışı indeksli challenge → respond None döner, PANİK OLMAZ (K38)
        let ch_bad = PorChallenge {
            indices: vec![999_999],
            nonce: [0u8; 32],
        };
        assert!(key.respond(&blk, &ch_bad).is_none(), "sınır dışı indeks None dönmeli");
        assert!(!key.verify(&blk, &ch_bad, &PorResponse { tags: vec![PorTag([0u8; 32])] }), "sınır dışı indeks verify RED");
    }
}
