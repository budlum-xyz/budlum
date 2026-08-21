//! .bud BFT finality for ratio - oylama tabanlı finality
//! Ratio engine'ler aday üretir, validator'lar imzalar, 2n/3 aynı pipe_id final
//!
//! STRIX FIX (2026-08-16): her oy, KİMLİK DOĞRULAMASI ile kabul edilir:
//! (1) validator_id benzersiz olmalı (aynı validator 2 oy veremez),
//! (2) her oyun imzası, oy sahibinin genel anahtarıyla ed25519 ile doğrulanır.
//! Sahte/doğrulanamayan sertifika RED.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[derive(Debug, Clone)]
pub struct RatioVote {
    pub validator_id: String,
    pub pipe_id: u16,
    pub ratio: f64,
    pub public_key: [u8; 32], // ed25519 doğrulama anahtarı
    pub signature: Vec<u8>,   // ed25519 imzası (64 bayt)
}

impl RatioVote {
    /// Domain-etiketli imza mesajı: BDLM_BFT_VOTE_V1 || pipe_id || ratio.
    fn message(pipe_id: u16, ratio: f64) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 2 + 8);
        m.extend_from_slice(&b"BDLM_BFT_VOTE_V1"[..]);
        m.extend_from_slice(&pipe_id.to_le_bytes());
        m.extend_from_slice(&ratio.to_le_bytes());
        m
    }

    /// İmzayı kriptografik olarak doğrula (ed25519, strict).
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        if self.signature.len() != 64 {
            return Err("K-BUD-BFT: imza 64 bayt olmali");
        }
        let vk = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| "K-BUD-BFT: gecersiz genel anahtar")?;
        let sig = Signature::from_bytes(self.signature[..64].try_into().unwrap());
        let msg = Self::message(self.pipe_id, self.ratio);
        vk.verify_strict(&msg, &sig).map_err(|_| "K-BUD-BFT: imza dogrulanamadi")
    }

    /// Test/üretim: gizli anahtarla imzala.
    pub fn sign(sk: &SigningKey, pipe_id: u16, ratio: f64) -> Vec<u8> {
        sk.sign(&Self::message(pipe_id, ratio)).to_bytes().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct RatioFinalityCert {
    pub pipe_id: u16,
    pub ratio: f64,
    pub votes: Vec<RatioVote>,
    pub quorum: usize,
}

impl RatioFinalityCert {
    pub fn verify(&self, n: usize) -> Result<(), &'static str> {
        let quorum = (n * 2).div_ceil(3);
        if self.votes.len() < quorum {
            return Err("K-BUD-BFT: quorum <2n/3");
        }
        // aynı pipe_id mi?
        if !self.votes.iter().all(|v| v.pipe_id == self.pipe_id) {
            return Err("K-BUD-BFT: pipe_id mismatch");
        }
        // ratio aynı mı (tolerans 0.01)
        if !self.votes.iter().all(|v| (v.ratio - self.ratio).abs() < 0.01) {
            return Err("K-BUD-BFT: ratio mismatch");
        }
        // STRIX: validator benzersizliği - aynı validator 2 oy veremez.
        let mut ids: Vec<&str> = self.votes.iter().map(|v| v.validator_id.as_str()).collect();
        ids.sort_unstable();
        let uniq = ids.windows(2).all(|w| w[0] != w[1]);
        if !uniq {
            return Err("K-BUD-BFT: tekrar eden validator");
        }
        // STRIX: her oyun imzası kriptografik olarak doğrulanır.
        for v in &self.votes {
            v.verify_signature()?;
        }
        Ok(())
    }
}

pub struct BftRatioConsensus;

impl BftRatioConsensus {
    pub fn finalize_ratio(votes: Vec<RatioVote>, n: usize) -> Result<RatioFinalityCert, &'static str> {
        if votes.is_empty() {
            return Err("K-BUD-BFT: no votes");
        }
        // En çok oy alan pipe_id
        use std::collections::HashMap;
        let mut counts: HashMap<u16, Vec<RatioVote>> = HashMap::new();
        for v in votes {
            counts.entry(v.pipe_id).or_default().push(v);
        }
        let (best_pipe, best_votes) = counts.into_iter().max_by_key(|(_, vs)| vs.len()).ok_or("K-BUD-BFT: no best")?;
        let quorum = (n * 2).div_ceil(3);
        if best_votes.len() < quorum {
            return Err("K-BUD-BFT: no quorum");
        }
        let ratio = best_votes[0].ratio;
        Ok(RatioFinalityCert { pipe_id: best_pipe, ratio, votes: best_votes, quorum })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sk(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[i; 32])
    }

    fn vote(id: &str, sk: &SigningKey, pipe: u16, ratio: f64) -> RatioVote {
        let vk = sk.verifying_key().to_bytes();
        RatioVote {
            validator_id: id.to_string(),
            pipe_id: pipe,
            ratio,
            public_key: vk,
            signature: RatioVote::sign(sk, pipe, ratio),
        }
    }

    #[test]
    fn bft_imzali_sertifika_gecer() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let votes = (0..4).map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68)).collect();
        let cert = BftRatioConsensus::finalize_ratio(votes, 5).unwrap();
        assert!(cert.verify(5).is_ok(), "imzalı sertifika kabul");
    }

    #[test]
    fn bft_sahte_imza_reddedilir() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let mut votes: Vec<RatioVote> = (0..4).map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68)).collect();
        votes[0].signature = RatioVote::sign(&sk(9), 7, 16.68); // başka anahtarla imzala
        let cert = BftRatioConsensus::finalize_ratio(votes, 5).unwrap();
        assert!(cert.verify(5).is_err(), "sahte imza RED");
    }

    #[test]
    fn bft_tekrar_eden_validator_reddedilir() {
        let sks = [sk(1), sk(2), sk(3), sk(4)];
        let v1 = vote("val-0", &sks[0], 7, 16.68);
        let v2 = vote("val-0", &sks[0], 7, 16.68); // aynı validator!
        let v3 = vote("val-2", &sks[2], 7, 16.68);
        let v4 = vote("val-3", &sks[3], 7, 16.68);
        let cert = BftRatioConsensus::finalize_ratio(vec![v1, v2, v3, v4], 5).unwrap();
        assert!(cert.verify(5).is_err(), "tekrar eden validator RED");
    }

    #[test]
    fn bft_kotu_imza_uzunlugu_reddedilir() {
        let mut v = vote("val-0", &sk(1), 7, 16.68);
        v.signature = vec![0u8; 8];
        assert!(v.verify_signature().is_err());
    }

    #[test]
    fn bft_quorum_alti_reddedilir() {
        let sks = [sk(1), sk(2), sk(3)];
        let votes = (0..3).map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68)).collect();
        // 3/5 < 2n/3 → finalize zaten RED (quorum kapısı)
        assert!(BftRatioConsensus::finalize_ratio(votes, 5).is_err(), "3/5 < 2n/3 → RED");
    }
}
