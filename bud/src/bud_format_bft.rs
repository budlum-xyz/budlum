//! BFT finality for the .bud compression ratio, decided by vote.
//!
//! Ratio engines produce candidates, validators sign them, and 2n/3 votes on
//! the same pipe_id finalise it.
//!
//! A vote counts only if its identity holds up: `validator_id` must be unique
//! (one validator cannot vote twice), and every vote's signature is verified
//! with ed25519 against the voter's own public key. A certificate that is
//! forged, or that cannot be verified, is refused.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[derive(Debug, Clone)]
pub struct RatioVote {
    pub validator_id: String,
    pub pipe_id: u16,
    pub ratio: f64,
    pub public_key: [u8; 32], // the ed25519 verifying key
    pub signature: Vec<u8>,   // the ed25519 signature, 64 bytes
}

impl RatioVote {
    /// The domain-tagged signing message: BDLM_BFT_VOTE_V1 || pipe_id || ratio.
    fn message(pipe_id: u16, ratio: f64) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 2 + 8);
        m.extend_from_slice(&b"BDLM_BFT_VOTE_V1"[..]);
        m.extend_from_slice(&pipe_id.to_le_bytes());
        m.extend_from_slice(&ratio.to_le_bytes());
        m
    }

    /// Verify the signature cryptographically (ed25519, strict).
    pub fn verify_signature(&self) -> Result<(), &'static str> {
        if self.signature.len() != 64 {
            return Err("K-BUD-BFT: a signature must be 64 bytes");
        }
        let vk = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| "K-BUD-BFT: invalid public key")?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature[..64]);
        let sig = Signature::from_bytes(&sig_bytes);
        let msg = Self::message(self.pipe_id, self.ratio);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| "K-BUD-BFT: signature did not verify")
    }

    /// Sign with a secret key.
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
        // Do they all name the same pipe_id?
        if !self.votes.iter().all(|v| v.pipe_id == self.pipe_id) {
            return Err("K-BUD-BFT: pipe_id mismatch");
        }
        // The finalised ratio has to be one a validator actually signed.
        //
        // This used to accept any vote within 0.01 of `self.ratio`, which
        // compares the votes against the claim instead of deriving the claim
        // from the votes. A certificate could then carry a number nobody
        // signed while every signature verified, because each validator had
        // signed its own measurement. Downstream reads `cert.ratio`, so that
        // forged value is the one that would be used.
        //
        // The comparison is on the bit pattern, not `==`: the signed message
        // covers `ratio.to_le_bytes()`, so bit equality is exactly what the
        // signature commits to, and it keeps NaN from comparing unequal to
        // itself.
        let claim = self.ratio.to_bits();
        if !self.votes.iter().any(|v| v.ratio.to_bits() == claim) {
            return Err("K-BUD-BFT: finalised ratio was signed by no validator");
        }
        // Every vote still has to agree on that ratio, bit for bit. A quorum
        // that signed different numbers has not agreed on one.
        if !self.votes.iter().all(|v| v.ratio.to_bits() == claim) {
            return Err("K-BUD-BFT: ratio mismatch");
        }
        // Validator uniqueness: one validator cannot cast two votes.
        let mut ids: Vec<&str> = self.votes.iter().map(|v| v.validator_id.as_str()).collect();
        ids.sort_unstable();
        let uniq = ids.windows(2).all(|w| w[0] != w[1]);
        if !uniq {
            return Err("K-BUD-BFT: duplicate validator");
        }
        // Every vote's signature is verified cryptographically.
        for v in &self.votes {
            v.verify_signature()?;
        }
        Ok(())
    }
}

pub struct BftRatioConsensus;

impl BftRatioConsensus {
    pub fn finalize_ratio(
        votes: Vec<RatioVote>,
        n: usize,
    ) -> Result<RatioFinalityCert, &'static str> {
        if votes.is_empty() {
            return Err("K-BUD-BFT: no votes");
        }
        // The pipe_id with the most votes
        use std::collections::HashMap;
        let mut counts: HashMap<u16, Vec<RatioVote>> = HashMap::new();
        for v in votes {
            counts.entry(v.pipe_id).or_default().push(v);
        }
        let (best_pipe, best_votes) = counts
            .into_iter()
            .max_by_key(|(_, vs)| vs.len())
            .ok_or("K-BUD-BFT: no best")?;
        let quorum = (n * 2).div_ceil(3);
        if best_votes.len() < quorum {
            return Err("K-BUD-BFT: no quorum");
        }
        let ratio = best_votes[0].ratio;
        Ok(RatioFinalityCert {
            pipe_id: best_pipe,
            ratio,
            votes: best_votes,
            quorum,
        })
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
    fn a_signed_certificate_is_accepted() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let votes = (0..4)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        let cert = BftRatioConsensus::finalize_ratio(votes, 5).unwrap();
        assert!(cert.verify(5).is_ok(), "a signed certificate is accepted");
    }

    #[test]
    fn a_forged_signature_is_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let mut votes: Vec<RatioVote> = (0..4)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        votes[0].signature = RatioVote::sign(&sk(9), 7, 16.68); // signed with a different key
        let cert = BftRatioConsensus::finalize_ratio(votes, 5).unwrap();
        assert!(
            cert.verify(5).is_err(),
            "a forged signature must be refused"
        );
    }

    #[test]
    fn a_repeated_validator_is_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4)];
        let v1 = vote("val-0", &sks[0], 7, 16.68);
        let v2 = vote("val-0", &sks[0], 7, 16.68); // the same validator!
        let v3 = vote("val-2", &sks[2], 7, 16.68);
        let v4 = vote("val-3", &sks[3], 7, 16.68);
        let cert = BftRatioConsensus::finalize_ratio(vec![v1, v2, v3, v4], 5).unwrap();
        assert!(
            cert.verify(5).is_err(),
            "a repeated validator must be refused"
        );
    }

    #[test]
    fn a_wrong_signature_length_is_refused() {
        let mut v = vote("val-0", &sk(1), 7, 16.68);
        v.signature = vec![0u8; 8];
        assert!(v.verify_signature().is_err());
    }

    /// A certificate must not publish a ratio that no vote attested to.
    ///
    /// `verify` is what a receiver calls on a certificate that arrived from
    /// somewhere else, and its ratio check was `|v.ratio - self.ratio| < 0.01`
    /// against every vote. That compares the votes to the claim instead of
    /// deriving the claim from the votes, so `self.ratio` could be a number
    /// nobody signed: every signature checks out, because each validator
    /// really did sign its own measurement. Downstream code reads
    /// `cert.ratio`, not the votes, so the forged value is the one that gets
    /// used.
    #[test]
    fn a_certificate_cannot_publish_a_ratio_nobody_signed() {
        let sks = [sk(1), sk(2), sk(3), sk(4)];
        // Four honest validators, each signing its own measurement. They sit
        // inside the old tolerance of each other.
        let spread = [16.680, 16.683, 16.685, 16.688];
        let votes: Vec<RatioVote> = (0..4)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, spread[i]))
            .collect();

        // A ratio no validator signed, within the tolerance of all of them.
        let forged = 16.684;
        assert!(
            !spread.contains(&forged),
            "the fixture is only meaningful if no vote carries this ratio"
        );
        let cert = RatioFinalityCert {
            pipe_id: 7,
            ratio: forged,
            votes,
            quorum: 3,
        };

        assert!(
            cert.verify(4).is_err(),
            "a certificate claiming {forged}, which no vote signed, was accepted"
        );
    }

    #[test]
    fn below_quorum_is_refused() {
        let sks = [sk(1), sk(2), sk(3)];
        let votes = (0..3)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        // 3/5 < 2n/3, so finalize already refuses at the quorum check
        assert!(
            BftRatioConsensus::finalize_ratio(votes, 5).is_err(),
            "3/5 is below 2n/3 and must be refused"
        );
    }
}
