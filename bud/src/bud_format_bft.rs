//! BFT finality for the .bud compression ratio, decided by vote.
//!
//! Ratio engines produce candidates, validators sign them, and more than two
//! thirds of the set voting for the same pipe_id finalise it.
//!
//! A vote counts only if its identity holds up: the voter's key must be one
//! of the registered validator keys, one key casts one vote, the signed
//! message names the voter, and every signature is verified with ed25519
//! against that key. A certificate that is forged, that cannot be verified,
//! or that a stranger to the validator set signed, is refused.
//!
//! The set is passed in as [`ValidatorSet`]. It used to be a bare count `n`:
//! a vote was checked against the key it carried itself, so whoever wrote the
//! certificate also chose who the validators were, and any fresh keys under
//! distinct ids reached the quorum.

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

/// The registered validators: the ed25519 verifying keys a vote may come
/// from. Quorum is two thirds of this set, rounded up.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    keys: Vec<[u8; 32]>,
}

impl ValidatorSet {
    /// A set of distinct keys; a repeated key is refused, since it would let
    /// one validator count twice.
    pub fn new(keys: Vec<[u8; 32]>) -> Result<Self, &'static str> {
        if keys.is_empty() {
            return Err("K-BUD-BFT: an empty validator set");
        }
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return Err("K-BUD-BFT: a validator key is registered twice");
        }
        Ok(Self { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The strict supermajority `n - f` with `f = (n - 1) / 3` faults
    /// tolerated, which is `floor(2n/3) + 1`.
    ///
    /// Two certificates from this quorum always share at least `f + 1`
    /// validators, so at least one honest one, and an honest validator
    /// signs one ratio per pipe. `ceil(2n/3)` was used before; for three
    /// validators that is two, and two certificates of two votes can
    /// overlap in the single Byzantine validator alone, so both could
    /// verify while the honest pair had signed different ratios.
    pub fn quorum(&self) -> usize {
        let n = self.keys.len();
        n - (n - 1) / 3
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(key)
    }
}

impl RatioVote {
    /// The domain-tagged signing message:
    /// BDLM_BFT_VOTE_V2 || len(validator_id) || validator_id || pipe_id || ratio.
    /// The voter's id is inside the message, so one signature cannot be
    /// reused under another id.
    fn message(validator_id: &str, pipe_id: u16, ratio: f64) -> Vec<u8> {
        let mut m = Vec::with_capacity(16 + 4 + validator_id.len() + 2 + 8);
        m.extend_from_slice(&b"BDLM_BFT_VOTE_V2"[..]);
        m.extend_from_slice(&(validator_id.len() as u32).to_le_bytes());
        m.extend_from_slice(validator_id.as_bytes());
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
        let msg = Self::message(&self.validator_id, self.pipe_id, self.ratio);
        vk.verify_strict(&msg, &sig)
            .map_err(|_| "K-BUD-BFT: signature did not verify")
    }

    /// Sign with a secret key, as the named validator.
    pub fn sign(sk: &SigningKey, validator_id: &str, pipe_id: u16, ratio: f64) -> Vec<u8> {
        sk.sign(&Self::message(validator_id, pipe_id, ratio))
            .to_bytes()
            .to_vec()
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
    /// Check the certificate against the registered validators. The votes have
    /// to reach the set's quorum, come from distinct keys inside the set, name
    /// the same pipe and the same ratio the certificate publishes, and carry
    /// signatures that verify.
    pub fn verify(&self, validators: &ValidatorSet) -> Result<(), &'static str> {
        let quorum = validators.quorum();
        if self.votes.len() < quorum {
            return Err("K-BUD-BFT: votes below the supermajority quorum");
        }
        if self.quorum != quorum {
            return Err("K-BUD-BFT: certificate quorum does not match the validator set");
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
        // Membership and uniqueness are decided on the key, not on the id a
        // vote names for itself: the id is free text, the key is what the
        // set registered. One key casts one vote.
        for v in &self.votes {
            if !validators.contains(&v.public_key) {
                return Err("K-BUD-BFT: vote from a key outside the validator set");
            }
        }
        let mut keys: Vec<&[u8; 32]> = self.votes.iter().map(|v| &v.public_key).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err("K-BUD-BFT: duplicate validator");
        }
        // Every vote's signature is verified cryptographically, over a message
        // that names the voter.
        for v in &self.votes {
            v.verify_signature()?;
        }
        Ok(())
    }
}

pub struct BftRatioConsensus;

impl BftRatioConsensus {
    /// Group the votes by pipe, take the pipe with the most votes, and issue
    /// a certificate if that group reaches quorum. The certificate is what
    /// `verify` checks; a vote from outside the set never reaches the count.
    pub fn finalize_ratio(
        votes: Vec<RatioVote>,
        validators: &ValidatorSet,
    ) -> Result<RatioFinalityCert, &'static str> {
        if votes.is_empty() {
            return Err("K-BUD-BFT: no votes");
        }
        if votes.iter().any(|v| !validators.contains(&v.public_key)) {
            return Err("K-BUD-BFT: vote from a key outside the validator set");
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
        let quorum = validators.quorum();
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

    fn set(sks: &[SigningKey]) -> ValidatorSet {
        ValidatorSet::new(sks.iter().map(|k| k.verifying_key().to_bytes()).collect()).unwrap()
    }

    fn vote(id: &str, sk: &SigningKey, pipe: u16, ratio: f64) -> RatioVote {
        let vk = sk.verifying_key().to_bytes();
        RatioVote {
            validator_id: id.to_string(),
            pipe_id: pipe,
            ratio,
            public_key: vk,
            signature: RatioVote::sign(sk, id, pipe, ratio),
        }
    }

    #[test]
    fn a_signed_certificate_is_accepted() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let validators = set(&sks);
        let votes = (0..4)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        let cert = BftRatioConsensus::finalize_ratio(votes, &validators).unwrap();
        assert!(
            cert.verify(&validators).is_ok(),
            "a signed certificate is accepted"
        );
    }

    #[test]
    fn a_forged_signature_is_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let validators = set(&sks);
        let mut votes: Vec<RatioVote> = (0..4)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        votes[0].signature = RatioVote::sign(&sk(9), "val-0", 7, 16.68); // signed with a different key
        let cert = BftRatioConsensus::finalize_ratio(votes, &validators).unwrap();
        assert!(
            cert.verify(&validators).is_err(),
            "a forged signature must be refused"
        );
    }

    /// The same key voting twice, under the same id or under two ids, counts
    /// once at most: uniqueness is on the key. With the id in the signed
    /// message the second copy does not even verify.
    #[test]
    fn a_repeated_validator_is_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let validators = set(&sks);
        let v1 = vote("val-0", &sks[0], 7, 16.68);
        let v2 = vote("val-0", &sks[0], 7, 16.68); // the same validator!
        let v3 = vote("val-2", &sks[2], 7, 16.68);
        let v4 = vote("val-3", &sks[3], 7, 16.68);
        let cert = BftRatioConsensus::finalize_ratio(
            vec![v1.clone(), v2, v3.clone(), v4.clone()],
            &validators,
        )
        .unwrap();
        assert!(
            cert.verify(&validators).is_err(),
            "a repeated validator must be refused"
        );
        // the same signature copied under a second id
        let mut copy = v1.clone();
        copy.validator_id = "val-1".to_string();
        let cert = RatioFinalityCert {
            pipe_id: 7,
            ratio: 16.68,
            votes: vec![v1, copy, v3, v4],
            quorum: validators.quorum(),
        };
        assert!(
            cert.verify(&validators).is_err(),
            "one signature under two ids must be refused"
        );
    }

    /// Keys the set never registered reach neither `finalize_ratio` nor
    /// `verify`, however many of them there are and whatever ids they carry.
    /// This is the case that used to pass: the count `n` came from the caller
    /// and every vote vouched for itself.
    #[test]
    fn votes_from_outside_the_validator_set_are_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let validators = set(&sks);
        let strangers: Vec<RatioVote> = (10u8..15)
            .map(|i| vote(&format!("val-{i}"), &sk(i), 7, 16.68))
            .collect();
        assert!(
            BftRatioConsensus::finalize_ratio(strangers.clone(), &validators).is_err(),
            "strangers must not finalise a ratio"
        );
        let cert = RatioFinalityCert {
            pipe_id: 7,
            ratio: 16.68,
            votes: strangers,
            quorum: validators.quorum(),
        };
        assert!(
            cert.verify(&validators).is_err(),
            "a certificate signed by strangers must be refused"
        );
        // three members plus one stranger: the member votes are below quorum
        let mut mixed: Vec<RatioVote> = (0..3)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        mixed.push(vote("val-x", &sk(20), 7, 16.68));
        let cert = RatioFinalityCert {
            pipe_id: 7,
            ratio: 16.68,
            votes: mixed,
            quorum: validators.quorum(),
        };
        assert!(cert.verify(&validators).is_err());
    }

    #[test]
    fn a_duplicate_key_cannot_be_registered() {
        let k = sk(1).verifying_key().to_bytes();
        assert!(ValidatorSet::new(vec![k, k]).is_err());
        assert!(ValidatorSet::new(vec![]).is_err());
        let one = ValidatorSet::new(vec![k]).unwrap();
        assert_eq!(one.quorum(), 1);
        assert_eq!(set(&[sk(1), sk(2), sk(3), sk(4), sk(5)]).quorum(), 4);
    }

    /// The quorum is a strict supermajority: any two quorums share an honest
    /// validator. `ceil(2n/3)` gave two of three and four of six, where two
    /// certificates can overlap in the one Byzantine validator alone.
    #[test]
    fn the_quorum_is_a_strict_supermajority() {
        assert_eq!(set(&[sk(1), sk(2), sk(3)]).quorum(), 3);
        assert_eq!(set(&[sk(1), sk(2), sk(3), sk(4)]).quorum(), 3);
        assert_eq!(set(&[sk(1), sk(2), sk(3), sk(4), sk(5), sk(6)]).quorum(), 5);
        assert_eq!(
            set(&[sk(1), sk(2), sk(3), sk(4), sk(5), sk(6), sk(7)]).quorum(),
            5
        );
        for n in 1..=40usize {
            let keys: Vec<SigningKey> = (1..=n as u8).map(sk).collect();
            let q = set(&keys).quorum();
            let f = (n - 1) / 3;
            assert!(
                2 * q > n + f,
                "n={n}: two quorums of {q} may miss every honest validator"
            );
            assert_eq!(q, n * 2 / 3 + 1, "n={n}");
        }
    }

    /// Three validators, one of them signing both sides: with a quorum of
    /// two, both certificates verified. With three, neither does.
    #[test]
    fn two_conflicting_certificates_cannot_both_verify() {
        let sks = [sk(1), sk(2), sk(3)];
        let validators = set(&sks);
        let left = vec![
            vote("val-0", &sks[0], 7, 16.68),
            vote("val-1", &sks[1], 7, 16.68),
        ];
        let right = vec![
            vote("val-1", &sks[1], 7, 12.5),
            vote("val-2", &sks[2], 7, 12.5),
        ];
        for votes in [left, right] {
            let ratio = votes[0].ratio;
            let cert = RatioFinalityCert {
                pipe_id: 7,
                ratio,
                votes,
                quorum: validators.quorum(),
            };
            assert!(
                cert.verify(&validators).is_err(),
                "a two-vote certificate for {ratio} verified against three validators"
            );
        }
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
        let validators = set(&sks);
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
            cert.verify(&validators).is_err(),
            "a certificate claiming {forged}, which no vote signed, was accepted"
        );
    }

    #[test]
    fn below_quorum_is_refused() {
        let sks = [sk(1), sk(2), sk(3), sk(4), sk(5)];
        let validators = set(&sks);
        let votes = (0..3)
            .map(|i| vote(&format!("val-{i}"), &sks[i], 7, 16.68))
            .collect();
        // 3 of 5 is below the quorum of 4, so finalize refuses at the quorum check
        assert!(
            BftRatioConsensus::finalize_ratio(votes, &validators).is_err(),
            "3 of 5 is below the supermajority quorum and must be refused"
        );
    }
}
