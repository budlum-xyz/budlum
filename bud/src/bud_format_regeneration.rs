//! B.U.D. 2.0 INVENTION - Regeneration-as-Consensus (2026-08-16)
//!
//! ideas2.0 I2 + the STORAGE-ZERO ARCHITECTURE THESIS: instead of "prove the
//! byte" (PoR/PoSt), consensus says **"verify the production"**: on demand the
//! validator produces the content from the producer, hashes it, and compares it
//! with the PACT commitment; the match is consensus itself.
//!
//! Why this is "new on a blockchain": existing approaches say "store+prove",
//! "store+BFT attestation", "store+proof of access", "compute+prove" (proving is
//! expensive) and "store events+recompute state" (the event log is permanent).
//! **None of them** says "the content byte is never stored; a production match
//! is the consensus verification".
//!
//! This module: a challenge -> produce -> hash -> compare with the commitment ->
//! a result. The challenge is not written on chain; only the result hash is kept
//! for audit (I2). A failed production lowers the reputation score (the
//! provider.rs pattern).
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, panic free.

#![forbid(unsafe_code)]

use crate::bud_format_pact::PactRecord;
use sha3::{Digest, Sha3_256};

pub const REGEN_MAGIC: [u8; 8] = *b"\xB5RGEN\0\0\0";
pub const REGEN_VERSION: u8 = 1;

/// The challenge result (I2): did the production consensus pass, and at what cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegenerationOutcome {
    Verified,      // the production matched the commitment -> consensus
    Mismatch,      // the production did not match the commitment -> REFUSED, reputation drops
    NotProducible, // the producer could not produce (a class lie or a broken producer)
}

/// The regeneration challenge: verify the produced bytes against the given
/// PACT. The I2 thesis is "the cost of producing is below the cost of proving" -
/// this function measures that cost.
pub struct RegenerationChallenge;

impl RegenerationChallenge {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_REGENERATION_V1";

    /// Verify the produced bytes against the PACT commitment (the core of I2).
    /// - PureProduction/RecipePlusResidual: commitment = H(produced bytes)
    /// - ResidualOnly: commitment = content_id(original) (lossless integrity)
    pub fn verify(pact: &PactRecord, produced: &[u8]) -> RegenerationOutcome {
        if !pact.verify() {
            return RegenerationOutcome::NotProducible;
        }
        if pact.verify_production(produced) {
            RegenerationOutcome::Verified
        } else {
            RegenerationOutcome::Mismatch
        }
    }

    /// Residual integrity: does the remainder that cannot be produced match the
    /// commitment (I6)? In RecipePlusResidual mode the residual must be verified
    /// too - a class lie is caught this way.
    pub fn verify_with_residual(
        pact: &PactRecord,
        produced: &[u8],
        residual: &[u8],
    ) -> RegenerationOutcome {
        match pact.verify() {
            false => RegenerationOutcome::NotProducible,
            true => {
                if pact.verify_production(produced) && pact.verify_residual(residual) {
                    RegenerationOutcome::Verified
                } else {
                    RegenerationOutcome::Mismatch
                }
            }
        }
    }

    /// The challenge record: epoch + pact_hash + result + cost (for audit, writable on chain).
    pub fn record_hash(
        epoch: u64,
        pact_hash: [u8; 32],
        outcome: RegenerationOutcome,
        cost_units: u64,
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(epoch.to_le_bytes());
        h.update(pact_hash);
        h.update([match outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        }]);
        h.update(cost_units.to_le_bytes());
        h.finalize().into()
    }

    /// The I2 acceptance rule: the cost of producing must be below 1 percent of
    /// the corresponding proving cost. (A zkVM proof is worth 222 years of
    /// storage - the STORAGE-ZERO measurement; producing costs about as much as
    /// reading.)
    pub fn regeneration_beats_proof(production_cost: u64, proof_cost: u64) -> bool {
        proof_cost > 0 && (production_cost as f64) < (proof_cost as f64) * 0.01
    }
}

/// The regeneration consensus record (a small on-chain record - within the I8 byte budget).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegenerationRecord {
    pub epoch: u64,
    pub pact_hash: [u8; 32],
    pub outcome: RegenerationOutcome,
    pub cost_units: u64,
}

impl RegenerationRecord {
    pub fn new(
        epoch: u64,
        pact_hash: [u8; 32],
        outcome: RegenerationOutcome,
        cost_units: u64,
    ) -> Self {
        RegenerationRecord {
            epoch,
            pact_hash,
            outcome,
            cost_units,
        }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        RegenerationChallenge::record_hash(
            self.epoch,
            self.pact_hash,
            self.outcome,
            self.cost_units,
        )
    }

    /// A deterministic blob (magic + version + fields + digest).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&REGEN_MAGIC);
        out.push(REGEN_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.pact_hash);
        out.push(match self.outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        });
        out.extend_from_slice(&self.cost_units.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 8 + 32 + 1 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != REGEN_MAGIC || bytes[8] != REGEN_VERSION {
            return None;
        }
        let epoch = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let mut pact_hash = [0u8; 32];
        pact_hash.copy_from_slice(&bytes[17..49]);
        let outcome = match bytes[49] {
            0 => RegenerationOutcome::Verified,
            1 => RegenerationOutcome::Mismatch,
            2 => RegenerationOutcome::NotProducible,
            _ => return None,
        };
        let cost_units = u64::from_le_bytes(bytes[50..58].try_into().ok()?);
        if bytes.len() != HDR + 32 {
            return None;
        }
        let rec = RegenerationRecord {
            epoch,
            pact_hash,
            outcome,
            cost_units,
        };
        if bytes[HDR..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }
}

// ---------------------------------------------------------------------------
// challenge selection from the Filiz epoch randomness, a
// result record signed with suite 0x0002 (ML-DSA-65 + Ed25519, validator
// suite), and reputation that moves only on a verified signed result.

use crate::bud_format_pact::{SignedRecordError, SuiteSigner, SuiteVerifier};
use std::collections::{BTreeMap, BTreeSet};

/// The composite suite of a regeneration result.
/// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
pub const RESULT_SUITE: u16 = 0x0002;
/// Domain tag of the signed result payload.
/// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
pub const RESULT_SIGN_DOMAIN: &[u8] = b"BDLM_BUD_REGEN_RESULT_V2";
/// Tag of the digest a ledger remembers for a signed result it has applied, so
/// replaying the same envelope cannot move a score twice.
const APPLIED_DOMAIN: &[u8] = b"BDLM_BUD_REGEN_APPLIED_V1";
const SELECT_DOMAIN: &[u8] = b"BDLM_BUD_REGEN_SELECT_V1";

/// Pick `count` distinct PACT records to challenge in `epoch`.
///
/// `epoch_randomness` is `consensus::filiz::epoch_randomness` of the epoch: it
/// is fixed by canonical reveals before anybody knows which PACT it picks, and
/// no single validator chose it. `pact_hashes` must be in the canonical
/// (sorted) order every validator holds. The result is a list of indexes into
/// it, in selection order; the same inputs give the same list everywhere.
#[must_use]
/// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
pub fn select_challenges(
    epoch_randomness: &[u8; 32],
    epoch: u64,
    pact_hashes: &[[u8; 32]],
    count: usize,
) -> Vec<usize> {
    let n = pact_hashes.len();
    let want = count.min(n);
    let mut picked: Vec<usize> = Vec::with_capacity(want);
    if want == 0 {
        return picked;
    }
    let mut counter: u64 = 0;
    // Bounded draw: rejection of repeats terminates quickly for want <= n,
    // and the bound keeps the worst case fixed.
    let limit = (want as u64).saturating_mul(64).saturating_add(64);
    while picked.len() < want && counter < limit {
        let mut h = Sha3_256::new();
        h.update(SELECT_DOMAIN);
        h.update(epoch_randomness);
        h.update(epoch.to_le_bytes());
        h.update((n as u64).to_le_bytes());
        h.update(counter.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut word = [0u8; 8];
        word.copy_from_slice(&digest[..8]);
        let index = (u64::from_le_bytes(word) % n as u64) as usize;
        if !picked.contains(&index) {
            picked.push(index);
        }
        counter += 1;
    }
    // Deterministic completion: the smallest indexes not yet picked.
    let mut next = 0usize;
    while picked.len() < want {
        if !picked.contains(&next) {
            picked.push(next);
        }
        next += 1;
    }
    picked
}

/// A regeneration result with the validator's suite 0x0002 signature.
///
/// The envelope names the provider the result is about, and the signature
/// covers that name. A result signed for one provider therefore cannot move
/// another provider's reputation: the provider is read from the envelope, never
/// from a caller argument.
#[derive(Debug, Clone, PartialEq, Eq)]
/// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
pub struct SignedRegenerationResult {
    pub record: RegenerationRecord,
    pub validator: [u8; 32],
    /// The provider this result scores, attested by the signature.
    pub provider: [u8; 32],
    pub suite: u16,
    pub signature: Vec<u8>,
}

impl SignedRegenerationResult {
    /// The bytes that are signed: tag, suite, validator, provider, record blob.
    #[must_use]
    pub fn payload(
        suite: u16,
        validator: &[u8; 32],
        provider: &[u8; 32],
        record: &RegenerationRecord,
    ) -> Vec<u8> {
        let blob = record.to_blob();
        let mut out = Vec::with_capacity(RESULT_SIGN_DOMAIN.len() + 2 + 32 + 32 + blob.len());
        out.extend_from_slice(RESULT_SIGN_DOMAIN);
        out.extend_from_slice(&suite.to_be_bytes());
        out.extend_from_slice(validator);
        out.extend_from_slice(provider);
        out.extend_from_slice(&blob);
        out
    }

    /// Sign `record`; the signer must be a [`RESULT_SUITE`] signer.
    ///
    /// # Errors
    ///
    /// [`SignedRecordError::WrongSuite`] or [`SignedRecordError::SigningFailed`].
    pub fn sign(
        record: RegenerationRecord,
        provider: [u8; 32],
        signer: &dyn SuiteSigner,
    ) -> Result<Self, SignedRecordError> {
        if signer.suite() != RESULT_SUITE {
            return Err(SignedRecordError::WrongSuite {
                got: signer.suite(),
            });
        }
        let validator = signer.signer_id();
        let payload = Self::payload(RESULT_SUITE, &validator, &provider, &record);
        let signature = signer
            .sign(&payload)
            .ok_or(SignedRecordError::SigningFailed)?;
        Ok(Self {
            record,
            validator,
            provider,
            suite: RESULT_SUITE,
            signature,
        })
    }

    /// Check the suite and the signature.
    ///
    /// # Errors
    ///
    /// [`SignedRecordError::WrongSuite`] for any suite but 0x0002,
    /// [`SignedRecordError::BadSignature`] when verification fails.
    pub fn verify(&self, verifier: &dyn SuiteVerifier) -> Result<(), SignedRecordError> {
        if self.suite != RESULT_SUITE {
            return Err(SignedRecordError::WrongSuite { got: self.suite });
        }
        let payload = Self::payload(self.suite, &self.validator, &self.provider, &self.record);
        if verifier.verify(self.suite, &self.validator, &payload, &self.signature) {
            Ok(())
        } else {
            Err(SignedRecordError::BadSignature)
        }
    }
}

/// The reputation of providers. It moves only through [`Self::apply`], which
/// takes a verified [`SignedRegenerationResult`] for the provider the signature
/// names, once: an unsigned, wrongly signed or classically signed result changes
/// nothing, and a result that was already applied moves nothing.
#[derive(Debug, Clone, Default)]
/// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
pub struct ReputationLedger {
    scores: BTreeMap<[u8; 32], i64>,
    applied: BTreeSet<[u8; 32]>,
}

impl ReputationLedger {
    /// Score gained for a verified production.
    /// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
    pub const REWARD: i64 = 1;
    /// Score lost for a mismatch or a producer that cannot produce.
    /// exposed for: the bud format crate's signed-record surface - the consumers land with the format adoption.
    pub const PENALTY: i64 = 10;

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The score of `provider`, zero when unknown.
    #[must_use]
    pub fn score(&self, provider: &[u8; 32]) -> i64 {
        self.scores.get(provider).copied().unwrap_or(0)
    }

    /// Apply `result` to the provider the signature attests, at most once.
    ///
    /// The provider is read from the signed envelope, never from a caller
    /// argument, so a result signed for one provider cannot move the score of
    /// another. The digest of the signed payload is remembered, so the same
    /// signed result moves a score exactly once.
    ///
    /// # Errors
    ///
    /// The refusal of [`SignedRegenerationResult::verify`]; the ledger is
    /// unchanged then.
    pub fn apply(
        &mut self,
        result: &SignedRegenerationResult,
        verifier: &dyn SuiteVerifier,
    ) -> Result<i64, SignedRecordError> {
        result.verify(verifier)?;
        let mut h = Sha3_256::new();
        h.update(APPLIED_DOMAIN);
        h.update(SignedRegenerationResult::payload(
            result.suite,
            &result.validator,
            &result.provider,
            &result.record,
        ));
        let digest: [u8; 32] = h.finalize().into();
        if !self.applied.insert(digest) {
            // Already counted. Report the score as it stands; nothing moves.
            return Ok(self.score(&result.provider));
        }
        let delta = match result.record.outcome {
            RegenerationOutcome::Verified => Self::REWARD,
            RegenerationOutcome::Mismatch | RegenerationOutcome::NotProducible => -Self::PENALTY,
        };
        let score = self.scores.entry(result.provider).or_insert(0);
        *score = score.saturating_add(delta);
        Ok(*score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_production_regenerates_consensus() {
        // I2: pure production - if the produced byte matches the commitment, consensus is VERIFIED
        let producer = [1u8; 32];
        let seed = [7u8; 32];
        let produced = b"deterministic production output 1234567890";
        let pact = PactRecord::pure(producer, seed, produced, 100);
        assert_eq!(
            RegenerationChallenge::verify(&pact, produced),
            RegenerationOutcome::Verified,
            "a production match is consensus itself"
        );
        assert_eq!(
            RegenerationChallenge::verify(&pact, b"wrong production"),
            RegenerationOutcome::Mismatch,
            "a different production is REFUSED"
        );
        // the challenge record can be written on chain
        let rec = RegenerationRecord::new(1, pact.record_hash(), RegenerationOutcome::Verified, 50);
        let blob = rec.to_blob();
        let back = RegenerationRecord::from_blob(&blob).expect("blob");
        assert_eq!(back.outcome, RegenerationOutcome::Verified);
        assert_eq!(back.record_hash(), rec.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(RegenerationRecord::from_blob(&bad).is_none());
    }

    #[test]
    fn residual_class_verified_with_residual() {
        // I6: producer + residual - the production AND the residual must be verified together
        let produced = b"the produced part";
        let residual = b"organic remainder 0x1234";
        let pact =
            PactRecord::producer_plus_residual([9u8; 32], [5u8; 32], produced, residual, 200);
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, residual),
            RegenerationOutcome::Verified
        );
        // a wrong residual -> Mismatch (a class lie)
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, b"different"),
            RegenerationOutcome::Mismatch
        );
        // a wrong production -> Mismatch
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, b"wrong", residual),
            RegenerationOutcome::Mismatch
        );
    }

    #[test]
    fn residual_only_matches_content_id() {
        // a lossless .bud: commitment = content_id -> production = the original bytes
        let original = b"lossless content 12345";
        let pact = PactRecord::residual_only(original, 300);
        assert_eq!(
            RegenerationChallenge::verify(&pact, original),
            RegenerationOutcome::Verified
        );
        assert_eq!(
            RegenerationChallenge::verify(&pact, b"different"),
            RegenerationOutcome::Mismatch
        );
    }

    #[test]
    fn regeneration_beats_proof_economy() {
        // The I2 rule: producing costs below 1 percent of proving (a zkVM proof is expensive)
        assert!(
            RegenerationChallenge::regeneration_beats_proof(1, 1000),
            "producing is 0.1 percent of the proving cost"
        );
        assert!(
            RegenerationChallenge::regeneration_beats_proof(50, 10_000),
            "%0.5"
        );
        assert!(
            !RegenerationChallenge::regeneration_beats_proof(200, 10_000),
            "%2 → kabul etmez"
        );
        assert!(
            !RegenerationChallenge::regeneration_beats_proof(1, 0),
            "proof_cost 0 → false"
        );
    }

    #[test]
    fn tampered_pact_rejected() {
        // a corrupt PACT (a class lie) -> NotProducible
        let produced = b"x";
        let mut pact = PactRecord::pure([1u8; 32], [2u8; 32], produced, 1);
        pact.residual_len = 5; // in PureProduction the residual must be 0 - verify REFUSES
        assert_eq!(
            RegenerationChallenge::verify(&pact, produced),
            RegenerationOutcome::NotProducible
        );
    }

    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x5247_454E_2026_0816);
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = RegenerationRecord::from_blob(&buf[..len]);
        }
    }
}

#[cfg(test)]
mod consensus_tests {
    use super::*;
    use crate::bud_format_pact::{SuiteSigner, SuiteVerifier};

    struct Toy {
        suite: u16,
        id: [u8; 32],
    }

    fn mac(id: &[u8; 32], payload: &[u8]) -> Vec<u8> {
        let mut h = Sha3_256::new();
        h.update(b"toy");
        h.update(id);
        h.update(payload);
        h.finalize().to_vec()
    }

    impl SuiteSigner for Toy {
        fn suite(&self) -> u16 {
            self.suite
        }
        fn signer_id(&self) -> [u8; 32] {
            self.id
        }
        fn sign(&self, payload: &[u8]) -> Option<Vec<u8>> {
            Some(mac(&self.id, payload))
        }
    }

    impl SuiteVerifier for Toy {
        fn verify(
            &self,
            _suite: u16,
            signer_id: &[u8; 32],
            payload: &[u8],
            signature: &[u8],
        ) -> bool {
            mac(signer_id, payload) == signature
        }
    }

    fn record(outcome: RegenerationOutcome) -> RegenerationRecord {
        RegenerationRecord::new(5, [3u8; 32], outcome, 12)
    }

    fn pacts(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8; 32]).collect()
    }

    #[test]
    fn selection_is_deterministic_distinct_and_bound_to_the_randomness() {
        let list = pacts(50);
        let a = select_challenges(&[1u8; 32], 9, &list, 8);
        assert_eq!(a, select_challenges(&[1u8; 32], 9, &list, 8));
        assert_eq!(a.len(), 8);
        let mut sorted = a.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 8, "distinct");
        assert!(a.iter().all(|i| *i < 50));
        assert_ne!(
            a,
            select_challenges(&[2u8; 32], 9, &list, 8),
            "randomness binds"
        );
        assert_ne!(
            a,
            select_challenges(&[1u8; 32], 10, &list, 8),
            "epoch binds"
        );
    }

    #[test]
    fn selection_handles_the_edges() {
        assert!(select_challenges(&[0u8; 32], 1, &[], 4).is_empty());
        assert!(select_challenges(&[0u8; 32], 1, &pacts(5), 0).is_empty());
        let all = select_challenges(&[0u8; 32], 1, &pacts(3), 10);
        let mut sorted = all.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![0, 1, 2],
            "asking for more than exist returns all"
        );
    }

    #[test]
    fn a_result_is_signed_under_suite_0002_only() {
        let validator = Toy {
            suite: RESULT_SUITE,
            id: [4u8; 32],
        };
        let provider = [7u8; 32];
        let signed = SignedRegenerationResult::sign(
            record(RegenerationOutcome::Verified),
            provider,
            &validator,
        )
        .expect("suite 0x0002 signs");
        assert_eq!(signed.suite, 0x0002);
        assert_eq!(signed.provider, provider, "the provider is attested");
        assert_eq!(signed.verify(&validator), Ok(()));
        let wrong = Toy {
            suite: 0x0001,
            id: [4u8; 32],
        };
        assert_eq!(
            SignedRegenerationResult::sign(record(RegenerationOutcome::Verified), provider, &wrong),
            Err(SignedRecordError::WrongSuite { got: 0x0001 })
        );
        let mut relabelled = signed;
        relabelled.suite = 0x0001;
        assert_eq!(
            relabelled.verify(&validator),
            Err(SignedRecordError::WrongSuite { got: 0x0001 })
        );
        // A provider swapped after signing does not verify: the name is covered.
        let mut moved = relabelled;
        moved.suite = RESULT_SUITE;
        moved.provider = [8u8; 32];
        assert_eq!(
            moved.verify(&validator),
            Err(SignedRecordError::BadSignature)
        );
    }

    #[test]
    fn reputation_moves_only_from_a_verified_signed_result() {
        let validator = Toy {
            suite: RESULT_SUITE,
            id: [4u8; 32],
        };
        let provider = [7u8; 32];
        let mut ledger = ReputationLedger::new();
        let good = SignedRegenerationResult::sign(
            record(RegenerationOutcome::Verified),
            provider,
            &validator,
        )
        .expect("signs");
        assert_eq!(ledger.apply(&good, &validator), Ok(1));
        let bad = SignedRegenerationResult::sign(
            record(RegenerationOutcome::Mismatch),
            provider,
            &validator,
        )
        .expect("signs");
        assert_eq!(ledger.apply(&bad, &validator), Ok(1 - 10));
        // A tampered outcome (flip the record) is refused and changes nothing.
        let mut forged = good.clone();
        forged.record = record(RegenerationOutcome::Mismatch);
        assert_eq!(
            ledger.apply(&forged, &validator),
            Err(SignedRecordError::BadSignature)
        );
        // An unsigned result (empty signature) is refused.
        let mut unsigned = good.clone();
        unsigned.signature = Vec::new();
        assert_eq!(
            ledger.apply(&unsigned, &validator),
            Err(SignedRecordError::BadSignature)
        );
        assert_eq!(ledger.score(&provider), -9);
        assert_eq!(ledger.score(&[0u8; 32]), 0);
    }

    /// The same signed envelope cannot move a score twice, and a result signed
    /// for one provider cannot move another provider's score.
    #[test]
    fn a_result_scores_only_the_provider_it_names_and_only_once() {
        let validator = Toy {
            suite: RESULT_SUITE,
            id: [4u8; 32],
        };
        let provider = [7u8; 32];
        let other = [9u8; 32];
        let mut ledger = ReputationLedger::new();
        let good = SignedRegenerationResult::sign(
            record(RegenerationOutcome::Verified),
            provider,
            &validator,
        )
        .expect("signs");
        assert_eq!(ledger.apply(&good, &validator), Ok(1));
        // Replaying the same envelope moves nothing, and says so by reporting
        // the score as it stands.
        assert_eq!(ledger.apply(&good, &validator), Ok(1));
        assert_eq!(ledger.score(&provider), 1);
        // The worker names the provider; there is no argument to point a signed
        // result at somebody else.
        assert_eq!(ledger.score(&other), 0);
    }
}
