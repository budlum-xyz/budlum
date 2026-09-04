//! Quantum-safe account abstraction V2: address derivation, the guardian
//! policy and the storage binding.
//!
//! # Size constants
//!
//! This file used to redefine the ML-DSA-87 lengths as its own `pub const`s
//! and used bare numbers instead of `[u8; ML_DSA_87_PUBLIC_KEY_LEN]` /
//! `[u8; ML_DSA_87_SIGNATURE_LEN]` everywhere. Two definitions of the same number
//! diverge silently when one of them changes. The lengths now come from
//! `crate::crypto::primitives`; there is a single definition.
//!
//! Because the directory was never reachable from `lib.rs` this file did not
//! compile; even its own test did not build (`GuardianVote.signature` is
//! `[u8; ML_DSA_87_SIGNATURE_LEN]`, the test said `vec![1u8; 4627]`). Code that
//! does not compile is code no gate sees.
//!
//! `validate_all` is now called by `registry::QuantumAccountRegistry`:
//! an account enters the registry only if it passes this check, and every path that
//! mutates the record goes through the same check again. This guard had been
//! written before, but no production path called it, because there was no registry
//! holding the account either.

use crate::crypto::primitives::{ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};
use sha3::{Digest, Sha3_256};

pub const MAX_MULTISIG_OWNERS: usize = 16;
pub const ADDRESS_DOMAIN_V2: &[u8] = b"BUDLUM_ADDRESS_V2";
pub const SEED_DOMAIN_V1: &[u8] = b"BUDLUM_MLDSA87_SEED_V1";
pub const RECOVERY_DOMAIN_V1: &[u8] = b"BUDLUM_WALLET_RECOVERY_PROPOSAL_V1";
pub const STORAGE_PACT_DOMAIN: &[u8] = b"BUDLUM_STORAGE_PACT_V1";

/// The minimum input bytes needed to derive a signing seed.
///
/// The derived seed is 256 bits. If the input is shorter the seed's search space is
/// that much smaller, and the hash does not grow it - it only hides it. The full rationale is
/// on [`QuantumAccount::seed_from_entropy`].
pub const MIN_SEED_ENTROPY_BYTES: usize = 32;

/// The condition seed derivation refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    /// The input is shorter than [`MIN_SEED_ENTROPY_BYTES`] bytes.
    InsufficientEntropy { given: usize, required: usize },
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientEntropy { given, required } => write!(
                f,
                "KQ-SEED-ENTROPY: the seed input is {given} bytes, at least {required} are required. \
                 The derived seed claims to carry 256 bits; if it is derived from a shorter input \
                 that claim is false and the addresses can be precomputed. \
                 The input must come from the operating system randomness source - \
                 the length is checked, the quality cannot be."
            ),
        }
    }
}

impl std::error::Error for SeedError {}
pub const BUD_MAGIC: [u8; 8] = *b"BUDLUM\x01\x00";

#[derive(Debug, Clone)]
pub struct QuantumAccount {
    pub address: [u8; 32],
    pub pq_public_key: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub storage_root: [u8; 32],
    pub pact_root: [u8; 32],
    pub guardian_root: [u8; 32],
    pub guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
    pub multisig_threshold: usize,
    pub recovery_threshold: usize,
    pub timelock_blocks: u64,
    pub nonce: u64,
    pub balance: u64,
    pub storage_bytes: u64, // for economics
}

impl QuantumAccount {
    #[must_use]
    pub fn address_from_public_key(pubkey: &[u8; ML_DSA_87_PUBLIC_KEY_LEN]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(ADDRESS_DOMAIN_V2);
        h.update(pubkey);
        h.finalize().into()
    }

    /// Derives the seed of an ML-DSA-87 signing key from entropy.
    ///
    /// # Why there is a lower bound
    ///
    /// This function always returns 32 bytes, whatever its input.
    /// The output **always looks high entropy**: the output of SHA3-256 is
    /// It reads like a random bit string even when it comes from a two-byte
    /// input, and that appearance misleads, because what breaks a seed is not
    /// the shape of the output but
    /// **the search space of the input**. If the input comes from 2 bytes the seed is one of
    /// 65 536 possibilities; an attacker precomputes them all, looks the
    /// published address up in that table and recovers the private key. The
    /// strength of the hash does nothing here - it has already found the right
    /// answer, it just does not know which one it is.
    ///
    /// This was the case of "a function named after entropy that never
    /// measured any": the signature took `&[u8]` and an empty slice was valid
    /// too. Returning `Result`
    /// makes it impossible for the caller to **skip** this decision; `#[must_use]`
    /// makes ignoring a value harder, but an `Err` cannot be ignored.
    ///
    /// # Why 32 bytes
    ///
    /// What is derived is a 256-bit seed. If the input is shorter, the output is
    /// only as strong as the bits it carries and the rest is decoration. Setting the lower
    /// bound equal to the output width makes the seed actually carry the
    /// security level it **declares**. A longer input is allowed: the excess
    /// does no harm.
    ///
    /// What is measured is length, not Shannon entropy. A caller can pass 32
    /// zero bytes and the gate stays silent. The reason is that whether a byte
    /// is genuinely random **cannot be measured** from this layer: 32 zero
    /// bytes and 32 bytes from a CSPRNG are indistinguishable here. Length is
    /// the part that is measurable and on the right side; the quality of the
    /// entropy source is the caller's responsibility, and the text of
    /// `SeedError` says so.
    ///
    /// # Errors
    ///
    /// If the input is shorter than [`MIN_SEED_ENTROPY_BYTES`] bytes
    /// [`SeedError::InsufficientEntropy`].
    pub fn seed_from_entropy(entropy: &[u8]) -> Result<[u8; 32], SeedError> {
        if entropy.len() < MIN_SEED_ENTROPY_BYTES {
            return Err(SeedError::InsufficientEntropy {
                given: entropy.len(),
                required: MIN_SEED_ENTROPY_BYTES,
            });
        }
        let mut h = Sha3_256::new();
        h.update(SEED_DOMAIN_V1);
        h.update(entropy);
        Ok(h.finalize().into())
    }

    #[must_use]
    pub fn guardian_root(guardians: &[[u8; ML_DSA_87_PUBLIC_KEY_LEN]]) -> [u8; 32] {
        let mut sorted = guardians.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut h = Sha3_256::new();
        for g in sorted {
            h.update(g);
        }
        h.finalize().into()
    }

    #[must_use]
    pub fn storage_cost(&self) -> f64 {
        // physical 0.23342 * e / r, device-only 0
        // For simplicity: storage_bytes * 0.23342 / 1_099_511_627_776 (1TB) / 16.68 (Duz ratio)
        // The byte count of an account is far below the exact integer range of f64 (2^53);
        // the cost is a fractional estimate anyway.
        #[allow(clippy::cast_precision_loss)]
        let tb = self.storage_bytes as f64 / 1_099_511_627_776.0;
        if self.storage_bytes == 0 {
            0.0
        } else {
            tb * 0.23342 / 16.68
        }
    }

    /// # Errors
    ///
    /// Errors if the threshold is outside 1..=16 or the guardian list is empty or larger than 16.
    pub const fn verify_multisig_threshold(&self) -> Result<(), &'static str> {
        if self.guardians.is_empty() {
            return Err("KQ-WALLET-MULTISIG-16: guardians empty");
        }
        if self.guardians.len() > MAX_MULTISIG_OWNERS {
            return Err("KQ-WALLET-MULTISIG-16: exceeds 16");
        }
        if self.multisig_threshold == 0 || self.multisig_threshold > self.guardians.len() {
            return Err("KQ-WALLET-MULTISIG-16: threshold outside");
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Errors if the recovery threshold is outside 1..=16 or the guardian list is empty or larger than 16.
    pub const fn verify_recovery_policy(&self) -> Result<(), &'static str> {
        if self.guardians.is_empty() {
            return Err("KQ-WALLET-RECOVERY-16: empty");
        }
        if self.guardians.len() > MAX_MULTISIG_OWNERS {
            return Err("KQ-WALLET-RECOVERY-16: exceeds 16");
        }
        if self.recovery_threshold == 0 || self.recovery_threshold > self.guardians.len() {
            return Err("KQ-WALLET-RECOVERY-16: threshold outside");
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Errors if `pact_root` is non-zero while `storage_root` is zero.
    pub fn verify_storage_bound(&self) -> Result<(), &'static str> {
        // storage_root zero but pact_root non-zero -> inconsistent
        if self.storage_root == [0u8; 32] && self.pact_root != [0u8; 32] {
            return Err("KQ-STORAGE-BOUND: storage_root zero but pact_root non-zero");
        }
        Ok(())
    }

    /// Calls all KQ-* guards from a single entry point.
    ///
    /// `verify_multisig_threshold`, `verify_recovery_policy` ve
    /// Because `verify_storage_bound` and friends are each `pub` separately, the gate cannot see
    /// that they are called from a production path; this function verifies all three in order
    /// and returns on the first error. This is the only surface the integration that wires
    /// into the main chain will call.
    /// # Errors
    ///
    /// Returns the first error if any of the three checks refuses.
    pub fn validate_all(&self) -> Result<(), &'static str> {
        self.verify_multisig_threshold()?;
        self.verify_recovery_policy()?;
        self.verify_storage_bound()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryProposal {
    pub current_owner: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub current_address: [u8; 32],
    pub new_owner: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub new_address: [u8; 32],
    pub created_block: u64,
    pub executable_after: u64,
}

impl RecoveryProposal {
    /// # Errors
    ///
    /// Errors if the new owner equals the current owner or the time lock overflows.
    pub fn new(
        current_owner: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
        new_owner: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
        timelock: u64,
        created: u64,
    ) -> Result<Self, &'static str> {
        if current_owner == new_owner {
            return Err("KQ-WALLET-RECOVERY-16: new==current");
        }
        let executable_after = created
            .checked_add(timelock)
            .ok_or("KQ-WALLET-RECOVERY-16: timelock overflow")?;
        let current_address = QuantumAccount::address_from_public_key(&current_owner);
        let new_address = QuantumAccount::address_from_public_key(&new_owner);
        Ok(Self {
            current_owner,
            current_address,
            new_owner,
            new_address,
            created_block: created,
            executable_after,
        })
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(RECOVERY_DOMAIN_V1);
        h.update(self.current_owner);
        h.update(self.current_address);
        h.update(self.new_owner);
        h.update(self.new_address);
        h.update(self.created_block.to_be_bytes());
        h.update(self.executable_after.to_be_bytes());
        h.finalize().into()
    }

    #[must_use]
    pub const fn is_timelock_satisfied(&self, current: u64) -> bool {
        current >= self.executable_after
    }
}

/// The PACT binding type lives in `src/storage/pact_binding.rs`.
///
/// There used to be a second `PactBinding` definition here: the same five fields, the same 128-byte
/// budget check, the same `verify_commitment`. `storage::Pact` is a superset of it -
/// it also carries `id` and `mod_flag`, and binds to a root through
/// `PactRegistry`.
///
/// Two definitions of the same concept diverge silently when one of them changes.
/// The copy here knew nothing of `mod_flag`: the distinction between `is_pure_production` and
/// `is_residual_only` did not exist on this side, so it could not tell a pure-production PACT
/// from a residual-only one. The copy was removed; the single definition
/// is used from outside.
pub use crate::storage::pact_binding::{Pact, PactRegistry};

/// One guardian's vote on a recovery proposal: the guardian's ML-DSA-87
/// public key, the digest of the proposal it approves, and its signature
/// over that digest under `GUARDIAN_VOTE_DOMAIN_V1`.
#[derive(Debug, Clone)]
pub struct GuardianVote {
    pub guardian_id: [u8; ML_DSA_87_PUBLIC_KEY_LEN],
    pub proposal_digest: [u8; 32],
    pub signature: [u8; ML_DSA_87_SIGNATURE_LEN],
}

/// The bytes a guardian signs: the domain tag, then the proposal digest.
const GUARDIAN_VOTE_DOMAIN_V1: &[u8] = b"BUDLUM_GUARDIAN_VOTE_V1";

impl GuardianVote {
    /// The message a vote's signature covers. Private until a signer in
    /// this tree produces votes; the finality check is the only reader.
    fn signed_message(proposal_digest: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(GUARDIAN_VOTE_DOMAIN_V1.len() + 32);
        m.extend_from_slice(GUARDIAN_VOTE_DOMAIN_V1);
        m.extend_from_slice(proposal_digest);
        m
    }
}

pub struct BftGuardianFinality;

impl BftGuardianFinality {
    /// Decide whether the votes finalise `proposal_digest` for an account
    /// with `guardians` and `threshold`.
    ///
    /// A vote counts when its key is one of the account's guardians, no
    /// other counted vote came from that key, it names this proposal, and
    /// its ML-DSA-87 signature over the proposal verifies under that key.
    /// The counted votes must reach both the account's threshold and two
    /// thirds of the guardian set.
    ///
    /// This used to compare `votes.len()` with the two numbers and return
    /// the votes. Duplicates, votes on some other proposal and votes with
    /// any bytes in the signature field all reached the count, so a single
    /// party holding no guardian key could finalise a recovery by sending
    /// enough vote records.
    ///
    /// # Errors
    ///
    /// Errors when the guardian set is empty, a vote is from a stranger,
    /// repeated, for another proposal or unsigned, or when the counted votes
    /// fall short of the threshold or the quorum.
    pub fn finalize(
        votes: Vec<GuardianVote>,
        guardians: &[[u8; ML_DSA_87_PUBLIC_KEY_LEN]],
        threshold: usize,
        proposal_digest: &[u8; 32],
    ) -> Result<Vec<GuardianVote>, &'static str> {
        if guardians.is_empty() {
            return Err("K-BUD-BFT-GUARDIAN: no guardians");
        }
        if threshold == 0 || threshold > guardians.len() {
            return Err("K-BUD-BFT-GUARDIAN: threshold outside 1..=guardians");
        }
        let message = GuardianVote::signed_message(proposal_digest);
        let mut seen: Vec<&[u8; ML_DSA_87_PUBLIC_KEY_LEN]> = Vec::with_capacity(votes.len());
        for vote in &votes {
            if !guardians.contains(&vote.guardian_id) {
                return Err("K-BUD-BFT-GUARDIAN: vote from a key outside the guardian set");
            }
            if seen.contains(&&vote.guardian_id) {
                return Err("K-BUD-BFT-GUARDIAN: duplicate guardian");
            }
            if &vote.proposal_digest != proposal_digest {
                return Err("K-BUD-BFT-GUARDIAN: vote names another proposal");
            }
            crate::crypto::primitives::verify_ml_dsa_87_signature(
                &message,
                &vote.signature,
                &vote.guardian_id,
            )
            .map_err(|_| "K-BUD-BFT-GUARDIAN: signature did not verify")?;
            seen.push(&vote.guardian_id);
        }
        if votes.len() < threshold {
            return Err("K-BUD-BFT-GUARDIAN: quorum < threshold");
        }
        let quorum = (guardians.len() * 2).div_ceil(3);
        if votes.len() < quorum {
            return Err("K-BUD-BFT-GUARDIAN: quorum <2n/3");
        }
        Ok(votes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: [u8; ML_DSA_87_PUBLIC_KEY_LEN] = [1u8; ML_DSA_87_PUBLIC_KEY_LEN];
    const SIG: [u8; ML_DSA_87_SIGNATURE_LEN] = [1u8; ML_DSA_87_SIGNATURE_LEN];

    fn account(
        guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]>,
        multisig_threshold: usize,
        recovery_threshold: usize,
    ) -> QuantumAccount {
        QuantumAccount {
            address: [0u8; 32],
            pq_public_key: [0u8; ML_DSA_87_PUBLIC_KEY_LEN],
            storage_root: [0u8; 32],
            pact_root: [0u8; 32],
            guardian_root: QuantumAccount::guardian_root(&guardians),
            guardians,
            multisig_threshold,
            recovery_threshold,
            timelock_blocks: 100,
            nonce: 0,
            balance: 0,
            storage_bytes: 0,
        }
    }

    #[test]
    fn the_address_is_bound_to_the_public_key() {
        let a = QuantumAccount::address_from_public_key(&PK);
        let b = QuantumAccount::address_from_public_key(&[2u8; ML_DSA_87_PUBLIC_KEY_LEN]);
        assert_ne!(a, b);
        assert_eq!(a, QuantumAccount::address_from_public_key(&PK));
    }

    #[test]
    fn a_well_formed_policy_validates() {
        let mut guardians = Vec::new();
        for i in 0..16u8 {
            guardians.push([i; ML_DSA_87_PUBLIC_KEY_LEN]);
        }
        let acc = account(guardians, 10, 10);
        assert!(acc.validate_all().is_ok());
    }

    /// `validate_all` must report all three gates passing; if one drops
    /// all of them must fail.
    #[test]
    fn validate_all_refuses_an_out_of_range_threshold() {
        let acc = account(vec![PK], 2, 1);
        assert!(acc.verify_multisig_threshold().is_err());
        assert!(acc.validate_all().is_err());
        let zero = account(vec![PK], 0, 1);
        assert!(zero.validate_all().is_err());
    }

    #[test]
    fn a_pact_root_without_a_storage_root_is_refused() {
        let mut acc = account(vec![PK], 1, 1);
        acc.pact_root = [1u8; 32];
        assert!(acc.verify_storage_bound().is_err());
        assert!(acc.validate_all().is_err());
    }

    /// The guardian root must be order independent: the same set in a different order must give the same
    /// root, otherwise the same policy looks like two different accounts.
    #[test]
    fn the_guardian_root_does_not_depend_on_order() {
        let a = [1u8; ML_DSA_87_PUBLIC_KEY_LEN];
        let b = [2u8; ML_DSA_87_PUBLIC_KEY_LEN];
        assert_eq!(
            QuantumAccount::guardian_root(&[a, b]),
            QuantumAccount::guardian_root(&[b, a])
        );
        assert_ne!(
            QuantumAccount::guardian_root(&[a]),
            QuantumAccount::guardian_root(&[a, b])
        );
    }

    #[test]
    fn a_recovery_proposal_respects_its_timelock() {
        let current = [1u8; ML_DSA_87_PUBLIC_KEY_LEN];
        let next = [2u8; ML_DSA_87_PUBLIC_KEY_LEN];
        let p = RecoveryProposal::new(current, next, 100, 10).expect("distinct owners");
        assert_eq!(p.executable_after, 110);
        assert!(!p.is_timelock_satisfied(109));
        assert!(p.is_timelock_satisfied(110));
        assert!(RecoveryProposal::new(current, current, 100, 10).is_err());
        assert!(RecoveryProposal::new(current, next, u64::MAX, 10).is_err());
    }

    #[test]
    fn the_pact_commitment_is_checked_against_the_payload() {
        let payload = b"hello";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([0u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0)
            .expect("budget of 10 is under the 128 byte limit");
        assert!(pact.verify_commitment(payload).is_ok());
        assert!(pact.verify_commitment(b"other").is_err());
        assert!(Pact::new([0u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 129, 0).is_err());
        // The distinction the single definition carries: the copy knew nothing of `mod_flag`.
        assert!(pact.is_pure_production());
        assert!(
            Pact::new([0u8; 32], [0u8; 32], [0u8; 32], comm, [1u8; 32], 10, 2)
                .expect("residual-only pact")
                .is_residual_only()
        );
        assert!(Pact::new([0u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 3).is_err());
    }

    /// Vote records filled with bytes reach neither the threshold nor the
    /// quorum: a vote is counted only after its signature verifies, and
    /// these never do. Before the check, four such records finalised any
    /// recovery on a four-guardian account.
    #[test]
    fn unsigned_vote_records_never_finalise() {
        let guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]> =
            (1u8..=4).map(|id| [id; ML_DSA_87_PUBLIC_KEY_LEN]).collect();
        let vote = |id: u8| GuardianVote {
            guardian_id: [id; ML_DSA_87_PUBLIC_KEY_LEN],
            proposal_digest: [0u8; 32],
            signature: SIG,
        };
        let proposal = [0u8; 32];
        for count in 1..=4u8 {
            let votes: Vec<GuardianVote> = (1..=count).map(vote).collect();
            assert!(
                BftGuardianFinality::finalize(votes, &guardians, 2, &proposal).is_err(),
                "{count} unsigned records must not finalise"
            );
        }
        // the guardian set and threshold are checked before any vote
        assert!(BftGuardianFinality::finalize(vec![vote(1)], &[], 1, &proposal).is_err());
        assert!(BftGuardianFinality::finalize(vec![vote(1)], &guardians, 0, &proposal).is_err());
        assert!(BftGuardianFinality::finalize(vec![vote(1)], &guardians, 5, &proposal).is_err());
    }

    /// A seed cannot be derived from a short input.
    ///
    /// What the gate measures is not the shape of the output but the search space of the input.
    /// Before the gate this function accepted any length: even from a single
    /// byte it produced a 32-byte, random-looking seed. That seed had exactly
    /// one possible value, and the address derived from it could be precomputed
    /// by anyone.
    #[test]
    fn a_seed_cannot_be_derived_from_thin_entropy() {
        // Every length below the bound is refused - including the empty slice.
        for len in [0usize, 1, 2, 16, MIN_SEED_ENTROPY_BYTES - 1] {
            let err = QuantumAccount::seed_from_entropy(&vec![7u8; len])
                .expect_err("input below the bound must be refused");
            assert_eq!(
                err,
                SeedError::InsufficientEntropy {
                    given: len,
                    required: MIN_SEED_ENTROPY_BYTES,
                },
                "the given/required values must be reported for {len} bytes"
            );
            // The message has to tell the caller what to do: the numbers and
            // the text must say where the entropy has to come from.
            let text = err.to_string();
            assert!(
                text.contains(&len.to_string()),
                "the message has to state the given length"
            );
            assert!(
                text.contains("32"),
                "the message has to state the required length"
            );
        }

        // Input at and above the bound passes.
        let at = QuantumAccount::seed_from_entropy(&[7u8; MIN_SEED_ENTROPY_BYTES])
            .expect("input at the bound must be accepted");
        let over = QuantumAccount::seed_from_entropy(&[7u8; MIN_SEED_ENTROPY_BYTES + 48])
            .expect("longer input must be accepted");

        // Extra input is not decoration: it enters the derivation, otherwise
        // raising the length would not raise the security.
        assert_ne!(at, over, "the whole input has to enter the seed");

        // The derivation is deterministic: the same input gives the same seed.
        assert_eq!(
            at,
            QuantumAccount::seed_from_entropy(&[7u8; MIN_SEED_ENTROPY_BYTES])
                .expect("the same input must be accepted again")
        );

        // The domain separator really separates: the same bytes in another context
        // must not give the same seed.
        let mut raw = sha3::Sha3_256::new();
        raw.update([7u8; MIN_SEED_ENTROPY_BYTES]);
        let undomained: [u8; 32] = raw.finalize().into();
        assert_ne!(
            at, undomained,
            "the domain separator has to enter the derivation"
        );
    }

    /// Votes are counted only from the account's guardians, once per key,
    /// on this proposal, with a verifying ML-DSA-87 signature. Every case
    /// below passed the old length check; each is a different way of not
    /// being a guardian vote.
    #[cfg(feature = "wallet-ml-dsa")]
    #[test]
    fn only_signed_votes_from_distinct_guardians_finalise() {
        use crate::crypto::primitives::WalletKeyPair;
        let keys: Vec<WalletKeyPair> = (0..3).map(|_| WalletKeyPair::generate()).collect();
        let guardians: Vec<[u8; ML_DSA_87_PUBLIC_KEY_LEN]> =
            keys.iter().map(WalletKeyPair::public_key_bytes).collect();
        let proposal = [7u8; 32];
        let other = [8u8; 32];
        let vote = |k: &WalletKeyPair, digest: [u8; 32]| GuardianVote {
            guardian_id: k.public_key_bytes(),
            proposal_digest: digest,
            signature: k.sign(&GuardianVote::signed_message(&digest)),
        };
        let honest: Vec<GuardianVote> = keys.iter().map(|k| vote(k, proposal)).collect();
        assert!(
            BftGuardianFinality::finalize(honest.clone(), &guardians, 2, &proposal).is_ok(),
            "three honest votes finalise"
        );
        assert!(
            BftGuardianFinality::finalize(honest[..2].to_vec(), &guardians, 2, &proposal).is_ok(),
            "two of three is both the threshold and 2n/3"
        );
        // the same guardian twice, padded to the count
        let dup = vec![honest[0].clone(), honest[0].clone()];
        assert!(BftGuardianFinality::finalize(dup, &guardians, 2, &proposal).is_err());
        // a stranger with a valid signature of its own
        let stranger = WalletKeyPair::generate();
        let mixed = vec![honest[0].clone(), vote(&stranger, proposal)];
        assert!(BftGuardianFinality::finalize(mixed, &guardians, 2, &proposal).is_err());
        // a vote on another proposal
        let elsewhere = vec![honest[0].clone(), vote(&keys[1], other)];
        assert!(BftGuardianFinality::finalize(elsewhere, &guardians, 2, &proposal).is_err());
        // a vote record that names this proposal but carries someone else's signature
        let mut forged = honest[1].clone();
        forged.signature = honest[0].signature;
        assert!(BftGuardianFinality::finalize(
            vec![honest[0].clone(), forged],
            &guardians,
            2,
            &proposal
        )
        .is_err());
        // one honest vote is below the threshold of two
        assert!(
            BftGuardianFinality::finalize(honest[..1].to_vec(), &guardians, 2, &proposal).is_err()
        );
        // an empty guardian set or a threshold outside the set is refused
        assert!(BftGuardianFinality::finalize(honest.clone(), &[], 1, &proposal).is_err());
        assert!(BftGuardianFinality::finalize(honest, &guardians, 4, &proposal).is_err());
    }
}
