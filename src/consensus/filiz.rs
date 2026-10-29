//! Filiz Chain: hash-chain leader election.
//!
//! Every validator commits to a hash chain `x_0 = s`, `x_{j+1} = H(link, x_j)`
//! and registers `c = x_L`. Each proposal opens one link: the reveal `p` with
//! `H(link, p) = c`. After a canonical block the commitment becomes `p`.
//!
//! Eligibility for slot `t` is `y = H(elig, p, epoch_randomness, chain_id,
//! slot)`, compared against the stake threshold by the same function the VRF
//! path used. Only the owner knows `p` before the reveal, so nobody else can
//! compute `y`. The proof is the 32-byte reveal. There is no VRF.
//!
//! Both the link hash and the eligibility output bind the validator identity.
//! Registering somebody else's commitment therefore gains nothing: a reveal that
//! opens `c` for validator A does not open it for validator B, and A's published
//! reveal gives B no eligibility value of its own.
//!
//! This module is the standalone part: the chain, the checkpoints, reveal
//! checking, eligibility output and epoch randomness. Block and registry
//! wiring is a separate consensus commit.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// Links in a full chain (`L = 2^20`).
pub const FILIZ_CHAIN_LENGTH: u64 = 1 << 20;
/// One stored link per this many positions (32 KiB for a full chain).
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const FILIZ_CHECKPOINT_INTERVAL: u64 = 1024;
/// A validator registers a new chain once fewer links than this remain.
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const FILIZ_EXHAUSTION_FLOOR: u64 = 1 << 16;
/// Epochs between a registration and the first proposal it can open.
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const FILIZ_ACTIVATION_DELAY_EPOCHS: u64 = 3;
/// Links in the chain of a development or test key set. Mainnet registrations
/// carry [`FILIZ_CHAIN_LENGTH`]; a full chain costs a million hashes to build.
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const FILIZ_DEV_CHAIN_LENGTH: u64 = 1 << 12;
/// Checkpoint interval of a development chain.
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub const FILIZ_DEV_CHECKPOINT_INTERVAL: u64 = 1 << 6;

const LINK_TAG: &[u8] = b"BDLM_FILIZ_LINK_V1";
const ELIG_TAG: &[u8] = b"BDLM_FILIZ_ELIG_V1";
const EPOCH_TAG: &[u8] = b"BDLM_FILIZ_EPOCH_V1";

/// One link of the chain.
pub type Link = [u8; 32];

/// The identity a chain is bound to: the validator address bytes.
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub type ValidatorId = [u8; 32];

fn absorb(hasher: &mut Sha3_256, field: &[u8]) {
    hasher.update((field.len() as u64).to_le_bytes());
    hasher.update(field);
}

/// `x_{j+1}` from `x_j`, for one validator.
#[must_use]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub fn next_link(validator: &ValidatorId, x: &Link) -> Link {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, LINK_TAG);
    absorb(&mut hasher, validator);
    absorb(&mut hasher, x);
    hasher.finalize().into()
}

/// Whether `reveal` is the preimage of `commitment` for this validator.
#[must_use]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub fn reveal_matches(validator: &ValidatorId, commitment: &Link, reveal: &Link) -> bool {
    next_link(validator, reveal) == *commitment
}

/// The eligibility output `y` of a validator holding reveal `p`.
#[must_use]
pub fn eligibility_output(
    validator: &ValidatorId,
    reveal: &Link,
    epoch_randomness: &[u8; 32],
    chain_id: u64,
    slot: u64,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, ELIG_TAG);
    absorb(&mut hasher, validator);
    absorb(&mut hasher, reveal);
    absorb(&mut hasher, epoch_randomness);
    absorb(&mut hasher, &chain_id.to_le_bytes());
    absorb(&mut hasher, &slot.to_le_bytes());
    hasher.finalize().into()
}

/// Randomness of `epoch` from the canonical reveals of epoch `epoch - 2`, in
/// block order. The chain is fixed before the randomness exists, so a
/// validator cannot grind it; the one bit it keeps is withholding a reveal.
#[must_use]
pub fn epoch_randomness(chain_id: u64, epoch: u64, reveals: &[Link]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    absorb(&mut hasher, EPOCH_TAG);
    absorb(&mut hasher, &chain_id.to_le_bytes());
    absorb(&mut hasher, &epoch.to_le_bytes());
    absorb(&mut hasher, &(reveals.len() as u64).to_le_bytes());
    for reveal in reveals {
        absorb(&mut hasher, reveal);
    }
    hasher.finalize().into()
}

/// Why a chain could not be built or advanced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub enum FilizError {
    /// The length is zero, above [`FILIZ_CHAIN_LENGTH`], or not a multiple of
    /// the checkpoint interval.
    BadLength,
    /// Every link is spent; register a new chain.
    Exhausted,
    /// The registration epoch is too close to `u64::MAX` to schedule activation.
    EpochOverflow,
    /// The previous registration has not yet taken effect.
    PendingRegistration,
    /// No registered commitment can be used at this epoch.
    NotActive,
    /// A replacement is bound to a different validator identity.
    WrongValidator,
}

/// The secret side: a validator's chain with its checkpoints.
pub struct FilizChain {
    validator: ValidatorId,
    length: u64,
    interval: u64,
    /// `checkpoints[k] = x_{k * interval}`, up to and including `x_L`.
    checkpoints: Vec<Link>,
    /// Reveals made so far. The registered commitment is `x_{L - spent}`.
    spent: u64,
}

impl FilizChain {
    /// A full chain (`L = 2^20`, checkpoint every 1,024 links) from `seed`.
    ///
    /// # Errors
    ///
    /// Never for the fixed parameters; the signature matches
    /// [`Self::with_parameters`].
    pub fn new(validator: ValidatorId, seed: Link) -> Result<Self, FilizError> {
        Self::with_parameters(
            validator,
            seed,
            FILIZ_CHAIN_LENGTH,
            FILIZ_CHECKPOINT_INTERVAL,
        )
    }

    /// A shorter chain for devnet and integration tests. Production validators
    /// use [`Self::new`] so their registered chain always has 2^20 links.
    ///
    /// # Errors
    ///
    /// Never for the fixed parameters.
    /// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
    pub fn new_dev(validator: ValidatorId, seed: Link) -> Result<Self, FilizError> {
        Self::with_parameters(
            validator,
            seed,
            FILIZ_DEV_CHAIN_LENGTH,
            FILIZ_DEV_CHECKPOINT_INTERVAL,
        )
    }

    /// A chain of `length` links, one checkpoint per `interval`. Short chains
    /// exist for tests; production uses [`Self::new`].
    ///
    /// # Errors
    ///
    /// [`FilizError::BadLength`] unless `0 < length <= FILIZ_CHAIN_LENGTH`,
    /// `interval > 0` and `interval` divides `length`.
    /// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
    pub fn with_parameters(
        validator: ValidatorId,
        seed: Link,
        length: u64,
        interval: u64,
    ) -> Result<Self, FilizError> {
        if length == 0
            || length > FILIZ_CHAIN_LENGTH
            || interval == 0
            || !length.is_multiple_of(interval)
        {
            return Err(FilizError::BadLength);
        }
        let mut checkpoints = Vec::new();
        let mut x = seed;
        checkpoints.push(x);
        for j in 1..=length {
            x = next_link(&validator, &x);
            if j % interval == 0 {
                checkpoints.push(x);
            }
        }
        x.zeroize();
        Ok(Self {
            validator,
            length,
            interval,
            checkpoints,
            spent: 0,
        })
    }

    /// The commitment currently registered: `x_{L - spent}`.
    #[must_use]
    pub fn commitment(&self) -> Link {
        self.link_at(self.length - self.spent)
    }

    /// Links not yet revealed.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.length - self.spent
    }

    /// Whether the validator should register a new chain.
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn needs_rotation(&self) -> bool {
        self.remaining() < FILIZ_EXHAUSTION_FLOOR.min(self.length)
    }

    /// The reveal for the next proposal: the preimage of the commitment.
    ///
    /// # Errors
    ///
    /// [`FilizError::Exhausted`] when no link is left.
    /// WIRING: the reveal tick calls this through the health and authority loop - the production caller lands with the filiz wiring wave.
    pub fn next_reveal(&self) -> Result<Link, FilizError> {
        if self.spent >= self.length {
            return Err(FilizError::Exhausted);
        }
        Ok(self.link_at(self.length - self.spent - 1))
    }

    /// The reveal that opens the commitment `x_remaining`, that is `x_{remaining - 1}`.
    ///
    /// The chain side tracks how many links are left, so a producer reads that
    /// number from the state and needs no cursor of its own: a block that is
    /// not canonical moves nothing.
    ///
    /// # Errors
    ///
    /// [`FilizError::Exhausted`] when `remaining` is zero and
    /// [`FilizError::BadLength`] when it is above the chain length.
    pub fn reveal_for_remaining(&self, remaining: u64) -> Result<Link, FilizError> {
        if remaining == 0 {
            return Err(FilizError::Exhausted);
        }
        if remaining > self.length {
            return Err(FilizError::BadLength);
        }
        Ok(self.link_at(remaining - 1))
    }

    /// Links in this chain.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Records that the reveal of a canonical block was accepted.
    ///
    /// # Errors
    ///
    /// [`FilizError::Exhausted`] when no link is left.
    pub fn advance(&mut self) -> Result<(), FilizError> {
        if self.spent >= self.length {
            return Err(FilizError::Exhausted);
        }
        self.spent += 1;
        Ok(())
    }

    /// `x_j`, recomputed from the nearest checkpoint below it.
    fn link_at(&self, j: u64) -> Link {
        let block = j / self.interval;
        let mut x = self.checkpoints[block as usize];
        for _ in 0..(j - block * self.interval) {
            x = next_link(&self.validator, &x);
        }
        x
    }
}

impl Drop for FilizChain {
    /// The seed and every unrevealed checkpoint let their holder compute all
    /// future reveals and eligibility values, so they are wiped on drop.
    fn drop(&mut self) {
        for link in &mut self.checkpoints {
            link.zeroize();
        }
    }
}

impl std::fmt::Debug for FilizChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilizChain")
            .field("length", &self.length)
            .field("spent", &self.spent)
            .finish_non_exhaustive()
    }
}

/// The chain side: one validator's registered commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// WIRING: consensus surface kept public for the QC/filiz/handoff wiring wave - production callers land with that wave.
pub struct FilizCommitment {
    validator: ValidatorId,
    commitment: Link,
    remaining: u64,
}

impl FilizCommitment {
    /// A registration of `commitment` over a chain of `length` links.
    ///
    /// # Errors
    ///
    /// [`FilizError::BadLength`] for a zero length or one above
    /// [`FILIZ_CHAIN_LENGTH`].
    pub fn register(
        validator: ValidatorId,
        commitment: Link,
        length: u64,
    ) -> Result<Self, FilizError> {
        if length == 0 || length > FILIZ_CHAIN_LENGTH {
            return Err(FilizError::BadLength);
        }
        Ok(Self {
            validator,
            commitment,
            remaining: length,
        })
    }

    /// The commitment the next reveal must hash to.
    #[must_use]
    pub const fn commitment(&self) -> &Link {
        &self.commitment
    }

    /// Links left. A validator at zero is not eligible.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Whether this validator may be elected: it has a link left.
    #[must_use]
    pub const fn is_eligible(&self) -> bool {
        self.remaining > 0
    }

    /// Whether `reveal` opens the current commitment.
    #[must_use]
    pub fn accepts(&self, reveal: &Link) -> bool {
        self.is_eligible() && reveal_matches(&self.validator, &self.commitment, reveal)
    }

    /// Applies the reveal of a canonical block: the commitment becomes the
    /// reveal.
    ///
    /// # Errors
    ///
    /// [`FilizError::Exhausted`] when no link is left. A reveal that does not
    /// open the commitment leaves the state unchanged and returns `false`.
    pub fn apply(&mut self, reveal: &Link) -> Result<bool, FilizError> {
        if !self.is_eligible() {
            return Err(FilizError::Exhausted);
        }
        if !reveal_matches(&self.validator, &self.commitment, reveal) {
            return Ok(false);
        }
        self.commitment = *reveal;
        self.remaining -= 1;
        Ok(true)
    }
}

/// A validator's current chain and a replacement that cannot be used until
/// three full epoch boundaries have passed since its registration. The caller
/// must authenticate registrations and persist this value in consensus state;
/// merely receiving a proposal must not advance it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilizRegistration {
    active: Option<FilizCommitment>,
    pending: Option<PendingFilizCommitment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingFilizCommitment {
    chain: FilizCommitment,
    activation_epoch: u64,
}

impl FilizRegistration {
    /// Schedule a new chain, including a replacement for an exhausted chain.
    /// A previous active chain remains usable until the new chain activates.
    /// An unactivated replacement cannot itself be overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`FilizError::PendingRegistration`] for an outstanding rotation,
    /// [`FilizError::EpochOverflow`] if activation cannot be represented,
    /// [`FilizError::WrongValidator`] if the active chain has another owner,
    /// or [`FilizError::BadLength`] for an invalid chain length.
    pub fn register(
        &mut self,
        validator: ValidatorId,
        commitment: Link,
        length: u64,
        current_epoch: u64,
    ) -> Result<(), FilizError> {
        if self.pending.is_some() {
            return Err(FilizError::PendingRegistration);
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.validator != validator)
        {
            return Err(FilizError::WrongValidator);
        }
        let activation_epoch = current_epoch
            .checked_add(FILIZ_ACTIVATION_DELAY_EPOCHS)
            .ok_or(FilizError::EpochOverflow)?;
        let chain = FilizCommitment::register(validator, commitment, length)?;
        self.pending = Some(PendingFilizCommitment {
            chain,
            activation_epoch,
        });
        Ok(())
    }

    /// The commitment required of a proposal in this epoch. A mature pending
    /// rotation supersedes the old chain even if that chain has unused links.
    #[must_use]
    pub fn at_epoch(&self, epoch: u64) -> Option<&FilizCommitment> {
        if let Some(pending) = &self.pending {
            if epoch >= pending.activation_epoch {
                return Some(&pending.chain);
            }
        }
        self.active.as_ref()
    }

    /// Apply a reveal only after a block becomes canonical. A failed reveal
    /// must not activate a pending rotation or consume a link.
    ///
    /// # Errors
    ///
    /// Returns [`FilizError::NotActive`] when no chain is yet active and
    /// [`FilizError::Exhausted`] when its final link has already been spent.
    pub fn apply(&mut self, epoch: u64, reveal: &Link) -> Result<bool, FilizError> {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| epoch >= pending.activation_epoch)
        {
            let pending = self.pending.as_mut().ok_or(FilizError::NotActive)?;
            if !pending.chain.accepts(reveal) {
                return if pending.chain.is_eligible() {
                    Ok(false)
                } else {
                    Err(FilizError::Exhausted)
                };
            }
            let mut activated = self.pending.take().ok_or(FilizError::NotActive)?.chain;
            activated.apply(reveal)?;
            self.active = Some(activated);
            return Ok(true);
        }
        self.active
            .as_mut()
            .ok_or(FilizError::NotActive)?
            .apply(reveal)
    }
}

/// Environment variable naming the file that holds a validator's Filiz seed
/// (64 hex characters). The seed never enters the tree or a log.
pub const FILIZ_SEED_FILE_ENV: &str = "BUDLUM_FILIZ_SEED_FILE";

/// Read a Filiz seed file: 64 hex characters, surrounding whitespace allowed.
///
/// # Errors
///
/// An unreadable file or anything that is not 32 hex-encoded bytes. The
/// message never carries the file's content.
pub fn read_seed_file(path: &std::path::Path) -> Result<Link, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read the Filiz seed file {}: {e}", path.display()))?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| format!("the Filiz seed file {} is not hex", path.display()))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "the Filiz seed file {} does not hold 32 bytes",
            path.display()
        )
    })
}

/// The chain a validator registers on `chain_id`: a full chain on mainnet
/// and testnet, the short development chain elsewhere. The node and the CLI
/// both build it here, so the registered commitment is the one the node opens.
///
/// # Errors
///
/// Never for the fixed parameters.
pub fn chain_for_network(
    validator: ValidatorId,
    seed: Link,
    chain_id: u64,
) -> Result<FilizChain, FilizError> {
    use crate::core::chain_config::Network;
    match Network::from_chain_id(chain_id) {
        Some(Network::Mainnet | Network::Testnet) => FilizChain::new(validator, seed),
        _ => FilizChain::new_dev(validator, seed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Link = [7u8; 32];
    const A: ValidatorId = [0xA1; 32];
    const B: ValidatorId = [0xB2; 32];

    fn short() -> FilizChain {
        FilizChain::with_parameters(A, SEED, 16, 4).unwrap()
    }

    #[test]
    fn cross_implementation_known_answers() {
        // Python hashlib.sha3_256, with little-endian u64 length prefixes.
        let link = next_link(&A, &SEED);
        assert_eq!(
            hex::encode(link),
            "4b5de930c1503a81e13d0356ed4af1ff5870da6e62e87b83790277eb249be020"
        );
        assert_eq!(
            hex::encode(eligibility_output(&A, &link, &[2; 32], 7, 5)),
            "a93ccd647ac0ba8c2d690ad095f746b9f59ae3329f3a4c2833d3df994e122d73"
        );
    }

    #[test]
    fn link_is_deterministic_and_moves() {
        assert_eq!(next_link(&A, &SEED), next_link(&A, &SEED));
        assert_ne!(next_link(&A, &SEED), SEED);
        assert_ne!(next_link(&A, &SEED), next_link(&A, &[8u8; 32]));
    }

    #[test]
    fn commitment_is_the_end_of_the_chain() {
        let mut x = SEED;
        for _ in 0..16 {
            x = next_link(&A, &x);
        }
        assert_eq!(short().commitment(), x);
    }

    #[test]
    fn checkpoints_agree_with_the_plain_walk() {
        let chain = short();
        let mut x = SEED;
        for j in 0..=16u64 {
            assert_eq!(chain.link_at(j), x, "link {j}");
            x = next_link(&A, &x);
        }
    }

    #[test]
    fn valid_reveal_opens_the_commitment() {
        let chain = short();
        let reveal = chain.next_reveal().unwrap();
        assert!(reveal_matches(&A, &chain.commitment(), &reveal));
    }

    #[test]
    fn wrong_preimage_is_refused() {
        let chain = short();
        let mut reveal = chain.next_reveal().unwrap();
        reveal[0] ^= 1;
        assert!(!reveal_matches(&A, &chain.commitment(), &reveal));
        let registered = FilizCommitment::register(A, chain.commitment(), 16).unwrap();
        assert!(!registered.accepts(&reveal));
    }

    #[test]
    fn one_valid_reveal_per_commitment() {
        let chain = short();
        let valid = chain.next_reveal().unwrap();
        for byte in 0..=255u8 {
            let guess = [byte; 32];
            if guess != valid {
                assert!(!reveal_matches(&A, &chain.commitment(), &guess));
            }
        }
    }

    #[test]
    fn commitment_follows_the_reveals() {
        let mut chain = short();
        let mut registered = FilizCommitment::register(A, chain.commitment(), 16).unwrap();
        for step in 0..16u64 {
            assert_eq!(registered.commitment(), &chain.commitment(), "step {step}");
            let reveal = chain.next_reveal().unwrap();
            assert_eq!(registered.apply(&reveal), Ok(true));
            chain.advance().unwrap();
            assert_eq!(registered.remaining(), 15 - step);
        }
        // The last reveal was the seed itself.
        assert_eq!(registered.commitment(), &SEED);
    }

    #[test]
    fn apply_with_a_bad_reveal_changes_nothing() {
        let chain = short();
        let mut registered = FilizCommitment::register(A, chain.commitment(), 16).unwrap();
        let before = registered;
        assert_eq!(registered.apply(&[0u8; 32]), Ok(false));
        assert_eq!(registered, before);
    }

    #[test]
    fn exhausted_chain_is_not_eligible() {
        let mut chain = FilizChain::with_parameters(A, SEED, 4, 2).unwrap();
        let mut registered = FilizCommitment::register(A, chain.commitment(), 4).unwrap();
        for _ in 0..4 {
            let reveal = chain.next_reveal().unwrap();
            assert_eq!(registered.apply(&reveal), Ok(true));
            chain.advance().unwrap();
        }
        assert_eq!(chain.next_reveal(), Err(FilizError::Exhausted));
        assert_eq!(chain.advance(), Err(FilizError::Exhausted));
        assert!(!registered.is_eligible());
        assert!(!registered.accepts(&SEED));
        assert_eq!(registered.apply(&SEED), Err(FilizError::Exhausted));
    }

    #[test]
    fn rotation_is_signalled_below_the_floor() {
        let mut chain = FilizChain::with_parameters(A, SEED, 8, 4).unwrap();
        assert!(!chain.needs_rotation());
        for _ in 0..8 {
            chain.advance().unwrap();
        }
        assert!(chain.needs_rotation());
    }

    #[test]
    fn bad_parameters_are_refused() {
        assert_eq!(
            FilizChain::with_parameters(A, SEED, 0, 4).unwrap_err(),
            FilizError::BadLength
        );
        assert_eq!(
            FilizChain::with_parameters(A, SEED, 10, 4).unwrap_err(),
            FilizError::BadLength
        );
        assert_eq!(
            FilizChain::with_parameters(A, SEED, FILIZ_CHAIN_LENGTH + 1024, 1024).unwrap_err(),
            FilizError::BadLength
        );
        assert_eq!(
            FilizCommitment::register(A, [0u8; 32], 0).unwrap_err(),
            FilizError::BadLength
        );
    }

    #[test]
    fn eligibility_binds_every_input() {
        let p = [1u8; 32];
        let r = [2u8; 32];
        let base = eligibility_output(&A, &p, &r, 7, 100);
        assert_ne!(base, eligibility_output(&A, &[9u8; 32], &r, 7, 100));
        assert_ne!(base, eligibility_output(&A, &p, &[9u8; 32], 7, 100));
        assert_ne!(base, eligibility_output(&A, &p, &r, 8, 100));
        assert_ne!(base, eligibility_output(&A, &p, &r, 7, 101));
    }

    #[test]
    fn eligibility_is_unpredictable_without_the_reveal() {
        // Knowing the commitment, the epoch randomness, the chain and the slot
        // is not enough: the output moves with the reveal, and the commitment
        // is not the reveal.
        let chain = short();
        let r = [2u8; 32];
        let with_reveal = eligibility_output(&A, &chain.next_reveal().unwrap(), &r, 7, 5);
        let with_commitment = eligibility_output(&A, &chain.commitment(), &r, 7, 5);
        assert_ne!(with_reveal, with_commitment);
    }

    #[test]
    fn eligibility_output_is_uniform_enough_for_the_threshold() {
        // A quarter threshold on the first eight bytes of the output must
        // elect about a quarter of the slots, the distribution the VRF
        // output had.
        let p = [3u8; 32];
        let r = [4u8; 32];
        let threshold = u64::MAX / 4;
        let slots = 4096u64;
        let hits = (0..slots)
            .filter(|slot| {
                let y = eligibility_output(&A, &p, &r, 1, *slot);
                let hash = Sha3_256::digest(y);
                u64::from_le_bytes(hash[0..8].try_into().unwrap()) < threshold
            })
            .count() as f64;
        let share = hits / slots as f64;
        assert!((0.20..0.30).contains(&share), "share {share}");
    }

    #[test]
    fn epoch_randomness_depends_on_order_and_context() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let base = epoch_randomness(1, 5, &[a, b]);
        assert_ne!(base, epoch_randomness(1, 5, &[b, a]));
        assert_ne!(base, epoch_randomness(2, 5, &[a, b]));
        assert_ne!(base, epoch_randomness(1, 6, &[a, b]));
        assert_ne!(base, epoch_randomness(1, 5, &[a]));
        assert_ne!(
            epoch_randomness(1, 5, &[]),
            epoch_randomness(1, 5, &[[0u8; 32]])
        );
    }

    #[test]
    fn another_validator_cannot_reuse_a_registered_commitment() {
        let chain = short();
        let reveal = chain.next_reveal().unwrap();
        // B registers A's commitment verbatim.
        let copied = FilizCommitment::register(B, chain.commitment(), 16).unwrap();
        assert!(
            !copied.accepts(&reveal),
            "A's reveal does not open the same commitment for B"
        );
        assert!(!reveal_matches(&B, &chain.commitment(), &reveal));
        assert!(reveal_matches(&A, &chain.commitment(), &reveal));
    }

    #[test]
    fn published_reveal_gives_no_eligibility_to_another_validator() {
        let chain = short();
        let reveal = chain.next_reveal().unwrap();
        let r = [2u8; 32];
        assert_ne!(
            eligibility_output(&A, &reveal, &r, 7, 5),
            eligibility_output(&B, &reveal, &r, 7, 5)
        );
    }

    #[test]
    fn development_chain_uses_bounded_checkpoints() {
        let chain = FilizChain::new_dev(A, SEED).unwrap();
        assert_eq!(chain.length(), FILIZ_DEV_CHAIN_LENGTH);
        assert_eq!(chain.checkpoints.len(), 65);
        assert_eq!(
            chain.reveal_for_remaining(chain.length()),
            chain.next_reveal()
        );
    }

    #[test]
    fn state_cursor_selects_the_same_reveal_without_advance() {
        let chain = short();
        for remaining in 1..=chain.length() {
            let reveal = chain.reveal_for_remaining(remaining).unwrap();
            let mut commitment = FilizCommitment::register(A, chain.commitment(), 16).unwrap();
            for _ in remaining..16 {
                let next = chain.reveal_for_remaining(commitment.remaining()).unwrap();
                assert_eq!(commitment.apply(&next), Ok(true));
            }
            assert!(commitment.accepts(&reveal));
        }
        assert_eq!(chain.reveal_for_remaining(0), Err(FilizError::Exhausted));
        assert_eq!(chain.reveal_for_remaining(17), Err(FilizError::BadLength));
    }

    #[test]
    fn registration_waits_three_epochs_and_rotates_at_the_boundary() {
        let first = FilizChain::with_parameters(A, SEED, 4, 2).unwrap();
        let second = FilizChain::with_parameters(A, [8; 32], 4, 2).unwrap();
        let mut registration = FilizRegistration::default();
        registration.register(A, first.commitment(), 4, 5).unwrap();
        for epoch in 5..8 {
            assert!(registration.at_epoch(epoch).is_none());
            assert_eq!(
                registration.apply(epoch, &first.next_reveal().unwrap()),
                Err(FilizError::NotActive)
            );
        }
        assert_eq!(registration.at_epoch(8).unwrap().remaining(), 4);
        let first_reveal = first.next_reveal().unwrap();
        assert_eq!(registration.apply(8, &first_reveal), Ok(true));
        let before_rotation = registration.clone();
        assert_eq!(
            registration.register(B, second.commitment(), 4, 8),
            Err(FilizError::WrongValidator)
        );
        assert_eq!(registration, before_rotation);
        registration.register(A, second.commitment(), 4, 8).unwrap();
        assert_eq!(registration.at_epoch(10).unwrap().remaining(), 3);
        assert_eq!(
            registration.apply(10, &first.reveal_for_remaining(3).unwrap()),
            Ok(true)
        );
        assert_eq!(
            registration.at_epoch(11).unwrap().commitment(),
            &second.commitment()
        );
        let before = registration.clone();
        assert_eq!(
            registration.apply(11, &first.reveal_for_remaining(2).unwrap()),
            Ok(false)
        );
        assert_eq!(registration, before);
        assert_eq!(
            registration.apply(11, &second.next_reveal().unwrap()),
            Ok(true)
        );
        assert_eq!(registration.at_epoch(11).unwrap().remaining(), 3);
    }

    #[test]
    fn unactivated_rotation_cannot_be_replaced_or_spent() {
        let chain = short();
        let mut registration = FilizRegistration::default();
        registration.register(A, chain.commitment(), 16, 1).unwrap();
        let before = registration.clone();
        assert_eq!(
            registration.register(A, [9; 32], 16, 2),
            Err(FilizError::PendingRegistration)
        );
        assert_eq!(registration, before);
        assert_eq!(
            registration.apply(3, &chain.next_reveal().unwrap()),
            Err(FilizError::NotActive)
        );
        assert_eq!(registration, before);
        assert_eq!(
            registration.register(A, [9; 32], 16, u64::MAX),
            Err(FilizError::PendingRegistration)
        );
        let mut fresh = FilizRegistration::default();
        assert_eq!(
            fresh.register(A, [9; 32], 16, u64::MAX),
            Err(FilizError::EpochOverflow)
        );
        assert_eq!(fresh, FilizRegistration::default());
    }

    #[test]
    fn chains_of_two_validators_from_one_seed_differ() {
        let a = FilizChain::with_parameters(A, SEED, 16, 4).unwrap();
        let b = FilizChain::with_parameters(B, SEED, 16, 4).unwrap();
        assert_ne!(a.commitment(), b.commitment());
    }
}
