//! The anchor key ledger.
//!
//! The PQ anchor is signed by three ML-DSA-87 keys held in three separate
//! HSMs, from at least two vendors, and a record is valid at two of three. The
//! ledger is the list of those keys. It is written into genesis and an anchor
//! signature names a key by its index in the ledger instead of carrying the
//! public key, so a verifier trusts the ledger and nothing the signature
//! brings along.
//!
//! WIRING: the node loads the ledger from the genesis file (`anchor_ledger`
//! field, `src/core/genesis.rs` reads it through [`AnchorKeyLedger`]) and the
//! anchor driver in `src/chain/blockchain.rs` verifies and suspends through
//! it. Rules are pinned by this file's tests.
//!
//! # Suspension
//!
//! Two different anchors at one height, both signed by one key at one key
//! epoch, are evidence that the key signs conflicting history. The evidence
//! suspends that key for that epoch ([`AnchorKeyLedger::apply_equivocation`]):
//! its signatures stop counting toward the threshold, while the other keys
//! keep the chain anchored. A cold committee rotation (new key epoch with new
//! keys) is what ends a suspension.
//!
//! The same rule covers the SLH-DSA key of the Root Seal
//! ([`AnchorKeyLedger::apply_seal_equivocation`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::pq_anchor::{AnchorError, PqAnchor};
use super::pq_anchor_verify::{verify_one, verify_seal_signature};
use super::root_seal::{RootSeal, SealKeys};
use crate::crypto::pq;
use crate::crypto::scheme::SchemeId;

/// Signatures an anchor needs: two of three.
pub const ANCHOR_THRESHOLD: usize = 2;

/// Anchor keys in the ledger: three, one per HSM.
pub const ANCHOR_KEY_COUNT: usize = 3;

/// Vendors the three anchor keys must span at least.
pub const MIN_ANCHOR_VENDORS: usize = 2;

/// The most Root Seal keys a ledger lists.
pub const MAX_SEAL_KEYS: usize = 4;

/// The longest vendor label.
pub const MAX_VENDOR_LABEL_BYTES: usize = 64;

/// One key of the ledger: its slot, the HSM vendor behind it and the public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerKey {
    /// The slot an anchor signature names.
    pub index: u8,
    /// The HSM vendor label, for the two-vendor rule and audit text.
    pub vendor: String,
    /// The raw public key: ML-DSA-87 for an anchor key, SLH-DSA-SHAKE-256s for
    /// a seal key.
    pub public_key: Vec<u8>,
}

/// Which family of keys a suspension names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeyFamily {
    /// The ML-DSA-87 anchor keys.
    Anchor,
    /// The SLH-DSA-SHAKE-256s Root Seal keys.
    Seal,
}

/// One suspended key slot at one key epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Suspension {
    /// The family of the key.
    pub family: KeyFamily,
    /// The slot in that family.
    pub index: u8,
    /// The key epoch the suspension covers.
    pub key_epoch: u32,
}

/// The key ledger: the keys of the current key epoch and the suspensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorKeyLedger {
    /// The chain the ledger belongs to.
    pub chain_id: u64,
    /// The key epoch the listed keys serve.
    pub key_epoch: u32,
    /// The three ML-DSA-87 anchor keys, slots `0..3`.
    pub anchor_keys: Vec<LedgerKey>,
    /// The Root Seal keys, slots `0..n`.
    pub seal_keys: Vec<LedgerKey>,
    /// The suspensions evidence has caused.
    #[serde(default)]
    pub suspended: BTreeSet<Suspension>,
}

/// Why the ledger or its evidence was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The ledger is malformed.
    Invalid(&'static str),
    /// The rotation does not start the next key epoch.
    NotNextEpoch { current: u32, requested: u32 },
    /// Two anchors do not form equivocation evidence.
    NotEquivocation(&'static str),
    /// No key signed both anchors validly.
    NoCommonSigner,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(rule) => write!(f, "anchor key ledger invalid: {rule}"),
            Self::NotNextEpoch { current, requested } => write!(
                f,
                "key epoch {requested} does not follow the ledger epoch {current}"
            ),
            Self::NotEquivocation(rule) => write!(f, "not equivocation evidence: {rule}"),
            Self::NoCommonSigner => write!(f, "no key signed both records validly"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl LedgerError {
    /// A stable label.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ledger-invalid",
            Self::NotNextEpoch { .. } => "ledger-not-next-epoch",
            Self::NotEquivocation(_) => "ledger-not-equivocation",
            Self::NoCommonSigner => "ledger-no-common-signer",
        }
    }
}

fn check_keys(
    keys: &[LedgerKey],
    scheme: SchemeId,
    min: usize,
    max: usize,
) -> Result<(), &'static str> {
    if keys.len() < min || keys.len() > max {
        return Err("key-count");
    }
    for (slot, key) in keys.iter().enumerate() {
        if usize::from(key.index) != slot {
            return Err("key-index-not-dense");
        }
        if key.vendor.is_empty() || key.vendor.len() > MAX_VENDOR_LABEL_BYTES {
            return Err("vendor-label");
        }
        if pq::validate_public_key(scheme, &key.public_key).is_err() {
            return Err("public-key-length");
        }
    }
    for (i, a) in keys.iter().enumerate() {
        if keys
            .iter()
            .skip(i + 1)
            .any(|b| b.public_key == a.public_key)
        {
            return Err("duplicate-public-key");
        }
    }
    Ok(())
}

impl AnchorKeyLedger {
    /// Check the ledger shape: three distinct ML-DSA-87 anchor keys across at
    /// least two vendors, one to four distinct SLH-DSA-SHAKE-256s seal keys,
    /// dense slots, a positive key epoch and no suspension of an unknown slot.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Invalid`] naming the rule.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.chain_id == 0 {
            return Err(LedgerError::Invalid("chain-id-zero"));
        }
        if self.key_epoch == 0 {
            return Err(LedgerError::Invalid("key-epoch-zero"));
        }
        check_keys(
            &self.anchor_keys,
            SchemeId::ML_DSA_87,
            ANCHOR_KEY_COUNT,
            ANCHOR_KEY_COUNT,
        )
        .map_err(LedgerError::Invalid)?;
        check_keys(
            &self.seal_keys,
            SchemeId::SLH_DSA_SHAKE_256S,
            1,
            MAX_SEAL_KEYS,
        )
        .map_err(LedgerError::Invalid)?;
        let vendors: Vec<&str> = self.anchor_keys.iter().map(|k| k.vendor.as_str()).collect();
        crate::crypto::mainnet_policy::check_mainnet_anchor_vendor_policy(&vendors).map_err(
            |violation| {
                use crate::crypto::mainnet_policy::MainnetKeyPolicyViolation as V;
                LedgerError::Invalid(match violation {
                    V::AnchorKeyCount => "key-count",
                    V::AnchorVendorMissing => "vendor-label",
                    V::AnchorSoftwareToken => "software-token",
                    V::AnchorVendorDiversity => "fewer-than-two-vendors",
                    _ => "anchor-key-policy",
                })
            },
        )?;
        for s in &self.suspended {
            let known = match s.family {
                KeyFamily::Anchor => self.anchor_keys.len(),
                KeyFamily::Seal => self.seal_keys.len(),
            };
            if usize::from(s.index) >= known {
                return Err(LedgerError::Invalid("suspension-of-unknown-slot"));
            }
        }
        Ok(())
    }

    /// The digest of the ledger: every key, vendor and the epoch, length
    /// prefixed. Suspensions are state, not identity, and stay out of it.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_ANCHOR_KEY_LEDGER_V1");
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.key_epoch.to_le_bytes());
        for (family, keys) in [(0u8, &self.anchor_keys), (1u8, &self.seal_keys)] {
            hasher.update([family]);
            hasher.update((keys.len() as u64).to_le_bytes());
            for key in keys {
                hasher.update([key.index]);
                hasher.update((key.vendor.len() as u64).to_le_bytes());
                hasher.update(key.vendor.as_bytes());
                hasher.update((key.public_key.len() as u64).to_le_bytes());
                hasher.update(&key.public_key);
            }
        }
        hasher.finalize().into()
    }

    /// The ML-DSA-87 public key of anchor slot `index`.
    #[must_use]
    pub fn anchor_key(&self, index: u8) -> Option<&[u8]> {
        self.anchor_keys
            .get(usize::from(index))
            .map(|k| k.public_key.as_slice())
    }

    /// Whether a slot is suspended at a key epoch.
    #[must_use]
    pub fn is_suspended(&self, family: KeyFamily, index: u8, key_epoch: u32) -> bool {
        self.suspended.contains(&Suspension {
            family,
            index,
            key_epoch,
        })
    }

    /// The vendors behind the anchor keys, sorted and distinct.
    #[must_use]
    pub fn vendors(&self) -> Vec<&str> {
        let set: BTreeSet<&str> = self.anchor_keys.iter().map(|k| k.vendor.as_str()).collect();
        set.into_iter().collect()
    }

    /// Install the keys of the next key epoch, after a cold committee rotation.
    /// Suspensions of the old epoch stay on record and cover only that epoch.
    ///
    /// # Errors
    ///
    /// [`LedgerError::NotNextEpoch`] unless `key_epoch` is the current epoch
    /// plus one, or [`LedgerError::Invalid`] when the new key set is malformed.
    pub fn install_rotated_keys(
        &mut self,
        key_epoch: u32,
        anchor_keys: Vec<LedgerKey>,
        seal_keys: Vec<LedgerKey>,
    ) -> Result<(), LedgerError> {
        if self.key_epoch.checked_add(1) != Some(key_epoch) {
            return Err(LedgerError::NotNextEpoch {
                current: self.key_epoch,
                requested: key_epoch,
            });
        }
        let next = Self {
            chain_id: self.chain_id,
            key_epoch,
            anchor_keys,
            seal_keys,
            suspended: self.suspended.clone(),
        };
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Apply two conflicting anchors as evidence.
    ///
    /// Both anchors must be for this chain, at one height and one key epoch,
    /// and differ in payload. Every key that signed both validly is suspended
    /// for that key epoch. Returns the suspended slots.
    ///
    /// # Errors
    ///
    /// [`LedgerError::NotEquivocation`] when the pair is not a conflict, or
    /// [`LedgerError::NoCommonSigner`] when no single key signed both.
    pub fn apply_equivocation(
        &mut self,
        first: &PqAnchor,
        second: &PqAnchor,
    ) -> Result<Vec<u8>, LedgerError> {
        if first.chain_id != self.chain_id || second.chain_id != self.chain_id {
            return Err(LedgerError::NotEquivocation("other-chain"));
        }
        if first.height != second.height {
            return Err(LedgerError::NotEquivocation("different-heights"));
        }
        if first.key_epoch != second.key_epoch {
            return Err(LedgerError::NotEquivocation("different-key-epochs"));
        }
        if first.key_epoch != self.key_epoch {
            return Err(LedgerError::NotEquivocation("not-the-current-key-epoch"));
        }
        let first_payload = first.payload();
        let second_payload = second.payload();
        if first_payload == second_payload {
            return Err(LedgerError::NotEquivocation("same-payload"));
        }
        let mut slots = Vec::new();
        for a in &first.signatures {
            let Some(b) = second
                .signatures
                .iter()
                .find(|s| s.key_index == a.key_index)
            else {
                continue;
            };
            let Some(public_key) = self.anchor_key(a.key_index) else {
                continue;
            };
            if verify_one(public_key, &first_payload, &a.signature).is_ok()
                && verify_one(public_key, &second_payload, &b.signature).is_ok()
                && !slots.contains(&a.key_index)
            {
                slots.push(a.key_index);
            }
        }
        if slots.is_empty() {
            return Err(LedgerError::NoCommonSigner);
        }
        for index in &slots {
            self.suspended.insert(Suspension {
                family: KeyFamily::Anchor,
                index: *index,
                key_epoch: first.key_epoch,
            });
        }
        slots.sort_unstable();
        Ok(slots)
    }

    /// Apply two conflicting Root Seals at one height as evidence against the
    /// seal key that signed both.
    ///
    /// # Errors
    ///
    /// [`LedgerError::NotEquivocation`] or [`LedgerError::NoCommonSigner`].
    pub fn apply_seal_equivocation(
        &mut self,
        first: &RootSeal,
        second: &RootSeal,
    ) -> Result<u8, LedgerError> {
        if first.chain_id != self.chain_id || second.chain_id != self.chain_id {
            return Err(LedgerError::NotEquivocation("other-chain"));
        }
        if first.seal_height != second.seal_height {
            return Err(LedgerError::NotEquivocation("different-heights"));
        }
        if first.key_epoch != second.key_epoch || first.key_epoch != self.key_epoch {
            return Err(LedgerError::NotEquivocation("not-the-current-key-epoch"));
        }
        if first.key_index != second.key_index {
            return Err(LedgerError::NoCommonSigner);
        }
        let first_payload = first.payload();
        let second_payload = second.payload();
        if first_payload == second_payload {
            return Err(LedgerError::NotEquivocation("same-payload"));
        }
        let Some(public_key) = self
            .seal_keys
            .get(usize::from(first.key_index))
            .map(|k| k.public_key.clone())
        else {
            return Err(LedgerError::NoCommonSigner);
        };
        if verify_seal_signature(&public_key, &first_payload, &first.signature).is_err()
            || verify_seal_signature(&public_key, &second_payload, &second.signature).is_err()
        {
            return Err(LedgerError::NoCommonSigner);
        }
        self.suspended.insert(Suspension {
            family: KeyFamily::Seal,
            index: first.key_index,
            key_epoch: first.key_epoch,
        });
        Ok(first.key_index)
    }

    /// The anchor keys that may count at `key_epoch`: not suspended.
    #[must_use]
    pub fn live_anchor_slots(&self, key_epoch: u32) -> Vec<u8> {
        self.anchor_keys
            .iter()
            .map(|k| k.index)
            .filter(|i| !self.is_suspended(KeyFamily::Anchor, *i, key_epoch))
            .collect()
    }
}

impl SealKeys for AnchorKeyLedger {
    fn seal_key(&self, index: u8) -> Option<&[u8]> {
        self.seal_keys
            .get(usize::from(index))
            .map(|k| k.public_key.as_slice())
    }

    fn seal_key_suspended(&self, index: u8, key_epoch: u32) -> bool {
        self.is_suspended(KeyFamily::Seal, index, key_epoch)
    }
}

impl From<LedgerError> for AnchorError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err.kind())
    }
}

/// Deterministic fixtures: three software ML-DSA-87 anchor keys across two
/// vendors and one software SLH-DSA seal key. Seeds are visible in this file,
/// so these keys are public knowledge and exist for tests only.
#[cfg(all(test, feature = "wallet-ml-dsa"))]
pub(crate) mod test_support {
    use super::*;
    use crate::settlement::pq_anchor::{AnchorSigner, SoftwareMlDsa87Signer};
    use crate::settlement::root_seal::{SealSigner, SoftwareSealSigner};

    /// The seed of test anchor key `index`.
    pub(crate) fn anchor_seed(index: u8) -> [u8; 32] {
        [0xA0 ^ index; 32]
    }

    /// The test anchor signer of slot `index`.
    pub(crate) fn signer(index: u8) -> SoftwareMlDsa87Signer {
        SoftwareMlDsa87Signer::from_seed(index, &anchor_seed(index))
    }

    /// The test seal signer.
    pub(crate) fn seal_signer() -> SoftwareSealSigner {
        SoftwareSealSigner::from_seed(&[0x5E; 96]).expect("a 96 byte seed")
    }

    /// The ledger of the test keys at `key_epoch` for `chain_id`.
    pub(crate) fn software_ledger(chain_id: u64, key_epoch: u32) -> AnchorKeyLedger {
        static SEAL_KEY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let seal_key = SEAL_KEY.get_or_init(|| seal_signer().public_key()).clone();
        let vendors = ["hsm-alpha", "hsm-beta", "hsm-alpha"];
        let anchor_keys = (0u8..3)
            .map(|i| LedgerKey {
                index: i,
                vendor: vendors[usize::from(i)].to_string(),
                public_key: signer(i).public_key(),
            })
            .collect();
        AnchorKeyLedger {
            chain_id,
            key_epoch,
            anchor_keys,
            seal_keys: vec![LedgerKey {
                index: 0,
                vendor: "hsm-gamma".to_string(),
                public_key: seal_key,
            }],
            suspended: BTreeSet::new(),
        }
    }

    #[test]
    fn the_test_ledger_is_valid_and_spans_two_vendors() {
        let ledger = software_ledger(1, 1);
        ledger.validate().expect("the fixture ledger validates");
        assert_eq!(ledger.vendors(), vec!["hsm-alpha", "hsm-beta"]);
        assert_eq!(ledger.digest(), software_ledger(1, 1).digest());
        assert_ne!(ledger.digest(), software_ledger(1, 2).digest());
        assert_ne!(ledger.digest(), software_ledger(2, 1).digest());
        assert!(signer(0).public_key() != signer(1).public_key());
        assert_eq!(signer(0).key_index(), 0);
    }

    #[test]
    fn ledger_shape_rules_refuse_one_vendor_duplicates_and_wrong_lengths() {
        let mut one_vendor = software_ledger(1, 1);
        for key in &mut one_vendor.anchor_keys {
            key.vendor = "hsm-alpha".to_string();
        }
        assert_eq!(
            one_vendor.validate().unwrap_err(),
            LedgerError::Invalid("fewer-than-two-vendors")
        );
        let mut software_vendor = software_ledger(1, 1);
        software_vendor.anchor_keys[0].vendor = "kryoptic".to_string();
        assert_eq!(
            software_vendor.validate().unwrap_err(),
            LedgerError::Invalid("software-token")
        );
        let mut duplicate = software_ledger(1, 1);
        duplicate.anchor_keys[2].public_key = duplicate.anchor_keys[0].public_key.clone();
        assert_eq!(
            duplicate.validate().unwrap_err(),
            LedgerError::Invalid("duplicate-public-key")
        );
        let mut short = software_ledger(1, 1);
        short.anchor_keys[1].public_key.pop();
        assert_eq!(
            short.validate().unwrap_err(),
            LedgerError::Invalid("public-key-length")
        );
        let mut two_keys = software_ledger(1, 1);
        two_keys.anchor_keys.pop();
        assert_eq!(
            two_keys.validate().unwrap_err(),
            LedgerError::Invalid("key-count")
        );
        let mut gap = software_ledger(1, 1);
        gap.anchor_keys[1].index = 5;
        assert_eq!(
            gap.validate().unwrap_err(),
            LedgerError::Invalid("key-index-not-dense")
        );
        let mut zero_epoch = software_ledger(1, 1);
        zero_epoch.key_epoch = 0;
        assert_eq!(
            zero_epoch.validate().unwrap_err(),
            LedgerError::Invalid("key-epoch-zero")
        );
    }

    #[test]
    fn a_rotation_installs_the_next_epoch_only() {
        let mut ledger = software_ledger(1, 1);
        let keys = ledger.anchor_keys.clone();
        let seals = ledger.seal_keys.clone();
        assert_eq!(
            ledger
                .install_rotated_keys(3, keys.clone(), seals.clone())
                .unwrap_err()
                .kind(),
            "ledger-not-next-epoch"
        );
        ledger
            .install_rotated_keys(2, keys, seals)
            .expect("epoch 2 follows epoch 1");
        assert_eq!(ledger.key_epoch, 2);
    }
}
