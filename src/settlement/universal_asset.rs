//! One asset, many chains: the identity a unified balance needs.
//!
//! # The question this answers
//!
//! A unified balance has to add things up. Before it can add, it has to decide
//! what counts as the *same thing*: is the USDC in an Ethereum account the same
//! asset as the USDC in a Solana account? Is `wBTC` the same as `BTC`?
//!
//! The tree currently has three unrelated answers to "what is an asset":
//!
//! - `cross_domain::bridge::AssetId([u8; 32])`
//! - `pollen::AssetId([u8; 32])`
//! - `object_layer::family::AssetKind`
//!
//! Three types, three namespaces, no relation. Nothing in the tree can say that
//! two of them denote one asset, which means nothing in the tree can sum across
//! chains.
//!
//! # The design decision that matters
//!
//! Asset equivalence is **not computable**. There is no function of two chain
//! native ids that tells you whether they are one asset - that is a fact about
//! the world, not about the bytes. Two designs follow from that:
//!
//! 1. Pretend it is computable (hash the issuer, hash the symbol, hope). This
//!    is how a unified balance silently sums two different assets and reports a
//!    number that is wrong in a way no test catches.
//! 2. Make equivalence an **explicit, anchored declaration**, and make the
//!    verifier refuse anything not declared.
//!
//! This module is (2). A [`Denomination`] is a claim "these members are one
//! asset", submitted by an issuer and carrying the anchor proof of the event
//! that declared it. A `UniversalAssetId` exists because somebody proved a
//! denomination, not because a hash happened to match.
//!
//! The consequence, stated plainly: **an asset with no anchored denomination has
//! no universal id and therefore cannot appear in a unified balance.** It can
//! still exist and still be moved by every ordinary path; it just is not summed.
//! Refusing to sum is the failure mode we want - a missing asset is visible, a
//! silently wrong sum is not.
//!
//! # What the id commits to
//!
//! The id commits to the whole member set, not to a name. Two denominations of
//! the same asset that list their members in a different order are the *same*
//! denomination and produce the same id; one that adds or drops a member is a
//! *different* denomination and cannot be mistaken for the old one. That is what
//! stops an issuer from quietly widening an existing asset to swallow a second
//! one.

use crate::core::address::Address;
use crate::domain::Hash32;
use sha2::{Digest, Sha256};

/// Domain tag of a universal asset id.
pub const ASSET_DOMAIN: &[u8] = b"BDLM_UNIVERSAL_ASSET_V1";

/// Most chain members one denomination may carry.
///
/// A denomination is read on every balance derivation, so this bounds the work
/// per asset. Thirty-two covers every chain the tree can verify with room to
/// spare, and matches the spirit of the other per-object ceilings.
pub const MAX_DENOMINATION_MEMBERS: usize = 32;

/// One chain's native identity for an asset.
///
/// This is the *native* naming, deliberately not normalised: `Ethereum`'s
/// `0xA0b8...` and `Solana`'s mint address are different lengths, different
/// alphabets, different meanings. Normalising them would be exactly the
/// "pretend it is computable" mistake. The member keeps the chain's own bytes
/// and the denomination is what says they are one asset.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct AssetMember {
    /// The chain this member lives on.
    pub domain: u32,
    /// The asset's identity on that chain, as that chain writes it.
    ///
    /// A 32-byte digest of the native identifier (an ERC-20 address padded, a
    /// Solana mint, a Bitcoin script hash) - not the identifier itself. Keeping
    /// the digest means the type is uniform and never truncates; keeping it a
    /// digest means the denomination must say *which* chain so the digest is
    /// interpreted in the right namespace.
    pub native_id: Hash32,
}

impl AssetMember {
    /// Builds a member.
    #[must_use]
    pub fn new(domain: u32, native_id: Hash32) -> Self {
        Self { domain, native_id }
    }
}

/// Why a denomination was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssetError {
    /// A denomination with no members denotes nothing.
    #[error("a denomination must carry at least one member")]
    NoMembers,
    /// More members than the ceiling.
    #[error("a denomination carries {0} members, more than {MAX_DENOMINATION_MEMBERS}")]
    TooManyMembers(usize),
    /// The same (domain, asset) listed twice.
    #[error("member {index} repeats an earlier member")]
    DuplicateMember {
        /// Index of the repeat.
        index: usize,
    },
    /// The domain is not one this chain can verify.
    ///
    /// A denomination naming an unverifiable domain could never have its
    /// balance proven, so admitting it would put a permanent hole in every
    /// sum it enters.
    #[error("member {index} names domain {domain}, which has no claim domain")]
    UnverifiedDomain {
        /// Index of the offending member.
        index: usize,
        /// The domain it named.
        domain: u32,
    },
    /// Two members share a domain, so a single balance could be counted twice.
    #[error("members {a} and {b} are on the same domain")]
    SameDomainTwice {
        /// First index.
        a: usize,
        /// Second index.
        b: usize,
    },
    /// The id does not match the members.
    #[error("denomination id does not match its members")]
    IdMismatch,
    /// The denomination carries no anchor proof for its declaration event.
    #[error("a denomination must carry the anchor proof of its declaration")]
    Unanchored,
    /// The issuer is the zero address.
    #[error("a denomination must name a non-zero issuer")]
    NoIssuer,
    /// A chain-native asset this denomination lists is already mapped to a
    /// different universal asset.
    ///
    /// This is the double-count failure: the same coins would be summed into
    /// two universal balances. It has no index into the new denomination on
    /// purpose - the conflict is between denominations, not between members.
    #[error("domain {domain} asset is already denominated under another universal asset")]
    AlreadyDenominated {
        /// The domain whose asset is double-claimed.
        domain: u32,
    },
    /// The index is full.
    #[error("the denomination index is full")]
    IndexFull,
}

/// A declared equivalence: these chain-native members are one asset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Denomination {
    /// Who declared it. Not a privilege - a signature - so a bad declaration is
    /// attributable rather than anonymous.
    pub issuer: Address,
    /// The members, in declared order. Order is not semantic (see
    /// [`Denomination::calculate_id`]) but is preserved for display.
    pub members: Vec<AssetMember>,
    /// The human label, for display only.
    ///
    /// Deliberately *not* part of the id: a label that entered the id would let
    /// two spellings of "USDC" split one asset in two.
    pub label: String,
    /// The block at which the declaration was anchored on the source chain.
    pub anchored_at_block: u64,
    /// The finality root the declaration event was proven against.
    ///
    /// A denomination with no root is a claim nobody proved. `validate_shape`
    /// refuses it as [`AssetError::Unanchored`], which is why this field exists
    /// at all: a set of members is not a fact about a chain until an anchored
    /// event says so.
    #[serde(default)]
    pub anchor_root: Hash32,
    /// The height of `anchor_root`.
    #[serde(default)]
    pub anchor_height: u64,
    /// The id, a function of issuer and members.
    pub denomination_id: Hash32,
}

impl Denomination {
    /// Declares a denomination and computes its id.
    ///
    /// Does not check validity: shape checks run at the door so a malformed
    /// denomination can be built for a test. It does guarantee the id matches
    /// the members passed.
    #[must_use]
    pub fn declare(issuer: Address, members: Vec<AssetMember>, label: &str) -> Self {
        let mut d = Self {
            issuer,
            members,
            label: label.to_string(),
            anchored_at_block: 0,
            anchor_root: [0u8; 32],
            anchor_height: 0,
            denomination_id: [0u8; 32],
        };
        d.denomination_id = d.calculate_id();
        d
    }

    /// Declares a denomination together with the finality root of the event
    /// that declared it.
    ///
    /// This is the only constructor that can produce a denomination
    /// [`Denomination::validate_shape`] accepts: [`Denomination::declare`]
    /// leaves the root zero, which the `Unanchored` rule refuses. The split is
    /// deliberate - a test can build an unanchored claim to prove it is
    /// refused, and the chain cannot admit one by accident.
    #[must_use]
    pub fn declare_anchored(
        issuer: Address,
        members: Vec<AssetMember>,
        label: &str,
        anchored_at_block: u64,
        anchor_root: Hash32,
        anchor_height: u64,
    ) -> Self {
        let mut d = Self::declare(issuer, members, label);
        d.anchored_at_block = anchored_at_block;
        d.anchor_root = anchor_root;
        d.anchor_height = anchor_height;
        d
    }

    /// The id: domain tag, issuer, member count, and every member sorted.
    ///
    /// Members are sorted before hashing because set identity is what is meant:
    /// the declaration "A and B are one asset" is the same claim as "B and A".
    /// Keeping declaration order in the id would let a one-member-set of the
    /// same asset present as a different denomination depending on input order.
    #[must_use]
    pub fn calculate_id(&self) -> Hash32 {
        let mut sorted: Vec<&AssetMember> = self.members.iter().collect();
        sorted.sort();

        let mut hasher = Sha256::new();
        hasher.update(ASSET_DOMAIN);
        hasher.update(self.issuer.as_bytes());
        hasher.update(
            u32::try_from(sorted.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for member in sorted {
            hasher.update(member.domain.to_le_bytes());
            hasher.update(member.native_id);
        }
        hasher.finalize().into()
    }

    /// Whether `denomination_id` is the id of these members.
    #[must_use]
    pub fn verify_id(&self) -> bool {
        self.denomination_id == self.calculate_id()
    }

    /// The denomination's own rules, checked before it is admitted.
    ///
    /// # Errors
    ///
    /// The first [`AssetError`] that applies.
    pub fn validate_shape<F>(&self, has_claim_domain: F) -> Result<(), AssetError>
    where
        F: Fn(u32) -> bool,
    {
        if self.issuer == Address::zero() {
            return Err(AssetError::NoIssuer);
        }
        if self.members.is_empty() {
            return Err(AssetError::NoMembers);
        }
        if self.members.len() > MAX_DENOMINATION_MEMBERS {
            return Err(AssetError::TooManyMembers(self.members.len()));
        }
        if !self.verify_id() {
            return Err(AssetError::IdMismatch);
        }
        // The claim must be anchored: a members-only denomination is a
        // statement about nothing.
        if self.anchor_root == [0u8; 32] {
            return Err(AssetError::Unanchored);
        }
        for (i, member) in self.members.iter().enumerate() {
            if !has_claim_domain(member.domain) {
                return Err(AssetError::UnverifiedDomain {
                    index: i,
                    domain: member.domain,
                });
            }
            for (j, earlier) in self.members.iter().enumerate().take(i) {
                if earlier == member {
                    return Err(AssetError::DuplicateMember { index: i });
                }
                // One domain cannot contribute two members: a unified balance
                // derives one amount per (denomination, domain), so a second
                // member on the same domain would either be ignored (silently
                // wrong) or double-counted (worse).
                if earlier.domain == member.domain {
                    return Err(AssetError::SameDomainTwice { a: j, b: i });
                }
            }
        }
        Ok(())
    }

    /// The domains this denomination spans.
    #[must_use]
    pub fn domains(&self) -> Vec<u32> {
        self.members.iter().map(|m| m.domain).collect()
    }

    /// Whether a given chain-native id is a member of this denomination.
    #[must_use]
    pub fn contains(&self, domain: u32, native_id: &Hash32) -> bool {
        self.members
            .iter()
            .any(|m| m.domain == domain && &m.native_id == native_id)
    }
}

/// What a unified balance is allowed to sum, and under what id.
///
/// The index is the only place that turns a chain-native asset into a universal
/// one, which is what makes "did this asset get summed, and as what" a question
/// with one answer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DenominationIndex {
    /// Admitted denominations, keyed by id.
    ///
    /// `serde(default)` matters: a snapshot written before this field existed
    /// must decode as an empty index, not fail to decode. A missing field that
    /// broke decoding would make every old snapshot unloadable, which is the
    /// one way a consensus field can be worse than no field.
    #[serde(default)]
    entries: Vec<Denomination>,
}

impl Default for DenominationIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Default ceiling on admitted denominations.
pub const MAX_DENOMINATIONS: usize = 1_024;

impl DenominationIndex {
    /// An empty index at the default ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many denominations are admitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is admitted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Admits a denomination.
    ///
    /// Two refusals beyond the shape rules, both about what an index is *for*:
    ///
    /// - a denomination whose id is already admitted is a no-op, not an error,
    ///   because declaring the same equivalence twice is the same claim;
    /// - a denomination that lists a `(domain, native_id)` pair already mapped
    ///   to a *different* universal id is refused. That is the concrete attack:
    ///   one chain asset declared as a member of two assets would be summed into
    ///   both, and the unified balance would report money that is not there
    ///   twice over.
    ///
    /// # Errors
    ///
    /// [`AssetError`] if the shape fails or the index would become ambiguous.
    pub fn admit<F>(
        &mut self,
        denomination: Denomination,
        has_claim_domain: F,
    ) -> Result<(), AssetError>
    where
        F: Fn(u32) -> bool,
    {
        denomination.validate_shape(has_claim_domain)?;

        if self
            .entries
            .iter()
            .any(|d| d.denomination_id == denomination.denomination_id)
        {
            return Ok(());
        }
        if self.entries.len() >= MAX_DENOMINATIONS {
            return Err(AssetError::IndexFull);
        }

        for member in &denomination.members {
            if let Some(other) = self.lookup(member.domain, &member.native_id) {
                if other != denomination.denomination_id {
                    return Err(AssetError::AlreadyDenominated {
                        domain: member.domain,
                    });
                }
            }
        }

        self.entries.push(denomination);
        Ok(())
    }

    /// The universal id of a chain-native asset, if somebody proved one.
    ///
    /// `None` is the honest answer for an un-denominated asset, and a caller
    /// that sums must skip it rather than fall back to the native id.
    #[must_use]
    pub fn lookup(&self, domain: u32, native_id: &Hash32) -> Option<Hash32> {
        self.entries
            .iter()
            .find(|d| d.contains(domain, native_id))
            .map(|d| d.denomination_id)
    }

    /// The denomination behind a universal id.
    #[must_use]
    pub fn get(&self, universal_id: &Hash32) -> Option<&Denomination> {
        self.entries
            .iter()
            .find(|d| &d.denomination_id == universal_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> Address {
        Address::from([0xD4; 32])
    }

    fn eth(g: u8) -> AssetMember {
        AssetMember::new(1, [g; 32])
    }

    fn sol(g: u8) -> AssetMember {
        AssetMember::new(9, [g; 32])
    }

    fn any_verified(_d: u32) -> bool {
        true
    }

    /// Declaration order is not part of the claim: "A and B are one asset" and
    /// "B and A are one asset" are the same denomination.
    #[test]
    fn the_same_members_in_any_order_are_one_denomination() {
        let a = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        let b = Denomination::declare_anchored(
            issuer(),
            vec![sol(1), eth(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        assert_eq!(
            a.denomination_id, b.denomination_id,
            "member order changed the denomination id"
        );
    }

    /// Widening an asset to swallow a second one produces a different id, so it
    /// cannot be mistaken for the old denomination.
    #[test]
    fn adding_a_member_is_a_different_denomination_not_a_wider_one() {
        let narrow = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        let wide = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1), eth(2)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        assert_ne!(
            narrow.denomination_id, wide.denomination_id,
            "a denomination absorbed a second asset under its old id"
        );
        assert!(
            !narrow.contains(1, &[2u8; 32]),
            "the narrow denomination already claimed the asset it did not list"
        );
    }

    /// The label is display only: two spellings do not split one asset.
    #[test]
    fn the_label_does_not_enter_the_id() {
        let a = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        let b = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "usd coin",
            1,
            [0xE1; 32],
            1,
        );
        assert_eq!(
            a.denomination_id, b.denomination_id,
            "a display label split one asset in two"
        );
    }

    /// The central safety rule: one chain-native asset cannot belong to two
    /// universal assets, because a unified balance would then count it twice.
    #[test]
    fn one_native_asset_cannot_be_summed_into_two_denominations() {
        let mut index = DenominationIndex::new();
        let first = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        index.admit(first, any_verified).expect("first admit");

        // A second denomination reusing Ethereum's asset 0x01 for a different
        // universal asset.
        let second = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(2)],
            "NOT-USDC",
            1,
            [0xE1; 32],
            1,
        );
        assert!(
            index.admit(second, any_verified).is_err(),
            "the same chain asset was admitted into two universal assets"
        );

        assert_eq!(index.len(), 1, "the refused denomination was stored anyway");
        assert_eq!(
            index.lookup(1, &[1u8; 32]),
            Some(first_id(&index)),
            "the lookup no longer resolves to the first denomination"
        );
    }

    fn first_id(index: &DenominationIndex) -> Hash32 {
        index.entries[0].denomination_id
    }

    /// An asset nobody denominated is not in the index, and the answer is
    /// `None`, not a guess.
    #[test]
    fn an_undenominated_asset_has_no_universal_id() {
        let mut index = DenominationIndex::new();
        index
            .admit(
                Denomination::declare_anchored(issuer(), vec![eth(1)], "DAI", 1, [0xE1; 32], 1),
                any_verified,
            )
            .expect("admit");
        assert_eq!(index.lookup(1, &[0xFF; 32]), None);
        assert_eq!(index.lookup(7, &[1u8; 32]), None);
    }

    /// A denomination naming a domain this chain cannot verify is refused: its
    /// balance could never be proven, so it would be a permanent hole in a sum.
    #[test]
    fn a_member_on_an_unverifiable_domain_is_refused() {
        let d = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), AssetMember::new(99, [5u8; 32])],
            "X",
            1,
            [0xE1; 32],
            1,
        );
        let has_claim = |domain: u32| domain != 99;
        assert_eq!(
            d.validate_shape(has_claim),
            Err(AssetError::UnverifiedDomain {
                index: 1,
                domain: 99
            })
        );
    }

    /// Two members on one domain is refused even when their native ids differ,
    /// because one domain contributes one amount to the sum.
    #[test]
    fn two_members_on_one_domain_are_refused() {
        let d =
            Denomination::declare_anchored(issuer(), vec![eth(1), eth(2)], "X", 1, [0xE1; 32], 1);
        assert_eq!(
            d.validate_shape(any_verified),
            Err(AssetError::SameDomainTwice { a: 0, b: 1 })
        );
    }

    /// A denomination with no anchor root is a claim nobody proved.
    #[test]
    fn an_unanchored_denomination_is_refused() {
        let d = Denomination::declare(issuer(), vec![eth(1), sol(1)], "USDC");
        assert_eq!(d.anchor_root, [0u8; 32]);
        assert_eq!(
            d.validate_shape(any_verified),
            Err(AssetError::Unanchored),
            "a members-only claim was admitted"
        );
    }

    /// Re-declaring the same equivalence is a no-op, not an error.
    #[test]
    fn redeclaring_the_same_asset_is_idempotent() {
        let mut index = DenominationIndex::new();
        let d = Denomination::declare_anchored(
            issuer(),
            vec![eth(1), sol(1)],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        index.admit(d.clone(), any_verified).expect("first");
        index
            .admit(d, any_verified)
            .expect("second must be a no-op");
        assert_eq!(index.len(), 1);
    }
}
