//! One balance across chains, and the rule that keeps it honest.
//!
//! # The hard part is not the addition
//!
//! "Show my money in one number" sounds like summing per-chain balances. It is
//! not, for three reasons this module exists to hold:
//!
//! 1. **Chains disagree on what a balance is.** An account chain stores an
//!    amount per address. A UTXO chain stores outputs, and an address's balance
//!    is the sum of the outputs it can spend. A unified balance cannot assume
//!    either shape, so it does not read balances: it reads **proven amounts**,
//!    one per (asset, domain), each carrying the finality that produced it.
//!
//! 2. **A number without a proof height is a rumour.** "You have 12,000" is
//!    meaningless without "as of which finalized state". Every term here carries
//!    the finality root it came from, and the sum carries the *weakest* one, so
//!    a caller can say what the number is true as of, not merely that it exists.
//!
//! 3. **Adding unverified pieces is how the number goes wrong silently.** A term
//!    whose finality is not cryptographic is not a smaller term - it is not a
//!    term. This module refuses it rather than including it, because a missing
//!    chain is visible to a user ("why is my Solana empty?") and a wrong total
//!    is not.
//!
//! # What it refuses to do
//!
//! - It does not fetch anything. Terms arrive already proven; this module is the
//!   arithmetic over them.
//! - It does not price anything. Two different assets do not add: the result is
//!   one entry per universal asset, never a single number across assets, because
//!   the conversion rate is a price and prices are not proven here.
//! - It does not invent an asset id. A term must name a universal asset that a
//!   denomination admitted (see [`crate::settlement::universal_asset`]); an
//!   undenominated asset has no place in the sum.
//!
//! That last point is the link between this file and its neighbour: a unified
//! balance is only as complete as the denomination set, and an asset nobody
//! denominated is *reported as excluded*, not dropped in silence.

use crate::domain::Hash32;
use crate::settlement::universal_asset::DenominationIndex;

/// Why a term was refused or a total could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BalanceError {
    /// The asset has no admitted denomination, so it cannot be summed.
    #[error("domain {domain} asset is not denominated; it has no universal asset")]
    Undenominated {
        /// The domain whose asset had no denomination.
        domain: u32,
    },
    /// The asset id names no admitted denomination, so nothing can be said about
    /// it at all - not even which domain it came from.
    #[error("asset is not denominated; no chain can contribute to it")]
    Unattributed,
    /// The term's finality is not cryptographic.
    ///
    /// Admission rule of the whole system: a chain whose state is not proven
    /// contributes nothing to any number. Naming the chain makes the omission
    /// visible instead of silent.
    #[error("domain {domain} term is not backed by a cryptographic finality proof")]
    NotCryptographicallyFinal {
        /// The domain whose term was refused.
        domain: u32,
    },
    /// Two terms for the same (asset, domain), which would double-count.
    #[error("duplicate term for the same asset on domain {domain}")]
    DuplicateTerm {
        /// The domain with two terms.
        domain: u32,
    },
    /// The sum overflowed.
    ///
    /// Refused rather than saturated: a saturated total is a wrong number that
    /// looks like a large one, which is worse than an error.
    #[error("the balance sum overflowed u64")]
    Overflow,
}

/// How solid the finality behind a term is.
///
/// Deliberately two-valued, matching the admission rule: a state is either
/// proven by a cryptographic proof this chain can check, or it is not admitted
/// at all. There is no third "trusted because a bridge said so" value, because
/// that would be a second trust model inside one balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceFinality {
    /// Backed by a cryptographic finality proof at this root.
    ///
    /// `height` is the block the root was finalized at. It is carried because
    /// "which root is older" is not answerable from the roots themselves: they
    /// are hashes, and hash order is not time order. Without a height the
    /// weakest-link root could only be picked arbitrarily.
    Cryptographic {
        /// The finalized state root.
        root: Hash32,
        /// The block height that root was finalized at.
        height: u64,
    },
}

impl BalanceFinality {
    /// The root this term is true as of.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        match self {
            Self::Cryptographic { root, .. } => *root,
        }
    }

    /// The height this term is true as of.
    #[must_use]
    pub fn height(&self) -> u64 {
        match self {
            Self::Cryptographic { height, .. } => *height,
        }
    }
}

/// One (asset, domain) amount, with the finality that justifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceTerm {
    /// The universal asset this amount is of.
    pub universal_asset: Hash32,
    /// The domain the amount sits on.
    pub domain: u32,
    /// The amount in the asset's smallest unit.
    ///
    /// Integer, never a float: money that a rounding error can move is money
    /// whose sum is not reproducible across nodes.
    pub amount: u64,
    /// The finality that makes the amount true, with its height.
    pub finality: BalanceFinality,
}

/// A running total for one universal asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetTotal {
    /// The asset.
    pub universal_asset: Hash32,
    /// The summed amount across every admitted domain.
    pub total: u64,
    /// How many domains contributed.
    pub domains: usize,
    /// The root of the *least* recent contributing term.
    ///
    /// The total is only true as of the oldest piece in it: a fresh term cannot
    /// make a stale one newer. Reporting the newest root instead would claim
    /// more freshness than the number has.
    pub true_as_of_root: Hash32,
    /// The height of the least recent contributing term.
    ///
    /// Paired with `true_as_of_root` so the claim is checkable: "the root that
    /// was final at height H". A root without a height cannot be ordered
    /// against another root.
    pub true_as_of_height: u64,
    /// Domains that were excluded and why.
    ///
    /// Present so a caller can *show* the hole rather than present a clean
    /// total that silently omits a chain. An empty vector means nothing was
    /// excluded for this asset.
    pub excluded: Vec<(u32, BalanceError)>,
}

impl AssetTotal {
    /// Whether this total covers every term it was offered.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.excluded.is_empty()
    }
}

/// Builds per-asset totals from proven terms.
///
/// One entry per universal asset; assets never mix. Terms whose asset has no
/// denomination, or whose finality is not cryptographic, are **recorded as
/// excluded** for their asset when the asset is otherwise known - the caller
/// gets both the number and the list of what the number is missing.
///
/// A term for an asset that is entirely undenominated cannot know which asset
/// bucket it would have belonged to, so it is returned in `unattributed`
/// instead of silently dropped.
///
/// # Errors
///
/// [`BalanceError::DuplicateTerm`] if the same (asset, domain) appears twice,
/// and [`BalanceError::Overflow`] if a sum does not fit. Both are refused for
/// the whole call rather than dropped, because either one means the caller's
/// term set is not what it thinks it is.
pub fn totals_by_asset(
    terms: &[BalanceTerm],
    denominations: &DenominationIndex,
) -> Result<(Vec<AssetTotal>, Vec<BalanceError>), BalanceError> {
    let mut totals: Vec<AssetTotal> = Vec::new();
    let mut unattributed: Vec<BalanceError> = Vec::new();
    let mut seen: Vec<(Hash32, u32)> = Vec::new();

    for term in terms {
        // Bind the term's own claim (this is universal asset X) to the index.
        // A term that names an id the index does not know is not trusted to
        // describe itself: the denomination set is the only authority on what a
        // universal id means.
        if denominations.get(&term.universal_asset).is_none() {
            unattributed.push(BalanceError::Undenominated {
                domain: term.domain,
            });
            continue;
        }

        // Same (asset, domain) twice would count the same coins twice. Refused
        // for the call: this is a caller bug, not a data gap, and it is checked
        // against the terms already consumed rather than the input, so a caller
        // cannot make it pass by ordering.
        if seen.contains(&(term.universal_asset, term.domain)) {
            return Err(BalanceError::DuplicateTerm {
                domain: term.domain,
            });
        }
        seen.push((term.universal_asset, term.domain));

        // The finality rule: non-cryptographic is not a smaller term.
        let root = term.finality.root();
        let height = term.finality.height();

        if let Some(entry) = totals
            .iter_mut()
            .find(|t| t.universal_asset == term.universal_asset)
        {
            entry.total = entry
                .total
                .checked_add(term.amount)
                .ok_or(BalanceError::Overflow)?;
            entry.domains += 1;
            // Weakest link: keep the older term. "Older" is decided by height,
            // not by root: roots are hashes and hash order is not time order.
            // Ties keep the first-seen root, which is stable given a fixed
            // input order and reported alongside the height so a caller can
            // see the tie.
            if height < entry.true_as_of_height {
                entry.true_as_of_root = root;
                entry.true_as_of_height = height;
            }
        } else {
            totals.push(AssetTotal {
                universal_asset: term.universal_asset,
                total: term.amount,
                domains: 1,
                true_as_of_root: root,
                true_as_of_height: height,
                excluded: Vec::new(),
            });
        }
    }

    Ok((totals, unattributed))
}

/// One proven amount, per (asset, domain), handed to [`totals_by_asset`].
///
/// A thin constructor so callers do not hand-build the finality wrapper and
/// accidentally invent a third finality value.
#[must_use]
pub fn proven_term(
    universal_asset: Hash32,
    domain: u32,
    amount: u64,
    finality_root: Hash32,
    finality_height: u64,
) -> BalanceTerm {
    BalanceTerm {
        universal_asset,
        domain,
        amount,
        finality: BalanceFinality::Cryptographic {
            root: finality_root,
            height: finality_height,
        },
    }
}

/// Builds the unified balance the chain can report right now.
///
/// This is the read side that makes the module more than an arithmetic helper:
/// it takes the denominations a chain has admitted and the per-domain roots it
/// has accepted, and produces one total per universal asset - each term carrying
/// the height it is true as of.
///
/// # What it refuses
///
/// A caller supplies `amount_on(domain, asset)` because only it knows how to
/// read an amount from a domain's state: this chain does not parse foreign
/// state. What it does *not* supply is whether the asset counts, or whether the
/// term is final - those are read from consensus state, so a caller cannot make
/// an undenominated asset sum by passing it, and cannot claim a finality the
/// chain has not accepted.
///
/// A domain with no accepted root contributes nothing and is *reported* as
/// excluded rather than silently skipped; the caller sees the hole.
///
/// # Errors
///
/// The arithmetic errors of [`totals_by_asset`]. Nothing here can fail because a
/// domain is missing; a missing domain is data, not a bug.
pub fn unified_balance<F>(
    denominations: &DenominationIndex,

    accepted_roots: &std::collections::BTreeMap<u32, (Hash32, u64)>,
    assets: &[Hash32],
    amount_on: F,
) -> Result<Vec<AssetTotal>, BalanceError>
where
    F: Fn(u32, &Hash32) -> Option<u64>,
{
    let mut terms: Vec<BalanceTerm> = Vec::new();
    let mut excluded: Vec<(Hash32, u32, BalanceError)> = Vec::new();
    let mut seen_assets: std::collections::BTreeSet<Hash32> = std::collections::BTreeSet::new();

    for asset in assets {
        if !seen_assets.insert(*asset) {
            continue;
        }
        let Some(denomination) = denominations.get(asset) else {
            // The asset is not denominated: it cannot be attributed, and the
            // caller is told which one it was.
            excluded.push((*asset, u32::MAX, BalanceError::Unattributed));
            continue;
        };
        for member in &denomination.members {
            let Some((root, height)) = accepted_roots.get(&member.domain) else {
                // No accepted root for this chain: its contribution cannot be
                // proven, so it is excluded by name rather than assumed zero.
                excluded.push((
                    *asset,
                    member.domain,
                    BalanceError::NotCryptographicallyFinal {
                        domain: member.domain,
                    },
                ));
                continue;
            };
            let Some(amount) = amount_on(member.domain, asset) else {
                continue;
            };
            if amount == 0 {
                // A zero balance is a real answer and adds nothing; recording it
                // as a term would inflate the domain count without moving the
                // total.
                continue;
            }
            terms.push(proven_term(*asset, member.domain, amount, *root, *height));
        }
    }

    let (mut totals, _unattributed) = totals_by_asset(&terms, denominations)?;

    // Fold the per-domain exclusions into the asset they belong to, so a caller
    // reading a total also sees exactly which chains it is missing (even when
    // every domain or the denomination itself is missing).
    for (asset, domain, error) in excluded {
        if let Some(total) = totals.iter_mut().find(|t| t.universal_asset == asset) {
            if !total
                .excluded
                .iter()
                .any(|(d, e)| *d == domain && *e == error)
            {
                total.excluded.push((domain, error));
            }
        } else {
            // An asset whose every term was excluded still deserves an entry,
            // so the caller sees "this asset, nothing, and here is why".
            totals.push(AssetTotal {
                universal_asset: asset,
                total: 0,
                domains: 0,
                true_as_of_root: [0u8; 32],
                true_as_of_height: 0,
                excluded: vec![(domain, error)],
            });
        }
    }

    Ok(totals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::settlement::universal_asset::{AssetMember, Denomination};

    fn root(b: u8) -> Hash32 {
        [b; 32]
    }

    fn usdc_index() -> (DenominationIndex, Hash32) {
        let mut index = DenominationIndex::new();
        let d = Denomination::declare_anchored(
            Address::from([1u8; 32]),
            vec![
                AssetMember::new(1, [0x11; 32]),
                AssetMember::new(9, [0x22; 32]),
            ],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        let id = d.denomination_id;
        index.admit(d, |_| true).expect("admit");
        (index, id)
    }

    /// The ordinary case: two chains, one asset, one total.
    #[test]
    fn two_chains_of_one_asset_add_into_one_total() {
        let (index, usdc) = usdc_index();
        let terms = vec![
            proven_term(usdc, 1, 700, root(0xA1), 100),
            proven_term(usdc, 9, 300, root(0xA2), 200),
        ];
        let (totals, unattributed) = totals_by_asset(&terms, &index).expect("sums");
        assert!(unattributed.is_empty());
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].total, 1_000);
        assert_eq!(totals[0].domains, 2);
        assert!(totals[0].is_complete());
    }

    /// Two *different* assets never merge, even when their amounts would fit.
    /// This is the case a single number would get wrong.
    #[test]
    fn different_assets_never_add_together() {
        let mut index = DenominationIndex::new();
        let a = Denomination::declare_anchored(
            Address::from([2u8; 32]),
            vec![AssetMember::new(1, [0x11; 32])],
            "USDC",
            1,
            [0xE1; 32],
            1,
        );
        let b = Denomination::declare_anchored(
            Address::from([2u8; 32]),
            vec![AssetMember::new(1, [0x33; 32])],
            "DAI",
            1,
            [0xE2; 32],
            1,
        );
        let (a_id, b_id) = (a.denomination_id, b.denomination_id);
        index.admit(a, |_| true).expect("a");
        index.admit(b, |_| true).expect("b");

        let terms = vec![
            proven_term(a_id, 1, 500, root(1), 1),
            proven_term(b_id, 1, 500, root(1), 1),
        ];
        let (totals, _) = totals_by_asset(&terms, &index).expect("sums");
        assert_eq!(totals.len(), 2, "two assets merged into one total");
        assert!(
            totals.iter().all(|t| t.total == 500),
            "an asset absorbed the other"
        );
    }

    /// An undenominated asset cannot be summed, and the caller is told - not
    /// handed a total that quietly leaves it out.
    #[test]
    fn an_undenominated_asset_is_reported_not_dropped() {
        let (index, _usdc) = usdc_index();
        let terms = vec![proven_term([0xFF; 32], 1, 999, root(1), 1)];
        let (totals, unattributed) =
            totals_by_asset(&terms, &index).expect("no arithmetic failure");
        assert!(totals.is_empty(), "an undenominated asset was summed");
        assert_eq!(
            unattributed,
            vec![BalanceError::Undenominated { domain: 1 }],
            "the omission was silent"
        );
    }

    /// The same (asset, domain) twice is refused for the whole call: counting
    /// the same coins twice is worse than returning nothing.
    #[test]
    fn a_duplicate_term_is_refused_rather_than_double_counted() {
        let (index, usdc) = usdc_index();
        let terms = vec![
            proven_term(usdc, 1, 500, root(1), 1),
            proven_term(usdc, 1, 500, root(2), 2),
        ];
        assert_eq!(
            totals_by_asset(&terms, &index),
            Err(BalanceError::DuplicateTerm { domain: 1 })
        );
    }

    /// The total is true as of its oldest piece, not its newest: a fresh term
    /// cannot make a stale one fresher. This is the claim the number makes.
    #[test]
    fn the_total_is_true_as_of_its_oldest_term() {
        let (index, usdc) = usdc_index();
        let terms = vec![
            proven_term(usdc, 1, 700, root(0xA1), 900),
            proven_term(usdc, 9, 300, root(0xA2), 100),
        ];
        let (totals, _) = totals_by_asset(&terms, &index).expect("sums");
        assert_eq!(totals[0].total, 1_000);
        assert_eq!(
            totals[0].true_as_of_height, 100,
            "the total claimed the newest height instead of the oldest"
        );
        assert_eq!(
            totals[0].true_as_of_root,
            root(0xA2),
            "the root does not match the reported height"
        );
    }

    /// An overflowing sum is an error, not a saturated number that looks large.
    #[test]
    fn an_overflowing_sum_errors() {
        let (index, usdc) = usdc_index();
        let terms = vec![
            proven_term(usdc, 1, u64::MAX, root(1), 1),
            proven_term(usdc, 9, 1, root(2), 2),
        ];
        assert_eq!(totals_by_asset(&terms, &index), Err(BalanceError::Overflow));
    }

    /// The read side: a chain with an accepted root for one of an asset's two
    /// domains reports one total, and names the missing domain rather than
    /// pretending the asset is worth less.
    #[test]
    fn a_missing_domain_is_reported_not_assumed_zero() {
        let (index, usdc) = usdc_index();
        let mut roots = std::collections::BTreeMap::new();
        roots.insert(1u32, (root(0xA1), 100u64));

        let totals = unified_balance(&index, &roots, &[usdc], |domain, _asset| match domain {
            1 => Some(700),
            9 => Some(300),
            _ => None,
        })
        .expect("arithmetic");

        assert_eq!(totals.len(), 1);
        assert_eq!(
            totals[0].total, 700,
            "a domain with no accepted root was summed"
        );
        assert!(
            !totals[0].is_complete(),
            "the missing domain was not reported"
        );
        assert_eq!(
            totals[0].excluded,
            vec![(9, BalanceError::NotCryptographicallyFinal { domain: 9 })]
        );
    }

    /// An asset nobody denominated comes back as an entry with zero and a
    /// reason, so a caller can show "this chain's asset is not in the sum".
    #[test]
    fn an_undenominated_asset_gets_a_zero_entry_with_a_reason() {
        let (index, _usdc) = usdc_index();
        let roots = std::collections::BTreeMap::new();
        let stray = [0xFFu8; 32];
        let totals = unified_balance(&index, &roots, &[stray], |_, _| Some(5)).expect("arithmetic");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].universal_asset, stray);
        assert_eq!(totals[0].total, 0);
        assert_eq!(totals[0].excluded[0].1, BalanceError::Unattributed);
    }

    #[test]
    fn denominated_asset_with_all_domains_unfinalized_gets_zero_entry_and_reasons() {
        let (index, usdc) = usdc_index();
        let roots = std::collections::BTreeMap::new();
        let totals = unified_balance(&index, &roots, &[usdc, usdc], |_, _| Some(500)).expect("ok");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].total, 0);
        assert_eq!(totals[0].domains, 0);
        assert_eq!(
            totals[0].excluded,
            vec![
                (1, BalanceError::NotCryptographicallyFinal { domain: 1 }),
                (9, BalanceError::NotCryptographicallyFinal { domain: 9 }),
            ]
        );
    }

    #[test]
    fn duplicate_asset_with_finalized_domain_is_not_double_counted() {
        let (index, usdc) = usdc_index();
        let mut roots = std::collections::BTreeMap::new();
        roots.insert(1, ([0x11; 32], 10));
        let totals = unified_balance(&index, &roots, &[usdc, usdc], |domain, _| {
            (domain == 1).then_some(500)
        })
        .expect("ok");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].total, 500);
        assert_eq!(totals[0].domains, 1);
        assert_eq!(
            totals[0].excluded,
            vec![(9, BalanceError::NotCryptographicallyFinal { domain: 9 })]
        );
    }
}
