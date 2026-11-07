//! Class-aware wide-stripe placement.
//!
//! The symbols of one segment go to `n = n_F + n_M` validators: `n_F` Full
//! shares of `s_F` symbols and `n_M` Mobile shares of `s_M` symbols. Every
//! share holds distinct ESIs, and any `k + 2` symbols of the union rebuild the
//! segment.
//!
//! The placement group is chosen by stake-weighted rendezvous hashing. Each
//! candidate draws `h = H(segment key, validator)`; its score is
//! `stake / -ln(u)` with `u = (h + 1) / 2^64`, which is the weighted
//! rendezvous rule. The logarithm is a Q32 fixed-point `log2` computed with
//! integers only, so every node ranks candidates identically. The choice is
//! sticky: a joining or leaving validator only moves the shares it wins or
//! held.
//!
//! A candidate whose free quota is below one share is skipped. Diversity: one
//! account holds at most `max(1, n / 64)` shares of a segment, and one network
//! prefix (IPv4 /24 or IPv6 /48, from the presence signal) at most
//! `max(2, n / 32)`. The network rule is a heuristic; the security argument
//! rests on stake weight.
//!
//! The [`PlacementTable`] is a genesis parameter computed off chain from the
//! class loss and availability rates. The consensus path only reads it, by
//! integer comparison.
//!
//! exposed for: B.U.D. 3.0 stake-weighted rendezvous placement and wide-stripe tables (`WP-20`).

use crate::core::hash::hash_fields_bytes;

/// Rendezvous draw tag.
pub const PLACEMENT_TAG: &[u8] = b"BDLM_BUD3_PLACEMENT_V1";

/// The validator class as placement sees it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Class {
    /// Full validator.
    Full,
    /// Mobile validator (Android, or the opportunistic iOS class).
    Mobile,
}

/// One placement candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Validator address.
    pub validator: [u8; 32],
    /// The owning account (several validators may share one).
    pub account: [u8; 32],
    /// Class.
    pub class: Class,
    /// Stake, the rendezvous weight. Zero stake is never chosen.
    pub stake: u64,
    /// Declared quota left, in bytes.
    pub free_quota_bytes: u64,
    /// Network prefix key from the presence signal, if known.
    pub network: Option<[u8; 8]>,
}

/// One custody share of the placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Share {
    /// The holder.
    pub validator: [u8; 32],
    /// The holder's class.
    pub class: Class,
    /// First ESI of the share.
    pub first_esi: u32,
    /// Number of consecutive ESIs.
    pub symbols: u32,
}

/// One row of the placement table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementRow {
    /// Full shares.
    pub n_full: u32,
    /// Symbols per Full share.
    pub s_full: u32,
    /// Mobile shares.
    pub n_mobile: u32,
    /// Symbols per Mobile share.
    pub s_mobile: u32,
}

impl PlacementRow {
    /// Total symbols of a segment.
    #[must_use]
    pub const fn total_symbols(&self) -> u64 {
        self.n_full as u64 * self.s_full as u64 + self.n_mobile as u64 * self.s_mobile as u64
    }

    /// Redundancy in thousandths: `total / k`.
    #[must_use]
    pub const fn redundancy_milli(&self, k: u32) -> u64 {
        if k == 0 {
            return 0;
        }
        self.total_symbols() * 1000 / k as u64
    }

    /// Symbols the Full shares hold on their own.
    #[must_use]
    pub const fn full_only_symbols(&self) -> u64 {
        self.n_full as u64 * self.s_full as u64
    }

    /// Whether the segment survives every Mobile validator leaving at once:
    /// the Full shares alone hold `k + 2` symbols.
    #[must_use]
    pub const fn survives_mobile_exit(&self, k: u32) -> bool {
        self.full_only_symbols() >= k as u64 + 2
    }

    /// The Mobile share of the symbols, in thousandths.
    #[must_use]
    pub const fn mobile_share_milli(&self) -> u64 {
        let total = self.total_symbols();
        if total == 0 {
            return 0;
        }
        self.n_mobile as u64 * self.s_mobile as u64 * 1000 / total
    }
}

/// Why a placement was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementError {
    /// No table row fits the candidates.
    NoRow,
    /// A row cannot rebuild the segment (`total < k + 2`).
    RowTooSmall,
    /// Fewer eligible candidates of a class than the row needs.
    NotEnough { class: Class, want: u32, got: u32 },
    /// The ESIs would leave the RFC 6330 range.
    EsiOverflow,
}

/// The placement table: rows by network size and class mix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementTable {
    /// Source symbols per segment the rows are computed for.
    pub k: u32,
    /// The rows.
    pub rows: Vec<PlacementRow>,
}

impl PlacementTable {
    /// The TESTNET-DEFAULT table for `k = 4096` (a computation, not a
    /// measurement; the off-chain tool recomputes it from measured rates).
    #[must_use]
    pub fn testnet_default() -> Self {
        let r = |n_full, s_full, n_mobile, s_mobile| PlacementRow {
            n_full,
            s_full,
            n_mobile,
            s_mobile,
        };
        Self {
            k: 4096,
            rows: vec![
                r(8, 443, 256, 13),
                r(16, 456, 0, 0),
                r(16, 242, 256, 8),
                r(32, 171, 0, 0),
                r(32, 116, 256, 7),
                r(64, 76, 0, 0),
                r(64, 54, 512, 4),
                r(128, 36, 0, 0),
                r(128, 26, 1024, 2),
            ],
        }
    }

    /// Check every row rebuilds a segment.
    ///
    /// # Errors
    ///
    /// [`PlacementError::RowTooSmall`].
    pub fn validate(&self) -> Result<(), PlacementError> {
        let need = u64::from(self.k) + 2;
        if self.rows.iter().any(|r| r.total_symbols() < need) {
            return Err(PlacementError::RowTooSmall);
        }
        Ok(())
    }

    /// The row for `full` and `mobile` eligible candidates: the largest
    /// `n_full` that fits, then the largest `n_mobile` that fits.
    #[must_use]
    pub fn lookup(&self, full: u32, mobile: u32) -> Option<PlacementRow> {
        self.rows
            .iter()
            .filter(|r| r.n_full <= full && r.n_mobile <= mobile)
            .max_by_key(|r| (r.n_full, r.n_mobile))
            .copied()
    }
}

/// `log2(x)` in Q32 fixed point for `x >= 1`, integers only.
fn log2_q32(x: u128) -> u64 {
    if x == 0 {
        return 0;
    }
    let int = 127 - u64::from(x.leading_zeros());
    // Normalise the mantissa to [1, 2) in Q62.
    let mut m: u128 = if int >= 62 {
        x >> (int - 62)
    } else {
        x << (62 - int)
    };
    let mut frac: u64 = 0;
    for bit in (0..32).rev() {
        m = (m * m) >> 62;
        if m >= 1u128 << 63 {
            m >>= 1;
            frac |= 1 << bit;
        }
    }
    (int << 32) | frac
}

/// `-log2(u)` in Q32 for `u = (h + 1) / 2^64`; at least 1 so no score is
/// infinite.
fn neg_log2_unit_q32(h: u64) -> u64 {
    let v = u128::from(h) + 1;
    ((64u64 << 32).saturating_sub(log2_q32(v))).max(1)
}

fn draw(segment_key: &[u8; 32], validator: &[u8; 32]) -> u64 {
    let h = hash_fields_bytes(&[PLACEMENT_TAG, segment_key, validator]);
    let mut b = [0u8; 8];
    b.copy_from_slice(h.get(..8).unwrap_or(&[0u8; 8]));
    u64::from_le_bytes(b)
}

/// A candidate with its rendezvous score `stake / l`.
#[derive(Clone, Copy)]
struct Ranked {
    c: Candidate,
    l: u64,
}

impl Ranked {
    /// `self` ranks before `other`: higher `stake / l`, ties by address.
    fn before(&self, other: &Self) -> core::cmp::Ordering {
        let a = u128::from(self.c.stake) * u128::from(other.l);
        let b = u128::from(other.c.stake) * u128::from(self.l);
        b.cmp(&a).then(self.c.validator.cmp(&other.c.validator))
    }
}

/// The rendezvous order of `candidates` for `segment_key`, best first.
/// Zero-stake candidates are dropped.
#[must_use]
pub fn rank(segment_key: &[u8; 32], candidates: &[Candidate]) -> Vec<Candidate> {
    let mut ranked: Vec<Ranked> = candidates
        .iter()
        .filter(|c| c.stake > 0)
        .map(|c| Ranked {
            c: *c,
            l: neg_log2_unit_q32(draw(segment_key, &c.validator)),
        })
        .collect();
    ranked.sort_by(Ranked::before);
    ranked.into_iter().map(|r| r.c).collect()
}

/// The segment key: the object commitment and the segment index.
#[must_use]
pub fn segment_key(object_commitment: &[u8; 32], segment: u64) -> [u8; 32] {
    hash_fields_bytes(&[PLACEMENT_TAG, object_commitment, &segment.to_le_bytes()])
}

/// Place one segment.
///
/// `symbol_size` sizes a share against each candidate's free quota. Full
/// shares take the lowest ESIs, in rank order, then the Mobile shares.
///
/// # Errors
///
/// [`PlacementError`] when the row is too small, a class has too few
/// eligible candidates, or the ESIs overflow.
pub fn place(
    segment_key: &[u8; 32],
    candidates: &[Candidate],
    row: &PlacementRow,
    k: u32,
    symbol_size: u32,
) -> Result<Vec<Share>, PlacementError> {
    if row.total_symbols() < u64::from(k) + 2 {
        return Err(PlacementError::RowTooSmall);
    }
    if row.total_symbols() > u64::from(super::fountain::MAX_ESI) {
        return Err(PlacementError::EsiOverflow);
    }
    let n = row.n_full.saturating_add(row.n_mobile);
    let account_cap = (n / 64).max(1);
    let network_cap = (n / 32).max(2);
    let ordered = rank(segment_key, candidates);
    let mut per_account: std::collections::BTreeMap<[u8; 32], u32> = Default::default();
    let mut per_network: std::collections::BTreeMap<[u8; 8], u32> = Default::default();
    let mut shares = Vec::new();
    let mut next_esi: u32 = 0;
    for (class, want, per) in [
        (Class::Full, row.n_full, row.s_full),
        (Class::Mobile, row.n_mobile, row.s_mobile),
    ] {
        let share_bytes = u64::from(per) * u64::from(symbol_size);
        let mut got = 0u32;
        for c in ordered.iter().filter(|c| c.class == class) {
            if got == want {
                break;
            }
            if c.free_quota_bytes < share_bytes {
                continue;
            }
            let acc = per_account.entry(c.account).or_insert(0);
            if *acc >= account_cap {
                continue;
            }
            if let Some(net) = c.network {
                if per_network.get(&net).copied().unwrap_or(0) >= network_cap {
                    continue;
                }
                *per_network.entry(net).or_insert(0) += 1;
            }
            *acc += 1;
            shares.push(Share {
                validator: c.validator,
                class,
                first_esi: next_esi,
                symbols: per,
            });
            next_esi = next_esi
                .checked_add(per)
                .ok_or(PlacementError::EsiOverflow)?;
            got += 1;
        }
        if got < want {
            return Err(PlacementError::NotEnough { class, want, got });
        }
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(i: u32, class: Class, stake: u64) -> Candidate {
        let mut v = [0u8; 32];
        v[..4].copy_from_slice(&i.to_le_bytes());
        Candidate {
            validator: v,
            account: v,
            class,
            stake,
            free_quota_bytes: u64::MAX,
            network: None,
        }
    }

    fn pool(full: u32, mobile: u32) -> Vec<Candidate> {
        (0..full)
            .map(|i| cand(i, Class::Full, 1000))
            .chain((0..mobile).map(|i| cand(100_000 + i, Class::Mobile, 10)))
            .collect()
    }

    #[test]
    fn log2_fixed_point_is_exact_on_powers_and_close_elsewhere() {
        assert_eq!(log2_q32(1), 0);
        assert_eq!(log2_q32(1 << 40), 40u64 << 32);
        // log2(3) = 1.584962500721156...
        let l3 = log2_q32(3) as f64 / (1u64 << 32) as f64;
        assert!((l3 - 1.584_962_500_721_156).abs() < 1e-8, "{l3}");
        assert_eq!(neg_log2_unit_q32(u64::MAX), 1, "never an infinite score");
        assert_eq!(neg_log2_unit_q32(0), 64u64 << 32);
    }

    #[test]
    fn testnet_table_rows_rebuild_and_match_the_computation() {
        let t = PlacementTable::testnet_default();
        assert!(t.validate().is_ok());
        let first = t.rows[0];
        assert_eq!(first.redundancy_milli(t.k), 1677);
        assert_eq!(first.mobile_share_milli(), 484);
        assert_eq!(t.lookup(8, 300), Some(first));
        assert_eq!(t.lookup(20, 0), Some(t.rows[1]));
        assert_eq!(t.lookup(40, 300), Some(t.rows[4]));
        assert_eq!(t.lookup(7, 1000), None);
        let mut bad = t.clone();
        bad.rows.push(PlacementRow {
            n_full: 1,
            s_full: 10,
            n_mobile: 0,
            s_mobile: 0,
        });
        assert_eq!(bad.validate(), Err(PlacementError::RowTooSmall));
    }

    #[test]
    fn mobile_exit_survival_is_measured_per_row() {
        let t = PlacementTable::testnet_default();
        let failing: Vec<_> = t
            .rows
            .iter()
            .filter(|r| !r.survives_mobile_exit(t.k))
            .collect();
        // The mixed rows of the default table do not survive a full Mobile
        // exit; this is the open table-versus-launch-gate decision.
        assert!(failing.iter().all(|r| r.n_mobile > 0));
        assert!(t
            .rows
            .iter()
            .filter(|r| r.n_mobile == 0)
            .all(|r| r.survives_mobile_exit(t.k)));
    }

    #[test]
    fn placement_gives_distinct_esis_and_the_row_shape() {
        let t = PlacementTable::testnet_default();
        let row = t.lookup(8, 256).unwrap();
        let shares = place(&[1; 32], &pool(10, 300), &row, t.k, 2911).unwrap();
        assert_eq!(shares.iter().filter(|s| s.class == Class::Full).count(), 8);
        assert_eq!(
            shares.iter().filter(|s| s.class == Class::Mobile).count(),
            256
        );
        let mut next = 0u32;
        for s in &shares {
            assert_eq!(s.first_esi, next, "contiguous, distinct ESIs");
            next += s.symbols;
        }
        assert_eq!(u64::from(next), row.total_symbols());
        let mut holders: Vec<_> = shares.iter().map(|s| s.validator).collect();
        holders.sort();
        holders.dedup();
        assert_eq!(holders.len(), shares.len(), "one share per validator here");
    }

    #[test]
    fn placement_is_sticky() {
        let row = PlacementRow {
            n_full: 16,
            s_full: 456,
            n_mobile: 0,
            s_mobile: 0,
        };
        let mut c = pool(40, 0);
        let before = place(&[7; 32], &c, &row, 4096, 2911).unwrap();
        c.push(cand(999, Class::Full, 1000));
        let after = place(&[7; 32], &c, &row, 4096, 2911).unwrap();
        let b: std::collections::BTreeSet<_> = before.iter().map(|s| s.validator).collect();
        let a: std::collections::BTreeSet<_> = after.iter().map(|s| s.validator).collect();
        assert!(
            b.difference(&a).count() <= 1,
            "one joiner moves at most one share"
        );
    }

    #[test]
    fn stake_weight_drives_selection() {
        // Ten heavy and thirty light Full candidates, 16 shares, many segments:
        // the heavy ones win far more than their head count.
        let mut c: Vec<Candidate> = (0..10).map(|i| cand(i, Class::Full, 100_000)).collect();
        c.extend((10..40).map(|i| cand(i, Class::Full, 1_000)));
        let row = PlacementRow {
            n_full: 4,
            s_full: 1100,
            n_mobile: 0,
            s_mobile: 0,
        };
        let mut heavy = 0u32;
        for seg in 0..200u64 {
            let key = segment_key(&[3; 32], seg);
            for s in place(&key, &c, &row, 4096, 2911).unwrap() {
                if u32::from_le_bytes(s.validator[..4].try_into().unwrap()) < 10 {
                    heavy += 1;
                }
            }
        }
        assert!(
            heavy > 700,
            "{heavy} of 800 shares went to the heavy quarter"
        );
        let zero = vec![cand(1, Class::Full, 0)];
        assert!(
            rank(&[0; 32], &zero).is_empty(),
            "zero stake is never chosen"
        );
    }

    #[test]
    fn quota_and_diversity_caps_are_enforced() {
        let row = PlacementRow {
            n_full: 4,
            s_full: 1100,
            n_mobile: 0,
            s_mobile: 0,
        };
        // All candidates in one /24: at most max(2, 4/32) = 2 shares.
        let mut c = pool(10, 0);
        for x in &mut c {
            x.network = Some([1; 8]);
        }
        assert_eq!(
            place(&[2; 32], &c, &row, 4096, 2911),
            Err(PlacementError::NotEnough {
                class: Class::Full,
                want: 4,
                got: 2
            })
        );
        // One account behind every validator: one share.
        let mut c = pool(10, 0);
        for x in &mut c {
            x.account = [5; 32];
        }
        assert!(matches!(
            place(&[2; 32], &c, &row, 4096, 2911),
            Err(PlacementError::NotEnough { got: 1, .. })
        ));
        // A full quota is skipped, not chosen.
        let mut c = pool(5, 0);
        c[0].free_quota_bytes = 0;
        let shares = place(&[2; 32], &c, &row, 4096, 2911).unwrap();
        assert!(shares.iter().all(|s| s.validator != c[0].validator));
    }
}
