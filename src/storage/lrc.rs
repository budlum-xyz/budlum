//! Local reconstruction codes: redundancy that costs almost nothing.
//!
//! Every scheme in `src/storage/erasure.rs` protects one object at a time. A
//! `(10, 16)` object carries six parity shards of its own, so redundancy
//! costs 0.600x on top of the data no matter how many objects exist.
//!
//! An LRC group holds the data shards of *many* objects and protects them
//! together. Measured, at a 24-hour repair window and 5% annual drive
//! failure:
//!
//! | scheme | shards | multiplier | shards read to repair one |
//! |---|---|---|---|
//! | RS (10,16) per object | 16 | 1.600x | 10 |
//! | RS (20,26) per object | 26 | 1.300x | 20 |
//! | LRC k=500, L=25, G=10 | 535 | **1.070x** | 20 |
//! | LRC k=2000, L=50, G=12 | 2062 | **1.031x** | 40 |
//!
//! Redundancy falls from 0.600x to 0.031x, which is a 95% cut in the
//! overhead alone, while a single-shard repair still reads only its local
//! group.
//!
//! # Why not simply share parity across a big group
//!
//! That was measured first and it collapses. Sharing `m` parity shards
//! across `g` objects gives a multiplier of `1 + m/(g*k)`, which looks
//! excellent at `g = 200`, but tolerance becomes group-wide: 2000 shards
//! surviving 6 losses is 125 times weaker than 16 shards surviving 6. Worse,
//! repairing one shard means reading the entire group, and since durability
//! is governed by the repair window rather than the parity count, a repair
//! 200 times more expensive gives the gain straight back.
//!
//! LRC exists for exactly those two problems. Local parity makes the common
//! case, a single loss, cheap. Global parity supplies the tolerance that
//! local groups alone cannot.
//!
//! # Read latency does not move
//!
//! Reading an object touches only that object's data shards. The parity is
//! for repair, so a wider group buys cheaper redundancy without making any
//! read wider. This is the property that makes a large `k` acceptable here
//! when it would not be inside a single object's erasure scheme.
//!
//! Azure's LRC and HDFS-Xorbas run this shape in production.
//!
//! WIRING: unwired - measured: no production path builds an `LrcLayout` yet.
//! Placement, the coding audit and the repair trigger all have to read from
//! the same group description, and wiring this before them would connect one
//! end of a chain whose other end is open.

use crate::core::hash::hash_fields_bytes;

/// Largest coding group this admits.
///
/// The group is the unit a repair reasons about, and its description is held
/// in memory while one runs. Past a few thousand shards the bookkeeping stops
/// being free and the marginal gain is already spent: going from `k = 2000`
/// to `k = 4000` moves the multiplier by 0.015x.
pub const MAX_GROUP_SHARDS: u32 = 4096;

/// Why a layout was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LrcError {
    /// No data shards. There is nothing to protect.
    NoDataShards,
    /// No local groups, which would make every repair read the whole group
    /// and turn this back into the shared-parity scheme LRC replaces.
    NoLocalGroups,
    /// More local groups than data shards, so a group would be empty and its
    /// parity would protect nothing while still costing a shard.
    MoreGroupsThanShards { data_shards: u32, local_groups: u32 },
    /// The group exceeds what a repair can hold.
    GroupTooLarge { shards: u32, max: u32 },
    /// A shard index outside the group.
    ShardOutOfRange { index: u32, data_shards: u32 },
}

impl std::fmt::Display for LrcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDataShards => write!(f, "an LRC group needs at least one data shard"),
            Self::NoLocalGroups => write!(
                f,
                "an LRC group needs at least one local group, or every repair reads \
                 the whole group"
            ),
            Self::MoreGroupsThanShards {
                data_shards,
                local_groups,
            } => write!(
                f,
                "{local_groups} local groups over {data_shards} data shards leaves a \
                 group empty, whose parity protects nothing and still costs a shard"
            ),
            Self::GroupTooLarge { shards, max } => {
                write!(f, "{shards} shards exceeds the {max} a repair can hold")
            }
            Self::ShardOutOfRange { index, data_shards } => write!(
                f,
                "shard {index} is outside a group of {data_shards} data shards"
            ),
        }
    }
}

impl std::error::Error for LrcError {}

/// The shape of one coding group.
///
/// Deliberately a description rather than the bytes. Placement, the coding
/// audit and repair all need to agree on which shards belong together, and a
/// second copy of that agreement is a second thing that can drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LrcLayout {
    /// Data shards in the group, drawn from many objects.
    pub data_shards: u32,
    /// How many local groups the data is split into. Each gets one local
    /// parity shard.
    pub local_groups: u32,
    /// Global parity shards, computed over all data shards.
    pub global_parity: u32,
}

impl LrcLayout {
    /// Build and check a layout.
    ///
    /// # Errors
    ///
    /// [`LrcError::NoDataShards`], [`LrcError::NoLocalGroups`],
    /// [`LrcError::MoreGroupsThanShards`] and [`LrcError::GroupTooLarge`].
    pub const fn new_lrc_group(
        data_shards: u32,
        local_groups: u32,
        global_parity: u32,
    ) -> Result<Self, LrcError> {
        if data_shards == 0 {
            return Err(LrcError::NoDataShards);
        }
        if local_groups == 0 {
            return Err(LrcError::NoLocalGroups);
        }
        if local_groups > data_shards {
            return Err(LrcError::MoreGroupsThanShards {
                data_shards,
                local_groups,
            });
        }
        let total = data_shards
            .saturating_add(local_groups)
            .saturating_add(global_parity);
        if total > MAX_GROUP_SHARDS {
            return Err(LrcError::GroupTooLarge {
                shards: total,
                max: MAX_GROUP_SHARDS,
            });
        }
        Ok(Self {
            data_shards,
            local_groups,
            global_parity,
        })
    }

    /// Every shard in the group: data, then local parity, then global.
    #[must_use]
    pub const fn lrc_total_shards(&self) -> u32 {
        self.data_shards + self.local_groups + self.global_parity
    }

    /// Parity shards, local and global together.
    #[must_use]
    pub const fn lrc_parity_shards(&self) -> u32 {
        self.local_groups + self.global_parity
    }

    /// Stored bytes per byte of content, scaled by 1000 to stay in integer
    /// arithmetic. `(10,16)` is 1600; an LRC group at `k=2000` is 1031.
    ///
    /// Integer because a multiplier that differed in its last bit between
    /// machines would make two nodes disagree about what a group costs.
    #[must_use]
    pub fn lrc_overhead_per_mille(&self) -> u32 {
        // total * 1000 / data, in u64 so a large group cannot overflow the
        // multiplication before the divide.
        let scaled = u64::from(self.lrc_total_shards()) * 1000 / u64::from(self.data_shards);
        u32::try_from(scaled).unwrap_or(u32::MAX)
    }

    /// Which local group a data shard belongs to.
    ///
    /// # Errors
    ///
    /// [`LrcError::ShardOutOfRange`] for an index past the data shards.
    pub const fn local_group_of(&self, index: u32) -> Result<u32, LrcError> {
        if index >= self.data_shards {
            return Err(LrcError::ShardOutOfRange {
                index,
                data_shards: self.data_shards,
            });
        }
        // Ceiling division so the last group takes the remainder rather than
        // an extra group appearing for it.
        let per = self.data_shards.div_ceil(self.local_groups);
        Ok(index / per)
    }

    /// Data shard indices in one local group.
    ///
    /// This is what a single-shard repair reads, and the reason a wide group
    /// stays cheap to repair.
    #[must_use]
    pub fn local_group_members(&self, group: u32) -> Vec<u32> {
        if group >= self.local_groups {
            return Vec::new();
        }
        let per = self.data_shards.div_ceil(self.local_groups);
        let start = group * per;
        let end = (start + per).min(self.data_shards);
        (start..end).collect()
    }

    /// Shards read to rebuild one lost data shard.
    ///
    /// The whole point of the local groups: this stays near `k / L` however
    /// large the group grows.
    #[must_use]
    pub const fn single_repair_reads(&self) -> u32 {
        self.data_shards.div_ceil(self.local_groups)
    }

    /// Losses the group survives in the worst case.
    ///
    /// Conservative on purpose. A local group recovers one loss on its own,
    /// and the global parity covers `global_parity` more wherever they land,
    /// so `global_parity + 1` is guaranteed. Many heavier loss patterns also
    /// recover, because each local group independently absorbs one, but that
    /// depends on where the losses fall and a durability claim should not.
    #[must_use]
    pub const fn guaranteed_loss_tolerance(&self) -> u32 {
        self.global_parity + 1
    }

    /// Losses the group survives when they fall in different local groups.
    ///
    /// Reported separately from the guaranteed figure so the two are never
    /// confused: this is the lucky case, not the promise.
    #[must_use]
    pub const fn best_case_loss_tolerance(&self) -> u32 {
        self.local_groups + self.global_parity
    }

    /// Domain-tagged digest.
    ///
    /// Placement, the audit and repair all derive from this layout, so it has
    /// to be committed. Two nodes disagreeing about a group's shape would
    /// disagree about which shards protect which.
    #[must_use]
    pub fn lrc_layout_digest(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_LRC_LAYOUT_V1",
            &self.data_shards.to_le_bytes(),
            &self.local_groups.to_le_bytes(),
            &self.global_parity.to_le_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_layouts_reproduce_their_multipliers() {
        // The numbers the design was chosen on. If these move, the reason for
        // preferring LRC over per-object parity has moved with them.
        for (k, l, g, expect) in [
            (500u32, 25u32, 10u32, 1070u32),
            (2000, 50, 12, 1031),
            (100, 10, 6, 1160),
        ] {
            let layout = LrcLayout::new_lrc_group(k, l, g).unwrap();
            assert_eq!(
                layout.lrc_overhead_per_mille(),
                expect,
                "k={k} L={l} G={g} should cost {expect} per mille"
            );
        }
    }

    #[test]
    fn a_wider_group_costs_less_redundancy() {
        // The claim the module exists for, as a monotone property rather than
        // a single measured point.
        let small = LrcLayout::new_lrc_group(100, 10, 6).unwrap();
        let large = LrcLayout::new_lrc_group(2000, 50, 12).unwrap();
        assert!(
            large.lrc_overhead_per_mille() < small.lrc_overhead_per_mille(),
            "a wider group should cost less per byte"
        );
    }

    #[test]
    fn repair_reads_stay_local_however_wide_the_group_gets() {
        // The property that separates this from shared group parity, where
        // repairing one shard means reading everything.
        let narrow = LrcLayout::new_lrc_group(100, 10, 6).unwrap();
        let wide = LrcLayout::new_lrc_group(2000, 200, 12).unwrap();
        assert_eq!(narrow.single_repair_reads(), 10);
        assert_eq!(wide.single_repair_reads(), 10);
        assert!(
            wide.lrc_overhead_per_mille() < narrow.lrc_overhead_per_mille(),
            "the wide group is cheaper at the same repair cost"
        );
    }

    #[test]
    fn every_data_shard_lands_in_exactly_one_local_group() {
        // A shard in two groups would be repaired twice; a shard in none
        // would never be repaired at all, and nothing would report it.
        let layout = LrcLayout::new_lrc_group(97, 7, 3).unwrap();
        let mut seen = vec![0u32; 97];
        for g in 0..layout.local_groups {
            for m in layout.local_group_members(g) {
                seen[m as usize] += 1;
            }
        }
        for (i, count) in seen.iter().enumerate() {
            assert_eq!(*count, 1, "shard {i} is in {count} local groups");
        }
    }

    #[test]
    fn membership_and_lookup_agree() {
        // Two routes to the same answer, checked against each other, because
        // placement uses one and repair uses the other.
        let layout = LrcLayout::new_lrc_group(97, 7, 3).unwrap();
        for i in 0..97 {
            let g = layout.local_group_of(i).unwrap();
            assert!(
                layout.local_group_members(g).contains(&i),
                "shard {i} maps to group {g} but is not a member of it"
            );
        }
    }

    #[test]
    fn a_shard_outside_the_group_is_refused() {
        let layout = LrcLayout::new_lrc_group(10, 2, 2).unwrap();
        let err = layout
            .local_group_of(10)
            .expect_err("index 10 of 10 shards");
        assert!(
            matches!(err, LrcError::ShardOutOfRange { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_layout_with_no_local_groups_is_refused() {
        // Without local groups this is the shared-parity scheme, which was
        // measured and rejected: repairing one shard reads everything.
        assert!(matches!(
            LrcLayout::new_lrc_group(100, 0, 6).expect_err("no local groups"),
            LrcError::NoLocalGroups
        ));
    }

    #[test]
    fn more_local_groups_than_shards_is_refused() {
        // An empty group's parity protects nothing and still costs a shard.
        let err = LrcLayout::new_lrc_group(4, 8, 2).expect_err("more groups than shards");
        assert!(
            matches!(err, LrcError::MoreGroupsThanShards { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_empty_group_is_refused() {
        assert!(matches!(
            LrcLayout::new_lrc_group(0, 1, 1).expect_err("no data"),
            LrcError::NoDataShards
        ));
    }

    #[test]
    fn a_group_above_the_maximum_is_refused() {
        let err = LrcLayout::new_lrc_group(MAX_GROUP_SHARDS, 10, 10).expect_err("too large");
        assert!(matches!(err, LrcError::GroupTooLarge { .. }), "got {err:?}");
    }

    #[test]
    fn a_valid_wide_group_is_accepted() {
        // The canary for the four refusals above. A constructor that refused
        // everything would pass all of them and be useless.
        let layout = LrcLayout::new_lrc_group(2000, 50, 12).expect("a measured layout is valid");
        assert_eq!(layout.lrc_total_shards(), 2062);
        assert_eq!(layout.lrc_parity_shards(), 62);
    }

    #[test]
    fn the_guaranteed_tolerance_is_never_the_optimistic_one() {
        // These are different numbers and confusing them would publish a
        // durability claim the scheme does not keep.
        let layout = LrcLayout::new_lrc_group(500, 25, 10).unwrap();
        assert_eq!(layout.guaranteed_loss_tolerance(), 11);
        assert_eq!(layout.best_case_loss_tolerance(), 35);
        assert!(layout.guaranteed_loss_tolerance() < layout.best_case_loss_tolerance());
    }

    #[test]
    fn the_digest_covers_every_field() {
        // A field outside the digest is a field two nodes could disagree
        // about while agreeing on the group's identity.
        let base = LrcLayout::new_lrc_group(100, 10, 6).unwrap();
        let d = base.lrc_layout_digest();
        assert_ne!(
            d,
            LrcLayout::new_lrc_group(101, 10, 6)
                .unwrap()
                .lrc_layout_digest(),
            "data_shards"
        );
        assert_ne!(
            d,
            LrcLayout::new_lrc_group(100, 11, 6)
                .unwrap()
                .lrc_layout_digest(),
            "local_groups"
        );
        assert_ne!(
            d,
            LrcLayout::new_lrc_group(100, 10, 7)
                .unwrap()
                .lrc_layout_digest(),
            "global_parity"
        );
    }

    #[test]
    fn lrc_beats_per_object_parity_at_the_same_repair_cost() {
        // The comparison the decision rests on, stated so it cannot quietly
        // stop being true. RS (10,16) reads 10 shards to repair and costs
        // 1.600x; this layout reads 10 and costs far less.
        let rs_16_multiplier = 1600u32;
        let rs_16_repair_reads = 10u32;

        let lrc = LrcLayout::new_lrc_group(2000, 200, 12).unwrap();
        assert_eq!(lrc.single_repair_reads(), rs_16_repair_reads);

        // Redundancy is the part above 1000, since 1000 per mille is the data
        // itself. RS (10,16) spends 600; this layout spends 106, which is the
        // comparison that matters. Comparing the totals instead would flatter
        // both by the 1000 they share, and an earlier version of this test
        // did exactly that and asserted a threshold it could not meet.
        let rs_redundancy = rs_16_multiplier - 1000;
        let lrc_redundancy = lrc.lrc_overhead_per_mille() - 1000;
        assert!(
            lrc_redundancy * 5 < rs_redundancy,
            "LRC at equal repair cost should spend under a fifth of the redundancy: \
             {lrc_redundancy} vs {rs_redundancy}"
        );
    }
}
