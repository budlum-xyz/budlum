//! On-device weight residency: where each part of a model lives, and why.
//!
//! # The problem this solves
//!
//! [`crate::config::ServeEngine::Vllm`] and `Sglang` require the whole model
//! resident in accelerator memory. That makes the operator set exactly the
//! people who own data-centre hardware, which contradicts the rule stated in
//! the chain's own effort module: an operator answers with the machine it
//! actually owns. A tier a phone cannot serve is a tier a phone cannot earn
//! from.
//!
//! The alternative, which this module plans for, is to stop treating fast
//! memory as a requirement and start treating it as a *placement*. A
//! mixture-of-experts model activates a small fraction of its parameters per
//! token: the dense part (attention, shared experts, embeddings) is needed for
//! every token, and the routed experts are needed one small subset at a time.
//! The dense part earns residency; the experts can be staged from slower
//! storage on demand.
//!
//! # The invariant, and why it is the whole point
//!
//! **Placement decides speed. It must never decide semantics.**
//!
//! A device short on fast memory produces the same tokens, more slowly. It does
//! not silently drop to a smaller quantisation, a shorter context, or a
//! different routing rule. This is not a style preference here the way it is in
//! a standalone inference engine: on this chain an answer is grouped with other
//! operators' answers by an exact 32-byte commitment, and one differing bit
//! puts an operator in a different group. An engine that quietly reduced
//! precision when memory was tight would produce an operator that silently
//! stops agreeing - and the symptom would be a request that never finalises,
//! which reads as a liveness fault rather than as the configuration error it
//! is.
//!
//! So [`ResidencyPlan::plan`] is allowed to move weights between tiers and is
//! not allowed to change [`SemanticProfile`]. The type carries no method that
//! could; the planner takes it by value and returns it unchanged, and
//! `plan_preserves_semantics` proves it for a machine with no fast memory at
//! all.
//!
//! # Where the weights come from
//!
//! B.U.D., and nothing else. The tiers below are placements of content already
//! addressed by [`WeightShard::content_id`]; there is no path here that fetches
//! from a URL, a mirror or a local file the chain has not seen. That is the
//! closed loop applied to weights rather than to training data: an operator who
//! could stage a shard from anywhere could stage a *different* shard, and the
//! model commitment would then describe something other than what ran.
//!
//! # What is deliberately not here
//!
//! No prefetch policy, no learned hot-set, no eviction heuristic. Those are
//! performance policies that have to be measured on real hardware before they
//! are believed, and an unmeasured policy written into the tree reads as a
//! decision when it is a guess. What is here is the part that has to be right
//! before any of them can be tried: the tier arithmetic, the fail-closed
//! refusal when the dense part does not fit anywhere, and the invariant that
//! none of it may touch semantics.

/// A storage tier, fastest first.
///
/// Ordered so `Tier::Accelerator < Tier::System < Tier::Disk`, which lets the
/// planner fill greedily without a separate speed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Accelerator memory (VRAM, or the GPU-visible half of a unified pool).
    Accelerator,
    /// Host memory.
    System,
    /// Local storage. Always present: a device with no disk cannot hold a
    /// model at all, so there is no plan to make.
    ///
    /// [`ResidencyPlan::plan`] treats it as unbounded; the operator's real,
    /// finite disk is bound by [`ResidencyPlan::plan_bounded_by_disk`], which
    /// refuses fail-closed when the routed part would not fit on it.
    Disk,
}

impl Tier {
    /// The name used in operator-facing output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Accelerator => "accelerator",
            Tier::System => "system",
            Tier::Disk => "disk",
        }
    }
}

/// What a device has, in bytes.
///
/// Byte counts rather than device names: the planner has no business knowing
/// whether the accelerator is a discrete card or a unified pool, and a plan
/// that branched on the brand would be untestable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBudget {
    /// Bytes usable in accelerator memory. Zero on a CPU-only device.
    pub accelerator_bytes: u64,
    /// Bytes usable in host memory.
    pub system_bytes: u64,
}

impl DeviceBudget {
    /// Bytes available in a tier.
    #[must_use]
    pub const fn bytes_in(self, tier: Tier) -> u64 {
        match tier {
            Tier::Accelerator => self.accelerator_bytes,
            Tier::System => self.system_bytes,
            // Disk is the overflow tier, treated as without limit so the
            // planner's own arithmetic never has to know a disk size. A real
            // operator's finite disk is bound afterwards by
            // [`ResidencyPlan::plan_bounded_by_disk`], which refuses fail-closed
            // when the routed part would not fit.
            Tier::Disk => u64::MAX,
        }
    }

    /// The fast-memory hierarchy this device can spend in total (accelerator +
    /// host). This is the measure of "runs on hardware you already own": a
    /// model is runnable on a device only if the whole fast hierarchy plus the
    /// stated disk can hold the routed-weighted part.
    #[must_use]
    pub const fn total_fast_bytes(&self) -> u64 {
        self.accelerator_bytes.saturating_add(self.system_bytes)
    }
}

/// How often a shard is needed.
///
/// Two values, not a score. A score invites a threshold, a threshold invites
/// tuning, and tuning a placement rule is how a placement rule turns into a
/// semantic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demand {
    /// Needed for every token: attention, shared experts, embeddings, the
    /// output head. Staging these per token would mean paying the full
    /// transfer cost on every step, which is the case streaming cannot help.
    EveryToken,
    /// Needed only when the router selects it.
    WhenRouted,
}

/// One placeable piece of a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightShard {
    /// The B.U.D. content identifier of the bytes.
    ///
    /// The identity of the shard, not a file path: two operators staging the
    /// same shard stage the same bytes, and a shard whose bytes do not hash to
    /// this is not this shard.
    pub content_id: [u8; 32],
    pub bytes: u64,
    pub demand: Demand,
}

/// Routing heat: how many times the router selected each routed shard since
/// the last placement decision.
///
/// The measured input to the rebalance step, the same way the probe in
/// [`crate::staging`] measures bandwidth before any split is decided. A heat
/// value that was guessed is not a heat value; callers record real router
/// selections, and a shard never selected simply has no entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutingHeat {
    /// Selection count per shard, keyed by content id.
    pub counts: std::collections::BTreeMap<[u8; 32], u64>,
}

impl RoutingHeat {
    /// Record one router selection of a shard.
    pub fn record(&mut self, content_id: [u8; 32]) {
        let current = self.counts.get(&content_id).copied().unwrap_or(0);
        self.counts.insert(content_id, current.saturating_add(1));
    }

    /// The measured selection count for a shard (zero when never selected).
    #[must_use]
    pub fn count(&self, content_id: &[u8; 32]) -> u64 {
        self.counts.get(content_id).copied().unwrap_or(0)
    }
}

/// The parts of a model's behaviour that placement may not alter.
///
/// Carried through the planner untouched. It exists so that "placement does not
/// change semantics" is a statement about a value that can be compared, rather
/// than a comment nobody can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticProfile {
    /// Bits per weight as published. A device short on memory does not get to
    /// lower this.
    pub weight_bits: u8,
    /// The context length the model was registered with.
    pub context_tokens: u32,
    /// Experts consulted per token by the router.
    pub experts_per_token: u16,
}

/// Why no plan could be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The per-token weights do not fit in accelerator or system memory
    /// together.
    ///
    /// Fail closed rather than placing them on disk. Streaming a weight that
    /// every token needs is not a slow plan, it is a plan that reads the same
    /// bytes from disk on every step; reporting the shortfall lets an operator
    /// decline the tier instead of registering a machine that will time out.
    DensePartDoesNotFit { needed: u64, available: u64 },
    /// A model with no shards.
    NothingToPlace,
    /// The routed part does not fit on the disk budget.
    ///
    /// Distinct from [`DensePartDoesNotFit`](Self::DensePartDoesNotFit):
    /// the dense part failing is a refusal that happens at planning; this one
    /// happens when the operator has stated a disk budget and the routed
    /// experts, pushed to disk by [`ResidencyPlan::plan`], exceed it. The
    /// consequence is the same - this machine cannot serve this model - but
    /// reporting the shortfall separately tells the operator the overshoot is
    /// on the disk side, not the fast-memory side.
    DiskPartDoesNotFit { needed: u64, available: u64 },
}

/// Where one shard was placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub content_id: [u8; 32],
    pub tier: Tier,
    pub bytes: u64,
    /// The demand that drove this placement. Carried so a plan is
    /// self-describing: a placement alone cannot say whether a fast-memory
    /// shard is the dense part or a routed expert, and the rebalance step
    /// needs to tell them apart without re-reading the model.
    pub demand: Demand,
}

/// The result of planning a model onto a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidencyPlan {
    pub placements: Vec<Placement>,
    /// Returned unchanged from the input. See the module header.
    pub semantics: SemanticProfile,
}

impl ResidencyPlan {
    /// Place `shards` onto `budget`.
    ///
    /// The rule, in order:
    ///
    /// 1. Every [`Demand::EveryToken`] shard is placed in fast memory,
    ///    accelerator first. If they do not all fit, the whole plan fails;
    ///    there is no partial answer here, because a dense part half on disk
    ///    pays the disk cost on every token anyway.
    /// 2. [`Demand::WhenRouted`] shards fill whatever fast memory is left,
    ///    largest first, and the rest go to disk. Largest first because the
    ///    win from residency is proportional to bytes moved, and a tie broken
    ///    by content id keeps two operators with the same device producing the
    ///    same plan.
    ///
    /// # Errors
    ///
    /// [`PlanError::NothingToPlace`] for an empty model,
    /// [`PlanError::DensePartDoesNotFit`] when rule 1 cannot be satisfied.
    pub fn plan(
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
    ) -> Result<Self, PlanError> {
        Self::place_internal(shards, budget, semantics, |a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.content_id.cmp(&b.content_id))
        })
    }

    /// Place `shards` onto `budget`, ordering the routed part by routing heat
    /// instead of by size.
    ///
    /// The dense-part rule is identical to [`ResidencyPlan::plan`]. The routed
    /// part then fills the remaining fast memory hottest first: a shard the
    /// router selects constantly earns residency, one it never selects is read
    /// from disk. Ties break by content id so two operators with the same
    /// device and the same measured heat produce the same plan.
    ///
    /// # Errors
    ///
    /// [`PlanError::NothingToPlace`] for an empty model,
    /// [`PlanError::DensePartDoesNotFit`] when the dense part cannot fit.
    pub fn plan_with_heat(
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        heat: &RoutingHeat,
    ) -> Result<Self, PlanError> {
        Self::place_internal(shards, budget, semantics, |a, b| {
            heat.count(&b.content_id)
                .cmp(&heat.count(&a.content_id))
                .then_with(|| a.content_id.cmp(&b.content_id))
        })
    }

    /// Re-place this plan's routed shards according to measured routing heat.
    ///
    /// Rebuilds the shards from the placements (a placement now carries its
    /// demand, so the plan is self-describing), orders the routed ones
    /// hottest-first, and re-runs placement under the same budget. Every-token
    /// shards never move - their placement is the dense invariant, not a
    /// performance knob - and the semantic profile is carried through
    /// unchanged.
    ///
    /// # Errors
    ///
    /// [`PlanError`] from the re-run. For a plan produced under the same
    /// budget this cannot fail, but the signature stays honest instead of
    /// panicking.
    pub fn rebalance(
        &self,
        heat: &RoutingHeat,
        budget: DeviceBudget,
    ) -> Result<Self, PlanError> {
        let shards: Vec<WeightShard> = self
            .placements
            .iter()
            .map(|p| WeightShard {
                content_id: p.content_id,
                bytes: p.bytes,
                demand: p.demand,
            })
            .collect();
        Self::plan_with_heat(&shards, budget, self.semantics, heat)
    }

    fn place_internal(
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        order_routed: impl FnMut(&&WeightShard, &&WeightShard) -> std::cmp::Ordering,
    ) -> Result<Self, PlanError> {
        if shards.is_empty() {
            return Err(PlanError::NothingToPlace);
        }

        let dense_needed: u64 = shards
            .iter()
            .filter(|s| s.demand == Demand::EveryToken)
            .map(|s| s.bytes)
            .fold(0, u64::saturating_add);
        let fast_total = budget.accelerator_bytes.saturating_add(budget.system_bytes);
        if dense_needed > fast_total {
            return Err(PlanError::DensePartDoesNotFit {
                needed: dense_needed,
                available: fast_total,
            });
        }

        let mut free_accelerator = budget.accelerator_bytes;
        let mut free_system = budget.system_bytes;
        let mut placements = Vec::with_capacity(shards.len());

        // Rule 1: the dense part, fastest tier first.
        for shard in shards.iter().filter(|s| s.demand == Demand::EveryToken) {
            let tier = if shard.bytes <= free_accelerator {
                free_accelerator -= shard.bytes;
                Tier::Accelerator
            } else if shard.bytes <= free_system {
                free_system -= shard.bytes;
                Tier::System
            } else {
                // The totals fit but no single tier holds this shard: it is
                // larger than either pool's remainder. Reported as the same
                // shortfall rather than silently spilled to disk, because the
                // consequence for the operator is identical - this machine
                // cannot serve this model.
                return Err(PlanError::DensePartDoesNotFit {
                    needed: dense_needed,
                    available: fast_total,
                });
            };
            placements.push(Placement {
                content_id: shard.content_id,
                tier,
                bytes: shard.bytes,
                demand: Demand::EveryToken,
            });
        }

        // Rule 2: routed experts, ordered by the caller (largest first, or
        // hottest first), deterministic on ties.
        let mut routed: Vec<&WeightShard> = shards
            .iter()
            .filter(|s| s.demand == Demand::WhenRouted)
            .collect();
        routed.sort_by(order_routed);
        for shard in routed {
            let tier = if shard.bytes <= free_accelerator {
                free_accelerator -= shard.bytes;
                Tier::Accelerator
            } else if shard.bytes <= free_system {
                free_system -= shard.bytes;
                Tier::System
            } else {
                Tier::Disk
            };
            placements.push(Placement {
                content_id: shard.content_id,
                tier,
                bytes: shard.bytes,
                demand: Demand::WhenRouted,
            });
        }

        Ok(Self {
            placements,
            semantics,
        })
    }

    /// Plan onto a device whose disk is **not** unbounded.
    ///
    /// [`ResidencyPlan::plan`] treats disk as the overflow tier with no
    /// capacity limit: a shard that does not fit in fast memory is placed on
    /// disk no matter how large the model is. That is right for the tier
    /// arithmetic, but it is not a faithful model of a real operator's machine,
    /// which has a finite disk. A phone that owns 64 GiB of storage cannot
    /// stage a 1.6T-parameter model any more than it can hold it in RAM.
    ///
    /// This bounds the plan by the operator's stated disk budget. It runs the
    /// same placement as [`ResidencyPlan::plan`] and then refuses the plan
    /// fail-closed if the bytes the placement would read from disk exceed
    /// `disk_bytes`. The placement itself is unchanged - disk pressure must
    /// never change which tier a shard lands in, because a placement that
    /// moved a shard to fast memory to stay under a disk budget would be a
    /// placement that changed semantics - so the plan that passes is the same
    /// plan [`ResidencyPlan::plan`] would have produced for an unbounded disk.
    ///
    /// # Errors
    ///
    /// [`PlanError::DiskPartDoesNotFit`] when the disk footprint exceeds the
    /// budget.
    pub fn plan_bounded_by_disk(
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        disk_bytes: u64,
    ) -> Result<Self, PlanError> {
        let plan = Self::plan(shards, budget, semantics)?;
        let disk_footprint = plan.bytes_in(Tier::Disk);
        if disk_footprint > disk_bytes {
            return Err(PlanError::DiskPartDoesNotFit {
                needed: disk_footprint,
                available: disk_bytes,
            });
        }
        Ok(plan)
    }

    /// Bytes placed in a tier.
    #[must_use]
    pub fn bytes_in(&self, tier: Tier) -> u64 {
        self.placements
            .iter()
            .filter(|p| p.tier == tier)
            .map(|p| p.bytes)
            .fold(0, u64::saturating_add)
    }

    /// Whether any weight is streamed from disk during decoding.
    #[must_use]
    pub fn streams_from_disk(&self) -> bool {
        self.placements.iter().any(|p| p.tier == Tier::Disk)
    }

    /// A one-line operator summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} shard(s): {} B accelerator, {} B system, {} B disk; {} bit weights, {} token context",
            self.placements.len(),
            self.bytes_in(Tier::Accelerator),
            self.bytes_in(Tier::System),
            self.bytes_in(Tier::Disk),
            self.semantics.weight_bits,
            self.semantics.context_tokens,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn profile() -> SemanticProfile {
        SemanticProfile {
            weight_bits: 4,
            context_tokens: 131_072,
            experts_per_token: 8,
        }
    }

    /// A dense shard plus four experts.
    fn model() -> Vec<WeightShard> {
        let mut v = vec![WeightShard {
            content_id: id(0),
            bytes: 1000,
            demand: Demand::EveryToken,
        }];
        for n in 1..=4u8 {
            v.push(WeightShard {
                content_id: id(n),
                bytes: 500,
                demand: Demand::WhenRouted,
            });
        }
        v
    }

    /// The invariant: a machine with no fast memory to spare returns the same
    /// semantics as one with plenty.
    ///
    /// This is the test the module exists for. Everything else here is
    /// arithmetic; this is the property that makes the arithmetic safe to
    /// apply on a consensus path.
    #[test]
    fn plan_preserves_semantics() {
        let generous = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 1_000_000,
                system_bytes: 1_000_000,
            },
            profile(),
        )
        .unwrap();

        // Exactly enough for the dense part and not one byte more.
        let starved = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1000,
            },
            profile(),
        )
        .unwrap();

        assert_eq!(
            generous.semantics, starved.semantics,
            "placement changed the model's semantics"
        );
        assert!(
            !generous.streams_from_disk(),
            "a machine with room to spare should not be streaming"
        );
        assert!(
            starved.streams_from_disk(),
            "a machine with no spare room must stream rather than fail"
        );
    }

    /// The dense part never lands on disk.
    #[test]
    fn per_token_weights_are_never_streamed() {
        let plan = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1200,
            },
            profile(),
        )
        .unwrap();
        let dense = plan
            .placements
            .iter()
            .find(|p| p.content_id == id(0))
            .expect("the dense shard vanished from the plan");
        assert_ne!(dense.tier, Tier::Disk);
    }

    /// A disk budget that holds the routed part is accepted, with the same
    /// placement as an unbounded-disk plan (disk pressure must never change
    /// placement semantics).
    #[test]
    fn a_disk_budget_that_holds_the_routed_part_is_accepted() {
        let shards = model(); // 1000 dense + four 500-byte routed experts
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        let unbounded = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        let bounded =
            ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 2000).unwrap();

        // The dense part (1000 B) fits in 1200 B of system memory; the four
        // 500-B routed experts (2000 B total) land on disk. A 2000-B disk
        // budget holds it exactly; accepted.
        assert_eq!(bounded.bytes_in(Tier::Disk), 2000);
        // The placement is identical to the unbounded plan.
        assert_eq!(bounded, unbounded);
    }

    /// A disk budget too small for the routed part is refused fail-closed,
    /// not silently moved onto fast memory (which would change semantics).
    #[test]
    fn a_disk_budget_too_small_for_the_routed_part_is_refused() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        let err = ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 1000)
            .expect_err("2000 bytes of routed experts cannot fit in a 1000-byte disk");
        assert_eq!(
            err,
            PlanError::DiskPartDoesNotFit {
                needed: 2000,
                available: 1000
            }
        );
    }

    /// A zero disk budget refuses anything with a routed footprint, and the
    /// semantics that came in are the semantics returned by a passing plan.
    #[test]
    fn a_zero_disk_budget_refuses_a_disk_footprint() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        assert!(ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 0).is_err());

        // A model with nothing on disk passes with semantics intact.
        let dense_only = vec![shards.first().cloned().expect("model has a dense shard")];
        let asked = profile();
        let plan = ResidencyPlan::plan_bounded_by_disk(&dense_only, budget, asked, 0).unwrap();
        assert_eq!(plan.semantics, asked);
    }

    /// Load/admission: a budget that holds the routed footprint *exactly* is
    /// accepted; one byte short is refused (fail-closed, no silent overflow).
    #[test]
    fn disk_budget_boundary_accepts_at_exact_fit_and_refuses_one_byte_over() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        // 4 x 500 = 2000 bytes routed -> disk. Exactly fits.
        let plan = ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 2000).unwrap();
        assert_eq!(plan.bytes_in(Tier::Disk), 2000);

        // One byte short is a hard refusal, not a degradation.
        let err = ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 1999)
            .expect_err("1999 bytes cannot hold a 2000-byte disk footprint");
        assert_eq!(
            err,
            PlanError::DiskPartDoesNotFit {
                needed: 2000,
                available: 1999
            }
        );
    }

    /// Load/debounce: repeated admission decisions are stable - the same
    /// input never flips between accept and refuse under load.
    #[test]
    fn disk_admission_is_deterministic_and_does_not_flap_under_repeated_calls() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        // Under the budget: every call refuses, no flapping.
        for _ in 0..25 {
            assert!(ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 1500).is_err());
        }
        // At the budget: every call accepts, no flapping.
        for _ in 0..25 {
            assert!(ResidencyPlan::plan_bounded_by_disk(&shards, budget, profile(), 2000).is_ok());
        }
    }

    /// Load/saturation: a disk that is already full refuses an additional
    /// model fail-closed, rather than admitting it and reading it off a disk it
    /// does not own.
    #[test]
    fn a_full_disk_refuses_an_additional_model_fail_closed() {
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        // The dense shard needs no disk, so it is admitted with disk=0.
        let dense_only = vec![model().first().cloned().expect("model has a dense shard")];
        assert!(ResidencyPlan::plan_bounded_by_disk(&dense_only, budget, profile(), 0).is_ok());

        // The full model needs 2000 bytes of disk; a disk with 0 free cannot
        // host it and the plan refuses, never silently spilling.
        assert!(matches!(
            ResidencyPlan::plan_bounded_by_disk(&model(), budget, profile(), 0),
            Err(PlanError::DiskPartDoesNotFit { .. })
        ));
    }

    /// A device too small for the dense part is refused, not degraded.
    #[test]
    fn a_device_that_cannot_hold_the_dense_part_is_refused() {
        let err = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 999,
            },
            profile(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            PlanError::DensePartDoesNotFit {
                needed: 1000,
                available: 999
            }
        );
    }

    /// Fast memory is filled before disk is used.
    #[test]
    fn fast_memory_is_filled_before_disk() {
        // 1000 dense + two 500-byte experts fit; two spill.
        let plan = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 2000,
            },
            profile(),
        )
        .unwrap();
        assert_eq!(plan.bytes_in(Tier::System), 2000);
        assert_eq!(plan.bytes_in(Tier::Disk), 1000);
    }

    /// The accelerator is filled before host memory.
    #[test]
    fn the_accelerator_is_preferred_over_host_memory() {
        let plan = ResidencyPlan::plan(
            &model(),
            DeviceBudget {
                accelerator_bytes: 1500,
                system_bytes: 1500,
            },
            profile(),
        )
        .unwrap();
        assert_eq!(plan.bytes_in(Tier::Accelerator), 1500);
        assert_eq!(plan.bytes_in(Tier::System), 1500);
        assert!(!plan.streams_from_disk());
    }

    /// Two operators with the same device produce the same plan.
    ///
    /// Not cosmetic: the plan decides which shards a node fetches from B.U.D.,
    /// and a plan that depended on iteration order would make two identical
    /// machines disagree about what they need.
    #[test]
    fn the_plan_is_deterministic_across_shard_order() {
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 2000,
        };
        let forward = ResidencyPlan::plan(&model(), budget, profile()).unwrap();

        let mut reversed = model();
        reversed.reverse();
        let backward = ResidencyPlan::plan(&reversed, budget, profile()).unwrap();

        let tier_of = |plan: &ResidencyPlan, n: u8| {
            plan.placements
                .iter()
                .find(|p| p.content_id == id(n))
                .map(|p| p.tier)
        };
        for n in 0..=4u8 {
            assert_eq!(
                tier_of(&forward, n),
                tier_of(&backward, n),
                "shard {n} landed in a different tier when the input order changed"
            );
        }
    }

    /// Every shard appears exactly once.
    #[test]
    fn every_shard_is_placed_exactly_once() {
        let shards = model();
        let plan = ResidencyPlan::plan(
            &shards,
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1000,
            },
            profile(),
        )
        .unwrap();
        assert_eq!(plan.placements.len(), shards.len());
        let mut ids: Vec<[u8; 32]> = plan.placements.iter().map(|p| p.content_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), shards.len(), "a shard was placed twice");
    }

    /// An empty model is an error rather than an empty plan.
    #[test]
    fn an_empty_model_is_refused() {
        assert_eq!(
            ResidencyPlan::plan(
                &[],
                DeviceBudget {
                    accelerator_bytes: 0,
                    system_bytes: 1000
                },
                profile()
            ),
            Err(PlanError::NothingToPlace)
        );
    }

    /// A dense shard larger than either pool alone is refused even when the
    /// totals would cover it.
    ///
    /// A shard is not divisible across tiers, so summing the pools would
    /// report a plan the device cannot execute.
    #[test]
    fn a_dense_shard_larger_than_any_single_pool_is_refused() {
        let shards = vec![WeightShard {
            content_id: id(7),
            bytes: 1500,
            demand: Demand::EveryToken,
        }];
        let err = ResidencyPlan::plan(
            &shards,
            DeviceBudget {
                accelerator_bytes: 800,
                system_bytes: 800,
            },
            profile(),
        )
        .unwrap_err();
        assert!(matches!(err, PlanError::DensePartDoesNotFit { .. }));
    }
}

/// Heat-aware placement: the rebalance step the "runs on hardware you own"
/// promise leans on. Placement stays a speed decision, never a semantic one.
#[cfg(test)]
mod heat_tests {
    use super::*;

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn profile() -> SemanticProfile {
        SemanticProfile {
            weight_bits: 8,
            context_tokens: 4096,
            experts_per_token: 2,
        }
    }

    fn model() -> Vec<WeightShard> {
        let mut shards = vec![WeightShard {
            content_id: id(0),
            bytes: 1000,
            demand: Demand::EveryToken,
        }];
        for n in 1..=4 {
            shards.push(WeightShard {
                content_id: id(n),
                bytes: 500,
                demand: Demand::WhenRouted,
            });
        }
        shards
    }

    fn tier_of(plan: &ResidencyPlan, n: u8) -> Tier {
        plan.placements
            .iter()
            .find(|p| p.content_id == id(n))
            .map(|p| p.tier)
            .expect("shard present")
    }

    #[test]
    fn heat_promotes_a_hot_expert_into_fast_memory() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700, // dense 1000 + room for exactly one 500-byte expert
        };
        // Size-first: the first expert (id 1, tie break) takes the fast slot.
        let cold = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        assert_eq!(tier_of(&cold, 1), Tier::System);

        // Heat-first: id 4 is the hot one, so it takes the fast slot instead.
        let mut heat = RoutingHeat::default();
        for _ in 0..100 {
            heat.record(id(4));
        }
        let hot = ResidencyPlan::plan_with_heat(&shards, budget, profile(), &heat).unwrap();
        assert_eq!(tier_of(&hot, 4), Tier::System);
        assert_eq!(tier_of(&hot, 1), Tier::Disk);
    }

    #[test]
    fn rebalance_moves_a_hot_expert_off_disk() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700,
        };
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        assert_eq!(tier_of(&plan, 4), Tier::Disk);

        let mut heat = RoutingHeat::default();
        heat.record(id(4));
        let rebalanced = plan.rebalance(&heat, budget).unwrap();

        assert_eq!(tier_of(&rebalanced, 4), Tier::System);
        assert_eq!(tier_of(&rebalanced, 1), Tier::Disk);
    }

    #[test]
    fn rebalance_preserves_semantics_and_dense_placement() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700,
        };
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        let mut heat = RoutingHeat::default();
        heat.record(id(3));

        let rebalanced = plan.rebalance(&heat, budget).unwrap();
        assert_eq!(rebalanced.semantics, plan.semantics);
        // The dense part never moves.
        assert_eq!(tier_of(&rebalanced, 0), tier_of(&plan, 0));
        assert_ne!(tier_of(&rebalanced, 0), Tier::Disk);
    }

    #[test]
    fn a_cold_expert_is_demoted_to_disk_when_a_hot_one_arrives() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700,
        };
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        assert_eq!(tier_of(&plan, 1), Tier::System);

        let mut heat = RoutingHeat::default();
        heat.record(id(2));
        heat.record(id(2));
        let rebalanced = plan.rebalance(&heat, budget).unwrap();

        assert_eq!(tier_of(&rebalanced, 2), Tier::System);
        assert_eq!(tier_of(&rebalanced, 1), Tier::Disk);
    }

    #[test]
    fn rebalance_is_deterministic() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700,
        };
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        let mut heat = RoutingHeat::default();
        heat.record(id(3));
        heat.record(id(4));

        let a = plan.rebalance(&heat, budget).unwrap();
        let b = plan.rebalance(&heat, budget).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_heat_keeps_the_size_first_plan() {
        let shards = model();
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1700,
        };
        let heat = RoutingHeat::default();
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        let rebalanced = plan.rebalance(&heat, budget).unwrap();
        assert_eq!(rebalanced, plan);
    }

    #[test]
    fn routing_heat_counts_selections() {
        let mut heat = RoutingHeat::default();
        assert_eq!(heat.count(&id(4)), 0);
        heat.record(id(4));
        heat.record(id(4));
        assert_eq!(heat.count(&id(4)), 2);
    }
}
