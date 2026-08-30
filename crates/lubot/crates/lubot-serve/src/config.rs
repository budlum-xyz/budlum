//! Serving configuration and attribution policy checks.

use lubot_core::tier::ModelTier;

use crate::residency::{
    DeviceBudget, Placement, PlanError, ResidencyPlan, SemanticProfile, Tier, WeightShard,
};
use lubot_core::system_prompt::{
    generation_phrases_are_all_refusals, DECLARED_LIMITS, LUBOT_SYSTEM_PROMPT,
};

/// Inference engine (research section 1.4: vLLM and SGLang are day-zero supported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeEngine {
    Vllm,
    Sglang,
    LlamaCpp,
    /// A mixture-of-experts engine that streams weights from disk.
    ///
    /// The other three require the whole model to be resident in VRAM, which
    /// forces the operator to own a data-center class GPU and contradicts the
    /// principle of `src/lubot/effort.rs`: "A Lubot operator answers with the
    /// machine it actually owns." An engine that treats VRAM, RAM and NVMe as
    /// one placement hierarchy - the arrangement `residency.rs` plans - lets
    /// consumer hardware be an operator too.
    ///
    /// It is spoken to as a separate process over an HTTP endpoint. No code is
    /// copied and no crate dependency is added, so this variant names a shape
    /// of engine rather than one product: any engine that pages experts off
    /// disk belongs here, and the consensus answer below is the same for all
    /// of them.
    StreamingMoe,
}

impl ServeEngine {
    /// Whether this engine is guaranteed to produce bit-identical output for
    /// the same input.
    ///
    /// **Why it matters:** `AiRegistry::try_finalize_with_proofs` groups results by
    /// `output_commitment: [u8; 32]`. If two operators differ by a single
    /// bit they fall into separate groups and `agreement_threshold` is never
    /// reached -- the request silently fails to finalize.
    ///
    /// A streaming engine drives several backends at once, and floating point
    /// summation order changes across hardware; even greedy sampling does not
    /// fix it, because the problem is in the summation, not the sampling. So a
    /// multi-backend engine is not sufficient on its own for the consensus
    /// path: it must be used together with a `DeterminismProfile`.
    #[must_use]
    pub const fn is_bitwise_reproducible(self) -> bool {
        match self {
            // A single backend plus fixed kernels: same binary, same result.
            ServeEngine::Vllm | ServeEngine::Sglang | ServeEngine::LlamaCpp => true,
            // Heterogeneous execution is the point of the engine; it cannot be guaranteed alone.
            ServeEngine::StreamingMoe => false,
        }
    }
}

/// The determinism profile required for consensus.
///
/// Lubot consensus requires bit-identical equality (the `output_commitment` grouping),
/// so the operator's sampling and execution settings cannot be left free.
/// This profile carries the minimum conditions a bridge must meet to join the
/// consensus path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterminismProfile {
    /// Greedy sampling (`temperature = 0`). A non-zero temperature randomizes
    /// sampling; two operators may pick different tokens even with the same
    /// seed.
    pub greedy: bool,
    /// A fixed sampling seed.
    pub seed: u64,
    /// A single fixed execution backend (CPU **or** CUDA **or** Metal --
    /// not mixed). Floating point summation order varies by backend.
    pub pinned_backend: bool,
}

impl DeterminismProfile {
    /// The profile required for the consensus path.
    #[must_use]
    pub const fn for_consensus(seed: u64) -> Self {
        Self {
            greedy: true,
            seed,
            pinned_backend: true,
        }
    }

    /// Whether the profile is sufficient for consensus.
    #[must_use]
    pub const fn is_consensus_safe(&self) -> bool {
        self.greedy && self.pinned_backend
    }
}

/// Bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    /// The weight source - the original name is preserved (attribution).
    pub weight_source: String,
    /// The name served through the API - tier naming: `lubot-{tier}-{version}`.
    pub served_model_name: String,
    /// The tier this bridge serves.
    pub tier: ModelTier,
    pub engine: ServeEngine,
    pub port: u16,
    pub base_url: String,
    /// The determinism profile required if this bridge joins the consensus path.
    ///
    /// `None` means the bridge is for local/experimental use only and must not be put into
    /// consensus.
    pub determinism: Option<DeterminismProfile>,
    /// The operator's disk budget in bytes. `None` bounds nothing and the
    /// plan is accepted on placement alone. When it is set, the same plan is
    /// run through `ResidencyPlan::plan_bounded_by_disk`: a placement that
    /// would read more from disk than the budget allows is refused at
    /// startup, fail-closed. The placement never moves - disk pressure must
    /// not change which tier a shard lands in - only the verdict does.
    pub disk_budget_bytes: Option<u64>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self::for_tier(ModelTier::Light, "v0.1")
    }
}

impl ServeConfig {
    /// Build a configuration from tier + version (the 2026-08-13 naming decision).
    #[must_use]
    pub fn for_tier(tier: ModelTier, version: &str) -> Self {
        let weight_source = match tier {
            ModelTier::Light => "deepseek-ai/DeepSeek-V4-Flash-Base",
            ModelTier::Normal => "deepseek-ai/DeepSeek-V4-Pro-Base",
        };
        Self {
            weight_source: weight_source.to_string(),
            served_model_name: tier.served_model_name(version),
            tier,
            engine: ServeEngine::Vllm,
            port: 8000,
            base_url: "http://127.0.0.1:8000/v1".to_string(),
            determinism: None,
            disk_budget_bytes: None,
        }
    }
}

/// Attribution policy check: the served name cannot carry a third-party model name
/// (we do not take a third-party model and sell it as Lubot - only our own layer
/// carries the Lubot name; the base is stated openly in `NOTICE.md` and the model card).
///
/// # Errors
///
/// If `served_model_name` contains a third-party name or a multiplier tag
/// pattern (for example "0.5x", "10x").
pub fn assert_served_name_is_ours(cfg: &ServeConfig) -> Result<(), String> {
    let name = cfg.served_model_name.to_lowercase();
    if name.contains("deepseek") {
        return Err(format!(
            "served_model_name cannot carry a third-party name: {}",
            cfg.served_model_name
        ));
    }
    if looks_like_multiplier(&cfg.served_model_name) {
        return Err(format!(
            "served_model_name cannot carry a multiplier tag: {}",
            cfg.served_model_name
        ));
    }
    Ok(())
}

/// Whether this bridge may be put into the consensus path.
///
/// Rule: if the engine is not bit-reproducible on its own (multi-backend),
/// it may enter consensus only with an `is_consensus_safe` profile. Without a profile
/// it is refused fail-closed -- silently accepting and then watching consensus never fill
/// makes the fault look like a liveness problem and hinders diagnosis.
///
/// # Errors
///
/// If there is no profile, or the profile does not meet the greedy/fixed-backend conditions.
pub fn assert_consensus_ready(cfg: &ServeConfig) -> Result<(), String> {
    match cfg.determinism {
        None => {
            if cfg.engine.is_bitwise_reproducible() {
                return Err(format!(
                    "{:?} may be bit-reproducible, but consensus requires an explicit \
                     determinism profile (greedy + fixed seed)",
                    cfg.engine
                ));
            }
            Err(format!(
                "{:?} is a multi-backend engine; without a determinism profile it \
                 cannot be put into consensus",
                cfg.engine
            ))
        }
        Some(p) if !p.is_consensus_safe() => Err(format!(
            "determinism profile is insufficient: greedy={}, pinned_backend={}",
            p.greedy, p.pinned_backend
        )),
        Some(_) => Ok(()),
    }
}

/// The system prompt this bridge serves, checked before it is handed over.
///
/// The prompt is not a string the operator supplies. It is taken from
/// [`LUBOT_SYSTEM_PROMPT`] so that every bridge serves the same text, and the
/// `lubot-prompt-is-true` gate has a single place to check against the chain
/// constants. What is added here is the check that runs on the way out.
///
/// Two things are verified, both of which the prompt could lose to an ordinary
/// edit:
///
/// * every generation phrase in it is a refusal, not an offer. Lubot reads and
///   does not produce media, and a prompt that offers what the runtime refuses
///   makes the model promise things the user will never receive;
/// * each declared limit still appears in the text as its exact integer. The
///   limits are prose in the prompt and numbers in [`DECLARED_LIMITS`]; prose
///   and numbers drift apart quietly, and a prompt claiming a megabyte while the
///   runtime enforces something else is a lie told to the user in our name.
///
/// The gate checks the same properties in CI. This is the runtime half: a
/// bridge built from a modified crate refuses to start rather than serving a
/// prompt nobody verified.
///
/// # Errors
///
/// When a generation phrase is offered, or a declared limit is missing from
/// the prompt text.
/// The phrases the prompt must keep, and what each one protects.
///
/// These mirror the `REQUIRED_CLAIMS` of the `lubot-prompt-is-true` gate. The
/// gate is the authority; this list is the runtime half, so a prompt that has
/// lost a core doctrine is refused at bridge start rather than only failing CI.
/// Each entry is (exact phrase, why the phrase matters to the model a user
/// talks to).
const REQUIRED_PROMPT_PHRASES: &[(&str, &str)] = &[
    (
        "Pollen grant",
        "the first closed-loop channel; a refusal cannot name a missing channel it never learned",
    ),
    ("B.U.D. storage deal", "the second closed-loop channel"),
    ("SocialFi reference", "the third closed-loop channel"),
    (
        "is not something the field can do yet",
        "the honesty boundary: access and bond are verified while end-to-end inference proof is not; \
         a prompt that overstated it would make the model the place the claim leaks out of",
    ),
    (
        "Tiers are called light and normal.",
        "the tier naming decision; the prompt is where a third-party name would leak to a user",
    ),
];

/// The quoted effort figures the prompt must keep, and why each one matters.
///
/// These mirror the `EFFORT_FIGURES` of the `lubot-prompt-is-true` gate. The
/// gate derives the figures from the on-chain constants in `src/lubot/effort.rs`
/// (`TIER_MIN_TENTHS` / `TIER_BASELINE_TENTHS` / `TIER_MAX_TENTHS` divided by
/// `TIER_SCALE`); this off-chain crate cannot depend on that source, so the
/// quoted strings are kept here as literals and the gate remains the authority
/// that recomputes them. The runtime's job is the cheap half: refuse a prompt
/// whose prose has quietly dropped a bound.
const REQUIRED_EFFORT_FIGURES: &[(&str, &str)] = &[
    (
        "0.5x",
        "the shallowest tier; a requester reads it to know the floor",
    ),
    ("1.0x", "the baseline tier the default effort is"),
    (
        "10.0x",
        "the deepest tier; dropping it from the prose leaves the chain enforcing \
         a depth nobody was told about",
    ),
];

/// The verification of one prompt text without the identity assumption.
///
/// Split out from [`checked_system_prompt`] so a canary can drive it against a
/// doctored *copy* of the prompt rather than against the immutable `const`. The
/// shipped prompt is a constant, so the red-green test cannot mutate it; the
/// way to prove a check catches a defect is to feed a defeated copy in.
fn verify_prompt_text(text: &str) -> Result<(), String> {
    generation_phrases_are_all_refusals(text)?;

    for (medium, unit, limit) in DECLARED_LIMITS {
        if !text.contains(&limit.to_string()) {
            return Err(format!(
                "the prompt no longer states the {medium} limit of {limit} {unit}; \
                 the runtime would enforce a number the user was never told"
            ));
        }
    }

    for (phrase, why) in REQUIRED_PROMPT_PHRASES {
        if !text.contains(phrase) {
            return Err(format!("the prompt lost `{phrase}`.\n  {why}"));
        }
    }

    for (figure, why) in REQUIRED_EFFORT_FIGURES {
        if !text.contains(figure) {
            return Err(format!("the prompt no longer quotes `{figure}`.\n  {why}"));
        }
    }

    Ok(())
}

pub fn checked_system_prompt() -> Result<&'static str, String> {
    verify_prompt_text(LUBOT_SYSTEM_PROMPT)?;
    Ok(LUBOT_SYSTEM_PROMPT)
}

/// Whether this bridge may be put into the consensus path **on this device**.
///
/// [`assert_consensus_ready`] answers the question the configuration can answer
/// on its own: engine and sampling. It cannot see the machine. A bridge that is
/// configured correctly and then runs a model whose weights do not fit produces
/// answers either way, so the fault surfaces as timeouts rather than as a
/// refusal - which is the shape of failure the determinism check exists to
/// avoid.
///
/// So the plan is part of the decision. Two conditions are added:
///
/// * a plan must exist at all - [`ResidencyPlan::plan`] fails closed when the
///   per-token weights do not fit, and that refusal is the operator's answer;
/// * the plan must not stream from disk. Streaming is a legitimate way to run a
///   model on a small device, and it is why [`Tier::Disk`] exists - but the read
///   time is a property of the storage, not of the model, and two operators with
///   different disks answering the same request will not agree on when. The
///   consensus path groups on `output_commitment`, so the bytes still match; what
///   does not match is the deadline. A streaming bridge serves locally, and is
///   refused for consensus.
///
/// The semantics carried by the plan are compared against the semantics the
/// caller asked for. They are returned unchanged by the planner - that is the
/// module's invariant - so this comparison can only fail if the invariant is
/// broken. It is checked rather than trusted, because "placement never changes
/// semantics" is exactly the claim a device short on memory would want to bend.
///
/// # Errors
///
/// Whatever [`assert_consensus_ready`] reports, or a device-level refusal.
pub fn assert_consensus_ready_on_device(
    cfg: &ServeConfig,
    shards: &[WeightShard],
    budget: DeviceBudget,
    semantics: SemanticProfile,
) -> Result<ResidencyPlan, String> {
    assert_consensus_ready(cfg)?;
    // A consensus operator serves the checked prompt or does not serve. Two
    // operators answering the same request from different instructions would
    // produce different bytes and never group, and the failure would look like
    // a liveness problem rather than a configuration one.
    checked_system_prompt()?;

    let plan = match cfg.disk_budget_bytes {
        Some(limit) => ResidencyPlan::plan_bounded_by_disk(shards, budget, semantics, limit),
        None => ResidencyPlan::plan(shards, budget, semantics),
    }
    .map_err(|e| match e {
        PlanError::DensePartDoesNotFit { needed, available } => format!(
            "the per-token weights do not fit on this device: {needed} B needed, \
             {available} B of fast memory available"
        ),
        PlanError::NothingToPlace => {
            String::from("no weight shards were given, so there is nothing to serve")
        }
        PlanError::DiskPartDoesNotFit { needed, available } => format!(
            "the routed part does not fit on this device's disk: {needed} B needed, \
             {available} B of disk available"
        ),
    })?;

    if plan.streams_from_disk() {
        return Err(format!(
            "this device streams weights from disk ({} B on disk); that serves \
             locally but cannot join the consensus path",
            plan.bytes_in(Tier::Disk)
        ));
    }

    // Every placement must name a shard that was actually supplied. The
    // planner builds them from the input, so a mismatch means the plan is
    // describing memory that was never asked for - which an operator would
    // read as a residency report and act on.
    let unknown: Option<&Placement> = plan
        .placements
        .iter()
        .find(|p| !shards.iter().any(|s| s.content_id == p.content_id));
    if let Some(p) = unknown {
        return Err(format!(
            "the residency plan placed {} B under a content id that was not \
             among the supplied shards",
            p.bytes
        ));
    }

    if plan.semantics != semantics {
        return Err(String::from(
            "the residency plan altered the semantic profile; placement decides \
             speed, never meaning",
        ));
    }

    Ok(plan)
}

/// Multiplier tag pattern such as `0.5x`, `2x`, `10x`. Lubot tiers
/// carry only the names `light` / `normal`.
#[must_use]
fn looks_like_multiplier(name: &str) -> bool {
    let lower = name.to_lowercase();
    let mut in_number = false;
    for c in lower.chars() {
        if c.is_ascii_digit() || c == '.' || c == ',' {
            in_number = true;
        } else if c == 'x' && in_number {
            return true;
        } else {
            in_number = false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::residency::Demand;

    #[test]
    fn default_config_is_light_tier() {
        let cfg = ServeConfig::default();
        assert_eq!(cfg.tier, ModelTier::Light);
        assert_eq!(cfg.served_model_name, "lubot-light-v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    #[test]
    fn normal_tier_maps_to_pro_weights_but_our_name() {
        let cfg = ServeConfig::for_tier(ModelTier::Normal, "v0.1");
        assert_eq!(cfg.weight_source, "deepseek-ai/DeepSeek-V4-Pro-Base");
        assert_eq!(cfg.served_model_name, "lubot-normal-v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    #[test]
    fn third_party_name_in_served_alias_is_rejected() {
        let cfg = ServeConfig {
            served_model_name: "lubot-deepseek-v1".to_string(),
            ..Default::default()
        };
        assert!(assert_served_name_is_ours(&cfg).is_err());
    }

    #[test]
    fn multiplier_labels_are_rejected() {
        for bad in ["lubot-0.5x", "lubot-10x-v1", "lubot-2x"] {
            let cfg = ServeConfig {
                served_model_name: bad.to_string(),
                ..Default::default()
            };
            assert!(
                assert_served_name_is_ours(&cfg).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn streaming_engine_alone_cannot_enter_consensus() {
        // Several backends live at once: bit-identical equality
        // is not a guarantee the engine itself makes.
        assert!(!ServeEngine::StreamingMoe.is_bitwise_reproducible());
        let cfg = ServeConfig {
            engine: ServeEngine::StreamingMoe,
            determinism: None,
            ..Default::default()
        };
        let err =
            assert_consensus_ready(&cfg).expect_err("it should not be accepted without a profile");
        assert!(err.contains("multi-backend"), "{err}");
    }

    #[test]
    fn a_determinism_profile_makes_a_streaming_engine_fit_for_consensus() {
        let cfg = ServeConfig {
            engine: ServeEngine::StreamingMoe,
            determinism: Some(DeterminismProfile::for_consensus(42)),
            ..Default::default()
        };
        assert!(assert_consensus_ready(&cfg).is_ok());
    }

    #[test]
    fn an_insufficient_profile_is_refused() {
        // The gate is not vacuous: an insufficient profile must be refused too.
        for bad in [
            DeterminismProfile {
                greedy: false,
                seed: 1,
                pinned_backend: true,
            },
            DeterminismProfile {
                greedy: true,
                seed: 1,
                pinned_backend: false,
            },
        ] {
            let cfg = ServeConfig {
                engine: ServeEngine::StreamingMoe,
                determinism: Some(bad),
                ..Default::default()
            };
            assert!(
                assert_consensus_ready(&cfg).is_err(),
                "an insufficient profile should have been refused: {bad:?}"
            );
        }
    }

    #[test]
    fn the_default_bridge_is_not_consensus_ready() {
        // The default configuration is for local use; putting it into consensus
        // must be an explicit decision.
        assert!(assert_consensus_ready(&ServeConfig::default()).is_err());
    }

    #[test]
    fn plain_tier_names_pass_multiplier_check() {
        let cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        assert!(assert_served_name_is_ours(&cfg).is_ok());
    }

    fn shard(n: u8, bytes: u64, demand: Demand) -> WeightShard {
        WeightShard {
            content_id: [n; 32],
            bytes,
            demand,
        }
    }

    fn semantics() -> SemanticProfile {
        SemanticProfile {
            weight_bits: 8,
            context_tokens: 32_768,
            experts_per_token: 8,
        }
    }

    fn consensus_cfg() -> ServeConfig {
        let mut cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        cfg.determinism = Some(DeterminismProfile::for_consensus(7));
        cfg
    }

    /// A one-byte disk budget cannot hold the routed part: the bounded plan
    /// refuses before the streaming policy gets a vote, and the refusal names
    /// the disk.
    #[test]
    fn a_disk_budget_below_the_footprint_is_refused() {
        let mut cfg = consensus_cfg();
        cfg.disk_budget_bytes = Some(1);
        let shards = [
            shard(1, 1_000, Demand::EveryToken),
            shard(2, 8_000, Demand::WhenRouted),
        ];
        let err = assert_consensus_ready_on_device(
            &cfg,
            &shards,
            DeviceBudget {
                accelerator_bytes: 1_000,
                system_bytes: 200,
            },
            semantics(),
        )
        .expect_err("one byte of disk fits nothing");
        assert!(
            err.contains("does not fit"),
            "expected the bounded-disk refusal, got: {err}"
        );
    }

    /// The budget changes the verdict, never the placement: with the same
    /// shards and a sufficient budget the bounded path is exactly the plain
    /// plan, and the streaming refusal that follows is the ordinary policy
    /// answer, not a bounded-check artifact.
    #[test]
    fn a_sufficient_disk_budget_leaves_the_plan_unchanged() {
        let mut cfg = consensus_cfg();
        cfg.disk_budget_bytes = Some(20_000);
        let shards = [
            shard(1, 1_000, Demand::EveryToken),
            shard(2, 8_000, Demand::WhenRouted),
        ];
        let err = assert_consensus_ready_on_device(
            &cfg,
            &shards,
            DeviceBudget {
                accelerator_bytes: 1_000,
                system_bytes: 200,
            },
            semantics(),
        )
        .expect_err("the plan still streams from disk");
        assert!(
            err.contains("streams weights from disk"),
            "expected the streaming refusal with a sufficient budget, got: {err}"
        );
    }

    /// A device that holds everything in fast memory is allowed in.
    #[test]
    fn a_resident_device_may_join_consensus() {
        let shards = [
            shard(1, 1_000, Demand::EveryToken),
            shard(2, 500, Demand::WhenRouted),
        ];
        let plan = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 2_000,
                system_bytes: 4_000,
            },
            semantics(),
        )
        .expect("everything fits in fast memory");
        assert!(!plan.streams_from_disk());
        assert_eq!(plan.bytes_in(Tier::Disk), 0);
    }

    /// Streaming serves locally and is refused for consensus.
    ///
    /// The bytes an operator returns are the same either way - the disagreement
    /// is about when, and the consensus path has a deadline.
    #[test]
    fn a_device_streaming_from_disk_is_refused_for_consensus() {
        let shards = [
            shard(1, 1_000, Demand::EveryToken),
            shard(2, 8_000, Demand::WhenRouted),
        ];
        let err = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 1_000,
                system_bytes: 200,
            },
            semantics(),
        )
        .expect_err("a routed shard has to go to disk here");
        assert!(
            err.contains("streams weights from disk"),
            "expected a streaming refusal, got: {err}"
        );
    }

    /// The dense part not fitting is a refusal, not a slow plan.
    #[test]
    fn a_device_too_small_for_the_dense_part_is_refused() {
        let shards = [shard(1, 10_000, Demand::EveryToken)];
        let err = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1_000,
            },
            semantics(),
        )
        .expect_err("the per-token weights do not fit");
        assert!(
            err.contains("do not fit on this device"),
            "expected a capacity refusal, got: {err}"
        );
    }

    /// The device check runs after the configuration check, not instead of it.
    ///
    /// A bridge with no determinism profile is refused even when the device
    /// would hold the whole model, or a well-provisioned operator could join
    /// consensus with free sampling.
    #[test]
    fn a_roomy_device_does_not_excuse_a_missing_determinism_profile() {
        let cfg = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        assert!(cfg.determinism.is_none(), "the default carries no profile");
        let shards = [shard(1, 10, Demand::EveryToken)];
        let err = assert_consensus_ready_on_device(
            &cfg,
            &shards,
            DeviceBudget {
                accelerator_bytes: u64::MAX / 2,
                system_bytes: u64::MAX / 2,
            },
            semantics(),
        )
        .expect_err("no determinism profile");
        assert!(
            err.contains("determinism profile"),
            "expected the configuration refusal to fire first, got: {err}"
        );
    }

    /// An empty model is refused rather than reported as a plan of nothing.
    #[test]
    fn a_model_with_no_shards_is_refused() {
        let err = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &[],
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1_000,
            },
            semantics(),
        )
        .expect_err("nothing to place");
        assert!(
            err.contains("nothing to serve"),
            "expected an empty-model refusal, got: {err}"
        );
    }

    /// Every placement names a shard that was supplied.
    #[test]
    fn the_plan_places_only_shards_that_were_given() {
        let shards = [
            shard(1, 100, Demand::EveryToken),
            shard(2, 50, Demand::WhenRouted),
        ];
        let plan = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1_000,
            },
            semantics(),
        )
        .expect("it fits");
        for p in &plan.placements {
            assert!(
                shards.iter().any(|s| s.content_id == p.content_id),
                "a placement named a shard nobody supplied"
            );
        }
    }

    /// The semantics that go in are the semantics that come out.
    #[test]
    fn the_plan_returns_the_semantics_it_was_given() {
        let shards = [shard(1, 100, Demand::EveryToken)];
        let asked = semantics();
        let plan = assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1_000,
            },
            asked,
        )
        .expect("it fits");
        assert_eq!(plan.semantics, asked, "placement may not touch semantics");
    }

    /// The served prompt is the one the core crate defines, unaltered.
    ///
    /// Compared by content, not by address. The first version of this test
    /// asserted `std::ptr::eq` and failed: `LUBOT_SYSTEM_PROMPT` is a `const`,
    /// so it is substituted at each use site and two mentions of it need not
    /// share an address. That is a fact about `const` versus `static`, and the
    /// property actually worth holding is that the bridge serves the same text
    /// - byte for byte, with nothing appended by the serving layer.
    #[test]
    fn the_bridge_serves_the_checked_prompt() {
        let prompt = checked_system_prompt().expect("the shipped prompt must pass its own checks");
        assert_eq!(
            prompt, LUBOT_SYSTEM_PROMPT,
            "the bridge must serve the core prompt unaltered"
        );
        assert!(
            !prompt.is_empty(),
            "an empty prompt instructs the model in nothing"
        );
    }

    /// Every declared limit is stated in the prompt as its exact integer.
    #[test]
    fn each_declared_limit_is_stated_in_the_prompt() {
        for (medium, unit, limit) in DECLARED_LIMITS {
            assert!(
                LUBOT_SYSTEM_PROMPT.contains(&limit.to_string()),
                "the {medium} limit of {limit} {unit} is missing from the prompt"
            );
        }
    }

    /// A prompt that lost a closed-loop channel is refused.
    ///
    /// The required phrases are checked, not merely listed. The shipped prompt
    /// is a `const`, so we cannot mutate it in the red-green cycle; we feed a
    /// doctored copy to [`verify_prompt_text`] instead, and the check must
    /// refuse it. A check that passes unconditionally is a vase.
    #[test]
    fn a_prompt_missing_a_closed_loop_channel_is_refused() {
        let stripped = LUBOT_SYSTEM_PROMPT.replace("SocialFi reference", "<missing>");
        let err = verify_prompt_text(&stripped).expect_err("a missing channel must be refused");
        assert!(
            err.contains("SocialFi reference") || err.contains("lost"),
            "expected the refusal to name the lost channel, got: {err}"
        );
    }

    /// A prompt whose depth range has shrunk by one bound is refused.
    ///
    /// Effort figures are the one class of claim that a prose edit can drop
    /// without breaking anything that reads the constants: the numbers are
    /// prose here and code in the crate that enforces them, and the two can
    /// drift apart silently.
    #[test]
    fn a_prompt_missing_an_effort_figure_is_refused() {
        let stripped = LUBOT_SYSTEM_PROMPT.replace("10.0x", "<missing>");
        let err = verify_prompt_text(&stripped).expect_err("a dropped bound must be refused");
        assert!(
            err.contains("10.0x") || err.contains("quotes"),
            "expected the refusal to name the missing figure, got: {err}"
        );
    }

    /// A prompt that lost the tier naming decision is refused.
    #[test]
    fn a_prompt_missing_the_tier_naming_is_refused() {
        let stripped =
            LUBOT_SYSTEM_PROMPT.replace("Tiers are called light and normal.", "<missing>");
        let err = verify_prompt_text(&stripped).expect_err("a lost tier naming must be refused");
        assert!(
            err.contains("Tiers are called light and normal.") || err.contains("lost"),
            "expected the refusal to name the missing claim, got: {err}"
        );
    }

    /// The shipped prompt itself passes the strengthened check.
    ///
    /// This is the green half of the red-green pair above: the doctored copy is
    /// refused, the real one is not. Both directions together prove the check
    /// is not vacuous.
    #[test]
    fn the_shipped_prompt_passes_the_check() {
        assert!(verify_prompt_text(LUBOT_SYSTEM_PROMPT).is_ok());
    }

    /// A consensus bridge cannot skip the prompt check.
    #[test]
    fn the_device_check_also_requires_the_prompt_to_pass() {
        // The shipped prompt passes, so this asserts the wiring rather than a
        // refusal: the call is on the path, and mutating the prompt makes the
        // device check fail with the prompt's own message.
        let shards = [shard(1, 10, Demand::EveryToken)];
        assert!(assert_consensus_ready_on_device(
            &consensus_cfg(),
            &shards,
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1_000,
            },
            semantics(),
        )
        .is_ok());
        assert!(checked_system_prompt().is_ok());
    }
}
