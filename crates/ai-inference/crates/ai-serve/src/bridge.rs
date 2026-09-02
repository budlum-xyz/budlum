//! Bringing a bridge up: the order in which an operator's claims are checked.
//!
//! The other modules in this crate each answer one question. `config` answers
//! whether the configuration is coherent, `residency` answers whether the model
//! fits the machine, `chain` answers what the chain says, `health` counts what
//! happened. Nothing joined them, and a set of checks that is never run in
//! order is a set of checks an operator can run in whichever order suits them.
//!
//! This module is that order. It exists to make one property inspectable: a
//! bridge either passed every check before its first request, or it did not
//! start. There is no partially-started bridge, and no request is served while
//! a check is still outstanding.
//!
//! The sequence is cheapest-first, and that is not only about speed. Each step
//! answers a question the next one would otherwise ask badly. A prompt that
//! offers what the runtime refuses makes every later answer wrong, so it is
//! checked before the machine is measured; the machine is measured before the
//! chain is asked, because an operator whose device cannot hold the model has
//! no reason to be told about their bond.

use crate::chain::{ChainClient, RpcError};
use crate::config::{
    assert_consensus_ready_on_device, assert_served_name_is_ours, checked_system_prompt,
    ServeConfig,
};
use crate::health::Health;
use crate::residency::{Demand, DeviceBudget, ResidencyPlan, SemanticProfile, WeightShard};
use ai_core::model::Hash32;

/// Why a bridge refused to start.
///
/// One variant per question, rather than a single string, because the operator
/// response differs: a naming problem is an edit, a capacity problem is a
/// different machine or a lower tier, and an unregistered model is a chain
/// transaction. Flattening them into text would make the three look alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRefusal {
    /// The served name carries something it may not.
    Attribution(String),
    /// The prompt, the configuration or the device refused.
    NotReadyOnDevice(String),
    /// The chain was asked and did not confirm.
    Chain(RpcError),
    /// The chain answered, and the answer was no.
    ModelNotRegistered(Hash32),
    /// The model has no shard that every token needs.
    ///
    /// Rejected rather than planned. A model built only from routed experts has
    /// no attention, no embeddings and no output head, so whatever was supplied
    /// is not a model - and the residency planner would happily place all of it
    /// on disk and report a plan, because "nothing is needed on every token" is
    /// trivially satisfiable.
    NoPerTokenWeights,
}

impl core::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartupRefusal::Attribution(m) | StartupRefusal::NotReadyOnDevice(m) => {
                write!(f, "{m}")
            }
            StartupRefusal::Chain(e) => write!(f, "the chain could not confirm the model: {e:?}"),
            StartupRefusal::ModelNotRegistered(id) => write!(
                f,
                "the chain reports model {} as unregistered",
                hex_prefix(id)
            ),
            StartupRefusal::NoPerTokenWeights => write!(
                f,
                "no shard is marked as needed on every token; a model with only \
                 routed experts has no attention or output head"
            ),
        }
    }
}

/// First four bytes of an id, for operator-facing messages.
fn hex_prefix(id: &Hash32) -> String {
    let [a, b, c, d, ..] = *id;
    format!("{a:02x}{b:02x}{c:02x}{d:02x}")
}

/// A bridge that passed every startup check.
///
/// Construction is the proof. There is no way to build this type without going
/// through [`Bridge::start`], so a value of it is evidence that the checks ran
///   - which is why the fields are readable but the struct cannot be assembled
///     from outside.
#[derive(Debug)]
pub struct Bridge {
    config: ServeConfig,
    plan: ResidencyPlan,
    prompt: &'static str,
    health: Health,
}

impl Bridge {
    /// Run every startup check, in order, and produce a bridge or a refusal.
    ///
    /// # Errors
    ///
    /// The first check that refuses, as a [`StartupRefusal`].
    pub fn start<C: ChainClient>(
        config: ServeConfig,
        model_id: &Hash32,
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        chain: &C,
        counters: Option<&Health>,
    ) -> Result<Self, StartupRefusal> {
        Self::start_counting(config, model_id, shards, budget, semantics, chain, counters)
    }

    /// [`Bridge::start`], recording a refusal into an existing counter.
    ///
    /// A supervisor restarting a bridge holds the counters across attempts,
    /// which is the only place a refusal loop is observable: the bridge that
    /// would have owned the counter is exactly the one that did not start.
    fn start_counting<C: ChainClient>(
        config: ServeConfig,
        model_id: &Hash32,
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        chain: &C,
        counters: Option<&Health>,
    ) -> Result<Self, StartupRefusal> {
        let outcome = Self::attempt(config, model_id, shards, budget, semantics, chain);
        if let (Err(why), Some(h)) = (&outcome, counters) {
            h.record_refused_startup(why);
        }
        outcome
    }

    /// The checks themselves, without the counting.
    fn attempt<C: ChainClient>(
        config: ServeConfig,
        model_id: &Hash32,
        shards: &[WeightShard],
        budget: DeviceBudget,
        semantics: SemanticProfile,
        chain: &C,
    ) -> Result<Self, StartupRefusal> {
        // 1. Naming. Free to check, and a bridge serving a third-party name is
        //    a problem no later check would notice.
        assert_served_name_is_ours(&config).map_err(StartupRefusal::Attribution)?;

        // 2. The model has a dense part. Checked before planning, because the
        //    planner treats "no per-token shards" as a plan with nothing to
        //    hold in fast memory rather than as a malformed model.
        if !shards.iter().any(|s| s.demand == Demand::EveryToken) {
            return Err(StartupRefusal::NoPerTokenWeights);
        }

        // 3. Prompt, determinism and residency. This is the composite check:
        //    it verifies the prompt the model will be given, refuses a device
        //    that cannot hold the per-token weights, and returns the plan.
        let plan = assert_consensus_ready_on_device(&config, shards, budget, semantics)
            .map_err(StartupRefusal::NotReadyOnDevice)?;

        // 4. The chain, last, because it is the only step that leaves the
        //    machine. `NotConnected` is a refusal rather than a warning: a
        //    bridge that starts without confirming registration would answer
        //    requests for a model the chain does not know, and the operator
        //    would discover it when settlement failed.
        if !chain
            .model_registered(model_id)
            .map_err(StartupRefusal::Chain)?
        {
            return Err(StartupRefusal::ModelNotRegistered(*model_id));
        }

        // The prompt is resolved once, at startup, and kept. Re-reading it per
        // request would let a bridge serve a text that passed the check at
        // boot and a different one afterwards; holding the checked value means
        // the thing served is the thing verified.
        let prompt = checked_system_prompt().map_err(StartupRefusal::NotReadyOnDevice)?;

        Ok(Self {
            config,
            plan,
            prompt,
            health: Health::new(),
        })
    }

    /// The configuration this bridge started with.
    #[must_use]
    pub const fn config(&self) -> &ServeConfig {
        &self.config
    }

    /// Where this bridge's weights ended up.
    #[must_use]
    pub const fn plan(&self) -> &ResidencyPlan {
        &self.plan
    }

    /// The system prompt this bridge serves.
    ///
    /// Checked at startup and unchanged since. A caller receives the verified
    /// text rather than a reference to the constant, so there is no path that
    /// serves an unchecked prompt.
    #[must_use]
    pub const fn system_prompt(&self) -> &'static str {
        self.prompt
    }

    /// The runtime counters.
    #[must_use]
    pub const fn health(&self) -> &Health {
        &self.health
    }

    /// A one-line operator summary of what started.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} on {:?}: {}",
            self.config.served_model_name,
            self.config.engine,
            self.plan.summary()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeterminismProfile;
    use crate::residency::{Demand, Placement, Tier};
    use ai_core::tier::ModelTier;

    /// A chain that answers a fixed registration verdict.
    struct FixedChain(bool);

    impl ChainClient for FixedChain {
        fn pollen_grant_active(&self, _c: &Hash32, _u: &Hash32) -> Result<bool, RpcError> {
            Ok(true)
        }
        fn model_registered(&self, _m: &Hash32) -> Result<bool, RpcError> {
            Ok(self.0)
        }
        fn operator_bond(&self, _o: &Hash32) -> Result<u64, RpcError> {
            Ok(0)
        }
    }

    fn cfg() -> ServeConfig {
        let mut c = ServeConfig::for_tier(ModelTier::Light, "v0.1");
        c.determinism = Some(DeterminismProfile::for_consensus(7));
        c
    }

    fn shards() -> Vec<WeightShard> {
        vec![
            WeightShard {
                content_id: [1; 32],
                bytes: 1_000,
                demand: Demand::EveryToken,
            },
            WeightShard {
                content_id: [2; 32],
                bytes: 400,
                demand: Demand::WhenRouted,
            },
        ]
    }

    fn semantics() -> SemanticProfile {
        SemanticProfile {
            weight_bits: 8,
            context_tokens: 32_768,
            experts_per_token: 8,
        }
    }

    fn roomy() -> DeviceBudget {
        DeviceBudget {
            accelerator_bytes: 4_000,
            system_bytes: 8_000,
        }
    }

    #[test]
    fn a_bridge_that_passes_every_check_starts() {
        let bridge = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect("every check passes");
        assert_eq!(bridge.config().tier, ModelTier::Light);
        assert!(!bridge.plan().streams_from_disk());
        assert_eq!(bridge.health().snapshot().requests, 0, "nothing served yet");
        assert!(bridge.summary().contains("ai_inference-light"));
    }

    /// The chain is consulted, and its "no" stops the bridge.
    #[test]
    fn an_unregistered_model_does_not_start() {
        let err = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(false),
            None,
        )
        .expect_err("the chain says the model is unknown");
        assert!(matches!(err, StartupRefusal::ModelNotRegistered(id) if id == [9; 32]));
        assert!(err.to_string().contains("09090909"), "{err}");
    }

    /// No chain connection is a refusal, not a warning.
    #[test]
    fn a_bridge_with_no_chain_connection_does_not_start() {
        let err = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &crate::chain::NotConnected,
            None,
        )
        .expect_err("fail closed");
        assert_eq!(err, StartupRefusal::Chain(RpcError::NotConnected));
    }

    /// The device check runs before the chain is asked.
    ///
    /// Asserted by the variant, not by the message: a machine that cannot hold
    /// the dense part must be told that, rather than being sent to look at its
    /// chain connection.
    #[test]
    fn a_device_too_small_is_refused_before_the_chain_is_asked() {
        let err = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 100,
            },
            semantics(),
            &crate::chain::NotConnected,
            None,
        )
        .expect_err("the dense part does not fit");
        assert!(
            matches!(err, StartupRefusal::NotReadyOnDevice(ref m) if m.contains("do not fit")),
            "expected a device refusal before any chain error, got: {err:?}"
        );
    }

    /// Attribution is checked first, before anything expensive.
    #[test]
    fn a_third_party_name_is_refused_before_the_device_is_measured() {
        let mut c = cfg();
        c.served_model_name = String::from("upstream-base-light");
        let err = Bridge::start(
            c,
            &[9; 32],
            &shards(),
            DeviceBudget {
                accelerator_bytes: 0,
                system_bytes: 1,
            }, // would also fail, and must not be reported
            semantics(),
            &crate::chain::NotConnected,
            None,
        )
        .expect_err("the name carries a third-party model");
        assert!(
            matches!(err, StartupRefusal::Attribution(_)),
            "attribution must be reported first, got: {err:?}"
        );
    }

    /// A started bridge counts what it does.
    #[test]
    fn the_health_counters_belong_to_the_bridge() {
        let bridge = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect("every check passes");
        bridge.health().record_request();
        bridge.health().record_rejected_closed_loop();
        let snap = bridge.health().snapshot();
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.rejected_closed_loop, 1);
        assert_eq!(snap.hash_failures, 0);
    }

    /// A refusal is counted where a supervisor can see it.
    #[test]
    fn a_refused_startup_is_counted_for_the_supervisor() {
        let counters = Health::new();
        for _ in 0..3 {
            let err = Bridge::start(
                cfg(),
                &[9; 32],
                &shards(),
                roomy(),
                semantics(),
                &FixedChain(false),
                Some(&counters),
            )
            .expect_err("the chain says no");
            assert!(matches!(err, StartupRefusal::ModelNotRegistered(_)));
        }
        assert_eq!(
            counters.snapshot().refused_startups,
            3,
            "a restart loop has to be visible as a number"
        );
    }

    /// A successful start does not raise the refusal counter.
    #[test]
    fn a_successful_start_is_not_counted_as_a_refusal() {
        let counters = Health::new();
        Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(true),
            Some(&counters),
        )
        .expect("every check passes");
        assert_eq!(counters.snapshot().refused_startups, 0);
    }

    /// A CPU-only host declares no accelerator, and the planner sees that.
    #[test]
    fn a_cpu_only_host_declares_no_accelerator() {
        let b = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 4_096,
        };
        assert_eq!(b.accelerator_bytes, 0, "no accelerator means zero bytes");
        assert_eq!(b.system_bytes, 4_096);
        let bridge = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            b,
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect("1 400 B fits in 4 096 B of host memory");
        assert!(
            !bridge.plan().streams_from_disk(),
            "a CPU-only host is not automatically a streaming host"
        );
    }

    /// A started bridge carries the checked prompt.
    #[test]
    fn a_started_bridge_serves_the_checked_prompt() {
        let bridge = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect("every check passes");
        assert_eq!(
            bridge.system_prompt(),
            checked_system_prompt().expect("the shipped prompt passes"),
            "the bridge must serve the verified prompt"
        );
        assert!(bridge.system_prompt().contains("AI inference layer"));
    }

    /// A model made only of routed experts is not a model.
    #[test]
    fn a_model_with_no_per_token_shard_does_not_start() {
        let routed_only = vec![WeightShard {
            content_id: [3; 32],
            bytes: 100,
            demand: Demand::WhenRouted,
        }];
        let err = Bridge::start(
            cfg(),
            &[9; 32],
            &routed_only,
            roomy(),
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect_err("there is no dense part");
        assert_eq!(err, StartupRefusal::NoPerTokenWeights);
        assert!(err.to_string().contains("output head"), "{err}");
    }

    /// A placement names the shard it placed.
    #[test]
    fn every_placement_names_a_shard_that_was_given() {
        let bridge = Bridge::start(
            cfg(),
            &[9; 32],
            &shards(),
            roomy(),
            semantics(),
            &FixedChain(true),
            None,
        )
        .expect("every check passes");
        let given: Vec<[u8; 32]> = shards().iter().map(|s| s.content_id).collect();
        for Placement {
            content_id, tier, ..
        } in &bridge.plan().placements
        {
            assert!(
                given.contains(content_id),
                "a placement named a shard nobody supplied"
            );
            assert_ne!(*tier, Tier::Disk, "this device holds everything");
        }
    }
}
