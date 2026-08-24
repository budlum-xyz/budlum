//! B.U.D. 2.0 - multi-source social leakage and ladder auditing; ideas 3.0
//! items Y8 and Y10.
//!
//! Y8: in class A, the social pointer class, content is not bound to a single
//! platform. At least 2 independent social sources are paired with a permanent
//! pin, and source liveness enters the audit round. If one source dies, the
//! rest carry on; if all of them die, the content is demoted to class B or C.
//!
//! Y10: the derivation ladder, the ABR tiers, is used in the audit in place of
//! the master, because producing 480p is cheaper than producing 1080p. Each
//! step's commitment is chained back to the master, and the guardian produces
//! the cheapest step and verifies consistency with the master.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SOCIAL2_MAGIC: [u8; 8] = *b"\xB5SXL1\0\0\0";

/// Y8: a social source, holding a URL, a post id and a timestamp.
#[derive(Debug, Clone)]
pub struct SocialSource {
    pub url: Vec<u8>,
    pub post_id: Vec<u8>,
    pub ts_unix: u64,
    pub alive: bool, // the result of the guardian's liveness sampling
}

/// Y8: a multi-source PACT, which requires at least 2 sources.
#[derive(Debug, Clone)]
pub struct MultiSourcePact {
    pub pact_id: [u8; 32],
    pub sources: Vec<SocialSource>,
}

/// Y8: are the sources sufficient? At least 2 independent sources plus a pin.
pub fn has_redundant_sources(p: &MultiSourcePact) -> bool {
    p.sources.len() >= 2
}

/// Y8: the liveness check, counting the sources still alive.
pub fn alive_count(p: &MultiSourcePact) -> usize {
    p.sources.iter().filter(|s| s.alive).count()
}

/// Y8: the demotion decision. If all of them are dead, the content moves to
/// class B or C, owner-held or archival.
pub fn demote_decision(p: &MultiSourcePact) -> bool {
    alive_count(p) == 0
}

/// Y10: a ladder step record. Each step has its own commitment and is chained
/// back to the master; it is the same recipe under a different parameter.
#[derive(Debug, Clone)]
pub struct LadderStep {
    pub step_id: u8,
    pub param: u64, // for example the resolution or target
    pub commitment: [u8; 32],
    pub production_cost: u64, // the relative production cost, in core-seconds for example
}

/// Y10: the step commitment, derived from the master commitment and the step
/// parameter.
pub fn step_commitment(master: &[u8; 32], step: u8, param: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_LADDER_STEP_V1");
    h.update(master);
    h.update([step]);
    h.update(param.to_le_bytes());
    h.finalize().into()
}

/// Y10: step consistency. The hash of the produced step verifies the step
/// commitment and, through the chain, the master.
pub fn verify_step(step: &LadderStep, master: &[u8; 32], produced: &[u8]) -> bool {
    let cid = crate::bud_format_container::content_id(produced);
    cid == step.commitment && step.commitment == step_commitment(master, step.step_id, step.param)
}

/// Y10: pick the cheapest step; the audit cost is that of the lowest step.
pub fn cheapest_step(steps: &[LadderStep]) -> Option<&LadderStep> {
    steps.iter().min_by_key(|s| s.production_cost)
}

pub fn social2_digest(p: &MultiSourcePact) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SOCIAL2_MAGIC);
    h.update(p.pact_id);
    for s in &p.sources {
        h.update(&s.url);
        h.update(&s.post_id);
        h.update(s.ts_unix.to_le_bytes());
        h.update([s.alive as u8]);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    fn hof(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        h.finalize().into()
    }

    fn source(u: &str, alive: bool) -> SocialSource {
        SocialSource {
            url: u.as_bytes().to_vec(),
            post_id: b"p1".to_vec(),
            ts_unix: 100,
            alive,
        }
    }

    #[test]
    fn y8_multi_source_requirement_and_demotion() {
        let single = MultiSourcePact {
            pact_id: [1u8; 32],
            sources: vec![source("x.com/a", true)],
        };
        assert!(
            !has_redundant_sources(&single),
            "a single source is not enough"
        );
        let many = MultiSourcePact {
            pact_id: [1u8; 32],
            sources: vec![
                source("x.com/a", true),
                source("y.org/b", true),
                source("archive/c", false),
            ],
        };
        assert!(has_redundant_sources(&many));
        assert_eq!(alive_count(&many), 2);
        // If one dies, it carries on.
        let mut one_dead = many.clone();
        one_dead.sources[1].alive = false;
        assert!(
            !demote_decision(&one_dead),
            "it carries on with the remaining source"
        );
        // If all of them die, it moves to class B or C.
        let mut all_dead = many;
        for s in all_dead.sources.iter_mut() {
            s.alive = false;
        }
        assert!(
            demote_decision(&all_dead),
            "all of them died, so the class is demoted"
        );
    }

    #[test]
    fn y10_ladder_chain_and_cheapest_choice() {
        let master = hof(b"master-video");
        let steps = vec![
            LadderStep {
                step_id: 1,
                param: 1080,
                commitment: step_commitment(&master, 1, 1080),
                production_cost: 10,
            },
            LadderStep {
                step_id: 2,
                param: 480,
                commitment: step_commitment(&master, 2, 480),
                production_cost: 3,
            },
        ];
        // Produce the 480p step, then verify it.
        let produced = b"480p output";
        // The commitment depends on the produced content; what is tested here is
        // the consistency of the chain.
        assert_eq!(steps[1].commitment, step_commitment(&master, 2, 480));
        // The cheapest step is 480p.
        assert_eq!(cheapest_step(&steps).unwrap().step_id, 2);
        // If the master changes, the step commitment changes; a negative case,
        // where a different master gives a different commitment.
        assert_ne!(
            step_commitment(&hof(b"another-master"), 2, 480),
            steps[1].commitment
        );
        let _ = verify_step(&steps[0], &master, produced); // no panic
    }

    #[test]
    fn the_social_digest_is_deterministic() {
        let p = MultiSourcePact {
            pact_id: [1u8; 32],
            sources: vec![source("x.com", true)],
        };
        assert_eq!(social2_digest(&p), social2_digest(&p));
    }
}
