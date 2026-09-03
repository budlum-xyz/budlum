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
//! step records the content id of its output and a commitment that chains
//! that content id, the step and its parameter back to the master; the
//! guardian produces the cheapest step and verifies it against the record.
//!
//! The first version of the record carried one field for two values: the
//! chain commitment, derived from the master alone, and the hash of the
//! produced step, which `verify_step` compared against the same field. No
//! output could satisfy both, so verification could never succeed and the
//! only test of it discarded the result. The record now carries both values
//! and the commitment covers the content id, so a produced step is checked
//! against what was published, and what was published is bound to the master.

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

/// Y10: a ladder step record. Each step is the same recipe under a different
/// parameter; it records the content id of its output and a commitment that
/// chains that output back to the master.
#[derive(Debug, Clone)]
pub struct LadderStep {
    pub step_id: u8,
    pub param: u64, // for example the resolution or target
    /// The content id of the step's output, as published.
    pub content_id: [u8; 32],
    /// [`step_commitment`] over the master, the step, the parameter and the
    /// content id: the link from this output to the master.
    pub commitment: [u8; 32],
    pub production_cost: u64, // the relative production cost, in core-seconds for example
}

impl LadderStep {
    /// The record for a step whose output is `produced`.
    pub fn new(master: &[u8; 32], step_id: u8, param: u64, produced: &[u8], cost: u64) -> Self {
        let content_id = crate::bud_format_container::content_id(produced);
        Self {
            step_id,
            param,
            content_id,
            commitment: step_commitment(master, step_id, param, &content_id),
            production_cost: cost,
        }
    }
}

/// Y10: the step commitment, derived from the master commitment, the step,
/// its parameter and the content id of the step's output.
pub fn step_commitment(master: &[u8; 32], step: u8, param: u64, content_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_LADDER_STEP_V2");
    h.update(master);
    h.update([step]);
    h.update(param.to_le_bytes());
    h.update(content_id);
    h.finalize().into()
}

/// Y10: step consistency. The produced bytes hash to the recorded content id,
/// and the recorded commitment chains that content id, under this step and
/// parameter, to the master. Both must hold: the first alone accepts a record
/// forged for another master, the second alone accepts any output.
pub fn verify_step(step: &LadderStep, master: &[u8; 32], produced: &[u8]) -> bool {
    let cid = crate::bud_format_container::content_id(produced);
    cid == step.content_id
        && step.commitment == step_commitment(master, step.step_id, step.param, &step.content_id)
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
            LadderStep::new(&master, 1, 1080, b"1080p output", 10),
            LadderStep::new(&master, 2, 480, b"480p output", 3),
        ];
        // The cheapest step is 480p, so that is the one the guardian produces.
        let cheapest = cheapest_step(&steps).unwrap();
        assert_eq!(cheapest.step_id, 2);
        // An honest reproduction of the published step verifies.
        assert!(
            verify_step(cheapest, &master, b"480p output"),
            "the published 480p output must verify against its own record"
        );
        // A different output does not, however the record looks.
        assert!(!verify_step(cheapest, &master, b"480p output, altered"));
        // The right output under another master does not: the chain is broken.
        assert!(!verify_step(
            cheapest,
            &hof(b"another-master"),
            b"480p output"
        ));
        // A record whose content id was swapped to match a forged output is
        // caught by the commitment, which still names the published one.
        let mut swapped = cheapest.clone();
        swapped.content_id = crate::bud_format_container::content_id(b"forged");
        assert!(!verify_step(&swapped, &master, b"forged"));
        // And a record re-committed for the forged output no longer chains
        // to this master, because the master is part of the commitment.
        let other = LadderStep::new(&hof(b"another-master"), 2, 480, b"forged", 3);
        assert!(!verify_step(&other, &master, b"forged"));
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
