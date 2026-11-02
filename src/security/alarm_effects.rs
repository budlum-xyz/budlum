//! What a quantum alarm changes.
//!
//! WIRING: wired - the `CanaryReveal` arm of the executor
//! (`src/execution/executor.rs`) calls [`apply_to_state`] in the block that
//! accepts the proof; `Blockchain::handle_finality_cert`
//! (`src/chain/blockchain.rs`) reads [`bls_required_for_finality`];
//! `AccountState::register_relayed_cross_domain_message` reads
//! [`classical_intake`]; `TeeGates::kq_wallet_tee_shortcut`
//! (`src/account_abstraction/tee_attestation.rs`) reads
//! [`tee_shortcuts_open`]. Rules are pinned by this file's tests.
//!
//! The levels, from the alarm of `quantum_canary`:
//!
//! | Level | Effect |
//! |---|---|
//! | Watch (Kiragi) | TEE shortcuts close; a classical-class message waits seven days |
//! | Restrict (Don) | a classical-class message is no longer taken at all |
//! | Isolate (Zemheri) | classical native domains freeze, classical external domains isolate, the BLS half leaves finality |
//!
//! A broken signature family is separate from the level: a lattice or hash
//! signature break takes the scheme family along the status ladder to
//! `Disabled` in the same block, which is also what opens the recovery
//! path of.

use super::quantum_canary::{AlarmKind, AlarmLevel, QuantumAlarmState};
use crate::core::account::AccountState;
use crate::crypto::scheme::{SchemeId, SchemeStatus, TransitionSource};

/// Blocks a classical-class message waits at Watch: seven days at the one
/// second block time.
pub const CLASSICAL_MESSAGE_WAIT_BLOCKS: u64 = 7 * 24 * 60 * 60;

/// What the message door does with a classical-class message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalIntake {
    /// No alarm: taken as before.
    Open,
    /// Watch: taken only after this many blocks past its source height.
    Wait(u64),
    /// Restrict and above: not taken.
    Stopped,
}

/// The class-dependent intake rule of the message door.
#[must_use]
pub fn classical_intake(alarm: &QuantumAlarmState) -> ClassicalIntake {
    match alarm.level() {
        AlarmLevel::Clear => ClassicalIntake::Open,
        AlarmLevel::Watch => ClassicalIntake::Wait(CLASSICAL_MESSAGE_WAIT_BLOCKS),
        AlarmLevel::Restrict | AlarmLevel::Isolate => ClassicalIntake::Stopped,
    }
}

/// Whether TEE shortcuts stay open. They close at Watch.
#[must_use]
pub fn tee_shortcuts_open(alarm: &QuantumAlarmState) -> bool {
    alarm.level() < AlarmLevel::Watch
}

/// Whether finality still needs the BLS certificate next to the ML-DSA QC.
/// At Isolate the BLS half drops out and the QC alone suffices.
#[must_use]
pub fn bls_required_for_finality(alarm: &QuantumAlarmState) -> bool {
    alarm.level() < AlarmLevel::Isolate
}

/// The signature schemes a broken family takes with it.
#[must_use]
pub fn dropped_schemes(alarm: &QuantumAlarmState) -> Vec<SchemeId> {
    let mut schemes = Vec::new();
    if alarm.has(AlarmKind::LatticeBreak) {
        schemes.extend([
            SchemeId::ML_DSA_44,
            SchemeId::ML_DSA_65,
            SchemeId::ML_DSA_87,
        ]);
    }
    if alarm.has(AlarmKind::HashSigBreak) {
        schemes.extend([SchemeId::SLH_DSA_SHAKE_128S, SchemeId::SLH_DSA_SHAKE_256S]);
    }
    schemes
}

/// What [`apply_to_state`] changed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlarmEffectReport {
    /// Schemes moved to `Disabled`.
    pub schemes_disabled: Vec<SchemeId>,
    /// Native domains frozen.
    pub domains_frozen: Vec<u32>,
    /// External domains isolated.
    pub external_isolated: usize,
}

/// Apply the effects of the alarm the state is in, idempotently. A scheme that
/// is `Active` or `Deprecated` takes the ladder to `Disabled` (one rung at a
/// time, source `CanaryAlarm`); a `Reserved` scheme is left alone, because
/// moving it would activate it. At Isolate the classical native domains freeze
/// and the classical external domains isolate.
pub fn apply_to_state(state: &mut AccountState) -> AlarmEffectReport {
    let mut report = AlarmEffectReport::default();
    let (schemes, isolate) = {
        let alarm = state.settlement.quantum.alarm();
        (dropped_schemes(alarm), alarm.level() >= AlarmLevel::Isolate)
    };
    for scheme in schemes {
        let mut moved = false;
        while let Some(status) = state.scheme_registry.scheme_status(scheme) {
            if !matches!(status, SchemeStatus::Active | SchemeStatus::Deprecated) {
                break;
            }
            let Some(next) = status.next() else {
                break;
            };
            if state
                .scheme_registry
                .transition_scheme(scheme, next, TransitionSource::CanaryAlarm)
                .is_err()
            {
                break;
            }
            moved = true;
        }
        if moved {
            report.schemes_disabled.push(scheme);
        }
    }
    if isolate {
        report.domains_frozen = state.settlement.domains.freeze_classical_domains();
        report.external_isolated = state
            .settlement
            .external_intake
            .registry
            .isolate_classical_domains();
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::quantum_canary::{CanaryBook, CanaryClaim, CanaryId};

    fn alarm_with(ids: &[CanaryId]) -> QuantumAlarmState {
        let mut book = CanaryBook::new();
        for id in ids {
            book.force_solved(
                *id,
                CanaryClaim {
                    commit_height: 1,
                    claimer: crate::core::address::Address([1; 32]),
                    accepted_height: 2,
                },
            );
        }
        book.alarm().clone()
    }

    #[test]
    fn the_levels_set_the_intake_tee_and_bls_rules() {
        let clear = alarm_with(&[]);
        assert_eq!(classical_intake(&clear), ClassicalIntake::Open);
        assert!(tee_shortcuts_open(&clear));
        assert!(bls_required_for_finality(&clear));

        let watch = alarm_with(&[CanaryId::Ecc192]);
        assert_eq!(
            classical_intake(&watch),
            ClassicalIntake::Wait(CLASSICAL_MESSAGE_WAIT_BLOCKS)
        );
        assert!(!tee_shortcuts_open(&watch));
        assert!(bls_required_for_finality(&watch));

        let restrict = alarm_with(&[CanaryId::Ecc224]);
        assert_eq!(classical_intake(&restrict), ClassicalIntake::Stopped);
        assert!(!tee_shortcuts_open(&restrict));
        assert!(bls_required_for_finality(&restrict));

        let isolate = alarm_with(&[CanaryId::EccK1]);
        assert_eq!(classical_intake(&isolate), ClassicalIntake::Stopped);
        assert!(!bls_required_for_finality(&isolate));
    }

    #[test]
    fn a_broken_family_drops_its_schemes_and_a_curve_does_not() {
        assert!(dropped_schemes(&alarm_with(&[CanaryId::EccK1])).is_empty());
        assert_eq!(
            dropped_schemes(&alarm_with(&[CanaryId::Lat87])),
            vec![
                SchemeId::ML_DSA_44,
                SchemeId::ML_DSA_65,
                SchemeId::ML_DSA_87
            ]
        );
        assert_eq!(
            dropped_schemes(&alarm_with(&[CanaryId::Slh256s])),
            vec![SchemeId::SLH_DSA_SHAKE_128S, SchemeId::SLH_DSA_SHAKE_256S]
        );
        assert!(dropped_schemes(&alarm_with(&[CanaryId::HashSha3])).is_empty());
    }

    fn state_with_alarm(ids: &[CanaryId]) -> AccountState {
        let mut state = AccountState::new();
        for id in ids {
            state.settlement.quantum.force_solved(
                *id,
                CanaryClaim {
                    commit_height: 1,
                    claimer: crate::core::address::Address([1; 32]),
                    accepted_height: 2,
                },
            );
        }
        state
    }

    fn register_domain(state: &mut AccountState, id: u32, bls: bool) {
        use crate::crypto::facts::{CryptoFacts, ObservedScheme};
        use crate::domain::types::ConsensusKind;
        state
            .settlement
            .domains
            .register(crate::domain::default_domain(
                id,
                ConsensusKind::PoS,
                1338,
                "pos",
                0,
            ))
            .expect("domain registers");
        let mut facts = CryptoFacts::new();
        facts.record(ObservedScheme::Scheme(if bls {
            SchemeId::BLS12381_MINSIG
        } else {
            SchemeId::ML_DSA_65
        }));
        state.settlement.domains.record_observed(id, &facts);
    }

    /// Watch and Restrict change no state by themselves: they act at the doors.
    #[test]
    fn watch_and_restrict_leave_domains_and_schemes_alone() {
        for ids in [&[CanaryId::Ecc192][..], &[CanaryId::Ecc224][..]] {
            let mut state = state_with_alarm(ids);
            register_domain(&mut state, 1, true);
            let before = state.scheme_registry.clone();
            assert_eq!(apply_to_state(&mut state), AlarmEffectReport::default());
            assert_eq!(state.scheme_registry, before);
            assert_eq!(
                state.settlement.domains.get(1).map(|d| d.status),
                Some(crate::domain::types::DomainStatus::Active)
            );
        }
    }

    /// Isolate freezes the classical native domain and leaves the lattice one.
    #[test]
    fn isolate_freezes_classical_domains_only() {
        let mut state = state_with_alarm(&[CanaryId::EccK1]);
        register_domain(&mut state, 1, true);
        register_domain(&mut state, 2, false);
        let report = apply_to_state(&mut state);
        assert_eq!(report.domains_frozen, vec![1]);
        assert_eq!(
            state.settlement.domains.get(1).map(|d| d.status),
            Some(crate::domain::types::DomainStatus::Frozen)
        );
        assert_eq!(
            state.settlement.domains.get(2).map(|d| d.status),
            Some(crate::domain::types::DomainStatus::Active)
        );
        // Idempotent: a second pass moves nothing.
        assert_eq!(apply_to_state(&mut state), AlarmEffectReport::default());
    }

    /// A lattice break takes the ML-DSA family to Disabled in the same pass.
    #[test]
    fn a_lattice_break_disables_the_ml_dsa_family() {
        let mut state = state_with_alarm(&[CanaryId::Lat65]);
        assert!(state.scheme_registry.scheme_verifies(SchemeId::ML_DSA_65));
        let report = apply_to_state(&mut state);
        assert!(report.schemes_disabled.contains(&SchemeId::ML_DSA_65));
        assert!(report.schemes_disabled.contains(&SchemeId::ML_DSA_87));
        assert!(!state.scheme_registry.scheme_verifies(SchemeId::ML_DSA_65));
        assert!(!state.scheme_registry.scheme_verifies(SchemeId::ML_DSA_87));
        assert_eq!(
            state.scheme_registry.scheme_status(SchemeId::ML_DSA_87),
            Some(SchemeStatus::Disabled)
        );
        // The hash-based family is untouched.
        assert!(state
            .scheme_registry
            .scheme_verifies(SchemeId::SLH_DSA_SHAKE_256S));
    }
}
