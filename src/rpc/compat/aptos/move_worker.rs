//! The Move worker admission boundary (WP-32, 2/N).
//!
//! `POST /v1/transactions` carries a BCS transaction. Delivery 1/N of WP-32
//! refuses those routes by name without reading the body, because a refusal
//! must not become an allocation door. This module is the next step: it parses
//! and checks the body, then still refuses execution by name, because the
//! aptos-vm worker is not wired yet. Every refusal names a rule; no Aptos
//! account state is invented from the Budlum ledger.
//!
//! WIRING: unwired - `crate::execution::coordinator::foreign::aptos` holds the envelope,
//! the alias, the pinned framework and the replay cache. This module is
//! declared by `aptos/mod.rs`; the REST `handle` continues to answer
//! `Answer::MoveUnavailable` with the same native door until the worker runs.

use crate::execution::coordinator::foreign::aptos::{
    check_envelope, AptosEnvelope, AptosRefusal, BcsError, ForeignReplayCache, MAX_BCS_BYTES,
};
use crate::execution::coordinator::foreign::Foreign;

/// Why a BCS transaction was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveWorkerError {
    /// The body is not canonical BCS.
    Body(BcsError),
    /// The envelope broke an admission rule.
    Envelope(AptosRefusal),
}

/// The bounded admission state of one Move worker.
#[derive(Debug, Clone, Default)]
pub struct MoveWorkerAdmission {
    cache: ForeignReplayCache,
}

impl MoveWorkerAdmission {
    /// An admission state with an empty replay cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and check one BCS body.
    ///
    /// A well-formed, fresh envelope still ends in
    /// [`AptosRefusal::WorkerUnavailable`]: the refusal is deliberately the
    /// last step, so a client cannot distinguish "the body was accepted" from
    /// "the worker refused" and cannot use this door to probe Move state.
    ///
    /// # Errors
    ///
    /// [`MoveWorkerError::Body`] for a BCS defect, or
    /// [`MoveWorkerError::Envelope`] for a chain, expiry, framework, replay or
    /// worker refusal.
    /// exposed for: Move BCS transaction admission once worker socket connects (`WP-32`).
    pub fn admit_bcs(&mut self, body: &[u8], now_secs: u64) -> Result<(), MoveWorkerError> {
        if body.len() > MAX_BCS_BYTES.saturating_add(64) {
            return Err(MoveWorkerError::Body(BcsError::LengthTooLarge));
        }
        let envelope = AptosEnvelope::bcs_decode(body).map_err(MoveWorkerError::Body)?;
        let foreign = Foreign::Aptos(envelope);
        check_envelope(foreign.envelope(), now_secs, &mut self.cache)
            .map_err(MoveWorkerError::Envelope)?;
        Err(MoveWorkerError::Envelope(AptosRefusal::WorkerUnavailable {
            door: foreign.worker_door(),
        }))
    }

    /// How many replay ids this worker holds.
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::coordinator::foreign::aptos::{
        move_alias, APTOS_CHAIN_ID, MOVE_WORKER_DOOR,
    };

    fn body(expiry: u64, payload: Vec<u8>) -> Vec<u8> {
        AptosEnvelope {
            chain_id: APTOS_CHAIN_ID,
            sequence_number: 11,
            expiration_timestamp_secs: expiry,
            sender_alias: move_alias(&[4u8; 32]),
            payload,
        }
        .bcs_encode()
        .unwrap()
    }

    #[test]
    fn aptos_move_worker_refuses_by_name_after_checks() {
        let mut worker = MoveWorkerAdmission::new();
        let bytes = body(500, vec![1, 2, 3]);
        assert_eq!(
            worker.admit_bcs(&bytes, 100),
            Err(MoveWorkerError::Envelope(AptosRefusal::WorkerUnavailable {
                door: MOVE_WORKER_DOOR,
            }))
        );
        assert_eq!(worker.cached(), 1);
    }

    #[test]
    fn uel_foreign_tx_replay_refused_at_the_move_worker() {
        let mut worker = MoveWorkerAdmission::new();
        let bytes = body(500, vec![9]);
        assert!(matches!(
            worker.admit_bcs(&bytes, 100),
            Err(MoveWorkerError::Envelope(AptosRefusal::WorkerUnavailable { .. }))
        ));
        assert_eq!(
            worker.admit_bcs(&bytes, 100),
            Err(MoveWorkerError::Envelope(AptosRefusal::Replay))
        );
        assert_eq!(worker.cached(), 1);
    }

    #[test]
    fn aptos_move_worker_refuses_bad_bcs_before_caching() {
        let mut worker = MoveWorkerAdmission::new();
        let mut bytes = body(500, vec![1]);
        bytes.push(0xff);
        assert_eq!(
            worker.admit_bcs(&bytes, 100),
            Err(MoveWorkerError::Body(BcsError::TrailingBytes))
        );
        assert_eq!(worker.cached(), 0);
    }
}
