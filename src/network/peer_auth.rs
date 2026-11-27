//! WIRING: wired - [`PeerProofBook`] holds one [`PeerProofState`] per connection
//! and [`PeerProofBook::due_for_drop`] is the sweep the transport calls on its
//! timer. What is still out of this module: the socket itself does not yet
//! call `opened`/`accept_proof`/`due_for_drop` - the transport integration is
//! the remaining step, and this book is the state it needs to do it.
//!
//! WIRING: unwired - `must_drop` now has a caller (`PeerProofState::must_drop_now`)
//! but the transport still does not close the socket it names.
//! ML-DSA-65 peer identity proof (`EXPORTER-budlum-pq-auth-v1`).
//!
//! After the TLS 1.3 handshake each side signs the TLS exporter value (32
//! bytes) together with both peer ids, under the FIPS 204 context
//! `BDLM/PEER/V1`. A man in the middle holds two different TLS sessions, so
//! the exporter value it can present to either victim differs from the one
//! the other side signed: the proof would not verify.
//!
//! The signed payload, verification and drop rule live here. The proof is
//! not yet called from the transport, so it is not yet an enforced part of
//! peer identity; this module documents the intended binding and tests its
//! mechanics. [`PROOF_DEADLINE`] is the deadline the enforcement will apply
//! once the transport wires the proof in.

use std::time::Duration;

use crate::crypto::ctx;
use crate::crypto::pq;
use crate::crypto::scheme::SchemeId;

/// The TLS exporter label both sides use.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-budlum-pq-auth-v1";

/// How long a validator peer may stay unproven before it is dropped.
pub const PROOF_DEADLINE: Duration = Duration::from_secs(5);

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// The bytes a peer signs: the exporter value and the two peer ids, the prover's own first.
/// Every field is length prefixed, so the split between the ids is unambiguous.
#[must_use]
pub fn auth_payload(exporter: &[u8; 32], own_peer_id: &[u8], remote_peer_id: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        EXPORTER_LABEL.len() + 32 + own_peer_id.len() + remote_peer_id.len() + 32,
    );
    push_field(&mut out, EXPORTER_LABEL);
    push_field(&mut out, exporter);
    push_field(&mut out, own_peer_id);
    push_field(&mut out, remote_peer_id);
    out
}

/// Verifies the proof a remote peer sent. `remote_peer_id` is the id of the peer that signed and
/// `own_peer_id` is the verifier's: the signer put its own id first, so they swap here.
///
/// # Errors
///
/// [`pq::PqError`] when the signature does not verify, is of the wrong length, or the key is not
/// an ML-DSA-65 key.
pub fn verify_peer_proof(
    public_key: &[u8],
    exporter: &[u8; 32],
    own_peer_id: &[u8],
    remote_peer_id: &[u8],
    signature: &[u8],
) -> Result<(), pq::PqError> {
    let payload = auth_payload(exporter, remote_peer_id, own_peer_id);
    pq::verify(
        SchemeId::ML_DSA_65,
        public_key,
        &payload,
        ctx::PEER_V1,
        signature,
    )
}

/// Whether a connection must be dropped now: a validator peer that is still unproven after
/// [`PROOF_DEADLINE`]. A peer that is not a validator is never dropped by this rule.
#[must_use]
/// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
pub fn must_drop(is_validator_peer: bool, proven: bool, connected_for: Duration) -> bool {
    is_validator_peer && !proven && connected_for >= PROOF_DEADLINE
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [11; 32];

    fn keys() -> Vec<u8> {
        pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &SEED).expect("public key")
    }

    fn sign(exporter: &[u8; 32], own: &[u8], remote: &[u8]) -> Vec<u8> {
        let payload = auth_payload(exporter, own, remote);
        pq::ml_dsa_sign(SchemeId::ML_DSA_65, &SEED, &payload, ctx::PEER_V1, &[0; 32]).expect("sign")
    }

    #[test]
    fn a_proof_over_the_same_session_verifies() {
        let sig = sign(&[1; 32], b"alice", b"bob");
        assert!(verify_peer_proof(&keys(), &[1; 32], b"bob", b"alice", &sig).is_ok());
    }

    #[test]
    fn a_man_in_the_middle_with_another_exporter_is_refused() {
        let sig = sign(&[1; 32], b"alice", b"bob");
        assert!(verify_peer_proof(&keys(), &[2; 32], b"bob", b"alice", &sig).is_err());
    }

    #[test]
    fn a_proof_replayed_to_another_peer_is_refused() {
        let sig = sign(&[1; 32], b"alice", b"bob");
        assert!(verify_peer_proof(&keys(), &[1; 32], b"carol", b"alice", &sig).is_err());
    }

    #[test]
    fn a_swapped_id_order_is_refused() {
        let sig = sign(&[1; 32], b"alice", b"bob");
        assert!(verify_peer_proof(&keys(), &[1; 32], b"alice", b"bob", &sig).is_err());
    }

    #[test]
    fn only_an_unproven_validator_peer_after_the_deadline_is_dropped() {
        let late = PROOF_DEADLINE;
        assert!(must_drop(true, false, late));
        assert!(!must_drop(true, true, late));
        assert!(!must_drop(false, false, late));
        assert!(!must_drop(
            true,
            false,
            PROOF_DEADLINE - Duration::from_millis(1)
        ));
    }
}

/// Per-connection proof state, and the rule that turns it into a decision.
///
/// # Why this exists
///
/// [`verify_peer_proof`] and [`must_drop`] were both written and tested, and
/// neither had a caller: the transport established a session, never read the
/// exporter value, never asked for a proof, and never dropped an unproven
/// validator peer. Two correct functions with no state between them are not a
/// rule, they are a comment.
///
/// This type is the state. It is the smallest thing that can sit between a
/// connection coming up and either a proof arriving or the deadline passing.
///
/// # What it does not do
///
/// It does not own the socket and it does not decide *which* peers are
/// validators - both belong to the caller, which knows its own set. It records,
/// for one connection, whether a valid proof arrived and when the connection
/// opened, which is everything [`must_drop`] needs and nothing more.
#[derive(Debug, Clone)]
pub struct PeerProofState {
    /// The local peer id, as bytes.
    own_peer_id: Vec<u8>,
    /// The remote peer id, as bytes.
    remote_peer_id: Vec<u8>,
    /// Whether this peer is in the validator set.
    is_validator_peer: bool,
    /// When the connection came up, used against [`PROOF_DEADLINE`].
    connected_at: std::time::Instant,
    /// The verified proof, once one has been accepted.
    proven_with: Option<Vec<u8>>,
}

impl PeerProofState {
    /// Opens the proof window for one connection.
    #[must_use]
    pub fn new(own_peer_id: Vec<u8>, remote_peer_id: Vec<u8>, is_validator_peer: bool) -> Self {
        Self {
            own_peer_id,
            remote_peer_id,
            is_validator_peer,
            connected_at: std::time::Instant::now(),
            proven_with: None,
        }
    }

    /// The remote peer this state belongs to.
    #[must_use]
    pub fn remote_peer_id(&self) -> &[u8] {
        &self.remote_peer_id
    }

    /// Whether a valid proof has been accepted.
    #[must_use]
    pub fn is_proven(&self) -> bool {
        self.proven_with.is_some()
    }

    /// The public key of the accepted proof, if any.
    #[must_use]
    pub fn proven_with(&self) -> Option<&[u8]> {
        self.proven_with.as_deref()
    }

    /// Accepts a proof for this session.
    ///
    /// The exporter value is supplied by the caller from the live TLS session;
    /// passing a wrong one is what makes the proof fail, which is the whole
    /// point of binding the proof to the session (a man in the middle holds two
    /// different sessions and therefore two different exporter values).
    ///
    /// # Errors
    ///
    /// [`pq::PqError`] when the signature does not verify. A failed attempt
    /// does **not** clear an earlier success and does **not** move the deadline:
    /// a peer that proved once is proven, and a peer that fails does not get
    /// extra time by failing.
    pub fn accept_proof(
        &mut self,
        public_key: &[u8],
        exporter: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), pq::PqError> {
        verify_peer_proof(
            public_key,
            exporter,
            &self.own_peer_id,
            &self.remote_peer_id,
            signature,
        )?;
        self.proven_with = Some(public_key.to_vec());
        Ok(())
    }

    /// Whether this connection must be dropped now.
    #[must_use]
    pub fn must_drop_now(&self) -> bool {
        must_drop(
            self.is_validator_peer,
            self.is_proven(),
            self.connected_at.elapsed(),
        )
    }

    /// How long this connection has been open.
    #[must_use]
    pub fn connected_for(&self) -> Duration {
        self.connected_at.elapsed()
    }
}

/// A set of per-peer proof states, with the sweep that drops the laggards.
///
/// A node holds one of these; the transport inserts on connect, feeds proofs
/// through [`Self::accept_proof`], and calls [`Self::due_for_drop`] on its
/// timer. Keeping the sweep here rather than in the transport means the rule
/// "drop unproven validator peers after the deadline" is testable without a
/// socket.
#[derive(Debug, Default)]
pub struct PeerProofBook {
    states: std::collections::BTreeMap<Vec<u8>, PeerProofState>,
}

impl PeerProofBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self {
            states: std::collections::BTreeMap::new(),
        }
    }

    /// How many connections are tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Whether nothing is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Records a new connection.
    ///
    /// Re-inserting a peer that is already tracked keeps its original deadline:
    /// a peer cannot reset its clock by reconnecting.
    pub fn opened(
        &mut self,
        own_peer_id: Vec<u8>,
        remote_peer_id: Vec<u8>,
        is_validator_peer: bool,
    ) -> &PeerProofState {
        self.states
            .entry(remote_peer_id.clone())
            .or_insert_with(|| PeerProofState::new(own_peer_id, remote_peer_id, is_validator_peer))
    }

    /// The state for a peer.
    #[must_use]
    pub fn get(&self, remote_peer_id: &[u8]) -> Option<&PeerProofState> {
        self.states.get(remote_peer_id)
    }

    /// Accepts a proof from a peer.
    ///
    /// # Errors
    ///
    /// A message when the peer is not tracked (a proof for a connection this
    /// node never opened is not evidence about that connection) or when the
    /// signature fails.
    pub fn accept_proof(
        &mut self,
        remote_peer_id: &[u8],
        public_key: &[u8],
        exporter: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), String> {
        let state = self
            .states
            .get_mut(remote_peer_id)
            .ok_or_else(|| String::from("peer proof: no open connection for this peer"))?;
        state
            .accept_proof(public_key, exporter, signature)
            .map_err(|err| format!("peer proof refused: {err:?}"))
    }

    /// The peers whose connections must be dropped now, and removes them.
    ///
    /// Removal is part of the sweep, not an afterthought: a dropped peer that
    /// stayed in the book would be swept again on every tick and grow without
    /// bound. The caller closes the sockets these ids name.
    pub fn due_for_drop(&mut self) -> Vec<Vec<u8>> {
        let doomed: Vec<Vec<u8>> = self
            .states
            .iter()
            .filter(|(_, state)| state.must_drop_now())
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in &doomed {
            self.states.remove(peer);
        }
        doomed
    }

    /// Removes a peer that closed its connection on its own.
    ///
    /// Returns whether it was tracked, so a caller can tell "closed cleanly" from
    /// "closed but this node never knew about it".
    pub fn closed(&mut self, remote_peer_id: &[u8]) -> bool {
        self.states.remove(remote_peer_id).is_some()
    }
}

#[cfg(test)]
mod book_tests {
    use super::*;

    #[test]
    fn a_validator_peer_that_never_proves_is_swept_after_the_deadline() {
        let mut book = PeerProofBook::new();
        book.opened(b"me".to_vec(), b"validator".to_vec(), true);
        assert!(book.due_for_drop().is_empty(), "swept before the deadline");

        // Move the connection's clock back past the deadline without sleeping.
        let state = book
            .states
            .get_mut(b"validator".as_slice())
            .expect("tracked");
        state.connected_at = std::time::Instant::now() - PROOF_DEADLINE - Duration::from_secs(1);

        assert_eq!(
            book.due_for_drop(),
            vec![b"validator".to_vec()],
            "an unproven validator peer was not swept"
        );
        assert!(
            book.is_empty(),
            "the swept peer stayed in the book and would be swept again"
        );
    }

    #[test]
    fn a_non_validator_peer_is_never_swept_by_this_rule() {
        let mut book = PeerProofBook::new();
        book.opened(b"me".to_vec(), b"leaf".to_vec(), false);
        let state = book.states.get_mut(b"leaf".as_slice()).expect("tracked");
        state.connected_at = std::time::Instant::now() - PROOF_DEADLINE - Duration::from_secs(60);
        assert!(book.due_for_drop().is_empty());
    }

    #[test]
    fn reconnecting_does_not_reset_the_proof_window() {
        let mut book = PeerProofBook::new();
        book.opened(b"me".to_vec(), b"peer".to_vec(), true);
        let first = book
            .states
            .get(b"peer".as_slice())
            .expect("tracked")
            .connected_at;
        book.opened(b"me".to_vec(), b"peer".to_vec(), true);
        let second = book
            .states
            .get(b"peer".as_slice())
            .expect("tracked")
            .connected_at;
        assert_eq!(first, second, "a peer reset its deadline by reconnecting");
    }

    #[test]
    fn a_verified_proof_saves_the_connection() {
        let mut book = PeerProofBook::new();
        book.opened(b"me".to_vec(), b"bob".to_vec(), true);
        let exporter = [3u8; 32];
        let seed = [9u8; 32];
        let payload = auth_payload(&exporter, b"me", b"bob");
        let sig = pq::ml_dsa_sign(SchemeId::ML_DSA_65, &seed, &payload, ctx::PEER_V1, &[0; 32])
            .expect("sign");
        let key = pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed).expect("key");

        book.accept_proof(b"bob", &key, &exporter, &sig)
            .expect("proof");
        let state = book.states.get_mut(b"bob".as_slice()).expect("tracked");
        state.connected_at = std::time::Instant::now() - PROOF_DEADLINE - Duration::from_secs(1);
        assert!(book.due_for_drop().is_empty(), "a proven peer was swept");
    }

    #[test]
    fn a_proof_for_an_unknown_connection_is_refused() {
        let mut book = PeerProofBook::new();
        let err = book
            .accept_proof(b"ghost", &[0u8; 32], &[0u8; 32], &[0u8; 8])
            .expect_err("a proof for an untracked peer was accepted");
        assert!(err.contains("no open connection"));
    }
}
