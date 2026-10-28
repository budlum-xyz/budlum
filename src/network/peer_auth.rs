//! WIRING: unwired - the peer-proof module is not reached by the transport yet; the enforcement wave wires it.
//! WIRING: unwired - no transport code reads the TLS exporter value (`EXPORTER-budlum-pq-auth-v1`, 32 bytes) from the live session and calls [`verify_peer_proof`] or [`must_drop`], so no peer is asked for a proof and no unproven validator peer is dropped; peer identity on the p2p path stays libp2p's own `PeerId` identity key until the wrapper lands.
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
/// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
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
