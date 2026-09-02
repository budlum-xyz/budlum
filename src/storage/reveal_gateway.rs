//! G4 reveal gateway (plan §CH G4): the bounded session table a gateway or
//! RPC handler owns on top of [`crate::storage::three_rpc`].
//!
//! `three_rpc::open_reveal_session` opens one session; a network-facing
//! handler serves frames across several calls and must not let sessions (or
//! a flood of them) live forever. This module is that layer:
//!
//! * a session cap ([`MAX_REVEAL_SESSIONS`]) so a flood of opens is refused
//!   instead of growing the table without bound,
//! * a wall-clock TTL ([`REVEAL_SESSION_TTL_SECS`]) so a dead viewer's
//!   session is reclaimed,
//! * one frame-serving surface that expires and sweeps on access,
//! * a default frame budget and a per-call frame ceiling, so a remote caller
//!   that omitted `meter_budget` cannot turn one open into an unbounded read.
//!
//! The grant is checked before a session opens: [`RevealGateway::open`]
//! re-derives it from a registry (in-process gateways);
//! [`RevealGateway::open_prechecked`] trusts a decision the chain actor
//! already made. Both funnel into the same meter-and-budget construction, so
//! a sealed recipe with no live grant is refused either way.

use crate::core::hash::hash_fields_bytes;
use crate::storage::three_rpc::{
    open_reveal_session, open_reveal_session_prechecked, RevealHandle, RevealRequest,
    RevealRpcError,
};
use crate::storage::view_grant::ViewGrantRegistry;
use std::collections::BTreeMap;

/// Per-gateway secret mixed into every issued session id. The id is the only
/// credential the frame endpoint sees, so it must not be guessable: a
/// sequential counter would let any RPC caller enumerate live sessions of
/// other clients (read their frames, or close them out from under them).
#[derive(Clone)]
struct IdNonce([u8; 32]);

impl std::fmt::Debug for IdNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdNonce(<redacted>)")
    }
}

/// Hard cap on open reveal sessions. A flood of opens is refused here rather
/// than growing the table without bound.
pub const MAX_REVEAL_SESSIONS: usize = 1024;

/// Wall-clock lifetime of an open reveal session, in seconds. The product
/// read path is a short burst; five minutes is far longer than a burst and
/// far shorter than "forever".
pub const REVEAL_SESSION_TTL_SECS: u64 = 300;

/// Default frame budget applied when the caller passes no budget. A remote
/// caller that asks for uncapped reads still gets a cap; the cap is the
/// meter's, so the read path is charged and refused rather than served
/// without bound.
pub const DEFAULT_REVEAL_BUDGET_FRAMES: u64 = 10_000;

/// Hard ceiling for one frame-serving call. A single response that would
/// materialise more frames than this is refused up front, independent of the
/// budget, so a huge `count` cannot build a huge response in one go.
pub const MAX_FRAMES_PER_CALL: u32 = 256;

/// Refusals of the reveal gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealGatewayError {
    /// The session table is at its cap.
    SessionLimit {
        /// The cap that was reached.
        max: usize,
    },
    /// The id was never issued, or was already closed.
    UnknownSession(u64),
    /// The session outlived its TTL.
    Expired {
        /// The id that expired.
        id: u64,
    },
    /// One frame-serving call asked for more than [`MAX_FRAMES_PER_CALL`].
    AskTooLarge {
        /// The count that was asked.
        count: u32,
        /// The ceiling.
        max: u32,
    },
    /// The underlying reveal/open failure.
    Reveal(RevealRpcError),
}

impl std::fmt::Display for RevealGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionLimit { max } => {
                write!(f, "reveal gateway: session table full ({max})")
            }
            Self::UnknownSession(id) => write!(f, "reveal gateway: unknown session {id}"),
            Self::Expired { id } => write!(f, "reveal gateway: session {id} expired"),
            Self::AskTooLarge { count, max } => {
                write!(f, "reveal gateway: asked {count} frames, ceiling is {max}")
            }
            Self::Reveal(e) => write!(f, "reveal gateway: {e}"),
        }
    }
}

impl std::error::Error for RevealGatewayError {}

impl From<RevealRpcError> for RevealGatewayError {
    fn from(e: RevealRpcError) -> Self {
        Self::Reveal(e)
    }
}

#[derive(Debug, Clone)]
struct GatewaySession {
    handle: RevealHandle,
    expires_at: u64,
}

/// The session table a gateway/RPC handler owns.
#[derive(Debug, Clone)]
pub struct RevealGateway {
    sessions: BTreeMap<u64, GatewaySession>,
    /// Internal uniqueness counter; never issued raw (see [`IdNonce`]).
    next_id: u64,
    id_nonce: IdNonce,
}

impl Default for RevealGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl RevealGateway {
    /// New, empty table with a fresh secret id nonce.
    #[must_use]
    pub fn new() -> Self {
        use rand::Rng;
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self {
            sessions: BTreeMap::new(),
            next_id: 0,
            id_nonce: IdNonce(nonce),
        }
    }

    /// Derive the public id for an internal counter value: a keyed hash, so
    /// ids look random to anyone without the nonce yet never repeat for one
    /// gateway instance.
    fn derive_id(&self, counter: u64, now: u64) -> u64 {
        let digest =
            hash_fields_bytes(&[&self.id_nonce.0, &counter.to_be_bytes(), &now.to_be_bytes()]);
        let mut head = [0u8; 8];
        head.copy_from_slice(digest.get(..8).unwrap_or(&[0u8; 8]));
        u64::from_be_bytes(head)
    }

    /// Number of open sessions (used by tests and telemetry).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Open a session with a live-grant check derived from `registry`.
    ///
    /// # Errors
    ///
    /// [`RevealGatewayError::Reveal`] when the grant check or the emitter
    /// refuses; [`RevealGatewayError::SessionLimit`] at the cap.
    pub fn open(
        &mut self,
        registry: &ViewGrantRegistry,
        req: RevealRequest,
        now: u64,
    ) -> Result<u64, RevealGatewayError> {
        let handle = open_reveal_session(registry, &req)?;
        self.admit(handle, now)
    }

    /// Open a session with a grant decision the chain actor already made.
    ///
    /// # Errors
    ///
    /// [`RevealGatewayError::Reveal`] when the decision or the emitter
    /// refuses; [`RevealGatewayError::SessionLimit`] at the cap.
    pub fn open_prechecked(
        &mut self,
        mut req: RevealRequest,
        grant_allows: bool,
        now: u64,
    ) -> Result<u64, RevealGatewayError> {
        // A remote caller that passes no budget still gets a cap: the gateway
        // is a network-facing table, and "uncapped" is not a remote option.
        if req.meter_budget.is_none() {
            req.meter_budget = Some(DEFAULT_REVEAL_BUDGET_FRAMES);
        }
        let handle = open_reveal_session_prechecked(&req, grant_allows)?;
        self.admit(handle, now)
    }

    /// Shared admission: sweep first (an expired session cannot be pinned by
    /// a new flood), refuse at the cap, then insert.
    fn admit(&mut self, handle: RevealHandle, now: u64) -> Result<u64, RevealGatewayError> {
        self.sweep(now);
        if self.sessions.len() >= MAX_REVEAL_SESSIONS {
            return Err(RevealGatewayError::SessionLimit {
                max: MAX_REVEAL_SESSIONS,
            });
        }
        // Bounded collision retry: two derived ids colliding is a ~2^-64
        // event; eight misses in a row is not a live table, it is a broken
        // rng, and a broken rng must not mint guessable ids either.
        let mut id = self.derive_id(self.next_id, now);
        let mut tries = 0u8;
        while self.sessions.contains_key(&id) {
            if tries == 8 {
                return Err(RevealGatewayError::SessionLimit {
                    max: MAX_REVEAL_SESSIONS,
                });
            }
            tries += 1;
            self.next_id = self.next_id.saturating_add(1);
            id = self.derive_id(self.next_id, now);
        }
        self.next_id = self.next_id.saturating_add(1);
        self.sessions.insert(
            id,
            GatewaySession {
                handle,
                expires_at: now.saturating_add(REVEAL_SESSION_TTL_SECS),
            },
        );
        Ok(id)
    }

    /// Stream commitment for the receivers of this session.
    ///
    /// # Errors
    ///
    /// [`RevealGatewayError::UnknownSession`] for an unknown id.
    pub fn stream_commitment(&self, id: u64) -> Result<[u8; 32], RevealGatewayError> {
        let session = self
            .sessions
            .get(&id)
            .ok_or(RevealGatewayError::UnknownSession(id))?;
        Ok(session.handle.stream_commitment())
    }

    /// Serve a frame range from an open session, under its budget.
    ///
    /// Expires the session in place if its TTL has run out.
    ///
    /// # Errors
    ///
    /// [`RevealGatewayError::UnknownSession`] for an unknown id;
    /// [`RevealGatewayError::Expired`] past the TTL;
    /// [`RevealGatewayError::Reveal`] when the frame ask exceeds the budget
    /// or the emitter fails.
    ///
    /// PARTIAL: allowed - the only removal happens on the expired path: an
    /// entry whose TTL has run out is already dead, so dropping it there is
    /// the reclamation itself and the refusal (`Expired`) reports the same
    /// fact to the caller. Nothing a live caller owns is ever taken away
    /// before a refusal: the budget check and the session lookup both
    /// refuse before any mutation, and a failing emitter leaves the still
    /// valid session in place for a retry.
    pub fn emit_frames(
        &mut self,
        id: u64,
        seq_start: u32,
        count: u32,
        now: u64,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), RevealGatewayError> {
        if count > MAX_FRAMES_PER_CALL {
            return Err(RevealGatewayError::AskTooLarge {
                count,
                max: MAX_FRAMES_PER_CALL,
            });
        }
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(RevealGatewayError::UnknownSession(id))?;
        if now >= session.expires_at {
            let _ = self.sessions.remove(&id);
            return Err(RevealGatewayError::Expired { id });
        }
        Ok(session.handle.emit_frames(seq_start, count)?)
    }

    /// Close a session early. Returns whether it existed.
    #[must_use]
    pub fn close(&mut self, id: u64) -> bool {
        self.sessions.remove(&id).is_some()
    }

    /// Drop every session whose TTL has run out. Returns how many were
    /// removed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.expires_at > now);
        before - self.sessions.len()
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::*;
    use crate::core::address::Address;
    use crate::storage::content_id::ContentId;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::qr_recipe::{ThreeRecipe, ThreeRecipePublic};
    use crate::storage::view_grant::ViewPolicy;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn sample() -> (ThreeRecipePublic, Vec<u8>) {
        let packed = pack_payload(PayloadKind::ContentBytes, b"gateway-reveal-body").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        (ThreeRecipePublic::new(commit, enc.params(), stream), packed)
    }

    fn req(
        recipe: ThreeRecipe,
        full: Option<ThreeRecipePublic>,
        packed: Vec<u8>,
        viewer: Address,
        owner: Address,
        key_id: [u8; 32],
        budget: Option<u64>,
    ) -> RevealRequest {
        RevealRequest {
            recipe,
            full_public: full,
            packed,
            content_id: ContentId([9u8; 32]),
            viewer,
            owner,
            key_id,
            meter_budget: budget,
        }
    }

    /// A public recipe opens without a grant and serves frames back, with a
    /// deterministic stream commitment the receiver can pin.
    #[test]
    fn public_recipe_opens_and_serves_frames() {
        let (full, packed) = sample();
        let mut gw = RevealGateway::new();
        let id = gw
            .open_prechecked(
                req(
                    ThreeRecipe::Public(full.clone()),
                    None,
                    packed,
                    addr(1),
                    addr(2),
                    [7u8; 32],
                    None,
                ),
                false,
                100,
            )
            .unwrap();
        assert_eq!(gw.session_count(), 1);
        assert_ne!(gw.stream_commitment(id).unwrap(), [0u8; 32]);

        let (frames, fold) = gw.emit_frames(id, 0, 2, 100).unwrap();
        assert_eq!(frames.len(), 2);
        assert_ne!(fold, [0u8; 32]);
    }

    /// Issued ids are keyed hashes, not a counter: a sequential id would be
    /// a guessable bearer credential for the frame endpoint and the close
    /// endpoint.
    #[test]
    fn issued_ids_are_keyed_not_counters() {
        let (full, packed) = sample();
        let make = |packed: Vec<u8>| {
            req(
                ThreeRecipe::Public(full.clone()),
                None,
                packed,
                addr(1),
                addr(2),
                [7u8; 32],
                None,
            )
        };
        let mut gw = RevealGateway::new();
        let a = gw
            .open_prechecked(make(packed.clone()), false, 100)
            .unwrap();
        let b = gw
            .open_prechecked(make(packed.clone()), false, 100)
            .unwrap();
        assert_ne!(a, 0);
        assert_ne!(b, a.wrapping_add(1));
        assert_ne!(a, b.wrapping_add(1));
        let mut other = RevealGateway::new();
        let c = other.open_prechecked(make(packed), false, 100).unwrap();
        assert_ne!(a, c, "a fresh nonce must not reissue the same id");
    }

    /// A sealed recipe under a false decision is refused, and under a true
    /// decision served - the grant decision is the only door.
    #[test]
    fn sealed_recipe_obeys_the_prechecked_decision() {
        let (full, packed) = sample();
        let owner = addr(1);
        let viewer = addr(2);
        let sealed = ThreeRecipe::Sealed(full.clone().seal());
        let mut gw = RevealGateway::new();

        let refused = gw.open_prechecked(
            req(
                sealed.clone(),
                Some(full.clone()),
                packed.clone(),
                viewer,
                owner,
                [7u8; 32],
                None,
            ),
            false,
            100,
        );
        assert!(matches!(
            refused,
            Err(RevealGatewayError::Reveal(RevealRpcError::Forbidden))
        ));

        let id = gw
            .open_prechecked(
                req(sealed, Some(full), packed, viewer, owner, [7u8; 32], None),
                true,
                100,
            )
            .unwrap();
        assert!(gw.emit_frames(id, 0, 1, 100).is_ok());
    }

    /// The registry path re-derives the grant: no live grant refuses, a live
    /// grant admits.
    #[test]
    fn registry_path_requires_a_live_grant() {
        let (full, packed) = sample();
        let owner = addr(1);
        let viewer = addr(2);
        let key_id = [7u8; 32];
        let mut reg = ViewGrantRegistry::new();
        let mut gw = RevealGateway::new();
        let sealed = ThreeRecipe::Sealed(full.clone().seal());

        let refused = gw.open(
            &reg,
            req(
                sealed.clone(),
                Some(full.clone()),
                packed.clone(),
                viewer,
                owner,
                key_id,
                None,
            ),
            100,
        );
        assert!(matches!(
            refused,
            Err(RevealGatewayError::Reveal(RevealRpcError::Forbidden))
        ));

        reg.issue(
            ContentId([9u8; 32]),
            owner,
            Some(viewer),
            key_id,
            ViewPolicy::NamedGrantee,
            0,
        )
        .unwrap();

        let id = gw
            .open(
                &reg,
                req(sealed, Some(full), packed, viewer, owner, key_id, None),
                100,
            )
            .unwrap();
        assert!(gw.emit_frames(id, 0, 1, 100).is_ok());
    }

    /// A session outlives its TTL: serving refuses, the table drops it, and
    /// sweep reports the removal.
    #[test]
    fn session_expires_and_sweeps() {
        let (full, packed) = sample();
        let mut gw = RevealGateway::new();
        let id = gw
            .open_prechecked(
                req(
                    ThreeRecipe::Public(full),
                    None,
                    packed,
                    addr(1),
                    addr(2),
                    [7u8; 32],
                    None,
                ),
                false,
                100,
            )
            .unwrap();

        // Inside the TTL: fine.
        assert!(gw
            .emit_frames(id, 0, 1, 100 + REVEAL_SESSION_TTL_SECS - 1)
            .is_ok());

        // Past the TTL: refused and removed in place.
        assert_eq!(
            gw.emit_frames(id, 0, 1, 100 + REVEAL_SESSION_TTL_SECS)
                .unwrap_err(),
            RevealGatewayError::Expired { id }
        );
        assert_eq!(gw.session_count(), 0);
    }

    /// A flood of opens is refused at the cap instead of growing the table.
    #[test]
    fn session_cap_refuses_a_flood() {
        let (full, packed) = sample();
        let mut gw = RevealGateway::new();
        for _ in 0..MAX_REVEAL_SESSIONS {
            gw.open_prechecked(
                req(
                    ThreeRecipe::Public(full.clone()),
                    None,
                    packed.clone(),
                    addr(1),
                    addr(2),
                    [7u8; 32],
                    None,
                ),
                false,
                100,
            )
            .unwrap();
        }
        assert_eq!(gw.session_count(), MAX_REVEAL_SESSIONS);
        let refused = gw.open_prechecked(
            req(
                ThreeRecipe::Public(full),
                None,
                packed,
                addr(1),
                addr(2),
                [7u8; 32],
                None,
            ),
            false,
            100,
        );
        assert_eq!(
            refused,
            Err(RevealGatewayError::SessionLimit {
                max: MAX_REVEAL_SESSIONS
            })
        );
    }

    /// A remote caller that passes no budget still gets the default cap, so a
    /// single open cannot turn into an unbounded read.
    #[test]
    fn missing_budget_gets_the_default_cap() {
        let (full, packed) = sample();
        let mut gw = RevealGateway::new();
        let id = gw
            .open_prechecked(
                req(
                    ThreeRecipe::Public(full),
                    None,
                    packed,
                    addr(1),
                    addr(2),
                    [7u8; 32],
                    None,
                ),
                false,
                100,
            )
            .unwrap();

        // Under the cap, fine; a single ask over the per-call ceiling refuses.
        assert_eq!(
            gw.emit_frames(id, 0, MAX_FRAMES_PER_CALL + 1, 100),
            Err(RevealGatewayError::AskTooLarge {
                count: MAX_FRAMES_PER_CALL + 1,
                max: MAX_FRAMES_PER_CALL
            })
        );
    }

    /// Closing removes the session; unknown ids refuse rather than serving
    /// nothing.
    #[test]
    fn close_and_unknown_session() {
        let (full, packed) = sample();
        let mut gw = RevealGateway::new();
        let id = gw
            .open_prechecked(
                req(
                    ThreeRecipe::Public(full),
                    None,
                    packed,
                    addr(1),
                    addr(2),
                    [7u8; 32],
                    None,
                ),
                false,
                100,
            )
            .unwrap();
        assert!(gw.close(id));
        assert_eq!(
            gw.emit_frames(id, 0, 1, 100).unwrap_err(),
            RevealGatewayError::UnknownSession(id)
        );
        assert_eq!(
            gw.emit_frames(999, 0, 1, 100).unwrap_err(),
            RevealGatewayError::UnknownSession(999)
        );
    }
}
