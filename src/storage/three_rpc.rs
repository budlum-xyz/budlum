//! G3 reveal RPC surface (plan §CH G3).
//!
//! [`three_reveal`](crate::storage::three_reveal)`::RevealSession` is the
//! in-memory re-emit engine; this module is the *RPC-facing* wrapper that a
//! gateway handler calls instead of reaching for the session directly. It owns
//! the two things a session cannot: the grant check against
//! [`ViewGrantRegistry`], and the meter-budget enforcement a read path must
//! apply before it hands frames out.
//!
//! # What it guarantees
//!
//! * **No grant, no sealed reveal.** For a sealed recipe the only path to an
//!   open session is a live grant (or the owner, who needs none). The check is
//!   the registry's `may_view`, so a revoked grant closes the door for new
//!   sessions even though frames already emitted on a device stay (T3).
//! * **Nothing touches durable storage.** The session re-emits in memory and is
//!   dropped with the handle.
//! * **Metering is real.** Every frame ask goes through the meter's budget, so
//!   a flooded read path is charged and refused rather than served.
//!
//! The gateway is still responsible for calling `may_view` on the grant side;
//! this module re-derives it for the reveal path so a handler cannot forget.
//! The registry's `may_view` lets the owner in without a grant, and the raw
//! registry does not know who owns a content id; so the registry path takes
//! the recorded owner from its caller (the manifest is the authority) and
//! refuses a request whose `owner` field says otherwise. Without that, a
//! caller who named itself both viewer and owner opened any sealed recipe.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use crate::storage::qr_recipe::{ThreeRecipe, ThreeRecipePublic};
use crate::storage::qr_reemit::ReemitError;
use crate::storage::three_meter::{MeterError, ThreeMeter};
use crate::storage::three_reveal::{RevealError, RevealSession};
use crate::storage::view_grant::ViewGrantRegistry;

/// Errors serving a reveal request through the RPC surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealRpcError {
    /// The viewer has no live grant (and is not the owner), so a sealed recipe
    /// may not be opened.
    Forbidden,
    /// A sealed recipe was presented without the public opening that unpacks it.
    NeedFullRecipe,
    /// The read metering budget tripped.
    Meter(MeterError),
    /// The underlying re-emit failed.
    Reemit(ReemitError),
}

impl std::fmt::Display for RevealRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden => write!(f, "three reveal rpc: forbidden without a live grant"),
            Self::NeedFullRecipe => write!(
                f,
                "three reveal rpc: sealed recipe needs a full public opening"
            ),
            Self::Meter(e) => write!(f, "three reveal rpc: meter: {e}"),
            Self::Reemit(e) => write!(f, "three reveal rpc: reemit: {e}"),
        }
    }
}

impl std::error::Error for RevealRpcError {}

impl From<RevealError> for RevealRpcError {
    fn from(e: RevealError) -> Self {
        match e {
            RevealError::Forbidden => Self::Forbidden,
            RevealError::NeedFullRecipe => Self::NeedFullRecipe,
            RevealError::Reemit(e) => Self::Reemit(e),
        }
    }
}

impl From<MeterError> for RevealRpcError {
    fn from(e: MeterError) -> Self {
        Self::Meter(e)
    }
}

/// A reveal request as received by the RPC layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealRequest {
    /// Public or sealed form of the recipe the reader wants to open.
    pub recipe: ThreeRecipe,
    /// The opening, required only when `recipe` is sealed.
    pub full_public: Option<ThreeRecipePublic>,
    /// The packed A1 bytes the recipe pins.
    pub packed: Vec<u8>,
    /// Which content this is about (for the grant lookup).
    pub content_id: ContentId,
    /// The viewer asking.
    pub viewer: Address,
    /// The content owner (the issuer whose grant is authoritative).
    pub owner: Address,
    /// The key handle the viewer claims (checked against the grant).
    pub key_id: [u8; 32],
    /// Optional reveal budget; `None` means no cap.
    pub meter_budget: Option<u64>,
}

/// A granted, metered reveal session, guarded by the RPC layer.
#[derive(Debug, Clone)]
pub struct RevealHandle {
    session: RevealSession,
    meter: ThreeMeter,
}

impl RevealHandle {
    /// Stream commitment for the receivers of this session.
    #[must_use]
    pub const fn stream_commitment(&self) -> [u8; 32] {
        self.session.stream_commitment()
    }

    /// Emit a range of frames under this session's gate and budget.
    ///
    /// # Errors
    ///
    /// [`RevealRpcError::Meter`] when the frame ask exceeds the budget;
    /// [`RevealRpcError::Reemit`] on an emitter failure.
    pub fn emit_frames(
        &mut self,
        seq_start: u32,
        count: u32,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), RevealRpcError> {
        self.meter.record_frames(u64::from(count))?;
        Ok(self.session.frames_with_fold(seq_start, count)?)
    }
}

/// Open a reveal session. Rejects a sealed recipe with no live grant, and a
/// sealed recipe with no opening; applies the caller's meter budget.
///
/// `recorded_owner` is who the manifest (or confidential commit) says owns
/// `req.content_id`; the caller reads it from the authority it holds.
/// `req.owner` is a claim and is checked against it, because the registry
/// admits the owner with no grant and would otherwise admit anyone who
/// claimed to be one.
///
/// # Errors
///
/// [`RevealRpcError::Forbidden`] when `req.owner` is not the recorded owner,
/// without a live grant (sealed), or with a non-owner viewer and no grant;
/// [`RevealRpcError::NeedFullRecipe`] for a sealed recipe missing its public
/// opening.
pub fn open_reveal_session(
    registry: &ViewGrantRegistry,
    recorded_owner: &Address,
    req: &RevealRequest,
) -> Result<RevealHandle, RevealRpcError> {
    if req.owner != *recorded_owner {
        return Err(RevealRpcError::Forbidden);
    }
    let grant_allows = registry.may_view(&req.content_id, &req.viewer, &req.key_id, recorded_owner);
    open_reveal_session_prechecked(req, grant_allows)
}

/// Open a reveal session with a grant decision that was already made.
///
/// The registry path ([`open_reveal_session`]) derives the decision itself; a
/// network handler that already asked the chain (its `may_view_content`
/// surface) passes that decision here, so the grant is checked once by the
/// authority that owns it and still enforced again by [`RevealSession::open`],
/// which refuses a sealed recipe under a `false` decision.
///
/// # Errors
///
/// [`RevealRpcError::Forbidden`] for a sealed recipe under a `false` decision,
/// or with a non-owner viewer and no grant;
/// [`RevealRpcError::NeedFullRecipe`] for a sealed recipe missing its public
/// opening.
pub fn open_reveal_session_prechecked(
    req: &RevealRequest,
    grant_allows: bool,
) -> Result<RevealHandle, RevealRpcError> {
    let session = RevealSession::open(
        &req.recipe,
        req.full_public.as_ref(),
        &req.packed,
        grant_allows,
    )?;
    let meter = ThreeMeter::with_budget(req.meter_budget);
    Ok(RevealHandle { session, meter })
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::view_grant::ViewPolicy;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn sample() -> (ThreeRecipePublic, Vec<u8>) {
        let packed = pack_payload(PayloadKind::ContentBytes, b"reveal-body").unwrap();
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
    ) -> RevealRequest {
        RevealRequest {
            recipe,
            full_public: full,
            packed,
            content_id: ContentId([9u8; 32]),
            viewer,
            owner,
            key_id,
            meter_budget: None,
        }
    }

    /// A live grant lets the grantee open; a viewer with no grant is refused.
    #[test]
    fn sealed_reveal_rpc_requires_live_grant() {
        let (full, packed) = sample();
        let owner = addr(1);
        let viewer = addr(2);
        let key_id = [7u8; 32];
        let mut reg = ViewGrantRegistry::new();

        let sealed = ThreeRecipe::Sealed(full.clone().seal());

        // No grant yet -> refused.
        let r = req(
            sealed.clone(),
            Some(full.clone()),
            packed.clone(),
            viewer,
            owner,
            key_id,
        );
        assert_eq!(
            open_reveal_session(&reg, &owner, &r).unwrap_err(),
            RevealRpcError::Forbidden
        );

        // Issue the grant -> the same request now opens.
        reg.issue(
            ContentId([9u8; 32]),
            owner,
            Some(viewer),
            key_id,
            ViewPolicy::NamedGrantee,
            1,
        )
        .unwrap();
        let mut handle = open_reveal_session(&reg, &owner, &r).unwrap();
        // And the handle produces frames under the gate.
        let (frames, _) = handle.emit_frames(0, 1).unwrap();
        assert!(!frames.is_empty());
    }

    /// Naming oneself the owner is not being the owner.
    ///
    /// The registry lets the owner open with no grant. A request whose
    /// `viewer` and `owner` were both the caller used to go through that
    /// shortcut for content somebody else owns; the recorded owner now
    /// decides, and a request that names anyone else is refused before the
    /// registry is asked.
    #[test]
    fn a_caller_who_names_itself_owner_is_refused() {
        let (full, packed) = sample();
        let owner = addr(1);
        let stranger = addr(3);
        let key_id = [7u8; 32];
        let reg = ViewGrantRegistry::new();
        let sealed = ThreeRecipe::Sealed(full.clone().seal());

        let r = req(sealed, Some(full), packed, stranger, stranger, key_id);
        assert!(
            reg.may_view(&r.content_id, &r.viewer, &r.key_id, &r.owner),
            "the raw registry would have let the self-styled owner in"
        );
        assert_eq!(
            open_reveal_session(&reg, &owner, &r).unwrap_err(),
            RevealRpcError::Forbidden
        );
    }

    /// A revoked grant blocks a *new* session; the revoked one cannot reopen.
    #[test]
    fn revoked_grant_blocks_new_reveal_session() {
        let (full, packed) = sample();
        let owner = addr(1);
        let viewer = addr(2);
        let key_id = [7u8; 32];
        let mut reg = ViewGrantRegistry::new();
        let grant_id = reg
            .issue(
                ContentId([9u8; 32]),
                owner,
                Some(viewer),
                key_id,
                ViewPolicy::NamedGrantee,
                1,
            )
            .unwrap();

        let sealed = ThreeRecipe::Sealed(full.clone().seal());
        let r = req(sealed, Some(full), packed, viewer, owner, key_id);

        // Opens while the grant is live.
        assert!(open_reveal_session(&reg, &owner, &r).is_ok());

        // Revoke; a fresh request for a new session is now refused.
        reg.revoke(grant_id, owner, 5).unwrap();
        assert_eq!(
            open_reveal_session(&reg, &owner, &r).unwrap_err(),
            RevealRpcError::Forbidden
        );
    }

    /// The meter budget really cuts a frame ask.
    #[test]
    fn reveal_meter_budget_trips() {
        let (full, packed) = sample();
        let owner = addr(1);
        let viewer = addr(2);
        let key_id = [7u8; 32];
        let mut reg = ViewGrantRegistry::new();
        reg.issue(
            ContentId([9u8; 32]),
            owner,
            Some(viewer),
            key_id,
            ViewPolicy::NamedGrantee,
            1,
        )
        .unwrap();

        let sealed = ThreeRecipe::Sealed(full.clone().seal());
        let mut r = req(sealed, Some(full), packed, viewer, owner, key_id);
        // Each frame charges 2 units; a budget of 3 allows one frame but not two.
        r.meter_budget = Some(3);
        let mut handle = open_reveal_session(&reg, &owner, &r).unwrap();
        assert!(handle.emit_frames(0, 1).is_ok());
        assert!(matches!(
            handle.emit_frames(1, 2),
            Err(RevealRpcError::Meter(MeterError::BudgetExceeded { .. }))
        ));
    }
}
