//! G5 - revoke / social event hooks (plan §CH G5).
//!
//! The chain already revokes grants (`ViewGrantRegistry`). Product surfaces
//! (DM delete, social fi, UI toast) need a **callback** when revoke happens so
//! they can drop local session keys. This trait is that seam; default is a
//! no-op sink so consensus does not depend on UI.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;

/// Why a Three-related social/privacy event fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeHookKind {
    /// Grant revoked - no new opens.
    GrantRevoked,
    /// Owner rotated payload key id (off-chain); old sessions should die.
    KeyRotated,
    /// NFT metadata visibility flipped sealed→public or reverse (rare).
    VisibilityChanged,
}

/// Event payload (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeHookEvent {
    pub kind: ThreeHookKind,
    pub content_id: ContentId,
    pub actor: Address,
    pub epoch: u64,
    /// Optional grant id when kind is `GrantRevoked`.
    pub grant_id: Option<u64>,
}

/// Implement on the social / gateway side.
pub trait ThreeEventHook {
    /// Deliver an event. Must not panic; errors are logged by the caller.
    fn on_three_event(&mut self, event: &ThreeHookEvent);
}

/// Default sink: discards events (tests / headless nodes).
#[derive(Debug, Default, Clone, Copy)]
pub struct NopThreeHook;

impl ThreeEventHook for NopThreeHook {
    fn on_three_event(&mut self, _event: &ThreeHookEvent) {}
}

/// Recording hook for tests.
#[derive(Debug, Default, Clone)]
pub struct RecordingThreeHook {
    /// Captured events.
    pub events: Vec<ThreeHookEvent>,
}

impl ThreeEventHook for RecordingThreeHook {
    fn on_three_event(&mut self, event: &ThreeHookEvent) {
        self.events.push(event.clone());
    }
}

/// Fan-out helper used by future RPC revoke paths.
pub fn emit_hook(hook: &mut dyn ThreeEventHook, event: ThreeHookEvent) {
    hook.on_three_event(&event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_captures_revoke() {
        let mut h = RecordingThreeHook::default();
        emit_hook(
            &mut h,
            ThreeHookEvent {
                kind: ThreeHookKind::GrantRevoked,
                content_id: ContentId([1u8; 32]),
                actor: Address::from([2u8; 32]),
                epoch: 9,
                grant_id: Some(3),
            },
        );
        assert_eq!(h.events.len(), 1);
        assert_eq!(h.events[0].kind, ThreeHookKind::GrantRevoked);
        assert_eq!(h.events[0].grant_id, Some(3));
    }
}
