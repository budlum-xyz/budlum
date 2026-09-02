//! Social/DM delete → key rotation (plan §CH G5; CK.5 dam item).
//!
//! Deleting content from a social surface or a DM must do two things for the
//! product to stay honest to the threat model (T3):
//!
//! 1. Every live view grant for the content is revoked, so no *new* reveal
//!    session opens.
//! 2. The payload key id rotates - the delete is the signal that the old key
//!    id is retired ([`crate::storage::three_visibility::delete_implies_key_rotate`]).
//!
//! Both go through the [`crate::storage::three_hooks::ThreeEventHook`] seam so
//! the gateway drops local session keys and stops serving frames. Devices that
//! already hold frames are not clawed back - the honest limit the docs state.

use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use crate::storage::three_hooks::{emit_hook, ThreeEventHook, ThreeHookEvent, ThreeHookKind};
use crate::storage::view_grant::ViewGrantRegistry;

/// What a social delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteOutcome {
    /// Live grants the delete revoked.
    pub grants_revoked: usize,
    /// Whether a key-rotation event was emitted. Always true: delete implies
    /// key rotation, and the flow obeys the rule rather than re-stating it.
    pub key_rotated: bool,
}

/// Process a social/DM delete for `content_id` by `owner` at `epoch`.
///
/// Revokes every live grant the owner issued for the content (each through
/// [`ViewGrantRegistry::revoke_with_hook`], so each revocation emits its own
/// `GrantRevoked` event), then emits one `KeyRotated` event. Grants issued by
/// someone else are left alone: the owner has no word over them, so the
/// per-grant revoke refuses and the delete does not pretend otherwise.
#[must_use]
pub fn process_social_delete(
    grants: &mut ViewGrantRegistry,
    content_id: ContentId,
    owner: Address,
    at_epoch: u64,
    hook: &mut dyn ThreeEventHook,
) -> DeleteOutcome {
    let live_ids: Vec<u64> = grants
        .live_for_content(&content_id)
        .into_iter()
        .map(|g| g.grant_id)
        .collect();
    let mut revoked = 0usize;
    for id in live_ids {
        if grants.revoke_with_hook(id, owner, at_epoch, hook).is_ok() {
            revoked += 1;
        }
    }
    let key_rotated = crate::storage::three_visibility::delete_implies_key_rotate();
    if key_rotated {
        emit_hook(
            hook,
            ThreeHookEvent {
                kind: ThreeHookKind::KeyRotated,
                content_id,
                actor: owner,
                epoch: at_epoch,
                grant_id: None,
            },
        );
    }
    DeleteOutcome {
        grants_revoked: revoked,
        key_rotated,
    }
}

#[cfg(test)]
mod social_delete_tests {
    use super::*;
    use crate::storage::three_hooks::RecordingThreeHook;
    use crate::storage::view_grant::ViewPolicy;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn cid(b: u8) -> ContentId {
        ContentId([b; 32])
    }

    #[test]
    fn delete_revokes_live_grants_and_rotates_the_key() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let alice = addr(2);
        let content = cid(9);
        let g1 = reg
            .issue(
                content,
                owner,
                Some(alice),
                [7u8; 32],
                ViewPolicy::NamedGrantee,
                10,
            )
            .unwrap();
        let _g2 = reg
            .issue(
                content,
                owner,
                Some(addr(3)),
                [8u8; 32],
                ViewPolicy::NamedGrantee,
                10,
            )
            .unwrap();
        let mut hook = RecordingThreeHook::default();

        let out = process_social_delete(&mut reg, content, owner, 20, &mut hook);

        assert_eq!(out.grants_revoked, 2);
        assert!(out.key_rotated);
        assert!(!reg.may_view(&content, &alice, &[7u8; 32], &owner));
        // Events: two GrantRevoked + one KeyRotated.
        assert_eq!(hook.events.len(), 3);
        assert!(hook
            .events
            .iter()
            .any(|e| e.kind == ThreeHookKind::KeyRotated));
        assert!(hook
            .events
            .iter()
            .any(|e| e.kind == ThreeHookKind::GrantRevoked && e.grant_id == Some(g1)));
    }

    #[test]
    fn delete_with_no_grants_still_rotates_the_key() {
        let mut reg = ViewGrantRegistry::new();
        let mut hook = RecordingThreeHook::default();
        let out = process_social_delete(&mut reg, cid(9), addr(1), 5, &mut hook);
        assert_eq!(out.grants_revoked, 0);
        assert!(out.key_rotated);
        assert_eq!(hook.events.len(), 1);
        assert_eq!(hook.events[0].kind, ThreeHookKind::KeyRotated);
    }

    #[test]
    fn delete_leaves_another_issuers_grant_alone() {
        let mut reg = ViewGrantRegistry::new();
        let owner = addr(1);
        let stranger = addr(7);
        let content = cid(9);
        // The stranger issues a grant for content they do not own: the row is
        // in the book but inert, and the owner must not revoke it.
        reg.issue(
            content,
            stranger,
            Some(addr(2)),
            [7u8; 32],
            ViewPolicy::NamedGrantee,
            10,
        )
        .unwrap();
        let mut hook = RecordingThreeHook::default();
        let out = process_social_delete(&mut reg, content, owner, 20, &mut hook);
        assert_eq!(
            out.grants_revoked, 0,
            "the owner has no word over the stranger's row"
        );
        assert!(out.key_rotated);
        assert_eq!(hook.events.len(), 1, "only the KeyRotated event");
    }
}
