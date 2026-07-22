//! Task 11.10 — storage deal lifecycle state machine.
//!
//! This pure module models the spec-frozen lifecycle before it is wired into the
//! existing `StorageRegistry`: Open → Proving → Challenged → terminal outcomes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageLifecycleState {
    Open,
    Proving,
    Challenged,
    Settled,
    Missed,
    Slashed,
    Expired,
}

impl StorageLifecycleState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Missed | Self::Slashed | Self::Expired
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::Proving)
                | (Self::Open, Self::Expired)
                | (Self::Proving, Self::Challenged)
                | (Self::Proving, Self::Settled)
                | (Self::Proving, Self::Expired)
                | (Self::Challenged, Self::Settled)
                | (Self::Challenged, Self::Missed)
                | (Self::Challenged, Self::Slashed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageLifecycleError {
    TerminalState {
        from: StorageLifecycleState,
        to: StorageLifecycleState,
    },
    InvalidTransition {
        from: StorageLifecycleState,
        to: StorageLifecycleState,
    },
}

pub fn transition(
    from: StorageLifecycleState,
    to: StorageLifecycleState,
) -> Result<StorageLifecycleState, StorageLifecycleError> {
    if from.is_terminal() {
        return Err(StorageLifecycleError::TerminalState { from, to });
    }
    if !from.can_transition_to(to) {
        return Err(StorageLifecycleError::InvalidTransition { from, to });
    }
    Ok(to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_happy_path_settled() {
        let state =
            transition(StorageLifecycleState::Open, StorageLifecycleState::Proving).unwrap();
        let state = transition(state, StorageLifecycleState::Challenged).unwrap();
        let state = transition(state, StorageLifecycleState::Settled).unwrap();
        assert_eq!(state, StorageLifecycleState::Settled);
        assert!(state.is_terminal());
    }

    #[test]
    fn lifecycle_challenge_can_miss_or_slash() {
        assert_eq!(
            transition(
                StorageLifecycleState::Challenged,
                StorageLifecycleState::Missed
            )
            .unwrap(),
            StorageLifecycleState::Missed
        );
        assert_eq!(
            transition(
                StorageLifecycleState::Challenged,
                StorageLifecycleState::Slashed
            )
            .unwrap(),
            StorageLifecycleState::Slashed
        );
    }

    #[test]
    fn lifecycle_rejects_skip_open_to_settled() {
        let err =
            transition(StorageLifecycleState::Open, StorageLifecycleState::Settled).unwrap_err();
        assert_eq!(
            err,
            StorageLifecycleError::InvalidTransition {
                from: StorageLifecycleState::Open,
                to: StorageLifecycleState::Settled,
            }
        );
    }

    #[test]
    fn lifecycle_terminal_states_are_final() {
        for terminal in [
            StorageLifecycleState::Settled,
            StorageLifecycleState::Missed,
            StorageLifecycleState::Slashed,
            StorageLifecycleState::Expired,
        ] {
            let err = transition(terminal, StorageLifecycleState::Open).unwrap_err();
            assert_eq!(
                err,
                StorageLifecycleError::TerminalState {
                    from: terminal,
                    to: StorageLifecycleState::Open,
                }
            );
        }
    }
}
