//! The WebSocket connection pattern - a transport-independent skeleton.
//!
//! It separates connection management (reconnection, the kill signal, session
//! authentication) from application logic. The transport
//! (tokio-tungstenite and friends) is built on top of these types.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConnState {
    /// The initial state: `SessionTracker::default()` expected it, but
    /// `ConnState` did not derive `Default`, so the derive did not compile.
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Failed,
}

/// The connection configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsConfig {
    pub url: String,
    /// The wait between reconnection attempts (in seconds).
    pub reconnect_delay_secs: u64,
    /// The maximum number of consecutive reconnection attempts (0 means
    /// unlimited).
    pub max_reconnects: u32,
}

/// The kill signal: broadcast to every listener; once `trigger()` is called,
/// `is_killed()` returns true.
#[derive(Debug, Default)]
pub struct KillSignal {
    flag: AtomicBool,
}

impl KillSignal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fires the signal (idempotent).
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_killed(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Produces a shared reference.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

/// The callback contract for handling a single WS message.
pub trait WsHandler {
    /// The login step after connecting (for example an authentication
    /// message).
    fn on_connected(&mut self) -> Result<String, String>;

    /// Handling an incoming message. Batched messages are handed over already
    /// split by `as_items`.
    fn on_message(&mut self, items: &[serde_json::Value]) -> Result<(), String>;

    /// Called when the connection drops.
    fn on_disconnect(&mut self, reason: &str);
}

/// Simple session management: it watches the `connected`/`authenticated`
/// messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionTracker {
    state: ConnState,
}

impl SessionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the session state from an incoming message.
    pub fn observe(&mut self, item: &serde_json::Value) {
        if crate::is_success_connected_or_authed(item) {
            self.state = ConnState::Authenticated;
        }
    }

    #[must_use]
    pub fn state(&self) -> ConnState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_signal_is_idempotent() {
        let signal = KillSignal::new();
        assert!(!signal.is_killed());
        signal.trigger();
        signal.trigger();
        assert!(signal.is_killed());
    }

    #[test]
    fn session_tracker_observes_auth() {
        let mut tracker = SessionTracker::new();
        assert_eq!(tracker.state(), ConnState::Disconnected);
        tracker.observe(&serde_json::json!({"T": "success", "msg": "authenticated"}));
        assert_eq!(tracker.state(), ConnState::Authenticated);
    }
}
