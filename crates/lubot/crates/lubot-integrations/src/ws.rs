//! WebSocket bağlantı deseni - taşıyıcıdan bağımsız iskelet.
//!
//! Bağlantı yönetimi (yeniden bağlanma, kapatma sinyali, oturum
//! doğrulama) ile uygulama mantığını ayırır. Taşıyıcı (tokio-tungstenite
//! vb.) bu türlerin üzerine kurulur.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Bağlantı durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Authenticated,
    Failed,
}

/// Bağlantı yapılandırması.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsConfig {
    pub url: String,
    /// Yeniden bağlanma denemeleri arası bekleme (saniye).
    pub reconnect_delay_secs: u64,
    /// Azami ardışık yeniden bağlanma denemesi (0 = sınırsız).
    pub max_reconnects: u32,
}

/// Kapatma (kill) sinyali: tüm dinleyicilere yayınlanır; `trigger()`
/// çağrıldığında `is_killed()` true döner.
#[derive(Debug, Default)]
pub struct KillSignal {
    flag: AtomicBool,
}

impl KillSignal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sinyali tetikler (idempotent).
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_killed(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Paylaşılan referans üretir.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

/// Tek bir WS iletisinin işlenmesi için geri çağrı sözleşmesi.
pub trait WsHandler {
    /// Bağlandıktan sonra oturum açma adımı (ör. kimlik doğrulama iletisi).
    fn on_connected(&mut self) -> Result<String, String>;

    /// Gelen bir iletinin işlenmesi. Toplu mesajlar `as_items` ile
    /// ayrıştırılmış biçimde verilir.
    fn on_message(&mut self, items: &[serde_json::Value]) -> Result<(), String>;

    /// Bağlantı koptuğunda çağrılır.
    fn on_disconnect(&mut self, reason: &str);
}

/// Basit oturum yönetimi: `connected`/`authenticated` iletilerini izler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionTracker {
    state: ConnState,
}

impl SessionTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gelen iletiden oturum durumunu günceller.
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
