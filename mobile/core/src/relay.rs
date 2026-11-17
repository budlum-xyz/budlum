//! Relay pool: when a reservation drops, the core binds the next relay
//! (section 7.6, relay row; section 7.9.7).

/// A relay a Full validator offered on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOffer {
    /// libp2p multiaddress.
    pub multiaddr: String,
    /// Advertised capacity in kilobits per second.
    pub capacity_kbps: u64,
}

/// Ordered relay candidates and the one currently bound.
#[derive(Debug, Clone, Default)]
pub struct RelayPool {
    relays: Vec<RelayOffer>,
    current: usize,
}

impl RelayPool {
    /// A pool over `relays`. The first entry is current when the list is not
    /// empty.
    #[must_use]
    pub fn new(relays: Vec<RelayOffer>) -> Self {
        Self { relays, current: 0 }
    }

    /// The currently bound relay.
    #[must_use]
    pub fn current(&self) -> Option<&RelayOffer> {
        self.relays.get(self.current)
    }

    /// Bind the next relay after a drop. Returns the new current relay.
    ///
    /// With one relay the pool stays on it (the host will retry). With none
    /// the result is `None`.
    pub fn on_drop(&mut self) -> Option<&RelayOffer> {
        if self.relays.is_empty() {
            return None;
        }
        if self.relays.len() == 1 {
            return self.relays.first();
        }
        self.current = (self.current + 1) % self.relays.len();
        self.relays.get(self.current)
    }
}
