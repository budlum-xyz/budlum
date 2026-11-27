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

const MAX_MULTIADDR_LEN: usize = 512;

fn is_valid_relay_offer(offer: &RelayOffer) -> bool {
    offer.capacity_kbps > 0
        && offer.multiaddr.starts_with('/')
        && offer.multiaddr.len() <= MAX_MULTIADDR_LEN
        && !offer
            .multiaddr
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

impl RelayPool {
    /// A pool over `relays`. Invalid, zero-capacity, or duplicate multiaddr
    /// entries are filtered out; the first valid entry is current.
    #[must_use]
    pub fn new(relays: Vec<RelayOffer>) -> Self {
        let mut filtered: Vec<RelayOffer> = Vec::with_capacity(relays.len());
        for offer in relays {
            if is_valid_relay_offer(&offer)
                && !filtered
                    .iter()
                    .any(|existing| existing.multiaddr == offer.multiaddr)
            {
                filtered.push(offer);
            }
        }
        Self {
            relays: filtered,
            current: 0,
        }
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
