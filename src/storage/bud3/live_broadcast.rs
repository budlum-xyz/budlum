//! WP-55, 2/N: the live broadcast driver and the gateway door.
//!
//! WP-55 1/N (`live.rs`) delivers the time-segment state machine, the
//! `prev_object` chain and the ratioless frame order. It deliberately leaves
//! three things owed: a driver that turns that order into actual RFC 6330
//! symbols and fans them out to viewers, a gateway door that refuses bit1
//! objects on the testnet chain id, and the activation-height check that opens
//! the feature after launch (M7). This module delivers all three.
//!
//! Directive 6.16 and 1.5: a live segment is a T-Expansion feature. It is
//! closed on the testnet chain id and opens only at an activation height. A
//! refusal is proved by `live_stream_is_closed_on_testnet`, and the refusal
//! is checked at the object door, not in a comment.
//!
//! WIRING: unwired - the content gateway calls [`LiveGateway::admit_object`] for every
//! registered object and [`LiveGateway::admit_viewer`] for every live view;
//! [`BroadcastDriver`] is the sender-side emission path. Like the rest of
//! `bud3`, the executor reaches these doors once the legacy storage
//! transactions are removed; until then the state machine and its refusals
//! are exercised by the tests below. No float, no wall clock and no unbounded
//! queue is used: every bound is a named integer constant.

use std::collections::{BTreeMap, VecDeque};

use super::bof1::{Flags, Object};
use super::fountain::{FountainError, SegmentEncoder, Symbol};
use super::limits::Profile;
use super::live::{
    LiveActivation, LiveContext, LiveError, LiveFrame, LiveSegment, LiveStream, RatiolessPlan,
    ViewerTicket, ACTIVATION,
};
use crate::core::chain_config::{ChainId, Network};

/// TESTNET-DEFAULT: the largest number of simultaneous viewers of one stream.
pub const MAX_LIVE_SUBSCRIBERS: usize = 1024;

/// TESTNET-DEFAULT: the largest pending-symbol queue of one viewer. A slow
/// viewer loses the oldest symbol; it never grows the sender's memory.
pub const MAX_LIVE_PENDING_SYMBOLS: usize = 4096;

/// Why a live call was refused at the gateway or in the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveGatewayRefusal {
    /// bit1 objects are refused on the testnet chain id at launch (6.16.6).
    ClosedOnTestnet {
        /// The chain that refused the object.
        chain_id: u64,
        /// The height the call was made at.
        height: u64,
    },
    /// The activation height is set but the chain has not reached it.
    BelowActivationHeight {
        /// The height the call was made at.
        height: u64,
        /// The height live opens at.
        activation: u64,
    },
    /// Live is closed on a chain other than the testnet.
    Closed {
        /// The height the call was made at.
        height: u64,
    },
    /// An object without bit1 was presented to the live-only door.
    NotLive,
    /// The stream state machine refused the call.
    Stream(LiveError),
}

impl From<LiveError> for LiveGatewayRefusal {
    fn from(error: LiveError) -> Self {
        Self::Stream(error)
    }
}

/// The one door every live object and every viewer request passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveGateway {
    chain_id: ChainId,
    activation: LiveActivation,
}

impl LiveGateway {
    /// The gateway of `chain_id` with its activation schedule.
    #[must_use]
    pub const fn for_chain(chain_id: ChainId, activation: LiveActivation) -> Self {
        Self {
            chain_id,
            activation,
        }
    }

    /// The testnet launch gateway: bit1 objects are refused.
    #[must_use]
    pub fn testnet() -> Self {
        Self::for_chain(Network::Testnet.chain_id(), ACTIVATION)
    }

    /// The activation schedule this gateway enforces.
    #[must_use]
    pub const fn activation(&self) -> LiveActivation {
        self.activation
    }

    /// The context a stream is created with at `height`.
    #[must_use]
    pub const fn context(&self, height: u64) -> LiveContext {
        LiveContext {
            height,
            activation: self.activation,
        }
    }

    fn check_open(&self, height: u64) -> Result<(), LiveGatewayRefusal> {
        if self.activation.is_open_at(height) {
            return Ok(());
        }
        match self.activation.height {
            Some(activation) => Err(LiveGatewayRefusal::BelowActivationHeight { height, activation }),
            None if self.chain_id == Network::Testnet.chain_id() => {
                Err(LiveGatewayRefusal::ClosedOnTestnet {
                    chain_id: self.chain_id.value(),
                    height,
                })
            }
            None => Err(LiveGatewayRefusal::Closed { height }),
        }
    }

    /// Admit an object. Plain objects are unaffected; a bit1 live object is
    /// refused while live is closed.
    ///
    /// # Errors
    ///
    /// [`LiveGatewayRefusal::ClosedOnTestnet`],
    /// [`LiveGatewayRefusal::BelowActivationHeight`] or
    /// [`LiveGatewayRefusal::Closed`] for a live-flagged object.
    pub fn admit_object(&self, object: &Object, height: u64) -> Result<(), LiveGatewayRefusal> {
        if object.header.flags.has(Flags::LIVE) {
            self.check_open(height)?;
        }
        Ok(())
    }

    /// Admit an object that must be a live segment.
    ///
    /// # Errors
    ///
    /// [`LiveGatewayRefusal::NotLive`] when bit1 is absent, or the activation
    /// refusals of [`Self::admit_object`].
    /// exposed for: T-Expansion live object gateway admission (`WP-55`).
    pub fn admit_live_object(
        &self,
        object: &Object,
        height: u64,
    ) -> Result<(), LiveGatewayRefusal> {
        if !object.header.flags.has(Flags::LIVE) {
            return Err(LiveGatewayRefusal::NotLive);
        }
        self.admit_object(object, height)
    }

    /// Admit a viewer at `now_ms`. The stream's own join-latency budget is
    /// preserved; a closed chain is refused before the stream is asked.
    ///
    /// # Errors
    ///
    /// The activation refusals, or [`LiveGatewayRefusal::Stream`] when the
    /// stream has no head or its head is stale.
    pub fn admit_viewer(
        &self,
        stream: &LiveStream,
        now_ms: u64,
        height: u64,
    ) -> Result<ViewerTicket, LiveGatewayRefusal> {
        self.check_open(height)?;
        stream.viewer_join(now_ms).map_err(LiveGatewayRefusal::from)
    }
}

/// Why a broadcast step refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    /// RFC 6330 could not code one segment.
    Encode(FountainError),
    /// The subscriber cap was reached.
    TooManySubscribers,
    /// The frame names a segment that the driver does not hold.
    UnknownSegment(u64),
    /// The frame names an ESI the encoder cannot produce.
    BadEsi(u32),
    /// A segment has more source symbols than the 32-bit ESI space allows.
    TooManySources,
}

impl From<FountainError> for BroadcastError {
    fn from(error: FountainError) -> Self {
        Self::Encode(error)
    }
}

/// The sender side of one live broadcast.
///
/// The frame order comes from [`RatiolessPlan`]. Each frame is mapped to the
/// RFC 6330 `Symbol` of its segment through [`SegmentEncoder`]. Every
/// subscriber holds a bounded queue; a slow subscriber drops the oldest
/// symbol, so the sender's memory never depends on the viewer.
#[derive(Debug)]
pub struct BroadcastDriver {
    sources: Vec<Vec<Symbol>>,
    encoders: Vec<SegmentEncoder>,
    plan: RatiolessPlan,
    subscribers: BTreeMap<u64, VecDeque<Symbol>>,
    dropped: BTreeMap<u64, u64>,
    emitted: u64,
}

impl BroadcastDriver {
    /// Build a driver over the segments of one stream. The segments are the
    /// P0 BOF-1 objects, so sender and receiver code the same bytes.
    ///
    /// # Errors
    ///
    /// [`BroadcastError::Encode`] when a segment cannot be coded under P0.
    pub fn new(segments: &[LiveSegment]) -> Result<Self, BroadcastError> {
        let mut sources = Vec::with_capacity(segments.len());
        let mut encoders = Vec::with_capacity(segments.len());
        let mut ks = Vec::with_capacity(segments.len());
        for segment in segments {
            let bytes = segment.object.encode();
            let encoder = SegmentEncoder::new(segment.index, &bytes, &Profile::P0)?;
            let source = encoder.source_symbols();
            ks.push(
                u32::try_from(source.len()).map_err(|_| BroadcastError::TooManySources)?,
            );
            sources.push(source);
            encoders.push(encoder);
        }
        Ok(Self {
            sources,
            encoders,
            plan: RatiolessPlan::new(&ks),
            subscribers: BTreeMap::new(),
            dropped: BTreeMap::new(),
            emitted: 0,
        })
    }

    /// The number of source symbols of `segment`.
    #[must_use]
    pub fn source_count(&self, segment: u64) -> u32 {
        self.sources
            .get(usize::try_from(segment).unwrap_or(usize::MAX))
            .map_or(0, |s| u32::try_from(s.len()).unwrap_or(u32::MAX))
    }

    /// How many symbols the driver has emitted.
    #[must_use]
    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    fn symbol_for(&self, frame: LiveFrame) -> Result<Symbol, BroadcastError> {
        match frame {
            LiveFrame::Source { segment, esi } => self
                .sources
                .get(usize::try_from(segment).unwrap_or(usize::MAX))
                .and_then(|s| s.get(usize::try_from(esi).unwrap_or(usize::MAX)))
                .cloned()
                .ok_or(BroadcastError::BadEsi(esi)),
            LiveFrame::Repair { segment, esi } => {
                let encoder = self
                    .encoders
                    .get(usize::try_from(segment).unwrap_or(usize::MAX))
                    .ok_or(BroadcastError::UnknownSegment(segment))?;
                let first = esi
                    .checked_sub(encoder.k())
                    .ok_or(BroadcastError::BadEsi(esi))?;
                encoder
                    .repair_symbols(first, 1)
                    .map_err(BroadcastError::from)?
                    .into_iter()
                    .next()
                    .ok_or(BroadcastError::BadEsi(esi))
            }
        }
    }

    /// Emit the next symbol of the ratioless order.
    pub fn next_symbol(&mut self) -> Option<Symbol> {
        let frame = self.plan.next()?;
        let symbol = self.symbol_for(frame).ok()?;
        self.emitted = self.emitted.saturating_add(1);
        Some(symbol)
    }

    /// Register a viewer.
    ///
    /// # Errors
    ///
    /// [`BroadcastError::TooManySubscribers`] at the cap.
    pub fn subscribe(&mut self, id: u64) -> Result<(), BroadcastError> {
        if !self.subscribers.contains_key(&id) && self.subscribers.len() >= MAX_LIVE_SUBSCRIBERS {
            return Err(BroadcastError::TooManySubscribers);
        }
        self.subscribers.entry(id).or_default();
        self.dropped.entry(id).or_insert(0);
        Ok(())
    }

    /// Remove a viewer and release its queue.
    pub fn unsubscribe(&mut self, id: u64) {
        self.subscribers.remove(&id);
        self.dropped.remove(&id);
    }

    /// Deliver one symbol to every viewer. Returns the number of viewers.
    pub fn fan_out(&mut self, symbol: &Symbol) -> usize {
        let count = self.subscribers.len();
        for (id, queue) in &mut self.subscribers {
            if queue.len() >= MAX_LIVE_PENDING_SYMBOLS {
                queue.pop_front();
                if let Some(d) = self.dropped.get_mut(id) {
                    *d = d.saturating_add(1);
                }
            }
            queue.push_back(symbol.clone());
        }
        count
    }

    /// Emit and fan out at most `limit` symbols. Returns the number emitted.
    pub fn drive(&mut self, limit: usize) -> usize {
        let mut sent = 0usize;
        while sent < limit {
            let Some(symbol) = self.next_symbol() else {
                break;
            };
            self.fan_out(&symbol);
            sent = sent.saturating_add(1);
        }
        sent
    }

    /// Take the oldest pending symbol of viewer `id`.
    pub fn deliver(&mut self, id: u64) -> Option<Symbol> {
        self.subscribers.get_mut(&id)?.pop_front()
    }

    /// How many symbols viewer `id` lost to backpressure.
    #[must_use]
    pub fn dropped(&self, id: u64) -> u64 {
        self.dropped.get(&id).copied().unwrap_or(0)
    }

    /// How many symbols are pending for viewer `id`.
    #[must_use]
    pub fn pending(&self, id: u64) -> usize {
        self.subscribers.get(&id).map_or(0, VecDeque::len)
    }
}

#[cfg(test)]
mod tests {
    use super::super::fountain::SymbolKind;
    use super::super::live::LIVE_SEGMENT_MS;
    use super::*;

    const ORIGINATOR: [u8; 32] = [7; 32];
    const NONCE: [u8; 32] = [9; 32];

    fn open_context() -> LiveContext {
        LiveContext {
            height: 10,
            activation: LiveActivation { height: Some(10) },
        }
    }

    fn two_segments() -> Vec<LiveSegment> {
        let mut stream = LiveStream::begin(ORIGINATOR, NONCE, open_context()).unwrap();
        stream.push_segment(0, b"first segment").unwrap();
        stream.push_segment(LIVE_SEGMENT_MS, b"second segment").unwrap();
        stream.segments().to_vec()
    }

    fn open_gateway() -> LiveGateway {
        LiveGateway::for_chain(Network::Devnet.chain_id(), LiveActivation { height: Some(10) })
    }

    #[test]
    fn live_stream_is_closed_on_testnet() {
        let gateway = LiveGateway::testnet();
        let segments = two_segments();
        assert_eq!(
            gateway.admit_object(&segments[0].object, 1),
            Err(LiveGatewayRefusal::ClosedOnTestnet {
                chain_id: Network::Testnet.chain_id().value(),
                height: 1,
            })
        );
        assert_eq!(
            gateway.admit_live_object(&segments[0].object, 1_000_000),
            Err(LiveGatewayRefusal::ClosedOnTestnet {
                chain_id: Network::Testnet.chain_id().value(),
                height: 1_000_000,
            })
        );
        // A plain object is never refused by the live door.
        let mut plain = segments[0].object.clone();
        plain.header.flags = Flags::from_byte(0).unwrap();
        assert_eq!(gateway.admit_object(&plain, 1), Ok(()));
        assert_eq!(
            gateway.admit_live_object(&plain, 1),
            Err(LiveGatewayRefusal::NotLive)
        );
        // The viewer door refuses before it asks the stream.
        let stream = LiveStream::begin(ORIGINATOR, NONCE, gateway.context(1));
        assert!(stream.is_err());
        assert_eq!(
            gateway.admit_viewer(
                &two_segments_stream(),
                0,
                1,
            ),
            Err(LiveGatewayRefusal::ClosedOnTestnet {
                chain_id: Network::Testnet.chain_id().value(),
                height: 1,
            })
        );
    }

    fn two_segments_stream() -> LiveStream {
        let mut stream = LiveStream::begin(ORIGINATOR, NONCE, open_context()).unwrap();
        stream.push_segment(0, b"first segment").unwrap();
        stream.push_segment(LIVE_SEGMENT_MS, b"second segment").unwrap();
        stream
    }

    #[test]
    fn bud3_live_gateway_opens_only_at_the_activation_height() {
        let gateway = LiveGateway::for_chain(
            Network::Devnet.chain_id(),
            LiveActivation { height: Some(100) },
        );
        let segments = two_segments();
        assert_eq!(
            gateway.admit_object(&segments[0].object, 99),
            Err(LiveGatewayRefusal::BelowActivationHeight {
                height: 99,
                activation: 100,
            })
        );
        assert_eq!(gateway.admit_object(&segments[0].object, 100), Ok(()));
        let mut plain = segments[0].object.clone();
        plain.header.flags = Flags::from_byte(0).unwrap();
        assert_eq!(gateway.admit_object(&plain, 1), Ok(()));
    }

    #[test]
    fn bud3_live_viewer_join_goes_through_the_gateway() {
        let gateway = open_gateway();
        let stream = two_segments_stream();
        let ticket = gateway.admit_viewer(&stream, 2 * LIVE_SEGMENT_MS, 10).unwrap();
        assert_eq!(ticket.start_index, 1);
        assert_eq!(
            gateway.admit_viewer(&stream, 20 * LIVE_SEGMENT_MS, 10),
            Err(LiveGatewayRefusal::Stream(LiveError::HeadStale {
                age_ms: 18 * LIVE_SEGMENT_MS,
                max_ms: 2 * LIVE_SEGMENT_MS,
            }))
        );
    }

    #[test]
    fn bud3_live_broadcast_emits_sources_before_repairs() {
        let segments = two_segments();
        let mut driver = BroadcastDriver::new(&segments).unwrap();
        let mut symbols = Vec::new();
        for _ in 0..8 {
            symbols.push(driver.next_symbol().unwrap());
        }
        let k0 = driver.source_count(0);
        let k1 = driver.source_count(1);
        assert!(k0 > 0 && k1 > 0);
        let kinds: Vec<SymbolKind> = symbols
            .iter()
            .map(|s| s.kind(driver.source_count(s.segment)))
            .collect();
        assert_eq!(&kinds[..2], &[SymbolKind::Source, SymbolKind::Source]);
        assert!(kinds[2..].iter().all(|k| *k == SymbolKind::Repair));
        assert_eq!(driver.emitted(), 8);
        // Every symbol carries exactly one P0 symbol's worth of bytes.
        assert!(symbols.iter().all(|s| s.data.len() == Profile::P0.symbol_size as usize));
    }

    #[test]
    fn bud3_live_broadcast_queue_is_bounded() {
        let segments = two_segments();
        let mut driver = BroadcastDriver::new(&segments).unwrap();
        driver.subscribe(1).unwrap();
        driver.subscribe(2).unwrap();
        let extra = 10usize;
        let sent = driver.drive(MAX_LIVE_PENDING_SYMBOLS + extra);
        assert_eq!(sent, MAX_LIVE_PENDING_SYMBOLS + extra);
        assert_eq!(driver.pending(1), MAX_LIVE_PENDING_SYMBOLS);
        assert_eq!(driver.dropped(1), extra as u64);
        assert!(driver.deliver(1).is_some());
        driver.unsubscribe(1);
        assert_eq!(driver.pending(1), 0);
        assert_eq!(driver.pending(2), MAX_LIVE_PENDING_SYMBOLS);
    }

    #[test]
    fn bud3_live_broadcast_refuses_too_many_subscribers() {
        let segments = two_segments();
        let mut driver = BroadcastDriver::new(&segments).unwrap();
        for id in 0..MAX_LIVE_SUBSCRIBERS as u64 {
            driver.subscribe(id).unwrap();
        }
        assert_eq!(
            driver.subscribe(MAX_LIVE_SUBSCRIBERS as u64),
            Err(BroadcastError::TooManySubscribers)
        );
        // Re-subscribing an existing viewer is not a new subscriber.
        assert_eq!(driver.subscribe(0), Ok(()));
    }
}
