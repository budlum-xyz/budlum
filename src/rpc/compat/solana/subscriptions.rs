//! Solana WebSocket subscriptions (WP-31, 2/N).
//!
//! Only the slot feed can be answered truthfully before the SVM worker exists.
//! Account, signature, log and program feeds are refused by name at the
//! subscription door. The slot feed reports Budlum chain progress, not Solana's
//! 400 ms slot clock; `docs/SOLANA_RPC.md` states that boundary.

use crate::chain::chain_actor::ChainHandle;
use jsonrpsee::PendingSubscriptionSink;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// One poll of the chain actor per second, shared with the native feed design.
const POLL: Duration = Duration::from_secs(1);
/// A slow subscriber never makes the node replay an unbounded history.
const MAX_SLOTS_PER_TICK: u64 = 64;
/// A subscriber that stops reading releases its node-wide feed slot.
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// The commitment levels this gateway can map without inventing SVM votes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Commitment {
    /// The locally validated head. This is the default for the compatibility feed.
    #[default]
    Processed,
    /// The last height covered by a Budlum finality certificate.
    Finalized,
}

/// The Solana `slotSubscribe` configuration object.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    /// Omitted means [`Commitment::Processed`].
    pub commitment: Option<Commitment>,
}

/// The Solana `slotNotification` result shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SlotNotification {
    /// Previous Budlum height, clamped at genesis.
    pub parent: u64,
    /// Finalized Budlum height, never above the reported slot.
    pub root: u64,
    /// The reported Budlum height.
    pub slot: u64,
}

impl SlotNotification {
    /// Build the wire result from one chain observation.
    #[must_use]
    pub const fn new(slot: u64, finalized: u64) -> Self {
        Self {
            parent: slot.saturating_sub(1),
            root: finalized.min(slot),
            slot,
        }
    }

    /// Serialize without a fallible unwrap on the production path.
    fn json(self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

/// The bounded range to emit after one poll. A lagging viewer jumps to the
/// newest window instead of making the chain actor replay arbitrary history.
#[must_use]
pub const fn catch_up_range(last: u64, tip: u64) -> Option<(u64, u64)> {
    if tip <= last {
        return None;
    }
    let first = last
        .saturating_add(1)
        .max(tip.saturating_sub(MAX_SLOTS_PER_TICK - 1));
    Some((first, tip))
}

/// Refuse an SVM-dependent subscription before accepting it, so no feed slot,
/// subscription id or background task is created for an unavailable stream.
pub async fn reject_svm(
    pending: PendingSubscriptionSink,
    method: &str,
    door: &'static str,
) -> jsonrpsee::core::SubscriptionResult {
    pending.reject(super::ee_unavailable(method, door)).await;
    Ok(())
}

/// Accept the one chain-backed feed and keep its permit until the client goes.
pub async fn accept_slots(
    pending: PendingSubscriptionSink,
    chain: ChainHandle,
    config: Option<SlotConfig>,
) -> jsonrpsee::core::SubscriptionResult {
    let commitment = config.unwrap_or_default().commitment.unwrap_or_default();
    let Some(slot) = crate::rpc::server::feed_slot() else {
        pending
            .reject(jsonrpsee::types::ErrorObjectOwned::owned(
                -32005,
                "subscription limit reached; retry later",
                None::<()>,
            ))
            .await;
        return Ok(());
    };
    let sink = pending.accept().await?;
    tokio::spawn(async move {
        let _slot = slot;
        run_slots(chain, sink, commitment).await;
    });
    Ok(())
}

async fn tip(chain: &ChainHandle, commitment: Commitment) -> u64 {
    match commitment {
        Commitment::Processed => chain.get_height().await,
        Commitment::Finalized => chain.get_finalized_height().await,
    }
}

async fn send(sink: &jsonrpsee::SubscriptionSink, notification: SlotNotification) -> bool {
    let Ok(value) = notification.json() else {
        return false;
    };
    let Ok(raw) = serde_json::value::to_raw_value(&value) else {
        return false;
    };
    matches!(
        sink.send_timeout(raw, SEND_TIMEOUT).await,
        Ok(())
    )
}

async fn run_slots(
    chain: ChainHandle,
    sink: jsonrpsee::SubscriptionSink,
    commitment: Commitment,
) {
    let mut last = tip(&chain, commitment).await;
    let finalized = chain.get_finalized_height().await;
    if !send(&sink, SlotNotification::new(last, finalized)).await {
        return;
    }
    let mut tick = tokio::time::interval(POLL);
    loop {
        tokio::select! {
            () = sink.closed() => return,
            _ = tick.tick() => {}
        }
        let current = tip(&chain, commitment).await;
        let Some((first, last_in_tick)) = catch_up_range(last, current) else {
            continue;
        };
        let finalized = chain.get_finalized_height().await;
        for height in first..=last_in_tick {
            if !send(&sink, SlotNotification::new(height, finalized)).await {
                return;
            }
            last = height;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solana_slot_notification_shape_is_the_solana_shape() {
        let value = SlotNotification::new(7, 5).json().unwrap();
        assert_eq!(value, serde_json::json!({"parent": 6, "root": 5, "slot": 7}));
        let genesis = SlotNotification::new(0, 9).json().unwrap();
        assert_eq!(genesis, serde_json::json!({"parent": 0, "root": 0, "slot": 0}));
    }

    #[test]
    fn solana_slot_catch_up_is_bounded_and_never_replays_a_reorg() {
        assert_eq!(catch_up_range(7, 7), None);
        assert_eq!(catch_up_range(8, 7), None);
        assert_eq!(catch_up_range(7, 9), Some((8, 9)));
        assert_eq!(catch_up_range(0, 1_000), Some((937, 1_000)));
        assert_eq!(catch_up_range(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn solana_slot_config_accepts_only_the_two_honest_commitments() {
        assert_eq!(serde_json::from_str::<SlotConfig>("{}").unwrap().commitment, None);
        for text in ["{\"commitment\":\"processed\"}", "{\"commitment\":\"finalized\"}"] {
            assert!(serde_json::from_str::<SlotConfig>(text).is_ok(), "{text}");
        }
        for text in ["{\"commitment\":\"confirmed\"}", "{\"limit\":1}", "[]", "null"] {
            assert!(serde_json::from_str::<SlotConfig>(text).is_err(), "{text}");
        }
    }
}
