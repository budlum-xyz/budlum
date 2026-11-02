//! WebSocket subscriptions.
//!
//! `bud_subscribe(kind, address?)` on the public listener's WebSocket
//! transport. Three feeds:
//!
//! - `newHeads`: every block appended to this node's chain, as
//!   `bud_getBlockByNumber` returns it.
//! - `finalizedHeads`: every block a finality certificate covers, in height
//!   order, once it is covered.
//! - `logs`: the transactions of every new block, one notification each;
//!   with an address, only those it sends or receives.
//!
//! A feed reads the chain through the same handle the read methods use and
//! writes nothing. It follows the chain by polling once a second and sends at
//! most [`MAX_BLOCKS_PER_TICK`] blocks per tick, so a subscriber that falls
//! behind costs a bounded amount of work; a block that a reorg replaces after
//! it was sent is not sent again.

use crate::chain::chain_actor::ChainHandle;
use crate::core::address::Address;
use crate::core::block::Block;
use std::time::Duration;

/// How often a feed looks for new blocks.
const POLL: Duration = Duration::from_secs(1);
/// The most blocks a feed sends per poll.
/// exposed for: the RPC surface - method handlers land with the subscription wiring.
pub const MAX_BLOCKS_PER_TICK: u64 = 64;

/// What a subscription follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feed {
    NewHeads,
    FinalizedHeads,
    Logs(Option<Address>),
}

impl Feed {
    /// Read the subscription parameters.
    ///
    /// # Errors
    ///
    /// An unknown kind, an address on a feed that takes none, or an address
    /// that is not 32 bytes of hex.
    pub fn parse(kind: &str, address: Option<&str>) -> Result<Self, String> {
        match (kind, address) {
            ("newHeads", None) => Ok(Self::NewHeads),
            ("finalizedHeads", None) => Ok(Self::FinalizedHeads),
            ("logs", None) => Ok(Self::Logs(None)),
            ("logs", Some(hex)) => Address::from_hex(hex)
                .map(|a| Self::Logs(Some(a)))
                .map_err(|e| format!("invalid address '{hex}': {e}")),
            ("newHeads" | "finalizedHeads", Some(_)) => {
                Err(format!("the {kind} feed takes no address"))
            }
            (other, _) => Err(format!(
                "unknown subscription '{other}' (newHeads, finalizedHeads or logs)"
            )),
        }
    }

    /// The notifications one block yields on this feed.
    pub fn items(
        self,
        block: Block,
        to_json: fn(Block) -> serde_json::Value,
    ) -> Vec<serde_json::Value> {
        match self {
            Self::NewHeads | Self::FinalizedHeads => vec![to_json(block)],
            Self::Logs(filter) => {
                let height = block.index;
                let hash = block.hash.clone();
                block
                    .transactions
                    .iter()
                    .filter(|tx| filter.is_none_or(|a| tx.from == a || tx.to == a))
                    .map(|tx| {
                        serde_json::json!({
                            "blockNumber": format!("0x{height:x}"),
                            "blockHash": format!("0x{hash}"),
                            "transactionHash": format!("0x{}", tx.hash),
                            "from": format!("0x{}", tx.from.to_hex()),
                            "to": format!("0x{}", tx.to.to_hex()),
                            "amount": tx.amount,
                            "nonce": tx.nonce,
                        })
                    })
                    .collect()
            }
        }
    }

    async fn tip(self, chain: &ChainHandle) -> u64 {
        match self {
            Self::FinalizedHeads => chain.get_finalized_height().await,
            Self::NewHeads | Self::Logs(_) => chain.get_height().await,
        }
    }

    /// Follow the chain and send this feed's notifications until the
    /// subscriber goes away.
    pub async fn run(
        self,
        chain: ChainHandle,
        sink: jsonrpsee::SubscriptionSink,
        to_json: fn(Block) -> serde_json::Value,
    ) {
        let mut last = self.tip(&chain).await;
        let mut tick = tokio::time::interval(POLL);
        loop {
            tokio::select! {
                () = sink.closed() => return,
                _ = tick.tick() => {}
            }
            let tip = self.tip(&chain).await;
            if tip <= last {
                continue;
            }
            let from = last
                .saturating_add(1)
                .max(tip.saturating_sub(MAX_BLOCKS_PER_TICK - 1));
            for height in from..=tip {
                let Some(block) = chain.get_block(height).await else {
                    break;
                };
                for item in self.items(block, to_json) {
                    let Ok(raw) = serde_json::value::to_raw_value(&item) else {
                        continue;
                    };
                    if sink.send(raw).await.is_err() {
                        return;
                    }
                }
                last = height;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameters_name_a_feed() {
        assert_eq!(Feed::parse("newHeads", None), Ok(Feed::NewHeads));
        assert_eq!(
            Feed::parse("finalizedHeads", None),
            Ok(Feed::FinalizedHeads)
        );
        assert_eq!(Feed::parse("logs", None), Ok(Feed::Logs(None)));
        let a = "11".repeat(32);
        assert_eq!(
            Feed::parse("logs", Some(&a)),
            Ok(Feed::Logs(Some(Address::from([0x11; 32]))))
        );
        assert!(Feed::parse("newHeads", Some(&a)).is_err());
        assert!(Feed::parse("logs", Some("zz")).is_err());
        assert!(Feed::parse("pendingTransactions", None).is_err());
    }

    #[test]
    fn a_logs_filter_keeps_the_transactions_of_its_address() {
        use crate::core::transaction::Transaction;
        let alice = Address::from([0xA1; 32]);
        let bob = Address::from([0xB0; 32]);
        let carol = Address::from([0xC0; 32]);
        let block = Block::new(
            7,
            "00".repeat(32),
            vec![
                Transaction::new(alice, bob, 1, vec![]),
                Transaction::new(carol, carol, 2, vec![]),
            ],
        );
        let to_json = |_b: Block| serde_json::Value::Null;
        assert_eq!(Feed::Logs(None).items(block.clone(), to_json).len(), 2);
        let bobs = Feed::Logs(Some(bob)).items(block.clone(), to_json);
        assert_eq!(bobs.len(), 1);
        assert_eq!(bobs[0]["blockNumber"], "0x7");
        assert_eq!(
            Feed::NewHeads.items(block, to_json),
            vec![serde_json::Value::Null]
        );
    }
}
