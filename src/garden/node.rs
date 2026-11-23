//! The Garden validator runtime.
//!
//! One task owns everything a validator holds: its key, the finalized chain,
//! the pending transactions, the content store and the swarm. It proposes
//! when it leads a round, executes and votes on the proposals of the others,
//! and reports every finalized block to the node's Budlum chain.
//!
//! # How a block becomes final
//!
//! 1. The leader of `(height, round)` proposes a block. A leader that stays
//!    silent loses the slot: after `round_ms` the next validator leads.
//! 2. Every validator in the electorate executes the block and signs it.
//! 3. The host signs last, once the other signatures it holds make its own
//!    the one that completes more than two thirds. The host signs one block
//!    per height, so two blocks never become final at the same height, and
//!    no block becomes final while the host is away.
//!
//! The host has no other power over blocks. It cannot finalize a block the
//! others did not sign, and it proposes only in its own turn. In a Garden
//! founded with host approval it also answers the keys that ask to join,
//! and it does that with a transaction like any other.

use super::invite::{fit_peers, GardenInvite};
use super::net::{
    self, announced_address, peer_id_of, validator_dial_address, BudgetedFrame, FramePermits,
    GardenGossip, GardenNet, GardenRequest, GardenResponse, NetCommand, NetEvent, MAX_GOSSIP_BATCH,
    MAX_SYNC_COMMITS,
};
use super::settlement::{GardenBudlumLink, GardenDomainView};
use super::state::{quorum, GardenLedger, GardenObject, GardenState};
use super::storage::GardenContentStore;
use super::types::{
    garden_domain_id, invite_keypair, join_message, status_label, GardenAdmission,
    GardenAdmissionState, GardenBlock, GardenCommit, GardenContentKind, GardenFounding,
    GardenGenesis, GardenKey, GardenLimits, GardenPlacementTable, GardenPresence, GardenTx,
    GardenTxKind, GardenValidatorStatus, GardenVote, SignedGardenTx,
};
use crate::crypto::primitives::{verify_signature, KeyPair};
use crate::domain::types::{DomainStatus, Hash32};
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

/// Most pending transactions a node keeps.
const MAX_MEMPOOL: usize = 4096;
/// Most bytes one pending transaction may take. Every field of a valid
/// transaction is bounded, so anything larger can never enter a block and
/// is refused before hashing, verification or storage.
const MAX_TX_BYTES: usize = 1024;
/// Most bytes the pending transaction set may hold together, whatever the
/// item count.
const MAX_MEMPOOL_BYTES: usize = 2 * 1024 * 1024;
/// Most proposals a node keeps for one height.
const MAX_PROPOSALS: usize = 32;
/// Most votes kept while their block has not arrived.
const MAX_ORPHAN_VOTES: usize = 256;
/// Most orphan votes one validator may hold at one height.
const MAX_ORPHAN_VOTES_PER_VOTER: usize = 4;
/// Most orphan votes one peer connection may contribute at one height.
const MAX_ORPHAN_VOTES_PER_PEER: usize = 16;
/// Most unjoined invite holders admitted concurrently into `peers`.
const MAX_UNJOINED_PEERS: usize = 4;
/// Maximum turned-away keys remembered for immediate refusal in `HostApproval`.
const MAX_TURNED_AWAY_KEYS: usize = 4096;
/// Maximum gossip items accepted from one peer per second.
const MAX_GOSSIP_ITEMS_PER_PEER_PER_SEC: usize = 128;
/// Maximum `GetCommits` sync requests accepted from one peer per second.
const MAX_SYNC_REQS_PER_PEER_PER_SEC: usize = 8;
/// Maximum peer-triggered outbound `GetCommits` requests sent per second.
const MAX_PEER_TRIGGERED_SYNCS_PER_SEC: usize = 8;
/// Maximum age of an unanswered in-flight outbound `GetCommits` request before
/// another sync request for the same height may be dispatched.
const SYNC_IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum `PutObject` deposits accepted from one peer per second.
const MAX_PUT_OBJECT_REQS_PER_PEER_PER_SEC: usize = 96;
/// Maximum concurrent disk `PutObject` write/fsync jobs across the node.
const MAX_IN_FLIGHT_DEPOSITS: usize = 8;
/// Maximum concurrent disk `PutObject` write/fsync jobs for one peer.
const MAX_IN_FLIGHT_DEPOSITS_PER_PEER: usize = 2;
/// Maximum unjoined invite holders admitted concurrently from one non-loopback
/// source prefix, so a single host cannot consume all `MAX_UNJOINED_PEERS`
/// slots and shut the join door to other newcomers.
const MAX_UNJOINED_PEERS_PER_SOURCE: usize = 1;
/// Maximum `(validator, address)` entries retained in `rejected_addresses`.
const MAX_REJECTED_ADDRESSES: usize = 512;
/// Sliding window for per-peer `GetObject` rate limiting.
const OBJECT_RATE_WINDOW: Duration = Duration::from_secs(10);
/// Maximum `GetObject` requests accepted from one peer per window.
const MAX_OBJECT_REQS_PER_WINDOW: usize = 32;
/// Maximum consecutive failed dials to one announced address before stopping.
const MAX_DIAL_FAILURES: u8 = 4;
/// Maximum `(validator, address)` dial records kept across leaves and returns.
const MAX_DIAL_RECORDS: usize = 512;
/// Retry interval for dialing invite peers during bootstrap.
const BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Expected byte length of an Ed25519 signature on a vote.
const VOTE_SIGNATURE_BYTES: usize = 64;
/// Most gossip ids remembered to forward each item once.
const MAX_SEEN: usize = 16_384;
/// Most gossip items that wait for one peer. Past it the oldest is dropped:
/// finalized blocks come back through sync and presence is sent again.
const MAX_OUTBOX: usize = 2_048;
/// Most bytes that may wait in one peer's gossip outbox.
const MAX_OUTBOX_BYTES: usize = 8 * 1024 * 1024;
/// Target byte ceiling for one outbound gossip batch, well below
/// `MAX_REQUEST_BYTES`.
const MAX_GOSSIP_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Target byte ceiling for one `GetCommits` response, leaving headroom
/// below `MAX_RESPONSE_BYTES`.
const MAX_SYNC_RESPONSE_BYTES: usize = net::MAX_RESPONSE_BYTES - 1024 * 1024;
/// How far ahead of this node's clock a block may be dated and still get its
/// vote: two minutes. TESTNET-DEFAULT. It covers the clocks of two phones
/// that were never set against each other, and no more.
const MAX_TIMESTAMP_AHEAD_MS: u64 = 120_000;
/// Most objects kept that no finalized transaction names yet.
const MAX_UNREFERENCED_OBJECTS: usize = 64;
/// Most such objects kept for one peer.
const MAX_UNREFERENCED_PER_PEER: usize = 8;
/// Most connected peers that have not shown the invite yet. A peer shows it
/// in its first request, so in a Garden that is left alone this is the few
/// that connected in the last moments. The connection table is much larger:
/// the rest of it stays for the peers that did show it.
const MAX_UNADMITTED: usize = 16;
/// Longest wait between two dials of an address that does not answer.
const MAX_DIAL_WAIT: Duration = Duration::from_mins(1);
/// Most validators dialed in one round.
const MAX_DIALS_PER_ROUND: usize = 8;
/// Peers asked at once for one object.
const FETCH_FANOUT: usize = 4;
/// How long a node waits for an object before it gives up.
const FETCH_TIMEOUT: Duration = Duration::from_secs(25);
/// How long joining may take before it is abandoned.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
/// Most entries one feed answer carries.
const MAX_FEED: usize = 200;

const TAG_IGNORE: u64 = 0;
const TAG_HELLO: u64 = 1;
const TAG_SYNC: u64 = 2;
const TAG_GOSSIP: u64 = 3;
const TAG_ADMISSION: u64 = 4;
const TAG_FIRST_FETCH: u64 = 100;

/// How this node runs its Garden swarm and where it keeps Garden content.
#[derive(Clone, Debug)]
pub struct GardenNodeConfig {
    /// Display name of this validator.
    pub name: String,
    /// Multiaddr the Garden swarm listens on.
    pub listen: String,
    /// Address to announce instead of the bound one, without the peer id.
    /// A node behind a NAT leaves it empty and listens on an unspecified
    /// address: it is then reached through the peers it dialed.
    pub announce: Option<String>,
    /// Directory for Garden content. `None` keeps content in memory.
    pub content_dir: Option<PathBuf>,
}

/// How a node enters a Garden.
#[derive(Clone, Debug)]
pub enum GardenEntry {
    /// Found a new Garden and be its host.
    Create { title: String, limits: GardenLimits },
    /// Enter an existing Garden with an invite. A key that is already in the
    /// identity record returns; a new key joins.
    Invite(GardenInvite),
}

/// What is left after a node leaves.
#[derive(Clone, Debug)]
pub struct GardenLeaveOutcome {
    pub chain_id: u64,
    /// True when the Garden itself ended with this departure.
    pub retired: bool,
    /// The invite this node can return with, while the Garden lives.
    pub invite: GardenInvite,
    pub height: u64,
}

enum GardenCommand {
    Status(oneshot::Sender<Value>),
    Invite(oneshot::Sender<Result<GardenInvite, String>>),
    Publish {
        kind: GardenContentKind,
        bytes: Vec<u8>,
        mime: String,
        caption: String,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    Resolve(Hash32, oneshot::Sender<Result<Vec<u8>, String>>),
    Trace(Hash32, oneshot::Sender<Result<Value, String>>),
    Feed(usize, oneshot::Sender<Value>),
    Leave(oneshot::Sender<GardenLeaveOutcome>),
    Admit {
        target: GardenKey,
        accept: bool,
        reply: oneshot::Sender<Result<Value, String>>,
    },
}

/// The library handle of a running Garden validator.
#[derive(Clone, Debug)]
pub struct GardenHandle {
    commands: mpsc::Sender<GardenCommand>,
    chain_id: u64,
    genesis_hash: Hash32,
}

impl GardenHandle {
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub const fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    async fn ask<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> GardenCommand,
    ) -> Result<T, String> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(build(reply))
            .await
            .map_err(|_| "garden node has stopped".to_string())?;
        answer
            .await
            .map_err(|_| "garden node has stopped".to_string())
    }

    /// The Garden as this validator sees it.
    pub async fn status(&self) -> Result<Value, String> {
        self.ask(GardenCommand::Status).await
    }

    /// The invite that lets someone else join through this validator.
    pub async fn invite(&self) -> Result<GardenInvite, String> {
        self.ask(GardenCommand::Invite).await?
    }

    /// Publish a message, a post or an image.
    pub async fn publish(
        &self,
        kind: GardenContentKind,
        bytes: Vec<u8>,
        mime: String,
        caption: String,
    ) -> Result<Value, String> {
        self.ask(|reply| GardenCommand::Publish {
            kind,
            bytes,
            mime,
            caption,
            reply,
        })
        .await?
    }

    /// Answer a key that waits for the host: admit it or turn it away. Only
    /// the host of a Garden with host approval has anybody to answer.
    pub async fn admit(&self, target: GardenKey, accept: bool) -> Result<Value, String> {
        self.ask(|reply| GardenCommand::Admit {
            target,
            accept,
            reply,
        })
        .await?
    }

    /// Resolve an object on this node and check it against its content id.
    pub async fn resolve(&self, content_id: Hash32) -> Result<Vec<u8>, String> {
        self.ask(|reply| GardenCommand::Resolve(content_id, reply))
            .await?
    }

    /// The path of a transaction through the chain. `tx_id` may also be the
    /// content id of a published object.
    pub async fn trace(&self, tx_id: Hash32) -> Result<Value, String> {
        self.ask(|reply| GardenCommand::Trace(tx_id, reply)).await?
    }

    /// The newest published objects, newest first.
    pub async fn feed(&self, limit: usize) -> Result<Value, String> {
        self.ask(|reply| GardenCommand::Feed(limit, reply)).await
    }

    /// Leave the Garden and wipe its data from this node.
    pub async fn leave(&self) -> Result<GardenLeaveOutcome, String> {
        self.ask(GardenCommand::Leave).await
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Thirty-two random bytes: a validator key seed or an invite token.
pub fn random_bytes() -> Hash32 {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn millis(value: u32) -> Duration {
    Duration::from_millis(u64::from(value))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Seen {
    Tx(Hash32),
    Block(Hash32),
    Vote(Hash32, GardenKey),
    Commit(Hash32),
    Presence(GardenKey, u64),
}

struct Fetch {
    waiters: Vec<oneshot::Sender<Result<Vec<u8>, String>>>,
    outstanding: usize,
    keep: bool,
    started: Instant,
}

struct Relay {
    requester: PeerId,
    channel: Option<ResponseChannel<BudgetedFrame>>,
    outstanding: usize,
    content_id: Hash32,
}

/// The height of the final block a gossip item carries.
const fn final_height(item: &GardenGossip) -> Option<u64> {
    match item {
        GardenGossip::Commit(commit) => Some(commit.block.header.height),
        _ => None,
    }
}

/// Estimated memory and wire weight of one signed transaction, in bytes.
///
/// Only the signature, name, address, invite signature, MIME type and caption
/// can grow; every other field is fixed size.
const fn tx_bytes(tx: &SignedGardenTx) -> usize {
    let grown = match &tx.tx.kind {
        GardenTxKind::Join {
            name,
            address,
            invite_signature,
        } => name
            .len()
            .saturating_add(address.len())
            .saturating_add(invite_signature.len()),
        GardenTxKind::Leave | GardenTxKind::Suspend { .. } | GardenTxKind::Admit { .. } => 0,
        GardenTxKind::Resume { address } => address.len(),
        GardenTxKind::Publish { mime, caption, .. } => mime.len().saturating_add(caption.len()),
    };
    grown.saturating_add(tx.signature.len()).saturating_add(256)
}

/// Estimated weight of one proposed block, in bytes.
fn block_bytes(block: &GardenBlock) -> usize {
    let txs: usize = block.txs.iter().map(tx_bytes).sum();
    block
        .proposer_signature
        .len()
        .saturating_add(512)
        .saturating_add(txs)
}

/// Estimated weight of one finalized commit, in bytes.
fn commit_bytes(commit: &GardenCommit) -> usize {
    let votes: usize = commit
        .votes
        .iter()
        .map(|vote| vote.signature.len().saturating_add(128))
        .sum();
    block_bytes(&commit.block).saturating_add(votes)
}

/// Estimated weight of one gossip item, in bytes.
fn gossip_bytes(item: &GardenGossip) -> usize {
    match item {
        GardenGossip::Tx(tx) => tx_bytes(tx),
        GardenGossip::Proposal(block) => block_bytes(block),
        GardenGossip::Vote(vote) => vote.signature.len().saturating_add(128),
        GardenGossip::Commit(commit) => commit_bytes(commit),
        GardenGossip::Presence(signal) => signal.signature.len().saturating_add(96),
    }
}

/// Append `item` to a peer's gossip outbox while enforcing both item-count and
/// byte budgets. Oldest entries are dropped first to make room.
fn queue_gossip_item(
    queue: &mut VecDeque<GardenGossip>,
    item: GardenGossip,
    max_items: usize,
    max_bytes: usize,
) {
    let item_bytes = gossip_bytes(&item);
    if max_items == 0 || item_bytes > max_bytes || item_bytes > net::MAX_REQUEST_BYTES {
        return;
    }
    let mut queued_bytes: usize = queue.iter().map(gossip_bytes).sum();
    while queue.len() >= max_items
        || (!queue.is_empty() && queued_bytes.saturating_add(item_bytes) > max_bytes)
    {
        let Some(dropped) = queue.pop_front() else {
            break;
        };
        queued_bytes = queued_bytes.saturating_sub(gossip_bytes(&dropped));
    }
    queue.push_back(item);
}

/// Drain the next outbound gossip batch from `queue` without crossing either
/// `max_items`, `max_bytes`, or the wire request frame limit.
fn drain_gossip_batch(
    queue: &mut VecDeque<GardenGossip>,
    max_items: usize,
    max_bytes: usize,
) -> Vec<GardenGossip> {
    const FRAME_OVERHEAD: u64 = 64;
    let mut batch = Vec::new();
    let mut batch_bytes = 0usize;
    let mut wire_bytes = FRAME_OVERHEAD;
    while batch.len() < max_items {
        let Some(front) = queue.front() else {
            break;
        };
        let next_bytes = gossip_bytes(front);
        let Ok(next_wire) = bincode::serialized_size(front) else {
            let _ = queue.pop_front();
            continue;
        };
        let fits_budget = batch_bytes.saturating_add(next_bytes) <= max_bytes;
        let fits_wire = wire_bytes.saturating_add(next_wire) <= net::MAX_REQUEST_BYTES as u64;
        if !batch.is_empty() && (!fits_budget || !fits_wire) {
            break;
        }
        let Some(item) = queue.pop_front() else {
            break;
        };
        batch.push(item);
        batch_bytes = batch_bytes.saturating_add(next_bytes);
        wire_bytes = wire_bytes.saturating_add(next_wire);
    }
    batch
}

/// Collect finalized commits from `from_height` up to `max` items without
/// crossing `max_bytes` or the wire response frame limit. At least one commit
/// is returned when `from_height` exists, so sync always makes progress.
fn take_sync_commits(
    ledger: &GardenLedger,
    from_height: u64,
    max: u32,
    max_bytes: usize,
) -> Vec<GardenCommit> {
    const FRAME_OVERHEAD: u64 = 64;
    let cap = max.min(MAX_SYNC_COMMITS) as usize;
    let mut commits = Vec::new();
    let mut total_bytes = 0usize;
    let mut wire_bytes = FRAME_OVERHEAD;
    let mut height = from_height.max(1);
    while commits.len() < cap {
        let Some((commit, _)) = ledger.commit_at(height) else {
            break;
        };
        let size = commit_bytes(commit);
        let Ok(next_wire) = bincode::serialized_size(commit) else {
            break;
        };
        let fits_budget = total_bytes.saturating_add(size) <= max_bytes;
        let fits_wire = wire_bytes.saturating_add(next_wire) <= net::MAX_RESPONSE_BYTES as u64;
        if !commits.is_empty() && (!fits_budget || !fits_wire) {
            break;
        }
        commits.push(commit.clone());
        total_bytes = total_bytes.saturating_add(size);
        wire_bytes = wire_bytes.saturating_add(next_wire);
        height = height.saturating_add(1);
    }
    commits
}

struct Leaving {
    deadline: Instant,
    tx_id: Option<Hash32>,
    /// The height of the block that carries this node's departure, once it
    /// is final here. The node stays until that block left its outboxes.
    sealed: Option<u64>,
    reply: oneshot::Sender<GardenLeaveOutcome>,
}

struct Node {
    key: KeyPair,
    me: GardenKey,
    name: String,
    token: Hash32,
    invite_signature: Vec<u8>,
    address: String,
    seeds: Vec<String>,
    ledger: GardenLedger,
    store: GardenContentStore,
    net: mpsc::Sender<NetCommand>,
    link: Option<GardenBudlumLink>,
    reported: u64,
    budlum_status: Option<DomainStatus>,
    budlum_error: Option<String>,
    peers: BTreeMap<PeerId, GardenKey>,
    /// Connected peers that have not shown the invite, and since when.
    unadmitted: BTreeMap<PeerId, Instant>,
    outbox: BTreeMap<PeerId, VecDeque<GardenGossip>>,
    /// The peers with a gossip request in flight, and the height of the
    /// highest final block that request carries (0 when it carries none).
    gossip_in_flight: BTreeMap<PeerId, u64>,
    /// The highest final block another validator is known to hold: it came
    /// from a peer, or a peer acknowledged it.
    held_elsewhere: u64,
    mempool: BTreeMap<(GardenKey, u64), SignedGardenTx>,
    my_next_nonce: u64,
    proposals: BTreeMap<Hash32, GardenBlock>,
    /// The round of this node's clock in which it last executed a candidate
    /// block of each proposer, for the height it is at.
    candidate_rounds: BTreeMap<GardenKey, u64>,
    votes: BTreeMap<Hash32, BTreeMap<GardenKey, GardenVote>>,
    orphan_votes: VecDeque<(Option<PeerId>, GardenVote)>,
    my_votes: BTreeSet<Hash32>,
    host_voted: bool,
    proposed_rounds: BTreeSet<u64>,
    height_started: Instant,
    pending_since: Option<Instant>,
    seen: BTreeSet<Seen>,
    seen_order: VecDeque<Seen>,
    last_seen: BTreeMap<GardenKey, Instant>,
    presence_windows: BTreeMap<GardenKey, u64>,
    my_window: u64,
    started: Instant,
    last_presence: Instant,
    /// When the last tick began. A long gap means this node stood still.
    last_tick: Instant,
    last_sync: Instant,
    last_dial: Instant,
    sync_cursor: usize,
    wanted: BTreeSet<Hash32>,
    /// The true size of published content this node fetched and did not
    /// keep, because no publication declares that size. It has one entry
    /// for a finalized publication at most.
    measured: BTreeMap<Hash32, u64>,
    /// Objects no finalized transaction names yet, by the peer that
    /// deposited them. A peer that deposits too much loses its own.
    unreferenced: BTreeMap<GardenKey, VecDeque<Hash32>>,
    /// Validators that have authenticated over a live connection.
    verified_peers: BTreeSet<GardenKey>,
    /// `(validator, announced_address)` pairs whose dial failed with a wrong
    /// peer id or exhausted retries; bounded FIFO so address churn cannot grow
    /// validator memory without limit.
    rejected_addresses: BTreeSet<(GardenKey, String)>,
    rejected_address_order: VecDeque<(GardenKey, String)>,
    /// Consecutive dial failures per `(validator, announced_address)`, kept
    /// across leaves and returns.
    dial_failures: BTreeMap<(GardenKey, String), u8>,
    /// `(validator, address)` backoff records: when to dial next, and the
    /// wait that led there. Kept across leaves and returns.
    dials: BTreeMap<(GardenKey, String), (Instant, Duration)>,
    /// Per-peer sliding window for inbound gossip items.
    gossip_budget: BTreeMap<PeerId, (Instant, usize)>,
    /// Per-peer sliding window for inbound `GetCommits` sync requests.
    sync_budget: BTreeMap<PeerId, (Instant, usize)>,
    /// Coalesced outbound `GetCommits` request currently in flight: `(peer, from_height, sent_at)`.
    sync_in_flight: Option<(PeerId, u64, Instant)>,
    /// Node-wide 1-second budget for peer-triggered outbound `GetCommits` requests.
    outbound_sync_budget: (Instant, usize),
    /// Per-peer sliding window for inbound `GetObject` requests and served bytes.
    object_budget: BTreeMap<PeerId, (Instant, usize, u64)>,
    /// Per-peer sliding window for inbound `PutObject` requests and deposited bytes.
    put_object_budget: BTreeMap<PeerId, (Instant, usize, u64)>,
    /// Background disk write/fsync completions for offloaded `PutObject` requests.
    deposit_tx: mpsc::Sender<DepositDone>,
    /// Live offloaded `PutObject` jobs per peer.
    deposits_in_flight: BTreeMap<PeerId, usize>,
    /// Total live offloaded `PutObject` jobs across all peers.
    total_deposits_in_flight: usize,
    /// Shared map of observed remote source prefixes per connected peer.
    peer_sources: std::sync::Arc<std::sync::Mutex<BTreeMap<PeerId, net::SourceKey>>>,
    /// Per-source sliding window throttling unjoined `Hello` slot churn from one non-loopback prefix.
    unjoined_source_budget: BTreeMap<net::SourceKey, (Instant, usize)>,
    /// When each connected peer passed `Hello`, used to expire idle unjoined peers.
    peer_admitted_at: BTreeMap<PeerId, Instant>,
    /// Peers scheduled for disconnect after their refusal/status response flushes.
    disconnect_after: BTreeMap<PeerId, Instant>,
    /// Keys refused by `Admit { accept: false }` on this Garden (bounded FIFO).
    turned_away_keys: BTreeSet<GardenKey>,
    turned_away_order: VecDeque<GardenKey>,
    /// Narrow remote status observed by an unseated joiner in `HostApproval` mode.
    remote_admission: Option<GardenAdmissionState>,
    /// The same record for the invite peers.
    seed_dials: Option<(Instant, Duration)>,
    fetches: BTreeMap<Hash32, Fetch>,
    fetch_tags: BTreeMap<u64, Hash32>,
    relays: BTreeMap<u64, Relay>,
    relay_tags: BTreeMap<u64, u64>,
    next_tag: u64,
    leaving: Option<Leaving>,
    /// True once the host turned this node's request away. The node stops
    /// asking: an answer is not something to be worn down.
    turned_away: bool,
    stopped: bool,
}

struct DepositDone {
    peer: PeerId,
    sender: GardenKey,
    content_id: Hash32,
    charged_len: u64,
    already_published_for_me: bool,
    outcome: Result<bool, String>,
    channel: ResponseChannel<BudgetedFrame>,
}

/// True when a gap of `gap` between two ticks means the node itself stood
/// still: its process was paused, or its device slept. The bound is half the
/// suspension window, the same grace the host gives a validator before it
/// signs a report about it.
fn stood_still(gap: Duration, limits: &GardenLimits) -> bool {
    gap >= millis(limits.suspend_after_ms / 2)
}

/// Start the silence clock of every validator in `others` again at `now`.
fn forgive_silence(
    last_seen: &mut BTreeMap<GardenKey, Instant>,
    others: impl Iterator<Item = GardenKey>,
    now: Instant,
) {
    for key in others {
        last_seen.insert(key, now);
    }
}

/// The display name of `key` in the identity record of `state`.
fn name_in(state: &GardenState, key: &GardenKey) -> String {
    state
        .validators
        .get(key)
        .map_or_else(String::new, |v| v.name.clone())
}

/// One entry of the feed.
fn feed_entry(state: &GardenState, object: &GardenObject, held_here: bool) -> Value {
    json!({
        "content_id": hex::encode(object.content_id),
        "tx_id": hex::encode(object.tx_id),
        "kind": object.kind.label(),
        "author": hex::encode(object.author),
        "author_name": name_in(state, &object.author),
        "size": object.size,
        "mime": object.mime,
        "caption": object.caption,
        "height": object.height,
        "held_here": held_here,
    })
}

/// The Garden domain as the node's Budlum chain records it.
fn budlum_record(view: &GardenDomainView, error: Option<&str>) -> Value {
    json!({
        "linked": true,
        "domain_id": view.domain_id,
        "status": status_label(view.status),
        "finalized_height": view.last_committed_height,
        "finalized_hash": hex::encode(view.last_committed_hash),
        "error": error,
    })
}

/// Start a Garden validator and return its handle.
///
/// `secret` is the seed of the validator key. It lives in memory only: a node
/// that restarts has no Garden identity left and joins again as a new
/// validator.
pub async fn spawn(
    entry: GardenEntry,
    config: GardenNodeConfig,
    secret: Hash32,
    link: Option<GardenBudlumLink>,
) -> Result<GardenHandle, String> {
    let key = KeyPair::from_seed(&secret).map_err(|e| e.to_string())?;
    let me = key.public_key_bytes();
    let mut garden_net = net::start(secret, &config.listen).await?;
    let address = match &config.announce {
        Some(base) if !base.trim().is_empty() => {
            format!("{}/p2p/{}", base.trim(), peer_id_of(&me)?)
        }
        _ => {
            // The bound address names one interface even when the node asked
            // for all of them, so the request decides, not the binding.
            let unspecified = config
                .listen
                .parse::<libp2p::Multiaddr>()
                .is_ok_and(|requested| net::is_unspecified(&requested));
            if unspecified {
                String::new()
            } else {
                announced_address(&garden_net.listen, &me)?
            }
        }
    };

    if !address.is_empty() {
        // The others dial this address under the same rule this node dials
        // theirs, so an address they would pass over is refused here.
        if let Err(e) = validator_dial_address(&address, &me) {
            let _ = garden_net.commands.send(NetCommand::Shutdown).await;
            return Err(format!(
                "the address {address} cannot be announced to the Garden: {e}"
            ));
        }
    }

    let mut peers = BTreeMap::new();
    let (ledger, token, seeds) = match entry {
        GardenEntry::Create { title, limits } => {
            if address.is_empty() {
                // The invite carries the host address. Without one nobody
                // could ever join, so the Garden is not founded at all.
                return Err(
                    "a Garden host needs an address the others can dial: listen on one \
                     interface or set the announce option"
                        .into(),
                );
            }
            let token = random_bytes();
            let nonce = u64::from_le_bytes({
                let mut low = [0u8; 8];
                for (dst, src) in low.iter_mut().zip(random_bytes().iter()) {
                    *dst = *src;
                }
                low
            });
            let genesis = GardenGenesis::new(
                GardenFounding {
                    title,
                    host_name: config.name.clone(),
                    host_address: address.clone(),
                    limits,
                },
                me,
                now_ms(),
                nonce,
                &token,
            )?;
            (GardenLedger::new(genesis)?, token, Vec::new())
        }
        GardenEntry::Invite(invite) => {
            match bootstrap(&mut garden_net, &invite, &key, &mut peers).await {
                Ok(ledger) => (ledger, invite.token, invite.peers.clone()),
                Err(e) => {
                    let _ = garden_net.commands.send(NetCommand::Shutdown).await;
                    return Err(e);
                }
            }
        }
    };

    let chain_id = ledger.state.chain_id();
    let genesis_hash = ledger.state.genesis.hash();
    let limits = ledger.state.genesis.limits.clone();
    let content_dir = config
        .content_dir
        .as_ref()
        .map(|dir| dir.join(format!("{chain_id:016x}")));
    let mut store = GardenContentStore::open_with_limit(
        content_dir.as_deref(),
        limits.max_object_bytes as usize,
        super::storage::MAX_LOCAL_GARDEN_BYTES,
    )?;
    let published_ids: BTreeSet<Hash32> = ledger
        .state
        .objects
        .values()
        .map(|obj| obj.content_id)
        .collect();
    store.prune_unaccounted(&published_ids);
    let invite_signature = invite_keypair(&token)?
        .sign(&join_message(chain_id, &me))
        .to_vec();

    let mut reported = 0;
    let mut budlum_status = None;
    if let Some(link) = &link {
        let genesis_hash = ledger.state.genesis.hash();
        if let Some(view) = link.view_for_genesis(chain_id, genesis_hash).await {
            reported = view.last_committed_height.min(ledger.state.height);
            budlum_status = Some(view.status);
        } else {
            link.register(&ledger.state.genesis, me).await?;
            budlum_status = Some(DomainStatus::Active);
        }
    }

    let (commands, command_rx) = mpsc::channel(256);
    let (deposit_tx, deposit_rx) = mpsc::channel(MAX_IN_FLIGHT_DEPOSITS.saturating_mul(2));
    let now = Instant::now();
    let my_next_nonce = ledger.state.next_nonce(&me);
    // What this node starts with came from the validators it synced from.
    let held_elsewhere = ledger.state.height;
    let verified_peers: BTreeSet<GardenKey> = peers.values().copied().collect();
    let peer_admitted_at: BTreeMap<PeerId, Instant> = peers.keys().map(|p| (*p, now)).collect();
    for peer in peers.keys().copied() {
        let _ = garden_net.commands.send(NetCommand::Admit(peer)).await;
    }
    let node = Node {
        key,
        me,
        name: config.name,
        token,
        invite_signature,
        address,
        seeds,
        ledger,
        store,
        net: garden_net.commands.clone(),
        link,
        reported,
        budlum_status,
        budlum_error: None,
        peers,
        unadmitted: BTreeMap::new(),
        outbox: BTreeMap::new(),
        gossip_in_flight: BTreeMap::new(),
        held_elsewhere,
        mempool: BTreeMap::new(),
        my_next_nonce,
        proposals: BTreeMap::new(),
        candidate_rounds: BTreeMap::new(),
        votes: BTreeMap::new(),
        orphan_votes: VecDeque::new(),
        my_votes: BTreeSet::new(),
        host_voted: false,
        proposed_rounds: BTreeSet::new(),
        height_started: now,
        pending_since: None,
        seen: BTreeSet::new(),
        seen_order: VecDeque::new(),
        last_seen: BTreeMap::new(),
        presence_windows: BTreeMap::new(),
        my_window: now_ms(),
        started: now,
        last_presence: now,
        last_tick: now,
        last_sync: now,
        last_dial: now,
        sync_cursor: 0,
        wanted: BTreeSet::new(),
        measured: BTreeMap::new(),
        unreferenced: BTreeMap::new(),
        verified_peers,
        rejected_addresses: BTreeSet::new(),
        rejected_address_order: VecDeque::new(),
        dial_failures: BTreeMap::new(),
        dials: BTreeMap::new(),
        gossip_budget: BTreeMap::new(),
        sync_budget: BTreeMap::new(),
        sync_in_flight: None,
        outbound_sync_budget: (now, 0),
        object_budget: BTreeMap::new(),
        put_object_budget: BTreeMap::new(),
        deposit_tx,
        deposits_in_flight: BTreeMap::new(),
        total_deposits_in_flight: 0,
        peer_sources: std::sync::Arc::clone(&garden_net.peer_sources),
        unjoined_source_budget: BTreeMap::new(),
        peer_admitted_at,
        disconnect_after: BTreeMap::new(),
        turned_away_keys: BTreeSet::new(),
        turned_away_order: VecDeque::new(),
        remote_admission: None,
        seed_dials: None,
        fetches: BTreeMap::new(),
        fetch_tags: BTreeMap::new(),
        relays: BTreeMap::new(),
        relay_tags: BTreeMap::new(),
        next_tag: TAG_FIRST_FETCH,
        leaving: None,
        turned_away: false,
        stopped: false,
    };
    tokio::spawn(node.run(garden_net.events, command_rx, deposit_rx));
    Ok(GardenHandle {
        commands,
        chain_id,
        genesis_hash,
    })
}

/// Fetch and verify the genesis and the finalized chain from the peers an
/// invite names.
///
/// Every validator stands in the invites the others hand out, so what one
/// peer answers is the answer of that peer and not of the Garden. A peer
/// that refuses, shows another genesis or serves a chain that does not
/// verify is passed over, and the join ends without a chain only when every
/// peer of the invite was passed over or the time is up.
async fn bootstrap(
    garden_net: &mut GardenNet,
    invite: &GardenInvite,
    key: &KeyPair,
    peers: &mut BTreeMap<PeerId, GardenKey>,
) -> Result<GardenLedger, String> {
    let me = key.public_key_bytes();
    let invite_key = invite_keypair(&invite.token)?;
    let hello = GardenRequest::Hello {
        chain_id: invite.chain_id,
        key: me,
        invite_signature: invite_key
            .sign(&join_message(invite.chain_id, &me))
            .to_vec(),
    };
    let mut named: BTreeSet<PeerId> = BTreeSet::new();
    let mut dial_targets: Vec<(libp2p::Multiaddr, PeerId)> = Vec::new();
    for peer in &invite.peers {
        if let Ok((address, id)) = net::dial_address(peer) {
            named.insert(id);
            dial_targets.push((address, id));
        }
    }
    if named.is_empty() {
        return Err("invite carries no dialable peer address".into());
    }
    // Dial one peer at a time before genesis is verified so untrusted invite
    // text cannot trigger a simultaneous probe against dozens of arbitrary IPs.
    let mut dialed_count = 1usize;
    if let Some((address, _)) = dial_targets.first() {
        let _ = garden_net
            .commands
            .send(NetCommand::Dial(address.clone()))
            .await;
    }
    let deadline = tokio::time::Instant::now() + BOOTSTRAP_TIMEOUT;
    let mut next_retry = tokio::time::Instant::now() + BOOTSTRAP_RETRY_INTERVAL;
    let mut genesis: Option<GardenGenesis> = None;
    let mut ledger: Option<GardenLedger> = None;
    let mut source: Option<PeerId> = None;
    // The peers that were passed over, each with its reason.
    let mut passed: BTreeMap<PeerId, String> = BTreeMap::new();
    loop {
        if source.is_none() {
            // Take the chain from a peer that welcomed this node and was
            // not passed over yet.
            let next = peers
                .keys()
                .find(|peer| !passed.contains_key(peer))
                .copied();
            if let (Some(peer), Some(genesis)) = (next, genesis.as_ref()) {
                ledger = Some(GardenLedger::new(genesis.clone())?);
                source = Some(peer);
                ask_commits(garden_net, peer, 1).await;
            } else if named.iter().all(|peer| passed.contains_key(peer)) {
                return Err(nobody_admitted(&passed));
            } else if dialed_count < dial_targets.len()
                && dial_targets
                    .iter()
                    .take(dialed_count)
                    .all(|(_, id)| passed.contains_key(id))
            {
                if let Some((address, _)) = dial_targets.get(dialed_count) {
                    let _ = garden_net
                        .commands
                        .send(NetCommand::Dial(address.clone()))
                        .await;
                }
                dialed_count += 1;
            }
        }
        let wake = deadline.min(next_retry);
        let event = match tokio::time::timeout_at(wake, garden_net.events.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => return Err("garden swarm stopped while joining".into()),
            Err(_) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    if passed.is_empty() {
                        return Err("no validator of this Garden answered the invite".into());
                    }
                    return Err(nobody_admitted(&passed));
                }
                next_retry = now + BOOTSTRAP_RETRY_INTERVAL;
                if dialed_count < dial_targets.len() {
                    dialed_count += 1;
                }
                for (address, id) in dial_targets.iter().take(dialed_count) {
                    if !peers.contains_key(id) && !passed.contains_key(id) {
                        let _ = garden_net
                            .commands
                            .send(NetCommand::Dial(address.clone()))
                            .await;
                    }
                }
                continue;
            }
        };
        match event {
            NetEvent::Connected(peer) => {
                let _ = garden_net
                    .commands
                    .send(NetCommand::Send {
                        peer,
                        request: hello.clone(),
                        tag: TAG_HELLO,
                    })
                    .await;
            }
            NetEvent::Disconnected(peer) => {
                peers.remove(&peer);
                if source == Some(peer) {
                    passed.insert(peer, "it went away before the chain arrived".into());
                    source = None;
                }
            }
            NetEvent::DialFailed {
                peer,
                wrong_peer_id,
            } => {
                if wrong_peer_id {
                    passed.insert(
                        peer,
                        "the peer at this address did not match its peer id".into(),
                    );
                }
            }
            NetEvent::Request { channel, .. } => {
                let _ = garden_net
                    .commands
                    .send(NetCommand::Respond {
                        channel,
                        response: GardenResponse::Refused("still joining".into()),
                    })
                    .await;
            }
            NetEvent::Response {
                peer,
                tag: TAG_HELLO,
                response,
                ..
            } => match response {
                Ok(GardenResponse::Welcome {
                    genesis: shown,
                    key: peer_key,
                    invite_signature,
                    ..
                }) => {
                    if let Err(reason) = invite.accepts(&shown) {
                        passed.insert(peer, reason);
                        continue;
                    }
                    if u64::from(shown.limits.max_object_bytes)
                        > super::storage::MAX_LOCAL_GARDEN_BYTES
                    {
                        passed.insert(
                            peer,
                            "garden object size limit exceeds local storage ceiling".into(),
                        );
                        continue;
                    }
                    if peer_id_of(&peer_key)? != peer
                        || verify_signature(
                            &join_message(invite.chain_id, &peer_key),
                            &invite_signature,
                            &invite_key.public_key_bytes(),
                        )
                        .is_err()
                    {
                        passed.insert(peer, "it does not hold the invite".into());
                        continue;
                    }
                    peers.insert(peer, peer_key);
                    let _ = garden_net.commands.send(NetCommand::Admit(peer)).await;
                    genesis.get_or_insert(*shown);
                }
                Ok(GardenResponse::Refused(reason)) => {
                    passed.insert(peer, reason);
                }
                _ => {}
            },
            NetEvent::Response {
                peer,
                tag: TAG_SYNC,
                response,
                ..
            } if Some(peer) == source => {
                let Some(chain) = ledger.as_mut() else {
                    continue;
                };
                let taken = match response {
                    Ok(GardenResponse::Commits(commits)) => {
                        let done = commits.is_empty();
                        commits
                            .into_iter()
                            .try_for_each(|commit| chain.append(commit))
                            .map(|()| done)
                    }
                    Ok(GardenResponse::Refused(reason))
                        if chain.state.genesis.limits.admission
                            == GardenAdmission::HostApproval
                            && reason.contains("not admitted") =>
                    {
                        // In HostApproval mode an unseated joiner is refused
                        // block history until the host seats its key, so start
                        // cleanly from genesis with zero posts exposed.
                        Ok(true)
                    }
                    _ => Err("it did not serve the chain".into()),
                };
                match taken {
                    Ok(true) => {
                        return ledger.ok_or_else(|| "the Garden chain could not be fetched".into())
                    }
                    Ok(false) => {
                        let from = chain.state.height.saturating_add(1);
                        ask_commits(garden_net, peer, from).await;
                    }
                    Err(reason) => {
                        // What it served is thrown away with it.
                        passed.insert(peer, reason);
                        ledger = None;
                        source = None;
                    }
                }
            }
            NetEvent::Response { .. } => {}
        }
    }
}

async fn ask_commits(garden_net: &GardenNet, peer: PeerId, from_height: u64) {
    let _ = garden_net
        .commands
        .send(NetCommand::Send {
            peer,
            request: GardenRequest::GetCommits {
                from_height,
                max: MAX_SYNC_COMMITS,
            },
            tag: TAG_SYNC,
        })
        .await;
}

/// The refusal of a join that every peer of the invite turned down.
fn nobody_admitted(passed: &BTreeMap<PeerId, String>) -> String {
    let reasons: BTreeSet<&str> = passed.values().map(String::as_str).collect();
    let reasons: Vec<&str> = reasons.into_iter().collect();
    format!(
        "no validator in the invite admitted this node: {}",
        reasons.join("; ")
    )
}

impl Node {
    async fn run(
        mut self,
        mut events: mpsc::Receiver<NetEvent>,
        mut commands: mpsc::Receiver<GardenCommand>,
        mut deposits: mpsc::Receiver<DepositDone>,
    ) {
        let limits = self.ledger.state.genesis.limits.clone();
        let step = (limits.presence_interval_ms.min(limits.round_ms) / 4).clamp(10, 250);
        let mut ticker = tokio::time::interval(millis(step));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.dial_known().await;
        while !self.stopped {
            tokio::select! {
                done = deposits.recv() => {
                    if let Some(done) = done {
                        self.on_deposit_done(done).await;
                    }
                },
                event = events.recv() => match event {
                    Some(event) => self.on_net(event).await,
                    None => break,
                },
                command = commands.recv() => if let Some(command) = command {
                    self.on_command(command).await;
                } else {
                    self.shutdown().await;
                    break;
                },
                _ = ticker.tick() => self.on_tick().await,
            }
        }
    }

    async fn on_deposit_done(&mut self, done: DepositDone) {
        self.total_deposits_in_flight = self.total_deposits_in_flight.saturating_sub(1);
        if let Some(count) = self.deposits_in_flight.get_mut(&done.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.deposits_in_flight.remove(&done.peer);
            }
        }
        let response = match done.outcome {
            Ok(wrote_new) => {
                if !wrote_new {
                    self.store.release_background_charge(done.charged_len);
                }
                self.finish_deposit(done.sender, done.content_id, done.already_published_for_me)
            }
            Err(err) => {
                self.store.release_background_charge(done.charged_len);
                GardenResponse::Refused(err)
            }
        };
        self.respond(done.channel, response).await;
    }

    fn record_rejected_address(&mut self, addr_key: (GardenKey, String)) {
        if self.rejected_addresses.contains(&addr_key) {
            return;
        }
        while self.rejected_addresses.len() >= MAX_REJECTED_ADDRESSES {
            let Some(oldest) = self.rejected_address_order.pop_front() else {
                break;
            };
            self.rejected_addresses.remove(&oldest);
        }
        self.rejected_addresses.insert(addr_key.clone());
        self.rejected_address_order.push_back(addr_key);
    }

    fn peer_source(&self, peer: &PeerId) -> Option<net::SourceKey> {
        self.peer_sources
            .lock()
            .ok()
            .and_then(|map| map.get(peer).copied())
    }

    fn source_unjoined_blocked(&mut self, peer: PeerId, grace: Duration) -> bool {
        let Some(src) = self.peer_source(&peer) else {
            return false;
        };
        if src.is_loopback() {
            return false;
        }
        let held_by_source = self
            .peers
            .iter()
            .filter(|(p, k)| {
                **p != peer && !self.is_seated_validator(k) && self.peer_source(p) == Some(src)
            })
            .count();
        if held_by_source >= MAX_UNJOINED_PEERS_PER_SOURCE {
            return true;
        }
        let window = grace.saturating_mul(2);
        let now = Instant::now();
        while self.unjoined_source_budget.len() >= 1024
            && !self.unjoined_source_budget.contains_key(&src)
        {
            self.unjoined_source_budget
                .retain(|_, (start, _)| now.duration_since(*start) < window);
            if self.unjoined_source_budget.len() >= 1024 {
                if let Some(first) = self.unjoined_source_budget.keys().next().copied() {
                    self.unjoined_source_budget.remove(&first);
                }
            }
        }
        let entry = self.unjoined_source_budget.entry(src).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 >= MAX_UNJOINED_PEERS_PER_SOURCE.saturating_mul(2)
    }

    fn note_source_unjoined_admitted(&mut self, peer: PeerId, grace: Duration) {
        let Some(src) = self.peer_source(&peer) else {
            return;
        };
        if src.is_loopback() {
            return;
        }
        let window = grace.saturating_mul(2);
        let now = Instant::now();
        let entry = self.unjoined_source_budget.entry(src).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
    }

    const fn limits(&self) -> &GardenLimits {
        &self.ledger.state.genesis.limits
    }

    const fn chain_id(&self) -> u64 {
        self.ledger.state.chain_id()
    }

    fn is_host(&self) -> bool {
        self.me == self.ledger.state.host()
    }

    /// True while the host's presence signal is fresh.
    fn host_present(&self) -> bool {
        if self.is_host() {
            return true;
        }
        let timeout = millis(self.limits().host_timeout_ms);
        self.last_seen.get(&self.ledger.state.host()).map_or_else(
            || self.started.elapsed() < timeout,
            |seen| seen.elapsed() < timeout,
        )
    }

    /// The Garden status this node observes: the chain's own status, and
    /// Frozen while the host is silent.
    fn observed_status(&self) -> DomainStatus {
        match self.ledger.state.status {
            DomainStatus::Active if !self.host_present() => DomainStatus::Frozen,
            status => status,
        }
    }

    fn silent_for(&self, key: &GardenKey, limit: Duration) -> bool {
        if *key == self.me {
            return false;
        }
        self.last_seen.get(key).map_or_else(
            || self.started.elapsed() >= limit,
            |seen| seen.elapsed() >= limit,
        )
    }

    async fn send(&self, peer: PeerId, request: GardenRequest, tag: u64) {
        let _ = self.net.send(NetCommand::Send { peer, request, tag }).await;
    }

    async fn respond(&self, channel: ResponseChannel<BudgetedFrame>, response: GardenResponse) {
        let _ = self
            .net
            .send(NetCommand::Respond { channel, response })
            .await;
    }

    /// Queue `item` for every peer but `except`. Each peer gets one gossip
    /// request at a time; what arrives meanwhile leaves in the next batch.
    async fn gossip(&mut self, item: &GardenGossip, except: Option<PeerId>) {
        if gossip_bytes(item) > MAX_OUTBOX_BYTES {
            return;
        }
        let withhold_unseated = self.limits().admission == GardenAdmission::HostApproval
            && match item {
                GardenGossip::Proposal(_) | GardenGossip::Commit(_) => true,
                GardenGossip::Tx(tx) => {
                    // An unseated joiner still delivers its own Join request to
                    // connected peers; every other tx (including Publish captions)
                    // goes only to seated validators.
                    !(matches!(tx.tx.kind, GardenTxKind::Join { .. })
                        && tx.tx.sender == self.me
                        && !self.is_key_seated(&self.me))
                }
                GardenGossip::Vote(_) | GardenGossip::Presence(_) => false,
            };
        let targets: Vec<PeerId> = self
            .peers
            .keys()
            .filter(|peer| Some(**peer) != except && (!withhold_unseated || self.is_seated(peer)))
            .copied()
            .collect();
        for peer in targets {
            let queue = self.outbox.entry(peer).or_default();
            queue_gossip_item(queue, item.clone(), MAX_OUTBOX, MAX_OUTBOX_BYTES);
            self.flush(peer).await;
        }
    }

    async fn flush(&mut self, peer: PeerId) {
        if self.gossip_in_flight.contains_key(&peer) {
            return;
        }
        let Some(queue) = self.outbox.get_mut(&peer) else {
            return;
        };
        let batch = drain_gossip_batch(queue, MAX_GOSSIP_BATCH, MAX_GOSSIP_BATCH_BYTES);
        if batch.is_empty() {
            return;
        }
        let carried = batch.iter().filter_map(final_height).max().unwrap_or(0);
        self.gossip_in_flight.insert(peer, carried);
        self.send(peer, GardenRequest::Gossip(batch), TAG_GOSSIP)
            .await;
    }

    /// Remember a gossip id. False when it was seen before.
    fn first_sight(&mut self, id: Seen) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.seen_order.push_back(id);
        if self.seen_order.len() > MAX_SEEN {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    /// Dial the validators this node is not connected to. An address that
    /// does not answer is dialed again after a wait that doubles each time:
    /// the address is chosen by whoever joined, and every dial is a socket.
    async fn dial_known(&mut self) {
        let now = Instant::now();
        self.last_dial = now;
        let first_wait = millis(self.limits().round_ms)
            .max(Duration::from_secs(1))
            .saturating_mul(2);
        let connected: BTreeSet<GardenKey> = self.peers.values().copied().collect();
        let mut targets = Vec::new();
        for validator in self.ledger.state.validators.values() {
            // A key that waits wrote its address without anybody's consent,
            // so nobody dials it: it dials the others.
            if validator.key == self.me
                || validator.status == GardenValidatorStatus::Left
                || validator.status == GardenValidatorStatus::Waiting
                || connected.contains(&validator.key)
            {
                continue;
            }
            let addr_key = (validator.key, validator.address.clone());
            if self.rejected_addresses.contains(&addr_key) {
                continue;
            }
            let waiting = self
                .dials
                .get(&addr_key)
                .is_some_and(|(next, _)| now < *next);
            if waiting || targets.len() >= MAX_DIALS_PER_ROUND {
                continue;
            }
            if let Ok(address) = validator_dial_address(&validator.address, &validator.key) {
                let wait = self
                    .dials
                    .get(&addr_key)
                    .map_or(first_wait, |(_, wait)| wait.saturating_mul(2))
                    .min(MAX_DIAL_WAIT);
                if self.dials.len() >= MAX_DIAL_RECORDS && !self.dials.contains_key(&addr_key) {
                    if let Some(oldest) = self
                        .dials
                        .iter()
                        .min_by_key(|(_, (next, _))| *next)
                        .map(|(k, _)| k.clone())
                    {
                        self.dials.remove(&oldest);
                    }
                }
                self.dials.insert(addr_key, (now + wait, wait));
                targets.push(address);
            }
        }
        if self.peers.is_empty() {
            if self.seed_dials.is_none_or(|(next, _)| now >= next) {
                let wait = self
                    .seed_dials
                    .map_or(first_wait, |(_, wait)| wait.saturating_mul(2))
                    .min(MAX_DIAL_WAIT);
                self.seed_dials = Some((now + wait, wait));
                targets.extend(
                    self.seeds
                        .iter()
                        .filter_map(|seed| net::dial_address(seed).ok())
                        .map(|(address, _)| address),
                );
            }
        } else {
            self.seed_dials = None;
        }
        for address in targets {
            let _ = self.net.send(NetCommand::Dial(address)).await;
        }
    }

    async fn on_net(&mut self, event: NetEvent) {
        match event {
            NetEvent::Connected(peer) => {
                if !self.peers.contains_key(&peer) {
                    self.unadmitted.entry(peer).or_insert_with(Instant::now);
                }
                // Strangers hold a part of the connection table and no more.
                // The one that kept silent longest goes when another comes,
                // so a crowd that shows no invite turns over among itself
                // and the seats of the validators stay free.
                while self.unadmitted.len() > MAX_UNADMITTED {
                    let oldest = self
                        .unadmitted
                        .iter()
                        .min_by_key(|(_, since)| **since)
                        .map(|(stranger, _)| *stranger);
                    let Some(stranger) = oldest else {
                        break;
                    };
                    self.unadmitted.remove(&stranger);
                    let _ = self.net.send(NetCommand::Disconnect(stranger)).await;
                }
                let hello = GardenRequest::Hello {
                    chain_id: self.chain_id(),
                    key: self.me,
                    invite_signature: self.invite_signature.clone(),
                };
                self.send(peer, hello, TAG_HELLO).await;
            }
            NetEvent::Disconnected(peer) => {
                if let Some(key) = self.peers.remove(&peer) {
                    if !self.ledger.state.validators.contains_key(&key)
                        && !self.peers.values().any(|other| *other == key)
                    {
                        self.verified_peers.remove(&key);
                    }
                }
                self.unadmitted.remove(&peer);
                self.peer_admitted_at.remove(&peer);
                self.disconnect_after.remove(&peer);
                self.outbox.remove(&peer);
                self.gossip_in_flight.remove(&peer);
                self.gossip_budget.remove(&peer);
                self.sync_budget.remove(&peer);
                if self.sync_in_flight.is_some_and(|(p, _, _)| p == peer) {
                    self.sync_in_flight = None;
                }
                self.object_budget.remove(&peer);
                self.put_object_budget.remove(&peer);
                self.finish_when_delivered().await;
            }
            NetEvent::DialFailed {
                peer,
                wrong_peer_id,
            } => {
                let matched = self
                    .ledger
                    .state
                    .validators
                    .values()
                    .find(|v| peer_id_of(&v.key).is_ok_and(|id| id == peer))
                    .map(|v| (v.key, v.address.clone()));
                if let Some(addr_key) = matched {
                    if !addr_key.1.is_empty() {
                        if wrong_peer_id {
                            self.record_rejected_address(addr_key);
                        } else {
                            if self.dial_failures.len() >= MAX_DIAL_RECORDS
                                && !self.dial_failures.contains_key(&addr_key)
                            {
                                if let Some(first) = self.dial_failures.keys().next().cloned() {
                                    self.dial_failures.remove(&first);
                                }
                            }
                            let count = self.dial_failures.entry(addr_key.clone()).or_insert(0);
                            *count = count.saturating_add(1);
                            if *count >= MAX_DIAL_FAILURES {
                                self.record_rejected_address(addr_key);
                            }
                        }
                    }
                }
            }
            NetEvent::Request {
                peer,
                request,
                channel,
                budget,
            } => self.on_request(peer, request, channel, budget).await,
            NetEvent::Response {
                peer,
                tag,
                response,
                budget,
            } => {
                self.on_response(peer, tag, response).await;
                drop(budget);
            }
        }
    }

    /// True when the content of the Garden is for `peer`.
    ///
    /// Under direct admission the invite is the whole credential. Under host
    /// approval the invite only lets a key ask: the bytes are for the keys
    /// the host seated, so one that waits, or was turned away, reads and
    /// deposits none. It still follows the blocks, which is how it learns
    /// the answer.
    fn is_key_seated(&self, key: &GardenKey) -> bool {
        match self.limits().admission {
            GardenAdmission::Direct => true,
            GardenAdmission::HostApproval => self
                .ledger
                .state
                .validators
                .get(key)
                .is_some_and(|v| v.status != GardenValidatorStatus::Waiting),
        }
    }

    fn is_seated(&self, peer: &PeerId) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|key| self.is_key_seated(key))
    }

    fn unjoined_grace(&self) -> Duration {
        millis(self.limits().round_ms)
            .saturating_mul(40)
            .clamp(Duration::from_secs(2), Duration::from_secs(15))
    }

    fn record_turned_away(&mut self, key: GardenKey) {
        if self.turned_away_keys.insert(key) {
            self.turned_away_order.push_back(key);
            if self.turned_away_order.len() > MAX_TURNED_AWAY_KEYS {
                if let Some(old) = self.turned_away_order.pop_front() {
                    self.turned_away_keys.remove(&old);
                }
            }
        }
    }

    async fn drop_peer_state(&mut self, victim: PeerId) {
        if let Some(key) = self.peers.remove(&victim) {
            if !self.ledger.state.validators.contains_key(&key)
                && !self.peers.values().any(|other| *other == key)
            {
                self.verified_peers.remove(&key);
            }
        }
        self.peer_admitted_at.remove(&victim);
        self.disconnect_after.remove(&victim);
        self.outbox.remove(&victim);
        self.gossip_in_flight.remove(&victim);
        self.gossip_budget.remove(&victim);
        self.sync_budget.remove(&victim);
        self.object_budget.remove(&victim);
        self.put_object_budget.remove(&victim);
        let _ = self.net.send(NetCommand::Disconnect(victim)).await;
    }

    fn record_verified_peer(&mut self, key: GardenKey) {
        if self.verified_peers.contains(&key) {
            return;
        }
        let cap = usize::try_from(self.ledger.state.genesis.limits.max_validators)
            .unwrap_or(usize::MAX)
            .saturating_mul(2)
            .max(16);
        if self.verified_peers.len() >= cap {
            let evict = self
                .verified_peers
                .iter()
                .find(|k| !self.ledger.state.validators.contains_key(*k))
                .copied();
            let Some(victim) = evict else {
                if !self.ledger.state.validators.contains_key(&key) {
                    return;
                }
                self.verified_peers.insert(key);
                return;
            };
            self.verified_peers.remove(&victim);
        }
        self.verified_peers.insert(key);
    }

    /// True when `key` is the peer's own key and the invite key signed it.
    fn holds_invite(&self, peer: PeerId, key: &GardenKey, signature: &[u8]) -> bool {
        peer_id_of(key).is_ok_and(|id| id == peer)
            && verify_signature(
                &join_message(self.chain_id(), key),
                signature,
                &self.ledger.state.genesis.invite_key,
            )
            .is_ok()
    }

    /// True only for keys the host has actually seated (active or offline
    /// validators). Keys in `GardenValidatorStatus::Waiting` are guests at the
    /// connection door and must share `MAX_UNJOINED_PEERS` and `unjoined_grace`
    /// rather than consuming the inbound connection budget reserved for seated
    /// validators.
    fn is_seated_validator(&self, key: &GardenKey) -> bool {
        self.ledger
            .state
            .validators
            .get(key)
            .is_some_and(|v| v.status != GardenValidatorStatus::Waiting)
    }

    async fn on_request(
        &mut self,
        peer: PeerId,
        request: GardenRequest,
        channel: ResponseChannel<BudgetedFrame>,
        frame_budget: FramePermits,
    ) {
        if let GardenRequest::Hello {
            chain_id,
            key,
            invite_signature,
        } = &request
        {
            let peer_cap = (self.limits().max_validators as usize)
                .saturating_mul(2)
                .saturating_add(8);
            let known_validator = self.is_seated_validator(key);
            let unjoined_count = self
                .peers
                .values()
                .filter(|k| !self.is_seated_validator(k))
                .count();
            let unjoined_grace = self.unjoined_grace();
            let already = self.peers.contains_key(&peer);
            let mut admit = false;
            let response = if *chain_id != self.chain_id() {
                GardenResponse::Refused("this node runs another Garden".into())
            } else if !self.holds_invite(peer, key, invite_signature) {
                GardenResponse::Refused("the invite does not match this Garden".into())
            } else if !known_validator && self.turned_away_keys.contains(key) {
                self.disconnect_after
                    .insert(peer, Instant::now() + Duration::from_millis(250));
                GardenResponse::Refused("the host turned this key away".into())
            } else if !already
                && !known_validator
                && self.source_unjoined_blocked(peer, unjoined_grace)
            {
                GardenResponse::Refused(
                    "this source already holds its share of unjoined slots".into(),
                )
            } else if !already && !known_validator && unjoined_count >= MAX_UNJOINED_PEERS {
                // Reclaim an expired or turned-away unjoined slot so idle or
                // rejected invite holders can never wedge the join door.
                let stale_victim = self
                    .peers
                    .iter()
                    .filter(|(_, k)| !self.is_seated_validator(k))
                    .filter(|(p, k)| {
                        self.turned_away_keys.contains(*k)
                            || self
                                .peer_admitted_at
                                .get(p)
                                .is_some_and(|at| at.elapsed() >= unjoined_grace)
                    })
                    .min_by_key(|(p, k)| {
                        (
                            !self.turned_away_keys.contains(*k),
                            self.peer_admitted_at.get(p).copied(),
                        )
                    })
                    .map(|(p, _)| *p);
                if let Some(victim) = stale_victim {
                    self.drop_peer_state(victim).await;
                    admit = true;
                    GardenResponse::Welcome {
                        genesis: Box::new(self.ledger.state.genesis.clone()),
                        height: self.ledger.state.height,
                        key: self.me,
                        invite_signature: self.invite_signature.clone(),
                    }
                } else {
                    GardenResponse::Refused(
                        "this validator has no room for more unjoined peers".into(),
                    )
                }
            } else if !already && self.peers.len() >= peer_cap {
                if known_validator {
                    let victim = self
                        .peers
                        .iter()
                        .find(|(_, k)| !self.ledger.state.validators.contains_key(*k))
                        .map(|(p, _)| *p);
                    if let Some(victim) = victim {
                        self.drop_peer_state(victim).await;
                        admit = true;
                        GardenResponse::Welcome {
                            genesis: Box::new(self.ledger.state.genesis.clone()),
                            height: self.ledger.state.height,
                            key: self.me,
                            invite_signature: self.invite_signature.clone(),
                        }
                    } else {
                        GardenResponse::Refused("this validator has no room for more peers".into())
                    }
                } else {
                    GardenResponse::Refused("this validator has no room for more peers".into())
                }
            } else {
                admit = true;
                GardenResponse::Welcome {
                    genesis: Box::new(self.ledger.state.genesis.clone()),
                    height: self.ledger.state.height,
                    key: self.me,
                    invite_signature: self.invite_signature.clone(),
                }
            };
            if admit {
                if !already && !known_validator {
                    self.note_source_unjoined_admitted(peer, unjoined_grace);
                }
                self.peers.insert(peer, *key);
                self.peer_admitted_at
                    .entry(peer)
                    .or_insert_with(Instant::now);
                self.unadmitted.remove(&peer);
                self.record_verified_peer(*key);
                self.dial_failures.retain(|(k, _), _| k != key);
                self.dials.retain(|(k, _), _| k != key);
                let _ = self.net.send(NetCommand::Admit(peer)).await;
            }
            self.respond(channel, response).await;
            return;
        }
        if !self.peers.contains_key(&peer) {
            self.unadmitted.entry(peer).or_insert_with(Instant::now);
            self.respond(
                channel,
                GardenResponse::Refused("show the invite first".into()),
            )
            .await;
            return;
        }
        match request {
            GardenRequest::Hello { .. } => {}
            GardenRequest::Gossip(items) => {
                if items.len() > MAX_GOSSIP_BATCH {
                    self.respond(
                        channel,
                        GardenResponse::Refused("gossip batch is too large".into()),
                    )
                    .await;
                    return;
                }
                let now = Instant::now();
                let entry = self.gossip_budget.entry(peer).or_insert((now, 0));
                if now.duration_since(entry.0) >= Duration::from_secs(1) {
                    *entry = (now, 0);
                }
                // Charge at least one unit even for an empty frame so a peer
                // cannot flood zero-item Gossip requests without hitting its quota.
                let charge = items.len().max(1);
                if entry.1.saturating_add(charge) > MAX_GOSSIP_ITEMS_PER_PEER_PER_SEC {
                    self.respond(
                        channel,
                        GardenResponse::Refused("gossip rate limit exceeded".into()),
                    )
                    .await;
                    return;
                }
                entry.1 = entry.1.saturating_add(charge);
                // Apply the batch before acknowledging it so a departing
                // validator that waits for `Ack` knows a peer actually applied
                // and retained its block before reporting to Budlum.
                for item in items {
                    self.on_gossip(item, Some(peer)).await;
                }
                self.respond(channel, GardenResponse::Ack).await;
            }
            GardenRequest::GetCommits { from_height, max } => {
                if !self.is_seated(&peer) {
                    self.respond(
                        channel,
                        GardenResponse::Refused("the host has not admitted this key".into()),
                    )
                    .await;
                    return;
                }
                let now = Instant::now();
                let entry = self.sync_budget.entry(peer).or_insert((now, 0));
                if now.duration_since(entry.0) >= Duration::from_secs(1) {
                    *entry = (now, 0);
                }
                if entry.1 >= MAX_SYNC_REQS_PER_PEER_PER_SEC {
                    self.respond(
                        channel,
                        GardenResponse::Refused("sync rate limit exceeded".into()),
                    )
                    .await;
                    return;
                }
                entry.1 = entry.1.saturating_add(1);
                let commits =
                    take_sync_commits(&self.ledger, from_height, max, MAX_SYNC_RESPONSE_BYTES);
                self.respond(channel, GardenResponse::Commits(commits))
                    .await;
            }
            GardenRequest::AdmissionStatus => {
                let verdict = match self.peers.get(&peer).copied() {
                    Some(key) if self.is_key_seated(&key) => GardenAdmissionState::Seated,
                    Some(key)
                        if self
                            .ledger
                            .state
                            .validators
                            .get(&key)
                            .is_some_and(|v| v.status == GardenValidatorStatus::Waiting) =>
                    {
                        GardenAdmissionState::Waiting
                    }
                    Some(key) if self.turned_away_keys.contains(&key) => {
                        self.disconnect_after
                            .entry(peer)
                            .or_insert_with(|| Instant::now() + Duration::from_millis(250));
                        GardenAdmissionState::TurnedAway
                    }
                    _ => GardenAdmissionState::Pending,
                };
                self.respond(channel, GardenResponse::AdmissionStatus(verdict))
                    .await;
            }
            GardenRequest::GetObject { .. } | GardenRequest::PutObject { .. }
                if !self.is_seated(&peer) =>
            {
                self.respond(
                    channel,
                    GardenResponse::Refused("the host has not admitted this key".into()),
                )
                .await;
            }
            GardenRequest::GetObject { content_id, relay } => {
                let now = Instant::now();
                let max_bytes = u64::from(self.limits().max_object_bytes)
                    .saturating_mul(4)
                    .max(4 * 1024 * 1024);
                let budget = self.object_budget.entry(peer).or_insert((now, 0, 0));
                if now.duration_since(budget.0) >= OBJECT_RATE_WINDOW {
                    *budget = (now, 0, 0);
                }
                if budget.1 >= MAX_OBJECT_REQS_PER_WINDOW || budget.2 >= max_bytes {
                    self.respond(
                        channel,
                        GardenResponse::Refused("object request rate limit exceeded".into()),
                    )
                    .await;
                    return;
                }
                budget.1 = budget.1.saturating_add(1);
                if let Some(bytes) = self.store.get(&content_id) {
                    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                    if let Some(entry) = self.object_budget.get_mut(&peer) {
                        entry.2 = entry.2.saturating_add(len);
                    }
                    self.respond(channel, GardenResponse::Object(Some(bytes)))
                        .await;
                    return;
                }
                let others: Vec<PeerId> = self
                    .fetch_targets(&content_id)
                    .into_iter()
                    .filter(|other| *other != peer)
                    .collect();
                if !relay || others.is_empty() || self.relays.len() >= MAX_PROPOSALS {
                    self.respond(channel, GardenResponse::Object(None)).await;
                    return;
                }
                let job = self.fresh_tag();
                self.relays.insert(
                    job,
                    Relay {
                        requester: peer,
                        channel: Some(channel),
                        outstanding: others.len(),
                        content_id,
                    },
                );
                for other in others {
                    let tag = self.fresh_tag();
                    self.relay_tags.insert(tag, job);
                    self.send(
                        other,
                        GardenRequest::GetObject {
                            content_id,
                            relay: false,
                        },
                        tag,
                    )
                    .await;
                }
            }
            GardenRequest::PutObject { bytes } => {
                let Some(sender) = self.peers.get(&peer).copied() else {
                    self.respond(
                        channel,
                        GardenResponse::Refused("show the invite first".into()),
                    )
                    .await;
                    return;
                };
                let now = Instant::now();
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                let max_bytes = u64::from(self.limits().max_object_bytes)
                    .saturating_mul(2)
                    .max(4 * 1024 * 1024);
                let budget = self.put_object_budget.entry(peer).or_insert((now, 0, 0));
                if now.duration_since(budget.0) >= Duration::from_secs(1) {
                    *budget = (now, 0, 0);
                }
                if budget.1 >= MAX_PUT_OBJECT_REQS_PER_PEER_PER_SEC
                    || budget.2.saturating_add(len) > max_bytes
                {
                    self.respond(
                        channel,
                        GardenResponse::Refused("deposit rate limit exceeded".into()),
                    )
                    .await;
                    return;
                }
                let peer_in_flight = self.deposits_in_flight.get(&peer).copied().unwrap_or(0);
                if self.total_deposits_in_flight >= MAX_IN_FLIGHT_DEPOSITS
                    || peer_in_flight >= MAX_IN_FLIGHT_DEPOSITS_PER_PEER
                {
                    self.respond(
                        channel,
                        GardenResponse::Refused("deposit write queue is busy".into()),
                    )
                    .await;
                    return;
                }
                budget.1 = budget.1.saturating_add(1);
                budget.2 = budget.2.saturating_add(len);
                if bytes.is_empty() || bytes.len() > self.limits().max_object_bytes as usize {
                    self.respond(
                        channel,
                        GardenResponse::Refused(format!(
                            "object size {} is outside 1..={} bytes",
                            bytes.len(),
                            self.limits().max_object_bytes
                        )),
                    )
                    .await;
                    return;
                }
                let content_id = crate::storage::content_id::ContentId::of(&bytes).0;
                // Refuse unsolicited copies of already-finalized publications
                // on validators outside that object's placement holder set, so
                // a peer cannot stuff past objects onto non-holders outside the
                // unreferenced deposit quotas.
                let published = self.ledger.state.accounts_for(&content_id, len);
                let is_holder = published && self.holders(&content_id).contains(&self.me);
                if published && !is_holder {
                    self.respond(
                        channel,
                        GardenResponse::Refused(
                            "this validator is not a holder of that publication".into(),
                        ),
                    )
                    .await;
                    return;
                }
                match self.store.reserve_background_write(content_id, &bytes) {
                    Ok(Some((path, charged_len))) => {
                        self.total_deposits_in_flight =
                            self.total_deposits_in_flight.saturating_add(1);
                        *self.deposits_in_flight.entry(peer).or_insert(0) += 1;
                        let tx = self.deposit_tx.clone();
                        tokio::spawn(async move {
                            let outcome = tokio::task::spawn_blocking(move || {
                                let res =
                                    GardenContentStore::write_object_file_blocking(path, bytes);
                                drop(frame_budget);
                                res
                            })
                            .await
                            .unwrap_or_else(|e| Err(format!("garden object write panicked: {e}")));
                            let _ = tx
                                .send(DepositDone {
                                    peer,
                                    sender,
                                    content_id,
                                    charged_len,
                                    already_published_for_me: is_holder,
                                    outcome,
                                    channel,
                                })
                                .await;
                        });
                    }
                    Ok(None) => {
                        let response = self.finish_deposit(sender, content_id, is_holder);
                        self.respond(channel, response).await;
                    }
                    Err(err) => {
                        self.respond(channel, GardenResponse::Refused(err)).await;
                    }
                }
            }
        }
    }

    fn fresh_tag(&mut self) -> u64 {
        self.next_tag = self.next_tag.wrapping_add(1).max(TAG_FIRST_FETCH);
        self.next_tag
    }

    /// True when an executable (contiguous-nonce, active-validator) pending
    /// publication in the mempool names `content_id`. Inapplicable gap-nonce
    /// transactions cannot pin deposits indefinitely.
    fn is_pending_content(&self, content_id: &Hash32) -> bool {
        self.mempool.values().any(|tx| {
            if !matches!(
                &tx.tx.kind,
                GardenTxKind::Publish { content_id: id, .. } if id == content_id
            ) {
                return false;
            }
            if !self.ledger.state.is_active(&tx.tx.sender) {
                return false;
            }
            let expected = self.ledger.state.next_nonce(&tx.tx.sender);
            if tx.tx.nonce < expected {
                return false;
            }
            // Every nonce in `expected..tx.tx.nonce` must also be present in
            // the mempool so this publication is actually reachable without a gap.
            (expected..tx.tx.nonce).all(|n| self.mempool.contains_key(&(tx.tx.sender, n)))
        })
    }

    /// True when this node holds `content_id` for a finalized publication:
    /// the bytes it holds have the size a publication declares. Bytes of
    /// another size were never charged to anybody, whatever names them.
    fn holds_published(&self, content_id: &Hash32) -> bool {
        self.store
            .stored_len(content_id)
            .is_some_and(|len| self.ledger.state.accounts_for(content_id, len))
    }

    /// True when this validator must keep an already-published `content_id`:
    /// it stands in the object's placement holder set, authored it, or carries
    /// an uncommitted local `Publish` naming it.
    fn should_retain_published(&self, sender: GardenKey, content_id: &Hash32) -> bool {
        sender == self.me
            || self.holders(content_id).contains(&self.me)
            || self
                .ledger
                .state
                .objects
                .values()
                .any(|obj| obj.content_id == *content_id && obj.author == self.me)
            || self.has_pending(|pending| {
                matches!(pending, GardenTxKind::Publish { content_id: cid, .. } if cid == content_id)
            })
    }

    /// Reconcile a freshly materialized `PutObject` against the live finalized
    /// state so a publication committed while the background disk write was in
    /// flight can never strand bytes on a non-holder validator.
    fn finish_deposit(
        &mut self,
        sender: GardenKey,
        content_id: Hash32,
        was_holder_at_admission: bool,
    ) -> GardenResponse {
        if self.holds_published(&content_id) {
            if self.should_retain_published(sender, &content_id) {
                self.wanted.remove(&content_id);
                GardenResponse::Ack
            } else {
                self.store.remove(&content_id);
                GardenResponse::Refused("this validator is not a holder of that publication".into())
            }
        } else if was_holder_at_admission && self.holders(&content_id).contains(&self.me) {
            self.wanted.remove(&content_id);
            GardenResponse::Ack
        } else if self.note_unreferenced(sender, content_id) {
            GardenResponse::Ack
        } else {
            GardenResponse::Refused("deposit queue is full".into())
        }
    }

    /// Track an object no finalized publication accounts for yet, under the
    /// peer that deposited it. Returns `false` when the object belongs to a
    /// finalized publication this validator does not hold, or when the deposit
    /// queue is saturated by executable pending publications and the new
    /// deposit had to be dropped instead of retained.
    fn note_unreferenced(&mut self, sender: GardenKey, content_id: Hash32) -> bool {
        if self.holds_published(&content_id) {
            if self.should_retain_published(sender, &content_id) {
                self.wanted.remove(&content_id);
                return true;
            }
            self.store.remove(&content_id);
            return false;
        }
        let queue = self.unreferenced.entry(sender).or_default();
        if queue.contains(&content_id) {
            return true;
        }
        queue.push_back(content_id);
        let mut dropped = Vec::new();
        let mut kept = true;
        if queue.len() > MAX_UNREFERENCED_PER_PEER {
            let evicted = self.evict_deposit(sender, sender, content_id);
            if evicted == content_id {
                kept = false;
            }
            dropped.push(evicted);
        }
        let total: usize = self.unreferenced.values().map(VecDeque::len).sum();
        if total > MAX_UNREFERENCED_OBJECTS {
            let state = &self.ledger.state;
            let heaviest = self
                .unreferenced
                .iter()
                .filter(|(_, queue)| queue.iter().any(|id| !self.is_pending_content(id)))
                .max_by_key(|(key, queue)| (!state.is_active(key), queue.len()))
                .or_else(|| {
                    self.unreferenced
                        .iter()
                        .max_by_key(|(key, queue)| (!state.is_active(key), queue.len()))
                })
                .map(|(key, _)| *key);
            if let Some(owner) = heaviest {
                let evicted = self.evict_deposit(owner, sender, content_id);
                if evicted == content_id {
                    kept = false;
                }
                dropped.push(evicted);
            }
        }
        self.unreferenced.retain(|_, queue| !queue.is_empty());
        for old in dropped {
            // What this node itself is publishing was put here by its own
            // operator, not by the deposit that named the same bytes.
            let own = self.has_pending(
                |pending| matches!(pending, GardenTxKind::Publish { content_id, .. } if *content_id == old),
            );
            let named = own
                || self.holds_published(&old)
                || self.unreferenced.values().any(|queue| queue.contains(&old));
            if !named {
                self.store.remove(&old);
            }
        }
        kept
    }

    /// Take one deposit out of the queue of `owner` and return it.
    ///
    /// The queues are the only record of bytes no publication accounts for,
    /// so nothing leaves a queue and stays on the disk. The oldest deposit
    /// no pending publication names goes. When a pending publication names
    /// every one of them, the deposit that just `arrived` from `sender` goes
    /// instead: the ones that stay are still counted, and the count is what
    /// bounds them.
    fn evict_deposit(&mut self, owner: GardenKey, sender: GardenKey, arrived: Hash32) -> Hash32 {
        let free = self.unreferenced.get(&owner).and_then(|queue| {
            queue
                .iter()
                .position(|id| *id != arrived && !self.is_pending_content(id))
        });
        if let (Some(index), Some(queue)) = (free, self.unreferenced.get_mut(&owner)) {
            return queue.remove(index).unwrap_or(arrived);
        }
        if let Some(queue) = self.unreferenced.get_mut(&sender) {
            queue.retain(|id| *id != arrived);
        }
        arrived
    }

    async fn on_response(
        &mut self,
        peer: PeerId,
        tag: u64,
        response: Result<GardenResponse, String>,
    ) {
        match tag {
            TAG_IGNORE => {}
            TAG_GOSSIP => {
                let carried = self.gossip_in_flight.remove(&peer).unwrap_or(0);
                let active_peer = self
                    .peers
                    .get(&peer)
                    .is_some_and(|key| self.ledger.state.is_active(key));
                if matches!(response, Ok(GardenResponse::Ack))
                    && active_peer
                    && carried > self.held_elsewhere
                {
                    self.held_elsewhere = carried;
                    self.report_to_budlum().await;
                }
                if self.peers.contains_key(&peer) {
                    self.flush(peer).await;
                } else {
                    self.outbox.remove(&peer);
                }
                self.finish_when_delivered().await;
            }
            TAG_HELLO => {
                if let Ok(GardenResponse::Welcome {
                    genesis,
                    key,
                    invite_signature,
                    ..
                }) = response
                {
                    if genesis.hash() == self.ledger.state.genesis.hash()
                        && self.holds_invite(peer, &key, &invite_signature)
                    {
                        self.peers.insert(peer, key);
                        self.peer_admitted_at
                            .entry(peer)
                            .or_insert_with(Instant::now);
                        self.unadmitted.remove(&peer);
                        self.record_verified_peer(key);
                        self.dial_failures.retain(|(k, _), _| *k != key);
                        self.dials.retain(|(k, _), _| *k != key);
                        let _ = self.net.send(NetCommand::Admit(peer)).await;
                    }
                }
            }
            TAG_ADMISSION => self.on_admission_response(peer, response).await,
            TAG_SYNC => {
                if self.sync_in_flight.is_some_and(|(p, _, _)| p == peer) {
                    self.sync_in_flight = None;
                }
                if let Ok(GardenResponse::Commits(commits)) = response {
                    let had_commits = !commits.is_empty();
                    let before = self.ledger.state.height;
                    for commit in commits {
                        if commit.block.header.height != self.ledger.state.height.saturating_add(1)
                        {
                            continue;
                        }
                        if !self.apply_commit(commit, Some(peer), false).await {
                            break;
                        }
                    }
                    if had_commits && self.ledger.state.height > before {
                        self.request_sync(Some(peer)).await;
                    }
                }
            }
            _ => {
                let bytes = match response {
                    Ok(GardenResponse::Object(Some(bytes))) => Some(bytes),
                    _ => None,
                };
                if let Some(job) = self.relay_tags.remove(&tag) {
                    self.on_relay_answer(job, bytes).await;
                } else if let Some(content_id) = self.fetch_tags.remove(&tag) {
                    self.on_fetch_answer(content_id, bytes);
                }
            }
        }
    }

    /// True when `bytes` is within the Garden's object size limit, matches an
    /// accounted publication size for `content_id`, and hashes to `content_id`.
    fn object_is_valid(&self, content_id: &Hash32, bytes: &[u8]) -> bool {
        let max_len = self.limits().max_object_bytes as usize;
        if bytes.is_empty() || bytes.len() > max_len {
            return false;
        }
        let Ok(len) = u64::try_from(bytes.len()) else {
            return false;
        };
        self.ledger.state.accounts_for(content_id, len)
            && crate::storage::content_id::ContentId::of(bytes).0 == *content_id
    }

    async fn on_relay_answer(&mut self, job: u64, bytes: Option<Vec<u8>>) {
        let Some((requester, content_id)) =
            self.relays.get(&job).map(|r| (r.requester, r.content_id))
        else {
            return;
        };
        let valid = bytes.filter(|b| self.object_is_valid(&content_id, b));
        let Some(relay) = self.relays.get_mut(&job) else {
            return;
        };
        relay.outstanding = relay.outstanding.saturating_sub(1);
        let answer = match (valid, relay.outstanding) {
            (Some(bytes), _) => relay.channel.take().map(|c| (c, Some(bytes))),
            (None, 0) => relay.channel.take().map(|c| (c, None)),
            (None, _) => None,
        };
        if relay.outstanding == 0 {
            self.relays.remove(&job);
        }
        if let Some((channel, bytes)) = answer {
            if let Some(payload) = &bytes {
                let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
                if let Some(entry) = self.object_budget.get_mut(&requester) {
                    entry.2 = entry.2.saturating_add(len);
                }
            }
            self.respond(channel, GardenResponse::Object(bytes)).await;
        }
    }

    fn on_fetch_answer(&mut self, content_id: Hash32, bytes: Option<Vec<u8>>) {
        let max_len = self.limits().max_object_bytes as usize;
        let Some(fetch) = self.fetches.get_mut(&content_id) else {
            return;
        };
        fetch.outstanding = fetch.outstanding.saturating_sub(1);
        let valid = bytes.filter(|b| {
            !b.is_empty()
                && b.len() <= max_len
                && crate::storage::content_id::ContentId::of(b).0 == content_id
        });
        match valid {
            Some(bytes) => {
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                let paid = self.ledger.state.accounts_for(&content_id, len);
                let Some(fetch) = self.fetches.remove(&content_id) else {
                    return;
                };
                if !paid {
                    // These are the bytes of this id, and no publication
                    // declares their size. No peer has other bytes for it,
                    // so the size is noted and the object is not asked for
                    // again until a publication accounts for it.
                    self.wanted.remove(&content_id);
                    self.measured.insert(content_id, len);
                    for waiter in fetch.waiters {
                        let _ = waiter.send(Err(
                            "this content does not have the size its publication declares".into(),
                        ));
                    }
                    return;
                }
                self.measured.remove(&content_id);
                if fetch.keep && self.store.put_verified(&content_id, &bytes).is_ok() {
                    self.wanted.remove(&content_id);
                }
                for waiter in fetch.waiters {
                    let _ = waiter.send(Ok(bytes.clone()));
                }
            }
            None if fetch.outstanding == 0 => {
                if let Some(fetch) = self.fetches.remove(&content_id) {
                    for waiter in fetch.waiters {
                        let _ = waiter
                            .send(Err("no connected validator could serve this content".into()));
                    }
                }
            }
            None => {}
        }
    }

    /// The validators that hold `content_id` under the genesis placement
    /// table.
    fn holders(&self, content_id: &Hash32) -> Vec<GardenKey> {
        let table: &GardenPlacementTable = &self.ledger.state.genesis.placement;
        table.holders(content_id, &self.ledger.state.active())
    }

    /// Connected peers to ask for an object: holders first, then its author,
    /// then anyone.
    fn fetch_targets(&self, content_id: &Hash32) -> Vec<PeerId> {
        let holders = self.holders(content_id);
        let authors: BTreeSet<GardenKey> = self
            .ledger
            .state
            .publications(content_id)
            .map(|object| object.author)
            .collect();
        let mut ranked: Vec<(u8, PeerId)> = self
            .peers
            .iter()
            .map(|(peer, key)| {
                let rank = if holders.contains(key) {
                    0
                } else if authors.contains(key) {
                    1
                } else {
                    2
                };
                (rank, *peer)
            })
            .collect();
        ranked.sort();
        ranked
            .into_iter()
            .take(FETCH_FANOUT)
            .map(|(_, peer)| peer)
            .collect()
    }

    async fn start_fetch(
        &mut self,
        content_id: Hash32,
        keep: bool,
        waiter: Option<oneshot::Sender<Result<Vec<u8>, String>>>,
    ) {
        if let Some(fetch) = self.fetches.get_mut(&content_id) {
            fetch.keep |= keep;
            fetch.waiters.extend(waiter);
            return;
        }
        let targets = self.fetch_targets(&content_id);
        if targets.is_empty() {
            if let Some(waiter) = waiter {
                let _ = waiter.send(Err("no validator is connected to serve this content".into()));
            }
            return;
        }
        self.fetches.insert(
            content_id,
            Fetch {
                waiters: waiter.into_iter().collect(),
                outstanding: targets.len(),
                keep,
                started: Instant::now(),
            },
        );
        for peer in targets {
            let tag = self.fresh_tag();
            self.fetch_tags.insert(tag, content_id);
            self.send(
                peer,
                GardenRequest::GetObject {
                    content_id,
                    relay: true,
                },
                tag,
            )
            .await;
        }
    }

    async fn on_admission_response(
        &mut self,
        peer: PeerId,
        response: Result<GardenResponse, String>,
    ) {
        // Only the Garden's host has authority to refuse or accept a waiting
        // request; a non-host peer cannot forge `TurnedAway` or clear `Waiting`.
        let from_host = self.peers.get(&peer) == Some(&self.ledger.state.host());
        if let Ok(GardenResponse::AdmissionStatus(state)) = response {
            match state {
                GardenAdmissionState::Waiting if from_host => {
                    self.remote_admission = Some(GardenAdmissionState::Waiting);
                }
                GardenAdmissionState::TurnedAway if from_host => {
                    self.turned_away = true;
                    self.remote_admission = None;
                }
                GardenAdmissionState::Seated if from_host => {
                    self.remote_admission = None;
                    self.request_sync(Some(peer)).await;
                }
                GardenAdmissionState::Seated if self.is_seated_peer(peer) => {
                    self.request_sync(Some(peer)).await;
                }
                _ => {}
            }
        }
    }

    async fn on_proposal(&mut self, block: GardenBlock, from: Option<PeerId>) {
        let hash = block.hash();
        if self.seen.contains(&Seen::Block(hash)) || block.header.chain_id != self.chain_id() {
            return;
        }
        if block.header.height > self.ledger.state.height.saturating_add(1) {
            if from.is_some_and(|peer| self.is_seated_peer(peer))
                && self.ledger.state.is_active(&block.header.proposer)
            {
                self.request_sync(from).await;
            }
            return;
        }
        // Verify header signature, signed transaction root and full execution
        // before inserting `Seen::Block(hash)` or charging the proposer's
        // per-round candidate slot.
        if self.ledger.state.check_header(&block).is_err() {
            return;
        }
        let proposer = block.header.proposer;
        let now_round = self.local_round();
        if self
            .candidate_rounds
            .get(&proposer)
            .is_some_and(|round| *round >= now_round)
        {
            return;
        }
        let held: Vec<(Hash32, u64)> = self
            .proposals
            .iter()
            .filter(|(_, held)| held.header.proposer == proposer)
            .map(|(held_hash, held)| (*held_hash, held.header.round))
            .collect();
        let reached = now_round.saturating_add(1);
        if held
            .iter()
            .any(|(_, round)| *round >= block.header.round && *round <= reached)
        {
            return;
        }
        self.candidate_rounds.insert(proposer, now_round);
        if self.ledger.state.run_block(&block).is_err() {
            return;
        }
        for (old, _) in held {
            self.proposals.remove(&old);
            self.votes.remove(&old);
        }
        if self.proposals.len() >= MAX_PROPOSALS.max(self.ledger.state.active().len()) {
            return;
        }
        if !self.first_sight(Seen::Block(hash)) {
            return;
        }
        self.proposals.insert(hash, block.clone());
        self.gossip(&GardenGossip::Proposal(block), from).await;
        let orphans: Vec<(Option<PeerId>, GardenVote)> = self.orphan_votes.drain(..).collect();
        for (src, vote) in orphans {
            self.on_vote(vote, src).await;
        }
        self.consider(hash).await;
    }

    async fn on_gossip(&mut self, item: GardenGossip, from: Option<PeerId>) {
        match item {
            GardenGossip::Tx(tx) => {
                let id = tx.id();
                // Verify signature and state admission before inserting `id`
                // into `seen`, so a peer cannot pre-poison `tx.id()` with a
                // forged-signature or premature frame before the real tx lands.
                if tx_bytes(&tx) <= MAX_TX_BYTES
                    && !self.seen.contains(&Seen::Tx(id))
                    && self.ledger.state.check_tx_shape(&tx).is_ok()
                    && self.admit_tx(tx.clone())
                {
                    self.first_sight(Seen::Tx(id));
                    self.gossip(&GardenGossip::Tx(tx), from).await;
                }
            }
            GardenGossip::Proposal(block) => self.on_proposal(block, from).await,
            GardenGossip::Vote(vote) => self.on_vote(vote, from).await,
            GardenGossip::Commit(commit) => {
                if commit.block.header.chain_id != self.chain_id() {
                    return;
                }
                let hash = commit.block.hash();
                if self.seen.contains(&Seen::Commit(hash)) {
                    return;
                }
                let height = commit.block.header.height;
                // Record `Seen::Commit(hash)` only inside `apply_commit` after
                // quorum verification succeeds, so a voteless or bad-quorum
                // wrapper around a real proposal cannot drop the true commit.
                if height == self.ledger.state.height.saturating_add(1) {
                    self.apply_commit(commit, from, true).await;
                } else if height > self.ledger.state.height
                    && !commit.votes.is_empty()
                    && from.is_some_and(|peer| self.is_seated_peer(peer))
                {
                    self.request_sync(from).await;
                }
            }
            GardenGossip::Presence(signal) => {
                let seated = self.is_seated_validator(&signal.validator);
                let newer = self
                    .presence_windows
                    .get(&signal.validator)
                    .is_none_or(|window| signal.window > *window);
                if !seated || !newer || signal.verify(self.chain_id()).is_err() {
                    return;
                }
                if !self.first_sight(Seen::Presence(signal.validator, signal.window)) {
                    return;
                }
                self.presence_windows
                    .insert(signal.validator, signal.window);
                self.last_seen.insert(signal.validator, Instant::now());
                self.gossip(&GardenGossip::Presence(signal), from).await;
            }
        }
    }

    /// True when `tx.tx.sender` is allowed to hold a slot in the pending set.
    ///
    /// A key outside the identity record may pool only a `Join` with the
    /// nonce the chain expects from it and a valid invite signature, while
    /// the Garden has room for it and pending joins stay within that cap.
    /// A recorded key may pool what its standing lets it apply: only an
    /// active validator publishes, and only the host admits. A transaction
    /// that can never apply would hold a slot, and a publication would
    /// shield the bytes it names, for as long as its sender liked.
    fn sender_may_pool(&self, tx: &SignedGardenTx) -> bool {
        let state = &self.ledger.state;
        match &tx.tx.kind {
            GardenTxKind::Join {
                invite_signature, ..
            } => {
                if state.validators.contains_key(&tx.tx.sender)
                    || tx.tx.nonce != state.next_nonce(&tx.tx.sender)
                {
                    return false;
                }
                let max_validators = self.limits().max_validators as usize;
                let room = match self.limits().admission {
                    GardenAdmission::Direct => state.has_room(),
                    GardenAdmission::HostApproval => state.waiting() < max_validators,
                };
                if !room {
                    return false;
                }
                let pending_joins = self
                    .mempool
                    .values()
                    .filter(|queued| matches!(queued.tx.kind, GardenTxKind::Join { .. }))
                    .count();
                if pending_joins >= max_validators {
                    return false;
                }
                verify_signature(
                    &join_message(self.chain_id(), &tx.tx.sender),
                    invite_signature,
                    &state.genesis.invite_key,
                )
                .is_ok()
            }
            GardenTxKind::Leave | GardenTxKind::Resume { .. } => state
                .validators
                .get(&tx.tx.sender)
                .is_some_and(|v| v.status != GardenValidatorStatus::Waiting),
            GardenTxKind::Publish { .. } => state.is_active(&tx.tx.sender),
            GardenTxKind::Admit { .. } => tx.tx.sender == state.host(),
            GardenTxKind::Suspend { .. } => false,
        }
    }

    /// True when `tx` meets every pool bound and may enter `self.mempool`.
    fn can_admit_tx(&self, tx: &SignedGardenTx) -> bool {
        let size = tx_bytes(tx);
        if size > MAX_TX_BYTES || self.ledger.state.check_tx_shape(tx).is_err() {
            return false;
        }
        // An absence report is written by the leader into its own block and
        // counts nowhere else, so one that waits in a pool can only hold the
        // nonce of its sender.
        if matches!(tx.tx.kind, GardenTxKind::Suspend { .. }) || !self.sender_may_pool(tx) {
            return false;
        }
        if tx.tx.nonce < self.ledger.state.next_nonce(&tx.tx.sender)
            || self.mempool.len() >= MAX_MEMPOOL
        {
            return false;
        }
        let held_bytes: usize = self.mempool.values().map(tx_bytes).sum();
        if held_bytes.saturating_add(size) > MAX_MEMPOOL_BYTES {
            return false;
        }
        let per_sender = (self.limits().max_sender_txs_per_block as usize).saturating_mul(4);
        let held = self
            .mempool
            .range((tx.tx.sender, 0)..=(tx.tx.sender, u64::MAX))
            .count();
        let slot = (tx.tx.sender, tx.tx.nonce);
        held < per_sender && !self.mempool.contains_key(&slot) && tx.verify(self.chain_id()).is_ok()
    }

    /// Put a transaction in the pending set. False when it is refused.
    fn admit_tx(&mut self, tx: SignedGardenTx) -> bool {
        if !self.can_admit_tx(&tx) {
            return false;
        }
        let slot = (tx.tx.sender, tx.tx.nonce);
        self.mempool.insert(slot, tx);
        if self.pending_since.is_none() {
            self.pending_since = Some(Instant::now());
        }
        true
    }

    async fn on_vote(&mut self, vote: GardenVote, from: Option<PeerId>) {
        if vote.signature.len() != VOTE_SIGNATURE_BYTES
            || vote.chain_id != self.chain_id()
            || vote.height != self.ledger.state.height.saturating_add(1)
        {
            return;
        }
        let Some(block) = self.proposals.get(&vote.block_hash) else {
            if self.ledger.state.is_active(&vote.voter) {
                // Attribute orphan votes by sending peer (`from`) because a
                // vote signature cannot be verified until the block header
                // arrives; one peer must not spoof another validator's voter
                // key to suppress or evict genuine orphan votes.
                let dup = self.orphan_votes.iter().any(|(src, v)| {
                    *src == from && v.block_hash == vote.block_hash && v.voter == vote.voter
                });
                let per_source = self
                    .orphan_votes
                    .iter()
                    .filter(|(src, _)| *src == from)
                    .count();
                let per_source_voter = self
                    .orphan_votes
                    .iter()
                    .filter(|(src, v)| *src == from && v.voter == vote.voter)
                    .count();
                if !dup
                    && per_source < MAX_ORPHAN_VOTES_PER_PEER
                    && per_source_voter < MAX_ORPHAN_VOTES_PER_VOTER
                {
                    self.orphan_votes.push_back((from, vote));
                    if self.orphan_votes.len() > MAX_ORPHAN_VOTES {
                        // Evict the oldest entry from the peer holding the most
                        // orphan slots so a single noisy peer cannot evict
                        // honest validators' votes.
                        let mut counts: BTreeMap<Option<PeerId>, usize> = BTreeMap::new();
                        for (src, _) in &self.orphan_votes {
                            *counts.entry(*src).or_insert(0) += 1;
                        }
                        if let Some((heaviest, _)) = counts.into_iter().max_by_key(|(_, n)| *n) {
                            if let Some(pos) = self
                                .orphan_votes
                                .iter()
                                .position(|(src, _)| *src == heaviest)
                            {
                                self.orphan_votes.remove(pos);
                            }
                        }
                    }
                }
            }
            return;
        };
        if self.seen.contains(&Seen::Vote(vote.block_hash, vote.voter)) {
            return;
        }
        let valid = self
            .ledger
            .state
            .electorate(&block.txs)
            .contains(&vote.voter)
            && vote.verify(&block.header).is_ok();
        if !valid || !self.first_sight(Seen::Vote(vote.block_hash, vote.voter)) {
            return;
        }
        let hash = vote.block_hash;
        self.votes
            .entry(hash)
            .or_default()
            .insert(vote.voter, vote.clone());
        self.gossip(&GardenGossip::Vote(vote), from).await;
        self.consider(hash).await;
    }

    /// The round this node is in, counted from the moment the current
    /// height had work to do.
    fn local_round(&self) -> u64 {
        let base = self.pending_since.map_or(self.height_started, |pending| {
            pending.max(self.height_started)
        });
        let round_ms = u128::from(self.limits().round_ms.max(1));
        u64::try_from(base.elapsed().as_millis() / round_ms).unwrap_or(u64::MAX)
    }

    /// Decide what to do about the proposal `hash`: sign it, and when this
    /// node is the host, finalize it once the others signed.
    async fn consider(&mut self, hash: Hash32) {
        let Some(block) = self.proposals.get(&hash).cloned() else {
            return;
        };
        let electorate = self.ledger.state.electorate(&block.txs);
        if !electorate.contains(&self.me) || self.stopped {
            return;
        }
        // No validator signs a block dated ahead of its own clock. The state
        // machine reads no clock, so the timestamp is what the leader wrote,
        // and every later block must be dated after it. The host signs every
        // block: one leader cannot move the chain to a time nobody reached.
        // The block is kept, and it gets the vote once the clock is there.
        if block.header.timestamp_ms > now_ms().saturating_add(MAX_TIMESTAMP_AHEAD_MS) {
            return;
        }
        // No validator signs away a validator it still hears. A report is
        // the word of one leader, and the validators a block reports have no
        // vote on it, so every vote that is cast says the same thing as the
        // report. The wait is half the window: whoever reports waited the
        // whole of it, and the clocks of two nodes do not start together.
        let grace = millis(self.limits().suspend_after_ms / 2);
        let reports_heard = block.txs.iter().any(|tx| {
            matches!(&tx.tx.kind, GardenTxKind::Suspend { target } if !self.silent_for(target, grace))
        });
        if reports_heard {
            return;
        }
        // No validator signs a round its own clock has not reached. The
        // proposer writes the round into its header, and the leader of a
        // round is a function of that number, so a block that names a far
        // round is led by whoever chose the number. One round of slack is
        // what two clocks that did not start together need. The block is
        // kept and gets the vote when the round comes.
        if block.header.round > self.local_round().saturating_add(1) {
            return;
        }
        if !self.is_host() {
            if self.my_votes.insert(hash) {
                let vote = GardenVote::sign(&block.header, &self.key);
                self.first_sight(Seen::Vote(hash, self.me));
                self.gossip(&GardenGossip::Vote(vote), None).await;
            }
            return;
        }
        if self.host_voted {
            return;
        }
        let others = self.votes.get(&hash).map_or(0, |votes| {
            votes.keys().filter(|voter| **voter != self.me).count()
        });
        if others.saturating_add(1) < quorum(electorate.len()) {
            return;
        }
        self.host_voted = true;
        let mut votes: Vec<GardenVote> = self
            .votes
            .get(&hash)
            .map(|votes| votes.values().cloned().collect())
            .unwrap_or_default();
        votes.retain(|vote| vote.voter != self.me);
        votes.push(GardenVote::sign(&block.header, &self.key));
        let commit = GardenCommit { block, votes };
        self.first_sight(Seen::Commit(hash));
        self.apply_commit(commit, None, true).await;
    }

    fn is_seated_peer(&self, peer: PeerId) -> bool {
        self.peers
            .get(&peer)
            .is_some_and(|key| self.is_seated_validator(key))
    }

    async fn request_sync(&mut self, from: Option<PeerId>) {
        if self.peers.is_empty() {
            return;
        }
        if let Some(peer) = from {
            if !self.is_seated_peer(peer) {
                return;
            }
        }
        let needed = self.ledger.state.height.saturating_add(1);
        let now = Instant::now();
        // Coalesce concurrent sync requests for the same height while a fresh
        // request to a still-connected peer is already awaiting its reply, and
        // cap peer-triggered syncs so future-height spam cannot fan out bursts
        // of multi-megabyte `GetCommits` exchanges.
        if let Some((in_flight_peer, in_flight_from, sent_at)) = self.sync_in_flight {
            if in_flight_from == needed
                && self.is_seated_peer(in_flight_peer)
                && now.duration_since(sent_at) < SYNC_IN_FLIGHT_TIMEOUT
            {
                return;
            }
            self.sync_in_flight = None;
        }
        if from.is_some() {
            if now.duration_since(self.outbound_sync_budget.0) >= Duration::from_secs(1) {
                self.outbound_sync_budget = (now, 0);
            }
            if self.outbound_sync_budget.1 >= MAX_PEER_TRIGGERED_SYNCS_PER_SEC {
                return;
            }
            self.outbound_sync_budget.1 = self.outbound_sync_budget.1.saturating_add(1);
        }
        let peer = if let Some(peer) = from {
            Some(peer)
        } else {
            let seated: Vec<PeerId> = self
                .peers
                .iter()
                .filter_map(|(peer, key)| self.is_seated_validator(key).then_some(*peer))
                .collect();
            if seated.is_empty() {
                None
            } else {
                self.sync_cursor = self.sync_cursor.wrapping_add(1) % seated.len();
                seated.get(self.sync_cursor).copied()
            }
        };
        if let Some(peer) = peer {
            self.sync_in_flight = Some((peer, needed, now));
            self.send(
                peer,
                GardenRequest::GetCommits {
                    from_height: needed,
                    max: MAX_SYNC_COMMITS,
                },
                TAG_SYNC,
            )
            .await;
        }
    }

    /// Append a finalized block. False when the chain refuses it.
    async fn apply_commit(
        &mut self,
        commit: GardenCommit,
        from: Option<PeerId>,
        spread: bool,
    ) -> bool {
        let active_before = self.ledger.state.active();
        if let Err(e) = self.ledger.append(commit.clone()) {
            tracing::debug!(error = %e, "garden commit refused");
            return false;
        }
        self.first_sight(Seen::Commit(commit.block.hash()));
        if from.is_some_and(|peer| {
            self.peers
                .get(&peer)
                .is_some_and(|key| self.ledger.state.is_active(key))
        }) {
            self.held_elsewhere = self.held_elsewhere.max(commit.block.header.height);
        }
        if self.is_seated_validator(&self.me) {
            self.remote_admission = None;
        }
        self.proposals.clear();
        self.candidate_rounds.clear();
        self.votes.clear();
        self.orphan_votes.clear();
        self.my_votes.clear();
        self.proposed_rounds.clear();
        self.host_voted = false;
        self.height_started = Instant::now();

        let state = &self.ledger.state;
        self.mempool
            .retain(|(sender, nonce), _| *nonce >= state.next_nonce(sender));
        self.pending_since = (!self.mempool.is_empty()).then(Instant::now);
        self.my_next_nonce = self.my_next_nonce.max(state.next_nonce(&self.me));

        for tx in &commit.block.txs {
            if let GardenTxKind::Publish { content_id, .. } = &tx.tx.kind {
                // A deposit stops being one when a publication accounts for
                // its bytes. A publication that declares another size was
                // charged for that size, not for these bytes: they stay a
                // deposit, and the next deposits of the same peer push them
                // out. Otherwise the share would bound what a validator
                // declares, not what it leaves on the disks of the others.
                if self.store.contains(content_id) && !self.holds_published(content_id) {
                    continue;
                }
                for queue in self.unreferenced.values_mut() {
                    queue.retain(|id| id != content_id);
                }
                self.unreferenced.retain(|_, queue| !queue.is_empty());
                if tx.tx.sender != self.me && !self.holders(content_id).contains(&self.me) {
                    let own = self.has_pending(|pending| {
                        matches!(pending, GardenTxKind::Publish { content_id: cid, .. } if cid == content_id)
                    });
                    if !own {
                        self.store.remove(content_id);
                    }
                }
            }
            match &tx.tx.kind {
                GardenTxKind::Join { address, .. } | GardenTxKind::Resume { address } => {
                    let sender = tx.tx.sender;
                    self.rejected_addresses
                        .retain(|(k, a)| *k != sender || a == address);
                    self.rejected_address_order
                        .retain(|(k, a)| *k != sender || a == address);
                }
                GardenTxKind::Leave => {
                    let sender = tx.tx.sender;
                    if !self.ledger.state.validators.contains_key(&sender) {
                        self.rejected_addresses.retain(|(k, _)| *k != sender);
                        self.rejected_address_order.retain(|(k, _)| *k != sender);
                    }
                }
                _ => {}
            }
            if matches!(
                tx.tx.kind,
                GardenTxKind::Join { .. } | GardenTxKind::Resume { .. }
            ) {
                self.last_seen.insert(tx.tx.sender, Instant::now());
            }
            if let GardenTxKind::Admit { target, accept } = &tx.tx.kind {
                // The silence of a key is counted from the block that seats
                // it, not from the request it sent while it waited.
                self.last_seen.insert(*target, Instant::now());
                if *accept {
                    self.turned_away_keys.remove(target);
                } else {
                    self.record_turned_away(*target);
                    if *target == self.me {
                        self.turned_away = true;
                        self.remote_admission = None;
                    } else {
                        // Give the rejected peer a brief window to poll its
                        // `TurnedAway` verdict, then reclaim its connection slot.
                        let grace = millis(self.limits().round_ms)
                            .saturating_mul(3)
                            .max(Duration::from_millis(750));
                        let rejected_peers: Vec<PeerId> = self
                            .peers
                            .iter()
                            .filter(|(_, key)| **key == *target)
                            .map(|(p, _)| *p)
                            .collect();
                        for p in rejected_peers {
                            self.disconnect_after
                                .entry(p)
                                .or_insert_with(|| Instant::now() + grace);
                        }
                    }
                }
            }
        }
        self.unreferenced.retain(|_, queue| !queue.is_empty());
        if active_before == self.ledger.state.active() {
            for tx in &commit.block.txs {
                if let GardenTxKind::Publish { content_id, .. } = &tx.tx.kind {
                    self.want_if_holder(*content_id);
                }
            }
        } else {
            for id in self.ledger.state.content_ids() {
                self.want_if_holder(id);
            }
        }

        if spread {
            self.gossip(&GardenGossip::Commit(commit.clone()), from)
                .await;
        }
        self.report_to_budlum().await;

        let height = self.ledger.state.height;
        let round = millis(self.limits().round_ms);
        let departed = self
            .leaving
            .as_ref()
            .and_then(|leaving| leaving.tx_id)
            .is_some_and(|tx_id| self.ledger.locate(&tx_id).is_some());
        if let Some(leaving) = self.leaving.as_mut().filter(|_| departed) {
            if leaving.sealed.is_none() {
                // The block is final here. It may be final nowhere else yet:
                // the host signs last, so the host alone holds the block of
                // its own departure until a peer has it.
                leaving.sealed = Some(height);
                leaving.deadline =
                    Instant::now() + round.saturating_mul(4).max(Duration::from_secs(2));
            }
        }
        self.finish_when_delivered().await;
        true
    }

    fn want_if_holder(&mut self, content_id: Hash32) {
        let unpaid = self
            .measured
            .get(&content_id)
            .is_some_and(|len| !self.ledger.state.accounts_for(&content_id, *len));
        if unpaid {
            return;
        }
        let declared_size = self
            .ledger
            .state
            .publications(&content_id)
            .map(|obj| u64::from(obj.size))
            .max()
            .unwrap_or(0);
        if !self.store.can_fit(declared_size) {
            return;
        }
        if self.holders(&content_id).contains(&self.me) && !self.store.contains(&content_id) {
            self.wanted.insert(content_id);
        }
    }

    /// Report finalized blocks to the node's Budlum chain and keep the
    /// domain status there equal to what this node observes.
    async fn report_to_budlum(&mut self) {
        let Some(link) = self.link.clone() else {
            return;
        };
        let chain_id = self.chain_id();
        while self.reported < self.ledger.state.height {
            let next = self.reported.saturating_add(1);
            let alone = self
                .ledger
                .commit_at(next)
                .is_some_and(|(_, electorate)| electorate.iter().all(|key| *key == self.me));
            if next > self.held_elsewhere && !alone {
                // Only this node holds the block. If it stops now the Garden
                // goes on from the block before, and Budlum would have seen
                // a block the Garden never had.
                break;
            }
            if self.budlum_status == Some(DomainStatus::Frozen) {
                match link
                    .move_domain(chain_id, self.me, DomainStatus::Active)
                    .await
                {
                    Ok(()) => self.budlum_status = Some(DomainStatus::Active),
                    Err(e) => {
                        self.budlum_failed(e);
                        return;
                    }
                }
            }
            let Some((commit, electorate)) = self.ledger.commit_at(next) else {
                return;
            };
            match link.report(self.me, electorate, commit).await {
                Ok(()) => {
                    self.reported = next;
                    self.budlum_error = None;
                }
                Err(e) => {
                    self.budlum_failed(e);
                    return;
                }
            }
        }
        let observed = match self.observed_status() {
            DomainStatus::Retired => DomainStatus::Frozen,
            status => status,
        };
        if self.budlum_status.is_some_and(|status| status != observed) {
            match link.move_domain(chain_id, self.me, observed).await {
                Ok(()) => self.budlum_status = Some(observed),
                Err(e) => self.budlum_failed(e),
            }
        }
    }

    /// Keep what the Budlum chain refused, and say it once in the log.
    fn budlum_failed(&mut self, error: String) {
        if self.budlum_error.as_deref() != Some(error.as_str()) {
            tracing::warn!(
                chain_id = %format!("{:016x}", self.chain_id()),
                %error,
                "garden: the Budlum chain refused a report"
            );
        }
        self.budlum_error = Some(error);
    }

    /// Sign one of this node's own transactions and spread it.
    async fn submit(&mut self, kind: GardenTxKind) -> Result<Hash32, String> {
        let tx = GardenTx {
            chain_id: self.chain_id(),
            sender: self.me,
            nonce: self.my_next_nonce,
            kind,
        }
        .sign(&self.key)?;
        let id = tx.id();
        self.first_sight(Seen::Tx(id));
        if !self.admit_tx(tx.clone()) {
            return Err("this node has too many pending transactions".into());
        }
        self.my_next_nonce = self.my_next_nonce.saturating_add(1);
        self.gossip(&GardenGossip::Tx(tx), None).await;
        Ok(id)
    }

    fn has_pending(&self, wanted: impl Fn(&GardenTxKind) -> bool) -> bool {
        self.mempool
            .range((self.me, 0)..=(self.me, u64::MAX))
            .any(|(_, tx)| wanted(&tx.tx.kind))
    }

    /// True when the chain holds this node as suspended: the others
    /// reported it absent, and it never signed a departure.
    fn reported_absent(&self) -> bool {
        self.ledger
            .state
            .validators
            .get(&self.me)
            .is_some_and(|v| v.status == GardenValidatorStatus::Suspended)
    }

    /// Enter or re-enter the identity record when this node is not active.
    async fn ensure_membership(&mut self) {
        // A retired Garden has no next block to enter with.
        if self.leaving.is_some() || self.ledger.state.status == DomainStatus::Retired {
            return;
        }
        let recorded = self.ledger.state.validators.get(&self.me);
        let settled = recorded.is_some_and(|v| {
            v.status == GardenValidatorStatus::Active && v.address == self.address
        });
        let record = recorded.map(|v| v.status);
        let kind = match record {
            Some(_) if settled => return,
            // The request is in the record; the answer is the host's.
            Some(GardenValidatorStatus::Waiting) => return,
            None if self.remote_admission == Some(GardenAdmissionState::Waiting) => return,
            None if self.turned_away => return,
            None if self.observed_status() != DomainStatus::Active => return,
            None => GardenTxKind::Join {
                name: self.name.clone(),
                address: self.address.clone(),
                invite_signature: self.invite_signature.clone(),
            },
            Some(_) if self.ledger.state.status == DomainStatus::Frozen && !self.is_host() => {
                return
            }
            Some(_) => GardenTxKind::Resume {
                address: self.address.clone(),
            },
        };
        let pending = self.has_pending(|kind| {
            matches!(
                kind,
                GardenTxKind::Join { .. } | GardenTxKind::Resume { .. }
            )
        });
        if pending {
            return;
        }
        // An earlier attempt may have been dropped, so restart the nonce
        // sequence from what the chain expects.
        self.my_next_nonce = self.ledger.state.next_nonce(&self.me);
        let _ = self.submit(kind).await;
    }

    /// Propose a block when this node leads the current round.
    async fn try_propose(&mut self) {
        let state = &self.ledger.state;
        if state.status == DomainStatus::Retired || self.mempool.is_empty() || self.host_voted {
            return;
        }
        if !self.is_host() && !self.host_present() {
            return;
        }
        let round = self.local_round();
        if state.leader(round) != Some(self.me) || self.proposed_rounds.contains(&round) {
            return;
        }
        let host = state.host();
        let pool = self
            .mempool
            .range((host, 0)..=(host, u64::MAX))
            .chain(
                self.mempool
                    .iter()
                    .filter(|((sender, _), _)| *sender != host),
            )
            .map(|(_, tx)| tx);
        // The leader reports the validators whose presence signal stopped.
        let limit = millis(self.limits().suspend_after_ms);
        let absent: Vec<GardenKey> = state
            .active()
            .into_iter()
            .filter(|key| *key != host && self.silent_for(key, limit))
            .collect();
        let (txs, dead) = state.assemble(pool, &self.me, &absent, |tx| tx.sign(&self.key).ok());
        self.mempool.retain(|_, tx| !dead.contains(&tx.id()));
        if txs.is_empty() {
            if self.mempool.is_empty() {
                self.pending_since = None;
            }
            return;
        }
        let Ok((header, _)) = state.build_header(&txs, self.me, round, now_ms()) else {
            return;
        };
        let block = GardenBlock {
            proposer_signature: self.key.sign(&header.hash()).to_vec(),
            header,
            txs,
        };
        let hash = block.hash();
        self.proposed_rounds.insert(round);
        self.first_sight(Seen::Block(hash));
        // One slot for each proposer, this node included: its block of an
        // earlier round gives way, as it does on every other node.
        let earlier: Vec<Hash32> = self
            .proposals
            .iter()
            .filter(|(_, held)| held.header.proposer == self.me)
            .map(|(held_hash, _)| *held_hash)
            .collect();
        for old in earlier {
            self.proposals.remove(&old);
            self.votes.remove(&old);
        }
        self.proposals.insert(hash, block.clone());
        self.gossip(&GardenGossip::Proposal(block), None).await;
        self.consider(hash).await;
    }

    /// Close the connections of peers that did not show the invite in time,
    /// peers that passed `Hello` but never joined before the unjoined grace
    /// expired, and peers scheduled for disconnect after a refusal/verdict.
    async fn drop_strangers(&mut self) {
        let grace = millis(self.limits().round_ms)
            .saturating_mul(2)
            .max(Duration::from_secs(2));
        let overdue: Vec<PeerId> = self
            .unadmitted
            .iter()
            .filter(|(peer, since)| !self.peers.contains_key(peer) && since.elapsed() >= grace)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in overdue {
            self.unadmitted.remove(&peer);
            let _ = self.net.send(NetCommand::Disconnect(peer)).await;
        }
        let unjoined_grace = self.unjoined_grace();
        let expired_unjoined: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(peer, key)| {
                !self.is_seated_validator(key)
                    && self
                        .peer_admitted_at
                        .get(peer)
                        .is_some_and(|at| at.elapsed() >= unjoined_grace)
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in expired_unjoined {
            self.note_source_unjoined_admitted(peer, unjoined_grace);
            self.drop_peer_state(peer).await;
        }
        let now = Instant::now();
        let scheduled: Vec<PeerId> = self
            .disconnect_after
            .iter()
            .filter(|(_, when)| now >= **when)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in scheduled {
            self.drop_peer_state(peer).await;
        }
    }

    async fn on_tick(&mut self) {
        let limits = self.limits().clone();
        // A node that stood still heard nobody for that long, and that says
        // nothing about the others. Without this a host that wakes up holds
        // every validator as silent, and the first block it leads reports
        // them all and leaves the host alone in the electorate. The host's
        // own clock is not touched: a validator that wakes up waits for the
        // next presence signal of the host before it counts the host in.
        let gap = self.last_tick.elapsed();
        self.last_tick = Instant::now();
        if stood_still(gap, &limits) {
            let host = self.ledger.state.host();
            let me = self.me;
            let others = self
                .ledger
                .state
                .validators
                .keys()
                .copied()
                .filter(|key| *key != host && *key != me);
            forgive_silence(&mut self.last_seen, others, self.last_tick);
        }
        self.drop_strangers().await;
        if self.last_presence.elapsed() >= millis(limits.presence_interval_ms) {
            self.last_presence = Instant::now();
            self.my_window = self.my_window.saturating_add(1);
            let signal = GardenPresence::sign(self.chain_id(), self.my_window, &self.key);
            self.first_sight(Seen::Presence(self.me, self.my_window));
            self.gossip(&GardenGossip::Presence(signal), None).await;
            self.report_to_budlum().await;
        }
        if self.last_sync.elapsed() >= millis(limits.round_ms.max(250)) {
            // Only the periodic timer resets `last_sync`; peer-triggered syncs
            // must never starve periodic sync or `wanted` content fetches.
            self.last_sync = Instant::now();
            if limits.admission == GardenAdmission::HostApproval
                && !self.is_key_seated(&self.me)
                && !self.turned_away
            {
                let host = self.ledger.state.host();
                let target_peer = self
                    .peers
                    .iter()
                    .find(|(_, key)| **key == host)
                    .map(|(peer, _)| *peer)
                    .or_else(|| self.peers.keys().next().copied());
                if let Some(peer) = target_peer {
                    self.send(peer, GardenRequest::AdmissionStatus, TAG_ADMISSION)
                        .await;
                }
            } else {
                self.request_sync(None).await;
            }
            let mut over_budget = Vec::new();
            let missing: Vec<Hash32> = self
                .wanted
                .iter()
                .filter(|id| !self.fetches.contains_key(*id))
                .filter(|id| {
                    let declared = self
                        .ledger
                        .state
                        .publications(id)
                        .map(|obj| u64::from(obj.size))
                        .max()
                        .unwrap_or(0);
                    if self.store.can_fit(declared) {
                        true
                    } else {
                        over_budget.push(**id);
                        false
                    }
                })
                .copied()
                .take(FETCH_FANOUT)
                .collect();
            for id in over_budget {
                self.wanted.remove(&id);
            }
            for id in missing {
                self.start_fetch(id, true, None).await;
            }
        }
        if self.last_dial.elapsed() >= millis(limits.round_ms.max(1_000)) {
            self.dial_known().await;
        }
        let stale: Vec<Hash32> = self
            .fetches
            .iter()
            .filter(|(_, fetch)| fetch.started.elapsed() >= FETCH_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(fetch) = self.fetches.remove(&id) {
                for waiter in fetch.waiters {
                    let _ = waiter.send(Err("fetching this content timed out".into()));
                }
            }
        }
        self.ensure_membership().await;
        self.renew_departure().await;
        self.try_propose().await;
        let hashes: Vec<Hash32> = self.proposals.keys().copied().collect();
        for hash in hashes {
            self.consider(hash).await;
        }
        if self.ledger.state.status == DomainStatus::Retired
            && self.leaving.is_none()
            && !self.reported_absent()
        {
            // The Garden ended while this node was not part of the last
            // block. Nothing is left to follow, so the node wipes and stops.
            // A node that was reported absent is the exception: it signed
            // no departure, and a report is the word of the validators that
            // stayed, in the end of the host alone. Their word does not
            // clear its disk. It keeps what it holds, readable, until its
            // own departure.
            let (reply, _) = oneshot::channel();
            self.leaving = Some(Leaving {
                deadline: Instant::now(),
                tx_id: None,
                sealed: None,
                reply,
            });
        }
        let overdue = self
            .leaving
            .as_ref()
            .is_some_and(|leaving| Instant::now() >= leaving.deadline);
        if overdue {
            self.finish_leave().await;
        }
    }

    async fn on_command(&mut self, command: GardenCommand) {
        match command {
            GardenCommand::Status(reply) => {
                let _ = reply.send(self.status().await);
            }
            GardenCommand::Invite(reply) => {
                let _ = reply.send(self.invite());
            }
            GardenCommand::Publish {
                kind,
                bytes,
                mime,
                caption,
                reply,
            } => {
                let _ = reply.send(self.publish(kind, bytes, mime, caption).await);
            }
            GardenCommand::Resolve(content_id, reply) => match self.store.get(&content_id) {
                Some(bytes) => {
                    let _ = reply.send(Ok(bytes));
                }
                None if !self.ledger.state.holds_content(&content_id) => {
                    let _ = reply.send(Err("this content is not published in the Garden".into()));
                }
                None => {
                    let keep = self.holders(&content_id).contains(&self.me);
                    self.start_fetch(content_id, keep, Some(reply)).await;
                }
            },
            GardenCommand::Trace(tx_id, reply) => {
                let _ = reply.send(self.trace(&tx_id));
            }
            GardenCommand::Feed(limit, reply) => {
                let _ = reply.send(self.feed(limit));
            }
            GardenCommand::Leave(reply) => self.begin_leave(reply).await,
            GardenCommand::Admit {
                target,
                accept,
                reply,
            } => {
                let _ = reply.send(self.answer_request(target, accept).await);
            }
        }
    }

    /// The host answers a key that waits. The answer is a transaction, so
    /// the seat is given or refused in a block and every node sees the same.
    async fn answer_request(&mut self, target: GardenKey, accept: bool) -> Result<Value, String> {
        if !self.is_host() {
            return Err("only the host of a Garden admits a key that waits".into());
        }
        let probe = GardenTx {
            chain_id: self.chain_id(),
            sender: self.me,
            nonce: self.ledger.state.next_nonce(&self.me),
            kind: GardenTxKind::Admit { target, accept },
        }
        .sign(&self.key)?;
        self.ledger.state.check_tx(&probe)?;
        let answered = self.has_pending(
            |pending| matches!(pending, GardenTxKind::Admit { target: named, .. } if *named == target),
        );
        if answered {
            return Err("this key is already being answered".into());
        }
        let tx_id = self.submit(GardenTxKind::Admit { target, accept }).await?;
        Ok(json!({
            "tx_id": hex::encode(tx_id),
            "key": hex::encode(target),
            "admitted": accept,
        }))
    }

    fn invite(&self) -> Result<GardenInvite, String> {
        let state = &self.ledger.state;
        let host = state.host();
        let mut peers: Vec<String> = Vec::new();
        let ordered = state
            .validators
            .get(&host)
            .into_iter()
            .chain(state.validators.values().filter(|v| v.key != host));
        for validator in ordered {
            let verified = validator.key == host
                || validator.key == self.me
                || self.verified_peers.contains(&validator.key);
            let rejected = self
                .rejected_addresses
                .contains(&(validator.key, validator.address.clone()));
            if validator.status != GardenValidatorStatus::Left
                && validator.status != GardenValidatorStatus::Waiting
                && verified
                && !rejected
                && validator_dial_address(&validator.address, &validator.key).is_ok()
                && !peers.contains(&validator.address)
            {
                peers.push(validator.address.clone());
            }
        }
        for seed in &self.seeds {
            if !peers.contains(seed) {
                peers.push(seed.clone());
            }
        }
        // The list is already in the order that matters: the host first,
        // then the validators this node has verified, then the seeds. The
        // record keeps as many of them as it has room for, so a Garden that
        // outgrows the record still hands out an invite that works.
        let peers = fit_peers(peers);
        GardenInvite::new(&state.genesis, self.token, peers)
    }

    async fn publish(
        &mut self,
        kind: GardenContentKind,
        bytes: Vec<u8>,
        mime: String,
        caption: String,
    ) -> Result<Value, String> {
        match self.observed_status() {
            DomainStatus::Active => {}
            DomainStatus::Frozen => {
                return Err(
                    "garden is frozen: the host is away, so there is no new transaction".into(),
                )
            }
            DomainStatus::Retired => return Err("garden is retired".into()),
        }
        if self.leaving.is_some() {
            return Err("this node is leaving the Garden".into());
        }
        if !self.ledger.state.is_active(&self.me) {
            return Err("this node is not an active validator of the Garden yet".into());
        }
        let size = u32::try_from(bytes.len()).map_err(|_| "object is too large".to_string())?;
        let content_id = crate::storage::content_id::ContentId::of(&bytes).0;
        let tx_kind = GardenTxKind::Publish {
            kind,
            content_id,
            size,
            mime,
            caption,
        };
        let probe = GardenTx {
            chain_id: self.chain_id(),
            sender: self.me,
            nonce: self.ledger.state.next_nonce(&self.me),
            kind: tx_kind.clone(),
        }
        .sign(&self.key)?;
        self.ledger.state.check_tx(&probe)?;
        let duplicate = self.has_pending(|pending| {
            matches!(pending, GardenTxKind::Publish { content_id: id, .. } if *id == content_id)
        });
        if duplicate {
            return Err("this content is already waiting to be published".into());
        }
        let candidate = GardenTx {
            chain_id: self.chain_id(),
            sender: self.me,
            nonce: self.my_next_nonce,
            kind: tx_kind.clone(),
        }
        .sign(&self.key)?;
        if !self.can_admit_tx(&candidate) {
            return Err("this node has too many pending transactions".into());
        }
        self.store.put(&bytes)?;
        // Hand the bytes to the validators that will hold them before the
        // chain names them, so a sudden departure of this node loses nothing.
        let holders = self.holders(&content_id);
        let targets: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, key)| holders.contains(key))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in targets {
            self.send(
                peer,
                GardenRequest::PutObject {
                    bytes: bytes.clone(),
                },
                TAG_IGNORE,
            )
            .await;
        }
        let tx_id = self.submit(tx_kind).await?;
        Ok(json!({
            "tx_id": hex::encode(tx_id),
            "content_id": hex::encode(content_id),
            "kind": kind.label(),
            "size": size,
        }))
    }

    fn trace(&self, tx_id: &Hash32) -> Result<Value, String> {
        let state = &self.ledger.state;
        // A content id stands for its first publication.
        let by_content = state
            .publications(tx_id)
            .min_by_key(|object| (object.height, object.author))
            .map(|object| object.tx_id);
        let tx_id = by_content.as_ref().unwrap_or(tx_id);
        let Some((height, index)) = self.ledger.locate(tx_id) else {
            let pending = self.mempool.values().any(|tx| tx.id() == *tx_id);
            if pending {
                return Ok(json!({ "tx_id": hex::encode(tx_id), "stage": "pending" }));
            }
            return Err("this transaction is not known to the Garden".into());
        };
        let (commit, electorate) = self
            .ledger
            .commit_at(height)
            .ok_or_else(|| "this node does not hold that block".to_string())?;
        let tx = commit
            .block
            .txs
            .get(index as usize)
            .ok_or_else(|| "transaction index is out of range".to_string())?;
        let name_of = |key: &GardenKey| name_in(state, key);
        let header = &commit.block.header;
        let signers: Vec<Value> = commit
            .votes
            .iter()
            .map(|vote| {
                json!({
                    "validator": hex::encode(vote.voter),
                    "name": name_of(&vote.voter),
                    "signature": hex::encode(&vote.signature),
                })
            })
            .collect();
        let content = match &tx.tx.kind {
            GardenTxKind::Publish { content_id, .. } => Value::String(hex::encode(content_id)),
            _ => Value::Null,
        };
        Ok(json!({
            "tx_id": hex::encode(tx_id),
            "stage": "final",
            "transaction": {
                "kind": tx.tx.kind.label(),
                "sender": hex::encode(tx.tx.sender),
                "sender_name": name_of(&tx.tx.sender),
                "nonce": tx.tx.nonce,
                "content_id": content,
                "signature": hex::encode(&tx.signature),
            },
            "block": {
                "height": header.height,
                "round": header.round,
                "index": index,
                "hash": hex::encode(header.hash()),
                "parent_hash": hex::encode(header.parent_hash),
                "proposer": hex::encode(header.proposer),
                "proposer_name": name_of(&header.proposer),
                "timestamp_ms": header.timestamp_ms,
                "state_root": hex::encode(header.state_root),
                "tx_root": hex::encode(header.tx_root),
            },
            "finality": {
                "electorate": electorate.len(),
                "needed": quorum(electorate.len()),
                "signers": signers,
            },
            "budlum": {
                "domain_id": garden_domain_id(self.chain_id()),
                "reported": self.link.is_some() && header.height <= self.reported,
            },
        }))
    }

    fn feed(&self, limit: usize) -> Value {
        let state = &self.ledger.state;
        let mut entries: Vec<_> = state.objects.values().collect();
        entries.sort_by_key(|object| {
            let index = self
                .ledger
                .locate(&object.tx_id)
                .map_or(0, |(_, index)| index);
            std::cmp::Reverse((object.height, index))
        });
        let items: Vec<Value> = entries
            .into_iter()
            .take(limit.clamp(1, MAX_FEED))
            .map(|object| feed_entry(state, object, self.store.contains(&object.content_id)))
            .collect();
        json!({ "total": state.objects.len(), "items": items })
    }

    async fn status(&self) -> Value {
        let state = &self.ledger.state;
        let limits = self.limits();
        let presence_limit = millis(limits.host_timeout_ms);
        let connected: BTreeSet<GardenKey> = self.peers.values().copied().collect();
        let validators: Vec<Value> = state
            .validators
            .values()
            .map(|v| {
                json!({
                    "key": hex::encode(v.key),
                    "name": v.name,
                    "address": v.address,
                    "status": v.status.label(),
                    "host": v.key == state.host(),
                    "present": !self.silent_for(&v.key, presence_limit),
                    "connected": v.key == self.me || connected.contains(&v.key),
                    "joined_height": v.joined_height,
                    "published_bytes": state.published.get(&v.key).copied().unwrap_or(0),
                })
            })
            .collect();
        let genesis_hash = state.genesis.hash();
        let budlum = match &self.link {
            Some(link) => link
                .view_for_genesis(self.chain_id(), genesis_hash)
                .await
                .map_or_else(
                    || json!({ "linked": false, "error": self.budlum_error }),
                    |view| budlum_record(&view, self.budlum_error.as_deref()),
                ),
            None => json!({ "linked": false, "error": Value::Null }),
        };
        json!({
            "chain_id": format!("{:016x}", self.chain_id()),
            "genesis_hash": hex::encode(state.genesis.hash()),
            "title": state.genesis.title,
            "status": status_label(self.observed_status()),
            "chain_status": status_label(state.status),
            "host_present": self.host_present(),
            "height": state.height,
            "last_hash": hex::encode(state.last_hash),
            "me": {
                "key": hex::encode(self.me),
                "name": self.name,
                "host": self.is_host(),
                "address": self.address,
                "member": state
                    .validators
                    .get(&self.me)
                    .map(|v| v.status.label())
                    .or_else(|| {
                        (self.remote_admission == Some(GardenAdmissionState::Waiting))
                            .then_some("Waiting")
                    }),
                "turned_away": self.turned_away,
                "leaving": self.leaving.is_some(),
            },
            "validators": validators,
            "active_validators": state.active().len(),
            "waiting_for_host": state.waiting(),
            "admission": limits.admission.label(),
            "connected_peers": self.peers.len(),
            "pending_transactions": self.mempool.len(),
            "objects": state.objects.len(),
            "objects_wanted_here": self.wanted.len(),
            "stored_object_bytes": self.store.total_bytes(),
            "limits": {
                "max_validators": limits.max_validators,
                "max_object_bytes": limits.max_object_bytes,
                "max_block_txs": limits.max_block_txs,
                "max_sender_txs_per_block": limits.max_sender_txs_per_block,
                "round_ms": limits.round_ms,
                "presence_interval_ms": limits.presence_interval_ms,
                "host_timeout_ms": limits.host_timeout_ms,
                "suspend_after_ms": limits.suspend_after_ms,
                "max_published_bytes_per_validator": limits.max_published_bytes_per_validator,
            },
            "budlum": budlum,
        })
    }

    async fn begin_leave(&mut self, reply: oneshot::Sender<GardenLeaveOutcome>) {
        if self.leaving.is_some() {
            // The first request owns the answer; this one is dropped and the
            // caller sees that the node stopped.
            return;
        }
        let state = &self.ledger.state;
        let member = matches!(
            state.validators.get(&self.me).map(|v| v.status),
            Some(GardenValidatorStatus::Active | GardenValidatorStatus::Suspended)
        );
        let can_finalize = member && state.status == DomainStatus::Active && self.host_present();
        let round = millis(self.limits().round_ms);
        let mut leaving = Leaving {
            deadline: Instant::now(),
            tx_id: None,
            sealed: None,
            reply,
        };
        if can_finalize {
            // Drop anything of this node that is still pending, so the
            // departure is the next thing the chain sees from it.
            self.mempool.retain(|(sender, _), _| *sender != self.me);
            self.my_next_nonce = self.ledger.state.next_nonce(&self.me);
            if let Ok(tx_id) = self.submit(GardenTxKind::Leave).await {
                leaving.tx_id = Some(tx_id);
                leaving.deadline =
                    Instant::now() + round.saturating_mul(8).max(Duration::from_secs(4));
            }
        }
        self.leaving = Some(leaving);
        if !can_finalize {
            self.finish_leave().await;
        }
    }

    /// Sign the departure again when the first one can no longer enter a
    /// block. That happens when a block this node had not seen yet used the
    /// same nonce. The deadline stays where it was.
    async fn renew_departure(&mut self) {
        let Some(tx_id) = self.leaving.as_ref().and_then(|leaving| leaving.tx_id) else {
            return;
        };
        let state = &self.ledger.state;
        let waiting = self.mempool.values().any(|tx| tx.id() == tx_id);
        let member = state
            .validators
            .get(&self.me)
            .is_some_and(|v| v.status == GardenValidatorStatus::Active);
        if waiting
            || !member
            || self.ledger.locate(&tx_id).is_some()
            || state.status != DomainStatus::Active
        {
            return;
        }
        self.mempool.retain(|(sender, _), _| *sender != self.me);
        self.my_next_nonce = self.ledger.state.next_nonce(&self.me);
        if let Ok(renewed) = self.submit(GardenTxKind::Leave).await {
            if let Some(leaving) = self.leaving.as_mut() {
                leaving.tx_id = Some(renewed);
            }
        }
    }

    /// Finish a departure whose block is final, once that block is on no
    /// outbox any more: every connected peer acknowledged it, or is gone.
    async fn finish_when_delivered(&mut self) {
        let Some(height) = self.leaving.as_ref().and_then(|leaving| leaving.sealed) else {
            return;
        };
        let in_flight = self.gossip_in_flight.values().any(|h| *h >= height);
        let queued = self
            .outbox
            .values()
            .flatten()
            .any(|item| final_height(item).is_some_and(|h| h >= height));
        if !in_flight && !queued {
            self.finish_leave().await;
        }
    }

    /// End this node's part: settle the Budlum record, wipe the content and
    /// close the swarm.
    async fn finish_leave(&mut self) {
        let Some(leaving) = self.leaving.take() else {
            return;
        };
        self.report_to_budlum().await;
        let retired = self.ledger.state.status == DomainStatus::Retired;
        let chain_id = self.chain_id();
        if let Some(link) = &self.link {
            let settled = if retired {
                link.retire(chain_id, self.me).await
            } else {
                link.move_domain(chain_id, self.me, DomainStatus::Frozen)
                    .await
            };
            if let Err(e) = settled {
                tracing::warn!(error = %e, "garden domain status could not be settled");
            }
        }
        // The fallback is reached when this node can no longer name a
        // dialable validator, so it falls back to the seeds it started
        // from. It builds the record directly, which means it does not go
        // through `check`, so the peer list is cut to the record's budget
        // here. Without that cut this one path could hand out a record
        // longer than the ceiling every other path enforces, and the
        // leaver's parting invite would be the one invite nobody can read.
        let invite = self.invite().unwrap_or_else(|_| GardenInvite {
            chain_id,
            genesis_hash: self.ledger.state.genesis.hash(),
            token: self.token,
            peers: fit_peers(self.seeds.clone()),
        });
        let outcome = GardenLeaveOutcome {
            chain_id,
            retired,
            invite,
            height: self.ledger.state.height,
        };
        self.shutdown().await;
        let _ = leaving.reply.send(outcome);
    }

    async fn shutdown(&mut self) {
        if let Err(e) = self.store.wipe() {
            tracing::warn!(error = %e, "garden content could not be wiped");
        }
        let _ = self.net.send(NetCommand::Shutdown).await;
        self.stopped = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(name: &str, listen: &str) -> GardenNodeConfig {
        GardenNodeConfig {
            name: name.into(),
            listen: listen.into(),
            announce: None,
            content_dir: None,
        }
    }

    async fn host() -> GardenHandle {
        spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits::testnet_default(),
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap()
    }

    /// A bare swarm that dials the host of `invite`.
    async fn stranger(invite: &GardenInvite) -> (GardenNet, KeyPair, PeerId) {
        let secret = random_bytes();
        let key = KeyPair::from_seed(&secret).unwrap();
        let mut swarm = net::start(secret, "/ip4/127.0.0.1/tcp/0").await.unwrap();
        let address = invite.peers.first().unwrap().parse().unwrap();
        swarm
            .commands
            .send(NetCommand::Dial(address))
            .await
            .unwrap();
        loop {
            if let Some(NetEvent::Connected(peer)) = swarm.events.recv().await {
                return (swarm, key, peer);
            }
        }
    }

    async fn ask(swarm: &mut GardenNet, peer: PeerId, request: GardenRequest) -> GardenResponse {
        swarm
            .commands
            .send(NetCommand::Send {
                peer,
                request,
                tag: 77,
            })
            .await
            .unwrap();
        loop {
            match swarm.events.recv().await.unwrap() {
                NetEvent::Response {
                    tag: 77, response, ..
                } => return response.unwrap(),
                NetEvent::Request { channel, .. } => {
                    // The host greets back; a refusal is all it gets here.
                    swarm
                        .commands
                        .send(NetCommand::Respond {
                            channel,
                            response: GardenResponse::Refused("test peer".into()),
                        })
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    }

    fn refusal(response: GardenResponse) -> String {
        match response {
            GardenResponse::Refused(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn garden_node_that_stood_still_does_not_hold_the_others_as_silent() {
        let limits = GardenLimits::testnet_default();
        let window = millis(limits.suspend_after_ms);
        assert!(!stood_still(millis(limits.presence_interval_ms), &limits));
        assert!(!stood_still(
            (window / 2).checked_sub(Duration::from_millis(1)).unwrap(),
            &limits
        ));
        assert!(stood_still(window / 2, &limits));
        assert!(stood_still(window * 4, &limits));

        let asleep = Instant::now();
        let woke = asleep + window * 4;
        let (heard, never_heard, host) = ([1u8; 32], [2u8; 32], [9u8; 32]);
        let mut last_seen = BTreeMap::from([(heard, asleep), (host, asleep)]);
        let silent = |last_seen: &BTreeMap<GardenKey, Instant>, key: &GardenKey| {
            last_seen
                .get(key)
                .is_none_or(|seen| woke.duration_since(*seen) >= window)
        };
        assert!(silent(&last_seen, &heard));
        assert!(silent(&last_seen, &never_heard));

        forgive_silence(&mut last_seen, [heard, never_heard].into_iter(), woke);
        assert!(!silent(&last_seen, &heard));
        assert!(!silent(&last_seen, &never_heard));
        // The host is not in the list, so its clock still shows the silence.
        assert!(silent(&last_seen, &host));
    }

    #[tokio::test]
    async fn garden_host_needs_an_address_the_others_can_dial() {
        let refusal = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits::testnet_default(),
            },
            config("host", "/ip4/0.0.0.0/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .err()
        .unwrap();
        assert!(refusal.contains("can dial"), "{refusal}");

        // An address the others would pass over is not announced either.
        let mut low_port = config("host", "/ip4/0.0.0.0/tcp/0");
        low_port.announce = Some("/ip4/127.0.0.1/tcp/22".into());
        let refusal = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits::testnet_default(),
            },
            low_port,
            random_bytes(),
            None,
        )
        .await
        .err()
        .unwrap();
        assert!(refusal.contains("cannot be announced"), "{refusal}");

        let mut announced = config("host", "/ip4/0.0.0.0/tcp/0");
        announced.announce = Some("/ip4/127.0.0.1/tcp/4001".into());
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits::testnet_default(),
            },
            announced,
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        assert!(invite
            .peers
            .first()
            .unwrap()
            .starts_with("/ip4/127.0.0.1/tcp/4001/p2p/"));
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn garden_peer_without_the_invite_does_not_keep_its_connection() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 200,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, _, peer) = stranger(&invite).await;
        // The stranger keeps the connection busy, so no idle timer closes
        // it. Only the host can end it.
        let closed = tokio::time::timeout(Duration::from_secs(12), async {
            let mut pause = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    event = swarm.events.recv() => match event {
                        Some(NetEvent::Disconnected(gone)) if gone == peer => return true,
                        Some(NetEvent::Request { channel, .. }) => {
                            let _ = swarm
                                .commands
                                .send(NetCommand::Respond {
                                    channel,
                                    response: GardenResponse::Refused("test peer".into()),
                                })
                                .await;
                        }
                        Some(_) => {}
                        None => return false,
                    },
                    _ = pause.tick() => {
                        let _ = swarm
                            .commands
                            .send(NetCommand::Send {
                                peer,
                                request: GardenRequest::Gossip(Vec::new()),
                                tag: 78,
                            })
                            .await;
                    }
                }
            }
        })
        .await;
        assert_eq!(closed, Ok(true), "the stranger held its connection");
        handle.leave().await.unwrap();
    }

    /// A bare swarm that showed the invite to the host of `invite`.
    async fn guest(invite: &GardenInvite) -> (GardenNet, KeyPair, PeerId) {
        let (mut swarm, key, peer) = stranger(invite).await;
        let me = key.public_key_bytes();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        let answer = ask(&mut swarm, peer, hello).await;
        assert!(
            matches!(answer, GardenResponse::Welcome { .. }),
            "{answer:?}"
        );
        (swarm, key, peer)
    }

    /// The address of a door in front of `address`: whoever dials it reaches
    /// the same validator, but only after a wait. A peer behind it answers
    /// later than every other peer of an invite.
    async fn slow_door(address: &str) -> String {
        use libp2p::multiaddr::Protocol;
        let parsed: libp2p::Multiaddr = address.parse().unwrap();
        let mut port = 0;
        let mut id = None;
        for part in &parsed {
            match part {
                Protocol::Tcp(tcp) => port = tcp,
                Protocol::P2p(peer) => id = Some(peer),
                _ => {}
            }
        }
        let door = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let door_port = door.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = door.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    let target = ("127.0.0.1", port);
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        format!("/ip4/127.0.0.1/tcp/{door_port}/p2p/{}", id.unwrap())
    }

    /// A peer that answers every greeting with `greeting` and refuses
    /// everything else. Returns the address it announces.
    async fn crooked_peer(
        greeting: impl Fn(&GardenKey) -> GardenResponse + Send + 'static,
    ) -> String {
        let secret = random_bytes();
        let key = KeyPair::from_seed(&secret).unwrap().public_key_bytes();
        let mut swarm = net::start(secret, "/ip4/127.0.0.1/tcp/0").await.unwrap();
        let address = net::announced_address(&swarm.listen, &key).unwrap();
        tokio::spawn(async move {
            while let Some(event) = swarm.events.recv().await {
                if let NetEvent::Request {
                    request, channel, ..
                } = event
                {
                    let response = match request {
                        GardenRequest::Hello { .. } => greeting(&key),
                        _ => GardenResponse::Refused("nothing is served here".into()),
                    };
                    let _ = swarm
                        .commands
                        .send(NetCommand::Respond { channel, response })
                        .await;
                }
            }
        });
        address
    }

    /// Join with `invite` and wait until the Garden counts two validators.
    async fn join_as_second(invite: GardenInvite) {
        let guest = spawn(
            GardenEntry::Invite(invite),
            config("guest", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .expect("one peer of the invite ended the join");
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if guest.status().await.unwrap()["active_validators"] == 2 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the guest never became a validator");
    }

    /// Inviting is not a host privilege. Any seated validator produces a
    /// record for the same Garden, and someone joins with it.
    ///
    /// This matters for what a Garden is: the host's only standing power is
    /// liveness. If only the host could invite, a host who stepped away
    /// would close the door behind them, and the Garden would be the host's
    /// property rather than its members'.
    #[tokio::test]
    async fn garden_invite_any_validator() {
        let host_handle = host().await;
        let from_host = host_handle.invite().await.unwrap();

        let guest = spawn(
            GardenEntry::Invite(from_host.clone()),
            config("guest", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            while guest.status().await.unwrap()["active_validators"] != 2 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the guest never became a validator");

        // The guest is not the host, and it hands out a record of its own.
        assert_eq!(
            guest.status().await.unwrap()["me"]["host"],
            json!(false),
            "the guest must not be the host for this test to mean anything"
        );
        let from_guest = guest.invite().await.unwrap();

        // It names the same Garden, not a new one.
        assert_eq!(from_guest.chain_id, from_host.chain_id);
        assert_eq!(from_guest.genesis_hash, from_host.genesis_hash);
        assert_eq!(from_guest.token, from_host.token);

        // It is a record, so it obeys the record's rules. Both of these
        // refuse an oversized record, so a round trip through them is the
        // ceiling being enforced, checked as behaviour rather than against
        // a number copied out of the module that owns it.
        let link = from_guest.to_link();
        assert_eq!(GardenInvite::parse(&link).unwrap(), from_guest);
        assert_eq!(from_guest.qr_content().unwrap(), link);

        // And it works: a third node joins on the guest's invite alone.
        let latecomer = spawn(
            GardenEntry::Invite(from_guest),
            config("latecomer", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .expect("a validator's invite did not admit anyone");
        tokio::time::timeout(Duration::from_secs(20), async {
            while latecomer.status().await.unwrap()["active_validators"] != 3 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the latecomer never became a validator");

        latecomer.leave().await.unwrap();
        guest.leave().await.unwrap();
        host_handle.leave().await.unwrap();
    }

    /// One peer of the invite refuses. The join goes on with the next one:
    /// every validator stands in the invites the others hand out, so a
    /// single refusal must not be the answer of the Garden.
    #[tokio::test]
    async fn garden_join_goes_on_when_one_invite_peer_refuses() {
        let handle = host().await;
        let mut invite = handle.invite().await.unwrap();
        let refuser =
            crooked_peer(|_| GardenResponse::Refused("no room for more peers".into())).await;
        // The host answers after the refusal.
        invite.peers = vec![refuser, slow_door(&invite.peers[0]).await];
        join_as_second(invite).await;
    }

    /// One peer of the invite welcomes the node and then serves no chain.
    /// The join takes the chain from the next peer.
    #[tokio::test]
    async fn garden_join_goes_on_when_one_invite_peer_serves_no_chain() {
        let handle = host().await;
        let mut invite = handle.invite().await.unwrap();
        // The genesis, the way any holder of the invite learns it.
        let (mut probe, probe_key, peer) = stranger(&invite).await;
        let me = probe_key.public_key_bytes();
        let invite_key = invite_keypair(&invite.token).unwrap();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_key
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        let GardenResponse::Welcome { genesis, .. } = ask(&mut probe, peer, hello).await else {
            panic!("the host did not welcome a holder of the invite");
        };
        let chain_id = invite.chain_id;
        let empty = crooked_peer(move |key| GardenResponse::Welcome {
            genesis: genesis.clone(),
            height: 0,
            key: *key,
            invite_signature: invite_key.sign(&join_message(chain_id, key)).to_vec(),
        })
        .await;
        invite.peers = vec![empty, slow_door(&invite.peers[0]).await];
        join_as_second(invite).await;
    }

    /// A Garden of four that the test can lie to. The test holds the key of
    /// one validator, so it speaks as a leader, and it is a peer of another
    /// validator, the witness, so it hears what the witness signs.
    struct LiarRoom {
        _nodes: Vec<GardenHandle>,
        swarm: GardenNet,
        peer: PeerId,
        ledger: GardenLedger,
        liar: KeyPair,
        target: GardenKey,
        witness: GardenKey,
        signed_by_witness: Vec<Hash32>,
    }

    impl LiarRoom {
        async fn open() -> Self {
            let mut limits = GardenLimits::testnet_default();
            limits.round_ms = 200;
            limits.presence_interval_ms = 100;
            let handle = spawn(
                GardenEntry::Create {
                    title: "Room".into(),
                    limits,
                },
                config("host", "/ip4/127.0.0.1/tcp/0"),
                random_bytes(),
                None,
            )
            .await
            .unwrap();
            let invite = handle.invite().await.unwrap();
            let liar_secret = random_bytes();
            let liar = KeyPair::from_seed(&liar_secret).unwrap();
            let mut nodes = Vec::new();
            for (name, secret) in [
                ("target", random_bytes()),
                ("witness", random_bytes()),
                ("liar", liar_secret),
            ] {
                let guest = spawn(
                    GardenEntry::Invite(invite.clone()),
                    config(name, "/ip4/127.0.0.1/tcp/0"),
                    secret,
                    None,
                )
                .await
                .unwrap();
                nodes.push(guest);
            }
            nodes.push(handle);
            tokio::time::timeout(Duration::from_mins(1), async {
                loop {
                    let mut settled = true;
                    for node in &nodes {
                        let status = node.status().await.unwrap();
                        settled &= status["active_validators"] == 4
                            && status["pending_transactions"] == 0
                            && status["connected_peers"].as_u64() >= Some(3);
                    }
                    if settled {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("the four validators never settled");

            // A peer of the witness that holds the invite and the chain. What
            // the witness signs it says to every peer, so it is heard here.
            let mut to_witness = invite.clone();
            let address = nodes[1].status().await.unwrap()["me"]["address"].clone();
            to_witness.peers = vec![address.as_str().unwrap().to_string()];
            let (swarm, peer, ledger) = peer_with_the_chain(&to_witness).await;
            let key_of = |name: &str| {
                let named = ledger.state.validators.values().find(|v| v.name == name);
                named.unwrap().key
            };
            let (target, witness) = (key_of("target"), key_of("witness"));
            Self {
                _nodes: nodes,
                swarm,
                peer,
                ledger,
                liar,
                target,
                witness,
                signed_by_witness: Vec::new(),
            }
        }

        /// The first rounds of the next height that the liar leads.
        fn rounds(&self) -> Vec<u64> {
            let liar = self.liar.public_key_bytes();
            (0..64)
                .filter(|round| self.ledger.state.leader(*round) == Some(liar))
                .take(2)
                .collect()
        }

        /// A block of the liar with one transaction of its own.
        fn propose(&self, round: u64, kind: GardenTxKind, timestamp_ms: u64) -> GardenBlock {
            let state = &self.ledger.state;
            let liar = self.liar.public_key_bytes();
            let tx = GardenTx {
                chain_id: state.chain_id(),
                sender: liar,
                nonce: state.next_nonce(&liar),
                kind,
            }
            .sign(&self.liar)
            .unwrap();
            let txs = vec![tx];
            let (header, _) = state.build_header(&txs, liar, round, timestamp_ms).unwrap();
            let proposer_signature = self.liar.sign(&header.hash()).to_vec();
            GardenBlock {
                header,
                txs,
                proposer_signature,
            }
        }

        /// Show `block` to the witness and note what the witness signs in
        /// the three seconds after it.
        async fn show(&mut self, block: &GardenBlock) {
            let gossip = GardenRequest::Gossip(vec![GardenGossip::Proposal(block.clone())]);
            self.swarm
                .commands
                .send(NetCommand::Send {
                    peer: self.peer,
                    request: gossip,
                    tag: 78,
                })
                .await
                .unwrap();
            let until = tokio::time::Instant::now() + Duration::from_secs(3);
            while let Ok(Some(event)) =
                tokio::time::timeout_at(until, self.swarm.events.recv()).await
            {
                let NetEvent::Request {
                    request, channel, ..
                } = event
                else {
                    continue;
                };
                if let GardenRequest::Gossip(items) = request {
                    for item in items {
                        if let GardenGossip::Vote(vote) = item {
                            if vote.voter == self.witness {
                                self.signed_by_witness.push(vote.block_hash);
                            }
                        }
                    }
                }
                let response = GardenResponse::Ack;
                self.swarm
                    .commands
                    .send(NetCommand::Respond { channel, response })
                    .await
                    .unwrap();
            }
        }
    }

    /// A bare swarm that showed the invite to the first peer of `invite` and
    /// read its whole chain.
    async fn peer_with_the_chain(invite: &GardenInvite) -> (GardenNet, PeerId, GardenLedger) {
        let (mut swarm, peer_key, peer) = stranger(invite).await;
        let me = peer_key.public_key_bytes();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        let GardenResponse::Welcome { genesis, .. } = ask(&mut swarm, peer, hello).await else {
            panic!("the peer did not welcome a holder of the invite");
        };
        let mut ledger = GardenLedger::new(*genesis).unwrap();
        loop {
            let request = GardenRequest::GetCommits {
                from_height: ledger.state.height + 1,
                max: MAX_SYNC_COMMITS,
            };
            let GardenResponse::Commits(commits) = ask(&mut swarm, peer, request).await else {
                panic!("the peer did not serve its chain");
            };
            if commits.is_empty() {
                break;
            }
            for commit in commits {
                ledger.append(commit).unwrap();
            }
        }
        (swarm, peer, ledger)
    }

    fn message(id: u8) -> GardenTxKind {
        GardenTxKind::Publish {
            kind: GardenContentKind::Message,
            content_id: [id; 32],
            size: 5,
            mime: "text/plain".into(),
            caption: String::new(),
        }
    }

    /// A report is the word of one leader. The votes are the word of the
    /// others, and the validators a block reports have no vote on it. So a
    /// validator that still hears a reported validator does not sign: with
    /// its vote the leader would set the quorum of its own block.
    #[tokio::test]
    async fn garden_validator_does_not_sign_away_a_validator_it_still_hears() {
        let mut room = LiarRoom::open().await;
        let rounds = room.rounds();
        let target = room.target;
        let false_report = room.propose(rounds[0], GardenTxKind::Suspend { target }, now_ms());
        let honest = room.propose(rounds[1], message(7), now_ms());
        room.show(&false_report).await;
        room.show(&honest).await;
        // The honest block shows that the witness votes and is heard here.
        assert!(
            room.signed_by_witness.contains(&honest.hash()),
            "the witness was not heard voting at all"
        );
        assert!(
            !room.signed_by_witness.contains(&false_report.hash()),
            "the witness signed a block that reports a validator it hears"
        );
    }

    /// The state machine reads no clock, so the timestamp of a block is what
    /// its leader wrote. A vote is cast by a node that has a clock: it does
    /// not sign a block dated ahead of it. The host signs every block, so
    /// one leader cannot move the chain clock to a time nobody has reached.
    #[tokio::test]
    async fn garden_validator_does_not_sign_a_block_dated_ahead_of_its_clock() {
        let mut room = LiarRoom::open().await;
        let rounds = room.rounds();
        let ahead = now_ms() + MAX_TIMESTAMP_AHEAD_MS + 60_000;
        let early = room.propose(rounds[0], message(7), ahead);
        assert_eq!(early.header.timestamp_ms, ahead);
        let honest = room.propose(rounds[1], message(8), now_ms());
        room.show(&early).await;
        room.show(&honest).await;
        assert!(
            room.signed_by_witness.contains(&honest.hash()),
            "the witness was not heard voting at all"
        );
        assert!(
            !room.signed_by_witness.contains(&early.hash()),
            "the witness signed a block dated ahead of its clock"
        );
    }

    /// A publication is charged by the size it declares, and the state
    /// machine never sees the bytes. So a node keeps bytes for a publication
    /// only when they have the declared size. Bytes of another size that a
    /// peer deposited stay what they were before the publication: a deposit
    /// that the next deposits of the same peer push out. Bytes of another
    /// size that the node fetched as a holder are not kept at all.
    #[tokio::test]
    async fn garden_publication_that_understates_its_size_does_not_keep_its_bytes() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 200,
                    suspend_after_ms: 600_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;
        let me = key.public_key_bytes();
        let sign = |nonce: u64, kind: GardenTxKind| {
            GardenTx {
                chain_id: invite.chain_id,
                sender: me,
                nonce,
                kind,
            }
            .sign(&key)
            .unwrap()
        };
        let join = sign(
            0,
            GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &me))
                    .to_vec(),
            },
        );
        let said = ask(
            &mut swarm,
            peer,
            GardenRequest::Gossip(vec![GardenGossip::Tx(join)]),
        )
        .await;
        assert!(matches!(said, GardenResponse::Ack), "{said:?}");
        let mut joined = false;
        for _ in 0..200 {
            if handle.status().await.unwrap()["active_validators"] == json!(2) {
                joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(joined, "guest did not join in time");

        // Two deposits, then one publication for each. The first says its
        // bytes are one byte long; the second says the truth.
        let heavy = vec![7u8; 10_000];
        let fair = vec![9u8; 10_000];
        // A third publication understates its size too, and nobody deposits
        // its bytes: the host asks for them as a holder.
        let pulled = vec![5u8; 10_000];
        let id_of = |bytes: &[u8]| crate::storage::content_id::ContentId::of(bytes).0;
        for bytes in [&heavy, &fair] {
            let put = GardenRequest::PutObject {
                bytes: bytes.clone(),
            };
            assert!(matches!(
                ask(&mut swarm, peer, put).await,
                GardenResponse::Ack
            ));
        }
        let publish = |nonce: u64, bytes: &[u8], size: u32| {
            sign(
                nonce,
                GardenTxKind::Publish {
                    kind: GardenContentKind::Message,
                    content_id: id_of(bytes),
                    size,
                    mime: "text/plain".into(),
                    caption: String::new(),
                },
            )
        };
        let txs = vec![
            GardenGossip::Tx(publish(1, &heavy, 1)),
            GardenGossip::Tx(publish(2, &fair, 10_000)),
            GardenGossip::Tx(publish(3, &pulled, 1)),
        ];
        swarm
            .commands
            .send(NetCommand::Send {
                peer,
                request: GardenRequest::Gossip(txs),
                tag: 78,
            })
            .await
            .unwrap();
        // The guest is a validator: the host finalizes nothing without its
        // vote, so the test votes for what the host proposes. It also serves
        // the bytes nobody deposited when the host asks for them.
        let until = tokio::time::Instant::now() + Duration::from_mins(1);
        loop {
            let status = handle.status().await.unwrap();
            if status["objects"] == json!(3) && status["objects_wanted_here"] == json!(0) {
                break;
            }
            let wait = tokio::time::Instant::now() + Duration::from_millis(100);
            let Ok(Some(event)) = tokio::time::timeout_at(wait, swarm.events.recv()).await else {
                assert!(
                    tokio::time::Instant::now() < until,
                    "the publications were not finalized and settled: {status}"
                );
                continue;
            };
            let NetEvent::Request {
                request, channel, ..
            } = event
            else {
                continue;
            };
            let (response, votes) = match request {
                GardenRequest::GetObject { content_id, .. } => {
                    let found = (content_id == id_of(&pulled)).then(|| pulled.clone());
                    (GardenResponse::Object(found), Vec::new())
                }
                GardenRequest::Gossip(items) => {
                    let votes: Vec<GardenVote> = items
                        .into_iter()
                        .filter_map(|item| match item {
                            GardenGossip::Proposal(block) => {
                                Some(GardenVote::sign(&block.header, &key))
                            }
                            _ => None,
                        })
                        .collect();
                    (GardenResponse::Ack, votes)
                }
                _ => (GardenResponse::Ack, Vec::new()),
            };
            swarm
                .commands
                .send(NetCommand::Respond { channel, response })
                .await
                .unwrap();
            for vote in votes {
                swarm
                    .commands
                    .send(NetCommand::Send {
                        peer,
                        request: GardenRequest::Gossip(vec![GardenGossip::Vote(vote)]),
                        tag: 79,
                    })
                    .await
                    .unwrap();
            }
        }

        // The peer goes on depositing. Its oldest deposits make room.
        for filler in 0..(MAX_UNREFERENCED_PER_PEER + 2) {
            let put = GardenRequest::PutObject {
                bytes: format!("filler-{filler}").into_bytes(),
            };
            assert!(matches!(
                ask(&mut swarm, peer, put).await,
                GardenResponse::Ack
            ));
        }
        let mut held = Vec::new();
        for bytes in [&heavy, &fair, &pulled] {
            let get = GardenRequest::GetObject {
                content_id: id_of(bytes),
                relay: false,
            };
            match ask(&mut swarm, peer, get).await {
                GardenResponse::Object(found) => held.push(found.is_some()),
                other => panic!("expected an object answer, got {other:?}"),
            }
        }
        assert!(
            held[1],
            "the host dropped bytes of the size their publication declares"
        );
        assert!(
            !held[0],
            "the host keeps 10000 deposited bytes for a publication that was charged for one"
        );
        assert!(
            !held[2],
            "the host fetched and keeps 10000 bytes for a publication that was charged for one"
        );
        handle.leave().await.unwrap();
    }

    /// A validator that was reported absent never signed a departure. When
    /// the others end the Garden, that takes nothing from it: it keeps what
    /// it holds, readable, until it leaves itself. Every block needs only
    /// the host once the others are reported, so without this the host could
    /// delete the Garden from the disk of a validator that is still there.
    #[tokio::test]
    async fn garden_end_does_not_wipe_a_validator_that_never_left() {
        let host_secret = random_bytes();
        let host_key = KeyPair::from_seed(&host_secret).unwrap();
        let limits = GardenLimits {
            round_ms: 200,
            presence_interval_ms: 100,
            suspend_after_ms: 600_000,
            ..GardenLimits::testnet_default()
        };
        let host = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits,
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            host_secret,
            None,
        )
        .await
        .unwrap();
        let invite = host.invite().await.unwrap();
        let stays = spawn(
            GardenEntry::Invite(invite.clone()),
            config("stays", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let kept = b"mine until I leave".to_vec();
        let content_id = crate::storage::content_id::ContentId::of(&kept).0;
        tokio::time::timeout(Duration::from_mins(1), async {
            let mut published = false;
            loop {
                let status = stays.status().await.unwrap();
                if !published && status["me"]["member"] == json!("Active") {
                    let message = GardenContentKind::Message;
                    let said = stays
                        .publish(message, kept.clone(), "text/plain".into(), String::new())
                        .await;
                    published = said.is_ok();
                }
                if status["objects"] == json!(1) && status["pending_transactions"] == json!(0) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the publication was not finalized");

        // The test speaks with the key of the host to the validator that
        // stays: one block reports it absent, the next one is the host's
        // own departure. The host is the whole electorate of both.
        let mut to_stays = invite.clone();
        let address = stays.status().await.unwrap()["me"]["address"].clone();
        to_stays.peers = vec![address.as_str().unwrap().to_string()];
        let (swarm, peer, mut ledger) = peer_with_the_chain(&to_stays).await;
        let host_id = host_key.public_key_bytes();
        let target = ledger
            .state
            .validators
            .values()
            .find(|v| v.name == "stays")
            .unwrap()
            .key;
        let mut commits = Vec::new();
        for kind in [GardenTxKind::Suspend { target }, GardenTxKind::Leave] {
            let state = &ledger.state;
            let round = (0..8)
                .find(|round| state.leader(*round) == Some(host_id))
                .unwrap();
            let tx = GardenTx {
                chain_id: state.chain_id(),
                sender: host_id,
                nonce: state.next_nonce(&host_id),
                kind,
            }
            .sign(&host_key)
            .unwrap();
            let txs = vec![tx];
            let (header, _) = state.build_header(&txs, host_id, round, now_ms()).unwrap();
            let commit = GardenCommit {
                votes: vec![GardenVote::sign(&header, &host_key)],
                block: GardenBlock {
                    proposer_signature: host_key.sign(&header.hash()).to_vec(),
                    header,
                    txs,
                },
            };
            ledger.append(commit.clone()).unwrap();
            commits.push(GardenGossip::Commit(commit));
        }
        assert_eq!(ledger.state.status, DomainStatus::Retired);
        swarm
            .commands
            .send(NetCommand::Send {
                peer,
                request: GardenRequest::Gossip(commits),
                tag: 78,
            })
            .await
            .unwrap();

        // The Garden is over on the chain of the validator that stays, and
        // the validator is still there with its content.
        let mut seen = None;
        for _ in 0..100 {
            match stays.status().await {
                Ok(status) if status["chain_status"] == json!("Retired") => {
                    seen = Some(status);
                    break;
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(_) => break,
            }
        }
        let status = seen.expect("the node stopped when the others ended the Garden");
        assert_eq!(status["me"]["member"], json!("Suspended"));
        // Several rounds later nothing has changed.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            stays.resolve(content_id).await,
            Ok(kept),
            "the end of the Garden took the content from a validator that never left"
        );
        assert_eq!(
            stays.status().await.unwrap()["pending_transactions"],
            json!(0)
        );
        // Its own departure is what clears its disk.
        let left = stays.leave().await.unwrap();
        assert!(left.retired);
    }

    /// One peer cannot push the pending content of another peer out of a
    /// node: content waits there so that it survives its publisher.
    #[tokio::test]
    async fn garden_deposits_of_one_peer_do_not_evict_the_deposits_of_another() {
        let handle = host().await;
        let invite = handle.invite().await.unwrap();
        let (mut first, _, peer) = guest(&invite).await;
        let (mut second, _, _) = guest(&invite).await;

        let kept = b"waits for its block".to_vec();
        let content_id = crate::storage::content_id::ContentId::of(&kept).0;
        let put = GardenRequest::PutObject {
            bytes: kept.clone(),
        };
        assert!(matches!(
            ask(&mut first, peer, put).await,
            GardenResponse::Ack
        ));
        for filler in 0..(MAX_UNREFERENCED_OBJECTS as u32 + 8) {
            let put = GardenRequest::PutObject {
                bytes: filler.to_be_bytes().to_vec(),
            };
            assert!(matches!(
                ask(&mut second, peer, put).await,
                GardenResponse::Ack
            ));
        }
        let get = GardenRequest::GetObject {
            content_id,
            relay: false,
        };
        match ask(&mut first, peer, get).await {
            GardenResponse::Object(found) => {
                assert_eq!(found, Some(kept), "another peer evicted the deposit");
            }
            other => panic!("expected the object, got {other:?}"),
        }
    }

    /// An absence report is the leader's own line in its own block. One that
    /// arrives as gossip is not kept: it could never be applied, and while
    /// the Garden does not run it would wait in the pool and be passed on.
    #[tokio::test]
    async fn garden_absence_report_from_the_network_is_not_pooled() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;
        let report = GardenTx {
            chain_id: invite.chain_id,
            sender: key.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Suspend { target: [7u8; 32] },
        }
        .sign(&key)
        .unwrap();
        let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(report)]);
        assert!(matches!(
            ask(&mut swarm, peer, gossip).await,
            GardenResponse::Ack
        ));
        let status = handle.status().await.unwrap();
        assert_eq!(
            status["pending_transactions"], 0,
            "an absence report from the network waits in the pool"
        );
    }

    /// A validator whose address accepts and never answers is not dialed on
    /// every round: each dial is a socket, and the address is chosen by
    /// whoever joined.
    #[tokio::test]
    async fn garden_validator_that_never_answers_is_not_dialed_every_round() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 200,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;
        let me = key.public_key_bytes();

        // The address this validator announces is a socket that accepts and
        // says nothing.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = silent.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                held.push(socket);
            }
            let _kept_open = held.len();
        });
        let join = GardenTx {
            chain_id: invite.chain_id,
            sender: me,
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "silent".into(),
                address: format!(
                    "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                    net::peer_id_of(&me).unwrap()
                ),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &me))
                    .to_vec(),
            },
        }
        .sign(&key)
        .unwrap();
        let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(join)]);
        assert!(matches!(
            ask(&mut swarm, peer, gossip).await,
            GardenResponse::Ack
        ));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = handle.status().await.unwrap();
                if status["active_validators"] == 2 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the join never became final");

        // The validator goes away. The host dials what it announced.
        drop(swarm);
        tokio::time::sleep(Duration::from_secs(9)).await;
        let dials = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert!(dials >= 1, "the host never dialed the validator");
        assert!(dials <= 3, "the host dialed a silent address {dials} times");
    }

    #[tokio::test]
    async fn garden_peer_without_the_invite_gets_nothing() {
        let handle = host().await;
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = stranger(&invite).await;
        let me = key.public_key_bytes();

        for request in [
            GardenRequest::GetCommits {
                from_height: 1,
                max: 4,
            },
            GardenRequest::GetObject {
                content_id: [1u8; 32],
                relay: true,
            },
            GardenRequest::PutObject {
                bytes: vec![1, 2, 3],
            },
            GardenRequest::Gossip(Vec::new()),
        ] {
            let reason = refusal(ask(&mut swarm, peer, request).await);
            assert!(reason.contains("show the invite first"), "{reason}");
        }

        // A signature by any key but the invite key is not the invite. The
        // genesis hash and the chain id are public; they open nothing.
        let forged = invite_keypair(&[9u8; 32])
            .unwrap()
            .sign(&join_message(invite.chain_id, &me))
            .to_vec();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: forged,
        };
        let reason = refusal(ask(&mut swarm, peer, hello).await);
        assert!(reason.contains("does not match this Garden"), "{reason}");

        // A real invite signature made for another key is not accepted for
        // this peer.
        let other = KeyPair::generate().unwrap().public_key_bytes();
        let borrowed = invite_keypair(&invite.token)
            .unwrap()
            .sign(&join_message(invite.chain_id, &other))
            .to_vec();
        for key in [me, other] {
            let hello = GardenRequest::Hello {
                chain_id: invite.chain_id,
                key,
                invite_signature: borrowed.clone(),
            };
            let reason = refusal(ask(&mut swarm, peer, hello).await);
            assert!(reason.contains("does not match this Garden"), "{reason}");
        }
        let reason = refusal(
            ask(
                &mut swarm,
                peer,
                GardenRequest::GetCommits {
                    from_height: 1,
                    max: 4,
                },
            )
            .await,
        );
        assert!(reason.contains("show the invite first"), "{reason}");

        let status = handle.status().await.unwrap();
        assert_eq!(status["connected_peers"], json!(0));
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn garden_gossip_batch_past_the_limit_is_refused() {
        let handle = host().await;
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = stranger(&invite).await;
        let me = key.public_key_bytes();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        assert!(matches!(
            ask(&mut swarm, peer, hello).await,
            GardenResponse::Welcome { .. }
        ));

        let signal = GardenGossip::Presence(GardenPresence::sign(invite.chain_id, 1, &key));
        let full = vec![signal.clone(); MAX_GOSSIP_BATCH];
        assert!(matches!(
            ask(&mut swarm, peer, GardenRequest::Gossip(full)).await,
            GardenResponse::Ack
        ));
        let over = vec![signal; MAX_GOSSIP_BATCH + 1];
        let answer = ask(&mut swarm, peer, GardenRequest::Gossip(over)).await;
        assert!(!matches!(answer, GardenResponse::Ack), "{answer:?}");
        let reason = refusal(answer);
        assert!(reason.contains("too large"), "{reason}");

        // The presence of a key that is no validator changes nothing.
        let status = handle.status().await.unwrap();
        assert_eq!(status["active_validators"], json!(1));
        assert_eq!(status["height"], json!(0));
        handle.leave().await.unwrap();
    }

    /// Oversized transactions, transactions from unknown senders and joins
    /// without a valid invite signature are refused at admission instead of
    /// entering the pending set.
    #[tokio::test]
    async fn garden_oversized_and_unknown_sender_transactions_are_not_pooled() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;

        // First join cleanly so `key` is a real validator and the Garden has
        // two validators (quorum = 2), keeping later transactions pending
        // while `swarm` does not vote.
        let join = GardenTx {
            chain_id: invite.chain_id,
            sender: key.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &key.public_key_bytes()))
                    .to_vec(),
            },
        }
        .sign(&key)
        .unwrap();
        assert!(matches!(
            ask(
                &mut swarm,
                peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(join)])
            )
            .await,
            GardenResponse::Ack
        ));
        let mut joined = false;
        for _ in 0..100 {
            if handle.status().await.unwrap()["active_validators"] == json!(2) {
                joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(joined, "guest did not join in time");

        // 1. An active validator sends a Publish with a 64 KiB caption.
        let oversized = GardenTx {
            chain_id: invite.chain_id,
            sender: key.public_key_bytes(),
            nonce: 1,
            kind: GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: [0x11; 32],
                size: 8,
                mime: "text/plain".into(),
                caption: "a".repeat(65_536),
            },
        }
        .sign(&key)
        .unwrap();

        // 2. An unknown throwaway key sends a Publish transaction.
        let throwaway = KeyPair::generate().unwrap();
        let unknown_publish = GardenTx {
            chain_id: invite.chain_id,
            sender: throwaway.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: [0x22; 32],
                size: 8,
                mime: "text/plain".into(),
                caption: String::new(),
            },
        }
        .sign(&throwaway)
        .unwrap();

        // 3. A Join with a forged invite signature.
        let forged_joiner = KeyPair::generate().unwrap();
        let forged_join = GardenTx {
            chain_id: invite.chain_id,
            sender: forged_joiner.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "mallory".into(),
                address: String::new(),
                invite_signature: invite_keypair(&[0x99; 32])
                    .unwrap()
                    .sign(&join_message(
                        invite.chain_id,
                        &forged_joiner.public_key_bytes(),
                    ))
                    .to_vec(),
            },
        }
        .sign(&forged_joiner)
        .unwrap();

        let batch = GardenRequest::Gossip(vec![
            GardenGossip::Tx(oversized),
            GardenGossip::Tx(unknown_publish),
            GardenGossip::Tx(forged_join),
        ]);
        assert!(matches!(
            ask(&mut swarm, peer, batch).await,
            GardenResponse::Ack
        ));
        let status = handle.status().await.unwrap();
        assert_eq!(
            status["pending_transactions"],
            json!(0),
            "oversized or unauthorized transactions entered the pending set: {status}"
        );
        handle.leave().await.unwrap();
    }

    /// A peer depositing the same bytes as a validator's pending local
    /// publication and then filling its own unreferenced quota must not
    /// delete the validator's pending object from disk.
    #[tokio::test]
    async fn garden_peer_deposits_do_not_evict_a_pending_local_publication() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;

        let join = GardenTx {
            chain_id: invite.chain_id,
            sender: key.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &key.public_key_bytes()))
                    .to_vec(),
            },
        }
        .sign(&key)
        .unwrap();
        assert!(matches!(
            ask(
                &mut swarm,
                peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(join)])
            )
            .await,
            GardenResponse::Ack
        ));
        let mut joined = false;
        for _ in 0..100 {
            if handle.status().await.unwrap()["active_validators"] == json!(2) {
                joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(joined, "guest did not join in time");

        // The host publishes locally; with two validators and no second vote,
        // the publication stays pending in the host's mempool.
        let kept = b"pending local host post".to_vec();
        let content_id = crate::storage::content_id::ContentId::of(&kept).0;
        handle
            .publish(
                GardenContentKind::Message,
                kept.clone(),
                "text/plain".into(),
                String::new(),
            )
            .await
            .unwrap();

        // The peer deposits the exact same bytes and then fills its own
        // unreferenced quota to evict them.
        assert!(matches!(
            ask(
                &mut swarm,
                peer,
                GardenRequest::PutObject {
                    bytes: kept.clone()
                }
            )
            .await,
            GardenResponse::Ack
        ));
        for filler in 0..(MAX_UNREFERENCED_PER_PEER + 2) {
            let put = GardenRequest::PutObject {
                bytes: format!("filler-{filler}").into_bytes(),
            };
            assert!(matches!(
                ask(&mut swarm, peer, put).await,
                GardenResponse::Ack
            ));
        }

        let get = GardenRequest::GetObject {
            content_id,
            relay: false,
        };
        match ask(&mut swarm, peer, get).await {
            GardenResponse::Object(found) => {
                assert_eq!(
                    found,
                    Some(kept),
                    "peer deposit eviction removed the host's pending local publication"
                );
            }
            other => panic!("expected the object, got {other:?}"),
        }
        handle.leave().await.unwrap();
    }

    /// Per-peer outboxes and outbound gossip batches are bounded by bytes in
    /// addition to item counts, so a slow peer never pins unbounded memory
    /// and no batch crosses the frame limit.
    #[test]
    fn garden_outbox_and_gossip_batch_enforce_byte_budgets() {
        let mut net = super::super::testkit::Net::new();
        let a = net.join("a");
        let items: Vec<GardenGossip> = (0..6u8)
            .map(|n| {
                let tx = GardenTx {
                    chain_id: net.ledger.state.chain_id(),
                    sender: a,
                    nonce: u64::from(n),
                    kind: GardenTxKind::Publish {
                        kind: GardenContentKind::Message,
                        content_id: [n; 32],
                        size: 16,
                        mime: "text/plain".into(),
                        caption: "x".repeat(128),
                    },
                }
                .sign(net.key(&a))
                .unwrap();
                GardenGossip::Tx(tx)
            })
            .collect();
        let one = gossip_bytes(&items[0]);
        assert!(one <= MAX_TX_BYTES);

        // Outbox byte budget evicts oldest entries when bytes would exceed
        // the limit even though item count is far below MAX_OUTBOX.
        let mut queue = VecDeque::new();
        for item in &items {
            queue_gossip_item(&mut queue, item.clone(), MAX_OUTBOX, one * 3);
        }
        assert_eq!(queue.len(), 3);
        let queued_bytes: usize = queue.iter().map(gossip_bytes).sum();
        assert!(queued_bytes <= one * 3);

        // Outbound batch draining splits strictly by byte budget and leaves
        // remaining items queued for the next flush.
        let first = drain_gossip_batch(&mut queue, MAX_GOSSIP_BATCH, one * 2);
        assert_eq!(first.len(), 2);
        assert_eq!(queue.len(), 1);
        let second = drain_gossip_batch(&mut queue, MAX_GOSSIP_BATCH, one * 2);
        assert_eq!(second.len(), 1);
        assert!(queue.is_empty());
    }

    /// `GetCommits` stops before crossing its response byte budget and always
    /// advances by at least one commit so sync never stalls on large blocks.
    #[test]
    fn garden_sync_commits_respect_the_response_byte_budget() {
        let mut net = super::super::testkit::Net::new();
        let a = net.join("a");
        for n in 1..=5u8 {
            net.commit(vec![net.publish(&a, n)]).unwrap();
        }
        let total = net.ledger.state.height;
        assert_eq!(total, 6);
        let one_size = commit_bytes(net.ledger.commit_at(2).unwrap().0);

        // Budget fits two commits at a time; iterating `from_height` recovers
        // the entire chain in order without skipping or exceeding the cap.
        let mut collected = Vec::new();
        let mut from = 1u64;
        while from <= total {
            let chunk = take_sync_commits(&net.ledger, from, MAX_SYNC_COMMITS, one_size * 2);
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= 2);
            from = chunk.last().unwrap().block.header.height + 1;
            collected.extend(chunk);
        }
        assert_eq!(collected.len(), usize::try_from(total).unwrap());
        for (idx, commit) in collected.iter().enumerate() {
            assert_eq!(commit.block.header.height, u64::try_from(idx + 1).unwrap());
        }

        // Even when a single commit is larger than the target budget, sync
        // still returns that one commit so forward progress never stalls.
        let single = take_sync_commits(&net.ledger, 1, MAX_SYNC_COMMITS, 1);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].block.header.height, 1);
    }

    /// One invite holder cannot flood the pending set with unbounded
    /// throwaway `Join` transactions past the Garden's validator cap.
    #[tokio::test]
    async fn garden_pending_joins_are_bounded_by_validator_capacity() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Small".into(),
                limits: GardenLimits {
                    max_validators: 3,
                    max_block_txs: 8,
                    max_sender_txs_per_block: 4,
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;

        // First guest joins cleanly so quorum becomes 2 and later joins stay
        // pending while `swarm` does not vote.
        let first_join = GardenTx {
            chain_id: invite.chain_id,
            sender: key.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &key.public_key_bytes()))
                    .to_vec(),
            },
        }
        .sign(&key)
        .unwrap();
        assert!(matches!(
            ask(
                &mut swarm,
                peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(first_join)])
            )
            .await,
            GardenResponse::Ack
        ));
        let mut joined = false;
        for _ in 0..100 {
            if handle.status().await.unwrap()["active_validators"] == json!(2) {
                joined = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(joined, "guest did not join in time");

        let invite_key = invite_keypair(&invite.token).unwrap();
        let flood: Vec<GardenGossip> = (0..12)
            .map(|idx| {
                let kp = KeyPair::generate().unwrap();
                let sender = kp.public_key_bytes();
                let tx = GardenTx {
                    chain_id: invite.chain_id,
                    sender,
                    nonce: 0,
                    kind: GardenTxKind::Join {
                        name: format!("bot-{idx}"),
                        address: String::new(),
                        invite_signature: invite_key
                            .sign(&join_message(invite.chain_id, &sender))
                            .to_vec(),
                    },
                }
                .sign(&kp)
                .unwrap();
                GardenGossip::Tx(tx)
            })
            .collect();
        assert!(matches!(
            ask(&mut swarm, peer, GardenRequest::Gossip(flood)).await,
            GardenResponse::Ack
        ));
        let status = handle.status().await.unwrap();
        let pending = status["pending_transactions"].as_u64().unwrap();
        assert!(
            pending <= 3,
            "pending joins exceeded max_validators cap (3): {status}"
        );
        handle.leave().await.unwrap();
    }

    /// The proposer writes the round into its header and the leader of a
    /// round is a function of that number. So a validator signs only a round
    /// its own clock has reached: otherwise whoever picks the number leads.
    /// The host already kept to this; every other validator signed any round.
    #[tokio::test]
    async fn garden_validator_does_not_sign_a_round_its_clock_has_not_reached() {
        let mut room = LiarRoom::open().await;
        let liar = room.liar.public_key_bytes();
        let far_round = (1_000_000..1_000_064)
            .find(|round| room.ledger.state.leader(*round) == Some(liar))
            .expect("the liar leads one round in any sixty-four");
        let far = room.propose(far_round, message(7), now_ms());
        assert!(
            room.ledger.state.verify_block(&far).is_ok(),
            "the block is valid for the state machine, which reads no clock"
        );
        // The far block goes first and is kept unsigned. The honest one takes
        // its slot: a block nobody signs yet gives way to one that can be.
        let honest = room.propose(room.rounds()[0], message(8), now_ms());
        room.show(&far).await;
        room.show(&honest).await;
        assert!(
            room.signed_by_witness.contains(&honest.hash()),
            "the witness was not heard voting at all"
        );
        assert!(
            !room.signed_by_witness.contains(&far.hash()),
            "the witness signed round {far_round}, which its clock is nowhere near"
        );
    }

    /// The queues of deposits are the only record of bytes no publication
    /// accounts for. A member that names each deposit in a publication that
    /// can never apply must not get them out of the queue and keep them on
    /// the disk: what a pending publication names stays counted, and the
    /// count is what bounds it.
    #[tokio::test]
    async fn garden_deposit_named_by_a_pending_publication_stays_counted() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;
        let me = key.public_key_bytes();
        let join = GardenTx {
            chain_id: invite.chain_id,
            sender: me,
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &me))
                    .to_vec(),
            },
        }
        .sign(&key)
        .unwrap();
        let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(join)]);
        assert!(matches!(
            ask(&mut swarm, peer, gossip).await,
            GardenResponse::Ack
        ));
        tokio::time::timeout(Duration::from_secs(20), async {
            while handle.status().await.unwrap()["active_validators"] != json!(2) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the guest never became a validator");

        // Twice the share of one peer, each deposit named by a publication
        // whose nonce is past a gap, so it waits in the pool for ever.
        let parked: Vec<Vec<u8>> = (0..MAX_UNREFERENCED_PER_PEER * 2)
            .map(|i| format!("parked-{i}").into_bytes())
            .collect();
        for (i, bytes) in parked.iter().enumerate() {
            let publish = GardenTx {
                chain_id: invite.chain_id,
                sender: me,
                nonce: 5 + i as u64,
                kind: GardenTxKind::Publish {
                    kind: GardenContentKind::Message,
                    content_id: crate::storage::content_id::ContentId::of(bytes).0,
                    size: u32::try_from(bytes.len()).unwrap(),
                    mime: "text/plain".into(),
                    caption: String::new(),
                },
            }
            .sign(&key)
            .unwrap();
            let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(publish)]);
            assert!(matches!(
                ask(&mut swarm, peer, gossip).await,
                GardenResponse::Ack
            ));
            let put = GardenRequest::PutObject {
                bytes: bytes.clone(),
            };
            assert!(matches!(
                ask(&mut swarm, peer, put).await,
                GardenResponse::Ack
            ));
        }
        let status = handle.status().await.unwrap();
        assert_eq!(
            status["pending_transactions"],
            json!(parked.len()),
            "the publications that name the deposits are not in the pool: {status}"
        );
        let mut kept = 0;
        for bytes in &parked {
            let get = GardenRequest::GetObject {
                content_id: crate::storage::content_id::ContentId::of(bytes).0,
                relay: false,
            };
            match ask(&mut swarm, peer, get).await {
                GardenResponse::Object(found) => kept += usize::from(found.is_some()),
                other => panic!("expected an object answer, got {other:?}"),
            }
        }
        assert!(
            kept <= MAX_UNREFERENCED_PER_PEER,
            "the host keeps {kept} deposits of one peer, past its share of \
             {MAX_UNREFERENCED_PER_PEER}: naming them in the pool took them out of the count"
        );
        handle.leave().await.unwrap();
    }

    /// Publish `words` as a message of the node behind `handle`.
    async fn say(handle: &GardenHandle, words: &str) -> Result<Value, String> {
        handle
            .publish(
                GardenContentKind::Message,
                words.as_bytes().to_vec(),
                "text/plain".into(),
                String::new(),
            )
            .await
    }

    /// Wait until `handle` reports `wanted` at `pointer` of its status.
    async fn status_becomes(handle: &GardenHandle, pointer: &str, wanted: Value) -> Value {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let status = handle.status().await.unwrap();
                if status.pointer(pointer) == Some(&wanted) {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{pointer} never became {wanted}"))
    }

    /// A Garden founded with host approval, between real nodes. The invite
    /// lets a node ask. It gets a seat, a vote and the content when the host
    /// says so, and a node the host turns away stops asking.
    #[tokio::test]
    async fn garden_host_approval_seats_a_node_only_after_the_host_answers() {
        let host = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 200,
                    presence_interval_ms: 100,
                    admission: GardenAdmission::HostApproval,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = host.invite().await.unwrap();
        let before = say(&host, "said before anybody came").await.unwrap();
        let content_id: Hash32 = hex::decode(before["content_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        status_becomes(&host, "/objects", json!(1)).await;

        let mut nodes = Vec::new();
        for name in ["welcome", "unwelcome"] {
            let node = spawn(
                GardenEntry::Invite(invite.clone()),
                config(name, "/ip4/127.0.0.1/tcp/0"),
                random_bytes(),
                None,
            )
            .await
            .unwrap();
            status_becomes(&node, "/me/member", json!("Waiting")).await;
            nodes.push(node);
        }
        let (welcome, unwelcome) = (&nodes[0], &nodes[1]);
        let status = status_becomes(&host, "/waiting_for_host", json!(2)).await;
        assert_eq!(status["admission"], json!("host_approval"));
        assert_eq!(
            status["active_validators"],
            json!(1),
            "a node that only holds the invite is a validator: {status}"
        );
        let key_of = |status: &Value| -> GardenKey {
            hex::decode(status["me"]["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let welcome_key = key_of(&welcome.status().await.unwrap());
        let unwelcome_key = key_of(&unwelcome.status().await.unwrap());

        // A node that waits publishes nothing, reads no content, receives no
        // block history or captions, and does not answer for the host: not for
        // another key, not for its own.
        assert_eq!(
            welcome.feed(20).await.unwrap()["total"],
            json!(0),
            "a waiting node must not receive posts or captions before admission"
        );
        assert_eq!(
            unwelcome.feed(20).await.unwrap()["total"],
            json!(0),
            "an unadmitted node must not receive posts or captions"
        );
        let refusal = say(welcome, "early").await.unwrap_err();
        assert!(refusal.contains("not an active validator"), "{refusal}");
        assert!(
            unwelcome.resolve(content_id).await.is_err(),
            "a node the host has not admitted read the content of the Garden"
        );
        let refusal = unwelcome.admit(unwelcome_key, true).await.unwrap_err();
        assert!(refusal.contains("only the host"), "{refusal}");
        // The host goes on alone meanwhile: nobody who waits has a vote.
        say(&host, "still alone").await.unwrap();
        status_becomes(&host, "/objects", json!(2)).await;

        let admitted = host.admit(welcome_key, true).await.unwrap();
        assert_eq!(admitted["admitted"], json!(true));
        status_becomes(welcome, "/me/member", json!("Active")).await;
        status_becomes(&host, "/active_validators", json!(2)).await;
        let turned = host.admit(unwelcome_key, false).await.unwrap();
        assert_eq!(turned["admitted"], json!(false));
        status_becomes(unwelcome, "/me/turned_away", json!(true)).await;
        status_becomes(&host, "/waiting_for_host", json!(0)).await;

        // The seated node reads what was there and is heard: two validators
        // need two signatures, so its publication is final only with both.
        assert_eq!(
            welcome.resolve(content_id).await.unwrap(),
            b"said before anybody came".to_vec()
        );
        say(welcome, "inside").await.unwrap();
        status_becomes(&host, "/objects", json!(3)).await;
        status_becomes(welcome, "/objects", json!(3)).await;

        // The node that was turned away holds no seat, reads nothing, and
        // does not ask again: rounds pass and nobody waits for the host.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let status = host.status().await.unwrap();
        assert_eq!(status["waiting_for_host"], json!(0), "{status}");
        assert_eq!(
            status["validators"].as_array().unwrap().len(),
            2,
            "{status}"
        );
        let outside = unwelcome.status().await.unwrap();
        assert_eq!(outside["me"]["member"], Value::Null, "{outside}");
        assert_eq!(
            unwelcome.feed(20).await.unwrap()["total"],
            json!(0),
            "a turned-away node must never have received posts or captions"
        );
        // A second answer for the same key has nothing to answer.
        let refusal = host.admit(unwelcome_key, true).await.unwrap_err();
        assert!(refusal.contains("not waiting"), "{refusal}");
        for node in nodes {
            node.leave().await.unwrap();
        }
        host.leave().await.unwrap();
    }

    /// A transaction that can never apply holds a slot in the pool, and a
    /// publication in the pool shields the bytes it names. So the pool takes
    /// from a recorded key only what its standing lets it apply.
    #[tokio::test]
    async fn garden_transactions_that_cannot_apply_are_not_pooled() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    admission: GardenAdmission::HostApproval,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;
        let me = key.public_key_bytes();
        let sign = |nonce: u64, kind: GardenTxKind| {
            GardenTx {
                chain_id: invite.chain_id,
                sender: me,
                nonce,
                kind,
            }
            .sign(&key)
            .unwrap()
        };
        let join = sign(
            0,
            GardenTxKind::Join {
                name: "guest".into(),
                address: String::new(),
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &me))
                    .to_vec(),
            },
        );
        let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(join)]);
        assert!(matches!(
            ask(&mut swarm, peer, gossip).await,
            GardenResponse::Ack
        ));
        status_becomes(&handle, "/waiting_for_host", json!(1)).await;
        status_becomes(&handle, "/pending_transactions", json!(0)).await;

        // The key waits. It publishes nothing, admits nobody, and neither
        // transaction is kept to hold a slot or to shield a deposit.
        let bytes = b"not mine to publish yet".to_vec();
        let publish = sign(
            1,
            GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: crate::storage::content_id::ContentId::of(&bytes).0,
                size: u32::try_from(bytes.len()).unwrap(),
                mime: "text/plain".into(),
                caption: String::new(),
            },
        );
        let admit = sign(
            1,
            GardenTxKind::Admit {
                target: me,
                accept: true,
            },
        );
        let leave = sign(1, GardenTxKind::Leave);
        for tx in [publish, admit, leave] {
            let gossip = GardenRequest::Gossip(vec![GardenGossip::Tx(tx)]);
            assert!(matches!(
                ask(&mut swarm, peer, gossip).await,
                GardenResponse::Ack
            ));
        }
        // Nor does the host take its bytes or give it any: content is for
        // the seated.
        let get = GardenRequest::GetObject {
            content_id: crate::storage::content_id::ContentId::of(&bytes).0,
            relay: true,
        };
        let put = GardenRequest::PutObject { bytes };
        for request in [put, get] {
            let answer = refusal(ask(&mut swarm, peer, request).await);
            assert!(answer.contains("has not admitted"), "{answer}");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let status = handle.status().await.unwrap();
        assert_eq!(
            status["pending_transactions"],
            json!(0),
            "the pool holds transactions of a key that only waits: {status}"
        );
        assert_eq!(status["active_validators"], json!(1), "{status}");
        handle.leave().await.unwrap();
    }

    /// Peers that show no invite hold a bounded part of the connection
    /// table. When more of them come the one that kept silent longest goes
    /// at once, not when its grace ends, so a crowd at the door does not
    /// fill the table a validator needs a seat in.
    #[tokio::test]
    async fn garden_peers_without_the_invite_hold_a_bounded_part_of_the_door() {
        // A long round: the grace of a stranger is two rounds, so nothing
        // here is dropped because its time ran out.
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 20_000,
                    host_timeout_ms: 40_000,
                    suspend_after_ms: 40_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let mut crowd = Vec::new();
        for _ in 0..(MAX_UNADMITTED + 4) {
            crowd.push(stranger(&invite).await);
        }
        // The four that came first were put out when the last four came.
        for (index, (swarm, _, peer)) in crowd.iter_mut().enumerate().take(4) {
            let gone = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match swarm.events.recv().await {
                        Some(NetEvent::Disconnected(left)) if left == *peer => return true,
                        Some(_) => {}
                        None => return false,
                    }
                }
            })
            .await;
            assert_eq!(
                gone,
                Ok(true),
                "stranger {index} still holds its connection with {} others behind it",
                MAX_UNADMITTED + 3 - index
            );
        }
        // And a node that holds the invite walks in past the rest.
        join_as_second(invite).await;
        drop(handle);
    }

    #[tokio::test]
    async fn garden_unjoined_invite_holders_are_capped_separately_from_validators() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_UNJOINED_PEERS {
            held.push(guest(&invite).await);
        }
        let (mut extra, key, peer) = stranger(&invite).await;
        let me = key.public_key_bytes();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        match ask(&mut extra, peer, hello).await {
            GardenResponse::Refused(reason) => {
                assert!(reason.contains("unjoined"), "{reason}");
            }
            other => panic!("expected unjoined refusal, got {other:?}"),
        }
        drop(held);
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn garden_gossip_and_object_requests_enforce_per_peer_rate_budgets() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Room".into(),
                limits: GardenLimits {
                    round_ms: 5_000,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let (mut swarm, key, peer) = guest(&invite).await;

        let mut refused_obj = false;
        for i in 0..(MAX_OBJECT_REQS_PER_WINDOW + 4) {
            let id = [u8::try_from(i % 255).unwrap_or(0); 32];
            if let GardenResponse::Refused(reason) = ask(
                &mut swarm,
                peer,
                GardenRequest::GetObject {
                    content_id: id,
                    relay: false,
                },
            )
            .await
            {
                if reason.contains("rate limit") {
                    refused_obj = true;
                    break;
                }
            }
        }
        assert!(refused_obj, "expected GetObject rate limit refusal");

        let vote = GardenVote {
            chain_id: invite.chain_id,
            height: 1,
            block_hash: [1u8; 32],
            voter: key.public_key_bytes(),
            signature: vec![0u8; 64],
        };
        let mut refused_gossip = false;
        for _ in 0..4 {
            let batch = vec![GardenGossip::Vote(vote.clone()); MAX_GOSSIP_BATCH];
            if let GardenResponse::Refused(reason) =
                ask(&mut swarm, peer, GardenRequest::Gossip(batch)).await
            {
                if reason.contains("rate limit") {
                    refused_gossip = true;
                    break;
                }
            }
        }
        assert!(refused_gossip, "expected Gossip rate limit refusal");

        let mut refused_sync = false;
        for _ in 0..(MAX_SYNC_REQS_PER_PEER_PER_SEC + 4) {
            if let GardenResponse::Refused(reason) = ask(
                &mut swarm,
                peer,
                GardenRequest::GetCommits {
                    from_height: 1,
                    max: 4,
                },
            )
            .await
            {
                if reason.contains("rate limit") {
                    refused_sync = true;
                    break;
                }
            }
        }
        assert!(refused_sync, "expected GetCommits rate limit refusal");

        let mut refused_put = false;
        for i in 0..(MAX_PUT_OBJECT_REQS_PER_PEER_PER_SEC + 4) {
            if let GardenResponse::Refused(reason) = ask(
                &mut swarm,
                peer,
                GardenRequest::PutObject {
                    bytes: format!("deposit-rate-{i}").into_bytes(),
                },
            )
            .await
            {
                if reason.contains("rate limit") {
                    refused_put = true;
                    break;
                }
            }
        }
        assert!(refused_put, "expected PutObject rate limit refusal");
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn garden_idle_unjoined_peers_expire_and_free_slots_for_new_joiners() {
        let handle = spawn(
            GardenEntry::Create {
                title: "Expire".into(),
                limits: GardenLimits {
                    round_ms: 50,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_UNJOINED_PEERS {
            held.push(guest(&invite).await);
        }
        // Wait past the 2-second unjoined grace so the idle guests expire.
        tokio::time::sleep(Duration::from_millis(2400)).await;
        let (mut fresh, key, peer) = stranger(&invite).await;
        let me = key.public_key_bytes();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: me,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &me))
                .to_vec(),
        };
        match ask(&mut fresh, peer, hello).await {
            GardenResponse::Welcome { .. } => {}
            other => panic!("expected Welcome after idle unjoined expiry, got {other:?}"),
        }
        drop(held);
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn waiting_keys_under_host_approval_count_against_unjoined_cap_and_expire() {
        let handle = spawn(
            GardenEntry::Create {
                title: "waiting-cap".into(),
                limits: GardenLimits {
                    round_ms: 50,
                    admission: GardenAdmission::HostApproval,
                    ..GardenLimits::testnet_default()
                },
            },
            config("host", "/ip4/127.0.0.1/tcp/0"),
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = handle.invite().await.unwrap();

        // Register MAX_UNJOINED_PEERS distinct keys into the host's Waiting
        // queue while keeping their connections open.
        let mut waiting = Vec::new();
        for idx in 0..MAX_UNJOINED_PEERS {
            let (mut net, key, host_peer) = stranger(&invite).await;
            let me = key.public_key_bytes();
            let hello = GardenRequest::Hello {
                chain_id: invite.chain_id,
                key: me,
                invite_signature: invite_keypair(&invite.token)
                    .unwrap()
                    .sign(&join_message(invite.chain_id, &me))
                    .to_vec(),
            };
            assert!(matches!(
                ask(&mut net, host_peer, hello).await,
                GardenResponse::Welcome { .. }
            ));
            let join_tx = GardenTx {
                chain_id: invite.chain_id,
                sender: me,
                nonce: 0,
                kind: GardenTxKind::Join {
                    name: format!("waiter-{idx}"),
                    address: String::new(),
                    invite_signature: invite_keypair(&invite.token)
                        .unwrap()
                        .sign(&join_message(invite.chain_id, &me))
                        .to_vec(),
                },
            }
            .sign(&key)
            .unwrap();
            let _ = ask(
                &mut net,
                host_peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(join_tx)]),
            )
            .await;
            waiting.push((net, key));
        }

        // Wait until all MAX_UNJOINED_PEERS keys are recorded as Waiting.
        status_becomes(&handle, "/waiting_for_host", json!(MAX_UNJOINED_PEERS)).await;

        // An extra invitee must be refused while all MAX_UNJOINED_PEERS waiting
        // slots are freshly occupied (Waiting keys do not bypass the cap).
        let (mut extra, extra_key, host_peer) = stranger(&invite).await;
        let extra_pk = extra_key.public_key_bytes();
        let extra_hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: extra_pk,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &extra_pk))
                .to_vec(),
        };
        assert!(
            matches!(
                ask(&mut extra, host_peer, extra_hello.clone()).await,
                GardenResponse::Refused(_)
            ),
            "fresh waiting connections must count against MAX_UNJOINED_PEERS"
        );

        // Once the unjoined grace elapses, the waiting connections expire and
        // a newcomer is welcomed at the door.
        tokio::time::sleep(Duration::from_millis(2400)).await;
        let (mut fresh, fresh_key, fresh_host_peer) = stranger(&invite).await;
        let fresh_pk = fresh_key.public_key_bytes();
        let fresh_hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: fresh_pk,
            invite_signature: invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &fresh_pk))
                .to_vec(),
        };
        match ask(&mut fresh, fresh_host_peer, fresh_hello).await {
            GardenResponse::Welcome { .. } => {}
            other => panic!("expected Welcome after waiting peers aged out, got {other:?}"),
        }
        drop(waiting);
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn forged_tx_gossip_does_not_poison_seen_filter_and_empty_gossip_is_budgeted() {
        let handle = host().await;
        let invite = handle.invite().await.unwrap();
        let (mut peer_net, peer_key, host_peer) = stranger(&invite).await;
        let pk = peer_key.public_key_bytes();
        let invite_sig = invite_keypair(&invite.token)
            .unwrap()
            .sign(&join_message(invite.chain_id, &pk))
            .to_vec();
        let hello = GardenRequest::Hello {
            chain_id: invite.chain_id,
            key: pk,
            invite_signature: invite_sig.clone(),
        };
        assert!(matches!(
            ask(&mut peer_net, host_peer, hello).await,
            GardenResponse::Welcome { .. }
        ));

        // 164-02: send a Join tx with a valid tx.id() but corrupted Ed25519
        // signature, then send the genuine signed Join with the exact same id.
        let real_join = (GardenTx {
            chain_id: invite.chain_id,
            sender: pk,
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "alice".into(),
                address: String::new(),
                invite_signature: invite_sig,
            },
        })
        .sign(&peer_key)
        .unwrap();
        let mut forged_join = real_join.clone();
        if let Some(byte) = forged_join.signature.first_mut() {
            *byte ^= 0x55;
        }
        assert_eq!(forged_join.id(), real_join.id());
        assert!(matches!(
            ask(
                &mut peer_net,
                host_peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(forged_join)])
            )
            .await,
            GardenResponse::Ack
        ));
        assert!(matches!(
            ask(
                &mut peer_net,
                host_peer,
                GardenRequest::Gossip(vec![GardenGossip::Tx(real_join)])
            )
            .await,
            GardenResponse::Ack
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = handle.status().await.unwrap();
            let seated = status["validators"]
                .as_array()
                .is_some_and(|vs| vs.iter().any(|v| v["name"] == "alice"));
            if seated {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "forged tx pre-poisoned seen filter; alice never seated: {status}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 164-12: empty Gossip(vec![]) frames must consume rate-limit quota.
        let mut refused_empty = false;
        for _ in 0..=MAX_GOSSIP_ITEMS_PER_PEER_PER_SEC {
            if matches!(
                ask(&mut peer_net, host_peer, GardenRequest::Gossip(Vec::new())).await,
                GardenResponse::Refused(msg) if msg.contains("gossip rate limit")
            ) {
                refused_empty = true;
                break;
            }
        }
        assert!(
            refused_empty,
            "empty Gossip frames must exhaust MAX_GOSSIP_ITEMS_PER_PEER_PER_SEC"
        );
        handle.leave().await.unwrap();
    }

    #[tokio::test]
    async fn disk_put_object_offloads_write_and_refuses_published_object_on_non_holder() {
        let dir = tempfile::tempdir().unwrap();
        let mut host_cfg = config("host", "/ip4/127.0.0.1/tcp/0");
        host_cfg.content_dir = Some(dir.path().join("host"));
        let host_handle = spawn(
            GardenEntry::Create {
                title: "DiskRoom".into(),
                limits: GardenLimits::testnet_default(),
            },
            host_cfg,
            random_bytes(),
            None,
        )
        .await
        .unwrap();
        let invite = host_handle.invite().await.unwrap();

        // Seat 4 additional validators (5 active total > REPLICAS=3) so every
        // published object has at least two non-holder validators.
        let mut members = Vec::new();
        for idx in 0..4 {
            let mut cfg = config(&format!("v{idx}"), "/ip4/127.0.0.1/tcp/0");
            cfg.content_dir = Some(dir.path().join(format!("v{idx}")));
            let h = spawn(
                GardenEntry::Invite(invite.clone()),
                cfg,
                random_bytes(),
                None,
            )
            .await
            .unwrap();
            members.push(h);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let st = host_handle.status().await.unwrap();
            if st["validators"].as_array().is_some_and(|v| v.len() == 5) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cluster did not reach 5 validators"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Publish an object (exercises 164-04 offloaded disk PutObject on holders).
        let payload = b"offloaded-disk-publication-payload".to_vec();
        let pub_res = host_handle
            .publish(
                GardenContentKind::Message,
                payload.clone(),
                "text/plain".into(),
                "hello".into(),
            )
            .await
            .unwrap();
        let cid_hex = pub_res["content_id"].as_str().unwrap();
        let cid_vec = hex::decode(cid_hex).unwrap();
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&cid_vec);

        // Wait until the publication is finalized on host and every member.
        let pub_deadline = Instant::now() + Duration::from_secs(10);
        let pub_height = loop {
            let st = host_handle.status().await.unwrap();
            if st["objects"].as_u64().unwrap_or(0) >= 1 {
                break st["height"].as_u64().unwrap();
            }
            assert!(
                Instant::now() < pub_deadline,
                "publication did not finalize on host: {st}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        for m in &members {
            let wait = Instant::now() + Duration::from_secs(10);
            while m.status().await.unwrap()["height"].as_u64().unwrap_or(0) < pub_height {
                assert!(Instant::now() < wait, "member did not sync publication");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        // Dial each validator's own announced address directly (with 5 active
        // validators and 3 holders, exactly 2 validators are non-holders).
        //
        // The addresses come from the status, which is the node's own list
        // of validators, and not from the invite. An invite is a record a
        // person carries, so it is held to a byte ceiling and names only as
        // many peers as fit; it is not a directory of the Garden and must
        // not be read as one.
        let host_status = host_handle.status().await.unwrap();
        let peer_addrs: Vec<String> = host_status["validators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["address"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(peer_addrs.len(), 5, "expected all 5 validator addresses");
        let mut refused_non_holders = 0usize;
        for addr in &peer_addrs {
            let mut one_peer_invite = invite.clone();
            one_peer_invite.peers = vec![addr.clone()];
            let (mut probe, probe_key, target_peer) = stranger(&one_peer_invite).await;
            let pk = probe_key.public_key_bytes();
            let sig = invite_keypair(&invite.token)
                .unwrap()
                .sign(&join_message(invite.chain_id, &pk))
                .to_vec();
            assert!(matches!(
                ask(
                    &mut probe,
                    target_peer,
                    GardenRequest::Hello {
                        chain_id: invite.chain_id,
                        key: pk,
                        invite_signature: sig,
                    }
                )
                .await,
                GardenResponse::Welcome { .. }
            ));
            if let GardenResponse::Refused(reason) = ask(
                &mut probe,
                target_peer,
                GardenRequest::PutObject {
                    bytes: payload.clone(),
                },
            )
            .await
            {
                if reason.contains("not a holder") {
                    refused_non_holders += 1;
                }
            }
        }
        assert_eq!(
            refused_non_holders,
            2,
            "both non-holder validators must refuse unsolicited published PutObject for {}",
            hex::encode(cid)
        );

        for m in members {
            let _ = m.leave().await;
        }
        let _ = host_handle.leave().await;
    }

    #[tokio::test]
    async fn node_unit_guards_cover_host_only_admission_sync_coalescing_source_cap_and_rejected_fifo(
    ) {
        let host_key = KeyPair::generate().unwrap();
        let peer_a_key = KeyPair::generate().unwrap();
        let peer_b_key = KeyPair::generate().unwrap();
        let token = [0x42u8; 32];
        let mut limits = GardenLimits::testnet_default();
        limits.admission = GardenAdmission::HostApproval;
        let genesis = GardenGenesis::new(
            GardenFounding {
                title: "UnitGuard".into(),
                host_name: "host".into(),
                host_address: String::new(),
                limits,
            },
            host_key.public_key_bytes(),
            1_700_000_000_000,
            7,
            &token,
        )
        .unwrap();
        let chain_id = genesis.chain_id;
        let ledger = GardenLedger::new(genesis).unwrap();
        let joiner_key = KeyPair::generate().unwrap();
        let me = joiner_key.public_key_bytes();
        let invite_signature = invite_keypair(&token)
            .unwrap()
            .sign(&join_message(chain_id, &me))
            .to_vec();
        let (net_tx, mut net_rx) = mpsc::channel(64);
        let (deposit_tx, _deposit_rx) = mpsc::channel(16);
        let peer_sources = std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let now = Instant::now();
        let host_peer = peer_id_of(&host_key.public_key_bytes()).unwrap();
        let non_host_peer = peer_id_of(&peer_a_key.public_key_bytes()).unwrap();
        let mut peers = BTreeMap::new();
        peers.insert(non_host_peer, peer_a_key.public_key_bytes());
        peers.insert(host_peer, host_key.public_key_bytes());

        let mut node = Node {
            key: joiner_key,
            me,
            name: "joiner".into(),
            token,
            invite_signature,
            address: String::new(),
            seeds: Vec::new(),
            ledger,
            store: GardenContentStore::open(None, 1024 * 1024).unwrap(),
            net: net_tx,
            link: None,
            reported: 0,
            budlum_status: None,
            budlum_error: None,
            peers,
            unadmitted: BTreeMap::new(),
            outbox: BTreeMap::new(),
            gossip_in_flight: BTreeMap::new(),
            held_elsewhere: 0,
            mempool: BTreeMap::new(),
            my_next_nonce: 0,
            proposals: BTreeMap::new(),
            candidate_rounds: BTreeMap::new(),
            votes: BTreeMap::new(),
            orphan_votes: VecDeque::new(),
            my_votes: BTreeSet::new(),
            host_voted: false,
            proposed_rounds: BTreeSet::new(),
            height_started: now,
            pending_since: None,
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            last_seen: BTreeMap::new(),
            presence_windows: BTreeMap::new(),
            my_window: 0,
            started: now,
            last_presence: now,
            last_tick: now,
            last_sync: now,
            last_dial: now,
            sync_cursor: 0,
            wanted: BTreeSet::new(),
            measured: BTreeMap::new(),
            unreferenced: BTreeMap::new(),
            verified_peers: BTreeSet::new(),
            rejected_addresses: BTreeSet::new(),
            rejected_address_order: VecDeque::new(),
            dial_failures: BTreeMap::new(),
            dials: BTreeMap::new(),
            gossip_budget: BTreeMap::new(),
            sync_budget: BTreeMap::new(),
            sync_in_flight: None,
            outbound_sync_budget: (now, 0),
            object_budget: BTreeMap::new(),
            put_object_budget: BTreeMap::new(),
            deposit_tx,
            deposits_in_flight: BTreeMap::new(),
            total_deposits_in_flight: 0,
            peer_sources: std::sync::Arc::clone(&peer_sources),
            unjoined_source_budget: BTreeMap::new(),
            peer_admitted_at: BTreeMap::new(),
            disconnect_after: BTreeMap::new(),
            turned_away_keys: BTreeSet::new(),
            turned_away_order: VecDeque::new(),
            remote_admission: None,
            seed_dials: None,
            fetches: BTreeMap::new(),
            fetch_tags: BTreeMap::new(),
            relays: BTreeMap::new(),
            relay_tags: BTreeMap::new(),
            next_tag: TAG_FIRST_FETCH,
            leaving: None,
            turned_away: false,
            stopped: false,
        };

        // Forged TurnedAway from a non-host peer is ignored; host's is honored.
        node.on_response(
            non_host_peer,
            TAG_ADMISSION,
            Ok(GardenResponse::AdmissionStatus(
                GardenAdmissionState::TurnedAway,
            )),
        )
        .await;
        assert!(!node.turned_away, "non-host peer must not set turned_away");
        node.on_response(
            host_peer,
            TAG_ADMISSION,
            Ok(GardenResponse::AdmissionStatus(
                GardenAdmissionState::TurnedAway,
            )),
        )
        .await;
        assert!(node.turned_away, "host peer TurnedAway verdict must apply");

        // Repeated sync triggers for the same height coalesce into one GetCommits.
        node.request_sync(Some(host_peer)).await;
        node.request_sync(Some(non_host_peer)).await;
        node.request_sync(None).await;
        let mut sent_syncs = 0usize;
        while let Ok(cmd) = net_rx.try_recv() {
            if matches!(
                cmd,
                NetCommand::Send {
                    request: GardenRequest::GetCommits { .. },
                    ..
                }
            ) {
                sent_syncs += 1;
            }
        }
        assert_eq!(sent_syncs, 1, "concurrent sync triggers must coalesce");

        // A non-loopback /24 holding an unjoined slot blocks a second unjoined
        // peer from the same /24, while another /24 is allowed through.
        let unjoined_2 = peer_id_of(&peer_b_key.public_key_bytes()).unwrap();
        let other_net_peer = PeerId::random();
        {
            let mut map = peer_sources.lock().unwrap();
            map.insert(non_host_peer, net::SourceKey::V4([203, 0, 113]));
            map.insert(unjoined_2, net::SourceKey::V4([203, 0, 113]));
            map.insert(other_net_peer, net::SourceKey::V4([198, 51, 100]));
        }
        let grace = Duration::from_secs(10);
        assert!(
            node.source_unjoined_blocked(unjoined_2, grace),
            "second unjoined peer from same public /24 must be refused"
        );
        assert!(
            !node.source_unjoined_blocked(other_net_peer, grace),
            "newcomer from distinct public /24 must still be welcomed"
        );

        // Rejected address tracking stays strictly bounded by MAX_REJECTED_ADDRESSES.
        for i in 0..(MAX_REJECTED_ADDRESSES + 40) {
            node.record_rejected_address((me, format!("/ip4/198.51.100.1/tcp/{}", 2000 + i)));
        }
        assert_eq!(node.rejected_addresses.len(), MAX_REJECTED_ADDRESSES);
        assert!(!node
            .rejected_addresses
            .contains(&(me, "/ip4/198.51.100.1/tcp/2000".into())));
    }

    fn build_signed_commit(
        ledger: &GardenLedger,
        txs: Vec<SignedGardenTx>,
        keys: &[&KeyPair],
        ts_ms: u64,
    ) -> GardenCommit {
        let leader = ledger.state.leader(0).unwrap();
        let proposer = keys
            .iter()
            .find(|k| k.public_key_bytes() == leader)
            .unwrap();
        let (header, _) = ledger.state.build_header(&txs, leader, 0, ts_ms).unwrap();
        let proposer_signature = proposer.sign(&header.hash()).to_vec();
        let votes = ledger
            .state
            .electorate(&txs)
            .into_iter()
            .map(|vk| {
                let signer = keys.iter().find(|k| k.public_key_bytes() == vk).unwrap();
                GardenVote::sign(&header, signer)
            })
            .collect();
        GardenCommit {
            block: GardenBlock {
                header,
                txs,
                proposer_signature,
            },
            votes,
        }
    }

    #[tokio::test]
    async fn unverified_proposal_and_commit_gossip_cannot_poison_seen_cache() {
        let host_key = KeyPair::generate().unwrap();
        let seat_key = KeyPair::generate().unwrap();
        let guest_key = KeyPair::generate().unwrap();
        let token = [0x71u8; 32];
        let genesis = GardenGenesis::new(
            GardenFounding {
                title: "seen-poison-guard".into(),
                host_name: "host".into(),
                host_address: String::new(),
                limits: GardenLimits::testnet_default(),
            },
            host_key.public_key_bytes(),
            1_000,
            1,
            &token,
        )
        .unwrap();
        let chain_id = genesis.chain_id;
        let invite_signer = invite_keypair(&token).unwrap();

        let mut ref_ledger = GardenLedger::new(genesis).unwrap();
        let seat_pub = seat_key.public_key_bytes();
        let join_tx = GardenTx {
            chain_id,
            sender: seat_pub,
            nonce: 0,
            kind: GardenTxKind::Join {
                name: "seat".into(),
                address: String::new(),
                invite_signature: invite_signer
                    .sign(&join_message(chain_id, &seat_pub))
                    .to_vec(),
            },
        }
        .sign(&seat_key)
        .unwrap();
        let h1 = build_signed_commit(&ref_ledger, vec![join_tx], &[&host_key], 1_100);
        ref_ledger.append(h1).unwrap();

        let publish_id = crate::storage::ContentId::of(b"genuine").0;
        let pub_tx = GardenTx {
            chain_id,
            sender: host_key.public_key_bytes(),
            nonce: 0,
            kind: GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: publish_id,
                size: 7,
                caption: String::new(),
                mime: "text/plain".into(),
            },
        }
        .sign(&host_key)
        .unwrap();
        let genuine_commit =
            build_signed_commit(&ref_ledger, vec![pub_tx], &[&host_key, &seat_key], 1_200);
        let genuine_block = genuine_commit.block.clone();
        let block_hash = genuine_block.hash();

        let host_peer = peer_id_of(&host_key.public_key_bytes()).unwrap();
        let guest_peer = peer_id_of(&guest_key.public_key_bytes()).unwrap();
        let mut peers = BTreeMap::new();
        peers.insert(host_peer, host_key.public_key_bytes());
        peers.insert(guest_peer, guest_key.public_key_bytes());
        let (net_tx, _net_rx) = mpsc::channel(64);
        let (deposit_tx, _deposit_rx) = mpsc::channel(16);
        let now = Instant::now();
        let mut node = Node {
            key: seat_key,
            me: seat_pub,
            name: "seat".into(),
            token,
            invite_signature: invite_signer
                .sign(&join_message(chain_id, &seat_pub))
                .to_vec(),
            address: String::new(),
            seeds: Vec::new(),
            ledger: ref_ledger,
            store: GardenContentStore::open(None, 1024 * 1024).unwrap(),
            net: net_tx,
            link: None,
            reported: 0,
            budlum_status: None,
            budlum_error: None,
            peers,
            unadmitted: BTreeMap::new(),
            outbox: BTreeMap::new(),
            gossip_in_flight: BTreeMap::new(),
            held_elsewhere: 0,
            mempool: BTreeMap::new(),
            my_next_nonce: 1,
            proposals: BTreeMap::new(),
            candidate_rounds: BTreeMap::new(),
            votes: BTreeMap::new(),
            orphan_votes: VecDeque::new(),
            my_votes: BTreeSet::new(),
            host_voted: false,
            proposed_rounds: BTreeSet::new(),
            height_started: now,
            pending_since: None,
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            last_seen: BTreeMap::new(),
            presence_windows: BTreeMap::new(),
            my_window: 0,
            started: now,
            last_presence: now,
            last_tick: now,
            last_sync: now,
            last_dial: now,
            sync_cursor: 0,
            wanted: BTreeSet::new(),
            measured: BTreeMap::new(),
            unreferenced: BTreeMap::new(),
            verified_peers: BTreeSet::new(),
            rejected_addresses: BTreeSet::new(),
            rejected_address_order: VecDeque::new(),
            dial_failures: BTreeMap::new(),
            dials: BTreeMap::new(),
            gossip_budget: BTreeMap::new(),
            sync_budget: BTreeMap::new(),
            sync_in_flight: None,
            outbound_sync_budget: (now, 0),
            object_budget: BTreeMap::new(),
            put_object_budget: BTreeMap::new(),
            deposit_tx,
            deposits_in_flight: BTreeMap::new(),
            total_deposits_in_flight: 0,
            peer_sources: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            unjoined_source_budget: BTreeMap::new(),
            peer_admitted_at: BTreeMap::new(),
            disconnect_after: BTreeMap::new(),
            turned_away_keys: BTreeSet::new(),
            turned_away_order: VecDeque::new(),
            remote_admission: None,
            seed_dials: None,
            fetches: BTreeMap::new(),
            fetch_tags: BTreeMap::new(),
            relays: BTreeMap::new(),
            relay_tags: BTreeMap::new(),
            next_tag: TAG_FIRST_FETCH,
            leaving: None,
            turned_away: false,
            stopped: false,
        };

        // Forged proposal sharing exact block.hash() (bad signature + stripped body)
        // must not poison Seen::Block.
        let mut forged_sig_block = genuine_block.clone();
        forged_sig_block.proposer_signature[0] ^= 0xff;
        assert_eq!(forged_sig_block.hash(), block_hash);
        node.on_gossip(GardenGossip::Proposal(forged_sig_block), Some(guest_peer))
            .await;
        let mut forged_body_block = genuine_block.clone();
        forged_body_block.txs.clear();
        assert_eq!(forged_body_block.hash(), block_hash);
        node.on_gossip(GardenGossip::Proposal(forged_body_block), Some(guest_peer))
            .await;
        assert!(!node.proposals.contains_key(&block_hash));

        // Genuine leader proposal arrives next and must be accepted.
        node.on_gossip(
            GardenGossip::Proposal(genuine_block.clone()),
            Some(host_peer),
        )
        .await;
        assert!(
            node.proposals.contains_key(&block_hash),
            "bad-signature/body Proposal poisoned Seen::Block and dropped the genuine proposal"
        );

        // Zero-vote Commit carrying real block.hash() must not poison Seen::Commit.
        let voteless_commit = GardenCommit {
            block: genuine_block,
            votes: Vec::new(),
        };
        node.on_gossip(GardenGossip::Commit(voteless_commit), Some(guest_peer))
            .await;
        assert_eq!(node.ledger.state.height, 1);

        // Genuine quorum Commit arrives next and must finalize height 2.
        node.on_gossip(GardenGossip::Commit(genuine_commit), Some(host_peer))
            .await;
        assert_eq!(
            node.ledger.state.height, 2,
            "voteless Commit poisoned Seen::Commit and dropped the finalized commit"
        );
    }

    #[tokio::test]
    async fn waiting_presence_sync_hijack_and_late_non_holder_deposit_are_blocked() {
        let host_key = KeyPair::generate().unwrap();
        let waiter_key = KeyPair::generate().unwrap();
        let other_a = KeyPair::generate().unwrap();
        let other_b = KeyPair::generate().unwrap();
        let other_c = KeyPair::generate().unwrap();
        let token = [0x72u8; 32];
        let mut limits = GardenLimits::testnet_default();
        limits.admission = GardenAdmission::HostApproval;
        let genesis = GardenGenesis::new(
            GardenFounding {
                title: "admission-sync-storage-guard".into(),
                host_name: "host".into(),
                host_address: String::new(),
                limits,
            },
            host_key.public_key_bytes(),
            2_000,
            2,
            &token,
        )
        .unwrap();
        let chain_id = genesis.chain_id;
        let invite_signer = invite_keypair(&token).unwrap();
        let mut ledger = GardenLedger::new(genesis).unwrap();
        let all = [&host_key, &other_a, &other_b, &other_c];

        for (idx, kp) in [&other_a, &other_b, &other_c, &waiter_key]
            .iter()
            .enumerate()
        {
            let pk = kp.public_key_bytes();
            let join = GardenTx {
                chain_id,
                sender: pk,
                nonce: 0,
                kind: GardenTxKind::Join {
                    name: format!("m{idx}"),
                    address: String::new(),
                    invite_signature: invite_signer.sign(&join_message(chain_id, &pk)).to_vec(),
                },
            }
            .sign(kp)
            .unwrap();
            let ts = 2_100 + (ledger.state.height + 1) * 10;
            let c1 = build_signed_commit(&ledger, vec![join], &all, ts);
            ledger.append(c1).unwrap();
            if idx < 3 {
                let admit = GardenTx {
                    chain_id,
                    sender: host_key.public_key_bytes(),
                    nonce: ledger.state.next_nonce(&host_key.public_key_bytes()),
                    kind: GardenTxKind::Admit {
                        target: pk,
                        accept: true,
                    },
                }
                .sign(&host_key)
                .unwrap();
                let ts2 = 2_100 + (ledger.state.height + 1) * 10;
                let c2 = build_signed_commit(&ledger, vec![admit], &all, ts2);
                ledger.append(c2).unwrap();
            }
        }
        assert_eq!(
            ledger
                .state
                .validators
                .get(&waiter_key.public_key_bytes())
                .map(|v| v.status),
            Some(GardenValidatorStatus::Waiting)
        );

        let active = ledger.state.active();
        let mut non_held_bytes = Vec::new();
        let mut non_held_id = [0u8; 32];
        for nonce in 0u32..10_000 {
            let candidate = format!("payload-{nonce}").into_bytes();
            let cid = crate::storage::ContentId::of(&candidate).0;
            let holders = ledger.state.genesis.placement.holders(&cid, &active);
            if holders.len() == 3 && !holders.contains(&host_key.public_key_bytes()) {
                non_held_bytes = candidate;
                non_held_id = cid;
                break;
            }
        }
        assert!(
            !non_held_bytes.is_empty(),
            "must find non-holder content id"
        );

        let pub_tx = GardenTx {
            chain_id,
            sender: other_a.public_key_bytes(),
            nonce: ledger.state.next_nonce(&other_a.public_key_bytes()),
            kind: GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: non_held_id,
                size: u32::try_from(non_held_bytes.len()).unwrap(),
                caption: String::new(),
                mime: "text/plain".into(),
            },
        }
        .sign(&other_a)
        .unwrap();
        let pub_commit = build_signed_commit(&ledger, vec![pub_tx], &all, 3_000);
        ledger.append(pub_commit).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store_root = dir.path().join("objects");
        let mut store = GardenContentStore::open(Some(&store_root), 1024 * 1024).unwrap();
        let (path, _charged_len) = store
            .reserve_background_write(non_held_id, &non_held_bytes)
            .unwrap()
            .unwrap();
        let wrote_new =
            GardenContentStore::write_object_file_blocking(path, non_held_bytes.clone()).unwrap();
        assert!(wrote_new);

        let host_pk = host_key.public_key_bytes();
        let waiter_pk = waiter_key.public_key_bytes();
        let other_a_peer = peer_id_of(&other_a.public_key_bytes()).unwrap();
        let waiter_peer = peer_id_of(&waiter_pk).unwrap();
        let mut peers = BTreeMap::new();
        peers.insert(other_a_peer, other_a.public_key_bytes());
        peers.insert(waiter_peer, waiter_pk);
        let (net_tx, mut net_rx) = mpsc::channel(64);
        let (deposit_tx, _deposit_rx) = mpsc::channel(16);
        let now = Instant::now();
        let mut node = Node {
            key: host_key,
            me: host_pk,
            name: "host".into(),
            token,
            invite_signature: invite_signer
                .sign(&join_message(chain_id, &host_pk))
                .to_vec(),
            address: String::new(),
            seeds: Vec::new(),
            ledger,
            store,
            net: net_tx,
            link: None,
            reported: 0,
            budlum_status: None,
            budlum_error: None,
            peers,
            unadmitted: BTreeMap::new(),
            outbox: BTreeMap::new(),
            gossip_in_flight: BTreeMap::new(),
            held_elsewhere: 0,
            mempool: BTreeMap::new(),
            my_next_nonce: 3,
            proposals: BTreeMap::new(),
            candidate_rounds: BTreeMap::new(),
            votes: BTreeMap::new(),
            orphan_votes: VecDeque::new(),
            my_votes: BTreeSet::new(),
            host_voted: false,
            proposed_rounds: BTreeSet::new(),
            height_started: now,
            pending_since: None,
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            last_seen: BTreeMap::new(),
            presence_windows: BTreeMap::new(),
            my_window: 0,
            started: now,
            last_presence: now,
            last_tick: now,
            last_sync: now,
            last_dial: now,
            sync_cursor: 0,
            wanted: BTreeSet::new(),
            measured: BTreeMap::new(),
            unreferenced: BTreeMap::new(),
            verified_peers: BTreeSet::new(),
            rejected_addresses: BTreeSet::new(),
            rejected_address_order: VecDeque::new(),
            dial_failures: BTreeMap::new(),
            dials: BTreeMap::new(),
            gossip_budget: BTreeMap::new(),
            sync_budget: BTreeMap::new(),
            sync_in_flight: None,
            outbound_sync_budget: (now, 0),
            object_budget: BTreeMap::new(),
            put_object_budget: BTreeMap::new(),
            deposit_tx,
            deposits_in_flight: BTreeMap::new(),
            total_deposits_in_flight: 0,
            peer_sources: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            unjoined_source_budget: BTreeMap::new(),
            peer_admitted_at: BTreeMap::new(),
            disconnect_after: BTreeMap::new(),
            turned_away_keys: BTreeSet::new(),
            turned_away_order: VecDeque::new(),
            remote_admission: Some(GardenAdmissionState::Waiting),
            seed_dials: None,
            fetches: BTreeMap::new(),
            fetch_tags: BTreeMap::new(),
            relays: BTreeMap::new(),
            relay_tags: BTreeMap::new(),
            next_tag: TAG_FIRST_FETCH,
            leaving: None,
            turned_away: false,
            stopped: false,
        };

        // Track all four independent checks so a single run reports every failure.
        let waiter_presence = GardenPresence::sign(chain_id, 7, &waiter_key);
        node.on_gossip(GardenGossip::Presence(waiter_presence), Some(waiter_peer))
            .await;
        let waiter_presence_leaked = node.presence_windows.contains_key(&waiter_pk);

        node.on_response(
            other_a_peer,
            TAG_ADMISSION,
            Ok(GardenResponse::AdmissionStatus(
                GardenAdmissionState::Seated,
            )),
        )
        .await;
        let non_host_seated_cleared = node.remote_admission != Some(GardenAdmissionState::Waiting);
        node.sync_in_flight = None;
        while net_rx.try_recv().is_ok() {}

        let mut fake_future = node.ledger.commits.last().unwrap().block.clone();
        fake_future.header.height = node.ledger.state.height + 5;
        node.on_gossip(GardenGossip::Proposal(fake_future), Some(waiter_peer))
            .await;
        let unseated_hijacked_sync = node.sync_in_flight.is_some();

        let resp = node.finish_deposit(other_a.public_key_bytes(), non_held_id, false);
        assert!(matches!(resp, GardenResponse::Refused(_)));
        let non_holder_deposit_leaked =
            node.store.contains(&non_held_id) || node.store.total_bytes() != 0;

        // Public-prefix unjoined peer that idles past grace accrues a second strike
        // on expiry so the same /24 cannot immediately reclaim the freed slot.
        let grace = node.unjoined_grace();
        let replacement_peer = PeerId::random();
        {
            let mut map = node.peer_sources.lock().unwrap();
            map.insert(waiter_peer, net::SourceKey::V4([192, 0, 2]));
            map.insert(replacement_peer, net::SourceKey::V4([192, 0, 2]));
        }
        node.note_source_unjoined_admitted(waiter_peer, grace);
        node.peer_admitted_at.insert(
            waiter_peer,
            Instant::now() - grace - Duration::from_millis(50),
        );
        node.drop_strangers().await;
        let idle_cycler_blocked = node.source_unjoined_blocked(replacement_peer, grace);

        assert!(
            !waiter_presence_leaked
                && !non_host_seated_cleared
                && !unseated_hijacked_sync
                && !non_holder_deposit_leaked
                && idle_cycler_blocked,
            "failures: waiter_presence_leaked={waiter_presence_leaked}, \
             non_host_seated_cleared={non_host_seated_cleared}, \
             unseated_hijacked_sync={unseated_hijacked_sync}, \
             non_holder_deposit_leaked={non_holder_deposit_leaked}, \
             idle_cycler_blocked={idle_cycler_blocked}"
        );
    }
}
