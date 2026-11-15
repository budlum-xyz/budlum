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
//! The host has no other power. It cannot finalize a block the others did
//! not sign, and it proposes only in its own turn.

use super::invite::{GardenInvite, MAX_INVITE_PEERS};
use super::net::{
    self, announced_address, peer_id_of, validator_dial_address, GardenGossip, GardenNet,
    GardenRequest, GardenResponse, NetCommand, NetEvent, MAX_GOSSIP_BATCH, MAX_SYNC_COMMITS,
};
use super::settlement::{GardenBudlumLink, GardenDomainView};
use super::state::{quorum, GardenLedger, GardenObject, GardenState};
use super::storage::GardenContentStore;
use super::types::{
    garden_domain_id, invite_keypair, join_message, status_label, GardenBlock, GardenCommit,
    GardenContentKind, GardenFounding, GardenGenesis, GardenKey, GardenLimits,
    GardenPlacementTable, GardenPresence, GardenTx, GardenTxKind, GardenValidatorStatus,
    GardenVote, SignedGardenTx,
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
/// Most proposals a node keeps for one height.
const MAX_PROPOSALS: usize = 32;
/// Most votes kept while their block has not arrived.
const MAX_ORPHAN_VOTES: usize = 256;
/// Most gossip ids remembered to forward each item once.
const MAX_SEEN: usize = 16_384;
/// Most gossip items that wait for one peer. Past it the oldest is dropped:
/// finalized blocks come back through sync and presence is sent again.
const MAX_OUTBOX: usize = 2_048;
/// Most objects kept that no finalized transaction names yet.
const MAX_UNREFERENCED_OBJECTS: usize = 64;
/// Most such objects kept for one peer.
const MAX_UNREFERENCED_PER_PEER: usize = 8;
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
}

/// The library handle of a running Garden validator.
#[derive(Clone, Debug)]
pub struct GardenHandle {
    commands: mpsc::Sender<GardenCommand>,
    chain_id: u64,
}

impl GardenHandle {
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
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
    channel: Option<ResponseChannel<Vec<u8>>>,
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
    votes: BTreeMap<Hash32, BTreeMap<GardenKey, GardenVote>>,
    orphan_votes: VecDeque<GardenVote>,
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
    /// Objects no finalized transaction names yet, by the peer that
    /// deposited them. A peer that deposits too much loses its own.
    unreferenced: BTreeMap<GardenKey, VecDeque<Hash32>>,
    /// Validators dialed without an answer: when to dial next, and the
    /// wait that led there. It doubles with every dial.
    dials: BTreeMap<GardenKey, (Instant, Duration)>,
    /// The same record for the invite peers.
    seed_dials: Option<(Instant, Duration)>,
    fetches: BTreeMap<Hash32, Fetch>,
    fetch_tags: BTreeMap<u64, Hash32>,
    relays: BTreeMap<u64, Relay>,
    relay_tags: BTreeMap<u64, u64>,
    next_tag: u64,
    leaving: Option<Leaving>,
    stopped: bool,
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
            let outcome = tokio::time::timeout(
                BOOTSTRAP_TIMEOUT,
                bootstrap(&mut garden_net, &invite, &key, &mut peers),
            )
            .await;
            match outcome {
                Ok(Ok(ledger)) => (ledger, invite.token, invite.peers.clone()),
                Ok(Err(e)) => {
                    let _ = garden_net.commands.send(NetCommand::Shutdown).await;
                    return Err(e);
                }
                Err(_) => {
                    let _ = garden_net.commands.send(NetCommand::Shutdown).await;
                    return Err("no validator of this Garden answered the invite".into());
                }
            }
        }
    };

    let chain_id = ledger.state.chain_id();
    let limits = ledger.state.genesis.limits.clone();
    let content_dir = config
        .content_dir
        .as_ref()
        .map(|dir| dir.join(format!("{chain_id:016x}")));
    let store = GardenContentStore::open(content_dir.as_deref(), limits.max_object_bytes as usize)?;
    let invite_signature = invite_keypair(&token)?
        .sign(&join_message(chain_id, &me))
        .to_vec();

    let mut reported = 0;
    let mut budlum_status = None;
    if let Some(link) = &link {
        match link.view(chain_id).await {
            Some(view) => {
                reported = view.last_committed_height.min(ledger.state.height);
                budlum_status = Some(view.status);
            }
            None => {
                link.register(&ledger.state.genesis, me).await?;
                budlum_status = Some(DomainStatus::Active);
            }
        }
    }

    let (commands, command_rx) = mpsc::channel(256);
    let now = Instant::now();
    let my_next_nonce = ledger.state.next_nonce(&me);
    // What this node starts with came from the validators it synced from.
    let held_elsewhere = ledger.state.height;
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
        unreferenced: BTreeMap::new(),
        dials: BTreeMap::new(),
        seed_dials: None,
        fetches: BTreeMap::new(),
        fetch_tags: BTreeMap::new(),
        relays: BTreeMap::new(),
        relay_tags: BTreeMap::new(),
        next_tag: TAG_FIRST_FETCH,
        leaving: None,
        stopped: false,
    };
    tokio::spawn(node.run(garden_net.events, command_rx));
    Ok(GardenHandle { commands, chain_id })
}

/// Fetch and verify the genesis and the finalized chain from the peers an
/// invite names.
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
    let mut dialed = 0usize;
    for peer in &invite.peers {
        if let Ok(address) = peer.parse() {
            let _ = garden_net.commands.send(NetCommand::Dial(address)).await;
            dialed += 1;
        }
    }
    if dialed == 0 {
        return Err("invite carries no dialable peer address".into());
    }
    let mut ledger: Option<GardenLedger> = None;
    let mut source: Option<PeerId> = None;
    loop {
        let event = garden_net
            .events
            .recv()
            .await
            .ok_or_else(|| "garden swarm stopped while joining".to_string())?;
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
            } => match response {
                Ok(GardenResponse::Welcome {
                    genesis,
                    key: peer_key,
                    invite_signature,
                    ..
                }) => {
                    invite.accepts(&genesis)?;
                    if peer_id_of(&peer_key)? != peer
                        || verify_signature(
                            &join_message(invite.chain_id, &peer_key),
                            &invite_signature,
                            &invite_key.public_key_bytes(),
                        )
                        .is_err()
                    {
                        continue;
                    }
                    peers.insert(peer, peer_key);
                    if ledger.is_none() {
                        ledger = Some(GardenLedger::new(*genesis)?);
                        source = Some(peer);
                        let _ = garden_net
                            .commands
                            .send(NetCommand::Send {
                                peer,
                                request: GardenRequest::GetCommits {
                                    from_height: 1,
                                    max: MAX_SYNC_COMMITS,
                                },
                                tag: TAG_SYNC,
                            })
                            .await;
                    }
                }
                Ok(GardenResponse::Refused(reason)) => {
                    return Err(format!("a Garden validator refused the invite: {reason}"));
                }
                _ => {}
            },
            NetEvent::Response {
                peer,
                tag: TAG_SYNC,
                response,
            } if Some(peer) == source => {
                let Some(chain) = ledger.as_mut() else {
                    continue;
                };
                let commits = match response {
                    Ok(GardenResponse::Commits(commits)) => commits,
                    _ => return Err("the Garden chain could not be fetched".into()),
                };
                if commits.is_empty() {
                    return ledger.ok_or_else(|| "the Garden chain could not be fetched".into());
                }
                for commit in commits {
                    chain.append(commit)?;
                }
                let _ = garden_net
                    .commands
                    .send(NetCommand::Send {
                        peer,
                        request: GardenRequest::GetCommits {
                            from_height: chain.state.height.saturating_add(1),
                            max: MAX_SYNC_COMMITS,
                        },
                        tag: TAG_SYNC,
                    })
                    .await;
            }
            NetEvent::Response { .. } => {}
        }
    }
}

impl Node {
    async fn run(
        mut self,
        mut events: mpsc::Receiver<NetEvent>,
        mut commands: mpsc::Receiver<GardenCommand>,
    ) {
        let limits = self.ledger.state.genesis.limits.clone();
        let step = (limits.presence_interval_ms.min(limits.round_ms) / 4).clamp(10, 250);
        let mut ticker = tokio::time::interval(millis(step));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.dial_known().await;
        while !self.stopped {
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => self.on_net(event).await,
                    None => break,
                },
                command = commands.recv() => match command {
                    Some(command) => self.on_command(command).await,
                    None => {
                        self.shutdown().await;
                        break;
                    }
                },
                _ = ticker.tick() => self.on_tick().await,
            }
        }
    }

    const fn limits(&self) -> &GardenLimits {
        &self.ledger.state.genesis.limits
    }

    fn chain_id(&self) -> u64 {
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
        match self.last_seen.get(&self.ledger.state.host()) {
            Some(seen) => seen.elapsed() < timeout,
            None => self.started.elapsed() < timeout,
        }
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
        match self.last_seen.get(key) {
            Some(seen) => seen.elapsed() >= limit,
            None => self.started.elapsed() >= limit,
        }
    }

    async fn send(&self, peer: PeerId, request: GardenRequest, tag: u64) {
        let _ = self.net.send(NetCommand::Send { peer, request, tag }).await;
    }

    async fn respond(&self, channel: ResponseChannel<Vec<u8>>, response: GardenResponse) {
        let _ = self
            .net
            .send(NetCommand::Respond { channel, response })
            .await;
    }

    /// Queue `item` for every peer but `except`. Each peer gets one gossip
    /// request at a time; what arrives meanwhile leaves in the next batch.
    async fn gossip(&mut self, item: &GardenGossip, except: Option<PeerId>) {
        let targets: Vec<PeerId> = self
            .peers
            .keys()
            .filter(|peer| Some(**peer) != except)
            .copied()
            .collect();
        for peer in targets {
            let queue = self.outbox.entry(peer).or_default();
            if queue.len() >= MAX_OUTBOX {
                queue.pop_front();
            }
            queue.push_back(item.clone());
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
        let take = queue.len().min(MAX_GOSSIP_BATCH);
        if take == 0 {
            return;
        }
        let batch: Vec<GardenGossip> = queue.drain(..take).collect();
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
        let mut absent = BTreeSet::new();
        let mut targets = Vec::new();
        for validator in self.ledger.state.validators.values() {
            if validator.key == self.me
                || validator.status == GardenValidatorStatus::Left
                || connected.contains(&validator.key)
            {
                continue;
            }
            absent.insert(validator.key);
            let waiting = self
                .dials
                .get(&validator.key)
                .is_some_and(|(next, _)| now < *next);
            if waiting || targets.len() >= MAX_DIALS_PER_ROUND {
                continue;
            }
            if let Ok(address) = validator_dial_address(&validator.address, &validator.key) {
                let wait = self
                    .dials
                    .get(&validator.key)
                    .map_or(first_wait, |(_, wait)| wait.saturating_mul(2))
                    .min(MAX_DIAL_WAIT);
                self.dials.insert(validator.key, (now + wait, wait));
                targets.push(address);
            }
        }
        // A validator that connected or left starts over.
        self.dials.retain(|key, _| absent.contains(key));
        if self.peers.is_empty() {
            if self.seed_dials.is_none_or(|(next, _)| now >= next) {
                let wait = self
                    .seed_dials
                    .map_or(first_wait, |(_, wait)| wait.saturating_mul(2))
                    .min(MAX_DIAL_WAIT);
                self.seed_dials = Some((now + wait, wait));
                targets.extend(self.seeds.iter().filter_map(|seed| seed.parse().ok()));
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
                let hello = GardenRequest::Hello {
                    chain_id: self.chain_id(),
                    key: self.me,
                    invite_signature: self.invite_signature.clone(),
                };
                self.send(peer, hello, TAG_HELLO).await;
            }
            NetEvent::Disconnected(peer) => {
                self.peers.remove(&peer);
                self.unadmitted.remove(&peer);
                self.outbox.remove(&peer);
                self.gossip_in_flight.remove(&peer);
                self.finish_when_delivered().await;
            }
            NetEvent::Request {
                peer,
                request,
                channel,
            } => self.on_request(peer, request, channel).await,
            NetEvent::Response {
                peer,
                tag,
                response,
            } => self.on_response(peer, tag, response).await,
        }
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

    async fn on_request(
        &mut self,
        peer: PeerId,
        request: GardenRequest,
        channel: ResponseChannel<Vec<u8>>,
    ) {
        if let GardenRequest::Hello {
            chain_id,
            key,
            invite_signature,
        } = &request
        {
            let room = self.peers.len()
                < (self.limits().max_validators as usize)
                    .saturating_mul(2)
                    .saturating_add(8);
            let response = if *chain_id != self.chain_id() {
                GardenResponse::Refused("this node runs another Garden".into())
            } else if !self.holds_invite(peer, key, invite_signature) {
                GardenResponse::Refused("the invite does not match this Garden".into())
            } else if !room && !self.peers.contains_key(&peer) {
                GardenResponse::Refused("this validator has no room for more peers".into())
            } else {
                self.peers.insert(peer, *key);
                self.unadmitted.remove(&peer);
                GardenResponse::Welcome {
                    genesis: Box::new(self.ledger.state.genesis.clone()),
                    height: self.ledger.state.height,
                    key: self.me,
                    invite_signature: self.invite_signature.clone(),
                }
            };
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
                self.respond(channel, GardenResponse::Ack).await;
                for item in items {
                    self.on_gossip(item, Some(peer)).await;
                }
            }
            GardenRequest::GetCommits { from_height, max } => {
                let mut commits = Vec::new();
                let mut height = from_height.max(1);
                while commits.len() < max.min(MAX_SYNC_COMMITS) as usize {
                    match self.ledger.commit_at(height) {
                        Some((commit, _)) => commits.push(commit.clone()),
                        None => break,
                    }
                    height = height.saturating_add(1);
                }
                self.respond(channel, GardenResponse::Commits(commits))
                    .await;
            }
            GardenRequest::GetObject { content_id, relay } => {
                if let Some(bytes) = self.store.get(&content_id) {
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
                let response = match self.peers.get(&peer).copied() {
                    None => GardenResponse::Refused("show the invite first".into()),
                    Some(sender) => match self.store.put(&bytes) {
                        Ok(content_id) => {
                            self.note_unreferenced(sender, content_id);
                            GardenResponse::Ack
                        }
                        Err(e) => GardenResponse::Refused(e),
                    },
                };
                self.respond(channel, response).await;
            }
        }
    }

    fn fresh_tag(&mut self) -> u64 {
        self.next_tag = self.next_tag.wrapping_add(1).max(TAG_FIRST_FETCH);
        self.next_tag
    }

    /// Track an object no finalized transaction names yet, under the peer
    /// that deposited it. A peer past its share loses its own oldest
    /// object. When all peers together hold too many, the peer that holds
    /// most loses one, and a peer that is no active validator goes first:
    /// only a validator can publish.
    fn note_unreferenced(&mut self, sender: GardenKey, content_id: Hash32) {
        if self.ledger.state.objects.contains_key(&content_id) {
            return;
        }
        let queue = self.unreferenced.entry(sender).or_default();
        if queue.contains(&content_id) {
            return;
        }
        queue.push_back(content_id);
        let mut dropped = Vec::new();
        if queue.len() > MAX_UNREFERENCED_PER_PEER {
            dropped.extend(queue.pop_front());
        }
        let total: usize = self.unreferenced.values().map(VecDeque::len).sum();
        if total > MAX_UNREFERENCED_OBJECTS {
            let state = &self.ledger.state;
            let heaviest = self
                .unreferenced
                .iter()
                .max_by_key(|(key, queue)| (!state.is_active(key), queue.len()))
                .map(|(key, _)| *key);
            if let Some(queue) = heaviest.and_then(|key| self.unreferenced.get_mut(&key)) {
                dropped.extend(queue.pop_front());
            }
        }
        self.unreferenced.retain(|_, queue| !queue.is_empty());
        for old in dropped {
            let named = self.ledger.state.objects.contains_key(&old)
                || self.unreferenced.values().any(|queue| queue.contains(&old));
            if !named {
                self.store.remove(&old);
            }
        }
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
                if response.is_ok() && carried > self.held_elsewhere {
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
                        self.unadmitted.remove(&peer);
                    }
                }
            }
            TAG_SYNC => {
                if let Ok(GardenResponse::Commits(commits)) = response {
                    for commit in commits {
                        if commit.block.header.height != self.ledger.state.height.saturating_add(1)
                        {
                            continue;
                        }
                        if !self.apply_commit(commit, Some(peer), false).await {
                            break;
                        }
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

    async fn on_relay_answer(&mut self, job: u64, bytes: Option<Vec<u8>>) {
        let Some(relay) = self.relays.get_mut(&job) else {
            return;
        };
        relay.outstanding = relay.outstanding.saturating_sub(1);
        let valid =
            bytes.filter(|b| crate::storage::content_id::ContentId::of(b).0 == relay.content_id);
        let answer = match (valid, relay.outstanding) {
            (Some(bytes), _) => relay.channel.take().map(|c| (c, Some(bytes))),
            (None, 0) => relay.channel.take().map(|c| (c, None)),
            (None, _) => None,
        };
        if relay.outstanding == 0 {
            self.relays.remove(&job);
        }
        if let Some((channel, bytes)) = answer {
            self.respond(channel, GardenResponse::Object(bytes)).await;
        }
    }

    fn on_fetch_answer(&mut self, content_id: Hash32, bytes: Option<Vec<u8>>) {
        let Some(fetch) = self.fetches.get_mut(&content_id) else {
            return;
        };
        fetch.outstanding = fetch.outstanding.saturating_sub(1);
        let valid = bytes.filter(|b| crate::storage::content_id::ContentId::of(b).0 == content_id);
        match valid {
            Some(bytes) => {
                if let Some(fetch) = self.fetches.remove(&content_id) {
                    if fetch.keep && self.store.put_verified(&content_id, &bytes).is_ok() {
                        self.wanted.remove(&content_id);
                    }
                    for waiter in fetch.waiters {
                        let _ = waiter.send(Ok(bytes.clone()));
                    }
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
        let author = self.ledger.state.objects.get(content_id).map(|o| o.author);
        let mut ranked: Vec<(u8, PeerId)> = self
            .peers
            .iter()
            .map(|(peer, key)| {
                let rank = if holders.contains(key) {
                    0
                } else if Some(*key) == author {
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

    async fn on_gossip(&mut self, item: GardenGossip, from: Option<PeerId>) {
        match item {
            GardenGossip::Tx(tx) => {
                if self.first_sight(Seen::Tx(tx.id())) && self.admit_tx(tx.clone()) {
                    self.gossip(&GardenGossip::Tx(tx), from).await;
                }
            }
            GardenGossip::Proposal(block) => {
                let hash = block.hash();
                if !self.first_sight(Seen::Block(hash)) {
                    return;
                }
                if block.header.height > self.ledger.state.height.saturating_add(1) {
                    self.request_sync(from).await;
                    return;
                }
                if self.proposals.len() >= MAX_PROPOSALS
                    || self.ledger.state.verify_block(&block).is_err()
                {
                    return;
                }
                self.proposals.insert(hash, block.clone());
                self.gossip(&GardenGossip::Proposal(block), from).await;
                let orphans: Vec<GardenVote> = self.orphan_votes.drain(..).collect();
                for vote in orphans {
                    self.on_vote(vote, None).await;
                }
                self.consider(hash).await;
            }
            GardenGossip::Vote(vote) => self.on_vote(vote, from).await,
            GardenGossip::Commit(commit) => {
                let height = commit.block.header.height;
                if !self.first_sight(Seen::Commit(commit.block.hash())) {
                    return;
                }
                if height == self.ledger.state.height.saturating_add(1) {
                    self.apply_commit(commit, from, true).await;
                } else if height > self.ledger.state.height {
                    self.request_sync(from).await;
                }
            }
            GardenGossip::Presence(signal) => {
                let known = self.ledger.state.validators.contains_key(&signal.validator);
                let newer = self
                    .presence_windows
                    .get(&signal.validator)
                    .is_none_or(|window| signal.window > *window);
                if !known || !newer || signal.verify(self.chain_id()).is_err() {
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

    /// Put a transaction in the pending set. False when it is refused.
    fn admit_tx(&mut self, tx: SignedGardenTx) -> bool {
        if tx.verify(self.chain_id()).is_err()
            || tx.tx.nonce < self.ledger.state.next_nonce(&tx.tx.sender)
            || self.mempool.len() >= MAX_MEMPOOL
        {
            return false;
        }
        let per_sender = (self.limits().max_sender_txs_per_block as usize).saturating_mul(4);
        let held = self
            .mempool
            .range((tx.tx.sender, 0)..=(tx.tx.sender, u64::MAX))
            .count();
        let slot = (tx.tx.sender, tx.tx.nonce);
        if held >= per_sender || self.mempool.contains_key(&slot) {
            return false;
        }
        self.mempool.insert(slot, tx);
        if self.pending_since.is_none() {
            self.pending_since = Some(Instant::now());
        }
        true
    }

    async fn on_vote(&mut self, vote: GardenVote, from: Option<PeerId>) {
        if vote.chain_id != self.chain_id()
            || vote.height != self.ledger.state.height.saturating_add(1)
        {
            return;
        }
        let Some(block) = self.proposals.get(&vote.block_hash) else {
            if self.ledger.state.validators.contains_key(&vote.voter) {
                self.orphan_votes.push_back(vote);
                if self.orphan_votes.len() > MAX_ORPHAN_VOTES {
                    self.orphan_votes.pop_front();
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
        let base = match self.pending_since {
            Some(pending) => pending.max(self.height_started),
            None => self.height_started,
        };
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
        if !self.is_host() {
            if self.my_votes.insert(hash) {
                let vote = GardenVote::sign(&block.header, &self.key);
                self.first_sight(Seen::Vote(hash, self.me));
                self.gossip(&GardenGossip::Vote(vote), None).await;
            }
            return;
        }
        if self.host_voted || block.header.round > self.local_round().saturating_add(1) {
            return;
        }
        // The host does not sign away a validator it still hears from.
        let grace = millis(self.limits().suspend_after_ms / 2);
        let suspends_live = block.txs.iter().any(|tx| {
            matches!(&tx.tx.kind, GardenTxKind::Suspend { target } if !self.silent_for(target, grace))
        });
        if suspends_live {
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

    async fn request_sync(&mut self, from: Option<PeerId>) {
        let peer = match from.filter(|peer| self.peers.contains_key(peer)) {
            Some(peer) => Some(peer),
            None => {
                let count = self.peers.len().max(1);
                self.sync_cursor = self.sync_cursor.wrapping_add(1) % count;
                self.peers.keys().nth(self.sync_cursor).copied()
            }
        };
        if let Some(peer) = peer {
            self.last_sync = Instant::now();
            self.send(
                peer,
                GardenRequest::GetCommits {
                    from_height: self.ledger.state.height.saturating_add(1),
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
        if from.is_some() {
            self.held_elsewhere = self.held_elsewhere.max(commit.block.header.height);
        }
        self.proposals.clear();
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
                for queue in self.unreferenced.values_mut() {
                    queue.retain(|id| id != content_id);
                }
            }
            if matches!(
                tx.tx.kind,
                GardenTxKind::Join { .. } | GardenTxKind::Resume { .. }
            ) {
                self.last_seen.insert(tx.tx.sender, Instant::now());
            }
        }
        if active_before == self.ledger.state.active() {
            for tx in &commit.block.txs {
                if let GardenTxKind::Publish { content_id, .. } = &tx.tx.kind {
                    self.want_if_holder(*content_id);
                }
            }
        } else {
            let ids: Vec<Hash32> = self.ledger.state.objects.keys().copied().collect();
            for id in ids {
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

    /// Enter or re-enter the identity record when this node is not active.
    async fn ensure_membership(&mut self) {
        if self.leaving.is_some() {
            return;
        }
        let recorded = self.ledger.state.validators.get(&self.me);
        let settled = recorded.is_some_and(|v| {
            v.status == GardenValidatorStatus::Active && v.address == self.address
        });
        let record = recorded.map(|v| v.status);
        let kind = match record {
            Some(_) if settled => return,
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
        self.proposals.insert(hash, block.clone());
        self.gossip(&GardenGossip::Proposal(block), None).await;
        self.consider(hash).await;
    }

    /// Close the connections of peers that did not show the invite in time.
    /// A refusal reaches the peer first: the grace is far longer than one
    /// answer takes. Without this a peer that holds no invite keeps one of
    /// the connection slots for as long as it keeps talking.
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
            self.request_sync(None).await;
            let missing: Vec<Hash32> = self
                .wanted
                .iter()
                .filter(|id| !self.fetches.contains_key(*id))
                .copied()
                .take(FETCH_FANOUT)
                .collect();
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
        if self.ledger.state.status == DomainStatus::Retired && self.leaving.is_none() {
            // The Garden ended while this node was not part of the last
            // block. Nothing is left to follow, so the node wipes and stops.
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
                None if !self.ledger.state.objects.contains_key(&content_id) => {
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
        }
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
            if validator.status != GardenValidatorStatus::Left
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
        peers.truncate(MAX_INVITE_PEERS);
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
        let by_content = state.objects.get(tx_id).map(|object| object.tx_id);
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
                })
            })
            .collect();
        let budlum = match &self.link {
            Some(link) => match link.view(self.chain_id()).await {
                Some(view) => budlum_record(&view, self.budlum_error.as_deref()),
                None => json!({ "linked": false, "error": self.budlum_error }),
            },
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
                "member": state.validators.get(&self.me).map(|v| v.status.label()),
                "leaving": self.leaving.is_some(),
            },
            "validators": validators,
            "active_validators": state.active().len(),
            "connected_peers": self.peers.len(),
            "pending_transactions": self.mempool.len(),
            "objects": state.objects.len(),
            "objects_wanted_here": self.wanted.len(),
            "limits": {
                "max_validators": limits.max_validators,
                "max_object_bytes": limits.max_object_bytes,
                "max_block_txs": limits.max_block_txs,
                "max_sender_txs_per_block": limits.max_sender_txs_per_block,
                "round_ms": limits.round_ms,
                "presence_interval_ms": limits.presence_interval_ms,
                "host_timeout_ms": limits.host_timeout_ms,
                "suspend_after_ms": limits.suspend_after_ms,
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
        let invite = self.invite().unwrap_or_else(|_| GardenInvite {
            chain_id,
            genesis_hash: self.ledger.state.genesis.hash(),
            token: self.token,
            peers: self.seeds.clone(),
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
        assert!(!stood_still(window / 2 - Duration::from_millis(1), &limits));
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
}
