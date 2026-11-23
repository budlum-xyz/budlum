//! The node-level Garden entry point behind the `bud_garden*` RPC methods.
//!
//! A node holds at most one Garden at a time. Creating, joining and leaving
//! are local actions of the node: they start or stop the validator runtime.
//! Everything that changes the Garden itself goes through a block.
//!
//! The service never acts for a key a caller names. It signs with the key of
//! this node's own validator, which lives in memory only.

use super::invite::GardenInvite;
use super::node::{
    random_bytes, spawn, GardenEntry, GardenHandle, GardenLeaveOutcome, GardenNodeConfig,
};
use super::settlement::GardenBudlumLink;
use super::types::{status_label, GardenAdmission, GardenContentKind, GardenLimits};
use crate::chain::chain_actor::ChainHandle;
use crate::crypto::primitives::KeyPair;
use crate::domain::types::Hash32;
use crate::garden::invite_record::GardenInviteRecord;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// The address a Garden swarm listens on when the caller names none. It is
/// unspecified, so the validator is treated as not reachable from outside
/// and is reached through the peers it dialed.
const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/tcp/0";
/// How long entering a Garden may take.
const ENTER_TIMEOUT: Duration = Duration::from_mins(1);
/// Largest payload a publish request may carry as text, in bytes.
const MAX_PUBLISH_TEXT_BYTES: usize = 40 * 1024 * 1024;

/// Optional settings of `bud_gardenCreate` and `bud_gardenJoin`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GardenOptions {
    /// Multiaddr the Garden swarm listens on.
    pub listen: Option<String>,
    /// Reachable address to announce, without the peer id.
    pub announce: Option<String>,
    pub max_validators: Option<u32>,
    pub max_object_bytes: Option<u32>,
    pub max_block_txs: Option<u32>,
    pub max_sender_txs_per_block: Option<u32>,
    pub round_ms: Option<u32>,
    pub presence_interval_ms: Option<u32>,
    pub host_timeout_ms: Option<u32>,
    pub suspend_after_ms: Option<u32>,
    pub max_published_bytes_per_validator: Option<u64>,
    /// How an invite holder becomes a validator: `direct` (default) or
    /// `host_approval`. Read at the founding only.
    pub admission: Option<String>,
}

impl GardenOptions {
    fn limits(&self) -> Result<GardenLimits, String> {
        let base = GardenLimits::testnet_default();
        let limits = GardenLimits {
            max_validators: self.max_validators.unwrap_or(base.max_validators),
            max_object_bytes: self.max_object_bytes.unwrap_or(base.max_object_bytes),
            max_block_txs: self.max_block_txs.unwrap_or(base.max_block_txs),
            max_sender_txs_per_block: self
                .max_sender_txs_per_block
                .unwrap_or(base.max_sender_txs_per_block),
            round_ms: self.round_ms.unwrap_or(base.round_ms),
            presence_interval_ms: self
                .presence_interval_ms
                .unwrap_or(base.presence_interval_ms),
            host_timeout_ms: self.host_timeout_ms.unwrap_or(base.host_timeout_ms),
            suspend_after_ms: self.suspend_after_ms.unwrap_or(base.suspend_after_ms),
            max_published_bytes_per_validator: self
                .max_published_bytes_per_validator
                .unwrap_or(base.max_published_bytes_per_validator),
            admission: match &self.admission {
                Some(label) => GardenAdmission::parse(label)?,
                None => base.admission,
            },
        };
        limits.validate()?;
        Ok(limits)
    }
}

/// What this node needs to take its place in a Garden again.
struct Seat {
    secret: [u8; 32],
    config: GardenNodeConfig,
}

enum Slot {
    Empty,
    Running(GardenHandle, Seat),
    /// The node left and may return while the Garden lives.
    Away(Seat, GardenInvite),
}

/// The Garden of this node.
pub struct GardenService {
    chain: Option<ChainHandle>,
    content_dir: Option<PathBuf>,
    slot: Mutex<Slot>,
}

impl std::fmt::Debug for GardenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GardenService")
            .field("content_dir", &self.content_dir)
            .finish_non_exhaustive()
    }
}

/// Wall-clock milliseconds, used to judge an invite record's expiry.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn parse_id(label: &str, value: &str) -> Result<Hash32, String> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|_| format!("{label} must be 64 hex digits"))?;
    Hash32::try_from(bytes.as_slice()).map_err(|_| format!("{label} must be 64 hex digits"))
}

impl GardenService {
    /// Build the service of a node.
    ///
    /// `chain` is the node's Budlum chain; with it every Garden registers as
    /// a domain there. `data_dir` is the node's data directory; Garden
    /// content goes under `garden/` inside it. A validator key never
    /// survives a restart, so anything a stopped process left there belongs
    /// to no one and is removed.
    pub fn new(chain: Option<ChainHandle>, data_dir: Option<PathBuf>) -> Self {
        let content_dir = data_dir.map(|dir| dir.join("garden"));
        if let Some(dir) = &content_dir {
            if dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(error = %e, "stale garden content could not be removed");
                }
            }
        }
        Self {
            chain,
            content_dir,
            slot: Mutex::new(Slot::Empty),
        }
    }

    fn link(&self) -> Option<GardenBudlumLink> {
        self.chain.clone().map(GardenBudlumLink::new)
    }

    fn config(&self, name: String, options: &GardenOptions) -> GardenNodeConfig {
        GardenNodeConfig {
            name,
            listen: options
                .listen
                .clone()
                .unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
            announce: options.announce.clone(),
            content_dir: self.content_dir.clone(),
        }
    }

    /// Wait until the validator is in the identity record: as active, or as
    /// waiting for the host in a Garden founded with host approval.
    async fn wait_until_member(handle: &GardenHandle) -> Result<Value, String> {
        let started = Instant::now();
        loop {
            let status = handle.status().await?;
            let member = status.pointer("/me/member").and_then(Value::as_str);
            // Under host approval the request standing in the record is as
            // far as the node gets on its own: the answer is the host's and
            // has no deadline.
            if member == Some("Active") || member == Some("Waiting") {
                return Ok(status);
            }
            if started.elapsed() >= ENTER_TIMEOUT {
                let _ = handle.leave().await;
                return Err(
                    "the Garden did not admit this node in time; it may be frozen or full".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Drop the link of an earlier Garden the node walked away from.
    async fn forget(&self, seat: &Seat, invite: &GardenInvite) {
        if let (Some(link), Ok(key)) = (self.link(), KeyPair::from_seed(&seat.secret)) {
            if let Err(e) = link.retire(invite.chain_id, key.public_key_bytes()).await {
                tracing::warn!(error = %e, "garden domain could not be retired");
            }
        }
    }

    async fn enter(
        &self,
        entry: GardenEntry,
        seat: Seat,
    ) -> Result<(GardenHandle, Seat, Value), String> {
        let handle = spawn(entry, seat.config.clone(), seat.secret, self.link()).await?;
        let status = Self::wait_until_member(&handle).await?;
        Ok((handle, seat, status))
    }

    /// Found a Garden. This node becomes its host.
    ///
    /// # Errors
    ///
    /// Refuses when the node already runs or holds a seat in a Garden, when
    /// the title, the name or a limit is out of bounds, and when the host
    /// has no address the others can dial.
    pub async fn create(
        &self,
        title: String,
        name: String,
        options: GardenOptions,
    ) -> Result<Value, String> {
        let limits = options.limits()?;
        let mut slot = self.slot.lock().await;
        match &*slot {
            Slot::Running(..) => {
                return Err("this node already runs a Garden; leave it first".into())
            }
            Slot::Away(seat, invite) => self.forget(seat, invite).await,
            Slot::Empty => {}
        }
        *slot = Slot::Empty;
        let seat = Seat {
            secret: random_bytes(),
            config: self.config(name, &options),
        };
        let (handle, seat, status) = self
            .enter(GardenEntry::Create { title, limits }, seat)
            .await?;
        let link = handle.invite().await?.to_link();
        *slot = Slot::Running(handle, seat);
        drop(slot);
        Ok(json!({ "garden": status, "invite": link, "qr": link }))
    }

    /// Join a Garden with an invite link or QR content.
    ///
    /// # Errors
    ///
    /// Refuses when the invite is malformed or names a primary Budlum chain,
    /// when the node already runs or holds a seat in a Garden, and when no
    /// validator of the Garden admits the node in time.
    pub async fn join(
        &self,
        invite: String,
        name: String,
        options: GardenOptions,
    ) -> Result<Value, String> {
        // A joiner may arrive with the old line, with the record link, with the
        // local-address QR content, or with the bare record a clipboard held.
        // The record forms are verified before anything else happens: a forged,
        // expired or spent record is refused with its reason.
        let invite = match GardenInviteRecord::parse_any(&invite) {
            Ok(record) => {
                record.verify_join(
                    now_unix_ms(),
                    0,
                    crate::garden::invite_record::INVITE_RECORD_VERSION,
                )?;
                record.to_invite()?
            }
            Err(_) => GardenInvite::parse(&invite)?,
        };
        let mut slot = self.slot.lock().await;
        match &*slot {
            Slot::Running(..) => {
                return Err("this node already runs a Garden; leave it first".into())
            }
            Slot::Away(_, away) if away.chain_id == invite.chain_id => {
                return Err(
                    "this node only stepped out of that Garden; use bud_gardenReturn".into(),
                )
            }
            Slot::Away(seat, away) => self.forget(seat, away).await,
            Slot::Empty => {}
        }
        *slot = Slot::Empty;
        let seat = Seat {
            secret: random_bytes(),
            config: self.config(name, &options),
        };
        let (handle, seat, status) = self.enter(GardenEntry::Invite(invite), seat).await?;
        *slot = Slot::Running(handle, seat);
        drop(slot);
        Ok(json!({ "garden": status }))
    }

    /// Leave the Garden. The node wipes the Garden data from its disk and
    /// keeps what it needs to return. Leaving again while away forgets the
    /// Garden for good.
    ///
    /// # Errors
    ///
    /// Refuses when the node is in no Garden, and when the validator stopped
    /// before it could answer.
    pub async fn leave(&self) -> Result<Value, String> {
        let mut slot = self.slot.lock().await;
        match std::mem::replace(&mut *slot, Slot::Empty) {
            Slot::Empty => Err("this node is in no Garden".into()),
            Slot::Running(handle, seat) => {
                let outcome: GardenLeaveOutcome = match handle.leave().await {
                    Ok(outcome) => outcome,
                    Err(e) => {
                        // The validator did not answer; it keeps its place
                        // so the caller can look at it and try again.
                        *slot = Slot::Running(handle, seat);
                        return Err(e);
                    }
                };
                let answer = json!({
                    "left": true,
                    "retired": outcome.retired,
                    "can_return": !outcome.retired,
                    "chain_id": format!("{:016x}", outcome.chain_id),
                    "height": outcome.height,
                });
                if !outcome.retired {
                    *slot = Slot::Away(seat, outcome.invite);
                }
                drop(slot);
                Ok(answer)
            }
            Slot::Away(seat, invite) => {
                self.forget(&seat, &invite).await;
                drop(slot);
                Ok(json!({
                    "left": true,
                    "retired": true,
                    "can_return": false,
                    "chain_id": format!("{:016x}", invite.chain_id),
                }))
            }
        }
    }

    /// Return to the Garden this node stepped out of.
    ///
    /// # Errors
    ///
    /// Refuses when the node has no Garden to return to or is already in
    /// it, and when the Garden does not admit the node in time. The seat is
    /// kept in the second case, so the node can try again.
    pub async fn rejoin(&self) -> Result<Value, String> {
        let mut slot = self.slot.lock().await;
        match std::mem::replace(&mut *slot, Slot::Empty) {
            Slot::Away(seat, invite) => {
                let again = Seat {
                    secret: seat.secret,
                    config: seat.config.clone(),
                };
                match self.enter(GardenEntry::Invite(invite.clone()), again).await {
                    Ok((handle, seat, status)) => {
                        *slot = Slot::Running(handle, seat);
                        drop(slot);
                        Ok(json!({ "garden": status }))
                    }
                    Err(e) => {
                        *slot = Slot::Away(seat, invite);
                        drop(slot);
                        Err(e)
                    }
                }
            }
            other => {
                let running = matches!(other, Slot::Running(..));
                *slot = other;
                Err(if running {
                    "this node is already in its Garden".into()
                } else {
                    "this node has no Garden to return to".into()
                })
            }
        }
    }

    /// The running validator, or the reason there is none.
    async fn running(&self) -> Result<GardenHandle, String> {
        match &*self.slot.lock().await {
            Slot::Running(handle, _) => Ok(handle.clone()),
            Slot::Away(..) => Err("this node stepped out of its Garden; return first".into()),
            Slot::Empty => Err("this node is in no Garden".into()),
        }
    }

    /// The Garden as this node sees it, and its status on Budlum.
    ///
    /// # Errors
    ///
    /// Fails when the validator stopped before it could answer.
    pub async fn status(&self) -> Result<Value, String> {
        let mut slot = self.slot.lock().await;
        let (stopped, stopped_genesis) = match &*slot {
            Slot::Empty => return Ok(json!({ "garden": Value::Null })),
            Slot::Away(_, invite) => {
                let budlum = match self.link() {
                    Some(link) => link
                        .view_for_genesis(invite.chain_id, invite.genesis_hash)
                        .await
                        .map(|view| {
                            json!({
                                "linked": true,
                                "domain_id": view.domain_id,
                                "status": status_label(view.status),
                                "finalized_height": view.last_committed_height,
                            })
                        }),
                    None => None,
                };
                return Ok(json!({
                    "garden": {
                        "chain_id": format!("{:016x}", invite.chain_id),
                        "status": "Away",
                        "budlum": budlum,
                    }
                }));
            }
            Slot::Running(handle, _) => match handle.status().await {
                Ok(status) => return Ok(json!({ "garden": status })),
                Err(_) => (handle.chain_id(), handle.genesis_hash()),
            },
        };
        // The validator stopped on its own: the Garden ended without it.
        *slot = Slot::Empty;
        let budlum = match self.link() {
            Some(link) => link
                .view_for_genesis(stopped, stopped_genesis)
                .await
                .map(|view| json!({ "status": status_label(view.status) })),
            None => None,
        };
        Ok(
            json!({ "garden": Value::Null, "ended": { "chain_id": format!("{stopped:016x}"), "budlum": budlum } }),
        )
    }

    /// The invite link of the running Garden. It is also the QR content.
    ///
    /// The answer also carries the invite *record* the optimisation directive
    /// asks for: one record, four transports. `record` is the canonical text a
    /// clipboard or a local announcement carries, `record_link` is
    /// `budlum://garden/join#<record>`, and `record_qr` is the local-address
    /// form `http://<address>/g#<record>`. `invite` and `qr` keep answering
    /// the line they have always answered, so an older client keeps working.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not running in a Garden, and when it has no
    /// address another node can dial.
    pub async fn invite(&self) -> Result<Value, String> {
        let handle = self.running().await?;
        let link = handle.invite().await?.to_link();
        let record = handle.invite_record().await?;
        Ok(json!({
            "invite": link,
            "qr": link,
            "record": record.encode()?,
            "record_link": record.link()?,
            "record_qr": record.qr(Some(&record.host_address))?,
            "record_expires_unix_ms": record.expires_unix_ms,
            "record_max_uses": record.max_uses,
        }))
    }

    /// Answer a key that waits for the host. `key` is the validator key as
    /// the status lists it; `accept` seats it or turns it away.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not running in a Garden or is not its host,
    /// when the key is malformed, and when the key is not waiting.
    pub async fn admit(&self, key: String, accept: bool) -> Result<Value, String> {
        let target = parse_id("key", &key)?;
        self.running().await?.admit(target, accept).await
    }

    /// Publish a message, a post or an image. `encoding` is `utf8` or `hex`.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not an active validator of a running
    /// Garden, when the kind, the encoding, the MIME type or the caption is
    /// invalid, when the object is empty or larger than the Garden allows,
    /// and when the node holds too many pending transactions.
    pub async fn publish(
        &self,
        kind: String,
        payload: String,
        encoding: Option<String>,
        mime: Option<String>,
        caption: Option<String>,
    ) -> Result<Value, String> {
        let kind = GardenContentKind::parse(&kind)?;
        if payload.len() > MAX_PUBLISH_TEXT_BYTES {
            return Err("payload is too large".into());
        }
        let (bytes, default_mime) = match encoding.as_deref().unwrap_or("utf8") {
            "utf8" => (payload.into_bytes(), "text/plain; charset=utf-8"),
            "hex" => (
                hex::decode(&payload).map_err(|_| "payload is not hex".to_string())?,
                "application/octet-stream",
            ),
            other => return Err(format!("unknown encoding '{other}', expected utf8 or hex")),
        };
        self.running()
            .await?
            .publish(
                kind,
                bytes,
                mime.unwrap_or_else(|| default_mime.to_string()),
                caption.unwrap_or_default(),
            )
            .await
    }

    /// Resolve an object on this node and verify it against its content id.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not running in a Garden, when the id is not
    /// 32 bytes of hex, when the Garden never published the object, and when
    /// no connected validator serves bytes that match the id.
    pub async fn resolve(&self, content_id: String) -> Result<Value, String> {
        let id = parse_id("content id", &content_id)?;
        let bytes = self.running().await?.resolve(id).await?;
        Ok(json!({
            "content_id": hex::encode(id),
            "size": bytes.len(),
            "verified": true,
            "text": std::str::from_utf8(&bytes).ok(),
            "hex": hex::encode(&bytes),
        }))
    }

    /// The path of a transaction, or of a published object, through the
    /// chain: the transaction, its block and the validators that signed.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not running in a Garden, when the id is not
    /// 32 bytes of hex, and when the Garden knows no such transaction or
    /// object.
    pub async fn trace(&self, id: String) -> Result<Value, String> {
        let id = parse_id("transaction id", &id)?;
        self.running().await?.trace(id).await
    }

    /// The newest published objects.
    ///
    /// # Errors
    ///
    /// Refuses when the node is not running in a Garden.
    pub async fn feed(&self, limit: Option<u32>) -> Result<Value, String> {
        self.running()
            .await?
            .feed(limit.unwrap_or(50) as usize)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::blockchain::Blockchain;
    use crate::chain::chain_actor::ChainActor;
    use crate::consensus::pow::PoWEngine;
    use crate::core::chain_config::Network;
    use crate::domain::types::DomainStatus;
    use std::path::Path;

    fn options() -> GardenOptions {
        GardenOptions {
            listen: Some("/ip4/127.0.0.1/tcp/0".into()),
            round_ms: Some(200),
            presence_interval_ms: Some(200),
            host_timeout_ms: Some(1500),
            suspend_after_ms: Some(3000),
            ..GardenOptions::default()
        }
    }

    fn text(value: &Value, pointer: &str) -> String {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no text at {pointer} in {value}"))
            .to_string()
    }

    fn files_under(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(next) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    found.push(path);
                }
            }
        }
        found
    }

    async fn wait_final(service: &GardenService, tx: &str) -> Value {
        for _ in 0..600 {
            if let Ok(trace) = service.trace(tx.to_string()).await {
                if trace.pointer("/stage").and_then(Value::as_str) == Some("final") {
                    return trace;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("transaction {tx} did not become final");
    }

    async fn wait_status(service: &GardenService, wanted: &str) -> Value {
        let mut last = Value::Null;
        for _ in 0..600 {
            last = service.status().await.unwrap();
            if last.pointer("/garden/status").and_then(Value::as_str) == Some(wanted) {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("Garden did not become {wanted}: {last}");
    }

    #[tokio::test]
    async fn garden_service_holds_one_garden_and_bounds_what_a_caller_asks_for() {
        let service = GardenService::new(None, None);
        let huge = GardenOptions {
            max_validators: Some(1_000_000),
            ..options()
        };
        let refusal = service
            .create("Room".into(), "host".into(), huge)
            .await
            .unwrap_err();
        assert!(refusal.contains("max_validators"), "{refusal}");
        let huge = GardenOptions {
            max_object_bytes: Some(u32::MAX),
            ..options()
        };
        assert!(service
            .create("Room".into(), "host".into(), huge)
            .await
            .is_err());
        assert_eq!(service.status().await.unwrap()["garden"], Value::Null);

        service
            .create("Room".into(), "host".into(), options())
            .await
            .unwrap();
        for _ in 0..3 {
            let refusal = service
                .create("Another".into(), "host".into(), options())
                .await
                .unwrap_err();
            assert!(refusal.contains("already runs a Garden"), "{refusal}");
        }
        let unknown: Result<GardenOptions, _> =
            serde_json::from_value(json!({ "listen": "/ip4/127.0.0.1/tcp/0", "peers": 9 }));
        assert!(unknown.is_err());
        service.leave().await.unwrap();
    }

    #[tokio::test]
    async fn garden_service_keeps_caller_text_out_of_file_paths() {
        let dir = tempfile::tempdir().unwrap();
        let service = GardenService::new(None, Some(dir.path().to_path_buf()));
        for (title, name) in [
            ("../../outside", "host"),
            ("Room", "../../outside"),
            ("Room", "a/b"),
            ("Room\u{0}", "host"),
            ("Room", ""),
        ] {
            assert!(
                service
                    .create(title.into(), name.into(), options())
                    .await
                    .is_err(),
                "{title:?} / {name:?} was accepted"
            );
        }
        assert!(files_under(dir.path()).is_empty());

        let created = service
            .create("Room".into(), "host".into(), options())
            .await
            .unwrap();
        let chain_id = text(&created, "/garden/chain_id");
        let published = service
            .publish("post".into(), "a post".into(), None, None, None)
            .await
            .unwrap();
        wait_final(&service, &text(&published, "/tx_id")).await;
        let files = files_under(dir.path());
        assert!(!files.is_empty());
        let root = dir.path().join("garden").join(&chain_id);
        for file in &files {
            assert!(file.starts_with(&root), "{file:?} is outside {root:?}");
        }
        let left = service.leave().await.unwrap();
        assert_eq!(left["retired"], json!(true));
        assert!(files_under(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn garden_service_removes_what_a_stopped_process_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("garden").join("00000000000000aa");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("object"), b"left over").unwrap();
        std::fs::write(dir.path().join("other"), b"not garden data").unwrap();
        let _service = GardenService::new(None, Some(dir.path().to_path_buf()));
        assert_eq!(files_under(dir.path()), vec![dir.path().join("other")]);
    }

    #[tokio::test]
    async fn garden_services_share_content_and_wipe_it_when_they_leave() {
        let host_dir = tempfile::tempdir().unwrap();
        let guest_dir = tempfile::tempdir().unwrap();
        let host = GardenService::new(None, Some(host_dir.path().to_path_buf()));
        let guest = GardenService::new(None, Some(guest_dir.path().to_path_buf()));
        let created = host
            .create("Room".into(), "host".into(), options())
            .await
            .unwrap();
        let invite = text(&created, "/invite");
        assert_eq!(invite, text(&created, "/qr"));
        let joined = guest
            .join(invite.clone(), "guest".into(), options())
            .await
            .unwrap();
        assert_eq!(text(&joined, "/garden/me/member"), "Active");

        let image = vec![0x5a_u8; 70_000];
        let published = guest
            .publish(
                "image".into(),
                hex::encode(&image),
                Some("hex".into()),
                Some("image/png".into()),
                None,
            )
            .await
            .unwrap();
        let tx = text(&published, "/tx_id");
        let content_id = text(&published, "/content_id");
        let trace = wait_final(&host, &tx).await;
        assert_eq!(text(&trace, "/transaction/sender_name"), "guest");
        assert_eq!(trace.pointer("/finality/needed"), Some(&json!(2)));
        let resolved = host.resolve(content_id.clone()).await.unwrap();
        assert_eq!(text(&resolved, "/hex"), hex::encode(&image));
        assert_eq!(text(&resolved, "/content_id"), content_id);
        assert!(!files_under(host_dir.path()).is_empty());

        // The guest steps out: its disk is clean and it may come back.
        let left = guest.leave().await.unwrap();
        assert_eq!(left["can_return"], json!(true));
        assert!(files_under(guest_dir.path()).is_empty());
        assert_eq!(
            text(&guest.status().await.unwrap(), "/garden/status"),
            "Away"
        );
        assert!(guest.resolve(content_id.clone()).await.is_err());
        let refusal = guest
            .join(invite, "guest".into(), options())
            .await
            .unwrap_err();
        assert!(refusal.contains("bud_gardenReturn"), "{refusal}");
        let back = guest.rejoin().await.unwrap();
        assert_eq!(text(&back, "/garden/me/member"), "Active");
        let resolved = guest.resolve(content_id.clone()).await.unwrap();
        assert_eq!(text(&resolved, "/hex"), hex::encode(&image));

        // The host steps out: the Garden stands still and stays readable.
        host.leave().await.unwrap();
        wait_status(&guest, "Frozen").await;
        let refusal = guest
            .publish("message".into(), "anyone?".into(), None, None, None)
            .await
            .unwrap_err();
        assert!(refusal.contains("frozen"), "{refusal}");
        assert_eq!(
            text(&guest.resolve(content_id.clone()).await.unwrap(), "/hex"),
            hex::encode(&image)
        );
        host.rejoin().await.unwrap();
        wait_status(&guest, "Active").await;

        // Everyone leaves: the Garden is over and no disk keeps its data.
        let left = guest.leave().await.unwrap();
        assert_eq!(left["retired"], json!(false));
        let left = host.leave().await.unwrap();
        assert_eq!(left["retired"], json!(true));
        assert_eq!(host.status().await.unwrap()["garden"], Value::Null);
        assert!(files_under(host_dir.path()).is_empty());
        assert!(files_under(guest_dir.path()).is_empty());
        assert!(host.rejoin().await.is_err());
    }

    #[tokio::test]
    async fn garden_service_shows_the_garden_on_budlum_until_it_retires() {
        let blockchain = Blockchain::new(
            std::sync::Arc::new(PoWEngine::new(2)),
            None,
            Network::Devnet.chain_id().value(),
            None,
        );
        let (actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            actor.run().await;
        });
        let service = GardenService::new(Some(chain.clone()), None);
        let created = service
            .create("Room".into(), "host".into(), options())
            .await
            .unwrap();
        assert_eq!(text(&created, "/garden/budlum/status"), "Active");
        let domain_id = created
            .pointer("/garden/budlum/domain_id")
            .and_then(Value::as_u64)
            .unwrap();

        let published = service
            .publish("message".into(), "hello".into(), None, None, None)
            .await
            .unwrap();
        wait_final(&service, &text(&published, "/tx_id")).await;
        let mut reported = false;
        for _ in 0..200 {
            let status = service.status().await.unwrap();
            let height = status.pointer("/garden/height").and_then(Value::as_u64);
            if height.is_some()
                && status
                    .pointer("/garden/budlum/finalized_height")
                    .and_then(Value::as_u64)
                    == height
                && text(&status, "/garden/budlum/finalized_hash")
                    == text(&status, "/garden/last_hash")
            {
                reported = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(reported, "Budlum did not record the Garden block");
        let record = |domains: Vec<crate::domain::ConsensusDomain>| {
            domains
                .into_iter()
                .find(|domain| u64::from(domain.id) == domain_id)
                .unwrap()
        };
        // Public consensus-domain and commitment reads must not expose
        // node-local Garden records.
        assert!(
            chain
                .get_consensus_domains()
                .await
                .into_iter()
                .all(|domain| u64::from(domain.id) != domain_id),
            "public get_consensus_domains must not disclose node-local Gardens"
        );
        assert!(
            chain
                .get_domain_commitments()
                .await
                .into_iter()
                .all(|c| u64::from(c.domain_id) != domain_id),
            "public get_domain_commitments must not disclose node-local Garden commitments"
        );
        let domain = record(chain.get_consensus_domains_with_garden().await);
        assert_eq!(domain.status, DomainStatus::Active);
        assert_eq!(domain.last_committed_height, 1);
        assert!(!domain.bridge_enabled);
        assert!(
            chain
                .get_domain_commitments_with_garden()
                .await
                .into_iter()
                .any(|c| u64::from(c.domain_id) == domain_id && c.domain_height == 1),
            "operator get_domain_commitments_with_garden must expose node-local Garden commitments"
        );

        let left = service.leave().await.unwrap();
        assert_eq!(left["retired"], json!(true));
        let domain = record(chain.get_consensus_domains_with_garden().await);
        assert_eq!(domain.status, DomainStatus::Retired);
    }

    async fn wait_frozen_on_chain(service: &GardenService, height: &Value) {
        let mut last = Value::Null;
        for _ in 0..200 {
            last = service.status().await.unwrap();
            if last.pointer("/garden/chain_status").and_then(Value::as_str) == Some("Frozen")
                && last.pointer("/garden/height") == Some(height)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the departure block of the host did not arrive: {last}");
    }

    async fn room_of(names: &[&str]) -> (GardenService, Vec<GardenService>) {
        let host = GardenService::new(None, None);
        let created = host
            .create("Room".into(), "host".into(), options())
            .await
            .unwrap();
        let invite = text(&created, "/invite");
        let mut guests = Vec::new();
        for name in names {
            let guest = GardenService::new(None, None);
            guest
                .join(invite.clone(), (*name).into(), options())
                .await
                .unwrap();
            guests.push(guest);
        }
        (host, guests)
    }

    #[tokio::test]
    async fn garden_host_departure_block_reaches_the_others_before_the_host_closes() {
        let (host, guests) = room_of(&["a", "b", "c"]).await;
        // The host signs last, so it is the only holder of the block that
        // carries its own departure at the moment the block becomes final.
        let left = host.leave().await.unwrap();
        assert_eq!(left["retired"], json!(false));
        for guest in &guests {
            wait_frozen_on_chain(guest, &left["height"]).await;
        }
        for guest in &guests {
            guest.leave().await.unwrap();
        }
    }

    #[tokio::test]
    async fn garden_host_returns_after_validators_left_the_frozen_garden() {
        let (host, mut guests) = room_of(&["a", "b", "c"]).await;
        let stays = guests.pop().unwrap();

        // The host steps out, then two of the three others walk away. No
        // block can record their departure: the Garden is frozen.
        let left = host.leave().await.unwrap();
        wait_frozen_on_chain(&stays, &left["height"]).await;
        for guest in &guests {
            wait_frozen_on_chain(guest, &left["height"]).await;
            let left = guest.leave().await.unwrap();
            assert_eq!(left["retired"], json!(false));
            assert_eq!(left["can_return"], json!(true));
        }

        // The host returns to one validator out of three. The Garden runs
        // again with the two that are there.
        host.rejoin().await.unwrap();
        let status = wait_status(&stays, "Active").await;
        assert_eq!(text(&status, "/garden/chain_status"), "Active");
        assert_eq!(status.pointer("/garden/active_validators"), Some(&json!(2)));
        let published = stays
            .publish("message".into(), "still here".into(), None, None, None)
            .await
            .unwrap();
        wait_final(&host, &text(&published, "/tx_id")).await;

        // One that walked away comes back.
        let back = guests[0].rejoin().await.unwrap();
        assert_eq!(text(&back, "/garden/me/member"), "Active");

        guests[0].leave().await.unwrap();
        stays.leave().await.unwrap();
        let left = host.leave().await.unwrap();
        assert_eq!(left["retired"], json!(true));
    }

    #[tokio::test]
    async fn garden_service_away_status_refuses_mismatched_genesis_record() {
        let blockchain = Blockchain::new(
            std::sync::Arc::new(PoWEngine::new(2)),
            None,
            Network::Devnet.chain_id().value(),
            None,
        );
        let (actor, chain) = ChainActor::new(blockchain);
        tokio::spawn(async move {
            actor.run().await;
        });
        let service = GardenService::new(Some(chain), None);
        service
            .create("genesis-bound".into(), "host".into(), options())
            .await
            .unwrap();
        let invite_json = service.invite().await.unwrap();
        let genuine_invite = GardenInvite::parse(&text(&invite_json, "/invite")).unwrap();
        let mut forged_invite = genuine_invite.clone();
        forged_invite.genesis_hash[0] ^= 0xff;
        // Swap into Away while the running Garden record stays Active on Budlum.
        let running = {
            let mut slot = service.slot.lock().await;
            let previous = std::mem::replace(&mut *slot, Slot::Empty);
            let Slot::Running(running, seat) = previous else {
                panic!("expected running slot");
            };
            *slot = Slot::Away(seat, forged_invite);
            running
        };
        let mismatched = service.status().await.unwrap();
        assert!(
            !mismatched["garden"]["budlum"].is_object(),
            "away status must refuse a Budlum record whose genesis hash differs"
        );
        assert_eq!(mismatched.pointer("/garden/budlum"), Some(&Value::Null));
        {
            let mut slot = service.slot.lock().await;
            if let Slot::Away(_, stored) = &mut *slot {
                *stored = genuine_invite;
            }
        }
        let matched = service.status().await.unwrap();
        assert_eq!(
            text(&matched, "/garden/budlum/status"),
            "Active",
            "away status must surface the matching genesis record"
        );
        let _ = running.leave().await;
    }
}
