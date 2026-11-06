//! Section 6.22.2 B.U.D. 3.0 JSON-RPC surface (`bud_storage*`, WP-21 item 6).
//! exposed for `src/rpc/server.rs` `bud_storage*` dispatch.
//!
//! Dispatches all 17 canonical `bud_storage*` methods over [`Bud3Registry`],
//! [`UploadSessionManager`], [`RevealSessionManager`], and [`NetworkSymbolSource`]:
//! * Upload sessions: `bud_storageUploadOpen`, `bud_storageUploadAppend`, `bud_storageUploadFinish`
//! * Chain reads: `bud_storageGetObject`, `bud_storageGetPlacement`, `bud_storageGetCustody`
//! * Symbol & paid fallback reads: `bud_storageGetSymbols`, `bud_storageGetContent`
//! * Unsigned tx builders: `bud_storagePrepareRegister`, `bud_storagePrepareBurn`, `bud_storagePrepareRenew`
//! * View grants: `bud_storageIssueViewGrant`, `bud_storageRevokeViewGrant`, `bud_storageMayView`, `bud_storageListViewGrants`
//! * Reveal sessions: `bud_storageOpenReveal`, `bud_storageRevealFrames`, `bud_storageCloseReveal`

use super::access_tiering::AccessTierTracker;
use super::content_gateway::Bud3ContentGateway;
use super::content_ref::ContentRef;
use super::fountain::Symbol;
use super::grants::GrantRow;
use super::limits::{Bud3Limits, Profile};
use super::maintenance::Bud3StorageMetrics;
use super::placement::{Candidate, PlacementRow};
use super::registry::{Address, Bud3Query, Bud3Registry, NftId, ObjectKey};
use super::repair::verify_repaired_symbol;
use super::segment::Segmentation;
use super::symbol_protocol::SymbolPeerLimiter;
use super::tx::StorageTxV3;
use super::upload::UploadSessionManager;
use super::view::{
    fallback_decode_public, NetworkSymbolSource, PaidViewReceipt, RevealSessionManager,
};
use serde_json::{json, Value};

/// Canonical Section 6.22.2 B.U.D. 3.0 RPC method names.
pub const BUD3_RPC_METHODS: &[&str] = &[
    "bud_storageUploadOpen",
    "bud_storageUploadAppend",
    "bud_storageUploadFinish",
    "bud_storageGetObject",
    "bud_storageGetSymbols",
    "bud_storageGetContent",
    "bud_storageGetPlacement",
    "bud_storageGetCustody",
    "bud_storagePrepareRegister",
    "bud_storagePrepareBurn",
    "bud_storagePrepareRenew",
    "bud_storageIssueViewGrant",
    "bud_storageRevokeViewGrant",
    "bud_storageMayView",
    "bud_storageListViewGrants",
    "bud_storageOpenReveal",
    "bud_storageRevealFrames",
    "bud_storageCloseReveal",
];

fn parse_hex32(val: Option<&Value>, field: &str) -> Result<[u8; 32], String> {
    let raw = val
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing hex string `{field}`"))?;
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex `{field}`: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("`{field}` must be 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes(val: Option<&Value>, field: &str) -> Result<Vec<u8>, String> {
    let raw = val
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing hex string `{field}`"))?;
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    hex::decode(trimmed).map_err(|e| format!("invalid hex `{field}`: {e}"))
}

/// Stateful node-local B.U.D. 3.0 RPC endpoint holding upload & reveal sessions.
pub struct Bud3RpcService {
    uploads: UploadSessionManager,
    reveals: RevealSessionManager,
    tiers: AccessTierTracker,
    limiter: SymbolPeerLimiter,
    metrics: Bud3StorageMetrics,
}

impl Default for Bud3RpcService {
    fn default() -> Self {
        Self {
            uploads: UploadSessionManager::new(Bud3Limits::default()),
            reveals: RevealSessionManager::default(),
            tiers: AccessTierTracker::default(),
            limiter: SymbolPeerLimiter::default(),
            metrics: Bud3StorageMetrics::default(),
        }
    }
}

impl Bud3RpcService {
    /// Dispatch a Section 6.22.2 `bud_storage*` JSON-RPC request.
    ///
    /// # Errors
    ///
    /// Returns an actionable error string if parameters are malformed, session
    /// limits trigger, or G8 paid/public rules refuse the request.
    pub fn handle<N: NetworkSymbolSource>(
        &mut self,
        method: &str,
        params: &Value,
        registry: &Bud3Registry,
        network: &N,
        placement_ctx: (&PlacementRow, &[Candidate], u64),
    ) -> Result<Value, String> {
        let (placement_row, candidates, now_sec) = placement_ctx;
        match method {
            "bud_storageUploadOpen" => {
                let account: Address = parse_hex32(params.get("account"), "account")?;
                let declared_len = params
                    .get("declared_len")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `declared_len`"))?;
                let raw_flags = u8::try_from(
                    params
                        .get("flags")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                )
                .map_err(|_| String::from("invalid `flags`"))?;
                let lifetime_epochs = params
                    .get("lifetime_epochs")
                    .and_then(Value::as_u64)
                    .unwrap_or(100);
                let pre_sealed = params
                    .get("pre_sealed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let sid = if let Some(days_u64) = params.get("lifetime_days").and_then(Value::as_u64) {
                    let days = u32::try_from(days_u64).map_err(|_| String::from("invalid `lifetime_days`"))?;
                    self.uploads
                        .open_session_for_days(
                            (account, [0u8; 16]),
                            declared_len,
                            raw_flags,
                            days,
                            pre_sealed,
                            now_sec,
                        )
                        .map_err(|e| format!("{e:?}"))?
                } else {
                    self.uploads
                        .open_session(
                            (account, [0u8; 16]),
                            declared_len,
                            raw_flags,
                            lifetime_epochs,
                            pre_sealed,
                            now_sec,
                        )
                        .map_err(|e| format!("{e:?}"))?
                };
                Ok(json!({ "session_id": sid }))
            }
            "bud_storageUploadAppend" => {
                let sid = params
                    .get("session_id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `session_id`"))?;
                let chunk = parse_hex_bytes(params.get("chunk_hex"), "chunk_hex")?;
                let received = self
                    .uploads
                    .append_chunk(sid, &chunk, now_sec)
                    .map_err(|e| format!("{e:?}"))?;
                Ok(json!({ "session_id": sid, "received_len": received }))
            }
            "bud_storageUploadFinish" => {
                let sid = params
                    .get("session_id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `session_id`"))?;
                let done = self
                    .uploads
                    .finish_session(
                        sid,
                        &Profile::P0,
                        placement_row,
                        candidates,
                        registry,
                        now_sec,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                Ok(json!({
                    "object_commitment": hex::encode(done.record.commitment),
                    "content_digest": hex::encode(done.record.content_id.digest),
                    "object_len": done.record.object_len,
                    "deduplicated_existing": done.deduplicated_existing.map(hex::encode),
                }))
            }
            "bud_storageGetObject" | "bud_storageGetPlacement" => {
                let key: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let mut val = registry.query_json(&Bud3Query::Object(key));
                if method == "bud_storageGetPlacement" {
                    if let Some(entry) = registry.object(&key) {
                        let total_src = Segmentation::new(entry.record.object_len, &entry.record.profile)
                            .map_or(0, |s| s.total_source_symbols());
                        let k_seg = u32::try_from(total_src).unwrap_or(1).max(1);
                        if let Some(map) = val.as_object_mut() {
                            map.insert("mobile_share_milli".to_owned(), json!(placement_row.mobile_share_milli()));
                            map.insert("redundancy_milli".to_owned(), json!(placement_row.redundancy_milli(k_seg)));
                            map.insert(
                                "total_physical_bytes".to_owned(),
                                json!(entry.endowment.fee_record.total_physical_bytes()),
                            );
                        }
                    }
                }
                Ok(val)
            }
            "bud_storageGetCustody" => {
                let validator: Address = parse_hex32(params.get("validator"), "validator")?;
                Ok(registry.query_json(&Bud3Query::Custody(validator)))
            }
            "bud_storageGetSymbols" => {
                let holder: Address = parse_hex32(params.get("holder"), "holder")?;
                let object: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let segment = params.get("segment").and_then(Value::as_u64).unwrap_or(0);
                let first_esi = u32::try_from(
                    params.get("first_esi").and_then(Value::as_u64).unwrap_or(0),
                )
                .map_err(|_| String::from("invalid `first_esi`"))?;
                let count = u32::try_from(
                    params.get("count").and_then(Value::as_u64).unwrap_or(1),
                )
                .map_err(|_| String::from("invalid `count`"))?;
                if count == 0 || count > super::symbol_protocol::MAX_SYMBOLS_PER_REQUEST {
                    return Err(String::from("symbol count outside 1..=64"));
                }
                let syms = network.fetch_holder_symbols(&holder, &object, segment, first_esi, count);
                let encoded: Vec<Value> = syms
                    .into_iter()
                    .map(|s| json!({ "segment": s.segment, "esi": s.esi, "data_hex": hex::encode(s.data) }))
                    .collect();
                Ok(json!({ "symbols": encoded }))
            }
            "bud_storageGetContent" => {
                let payer: Address = parse_hex32(params.get("payer"), "payer")?;
                let object: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let fee_paid_atoms = params
                    .get("fee_paid_atoms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let receipt = PaidViewReceipt {
                    payer,
                    object,
                    fee_paid_atoms,
                };
                let content = fallback_decode_public(registry, &object, &receipt, network)
                    .map_err(|e| format!("{e:?}"))?;
                let _ = self.tiers.record_access(object, false, now_sec);
                Ok(json!({ "content_hex": hex::encode(content) }))
            }
            "bud_storagePrepareBurn"
            | "bud_storagePrepareRenew"
            | "bud_storagePrepareRegister"
            | "bud_storageIssueViewGrant"
            | "bud_storageRevokeViewGrant"
            | "bud_storageMayView"
            | "bud_storageListViewGrants"
            | "bud_storageOpenReveal"
            | "bud_storageRevealFrames"
            | "bud_storageCloseReveal"
            | "bud_storageFetchBundle"
            | "bud_storageAuditRepairSymbol" => {
                self.handle_grants_and_reveal(method, params, registry, network)
            }
            other => Err(format!("unknown B.U.D. 3.0 RPC method `{other}`")),
        }
    }

    fn handle_grants_and_reveal<N: NetworkSymbolSource>(
        &mut self,
        method: &str,
        params: &Value,
        registry: &Bud3Registry,
        network: &N,
    ) -> Result<Value, String> {
        match method {
            "bud_storagePrepareBurn" => {
                let nft: NftId = parse_hex32(params.get("nft"), "nft")?;
                let tx = StorageTxV3::BurnReference { nft };
                Ok(serde_json::to_value(tx).map_err(|e| e.to_string())?)
            }
            "bud_storagePrepareRenew" => {
                let object: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let extra_epochs = params
                    .get("extra_epochs")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `extra_epochs`"))?;
                let tx = StorageTxV3::RenewObject {
                    object,
                    extra_epochs,
                };
                Ok(serde_json::to_value(tx).map_err(|e| e.to_string())?)
            }
            "bud_storagePrepareRegister" => {
                Ok(json!({ "ready": true, "via": "bud_storageUploadFinish" }))
            }
            "bud_storageIssueViewGrant" => {
                let grant_tag = parse_hex32(params.get("grant_tag"), "grant_tag")?;
                let one_time_pk = parse_hex_bytes(params.get("one_time_pk"), "one_time_pk")?;
                let sealed_key_package =
                    parse_hex_bytes(params.get("sealed_key_package"), "sealed_key_package")?;
                let expires_at_epoch = params
                    .get("expires_at_epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `expires_at_epoch`"))?;
                let tx = StorageTxV3::IssueViewGrant {
                    row: GrantRow {
                        grant_tag,
                        one_time_pk,
                        sealed_key_package,
                        expires_at_epoch,
                    },
                };
                Ok(serde_json::to_value(tx).map_err(|e| e.to_string())?)
            }
            "bud_storageRevokeViewGrant" => {
                let grant_tag = parse_hex32(params.get("grant_tag"), "grant_tag")?;
                let one_time_signature =
                    parse_hex_bytes(params.get("one_time_signature"), "one_time_signature")?;
                let tx = StorageTxV3::RevokeViewGrant {
                    grant_tag,
                    one_time_signature,
                };
                Ok(serde_json::to_value(tx).map_err(|e| e.to_string())?)
            }
            "bud_storageMayView" => {
                let grant_tag = parse_hex32(params.get("grant_tag"), "grant_tag")?;
                let active = registry.grant_row(&grant_tag).is_some();
                Ok(json!({ "grant_tag": hex::encode(grant_tag), "may_view": active }))
            }
            "bud_storageListViewGrants" => {
                let grant_tag = parse_hex32(params.get("grant_tag"), "grant_tag")?;
                Ok(registry.query_json(&Bud3Query::Grant(grant_tag)))
            }
            "bud_storageOpenReveal" => {
                let object: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let sid = self
                    .reveals
                    .open_reveal(registry, &object, 2, network)
                    .map_err(|e| format!("{e:?}"))?;
                Ok(json!({ "reveal_session_id": sid }))
            }
            "bud_storageRevealFrames" => {
                let sid = params
                    .get("reveal_session_id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `reveal_session_id`"))?;
                let offset = usize::try_from(
                    params.get("offset").and_then(Value::as_u64).unwrap_or(0),
                )
                .unwrap_or(0);
                let limit = usize::try_from(
                    params.get("limit").and_then(Value::as_u64).unwrap_or(16),
                )
                .unwrap_or(16);
                let (obj, frames, total) = self
                    .reveals
                    .reveal_frames(sid, offset, limit)
                    .map_err(|e| format!("{e:?}"))?;
                let encoded: Vec<String> = frames.iter().map(|f| hex::encode(f.encode())).collect();
                Ok(json!({
                    "object": hex::encode(obj),
                    "total_frames": total,
                    "frames_hex": encoded,
                }))
            }
            "bud_storageCloseReveal" => {
                let sid = params
                    .get("reveal_session_id")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| String::from("missing `reveal_session_id`"))?;
                self.reveals
                    .close_reveal(sid)
                    .map_err(|e| format!("{e:?}"))?;
                Ok(json!({ "closed": true }))
            }
            "bud_storageFetchBundle" => {
                let object: ObjectKey = parse_hex32(params.get("object"), "object")?;
                let entry = registry
                    .object(&object)
                    .ok_or_else(|| String::from("unknown object"))?;
                let cref = ContentRef::new(entry.record.content_id, object, None)
                    .map_err(|e| format!("{e:?}"))?;
                let bundle = Bud3ContentGateway::fetch_symbol_bundle(registry, &cref, network)
                    .map_err(|e| format!("{e:?}"))?;
                Ok(json!({
                    "object": hex::encode(bundle.record.commitment),
                    "symbol_count": bundle.symbols.len(),
                }))
            }
            "bud_storageAuditRepairSymbol" => {
                let peer: Address = parse_hex32(params.get("peer"), "peer")?;
                self.limiter
                    .open_custody_stream(&peer)
                    .map_err(|e| format!("{e:?}"))?;
                let segment = params.get("segment").and_then(Value::as_u64).unwrap_or(0);
                let esi = u32::try_from(params.get("esi").and_then(Value::as_u64).unwrap_or(0))
                    .map_err(|_| String::from("invalid `esi`"))?;
                let segment_bytes = parse_hex_bytes(params.get("segment_hex"), "segment_hex")?;
                let symbol_bytes = parse_hex_bytes(params.get("symbol_hex"), "symbol_hex")?;
                let claimed = Symbol {
                    segment,
                    esi,
                    data: symbol_bytes,
                };
                let res = verify_repaired_symbol(segment, &segment_bytes, &Profile::P0, &claimed);
                self.limiter.close_custody_stream(&peer);
                let valid = res.map_err(|e| format!("{e:?}"))?;
                Ok(json!({
                    "valid": valid,
                    "metrics": self.metrics.render_prometheus(),
                }))
            }
            other => Err(format!("unknown B.U.D. 3.0 RPC method `{other}`")),
        }
    }
}
