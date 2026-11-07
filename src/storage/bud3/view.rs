//! Client-side B.U.D. 3.0 symbol collection and content reconstruction (`bud3::view`).
//!
//! Convenience: BNS `resolve_via_bud3_view`, Data Market buyers, and `bud storage view`.

use super::bof1::Profile;
use super::content_id::{ContentId, ContentIdKind, ContentKey};
use super::fountain::Symbol;
use super::limits::{Bud3Limits, LimitError};
use super::pipeline::{view_public, PipelineError};
use super::placement::PlacementTable;
use super::registry::{AuditParams, Bud3Registry, ObjectKey};
use super::segment::Segmentation;
use crate::core::address::Address;
use std::collections::BTreeMap;

/// Minimum paid-view fallback fee in whole BUD atoms (G8).
pub const MIN_PAID_VIEW_FEE_ATOMS: u64 = 1;

/// Paid fallback receipt for viewing public content when the viewer holds no NFT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidViewReceipt {
    pub payer: [u8; 32],
    pub object: ObjectKey,
    pub fee_paid_atoms: u64,
}

/// Source providing RFC 6330 symbols by `(ObjectKey, segment)`.
pub trait SymbolSource {
    /// Fetch available symbols for `(object, segment)`.
    fn fetch_segment_symbols(&self, object: &ObjectKey, segment: u64) -> Vec<Symbol>;
}

/// In-memory symbol network table used by local gateways and tests.
#[derive(Debug, Clone, Default)]
pub struct InMemorySymbolSource {
    by_object: BTreeMap<(ObjectKey, u64), Vec<Symbol>>,
}

impl InMemorySymbolSource {
    /// Create an empty symbol table.
    ///
    /// Convenience: `bud3::view` callers and tests (`WP-23`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store symbols for `(object, segment)`.
    ///
    /// Convenience: `bud3::view` callers and tests (`WP-23`).
    pub fn insert_segment(&mut self, object: ObjectKey, segment: u64, symbols: Vec<Symbol>) {
        self.by_object.insert((object, segment), symbols);
    }
}

impl SymbolSource for InMemorySymbolSource {
    fn fetch_segment_symbols(&self, object: &ObjectKey, segment: u64) -> Vec<Symbol> {
        self.by_object
            .get(&(*object, segment))
            .cloned()
            .unwrap_or_default()
    }
}

/// Errors refused during `bud3::view` reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewBud3Error {
    UnknownObject,
    ObjectExpired,
    GrantRequired,
    GrantExpiredOrMissing,
    InsufficientPaidViewFee,
    ContentIdMismatch,
    Pipeline(String),
}

/// Reconstruct and verify content for `object_key` from `source` at `current_epoch`.
///
/// Enforces sealed-object grant checks and verifies that the reconstructed bytes
/// match the registered `ContentId` bit-for-bit (`6.1.1` item 10).
///
/// Convenience: BNS `Bud3BnsResolver`, Data Market readers, and CLI `bud storage view`.
pub fn view_from_network(
    registry: &Bud3Registry,
    object_key: &ObjectKey,
    source: &dyn SymbolSource,
    current_epoch: u64,
    grant_tag: Option<&[u8; 32]>,
    content_key: Option<&ContentKey>,
    paid_receipt: Option<&PaidViewReceipt>,
) -> Result<Vec<u8>, ViewBud3Error> {
    let entry = registry
        .object(object_key)
        .ok_or(ViewBud3Error::UnknownObject)?;
    if entry.expires_at <= current_epoch {
        return Err(ViewBud3Error::ObjectExpired);
    }

    if entry.record.content_id.kind == ContentIdKind::Sealed {
        let Some(tag) = grant_tag else {
            return Err(ViewBud3Error::GrantRequired);
        };
        let Some(grant) = registry.active_grant(tag, current_epoch) else {
            return Err(ViewBud3Error::GrantExpiredOrMissing);
        };
        let _ = &grant.sealed_key_package;
        if content_key.is_none() {
            return Err(ViewBud3Error::GrantRequired);
        }
    } else if let Some(rcpt) = paid_receipt {
        if rcpt.object != *object_key || rcpt.fee_paid_atoms < MIN_PAID_VIEW_FEE_ATOMS {
            return Err(ViewBud3Error::InsufficientPaidViewFee);
        }
    }

    let seg_layout = Segmentation::new(entry.record.content_id.len, &Profile::P0)
        .ok_or_else(|| ViewBud3Error::Pipeline("invalid profile layout".to_string()))?;
    if seg_layout.total_source_symbols() == 0 {
        return Err(ViewBud3Error::Pipeline("zero source symbols".to_string()));
    }

    let seg_count = entry.record.symbol_roots.len() as u64;
    let mut all_symbols = Vec::new();
    for seg in 0..seg_count {
        all_symbols.extend(source.fetch_segment_symbols(object_key, seg));
    }

    let bytes = view_public(&entry.record, all_symbols)
        .map_err(|e: PipelineError| ViewBud3Error::Pipeline(format!("{e:?}")))?;

    match (entry.record.content_id.kind, content_key) {
        (ContentIdKind::Public, _) => {
            if ContentId::public(&bytes) != entry.record.content_id {
                return Err(ViewBud3Error::ContentIdMismatch);
            }
        }
        (ContentIdKind::Sealed, Some(ck)) => {
            if !entry.record.content_id.matches_sealed(ck, &bytes) {
                return Err(ViewBud3Error::ContentIdMismatch);
            }
        }
        (ContentIdKind::Sealed, None) => return Err(ViewBud3Error::GrantRequired),
    }
    Ok(bytes)
}

/// Admit object lifetime and mobile custody quota against testnet `Bud3Limits`.
///
/// Convenience: B.U.D. 3.0 upload and mobile custody admission (`WP-21`, `WP-36`).
pub fn evaluate_custody_policy(
    limits: &Bud3Limits,
    lifetime_days: u32,
    mobile_quota_bytes: u64,
) -> Result<(), LimitError> {
    limits.admit_lifetime(lifetime_days)?;
    limits.admit_mobile_quota(mobile_quota_bytes)
}

/// Summary of the default testnet placement table invariants (`6.9`, `6.11`).
///
/// Convenience: explorer placement proof views and diagnostics (`WP-40`).
#[must_use]
pub fn testnet_placement_diagnostics() -> (u64, u64, bool) {
    let table = PlacementTable::testnet_default();
    let Some(first) = table.rows.first() else {
        return (0, 0, false);
    };
    (
        first.redundancy_milli(table.k),
        first.mobile_share_milli(),
        first.survives_mobile_exit(table.k),
    )
}

/// Mark shares held by an unseen validator as lost after `window_hours` (`7.8`).
///
/// Convenience: presence suspension and repair scheduling (`WP-13`, `WP-20`).
pub fn evict_unseen_holder_after_hours(
    registry: &mut Bud3Registry,
    holder: &Address,
    window_hours: u64,
    slot_secs: u64,
    epoch_slots: u64,
    unseen_epochs: u64,
) -> usize {
    let required_epochs = AuditParams::hours_to_epochs(window_hours, slot_secs, epoch_slots);
    if unseen_epochs >= required_epochs {
        registry.mark_unseen(holder)
    } else {
        0
    }
}
