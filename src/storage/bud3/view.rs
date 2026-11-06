//! Client-side B.U.D. 3.0 symbol collection and content reconstruction (`bud3::view`).
//!
//! exposed for: BNS `resolve_via_bud3_view`, Data Market buyers, and `bud storage view`.

use super::content_id::{ContentId, ContentIdKind, ContentKey};
use super::fountain::Symbol;
use super::pipeline::{view_public, PipelineError};
use super::registry::{Bud3Registry, ObjectKey};
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
    /// exposed for: `bud3::view` callers and tests (`WP-23`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store symbols for `(object, segment)`.
    ///
    /// exposed for: `bud3::view` callers and tests (`WP-23`).
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
/// exposed for: BNS `Bud3BnsResolver`, Data Market readers, and CLI `bud storage view`.
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

    let seg_count = entry.record.symbol_roots.len() as u64;
    let mut all_symbols = Vec::new();
    for seg in 0..seg_count {
        all_symbols.extend(source.fetch_segment_symbols(object_key, seg));
    }

    let bytes = view_public(&entry.record, all_symbols)
        .map_err(|e: PipelineError| ViewBud3Error::Pipeline(format!("{e:?}")))?;

    let computed = match (entry.record.content_id.kind, content_key) {
        (ContentIdKind::Public, _) => ContentId::public(&bytes),
        (ContentIdKind::Sealed, Some(ck)) => ContentId::sealed(ck, &bytes),
        (ContentIdKind::Sealed, None) => return Err(ViewBud3Error::GrantRequired),
    };
    if computed != entry.record.content_id {
        return Err(ViewBud3Error::ContentIdMismatch);
    }
    Ok(bytes)
}
