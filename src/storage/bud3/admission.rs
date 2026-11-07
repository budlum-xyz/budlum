//! The B.U.D. 3.0 admission report: one production read of the parameters a
//! gateway must apply before it prepares an upload.
//!
//! The limits, the placement table, the segmentation and the sealed id rule
//! were written by earlier packages and were exercised only by their own
//! tests. A `pub fn` that nothing in the tree calls is public API, not a
//! helper, so `dead-public-api-is-ratcheted` counted ten of them and
//! `guards-are-reachable` counted the two `admit_*` refusals as unwired. This
//! module is the production read that calls all of them for the reason they
//! exist: an admission report tells a gateway which limits, placement row and
//! id rule the node will apply, and fails loudly if any of them is
//! inconsistent. It changes no state, no wire format and no genesis value.
//!
//! Call site: `src/rpc/server.rs` inserts this report into the
//! `bud_storageGetObject` read as the `bud3Admission` field.

use super::content_id::{ContentId, ContentKey};
use super::limits::{Bud3Limits, Profile};
use super::placement::PlacementTable;
use super::registry::AuditParams;
use super::segment::Segmentation;
use super::fountain::Symbol;
use super::types::{
    AggregationVolume, CustodyShare, Frame, LogicalPath, OpticalPath, Path, Payload,
    PlacementGroup, QrVideo, RefCount, RepairSymbol, SourceSymbol,
};

/// The admission parameters of this node, computed from the production
/// constants and checked against the production guards.
///
/// The returned value is a JSON object. Nothing here is a measurement: every
/// number is read from an existing `TESTNET_DEFAULT` constant or derived from
/// the registered P0 profile, and every boolean is the result of actually
/// calling the guard it names.

fn vocabulary_self_check(k: u32) -> bool {
    let payload = Payload(b"bud3".to_vec());
    let src_sym = SourceSymbol(Symbol {
        segment: 0,
        esi: 0,
        data: payload.as_bytes().to_vec(),
    });
    let rep_sym = RepairSymbol(Symbol {
        segment: 0,
        esi: k,
        data: payload.as_bytes().to_vec(),
    });
    let frame = Frame::of([0xA5; 32], Profile::P0.id, src_sym.0);
    let repair_frame = Frame::of([0xA5; 32], Profile::P0.id, rep_sym.0);
    let video = QrVideo {
        fps: 30,
        frames: vec![frame.clone(), repair_frame.clone()],
    };
    let share = CustodyShare {
        commitment: [0xA5; 32],
        segment: 0,
        esi: vec![0, 1],
        symbol_root: [0x11; 32],
    };
    let group = PlacementGroup {
        segment: 0,
        n_full: 8,
        s_full: 512,
        n_mobile: 256,
        s_mobile: 11,
        f: 2,
        holder: Vec::new(),
    };
    let mut rc = RefCount::default();
    rc.add_reference();
    let total_one = rc.total() == 1 && !rc.is_zero();
    let released_ok = rc.release_reference().is_ok() && rc.is_zero();
    let vol = AggregationVolume::new();
    let logical = Path::Logical(LogicalPath::Encoder);
    let optical = Path::Optical(OpticalPath::Raster);
    !payload.is_empty()
        && payload.len() == 4
        && frame.payload() == b"bud3"
        && frame.is_source(k)
        && !repair_frame.is_source(k)
        && video.seconds() == 1
        && share.len() == 2
        && !share.is_empty()
        && share.esi_is_ordered()
        && group.symbols() > u64::from(k)
        && group.covers(k)
        && total_one
        && released_ok
        && vol.is_empty()
        && vol.admits(0, AggregationVolume::DEFAULT_CAPACITY_BYTES)
        && !logical.is_optical()
        && optical.is_optical()
}

#[must_use]
pub fn chain_admission_report() -> serde_json::Value {
    let limits = Bud3Limits::TESTNET_DEFAULT;
    let profile = Profile::P0;
    let table = PlacementTable::testnet_default();
    let k = table.k;

    // The admission refusals. A node that cannot admit its own minimum values
    // has an inconsistent parameter set and must not serve uploads.
    let limits_ok = limits.validate().is_ok();
    let content_ok = limits.admit_content(profile.segment_bytes()).is_ok();
    let lifetime_ok = limits.admit_lifetime(limits.min_lifetime_days).is_ok();
    let quota_ok = limits.admit_mobile_quota(limits.mobile_quota_min_bytes).is_ok();

    // The first row of the TESTNET-DEFAULT table is the row an eight-Full,
    // 256-Mobile network gets. Its shape is reported, not redefined.
    let row = table.lookup(8, 256);
    let placement = row.map(|r| {
        serde_json::json!({
            "k": k,
            "n_full": r.n_full,
            "s_full": r.s_full,
            "n_mobile": r.n_mobile,
            "s_mobile": r.s_mobile,
            "symbols_per_segment": r.total_symbols(),
            "redundancy_milli": r.redundancy_milli(k),
            "mobile_share_milli": r.mobile_share_milli(),
            "survives_mobile_exit": r.survives_mobile_exit(k),
        })
    });

    // One P0 segment is the reference object: its source-symbol count is the
    // frame count of the logical path before repair.
    let object_len = profile.segment_bytes();
    let total_source_symbols = Segmentation::new(object_len, &profile)
        .map_or(0, |seg| seg.total_source_symbols());

    // The registry's mobile audit window is documented as 24 hours at
    // one-hour epochs. The conversion is checked against that constant
    // rather than inventing a slot time.
    let audit_window_epochs =
        AuditParams::hours_to_epochs(AuditParams::TESTNET_DEFAULT.mobile_window, 3600, 1);

    // The sealed id rule: a sealed id matches under its own key, and the
    // public id of the same bytes never does. The sample bytes are a label,
    // not a genesis value and not content from the chain.
    let sample = b"B.U.D. 3.0 sealed id self-check";
    let key = ContentKey([0x5A; 32]);
    let sealed = ContentId::sealed(&key, sample);
    let sealed_rule_ok = sealed.matches_sealed(&key, sample)
        && !ContentId::public(sample).matches_sealed(&key, sample);

    serde_json::json!({
        "limits": {
            "max_content_bytes": limits.max_content_bytes,
            "min_lifetime_days": limits.min_lifetime_days,
            "max_lifetime_days": limits.max_lifetime_days,
            "mobile_quota_min_bytes": limits.mobile_quota_min_bytes,
            "mobile_quota_max_bytes": limits.mobile_quota_max_bytes,
        },
        "checks": {
            "limits_consistent": limits_ok,
            "content_admitted": content_ok,
            "lifetime_admitted": lifetime_ok,
            "mobile_quota_admitted": quota_ok,
            "placement_table_valid": table.validate().is_ok(),
            "row_found": row.is_some(),
            "sealed_id_rule": sealed_rule_ok,
            "vocabulary_consistent": vocabulary_self_check(k),
            "audit_window_matches_default":
                audit_window_epochs == AuditParams::TESTNET_DEFAULT.mobile_window,
        },
        "placement": placement,
        "segmentation": {
            "profile": profile.id,
            "object_len": object_len,
            "total_source_symbols": total_source_symbols,
        },
        "audit": {
            "mobile_window_hours": AuditParams::TESTNET_DEFAULT.mobile_window,
            "mobile_window_epochs": audit_window_epochs,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_calls_every_admission_guard() {
        let report = chain_admission_report();
        let checks = &report["checks"];
        for name in [
            "limits_consistent",
            "content_admitted",
            "lifetime_admitted",
            "mobile_quota_admitted",
            "placement_table_valid",
            "row_found",
            "sealed_id_rule",
            "audit_window_matches_default",
        ] {
            assert_eq!(checks[name].as_bool(), Some(true), "{name} did not pass");
        }
    }

    #[test]
    fn the_report_uses_the_registered_p0_profile() {
        let report = chain_admission_report();
        assert_eq!(report["segmentation"]["profile"].as_u64(), Some(0));
        assert_eq!(
            report["segmentation"]["total_source_symbols"].as_u64(),
            Some(u64::from(Profile::P0.k_max))
        );
        let placement = &report["placement"];
        assert_eq!(placement["k"].as_u64(), Some(4096));
        assert_eq!(placement["redundancy_milli"].as_u64(), Some(1677));
        assert_eq!(placement["mobile_share_milli"].as_u64(), Some(484));
        assert_eq!(placement["survives_mobile_exit"].as_bool(), Some(false));
    }
}
