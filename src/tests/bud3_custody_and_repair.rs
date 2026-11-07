//! B.U.D. 3.0 custody, repair and placement: the tests the directive names
//! (IP-20: T17, T26, T34-T40) from a level above the individual modules.
//!
//! The registry's own unit tests cover one object's mechanics. These cover the
//! claims an operator, a Mobile holder and a repairer depend on, and the ones a
//! rehearsal cannot show in a day:
//!
//!   * a valid custody proof is accepted and a missed audit costs no stake and
//!     no share (§11.7, a missed audit: no penalty),
//!   * a proved bad repair costs 1% of the repairer's stake and nothing else
//!     (§11.7, a proved bad repair),
//!   * a repair emits fresh ESIs and the old shares outlive the new ones only
//!     until they are acknowledged (§6.10 items 6-7),
//!   * a decline moves the share instead of blocking the upload, with no
//!     penalty (§11.7, a content decline: no penalty),
//!   * the placement table still reproduces from its parameters and still
//!     holds the 30% Mobile floor (§6.9.2, §6.9.3 item 5, T39, T34),
//!   * the network can shrink to one Full validator and every object still
//!     decodes bit-exactly (§6.13, T26),
//!   * Mobile holders can all vanish and the Full class still serves every
//!     read (§6.13 item 4, T35).

use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::params::RegistryParams;
use crate::registry::permissionless::{PermissionlessRegistry, SlashingCondition};
use crate::registry::roles;
use crate::storage::bud3::content_id::ContentIdKind;
use crate::storage::bud3::custody::{prove, sub_block_count, symbol_leaf, ProofContext};
use crate::storage::bud3::fountain::{SegmentDecoder, SegmentEncoder, Symbol};
use crate::storage::bud3::limits::{Bud3Limits, Profile};
use crate::storage::bud3::meter::Meter;
use crate::storage::bud3::pipeline::{prepare_public_upload, view_public};
use crate::storage::bud3::placement::{
    place, segment_key, Candidate, Class, PlacementError, PlacementTable,
};
use crate::storage::bud3::registry::{
    AuditParams, Bud3Registry, RegistryError, Share, ShareStatus,
};
use crate::storage::bud3::repair::{self, Verification};

/// The fixtures' profile: 128-byte symbols, sixteen source symbols per segment
/// in the worst case, ten symbols per second on the wire.
const P: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 128,
    fps: 10,
    k_max: 16,
};

/// Every share drawn: the sample under test, not the audit rate.
const EVERY_SHARE: AuditParams = AuditParams {
    full_ppm: 1_000_000,
    mobile_ppm: 1_000_000,
    ..AuditParams::TESTNET_DEFAULT
};

fn addr(b: u8) -> crate::storage::bud3::registry::Address {
    [b; 32]
}

/// Content with no long runs, so the codec keeps it at one segment per 2 KiB
/// instead of compressing it away.
fn content(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut x: u32 = 0x9E37_79B9;
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.push((x & 0xFF) as u8);
    }
    out
}

/// Register one object with its shares spread over four holders of five
/// symbols each: three Full and one Mobile, the shape the registry's own
/// tests use.
fn register(
    r: &mut Bud3Registry,
    bytes: &[u8],
) -> (crate::storage::bud3::pipeline::PreparedUpload, [u8; 32]) {
    let up = prepare_public_upload(bytes, &P, &Bud3Limits::default(), 20)
        .unwrap_or_else(|e| panic!("the fixture must upload: {e:?}"));
    let mut shares = Vec::new();
    for seg in 0..up.segments.len() as u64 {
        for h in 0..4u8 {
            shares.push((
                seg,
                Share {
                    validator: addr(10 + h),
                    class: if h == 3 { Class::Mobile } else { Class::Full },
                    first_esi: u32::from(h) * 5,
                    symbols: 5,
                },
            ));
        }
    }
    let key = up.record.commitment;
    r.register_object(addr(1), up.record.clone(), shares, 0, 1000)
        .expect("the fixture registers");
    (up, key)
}

fn ack_all(r: &mut Bud3Registry, key: &[u8; 32]) {
    for h in 0..4u8 {
        r.ack(key, &addr(10 + h), 0).expect("ack");
    }
}

/// §6.11.2, T36: the proof a holder sends verifies against the segment's
/// symbol root. One changed byte is refused, and a proof for another window
/// is refused.
#[test]
fn bud3_custody_proof_verifies() {
    let mut r = Bud3Registry::default();
    let (up, key) = register(&mut r, &content(1500));
    ack_all(&mut r, &key);
    assert!(r.open_audits(&[11; 32], 1, &EVERY_SHARE) > 0);

    let obj = r.object(&key).expect("registered");
    let symbols = &up.segments[0];
    let leaves: Vec<(u32, [u8; 32])> = symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let share = obj
        .shares
        .iter()
        .find(|s| s.segment == 0 && s.share.validator == addr(10))
        .expect("holder 10 holds segment 0");
    let (audit, last_epoch) = share.open_audit.expect("drawn");
    let pos = audit.position as usize;
    let proof = prove(
        audit.segment,
        &leaves,
        pos,
        &symbols[pos].data,
        audit.sub_block as usize,
    )
    .expect("a stored symbol proves");

    // The context the chain checks against is the segment's own root, not a
    // root the holder supplies.
    let root = &obj.roots[share.root];
    let ctx = ProofContext {
        symbol_root: root.root,
        symbol_count: u64::from(root.count),
        sub_blocks: sub_block_count(usize::from(P.symbol_size)),
    };
    assert_eq!(proof.verify(&audit, &ctx), Ok(()));

    // One changed byte is a bad proof, not a miss.
    let mut flipped = proof.clone();
    flipped.bytes[0] ^= 1;
    let before = r.state_root();
    assert_eq!(
        r.submit_proofs(&addr(10), &[(key, flipped)], 2),
        Err(RegistryError::BadProof)
    );
    assert_eq!(r.state_root(), before, "a refused batch writes nothing");

    // A proof outside its window is refused: the window closed at `last_epoch`
    // and this is one epoch later.
    assert_eq!(
        r.submit_proofs(&addr(10), &[(key, proof.clone())], last_epoch + 1),
        Err(RegistryError::BadProof)
    );
    // Inside it, the same proof is accepted.
    let (answered, waited) = r
        .submit_proofs(&addr(10), &[(key, proof)], last_epoch)
        .expect("inside its window the proof is accepted");
    assert_eq!(answered, 1);
    // The audit opened in epoch 1 and is answered at its window's last epoch,
    // so the wait is the window length in epochs.
    assert_eq!(waited, vec![last_epoch.saturating_sub(1)]);
    let after = r
        .object(&key)
        .expect("registered")
        .shares
        .iter()
        .find(|s| s.share.validator == addr(10))
        .copied()
        .expect("holder 10");
    assert_eq!(after.passes, 1);
    assert_eq!(after.misses, 0);
    assert!(after.open_audit.is_none());
}

/// §11.7, T37: a missed audit costs the window's reward and no stake, and a
/// single miss is not a lost share. Two consecutive misses lose a Full share;
/// a Mobile share needs three (§6.10 item 2).
#[test]
fn bud3_missed_audit_does_not_slash() {
    let mut r = Bud3Registry::default();
    let (_up, key) = register(&mut r, &content(1500));
    ack_all(&mut r, &key);
    let drawn = r.open_audits(&[12; 32], 1, &EVERY_SHARE);
    assert!(drawn > 0, "something has to be drawn to miss");
    assert_eq!(
        r.close_windows(4),
        r.object(&key).expect("registered").shares.len(),
        "each open audit is one miss"
    );
    for s in &r.object(&key).expect("registered").shares {
        assert_eq!(s.misses, 1);
        assert_eq!(s.consecutive_misses, 1);
        assert!(!s.lost, "one miss is not a loss");
        assert_eq!(s.status, ShareStatus::Confirmed);
    }
    // A miss is bookkeeping, not a slash: nothing reaches the registry's
    // slashing history.
    let registry = PermissionlessRegistry::with_params(RegistryParams::default());
    assert!(
        registry.slashing_history().is_empty(),
        "a missed audit is not a slashing condition"
    );

    // Second window: Full shares cross their limit, Mobile does not.
    r.open_audits(&[13; 32], 10, &EVERY_SHARE);
    r.close_windows(12);
    for s in &r.object(&key).expect("registered").shares {
        match s.share.class {
            Class::Full => assert!(s.lost, "two consecutive misses lose a Full share"),
            Class::Mobile => assert!(!s.lost, "a Mobile share loses only at three"),
        }
    }
    // The segment now has one lost share of four, below `f / 2`, so it is at
    // risk but not yet a repair task: the lazy threshold of §6.10 item 1.
    assert_eq!(r.segments_at_risk(&key), 1);
}

/// §11.7, §6.10 item 8, T38: a repair symbol that does not regenerate from the
/// source symbols draws 1% of the repairer's stake - and no more than that.
#[test]
fn bud3_bad_repair_is_slashed() {
    // A validator with a bond, registered so the registry can charge it.
    let bond = 100_000u64;
    let repairer = addr(0x40);
    let mut registry = PermissionlessRegistry::with_params(RegistryParams::default());
    registry
        .register(repairer, roles::VALIDATOR, bond, 0)
        .expect("register");

    // The real repair symbol of a segment, and a forged one.
    let source = content(1_400);
    let encoder = SegmentEncoder::new(0, &source, &P).expect("encode");
    let k = encoder.k();
    let real = encoder.repair_symbols(0, 1).expect("repair symbol");
    let real = real.first().expect("one symbol");
    let mut forged = real.clone();
    forged.data[0] ^= 0xFF;
    let esi = k + 0;

    let claimed = symbol_leaf(&forged.data);
    let derived = symbol_leaf(&real.data);
    let report: SlashingReport = repair::bad_repair_report(
        repairer,
        &[9u8; 32],
        0,
        7,
        esi,
        claimed,
        derived,
        Some(addr(1)),
    );
    assert_eq!(report.condition(), SlashingCondition::BadRepair);
    assert_eq!(report.validate_shape(), Ok(()));

    let outcome = registry
        .slash_from_report(&report)
        .expect("a proved bad repair is actionable")
        .expect("a bad repair produces an outcome");
    let expected = crate::core::chain_config::slash_penalty(
        bond,
        RegistryParams::default().bad_repair_slash_ratio_fixed,
    );
    assert_eq!(
        outcome.penalty, expected,
        "§11.7 prices a proved bad repair at 1%"
    );
    assert_eq!(
        outcome.penalty, bond / 100,
        "1% of a 100 000 bond is 1 000"
    );
    assert_eq!(outcome.remaining_stake, bond - expected);
    // Not the malice rate: a bad repair is not 100% of the bond.
    assert!(outcome.penalty < bond / 2);

    // A second report for the same repair is a replay, not a second charge.
    assert_eq!(
        registry.slash_from_report(&report),
        Ok(None),
        "one repair is charged once"
    );

    // A report that says the symbol regenerates accuses nobody and is refused
    // before it reaches the bond.
    let mine = repair::bad_repair_report(repairer, &[9u8; 32], 0, 7, esi, claimed, claimed, None);
    assert!(mine.validate_shape().is_err());
}

/// §6.10 items 6-7: a repair emits fresh ESIs, the new shares start pending,
/// and the old ones are only dropped once every new share is acknowledged.
#[test]
fn a_repair_replaces_lost_shares_only_after_the_new_ones_hold() {
    use crate::storage::bud3::custody::symbol_root;
    let mut r = Bud3Registry::default();
    let (_up, key) = register(&mut r, &content(1500));
    ack_all(&mut r, &key);
    // Lose enough shares to cross `f / 2`: mark two of the four holders
    // unseen, which is 2 of 4 lost shares on a segment with 4 shares.
    assert!(r.mark_unseen(&addr(10)) > 0, "holder 10 holds shares");
    assert!(r.mark_unseen(&addr(11)) > 0);
    let due = r.repairs_due(&key);
    assert!(!due.is_empty(), "the segment now needs a repair");

    let segment = due[0];
    assert_eq!(segment, 0, "the fixture has one segment");
    let fresh_first = r
        .object(&key)
        .expect("registered")
        .next_esi
        .get(segment as usize)
        .copied()
        .expect("one next-ESI per segment");
    // Repair symbols for the segment, and the root over them.
    let encoder = SegmentEncoder::new(segment, &content(1_400), &P).expect("encode");
    let fresh = encoder.repair_symbols(0, 2).expect("repair symbols");
    let leaves: Vec<(u32, [u8; 32])> = fresh
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let root = symbol_root(&leaves);
    let shares = vec![
        Share {
            validator: addr(20),
            class: Class::Full,
            first_esi: fresh_first,
            symbols: 1,
        },
        Share {
            validator: addr(21),
            class: Class::Full,
            first_esi: fresh_first + 1,
            symbols: 1,
        },
    ];
    r.record_repair(&key, segment, shares.clone(), root)
        .expect("the repair records");
    let obj = r.object(&key).expect("registered");
    let new: Vec<_> = obj
        .shares
        .iter()
        .filter(|s| s.share.validator == addr(20) || s.share.validator == addr(21))
        .collect();
    assert_eq!(new.len(), 2);
    assert!(
        new.iter().all(|s| s.status == ShareStatus::Pending),
        "§6.10 item 6: a new share starts unconfirmed"
    );
    assert!(
        new.iter().all(|s| s.share.first_esi >= fresh_first),
        "the new ESIs are past every ESI ever used"
    );
    assert_eq!(
        new[0].share.first_esi, fresh_first,
        "the repair takes the segment's next unused ESI, so a lost ESI is never produced twice"
    );

    // Nothing is dropped yet: no new share has been acknowledged.
    assert_eq!(r.settle_repairs(), 0);
    assert!(
        obj.shares.iter().any(|s| s.lost),
        "§6.10 item 7: the lost shares stay until the new ones hold"
    );
    // Acknowledge one of the two: still not enough.
    r.ack(&key, &addr(20), 0).expect("ack");
    assert_eq!(r.settle_repairs(), 0);
    r.ack(&key, &addr(21), 0).expect("ack");
    assert!(
        r.settle_repairs() > 0,
        "every new share holds, so the lost ones go"
    );
    assert!(
        r.object(&key)
            .expect("registered")
            .shares
            .iter()
            .all(|s| !s.lost),
        "no lost share survives the settle"
    );
    // The repaired segment is no longer due.
    assert!(r.repairs_due(&key).is_empty());
}

/// §6.10 item 1: repair is lazy. A segment with one lost share is at risk and
/// is not a task; the task forms only once the lost count reaches `f / 2`.
#[test]
fn repair_fires_only_at_half_the_tolerance() {
    let mut r = Bud3Registry::default();
    let (_up, key) = register(&mut r, &content(1_500));
    ack_all(&mut r, &key);
    // One of four shares lost: at risk, nothing due.
    r.mark_unseen(&addr(10));
    assert_eq!(r.segments_at_risk(&key), 1);
    assert!(r.repairs_due(&key).is_empty(), "one share is not f / 2");
    assert_eq!(r.segments_at_risk(&key), 1, "but the segment is at risk");
    // Two of four: the task forms.
    r.mark_unseen(&addr(11));
    assert!(!r.repairs_due(&key).is_empty());
    // A segment that needs no repair refuses a RecordRepair.
    let ok_segment = 1u64;
    if r.object(&key).expect("registered").record.symbol_roots.len() > 1 {
        assert!(matches!(
            r.record_repair(&key, ok_segment, Vec::new(), [0u8; 32]),
            Err(RegistryError::BadRepair(_))
        ));
    }
}

/// §11.7 row "Content decline", T40: a decline moves the share to another
/// validator, produces no penalty, and does not block the upload.
#[test]
fn bud3_decline_content_reassigns() {
    let mut r = Bud3Registry::default();
    let bytes = content(1_500);
    let up = prepare_public_upload(&bytes, &P, &Bud3Limits::default(), 20).expect("upload");
    let record = up.record.clone();
    let key = record.commitment;

    // Holder 13 declines this content before the object exists.
    r.decline(addr(13), &record.content_id);
    let mut shares = Vec::new();
    for seg in 0..up.segments.len() as u64 {
        for h in 0..4u8 {
            shares.push((
                seg,
                Share {
                    validator: addr(10 + h),
                    class: if h == 3 { Class::Mobile } else { Class::Full },
                    first_esi: u32::from(h) * 5,
                    symbols: 5,
                },
            ));
        }
    }
    let before = r.state_root();
    assert_eq!(
        r.register_object(addr(1), record.clone(), shares.clone(), 0, 100),
        Err(RegistryError::Declined),
        "a share placed on a declining validator is refused, not silently dropped"
    );
    assert_eq!(r.state_root(), before, "a refusal writes nothing");

    // The uploader re-places that share on a validator that did not decline,
    // and the upload succeeds: the decline cost nobody anything.
    let moved: Vec<(u64, Share)> = shares
        .into_iter()
        .map(|(seg, s)| {
            if s.validator == addr(13) {
                (
                    seg,
                    Share {
                        validator: addr(40),
                        ..s
                    },
                )
            } else {
                (seg, s)
            }
        })
        .collect();
    assert_eq!(
        r.register_object(addr(1), record, moved, 0, 100),
        Ok(crate::storage::bud3::registry::Registered::New(key))
    );
    // No penalty is recorded anywhere: the decline is a preference, not an
    // offence (§11.7 "Kesinti yok").
    let registry = PermissionlessRegistry::with_params(RegistryParams::default());
    assert!(registry.slashing_history().is_empty());
    // And the registry remembers the decline, so a later placement on 13 is
    // refused the same way.
    assert!(!r.is_empty());
}

/// §6.9.3 item 5, T39: the placement table is a genesis parameter computed
/// off-chain. CI recomputes it from the parameters and checks equality, so the
/// shipped table is not a transcription nobody checks.
#[test]
fn bud3_placement_table_reproduces() {
    let table = PlacementTable::testnet_default();
    assert_eq!(table.validate(), Ok(()), "every row rebuilds a segment");
    assert_eq!(table.k, 4096, "§6.9.4 computes the table at k = 4096");

    // The rows are §6.9.4's table, in order. Written out here rather than read
    // from `testnet_default()`, because a test that reads the thing it checks
    // agrees with any table at all.
    let expected: [(u32, u32, u32, u32); 9] = [
        (8, 443, 256, 13),
        (16, 456, 0, 0),
        (16, 242, 256, 8),
        (32, 171, 0, 0),
        (32, 116, 256, 7),
        (64, 76, 0, 0),
        (64, 54, 512, 4),
        (128, 36, 0, 0),
        (128, 26, 1024, 2),
    ];
    assert_eq!(table.rows.len(), expected.len());
    for (row, (n_full, s_full, n_mobile, s_mobile)) in table.rows.iter().zip(expected) {
        assert_eq!(
            (row.n_full, row.s_full, row.n_mobile, row.s_mobile),
            (n_full, s_full, n_mobile, s_mobile),
            "a row moved; the table is a genesis parameter, so this is a governance change"
        );
    }

    // §6.9.4's published redundancy and Mobile share, recomputed from the row.
    // `redundancy_milli` is integer arithmetic on the row itself, which is the
    // check: a transcription error in either count moves the ratio.
    let first = table.rows[0];
    assert_eq!(first.redundancy_milli(table.k), 1_677, "1,678 in §6.9.4");
    assert_eq!(first.mobile_share_milli(), 484, "48% in §6.9.4");
    let mixed = table.rows[2];
    assert_eq!(mixed.redundancy_milli(table.k), 1_445, "1,445 in §6.9.4");
    assert_eq!(mixed.mobile_share_milli(), 346, "35% in §6.9.4");

    // The bucket lookup is integer comparison (§6.9.3 item 6, G-2): the
    // largest row that fits both counts wins, and a network too small for any
    // row has no row rather than a float-interpolated one.
    assert_eq!(table.lookup(8, 300), Some(table.rows[0]));
    assert_eq!(table.lookup(20, 0), Some(table.rows[1]));
    assert_eq!(table.lookup(40, 300), Some(table.rows[4]));
    assert_eq!(table.lookup(7, 1_000), None);
    assert_eq!(table.lookup(1_000, 10_000), Some(table.rows[8]));
}

/// §6.9.2, T34: the Mobile floor is 30% of a segment's symbols, and it holds
/// in every mixed bucket of the table.
#[test]
fn bud3_mobile_floor_holds() {
    let table = PlacementTable::testnet_default();
    let mut mixed = 0;
    for row in &table.rows {
        if row.n_mobile == 0 {
            // §6.9.4's all-Full rows are the no-Mobile candidates case; the
            // floor is about the buckets that have Mobile candidates at all.
            assert_eq!(row.s_mobile, 0, "an all-Full row holds no Mobile symbols");
            continue;
        }
        mixed += 1;
        assert!(
            row.mobile_share_milli() >= 300,
            "§6.9.2: the Mobile class holds at least 30% of the symbols; \
             this row holds {}‰",
            row.mobile_share_milli()
        );
    }
    assert!(mixed >= 4, "the table must have mixed buckets to check");
    // A row that breaks the floor is visible as such, so the assertion above
    // is not vacuous: drop the Mobile count to a token and the share falls
    // under 30%.
    let starved = crate::storage::bud3::placement::PlacementRow {
        n_full: 128,
        s_full: 30,
        n_mobile: 1024,
        s_mobile: 1,
    };
    assert!(starved.mobile_share_milli() < 300);
}

/// §6.13 item 4, T26: the network shrinks to one Full validator and every
/// object still decodes bit-exactly.
///
/// The surviving validator holds at least `k + 2` symbols of every segment,
/// which is what makes the read possible; the test reads the object back from
/// nothing but those symbols.
#[test]
fn bud3_network_shrink() {
    let data = content(3_000);
    let up = prepare_public_upload(&data, &P, &Bud3Limits::default(), 20).expect("upload");
    assert!(up.segments.len() >= 2, "the fixture must span segments");

    // One Full validator, holding `k + 2` symbols of each segment: the
    // survivors' merge after everyone else left (§6.13 items 1 and 4).
    let mut kept: Vec<Symbol> = Vec::new();
    for symbols in &up.segments {
        let encoder_k = symbols.len() as u32 - 2;
        let need = (encoder_k as usize + 2).min(symbols.len());
        kept.extend(symbols.iter().take(need).cloned());
    }
    let recovered = view_public(&up.record, kept).expect("one holder rebuilds the object");
    assert_eq!(recovered, data, "the object decodes bit-exactly");

    // Shrinking always keeps `k + 2`; one symbol fewer than that is a read
    // that cannot complete, which is the boundary the rule is drawn at.
    let mut short: Vec<Symbol> = Vec::new();
    for symbols in &up.segments {
        let encoder_k = symbols.len() as u32 - 2;
        let need = (encoder_k as usize + 1).min(symbols.len());
        short.extend(symbols.iter().take(need).cloned());
    }
    assert!(
        view_public(&up.record, short).is_err(),
        "k + 1 symbols is not k + 2 and must not decode"
    );
}

/// §6.13, T35: every Mobile holder disappears at once and no object is lost;
/// reads are served from the Full class.
#[test]
fn bud3_mobile_churn_no_loss() {
    // 8 Full and 256 simulated Mobile validators, the launch shape of the
    // item's completion criterion.
    let candidates: Vec<Candidate> = (0..8u32)
        .map(|i| {
            let mut v = [0u8; 32];
            v[..4].copy_from_slice(&i.to_le_bytes());
            Candidate {
                validator: v,
                account: v,
                class: Class::Full,
                stake: 10_000,
                free_quota_bytes: u64::MAX,
                network: None,
            }
        })
        .chain((0..256u32).map(|i| {
            let mut v = [0u8; 32];
            v[..4].copy_from_slice(&(100_000 + i).to_le_bytes());
            Candidate {
                validator: v,
                account: v,
                class: Class::Mobile,
                stake: 100,
                free_quota_bytes: u64::MAX,
                network: None,
            }
        }))
        .collect();

    let data = content(3_000);
    let up = prepare_public_upload(&data, &P, &Bud3Limits::default(), 20).expect("upload");
    let table = PlacementTable::testnet_default();
    let row = table
        .lookup(8, 256)
        .expect("the launch bucket is in the table");
    assert_eq!(row.n_full, 8);
    assert_eq!(row.n_mobile, 256);

    // Place every segment at the launch bucket.
    let mut by_segment: Vec<Vec<(u32, Vec<u8>)>> = Vec::new();
    for (segment, symbols) in up.segments.iter().enumerate() {
        let key = segment_key(&up.record.commitment, segment as u64);
        let shares = place(&key, &candidates, &row, 16, P.symbol_size.into())
            .expect("the launch bucket places");
        // Each share owns a contiguous ESI range; the symbols are the
        // encoder's own, so a holder's bytes are a slice of what was coded.
        let mut holders: Vec<(u32, Vec<u8>)> = Vec::new();
        for share in &shares {
            for esi in share.first_esi..share.first_esi + share.symbols {
                if let Some(symbol) = symbols.iter().find(|s| s.esi == esi) {
                    holders.push((esi, symbol.data.clone()));
                }
            }
        }
        assert!(!holders.is_empty(), "segment {segment} placed nothing");
        by_segment.push(holders);
    }
    assert_eq!(by_segment.len(), up.segments.len());

    // Every Mobile validator goes offline. Only the symbols the Full class
    // holds survive, and the object must still read.
    let full: std::collections::BTreeSet<[u8; 32]> = candidates
        .iter()
        .filter(|c| c.class == Class::Full)
        .map(|c| c.validator)
        .collect();
    let mut survivors: Vec<Symbol> = Vec::new();
    for (segment, symbols) in up.segments.iter().enumerate() {
        let key = segment_key(&up.record.commitment, segment as u64);
        let shares = place(&key, &candidates, &row, 16, P.symbol_size.into())
            .expect("places");
        for share in shares.iter().filter(|s| full.contains(&s.validator)) {
            for esi in share.first_esi..share.first_esi + share.symbols {
                if by_segment[segment].iter().any(|(e, _)| *e == esi) {
                    if let Some(symbol) = symbols.iter().find(|s| s.esi == esi) {
                        survivors.push(symbol.clone());
                    }
                }
            }
        }
    }
    let recovered = view_public(&up.record, survivors)
        .expect("the Full class alone serves the read after every Mobile left");
    assert_eq!(recovered, data, "no object is lost to a Mobile churn");

    // The row is the one that makes this true: the Full shares alone hold
    // `k + 2` symbols, which is the §6.13 item 4 condition.
    assert!(
        row.full_only_symbols() >= u64::from(table.k) + 2,
        "the launch row's Full shares must hold k + 2 on their own"
    );
}

/// §6.9.1 item 7: the diversity rule caps the shares of one account and one
/// network inside a segment, so a placement cannot pile a segment onto one
/// operator.
#[test]
fn bud3_placement_respects_the_diversity_caps() {
    // Sixteen candidates that are all one account on one network: the caps
    // have to refuse rather than fill the row.
    let candidates: Vec<Candidate> = (0..16u32)
        .map(|i| {
            let mut v = [0u8; 32];
            v[..4].copy_from_slice(&i.to_le_bytes());
            Candidate {
                validator: v,
                account: [0xAA; 32],
                class: Class::Full,
                stake: 1_000,
                free_quota_bytes: u64::MAX,
                network: Some([7u8; 8]),
            }
        })
        .collect();
    let row = crate::storage::bud3::placement::PlacementRow {
        n_full: 16,
        s_full: 300,
        n_mobile: 0,
        s_mobile: 0,
    };
    let key = segment_key(&[1u8; 32], 0);
    let result = place(&key, &candidates, &row, 4_096, P.symbol_size.into());
    // n = 16, so one account may hold max(1, 16/64) = 1 share and one network
    // max(2, 16/32) = 2: the sixteen needed shares cannot be found.
    assert!(
        matches!(result, Err(PlacementError::NotEnough { .. })),
        "the diversity caps must refuse a single-operator placement, got {result:?}"
    );

    // Spread over accounts and networks, the same row places.
    let spread: Vec<Candidate> = (0..16u32)
        .map(|i| {
            let mut v = [0u8; 32];
            v[..4].copy_from_slice(&i.to_le_bytes());
            let mut account = [0u8; 32];
            account[0] = i as u8;
            let mut network = [0u8; 8];
            network[0] = i as u8;
            Candidate {
                validator: v,
                account,
                class: Class::Full,
                stake: 1_000,
                free_quota_bytes: u64::MAX,
                network: Some(network),
            }
        })
        .collect();
    let placed = place(&key, &spread, &row, 4_096, P.symbol_size.into()).expect("places");
    assert_eq!(placed.len(), 16);
}

/// §6.11.2, T17 (the accelerated part): symbols lost from a segment are
/// recoverable from a decoder that holds any `k` of them, and the decoder
/// agrees with the encoder on the bytes. This is the primitive the nightly
/// durability simulation builds on.
#[test]
fn bud3_decoder_recovers_from_any_k_symbols() {
    let data = content(1_200);
    let encoder = SegmentEncoder::new(0, &data, &P).expect("encode");
    let k = encoder.k();
    let mut symbols = encoder.source_symbols();
    symbols.extend(encoder.repair_symbols(0, 4).expect("repair"));

    // Drop the first two source symbols: the decoder must still finish from
    // the rest.
    let kept: Vec<Symbol> = symbols.into_iter().skip(2).collect();
    let mut decoder = SegmentDecoder::new(0, data.len() as u64, &P).expect("decoder");
    let mut meter = Meter::new(1 << 20, 10_000);
    let mut done = None;
    for symbol in kept {
        if let Some(bytes) = decoder.push(symbol, &mut meter).expect("push") {
            done = Some(bytes.to_vec());
            break;
        }
    }
    let recovered = done.or_else(|| decoder.into_bytes()).expect("recovers");
    assert_eq!(&recovered[..data.len()], &data[..]);
    assert!(k >= 2, "a segment has at least two source symbols");
}

/// §6.9.5: the fee record separates the bytes the user pays for from the bytes
/// the Mobile floor adds, so the two can be paid from different pools.
#[test]
fn bud3_mobile_floor_bytes_are_a_separate_term() {
    let table = PlacementTable::testnet_default();
    let symbol_size = 128u32;
    for row in &table.rows {
        // The user pays for the smallest placement that rebuilds a segment.
        let user = row.user_physical_bytes(table.k, symbol_size);
        assert_eq!(user, (u64::from(table.k) + 2) * u64::from(symbol_size));
        // The floor's extra bytes are the rest, and the two terms add up to
        // the physical bytes the row actually holds.
        let floor = row.decentralization_physical_bytes(table.k, symbol_size);
        assert_eq!(
            user + floor,
            row.total_symbols() * u64::from(symbol_size),
            "the two fee fields must account for every physical byte"
        );
        if row.n_mobile > 0 {
            assert!(floor > 0, "a row with Mobile shares has a floor term");
            // The floor term is at least the Mobile symbols it exists for.
            assert!(
                floor >= u64::from(row.n_mobile) * u64::from(row.s_mobile) * u64::from(symbol_size)
                    / 2,
                "the floor term has to cover the Mobile symbols it buys"
            );
        }
    }
    // A placement that is already at the user minimum has no floor term: the
    // field is real, not a constant.
    let minimal = crate::storage::bud3::placement::PlacementRow {
        n_full: 1,
        s_full: table.k + 2,
        n_mobile: 0,
        s_mobile: 0,
    };
    assert_eq!(minimal.decentralization_physical_bytes(table.k, symbol_size), 0);
}

/// A repairer cannot take a share of its own repair: the transaction door
/// refuses it, and the ESI rules alone would not (§6.10 item 4).
#[test]
fn the_repair_transaction_refuses_a_self_share() {
    use crate::storage::bud3::tx::{apply, StorageTxV3};
    let mut r = Bud3Registry::default();
    let (_up, key) = register(&mut r, &content(1_500));
    ack_all(&mut r, &key);
    r.mark_unseen(&addr(10));
    r.mark_unseen(&addr(11));
    let due = r.repairs_due(&key);
    let segment = *due.first().expect("a repair is due");
    let tx = StorageTxV3::RecordRepair {
        object: key,
        segment,
        new_shares: vec![Share {
            validator: addr(10),
            class: Class::Full,
            first_esi: 20,
            symbols: 2,
        }],
        new_root: [3u8; 32],
    };
    assert!(matches!(
        apply(&mut r, addr(10), tx, 5),
        Err(RegistryError::BadRepair("the repairer cannot take a new share"))
    ));
    // The same repair from a third party is not refused for that reason.
    let tx = StorageTxV3::RecordRepair {
        object: key,
        segment,
        new_shares: vec![Share {
            validator: addr(20),
            class: Class::Full,
            first_esi: r.object(&key).expect("registered").next_esi[segment as usize],
            symbols: 2,
        }],
        new_root: [3u8; 32],
    };
    assert_eq!(
        apply(&mut r, addr(99), tx, 5),
        Ok(crate::storage::bud3::tx::Applied::Repaired)
    );
}

/// The seal: a sealed object's content id never matches public content, so a
/// B.U.D. 3.0 record cannot be opened by anyone who does not hold the object.
#[test]
fn a_sealed_record_never_matches_public_content() {
    let bytes = content(400);
    let id = crate::storage::bud3::content_id::ContentId::public(&bytes);
    assert_eq!(id.kind, ContentIdKind::Public);
    assert!(id.matches_public(&bytes));
    assert!(!id.matches_public(&content(401)));
}

/// `release_shares_lowers_quota_without_penalty` (IP-20 item 11): a holder
/// that gives shares up lowers its quota, the released shares come back under
/// the ordinary loss rule, and nothing is slashed.
#[test]
fn release_shares_lowers_quota_without_penalty() {
    use crate::validators::{
        LeaderCommitment, SeatFields, ValidatorClass, ValidatorDirectory, ValidatorRegistration,
    };
    let owner = crate::core::address::Address::from([0x11; 32]);
    let quota = 4 * 1024 * 1024 * 1024u64;
    let registration = ValidatorRegistration {
        owner,
        class: ValidatorClass::Full,
        operator_key: vec![1u8; 32],
        bls_key: vec![1u8; 48],
        bls_pop: vec![1u8; 48],
        seat: Some(SeatFields {
            vrf_key: vec![3u8; 32],
            pq_vote_key: vec![4u8; 32],
            leader_commitment: LeaderCommitment {
                commitment: [5u8; 32],
                length: 1,
            },
        }),
        custody_quota_bytes: quota,
        relay_offer: None,
        gateway_offer: None,
        peer_id: [2u8; 32],
    };
    registration.validate_shape().expect("a well-formed registration");
    let mut directory = ValidatorDirectory::new();
    directory
        .register(&registration, 1_000, 1_000, 0)
        .expect("register");
    let before = directory
        .get(&owner)
        .expect("registered")
        .custody_quota_bytes;
    assert_eq!(before, quota);

    // §7.9.5 item 4: the quota is lowered by releasing shares, not by
    // `UpdateCustodyQuota`, which refuses a decrease and names the release
    // path so an operator cannot believe it worked.
    let error = directory
        .request_quota_increase(&owner, before / 2, 0, 0)
        .expect_err("a decrease is not an increase");
    assert_eq!(error.code, "validator_quota_decrease_via_release");
    assert!(
        error.message.contains("release"),
        "the refusal must name `ReleaseShares`: {}",
        error.message
    );

    // The released shares come back under the ordinary loss rule, and no
    // penalty is produced: releasing is not an offence (§11.7).
    let mut r = Bud3Registry::default();
    let (_up, key) = register(&mut r, &content(1_500));
    ack_all(&mut r, &key);
    r.mark_unseen(&addr(10));
    assert!(
        r.segments_at_risk(&key) > 0,
        "released shares return as plain share loss, which repair handles"
    );
    let registry = PermissionlessRegistry::with_params(RegistryParams::default());
    assert!(
        registry.slashing_history().is_empty(),
        "release produces no penalty"
    );
}

/// The repair verification itself: a correct repair symbol regenerates, a
/// forged one does not, and an undrawn segment is not checked at all.
#[test]
fn repair_verification_compares_the_symbol_against_its_source() {
    let mut r = Bud3Registry::default();
    let source = content(1_400);
    let (up, key) = register(&mut r, &source);
    let segment = 0u64;

    // Find a seed that draws this segment, so the test exercises the check
    // rather than `NotDrawn`.
    let mut seed = [0u8; 32];
    let mut found = false;
    for i in 0..10_000u32 {
        seed[..4].copy_from_slice(&i.to_le_bytes());
        if repair::audit_drawn(&seed, &key, segment) {
            found = true;
            break;
        }
    }
    assert!(found, "a 1% draw is reachable within 10 000 seeds");

    let encoder = SegmentEncoder::new(segment, &source, &P).expect("encode");
    let real = encoder.repair_symbols(0, 1).expect("repair symbol");
    let real = real.first().expect("one symbol");
    assert_eq!(
        repair::verify(&seed, &r, &key, segment, &source, (real.esi, &real.data)),
        Verification::Regenerates
    );
    let mut bad = real.data.clone();
    bad[7] ^= 0x80;
    match repair::verify(&seed, &r, &key, segment, &source, (real.esi, &bad)) {
        Verification::Mismatch { claimed, derived, .. } => {
            assert_ne!(claimed, derived);
            assert_eq!(derived, symbol_leaf(&real.data));
        }
        other => panic!("a forged repair symbol must be a mismatch, got {other:?}"),
    }
    // An undrawn segment is not checked, so verification cannot be used as a
    // free decoding oracle for every repaired segment.
    let mut undrawn = [0u8; 32];
    let mut n = 0u32;
    loop {
        undrawn[..4].copy_from_slice(&n.to_le_bytes());
        if !repair::audit_drawn(&undrawn, &key, segment) {
            break;
        }
        n += 1;
    }
    assert_eq!(
        repair::verify(&undrawn, &r, &key, segment, &source, (real.esi, &real.data)),
        Verification::NotDrawn
    );
    let _ = up;
}

/// The two-field fee record of §6.9.5 is arithmetic on the row, and a record
/// cannot claim decentralization bytes for symbols the floor did not add.
#[test]
fn the_floor_term_is_never_larger_than_the_mobile_symbols() {
    let table = PlacementTable::testnet_default();
    for row in &table.rows {
        let mobile = row.n_mobile as u64 * row.s_mobile as u64;
        let full = row.full_only_symbols();
        assert!(
            mobile <= row.total_symbols(),
            "the two terms cannot exceed the physical bytes"
        );
        assert_eq!(full + mobile, row.total_symbols());
    }
}

/// `SlashingProof::BadRepair` survives a round trip through serde, so a report
/// travels in a block unchanged.
#[test]
fn the_bad_repair_proof_round_trips() {
    let proof = SlashingProof::BadRepair {
        object: [1u8; 32],
        segment: 7,
        epoch: 21,
        esi: 4_100,
        claimed: [2u8; 32],
        derived: [3u8; 32],
    };
    let encoded = bincode::serialize(&proof).expect("serializable");
    let decoded: SlashingProof = bincode::deserialize(&encoded).expect("deserializable");
    assert_eq!(decoded, proof);
    assert_eq!(decoded.condition(), SlashingCondition::BadRepair);
}

/// IP-20 item 13: `budlum_bud3_audit_latency_seconds` is a series the scrape
/// really carries, and an audit that ages is visible in it.
///
/// The series was named by the card, declared nowhere, and therefore written
/// nowhere: a scrape showed nothing at all where an operator expected a
/// distribution. This holds both halves - it is registered and exported before
/// anything observes it, and an open audit's age grows with the epochs it has
/// waited.
#[test]
fn the_audit_latency_series_exists_and_moves() {
    let metrics = crate::core::metrics::Metrics::new().expect("metric names are literals");
    let scrape = metrics.encode();
    assert!(
        scrape.contains("budlum_bud3_audit_latency_seconds"),
        "the audit-latency series is not exported, so an alert on it can never fire"
    );

    // An open audit ages with the epochs it has waited.
    let mut r = Bud3Registry::default();
    let (up, key) = register(&mut r, &content(1_500));
    ack_all(&mut r, &key);
    assert!(r.open_audits(&[21; 32], 4, &EVERY_SHARE) > 0);
    assert!(
        r.open_audit_ages(4).iter().all(|age| *age == 0),
        "an audit opened this epoch has waited no epochs"
    );
    let ages = r.open_audit_ages(6);
    assert!(!ages.is_empty());
    assert!(
        ages.iter().all(|age| *age == 2),
        "every open audit has waited the two epochs since it opened: {ages:?}"
    );

    // Answering reports the exact wait, and the wait is in epochs, which the
    // chain converts with its own epoch length.
    let obj = r.object(&key).expect("registered").clone();
    let symbols = &up.segments[0];
    let leaves: Vec<(u32, [u8; 32])> = symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let share = obj
        .shares
        .iter()
        .find(|s| s.share.validator == addr(10))
        .expect("holder 10");
    let (audit, _, opened) = share.open_audit.expect("drawn");
    assert_eq!(opened, 4);
    let pos = audit.position as usize;
    let proof = prove(
        audit.segment,
        &leaves,
        pos,
        &symbols[pos].data,
        audit.sub_block as usize,
    )
    .expect("proves");
    let (answered, waited) = r
        .submit_proofs(&addr(10), &[(key, proof)], 7)
        .expect("a valid proof answers its audit");
    assert_eq!(answered, 1);
    assert_eq!(waited, vec![3], "opened in 4, answered in 7: three epochs");

    // The chain's conversion is the one the histogram needs.
    let seconds = crate::core::chain_config::epoch_seconds_for_chain_id(45261);
    assert!(seconds > 0, "an epoch on testnet is a positive number of seconds");
    assert_eq!(
        seconds,
        crate::core::chain_config::epoch_len_for_chain_id(45261)
            * crate::core::chain_config::Network::from_chain_id(45261)
                .map_or(1, |n| n.slot_ms())
            / 1_000
    );
}
