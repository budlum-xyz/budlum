//! Task 0.40 §1.3 — Finality live-path son taraması.
//!
//! Mevcut `finality_adversarial.rs` (12 test) Task 0.36 + Task 0.38 düzeltmelerini
//! (equivocation → slashing evidence, ingest-time imza doğrulama) kapsar.
//! Bu dosya, **live-path pencerelerini** ve **dürüstlük sınırlarını** test
//! eder — son taramada eksik kalan senaryolar.
//!
//! ## Kapsam
//!
//! - **2.1 Epoch değişimi**: validator seti her epoch'ta yenileniyor; eski
//!   epoch'un oyları yeni aggregator'a karışmamalı.
//! - **2.2 Geç prevote (height uyumsuzluğu)**: aynı epoch içinde farklı
//!   checkpoint_height'e verilen oy "height mismatch" ile reddedilmeli.
//! - **2.3 Çift sign (aynı voter, aynı epoch)**: bir voter aynı epoch'ta iki
//!   kez sign edip ardı ardına iki farklı hash'e oy atarsa sadece İLK oyu
//!   sayılır, ikincisi reddedilir; oy penceresi sızdırmaz.
//! - **2.4 Snapshot hash tutarlılığı**: farklı validator setlerinin aynı
//!   `compute_hash` çıktısı eşit olmamalı (collision-free kabul).
//!
//! ## Yapmadıkları
//!
//! - Quorum / split-brain / byzantine gürültü: `finality_adversarial.rs`
//!   bunları Task 0.36'te kapsadı, regresyon DEĞİL.
//! - Snapshot roundtrip: `equivocation_slashing_record_survives_snapshot_roundtrip`
//!   bunu Task 0.40 Görev 1'de kapsadı.
//! - Rate-limit invalid sig slashing: `repeated_invalid_signatures_trigger_slash`
//!   Task 0.40 Görev 2'de kapsadı.

#![allow(clippy::needless_range_loop)]

use crate::chain::finality::{
    pop_signing_message, sign_bls, FinalityAggregator, Prevote, ValidatorEntry,
    ValidatorSetSnapshot,
};
use crate::core::address::Address;
use crate::core::transaction::DEFAULT_CHAIN_ID;
use bls12_381::{G2Affine, G2Projective, Scalar};

// --- Test harness ------------------------------------------------------------

/// Deterministik ama gerçek bir BLS anahtar çifti (mock DEĞİL).
fn make_key(seed: u8) -> (Scalar, Vec<u8>) {
    let mut sk_bytes = [0u8; 64];
    sk_bytes[0] = seed + 1;
    let sk = Scalar::from_bytes_wide(&sk_bytes);
    let pk = G2Affine::from(G2Projective::generator() * sk);
    (sk, pk.to_compressed().to_vec())
}

fn addr_for(i: usize) -> Address {
    let mut b = [0u8; 32];
    b[0] = (i + 1) as u8;
    Address::from(b)
}

/// n validator'lık, her biri gerçek BLS + geçerli PoP taşıyan snapshot.
fn make_snapshot(n: usize, epoch: u64, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
    let mut sks = Vec::new();
    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| {
            let (sk, pk_bytes) = make_key(i as u8);
            sks.push(sk);
            let addr = addr_for(i);
            let pop_msg = pop_signing_message(DEFAULT_CHAIN_ID, &addr, &pk_bytes);
            let pop_sig = sign_bls(&sk, &pop_msg);
            ValidatorEntry {
                address: addr,
                stake: stake_each,
                bls_public_key: pk_bytes,
                pop_signature: pop_sig,
                pq_public_key: Vec::new(),
            }
        })
        .collect();
    (ValidatorSetSnapshot::new(epoch, validators), sks)
}

fn sign_prevote(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Prevote {
    let mut v = Prevote {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: voter,
        sig_bls: vec![],
    };
    v.sig_bls = sign_bls(sk, &v.signing_message());
    v
}

// =============================================================================
// 2.1 — Epoch değişimi (pencere izolasyonu)
// =============================================================================

/// Farklı epoch'ların aggregator'ları birbirinden tamamen izole: epoch 1'de
/// oy veren bir voter, epoch 2'de aynı hash'e oy verse de yeni aggregator
/// bunu kendi penceresinde sayar (eski aggregator'ı etkilemez, yenisini de
/// kirletmez).
#[test]
fn live_path_epoch_change_isolates_votes() {
    let (snap1, sks1) = make_snapshot(4, 1, 1000);
    let mut agg1 = FinalityAggregator::new(1, 10, "H".into());
    agg1.set_validator_snapshot(snap1.clone());
    // 3/4 prevote -> epoch 1 penceresi 3 oy alır.
    for i in 0..3 {
        let pv = sign_prevote(&sks1[i], 1, 10, "H", snap1.validators[i].address);
        agg1.add_prevote(pv).expect("epoch 1 prevote");
    }
    assert_eq!(agg1.prevotes.len(), 3, "epoch 1 pencere 3 oy almalı");

    // Epoch 2 için YENİ bir aggregator + YENİ bir snapshot üret.
    let (snap2, sks2) = make_snapshot(4, 2, 1000);
    let mut agg2 = FinalityAggregator::new(2, 20, "H2".into());
    agg2.set_validator_snapshot(snap2.clone());

    // Epoch 2'de 1 validator oy verir — kendi penceresinde sayılır.
    let pv2 = sign_prevote(&sks2[0], 2, 20, "H2", snap2.validators[0].address);
    agg2.add_prevote(pv2).expect("epoch 2 prevote");
    assert_eq!(agg2.prevotes.len(), 1);
    // Epoch 1 aggregator hâlâ kendi penceresinde, etkilenmedi.
    assert_eq!(agg1.prevotes.len(), 3, "epoch 1 penceresi kirletilmemeli");
}

// =============================================================================
// 2.2 — Geç prevote (height uyumsuzluğu)
// =============================================================================

/// Aynı epoch içinde FARKLI checkpoint_height'e verilen oy reddedilir —
/// aggregator'ın `checkpoint_height`'i sabit, farklı height'tan gelen oy
/// kabul edilmez (pencere sızıntısı yok).
#[test]
fn live_path_prevote_with_wrong_height_rejected() {
    let (snap, sks) = make_snapshot(4, 1, 1000);
    let mut agg = FinalityAggregator::new(1, 10, "H".into());
    agg.set_validator_snapshot(snap.clone());

    // Doğru height=10, doğru hash.
    let pv_ok = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    agg.add_prevote(pv_ok).expect("doğru height kabul");

    // Yanlış height=11. İmza farklı mesaj üzerinden atıldığı için
    // aggregator'ın beklediği mesaja UYMUYOR → reddedilir.
    let pv_bad = sign_prevote(&sks[0], 1, 11, "H", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_bad)
        .expect_err("yanlış height imza geçersiz olmalı");
    let err_lower = err.to_lowercase();
    assert!(
        err_lower.contains("invalid")
            || err_lower.contains("signature")
            || err_lower.contains("mismatch")
            || err_lower.contains("height"),
        "görülen: {err}"
    );
    // Aggregator'a sadece ilk oy girdi.
    assert_eq!(agg.prevotes.len(), 1);
}

// =============================================================================
// 2.3 — Çift sign penceresi (aynı voter, aynı epoch, ardışık iki oy)
// =============================================================================

/// Aynı voter aynı epoch'ta aynı hash'e İKİ kez oy veremez (pencere
/// tek-oy kabul eder; ikincisi Duplicate ile reddedilir). Farklı hash'e ikinci
/// oy da reddedilir. Pencerenin "sızdırmaz" olduğu doğrulanır.
#[test]
fn live_path_double_sign_window_is_tight() {
    let (snap, sks) = make_snapshot(3, 1, 1000);
    let mut agg = FinalityAggregator::new(1, 10, "H".into());
    agg.set_validator_snapshot(snap.clone());

    // 1. oy (canonical) — kabul.
    let pv1 = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    agg.add_prevote(pv1).expect("first prevote");

    // 2. oy (AYNI voter, AYNI hash) — Duplicate, reddedilir.
    let pv_dup = sign_prevote(&sks[0], 1, 10, "H", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_dup)
        .expect_err("duplicate prevote reddedilmeli");
    assert!(err.contains("Duplicate"), "görülen: {err}");

    // 3. oy (AYNI voter, FARKLI hash) — hash mismatch + evidence.
    let pv_conflict = sign_prevote(&sks[0], 1, 10, "H2", snap.validators[0].address);
    let _ = agg.add_prevote(pv_conflict); // reddedilir ama evidence üretir
    assert_eq!(agg.prevotes.len(), 1, "sadece ilk oy sayılmalı");
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "çelişkili-hash oyu evidence üretmeli"
    );
}

// =============================================================================
// 2.4 — Snapshot hash çeşitliliği
// =============================================================================

/// Farklı validator setleri (farklı sıralama, farklı sayı) farklı snapshot
/// hash üretir — collision-free kabul. AYNI set aynı hash üretir
/// (deterministik kabul).
#[test]
fn live_path_snapshot_hash_distinguishes_sets() {
    let (snap_a, _) = make_snapshot(3, 1, 1000);
    let hash_a = ValidatorSetSnapshot::compute_hash(&snap_a.validators);

    let (snap_b, _) = make_snapshot(4, 1, 1000);
    let hash_b = ValidatorSetSnapshot::compute_hash(&snap_b.validators);

    let (snap_c, _) = make_snapshot(3, 1, 2000);
    let hash_c = ValidatorSetSnapshot::compute_hash(&snap_c.validators);

    assert_ne!(
        hash_a, hash_b,
        "3 vs 4 validator setleri aynı hash olmamalı"
    );
    assert_ne!(
        hash_a, hash_c,
        "1000 vs 2000 stake setleri aynı hash olmamalı"
    );
    assert_ne!(
        hash_b, hash_c,
        "farklı stake + farklı boyut aynı hash olmamalı"
    );

    // AYNI set deterministik olarak aynı hash üretir.
    let hash_a2 = ValidatorSetSnapshot::compute_hash(&snap_a.validators);
    assert_eq!(hash_a, hash_a2, "compute_hash deterministik olmalı");
}
