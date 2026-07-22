//! Task 0.36: Çok-node / adversarial finality testleri.
//!
//! Bu paket, gerçek libp2p ağı kurmadan, `FinalityAggregator` + `sign_bls` +
//! `FinalityCert::verify` fonksiyonlarını doğrudan çağırarak birden görevla
//! "sanal" validator kimliğini (her biri kendi GERÇEK BLS anahtar çiftiyle)
//! simüle eder. `src/chain/finality.rs` içindeki mevcut test-harness deseninin
//! (`make_test_key`, `make_snapshot_with_keys`, gerçek `sign_bls` imzaları)
//! doğal bir genişlemesidir — mock/placeholder imza KULLANILMAZ.
//!
//! ## Task 0.38 sonrası davranış (Task 0.36 bulguları düzeltildi)
//!
//! * **1.1 Equivocation:** Aynı voter'ın FARKLI bir hash'e verdiği oy hâlâ
//!   sayıma girmez, AMA artık (Task 0.38 Fix 1) bir `DoubleSign` slashing-evidence
//!   ÜRETİLİR ve mevcut `submit_registry_slashing_report` yolundan geçirilerek
//!   gerçek bir slash'e yol açar (bkz. `equivocation_generates_slashing_evidence`).
//! * **1.3 Geçersiz imza:** `add_prevote`/`add_precommit` artık bireysel BLS
//!   imzasını INGEST'te doğrular (Task 0.38 Fix 2, Seçenek A). Geçersiz imza
//!   aggregat'a HİÇ girmez; dürüst alt-küme her zaman finalize edebilir — tek
//!   kötü aktör round'u durduramaz (bkz.
//!   `finality_recovers_honest_subset_after_invalid_signature`).

// Bu testler `sks[i]` ve `snap.validators[i]` paralel dizilerini AYNI indeksle
// eşleştirir; index-tabanlı döngü burada `enumerate()`'ten daha okunaklıdır.
#![allow(clippy::needless_range_loop)]

use crate::chain::blockchain::Blockchain;
use crate::chain::finality::{
    checkpoint_signing_message, pop_signing_message, sign_bls, FinalityAggregator, Precommit,
    Prevote, ValidatorEntry, ValidatorSetSnapshot,
};
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::registry::role::roles;
use crate::registry::MemberStatus;
use bls12_381::{G2Affine, G2Projective, Scalar};
use std::sync::Arc;

// --- Test harness: gerçek BLS anahtar çiftleri --------------------------------

/// Deterministik ama gerçek bir BLS anahtar çifti üretir (mock DEĞİL).
fn make_test_key(seed: u8) -> (Scalar, Vec<u8>) {
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

/// `n` validator'lık, her biri gerçek BLS + geçerli PoP taşıyan bir snapshot.
fn make_snapshot_with_keys(n: usize, stake_each: u64) -> (ValidatorSetSnapshot, Vec<Scalar>) {
    let mut sks = Vec::new();
    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| {
            let (sk, pk_bytes) = make_test_key(i as u8);
            sks.push(sk);
            let addr = addr_for(i);
            let pop_msg =
                pop_signing_message(crate::core::transaction::DEFAULT_CHAIN_ID, &addr, &pk_bytes);
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
    (ValidatorSetSnapshot::new(1, validators), sks)
}

/// Gerçek BLS imzalı bir prevote üretir.
fn signed_prevote(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Prevote {
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

/// Gerçek BLS imzalı bir precommit üretir (imza `hash` üzerinden).
fn signed_precommit(sk: &Scalar, epoch: u64, height: u64, hash: &str, voter: Address) -> Precommit {
    let msg = checkpoint_signing_message(epoch, height, hash);
    Precommit {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: voter,
        sig_bls: sign_bls(sk, &msg),
    }
}

/// Prevote quorum'una ulaşana kadar ilk `count` validator ile prevote atar.
fn drive_prevote_quorum(
    agg: &mut FinalityAggregator,
    snap: &ValidatorSetSnapshot,
    sks: &[Scalar],
    count: usize,
    epoch: u64,
    height: u64,
    hash: &str,
) {
    for i in 0..count {
        let pv = signed_prevote(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_prevote(pv).expect("prevote must be accepted");
    }
}

// =============================================================================
// 1.1 — Equivocation (eşdeğer oy)
// =============================================================================

/// Bir voter aynı yükseklik/epoch için iki FARKLI checkpoint hash'e prevote
/// imzalıyor. Çelişkili oy sayıma GİRMEZ (aggregator tek-hash'e bağlı) AMA artık
/// (Task 0.38 Fix 1) bir equivocation slashing-evidence ÜRETİLİR — sessizce yutulmaz.
/// Aynı hash'e tekrar oy ise "Duplicate" olur ve yeni evidence üretmez.
#[test]
fn finality_rejects_equivocating_voter() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let mut agg = FinalityAggregator::new(epoch, height, "HASH_A".into());
    agg.set_validator_snapshot(snap.clone());

    // Voter 0, doğru hash'e (HASH_A) oy verir -> kabul, evidence yok.
    let pv_a = signed_prevote(&sks[0], epoch, height, "HASH_A", snap.validators[0].address);
    agg.add_prevote(pv_a).expect("first (honest) vote accepted");
    assert!(
        agg.detected_equivocations.is_empty(),
        "tek dürüst oy evidence üretmemeli"
    );

    // Aynı voter, ÇELİŞKİLİ hash'e (HASH_B) oy verir -> sayıma girmez ama
    // equivocation evidence üretir.
    let pv_b = signed_prevote(&sks[0], epoch, height, "HASH_B", snap.validators[0].address);
    let err = agg
        .add_prevote(pv_b)
        .expect_err("equivocating (conflicting-hash) vote must not count");
    assert!(
        err.contains("hash mismatch"),
        "beklenen 'hash mismatch', görülen: {err}"
    );
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "çelişkili oy tam olarak bir slashing-evidence üretmeli"
    );

    // Aynı voter, AYNI hash'e ikinci oy verirse -> Duplicate, yeni evidence YOK.
    let pv_a2 = signed_prevote(&sks[0], epoch, height, "HASH_A", snap.validators[0].address);
    let err2 = agg
        .add_prevote(pv_a2)
        .expect_err("duplicate vote must be rejected");
    assert!(
        err2.contains("Duplicate"),
        "beklenen 'Duplicate', görülen: {err2}"
    );
    assert_eq!(
        agg.detected_equivocations.len(),
        1,
        "duplicate yeni evidence üretmemeli"
    );

    // Yalnızca tek (dürüst) oy sayıldı; equivocation quorum'u zorlayamadı.
    assert_eq!(agg.prevotes.len(), 1);
    assert!(!agg.prevote_quorum_reached);
}

// =============================================================================
// 1.2 — Quorum altı senaryo
// =============================================================================

/// N=4, quorum 2/3 -> 2667 gerekiyor. Sadece 2 validator (2000 stake) imzalarsa
/// cert üretilmez, finality Pending kalır.
#[test]
fn finality_stays_pending_below_quorum() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    // Yalnız 2/4 prevote -> 2000 < 2667.
    drive_prevote_quorum(&mut agg, &snap, &sks, 2, epoch, height, hash);
    assert!(!agg.prevote_quorum_reached, "2/4 quorum'u karşılamamalı");

    // Prevote quorum olmadan precommit reddedilir.
    let pc = signed_precommit(&sks[0], epoch, height, hash, snap.validators[0].address);
    assert!(agg.add_precommit(pc).is_err());

    // Cert üretilemez.
    assert!(agg.try_produce_cert().is_none());
}

// =============================================================================
// 1.3 — Karışık geçersiz imza (Task 0.38 Fix 2, Seçenek A: ingest-time doğrulama)
// =============================================================================

/// **Task 0.36'ten BİLİNÇLİ davranış değişikliği** (regresyon DEĞİL):
/// Eski `finality_invalid_signature_poisons_aggregate` testi, tek geçersiz
/// imzanın tüm agregasyonu düşürdüğünü (fail-closed) doğruluyordu. Task 0.38 Fix 2
/// (Seçenek A) ile geçersiz imza artık AGGREGAT'A HİÇ GİRMEZ — ingest'te
/// reddedilir. Böylece dürüst alt-küme (3/4) yine de finalize edebilir ve tek
/// kötü aktör round'u durduramaz (DoS önlendi).
#[test]
fn finality_recovers_honest_subset_after_invalid_signature() {
    // 4 validator, quorum 3 (2667). 4 dürüst prevote ile prevote quorum'u aş.
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 4, epoch, height, hash);
    assert!(agg.prevote_quorum_reached);

    // Validator 3 GEÇERSİZ imzalı precommit gönderir (yanlış mesajdan imza).
    let wrong_msg = checkpoint_signing_message(epoch, height, "WRONG_HASH");
    let bad_pc = Precommit {
        epoch,
        checkpoint_height: height,
        checkpoint_hash: hash.to_string(),
        voter_id: snap.validators[3].address,
        sig_bls: sign_bls(&sks[3], &wrong_msg),
    };
    // Fix 2: ingest'te REDDEDİLİR, aggregat'a hiç girmez.
    let err = agg
        .add_precommit(bad_pc)
        .expect_err("geçersiz imza ingest'te reddedilmeli");
    assert!(
        err.contains("Invalid precommit signature"),
        "görülen: {err}"
    );

    // Dürüst 3/4 precommit -> quorum karşılanır.
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("honest precommit accepted");
    }
    assert!(
        agg.precommit_quorum_reached,
        "dürüst 3/4 quorum'u karşılamalı"
    );

    // Cert üretilir VE doğrulanır — dürüst alt-küme kötü aktöre rağmen finalize etti.
    let cert = agg.try_produce_cert().expect("honest subset cert produced");
    assert_eq!(cert.signer_count(4), 3, "sadece dürüst 3 imza sayılmalı");
    cert.verify(&snap)
        .expect("dürüst alt-küme sertifikası doğrulanabilir olmalı");
}

/// Karşı-kanıt: aynı 3 validator TÜMÜ geçerli imza atarsa cert doğrulanır.
/// Bu, 1.3'teki başarısızlığın gerçekten geçersiz imzadan kaynaklandığını,
/// harness'tan değil, kanıtlar.
#[test]
fn finality_valid_quorum_produces_verifiable_cert() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 3, epoch, height, hash);
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("precommit accepted");
    }
    let cert = agg.try_produce_cert().expect("cert produced");
    assert_eq!(cert.signer_count(4), 3);
    cert.verify(&snap).expect("valid quorum cert must verify");
}

// =============================================================================
// 1.4 — Ağ bölünmesi (split quorum) / split-brain
// =============================================================================

/// 4 validator, quorum 3 (2667). İki alt-grup 2-2 bölünür, her biri FARKLI bir
/// checkpoint hash'e oy verir. Hiçbir taraf kendi başına quorum'a ulgörevz;
/// dolayısıyla aynı yükseklikte iki çelişkili cert (split-brain) OLUŞAMAZ.
#[test]
fn finality_prevents_split_brain_on_partition() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;

    // Grup A: validator 0,1 -> HASH_A
    let mut agg_a = FinalityAggregator::new(epoch, height, "HASH_A".into());
    agg_a.set_validator_snapshot(snap.clone());
    for i in 0..2 {
        let pv = signed_prevote(&sks[i], epoch, height, "HASH_A", snap.validators[i].address);
        agg_a.add_prevote(pv).expect("group A prevote");
    }

    // Grup B: validator 2,3 -> HASH_B
    let mut agg_b = FinalityAggregator::new(epoch, height, "HASH_B".into());
    agg_b.set_validator_snapshot(snap.clone());
    for i in 2..4 {
        let pv = signed_prevote(&sks[i], epoch, height, "HASH_B", snap.validators[i].address);
        agg_b.add_prevote(pv).expect("group B prevote");
    }

    // İki taraf da quorum altında -> hiçbir cert yok.
    assert!(
        !agg_a.prevote_quorum_reached,
        "grup A tek başına finalize edememeli"
    );
    assert!(
        !agg_b.prevote_quorum_reached,
        "grup B tek başına finalize edememeli"
    );
    assert!(agg_a.try_produce_cert().is_none());
    assert!(agg_b.try_produce_cert().is_none());
}

// =============================================================================
// 1.5 — Geç gelen oylar (cert üretildikten sonra)
// =============================================================================

/// Cert üretildikten sonra gelen oylar sistemi bozmaz: (a) daha önce sayılmış
/// bir voter'ın tekrar oyu "Duplicate" ile reddedilir, (b) yeni bir geç oy
/// eklense bile ilk cert'in checkpoint bağlamı değişmez ve doğrulanabilir kalır.
#[test]
fn finality_ignores_late_votes_after_cert() {
    let (snap, sks) = make_snapshot_with_keys(4, 1000);
    let epoch = 1;
    let height = 10;
    let hash = "cp";
    let mut agg = FinalityAggregator::new(epoch, height, hash.into());
    agg.set_validator_snapshot(snap.clone());

    drive_prevote_quorum(&mut agg, &snap, &sks, 3, epoch, height, hash);
    for i in 0..3 {
        let pc = signed_precommit(&sks[i], epoch, height, hash, snap.validators[i].address);
        agg.add_precommit(pc).expect("precommit accepted");
    }
    let cert = agg.try_produce_cert().expect("cert produced");
    cert.verify(&snap).expect("cert verifies");
    let original_hash = cert.checkpoint_hash.clone();
    let original_height = cert.checkpoint_height;

    // (a) Zaten sayılmış voter'ın geç/tekrar oyu -> Duplicate, güvenle reddedilir.
    let dup = signed_precommit(&sks[0], epoch, height, hash, snap.validators[0].address);
    assert!(
        agg.add_precommit(dup).is_err(),
        "geç gelen tekrar oy reddedilmeli"
    );

    // (b) Yeni (4.) validator'dan geç oy; state bozulmamalı, cert bağlamı sabit.
    let late = signed_precommit(&sks[3], epoch, height, hash, snap.validators[3].address);
    agg.add_precommit(late)
        .expect("new late precommit ingested");
    let cert2 = agg.try_produce_cert().expect("cert still producible");
    assert_eq!(
        cert2.checkpoint_hash, original_hash,
        "checkpoint hash değişmemeli"
    );
    assert_eq!(
        cert2.checkpoint_height, original_height,
        "yükseklik değişmemeli"
    );
    cert2.verify(&snap).expect("post-late cert still verifies");
}

// =============================================================================
// 1.6 — Gürültü altında dürüst quorum
// =============================================================================

/// 7 validator, quorum 2/3 -> 4667. 5 dürüst validator HONEST hash'e oy verir
/// (5000 >= 4667). 2 byzantine validator ÇELİŞKİLİ bir hash'e "gürültü" oyu
/// gönderir; bunlar honest aggregator tarafından reddedilir ve honest finality'yi
/// ENGELLEMEZ — dürüst quorum yine de doğrulanabilir cert üretir.
#[test]
fn finality_honest_quorum_survives_byzantine_noise() {
    let (snap, sks) = make_snapshot_with_keys(7, 1000);
    let epoch = 1;
    let height = 10;
    let honest_hash = "HONEST";
    let byz_hash = "BYZANTINE";
    let mut agg = FinalityAggregator::new(epoch, height, honest_hash.into());
    agg.set_validator_snapshot(snap.clone());

    // Byzantine gürültüsü ÖNCE gelsin (çelişkili hash) -> reddedilmeli.
    for i in 5..7 {
        let noise = signed_prevote(&sks[i], epoch, height, byz_hash, snap.validators[i].address);
        assert!(
            agg.add_prevote(noise).is_err(),
            "byzantine (çelişkili-hash) gürültü reddedilmeli"
        );
    }

    // 5 dürüst prevote.
    drive_prevote_quorum(&mut agg, &snap, &sks, 5, epoch, height, honest_hash);
    assert!(
        agg.prevote_quorum_reached,
        "dürüst 5/7 quorum'u karşılamalı"
    );

    // Byzantine gürültü precommit görevında da tekrar denesin -> yine reddedilir.
    for i in 5..7 {
        let noise = Precommit {
            epoch,
            checkpoint_height: height,
            checkpoint_hash: byz_hash.to_string(),
            voter_id: snap.validators[i].address,
            sig_bls: sign_bls(
                &sks[i],
                &checkpoint_signing_message(epoch, height, byz_hash),
            ),
        };
        assert!(
            agg.add_precommit(noise).is_err(),
            "byzantine precommit reddedilmeli"
        );
    }

    // 5 dürüst precommit -> quorum, cert üretilir ve DOĞRULANIR.
    for i in 0..5 {
        let pc = signed_precommit(
            &sks[i],
            epoch,
            height,
            honest_hash,
            snap.validators[i].address,
        );
        agg.add_precommit(pc).expect("honest precommit accepted");
    }
    assert!(agg.precommit_quorum_reached);
    let cert = agg.try_produce_cert().expect("honest cert produced");
    assert_eq!(cert.signer_count(7), 5);
    cert.verify(&snap)
        .expect("honest quorum cert must verify despite noise");
}

// =============================================================================
// Task 0.38 — Uçtan uca: equivocation -> evidence -> slash (Blockchain akışı)
// =============================================================================

/// Bir Blockchain kurar, `checkpoint_height` gerçek bloğa kadar üretir,
/// prevote görevını başlatır. `voter` gerçek BLS anahtarıyla önce doğru hash'e,
/// sonra çelişkili bir hash'e imza atar. `Blockchain::handle_prevote`, tespit
/// edilen equivocation evidence'ını mevcut `submit_registry_slashing_report`
/// yolundan geçirir ve gerçek bir slash uygular.
#[test]
fn equivocation_generates_slashing_evidence() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;

    // İki validator: `honest` blokları üretir, `equivocator` çifte imza atacak.
    let mut hsk = [0u8; 64];
    hsk[0] = 11;
    let honest_bls = Scalar::from_bytes_wide(&hsk);
    let honest_pk = G2Affine::from(G2Projective::generator() * honest_bls)
        .to_compressed()
        .to_vec();
    let honest = Address::from([1u8; 32]);

    let mut esk = [0u8; 64];
    esk[0] = 22;
    let equiv_bls = Scalar::from_bytes_wide(&esk);
    let equiv_pk = G2Affine::from(G2Projective::generator() * equiv_bls)
        .to_compressed()
        .to_vec();
    let equivocator = Address::from([2u8; 32]);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(equivocator, 10_000);
    bc.state.validators.get_mut(&honest).unwrap().bls_public_key = honest_pk;
    bc.state
        .validators
        .get_mut(&equivocator)
        .unwrap()
        .bls_public_key = equiv_pk;

    // Slash öncesi: equivocator kayıtlı, aktif, tam stake.
    let before = bc
        .state
        .registry
        .get(&equivocator, roles::VALIDATOR)
        .expect("equivocator registered")
        .clone();
    assert_eq!(before.stake, 10_000);
    assert!(matches!(before.status, MemberStatus::Active));

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    assert_eq!(block.index, cp);

    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc
        .finality_aggregator
        .as_ref()
        .expect("aggregator active")
        .epoch;

    // Equivocator önce KANONİK hash'e imzalar (sayılır), sonra ÇELİŞKİLİ hash'e.
    let mut pv1 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv1.sig_bls = sign_bls(&equiv_bls, &pv1.signing_message());
    bc.handle_prevote(pv1).expect("canonical prevote accepted");

    let mut pv2 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: "CONFLICTING_HASH".to_string(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv2.sig_bls = sign_bls(&equiv_bls, &pv2.signing_message());
    // Çelişkili oy sayıma girmez (hash mismatch) ama evidence üretip slash tetikler.
    let _ = bc.handle_prevote(pv2);

    // Slash sonrası: equivocator jail'lenmiş (Slashed) ve stake %50 kesilmiş.
    let after = bc
        .state
        .registry
        .get(&equivocator, roles::VALIDATOR)
        .expect("still present after slash");
    assert!(
        matches!(after.status, MemberStatus::Slashed),
        "equivocator jail'lenmeli, görülen: {:?}",
        after.status
    );
    assert_eq!(
        after.stake, 5_000,
        "double-sign %50 kesmeli (10000 -> 5000)"
    );
    // Dürüst validator etkilenmez.
    let honest_reg = bc.state.registry.get(&honest, roles::VALIDATOR).unwrap();
    assert!(matches!(honest_reg.status, MemberStatus::Active));
    assert_eq!(honest_reg.stake, 10_000);
}

// =============================================================================
// Task 0.40 Görev 1 — equivocation -> slash -> KALICILIK (snapshot round-trip)
// =============================================================================

/// Equivocation üretilip slash uygulandıktan SONRA snapshot alınır
/// (`try_to_bytes`) ve geri yüklenir (`from_snapshot_v2`). Kalıcı slashing
/// geçmişi kaydının hayatta kaldığı ve birebir aynı olduğu doğrulanır.
#[test]
fn equivocation_slashing_record_survives_snapshot_roundtrip() {
    use crate::chain::snapshot::{StateSnapshotV2, StateSnapshotV2Params};
    use crate::core::account::AccountState;
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::evidence::SlashingProof;

    // BLS anahtarlı equivocator + dürüst üretici.
    let mut esk = [0u8; 64];
    esk[0] = 44;
    let equiv_bls = Scalar::from_bytes_wide(&esk);
    let equiv_pk = G2Affine::from(G2Projective::generator() * equiv_bls)
        .to_compressed()
        .to_vec();
    let equivocator = Address::from([2u8; 32]);
    let honest = Address::from([1u8; 32]);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(equivocator, 10_000);
    bc.state
        .validators
        .get_mut(&equivocator)
        .unwrap()
        .bls_public_key = equiv_pk;

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    let mut pv1 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv1.sig_bls = sign_bls(&equiv_bls, &pv1.signing_message());
    bc.handle_prevote(pv1).expect("canonical prevote accepted");

    let mut pv2 = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: "CONFLICTING_HASH".to_string(),
        voter_id: equivocator,
        sig_bls: vec![],
    };
    pv2.sig_bls = sign_bls(&equiv_bls, &pv2.signing_message());
    let _ = bc.handle_prevote(pv2);

    // Slash uygulandı VE kalıcı geçmişe yazıldı.
    let history_before = bc.state.registry.slashing_history_for(&equivocator);
    assert_eq!(
        history_before.len(),
        1,
        "equivocation kalıcı geçmişe yazılmalı"
    );
    let rec_penalty = history_before[0].penalty;
    let rec_remaining = history_before[0].remaining_stake;
    assert!(matches!(
        history_before[0].report.proof,
        SlashingProof::DoubleSign { .. }
    ));

    // Snapshot al -> geri yükle.
    let params = StateSnapshotV2Params {
        height: cp,
        block_hash: block.hash.clone(),
        genesis_hash: "aa".repeat(32),
        chain_id: 1337,
        finalized_height: 0,
        finalized_hash: String::new(),
        finality_certificates: vec![],
    };
    let v2 = StateSnapshotV2::from_state(&bc.state, params);
    let bytes = v2.try_to_bytes().expect("snapshot serialize must succeed");
    let restored = StateSnapshotV2::from_bytes(&bytes).expect("snapshot deserialize");
    let restored_state = AccountState::from_snapshot_v2(&restored);

    // Kayıt hayatta ve birebir aynı.
    let history_after = restored_state.registry.slashing_history_for(&equivocator);
    assert_eq!(
        history_after.len(),
        1,
        "restore sonrası kayıt kaybolmamalı (Task 0.16 dersi)"
    );
    assert_eq!(history_after[0].report.offender, equivocator);
    assert_eq!(history_after[0].penalty, rec_penalty);
    assert_eq!(history_after[0].remaining_stake, rec_remaining);
    assert!(matches!(
        history_after[0].report.proof,
        SlashingProof::DoubleSign { .. }
    ));
}

// =============================================================================
// Task 0.40 Görev 2 — tekrarlı geçersiz imza -> rate-limit tabanlı slash
// =============================================================================

/// Bir validator eşik (`max_invalid_votes_per_epoch`) kadar geçersiz imzalı oy
/// gönderir → uçtan uca `handle_prevote` akışından slash tetiklenir.
#[test]
fn repeated_invalid_signatures_trigger_slash() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::params::RegistryParams;

    let honest = Address::from([1u8; 32]);
    let spammer = Address::from([2u8; 32]);
    // Spammer'a gerçek BLS anahtarı ver (üyelik kontrolünü geçsin) ama geçersiz
    // imza göndersin.
    let mut ssk = [0u8; 64];
    ssk[0] = 55;
    let spammer_bls = Scalar::from_bytes_wide(&ssk);
    let spammer_pk = G2Affine::from(G2Projective::generator() * spammer_bls)
        .to_compressed()
        .to_vec();

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(spammer, 10_000);
    bc.state
        .validators
        .get_mut(&spammer)
        .unwrap()
        .bls_public_key = spammer_pk;

    // Küçük eşik ile testi hızlandır.
    let threshold = 3u64;
    bc.state.registry.set_params(RegistryParams {
        max_invalid_votes_per_epoch: threshold,
        ..RegistryParams::default()
    });

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // Eşik-1 geçersiz imza: henüz slash yok.
    for _ in 0..(threshold - 1) {
        let bad = Prevote {
            epoch,
            checkpoint_height: cp,
            checkpoint_hash: block.hash.clone(),
            voter_id: spammer,
            sig_bls: vec![0u8; 48], // geçersiz
        };
        let _ = bc.handle_prevote(bad);
    }
    let mid = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(mid.status, MemberStatus::Active),
        "eşik altında slash olmamalı"
    );
    assert_eq!(mid.stake, 10_000);

    // Eşiği aşan geçersiz imza -> slash.
    let bad = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: spammer,
        sig_bls: vec![0u8; 48],
    };
    let _ = bc.handle_prevote(bad);

    let after = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(after.status, MemberStatus::Slashed),
        "eşik aşılınca slash+jail olmalı, görülen: {:?}",
        after.status
    );
    // MaliciousBehaviour oranı %100 (onaylı karar): stake sıfırlanır.
    assert_eq!(
        after.stake, 0,
        "invalid-sig spam MaliciousBehaviour %100 kesmeli"
    );
    // Kalıcı geçmişte InvalidSignatureSpam kaydı var.
    let hist = bc.state.registry.slashing_history_for(&spammer);
    assert_eq!(hist.len(), 1);
    assert!(matches!(
        hist[0].report.proof,
        crate::registry::evidence::SlashingProof::InvalidSignatureSpam { .. }
    ));
    // Dürüst validator etkilenmez.
    assert!(matches!(
        bc.state
            .registry
            .get(&honest, roles::VALIDATOR)
            .unwrap()
            .status,
        MemberStatus::Active
    ));
}

/// Eşiğin ALTINDA kalan sayıda geçersiz imza slash tetiklemez (yanlış pozitif
/// yok).
#[test]
fn invalid_signatures_below_threshold_do_not_slash() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;
    use crate::registry::params::RegistryParams;

    let honest = Address::from([1u8; 32]);
    let spammer = Address::from([2u8; 32]);
    let mut ssk = [0u8; 64];
    ssk[0] = 66;
    let spammer_bls = Scalar::from_bytes_wide(&ssk);
    let spammer_pk = G2Affine::from(G2Projective::generator() * spammer_bls)
        .to_compressed()
        .to_vec();

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.add_validator(spammer, 10_000);
    bc.state
        .validators
        .get_mut(&spammer)
        .unwrap()
        .bls_public_key = spammer_pk;

    let threshold = 5u64;
    bc.state.registry.set_params(RegistryParams {
        max_invalid_votes_per_epoch: threshold,
        ..RegistryParams::default()
    });

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // threshold-1 geçersiz imza: slash YOK.
    for _ in 0..(threshold - 1) {
        let bad = Prevote {
            epoch,
            checkpoint_height: cp,
            checkpoint_hash: block.hash.clone(),
            voter_id: spammer,
            sig_bls: vec![0u8; 48],
        };
        let _ = bc.handle_prevote(bad);
    }

    let reg = bc.state.registry.get(&spammer, roles::VALIDATOR).unwrap();
    assert!(
        matches!(reg.status, MemberStatus::Active),
        "eşik altında slash olmamalı"
    );
    assert_eq!(reg.stake, 10_000);
    assert!(bc.state.registry.slashing_history_for(&spammer).is_empty());
    assert_eq!(
        bc.state.invalid_votes.invalid_count(&spammer),
        threshold - 1
    );
}

/// Task 0.38 Fix 2 uçtan uca: `Blockchain::handle_prevote` geçersiz BLS imzalı bir
/// oyu ingest'te reddeder — aggregat'a hiç girmez, state değişmez.
#[test]
fn blockchain_rejects_invalid_vote_signature_at_ingest() {
    use crate::core::chain_config::FINALITY_CHECKPOINT_INTERVAL;

    let mut hsk = [0u8; 64];
    hsk[0] = 33;
    let honest_bls = Scalar::from_bytes_wide(&hsk);
    let honest_pk = G2Affine::from(G2Projective::generator() * honest_bls)
        .to_compressed()
        .to_vec();
    let honest = Address::from([1u8; 32]);

    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    bc.state.add_balance(&honest, 10_000);
    bc.state.add_validator(honest, 10_000);
    bc.state.validators.get_mut(&honest).unwrap().bls_public_key = honest_pk;

    let cp = FINALITY_CHECKPOINT_INTERVAL;
    for _ in 1..cp {
        let _ = bc.produce_block(honest).unwrap();
    }
    let (block, _) = bc.produce_block(honest).unwrap();
    bc.start_prevote_task(block.index, block.hash.clone());
    let epoch = bc.finality_aggregator.as_ref().unwrap().epoch;

    // Geçersiz imzalı oy -> ingest'te reddedilir.
    let bad = Prevote {
        epoch,
        checkpoint_height: cp,
        checkpoint_hash: block.hash.clone(),
        voter_id: honest,
        sig_bls: vec![0u8; 48],
    };
    let err = bc
        .handle_prevote(bad)
        .expect_err("garbage sig must be rejected");
    assert!(err.contains("Invalid prevote signature"), "görülen: {err}");
    assert_eq!(
        bc.finality_aggregator.as_ref().unwrap().prevotes.len(),
        0,
        "geçersiz oy aggregat'a girmemeli"
    );
}
