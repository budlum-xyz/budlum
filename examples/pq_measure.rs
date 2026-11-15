//! The post-quantum measurement tables.
//!
//! `cargo run --release --example pq_measure -- tables` prints the deterministic tables
//! (sizes, QC blobs, signature capacity, daily seal traffic) as Markdown. `-- timings`
//! prints the timing table, which depends on the machine and is therefore uploaded as a
//! CI artifact and never compared by `pq-measure --check`. The `pq-measure` tool in
//! `xtask/tools` splices the first output into `docs/pq/MEASUREMENTS.md`.

use std::fmt::Write as _;
use std::time::Instant;

use budlum_core::consensus::qc::{qc_blob_max_bytes, QC_CHUNK_BYTES};
use budlum_core::crypto::composite::{
    self, CompositeKeypair, CompositePublicKey, CompositeSignature,
};
use budlum_core::crypto::ctx;
use budlum_core::crypto::pq;
use budlum_core::crypto::scheme::{SchemeId, SchemeInfo, SuiteId, SCHEMES, SUITES};
use budlum_core::settlement::pq_anchor::ANCHOR_INTERVAL;
use budlum_core::settlement::root_seal::ROOT_SEAL_INTERVAL;
use ed25519_dalek::{Signer, SigningKey};

/// The body budget of, in bytes.
const BODY_BUDGET: usize = 1_000_000;
/// The shortest block interval the consensus accepts (`MIN_BLOCK_INTERVAL_MS`).
const MIN_BLOCK_INTERVAL_MS: u64 = 1_000;
/// Anchor signatures per anchor.
const ANCHOR_SIGNATURES: usize = 2;
/// Hot validator counts the QC table covers.
const VALIDATOR_COUNTS: [usize; 6] = [50, 100, 200, 512, 750, 1000];

fn opt(value: Option<usize>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| v.to_string())
}

fn sizes_table(out: &mut String) {
    out.push_str("### Scheme sizes (read from `SCHEMES`)\n\n");
    out.push_str(
        "| Scheme | Id | Family | NIST category | Genesis status | Public key | Signature |\n",
    );
    out.push_str("|---|---|---|---|---|---|---|\n");
    for s in SCHEMES {
        write_scheme_row(out, s);
    }
    out.push_str("\n### Suite sizes (read from `SUITES`, encoded with the composite codec)\n\n");
    out.push_str("| Suite | Id | PQ component | Genesis status | Composite public key | Composite signature | Recovery public key |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for suite in SUITES {
        let pk = CompositePublicKey::encoded_len(suite.id).ok();
        let sig = CompositeSignature::encoded_len(suite.id).ok();
        let recovery = suite
            .recovery
            .and_then(|r| r.info())
            .and_then(|i| i.public_key_len);
        let pq_name = suite.pq.info().map_or("unlisted", |i| i.short);
        let _ = writeln!(
            out,
            "| 0x{:04x} | {} | {} | {:?} | {} | {} | {} |",
            suite.id.0,
            suite_name(suite.id),
            pq_name,
            suite.genesis_status,
            opt(pk),
            opt(sig),
            opt(recovery),
        );
    }
    out.push('\n');
}

fn suite_name(id: SuiteId) -> &'static str {
    if id == SuiteId::USER {
        "user"
    } else if id == SuiteId::VALIDATOR {
        "validator"
    } else if id == SuiteId::USER_FN_DSA {
        "user-fn-dsa"
    } else if id == SuiteId::EMERGENCY_VALIDATOR {
        "emergency-validator"
    } else {
        "unlisted"
    }
}

fn write_scheme_row(out: &mut String, s: &SchemeInfo) {
    let _ = writeln!(
        out,
        "| {} | 0x{:04x} | {:?} | {} | {:?} | {} | {} |",
        s.short,
        s.id.0,
        s.family,
        s.nist_category.map_or("n/a".to_string(), |c| c.to_string()),
        s.genesis_status,
        opt(s.public_key_len),
        opt(s.signature_len),
    );
}

fn signature_capacity_table(out: &mut String) {
    out.push_str("### Signature material per transaction\n\n");
    let _ = writeln!(
        out,
        "Counts what a signed transaction must carry for its authorization: one composite public key and one composite signature. The rest of the envelope is not counted, so the transactions per body are an upper bound. Body budget: {BODY_BUDGET} bytes.\n"
    );
    out.push_str(
        "| Suite | Key + signature bytes | Upper bound of transactions per body |\n|---|---|---|\n",
    );
    for suite in SUITES {
        let (Ok(pk), Ok(sig)) = (
            CompositePublicKey::encoded_len(suite.id),
            CompositeSignature::encoded_len(suite.id),
        ) else {
            continue;
        };
        let total = pk + sig;
        let _ = writeln!(
            out,
            "| {} (0x{:04x}) | {} | {} |",
            suite_name(suite.id),
            suite.id.0,
            total,
            BODY_BUDGET / total
        );
    }
    out.push('\n');
}

fn qc_table(out: &mut String) {
    out.push_str("### QC blob size bound (read from `qc_blob_max_bytes`)\n\n");
    let _ = writeln!(
        out,
        "Each entry is bounded at the longest registered signature (ML-DSA-87). The chunk size is {QC_CHUNK_BYTES} bytes.\n"
    );
    out.push_str("| Validators | Blob bytes (bound) | Chunks |\n|---|---|---|\n");
    for n in VALIDATOR_COUNTS {
        let bytes = qc_blob_max_bytes(n);
        let _ = writeln!(
            out,
            "| {n} | {bytes} | {} |",
            bytes.div_ceil(QC_CHUNK_BYTES)
        );
    }
    out.push('\n');
}

fn daily_table(out: &mut String) {
    out.push_str("### Daily seal traffic\n\n");
    let blocks_per_day = 86_400_000 / MIN_BLOCK_INTERVAL_MS;
    let anchors = blocks_per_day / ANCHOR_INTERVAL;
    let seals = blocks_per_day / ROOT_SEAL_INTERVAL;
    let ml87 = SCHEMES
        .iter()
        .find(|s| s.id == SchemeId::ML_DSA_87)
        .and_then(|s| s.signature_len)
        .unwrap_or(0);
    let slh = SCHEMES
        .iter()
        .find(|s| s.id == SchemeId::SLH_DSA_SHAKE_256S)
        .and_then(|s| s.signature_len)
        .unwrap_or(0);
    let anchor_sig_bytes = ANCHOR_SIGNATURES * ml87;
    let _ = writeln!(
        out,
        "At the shortest accepted block interval ({MIN_BLOCK_INTERVAL_MS} ms) a day has {blocks_per_day} blocks, so the figures are the most a day can carry. The anchor interval is {ANCHOR_INTERVAL} blocks and the Root Seal interval {ROOT_SEAL_INTERVAL} blocks.\n"
    );
    out.push_str(
        "| Item | Per day | Signature bytes each | Signature bytes per day |\n|---|---|---|---|\n",
    );
    let _ = writeln!(
        out,
        "| Anchor (2 x ML-DSA-87) | {anchors} | {anchor_sig_bytes} | {} |",
        anchors * anchor_sig_bytes as u64
    );
    let _ = writeln!(
        out,
        "| Root Seal (SLH-DSA-SHAKE-256s) | {seals} | {slh} | {} |",
        seals * slh as u64
    );
    out.push_str("| Handoff Certificate | n/a | n/a | n/a |\n\n");
    out.push_str("Signature bytes only: the digests, indices and headers of each record are not counted.\n\n");
}

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn time_us(iterations: usize, mut op: impl FnMut()) -> f64 {
    op();
    let samples = (0..iterations)
        .map(|_| {
            let start = Instant::now();
            op();
            start.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    median(samples)
}

fn timing_row(out: &mut String, name: &str, iterations: usize, op: impl FnMut()) {
    let us = time_us(iterations, op);
    let _ = writeln!(out, "| {name} | {iterations} | {us:.1} |");
}

fn timings_table(out: &mut String) -> Result<(), String> {
    out.push_str("### Timings (median, this machine)\n\n");
    out.push_str("| Operation | Runs | Median microseconds |\n|---|---|---|\n");
    let message = b"pq-measure message of a few dozen bytes!";
    let seed = [7u8; 32];
    let rnd = [0u8; 32];
    for scheme in [SchemeId::ML_DSA_65, SchemeId::ML_DSA_87] {
        let name = scheme.info().map_or("ml-dsa", |i| i.short);
        let pk = pq::ml_dsa_public_key(scheme, &seed).map_err(|e| e.to_string())?;
        let sig =
            pq::ml_dsa_sign(scheme, &seed, message, ctx::TX_V5, &rnd).map_err(|e| e.to_string())?;
        timing_row(out, &format!("{name} sign"), 50, || {
            let _ = pq::ml_dsa_sign(scheme, &seed, message, ctx::TX_V5, &rnd);
        });
        timing_row(out, &format!("{name} dual-library verify"), 200, || {
            let _ = pq::verify(scheme, &pk, message, ctx::TX_V5, &sig);
        });
    }
    let slh = SchemeId::SLH_DSA_SHAKE_256S;
    let slh_seed = vec![9u8; pq::slh_dsa_seed_len(slh).map_err(|e| e.to_string())?];
    let slh_pk = pq::slh_dsa_public_key(slh, &slh_seed).map_err(|e| e.to_string())?;
    let slh_sig =
        pq::slh_dsa_sign(slh, &slh_seed, message, ctx::SEAL_V1, None).map_err(|e| e.to_string())?;
    timing_row(out, "slh-dsa-shake-256s sign", 3, || {
        let _ = pq::slh_dsa_sign(slh, &slh_seed, message, ctx::SEAL_V1, None);
    });
    timing_row(out, "slh-dsa-shake-256s verify", 100, || {
        let _ = pq::verify(slh, &slh_pk, message, ctx::SEAL_V1, &slh_sig);
    });
    let ed = SigningKey::from_bytes(&[5u8; 32]);
    let ed_sig = ed.sign(message);
    let ed_vk = ed.verifying_key();
    timing_row(out, "ed25519 verify_strict", 2000, || {
        let _ = ed_vk.verify_strict(message, &ed_sig);
    });
    for suite in [SuiteId::USER, SuiteId::VALIDATOR] {
        let info = suite.info().ok_or("suite is not listed")?;
        let pq_seed = vec![3u8; pq_seed_len(info.pq)?];
        let kp =
            CompositeKeypair::from_seeds(suite, &pq_seed, &[4u8; 32]).map_err(|e| e.to_string())?;
        let pk = kp.public_key().map_err(|e| e.to_string())?;
        let sig = kp
            .sign(ctx::TX_V7, message, &rnd)
            .map_err(|e| e.to_string())?;
        timing_row(
            out,
            &format!("composite {} sign", suite_name(suite)),
            50,
            || {
                let _ = kp.sign(ctx::TX_V7, message, &rnd);
            },
        );
        timing_row(
            out,
            &format!("composite {} verify", suite_name(suite)),
            200,
            || {
                let _ = composite::verify(&pk, ctx::TX_V7, message, &sig);
            },
        );
    }
    out.push('\n');
    Ok(())
}

fn pq_seed_len(scheme: SchemeId) -> Result<usize, String> {
    if scheme == SchemeId::ML_DSA_65 || scheme == SchemeId::ML_DSA_87 {
        Ok(pq::ML_DSA_SEED_LEN)
    } else {
        pq::slh_dsa_seed_len(scheme).map_err(|e| e.to_string())
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let mut out = String::new();
    match mode.as_str() {
        "tables" => {
            sizes_table(&mut out);
            signature_capacity_table(&mut out);
            qc_table(&mut out);
            daily_table(&mut out);
        }
        "timings" => {
            if let Err(e) = timings_table(&mut out) {
                eprintln!("pq_measure: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: pq_measure tables | timings");
            std::process::exit(2);
        }
    }
    print!("{out}");
}
