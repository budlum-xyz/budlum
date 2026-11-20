//! `benches/agg_baseline.rs` - the Phase 0 baseline of the aggregation layer.
//!
//! The aggregation layer replaces the post-quantum witness of a transaction
//! (public key and signature) with a short claim. Before any of it exists this
//! harness records what the witness costs today, so later phases are compared
//! against a measured number and not against an estimate:
//!
//! 1. Per scheme: the canonical name, the public key bytes, the signature
//!    bytes and the time one verification takes. The schemes are the ones a
//!    transaction witness can carry: ML-DSA-87 (user suite, V5 and V7),
//!    ML-DSA-65 (validator suite) and SLH-DSA-SHAKE-256s (recovery).
//! 2. Per block of 100 and of 1000 transfers, for the V5 and the V7 form: the
//!    protobuf size of the block with and without witnesses, the share of the
//!    witness section, and the time to verify every transaction.
//!
//! Sizes are measured on the wire encoding the block budgets use
//! (`ProtoBlock::encoded_len`), not derived from the scheme table. The harness
//! checks itself: a verification that fails, a length that differs from the
//! scheme table or a block whose witnesses do not strip ends the run with
//! exit code 2, so a broken measurement never prints a number.
//!
//! Running:
//! cargo bench --bench `agg_baseline`
//!
//! The timings belong to the host that ran the step; nothing in the tree pins
//! them. Lines starting with `agg_baseline:` are the machine-readable record.

use std::process::exit;
use std::time::{Duration, Instant};

use budlum_core::consensus::budget::{BODY_BUDGET_BYTES, WITNESS_BUDGET_BYTES};
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use budlum_core::crypto::ctx;
use budlum_core::crypto::key_derivation::{RootSecret, UserAccount};
use budlum_core::crypto::pq;
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use budlum_core::network::proto_conversions::pb::ProtoBlock;
use prost::Message;

/// Distinct signers a block is built from. Sizes do not depend on the count;
/// more signers only make key generation slower.
const SIGNERS: u32 = 8;
/// Block sizes the directive asks for.
const BLOCK_SIZES: [usize; 2] = [100, 1000];
/// Messages signed per lattice scheme, each verified `VERIFY_ROUNDS` times.
const LATTICE_SAMPLES: usize = 16;
/// Messages signed for the hash-based scheme: one signature costs seconds
/// there, and the verification time is what is measured.
const HASH_SAMPLES: usize = 2;
/// Verifications per sample.
const VERIFY_ROUNDS: usize = 8;

fn fail(reason: &str) -> ! {
    eprintln!("agg_baseline: {reason}");
    exit(2);
}

#[must_use]
fn usize_to_f64(n: usize) -> f64 {
    let wide = u64::try_from(n).unwrap_or(u64::MAX);
    let high = u32::try_from(wide >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(wide & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

#[must_use]
fn micros(spent: Duration) -> f64 {
    spent.as_secs_f64() * 1e6
}

#[must_use]
fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    usize_to_f64(part) / usize_to_f64(whole) * 100.0
}

/// Minimum and median of a set of samples. Interruptions only add time, so
/// the minimum is the cleanest single figure; the median shows the spread.
fn min_and_median(mut samples: Vec<Duration>) -> (Duration, Duration) {
    if samples.is_empty() {
        fail("no timing sample was taken");
    }
    samples.sort_unstable();
    let min = samples[0];
    let median = samples[samples.len() / 2];
    (min, median)
}

struct SchemeRow {
    name: &'static str,
    public_key_bytes: usize,
    signature_bytes: usize,
    verify_min: Duration,
    verify_median: Duration,
}

fn canonical_name(scheme: SchemeId) -> &'static str {
    match scheme.info() {
        Some(info) => info.canonical,
        None => fail("a measured scheme is missing from the scheme table"),
    }
}

/// Measure one scheme from `(public key, [(message, signature)])`. `context`
/// is a registered signing context: the verifier refuses a free-form one.
fn measure_scheme(
    scheme: SchemeId,
    context: &[u8],
    public_key: &[u8],
    signed: &[(Vec<u8>, Vec<u8>)],
) -> SchemeRow {
    let expected_key = pq::public_key_len(scheme)
        .unwrap_or_else(|_| fail("the scheme table has no public key length"));
    let expected_sig = pq::signature_len(scheme)
        .unwrap_or_else(|_| fail("the scheme table has no signature length"));
    if public_key.len() != expected_key {
        fail("a generated public key length differs from the scheme table");
    }
    let mut samples = Vec::with_capacity(signed.len() * VERIFY_ROUNDS);
    for (message, signature) in signed {
        if signature.len() != expected_sig {
            fail("a produced signature length differs from the scheme table");
        }
        for _ in 0..VERIFY_ROUNDS {
            let start = Instant::now();
            let verdict = pq::verify(scheme, public_key, message, context, signature);
            let spent = start.elapsed();
            if verdict.is_err() {
                fail("a signature produced by this harness did not verify");
            }
            samples.push(spent);
        }
        let mut wrong = message.clone();
        wrong.push(0x01);
        if pq::verify(scheme, public_key, &wrong, context, signature).is_ok() {
            fail("a signature verified over a message it does not cover");
        }
    }
    let (verify_min, verify_median) = min_and_median(samples);
    SchemeRow {
        name: canonical_name(scheme),
        public_key_bytes: public_key.len(),
        signature_bytes: expected_sig,
        verify_min,
        verify_median,
    }
}

fn message(index: usize) -> Vec<u8> {
    format!("budlum aggregation baseline message {index}").into_bytes()
}

fn lattice_row(scheme: SchemeId) -> SchemeRow {
    let seed = [0x5A_u8; pq::ML_DSA_SEED_LEN];
    let public_key = pq::ml_dsa_public_key(scheme, &seed)
        .unwrap_or_else(|_| fail("ML-DSA key generation failed"));
    let signed: Vec<(Vec<u8>, Vec<u8>)> = (0..LATTICE_SAMPLES)
        .map(|i| {
            let msg = message(i);
            let sig = pq::ml_dsa_sign(scheme, &seed, &msg, ctx::TX_V7, &[0x11_u8; 32])
                .unwrap_or_else(|_| fail("ML-DSA signing failed"));
            (msg, sig)
        })
        .collect();
    measure_scheme(scheme, ctx::TX_V7, &public_key, &signed)
}

fn hash_row(scheme: SchemeId) -> SchemeRow {
    let seed_len =
        pq::slh_dsa_seed_len(scheme).unwrap_or_else(|_| fail("SLH-DSA has no seed length"));
    let seed = vec![0xA5_u8; seed_len];
    let public_key = pq::slh_dsa_public_key(scheme, &seed)
        .unwrap_or_else(|_| fail("SLH-DSA key generation failed"));
    let signed: Vec<(Vec<u8>, Vec<u8>)> = (0..HASH_SAMPLES)
        .map(|i| {
            let msg = message(i);
            let sig = pq::slh_dsa_sign(scheme, &seed, &msg, ctx::RECOVERY_V1, None)
                .unwrap_or_else(|_| fail("SLH-DSA signing failed"));
            (msg, sig)
        })
        .collect();
    measure_scheme(scheme, ctx::RECOVERY_V1, &public_key, &signed)
}

#[derive(Clone, Copy)]
enum TxForm {
    /// ML-DSA-87 alone; `from` is the hash of the key.
    V5,
    /// Composite ML-DSA-87 and Ed25519 with a recovery key digest.
    V7,
}

impl TxForm {
    const fn label(self) -> &'static str {
        match self {
            Self::V5 => "v5 ml-dsa-87",
            Self::V7 => "v7 ml-dsa-87+ed25519",
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::V5 => "v5",
            Self::V7 => "v7",
        }
    }
}

struct Signers {
    wallets: Vec<WalletKeyPair>,
    accounts: Vec<UserAccount>,
    registry: SchemeStatusRegistry,
}

impl Signers {
    fn new() -> Self {
        let root = RootSecret::derive(&[0x42_u8; 32], "")
            .unwrap_or_else(|_| fail("the root secret could not be derived"));
        let mut wallets = Vec::new();
        let mut accounts = Vec::new();
        for index in 0..SIGNERS {
            let low = u8::try_from(index).unwrap_or(u8::MAX);
            wallets.push(WalletKeyPair::from_seed(&[low.wrapping_add(1); 32]));
            accounts.push(
                root.user_account(0, index)
                    .unwrap_or_else(|_| fail("a user account could not be derived")),
            );
        }
        Self {
            wallets,
            accounts,
            registry: SchemeStatusRegistry::genesis(),
        }
    }

    fn transfer(&self, form: TxForm, position: usize) -> Transaction {
        let slot = position % self.wallets.len();
        let nonce = u64::try_from(position / self.wallets.len()).unwrap_or(u64::MAX);
        let to = Address::from([0x09_u8; 32]);
        match form {
            TxForm::V5 => {
                let wallet = &self.wallets[slot];
                let mut tx = Transaction::new_with_chain_id(
                    wallet.address(),
                    to,
                    5,
                    1,
                    nonce,
                    Vec::new(),
                    DEFAULT_CHAIN_ID,
                    TransactionType::Transfer,
                );
                tx.sign_v5(wallet);
                tx
            }
            TxForm::V7 => {
                let account = &self.accounts[slot];
                let mut tx = Transaction::new_with_chain_id(
                    Address::from(account.address),
                    to,
                    5,
                    1,
                    nonce,
                    Vec::new(),
                    DEFAULT_CHAIN_ID,
                    TransactionType::Transfer,
                );
                if tx
                    .sign_v7(
                        &self.registry,
                        &account.signing,
                        &account.recovery_public_key,
                        &[0x33_u8; 32],
                    )
                    .is_err()
                {
                    fail("a V7 transfer could not be signed");
                }
                tx
            }
        }
    }
}

struct BlockRow {
    form: TxForm,
    transactions: usize,
    block_bytes: usize,
    body_bytes: usize,
    witness_bytes: usize,
    verify_all: Duration,
}

fn measure_block(signers: &Signers, form: TxForm, count: usize) -> BlockRow {
    let transactions: Vec<Transaction> = (0..count).map(|i| signers.transfer(form, i)).collect();

    let start = Instant::now();
    let all_valid = transactions
        .iter()
        .all(|tx| tx.verify_in(&signers.registry));
    let verify_all = start.elapsed();
    if !all_valid {
        fail("a transfer signed by this harness did not verify");
    }

    let block = Block::new_with_chain_id(1, "0".repeat(64), transactions, DEFAULT_CHAIN_ID);
    let stripped = block.without_witnesses();
    if !stripped.witness_is_stripped() {
        fail("the witnesses of the block did not strip");
    }
    let block_bytes = ProtoBlock::from(&block).encoded_len();
    let body_bytes = ProtoBlock::from(&stripped).encoded_len();
    if body_bytes >= block_bytes {
        fail("the block without witnesses is not smaller than the block");
    }
    BlockRow {
        form,
        transactions: count,
        block_bytes,
        body_bytes,
        witness_bytes: block_bytes - body_bytes,
        verify_all,
    }
}

fn print_schemes(rows: &[SchemeRow]) {
    println!("\nAGGREGATION BASELINE: post-quantum signature schemes");
    println!(
        "{:<32} {:>10} {:>10} {:>14} {:>14}",
        "scheme", "pk bytes", "sig bytes", "verify min us", "verify med us"
    );
    for row in rows {
        println!(
            "{:<32} {:>10} {:>10} {:>14.1} {:>14.1}",
            row.name,
            row.public_key_bytes,
            row.signature_bytes,
            micros(row.verify_min),
            micros(row.verify_median)
        );
        println!(
            "agg_baseline: scheme={} public_key_bytes={} signature_bytes={} verify_min_us={:.1} verify_median_us={:.1}",
            row.name,
            row.public_key_bytes,
            row.signature_bytes,
            micros(row.verify_min),
            micros(row.verify_median)
        );
    }
}

fn print_blocks(rows: &[BlockRow]) {
    println!("\nAGGREGATION BASELINE: witness share of a block of transfers");
    println!(
        "{:<22} {:>6} {:>12} {:>11} {:>14} {:>8} {:>10} {:>11}",
        "form",
        "txs",
        "block bytes",
        "body bytes",
        "witness bytes",
        "share %",
        "verify ms",
        "fits budget"
    );
    for row in rows {
        let share = percent(row.witness_bytes, row.block_bytes);
        let verify_ms = row.verify_all.as_secs_f64() * 1e3;
        let fits = row.body_bytes <= BODY_BUDGET_BYTES && row.witness_bytes <= WITNESS_BUDGET_BYTES;
        println!(
            "{:<22} {:>6} {:>12} {:>11} {:>14} {:>8.2} {:>10.1} {:>11}",
            row.form.label(),
            row.transactions,
            row.block_bytes,
            row.body_bytes,
            row.witness_bytes,
            share,
            verify_ms,
            if fits { "yes" } else { "no" }
        );
        println!(
            "agg_baseline: form={} txs={} block_bytes={} body_bytes={} witness_bytes={} witness_share_percent={:.2} verify_all_ms={:.1} fits_budget={}",
            row.form.key(),
            row.transactions,
            row.block_bytes,
            row.body_bytes,
            row.witness_bytes,
            share,
            verify_ms,
            fits
        );
    }
    println!(
        "budgets: body {BODY_BUDGET_BYTES} bytes, witness {WITNESS_BUDGET_BYTES} bytes (consensus::budget)"
    );
}

fn main() {
    let schemes = [
        lattice_row(SchemeId::ML_DSA_87),
        lattice_row(SchemeId::ML_DSA_65),
        hash_row(SchemeId::SLH_DSA_SHAKE_256S),
    ];
    print_schemes(&schemes);

    let signers = Signers::new();
    let mut blocks = Vec::new();
    for form in [TxForm::V5, TxForm::V7] {
        for count in BLOCK_SIZES {
            blocks.push(measure_block(&signers, form, count));
        }
    }
    print_blocks(&blocks);
    println!("agg_baseline: done");
}
