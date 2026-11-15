// Benchmark harness, not node code: this binary measures throughput and is
// never part of a running validator. A failed setup step should stop the
// measurement loudly rather than be threaded through `Result`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use budlum_core::chain::blockchain::Blockchain;
use budlum_core::chain::chain_actor::ChainActor;
use budlum_core::consensus::pos::{PoSConfig, PoSEngine};
use budlum_core::core::address::Address;
use budlum_core::core::transaction::Transaction;
use budlum_core::crypto::primitives::{KeyPair, ValidatorKeys};
use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Block production refusal reasons are `tracing` warnings in the node;
    // without a subscriber the harness would report a silent empty run
    // instead of the reason production stopped.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .try_init();
    println!("\nBUDLUM SINGLE-NODE INTERNAL PIPELINE BENCHMARK");
    println!("--------------------------------------------------");

    // Config
    let tx_count = 10_000;
    let sender_count = 10_000;
    let concurrency = 64;

    // 1. Setup
    // The devnet chain id: the faucet, genesis and network parameters this
    // harness relies on are defined for known networks, and every passing
    // PoS produce test in the suite runs on this chain. The previous 1337
    // is not a network the codebase knows, so its parameter lookups fell
    // back to defaults that match no genesis.
    let chain_id = budlum_core::core::transaction::DEFAULT_CHAIN_ID;
    // The chain layer derives epoch boundaries from the chain id, the engine
    // from this config; they must agree or every block after the first epoch
    // boundary fails validation (C-12).
    let pos_config = PoSConfig {
        epoch_length: budlum_core::core::chain_config::epoch_len_for_chain_id(chain_id),
        ..Default::default()
    };
    let validator_keys = ValidatorKeys::generate().unwrap();
    let consensus = Arc::new(PoSEngine::new(pos_config, Some(validator_keys.clone())));

    let mut blockchain = Blockchain::new(consensus, None, chain_id, None);
    // PoS fails closed with an empty validator set: keys living only inside
    // the engine produce nothing. Register the benchmark validator the way
    // the passing produce tests do - genesis-seeded entries cleared, then
    // one funded, staked, fully keyed (VRF + BLS + PoP + PQ) and active
    // validator - or `produce_block` returns `None` for the whole run and
    // the harness measures an empty chain.
    let producer_addr = Address::from(validator_keys.sig_key.public_key_bytes());
    blockchain
        .fund_development_account(&producer_addr)
        .expect("benchmark runs on a devnet chain");
    blockchain.state.validators.clear();
    {
        let bls = validator_keys
            .bls_key
            .as_ref()
            .expect("validator keys carry BLS");
        let mut validator = budlum_core::core::account::Validator::new(producer_addr, 2_000);
        validator.vrf_public_key = validator_keys.vrf_key.public.to_bytes().to_vec();
        validator.bls_public_key = bls.public_key.clone();
        validator.pop_signature = bls.generate_pop(chain_id, &producer_addr);
        validator.pq_public_key = validator_keys
            .pq_key
            .as_ref()
            .expect("validator keys carry PQ")
            .public_key_bytes()
            .to_vec();
        validator.active = true;
        blockchain.state.validators.insert(producer_addr, validator);
    }
    let (chain_actor, chain) = ChainActor::new(blockchain);

    tokio::spawn(async move {
        chain_actor.run().await;
    });

    // 2. Pre-generate Transactions & Fund Accounts
    println!("Generating {sender_count} unique senders and funding them...");
    let mut keypairs = Vec::new();
    for _ in 0..sender_count {
        let kp = KeyPair::generate().unwrap();
        chain
            .credit_development_account(&Address::from(kp.public_key_bytes()), 1_000_000)
            .await
            .expect("benchmark runs on a devnet chain");
        keypairs.push(kp);
    }

    println!("Generating {tx_count} transactions...");
    let start_gen = Instant::now();

    let txs: Vec<Transaction> = (0..tx_count)
        .map(|i| {
            let sender_idx = i % sender_count;
            let mut tx = Transaction::new_with_fee(
                Address::from(keypairs[sender_idx].public_key_bytes()),
                Address::from(keypairs[(sender_idx + 1) % sender_count].public_key_bytes()),
                1,
                1,
                (i / sender_count) as u64,
                vec![],
            );
            tx.chain_id = chain_id;
            tx.sign(&keypairs[sender_idx]);
            tx
        })
        .collect();
    let gen_duration = start_gen.elapsed();
    println!("Generation time: {gen_duration:?}");

    // 3. Measure INGEST TPS (Mempool Internal Throughput)
    println!("Starting Ingestion (Internal Channel)...");
    let start_ingest = Instant::now();
    type IngestFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
    let mut futures: FuturesUnordered<IngestFuture> = FuturesUnordered::new();
    let mut tx_iter = txs.into_iter();

    for _ in 0..concurrency {
        if let Some(tx) = tx_iter.next() {
            let c = chain.clone();
            futures.push(Box::pin(async move { c.add_transaction(tx).await }));
        }
    }

    let mut ingested = 0;
    let mut ingest_failed = 0;
    let mut first_refusal = String::new();
    while let Some(res) = futures.next().await {
        match res {
            Ok(_) => ingested += 1,
            Err(e) => {
                ingest_failed += 1;
                if first_refusal.is_empty() {
                    first_refusal = e;
                }
            }
        }

        if let Some(tx) = tx_iter.next() {
            let c = chain.clone();
            futures.push(Box::pin(async move { c.add_transaction(tx).await }));
        }
    }
    let ingest_duration = start_ingest.elapsed();
    assert!(
        ingested > 0,
        "no transaction was ingested ({ingest_failed} refused, first reason: {first_refusal}); the numbers would mean nothing"
    );
    let ingest_tps = ingested as f64 / ingest_duration.as_secs_f64();

    // 4. Measure EXECUTION/COMMIT TPS
    println!("Starting Block Production (Execution + State Root)...");
    let start_exec = Instant::now();
    let mut processed = 0;
    let mut blocks = 0;
    let producer = Address::from(validator_keys.sig_key.public_key_bytes());

    while processed < ingested {
        if let Some((block, _)) = chain.produce_block(producer).await {
            processed += block.transactions.len();
            blocks += 1;
            if blocks % 2 == 0 {
                print!(".");
                use std::io::Write;
                std::io::stdout().flush().unwrap();
            }
        } else {
            break;
        }
    }
    println!("\nExecution completed.");
    let exec_duration = start_exec.elapsed();
    if processed < ingested {
        eprintln!("WARNING: only {processed} of {ingested} ingested transactions were produced");
    }
    let exec_tps = processed as f64 / exec_duration.as_secs_f64();

    // 5. Results
    println!("\n--------------------------------------------------");
    println!("BENCHMARK RESULTS (Internal Pipeline):");
    println!("Total Transactions: {processed} (Failed Ingest: {ingest_failed})");
    println!("Total Blocks:       {blocks}");
    println!("--------------------------------------------------");
    println!("TX Generation:      {gen_duration:?}");
    println!("INGEST TPS (Int):   {ingest_tps:.2} tx/s");
    println!("EXECUTION TPS:      {exec_tps:.2} tx/s");
    if blocks > 0 {
        // The CI vacuity gate keys on an `Avg per` metric line:
        // it is printed only when blocks were actually produced, so an
        // empty run still has no metric to hide behind.
        println!("Avg per Block:     {:?}", exec_duration / blocks as u32);
    } else {
        println!("Avg Block Build:   N/A");
    }
    println!("Note: This bypasses Network, RPC and Serialization.");
    println!("--------------------------------------------------\n");
}
