//! Domain Throughput & Latency Benchmarks (criterion.rs)
//!
//! Her domain için somut throughput/latency ölçümleri:
//! - Transaction execution (per-type TPS)
//! - State root calculation (flat hash vs Merkle trie)
//! - Block production & validation
//! - Signature verification (Ed25519, BLS)
//! - Serialization (Block, Transaction, Snapshot)
//! - Registry operations (register, slash, query)
//! - Bridge state transitions (lock, mint, burn, unlock)
//! - Proof verification (envelope validation)
//! - Governance proposal lifecycle
//!
//! Çalıştırma:
//!   cargo bench --bench domain_throughput
//!   cargo bench --bench domain_throughput -- "tx_execute"  (tek grup)
//!   cargo bench --bench domain_throughput -- --save-baseline main  (baseline)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::chain_config::FIXED_POINT_SCALE;
use budlum_core::core::hash::hash_fields_bytes;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::cross_domain::bridge::{AssetId, BridgeState};
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::execution::executor::Executor;
use budlum_core::execution::proof_verifier::{ExecutionPublicInputs, ProofEnvelope, ProofVerifier};
use budlum_core::network::gossip_dedup::GossipDedup;
use budlum_core::registry::permissionless::{
    PermissionlessRegistry, SlashingCondition, MIN_REGISTRATION_STAKE,
};
use budlum_core::registry::role::roles;
use budlum_core::storage::merkle_trie::MerkleTrie;

// ─── Helpers ────────────────────────────────────────────────────────

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn setup_funded_state(n: usize) -> (AccountState, Vec<KeyPair>) {
    let mut state = AccountState::new();
    let mut keypairs = Vec::new();
    for i in 0..n {
        let kp = KeyPair::generate().unwrap();
        let a = Address::from(kp.public_key_bytes());
        state.add_balance(&a, 10_000_000);
        state.add_validator(a, 1_000_000);
        keypairs.push(kp);
    }
    (state, keypairs)
}

// ─── 1. Transaction Execution ───────────────────────────────────────

fn bench_tx_execution(c: &mut Criterion) {
    let mut group = c.benchmark_group("tx_execute");
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(10));

    // Transfer
    let (state, kps) = setup_funded_state(2);
    let sender = &kps[0];
    let recipient = addr(0xFF);
    let mut tx = Transaction::new(
        Address::from(sender.public_key_bytes()),
        recipient,
        100,
        vec![],
    );
    tx.fee = 1;
    tx.nonce = 0;
    tx.sign(sender);

    group.bench_function("transfer", |b| {
        b.iter(|| {
            let mut s = state.clone();
            let _ = Executor::apply_transaction(&mut s, black_box(&tx));
        })
    });

    // Stake
    let (state2, kps2) = setup_funded_state(1);
    let mut stake_tx = Transaction::new(
        Address::from(kps2[0].public_key_bytes()),
        Address::from(kps2[0].public_key_bytes()),
        500_000,
        vec![],
    );
    stake_tx.fee = 1;
    stake_tx.nonce = 0;
    stake_tx.tx_type = TransactionType::Stake;
    stake_tx.sign(&kps2[0]);

    group.bench_function("stake", |b| {
        b.iter(|| {
            let mut s = state2.clone();
            s.validators.clear();
            let _ = Executor::apply_transaction(&mut s, black_box(&stake_tx));
        })
    });

    // Vote (governance)
    let (state3, kps3) = setup_funded_state(1);
    let mut vote_data = vec![1u8]; // vote_for = true
    vote_data.extend_from_slice(&0u64.to_le_bytes()); // proposal_id = 0
    let mut vote_tx = Transaction::new(
        Address::from(kps3[0].public_key_bytes()),
        Address::zero(),
        0,
        vote_data,
    );
    vote_tx.fee = 1;
    vote_tx.nonce = 0;
    vote_tx.sign(&kps3[0]);

    group.bench_function("vote", |b| {
        b.iter(|| {
            let mut s = state3.clone();
            let _ = Executor::apply_transaction(&mut s, black_box(&vote_tx));
        })
    });

    group.finish();
}

// ─── 2. State Root — Flat Hash vs Merkle Trie ───────────────────────

fn bench_state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");

    for n in [100, 500, 1000, 5000] {
        // Flat hash (current)
        let (mut state, _) = setup_funded_state(n);
        group.bench_with_input(BenchmarkId::new("flat_hash", n), &n, |b, _| {
            b.iter(|| {
                black_box(state.calculate_state_root());
            })
        });

        // Merkle trie
        group.bench_with_input(BenchmarkId::new("merkle_trie", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut trie = MerkleTrie::new();
                    for i in 0..n as u8 {
                        let a = addr(i);
                        trie.insert(a.as_bytes(), (i as u64) * 1000, i as u64);
                    }
                    trie
                },
                |mut trie| {
                    black_box(trie.root());
                },
            )
        });

        // Merkle trie — single update
        group.bench_with_input(BenchmarkId::new("merkle_trie_update", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut trie = MerkleTrie::new();
                    for i in 0..n as u8 {
                        let a = addr(i);
                        trie.insert(a.as_bytes(), (i as u64) * 1000, i as u64);
                    }
                    trie
                },
                |mut trie| {
                    trie.insert(&addr(0xFF), 9999, 42);
                    black_box(trie.root());
                },
            )
        });

        // Merkle proof generation
        group.bench_with_input(BenchmarkId::new("merkle_proof_generate", n), &n, |b, &n| {
            b.iter_with_setup(
                || {
                    let mut trie = MerkleTrie::new();
                    for i in 0..n as u8 {
                        let a = addr(i);
                        trie.insert(a.as_bytes(), (i as u64) * 1000, i as u64);
                    }
                    trie
                },
                |trie| {
                    black_box(trie.proof(&addr(42)));
                },
            )
        });
    }

    group.finish();
}

// ─── 3. Block Production & Validation ───────────────────────────────

fn bench_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("block");
    group.sample_size(100);

    // Block creation
    group.bench_function("new_empty", |b| {
        b.iter(|| {
            black_box(Block::new(1, "0".repeat(64), vec![]));
        })
    });

    // Block hash calculation
    let block = Block::new(1, "0".repeat(64), vec![]);
    group.bench_function("calculate_hash", |b| {
        b.iter(|| {
            let mut b2 = block.clone();
            b2.hash = black_box(b2.calculate_hash());
        })
    });

    // Block with N transactions — hash
    for n in [10, 50, 100] {
        let kps: Vec<_> = (0..n).map(|_| KeyPair::generate().unwrap()).collect();
        let txs: Vec<Transaction> = kps
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                let mut tx = Transaction::new(
                    Address::from(kp.public_key_bytes()),
                    addr(i as u8),
                    100,
                    vec![],
                );
                tx.fee = 1;
                tx.nonce = i as u64;
                tx.sign(kp);
                tx
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("calculate_hash_with_txs", n),
            &txs,
            |b, txs| {
                b.iter(|| {
                    let mut block = Block::new(1, "0".repeat(64), txs.clone());
                    block.hash = black_box(block.calculate_hash());
                })
            },
        );
    }

    // Block signature
    let kp = KeyPair::generate().unwrap();
    group.bench_function("sign", |b| {
        b.iter(|| {
            let mut block = Block::new(1, "0".repeat(64), vec![]);
            block.sign(black_box(&kp));
        })
    });

    // Block signature verification
    let mut signed_block = Block::new(1, "0".repeat(64), vec![]);
    signed_block.sign(&kp);
    signed_block.hash = signed_block.calculate_hash();

    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            black_box(signed_block.verify_signature());
        })
    });

    group.finish();
}

// ─── 4. Signature Verification ──────────────────────────────────────

fn bench_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature");
    group.sample_size(500);

    // Ed25519 sign
    let kp = KeyPair::generate().unwrap();
    let msg = b"benchmark message for ed25519 signing";

    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(kp.sign(black_box(msg)));
        })
    });

    // Ed25519 verify
    let sig = kp.sign(msg);
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            black_box(KeyPair::verify(
                black_box(msg),
                black_box(&sig),
                black_box(&kp.public_key_bytes()),
            ));
        })
    });

    // KeyPair generation
    group.bench_function("keypair_generate", |b| {
        b.iter(|| {
            black_box(KeyPair::generate().unwrap());
        })
    });

    group.finish();
}

// ─── 5. Serialization ───────────────────────────────────────────────

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    // Transaction serialization
    let kp = KeyPair::generate().unwrap();
    let mut tx = Transaction::new(
        Address::from(kp.public_key_bytes()),
        addr(0xFF),
        100,
        vec![1, 2, 3],
    );
    tx.fee = 1;
    tx.sign(&kp);

    group.bench_function("tx_to_bytes", |b| {
        b.iter(|| {
            black_box(black_box(&tx).to_bytes());
        })
    });

    let tx_bytes = tx.to_bytes();
    group.bench_function("tx_from_bytes", |b| {
        b.iter(|| {
            black_box(Transaction::from_bytes(black_box(&tx_bytes)));
        })
    });

    // Block serialization
    let block = Block::new(42, "aabbccdd".repeat(8), vec![tx.clone()]);
    group.bench_function("block_to_json", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(black_box(&block)));
        })
    });

    let block_json = serde_json::to_string(&block).unwrap();
    group.bench_function("block_from_json", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<Block>(black_box(&block_json)));
        })
    });

    // Transaction hash calculation
    group.bench_function("tx_calculate_hash", |b| {
        b.iter(|| {
            let mut t = tx.clone();
            black_box(t.calculate_hash());
        })
    });

    group.finish();
}

// ─── 6. Registry Operations ─────────────────────────────────────────

fn bench_registry(c: &mut Criterion) {
    let mut group = c.benchmark_group("registry");

    // Register
    group.bench_function("register_validator", |b| {
        b.iter_with_setup(
            || PermissionlessRegistry::new(),
            |mut reg| {
                for i in 0..100u8 {
                    let _ = reg.register_validator(addr(i), MIN_REGISTRATION_STAKE, 0);
                }
                black_box(reg.len());
            },
        )
    });

    // is_active query
    group.bench_function("is_active_query", |b| {
        b.iter_with_setup(
            || {
                let mut reg = PermissionlessRegistry::new();
                for i in 0..100u8 {
                    reg.register_validator(addr(i), MIN_REGISTRATION_STAKE, 0)
                        .unwrap();
                }
                reg
            },
            |reg| {
                for i in 0..100u8 {
                    black_box(reg.is_active(&addr(i), roles::VALIDATOR));
                }
            },
        )
    });

    // Slash
    group.bench_function("slash_double_sign", |b| {
        b.iter_with_setup(
            || {
                let mut reg = PermissionlessRegistry::new();
                for i in 0..100u8 {
                    reg.register_validator(addr(i), 10_000, 0).unwrap();
                }
                reg
            },
            |mut reg| {
                black_box(reg.slash(
                    addr(50),
                    roles::VALIDATOR,
                    SlashingCondition::DoubleSign,
                    FIXED_POINT_SCALE / 2,
                ));
            },
        )
    });

    // Cross-role slash (slash one → jail all roles)
    group.bench_function("cross_role_slash", |b| {
        b.iter_with_setup(
            || {
                let mut reg = PermissionlessRegistry::new();
                for i in 0..50u8 {
                    reg.register_validator(addr(i), 10_000, 0).unwrap();
                    reg.register_relayer(addr(i), 5_000, 0).unwrap();
                }
                reg
            },
            |mut reg| {
                black_box(reg.slash(
                    addr(25),
                    roles::VALIDATOR,
                    SlashingCondition::DoubleSign,
                    FIXED_POINT_SCALE / 2,
                ));
            },
        )
    });

    // active_members query
    group.bench_function("active_members_100", |b| {
        b.iter_with_setup(
            || {
                let mut reg = PermissionlessRegistry::new();
                for i in 0..100u8 {
                    reg.register_validator(addr(i), MIN_REGISTRATION_STAKE, 0)
                        .unwrap();
                }
                reg
            },
            |reg| {
                black_box(reg.active_members(roles::VALIDATOR));
            },
        )
    });

    group.finish();
}

// ─── 7. Bridge State Transitions ────────────────────────────────────

fn bench_bridge(c: &mut Criterion) {
    let mut group = c.benchmark_group("bridge");

    // Lock
    group.bench_function("lock", |b| {
        b.iter_with_setup(
            || {
                let mut bridge = BridgeState::new();
                let asset = AssetId(hash_fields_bytes(&[b"bench_asset"]));
                bridge.register_asset(asset, 1).unwrap();
                (bridge, asset)
            },
            |(mut bridge, asset)| {
                let _ = bridge.lock(1, 2, 10, 0, asset, addr(1), addr(2), 100, 1000);
                black_box(());
            },
        )
    });

    // Full lifecycle: lock → mint → burn → unlock
    group.bench_function("full_lifecycle", |b| {
        b.iter_with_setup(
            || {
                let mut bridge = BridgeState::new();
                let asset = AssetId(hash_fields_bytes(&[b"lifecycle_asset"]));
                bridge.register_asset(asset, 1).unwrap();
                bridge
            },
            |mut bridge| {
                let asset = AssetId(hash_fields_bytes(&[b"lifecycle_asset"]));
                let (transfer, event) = bridge
                    .lock(1, 2, 10, 0, asset, addr(1), addr(2), 100, 1000)
                    .unwrap();
                let message = event.message.unwrap();
                bridge.mint(&message).unwrap();
                bridge.burn(transfer.message_id, 2).unwrap();
                bridge.unlock(transfer.message_id, 2).unwrap();
                black_box(());
            },
        )
    });

    // sweep_expired_locks
    group.bench_function("sweep_expired_100", |b| {
        b.iter_with_setup(
            || {
                let mut bridge = BridgeState::new();
                for i in 0..100u8 {
                    let asset = AssetId(hash_fields_bytes(&[b"sweep", &[i]]));
                    bridge.register_asset(asset, 1).unwrap();
                    bridge
                        .lock(
                            1,
                            2,
                            10 + i as u64,
                            i as u32,
                            asset,
                            addr(i),
                            addr(i + 1),
                            100,
                            100 + i as u64,
                        )
                        .unwrap();
                }
                bridge
            },
            |mut bridge| {
                black_box(bridge.sweep_expired_locks(200));
            },
        )
    });

    group.finish();
}

// ─── 8. Proof Verification ──────────────────────────────────────────

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof");

    let inputs = ExecutionPublicInputs {
        chain_id: 1337,
        program_hash: [1u8; 32],
        initial_state_root: [2u8; 32],
        final_state_root: [3u8; 32],
        sender: 100,
        nonce: 1,
        block_height: 50,
        gas_limit: 1_000_000,
        gas_used: 50_000,
        exit_code: 0,
        trace_len: 1024,
        event_digest: [4u8; 32],
    };

    // Public inputs hash
    group.bench_function("public_inputs_hash", |b| {
        b.iter(|| {
            black_box(black_box(&inputs).hash());
        })
    });

    // Envelope validation (structural)
    let envelope = ProofEnvelope {
        proof_format_version: 1,
        backend: "plonky3-stark".into(),
        public_inputs_hash: inputs.hash(),
        proof_bytes: vec![0u8; 10_000],
        degree_bits: 12,
    };

    group.bench_function("envelope_validate_structure", |b| {
        b.iter(|| {
            black_box(ProofVerifier::validate_envelope_structure(black_box(
                &envelope,
            )));
        })
    });

    // Full verify (structural + inputs hash)
    group.bench_function("full_verify", |b| {
        b.iter(|| {
            black_box(ProofVerifier::verify(
                black_box(&envelope),
                black_box(&inputs),
                1_000_000,
            ));
        })
    });

    group.finish();
}

// ─── 9. Governance ──────────────────────────────────────────────────

fn bench_governance(c: &mut Criterion) {
    let mut group = c.benchmark_group("governance");

    // Full proposal lifecycle: create + vote + advance_epoch × 11 + finalize
    group.bench_function("full_proposal_lifecycle", |b| {
        b.iter_with_setup(
            || {
                let mut state = AccountState::new();
                let kp = KeyPair::generate().unwrap();
                let addr = Address::from(kp.public_key_bytes());
                state.add_balance(&addr, 10_000);
                state.add_validator(addr, 5_000);
                (state, kp, addr)
            },
            |(mut state, kp, addr)| {
                use budlum_core::core::governance::ProposalType;
                let p_type = ProposalType::ChangeBaseFee(10);
                let mut prop_tx = Transaction::new_proposal(addr, p_type, 10, 0);
                prop_tx.sign(&kp);
                let _ = Executor::apply_transaction(&mut state, &prop_tx);

                if !state.governance.proposals.is_empty() {
                    let prop_id = state.governance.proposals[0].id;
                    let mut vote_tx = Transaction::new_vote(addr, prop_id, true, 1);
                    vote_tx.sign(&kp);
                    let _ = Executor::apply_transaction(&mut state, &vote_tx);

                    for _ in 0..11 {
                        state.advance_epoch(1000);
                    }
                }
                black_box(&state.governance);
            },
        )
    });

    group.finish();
}

// ─── 10. P2P Gossip Dedup ───────────────────────────────────────────

fn bench_gossip_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip_dedup");

    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();

    // Check-and-record (new message)
    group.bench_function("check_new", |b| {
        b.iter_with_setup(
            || GossipDedup::new(10_000),
            |mut dedup| {
                let msg = format!("unique_msg_{}", rand::random::<u64>());
                black_box(dedup.check_and_record(msg.as_bytes(), &peer_id));
            },
        )
    });

    // Check-and-record (duplicate)
    group.bench_function("check_duplicate", |b| {
        b.iter_with_setup(
            || {
                let mut dedup = GossipDedup::new(10_000);
                dedup.check_and_record(b"hello", &peer_id);
                dedup
            },
            |mut dedup| {
                black_box(dedup.check_and_record(b"hello", &peer_id));
            },
        )
    });

    // 10K messages throughput
    group.bench_function("throughput_10k", |b| {
        b.iter_with_setup(
            || GossipDedup::new(10_000),
            |mut dedup| {
                for i in 0..10_000u64 {
                    let msg = i.to_le_bytes();
                    black_box(dedup.check_and_record(&msg, &peer_id));
                }
            },
        )
    });

    group.finish();
}

// ─── Criterion Groups ───────────────────────────────────────────────

criterion_group!(
    benches,
    bench_tx_execution,
    bench_state_root,
    bench_block,
    bench_signatures,
    bench_serialization,
    bench_registry,
    bench_bridge,
    bench_proof,
    bench_governance,
    bench_gossip_dedup,
);
criterion_main!(benches);
