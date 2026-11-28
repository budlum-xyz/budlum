use std::collections::BTreeMap;

use budlum_core::aggregation::chain::{claim_domain, claim_signature};
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::AggParams;
use budlum_core::aggregation::pool::{
    Admission, ObjectPool, Rejection, TxFacts, TxLookup, ANTI_CENSORSHIP_WAIT_TICKS,
};
use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::Transaction;
use budlum_core::cross_domain::external::phase_a_dual::{
    BlockBatchProof, RootProofStatus, MAX_BATCH_PROOF_DELAY_BLOCKS,
};
use budlum_core::cross_domain::external::sentry::ConsensusSentry;
use budlum_core::crypto::facts::QuantumClass;
use budlum_core::crypto::primitives::WalletKeyPair;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::domain::types::Hash32;
use budlum_core::light_client::LightClient;
use budlum_core::settlement::finality_gate::{
    ProofLivenessCheck, ProofRequirement, ValueGate, ValueGateRefusal,
};
use budlum_core::settlement::universal_finality::{
    compose, DomainFinalityEntry, FinalityBinds, FinalityGuarantee, FinalityReversibility,
    FinalityVerdict, FINALITY_BINDS_ALL,
};

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn some<T>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(v) => v,
        None => panic!("{msg}"),
    }
}

struct MapLookup {
    txs: BTreeMap<Hash32, (TxFacts, Hash32)>,
}

impl TxLookup for MapLookup {
    fn tx_facts(&self, tx_hash: &Hash32) -> Option<TxFacts> {
        self.txs.get(tx_hash).map(|(facts, _)| *facts)
    }

    fn accepts_claim(&self, tx_hash: &Hash32, digest: &Hash32) -> bool {
        self.txs
            .get(tx_hash)
            .is_some_and(|(_, expected)| expected == digest)
    }
}

fn established_entry(domain_id: u32, height: u64) -> DomainFinalityEntry {
    DomainFinalityEntry {
        domain_id,
        height,
        checkpoint_height: height,
        state_root: [u8::try_from(domain_id).unwrap_or(1); 32],
        adapter_id: "stark-validity-v1".to_owned(),
        adapter_version: 1,
        finality_proof_hash: [0x11; 32],
        guarantee_backing_hash: [0x22; 32],
        bond_atoms: 10_000_000,
        guarantee: FinalityGuarantee {
            reversibility: FinalityReversibility::CryptographicValidity,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: true,
            fault_tolerance_bps: 9_999,
        },
        binds: FinalityBinds::ALL,
        verdict: FinalityVerdict::Established,
    }
}

#[test]
fn k2h_th1_chain_advances_20_blocks_without_prover_and_value_gate_distinguishes_voted_vs_proven() {
    let cert = must(
        compose(&[established_entry(1, 20), established_entry(2, 20)]),
        "compose finality certificate",
    );
    let sentry = ConsensusSentry::new();

    // Prover is silent for 20 finalized blocks (proven_height stays 0):
    // 1. Chain & light-client advance through PendingProof (1..=8) and DelayExceeded (9..=20).
    // 2. VotedOnly value gate succeeds on every block (liveness independent of prover).
    // 3. ProvenRequired value gate waits (ProofPending) on every block.
    let proven_height = 0u64;
    for block_height in 1..=20u64 {
        let status = LightClient::checkpoint_proof_status(block_height, proven_height);
        if block_height <= MAX_BATCH_PROOF_DELAY_BLOCKS {
            assert_eq!(
                status,
                RootProofStatus::PendingProof {
                    blocks_behind: block_height,
                }
            );
        } else {
            assert_eq!(
                status,
                RootProofStatus::DelayExceeded {
                    blocks_behind: block_height,
                }
            );
        }

        let voted_verdict = must(
            LightClient::check_value_gate_liveness(
                &cert,
                &sentry,
                ValueGate::UniversalPayment,
                1,
                Some(2),
                FinalityBinds::EVENT_ROOT,
                ProofLivenessCheck {
                    block_height,
                    proven_height,
                    requirement: ProofRequirement::VotedOnly,
                },
            ),
            "VotedOnly gate must proceed while prover is silent",
        );
        assert_eq!(voted_verdict.gate, ValueGate::UniversalPayment);

        let proven_res = LightClient::check_value_gate_liveness(
            &cert,
            &sentry,
            ValueGate::BridgeMint,
            1,
            Some(2),
            FinalityBinds::EVENT_ROOT,
            ProofLivenessCheck {
                block_height,
                proven_height,
                requirement: ProofRequirement::ProvenRequired,
            },
        );
        assert_eq!(
            proven_res,
            Err(ValueGateRefusal::ProofPending {
                block_height,
                proven_height,
                status,
            })
        );
    }

    // Prover catches up by sealing a BlockBatchProof covering 1..=20.
    let inner_digests: Vec<Hash32> = (1u8..=20u8).map(|i| [i; 32]).collect();
    let batch = must(BlockBatchProof::seal(1, 20, inner_digests), "seal batch");
    assert_eq!(batch.proven_height, 20);
    assert_eq!(
        LightClient::checkpoint_proof_status(20, batch.proven_height),
        RootProofStatus::Proven
    );

    // Once proven_height reaches 20, ProvenRequired value gate succeeds immediately.
    let final_verdict = must(
        LightClient::check_value_gate_liveness(
            &cert,
            &sentry,
            ValueGate::BridgeMint,
            1,
            Some(2),
            FinalityBinds::EVENT_ROOT,
            ProofLivenessCheck {
                block_height: 20,
                proven_height: batch.proven_height,
                requirement: ProofRequirement::ProvenRequired,
            },
        ),
        "ProvenRequired gate must complete once prover catches up",
    );
    assert_eq!(final_verdict.gate, ValueGate::BridgeMint);
}

#[test]
fn k2h_th5_aged_valid_object_wins_priority_after_ten_ticks_and_resists_fee_spam() {
    let devnet_id = Network::Devnet.chain_id().value();
    let domain = some(claim_domain(devnet_id), "devnet claim domain");
    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams {
        tick_max_objects: 1,
        sender_tick_limit: 16,
        ..AggParams::default()
    };

    let mut pool = ObjectPool::new(params, domain);
    let mut lookup = MapLookup {
        txs: BTreeMap::new(),
    };

    let make_obj = |nonce: u64, fee: u64, lookup: &mut MapLookup| {
        let sender = WalletKeyPair::generate();
        let mut raw = Transaction::new(sender.address(), Address::from([0x44; 32]), 5, Vec::new());
        raw.chain_id = devnet_id;
        raw.nonce = nonce;
        raw.fee = fee;
        raw.sign_v5(&sender);
        let (_claimed, env) = some(claim_signature(&raw), "claim signature");
        let claim = must(derive_claim(&registry, &env), "derive claim");
        let digest = claim.digest(domain);
        lookup.txs.insert(
            env.tx_hash,
            (
                TxFacts {
                    from: raw.from,
                    fee: raw.fee,
                },
                digest,
            ),
        );
        (env, digest)
    };

    // Admit a valid low-fee object that could otherwise be starved by high-fee spam.
    let (low_env, low_digest) = make_obj(0, 25_000, &mut lookup);
    let low_bytes = low_env.encode().len();
    assert!(matches!(
        must(pool.admit(low_env, &lookup, &registry), "admit low-fee obj"),
        Admission::Accepted(_)
    ));

    // For ANTI_CENSORSHIP_WAIT_TICKS (10) consecutive ticks, higher-fee objects arrive
    // and occupy the single tick slot while low_digest ages.
    for tick in 0..ANTI_CENSORSHIP_WAIT_TICKS {
        let (hi_env, hi_digest) = make_obj(tick + 1, 500_000, &mut lookup);
        assert!(matches!(
            must(pool.admit(hi_env, &lookup, &registry), "admit hi-fee obj"),
            Admission::Accepted(_)
        ));
        let picked = pool.next_items();
        assert_eq!(picked.len(), 1);
        let picked_first = some(picked.first(), "picked item");
        assert_eq!(
            picked_first.claim.digest(domain),
            hi_digest,
            "before 10 ticks, higher fee/byte still takes the slot"
        );
        pool.mark_proven(&picked);
        assert!(pool.tracks_claim(&low_digest));
        pool.begin_tick(&lookup, &registry);
    }

    // After 10 ticks of waiting, low_digest has aged into the anti-censorship lane:
    // even a 2000x higher-fee newcomer cannot jump ahead of it!
    let (whale_env, _whale_digest) = make_obj(999, 50_000_000, &mut lookup);
    assert!(matches!(
        must(
            pool.admit(whale_env, &lookup, &registry),
            "admit whale newcomer"
        ),
        Admission::Accepted(_)
    ));
    let promoted = pool.next_items();
    assert_eq!(promoted.len(), 1);
    let promoted_first = some(promoted.first(), "promoted item");
    assert_eq!(
        promoted_first.claim.digest(domain),
        low_digest,
        "object waiting 10 ticks must be prioritized ahead of newer high-fee spam"
    );

    // Also verify eviction protection: an aged ready object cannot be evicted
    // by a higher-fee newcomer when pool_max_bytes is full.
    let tight_params = AggParams {
        tick_max_objects: 1,
        pool_max_bytes: low_bytes.saturating_add(16),
        ..AggParams::default()
    };
    let mut tight_pool = ObjectPool::new(tight_params, domain);
    let (aged_env, aged_digest) = make_obj(1001, 25_000, &mut lookup);
    assert!(matches!(
        must(
            tight_pool.admit(aged_env, &lookup, &registry),
            "admit aged obj into tight pool"
        ),
        Admission::Accepted(_)
    ));
    for _ in 0..ANTI_CENSORSHIP_WAIT_TICKS {
        tight_pool.begin_tick(&lookup, &registry);
    }
    let (spam_env, _) = make_obj(1002, 50_000_000, &mut lookup);
    assert_eq!(
        tight_pool.admit(spam_env, &lookup, &registry),
        Err(Rejection::PoolFull),
        "aged ready object must not be evicted by fee-bidding spam"
    );
    assert!(tight_pool.tracks_claim(&aged_digest));
}
