use super::*;
use crate::core::account::AccountState;
use crate::execution::executor::Executor;
use proptest::prelude::*;

fn addr(n: u8) -> Address {
    Address::from([n; 32])
}

fn transfer(from: u8, to: u8, amount: u64) -> Transaction {
    let mut tx = Transaction::new(addr(from), addr(to), amount, Vec::new());
    tx.fee = 1;
    tx
}

fn stake(from: u8, amount: u64) -> Transaction {
    let mut tx = Transaction::new_stake(addr(from), amount, 0);
    tx.fee = 1;
    tx
}

fn funded() -> AccountState {
    let mut state = AccountState::new();
    for n in 1..=6u8 {
        state.add_balance(&addr(n), 1_000);
    }
    state
}

fn check_invariants(sets: &[AccessSet], plan: &Plan) {
    let mut wave_of: BTreeMap<usize, usize> = BTreeMap::new();
    for (w, wave) in plan.waves.iter().enumerate() {
        assert!(!wave.is_empty(), "no empty waves");
        assert!(
            wave.windows(2).all(|p| p.first() < p.last()),
            "block order inside a wave"
        );
        for &i in wave {
            assert!(wave_of.insert(i, w).is_none(), "index {i} scheduled twice");
        }
    }
    assert_eq!(wave_of.len(), sets.len(), "every index scheduled");
    for (i, a) in sets.iter().enumerate() {
        for (j, b) in sets.iter().enumerate().skip(i + 1) {
            let (wi, wj) = (wave_of.get(&i), wave_of.get(&j));
            if a.conflicts_with(b) {
                assert!(wi < wj, "{i} before {j}");
            }
            if wi == wj {
                assert!(!a.conflicts_with(b), "{i} and {j} share a wave");
            }
        }
    }
}

/// Apply in block order.
fn sequential(txs: &[Transaction]) -> String {
    let mut state = funded();
    for tx in txs {
        let _ = Executor::apply_transaction(&mut state, tx);
    }
    state.calculate_state_root()
}

/// Apply wave by wave, each wave in reverse: inside a wave any order must
/// give the same state, so the most different order is the strongest test.
fn planned(txs: &[Transaction]) -> String {
    let sets: Vec<AccessSet> = txs.iter().map(access_set).collect();
    let plan = plan(&sets);
    check_invariants(&sets, &plan);
    let mut state = funded();
    for wave in &plan.waves {
        for tx in wave.iter().rev().filter_map(|&i| txs.get(i)) {
            let _ = Executor::apply_transaction(&mut state, tx);
        }
    }
    state.calculate_state_root()
}

#[test]
fn disjoint_transfers_share_one_wave() {
    let txs = [transfer(1, 2, 5), transfer(3, 4, 5), transfer(5, 6, 5)];
    let sets: Vec<_> = txs.iter().map(access_set).collect();
    assert_eq!(plan(&sets).waves, vec![vec![0, 1, 2]]);
}

#[test]
fn a_chain_of_transfers_keeps_its_order() {
    let txs = [
        transfer(1, 2, 5),
        transfer(2, 3, 5),
        transfer(4, 5, 5),
        transfer(3, 1, 5),
    ];
    let sets: Vec<_> = txs.iter().map(access_set).collect();
    assert_eq!(plan(&sets).waves, vec![vec![0, 2], vec![1], vec![3]]);
}

#[test]
fn a_global_transaction_is_a_barrier() {
    let txs = [
        transfer(1, 2, 5),
        stake(3, 10),
        transfer(4, 5, 5),
        transfer(1, 6, 1),
    ];
    let sets: Vec<_> = txs.iter().map(access_set).collect();
    let p = plan(&sets);
    assert_eq!(p.waves, vec![vec![0], vec![1], vec![2, 3]]);
    check_invariants(&sets, &p);
}

#[test]
fn a_block_of_unknown_types_is_scheduled_sequentially() {
    let txs: Vec<_> = (1..=4u8).map(|n| stake(n, 10)).collect();
    let sets: Vec<_> = txs.iter().map(access_set).collect();
    assert_eq!(plan(&sets).waves, vec![vec![0], vec![1], vec![2], vec![3]]);
}

#[test]
fn reads_do_not_conflict_with_reads() {
    let reader = |n: u8| AccessSet {
        reads: [StateKey::Account(addr(n))].into_iter().collect(),
        ..AccessSet::default()
    };
    let writer = |n: u8| AccessSet {
        writes: [StateKey::Account(addr(n))].into_iter().collect(),
        ..AccessSet::default()
    };
    let sets = [reader(1), reader(1), writer(1), reader(1)];
    assert_eq!(plan(&sets).waves, vec![vec![0, 1], vec![2], vec![3]]);
}

/// Pinned waves for a fixed block: the same on every architecture, because
/// the planner is a pure function over ordered collections.
#[test]
fn parallel_scheduler_is_deterministic_across_arch() {
    let txs: Vec<Transaction> = (0..24u64)
        .map(|i| {
            let from = (i * 7 % 6 + 1) as u8;
            let to = (i * 5 % 6 + 1) as u8;
            if i % 9 == 4 {
                stake(from, 3)
            } else {
                transfer(from, to, i + 1)
            }
        })
        .collect();
    let sets: Vec<_> = txs.iter().map(access_set).collect();
    let p = plan(&sets);
    check_invariants(&sets, &p);
    assert_eq!(p.len(), txs.len());
    let encoded: Vec<String> = p
        .waves
        .iter()
        .map(|w| {
            w.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    assert_eq!(encoded.join("|"), PINNED_WAVES);
    // Running the planner twice gives the same plan.
    assert_eq!(plan(&sets), p);
}

const PINNED_WAVES: &str = "0,1,2,3|4|5,6,8,9|7,10,12|11|13|14,15,17,18|16,19,21|20|22|23";

#[test]
fn parallel_scheduler_is_closed_on_testnet() {
    let default_policy = ParallelSchedulerPolicy::default();
    assert!(!default_policy.scheduler_active());
    assert!(!default_policy.intra_ee_parallelism_active());

    let txs = [transfer(1, 2, 5), transfer(3, 4, 5), transfer(5, 6, 5)];
    let mut state = funded();
    let rep = execute_block_with_policy(&mut state, &txs, default_policy);
    assert!(!rep.used_parallel_waves);
    assert!(!rep.intra_ee_parallelism);
    assert_eq!(rep.state_root, sequential(&txs));
}

#[test]
fn intra_ee_block_stm_requires_separate_flag_and_equality_gate() {
    let active_only = ParallelSchedulerPolicy {
        chain_id: 45_261,
        block_height: 500,
        activation_height: Some(500),
        intra_ee_block_stm_enabled: false,
        intra_ee_equality_verified: true,
    };
    assert!(active_only.scheduler_active());
    assert!(!active_only.intra_ee_parallelism_active());

    let unverified = ParallelSchedulerPolicy {
        intra_ee_block_stm_enabled: true,
        intra_ee_equality_verified: false,
        ..active_only
    };
    assert!(!unverified.intra_ee_parallelism_active());

    let both_green = ParallelSchedulerPolicy {
        intra_ee_block_stm_enabled: true,
        intra_ee_equality_verified: true,
        ..active_only
    };
    assert!(both_green.intra_ee_parallelism_active());
}

#[test]
fn uel_slot_conflicts_fallback_to_sequential_wave() {
    let slot_a = [0xA1; 32];
    let slot_b = [0xB2; 32];
    let s0 = access_set_with_uel_hint(&stake(1, 5), &[], &[(0x01, slot_a)]);
    let s1 = access_set_with_uel_hint(&stake(2, 5), &[], &[(0x02, slot_b)]);
    let s2 = access_set_with_uel_hint(&stake(3, 5), &[(0x01, slot_a)], &[]);
    let p = plan(&[s0, s1, s2]);
    assert_eq!(p.waves, vec![vec![0, 1], vec![2]]);
}

#[test]
fn parallel_block_execution_duration_report_matches_sequential_root() {
    let txs: Vec<Transaction> = (0..64u64)
        .map(|i| {
            let from = (i % 6 + 1) as u8;
            let to = ((i + 3) % 6 + 1) as u8;
            transfer(from, to, (i % 7) + 1)
        })
        .collect();
    let mut seq_state = funded();
    let seq_rep = execute_block_with_policy(
        &mut seq_state,
        &txs,
        ParallelSchedulerPolicy::testnet_launch(),
    );
    let mut par_state = funded();
    let par_rep = execute_block_with_policy(
        &mut par_state,
        &txs,
        ParallelSchedulerPolicy {
            chain_id: 45_261,
            block_height: 1_000,
            activation_height: Some(1_000),
            intra_ee_block_stm_enabled: false,
            intra_ee_equality_verified: true,
        },
    );
    assert!(par_rep.used_parallel_waves);
    assert_eq!(seq_rep.state_root, par_rep.state_root);
    println!(
        "PARALLEL_BLOCK_TIMING_JSON={{\"tx_count\":{},\"waves\":{},\"seq_us\":{},\"par_us\":{}}}",
        par_rep.tx_count, par_rep.wave_count, seq_rep.elapsed_micros, par_rep.elapsed_micros
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Random blocks of transfers (some overdrawn, some self-transfers)
    /// with stakes mixed in: the planned execution reaches the sequential
    /// state root.
    #[test]
    fn parallel_schedule_equals_sequential_root(
        ops in proptest::collection::vec((1u8..=6, 1u8..=6, 0u64..700, 0u8..10), 0..40)
    ) {
        let txs: Vec<Transaction> = ops
            .iter()
            .map(|(from, to, amount, kind)| {
                if *kind == 0 {
                    stake(*from, *amount % 50 + 1)
                } else {
                    transfer(*from, *to, *amount)
                }
            })
            .collect();
        let seq_root = sequential(&txs);
        prop_assert_eq!(&seq_root, &planned(&txs));
        let mut par_state = funded();
        let rep = execute_block_with_policy(
            &mut par_state,
            &txs,
            ParallelSchedulerPolicy {
                chain_id: 45_261,
                block_height: 100,
                activation_height: Some(100),
                intra_ee_block_stm_enabled: false,
                intra_ee_equality_verified: true,
            },
        );
        prop_assert_eq!(seq_root, rep.state_root);
    }
}
