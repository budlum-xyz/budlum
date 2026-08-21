//! Every interleaving of the consensus engine's nested locks, checked.
//!
//! `PoSEngine` owns four `RwLock`s: `seen_blocks`, `slashing_evidence`,
//! `checkpoints` and `epoch_seed`. Three call sites take two of them at once:
//!
//! | site | order |
//! |---|---|
//! | `record_block_header` on a double sign | `seen_blocks` then `slashing_evidence` |
//! | `record_block_header` on a first sighting, via `add_checkpoint` | `seen_blocks` then `checkpoints` |
//! | `serialize_state` | `checkpoints` then `slashing_evidence` |
//!
//! Read those three as edges and they form a total order:
//! `seen_blocks` before `checkpoints` before `slashing_evidence`. No call
//! site takes them the other way round, so the graph is acyclic and the
//! engine cannot deadlock against itself.
//!
//! That paragraph is an argument, and an argument is what these tests replace.
//! Reading the code is how a lock order gets believed and it is not how one
//! gets proven: the reasoning is only as current as the last person to redo
//! it, and it fails silently the first time somebody adds a fourth call site
//! in the other direction.
//!
//! ThreadSanitizer does not close that gap either. It reports a race it
//! observed, on the schedule the machine happened to pick, so a green TSan run
//! says the schedules it tried were clean. A lock inversion needs two threads
//! to arrive in the wrong order at the wrong moment, which is exactly the
//! schedule a loaded CI runner is least likely to produce.
//!
//! loom runs the model instead: every interleaving the C11 memory model
//! permits, exhaustively, and it detects a deadlock as a state with no
//! runnable thread rather than by waiting for one. When a loom test passes,
//! the ordering is proven for the model, not observed once.
//!
//! # What is modelled
//!
//! The locks and the order in which the call sites take them, not the data
//! inside. `HashMap<(Address, u64), (BlockHeader, Vec<u8>)>` under a lock
//! contributes nothing to whether two threads can deadlock; the acquisition
//! order is the whole question, and loom's state space is small enough to be
//! exhaustive precisely because the model stays this thin.
//!
//! The risk of a model is that it drifts from the code it claims to describe.
//! `the_model_matches_the_engines_lock_inventory` is the guard: it reads
//! `src/consensus/pos.rs` and fails when the engine grows a lock the model
//! does not have.

#[cfg(loom)]
mod model {
    use loom::sync::RwLock;
    use loom::thread;
    use std::sync::Arc;

    /// The four locks of `PoSEngine`, with the contents left out.
    ///
    /// Field order is the lock order, and it is the one the engine uses.
    struct Engine {
        seen_blocks: RwLock<u32>,
        checkpoints: RwLock<u32>,
        slashing_evidence: RwLock<u32>,
        epoch_seed: RwLock<u32>,
    }

    impl Engine {
        fn new() -> Self {
            Self {
                seen_blocks: RwLock::new(0),
                checkpoints: RwLock::new(0),
                slashing_evidence: RwLock::new(0),
                epoch_seed: RwLock::new(0),
            }
        }

        /// `record_block_header`, double-sign branch: `seen_blocks` is held
        /// while `slashing_evidence` is taken to push the evidence.
        fn record_double_sign(&self) {
            let mut seen = self.seen_blocks.write().unwrap();
            *seen += 1;
            let mut evidence = self.slashing_evidence.write().unwrap();
            *evidence += 1;
        }

        /// `record_block_header`, first-sighting branch: `seen_blocks` is
        /// held across the `add_checkpoint` call, which takes `checkpoints`.
        fn record_first_sighting(&self) {
            let mut seen = self.seen_blocks.write().unwrap();
            *seen += 1;
            let mut checkpoints = self.checkpoints.write().unwrap();
            *checkpoints += 1;
        }

        /// `serialize_state`: both read guards are arguments to one `json!`,
        /// so they are alive at the same time.
        fn serialize_state(&self) -> u32 {
            let seed = *self.epoch_seed.read().unwrap();
            let checkpoints = self.checkpoints.read().unwrap();
            let evidence = self.slashing_evidence.read().unwrap();
            seed + *checkpoints + *evidence
        }

        /// `drain_slashing_evidence` and `prune_slashing_evidence`: one lock,
        /// which is what makes them safe to call from anywhere.
        fn drain_evidence(&self) -> u32 {
            let mut evidence = self.slashing_evidence.write().unwrap();
            let n = *evidence;
            *evidence = 0;
            n
        }
    }

    /// Two threads on the two nesting branches of `record_block_header`.
    ///
    /// Both start from `seen_blocks`, so one blocks the other at the outer
    /// lock and neither can be holding an inner one. A deadlock here would
    /// mean the branches disagree about which lock comes first.
    #[test]
    fn the_two_nesting_branches_cannot_deadlock_against_each_other() {
        loom::model(|| {
            let engine = Arc::new(Engine::new());

            let a = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_double_sign())
            };
            let b = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_first_sighting())
            };

            a.join().unwrap();
            b.join().unwrap();

            assert_eq!(*engine.seen_blocks.read().unwrap(), 2);
        });
    }

    /// Block recording against state serialisation.
    ///
    /// This is the pair that could invert. A recorder holds `seen_blocks` and
    /// reaches for `checkpoints`; a serialiser holds `checkpoints` and
    /// reaches for `slashing_evidence`. The orders chain rather than oppose,
    /// and loom is what says so for every interleaving instead of the one
    /// that happened to run.
    #[test]
    fn recording_a_block_cannot_deadlock_against_serialising_state() {
        loom::model(|| {
            let engine = Arc::new(Engine::new());

            let recorder = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_first_sighting())
            };
            let serialiser = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.serialize_state())
            };

            recorder.join().unwrap();
            serialiser.join().unwrap();
        });
    }

    /// A double sign against a serialisation, which is the other way the two
    /// inner locks can be reached at once.
    #[test]
    fn a_double_sign_cannot_deadlock_against_serialising_state() {
        loom::model(|| {
            let engine = Arc::new(Engine::new());

            let recorder = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_double_sign())
            };
            let serialiser = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.serialize_state())
            };

            recorder.join().unwrap();
            serialiser.join().unwrap();
        });
    }

    /// Draining evidence while a block is recorded.
    ///
    /// The drain takes the innermost lock on its own, so it can interleave
    /// anywhere. What is asserted is the count: every evidence item recorded
    /// is either drained or still there, never both and never neither.
    #[test]
    fn draining_evidence_loses_nothing_and_invents_nothing() {
        loom::model(|| {
            let engine = Arc::new(Engine::new());

            let recorder = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_double_sign())
            };
            let drainer = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.drain_evidence())
            };

            recorder.join().unwrap();
            let drained = drainer.join().unwrap();
            let left = *engine.slashing_evidence.read().unwrap();

            assert_eq!(
                drained + left,
                1,
                "the one recorded evidence item was either drained or is still held"
            );
        });
    }

    /// Three threads at once, which is where an ordering that survives pairs
    /// can still fail.
    #[test]
    fn all_three_call_sites_at_once_cannot_deadlock() {
        loom::model(|| {
            let engine = Arc::new(Engine::new());

            let one = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_double_sign())
            };
            let two = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.record_first_sighting())
            };
            let three = {
                let engine = Arc::clone(&engine);
                thread::spawn(move || engine.serialize_state())
            };

            one.join().unwrap();
            two.join().unwrap();
            three.join().unwrap();
        });
    }
}

/// The model describes the engine that exists, not one that used to.
///
/// A loom proof is about the model, so it is worth exactly as much as the
/// model's resemblance to the code. The way that resemblance dies is quiet:
/// somebody adds a fifth lock, takes it while holding a second, and every
/// loom test keeps passing because the model never heard about it.
///
/// This reads the engine and fails when the inventory moves. It runs on the
/// ordinary test profile, not under `cfg(loom)`, so the check is present in
/// every CI run rather than only in the nightly loom job.
#[test]
fn the_model_matches_the_engines_lock_inventory() {
    let src = include_str!("../consensus/pos.rs");

    // Field declarations, not uses: `RwLock<` appears in the struct once per
    // lock the engine owns.
    let declared: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("RwLock<") && l.trim_end().ends_with(','))
        .map(str::trim)
        .collect();

    assert_eq!(
        declared.len(),
        4,
        "PoSEngine's lock count moved. The loom model in this file covers four \
         locks in the order seen_blocks, checkpoints, slashing_evidence, epoch_seed. \
         A lock that is not in the model is a lock no interleaving was checked \
         against, so add it there before adding it here.\nFound: {declared:#?}"
    );

    for name in [
        "seen_blocks",
        "slashing_evidence",
        "checkpoints",
        "epoch_seed",
    ] {
        assert!(
            declared
                .iter()
                .any(|l| l.starts_with(name) || l.starts_with(&format!("pub {name}"))),
            "{name} is no longer a lock field on PoSEngine, but the loom model \
             still models it. The model has stopped describing the engine."
        );
    }
}
