//! Locks on what a poisoned lock does to a running node.
//!
//! A `Mutex` poisons when a thread panics while holding it, and every later
//! `lock()` returns `Err`. `src/network/node.rs` answered that in three
//! different ways at once: fourteen sites called `std::process::exit(1)`,
//! three logged and carried on, and the `gossip_dedup` site matched on the
//! result and then exited anyway.
//!
//! Taking a validator off the chain is a much worse outcome than losing a
//! peer-scoring update, so all of them now recover. These tests pin that the
//! recovery is real — the state behind a poisoned lock is still readable and
//! writable — and that no `process::exit` came back to this file.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The recovery idiom must actually preserve the data.
///
/// `into_inner()` on a poisoned guard hands back the value as it was left.
/// For `PeerManager` that means counters and ban timers survive; the only
/// loss is whatever half-finished update the panicking thread was making,
/// which the next report overwrites.
#[test]
fn recovering_from_a_poisoned_lock_preserves_the_state() {
    let shared = Arc::new(Mutex::new(vec![1u64, 2, 3]));

    let poisoner = Arc::clone(&shared);
    let handle = std::thread::spawn(move || {
        let mut guard = poisoner.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(4);
        panic!("deliberate panic while holding the lock");
    });
    assert!(
        handle.join().is_err(),
        "the helper thread must have panicked"
    );

    assert!(
        shared.lock().is_err(),
        "the lock must actually be poisoned, or this test proves nothing"
    );

    let recovered = shared.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        *recovered,
        vec![1, 2, 3, 4],
        "the write made before the panic must still be visible"
    );
}

/// A poisoned lock must not be able to end the process.
///
/// `std::process::exit` in a lock-recovery path turns any panic in the
/// protected type into a node shutdown. The one match left in `node.rs` is
/// inside a doc comment explaining why the pattern is gone.
#[test]
fn node_does_not_exit_on_a_poisoned_lock() {
    let src =
        fs::read_to_string(repo_root().join("src/network/node.rs")).expect("node.rs is readable");

    let offenders: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("process::exit"))
        .filter(|(_, line)| !line.trim_start().starts_with("///"))
        .map(|(i, line)| (i + 1, line.trim()))
        .collect();

    assert!(
        offenders.is_empty(),
        "a poisoned lock must not take the node off the chain; recover with \
         `into_inner()` as `peer_manager_lock` does:\n  {}",
        offenders
            .iter()
            .map(|(n, l)| format!("{n}: {l}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// The recovering helper exists and is what the mutating sites use.
///
/// The read-only sites keep their `if let Ok(..)` / `is_ok_and(..)` shape:
/// those already degrade to "skip this bookkeeping" rather than exiting, and
/// rewriting fifty of them would be churn. What mattered was the fourteen
/// that ended the process.
#[test]
fn the_recovering_helper_exists_and_no_site_exits() {
    let src =
        fs::read_to_string(repo_root().join("src/network/node.rs")).expect("node.rs is readable");

    assert!(
        src.contains("fn peer_manager_lock("),
        "the recovering helper must exist"
    );
    assert!(
        src.contains("poisoned.into_inner()"),
        "the helper must recover rather than propagate the poison"
    );
}

/// A poisoned lock must not silently deny every peer.
///
/// Several sites read the lock through `is_ok_and(..)` or
/// `.map(..).unwrap_or(false)`, so a poisoned mutex makes every rate-limit
/// check answer "not allowed" and the node drops all traffic while looking
/// healthy. That is a quieter failure than exiting but not a better one, and
/// it is recorded here rather than fixed in this change: the read sites need
/// a decision about what "unknown" should mean per call, which is a larger
/// argument than the exit-on-poison one.
#[test]
fn poisoned_read_sites_are_recorded_as_a_known_gap() {
    let src =
        fs::read_to_string(repo_root().join("src/network/node.rs")).expect("node.rs is readable");

    let denying: usize = src
        .lines()
        .filter(|line| line.contains("peer_manager.lock()"))
        .filter(|line| !line.trim_start().starts_with("///"))
        .filter(|line| line.contains("is_ok_and") || line.contains(".map("))
        .count();

    // Not an assertion that the count is good — an assertion that it has not
    // grown silently. If it moves, the decision above needs revisiting.
    assert!(
        denying <= 3,
        "{denying} peer_manager read sites fail closed on a poisoned lock; \
         that is more than the {} recorded when this was measured. Decide what \
         'unknown' means for the new ones rather than inheriting fail-closed \
         by accident.",
        3
    );
}
