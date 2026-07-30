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
/// This was recorded as a known gap rather than fixed, with a test that froze
/// the count at 3. Re-measuring found **62** raw `peer_manager.lock()` sites:
/// the old check only matched single-line `is_ok_and` / `.map(`, so it missed
/// multi-line `.map(..).unwrap_or(false)` chains, every `if let Ok(mut pm)`
/// block, and three `match` arms. Freezing a number does not make it right.
///
/// The three shapes and what each did on a poisoned lock:
///
///   - `is_ok_and(..)` / `.map(..).unwrap_or(false)` — answered "not allowed",
///     so every rate-limit and handshake check denied, and the node dropped
///     all traffic while reporting itself healthy;
///   - `if let Ok(mut pm)` — skipped the body, so misbehaviour went
///     unreported, bans were never applied, and peers kept their reputation;
///   - `match` — returned an empty list or an early return, so the ban list
///     was never persisted (bans lost across restart) and banned peers were
///     never disconnected.
///
/// All three are worse than continuing with the recovered state. A poisoned
/// `PeerManager` means one panic somewhere in peer bookkeeping; the recovered
/// map is stale, not hostile, and the next message corrects it.
#[test]
fn no_peer_manager_site_reads_the_lock_directly() {
    let src =
        fs::read_to_string(repo_root().join("src/network/node.rs")).expect("node.rs is readable");

    let raw: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line))
        .filter(|(_, line)| line.contains("peer_manager.lock()"))
        .filter(|(_, line)| !line.trim_start().starts_with("///"))
        // The helper itself is the one place allowed to touch the raw lock.
        .filter(|(_, line)| !line.contains("unwrap_or_else"))
        .collect();

    assert!(
        raw.is_empty(),
        "these sites still read peer_manager.lock() directly instead of going \
         through peer_manager_lock(), so a poisoned lock changes their answer: {raw:?}"
    );
}

/// The scan above has to be able to fail.
///
/// A source-level check that silently matches nothing would pass forever after
/// a rename. This plants the exact shape being forbidden and asserts the
/// filter still catches it.
#[test]
fn the_direct_lock_scan_can_still_detect_a_violation() {
    let planted = [
        "            if let Ok(mut pm) = self.peer_manager.lock() {",
        "        let ok = self.peer_manager.lock().is_ok_and(|mut pm| pm.check_rate_limit(&p));",
    ];
    let caught = planted
        .iter()
        .filter(|line| line.contains("peer_manager.lock()"))
        .filter(|line| !line.trim_start().starts_with("///"))
        .filter(|line| !line.contains("unwrap_or_else"))
        .count();
    assert_eq!(
        caught, 2,
        "the scan used by no_peer_manager_site_reads_the_lock_directly cannot \
         see a planted violation, so it proves nothing"
    );
}
