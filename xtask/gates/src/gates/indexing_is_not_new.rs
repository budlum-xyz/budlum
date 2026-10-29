//! A new file may not add a panicking index.
//!
//! # Why a ratchet and not a ban
//!
//! `clippy::indexing_slicing` reports 213 sites across 42 files. Every one of
//! them is a `slice[i]` that panics when `i` is out of range, and under the
//! release profile (`panic = "abort"`) a panic is not an exception the node
//! recovers from: the process stops. That is the same liveness class the
//! `unwrap`/`expect` gate closed.
//!
//! Fixing all 213 in one change is the wrong trade. Most live in index-heavy
//! code where the arithmetic is the point: RLP and MPT decoding walk a cursor
//! over bytes, erasure coding steps `i`/`j` across several arrays at once, and
//! rewriting those into iterators makes the index-equality bug they are
//! guarding against *harder* to see, not easier. A rewrite of that shape is
//! how a correct decoder becomes a subtly wrong one.
//!
//! So the number is frozen instead. The 42 files that carry an index today are
//! listed, and they may keep it. Any file not on that list may not introduce
//! one. New code starts clean and the debt cannot grow while it is paid down.
//!
//! # What is measured
//!
//! Indexing forms in shipped library code, outside test modules:
//!
//! * `expr[i]` where `i` is not a literal - a runtime index into a slice.
//! * `expr[a..b]` range slicing with non-literal bounds.
//!
//! Accepted, because none of them can panic at runtime on a slice:
//!
//! * Array *types* and repeat expressions (`[u8; 32]`, `[0u8; 32]`).
//! * Attributes and generics, which are not indexing at all.
//! * Constant literal indexes into a fixed-size array the same line declares.
//! * Test modules and test-support files: a panicking index in a test is a
//!   failing test, which is the behaviour a test wants.
//!
//! The list is a ratchet in one direction. Removing a file from it after
//! fixing that file's indexes is a normal change; adding one is the failure
//! this gate exists to report.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Roots holding shipped library code.
const SCAN_ROOTS: &[&str] = &["src"];

/// Files that carried a panicking index when the gate was written.
///
/// Measured by running this gate against the tree, not typed by hand. The
/// scan is wider than `clippy::indexing_slicing` on purpose: it also sees
/// range slicing (`&buf[a..b]`) and the binaries under `src/bin`, which the
/// `--lib` clippy run never reaches. 66 files carried the original frozen debt; fourteen more joined it on 2026-10-27, each measured against the bound beside it.
const BASELINE: &[&str] = &[
    "src/account_abstraction/tee_attestation.rs",
    "src/ai/execution/guest.rs",
    "src/ai/execution/verify.rs",
    "src/ai/mod.rs",
    "src/bin/budlum-relayer.rs",
    "src/bns/mod.rs",
    "src/budlumxyz/mod.rs",
    "src/chain/blockchain.rs",
    "src/chain/chain_actor.rs",
    "src/chain/finality.rs",
    "src/chain/snapshot.rs",
    "src/consensus/merkle_tree.rs",
    "src/consensus/mod.rs",
    "src/consensus/poa.rs",
    "src/consensus/pos.rs",
    "src/consensus/pow.rs",
    "src/core/account.rs",
    "src/core/block.rs",
    "src/core/governance.rs",
    "src/core/hash.rs",
    "src/core/transaction.rs",
    "src/cross_domain/bridge.rs",
    "src/cross_domain/event_tree.rs",
    "src/cross_domain/evm/adapter.rs",
    "src/cross_domain/evm/bud_to_eth.rs",
    "src/cross_domain/evm/mpt.rs",
    "src/cross_domain/evm/receipt.rs",
    "src/cross_domain/evm/rlp.rs",
    "src/cross_domain/evm/sync_committee.rs",
    "src/crypto/pkcs11.rs",
    "src/crypto/primitives.rs",
    "src/developer_os.rs",
    "src/domain/finality_adapter.rs",
    "src/domain/fork_choice.rs",
    "src/domain/plugin.rs",
    "src/domain/storage_deal.rs",
    "src/execution/executor.rs",
    "src/execution/zkvm.rs",
    "src/gateway/service.rs",
    "src/light_client/mod.rs",
    "src/ai_inference/mod.rs",
    "src/main.rs",
    "src/network/mobile.rs",
    "src/network/node.rs",
    "src/network/protocol.rs",
    "src/pollen/content_gate.rs",
    "src/pollen/data_rights.rs",
    "src/pollen/mod.rs",
    "src/privacy/note_registry.rs",
    "src/registry/permissionless.rs",
    "src/rpc/server.rs",
    "src/settlement/mod.rs",
    "src/settlement/proof_market.rs",
    "src/sharding/mod.rs",
    "src/socialfi/mod.rs",
    "src/storage/assignment.rs",
    "src/storage/content_id.rs",
    "src/storage/dictionary.rs",
    "src/storage/erasure.rs",
    "src/storage/generated.rs",
    "src/storage/manifest.rs",
    "src/storage/merkle_trie.rs",
    "src/storage/msr.rs",
    "src/storage/provider.rs",
    "src/storage/render.rs",
    "src/tokenomics/mod.rs",
    // The 2026-10-27 change: fourteen more files, each measured against the
    // bound that makes its index unreachable at runtime, cited beside it.
    "src/bin/budlum-domain-producer.rs", // "one BLS seed per member is required" above the loop: index < members.len() <= bls_seeds.len()
    "src/bin/budlum-indexer.rs", // serde_json string-key indexing on Value never panics: objects insert, anything else reads null
    "src/consensus/filiz.rs", // checkpoints[k] = x_{k*interval} up to x_L with interval dividing length; every caller passes j <= L
    "src/consensus/handoff.rs", // binary_search Ok(at) is an index the Vec contains
    "src/cross_domain/evm/outbound.rs", // w is [u8; 32] from word(); [..24] and [24..] split a fixed word
    "src/cross_domain/external/evm_hybrid.rs", // word is a local [u8; 32]; [24..] writes into that fixed word
    "src/crypto/hpke.rs", // minimum-length guard above is SUITE_HEADER_LEN + HPKE_ENCAPPED_KEY_LEN + AEAD_TAG_LEN
    "src/crypto/secp256k1_recover.rs", // "signature.len() != 65" guard above; [..32] and [32..64] split 65
    "src/domain/producer.rs", // bitmap is vec![0; members.len().div_ceil(8)] and members.get(index)? bounds the signer index first
    "src/network/witness_protocol.rs", // "bytes.len() < 12" guard above; [..8] and [8..12] read the 12-byte header
    "src/security/quantum_canary.rs", // try-and-increment: P-192/P-224/P-256 field sizes 24/28/32 never exceed the 32-byte SHA3-256 digest
    "src/settlement/graft.rs",        // "origin.len() <= 32" guard in origin_emitter
    "src/storage/db.rs",              // &[1u8][..] is a one-byte literal
    "src/storage/key_package.rs", // "bytes.len() < 64" guard above; [..32] and [32..64] split the first 64
];

/// Strip every `#[cfg(test)]` item. A body-less item (`use`, `mod tests;`)
/// ends at its own `;` and must not swallow the next production block.
fn strip_test_modules(text: &str) -> String {
    super::capability_modules_are_wired::strip_test_mods(text)
}

/// Does this line index into something at runtime?
///
/// Deliberately conservative: the gate reports a file, and a false report on
/// a new file costs a developer an argument with a gate. It looks for `[`
/// immediately after an identifier, closing paren or `]` - the shapes that
/// mean "index into this value" - and then requires the contents to be
/// something other than a plain literal or a type.
pub fn indexes_at_runtime(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with("#[") || trimmed.starts_with("#!") {
        return false;
    }
    let bytes = trimmed.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if c != b'[' {
            continue;
        }
        // Must follow a value: identifier char, `)` or `]`.
        let Some(prev) = i.checked_sub(1).map(|p| bytes[p]) else {
            continue;
        };
        if !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b')' || prev == b']') {
            continue;
        }
        // A generic argument list (`Vec<[u8; 32]>`) never reaches here because
        // `<` is not a value char. Find the matching bracket.
        let mut depth = 0usize;
        let mut close = None;
        for (j, &d) in bytes.iter().enumerate().skip(i) {
            if d == b'[' {
                depth += 1;
            } else if d == b']' {
                depth -= 1;
                if depth == 0 {
                    close = Some(j);
                    break;
                }
            }
        }
        let Some(close) = close else { continue };
        let inner = trimmed[i + 1..close].trim();
        if inner.is_empty() {
            continue;
        }
        // `[u8; 32]` / `[0u8; 32]`: a type or a repeat expression, not an index.
        if inner.contains(';') {
            continue;
        }
        // A plain numeric literal index into a fixed-size array cannot be made
        // out of range by input; the compiler checks it against the length.
        if inner.chars().all(|c| c.is_ascii_digit() || c == '_') {
            continue;
        }
        return true;
    }
    false
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            if matches!(&*name, "target" | ".git" | "tests" | "benches" | "fuzz") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Is this a test-support file, where a panicking index is a failing test?
fn is_test_support(path: &str) -> bool {
    path.contains("/tests/") || path.ends_with("_tests.rs") || path.contains("/test_")
}

/// Run the gate.
///
/// # Errors
///
/// Returns an error when a file outside the baseline indexes at runtime, or
/// when a baseline entry no longer exists.
pub fn run(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for r in SCAN_ROOTS {
        walk(&root.join(r), &mut files);
    }
    files.sort();

    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_support(&rel) {
            continue;
        }
        scanned += 1;
        if BASELINE.contains(&rel.as_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let body = strip_test_modules(&text);
        for (n, line) in body.lines().enumerate() {
            if indexes_at_runtime(line) {
                offenders.push(format!("  {rel}:{}: {}", n + 1, line.trim()));
                break;
            }
        }
    }

    // A baseline entry that no longer exists is a stale exemption: the file was
    // renamed or deleted and the list now protects nothing.
    let mut stale: Vec<&str> = Vec::new();
    for b in BASELINE {
        if !root.join(b).is_file() {
            stale.push(b);
        }
    }

    if !offenders.is_empty() || !stale.is_empty() {
        let mut msg = String::new();
        if !offenders.is_empty() {
            let _ = writeln!(
                msg,
                "{} file(s) outside the baseline index at runtime:",
                offenders.len()
            );
            for o in &offenders {
                let _ = writeln!(msg, "{o}");
            }
            let _ = writeln!(
                msg,
                "\n  `slice[i]` panics when `i` is out of range, and release builds abort on \
                 panic. Use `.get(i)` and decide what an absent element means, or - if this \
                 file genuinely belongs with the index-heavy decoders - add it to BASELINE \
                 with the measurement that justifies it."
            );
        }
        if !stale.is_empty() {
            let _ = writeln!(msg, "\n{} baseline entr(ies) no longer exist:", stale.len());
            for s in &stale {
                let _ = writeln!(msg, "  {s}");
            }
            let _ = writeln!(
                msg,
                "\n  Remove them: an exemption for a file that is gone hides the next file \
                 that takes its name."
            );
        }
        return Err(msg);
    }

    Ok(format!(
        "Indexing ratchet OK: {scanned} files scanned, {} carrying the frozen debt, \
         none outside it added a runtime index.",
        BASELINE.len()
    ))
}

/// Canaries.
///
/// # Errors
///
/// Returns an error when a canary does not behave as stated.
pub fn self_test() -> Result<String, String> {
    let must_flag = [
        "let x = data[i];",
        "let b = buf[pos + 1];",
        "let s = &bytes[a..b];",
        "out[idx] = value;",
        "return frame[self.cursor];",
    ];
    for c in must_flag {
        if !indexes_at_runtime(c) {
            return Err(format!("a runtime index was missed: {c:?}"));
        }
    }

    let must_pass = [
        "let mut w = [0u8; 32];",
        "pub fn f(x: &[u8; 64]) -> [u8; 32] {",
        "// data[i] in a comment",
        "#[allow(clippy::indexing_slicing)]",
        "let arr: Vec<[u8; 4]> = Vec::new();",
        "let first = tuple[0];",
        "let v: Vec<u8> = Vec::new();",
        "hasher.update(self.version.to_le_bytes());",
    ];
    for c in must_pass {
        if indexes_at_runtime(c) {
            return Err(format!("a safe line was flagged: {c:?}"));
        }
    }

    // A runtime index inside a test module must be invisible to the scan.
    let with_test = "fn a() {}\n\
                     #[cfg(test)]\n\
                     mod tests {\n\
                     fn b() { if true { } }\n\
                     let x = data[i];\n\
                     }\n\
                     fn c() {}\n";
    let stripped = strip_test_modules(with_test);
    if stripped.contains("data[i]") {
        return Err(String::from("a test-module index was not skipped"));
    }
    if !stripped.contains("fn c() {}") {
        return Err(String::from(
            "the brace counter ended the skip early and lost code after the test module",
        ));
    }

    if !is_test_support("src/tests/foo.rs") || is_test_support("src/storage/erasure.rs") {
        return Err(String::from("test-support detection is wrong"));
    }

    Ok(String::from(
        "indexing ratchet self-test OK: five runtime indexes flagged, eight safe lines \
         (array types, repeat exprs, comments, attributes, literal indexes) passed, \
         test modules skipped with the brace counter intact.",
    ))
}

#[cfg(test)]
mod strip_tests {
    use super::*;

    #[test]
    fn bodyless_test_item_does_not_hide_the_next_function() {
        let src =
            "#[cfg(test)]\npub mod tests;\nfn prod(v: &[u8], i: usize) -> u8 {\n    v[i]\n}\n";
        let body = strip_test_modules(src);
        assert!(body.lines().any(indexes_at_runtime));
    }
}
