//! The public surface of the crate, read from its own source.
//!
//! A `.bud` proof is worth what its anchor is worth. A public function that takes
//! the registry root and the epoch as arguments lets a caller hand it the node's
//! own answer, and a node that invents the root invents the matching branch and
//! epoch with it. The only way in from outside the crate is the header path, which
//! reads both values out of a `HeaderSource` the wallet trusts.
//!
//! These tests read the source files, so a new public function of that shape fails
//! here and not in review.

use std::path::{Path, PathBuf};

/// Where a signature ends: the first `{` or `;` that is not inside parentheses or
/// brackets. A `;` inside `[u8; 32]` does not end it.
fn signature_end(tail: &str) -> usize {
    let mut depth = 0usize;
    for (i, c) in tail.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '{' | ';' if depth == 0 => return i,
            _ => {}
        }
    }
    tail.len()
}

/// Every `pub fn` signature in `src`, from `pub fn` up to the opening brace or the
/// semicolon, with the whitespace collapsed to single spaces.
fn public_signatures(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("pub fn ") {
        let tail = &rest[at..];
        let end = signature_end(tail);
        out.push(tail[..end].split_whitespace().collect::<Vec<_>>().join(" "));
        rest = &tail[end..];
    }
    out
}

/// The parameters of a signature, split at the commas that are not nested in
/// brackets, parentheses or angle brackets.
fn parameters(signature: &str) -> Vec<String> {
    let Some(open) = signature.find('(') else {
        return Vec::new();
    };
    let mut depth = 0usize;
    let mut current = String::new();
    let mut out = Vec::new();
    for c in signature[open + 1..].chars() {
        match c {
            '(' | '[' | '<' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '>' if depth > 0 => {
                depth -= 1;
                current.push(c);
            }
            ')' => {
                out.push(current.trim().to_string());
                return out;
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    out
}

/// True when the signature takes a 32-byte root and a bare epoch, whatever the
/// parameters are called.
fn takes_a_root_and_an_epoch(signature: &str) -> bool {
    let params = parameters(signature);
    let root = params
        .iter()
        .any(|p| p.contains("root") && p.contains("[u8; 32]"));
    let epoch = params
        .iter()
        .any(|p| p.contains("epoch") && p.contains("u64"));
    root && epoch
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_public_function_takes_the_bns_root_and_the_epoch_as_arguments() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut scanned = 0usize;
    let mut with_arrays = 0usize;
    let mut saw_header_entry_point = false;
    let mut offenders = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).unwrap();
        for signature in public_signatures(&src) {
            scanned += 1;
            if parameters(&signature)
                .iter()
                .any(|p| p.contains("[u8; 32]"))
            {
                with_arrays += 1;
            }
            if signature.contains("fn verify_bns_recipient_proof_from_header") {
                saw_header_entry_point = true;
            }
            if takes_a_root_and_an_epoch(&signature) {
                offenders.push(format!("{}: {signature}", file.display()));
            }
        }
    }
    // A scan that cuts a signature at the `;` inside `[u8; 32]` sees none of the shapes it
    // is looking for, so it has to prove that it reads whole parameter lists.
    assert!(
        files.len() >= 8 && scanned >= 40 && with_arrays >= 5 && saw_header_entry_point,
        "the scan must not be vacuous: {} files, {scanned} public functions, {with_arrays} with \
         a 32-byte parameter, header entry point seen: {saw_header_entry_point}",
        files.len()
    );
    assert!(
        offenders.is_empty(),
        "a public function takes the root and the epoch from its caller, so a node's own \
         answer can choose what the wallet signs over. Read both from a `HeaderSource`:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scan_flags_the_shape_it_exists_to_forbid_and_passes_the_header_path() {
    // Split so that this file does not contain the text the scan looks for.
    let from_caller = concat!(
        "pub",
        " fn verify_bns_recipient_proof(requested_name: &str, claimed_target: &[u8; 32], \
         proof: &WalletBnsProof, expected_bns_root: &[u8; 32], current_epoch: u64) \
         -> Result<[u8; 32], String> {}"
    );
    let sigs = public_signatures(from_caller);
    assert_eq!(sigs.len(), 1);
    assert!(takes_a_root_and_an_epoch(&sigs[0]));

    let from_header = concat!(
        "pub",
        " fn verify_bns_recipient_proof_from_header<S: HeaderSource + ?Sized>(\n    \
         requested_name: &str,\n    claimed_target: &[u8; 32],\n    proof: &WalletBnsProof,\n    \
         headers: &S,\n) -> Result<[u8; 32], String> {}"
    );
    let sigs = public_signatures(from_header);
    assert_eq!(sigs.len(), 1);
    assert!(!takes_a_root_and_an_epoch(&sigs[0]));

    // A root alone, or an epoch alone, is not the shape: hashing helpers take a root.
    let root_only = concat!("pub", " fn fold(root: &[u8; 32]) -> [u8; 32] {}");
    assert!(!takes_a_root_and_an_epoch(&public_signatures(root_only)[0]));
    let epoch_only = concat!("pub", " fn expired(expires_at: u64, epoch: u64) -> bool {}");
    assert!(!takes_a_root_and_an_epoch(
        &public_signatures(epoch_only)[0]
    ));
}
