//! Arweave `data_root` verification.
//!
//! A `.eth` name can point, through the ENS `contenthash` field, at an Arweave
//! transaction id. That id is the hash of the signature and NOT the hash of the
//! **content**; the field bound to the content is `data_root`: the data is split
//! into 256 KiB chunks, each chunk becomes a leaf, and the root of the tree is
//! committed in the transaction.
//!
//! This module rebuilds that tree. If the fetched bytes do not produce the
//! `data_root`, the page is not shown.
//!
//! # Why SHA-384
//!
//! It is Arweave's choice and is not being re-chosen here. The leaf and branch
//! hashes are all SHA-384, and the `note` field is a 32-byte **big-endian**
//! offset. Change any one of those and the root produced is not Arweave's root.
//!
//! # What is not verified
//!
//! The transaction signature, RSA-PSS, is not verified, because the question
//! this scanner asks is "do these bytes belong to this root", not "who signed
//! this transaction". The root comes from an ENS record, and verifying that
//! record is the ENS side's job. Conflating the two would put two separate
//! claims behind a single "verified" badge.

use sha2::{Digest, Sha384};

/// Arweave's maximum chunk size.
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Arweave's minimum chunk size, used when rebalancing the last chunk.
pub const MIN_CHUNK_SIZE: usize = 32 * 1024;

/// The `note`: a 32-byte big-endian offset.
fn note_bytes(offset: usize) -> [u8; 32] {
    let mut note = [0u8; 32];
    let be = (offset as u128).to_be_bytes(); // 16 bytes
    note[16..].copy_from_slice(&be);
    note
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[derive(Debug, Clone, Copy)]
struct Node {
    id: [u8; 48],
    max_byte_range: usize,
}

/// Splits the bytes according to Arweave's chunking rule.
///
/// If the last chunk falls below `MIN_CHUNK_SIZE`, it is rebalanced together
/// with the one before it. That rule is arweave-js's own; skip it and the last
/// two chunks land on different boundaries, so the root does not hold.
fn split_chunks(data: &[u8]) -> Vec<(usize, usize)> {
    if data.is_empty() {
        return vec![(0, 0)];
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut start = 0;
    while start < data.len() {
        let end = (start + MAX_CHUNK_SIZE).min(data.len());
        spans.push((start, end));
        start = end;
    }
    if spans.len() >= 2 {
        let last = spans[spans.len() - 1];
        if last.1 - last.0 < MIN_CHUNK_SIZE {
            let prev = spans[spans.len() - 2];
            let remaining_start = prev.0;
            let remaining_end = last.1;
            let total = remaining_end - remaining_start;
            let first_half = total.div_ceil(2);
            spans.truncate(spans.len() - 2);
            spans.push((remaining_start, remaining_start + first_half));
            spans.push((remaining_start + first_half, remaining_end));
        }
    }
    spans
}

fn build_layers(mut nodes: Vec<Node>) -> Node {
    while nodes.len() > 1 {
        let mut next: Vec<Node> = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;
        while i < nodes.len() {
            if i + 1 < nodes.len() {
                let left = nodes[i];
                let right = nodes[i + 1];
                let id = sha384(&[
                    &sha384(&[&left.id]),
                    &sha384(&[&right.id]),
                    &sha384(&[&note_bytes(left.max_byte_range)]),
                ]);
                next.push(Node {
                    id,
                    max_byte_range: right.max_byte_range,
                });
            } else {
                next.push(nodes[i]);
            }
            i += 2;
        }
        nodes = next;
    }
    nodes[0]
}

/// Computes the `data_root` of the bytes.
///
/// Arweave node ids are 48 bytes, since they are SHA-384. In practice
/// arweave-js uses the root node's `id` as it is, and that is 48 bytes; the
/// value written into the transaction field is 48 bytes too. So nothing is
/// truncated here: the value returned is the full node id.
#[must_use]
pub fn data_root(data: &[u8]) -> [u8; 48] {
    let leaves: Vec<Node> = split_chunks(data)
        .into_iter()
        .map(|(start, end)| {
            let chunk = &data[start..end];
            let data_hash = sha384(&[chunk]);
            let id = sha384(&[&sha384(&[&data_hash]), &sha384(&[&note_bytes(end)])]);
            Node {
                id,
                max_byte_range: end,
            }
        })
        .collect();
    build_layers(leaves).id
}

/// The verdict that can be reached about an Arweave target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArweaveVerdict {
    Verified,
    RootMismatch { expected: String, produced: String },
}

/// Verifies the fetched bytes against the expected `data_root`.
#[must_use]
pub fn verify(expected_root: &[u8], data: &[u8]) -> ArweaveVerdict {
    let produced = data_root(data);
    // HIGH (CWE-354): a short expected root used to be accepted as a
    // prefix, so an attacker could brute-force content for a prefix of 1 to 47
    // bytes and raise a truncated root to the strength of full verification. A
    // truncated root is now refused: verification is granted only on exact
    // equality.
    let matches = expected_root.len() == produced.len() && expected_root == &produced[..];
    if matches {
        ArweaveVerdict::Verified
    } else {
        ArweaveVerdict::RootMismatch {
            expected: hex::encode(expected_root),
            produced: hex::encode(produced),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_chunk_root_is_the_leaf_id() {
        let data = b"budlum";
        let root = data_root(data);
        let data_hash = sha384(&[data.as_slice()]);
        let leaf = sha384(&[&sha384(&[&data_hash]), &sha384(&[&note_bytes(data.len())])]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn the_root_changes_with_one_byte() {
        assert_ne!(data_root(b"budlum"), data_root(b"budlun"));
    }

    #[test]
    fn multi_chunk_data_builds_a_tree() {
        let data = vec![7u8; MAX_CHUNK_SIZE * 2 + MIN_CHUNK_SIZE];
        let root = data_root(&data);
        // It must differ from the two-chunk case, since the chunk count changed.
        let smaller = vec![7u8; MAX_CHUNK_SIZE * 2];
        assert_ne!(root, data_root(&smaller));
    }

    #[test]
    fn a_short_tail_is_rebalanced_not_left_tiny() {
        let data = vec![3u8; MAX_CHUNK_SIZE + 10];
        let spans = split_chunks(&data);
        assert_eq!(spans.len(), 2);
        for (start, end) in spans {
            assert!(end - start >= MIN_CHUNK_SIZE, "a tiny tail was left");
        }
    }

    #[test]
    fn verify_reports_both_roots_on_mismatch() {
        let data = b"budlum";
        match verify(&[0u8; 32], data) {
            ArweaveVerdict::RootMismatch { expected, produced } => {
                assert_ne!(expected, produced);
            }
            ArweaveVerdict::Verified => panic!("a zero root should not have verified"),
        }
        assert_eq!(verify(&data_root(data), data), ArweaveVerdict::Verified);
    }

    #[test]
    fn a_truncated_expected_root_is_rejected_not_verified() {
        // The HIGH (CWE-354) regression: a truncated root of 1 to 47 bytes
        // must not be raised to Verified merely for being a prefix of the correct
        // full-length root. The 32-byte prefix of the 48-byte full root is used
        // here, and it must be refused.
        let data = vec![9u8; MAX_CHUNK_SIZE + 1];
        let full_root = data_root(&data);
        assert_eq!(full_root.len(), 48, "a fixed precondition: a 48-byte root");
        let truncated = &full_root[..32];
        match verify(truncated, &data) {
            ArweaveVerdict::RootMismatch { .. } => {}
            ArweaveVerdict::Verified => {
                panic!("a truncated root should not have been raised to Verified (CWE-354)")
            }
        }
    }
}
