//! The README definition block is byte-for-byte the one the directive states.
//!
//! # What this protects
//!
//! `README.md` lines 1 to 14 are the project's definition: the opening image,
//! the two sentences that say what Budlum is, and the paragraph that says what
//! "consensus of consensuses" means. `README.tr.md` lines 1 to 15 are the same
//! block in Turkish. The directive carries both blocks and states a SHA-256
//! digest of each, computed over the LF line endings:
//!
//! ```text
//! README.md      1..14  dd9be5206be37e05a39e26d002af633c23f56be7378bc8dfe10861406f063467
//! README.tr.md   1..15  c883e0017f8c96de3ce27d863bc2b8625685b761ecef08e3af72284473c903fe
//! ```
//!
//! # Why a digest and not a reader
//!
//! The definition is the one part of the tree a translation pass, a badge
//! update or a "tighten the wording" edit can quietly change, and every such
//! edit reads as an improvement while it is being made. Pinning the bytes means
//! the change is a decision with a red gate attached, not a side effect. The
//! block is compared as bytes, so a change of a single character fails, and a
//! file with CRLF endings fails too: it is not the block the directive states.
//!
//! An image is referenced in the block but not scanned: the digest covers the
//! text, and a missing image is `docs-links-resolve`'s finding, not this one.

use std::fmt::Write as _;
use std::path::Path;

/// One pinned block: the file, how many leading lines it covers, and the digest
/// the directive states for it.
struct Block {
    file: &'static str,
    lines: usize,
    sha256: &'static str,
}

/// The two blocks, from the specification appendices.
const BLOCKS: &[Block] = &[
    Block {
        file: "README.md",
        lines: 14,
        sha256: "dd9be5206be37e05a39e26d002af633c23f56be7378bc8dfe10861406f063467",
    },
    Block {
        file: "README.tr.md",
        lines: 15,
        sha256: "c883e0017f8c96de3ce27d863bc2b8625685b761ecef08e3af72284473c903fe",
    },
];

/// The first `n` lines of `text` with LF endings, the trailing newline
/// included.
///
/// The block is a prefix of the file, so it is cut at the `n`-th newline
/// rather than rebuilt from `lines()`: rebuilding would normalise a CRLF file
/// into a match, which is exactly the edit this gate exists to refuse.
fn block_bytes(text: &str, n: usize) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut seen = 0usize;
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            seen += 1;
            if seen == n {
                return Some(bytes[..=i].to_vec());
            }
        }
    }
    None
}

/// The digest of a file's pinned block, or why it has none.
fn block_digest(root: &Path, block: &Block) -> Result<String, String> {
    let path = root.join(block.file);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("{} could not be read: {e}", block.file))?;
    let bytes = block_bytes(&text, block.lines).ok_or_else(|| {
        format!(
            "{} has fewer than {} lines, so the definition block is not there at all",
            block.file, block.lines
        )
    })?;
    Ok(crate::sha256::hex_digest(&bytes))
}

/// Run the gate.
///
/// # Errors
///
/// A block whose bytes differ from the pinned digest, or a file that is gone.
pub fn run(root: &Path) -> Result<String, String> {
    let mut wrong = Vec::new();
    for block in BLOCKS {
        match block_digest(root, block) {
            Ok(digest) if digest == block.sha256 => {}
            Ok(digest) => wrong.push((block, digest)),
            Err(finding) => return Err(format!("FAIL: {finding}")),
        }
    }
    if !wrong.is_empty() {
        let mut msg = String::from(
            "FAIL: the README definition block is not the text the directive states.\n\
             These lines are the project's definition and are pinned byte for byte,\n\
             so a wording change here is a decision, not an edit:\n",
        );
        for (block, digest) in &wrong {
            let _ = writeln!(
                msg,
                "  - {} lines 1..{}: digest {} , pinned {}",
                block.file, block.lines, digest, block.sha256
            );
        }
        msg.push_str(
            "\nIf the change is intended, the directive's Appendix A and Appendix B\n\
             must state the new digest in the same change; the gate reads its pins\n\
             from this file, so both move together with the reason written down.\n\
             A CRLF line ending is also a difference: the digest is over LF.",
        );
        return Err(msg);
    }
    let mut ok = String::from("readme-definition-block-is-verbatim OK: ");
    for (i, block) in BLOCKS.iter().enumerate() {
        if i > 0 {
            ok.push_str(", ");
        }
        let _ = write!(ok, "{} 1..{}", block.file, block.lines);
    }
    ok.push_str(" match their pinned digests.");
    Ok(ok)
}

/// The canary: every way the block can move must be caught.
///
/// # Errors
///
/// When the gate does not behave.
pub fn self_test() -> Result<String, String> {
    let dir = crate::gates::rust_literals::exclusive_scratch_dir("budlum-gates-readme-block")?;
    let result = (|| {
        let body = |n: usize| -> String {
            (1..=n).map(|i| format!("line {i}\n")).collect::<String>()
        };
        let pinned = crate::sha256::hex_digest(body(3).as_bytes());
        let put = |rel: &str, text: &str| -> Result<(), String> {
            std::fs::write(dir.join(rel), text).map_err(|e| e.to_string())
        };
        put("README.md", &format!("{}line 4\n", body(3)))?;
        // The block digest and the block cut agree on a clean file.
        let cut = block_bytes(&body(3), 3).ok_or("canary: a clean block was not cut")?;
        if crate::sha256::hex_digest(&cut) != pinned {
            return Err(String::from("canary: the prefix cut lost a byte"));
        }
        // One changed character inside the block is a different digest.
        let edited = "line 1\nLINE 2\nline 3\n";
        if block_bytes(edited, 3).map(|b| crate::sha256::hex_digest(&b)) == Some(pinned.clone()) {
            return Err(String::from(
                "canary: a case change inside the block produced the pinned digest",
            ));
        }
        // A CRLF file is not the same block.
        let crlf = "line 1\r\nline 2\r\nline 3\r\n";
        if block_bytes(crlf, 3).map(|b| crate::sha256::hex_digest(&b)) == Some(pinned.clone()) {
            return Err(String::from(
                "canary: CRLF line endings produced the pinned digest",
            ));
        }
        // A block that is not there is a finding, not a pass.
        if block_bytes("line 1\nline 2\n", 3).is_some() {
            return Err(String::from(
                "canary: a file shorter than its block was cut anyway",
            ));
        }
        // A missing README is a finding.
        std::fs::remove_file(dir.join("README.md")).map_err(|e| e.to_string())?;
        if block_digest(&dir, &BLOCKS[0]).is_ok() {
            return Err(String::from(
                "canary: a missing README.md was reported as a block",
            ));
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(String::from(
        "readme-definition-block-is-verbatim canary OK: one changed character, a CRLF \
         file, a short file and a missing file all fail; a clean block passes.",
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn readme_definition_block_is_verbatim() {
        assert!(super::self_test().is_ok(), "{:?}", super::self_test());
    }
}
