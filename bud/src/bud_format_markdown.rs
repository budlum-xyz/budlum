//! B.U.D. 2.0 - markdown / AI file compression (2026-08-16)
//!
//! Scope: structural compression of markdown/text documents.
//! Bulgular (K106):
//!   - HTML -> markdown: 87.5-90 percent token reduction (web2md/Fern measurement) - md is the most efficient
//!     human-readable format for an LLM.
//!   - JSON → Markdown tablo: token %20-40 (reinforcementcoding).
//!   - llms.txt / llms-full.txt: AI agents fetch the md document in a single request (Fern).
//!   - Markdown is the compressed form of HTML (structure is kept, tags go away).
//!
//! The B.U.D. transform (lossless) splits markdown into STRUCTURAL SECTIONS - heading/paragraph/
//! list/code/link/table - each section type is serialized compactly (heading level as a
//! separate byte, code blocks as a separate stream). Output: an md-token stream (compresses better with zstd,
//! because structural repetition separates out) plus a compiled view for LLM context (heading tree + digest).
//! Lossless: token stream -> original md (roundtrip tested). Blank lines are carried as
//! sections too (`MdSection::Blank`) and the trailing newline lives in a separate
//! flag; both are separators in markdown, and dropping them means the document cannot be restored.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MD_MAGIC: [u8; 8] = *b"\xB5MDCP\0\0\0";
pub const MD_VERSION: u8 = 2;

/// Markdown section type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdSection {
    Heading(u8), // # seviyesi 1-6
    Paragraph,
    List,      // - / * / 1.
    CodeBlock, // ``` ...
    Link,      // [text](url)
    Table,     // | a | b |
    Blank,     // blank line: a separator; dropping it loses the document
    Other,
}

/// The result of structural markdown parsing: section types + contents (lossless).
#[derive(Debug, Clone)]
pub struct MarkdownSplit {
    pub sections: Vec<MdSection>,
    pub contents: Vec<String>, // the text of each section (including the heading marker - verbatim)
    pub heading_tree: Vec<String>, // LLM context: the heading hierarchy (compiled view)
    /// Whether the input ended with a newline. `str::lines` swallows this; it must be carried
    /// separately for losslessness.
    pub trailing_newline: bool,
}

impl MarkdownSplit {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_MARKDOWN_V1";

    /// Split markdown into sections (line based, lossless: joining contents gives the original).
    pub fn encode(md: &str) -> Option<Self> {
        if md.is_empty() || md.len() > 32 * 1024 * 1024 {
            return None;
        }
        let mut sections = Vec::new();
        let mut contents = Vec::new();
        let mut heading_tree = Vec::new();
        let mut in_code = false;
        for line in md.lines() {
            // open/close a code block (independent of in_code - toggle when the line is ```)
            let is_fence = line.trim_start().starts_with("```");
            let t = if is_fence {
                in_code = !in_code;
                MdSection::CodeBlock
            } else if in_code {
                MdSection::CodeBlock
            } else if let Some(stripped) = line.strip_prefix('#') {
                // heading: the number of #
                let depth = line.len() - stripped.len();
                if depth <= 6 && stripped.starts_with(' ') {
                    heading_tree.push(line.to_string());
                    MdSection::Heading(depth as u8)
                } else {
                    MdSection::Other
                }
            } else if line.trim_start().starts_with('-')
                || line.trim_start().starts_with('*')
                || line.trim_start().starts_with(|c: char| c.is_ascii_digit())
            {
                MdSection::List
            } else if line.contains("](") {
                MdSection::Link
            } else if line.trim_start().starts_with('|') && line.contains('|') {
                MdSection::Table
            } else if line.trim().is_empty() {
                // A blank line is a separator in markdown: it separates paragraph from paragraph,
                // and list from list. If dropped, `decode` cannot return the
                // cannot restore, and the module claim of losslessness becomes false. As a type
                // is recorded, and so is its content verbatim (inline whitespace included).
                MdSection::Blank
            } else {
                MdSection::Paragraph
            };
            sections.push(t);
            contents.push(line.to_string());
        }
        if sections.is_empty() {
            return None;
        }
        let trailing_newline = md.ends_with('\n');
        Some(MarkdownSplit {
            sections,
            contents,
            heading_tree,
            trailing_newline,
        })
    }

    /// Join the sections. Returns the input of `encode` byte for byte.
    ///
    /// `str::lines` swallows a trailing newline, so its presence is recorded
    /// is carried: otherwise "a\n" and "a" produce the same section list and one of them
    /// otekine donusur.
    #[must_use]
    pub fn decode(&self) -> String {
        let mut out = self.contents.join("\n");
        if self.trailing_newline {
            out.push('\n');
        }
        out
    }

    /// LLM context efficiency: heading tree size / original size (compiled view).
    pub fn context_ratio(&self) -> f64 {
        let tree_len: usize = self.heading_tree.iter().map(|s| s.len() + 1).sum();
        let orig: usize = self.contents.iter().map(|s| s.len() + 1).sum();
        if orig == 0 {
            return 1.0;
        }
        orig as f64 / tree_len.max(1) as f64
    }

    /// Deterministic blob: types + contents + heading tree + digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MD_MAGIC);
        out.push(MD_VERSION);
        out.extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        for (t, c) in self.sections.iter().zip(self.contents.iter()) {
            out.push(section_code(*t));
            push_str(&mut out, c);
        }
        out.extend_from_slice(&(self.heading_tree.len() as u32).to_le_bytes());
        for h in &self.heading_tree {
            push_str(&mut out, h);
        }
        // The trailing newline: `str::lines` swallows it and it cannot be recovered from the
        // cannot be derived, so it enters the blob as a separate byte.
        out.push(u8::from(self.trailing_newline));
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != MD_MAGIC || bytes[8] != MD_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&bytes[..payload_len]);
        if h.finalize().as_slice() != &bytes[payload_len..] {
            return None;
        }
        let count = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let mut pos = HDR;
        // `count` is an ATTACKER-CONTROLLED number, and handed straight to
        // `with_capacity` a 45-byte blob produces an 8.6 GB allocation request (measured:
        // "memory allocation of 8589934590 bytes failed" -> SIGABRT; crate
        // with panic="abort" the node dies instantly). The SHA3 above
        // integrity check above does NOT prevent this: the digest is keyless and
        // DOMAIN is a public constant, so producing a blob with a valid digest is free.
        //
        // The ceiling is derived from the input's OWN length: each section consumes at least 1 byte
        // of type + 4 bytes of length = 5 bytes. That keeps allocation always
        // proportional to the input, with no separate magic constant to maintain.
        if count > payload_len.saturating_sub(pos) / 5 {
            return None;
        }
        let mut sections = Vec::with_capacity(count);
        let mut contents = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < pos + 1 {
                return None;
            }
            let t = section_from_code(bytes[pos])?;
            pos += 1;
            let c = read_str(bytes, &mut pos)?;
            sections.push(t);
            contents.push(c);
        }
        if bytes.len() < pos + 4 {
            return None;
        }
        let tree_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        // Same rationale: each heading consumes at least a 4-byte length field.
        if tree_count > payload_len.saturating_sub(pos) / 4 {
            return None;
        }
        let mut heading_tree = Vec::with_capacity(tree_count);
        for _ in 0..tree_count {
            let h = read_str(bytes, &mut pos)?;
            heading_tree.push(h);
        }
        if bytes.len() < pos + 1 {
            return None;
        }
        let trailing_newline = match bytes[pos] {
            0 => false,
            1 => true,
            // A single correct encoding: bytes of 2 and above are refused, otherwise the same
            // document would have several valid blobs and the digest would not be unique.
            _ => return None,
        };
        pos += 1;
        if pos != payload_len {
            return None;
        }
        Some(MarkdownSplit {
            sections,
            contents,
            heading_tree,
            trailing_newline,
        })
    }
}

fn section_code(t: MdSection) -> u8 {
    match t {
        MdSection::Heading(d) => d, // 1-6
        MdSection::Paragraph => 10,
        MdSection::List => 11,
        MdSection::CodeBlock => 12,
        MdSection::Link => 13,
        MdSection::Table => 14,
        MdSection::Blank => 9,
        MdSection::Other => 15,
    }
}

fn section_from_code(v: u8) -> Option<MdSection> {
    match v {
        1..=6 => Some(MdSection::Heading(v)),
        9 => Some(MdSection::Blank),
        10 => Some(MdSection::Paragraph),
        11 => Some(MdSection::List),
        12 => Some(MdSection::CodeBlock),
        13 => Some(MdSection::Link),
        14 => Some(MdSection::Table),
        15 => Some(MdSection::Other),
        _ => None,
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        return None;
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len])
        .ok()?
        .to_string();
    *pos += len;
    Some(s)
}

#[cfg(test)]
mod tests {

    /// RAM AUDIT (2026-08-21): a small blob with an inflated `count` field
    /// triggered an enormous pre-allocation even though the body held nothing
    /// matching it.
    /// Measured: a 45-byte input -> an 8,589,934,590-byte allocation request ->
    /// SIGABRT (the crate uses panic="abort"). The SHA3 integrity field does NOT
    /// protect: the digest is keyless and the DOMAIN constant is public, so a
    /// blob with a valid digest can be produced.
    #[test]
    fn an_inflated_section_count_is_refused_before_any_allocation() {
        use sha3::{Digest, Sha3_256};
        let mut b = Vec::new();
        b.extend_from_slice(&MD_MAGIC);
        b.push(MD_VERSION);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut h = Sha3_256::new();
        h.update(MarkdownSplit::DOMAIN);
        h.update(&b);
        b.extend_from_slice(&h.finalize());

        // The digest is VALID -- so the refusal must come from the ceiling, not a broken digest.
        assert!(
            MarkdownSplit::from_blob(&b).is_none(),
            "a u32::MAX section count with no body must be refused"
        );
    }

    /// Canary: the ceiling must not refuse valid input (an over-tightening check).
    #[test]
    fn gercek_markdown_tavandan_etkilenmez() {
        let md = "# Heading\n\nParagraph text.\n\n## Subheading\n\n- item\n";
        let split = MarkdownSplit::encode(md).expect("encode");
        let blob = split.to_blob();
        let back = MarkdownSplit::from_blob(&blob).expect("a valid blob must be accepted");
        assert_eq!(back.sections, split.sections, "section types are identical");
        assert_eq!(
            back.contents, split.contents,
            "section contents are identical"
        );
        assert_eq!(
            back.heading_tree, split.heading_tree,
            "the heading tree is identical"
        );
    }

    /// Losslessness: `encode` -> `decode` returns the input byte for byte.
    ///
    /// In the previous version `encode` dropped blank lines with `continue` and a
    /// test locked that loss as a known limitation. But the module docs say lossless in three
    /// places and the type is exported from `lib.rs`: a caller could believe
    /// it. Instead of locking the limitation, the limitation was removed.
    ///
    /// A blank line is a separator in markdown - it separates paragraph from paragraph and list
    /// from list - so what is dropped is meaning, not formatting.
    #[test]
    fn the_markdown_transform_returns_byte_for_byte() {
        let cases = [
            "# Heading\n\nParagraph text.\n\n## Subheading\n\n- item\n",
            "# Heading\n\nParagraph text.\n\n## Subheading\n\n- item",
            "a single line",
            "a single line\n",
            "\n\n\nconsecutive blank lines\n\n\n",
            "# B\n\n```rust\nlet x = 1;\n\nlet y = 2;\n```\n\nend\n",
            "   \na blank line with spaces is preserved\n",
        ];
        for md in cases {
            let split = MarkdownSplit::encode(md).expect("encode");
            assert_eq!(
                split.decode(),
                md,
                "encode/decode must be byte for byte: {md:?}"
            );
            // The blob path must return the same document.
            let blob = split.to_blob();
            let back = MarkdownSplit::from_blob(&blob).expect("valid blob");
            assert_eq!(
                back.decode(),
                md,
                "the blob path must be lossless too: {md:?}"
            );
        }
    }

    /// Evidence that the separator is carried: two different documents must not fall into the same
    /// section list. Had the blank line been dropped these two would be indistinguishable.
    #[test]
    fn a_blank_line_keeps_two_documents_apart() {
        let a = MarkdownSplit::encode("bir\n\niki\n").expect("encode");
        let b = MarkdownSplit::encode("bir\niki\n").expect("encode");
        assert_ne!(
            a.contents, b.contents,
            "the blank line must appear in the contents"
        );
        assert_ne!(
            a.to_blob(),
            b.to_blob(),
            "two documents must not fall into the same blob"
        );
        assert_eq!(a.decode(), "bir\n\niki\n");
        assert_eq!(b.decode(), "bir\niki\n");
    }

    /// A trailing newline on its own separates a document.
    #[test]
    fn a_trailing_newline_enters_the_blob() {
        let a = MarkdownSplit::encode("metin\n").expect("encode");
        let b = MarkdownSplit::encode("metin").expect("encode");
        assert_eq!(a.contents, b.contents, "the section lists are the same");
        assert_ne!(a.to_blob(), b.to_blob(), "but the blobs must differ");
        assert!(a.trailing_newline && !b.trailing_newline);
    }
    use super::*;

    fn sample_md() -> String {
        "# B.U.D. 2.0\n\nUnified storage engine.\n\n- lossless\n- verifiable\n\n```rust\nlet x = 1;\n```\n\n[link](https://example.com)\n\n| a | b |\n|---|---|\n| 1 | 2 |\n".to_string()
    }

    #[test]
    fn md_structural_parse() {
        let md = sample_md();
        let split = MarkdownSplit::encode(&md).expect("encode");
        assert!(split.sections.contains(&MdSection::Heading(1)), "heading");
        assert!(split.sections.contains(&MdSection::Paragraph), "paragraf");
        assert!(split.sections.contains(&MdSection::List), "liste");
        assert!(split.sections.contains(&MdSection::CodeBlock), "kod");
        assert!(split.sections.contains(&MdSection::Link), "link");
        assert!(split.sections.contains(&MdSection::Table), "tablo");
        assert!(!split.heading_tree.is_empty(), "heading tree (LLM view)");
        // context_ratio: the heading tree is far smaller than the original
        assert!(
            split.context_ratio() > 3.0,
            "LLM context is compact: {:.1}x",
            split.context_ratio()
        );
    }

    #[test]
    fn md_blob_roundtrip() {
        let md = sample_md();
        let split = MarkdownSplit::encode(&md).expect("encode");
        let blob = split.to_blob();
        let back = MarkdownSplit::from_blob(&blob).expect("blob");
        assert_eq!(back.sections.len(), split.sections.len());
        assert_eq!(back.heading_tree, split.heading_tree);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(MarkdownSplit::from_blob(&bad).is_none());
        assert!(MarkdownSplit::from_blob(&[0u8; 10]).is_none());
        assert!(MarkdownSplit::encode("").is_none());
    }

    #[test]
    fn md_token_efficiency_documented() {
        // K106: md is the compressed form of HTML (87-90 percent of tokens); this transform splits the
        // structure so zstd sees it better. The heading tree also doubles as LLM context.
        let md = sample_md();
        let split = MarkdownSplit::encode(&md).unwrap();
        // section types are deterministic
        assert_eq!(split.sections[0], MdSection::Heading(1));
        // blank lines separate out of the structure (the \n is kept when joining)
        let joined = split.decode();
        assert!(joined.contains("# B.U.D."), "content is preserved");
    }
}
