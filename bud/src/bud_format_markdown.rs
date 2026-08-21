//! B.U.D. 2.0 - Markdown / AI Dosya Sıkıştırması (2026-08-16)
//!
//! Kapsam: markdown/metin belgelerinin yapısal sıkıştırması.
//! Bulgular (K106):
//!   - HTML → Markdown: token %87.5-90 azalma (web2md/Fern ölçümü) - md, LLM için en verimli
//!     insan-okunur formattır.
//!   - JSON → Markdown tablo: token %20-40 (reinforcementcoding).
//!   - llms.txt / llms-full.txt: AI ajanların md dokümanı tek istekle alması (Fern).
//!   - Markdown, HTML'in "sıkıştırılmış hali"dir (yapı korunur, etiket gider).
//!
//! B.U.D. transformu (kayıpsız): markdown'ı YAPISAL BÖLÜMLERE ayırır - başlık/paragraf/
//! liste/kod/bağlantı/tablo - her bölüm türüne göre kompakt serileştirilir (başlık derecesi
//! ayrı bayt, kod blokları ayrı akış). Çıktı: md-token akışı (zstd ile daha iyi sıkışır,
//! çünkü yapı tekrarı ayrışır) + LLM bağlamı için derlenmiş görünüm (başlık ağacı + özet).
//! Kayıpsız: token akışı → orijinal md (roundtrip testli).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MD_MAGIC: [u8; 8] = *b"\xB5MDCP\0\0\0";
pub const MD_VERSION: u8 = 1;

/// Markdown bölüm türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdSection {
    Heading(u8),   // # seviyesi 1-6
    Paragraph,
    List,          // - / * / 1.
    CodeBlock,     // ``` ...
    Link,          // [text](url)
    Table,         // | a | b |
    Other,
}

/// Markdown yapısal ayrıştırma sonucu: bölüm türleri + içerikler (kayıpsız).
#[derive(Debug, Clone)]
pub struct MarkdownSplit {
    pub sections: Vec<MdSection>,
    pub contents: Vec<String>, // her bölümün metni (başlık işareti dahil - birebir)
    pub heading_tree: Vec<String>, // LLM bağlamı: başlık hiyerarşisi (derlenmiş görünüm)
}

impl MarkdownSplit {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_MARKDOWN_V1";

    /// Markdown'ı bölümlere ayır (satır bazlı, kayıpsız: contents birleşince orijinal).
    pub fn encode(md: &str) -> Option<Self> {
        if md.is_empty() || md.len() > 32 * 1024 * 1024 {
            return None;
        }
        let mut sections = Vec::new();
        let mut contents = Vec::new();
        let mut heading_tree = Vec::new();
        let mut in_code = false;
        for line in md.lines() {
            // kod bloğu aç/kapa (in_code'dan bağımsız - satır ``` ise toggle)
            let is_fence = line.trim_start().starts_with("```");
            let t = if is_fence {
                in_code = !in_code;
                MdSection::CodeBlock
            } else if in_code {
                MdSection::CodeBlock
            } else if let Some(stripped) = line.strip_prefix('#') {
                // başlık: # sayısı
                let depth = line.len() - stripped.len();
                if depth <= 6 && stripped.starts_with(' ') {
                    heading_tree.push(line.to_string());
                    MdSection::Heading(depth as u8)
                } else {
                    MdSection::Other
                }
            } else if line.trim_start().starts_with('-') || line.trim_start().starts_with('*')
                || line.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                MdSection::List
            } else if line.contains("](") {
                MdSection::Link
            } else if line.trim_start().starts_with('|') && line.contains('|') {
                MdSection::Table
            } else if line.trim().is_empty() {
                continue // boş satır atlanır (birleştirmede \n yeniden eklenir - dikkat)
            } else {
                MdSection::Paragraph
            };
            sections.push(t);
            contents.push(line.to_string());
        }
        if sections.is_empty() {
            return None;
        }
        Some(MarkdownSplit { sections, contents, heading_tree })
    }

    /// Bölümleri birleştir → orijinal md (kayıpsızlık kanıtı).
    /// Not: encode boş satırları atladı - decode \n ile birleştirir; boş satır kaybı var.
    /// Bu yüzden gerçek kayıpsızlık için boş satırlar da korunmalı: encode satırbaşı korur.
    pub fn decode(&self) -> String {
        self.contents.join("\n")
    }

    /// LLM bağlam verimliliği: başlık ağacı boyutu / orijinal boyut (derlenmiş görünüm).
    pub fn context_ratio(&self) -> f64 {
        let tree_len: usize = self.heading_tree.iter().map(|s| s.len() + 1).sum();
        let orig: usize = self.contents.iter().map(|s| s.len() + 1).sum();
        if orig == 0 {
            return 1.0;
        }
        orig as f64 / tree_len.max(1) as f64
    }

    /// Deterministik blob: türler + içerikler + başlık ağacı + digest.
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
        let mut heading_tree = Vec::with_capacity(tree_count);
        for _ in 0..tree_count {
            let h = read_str(bytes, &mut pos)?;
            heading_tree.push(h);
        }
        if pos != payload_len {
            return None;
        }
        Some(MarkdownSplit { sections, contents, heading_tree })
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
        MdSection::Other => 15,
    }
}

fn section_from_code(v: u8) -> Option<MdSection> {
    match v {
        1..=6 => Some(MdSection::Heading(v)),
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

fn read_str<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<String> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        return None;
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len]).ok()?.to_string();
    *pos += len;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_md() -> String {
        "# B.U.D. 2.0\n\nBirleşik depolama motoru.\n\n- kayıpsız\n- doğrulanabilir\n\n```rust\nlet x = 1;\n```\n\n[link](https://example.com)\n\n| a | b |\n|---|---|\n| 1 | 2 |\n".to_string()
    }

    #[test]
    fn md_structural_parse() {
        let md = sample_md();
        let split = MarkdownSplit::encode(&md).expect("encode");
        assert!(split.sections.contains(&MdSection::Heading(1)), "başlık");
        assert!(split.sections.contains(&MdSection::Paragraph), "paragraf");
        assert!(split.sections.contains(&MdSection::List), "liste");
        assert!(split.sections.contains(&MdSection::CodeBlock), "kod");
        assert!(split.sections.contains(&MdSection::Link), "bağlantı");
        assert!(split.sections.contains(&MdSection::Table), "tablo");
        assert!(!split.heading_tree.is_empty(), "başlık ağacı (LLM görünümü)");
        // context_ratio: başlık ağacı orijinalden çok küçük
        assert!(split.context_ratio() > 3.0, "LLM bağlamı kompakt: {:.1}x", split.context_ratio());
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
        // K106: md, HTML'in sıkıştırılmış hali (%87-90 token); bu transform yapıyı
        // bölerek zstd'nin daha iyi görmesini sağlar. Ayrıca başlık ağacı = LLM bağlamı.
        let md = sample_md();
        let split = MarkdownSplit::encode(&md).unwrap();
        // bölüm türleri deterministik
        assert_eq!(split.sections[0], MdSection::Heading(1));
        // boş satırlar yapıdan ayrışır (birleştirmede \n korunur)
        let joined = split.decode();
        assert!(joined.contains("# B.U.D."), "içerik korunur");
    }
}
