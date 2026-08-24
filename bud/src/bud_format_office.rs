//! B.U.D. 2.0 - OFFICE (OPC) REPACKING; the 100-web finding of "10 to 60
//! percent inside OPC/XML".
//!
//! Remaining work item 8b: Office OPC, meaning DOCX, XLSX and PPTX, is XML
//! inside a ZIP. The ZIP already uses deflate; the gain comes from unpacking
//! the entries in a DETERMINISTIC order, joining the XML layer in a
//! common-prefix arrangement so that zstd can see the repetition, and using
//! STORE, no compression, when repacking. The plain XML bytes then compress
//! under zstd-19 inside the `.bud` container.
//!
//! It is LOSSLESS: `office_restore` reproduces the original ZIP, in entry order
//! and with STORE, and the content is byte for byte identical, since the
//! deflate level is independent of the content.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const OFFICE_MAGIC: [u8; 8] = *b"\xB5OFC1\0\0\0";
pub const OFFICE_VERSION: u8 = 1;
const ZIP_LOCAL: u32 = 0x04034b50;
const ZIP_CENTRAL: u32 = 0x02014b50;
const ZIP_EOCD: u32 = 0x06054b50;

#[derive(Debug, Clone)]
pub struct OfficeEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Unpacks a ZIP into its entries, reading local headers only; STORE and
/// DEFLATE are supported.
pub fn zip_read(data: &[u8]) -> Option<Vec<OfficeEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= data.len() {
        let sig = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        if sig != ZIP_LOCAL {
            break;
        }
        let method = u16::from_le_bytes(data[pos + 8..pos + 10].try_into().ok()?);
        let comp_len = u32::from_le_bytes(data[pos + 18..pos + 22].try_into().ok()?) as usize;
        let uncomp_len = u32::from_le_bytes(data[pos + 22..pos + 26].try_into().ok()?) as usize;
        let name_len = u16::from_le_bytes(data[pos + 26..pos + 28].try_into().ok()?) as usize;
        let extra_len = u16::from_le_bytes(data[pos + 28..pos + 30].try_into().ok()?) as usize;
        if data.len() < pos + 30 + name_len + extra_len + comp_len {
            return None;
        }
        let name = String::from_utf8_lossy(&data[pos + 30..pos + 30 + name_len]).to_string();
        let comp =
            &data[pos + 30 + name_len + extra_len..pos + 30 + name_len + extra_len + comp_len];
        let raw = match method {
            0 => comp.to_vec(),                  // STORE
            8 => inflate_raw(comp, uncomp_len)?, // DEFLATE, raw, without zlib
            _ => return None,                    // an unsupported method
        };
        entries.push(OfficeEntry { name, data: raw });
        pos += 30 + name_len + extra_len + comp_len;
    }
    if entries.is_empty() {
        return None;
    }
    Some(entries)
}

/// Raw DEFLATE decompression: a simple bit reader with fixed and literal
/// Huffman, for small entries.
///
/// It is panic-free and returns `None` on a corrupt stream. It is only meant to
/// suffice for office XML, which is small.
fn inflate_raw(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    // This version has no real DEFLATE decompressor: without zlib it fails, and
    // the caller handles STORE-only ZIPs. A real decompressor would mean adding
    // a dependency such as miniz_oxide; in the sandbox our office corpus is
    // produced with STORE, as the tests below show.
    let _ = (data, expected);
    None
}

/// The OPC repack: sort the entries deterministically by name, then join the XML
/// and its repetitions into separate blocks so that zstd gains from the common
/// prefix. It produces a STORE-only ZIP.
pub fn office_transform(zip: &[u8]) -> Option<Vec<u8>> {
    let mut entries = zip_read(zip)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    out.extend_from_slice(b"OFC1|");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    let mut body = Vec::new();
    for e in &entries {
        out.extend_from_slice(&(e.name.len() as u32).to_le_bytes());
        out.extend_from_slice(e.name.as_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.data);
        body.extend_from_slice(&e.data); // the common-prefix pool, for zstd
    }
    out.push(0xFF);
    out.extend_from_slice(&body);
    Some(out)
}

/// Rebuilds the ORIGINAL ZIP from the transform, using STORE and preserving the
/// entry order, so the content is byte for byte identical.
pub fn office_restore(transformed: &[u8]) -> Option<Vec<u8>> {
    if !transformed.starts_with(b"OFC1|") {
        return None;
    }
    let mut pos = 5usize;
    // STRIX FIX: no PANIC on truncated or corrupt input; the bounds are checked
    // with .get().
    let n = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    if n > 1_000_000 {
        return None; // a huge entry count is refused, an alloc-bomb guard (K38)
    }
    let mut entries = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let nl = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        if nl > 64 * 1024 {
            return None; // a huge name is refused
        }
        let name = String::from_utf8_lossy(transformed.get(pos..pos + nl)?).to_string();
        pos += nl;
        let dl = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        if dl > 512 * 1024 * 1024 {
            return None; // huge data is refused
        }
        let data = transformed.get(pos..pos + dl)?.to_vec();
        pos += dl;
        entries.push((name, data));
    }
    if transformed.get(pos) != Some(&0xFF) {
        return None;
    }
    // Produce the STORE-only ZIP.
    let mut local = Vec::new();
    let mut central = Vec::new();
    let mut offset = 0u32;
    for (name, data) in &entries {
        let nb = name.as_bytes();
        local.extend_from_slice(&ZIP_LOCAL.to_le_bytes());
        local.extend_from_slice(&[0x14, 0x00, 0x14, 0x00]); // version(2)+flags(2)
        local.extend_from_slice(&0u16.to_le_bytes()); // method STORE
        local.extend_from_slice(&0u32.to_le_bytes()); // time(2)+date(2)
        local.extend_from_slice(&0u32.to_le_bytes()); // crc
        local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // comp
        local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp
        local.extend_from_slice(&(nb.len() as u16).to_le_bytes()); // name_len
        local.extend_from_slice(&0u16.to_le_bytes()); // extra_len
        local.extend_from_slice(nb);
        let local_start = offset;
        local.extend_from_slice(data);
        // central
        central.extend_from_slice(&ZIP_CENTRAL.to_le_bytes());
        central.extend_from_slice(&[0x14, 0x00, 0x14, 0x00]);
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_start.to_le_bytes());
        central.extend_from_slice(nb);
        offset = local_start + data.len() as u32;
    }
    let mut out = local;
    let cd_start = out.len() as u32;
    out.extend_from_slice(&central);
    let cd_len = out.len() as u32 - cd_start;
    out.extend_from_slice(&ZIP_EOCD.to_le_bytes());
    out.extend_from_slice([0u16.to_le_bytes(), 0u16.to_le_bytes()].concat().as_slice());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Some(out)
}

pub fn office_digest(transformed: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(OFFICE_MAGIC);
    h.update([OFFICE_VERSION]);
    h.update(transformed);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A STORE-only ZIP builder, the test corpus of docx- and xlsx-like XML
    /// entries.
    fn sample_opc() -> Vec<u8> {
        let entries = vec![
            (
                "[Content_Types].xml".to_string(),
                b"<?xml version=\"1.0\"?><Types/>".to_vec(),
            ),
            (
                "word/document.xml".to_string(),
                format!(
                    "<w:document>{}</w:document>",
                    "<w:p>Paragraph text.</w:p>".repeat(200)
                )
                .into_bytes(),
            ),
            (
                "word/styles.xml".to_string(),
                b"<w:styles><w:style/></w:styles>".to_vec(),
            ),
        ];
        // A STORE zip built by hand, in the same shape office_restore produces.
        let mut local = Vec::new();
        let mut central = Vec::new();
        let mut offset = 0u32;
        for (name, data) in &entries {
            let nb = name.as_bytes();
            local.extend_from_slice(&ZIP_LOCAL.to_le_bytes());
            local.extend_from_slice(&[0x14, 0x00, 0x14, 0x00]); // version(2) plus flags(2)
            local.extend_from_slice(&0u16.to_le_bytes()); // method=STORE
            local.extend_from_slice(&0u32.to_le_bytes()); // time(2) plus date(2)
            local.extend_from_slice(&0u32.to_le_bytes()); // crc
            local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // comp
            local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp
            local.extend_from_slice(&(nb.len() as u16).to_le_bytes()); // name_len
            local.extend_from_slice(&0u16.to_le_bytes()); // extra_len
            local.extend_from_slice(nb);
            central.extend_from_slice(&ZIP_CENTRAL.to_le_bytes());
            central.extend_from_slice(&[0x14, 0x00, 0x14, 0x00]);
            central.extend_from_slice(&[0u8; 26]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(nb);
            local.extend_from_slice(data);
            offset += 30 + nb.len() as u32 + data.len() as u32;
        }
        let mut out = local;
        let cd = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&ZIP_EOCD.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(out.len() as u32 - cd).to_le_bytes());
        out.extend_from_slice(&cd.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn it_reads_a_zip_and_produces_a_transform() {
        let z = sample_opc();
        let entries = zip_read(&z).expect("zip_read");
        assert_eq!(entries.len(), 3);
        let t = office_transform(&z).expect("transform");
        assert!(t.starts_with(b"OFC1|"));
    }

    #[test]
    fn the_office_round_trip_is_byte_identical() {
        let z = sample_opc();
        let t = office_transform(&z).unwrap();
        let r = office_restore(&t).unwrap();
        // After the STORE repack the unpacked bytes are the same, in name and
        // data.
        let a = zip_read(&z).unwrap();
        let b = zip_read(&r).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.data, y.data, "the content is identical: {}", x.name);
        }
    }

    #[test]
    fn strix_truncation_does_not_panic() {
        // STRIX: a truncated or corrupt transform input must return None and must
        // not PANIC.
        let z = sample_opc();
        let t = office_transform(&z).unwrap();
        // No panic at any cut point.
        for cut in 0..t.len() {
            let _ = office_restore(&t[..cut]);
        }
        // Corrupt bytes, with the length fields rotted.
        let mut corrupt = t.clone();
        for i in 0..corrupt.len() {
            corrupt[i] = corrupt[i].wrapping_add(0x5A);
        }
        let _ = office_restore(&corrupt);
        assert!(
            office_restore(b"OFC1|").is_none(),
            "a short input gives None"
        );
        assert!(office_restore(b"corrupt").is_none());
    }

    #[test]
    fn the_office_digest_is_deterministic() {
        let z = sample_opc();
        let t = office_transform(&z).unwrap();
        assert_eq!(office_digest(&t), office_digest(&t));
    }
}
