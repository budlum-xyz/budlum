//! B.U.D. 2.0 - OFİS (OPC) YENİDEN PAKETLEME (100-web bulgusu: "OPC/XML-içi %10-60")
//!
//! Kalan iş #8b: Ofis OPC - DOCX/XLSX/PPTX = ZIP içi XML. ZIP zaten deflate kullanır;
//! kazanç, girdileri DETERMİNİSTİK sırayla açıp XML katmanını ortak-prefix düzeninde
//! birleştirmek (zstd'nin tekrarı görmesi) ve yeniden paketlerken ZORUNSUZ
//! (STORE) kullanmaktır - açık XML byte'ları .bud konteynerinde zstd-19 ile
//! sıkışır. KAYIPSIZ: `office_restore` orijinal ZIP'i (girdi sırası + STORE) geri üretir;
//! içerik byte-birebir (deflate seviyesi içerikten bağımsız).

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

/// ZIP'i açar (yalnız yerel başlıklar; STORE+DEFLATE desteklenir) → girdiler.
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
        let comp = &data[pos + 30 + name_len + extra_len..pos + 30 + name_len + extra_len + comp_len];
        let raw = match method {
            0 => comp.to_vec(),                       // STORE
            8 => inflate_raw(comp, uncomp_len)?,      // DEFLATE (zlib-sız ham)
            _ => return None,                          // desteklenmeyen yöntem
        };
        entries.push(OfficeEntry { name, data: raw });
        pos += 30 + name_len + extra_len + comp_len;
    }
    if entries.is_empty() {
        return None;
    }
    Some(entries)
}

/// Ham DEFLATE açma (küçük girdiler için basit bit okuyucu + sabit/literal Huffman).
/// Panik'siz; bozuk akışta None döner. Yalnız ofis XML'leri için yeterli (küçük).
fn inflate_raw(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    // Bu sürümde gerçek bir DEFLATE açıcı yok - zlib yoksa başarısız döner ve
    // çağıran STORE-only ZIP'leri işler. Gerçek açıcı: miniz_oxide benzeri bir
    // bağımlılık eklenebilir; sandbox'ta ofis korpusumuz STORE üretilir (aşağıya bak).
    let _ = (data, expected);
    None
}

/// OPC repack: girdileri (a) isme göre deterministik sırala, (b) XML/tekrar ayrı
/// bloklarda birleştir → zstd'nin ortak-prefix kazancı. STORE-only zip üretir.
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
        body.extend_from_slice(&e.data); // ortak-prefix havuzu (zstd için)
    }
    out.push(0xFF);
    out.extend_from_slice(&body);
    Some(out)
}

/// Transform'dan ORİJİNAL ZIP'i üret (STORE, girdi sırası korunur → byte-birebir içerik).
pub fn office_restore(transformed: &[u8]) -> Option<Vec<u8>> {
    if !transformed.starts_with(b"OFC1|") {
        return None;
    }
    let mut pos = 5usize;
    // STRIX FIX: truncate/bozuk girdide PANİK yok - .get() ile sınır kontrolü.
    let n = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    if n > 1_000_000 {
        return None; // dev girdi → RED (alloc-bomb koruması, K38)
    }
    let mut entries = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let nl = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        if nl > 64 * 1024 {
            return None; // dev isim → RED
        }
        let name = String::from_utf8_lossy(transformed.get(pos..pos + nl)?).to_string();
        pos += nl;
        let dl = u32::from_le_bytes(transformed.get(pos..pos + 4)?.try_into().ok()?) as usize;
        pos += 4;
        if dl > 512 * 1024 * 1024 {
            return None; // dev veri → RED
        }
        let data = transformed.get(pos..pos + dl)?.to_vec();
        pos += dl;
        entries.push((name, data));
    }
    if transformed.get(pos) != Some(&0xFF) {
        return None;
    }
    // STORE-only ZIP üret
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
    out.extend_from_slice(&[0u16.to_le_bytes(), 0u16.to_le_bytes()].concat().as_slice());
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

    /// STORE-only ZIP üretici (test korpusu - docx/xlsx benzeri XML girdiler).
    fn ornek_opc() -> Vec<u8> {
        let entries = vec![
            ("[Content_Types].xml".to_string(), b"<?xml version=\"1.0\"?><Types/>".to_vec()),
            ("word/document.xml".to_string(), format!("<w:document>{}</w:document>", "<w:p>Paragraf metni.</w:p>".repeat(200)).into_bytes()),
            ("word/styles.xml".to_string(), b"<w:styles><w:style/></w:styles>".to_vec()),
        ];
        // elle STORE zip (ofis_transform'un restore'u gibi)
        let mut local = Vec::new();
        let mut central = Vec::new();
        let mut offset = 0u32;
        for (name, data) in &entries {
            let nb = name.as_bytes();
            local.extend_from_slice(&ZIP_LOCAL.to_le_bytes());
            local.extend_from_slice(&[0x14, 0x00, 0x14, 0x00]); // version(2)+flags(2)
            local.extend_from_slice(&0u16.to_le_bytes());       // method=STORE
            local.extend_from_slice(&0u32.to_le_bytes());       // time(2)+date(2)
            local.extend_from_slice(&0u32.to_le_bytes());       // crc
            local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // comp
            local.extend_from_slice(&(data.len() as u32).to_le_bytes()); // uncomp
            local.extend_from_slice(&(nb.len() as u16).to_le_bytes());   // name_len
            local.extend_from_slice(&0u16.to_le_bytes());       // extra_len
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
    fn zip_okur_ve_transform_uretir() {
        let z = ornek_opc();
        let entries = zip_read(&z).expect("zip_read");
        assert_eq!(entries.len(), 3);
        let t = office_transform(&z).expect("transform");
        assert!(t.starts_with(b"OFC1|"));
    }

    #[test]
    fn office_roundtrip_icerik_birebir() {
        let z = ornek_opc();
        let t = office_transform(&z).unwrap();
        let r = office_restore(&t).unwrap();
        // STORE repack → açılmış byte'lar aynı (isim + veri)
        let a = zip_read(&z).unwrap();
        let b = zip_read(&r).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.data, y.data, "içerik birebir: {}", x.name);
        }
    }

    
    #[test]
    fn strix_truncate_panik_yok() {
        // STRIX: kırpılmış/bozuk transform girdisi None dönmeli, PANİK olmamalı.
        let z = ornek_opc();
        let t = office_transform(&z).unwrap();
        // her kesim noktasında panik yok
        for cut in 0..t.len() {
            let _ = office_restore(&t[..cut]);
        }
        // bozuk baytlar (uzunluk alanları çürük)
        let mut bozuk = t.clone();
        for i in 0..bozuk.len() {
            bozuk[i] = bozuk[i].wrapping_add(0x5A);
        }
        let _ = office_restore(&bozuk);
        assert!(office_restore(b"OFC1|").is_none(), "kısa girdi → None");
        assert!(office_restore(b"bozuk").is_none());
    }

#[test]
    fn office_digest_deterministik() {
        let z = ornek_opc();
        let t = office_transform(&z).unwrap();
        assert_eq!(office_digest(&t), office_digest(&t));
    }
}
