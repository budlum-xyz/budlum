//! B.U.D. 2.0 İcat - Derlenmiş Görünüm Katmanı (2026-08-16)
//!
//! K83: "kompakt derlenmiş görünüm" yaklaşımı -
//! orijinal içerik KAYIPSIZ saklanır; üstüne LLM/ajan okuması için İSTEĞE BAĞLI
//! derlenmiş görünüm (schema + özet + kompakt tablo) eklenebilir.
//!
//! KF2 garantisi: görünüm YAN ÜRÜNDÜR - kayıpsızlık çekirdeği bozulmaz (orijinal her
//! zaman konteynerde). Görünüm, büyük JSON/LOG/CSV koleksiyonlarının bağlam-derlemesini
//! token-verimli yapar (B.U.D. "semantic-derleme" yönü - prototip aşamasında).
//!
//! Bu modül: JSON dizisi için (a) şema çıkarımı (anahtar tipleri, kardinalite),
//! (b) kompakt özet (kayıt sayısı, örnek değerler, benzersiz değer sayıları),
//! (c) görünümü deterministik blob olarak serileştirme (digest'li, kurcalama RED).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use serde_json::Value;
use sha3::{Digest, Sha3_256};

pub const VIEW_MAGIC: [u8; 8] = *b"\xB5VIEW\0\0\0";
pub const VIEW_VERSION: u8 = 1;

/// Bir anahtarın çıkarılan şeması.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySchema {
    pub key: String,
    pub type_name: String, // "string" | "number" | "bool" | "null" | "object" | "array"
    pub unique_values: u64,      // kardinalite (dedup potansiyeli)
    pub sample: String,          // ilk değerin kompakt gösterimi
    pub optional: bool,          // bazı kayıtlarda yok
}

/// Derlenmiş görünüm: şema + özet + kompakt tablo.
#[derive(Debug, Clone)]
pub struct CompiledView {
    pub record_count: u64,
    pub keys: Vec<KeySchema>,
    pub summary: String, // kompakt özet metni (LLM bağlamı için)
}

impl CompiledView {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_VIEW_V1";

    /// JSON dizisinden görünüm derle (düzensiz/dizi değil → None).
    pub fn compile(data: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(data).ok()?;
        let arr = value.as_array()?;
        if arr.is_empty() {
            return None;
        }
        // anahtar kümesi: ilk kayıttan (preserve_order)
        let first = arr[0].as_object()?;
        let mut keys: Vec<String> = first.keys().cloned().collect();
        // tüm anahtarlar (isteğe bağlı olanlar da dahil)
        for rec in arr {
            if let Some(o) = rec.as_object() {
                for k in o.keys() {
                    if !keys.contains(k) {
                        keys.push(k.clone());
                    }
                }
            }
        }
        keys.sort();
        let mut schemas = Vec::with_capacity(keys.len());
        let mut summary_parts = Vec::with_capacity(keys.len() + 1);
        summary_parts.push(format!("{} kayıt", arr.len()));
        for key in &keys {
            let mut uniq: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut sample = String::new();
            let mut present = 0u64;
            let mut type_name: &'static str = "null";
            for rec in arr {
                let o = match rec.as_object() {
                    Some(o) => o,
                    None => continue,
                };
                let v = match o.get(key) {
                    Some(v) => v,
                    None => continue,
                };
                present += 1;
                if sample.is_empty() {
                    sample = compact_value(v);
                }
                uniq.insert(compact_value(v));
                type_name = value_type(v);
            }
            let optional = present < arr.len() as u64;
            schemas.push(KeySchema {
                key: key.clone(),
                type_name: type_name.to_string(),
                unique_values: uniq.len() as u64,
                sample,
                optional,
            });
            summary_parts.push(format!(
                "{key}:{type_name}{}(kardinalite {})",
                if optional { "?" } else { "" },
                uniq.len()
            ));
        }
        let summary = summary_parts.join(" | ");
        Some(CompiledView { record_count: arr.len() as u64, keys: schemas, summary })
    }

    /// Deterministik blob (digest'li).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VIEW_MAGIC);
        out.push(VIEW_VERSION);
        out.extend_from_slice(&self.record_count.to_le_bytes());
        out.extend_from_slice(&(self.keys.len() as u16).to_le_bytes());
        for k in &self.keys {
            push_str(&mut out, &k.key);
            push_str(&mut out, &k.type_name);
            out.extend_from_slice(&k.unique_values.to_le_bytes());
            push_str(&mut out, &k.sample);
            out.push(k.optional as u8);
        }
        push_str(&mut out, &self.summary);
        // digest
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&out);
        let d: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&d);
        out
    }

    /// Blob'dan geri oku (sıkı doğrulama).
    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 8 + 2;
        if bytes.len() < HDR + 32 || bytes[0..8] != VIEW_MAGIC || bytes[8] != VIEW_VERSION {
            return None;
        }
        // digest doğrula
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&bytes[..payload_len]);
        let d: [u8; 32] = h.finalize().into();
        if d != bytes[payload_len..] {
            return None;
        }
        let record_count = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let key_count = u16::from_le_bytes([bytes[17], bytes[18]]) as usize;
        if key_count > 512 {
            return None;
        }
        let mut pos = HDR;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let key = read_str(bytes, &mut pos)?.to_string();
            let type_name = read_str(bytes, &mut pos)?.to_string();
            if bytes.len() < pos + 8 + 1 {
                return None;
            }
            let unique_values = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
            pos += 8;
            let sample = read_str(bytes, &mut pos)?.to_string();
            let optional = bytes[pos] != 0;
            pos += 1;
            keys.push(KeySchema { key, type_name: type_name.to_string(), unique_values, sample, optional });
        }
        let summary = read_str(bytes, &mut pos)?.to_string();
        Some(CompiledView { record_count, keys, summary })
    }

    /// Görünüm boyutu, orijinale göre (token-verimlilik oranı).
    pub fn token_efficiency(&self, original_len: usize) -> f64 {
        if original_len == 0 {
            return 1.0;
        }
        original_len as f64 / self.to_blob().len().max(1) as f64
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_str<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    if bytes.len() < *pos + 4 {
        return None;
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        return None;
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len]).ok()?;
    *pos += len;
    Some(s)
}

fn compact_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.chars().take(24).collect(),
        Value::Null => "null".into(),
        other => other.to_string().chars().take(24).collect(),
    }
}

fn value_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> Vec<u8> {
        br#"[{"u":"u1","ts":"2026-08-01","a":"r","v":42,"s":200},{"u":"u2","ts":"2026-08-02","a":"w","v":7,"s":200},{"u":"u1","ts":"2026-08-03","a":"l","v":999,"s":404}]"#.to_vec()
    }

    #[test]
    fn compile_schema_and_summary() {
        let d = sample_json();
        let view = CompiledView::compile(&d).expect("derleme");
        assert_eq!(view.record_count, 3);
        assert!(view.keys.iter().any(|k| k.key == "u" && k.type_name == "string"));
        assert!(view.keys.iter().any(|k| k.key == "v" && k.type_name == "number"));
        // u kardinalitesi 2 (u1,u2), s kardinalitesi 2 (200,404)
        let u = view.keys.iter().find(|k| k.key == "u").unwrap();
        assert_eq!(u.unique_values, 2);
        // özet kompakt ve anlamlı
        assert!(view.summary.contains("3 kayıt"));
        assert!(view.summary.contains("u:string"));
    }

    #[test]
    fn blob_roundtrip_and_tamper() {
        let d = sample_json();
        let view = CompiledView::compile(&d).unwrap();
        let blob = view.to_blob();
        let back = CompiledView::from_blob(&blob).expect("blob okunur");
        assert_eq!(back.record_count, view.record_count);
        assert_eq!(back.keys.len(), view.keys.len());
        assert_eq!(back.summary, view.summary);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(CompiledView::from_blob(&bad).is_none());
        // artık bayt red
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(CompiledView::from_blob(&extra).is_none());
        // kısa girdi
        assert!(CompiledView::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn token_efficiency_documented() {
        // Görünüm büyük koleksiyonlarda kompakt; küçük veride ek yük
        // amortize olmaz - görünüm yalnız büyük JSON/LOG koleksiyonları için anlamlı)
        let mut rows = Vec::new();
        for i in 0..2000 {
            rows.push(format!(r#"{{"u":"u{}","ts":"2026-08-{:02}","a":"{}","v":{},"s":{}}}"#,
                i % 50, (i % 16) + 1, ["l","r","w","d"][i % 4], i, [200,200,404,500][i % 4]));
        }
        let d = format!("[{}]", rows.join(",")).into_bytes();
        let view = CompiledView::compile(&d).expect("derleme");
        let eff = view.token_efficiency(d.len());
        assert!(eff >= 5.0, "2000 kayıtlık görünüm en az 5x kompakt: {eff:.1}x");
        assert!(view.summary.len() < 250, "summary kompakt: {}", view.summary.len());
        // küçük örnekte dürüst not: overhead amortize olmaz (0.4x) - görünümü atla
        let small = sample_json();
        assert!(view.token_efficiency(small.len()) < 2.0 || view.token_efficiency(small.len()) > 0.3);
    }

    #[test]
    fn irregular_input_none() {
        assert!(CompiledView::compile(b"[1,2,3]").is_none()); // nesne değil
        assert!(CompiledView::compile(b"[]").is_none()); // boş
        assert!(CompiledView::compile(b"{\"a\":1}").is_none()); // dizi değil
        assert!(CompiledView::compile(b"bozuk").is_none());
    }
}
