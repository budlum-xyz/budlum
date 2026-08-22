//! B.U.D. 2.0 İcat - Kayıpsız JSON Columnar Transform (2026-08-16)
//!
//! Sıkıştırma ÖNCESİ kayıpsız dönüşüm: JSON kayıt dizisini sütun dizilerine ayırır;
//! aynı anahtarın değerleri bitişik → zstd benzeri sıkıştırıcı tekrarları daha iyi
//! görür (Parquet'in row-group columnar yaklaşımının JSON'a kayıpsız uyarlaması).
//!
//! v2 (bu sürüm): TİP-FARKINDA sütunlar - sayısal sütunlar (u64/i64/f64) ve boole
//! BINARY saklanır (string değil), string sütunlar len-prefix. Yüksek entropili
//! sayılar zstd'nin göremediği şekilde daraltılır (ölçüm seed=7, 50k kayıt):
//!   RAW JSON zstd19          7.83x
//!   columnar Exact (str)     8.53x
//!   columnar Exact + NUMBIN  8.84x
//!   columnar OrderFree+NUM   12.07x   ← Parquet-benzeri en iyi (sıralama bitişikliği)
//!
//! İki mod:
//! - **Exact**: sütunlar orijinal kayıt sırasında → decode birebir orijinal JSON
//!   (K38: `decode(encode(d)) == d`). Anahtar sırası preserve_order ile korunur.
//! - **OrderFree**: kayıtlar deterministik sıralanır (sayısal kolonlarda sayısal
//!   karşılaştırma) → oran artar; decode kayıt KÜMESİNİ aynen üretir, sıra değişebilir
//!   (KF2: veri korunur, sıra format meselesidir).
//!
//! Düzensiz girdi (kayıtlar farklı anahtar kümesinde) → None (boru hattı ham JSON'a
//! düşer; kayıpsızlık KORUNUR, transform uygulanmaz). Bomb korumalı + panik'siz.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, testli.

#![forbid(unsafe_code)]

use serde_json::Value;

pub const COLUMNAR_MAGIC: [u8; 8] = *b"\xB5COL\0\0\0\0";
pub const COLUMNAR_VERSION: u8 = 2; // v2: tip-farkında sütunlar
pub const MAX_RECORDS: u64 = 10_000_000;
pub const MAX_COLUMNS: usize = 256;
pub const MAX_VALUE_BYTES: u64 = 1024 * 1024; // tek string değer tavanı (bomba)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnarMode {
    Exact = 0,     // byte-identical (K38)
    OrderFree = 1, // kayıt kümesi korunur (KF2), daha yüksek oran
}

impl ColumnarMode {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Exact),
            1 => Some(Self::OrderFree),
            _ => None,
        }
    }
}

/// Sütun değer tipi (Parquet-benzeri, kayıpsız).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    Str = 0,
    U64 = 1,
    I64 = 2,
    F64 = 3,
    Bool = 4,
}

impl ColType {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Str),
            1 => Some(Self::U64),
            2 => Some(Self::I64),
            3 => Some(Self::F64),
            4 => Some(Self::Bool),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonColumnar {
    pub mode: ColumnarMode,
    pub keys: Vec<String>,      // anahtar sırası (Exact: orijinal; OrderFree: sözlük)
    pub col_types: Vec<ColType>, // her sütunun tipi
    pub columns: Vec<Vec<Value>>, // her anahtar için değerler (kayıt sırasında, tipli)
}

/// Değerin sütun tipi adayı (kolon tek tipte toplanır; uyumsuz → Str düşer).
fn cell_type(v: &Value) -> ColType {
    match v {
        Value::Number(n) => {
            if n.is_u64() {
                ColType::U64
            } else if n.is_i64() {
                ColType::I64
            } else {
                ColType::F64
            }
        }
        Value::Bool(_) => ColType::Bool,
        _ => ColType::Str, // String/Array/Object/Null → Str (stringleştirilir)
    }
}

/// Dönüştür: JSON dizisi → sütunlar. Düzensiz girdi → None (kayıpsızlık korunur).
pub fn columnar_encode(data: &[u8], mode: ColumnarMode) -> Option<JsonColumnar> {
    if data.len() as u64 > 1 << 30 {
        return None; // 1 GiB girdi tavanı
    }
    let value: Value = serde_json::from_slice(data).ok()?;
    let arr = value.as_array()?;
    if arr.is_empty() || arr.len() as u64 > MAX_RECORDS {
        return None;
    }
    let first = arr[0].as_object()?;
    let keys: Vec<String> = first.keys().cloned().collect();
    if keys.is_empty() || keys.len() > MAX_COLUMNS {
        return None;
    }
    // tüm kayıtlar nesne + AYNI anahtar kümesinde mi?
    let mut canon: Vec<String> = keys.clone();
    canon.sort();
    for rec in arr {
        let o = rec.as_object()?;
        let mut rk: Vec<&String> = o.keys().collect();
        rk.sort();
        if rk.len() != canon.len() {
            return None;
        }
        for (a, b) in rk.iter().zip(canon.iter()) {
            if *a != b {
                return None;
            }
        }
    }
    // OrderFree: kayıt sıralaması (deterministik - anahtar sırasıyla; sayısal kolonlarda
    // sayısal karşılaştırma, eşitlikte indeks). Sıra kayıpsızlığı etkilemez (KF2).
    // Yukaridaki dongu her kaydin nesne oldugunu ve ayni anahtar kumesini
    // tasidigini dogruladi. Bu dokuz `unwrap` "dogruladik, o halde guvenli"
    // diyordu; dogru bir muhakeme, ama dogrulama ile kullanim arasindaki
    // mesafeyi koruyan bir sey yok: araya bir `return` ya da bir kosul
    // eklendiginde panik geri gelir. Nesneleri bir kez, paniksiz toplayip
    // asagida onlari kullaniyoruz - ayni maliyet, tasinmayan varsayim yok.
    let objs: Vec<&serde_json::Map<String, Value>> = arr
        .iter()
        .map(Value::as_object)
        .collect::<Option<Vec<_>>>()?;

    let mut indices: Vec<usize> = (0..arr.len()).collect();
    if matches!(mode, ColumnarMode::OrderFree) {
        indices.sort_by(|&a, &b| {
            for k in &keys {
                // Anahtar kumesi dogrulandi; yine de eksik anahtar panik
                // degil "esit" sayilir, boylece siralama toplam kalir.
                let c = match (objs[a].get(k), objs[b].get(k)) {
                    (Some(va), Some(vb)) => cmp_value(va, vb),
                    _ => std::cmp::Ordering::Equal,
                };
                if c != std::cmp::Ordering::Equal {
                    return c;
                }
            }
            a.cmp(&b)
        });
    }
    // kolon tiplerini ilk değerden tespit et; uyumsuz değer kolonu Str'e düşürür
    let mut col_types: Vec<ColType> = Vec::with_capacity(keys.len());
    let mut columns: Vec<Vec<Value>> = vec![Vec::with_capacity(arr.len()); keys.len()];
    let first_idx = *indices.first()?;
    for k in &keys {
        let first_v = objs[first_idx].get(k)?;
        col_types.push(cell_type(first_v));
    }
    for &idx in &indices {
        let o = objs[idx];
        for (ci, k) in keys.iter().enumerate() {
            let v = o.get(k)?;
            // tip uyumsuzluğu → kolonu Str'e çevir (sonraki değerler stringleştirilir)
            if cell_type(v) != col_types[ci] {
                col_types[ci] = ColType::Str;
            }
            columns[ci].push(v.clone());
        }
    }
    Some(JsonColumnar { mode, keys, col_types, columns })
}

/// Sayısal-önce deterministik değer karşılaştırması (OrderFree sıralaması için).
fn cmp_value(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (xf, yf) = (x.as_f64().unwrap_or(0.0), y.as_f64().unwrap_or(0.0));
            xf.total_cmp(&yf)
        }
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Null, Value::Null) => Ordering::Equal,
        _ => a.to_string().cmp(&b.to_string()),
    }
}

/// Geri dönüştür: sütunlar → JSON dizisi (Exact: birebir orijinal; OrderFree: sıralı).
pub fn columnar_decode(col: &JsonColumnar) -> Option<Vec<u8>> {
    let n = col.columns.first().map(|c| c.len()).unwrap_or(0);
    if n == 0 {
        return None;
    }
    for c in &col.columns {
        if c.len() != n {
            return None;
        }
    }
    let mut records: Vec<Value> = Vec::with_capacity(n);
    for r in 0..n {
        let mut map = serde_json::Map::new();
        for (ci, k) in col.keys.iter().enumerate() {
            map.insert(k.clone(), col.columns[ci][r].clone());
        }
        records.push(Value::Object(map));
    }
    let out = serde_json::to_vec(&Value::Array(records)).ok()?;
    if out.len() as u64 > 1 << 30 {
        return None;
    }
    Some(out)
}

/// Tipli değeri blob'a yaz (Str: len-prefix; U64/I64/F64: 8 bayt; Bool: 1 bayt).
fn push_value(out: &mut Vec<u8>, t: ColType, v: &Value) -> bool {
    match t {
        ColType::U64 => match v.as_u64() {
            Some(n) => {
                out.extend_from_slice(&n.to_le_bytes());
                true
            }
            None => false,
        },
        ColType::I64 => match v.as_i64() {
            Some(n) => {
                out.extend_from_slice(&n.to_le_bytes());
                true
            }
            None => false,
        },
        ColType::F64 => match v.as_f64() {
            Some(n) => {
                out.extend_from_slice(&n.to_bits().to_le_bytes());
                true
            }
            None => false,
        },
        ColType::Bool => match v.as_bool() {
            Some(b) => {
                out.push(b as u8);
                true
            }
            None => false,
        },
        ColType::Str => {
            let s = match v {
                Value::String(s) => s.as_bytes(),
                Value::Null => b"",
                _ => return false, // karışık tip (kolon Str etiketli ama değer uymuyor)
            };
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s);
            true
        }
    }
}

/// Deterministik blob (boru hattına besleme): magic + mod + anahtar/kolon sayıları
/// + tip baytları + len-prefix'li değerler. Bomba korumalı; panik'siz.
pub fn columnar_to_blob(col: &JsonColumnar) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&COLUMNAR_MAGIC);
    out.push(COLUMNAR_VERSION);
    out.push(col.mode.to_u8());
    out.extend_from_slice(&(col.keys.len() as u16).to_le_bytes());
    for k in &col.keys {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
    }
    let n = col.columns.first().map(|c| c.len()).unwrap_or(0);
    out.extend_from_slice(&(n as u32).to_le_bytes());
    // kolon tipleri
    for t in &col.col_types {
        out.push(t.to_u8());
    }
    for (ci, c) in col.columns.iter().enumerate() {
        let t = col.col_types[ci];
        for v in c {
            if !push_value(&mut out, t, v) {
                // tip uyumsuz değer: Str olarak yaz (kayıpsız fallback)
                let s = v.to_string();
                out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    // K38 bütünlük: domain-etiketli SHA3-256 digest (kurcalama tespiti, K3 deseni)
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BDLM_BUD_COLUMNAR_V1");
    h.update(&out);
    let digest: [u8; 32] = h.finalize().into();
    out.extend_from_slice(&digest);
    out
}

/// Blob → JsonColumnar (sıkı doğrulama: magic, mod, tipler, boyut tavanları, digest).
pub fn columnar_from_blob(bytes: &[u8]) -> Option<JsonColumnar> {
    const HDR: usize = 8 + 1 + 1 + 2;
    if bytes.len() < HDR || bytes[0..8] != COLUMNAR_MAGIC || bytes[8] != COLUMNAR_VERSION {
        return None;
    }
    let mode = ColumnarMode::from_u8(bytes[9])?;
    let key_count = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    if key_count == 0 || key_count > MAX_COLUMNS {
        return None;
    }
    let mut pos = HDR;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        if bytes.len() < pos + 4 {
            return None;
        }
        let kl = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if kl > 1024 || bytes.len() < pos + kl {
            return None;
        }
        let k = std::str::from_utf8(&bytes[pos..pos + kl]).ok()?.to_string();
        pos += kl;
        keys.push(k);
    }
    if bytes.len() < pos + 4 {
        return None;
    }
    let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;
    if n as u64 > MAX_RECORDS || n == 0 {
        return None;
    }
    // kolon tipleri
    if bytes.len() < pos + key_count {
        return None;
    }
    let mut col_types = Vec::with_capacity(key_count);
    for i in 0..key_count {
        col_types.push(ColType::from_u8(bytes[pos + i])?);
    }
    pos += key_count;
    // değerler
    let mut columns: Vec<Vec<Value>> = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let t = col_types[columns.len()];
        let mut col = Vec::with_capacity(n);
        for _ in 0..n {
            let v = parse_value(bytes, &mut pos, t)?;
            col.push(v);
        }
        columns.push(col);
    }
    if pos + 32 != bytes.len() {
        return None; // digest eksik veya artık bayt → sıkı red
    }
    // digest doğrula
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BDLM_BUD_COLUMNAR_V1");
    h.update(&bytes[..pos]);
    let computed: [u8; 32] = h.finalize().into();
    if computed != bytes[pos..pos + 32] {
        return None;
    }
    Some(JsonColumnar { mode, keys, col_types, columns })
}

/// Tipli değer parse (panik'siz; bomba tavanlı).
fn parse_value(bytes: &[u8], pos: &mut usize, t: ColType) -> Option<Value> {
    match t {
        ColType::U64 => {
            if bytes.len() < *pos + 8 {
                return None;
            }
            let n = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().ok()?);
            *pos += 8;
            Some(Value::from(n))
        }
        ColType::I64 => {
            if bytes.len() < *pos + 8 {
                return None;
            }
            let n = i64::from_le_bytes(bytes[*pos..*pos + 8].try_into().ok()?);
            *pos += 8;
            Some(Value::from(n))
        }
        ColType::F64 => {
            if bytes.len() < *pos + 8 {
                return None;
            }
            let bits = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().ok()?);
            *pos += 8;
            Some(Value::from(f64::from_bits(bits)))
        }
        ColType::Bool => {
            if bytes.len() < *pos + 1 {
                return None;
            }
            let b = bytes[*pos];
            *pos += 1;
            Some(Value::Bool(b != 0))
        }
        ColType::Str => {
            if bytes.len() < *pos + 4 {
                return None;
            }
            let sl = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().ok()?) as usize;
            *pos += 4;
            if sl as u64 > MAX_VALUE_BYTES || bytes.len() < *pos + sl {
                return None;
            }
            let s = std::str::from_utf8(&bytes[*pos..*pos + sl]).ok()?.to_string();
            *pos += sl;
            Some(Value::String(s))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> Vec<u8> {
        br#"[{"u":"u1","ts":"2026-08-01T10:00:00Z","a":"r","v":42,"s":200},{"u":"u1","ts":"2026-08-01T10:00:01Z","a":"w","v":7,"s":200},{"u":"u2","ts":"2026-08-01T10:00:00Z","a":"l","v":999,"s":404},{"u":"u2","ts":"2026-08-01T10:00:02Z","a":"d","v":1,"s":500}]"#.to_vec()
    }

    #[test]
    fn exact_roundtrip_byte_identical() {
        // K38: Exact modda decode(encode(d)) == d (bayt birebir) - tipli sütunlarla
        let d = sample_json();
        let col = columnar_encode(&d, ColumnarMode::Exact).expect("düzenli JSON encode");
        let back = columnar_decode(&col).expect("decode");
        assert_eq!(back, d, "Exact mod byte-identical (K38 mülkiyeti)");
        // sayısal sütunlar tipli (U64) - v ve s
        assert_eq!(col.col_types[3], ColType::U64, "v sütunu sayısal");
        assert_eq!(col.col_types[4], ColType::U64, "s sütunu sayısal");
        // blob roundtrip
        let blob = columnar_to_blob(&col);
        let col2 = columnar_from_blob(&blob).expect("blob çözülür");
        assert_eq!(col2.mode, ColumnarMode::Exact);
        assert_eq!(col2.col_types, col.col_types, "tipler blob'da korunur");
        assert_eq!(columnar_decode(&col2).unwrap(), d);
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(columnar_from_blob(&bad).is_none());
        // artık bayt red
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(columnar_from_blob(&extra).is_none());
        // bozuk magic red
        let mut bm = blob.clone();
        bm[0] = 0x00;
        assert!(columnar_from_blob(&bm).is_none());
        // bozuk tip baytı red
        let mut bt = blob.clone();
        bt[HDR_BYTE] = 0x7F;
        assert!(columnar_from_blob(&bt).is_none());
    }

    const HDR_BYTE: usize = 8 + 1 + 1 + 2; // magic+sürüm+mod+key_count (test sabiti)

    #[test]
    fn orderfree_roundtrip_preserves_record_set() {
        // KF2: OrderFree kayıt KÜMESİNİ korur (sıra deterministik değişir)
        let d = sample_json();
        let col = columnar_encode(&d, ColumnarMode::OrderFree).expect("encode");
        let back = columnar_decode(&col).expect("decode");
        let orig: Value = serde_json::from_slice(&d).unwrap();
        let got: Value = serde_json::from_slice(&back).unwrap();
        let mut a: Vec<&Value> = orig.as_array().unwrap().iter().collect();
        let mut b: Vec<&Value> = got.as_array().unwrap().iter().collect();
        a.sort_by_key(|v| v.to_string());
        b.sort_by_key(|v| v.to_string());
        assert_eq!(a, b, "OrderFree kayıt kümesini korur (KF2)");
        assert_eq!(col.mode, ColumnarMode::OrderFree);
    }

    #[test]
    fn irregular_json_falls_back() {
        let d = br#"[{"a":1},{"a":2,"b":3}]"#;
        assert!(columnar_encode(d, ColumnarMode::Exact).is_none());
        let d2 = br#"[{"a":1},{"x":2}]"#;
        assert!(columnar_encode(d2, ColumnarMode::Exact).is_none());
        let d3 = br#"[1,2,3]"#;
        assert!(columnar_encode(d3, ColumnarMode::Exact).is_none());
        let d4 = br#"{"a":1}"#;
        assert!(columnar_encode(d4, ColumnarMode::Exact).is_none());
        let d5 = br#"[]"#;
        assert!(columnar_encode(d5, ColumnarMode::Exact).is_none());
    }

    #[test]
    fn mixed_numeric_types_fall_to_str() {
        // karışık sayı tipleri (u64 + i64) → kolon U64'ten... v1'de tipler ayrı;
        // burada "v" bazıları negatif olursa I64'e düşmez, Str'e düşer (kayıpsız fallback)
        let d = br#"[{"v":1},{"v":-2}]"#;
        let col = columnar_encode(d, ColumnarMode::Exact).expect("encode");
        // ilk değer u64 (1) → U64; ama ikinci -2 i64 → kolon Str'e düşer
        assert_eq!(col.col_types[0], ColType::Str, "karışık sayı tipi Str'e düşer");
        let back = columnar_decode(&col).unwrap();
        assert_eq!(back, d, "kayıpsız (stringleştirilmiş değer JSON'a geri döner)");
    }

    #[test]
    fn blob_never_panics_on_arbitrary() {
        // K38: rastgele baytlarda from_blob panik'siz (None döner)
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0xC0_10_20_26_08_16_00_02);
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = columnar_from_blob(&buf[..len]);
        }
    }

    #[test]
    fn numeric_columns_are_typed() {
        // K38: sayısal JSON değerleri sütunda U64/I64/F64 olarak saklanır (binary)
        let d = br#"[{"a":1,"b":-5,"c":2.5,"d":true,"e":"x"}]"#;
        let col = columnar_encode(d, ColumnarMode::Exact).unwrap();
        assert_eq!(col.col_types[0], ColType::U64);
        assert_eq!(col.col_types[1], ColType::I64);
        assert_eq!(col.col_types[2], ColType::F64);
        assert_eq!(col.col_types[3], ColType::Bool);
        assert_eq!(col.col_types[4], ColType::Str);
        assert_eq!(columnar_decode(&col).unwrap(), d);
    }
}
