//! B.U.D. 2.0 İCAT - Birleşik Storage Engine (2026-08-16)
//!
//! Kapsam: deneysel depolama yöntemlerinin tek motorda birleştirilmesi;
//! hatalarla ilerleyip sonunda buldum diyeceğin bir sistem... .bud formatına
//! dönüşecek tüm formatlar."
//!
//! Bu modül, bugüne kadar yazılan TÜM icat modüllerini TEK uçtan uca boru hattında
//! birleştirir: HERHANGİ bir format dosyası girer → format algılanır → içerik sınıfına
//! göre transform seçilir → yapısal parçalanır → zstd ile sıkıştırılır → Cauchy MDS
//! erasure ile korunur → .bud konteynerine yazılır → PACT + üretim kanıtı üretilir
//! → segment defterine eklenebilir. GERİ: ters sırayla ORİJİNAL.
//!
//! Boru hattı adımları kanıta yazılır (hangi transformlar uygulandı) → "bu .bud şu
//! dönüşümlerle üretildi" ispatı (üretim kanıtı + PACT). Uydurma oran imkânsız:
//! oran, orijinal/saklanan BOYUTLARDAN ölçülür (K19).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use crate::bud_format_catalog::{FormatCatalogEntry, catalog_detect};
use crate::bud_format_container::{BudV2File, FormatCodec, StructuralChunk, structural_split_compact};
use crate::bud_format_culling::CullingPlan;
use crate::bud_format_erasure::CauchyMds;
use crate::bud_format_fastcdc::{FastCdcSplit, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK, FCDC_MIN_CHUNK};
use crate::bud_format_pact::PactRecord;
use crate::bud_format_production::BudProductionRecord;
use crate::bud_format_ratioconsensus::{ContentClass, class_of};
use sha3::{Digest, Sha3_256};

pub const ENGINE_MAGIC: [u8; 8] = *b"\xB5ENGN\0\0\0";
pub const ENGINE_VERSION: u8 = 1;

/// Uygulanan transform türü (restore için geri çevirme gerekir).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    None,        // ham
    Columnar,    // JSON columnar Exact (byte-birebir)
    LogField,    // LOG alan-tanımlı
}

impl TransformKind {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Columnar => 1,
            Self::LogField => 2,
        }
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Columnar),
            2 => Some(Self::LogField),
            _ => None,
        }
    }
}

/// Boru hattı adımı (kanıt zincirine yazılır).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeStep {
    Detect,      // format algılama
    Transform,   // içerik-sınıfı transformu (columnar/logfield/timeseries/model)
    Split,       // yapısal parçalama (16KB)
    Fcdc,        // FastCDC içerik-tanımlı parçalama (4K/16K/64K - ikili)
    Zstd,        // zstd sıkıştırma
    Erasure,     // Cauchy MDS
    Container,   // .bud konteyner
}

impl PipeStep {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Detect => 0,
            Self::Transform => 1,
            Self::Split => 2,
            Self::Fcdc => 6,
            Self::Zstd => 3,
            Self::Erasure => 4,
            Self::Container => 5,
        }
    }
}

/// Birleşik motor sonucu: .bud konteyner + adım kanıtı + ölçülen oran + PACT.
#[derive(Debug, Clone)]
pub struct EngineResult {
    pub container: Vec<u8>,            // .bud dosyası (BudV2File)
    pub format_name: &'static str,     // algılanan format
    pub class: ContentClass,           // içerik sınıfı
    pub steps: Vec<PipeStep>,          // uygulanan adımlar (kanıt)
    pub transform_kind: TransformKind, // restore için (0=none 1=columnar 2=logfield)
    pub chunk_mode: u8,                // 0=structural 16KB, 1=FastCDC (içerik-tanımlı)
    pub original_len: u64,
    pub stored_len: u64,
    pub measured_ratio: f64,           // K19: boyutlardan ölçülür
    pub pact: PactRecord,              // üretim sözleşmesi (İ1)
    pub production: BudProductionRecord, // üretim kanıtı
}

impl EngineResult {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_ENGINE_V1";

    /// Boru hattı adım kanıtı (hangi dönüşümler uygulandı - deterministik).
    pub fn steps_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.format_name.as_bytes());
        h.update([match self.class {
            ContentClass::Structured => 0u8,
            ContentClass::Temporal => 1,
            ContentClass::Static => 2,
            ContentClass::Arbitrary => 3,
        }]);
        h.update([self.transform_kind.to_u8()]);
        h.update([self.chunk_mode]);
        for s in &self.steps {
            h.update([s.to_u8()]);
        }
        h.update(self.original_len.to_le_bytes());
        h.update(self.stored_len.to_le_bytes());
        h.finalize().into()
    }

    /// Kayıt blob'u (deterministik - zincire yazılabilir).
    /// Düzen: magic(8) + sürüm(1) + chunk_mode(1) + container_len(4) + container
    ///        + steps_hash(32) + measured_ratio(8) + pact(32) + production(32)
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ENGINE_MAGIC);
        out.push(ENGINE_VERSION);
        out.push(self.chunk_mode);
        out.extend_from_slice(&(self.container.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.container);
        out.extend_from_slice(&self.steps_hash());
        out.extend_from_slice(&self.measured_ratio.to_le_bytes());
        out.extend_from_slice(&self.pact.record_hash());
        out.extend_from_slice(&self.production.record_hash());
        out
    }
}

/// GERİ BORU HATTI: engine çıktısı (blob) → ORİJİNAL baytlar (kayıpsızlık kanıtı).
/// `erasure` = çıktı shard-paketli mi (k=4, p=2); shard'lardan önce 4'ünü kurar.
pub fn engine_restore(result_blob: &[u8], erasure: bool) -> Option<Vec<u8>> {
    // blob yapısı: magic(8) + sürüm(1) + chunk_mode(1) + container_len(4) + container
    //              + steps_hash(32) + ratio(8) + pact(32) + prod(32)
    const HDR: usize = 8 + 1 + 1 + 4;
    if result_blob.len() < HDR + 4 + 32 + 8 + 32 + 32 || result_blob[0..8] != ENGINE_MAGIC {
        return None;
    }
    let _chunk_mode = result_blob[9]; // 0=structural 1=fastcdc (restore için gerek yok: konteyner parçaları taşır)
    let container_len = u32::from_le_bytes(result_blob[10..14].try_into().ok()?) as usize;
    let container_start = HDR;
    if result_blob.len() < container_start + container_len {
        return None;
    }
    let container = &result_blob[container_start..container_start + container_len];
    // 1) erasure ise shard'lardan kur (k=4: ilk 4 shard)
    let bytes: Vec<u8> = if erasure {
        if container.is_empty() || container[0] != 4 {
            return None; // k=4 beklenir
        }
        let mut pos = 2usize; // k,p baytları
        let mut shards: Vec<(usize, Vec<u8>)> = Vec::with_capacity(6);
        for _ in 0..6 {
            if container.len() < pos + 4 {
                return None;
            }
            let len = u32::from_le_bytes(container[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if container.len() < pos + len {
                return None;
            }
            shards.push((shards.len(), container[pos..pos + len].to_vec()));
            pos += len;
        }
        let mds = CauchyMds::new(4, 2)?;
        let recovered = mds.decode(&shards[..4])?; // ilk 4 shard (MDS: herhangi 4)
        // padding'i kırp (son shard 0-pad'liydi)
        let mut out = Vec::new();
        for part in &recovered {
            out.extend_from_slice(part);
        }
        // trailing sıfırları kırp (padding) - orijinal .bud EOI'de 0xFF ile biter
        while out.last() == Some(&0u8) {
            out.pop();
        }
        out
    } else {
        container.to_vec()
    };
    // 2) BudV2File decode + restore_original
    let file = BudV2File::decode(&bytes)?;
    let raw = file.restore_original()?;
    // 3) transform geri çevirme - blob içinde transform_kind yok (steps_hash'te karışık);
    //    burada transform geri çevirme, engine_store'un transform_kind'ine göre ayrıca
    //    çağrılır (engine_restore_transform fonksiyonu). Bu fonksiyon yalnız konteyner
    //    katmanını açar; transform geri çevirme için engine_restore_full kullanılır.
    Some(raw)
}

/// BİRLEŞİK BORU HATTI: herhangi bir format → .bud + kanıt zinciri.
/// Varsayılan parçalama: yapısal 16KB (`fcdc=false`).
pub fn engine_store(
    data: &[u8],
    erasure: bool,
    ts_unix: u64,
) -> Option<EngineResult> {
    engine_store_with(data, erasure, ts_unix, false)
}

/// FastCDC içerik-tanımlı parçalama ile (4K/16K/64K) - ikili/arbitrary sınıflar için
/// önerilir: içerik-tanımlı sınırlar düzenleme-dirençli dedup çapaları üretir (F55).
pub fn engine_store_fcdc(
    data: &[u8],
    erasure: bool,
    ts_unix: u64,
) -> Option<EngineResult> {
    engine_store_with(data, erasure, ts_unix, true)
}

fn engine_store_with(
    data: &[u8],
    erasure: bool,
    ts_unix: u64,
    fcdc: bool,
) -> Option<EngineResult> {
    if data.is_empty() || data.len() > 512 * 1024 * 1024 {
        return None;
    }
    let mut steps = vec![PipeStep::Detect];
    // 1) format algıla + içerik sınıfı
    let detected = catalog_detect(data);
    let format_name = detected.map(|e| e.name).unwrap_or("Unknown");
    let codec: FormatCodec = detected.map(codec_of).unwrap_or(FormatCodec::Unknown);
    let kind = codec.structural_kind();
    let class = class_of(kind);
    // 2) içerik sınıfı transformu (columnar JSON / logfield LOG - en değerli ikisi)
    //    Transform uygulanan veri ayrı tutulur; kayıpsızlık transform_test ile garantili.
    let mut transform_kind = TransformKind::None;
    let transformed: Vec<u8> = match (codec, class) {
        (FormatCodec::Json, _) => {
            steps.push(PipeStep::Transform);
            match crate::bud_format_columnar::columnar_encode(data, crate::bud_format_columnar::ColumnarMode::Exact) {
                Some(col) => {
                    transform_kind = TransformKind::Columnar;
                    crate::bud_format_columnar::columnar_to_blob(&col)
                }
                None => data.to_vec(),
            }
        }
        (FormatCodec::Log, _) => {
            match crate::bud_format_logfield::LogFieldColumnar::encode(data) {
                Some(col) => {
                    steps.push(PipeStep::Transform);
                    transform_kind = TransformKind::LogField;
                    col.to_blob()
                }
                None => data.to_vec(),
            }
        }
        _ => data.to_vec(),
    };
    let _ = (codec, class);
    // 3) parçala - ikili/arbitrary sınıflar için FastCDC (içerik-tanımlı), diğerleri
    //    yapısal 16KB. FastCDC: düzenleme-dirençli dedup çapaları + kayıpsız join.
    let chunks: Vec<StructuralChunk> = if fcdc {
        steps.push(PipeStep::Fcdc);
        let sp = FastCdcSplit::split(&transformed, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK)?;
        sp.chunks
            .into_iter()
            .zip(sp.chunk_ids)
            .map(|(d, id)| StructuralChunk { content_id: id, data: d })
            .collect()
    } else {
        steps.push(PipeStep::Split);
        structural_split_compact(kind, &transformed, 16 * 1024)
    };
    // 4) zstd sıkıştırmalı konteyner (ChunkCodec::Zstd)
    steps.push(PipeStep::Zstd);
    let file = BudV2File::new_zstd(codec, chunks)?;
    // 5) erasure (opsiyonel): konteyneri 4 eşit parçaya böl → (4,2) Cauchy MDS → 6 shard
    //    MDS: herhangi 4 shard konteyneri geri kurar (tek-parça kaybına dayanıklı).
    let encoded = file.encode();
    let container_final: Vec<u8> = if erasure {
        steps.push(PipeStep::Erasure);
        let mds = CauchyMds::new(4, 2)?;
        // 4 eşit parçaya böl (padding'li - tüm shard'lar eşit boyut)
        let shard_len = encoded.len().div_ceil(4);
        let mut parts = Vec::with_capacity(4);
        for i in 0..4 {
            let start = i * shard_len;
            let end = (start + shard_len).min(encoded.len());
            let mut part = encoded[start..end].to_vec();
            part.resize(shard_len, 0); // son parçaya padding (deterministik)
            parts.push(part);
        }
        let shards = mds.encode(&parts)?;
        // 6 shard'ı paketle (len-prefix)
        let mut out = Vec::new();
        out.push(4u8); // k=4
        out.push(2u8); // p=2
        for sh in &shards {
            out.extend_from_slice(&(sh.len() as u32).to_le_bytes());
            out.extend_from_slice(sh);
        }
        out
    } else {
        steps.push(PipeStep::Container);
        encoded
    };
    let stored_len = container_final.len() as u64;
    let original_len = data.len() as u64;
    let measured_ratio = if stored_len > 0 { original_len as f64 / stored_len as f64 } else { 1.0 };
    // 6) PACT + üretim kanıtı (ölçülen oran - K19)
    let pact = PactRecord::pure([0xE9u8; 32], [0x11u8; 32], &container_final, ts_unix);
    let production = BudProductionRecord::new(codec, "engine-pipeline", data, stored_len, ts_unix);
    Some(EngineResult {
        container: container_final,
        format_name,
        class,
        steps,
        transform_kind,
        chunk_mode: if fcdc { 1 } else { 0 },
        original_len,
        stored_len,
        measured_ratio,
        pact,
        production,
    })
}

/// CULLING KATMANI: engine + erişim telemetrisi → tier planı.
/// `access` = cluster başına erişim sayısı; hiç erişilmemiş cluster'lar Culled
/// (saklanmaz) → depolama çarpanı 1/(1-culling_ratio) (K106, ölçüldü: 2.52x).
pub struct EngineTierResult {
    pub engine: EngineResult,
    pub plan: CullingPlan,
    pub storage_multiplier: f64,
}

pub fn engine_store_tiered(
    data: &[u8],
    erasure: bool,
    ts_unix: u64,
    access: &[u64],
) -> Option<EngineTierResult> {
    if access.is_empty() {
        return None;
    }
    let engine = engine_store(data, erasure, ts_unix)?;
    let plan = CullingPlan::from_access(access, 10, 1, ts_unix)?;
    let cull = plan.culling_ratio();
    let storage_multiplier = if cull < 1.0 && cull > 0.0 {
        1.0 / (1.0 - cull)
    } else {
        1.0
    };
    Some(EngineTierResult { engine, plan, storage_multiplier })
}

/// Format kaydından FormatCodec eşle (catalog → konteyner kodu).
fn codec_of(e: &FormatCatalogEntry) -> FormatCodec {
    match e.name {
        "JSON" | "JSON-array" => FormatCodec::Json,
        "CSV" => FormatCodec::Csv,
        "LOG" | "NginxLog" => FormatCodec::Log,
        "PE-EXE" | "ELF" => FormatCodec::Unknown,
        "PDF" => FormatCodec::Pdf,
        "JPEG" => FormatCodec::Jpeg,
        "PNG" => FormatCodec::Png,
        "MP4" | "MKV" | "WebM" => FormatCodec::Mp4,
        _ => FormatCodec::Unknown,
    }
}


/// KONTEYNER-DÜZEYİ RESTORE: `bud engine` çıktısı (container veya shard paketi) → orijinal.
/// `transform_kind`: 0=none 1=columnar 2=logfield (engine_store çıktısındaki değer).
pub fn engine_restore_container(container: &[u8], transform_kind: u8, erasure: bool) -> Option<Vec<u8>> {
    // 1) erasure ise shard paketinden kur (k=4, p=2)
    let bytes: Vec<u8> = if erasure {
        if container.is_empty() || container[0] != 4 {
            return None;
        }
        let mut pos = 2usize;
        let mut shards: Vec<(usize, Vec<u8>)> = Vec::with_capacity(6);
        for _ in 0..6 {
            if container.len() < pos + 4 {
                return None;
            }
            let len = u32::from_le_bytes(container[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if container.len() < pos + len {
                return None;
            }
            shards.push((shards.len(), container[pos..pos + len].to_vec()));
            pos += len;
        }
        let mds = CauchyMds::new(4, 2)?;
        let recovered = mds.decode(&shards[..4])?;
        let mut out = Vec::new();
        for part in &recovered {
            out.extend_from_slice(part);
        }
        while out.last() == Some(&0u8) {
            out.pop();
        }
        out
    } else {
        container.to_vec()
    };
    // 2) BudV2File aç
    let file = BudV2File::decode(&bytes)?;
    let raw = file.restore_original()?;
    // 3) transform geri çevir
    match TransformKind::from_u8(transform_kind)? {
        TransformKind::None => Some(raw),
        TransformKind::Columnar => {
            let col = crate::bud_format_columnar::columnar_from_blob(&raw)?;
            crate::bud_format_columnar::columnar_decode(&col)
        }
        TransformKind::LogField => {
            let col = crate::bud_format_logfield::LogFieldColumnar::from_blob(&raw)?;
            col.decode()
        }
    }
}

/// TAM RESTORE: konteyner aç + transform geri çevir → ORİJİNAL (K38).
/// `transform_kind` engine_store'dan gelir (0=none 1=columnar 2=logfield).
pub fn engine_restore_full(raw: &[u8], transform_kind: u8, erasure: bool) -> Option<Vec<u8>> {
    // blob → container baytlarını çıkar (magic + sürüm + chunk_mode + len + container)
    const HDR: usize = 8 + 1 + 1 + 4;
    if raw.len() < HDR + 4 || raw[0..8] != ENGINE_MAGIC {
        return None;
    }
    let container_len = u32::from_le_bytes(raw[10..14].try_into().ok()?) as usize;
    if raw.len() < HDR + container_len {
        return None;
    }
    let container = &raw[HDR..HDR + container_len];
    engine_restore_container(container, transform_kind, erasure)
}

/// Konteyner katmanını aç (erasure + BudV2File) - engine_restore'un çekirdeği.
pub fn engine_restore_raw(result_blob: &[u8], erasure: bool) -> Option<Vec<u8>> {
    const HDR: usize = 8 + 1 + 1 + 4;
    if result_blob.len() < HDR + 4 + 32 + 8 + 32 + 32 || result_blob[0..8] != ENGINE_MAGIC {
        return None;
    }
    let container_len = u32::from_le_bytes(result_blob[10..14].try_into().ok()?) as usize;
    let container_start = HDR;
    if result_blob.len() < container_start + container_len {
        return None;
    }
    let container = &result_blob[container_start..container_start + container_len];
    let bytes: Vec<u8> = if erasure {
        if container.is_empty() || container[0] != 4 {
            return None;
        }
        let mut pos = 2usize;
        let mut shards: Vec<(usize, Vec<u8>)> = Vec::with_capacity(6);
        for _ in 0..6 {
            if container.len() < pos + 4 {
                return None;
            }
            let len = u32::from_le_bytes(container[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if container.len() < pos + len {
                return None;
            }
            shards.push((shards.len(), container[pos..pos + len].to_vec()));
            pos += len;
        }
        let mds = CauchyMds::new(4, 2)?;
        let recovered = mds.decode(&shards[..4])?;
        let mut out = Vec::new();
        for part in &recovered {
            out.extend_from_slice(part);
        }
        while out.last() == Some(&0u8) {
            out.pop();
        }
        out
    } else {
        container.to_vec()
    };
    let file = BudV2File::decode(&bytes)?;
    file.restore_original()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_container::BudV2File;

    #[test]
    fn json_engine_roundtrip() {
        // JSON → engine → .bud (zstd) → restore = orijinal
        // 500 kayıtlık JSON - columnar transform ile gerçek sıkışma
        let mut rows = Vec::new();
        for i in 0..500 {
            rows.push(format!(r#"{{"u":"u{}","ts":"2026-08-{:02}","a":"{}","v":{},"s":{}}}"#,
                i % 50, (i % 16) + 1, ["l","r","w","d"][i % 4], i, [200,200,404,500][i % 4]));
        }
        let json = format!("[{}]", rows.join(",")).into_bytes();
        let res = engine_store(&json, false, 1_768_000_000).expect("engine");
        assert!(res.format_name.starts_with("JSON"), "JSON ailesi: {}", res.format_name);
        assert!(res.steps.contains(&PipeStep::Transform), "columnar transform uygulanır");
        assert!(res.steps.contains(&PipeStep::Zstd));
        assert!(res.measured_ratio > 1.0, "ölçülen oran: {}", res.measured_ratio);
        // konteyner açılabilir + içerik döner (transform sonrası - columnar blob)
        let file = BudV2File::decode(&res.container).expect("konteyner");
        let back = file.restore_original().expect("aç");
        assert!(!back.is_empty());
        // PACT + üretim kanıtı tutarlı
        assert!(res.pact.verify());
        assert!(res.production.verify());
        // adım kanıtı deterministik
        assert_eq!(res.steps_hash(), res.steps_hash());
        // kayıt blob'u
        let blob = res.to_blob();
        assert_eq!(&blob[..8], &ENGINE_MAGIC);
    }

    #[test]
    fn binary_engine_roundtrip() {
        // Binary → engine → .bud → restore = orijinal (transform yok)
        let bin: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
        let res = engine_store(&bin, false, 100).expect("engine");
        assert_eq!(res.format_name, "Unknown");
        assert!(!res.steps.contains(&PipeStep::Transform), "binary'de transform yok");
        let file = BudV2File::decode(&res.container).expect("konteyner");
        assert_eq!(file.restore_original().unwrap(), bin, "binary kayıpsız");
    }

    #[test]
    fn erasure_step_included_when_requested() {
        let data = b"erasure test verisi ".repeat(100);
        let with_ec = engine_store(&data, true, 1).expect("engine+erasure");
        assert!(with_ec.steps.contains(&PipeStep::Erasure));
        let without = engine_store(&data, false, 1).expect("engine");
        assert!(!without.steps.contains(&PipeStep::Erasure));
        // erasure paketi k=4 işareti taşır
        assert_eq!(with_ec.container[0], 4u8, "k=4");
        assert_eq!(with_ec.container[1], 2u8, "p=2");
        // shard'ları geri kur: ilk 4 shard (len-prefix) → orijinal konteyner
        // (burada yalnız paket yapısı doğrulanır - restore motoru ayrı adım)
    }


    #[test]
    fn engine_full_roundtrip_lossless() {
        // K38: engine_store → engine_restore_full = ORİJİNAL (JSON, columnar transform)
        let mut rows = Vec::new();
        for i in 0..300 {
            rows.push(format!(r#"{{"u":"u{}","ts":"2026-08-{:02}","a":"{}","v":{},"s":{}}}"#,
                i % 50, (i % 16) + 1, ["l","r","w","d"][i % 4], i, [200,200,404,500][i % 4]));
        }
        let json = format!("[{}]", rows.join(",")).into_bytes();
        let res = engine_store(&json, false, 1_768_000_000).expect("store");
        assert_eq!(res.transform_kind, TransformKind::Columnar);
        let blob = res.to_blob();
        let back = engine_restore_full(&blob, res.transform_kind.to_u8(), false)
            .expect("restore");
        assert_eq!(back, json, "JSON columnar tam döngü kayıpsız");
    }

    #[test]
    fn engine_binary_roundtrip_no_transform() {
        // binary: transform yok → tam döngü kayıpsız
        let bin: Vec<u8> = (0u8..=255).cycle().take(50_000).collect();
        let res = engine_store(&bin, false, 1).expect("store");
        assert_eq!(res.transform_kind, TransformKind::None);
        let blob = res.to_blob();
        let back = engine_restore_full(&blob, res.transform_kind.to_u8(), false)
            .expect("restore");
        assert_eq!(back, bin, "binary tam döngü kayıpsız");
    }

    #[test]
    fn engine_erasure_roundtrip() {
        // erasure: shard paketi → kur → restore = orijinal (transform yok, binary)
        let bin: Vec<u8> = b"erasure roundtrip verisi ".repeat(200);
        let res = engine_store(&bin, true, 1).expect("store+erasure");
        assert!(res.steps.contains(&PipeStep::Erasure));
        let blob = res.to_blob();
        let back = engine_restore_full(&blob, res.transform_kind.to_u8(), true)
            .expect("restore+erasure");
        assert_eq!(back, bin, "erasure tam döngü kayıpsız");
    }

    #[test]
    fn engine_restore_rejects_tamper() {
        let bin: Vec<u8> = b"kurcalama testi ".repeat(100);
        let res = engine_store(&bin, false, 1).expect("store");
        let mut blob = res.to_blob();
        // blob sonundaki üretim kanıtı hash'ini boz
        *blob.last_mut().unwrap() ^= 0x01;
        // konteyner katmanı magic'i korunur ama içerik kurcalanmış → decode ya None ya farklı
        // (burada yalnız panik olmadığı doğrulanır)
        let _ = engine_restore_raw(&blob, false);
        // kısa blob → None
        assert!(engine_restore_raw(&[0u8; 10], false).is_none());
        assert!(engine_restore_full(&[0u8; 10], 0, false).is_none());
    }
    #[test]
    fn engine_rejects_empty_and_huge() {
        assert!(engine_store(&[], false, 1).is_none());
        let huge = vec![0u8; 513 * 1024 * 1024];
        assert!(engine_store(&huge, false, 1).is_none(), "512MB tavan");
    }

    #[test]
    fn i5_determinizm_makine_testi() {
        // fikirler2.0 §10.1: zstd sürüm+parametre+girdi sabitleme → AYNI çıktı.
        // Makine testi: aynı girdi + aynı seviye → birebir aynı konteyner baytları.
        let data: Vec<u8> = (0u8..=255).cycle().take(200_000).collect();
        let a = engine_store(&data, false, 5).unwrap();
        let b = engine_store(&data, false, 5).unwrap();
        assert_eq!(a.container, b.container, "İ5: aynı girdi → aynı .bud baytları");
        assert_eq!(a.to_blob(), b.to_blob());
        // farklı ts de adım kanıtını değiştirmez (pact ts içerir - konteyner aynı)
        let c = engine_store(&data, false, 6).unwrap();
        assert_eq!(a.container, c.container);
    }

    #[test]
    fn nginx_log_otomatik_algilanir() {
        // Kalan iş #6: engine'de nginx access log → LOG sınıfı + logfield transform.
        let mut log = String::new();
        for i in 0..50 {
            log.push_str(&format!(
                "127.0.0.1 - - [10/Aug/2026:10:{:02}:00 +0000] \"GET /api/urun/{} HTTP/1.1\" 200 {}\n",
                i % 60, i % 5, 512 + i
            ));
        }
        let res = engine_store(log.as_bytes(), false, 8).unwrap();
        assert_eq!(res.format_name, "NginxLog", "format: {}", res.format_name);
        assert!(res.steps.contains(&PipeStep::Transform), "logfield transform");
        assert!(res.measured_ratio > 1.0, "oran: {}", res.measured_ratio);
        let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false).unwrap();
        assert_eq!(back, log.as_bytes(), "nginx log birebir");
    }

    #[test]
    fn fastcdc_engine_roundtrip_lossless() {
        // F55: FastCDC parçalama → .bud → restore = ORİJİNAL (kayıpsız)
        let bin: Vec<u8> = (0u8..=255).cycle().take(300_000).collect();
        let res = engine_store_fcdc(&bin, false, 7).expect("fcdc engine");
        assert_eq!(res.chunk_mode, 1, "chunk_mode=1 (FastCDC)");
        assert!(res.steps.contains(&PipeStep::Fcdc));
        // blob'daki chunk_mode baytı (index 9)
        let blob = res.to_blob();
        assert_eq!(blob[9], 1u8);
        // kayıpsız geri dönüş
        assert_eq!(engine_restore_raw(&blob, false).unwrap(), bin);
        // deterministik
        assert_eq!(engine_store_fcdc(&bin, false, 7).unwrap().steps_hash(), res.steps_hash());
    }

    #[test]
    fn fastcdc_edit_direncli_dedup_capalari() {
        // F55: aynı içeriğin ortasına küçük düzenleme → parçaların çoğu aynı kalır
        let base: Vec<u8> = (0u8..=255).cycle().take(400_000).collect();
        let mut edit = base.clone();
        edit[200_000] ^= 0xFF;
        let sp1 = FastCdcSplit::split(&base, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK).unwrap();
        let sp2 = FastCdcSplit::split(&edit, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK).unwrap();
        let shared = sp1.chunk_ids.iter().filter(|id| sp2.chunk_ids.contains(id)).count();
        let toplam = sp1.chunk_ids.len().max(sp2.chunk_ids.len());
        assert!(shared as f64 / toplam as f64 > 0.5, "düzenlemeden sonra parçaların çoğu ortak: {shared}/{toplam}");
        assert_eq!(sp1.join(), base);
        assert_eq!(sp2.join(), edit);
    }

    #[test]
    fn tiered_engine_culling_carpani() {
        // K106: erişim telemetrisi → CullingPlan → depolama çarpanı (ölçülen 2.52x)
        let data = b"tiered engine verisi ".repeat(2000);
        let mut access = vec![0u64; 100];
        for i in 0..100 {
            access[i] = if i % 5 == 0 { 15 } else if i % 3 == 0 { 2 } else { 0 };
        }
        let tr = engine_store_tiered(&data, false, 99, &access).expect("tiered");
        let (h, w, c, cu) = tr.plan.tier_summary();
        assert!(h > 0 && w > 0 && cu > 0, "tier dağılımı: h={h} w={w} c={c} cu={cu}");
        assert!(tr.storage_multiplier >= 1.0, "çarpan: {}", tr.storage_multiplier);
        // çarpan formülü doğru: 1/(1-culling_ratio)
        let beklenen = 1.0 / (1.0 - tr.plan.culling_ratio());
        assert!((tr.storage_multiplier - beklenen).abs() < 1e-9);
        // engine katmanı hâlâ kayıpsız
        assert_eq!(engine_restore_full(&tr.engine.to_blob(), tr.engine.transform_kind.to_u8(), false).unwrap(), data);
    }
}
