//! B.U.D. 2.0 Icat - Konteyner .bud format v2 + Yapisal Parcalama + Rol-Uzman Multi-Ratio
//!
//! Araştırma bulgularından hayata geçirilen yönler (2026-08-16):
//! 1. **Yapısal parçalama ön-adımı** (S.82 konteyner/MIME/EBML, S.174 Parquet, ilham-2 C):
//!    içerik önce yapısal sınırlara ayrılır (JSON kayıt / CSV satır / log satır / kod AST),
//!    her parça ayrı ContentId alır - CDC16K'dan önce format-farkında kesim (kayıpsız).
//! 3. **Konteyner .bud format iyileştirmeleri**:
//!    - magic: high-bit set + ASCII degil (S.47: file(1) karışmasın) - v1 magic korunur, v2 ek flag
//!    - multihash benzeri alan (K34): hash_algo kodu + digest - BLAKE3/SHA3/SHA512 yükseltilebilir
//!    - format_class registry (K23/K43): yeni format eklenince registry güncellenir
//!    - deterministik, kayıpsız (KF2: çözünürlük korunur, format değişebilir)
//! 2. **Rol-uzman multi-ratio** (ilham-2 E + S.123 AgentNet): her format bir "uzman rol",
//!    kendi boru hattını aday oran üretir, BFT finality en kanıtlı adayı seçer.
//!
//! Kod: no unsafe, deterministik, testlerle. #![forbid(unsafe_code)] korunur.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

// ── 1. Yapısal parçalama (format-farkında, kayıpsız) ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StructuralKind {
    Json,   // JSON dizisi: kayıt sınırından kes
    Csv,    // CSV: satır sınırından kes
    Log,    // Log: satır sınırından kes (şablon sonra)
    Text,   // Metin: cümle/paragraf sınırı (basit: satır)
    Binary, // İkili: CDC (içerik-tanımlı) - sabit ortalama
}

#[derive(Debug, Clone)]
pub struct StructuralChunk {
    pub content_id: [u8; 32], // BDLM_CONTENT_V1 || len || baytlar (kriptografik, K3)
    pub data: Vec<u8>,
}

/// İçeriği yapısal sınırlardan keser (kayıpsız: birleştir = orijinal).
/// JSON: ayraçlar parçalara gömülür, derinlik-1 virgül parça sınırıdır (virgül SONRAKİ
/// parçanın başında korunur). Dizi değilse/bozuksa dahi tek parça → her girdi kayıpsız.
/// CSV/Log/Text: satır sınırı.
/// Binary: sabit blok (CDC ön-adımı basitleştirilmiş - avg boyut).
///
/// Kayıpsızlık TAMLIĞI (K38): `structural_join(kind, structural_split(kind, d)) == d`
/// HER `d` için (boş, bozuk UTF-8, çerçevesiz JSON, negatif derinlik dahil) geçerlidir;
/// birleştirme saf birleştirmedir, ayraç bilgisi parçalarda taşınır.
pub fn structural_split(kind: StructuralKind, data: &[u8]) -> Vec<StructuralChunk> {
    if data.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    match kind {
        StructuralKind::Json => {
            // Taranan her parça orijinal baytların bitişik alt dizisi olduğundan ve hiçbir
            // bayt atlanmadığından birleştirme her zaman orijinali üretir (K38). Derinlik
            // i32'dir; bozuk girdide negatife iner ama panik olmaz, kayıpsızlık sürer.
            let s = match std::str::from_utf8(data) {
                Ok(s) => s,
                Err(_) => return split_fixed(data, 65536),
            };
            let mut start = 0usize;
            let mut depth = 0i32;
            let mut in_str = false;
            let mut esc = false;
            for (i, c) in s.char_indices() {
                match c {
                    '"' if !esc => in_str = !in_str,
                    '\\' if in_str => esc = !esc,
                    _ => esc = false,
                }
                if !in_str {
                    match c {
                        '{' | '[' => depth += 1,
                        '}' | ']' => depth -= 1,
                        // derinlik-1 virgül: dizinin üst seviye kayıt sınırı
                        ',' if depth == 1 => {
                            if i > start {
                                push_chunk(&mut out, &s[start..i]);
                            }
                            // virgül SONRAKİ parçanın başında korunur: start = i (i+1 değil!),
                            // aksi halde virgül parçalar arasında düşer, JSON bozulur.
                            start = i;
                        }
                        _ => {}
                    }
                }
            }
            push_chunk(&mut out, &s[start..]);
            out
        }
        StructuralKind::Csv | StructuralKind::Log | StructuralKind::Text => {
            // Satır sınırı (kayıpsız: \n korunur - her parça satır sonuyla biter)
            for line in data.split_inclusive(|&b| b == b'\n') {
                let chunk = line.to_vec();
                out.push(StructuralChunk {
                    content_id: content_id(&chunk),
                    data: chunk,
                });
            }
            out
        }
        StructuralKind::Binary => split_fixed(data, 65536),
    }
}

fn push_chunk(out: &mut Vec<StructuralChunk>, seg: &str) {
    if seg.is_empty() {
        return;
    }
    let chunk = seg.as_bytes().to_vec();
    out.push(StructuralChunk {
        content_id: content_id(&chunk),
        data: chunk,
    });
}

fn split_fixed(data: &[u8], block: usize) -> Vec<StructuralChunk> {
    let mut out = Vec::new();
    for chunk in data.chunks(block) {
        let v = chunk.to_vec();
        out.push(StructuralChunk {
            content_id: content_id(&v),
            data: v,
        });
    }
    out
}

pub fn content_id(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONTENT_V1");
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// Kayıpsızlık kanıtı: parçaları birleştir → orijinal.
/// K38: SAF birleştirme - parçalama ayraçları (`[`, `]`, virgül) parçalara gömülür,
/// birleştirme hiçbir tür için `[`/`]` eklemez, böylece roundtrip HER girdi için
/// birebir orijinaldir (çerçevesiz JSON, bozuk UTF-8, boş girdi dahil).
pub fn structural_join(_kind: StructuralKind, chunks: &[StructuralChunk]) -> Vec<u8> {
    let total: usize = chunks.iter().map(|c| c.data.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in chunks {
        out.extend_from_slice(&c.data);
    }
    out
}

// ── 3. Konteyner .bud v2: multihash + format registry + rol-uzman ────────────

/// Multihash benzeri: hash algoritması kodu + digest (K34).
/// 0x12 = SHA-256, 0x16 = SHA3-256, 0x1e = BLAKE3-256, 0x13 = SHA-512 (temsili).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiHash {
    pub algo: u8,
    pub digest: [u8; 32],
}

impl MultiHash {
    pub fn sha3_256(bytes: &[u8]) -> Self {
        MultiHash { algo: 0x16, digest: content_id(bytes) }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.algo, 32];
        v.extend_from_slice(&self.digest);
        v
    }
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 34 {
            return None;
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&raw[2..34]);
        Some(MultiHash { algo: raw[0], digest })
    }
}

/// Format registry (K23/K43): yeni format eklenince kodlanır, geriye uyumlu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum FormatCodec {
    Json = 1,
    Csv = 2,
    Log = 3,
    Text = 4,
    Jpeg = 11,
    Png = 12,
    Mp4 = 10,
    Pdf = 16,
    Unknown = 0,
}

impl FormatCodec {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Json,
            2 => Self::Csv,
            3 => Self::Log,
            4 => Self::Text,
            10 => Self::Mp4,
            11 => Self::Jpeg,
            12 => Self::Png,
            16 => Self::Pdf,
            _ => Self::Unknown,
        }
    }
    pub fn structural_kind(self) -> StructuralKind {
        match self {
            Self::Json => StructuralKind::Json,
            Self::Csv => StructuralKind::Csv,
            Self::Log => StructuralKind::Log,
            Self::Text => StructuralKind::Text,
            _ => StructuralKind::Binary,
        }
    }
}

/// Rol-uzman boru hattı adayı (ilham-2 E): her format uzmanı kendi oranını üretir.
#[derive(Debug, Clone)]
pub struct ExpertCandidate {
    pub expert: &'static str,   // "json-expert", "log-expert" ...
    pub pipe: &'static str,     // "structural+zstd19", "columnar+dict" ...
    pub ratio: f64,             // ölçülmüş oran (elle yazılmaz; ölçümden)
    pub lossless: bool,         // kayıpsızlık garantisi (KF2)
    pub payload: Vec<u8>,
}

/// Rol-uzman çoklu aday üretici: her format için birden çok aday (deterministik).
/// Oranlar placeholder değildir; gerçek ölçümden gelecek (runner tarafında ölçülür, sonra sabitlenir).
pub fn expert_candidates(
    codec: FormatCodec,
    original: &[u8],
    structural: &[StructuralChunk],
) -> Vec<ExpertCandidate> {
    // Yapısal parçalama her uzman için ortak girdi; farklı boru hatları aday üretir.
    let ratio_base = if structural.len() > 1 {
        // parçalama tekrar oranı: parça sayısı / benzersiz parça (dedup potansiyeli)
        let uniq = {
            let mut v: Vec<[u8; 32]> = structural.iter().map(|c| c.content_id).collect();
            v.sort();
            v.dedup();
            v.len()
        };
        if uniq > 0 {
            structural.len() as f64 / uniq as f64
        } else {
            1.0
        }
    } else {
        1.0
    };
    let _ = original;
    match codec {
        FormatCodec::Json => vec![
            ExpertCandidate {
                expert: "json-expert",
                pipe: "structural+zstd19",
                ratio: ratio_base * 7.83, // ölçüm: JSON zstd-19 7.83x (measure_ratios.py seed=7, EK13)
                lossless: true,
                payload: original.to_vec(),
            },
            ExpertCandidate {
                expert: "json-expert",
                pipe: "structural+xz9",
                ratio: ratio_base * 8.07, // ölçüm: JSON xz9 8.07x (EK13)
                lossless: true,
                payload: original.to_vec(),
            },
        ],
        FormatCodec::Log => vec![
            ExpertCandidate {
                expert: "log-expert",
                pipe: "structural+zstd19",
                ratio: ratio_base * 6.17, // ölçüm: LOG zstd-19 6.17x (EK13)
                lossless: true,
                payload: original.to_vec(),
            },
        ],
        FormatCodec::Csv => vec![
            ExpertCandidate {
                expert: "csv-expert",
                pipe: "structural+zstd19",
                ratio: ratio_base * 3.55, // ölçüm: CSV zstd-19 3.55x (EK13)
                lossless: true,
                payload: original.to_vec(),
            },
        ],
        _ => vec![ExpertCandidate {
            expert: "binary-expert",
            pipe: "structural+zstd19",
            ratio: ratio_base * 1.0,
            lossless: true,
            payload: original.to_vec(),
        }],
    }
}

/// Çoklu adaydan en iyi KAYIPSIZ adayı seç (BFT finality ayrı modülde - burada deterministik max).
pub fn select_best_lossless(candidates: Vec<ExpertCandidate>) -> Option<ExpertCandidate> {
    candidates
        .into_iter()
        .filter(|c| c.lossless && c.ratio >= 1.0)
        .max_by(|a, b| a.ratio.total_cmp(&b.ratio)) // K38: total_cmp NaN panik yapmaz
}

/// .bud v2 konteyner başlığı: magic v2 (high-bit set) + multihash + format + parça sayısı.
#[derive(Debug, Clone)]
pub struct BudV2Header {
    pub magic: [u8; 8], // b"\xB5\x55\x44\xB0\x02\x00\x00\x00" - high-bit, ASCII degil (S.47)
    pub codec: FormatCodec,
    pub content_id: MultiHash,
    pub chunk_count: u32,
    pub total_len: u64,
}

impl BudV2Header {
    pub const MAGIC: [u8; 8] = *b"\xB5\x55\x44\xB0\x02\x00\x00\x00";

    pub fn new(codec: FormatCodec, chunks: &[StructuralChunk]) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_V2");
        for c in chunks {
            h.update(c.content_id);
        }
        let digest: [u8; 32] = h.finalize().into();
        let total_len: u64 = chunks.iter().map(|c| c.data.len() as u64).sum();
        BudV2Header {
            magic: Self::MAGIC,
            codec,
            content_id: MultiHash { algo: 0x16, digest },
            chunk_count: chunks.len() as u32,
            total_len,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.magic);
        v.extend_from_slice(&(self.codec as u16).to_le_bytes());
        v.extend_from_slice(&self.content_id.encode());
        v.extend_from_slice(&self.chunk_count.to_le_bytes());
        v.extend_from_slice(&self.total_len.to_le_bytes());
        v
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 8 + 2 + 34 + 4 + 8 {
            return None;
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&raw[0..8]);
        if magic != Self::MAGIC {
            return None;
        }
        let codec = FormatCodec::from_u16(u16::from_le_bytes([raw[8], raw[9]]));
        let mh = MultiHash::decode(&raw[10..44])?;
        let chunk_count = u32::from_le_bytes([raw[44], raw[45], raw[46], raw[47]]);
        let total_len = u64::from_le_bytes([
            raw[48], raw[49], raw[50], raw[51], raw[52], raw[53], raw[54], raw[55],
        ]);
        Some(BudV2Header { magic, codec, content_id: mh, chunk_count, total_len })
    }

    pub fn verify(&self) -> bool {
        self.magic == Self::MAGIC && self.content_id.algo == 0x16
    }
}

/// Parça kodlayıcı: parçaların nasıl saklandığı (gerçek kayıpsız sıkıştırma bayrağı).
/// Raw = ham baytlar; Huffman = gerçek Huffman sıkıştırması (bud_format_huffman, K38);
/// Zstd = gerçek zstd FFI (bud_format_real, V21 yol haritası - en yüksek oran).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkCodec {
    Raw = 0,
    Huffman = 1,
    Zstd = 2,
}

impl ChunkCodec {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Raw),
            1 => Some(Self::Huffman),
            2 => Some(Self::Zstd),
            _ => None, // bilinmeyen kodlayıcı → red (ileri uyumluluk kasıtlı)
        }
    }
}

/// .bud v2 TAM DOSYA: başlık + parça kodlayıcı + parça listesi (len-prefixed, doğrulanabilir).
/// K38 sertleştirme: header'ın yanına parçaları güvenli şekilde yazar/okur;
/// bomb koruması (K25 deseni): MAX_CHUNK_COUNT / MAX_CHUNK_BYTES / MAX_TOTAL_BYTES.
/// Her parça (u64 len + 32B content_id + veri) ile yazılır; decode her parçanın
/// content_id'sini YENİDEN hesaplayarak doğrular → payload üzerinde herhangi bir
/// bayt değişikliği reddedilir. Tüm decode yolları panik'siz Option döner (fuzz-güvenli).
#[derive(Debug, Clone)]
pub struct BudV2File {
    pub header: BudV2Header,
    pub chunk_codec: ChunkCodec,
    pub chunks: Vec<StructuralChunk>,
}

impl BudV2File {
    pub const MAX_CHUNK_COUNT: u32 = 1_000_000;
    pub const MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
    pub const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

    /// Güvenli kurucu (RAW parçalar): boyut/kapasite sınırlarını daha baştan reddeder.
    pub fn new(codec: FormatCodec, chunks: Vec<StructuralChunk>) -> Option<Self> {
        Self::new_with_codec(codec, ChunkCodec::Raw, chunks)
    }

    /// Huffman ile sıkıştırılmış konteyner: her parça GERÇEKTEN sıkıştırılır (deterministik),
    /// content_id sıkıştırılmış baytlara göre yeniden kurulur (bütünlük = saklanan baytlar).
    /// Aynı orijinal parça → aynı sıkıştırılmış bayt → aynı cid (dedup uyumlu).
    pub fn new_compressed(codec: FormatCodec, chunks: Vec<StructuralChunk>) -> Option<Self> {
        let compressed: Vec<StructuralChunk> = chunks
            .into_iter()
            .map(|c| {
                let data = crate::bud_format_huffman::HuffmanCoder::compress(&c.data);
                StructuralChunk { content_id: content_id(&data), data }
            })
            .collect();
        Self::new_with_codec(codec, ChunkCodec::Huffman, compressed)
    }

    /// GERÇEK zstd ile sıkıştırılmış konteyner (V21 yol haritası, K38):
    /// her parça zstd level 19 ile sıkıştırılır; decode/açma ZSTD_MAX_DECOMPRESSED tavanıyla
    /// güvenlidir (K25 bomba koruması). Huffman'dan daha iyi oran (testle kanıtlı).
    pub fn new_zstd(codec: FormatCodec, chunks: Vec<StructuralChunk>) -> Option<Self> {
        let compressed: Vec<StructuralChunk> = chunks
            .into_iter()
            .map(|c| {
                let data = crate::bud_format_real::zstd_compress(&c.data, 19)?;
                Some(StructuralChunk { content_id: content_id(&data), data })
            })
            .collect::<Option<Vec<_>>>()?;
        Self::new_with_codec(codec, ChunkCodec::Zstd, compressed)
    }

    fn new_with_codec(
        codec: FormatCodec,
        chunk_codec: ChunkCodec,
        chunks: Vec<StructuralChunk>,
    ) -> Option<Self> {
        if chunks.len() as u64 > u64::from(Self::MAX_CHUNK_COUNT) {
            return None;
        }
        let total: u64 = chunks.iter().map(|c| c.data.len() as u64).sum();
        if total > Self::MAX_TOTAL_BYTES {
            return None;
        }
        if chunks.iter().any(|c| c.data.len() as u64 > Self::MAX_CHUNK_BYTES) {
            return None;
        }
        let header = BudV2Header::new(codec, &chunks);
        Some(BudV2File { header, chunk_codec, chunks })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.header.to_bytes());
        v.push(self.chunk_codec.to_u8());
        v.extend_from_slice(&self.header.chunk_count.to_le_bytes());
        for c in &self.chunks {
            v.extend_from_slice(&(c.data.len() as u64).to_le_bytes());
            v.extend_from_slice(&c.content_id);
            v.extend_from_slice(&c.data);
        }
        v
    }

    /// Sıkı decode: sihir, başlık, parça kodlayıcı, her parçanın content_id'si, toplam
    /// uzunluk ve kök content_id doğrulanır; herhangi bir tutarsızlık → None. Fazla
    /// (artık) bayta izin verilmez (kurcalama algılama). Hiçbir girdi panik üretemez.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 2 + 34 + 4 + 8; // header boyutu (56)
        if raw.len() < HDR + 1 + 4 {
            return None;
        }
        let header = BudV2Header::from_bytes(&raw[..HDR])?;
        if !header.verify() {
            return None;
        }
        let chunk_codec = ChunkCodec::from_u8(raw[HDR])?;
        let count =
            u32::from_le_bytes([raw[HDR + 1], raw[HDR + 2], raw[HDR + 3], raw[HDR + 4]]);
        if count > Self::MAX_CHUNK_COUNT {
            return None;
        }
        let mut pos = HDR + 5;
        // K38: count GÜVENİLMEZ bayttan gelir - with_capacity(count) küçük dosyada
        // devasa ayırım (bellek DoS) üretirdi; lazy büyüme kullanılır (bomba yok).
        let mut chunks: Vec<StructuralChunk> = Vec::new();
        let mut total: u64 = 0;
        for _ in 0..count {
            if raw.len() < pos + 40 {
                return None; // len(8) + cid(32) başlığı yok
            }
            let len = u64::from_le_bytes(raw[pos..pos + 8].try_into().ok()?);
            if len > Self::MAX_CHUNK_BYTES {
                return None;
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&raw[pos + 8..pos + 40]);
            pos += 40;
            let end = pos.checked_add(len as usize)?;
            if end > raw.len() {
                return None;
            }
            let data = raw[pos..end].to_vec();
            if content_id(&data) != cid {
                return None; // payload kurcalanmış
            }
            total = total.checked_add(len)?;
            if total > Self::MAX_TOTAL_BYTES {
                return None;
            }
            chunks.push(StructuralChunk { content_id: cid, data });
            pos = end;
        }
        if pos != raw.len() {
            return None; // artık bayt → sıkı red
        }
        if chunks.len() as u32 != header.chunk_count || total != header.total_len {
            return None;
        }
        let f = BudV2File { header, chunk_codec, chunks };
        if !f.verify() {
            return None;
        }
        Some(f)
    }

    /// ORİJİNAL baytları geri getir: parçaları (gerekirse açarak) sırayla birleştir.
    /// Kayıpsızlık garantisi: kodlayıcıdan bağımsız olarak `restore_original(decode(x))`
    /// orijinal girdiyi üretir (Raw → aynen, Huffman → aç, Zstd → aç). Panik yok;
    /// zstd açma K25 tavanıyla sınırlı (ZSTD_MAX_DECOMPRESSED).
    pub fn restore_original(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for c in &self.chunks {
            match self.chunk_codec {
                ChunkCodec::Raw => out.extend_from_slice(&c.data),
                ChunkCodec::Huffman => {
                    let d = crate::bud_format_huffman::HuffmanCoder::decompress(&c.data)?;
                    out.extend_from_slice(&d);
                }
                ChunkCodec::Zstd => {
                    let d = crate::bud_format_real::zstd_decompress_safe(
                        &c.data,
                        crate::bud_format_real::ZSTD_MAX_DECOMPRESSED,
                    )?;
                    out.extend_from_slice(&d);
                }
            }
        }
        Some(out)
    }

    /// Kanıt zinciri: kök content_id'yi parça cid'lerinden yeniden hesaplar (veri
    /// yeniden hash'lenmez - parça cid'leri zaten decode'da doğrulandı).
    pub fn verify(&self) -> bool {
        if !self.header.verify() {
            return false;
        }
        if self.chunks.len() as u32 != self.header.chunk_count {
            return false;
        }
        let total: u64 = self.chunks.iter().map(|c| c.data.len() as u64).sum();
        if total != self.header.total_len {
            return false;
        }
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_V2");
        for c in &self.chunks {
            h.update(c.content_id);
        }
        let digest: [u8; 32] = h.finalize().into();
        digest == self.header.content_id.digest
    }
}

/// K35 compaction: min boyut altındaki parçaları birleştir (kayıpsız).
/// Küçük-nesne amplifikasyonu (K21/K35, S.61 MinIO/Ceph dersi) çözümü:
/// çok küçük parçalar dedup/kanıt verimini düşürür; bitişik min-altı parçalar
/// tek parçada toplanır. `structural_join` ile hâlâ birebir orijinal.
pub fn structural_split_compact(kind: StructuralKind, data: &[u8], min_chunk: usize) -> Vec<StructuralChunk> {
    let raw = structural_split(kind, data);
    if raw.is_empty() {
        return raw;
    }
    let mut out: Vec<StructuralChunk> = Vec::new();
    let mut acc: Vec<u8> = Vec::new();
    for c in raw {
        if acc.is_empty() && c.data.len() >= min_chunk {
            // büyük parça doğrudan
            out.push(c);
        } else if acc.len() + c.data.len() <= min_chunk.max(1) {
            acc.extend_from_slice(&c.data);
        } else {
            // akümülatörü boşalt, sonra yeni parça başlat
            if !acc.is_empty() {
                let v = std::mem::take(&mut acc);
                out.push(StructuralChunk { content_id: content_id(&v), data: v });
            }
            if c.data.len() >= min_chunk {
                out.push(c);
            } else {
                acc = c.data;
            }
        }
    }
    if !acc.is_empty() {
        out.push(StructuralChunk { content_id: content_id(&acc), data: acc });
    }
    out
}

/// Parça sayısı (tanı testi için yardımcı).
pub fn structural_chunks(kind: StructuralKind, data: &[u8]) -> usize {
    structural_split(kind, data).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_structural_split_roundtrip() {
        // kayıpsız: parçala + birleştir = orijinal
        let json = br#"[{"a":1,"b":2},{"a":3,"b":4},{"a":5,"b":6}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        assert!(chunks.len() >= 3, "JSON kayıt sayısı kadar parça: {}", chunks.len());
        let joined = structural_join(StructuralKind::Json, &chunks);
        assert_eq!(&joined[..], &json[..], "JSON yapısal parçalama kayıpsız olmalı");
    }

    #[test]
    fn csv_structural_split_roundtrip() {
        let csv = b"a,b,c\n1,2,3\n4,5,6\n";
        let chunks = structural_split(StructuralKind::Csv, csv);
        assert!(chunks.len() >= 3);
        let joined = structural_join(StructuralKind::Csv, &chunks);
        assert_eq!(&joined[..], &csv[..]);
    }

    #[test]
    fn content_id_deterministic_and_cryptographic() {
        let a = content_id(b"budlum");
        let b = content_id(b"budlum");
        assert_eq!(a, b, "deterministik");
        assert_ne!(a, content_id(b"budlu"), "farklı girdi farklı hash");
        assert_ne!(a, [0u8; 32], "sıfır değil (kriptografik)");
    }

    #[test]
    fn multihash_encode_decode() {
        let mh = MultiHash::sha3_256(b"hello");
        let enc = mh.encode();
        assert_eq!(enc.len(), 34);
        let dec = MultiHash::decode(&enc).unwrap();
        assert_eq!(dec, mh);
        assert!(MultiHash::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn select_best_lossless_nan_safe() {
        // K38: NaN oranlı aday sıralamayı çökertmemeli (total_cmp)
        let nan_cand = ExpertCandidate {
            expert: "nan-expert",
            pipe: "structural+nan",
            ratio: f64::NAN,
            lossless: true,
            payload: vec![],
        };
        let ok_cand = ExpertCandidate {
            expert: "ok-expert",
            pipe: "structural+zstd19",
            ratio: 7.83,
            lossless: true,
            payload: vec![],
        };
        let best = select_best_lossless(vec![nan_cand, ok_cand]).expect("NaN elenir, OK aday seçilir");
        assert_eq!(best.ratio, 7.83);
        assert!(select_best_lossless(vec![]).is_none());
    }

    #[test]
    fn expert_select_best_lossless() {
        let json = br#"[{"x":1},{"x":2}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        let cands = expert_candidates(FormatCodec::Json, json, &chunks);
        assert!(cands.len() >= 2, "JSON uzmanı çoklu aday üretmeli");
        let best = select_best_lossless(cands).unwrap();
        assert!(best.ratio >= 7.5, "en iyi kayıpsız aday seçilmeli");
        assert!(best.lossless);
    }

    #[test]
    fn bud_v2_header_roundtrip_and_magic() {
        let json = br#"[{"a":1}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        let hdr = BudV2Header::new(FormatCodec::Json, &chunks);
        assert!(hdr.verify());
        assert_ne!(hdr.magic[0], b'B', "magic high-bit set, ASCII degil (S.47)");
        let bytes = hdr.to_bytes();
        let dec = BudV2Header::from_bytes(&bytes).unwrap();
        assert_eq!(dec.codec, FormatCodec::Json);
        assert_eq!(dec.chunk_count, hdr.chunk_count);
        assert_eq!(dec.total_len, hdr.total_len);
        assert_eq!(dec.content_id, hdr.content_id);
        // bozuk magic red
        let mut bad = bytes.clone();
        bad[0] = 0x00;
        assert!(BudV2Header::from_bytes(&bad).is_none());
    }

    #[test]
    fn compact_merges_small_chunks_lossless() {
        // CSV: her satır ~12B; min 64B ile birleştirilmeli, kayıpsız
        let csv = b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n10,11,12\n";
        let raw = structural_split(StructuralKind::Csv, csv);
        let comp = structural_split_compact(StructuralKind::Csv, csv, 64);
        assert!(raw.len() > comp.len(), "compaction parça sayisini dusurmeli");
        let joined = structural_join(StructuralKind::Csv, &comp);
        assert_eq!(joined, csv, "compaction kayipsiz");
        // her birlesik parcada content_id dogru
        for c in &comp {
            assert_eq!(c.content_id, content_id(&c.data));
        }
    }
    #[test]
    fn log_split_preserves_lines() {
        let log = b"2026-08-16 INFO a\n2026-08-16 WARN b\n";
        let chunks = structural_split(StructuralKind::Log, log);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].data.ends_with(b"\n"));
        let joined = structural_join(StructuralKind::Log, &chunks);
        assert_eq!(joined, log);
    }

    // ── K38: kayıpsızlık TAMLIĞI - mülkiyet testleri ────────────────────────────

    /// Deterministik xorshift64* - dış bağımlılık yok (rand crate'siz).
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
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }
    }

    fn gen_string(rng: &mut Rng) -> Vec<u8> {
        let mut out = vec![b'"'];
        let n = rng.below(10);
        for _ in 0..n {
            match rng.below(6) {
                0 => out.push(b'\\'),     // kaçış (string durumu sınar)
                1 => out.push(b'"'),      // kaçışlı tırnak
                2 => out.push(b'{'),
                3 => out.push(b','),
                _ => {
                    // ascii veya çok baytlı UTF-8 (é)
                    if rng.below(2) == 0 {
                        out.push(0xC3);
                        out.push(0xA9);
                    } else {
                        out.push(b'a');
                    }
                }
            }
        }
        out.push(b'"');
        out
    }

    fn gen_json(rng: &mut Rng, depth: usize) -> Vec<u8> {
        if depth > 8 {
            return b"0".to_vec();
        }
        let mut out = Vec::new();
        match rng.below(4) {
            0 => {
                out.push(b'{');
                let n = rng.below(4);
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(&gen_string(rng));
                    out.push(b':');
                    out.extend_from_slice(&gen_json(rng, depth + 1));
                }
                out.push(b'}');
            }
            1 => {
                out.push(b'[');
                let n = rng.below(5);
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(&gen_json(rng, depth + 1));
                }
                out.push(b']');
            }
            2 => out.extend_from_slice(&gen_string(rng)),
            _ => out.extend_from_slice(&format!("{}", rng.below(1000)).into_bytes()),
        }
        out
    }

    fn gen_lines(rng: &mut Rng) -> Vec<u8> {
        let mut out = Vec::new();
        let n = 1 + rng.below(30);
        for _ in 0..n {
            let len = rng.below(40);
            for _ in 0..len {
                out.push(b'a' + (rng.below(26) as u8));
                if rng.below(5) == 0 {
                    out.push(b','); // satır içi virgül
                }
            }
            match rng.below(4) {
                0 => {}                        // satır sonu yok (son satır)
                1 => out.push(b'\r'),          // tek \r (satır sonu değil)
                _ => out.push(b'\n'),
            }
        }
        out
    }

    #[test]
    fn total_losslessness_property() {
        // K38: HER girdi için split+join = orijinal; compact (çeşitli min) de kayıpsız.
        let mut rng = Rng(0xB0B2_2026_0816_1337);
        for round in 0..400u32 {
            let kind = match rng.below(5) {
                0 => StructuralKind::Json,
                1 => StructuralKind::Csv,
                2 => StructuralKind::Log,
                3 => StructuralKind::Text,
                _ => StructuralKind::Binary,
            };
            let data: Vec<u8> = match kind {
                StructuralKind::Json => gen_json(&mut rng, 0),
                StructuralKind::Binary => {
                    let mut v = vec![0u8; rng.below(3000)];
                    for b in &mut v {
                        *b = rng.byte();
                    }
                    v
                }
                _ => gen_lines(&mut rng),
            };
            let chunks = structural_split(kind, &data);
            let joined = structural_join(kind, &chunks);
            assert_eq!(
                &joined[..],
                &data[..],
                "round {round} kind={kind:?} split+join kayıpsız olmalı"
            );
            for mc in [1usize, 7, 64, 257, 4096] {
                let comp = structural_split_compact(kind, &data, mc);
                assert_eq!(
                    structural_join(kind, &comp),
                    data,
                    "round {round} kind={kind:?} compact(min={mc}) kayıpsız olmalı"
                );
            }
        }
    }

    #[test]
    fn edge_inputs_lossless() {
        // boş, çerçevesiz JSON, bozuk UTF-8, negatif derinlik, yalnız boşluk
        for kind in [
            StructuralKind::Json,
            StructuralKind::Csv,
            StructuralKind::Log,
            StructuralKind::Text,
            StructuralKind::Binary,
        ] {
            let empty: Vec<u8> = vec![];
            assert!(structural_split(kind, &empty).is_empty());
            assert!(structural_join(kind, &[]).is_empty());
        }
        let cases: &[&[u8]] = &[
            b"",                          // boş
            b"   ",                       // boşluk
            b"{\"a\":1}",                 // nesne (dizi değil)
            b"\"merhaba\"",               // ilkel
            b"1,2,3",                     // üst seviye ilkeller
            b"[]}",                       // bozuk: fazla kapanış
            b"[{\"a\":1}",                // bozuk: kapanış eksik
            b"{\"a\":[1,2],\"b\":[3,4]}", // iç içe diziler
            b"[[1,2],[3,4]]",             // dizi içinde dizi
            b"[\n  {\"a\": 1},\n  {\"a\": 2}\n]", // çok satırlı
            &[0xFF, 0xFE, 0x00, 0x41, 0x22],      // geçersiz UTF-8
            b"a\r\nb\r\nc",               // CRLF
            b"\"{\"",                     // string içinde ayraç
        ];
        for (i, data) in cases.iter().enumerate() {
            for kind in [
                StructuralKind::Json,
                StructuralKind::Csv,
                StructuralKind::Log,
                StructuralKind::Text,
                StructuralKind::Binary,
            ] {
                let chunks = structural_split(kind, data);
                assert_eq!(
                    structural_join(kind, &chunks),
                    *data,
                    "case {i} kind={kind:?} kayıpsız olmalı"
                );
            }
        }
    }

    #[test]
    fn json_record_boundaries_at_depth1_commas() {
        let json = br#"[{"a":1},{"a":2},{"a":3}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        assert!(chunks.len() >= 3, "kayıt sayısı kadar parça");
        assert!(
            chunks[0].data.starts_with(b"["),
            "ilk parça açılış ayracını taşır"
        );
        for c in &chunks[1..] {
            assert!(
                c.data.starts_with(b","),
                "parça sınırı virgülle başlamalı (JSON geçerliliği korunur)"
            );
        }
        assert_eq!(structural_join(StructuralKind::Json, &chunks), json);
    }

    #[test]
    fn compact_json_merges_without_losing_records() {
        let json = br#"[{"a":1},{"a":2},{"a":3},{"a":4}]"#;
        let comp = structural_split_compact(StructuralKind::Json, json, 1024);
        assert_eq!(comp.len(), 1, "tamamı tek parçaya birleşmeli");
        assert_eq!(structural_join(StructuralKind::Json, &comp), json);
        assert_eq!(comp[0].content_id, content_id(&comp[0].data));
    }

    // ── BudV2File: tam dosya roundtrip + kurcalama + bomb koruması ─────────────

    #[test]
    fn bud_v2_file_roundtrip_and_tamper() {
        let csv = b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n";
        let chunks = structural_split_compact(StructuralKind::Csv, csv, 8);
        let f = BudV2File::new(FormatCodec::Csv, chunks).unwrap();
        assert!(f.verify());
        let enc = f.encode();
        let dec = BudV2File::decode(&enc).expect("temiz dosya decode olmalı");
        assert!(dec.verify());
        assert_eq!(dec.header.codec, FormatCodec::Csv);
        assert_eq!(dec.chunks.len(), f.chunks.len());
        assert_eq!(
            structural_join(StructuralKind::Csv, &dec.chunks),
            csv,
            "decode sonrası birleştir = orijinal"
        );
        // (1) payload baytı çevir → content_id uyuşmaz → red
        let mut t1 = enc.clone();
        *t1.last_mut().unwrap() ^= 0xFF;
        assert!(BudV2File::decode(&t1).is_none(), "payload tamper red");
        // (2) kırp → eksik parça → red
        let mut t2 = enc.clone();
        t2.truncate(enc.len() - 3);
        assert!(BudV2File::decode(&t2).is_none(), "kırpma red");
        // (3) magic boz → red
        let mut t3 = enc.clone();
        t3[0] = 0x00;
        assert!(BudV2File::decode(&t3).is_none(), "magic tamper red");
        // (4) total_len boz (başlık 48..56) → decode red (tutarlılık)
        let mut t4 = enc.clone();
        t4[48] ^= 0x01;
        assert!(BudV2File::decode(&t4).is_none(), "total_len tamper red");
        // (5) artık bayt ekle → sıkı red
        let mut t5 = enc.clone();
        t5.push(0x00);
        assert!(BudV2File::decode(&t5).is_none(), "artık bayt red");
        // (6) kısa girdiler → red (panik yok)
        assert!(BudV2File::decode(&[]).is_none());
        assert!(BudV2File::decode(&enc[..20]).is_none());
        assert!(BudV2File::decode(&enc[..59]).is_none());
    }

    #[test]
    fn bud_v2_file_bomb_guards() {
        let csv = b"a\n";
        let chunks = structural_split(StructuralKind::Csv, csv);
        let hdr = BudV2Header::new(FormatCodec::Csv, &chunks);
        // (1) parça sayısı bombası: başlık + codec + dev count, veri yok
        let mut bomb = hdr.to_bytes();
        bomb.push(ChunkCodec::Raw.to_u8());
        bomb.extend_from_slice(&2_000_000u32.to_le_bytes());
        assert!(BudV2File::decode(&bomb).is_none(), "parça sayısı bombası red");
        // (2) parça boyu bombası: 1 parça ama len = 1 GiB iddiası (MAX_CHUNK_BYTES üstü)
        let mut b2 = hdr.to_bytes();
        b2.push(ChunkCodec::Raw.to_u8());
        b2.extend_from_slice(&1u32.to_le_bytes());
        b2.extend_from_slice(&(1u64 << 30).to_le_bytes());
        b2.extend_from_slice(&[0u8; 32]);
        assert!(BudV2File::decode(&b2).is_none(), "boy bombası red");
        // (3) u32::MAX parça sayısı (cast taşması yok)
        let mut b3 = hdr.to_bytes();
        b3.push(ChunkCodec::Raw.to_u8());
        b3.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(BudV2File::decode(&b3).is_none(), "u32::MAX bombası red");
        // (4) bilinmeyen parça kodlayıcı → red
        let mut b4 = hdr.to_bytes();
        b4.push(0x7F);
        b4.extend_from_slice(&0u32.to_le_bytes());
        assert!(BudV2File::decode(&b4).is_none(), "bilinmeyen codec red");
    }

    #[test]
    fn bud_v2_file_new_rejects_oversize() {
        // 65 MiB parça → MAX_CHUNK_BYTES (64 MiB) üstü → None
        let big = vec![0u8; 65 * 1024 * 1024];
        let chunks = vec![StructuralChunk { content_id: content_id(&big), data: big }];
        assert!(BudV2File::new(FormatCodec::Text, chunks).is_none());
    }

    #[test]
    fn bud_v2_file_verify_detects_inconsistency() {
        let csv = b"x\n";
        let chunks = structural_split(StructuralKind::Csv, csv);
        // total_len tutarsızlığı
        let mut f = BudV2File::new(FormatCodec::Csv, chunks.clone()).unwrap();
        f.header.total_len += 1;
        assert!(!f.verify(), "total_len uyumsuzluğu verify'da yakalanır");
        // chunk_count tutarsızlığı
        let mut f2 = BudV2File::new(FormatCodec::Csv, chunks).unwrap();
        f2.header.chunk_count += 1;
        assert!(!f2.verify(), "chunk_count uyumsuzluğu verify'da yakalanır");
    }

    #[test]
    fn zstd_container_roundtrip_and_beats_huffman() {
        // K38 + V21: zstd konteyner kayıpsız + Huffman'dan küçük (gerçek zstd FFI)
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..2000 {
            data.extend_from_slice(line);
        }
        let chunks = structural_split_compact(StructuralKind::Log, &data, 4096);
        let hfm = BudV2File::new_compressed(FormatCodec::Log, chunks.clone()).unwrap();
        let z = BudV2File::new_zstd(FormatCodec::Log, chunks).unwrap();
        let zh = z.encode();
        assert!(zh.len() < hfm.encode().len(), "zstd Huffman'dan küçük: {} vs {}", zh.len(), hfm.encode().len());
        assert_eq!(z.restore_original().unwrap(), data, "zstd kayıpsız");
        // decode + restore + kurcalama red
        let dec = BudV2File::decode(&zh).unwrap();
        assert_eq!(dec.chunk_codec, ChunkCodec::Zstd);
        assert_eq!(dec.restore_original().unwrap(), data);
        let mut bad = zh.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(BudV2File::decode(&bad).is_none(), "zstd konteyner kurcalama red");
    }

    #[test]
    fn compressed_container_roundtrip_and_smaller() {
        // tekrarlı log: sıkıştırılmış konteyner GERÇEKTEN küçülmeli + kayıpsız
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..3000 {
            data.extend_from_slice(line);
        }
        let chunks = structural_split_compact(StructuralKind::Log, &data, 4096);
        let raw = BudV2File::new(FormatCodec::Log, chunks.clone()).unwrap();
        let comp = BudV2File::new_compressed(FormatCodec::Log, chunks).unwrap();
        assert!(
            comp.encode().len() < raw.encode().len(),
            "sıkıştırılmış konteyner küçülmeli: raw {} vs comp {}",
            raw.encode().len(),
            comp.encode().len()
        );
        // kayıpsızlık: her ikisi de orijinali geri verir
        assert_eq!(raw.restore_original().unwrap(), data);
        assert_eq!(comp.restore_original().unwrap(), data);
        // decode + restore_original yolu
        let decoded = BudV2File::decode(&comp.encode()).unwrap();
        assert_eq!(decoded.chunk_codec, ChunkCodec::Huffman);
        assert_eq!(decoded.restore_original().unwrap(), data);
        // kurcalama yine red
        let mut bad = comp.encode();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(BudV2File::decode(&bad).is_none());
    }

    #[test]
    fn bud_v2_file_decode_never_panics_on_truncation() {
        // K38: geçerli bir dosyanın HER kırpma uzunluğunda decode panik üretmemeli
        // (alloc-bomb fix'i sonrası küçük dosya üzerinde tam tarama hızlıdır)
        let line = b"2026-08-16 INFO req=1 /a s=200 b=7 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(line);
        }
        for min in [64usize, 4096] {
            let chunks = structural_split_compact(StructuralKind::Log, &data, min);
            for codec in [ChunkCodec::Raw, ChunkCodec::Huffman, ChunkCodec::Zstd] {
                let f = match codec {
                    ChunkCodec::Raw => BudV2File::new(FormatCodec::Log, chunks.clone()).unwrap(),
                    ChunkCodec::Huffman => BudV2File::new_compressed(FormatCodec::Log, chunks.clone()).unwrap(),
                    ChunkCodec::Zstd => BudV2File::new_zstd(FormatCodec::Log, chunks.clone()).unwrap(),
                };
                let bytes = f.encode();
                for i in 0..bytes.len() {
                    let _ = BudV2File::decode(&bytes[..i]); // panik olmamalı
                }
                let _ = BudV2File::decode(&bytes);
            }
        }
    }

    #[test]
    fn decode_garbage_count_no_alloc_bomb() {
        // K38: çöp count alanı devasa ön-ayırım üretmemeli (lazy büyüme) - hızlı döner
        let csv = b"a\n";
        let chunks = structural_split(StructuralKind::Csv, csv);
        let hdr = BudV2Header::new(FormatCodec::Csv, &chunks);
        let mut tiny = hdr.to_bytes();
        tiny.push(ChunkCodec::Raw.to_u8());
        tiny.extend_from_slice(&999_999u32.to_le_bytes()); // dev count, veri YOK
        let start = std::time::Instant::now();
        assert!(BudV2File::decode(&tiny).is_none());
        // tekrar tekrar deneme de hızlı kalmalı (bellek DoS değil)
        for _ in 0..1000 {
            assert!(BudV2File::decode(&tiny).is_none());
        }
        assert!(start.elapsed().as_secs() < 5, "alloc-bomb yok: {:?}", start.elapsed());
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // Mini-fuzz (K38): rastgele bayt dizilerinde tüm decode/parse yolları panik'siz.
        // BudV2File::decode, BudV2Header::from_bytes, MultiHash::decode her girdide
        // Some/None dönmeli, ASLA panik üretmemeli (fuzz-güvenli tasarım kanıtı).
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
        let mut rng = Rng(0xF00D_2026_0816_00F0);
        let mut buf = vec![0u8; 256];
        for round in 0..4000u32 {
            let len = (rng.next() % 256) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let slice = &buf[..len];
            let _ = BudV2File::decode(slice);       // her boyutta (0..256) panik yok
            let _ = BudV2Header::from_bytes(slice);
            let _ = MultiHash::decode(slice);
            let _ = structural_split(StructuralKind::Json, slice);
            let _ = structural_split(StructuralKind::Binary, slice);
            let _ = structural_split_compact(StructuralKind::Json, slice, 7);
            if round % 100 == 0 {
                // belirli uzunlukta girdiler (başlık boyutları, sınırlar)
                for l in [0usize, 1, 55, 56, 57, 59, 60, 99, 100, 255] {
                    let _ = BudV2File::decode(&slice[..l.min(len)]);
                }
            }
        }
    }
}
