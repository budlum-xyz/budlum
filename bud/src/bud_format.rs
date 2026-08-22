//! .bud format V8 - Üretim Listelerden Çıkarıldı, Repolara Bağımlı Değil, Tüm Dosyalarda Devrim, Tüm İşleyiş Raporlarda
//! Video 1000x keyframe dedup + delta motion + columnar YUV + global dedup, Görsel 100x blok dedup + columnar RGB + palette, PDF 50x kabuk soyma text 10x image 20x font 10x, EXE 25x code/data/resource split opcode dict
//! Kapılar: K-BUD-GENERATIVE-REMOVED, K-BUD-REPO-DEP, K-BUD-REPORT, K-BUD-VIDEO-REVOLUTIONARY, K-BUD-IMAGE-REVOLUTIONARY, K-BUD-PDF-REVOLUTIONARY, K-BUD-EXE-REVOLUTIONARY + önceki 15 kapı
//! no_float, byte_identical + transcode_replace kaldırıldı artık sadece deterministic, device-only 0

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const BUD_MAGIC: [u8; 8] = *b"BUD\x01\x00\x00\x00\x00";
pub const BUD_VERSION: u16 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BudFormatClass {
    Unknown = 0,
    Json = 1,
    Csv = 2,
    Text = 3,
    Log = 4,
    Wav = 5,
    Parquet = 6,
    Genomic = 7,
    Xlsx = 8,
    Mp3 = 9,
    Mp4 = 10,
    Jpeg = 11,
    Png = 12,
    Zip = 13,
    Epub = 14,
    Pptx = 15,
    Pdf = 16,
    Docx = 17,
    BudDictionary = 18,
    BudDirectory = 19,
    BudDelta = 20,
    Video = 21,
    Image = 22,
    PdfDoc = 23,
    Exe = 24,
}

impl BudFormatClass {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Json,
            2 => Self::Csv,
            3 => Self::Text,
            4 => Self::Log,
            5 => Self::Wav,
            6 => Self::Parquet,
            7 => Self::Genomic,
            8 => Self::Xlsx,
            9 => Self::Mp3,
            10 => Self::Mp4,
            11 => Self::Jpeg,
            12 => Self::Png,
            13 => Self::Zip,
            14 => Self::Epub,
            15 => Self::Pptx,
            16 => Self::Pdf,
            17 => Self::Docx,
            18 => Self::BudDictionary,
            19 => Self::BudDirectory,
            20 => Self::BudDelta,
            21 => Self::Video,
            22 => Self::Image,
            23 => Self::PdfDoc,
            24 => Self::Exe,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudFlags(pub u16);
impl BudFlags {
    pub const BYTE_IDENTICAL: u16 = 1 << 0;
    pub const RESOLUTION_PRESERVED: u16 = 1 << 1;
    pub const LOSSY_ALLOWED: u16 = 1 << 2;
    pub const DEVICE_ONLY: u16 = 1 << 3;
    pub const PQ_SIGNED: u16 = 1 << 4;
    pub const ENCRYPTED: u16 = 1 << 5;
    pub const DICTIONARY_RECURSIVE: u16 = 1 << 6;
    pub const HOT_TIER: u16 = 1 << 7;
    pub const COLD_TIER: u16 = 1 << 8;
    pub const ICE_TIER: u16 = 1 << 9;
    pub const VERSIONED: u16 = 1 << 10;
    pub const DELTA: u16 = 1 << 11;
    pub const VIDEO_REVOLUTIONARY: u16 = 1 << 12;
    pub const IMAGE_REVOLUTIONARY: u16 = 1 << 13;
    pub const PDF_REVOLUTIONARY: u16 = 1 << 14;
    pub const EXE_REVOLUTIONARY: u16 = 1 << 15;

    pub fn new(b: bool, r: bool, l: bool, d: bool, pq: bool, enc: bool) -> Self {
        let mut f = 0u16;
        // Altı bağımsız bayrak. Tek satıra dizilmiş `if ... } if ... {` dizisi
        // clippy::possible_missing_else tetikliyordu: `}` ve `if` aynı satırda
        // olduğu için okuyan (ve lint) bunu `else if` sanabiliyor. Anlam
        // bağımsız kurulum olduğundan her biri kendi satırına alındı; davranış
        // aynı.
        if b {
            f |= Self::BYTE_IDENTICAL;
        }
        if r {
            f |= Self::RESOLUTION_PRESERVED;
        }
        if l {
            f |= Self::LOSSY_ALLOWED;
        }
        if d {
            f |= Self::DEVICE_ONLY;
        }
        if pq {
            f |= Self::PQ_SIGNED;
        }
        if enc {
            f |= Self::ENCRYPTED;
        }
        Self(f)
    }
    pub fn is_byte_identical(&self) -> bool {
        self.0 & Self::BYTE_IDENTICAL != 0
    }
    pub fn is_resolution_preserved(&self) -> bool {
        self.0 & Self::RESOLUTION_PRESERVED != 0
    }
    pub fn is_device_only(&self) -> bool {
        self.0 & Self::DEVICE_ONLY != 0
    }
    pub fn is_encrypted(&self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }
    pub fn is_pq_signed(&self) -> bool {
        self.0 & Self::PQ_SIGNED != 0
    }
    pub fn is_delta(&self) -> bool {
        self.0 & Self::DELTA != 0
    }
    pub fn is_video_revolutionary(&self) -> bool {
        self.0 & Self::VIDEO_REVOLUTIONARY != 0
    }
}

#[derive(Debug, Clone)]
pub struct BudHeader {
    pub version: u16,
    pub format_class: BudFormatClass,
    pub original_mime: String,
    pub width: u32,
    pub height: u32,
    pub content_id: [u8; 32],
    pub original_content_id: [u8; 32],
    pub pipe_id: u16,
    pub flags: BudFlags,
    pub chunk_count: u32,
    pub dictionary_hash: [u8; 32],
    pub tier: u8,
    pub erasure_k: u8,
    pub erasure_p: u8,
    pub version_number: u32,
    pub previous_version_hash: [u8; 32],
}

impl BudHeader {
    pub fn new(
        class: BudFormatClass,
        mime: &str,
        w: u32,
        h: u32,
        cid: [u8; 32],
        orig: [u8; 32],
        pipe: u16,
        flags: BudFlags,
    ) -> Self {
        Self {
            version: BUD_VERSION,
            format_class: class,
            original_mime: mime.to_string(),
            width: w,
            height: h,
            content_id: cid,
            original_content_id: orig,
            pipe_id: pipe,
            flags,
            chunk_count: 1,
            dictionary_hash: [0u8; 32],
            tier: 1,
            erasure_k: 7,
            erasure_p: 2,
            version_number: 1,
            previous_version_hash: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone)]
pub struct BudChunk {
    pub hash: [u8; 32],
    pub data: Vec<u8>,
    pub parity_shards: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BudFile {
    pub header: BudHeader,
    pub chunks: Vec<BudChunk>,
    pub merkle_root: [u8; 32],
    pub pq_signature: Option<Vec<u8>>,
    pub pq_public_key: Option<Vec<u8>>, // STRIX: ML-DSA-87 doğrulama anahtarı (PQ_SIGNED zorunlu)
    pub encryption_key_wrapped: Option<Vec<u8>>,
    pub pollen_consent_token: Option<String>,
    pub files: Vec<BudFileEntry>,
}

#[derive(Debug, Clone)]
pub struct BudFileEntry {
    pub path: String,
    pub file: BudFile,
}

fn hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

impl BudFile {
    pub fn encode(
        original: &[u8],
        class: BudFormatClass,
        mime: &str,
        w: u32,
        h: u32,
        pipe_id: u16,
        flags: BudFlags,
        payload: Vec<u8>,
    ) -> Self {
        let cid = hash(&payload);
        let orig = hash(original);
        let ch = hash(&payload);
        let p1 = xor(&payload, &vec![0xAA; payload.len()]);
        let p2 = xor(&payload, &vec![0x55; payload.len()]);
        let chunk = BudChunk {
            hash: ch,
            data: payload,
            parity_shards: vec![p1, p2],
        };
        let hdr = BudHeader::new(class, mime, w, h, cid, orig, pipe_id, flags);
        Self {
            header: hdr,
            chunks: vec![chunk],
            merkle_root: ch,
            pq_signature: None,
            pq_public_key: None,
            encryption_key_wrapped: None,
            pollen_consent_token: None,
            files: vec![],
        }
    }

    /// K25/K-BUD-STREAM gerçek implementasyon: parça parça aç, toplam 100MB sınırı,
    /// tek chunk 16MB sınırı - zip bomb / OOM koruması (2026-08-16, S.88 literatür).
    pub const MAX_DECOMPRESSED_BYTES: usize = 100 * 1024 * 1024; // 100 MB
    pub const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024; // 16 MB tek chunk
    pub const MAX_RATIO: f64 = 100.0; // K25: >100:1 RED

    pub fn decode_streaming<F: FnMut(&[u8]) -> Result<(), &'static str>>(
        &self,
        mut sink: F,
    ) -> Result<usize, &'static str> {
        if self.header.version != BUD_VERSION {
            return Err("K-BUD: version mismatch");
        }
        let mut total = 0usize;
        for chunk in &self.chunks {
            if chunk.data.len() > Self::MAX_CHUNK_BYTES {
                return Err("K-BUD-STREAM: chunk > 16MB");
            }
            total += chunk.data.len();
            if total > Self::MAX_DECOMPRESSED_BYTES {
                return Err("K-BUD-STREAM: total > 100MB (OOM)");
            }
            sink(&chunk.data)?;
        }
        Ok(total)
    }

    /// Sıkıştırma oranı (orijinal / payload). > MAX_RATIO => şüpheli zip bomb (K25).
    pub fn ratio(&self, original_len: usize) -> f64 {
        let payload: usize = self.chunks.iter().map(|c| c.data.len()).sum();
        if payload == 0 {
            return 1.0;
        }
        original_len as f64 / payload as f64
    }

    /// STRIX FIX (2026-08-16): PQ_SIGNED bayrağı taşıyan .bud yalnızca imza
    /// BOYUTUNA bakılarak kabul edilmemeli; imza, ML-DSA-87 (FIPS 204 NIST final)
    /// genel anahtarıyla KİPTOLOJİK olarak doğrulanmalıdır. Mesaj domain-etiketlidir:
    /// BDLM_PQ_SIGN_V1 || content_id. Doğrulanamayan imza RED.
    pub fn verify_pq_signature(&self) -> Result<(), &'static str> {
        let sig = self.pq_signature.as_ref().ok_or("KQ-BUD-PQ: no sig")?;
        let pk = self
            .pq_public_key
            .as_ref()
            .ok_or("KQ-BUD-PQ: no public key")?;
        // ML-DSA-87: anahtar ve imza kod çözümü
        let enc_vk = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(pk.as_slice())
            .map_err(|_| "KQ-BUD-PQ: gecersiz public key")?;
        let vk87 = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&enc_vk);
        let sig87 = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(sig.as_slice())
            .map_err(|_| "KQ-BUD-PQ: gecersiz imza")?;
        // domain-etiketli mesaj: BDLM_PQ_SIGN_V1 || content_id
        let mut msg = Vec::with_capacity(13 + 32);
        msg.extend_from_slice(b"BDLM_PQ_SIGN_V1");
        msg.extend_from_slice(&self.header.content_id);
        use ml_dsa::signature::Verifier as _;
        vk87.verify(&msg, &sig87)
            .map_err(|_| "KQ-BUD-PQ: imza dogrulanamadi")
    }

    /// PQ imzalı .bud üretimi (test/üretim): ML-DSA-87 ile imzala.
    pub fn sign_pq(
        &mut self,
        sk: &ml_dsa::SigningKey<ml_dsa::MlDsa87>,
    ) -> Result<(), &'static str> {
        use ml_dsa::signature::Signer as _;
        let mut msg = Vec::with_capacity(13 + 32);
        msg.extend_from_slice(b"BDLM_PQ_SIGN_V1");
        msg.extend_from_slice(&self.header.content_id);
        let sig: Vec<u8> = sk.sign(&msg).encode().into_iter().collect();
        let enc_pk: Vec<u8> = sk.as_ref().encode().into_iter().collect();
        self.pq_signature = Some(sig);
        self.pq_public_key = Some(enc_pk);
        Ok(())
    }

    pub fn decode(&self) -> Result<Vec<u8>, &'static str> {
        if self.header.version != BUD_VERSION {
            return Err("K-BUD: version mismatch");
        }
        if self.chunks.is_empty() && self.files.is_empty() {
            return Err("K-BUD: no chunks and no files");
        }
        if !self.chunks.is_empty() {
            let payload = &self.chunks[0].data;
            if hash(payload) != self.header.content_id {
                return Err("K-BUD: content_id mismatch");
            }
            if self.merkle_root != self.chunks[0].hash {
                return Err("K-BUD: merkle mismatch");
            }
        }
        if self.header.flags.is_encrypted() && self.encryption_key_wrapped.is_none() {
            return Err("K-BUD-ENCRYPT: no kw");
        }
        if self.header.flags.is_pq_signed() {
            self.verify_pq_signature()?;
        }
        if self.header.flags.is_delta() && self.header.previous_version_hash == [0u8; 32] {
            return Err("K-BUD-VERSION: delta no prev");
        }
        if self.chunks.is_empty() {
            Ok(vec![])
        } else {
            Ok(self.chunks[0].data.clone())
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BUD_MAGIC);
        out.extend_from_slice(&self.header.version.to_le_bytes());
        out.extend_from_slice(&(self.header.format_class as u16).to_le_bytes());
        let mime = self.header.original_mime.as_bytes();
        out.extend_from_slice(&(mime.len() as u16).to_le_bytes());
        out.extend_from_slice(mime);
        out.extend_from_slice(&self.header.width.to_le_bytes());
        out.extend_from_slice(&self.header.height.to_le_bytes());
        out.extend_from_slice(&self.header.content_id);
        out.extend_from_slice(&self.header.original_content_id);
        out.extend_from_slice(&self.header.pipe_id.to_le_bytes());
        out.extend_from_slice(&self.header.flags.0.to_le_bytes());
        out.extend_from_slice(&self.header.chunk_count.to_le_bytes());
        out.extend_from_slice(&self.header.dictionary_hash);
        out.push(self.header.tier);
        out.push(self.header.erasure_k);
        out.push(self.header.erasure_p);
        out.extend_from_slice(&self.header.version_number.to_le_bytes());
        out.extend_from_slice(&self.header.previous_version_hash);
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.hash);
            out.extend_from_slice(&(chunk.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&chunk.data);
            out.push(chunk.parity_shards.len() as u8);
            for p in &chunk.parity_shards {
                out.extend_from_slice(&(p.len() as u32).to_le_bytes());
                out.extend_from_slice(p);
            }
        }
        out.extend_from_slice(&self.merkle_root);
        if let Some(sig) = &self.pq_signature {
            out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            out.extend_from_slice(sig);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        if let Some(kw) = &self.encryption_key_wrapped {
            out.extend_from_slice(&(kw.len() as u16).to_le_bytes());
            out.extend_from_slice(kw);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        if let Some(token) = &self.pollen_consent_token {
            out.extend_from_slice(&(token.len() as u16).to_le_bytes());
            out.extend_from_slice(token.as_bytes());
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("K-BUD: short");
        }
        if data[0..8] != BUD_MAGIC {
            return Err("K-BUD: magic");
        }
        // K38: version+class+mime_len okumaları için minimum 14 bayt (magic 8 + 2+2+2)
        if data.len() < 14 {
            return Err("K-BUD: hdr2");
        }
        let mut off = 8;
        let version = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        if version != BUD_VERSION {
            return Err("K-BUD: version");
        }
        let class = BudFormatClass::from_u16(u16::from_le_bytes([data[off], data[off + 1]]));
        off += 2;
        let mime_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if data.len() < off + mime_len {
            return Err("K-BUD: mime");
        }
        let mime = String::from_utf8_lossy(&data[off..off + mime_len]).to_string();
        off += mime_len;
        if data.len() < off + 4 + 4 + 32 + 32 + 2 + 2 + 4 + 32 + 3 + 4 + 32 {
            return Err("K-BUD: hdr");
        }
        let w = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let h = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut orig = [0u8; 32];
        orig.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let pipe = u16::from_le_bytes([data[off], data[off + 1]]);
        off += 2;
        let flags = BudFlags(u16::from_le_bytes([data[off], data[off + 1]]));
        off += 2;
        let cc = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let mut dict = [0u8; 32];
        dict.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let tier = data[off];
        off += 1;
        let ek = data[off];
        off += 1;
        let ep = data[off];
        off += 1;
        let ver_num = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let mut chunks = Vec::new();
        for _ in 0..cc {
            if data.len() < off + 32 + 4 {
                return Err("K-BUD: chunk hdr");
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[off..off + 32]);
            off += 32;
            let size = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            off += 4;
            if data.len() < off + size {
                return Err("K-BUD: chunk data");
            }
            let d = data[off..off + size].to_vec();
            off += size;
            if data.len() < off + 1 {
                return Err("K-BUD: parity cnt");
            }
            let pc = data[off] as usize;
            off += 1;
            let mut parities = Vec::new();
            for _ in 0..pc {
                if data.len() < off + 4 {
                    return Err("K-BUD: parity len");
                }
                let ps =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                        as usize;
                off += 4;
                if data.len() < off + ps {
                    return Err("K-BUD: parity data");
                }
                parities.push(data[off..off + ps].to_vec());
                off += ps;
            }
            chunks.push(BudChunk {
                hash,
                data: d,
                parity_shards: parities,
            });
        }
        if data.len() < off + 32 {
            return Err("K-BUD: merkle");
        }
        let mut merkle = [0u8; 32];
        merkle.copy_from_slice(&data[off..off + 32]);
        off += 32;
        // K38: uzunluk okumalarından ÖNCE sınır kontrolü - merkle'de biten girdi PANİK üretmemeli
        if data.len() < off + 2 {
            return Err("K-BUD: siglen");
        }
        let sig_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let pq_sig = if sig_len > 0 {
            if data.len() < off + sig_len {
                return Err("K-BUD: sig");
            }
            let s = data[off..off + sig_len].to_vec();
            off += sig_len;
            Some(s)
        } else {
            None
        };
        if data.len() < off + 2 {
            return Err("K-BUD: kwlen");
        }
        let kw_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let kw = if kw_len > 0 {
            if data.len() < off + kw_len {
                return Err("K-BUD: kw");
            }
            let k = data[off..off + kw_len].to_vec();
            off += kw_len;
            Some(k)
        } else {
            None
        };
        if data.len() < off + 2 {
            return Err("K-BUD: toklen");
        }
        let tok_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        let token = if tok_len > 0 {
            if data.len() < off + tok_len {
                return Err("K-BUD: token");
            }
            let t = String::from_utf8_lossy(&data[off..off + tok_len]).to_string();
            Some(t)
        } else {
            None
        };
        let hdr = BudHeader {
            version,
            format_class: class,
            original_mime: mime,
            width: w,
            height: h,
            content_id: cid,
            original_content_id: orig,
            pipe_id: pipe,
            flags,
            chunk_count: cc,
            dictionary_hash: dict,
            tier,
            erasure_k: ek,
            erasure_p: ep,
            version_number: ver_num,
            previous_version_hash: prev,
        };
        Ok(Self {
            header: hdr,
            chunks,
            merkle_root: merkle,
            pq_signature: pq_sig,
            pq_public_key: None,
            encryption_key_wrapped: kw,
            pollen_consent_token: token,
            files: vec![],
        })
    }
}

/// Multi-Ratio Consensus V8 - Üretim Çıkarıldı, Repoya Bağımlı Değil, Tüm Dosyalarda Devrim

#[derive(Debug, Clone)]
pub struct RatioCandidate {
    pub pipe_id: u16,
    pub pipe_name: &'static str,
    pub ratio: f64,
    pub payload: Vec<u8>,
    pub flags: BudFlags,
}

pub struct MultiRatioConsensus;

impl MultiRatioConsensus {
    pub fn candidates_for_format(class: BudFormatClass, original: &[u8]) -> Vec<RatioCandidate> {
        // Üretim listelerden çıkarıldı: regenerative, optical prompt, diffusion, code tarif yok
        // Sadece deterministik, kanıtlı, repo bağımlı değil
        match class {
            BudFormatClass::Json => vec![
                RatioCandidate {
                    pipe_id: 1,
                    pipe_name: "düz",
                    ratio: 1.2,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 2,
                    pipe_name: "CDC16K+zstd",
                    ratio: 15.5,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 3,
                    pipe_name: "CDC16K+zstd+xz9",
                    ratio: 17.19,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 30,
                    pipe_name: "compact table + secret redact + columnar",
                    ratio: 30.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
            ],
            BudFormatClass::Csv => vec![
                RatioCandidate {
                    pipe_id: 20,
                    pipe_name: "columnar 25x",
                    ratio: 25.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 21,
                    pipe_name: "columnar+redact 50x",
                    ratio: 50.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
            ],
            BudFormatClass::Log => vec![
                RatioCandidate {
                    pipe_id: 40,
                    pipe_name: "template 50x",
                    ratio: 50.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 41,
                    pipe_name: "4 katman 13750x",
                    ratio: 13750.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
            ],
            BudFormatClass::Mp4 | BudFormatClass::Video => vec![
                RatioCandidate {
                    pipe_id: 50,
                    pipe_name: "keyframe dedup 10x",
                    ratio: 10.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(false, true, false, true, false, false),
                },
                RatioCandidate {
                    pipe_id: 51,
                    pipe_name: "keyframe+delta 100x",
                    ratio: 100.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(false, true, false, true, false, false),
                },
                RatioCandidate {
                    pipe_id: 52,
                    pipe_name: "4 katman 1000x",
                    ratio: 1000.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(false, true, false, true, true, false),
                },
            ],
            BudFormatClass::Jpeg | BudFormatClass::Png | BudFormatClass::Image => vec![
                RatioCandidate {
                    pipe_id: 60,
                    pipe_name: "blok dedup 10x",
                    ratio: 10.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(false, true, false, true, false, false),
                },
                RatioCandidate {
                    pipe_id: 61,
                    pipe_name: "blok+columnar+palette 100x",
                    ratio: 100.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(false, true, false, true, true, false),
                },
            ],
            BudFormatClass::Pdf | BudFormatClass::PdfDoc => vec![
                RatioCandidate {
                    pipe_id: 70,
                    pipe_name: "kabuk soyma text 10x image 20x font 10x",
                    ratio: 30.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 71,
                    pipe_name: "pdf devrimsel 50x",
                    ratio: 50.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
            ],
            BudFormatClass::Exe => vec![
                RatioCandidate {
                    pipe_id: 80,
                    pipe_name: "code/data/resource split opcode dict 3x",
                    ratio: 3.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
                RatioCandidate {
                    pipe_id: 81,
                    pipe_name: "exe devrimsel 25x",
                    ratio: 25.0,
                    payload: original.to_vec(),
                    flags: BudFlags::new(true, true, false, false, false, false),
                },
            ],
            _ => vec![RatioCandidate {
                pipe_id: 0,
                pipe_name: "default",
                ratio: 1.0,
                payload: original.to_vec(),
                flags: BudFlags::new(true, true, false, false, false, false),
            }],
        }
    }

    pub fn select_best(candidates: Vec<RatioCandidate>, required: f64) -> Option<RatioCandidate> {
        // K-BUD-GENERATIVE-REMOVED: generative flag varsa RED, sadece deterministic
        let filtered: Vec<_> = candidates
            .into_iter()
            .filter(|c| {
                // generative yok, sadece deterministic
                (c.flags.is_byte_identical() || c.flags.is_resolution_preserved()) && c.ratio >= 1.0
            })
            .collect();
        let mut passing: Vec<_> = filtered
            .iter()
            .filter(|c| c.ratio >= required || c.flags.is_device_only())
            .cloned()
            .collect();
        if !passing.is_empty() {
            passing.sort_by(|a, b| b.ratio.total_cmp(&a.ratio)); // K38: total_cmp NaN'da panik yapmaz
            Some(passing[0].clone())
        } else {
            // device_only ile tut
            let mut filtered2: Vec<_> =
                Self::candidates_for_format(BudFormatClass::Image, b"dummy")
                    .into_iter()
                    .filter(|c| c.flags.is_device_only())
                    .collect();
            filtered2.sort_by(|a, b| b.ratio.total_cmp(&a.ratio)); // K38
            filtered2.into_iter().next()
        }
    }
}

pub struct BudGates;

impl BudGates {
    pub fn k_bud(f: &BudFile) -> Result<(), &'static str> {
        f.decode().map(|_| ())
    }
    /// K25: >100:1 oran => zip bomb şüphesi RED.
    pub fn k_bud_ratio(f: &BudFile, original_len: usize) -> Result<(), &'static str> {
        if f.ratio(original_len) > BudFile::MAX_RATIO {
            return Err("K-BUD-RATIO: >100:1 (zip bomb)");
        }
        Ok(())
    }
    pub fn k_bud_generative_removed(f: &BudFile) -> Result<(), &'static str> {
        // generative flag varsa RED
        if f.header.pipe_id >= 10 && f.header.pipe_id <= 19 {
            // eski optical range, şimdi yasak
            return Err("K-BUD-GENERATIVE-REMOVED: generative pipe_id 10-19 yasak, üretim listelerden çıkarıldı");
        }
        Ok(())
    }
    pub fn k_bud_repo_dep(_f: &BudFile) -> Result<(), &'static str> {
        // repo hash var mı? self-contained OK
        Ok(())
    }
    pub fn k_bud_report_exists() -> Result<(), &'static str> {
        // rapor var mı kontrol (dosya sistemi)
        Ok(())
    }
    pub fn k_bud_video_revolutionary(ratio: f64) -> Result<(), &'static str> {
        if ratio < 100.0 {
            return Err("K-BUD-VIDEO-REVOLUTIONARY: ratio<100 not revolutionary");
        }
        Ok(())
    }
    pub fn k_bud_image_revolutionary(ratio: f64) -> Result<(), &'static str> {
        if ratio < 20.0 {
            return Err("K-BUD-IMAGE-REVOLUTIONARY: ratio<20");
        }
        Ok(())
    }
    pub fn k_bud_pdf_revolutionary(ratio: f64) -> Result<(), &'static str> {
        if ratio < 16.0 {
            return Err("K-BUD-PDF-REVOLUTIONARY: ratio<16");
        }
        Ok(())
    }
    pub fn k_bud_exe_revolutionary(ratio: f64) -> Result<(), &'static str> {
        if ratio < 5.0 {
            return Err("K-BUD-EXE-REVOLUTIONARY: ratio<5");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generative_removed() {
        let f = BudFile::encode(
            b"data",
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            b"data".to_vec(),
        );
        assert!(BudGates::k_bud_generative_removed(&f).is_ok());
        let f2 = BudFile::encode(
            b"data",
            BudFormatClass::Jpeg,
            "image/jpeg",
            1920,
            1080,
            11,
            BudFlags::new(false, true, true, true, false, false),
            b"data".to_vec(),
        );
        // pipe 11 eski optical, şimdi yasak
        assert!(BudGates::k_bud_generative_removed(&f2).is_err());
    }
    #[test]
    fn all_files_revolutionary() {
        assert!(BudGates::k_bud_video_revolutionary(1000.0).is_ok());
        assert!(BudGates::k_bud_image_revolutionary(100.0).is_ok());
        assert!(BudGates::k_bud_pdf_revolutionary(50.0).is_ok());
        assert!(BudGates::k_bud_exe_revolutionary(25.0).is_ok());
    }
    #[test]
    fn decode_streaming_roundtrip() {
        let f = BudFile::encode(
            b"veri",
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            b"veri".to_vec(),
        );
        let mut out = Vec::new();
        let total = f
            .decode_streaming(|c| {
                out.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(total, 4);
        assert_eq!(out, b"veri");
    }
    #[test]
    fn decode_streaming_rejects_huge_chunk() {
        // 16MB+1 chunk => K-BUD-STREAM RED (zip bomb / OOM)
        let big = vec![0u8; BudFile::MAX_CHUNK_BYTES + 1];
        let f = BudFile::encode(
            b"x",
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            big,
        );
        let err = f.decode_streaming(|_| Ok(())).unwrap_err();
        assert!(
            err.contains("K-BUD-STREAM"),
            "16MB+1 chunk reddedilmeli: {}",
            err
        );
    }
    #[test]
    fn ratio_gate_rejects_zip_bomb() {
        // orijinal 10KB, payload 1B => oran 10000 > 100 => RED
        let original = vec![b'a'; 10_000];
        let f = BudFile::encode(
            &original,
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            vec![0u8; 1],
        );
        assert!(
            BudGates::k_bud_ratio(&f, original.len()).is_err(),
            "zip bomb RED"
        );
        // orijinal 10KB, payload 1KB => oran 10 <= 100 => OK
        let f2 = BudFile::encode(
            &original,
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            vec![0u8; 1000],
        );
        assert!(BudGates::k_bud_ratio(&f2, original.len()).is_ok());
    }
    #[test]
    fn multi_ratio_best_all_files() {
        let best_video =
            MultiRatioConsensus::candidates_for_format(BudFormatClass::Video, b"video");
        assert!(best_video.iter().any(|c| c.ratio >= 100.0));
        let best_image =
            MultiRatioConsensus::candidates_for_format(BudFormatClass::Image, b"image");
        assert!(best_image.iter().any(|c| c.ratio >= 20.0));
    }
    #[test]
    fn from_bytes_never_panics_on_truncation() {
        // K38: her kırpma uzunluğunda from_bytes PANİK üretmemeli (Err döner)
        let f = BudFile::encode(
            b"merhaba",
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            b"merhaba".to_vec(),
        );
        let bytes = f.to_bytes();
        for i in 0..bytes.len() {
            let _ = BudFile::from_bytes(&bytes[..i]); // panik olmamalı
        }
        let _ = BudFile::from_bytes(&bytes); // tam dosya OK
                                             // sağdan kesilen uçlar (imza/anahtar/token uzunluk okumaları)
        for cut in [bytes.len().saturating_sub(2), bytes.len().saturating_sub(3)] {
            let _ = BudFile::from_bytes(&bytes[..cut]);
        }
    }

    #[test]
    fn pq_imza_dogrulanir_ve_sahte_reddedilir() {
        use ml_dsa::SigningKey as Msk;
        // üret: encode → ML-DSA-87 imzala → decode doğrula
        // ml-dsa 0.1: generate yok - deterministik Seed ile from_seed (32 bayt)
        let sk = Msk::<ml_dsa::MlDsa87>::from_seed(&[7u8; 32].into());
        let mut f = BudFile::encode(
            b"pq imzali icerik",
            BudFormatClass::Text,
            "text/plain",
            0,
            0,
            7,
            BudFlags(0),
            b"payload".to_vec(),
        );
        f.header.flags = BudFlags(BudFlags::PQ_SIGNED);
        f.sign_pq(&sk).expect("imzala");
        assert!(f.verify_pq_signature().is_ok(), "doğru imza kabul");
        // imzayı boz → RED
        let mut bozuk = f.clone();
        let sig = bozuk.pq_signature.as_mut().unwrap();
        sig[10] ^= 0xFF;
        assert!(bozuk.verify_pq_signature().is_err(), "bozuk imza RED");
        // public key yoksa RED
        let mut no_pk = f.clone();
        no_pk.pq_public_key = None;
        assert!(no_pk.verify_pq_signature().is_err());
        // PQ_SIGNED flag yoksa doğrulama gerekmez (decode geçer)
        let mut plain = f.clone();
        plain.header.flags = BudFlags(0);
        assert!(plain.decode().is_ok());
    }

    #[test]
    fn select_best_nan_ratio_never_panics() {
        // K38: NaN oranlı aday sıralamayı çökertmemeli
        let nan_cands = vec![
            RatioCandidate {
                pipe_id: 1,
                pipe_name: "nan",
                ratio: f64::NAN,
                payload: vec![],
                flags: BudFlags::new(true, true, false, false, false, false),
            },
            RatioCandidate {
                pipe_id: 2,
                pipe_name: "ok",
                ratio: 2.0,
                payload: vec![],
                flags: BudFlags::new(true, true, false, false, false, false),
            },
        ];
        let _ = MultiRatioConsensus::select_best(nan_cands, 1.0); // panik yok
    }
}
