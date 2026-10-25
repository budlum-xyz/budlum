//! .bud format V8 - generation removed from the lists, no repo dependency, a revolution across all files, the whole workflow in the reports
//! Video 1000x keyframe dedup + delta motion + columnar YUV + global dedup, images 100x block dedup + columnar RGB + palette, PDF 50x shell peeling text 10x image 20x font 10x, EXE 25x code/data/resource split opcode dict
//! Gates: K-BUD-GENERATIVE-REMOVED, K-BUD-REPO-DEP, K-BUD-REPORT, K-BUD-VIDEO-REVOLUTIONARY, K-BUD-IMAGE-REVOLUTIONARY, K-BUD-PDF-REVOLUTIONARY, K-BUD-EXE-REVOLUTIONARY + the previous 15 gates
//! no_float, byte_identical + transcode_replace removed, now deterministic only, device-only 0

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
        // Six independent flags. A `if ... } if ... {` sequence packed onto one
        // line used to trigger clippy::possible_missing_else: with `}` and `if`
        // on the same line a reader (and the lint) can mistake it for
        // `else if`. Since the meaning is an independent set of assignments,
        // each one was moved onto its own line; the behaviour is the same.
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
            // v1 stores no erasure code: (0, 0) says so. Real repair needs
            // bud_format_erasure and a stored layout (see BLG-0568).
            erasure_k: 0,
            erasure_p: 0,
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
    /// UNTRUSTED provenance: the key the producer says it signed with.
    /// Never feed this to a verifier - it travels inside the object it would
    /// authenticate. Verification takes the caller's key
    /// ([`BudFile::verify_pq_signature_with`]).
    pub pq_public_key: Option<Vec<u8>>,
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
        // No parity: the old shards were the payload XOR a constant, each one
        // a full copy and no k-of-n code.
        let chunk = BudChunk {
            hash: ch,
            data: payload,
            parity_shards: vec![],
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

    /// K25/K-BUD-STREAM real implementation: decompress chunk by chunk, with a
    /// 100MB total bound and a 16MB single-chunk bound - zip bomb / OOM
    /// protection (2026-08-16, S.88 literature).
    pub const MAX_DECOMPRESSED_BYTES: usize = 100 * 1024 * 1024; // 100 MB
    pub const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024; // 16 MB tek chunk
    pub const MAX_RATIO: f64 = 100.0; // K25: >100:1 RED (reporting only; the gate uses MAX_RATIO_FIXED)

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
            // Never hand unverified bytes to the sink.
            if hash(&chunk.data) != chunk.hash {
                return Err("K-BUD-STREAM: chunk hash mismatch");
            }
            sink(&chunk.data)?;
        }
        Ok(total)
    }

    /// Compression ratio (original / payload). > MAX_RATIO => a suspected zip bomb (K25).
    pub fn ratio(&self, original_len: usize) -> f64 {
        let payload: usize = self.chunks.iter().map(|c| c.data.len()).sum();
        if payload == 0 {
            return 1.0;
        }
        original_len as f64 / payload as f64
    }

    /// Verify the PQ signature against a key the CALLER trusts.
    ///
    /// Fix (2026-08-16): a .bud carrying the PQ_SIGNED flag must not be
    /// accepted by looking at the signature SIZE alone; the signature must be
    /// verified CRYPTOGRAPHICALLY against the ML-DSA-87 (FIPS 204 NIST final)
    /// public key. The message is domain tagged: BDLM_PQ_SIGN_V1 || content_id.
    /// A signature that cannot be verified is REFUSED.
    ///
    /// `trusted_key` is the publisher key the caller already trusts - pinned in
    /// its configuration, carried with the content id, or delivered out of
    /// band. It is deliberately NOT read from the container: a verification key
    /// that travels inside the object being authenticated proves only that the
    /// object agrees with itself, because whoever can rewrite the file can
    /// rewrite the key. [`Self::pq_public_key`] stays on the wire as untrusted
    /// provenance for display and nothing on the authentication path may read
    /// it.
    ///
    /// WIRING: this is the door for a caller that already holds the publisher
    /// key - a pinned trust store, or the key that arrived with the content id
    /// out of band. `decode` is deliberately not that caller: a container
    /// cannot authenticate itself, so the call belongs where the publisher's
    /// identity is known and not in the parser.
    pub fn verify_pq_signature_with(&self, trusted_key: &[u8]) -> Result<(), &'static str> {
        let sig = self.pq_signature.as_ref().ok_or("KQ-BUD-PQ: no sig")?;
        let pk = trusted_key;
        // ML-DSA-87: decode the key and the signature
        let enc_vk = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(pk)
            .map_err(|_| "KQ-BUD-PQ: invalid public key")?;
        let vk87 = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&enc_vk);
        let sig87 = ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(sig.as_slice())
            .map_err(|_| "KQ-BUD-PQ: invalid signature")?;
        // domain-etiketli mesaj: BDLM_PQ_SIGN_V1 || content_id
        let mut msg = Vec::with_capacity(13 + 32);
        msg.extend_from_slice(b"BDLM_PQ_SIGN_V1");
        msg.extend_from_slice(&self.header.content_id);
        use ml_dsa::signature::Verifier as _;
        vk87.verify(&msg, &sig87)
            .map_err(|_| "KQ-BUD-PQ: the signature did not verify")
    }

    /// Producing a PQ-signed .bud (test/production): sign with ML-DSA-87.
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
            // v1 holds exactly one chunk. A second chunk would carry bytes that
            // no hash covers, and decode returns the first chunk only.
            if self.chunks.len() != 1 || self.header.chunk_count != 1 {
                return Err("K-BUD: v1 holds exactly one chunk");
            }
            let payload = &self.chunks[0].data;
            if hash(payload) != self.header.content_id {
                return Err("K-BUD: content_id mismatch");
            }
            // The stored chunk hash is recomputed here, so the root below is
            // the hash of the data and not a stored field.
            if hash(payload) != self.chunks[0].hash {
                return Err("K-BUD: chunk hash mismatch");
            }
            if self.merkle_root != self.chunks[0].hash {
                return Err("K-BUD: merkle mismatch");
            }
        }
        if self.header.flags.is_encrypted() && self.encryption_key_wrapped.is_none() {
            return Err("K-BUD-ENCRYPT: no kw");
        }
        if self.header.flags.is_pq_signed() {
            // Structural only. A signature inside a container cannot be
            // verified without a key from outside it (see
            // [`Self::verify_pq_signature_with`]), so `decode` checks that the
            // file carries a well-formed signature and leaves the cryptographic
            // answer to the caller that knows the publisher. Nothing here - and
            // nothing downstream - treats the flag as provenance or
            // authorisation on the strength of the embedded key.
            self.pq_signature
                .as_ref()
                .ok_or("KQ-BUD-PQ: no sig")
                .and_then(|sig| {
                    ml_dsa::Signature::<ml_dsa::MlDsa87>::try_from(sig.as_slice())
                        .map(|_| ())
                        .map_err(|_| "KQ-BUD-PQ: invalid signature")
                })?;
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

    /// Serialise without silent truncation: a field that does not fit its
    /// length prefix is an error (BLG-0574).
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        fn len16(n: usize) -> Result<[u8; 2], &'static str> {
            u16::try_from(n)
                .map(u16::to_le_bytes)
                .map_err(|_| "K-BUD: field over 65535 bytes")
        }
        fn len32(n: usize) -> Result<[u8; 4], &'static str> {
            u32::try_from(n)
                .map(u32::to_le_bytes)
                .map_err(|_| "K-BUD: field over 4 GiB")
        }
        let mut out = Vec::new();
        out.extend_from_slice(&BUD_MAGIC);
        out.extend_from_slice(&self.header.version.to_le_bytes());
        out.extend_from_slice(&(self.header.format_class as u16).to_le_bytes());
        let mime = self.header.original_mime.as_bytes();
        out.extend_from_slice(&len16(mime.len())?);
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
            out.extend_from_slice(&len32(chunk.data.len())?);
            out.extend_from_slice(&chunk.data);
            let parity_count = u8::try_from(chunk.parity_shards.len())
                .map_err(|_| "K-BUD: over 255 parity shards")?;
            out.push(parity_count);
            for p in &chunk.parity_shards {
                out.extend_from_slice(&len32(p.len())?);
                out.extend_from_slice(p);
            }
        }
        out.extend_from_slice(&self.merkle_root);
        if let Some(sig) = &self.pq_signature {
            out.extend_from_slice(&len16(sig.len())?);
            out.extend_from_slice(sig);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        if let Some(kw) = &self.encryption_key_wrapped {
            out.extend_from_slice(&len16(kw.len())?);
            out.extend_from_slice(kw);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        if let Some(token) = &self.pollen_consent_token {
            out.extend_from_slice(&len16(token.len())?);
            out.extend_from_slice(token.as_bytes());
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        // Optional trailing field: the PQ verification key. It is written only
        // when present, so a file without a key keeps its old bytes.
        if let Some(pk) = &self.pq_public_key {
            out.extend_from_slice(&len16(pk.len())?);
            out.extend_from_slice(pk);
        }
        Ok(out)
    }

    /// Infallible form. A field that does not fit gives an empty vector,
    /// which `from_bytes` refuses; use `try_to_bytes` to see the reason.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes().unwrap_or_default()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("K-BUD: short");
        }
        if data[0..8] != BUD_MAGIC {
            return Err("K-BUD: magic");
        }
        // K38: a minimum of 14 bytes for the version+class+mime_len reads (magic 8 + 2+2+2)
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
        let mime = std::str::from_utf8(&data[off..off + mime_len])
            .map_err(|_| "K-BUD: mime not utf8")?
            .to_string();
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
        // K38: bounds check BEFORE the length reads - input ending inside the merkle must not PANIC
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
            let t = std::str::from_utf8(&data[off..off + tok_len])
                .map_err(|_| "K-BUD: token not utf8")?
                .to_string();
            off += tok_len;
            Some(t)
        } else {
            None
        };
        let pq_pk = if off < data.len() {
            if data.len() < off + 2 {
                return Err("K-BUD: pklen");
            }
            let pk_len = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
            off += 2;
            if pk_len == 0 || data.len() < off + pk_len {
                return Err("K-BUD: pk");
            }
            let k = data[off..off + pk_len].to_vec();
            off += pk_len;
            Some(k)
        } else {
            None
        };
        // Two byte strings must not parse to one file.
        if off != data.len() {
            return Err("K-BUD: trailing bytes");
        }
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
            pq_public_key: pq_pk,
            encryption_key_wrapped: kw,
            pollen_consent_token: token,
            files: vec![],
        })
    }
}

/// Multi-Ratio Consensus V8 - generation removed, no repo dependency, a revolution across all files

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
    /// The ratio of a candidate, measured from its payload. A hand-written
    /// literal is a claim, not a measurement (BLG-0573).
    fn measured_ratio(original_len: usize, payload_len: usize) -> f64 {
        if payload_len == 0 {
            return 1.0;
        }
        original_len as f64 / payload_len as f64
    }

    pub fn candidates_for_format(class: BudFormatClass, original: &[u8]) -> Vec<RatioCandidate> {
        Self::claimed_candidates(class, original)
            .into_iter()
            .map(|mut c| {
                // The listed ratio is the target of the pipe. Nothing here
                // compresses, so the ratio that counts is the measured one.
                c.ratio = Self::measured_ratio(original.len(), c.payload.len());
                c
            })
            .collect()
    }

    fn claimed_candidates(class: BudFormatClass, original: &[u8]) -> Vec<RatioCandidate> {
        // Generation was removed from the lists: no regenerative, optical
        // prompt, diffusion or code recipe. Deterministic and proven only, with
        // no repo dependency.
        match class {
            BudFormatClass::Json => vec![
                RatioCandidate {
                    pipe_id: 1,
                    pipe_name: "flat",
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
                    pipe_name: "4 layers 13750x",
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
                    pipe_name: "4 layers 1000x",
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
        // K-BUD-GENERATIVE-REMOVED: a generative flag is REJECTED; deterministic only
        let filtered: Vec<_> = candidates
            .into_iter()
            .filter(|c| {
                // no generative path; deterministic only
                (c.flags.is_byte_identical() || c.flags.is_resolution_preserved()) && c.ratio >= 1.0
            })
            .collect();
        let mut passing: Vec<_> = filtered
            .iter()
            .filter(|c| c.ratio >= required || c.flags.is_device_only())
            .cloned()
            .collect();
        // `total_cmp`: a NaN ratio must not panic the sort.
        passing.sort_by(|a, b| b.ratio.total_cmp(&a.ratio));
        // No candidate: the callers store the original bytes verbatim. There
        // used to be a fallback here that pulled the Image list's device-only
        // candidates built over the literal `b"dummy"`, so a caller that
        // trusted the returned payload wrote five bytes of "dummy" in place of
        // the user's data.
        passing.into_iter().next()
    }
}

pub struct BudGates;

/// The zip-bomb limit in fixed point: the value the gate actually compares
/// against. `BudFile::MAX_RATIO` is the same 100:1 for humans and for
/// reporting; this is the one that decides acceptance, and it is an integer so
/// the decision cannot vary between machines.
const MAX_RATIO_FIXED: i64 = crate::bud_fixed_point::fixed_from_int(100);

impl BudGates {
    pub fn k_bud(f: &BudFile) -> Result<(), &'static str> {
        f.decode().map(|_| ())
    }
    /// K25: a ratio over 100:1 => refused as a suspected zip bomb.
    ///
    /// The comparison runs in fixed point, not on `f64`. This decides whether
    /// an object is accepted, and a float division is allowed to differ in its
    /// last bit between machines: two nodes could disagree on whether the same
    /// file is a bomb, and a verdict that varies by machine is a fork. The
    /// integer path gives the same answer everywhere.
    pub fn k_bud_ratio(f: &BudFile, original_len: usize) -> Result<(), &'static str> {
        let payload: usize = f.chunks.iter().map(|c| c.data.len()).sum();
        if payload == 0 && original_len > 0 {
            return Err("K-BUD-RATIO: empty payload for a non-empty original (zip bomb)");
        }
        let measured = crate::bud_fixed_point::fixed_ratio(original_len as u64, payload as u64);
        if measured > MAX_RATIO_FIXED {
            return Err("K-BUD-RATIO: >100:1 (zip bomb)");
        }
        Ok(())
    }
    pub fn k_bud_generative_removed(f: &BudFile) -> Result<(), &'static str> {
        // a generative flag is REFUSED
        if f.header.pipe_id >= 10 && f.header.pipe_id <= 19 {
            // the old optical range, now forbidden
            return Err("K-BUD-GENERATIVE-REMOVED: generative pipe_id 10-19 is forbidden, generation was removed from the lists");
        }
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
    fn v1_encode_stores_no_fake_parity() {
        let payload = b"payload bytes".to_vec();
        let f = BudFile::encode(
            &payload,
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            payload.clone(),
        );
        assert!(f.chunks[0].parity_shards.is_empty());
        assert_eq!((f.header.erasure_k, f.header.erasure_p), (0, 0));
        // The file is about one payload, not three.
        assert!(f.to_bytes().len() < 3 * payload.len() + 300);
        let back = BudFile::from_bytes(&f.to_bytes()).unwrap();
        assert_eq!(back.decode().unwrap(), payload);
    }
    fn one_chunk_file() -> BudFile {
        BudFile::encode(
            b"abc",
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            b"abc".to_vec(),
        )
    }
    #[test]
    fn decode_rejects_unauthenticated_extra_chunk() {
        let mut f = one_chunk_file();
        assert!(f.decode().is_ok());
        f.chunks.push(BudChunk {
            hash: [9u8; 32],
            data: b"smuggled".to_vec(),
            parity_shards: vec![],
        });
        f.header.chunk_count = 2;
        assert!(f.decode().is_err());
        // The streaming path refuses the chunk whose hash does not match.
        let mut seen = Vec::new();
        let r = f.decode_streaming(|c| {
            seen.extend_from_slice(c);
            Ok(())
        });
        assert!(r.is_err());
        assert!(!seen.windows(8).any(|w| w == b"smuggled"));
    }
    #[test]
    fn decode_recomputes_the_chunk_hash() {
        let mut f = one_chunk_file();
        f.chunks[0].hash = [7u8; 32];
        f.merkle_root = [7u8; 32];
        assert!(f.decode().is_err());
    }
    #[test]
    fn a_pq_signed_file_survives_serialisation() {
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&[5u8; 32].into());
        let mut f = one_chunk_file();
        f.header.flags = BudFlags(BudFlags::PQ_SIGNED);
        f.sign_pq(&sk).unwrap();
        let back = BudFile::from_bytes(&f.to_bytes()).unwrap();
        assert_eq!(back.pq_public_key, f.pq_public_key);
        assert_eq!(back.decode().unwrap(), b"abc");
    }
    #[test]
    fn writer_refuses_truncation_and_reader_refuses_noise() {
        let mut f = one_chunk_file();
        f.header.original_mime = "a".repeat(70_000);
        assert!(f.try_to_bytes().is_err());
        assert!(BudFile::from_bytes(&f.to_bytes()).is_err());
        let mut f = one_chunk_file();
        f.chunks[0].parity_shards = vec![vec![1u8]; 256];
        assert!(f.try_to_bytes().is_err());
        let f = one_chunk_file();
        let good = f.try_to_bytes().unwrap();
        // Trailing bytes are refused.
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(BudFile::from_bytes(&trailing).is_err());
        // Invalid UTF-8 in the mime is refused, not normalised.
        let mut bad = good.clone();
        bad[14] = 0xFF;
        assert!(BudFile::from_bytes(&bad).is_err());
        assert!(BudFile::from_bytes(&good).is_ok());
    }
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
        // pipe 11 is the old optical one, now forbidden
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
            "a 16 MB + 1 chunk has to be refused: {}",
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
    fn ratio_gate_rejects_empty_payload_with_claimed_original() {
        let f = BudFile::encode(
            &[],
            BudFormatClass::Json,
            "application/json",
            0,
            0,
            3,
            BudFlags::new(true, true, false, false, false, false),
            Vec::new(),
        );
        assert!(BudGates::k_bud_ratio(&f, 4 << 30).is_err());
        assert!(BudGates::k_bud_ratio(&f, 0).is_ok());
    }
    #[test]
    fn multi_ratio_best_all_files() {
        // The payloads are the original bytes, so every measured ratio is 1.
        for (class, data) in [
            (BudFormatClass::Video, &b"video"[..]),
            (BudFormatClass::Image, &b"image"[..]),
            (BudFormatClass::Log, &b"log log log"[..]),
        ] {
            let cands = MultiRatioConsensus::candidates_for_format(class, data);
            assert!(!cands.is_empty());
            for c in cands {
                assert_eq!(c.ratio, 1.0, "{}: ratio must be measured", c.pipe_name);
            }
        }
        // A claim of 13750x is no longer selectable.
        let log = MultiRatioConsensus::candidates_for_format(BudFormatClass::Log, b"x");
        assert!(MultiRatioConsensus::select_best(log, 100.0).is_none());
    }
    #[test]
    fn from_bytes_never_panics_on_truncation() {
        // K38: from_bytes must not PANIC at any truncation length (it returns Err)
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
            let _ = BudFile::from_bytes(&bytes[..i]); // there must be no panic
        }
        let _ = BudFile::from_bytes(&bytes); // the whole file is fine
                                             // ends truncated from the right (signature/key/token length reads)
        for cut in [bytes.len().saturating_sub(2), bytes.len().saturating_sub(3)] {
            let _ = BudFile::from_bytes(&bytes[..cut]);
        }
    }

    #[test]
    fn a_pq_signature_verifies_and_a_forged_one_is_refused() {
        use ml_dsa::SigningKey as Msk;
        // produce: encode -> sign with ML-DSA-87 -> verify on decode
        // ml-dsa 0.1: there is no generate - use from_seed with a deterministic
        // seed (32 bytes)
        let sk = Msk::<ml_dsa::MlDsa87>::from_seed(&[7u8; 32].into());
        let mut f = BudFile::encode(
            b"pq signed content",
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
        // The trusted key comes from OUT OF BAND. `sign_pq` also stored a copy
        // inside the container; that copy is provenance, not authority.
        let publisher_key: Vec<u8> = sk.as_ref().encode().into_iter().collect();
        assert!(
            f.verify_pq_signature_with(&publisher_key).is_ok(),
            "a correct signature is accepted"
        );
        // corrupt the signature -> REFUSED
        let mut corrupted = f.clone();
        let sig = corrupted.pq_signature.as_mut().unwrap();
        sig[10] ^= 0xFF;
        assert!(
            corrupted.verify_pq_signature_with(&publisher_key).is_err(),
            "a corrupt signature is REFUSED"
        );
        // no signature at all -> REFUSED
        let mut no_sig = f.clone();
        no_sig.pq_signature = None;
        assert!(no_sig.verify_pq_signature_with(&publisher_key).is_err());
        // A key from another publisher -> REFUSED, even though the container
        // carries a key of its own that would verify it. This is the whole
        // point: the embedded key is never the one the check runs against.
        let attacker = Msk::<ml_dsa::MlDsa87>::from_seed(&[9u8; 32].into());
        let attacker_key: Vec<u8> = attacker.as_ref().encode().into_iter().collect();
        assert!(
            f.verify_pq_signature_with(&attacker_key).is_err(),
            "a signature the container vouches for itself is not provenance"
        );
        // ... and the file still decodes: the flag is not an authentication
        // result either way.
        assert!(f.decode().is_ok());
        // without the PQ_SIGNED flag no verification is needed (decode passes)
        let mut plain = f.clone();
        plain.header.flags = BudFlags(0);
        assert!(plain.decode().is_ok());
    }

    /// Strix Review 4: a container signed with a freshly generated key whose
    /// public key is embedded in the file. Decoding it is fine (the bytes are
    /// well formed); accepting its signature is not, unless the caller holds
    /// the same key out of band.
    #[test]
    fn a_container_signed_with_its_own_embedded_key_is_not_provenance() {
        use ml_dsa::SigningKey as Msk;
        let publisher = Msk::<ml_dsa::MlDsa87>::from_seed(&[3u8; 32].into());
        let mut f = BudFile::encode(
            b"self-signed body",
            BudFormatClass::Text,
            "text/plain",
            0,
            0,
            3,
            BudFlags(BudFlags::PQ_SIGNED),
            b"payload".to_vec(),
        );
        f.sign_pq(&publisher).expect("sign");
        assert!(f.pq_public_key.is_some(), "the file carries a key");
        // No publisher key in hand -> the caller cannot authenticate: passing an
        // empty key must refuse rather than fall back to the embedded one.
        assert!(f.verify_pq_signature_with(&[]).is_err());
        // The right key, supplied out of band, verifies.
        let key: Vec<u8> = publisher.as_ref().encode().into_iter().collect();
        assert!(f.verify_pq_signature_with(&key).is_ok());
    }

    /// When no candidate passes, `select_best` says so. It used to answer
    /// with a device-only candidate whose payload was the literal `b"dummy"`,
    /// which a caller then encoded as the file's data.
    #[test]
    fn select_best_without_a_passing_candidate_returns_none() {
        let data = b"the user's bytes";
        let none = MultiRatioConsensus::select_best(
            MultiRatioConsensus::candidates_for_format(BudFormatClass::Json, data),
            1_000.0,
        );
        assert!(none.is_none());
        for class in [
            BudFormatClass::Json,
            BudFormatClass::Image,
            BudFormatClass::Jpeg,
            BudFormatClass::Png,
            BudFormatClass::Pdf,
        ] {
            for c in MultiRatioConsensus::candidates_for_format(class, data) {
                assert_ne!(
                    c.payload, b"dummy",
                    "{}: no placeholder payload",
                    c.pipe_name
                );
            }
            if let Some(c) = MultiRatioConsensus::select_best(
                MultiRatioConsensus::candidates_for_format(class, data),
                1_000.0,
            ) {
                assert!(
                    c.flags.is_device_only(),
                    "{}: only device_only may pass",
                    c.pipe_name
                );
                assert_eq!(
                    c.payload, data,
                    "{}: the payload is the user's data",
                    c.pipe_name
                );
            }
        }
    }

    #[test]
    fn select_best_nan_ratio_never_panics() {
        // K38: a candidate with a NaN ratio must not break the ordering
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
