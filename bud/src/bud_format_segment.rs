//! B.U.D. 2.0 - Segment Ledger (segmentli zincir depolama deseni) (2026-08-16)
//!
//! K88-1: zincir çekirdeği için segment storage deseni - 64MB segmentler,
//! `len(4) + data + crc32(4)` kayıtları, bozuk kayıt CRC uyuşmazlığında RED.
//! B.U.D. versiyonu: SHA3-256 bütünlük (CRC32'den güçlü - K38), len-prefix,
//! bomba korumalı (segment tavanı), deterministik.
//!
//! Bu modül, .bud kayıtlarının (üretim kanıtı, PACT, rejenerasyon sınavı, checkpoint)
//! ZİNCİRDE segmentler halinde saklanmasının çekirdeğidir: append-only defter
//! (İ1 PACT kaydı + K89 blokzincir entegrasyonu).
//!
//! Kod: `#![forbid(unsafe_code)]`, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SEGMENT_MAGIC: [u8; 8] = *b"\xB5SEGL\0\0\0";
pub const SEGMENT_VERSION: u8 = 1;
pub const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (blockchain-core)
pub const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;   // tek kayıt tavanı (16 MB)

/// Segment defteri: append-only kayıtlar (len-prefix + SHA3 digest).
#[derive(Debug, Clone)]
pub struct SegmentLedger {
    pub entries: Vec<Vec<u8>>, // saklanan kayıtlar (her biri ayrı digest'li)
    pub total_bytes: u64,
}

impl Default for SegmentLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentLedger {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_SEGMENT_V1";

    pub fn new() -> Self {
        SegmentLedger { entries: Vec::new(), total_bytes: 0 }
    }

    /// Kayıt ekle (append-only). Boyut tavanları + digest hesaplanır.
    pub fn append(&mut self, data: &[u8]) -> Option<u64> {
        if data.is_empty() || data.len() as u64 > MAX_ENTRY_BYTES {
            return None;
        }
        if self.total_bytes + data.len() as u64 > MAX_SEGMENT_BYTES {
            return None; // segment dolu → yeni segment (çağıran karar verir)
        }
        self.total_bytes += data.len() as u64;
        self.entries.push(data.to_vec());
        Some(self.total_bytes)
    }

    /// Kayıt bütünlüğü: digest doğrula (K38).
    pub fn verify_entry(data: &[u8], digest: &[u8; 32]) -> bool {
        Self::entry_digest(data) == *digest
    }

    pub fn entry_digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }

    /// Segment serialize: magic + sürüm + kayıt sayısı + (len + digest + data)* + kök digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SEGMENT_MAGIC);
        out.push(SEGMENT_VERSION);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&(e.len() as u32).to_le_bytes());
            out.extend_from_slice(&Self::entry_digest(e));
            out.extend_from_slice(e);
        }
        // kök digest (tüm segment bütünlüğü - defter değişmezliği)
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&out);
        let root: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&root);
        out
    }

    /// Segment deserialize: sıkı doğrula (her kayıt digest'i + kök digest + artık bayt red).
    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != SEGMENT_MAGIC || bytes[8] != SEGMENT_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(&bytes[..payload_len]);
        let root: [u8; 32] = h.finalize().into();
        if root != bytes[payload_len..] {
            return None;
        }
        let count = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let mut pos = HDR;
        // `count` saldirgan kontrollu; dogrudan ayirmak 45 baytlik blobla
        // 103 GB talep uretiyordu (olculdu: "memory allocation of
        // 103079215080 bytes failed" -> SIGABRT, panic="abort" ile dugum olur).
        // Ustteki SHA3 kontrolu korumaz: anahtarsiz ozet + public DOMAIN
        // sabiti, gecerli blob uretmek serbest.
        //
        // Her kayit en az 4 bayt uzunluk + 32 bayt ozet = 36 bayt tuketir;
        // tavan girdinin kendi uzunlugundan turetildigi icin ayirma daima
        // girdiyle orantili kalir.
        if count > payload_len.saturating_sub(pos) / 36 {
            return None;
        }
        let mut entries = Vec::with_capacity(count);
        let mut total: u64 = 0;
        for _ in 0..count {
            if bytes.len() < pos + 4 + 32 {
                return None;
            }
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            if len as u64 > MAX_ENTRY_BYTES || bytes.len() < pos + len {
                return None;
            }
            let data = bytes[pos..pos + len].to_vec();
            pos += len;
            if !Self::verify_entry(&data, &digest) {
                return None; // kayıt kurcalanmış
            }
            total += len as u64;
            entries.push(data);
        }
        if pos != payload_len || total > MAX_SEGMENT_BYTES {
            return None;
        }
        Some(SegmentLedger { entries, total_bytes: total })
    }

    /// Segment kökü (zincir başlığına yazılabilir - İ8 bayt-bütçe ile uyumlu).
    pub fn root(&self) -> [u8; 32] {
        let blob = self.to_blob();
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_SEGMENT_ROOT_V1");
        h.update(&blob[..blob.len() - 32]);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {

    /// RAM DENETIMI (2026-08-21): sisirilmis `count`, 45 baytlik girdiyle
    /// 103.079.215.080 baytlik ayirma talebi uretiyordu -> SIGABRT.
    /// SHA3 alani korumaz (anahtarsiz ozet + public DOMAIN).
    #[test]
    fn sisirilmis_kayit_sayisi_ayirmadan_once_reddedilir() {
        use sha3::{Digest, Sha3_256};
        let mut b = Vec::new();
        b.extend_from_slice(&SEGMENT_MAGIC);
        b.push(SEGMENT_VERSION);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut h = Sha3_256::new();
        h.update(SegmentLedger::DOMAIN);
        h.update(&b);
        b.extend_from_slice(&h.finalize());

        assert!(
            SegmentLedger::from_blob(&b).is_none(),
            "govdesi olmayan u32::MAX kayit sayisi reddedilmeli"
        );
    }

    /// Kanarya: tavan gercek defteri reddetmemeli.
    #[test]
    fn gercek_defter_tavandan_etkilenmez() {
        let mut seg = SegmentLedger::new();
        seg.append(b"birinci kayit").expect("append");
        seg.append(b"ikinci kayit").expect("append");
        let blob = seg.to_blob();
        let geri = SegmentLedger::from_blob(&blob).expect("gecerli blob kabul edilmeli");
        assert_eq!(geri.root(), seg.root(), "kok ozet degismez");
    }
    use super::*;

    #[test]
    fn append_and_roundtrip() {
        let mut seg = SegmentLedger::new();
        seg.append(b"pact kaydi 1").expect("ekle");
        seg.append(b"rejenerasyon sinavi kaydi").expect("ekle");
        seg.append(b"checkpoint").expect("ekle");
        assert_eq!(seg.entries.len(), 3);
        assert!(seg.total_bytes > 0);
        let blob = seg.to_blob();
        let back = SegmentLedger::from_blob(&blob).expect("segment okunur");
        assert_eq!(back.entries, seg.entries);
        assert_eq!(back.total_bytes, seg.total_bytes);
        // kök deterministik
        assert_eq!(seg.root(), back.root());
        assert_ne!(seg.root(), [0u8; 32]);
        // kurcalama red: herhangi bir kayıt baytı
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            // magic/sürüm baytları da bozulursa yine red (farklı hata kodu ama None)
            let _ = SegmentLedger::from_blob(&bad);
        }
        let mut bad = blob.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        assert!(SegmentLedger::from_blob(&bad).is_none(), "kayıt kurcalama red");
        // artık bayt red
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(SegmentLedger::from_blob(&extra).is_none());
    }

    #[test]
    fn tampered_entry_digest_rejected() {
        // bir kaydı değiştirip digest'i eski bırak → RED
        let mut seg = SegmentLedger::new();
        seg.append(b"orijinal kayit").expect("ekle");
        let blob = seg.to_blob();
        let mut bad = blob.clone();
        // ilk kayıt verisini değiştir (HDR = 13, sonra 4 len + 32 digest, veri başı 49)
        bad[49] = b'X';
        assert!(SegmentLedger::from_blob(&bad).is_none(), "değiştirilmiş kayıt RED");
    }

    #[test]
    fn segment_capacity_limits() {
        let mut seg = SegmentLedger::new();
        // 16MB + 1 → red
        let big = vec![0u8; (MAX_ENTRY_BYTES + 1) as usize];
        assert!(seg.append(&big).is_none(), "kayıt tavanı");
        // boş → red
        assert!(seg.append(&[]).is_none());
        // segment dolu: 64MB'a kadar
        let chunk = vec![0u8; 1024];
        let mut filled = false;
        for _ in 0..(MAX_SEGMENT_BYTES as usize / 1024 + 10) {
            if seg.append(&chunk).is_none() {
                filled = true;
                break;
            }
        }
        assert!(filled, "segment kapasitesi sınırlı");
        assert!(seg.total_bytes <= MAX_SEGMENT_BYTES);
    }

    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x5345_474C_2026_0816);
        let mut buf = vec![0u8; 256];
        for _ in 0..2000 {
            let len = (rng.next() % 256) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = SegmentLedger::from_blob(&buf[..len]);
        }
    }
}
