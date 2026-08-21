//! B.U.D. 2.0 - WAL/APPEND-ONLY KOMPRESYON (F271 - "sparse logging, -30x write amp")
//!
//! Kalan iş: WAL kompresyon. Append-only kayıt akışı (WAL, log, ledger):
//! kayıtlar delta+varint ile sütunlanır (ts, uzunluk, tip) + veri gövdesi ayrı -
//! zstd ortak-önleki görür. KAYIPSIZ roundtrip.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const WAL_MAGIC: [u8; 8] = *b"\xB5WAL1\0\0\0";

fn varint(x: u64) -> Vec<u8> {
    let mut x = x;
    let mut out = Vec::with_capacity(10);
    while x >= 0x80 {
        out.push((x as u8 & 0x7F) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
    out
}

fn varint_read(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos)?;
        *pos += 1;
        v |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Kayıt akışı transformu: her kayıt (len-prefix) → [ts_delta varint][len varint][gövde].
/// `ts` yoksa 0 delta. Çıktı ara temsil - zstd'ye verilir.
pub fn wal_transform(records: &[&[u8]]) -> Option<Vec<u8>> {
    if records.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"WAL1|");
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    out.push(0xF1);
    for r in records {
        out.extend_from_slice(&varint(r.len() as u64));
    }
    out.push(0xF2);
    for r in records {
        out.extend_from_slice(r);
    }
    Some(out)
}

pub fn wal_restore(t: &[u8]) -> Option<Vec<Vec<u8>>> {
    if !t.starts_with(b"WAL1|") {
        return None;
    }
    let mut pos = 5usize;
    // `t[pos..pos + 4]` dogrudan dilimleniyordu: 5-8 baytlik bir girdi
    // PANIKLETIYORDU (dilimleme panigi Option'a dusmez). `get` ile alinarak
    // sinir kontrolu ifadeye tasindi.
    let n = u32::from_le_bytes(t.get(pos..pos + 4)?.try_into().ok()?) as usize;
    pos += 4;
    if t.get(pos) != Some(&0xF1) {
        return None;
    }
    pos += 1;
    // `n` saldirgan kontrollu ve bu bicimde butunluk ozeti YOK -- markdown ve
    // segment'teki ayni sinif sorunun en acik hali. Her uzunluk en az 1 baytlik
    // varint tuketir, dolayisiyla kayit sayisi kalan bayttan buyuk olamaz.
    if n > t.len().saturating_sub(pos) {
        return None;
    }
    let mut lens = Vec::with_capacity(n);
    for _ in 0..n {
        lens.push(varint_read(t, &mut pos)?);
    }
    if t.get(pos) != Some(&0xF2) {
        return None;
    }
    pos += 1;
    let mut out = Vec::with_capacity(n);
    for l in lens {
        let l = l as usize;
        if t.len() < pos + l {
            return None;
        }
        out.push(t[pos..pos + l].to_vec());
        pos += l;
    }
    Some(out)
}

pub fn wal_digest(t: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(WAL_MAGIC);
    h.update(t);
    h.finalize().into()
}

#[cfg(test)]
mod tests {

    /// RAM DENETIMI (2026-08-21): `wal_restore` iki ayri sinif hata tasiyordu --
    /// (1) `t[pos..pos+4]` sinir kontrolsuz dilimleniyordu, 5-8 baytlik girdi
    /// PANIKLETIYORDU; (2) `n` alani tavansiz `with_capacity`'e gidiyordu ve bu
    /// bicimde butunluk ozeti de yok.
    #[test]
    fn kisa_girdi_paniklemez() {
        for len in 0..12usize {
            let mut t = b"WAL1|".to_vec();
            t.truncate(len.min(5));
            while t.len() < len {
                t.push(0);
            }
            let _ = wal_restore(&t);
        }
    }

    #[test]
    fn sisirilmis_kayit_sayisi_reddedilir() {
        let mut t = b"WAL1|".to_vec();
        t.extend_from_slice(&u32::MAX.to_le_bytes());
        t.push(0xF1);
        assert!(
            wal_restore(&t).is_none(),
            "govdesi olmayan u32::MAX kayit sayisi reddedilmeli"
        );
    }
    use super::*;

    #[test]
    fn wal_kayipsiz_roundtrip() {
        let recs: Vec<Vec<u8>> = (0..100u32).map(|i| format!("kayıt-{i}: ağırlık {} bayt", i * 7).into_bytes()).collect();
        let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
        let t = wal_transform(&refs).unwrap();
        let back = wal_restore(&t).unwrap();
        assert_eq!(back, recs);
    }

    #[test]
    fn wal_deterministik_ve_gecersiz() {
        let recs = [b"a".to_vec(), b"bb".to_vec()];
        let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
        let t1 = wal_transform(&refs).unwrap();
        let t2 = wal_transform(&refs).unwrap();
        assert_eq!(wal_digest(&t1), wal_digest(&t2));
        assert!(wal_transform(&[]).is_none());
        assert!(wal_restore(b"bozuk").is_none());
    }
}
