//! B.U.D. 2.0 - GENOMİK REFERANS TRANSFORMU (F21/F228-F231 - CRAM/genozip deseni)
//!
//! Kalan iş #7 (genom ayağı): FASTQ/FASTA benzeri dizileri REFERANS dizisine göre
//! delta'ya çevirir: eşleşen bazlar örtülür (referans + fark), sapmalar kaydedilir.
//! KAYIPSIZ: orijinal dizi referans+farktan birebir kurulur. Referans yoksa ham
//! 2-bit kodlama (A/C/G/T → 2 bit) düşer. Bu bir TOHUMdur - gerçek genozip
//! seviyesi (quality-score modeli vb.) uzun vade; dürüstçe işaretli.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const GEN_MAGIC: [u8; 8] = *b"\xB5GEN1\0\0\0";

fn base2bit(b: u8) -> Option<u8> {
    match b {
        b'A' => Some(0),
        b'C' => Some(1),
        b'G' => Some(2),
        b'T' => Some(3),
        _ => None,
    }
}

fn bit2base(x: u8) -> u8 {
    match x {
        0 => b'A',
        1 => b'C',
        2 => b'G',
        _ => b'T',
    }
}

/// Referans tabanlı delta kodla: dizi ile referansın aynı olduğu yerlerde
/// "0" (örtük), farklı bazlarda "1+2bit". Çıktı: vektör (0 = aynı, 1-4 = farklı baz).
pub fn ref_encode(seq: &[u8], ref_seq: &[u8]) -> Option<Vec<u8>> {
    if seq.len() != ref_seq.len() || seq.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(seq.len());
    for i in 0..seq.len() {
        if seq[i] == ref_seq[i] {
            out.push(0);
        } else {
            let b = base2bit(seq[i])?;
            out.push(1 + b); // 1..4
        }
    }
    Some(out)
}

pub fn ref_decode(delta: &[u8], ref_seq: &[u8]) -> Option<Vec<u8>> {
    if delta.len() != ref_seq.len() {
        return None;
    }
    let mut out = Vec::with_capacity(delta.len());
    for i in 0..delta.len() {
        match delta[i] {
            0 => out.push(ref_seq[i]),
            1..=4 => out.push(bit2base(delta[i] - 1)),
            _ => return None,
        }
    }
    Some(out)
}

/// Referanssız 2-bit kodlama (A/C/G/T) - ham dizi için.
pub fn two_bit_encode(seq: &[u8]) -> Option<Vec<u8>> {
    if seq.is_empty() {
        return None;
    }
    let n = seq.len();
    let mut out = vec![0u8; n.div_ceil(4)];
    for i in 0..n {
        let b = base2bit(seq[i])?;
        out[i / 4] |= b << (2 * (i % 4));
    }
    Some(out)
}

pub fn two_bit_decode(data: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let b = (data[i / 4] >> (2 * (i % 4))) & 0x3;
        out.push(bit2base(b));
    }
    Some(out)
}

pub fn gen_digest(delta: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(GEN_MAGIC);
    h.update(delta);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referans_delta_kayipsiz() {
        let ref_seq = b"ACGTACGTACGTACGTACGT";
        let seq = b"ACGTACGTATGTACGTACGT"; // 1 sapma (T→A)
        let d = ref_encode(seq, ref_seq).unwrap();
        // sapma sayısı: 1
        let mut snp = 0;
        for &x in &d {
            if x != 0 {
                snp += 1;
            }
        }
        assert_eq!(snp, 1);
        assert_eq!(ref_decode(&d, ref_seq).unwrap(), seq.to_vec());
        // zstd'ye verilecek delta çok seyrek → yüksek oran
        assert!(d.iter().filter(|&&x| x == 0).count() > d.len() / 2);
    }

    #[test]
    fn iki_bit_kodlama_kayipsiz() {
        let seq = b"ACGTACGTACGT";
        let enc = two_bit_encode(seq).unwrap();
        assert_eq!(enc.len(), 3); // 12 baz / 4
        assert_eq!(two_bit_decode(&enc, seq.len()).unwrap(), seq.to_vec());
    }

    #[test]
    fn gecersiz_baz_red() {
        assert!(ref_encode(b"ACGN", b"ACGT").is_none());
        assert!(two_bit_encode(b"NACGT").is_none());
        assert!(ref_encode(b"ACGT", b"ACG").is_none());
    }

    #[test]
    fn gen_deterministik() {
        let d = ref_encode(b"ACGT", b"ACGA").unwrap();
        assert_eq!(gen_digest(&d), gen_digest(&d));
    }
}
