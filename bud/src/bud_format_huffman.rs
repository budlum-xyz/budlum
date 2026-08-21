//! B.U.D. 2.0 Icat - Gerçek Kayıpsız Huffman Codec (2026-08-16)
//!
//! Sıfır dış bağımlılıkla GERÇEK bir kayıpsız sıkıştırıcı: kanonik Huffman.
//! (Önceki "RealCompressor" zstd/xz magic taklidi + ilk 100 bayt döndüren STUB'ti -
//! gerçek sıkıştırma değildi ve sahte zarf üretiyordu; bu modül onu değiştirir.)
//!
//! Tasarım:
//! - Magic: `\xB5` öncülü yüksek-bit (file(1)/ASCII karışmasın, S.47) + "HFM1".
//! - Kompakt tablo: kullanılan sembol sayısı (u16) + (sym, len) çiftleri (2 bayt/sembol).
//! - Kanonik kod ataması: (uzunluk, sembol) sırası - DEFLATE benzeri, deterministik.
//! - Gövde: MSB-önce bit-paketli kodlar.
//! - Sınır güvenli: original_len tavanı (bomba), Kraft eşitsizliği, geçersiz önek → None.
//! - Kayıpsızlık: compress → decompress = orijinal (mülkiyet testi). Panik yok.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, no unsafe.

#![forbid(unsafe_code)]

pub const BUD_HFM_MAGIC: [u8; 8] = *b"\xB5HFM1\0\0\0";
pub const BUD_HFM_VERSION: u8 = 1;
pub const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB bomba tavanı
pub const MAX_CODE_LEN: usize = 32; // tablo bozulmasına karşı kod uzunluğu sınırı

#[derive(Debug, Clone)]
pub struct HuffmanCoder;

impl HuffmanCoder {
    /// Sıkıştır: BUD-HFM1 zarfı (magic + sürüm + uzunluk + kompakt tablo + gövde).
    pub fn compress(data: &[u8]) -> Vec<u8> {
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let lens = Self::lengths_by_freq(&freq);
        let mut out = Vec::new();
        out.extend_from_slice(&BUD_HFM_MAGIC);
        out.push(BUD_HFM_VERSION);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // kompakt tablo: kullanılan sembol sayısı + (sym, len) çiftleri
        let used: Vec<(u8, u8)> = lens
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(s, &l)| (s as u8, l))
            .collect();
        out.extend_from_slice(&(used.len() as u16).to_le_bytes());
        for (s, l) in &used {
            out.push(*s);
            out.push(*l);
        }
        // kanonik kod tablosunu önceden kur (uzunluk, sembol) sırasına göre
        let mut codes = [0u64; 256];
        let mut order: Vec<usize> = (0..256).filter(|&s| lens[s] > 0).collect();
        order.sort_by_key(|&s| (lens[s], s));
        let mut code: u64 = 0;
        let mut prev_len = 0usize;
        for &s in &order {
            let l = lens[s] as usize;
            if prev_len > 0 {
                code = (code + 1) << (l - prev_len);
            }
            codes[s] = code;
            prev_len = l;
        }
        // gövde: kodları bit-paketle (MSB-önce)
        let mut bit_buf: u64 = 0;
        let mut bit_cnt: u32 = 0;
        for &b in data {
            let sym = b as usize;
            let len = lens[sym];
            debug_assert!(len > 0);
            bit_buf = (bit_buf << len) | codes[sym];
            bit_cnt += len as u32;
            while bit_cnt >= 8 {
                let byte = ((bit_buf >> (bit_cnt - 8)) & 0xFF) as u8;
                out.push(byte);
                bit_cnt -= 8;
            }
        }
        if bit_cnt > 0 {
            let byte = ((bit_buf << (8 - bit_cnt)) & 0xFF) as u8;
            out.push(byte);
        }
        out
    }

    /// Aç: sıkı doğrula (magic, sürüm, uzunluk tavanı, Kraft, kod geçerliliği) → orijinal.
    pub fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
        const FIXED: usize = 8 + 1 + 8 + 2; // magic + sürüm + len + tablo sayısı
        if bytes.len() < FIXED {
            return None;
        }
        if bytes[0..8] != BUD_HFM_MAGIC {
            return None;
        }
        if bytes[8] != BUD_HFM_VERSION {
            return None;
        }
        let orig_len = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        if orig_len > MAX_DECOMPRESSED_BYTES {
            return None; // bomba
        }
        let sym_count = u16::from_le_bytes([bytes[17], bytes[18]]) as usize;
        if bytes.len() < FIXED + sym_count * 2 {
            return None;
        }
        let mut lens = [0u8; 256];
        for i in 0..sym_count {
            let sym = bytes[FIXED + i * 2] as usize;
            let l = bytes[FIXED + i * 2 + 1];
            if lens[sym] != 0 {
                return None; // yinelenen sembol → bozuk tablo
            }
            lens[sym] = l;
        }
        let body = &bytes[FIXED + sym_count * 2..];
        if orig_len == 0 {
            // boş girdi: sembol olmamalı, gövde boş olmalı
            if sym_count != 0 || !body.is_empty() {
                return None;
            }
            return Some(Vec::new());
        }
        let lens_usize: Vec<usize> = lens.iter().map(|&l| l as usize).collect();
        if sym_count == 0 {
            return None; // orijinal var ama sembol yok - tutarsız
        }
        // Kraft eşitsizliği: bozuk tablo → red
        if !Self::kraft_ok(&lens_usize) {
            return None;
        }
        let max_len = *lens_usize.iter().max().unwrap_or(&0);
        if max_len == 0 || max_len > MAX_CODE_LEN {
            return None;
        }
        // kanonik yapı: count[len], ilk_kod[len], semboller
        let mut count = [0usize; MAX_CODE_LEN + 1];
        let mut syms_by_len: Vec<Vec<usize>> = vec![Vec::new(); MAX_CODE_LEN + 1];
        for (sym, &l) in lens_usize.iter().enumerate() {
            if l > 0 && l <= MAX_CODE_LEN {
                count[l] += 1;
                syms_by_len[l].push(sym);
            }
        }
        let mut first = [0u64; MAX_CODE_LEN + 1];
        let mut c: u64 = 0;
        for l in 1..=MAX_CODE_LEN {
            first[l] = c;
            c = (c + count[l] as u64) << 1;
        }
        // gövde bitleri üzerinde gezin - K38: orig_len GÜVENİLMEZ başlıktan gelir;
        // with_capacity(orig_len) küçük dosyada devasa ayırım (OOM DoS) yapardı.
        // Lazy büyüme: gerçek büyük açma zaten gövde boyutuyla sınırlıdır.
        let mut out: Vec<u8> = Vec::new();
        let mut bit_pos = 0usize;
        let total_bits = body.len() * 8;
        let mut code: u64 = 0;
        let mut cur_len = 0usize;
        while (out.len() as u64) < orig_len {
            if bit_pos >= total_bits {
                return None; // gövde erken bitti
            }
            let byte = body[bit_pos / 8];
            let bit = (byte >> (7 - (bit_pos % 8))) & 1;
            bit_pos += 1;
            code = (code << 1) | bit as u64;
            cur_len += 1;
            if cur_len > max_len {
                return None; // geçersiz önek (bozuk gövde)
            }
            let cnt = count[cur_len];
            if cnt > 0 && code >= first[cur_len] && code < first[cur_len] + cnt as u64 {
                let sym = syms_by_len[cur_len][(code - first[cur_len]) as usize];
                out.push(sym as u8);
                code = 0;
                cur_len = 0;
            }
        }
        // Son bayttaki padding bitleri serbesttir (DEFLATE benzeri). Kayıpsızlık tam.
        Some(out)
    }

    /// Kod uzunlukları: her adımda iki en küçük (freq, sonra indis) düğüm birleştirilir,
    /// kökten DFS ile yaprak derinlikleri = kod uzunlukları. Deterministik.
    fn lengths_by_freq(freq: &[u64; 256]) -> [u8; 256] {
        let mut fs: Vec<(u64, Option<usize>, Option<usize>, Option<usize>)> = Vec::new();
        let mut used: Vec<bool> = Vec::new();
        for (sym, &f) in freq.iter().enumerate() {
            if f > 0 {
                fs.push((f, None, None, Some(sym)));
                used.push(false);
            }
        }
        if fs.is_empty() {
            return [0u8; 256];
        }
        if fs.len() == 1 {
            let mut lens = [0u8; 256];
            lens[fs[0].3.unwrap()] = 1;
            return lens;
        }
        let mut internal = fs.len();
        while internal > 1 {
            let mut best1: Option<usize> = None;
            let mut best2: Option<usize> = None;
            for i in 0..fs.len() {
                if used[i] {
                    continue;
                }
                if best1.is_none() || fs[i].0 < fs[best1.unwrap()].0
                    || (fs[i].0 == fs[best1.unwrap()].0 && i < best1.unwrap())
                {
                    best2 = best1;
                    best1 = Some(i);
                } else if best2.is_none() || fs[i].0 < fs[best2.unwrap()].0
                    || (fs[i].0 == fs[best2.unwrap()].0 && i < best2.unwrap())
                {
                    best2 = Some(i);
                }
            }
            let (i1, i2) = (best1.unwrap(), best2.unwrap());
            let f = fs[i1].0 + fs[i2].0;
            fs.push((f, Some(i1), Some(i2), None));
            used.push(false);
            used[i1] = true;
            used[i2] = true;
            internal -= 1;
        }
        let root_idx = (0..fs.len()).find(|&i| !used[i]).unwrap();
        let mut lens = [0u8; 256];
        Self::dfs_lengths(&fs, root_idx, 0, &mut lens);
        lens
    }

    fn dfs_lengths(
        fs: &[(u64, Option<usize>, Option<usize>, Option<usize>)],
        idx: usize,
        depth: usize,
        lens: &mut [u8; 256],
    ) {
        let (_, l, r, sym) = fs[idx];
        if let Some(s) = sym {
            lens[s] = depth.max(1) as u8;
            return;
        }
        if let Some(li) = l {
            Self::dfs_lengths(fs, li, depth + 1, lens);
        }
        if let Some(ri) = r {
            Self::dfs_lengths(fs, ri, depth + 1, lens);
        }
    }

    fn kraft_ok(lens: &[usize]) -> bool {
        // Kraft: sum 2^(-len) <= 1 - tamsayı aritmetiğiyle
        let mut maxl = 0usize;
        for &l in lens {
            maxl = maxl.max(l);
        }
        if maxl > MAX_CODE_LEN {
            return false;
        }
        let mut acc: u128 = 0;
        for &l in lens {
            if l > 0 {
                acc += 1u128 << (MAX_CODE_LEN - l);
            }
        }
        acc <= (1u128 << MAX_CODE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        // Küçük girdilerde başlık gideri amortize olmaz (dürüst Huffman davranışı);
        // tekrarlı YETERLİ uzunlukta girdi ile gerçek sıkışma kanıtlanır.
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(line);
        }
        let c = HuffmanCoder::compress(&data);
        assert!(
            c.len() < data.len(),
            "tekrarlı veri sıkışmalı: {} -> {}",
            data.len(),
            c.len()
        );
        let d = HuffmanCoder::decompress(&c).unwrap();
        assert_eq!(d, data);
    }

    #[test]
    fn roundtrip_uniform() {
        let data = vec![b'a'; 20_000];
        let c = HuffmanCoder::compress(&data);
        // tek sembol → ~1 bit/sembol; tablo/başlık sabiti ile ~7x civarı
        assert!(
            c.len() * 7 < data.len(),
            "tek sembol ~7x olmalı: {} -> {}",
            data.len(),
            c.len()
        );
        assert_eq!(HuffmanCoder::decompress(&c).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let c = HuffmanCoder::compress(b"");
        assert_eq!(HuffmanCoder::decompress(&c).unwrap(), b"");
    }

    #[test]
    fn roundtrip_all_bytes_random() {
        // deterministik PRNG - 300 farklı girdi, her boyut
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
        let mut rng = Rng(0x48_55_46_46_20_31_00_00);
        for round in 0..300u32 {
            let n = (rng.next() % 5000) as usize;
            let mut data = vec![0u8; n];
            for b in &mut data {
                *b = if round % 3 == 0 { rng.byte() % 8 } else { rng.byte() };
            }
            let c = HuffmanCoder::compress(&data);
            let d = HuffmanCoder::decompress(&c).unwrap_or_else(|| panic!("round {round} decompress"));
            assert_eq!(d, data, "round {round} kayıpsız");
        }
    }

    #[test]
    fn reject_tampered_and_bombs() {
        let data = b"merhaba dunya bu bir test verisi";
        let c = HuffmanCoder::compress(data);
        // payload kurcalama (panik yok)
        let mut t = c.clone();
        let last = t.len() - 1;
        t[last] ^= 0xFF;
        let _ = HuffmanCoder::decompress(&t);
        // magic boz
        let mut t2 = c.clone();
        t2[0] = 0x00;
        assert!(HuffmanCoder::decompress(&t2).is_none());
        // kısa girdi
        assert!(HuffmanCoder::decompress(&[]).is_none());
        assert!(HuffmanCoder::decompress(&c[..20]).is_none());
        // boyut bombası: original_len = 1 GiB (MAX altı ama gövde yok → hızlı red)
        let mut b = BUD_HFM_MAGIC.to_vec();
        b.push(BUD_HFM_VERSION);
        b.extend_from_slice(&(1u64 << 30).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        assert!(HuffmanCoder::decompress(&b).is_none(), "boyut bombası red");
        // alloc-bomb: 3.9 GiB orig_len + tek sembol tablo + küçük gövde → OOM OLMADAN hızlı red
        let mut bomb = BUD_HFM_MAGIC.to_vec();
        bomb.push(BUD_HFM_VERSION);
        bomb.extend_from_slice(&((4u64 << 30) - 1).to_le_bytes()); // MAX altı
        bomb.extend_from_slice(&1u16.to_le_bytes());
        bomb.extend_from_slice(&[65, 1]); // tek sembol 'A', uzunluk 1
        bomb.extend_from_slice(&[0u8; 64]); // küçük gövde
        let start = std::time::Instant::now();
        for _ in 0..100 {
            assert!(HuffmanCoder::decompress(&bomb).is_none());
        }
        assert!(start.elapsed().as_secs() < 5, "alloc-bomb yok: {:?}", start.elapsed());
        // geçersiz tablo (Kraft bozuk): 256 sembol, hepsi uzunluk 32
        let mut b2 = BUD_HFM_MAGIC.to_vec();
        b2.push(BUD_HFM_VERSION);
        b2.extend_from_slice(&64u64.to_le_bytes());
        b2.extend_from_slice(&256u16.to_le_bytes());
        for s in 0u16..256 {
            b2.push(s as u8);
            b2.push(32);
        }
        assert!(HuffmanCoder::decompress(&b2).is_none(), "Kraft bozuk tablo red");
        // yinelenen sembol → bozuk tablo red
        let mut b3 = BUD_HFM_MAGIC.to_vec();
        b3.push(BUD_HFM_VERSION);
        b3.extend_from_slice(&8u64.to_le_bytes());
        b3.extend_from_slice(&2u16.to_le_bytes());
        b3.extend_from_slice(&[65, 3, 65, 3]); // aynı sembol iki kez
        assert!(HuffmanCoder::decompress(&b3).is_none(), "yinelenen sembol red");
        // çöp gövde (panik yok)
        let mut b4 = BUD_HFM_MAGIC.to_vec();
        b4.push(BUD_HFM_VERSION);
        b4.extend_from_slice(&16u64.to_le_bytes());
        b4.extend_from_slice(&1u16.to_le_bytes());
        b4.extend_from_slice(&[65, 8]); // tek sembol, uzunluk 8
        b4.extend_from_slice(&[0b1010_1010]);
        let _ = HuffmanCoder::decompress(&b4);
    }
}
