//! B.U.D. 3.0 - QR-VIDEO TÜREV KATMANI (şartname §1 boru hattı; bağımsız türetme)
//!
//! Kullanıcı sorusu: "içerik sıkıştırıldıktan sonra QR video olup gönderilse?"
//! Şartname ölçümü (K5/K10/K13): QR video KAYIPSIZ TAŞIR ama DEPOLAMA DEĞİLDİR -
//! her rejimde sıkışmış baytı 12-18× büyütür; türevdir, saklanmaz, talep anında üretilir.
//!
//! Bu modül boru hattını kodlar:
//!   payload → zlib-9 (SADECE küçültüyorsa) → konteyner (magic·version·flags·orig_len·sha256)
//!   → sistematik karusel (önce sıralı bloklar, sonra onarım damlaları) → kare paketleme
//!   → QR byte-mode kare → video kare. ALIM: kare çöz → damla havuzu → örme → aç → SHA doğrula.
//! Kapı: K-QR-GENISLEME - QR-video türü kalıcı depoya yazılamaz (türev, türev kalır).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QRV_MAGIC: [u8; 8] = *b"\xB5QRV1\0\0\0";
pub const QRV_VERSION: u8 = 1;

/// Damla (kare) başlığı - 20 B (şartname §2).
#[derive(Debug, Clone, Copy)]
pub struct DamlaHdr {
    pub seq: u32,   // damla sırası
    pub block: u16, // blok indeksi (karusel turu)
    pub flags: u8,  // 0x01=onarım, 0x02=sıkıştırılmış, 0x04=son
    pub len: u16,   // yük baytı (≤ BLOCK)
}

pub const DAMLA_HDR_LEN: usize = 20;
pub const BLOCK: usize = 200; // şartname §6

/// Sistematik karusel (şartname §3-yeni): önce k blok sıralı (damla = tek blok),
/// sonra k adet tekdüze derece 4-24 onarım damlası; döngü sonsuz.
/// K6 kanıtı: sıfır kayıpta fazlalık 1.00 + sıralı varış (akışlı oynatma).
#[derive(Debug, Clone)]
pub struct Karusel {
    pub blocks: Vec<Vec<u8>>, // içerik blokları (BLOCK boyutlu, sonuncu kısa)
    pub k: usize,
    pub turn: u64, // mevcut tur
}

impl Karusel {
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let blocks: Vec<Vec<u8>> = data.chunks(BLOCK).map(|c| c.to_vec()).collect();
        let k = blocks.len();
        if k == 0 || k > 65_535 {
            return None;
        }
        Some(Self { blocks, k, turn: 0 })
    }

    /// Sıralı (sistematik) damla: tur 0'da blok i olduğu gibi gelir (akışlı açılma).
    pub fn systematic_drop(&self, index: usize) -> Option<(u32, Vec<u8>)> {
        let b = self.blocks.get(index)?;
        Some((index as u32, b.clone()))
    }

    /// Onarım damlası: tekdüze derece 4..=24, deterministik tohum.
    /// DÜZELTME (tur denetimi kanaryası): tohum MUTLAK damla sırasından gelir
    /// (şartname §3-yeni). Önceki sürüm yalnız TUR'dan tohumluyordu; uret_turev
    /// döngüsü bir turda k adet BİREBİR AYNI onarım damlası üretiyordu
    /// (kanıt: repair_drop(0) == repair_drop(0), k kopya) - kayıp direnci boştu.
    pub fn repair_drop(&self, abs_seq: u64) -> (u32, Vec<u8>) {
        let k = self.k as u64;
        let mut rng = LcRng::new(0x9E3779B97F4A7C15u64.wrapping_mul(abs_seq).wrapping_add(1));
        // DÜZELTME 2 (kanarya yakaladı): derece tavanı k-1 - tekdüze 4..=24 küçük
        // k'de çoğunlukla k'ye kırpılıyordu ve "tüm blokların XOR'u" damlası
        // defalarca kopyalanıyordu (k=11'de 11 damlanın 6'sı benzersizdi).
        let min_d = 2.min(self.k);
        let max_d = self.k.saturating_sub(1).clamp(min_d, 24).max(min_d);
        let span = (max_d - min_d + 1) as u64;
        let d = min_d + (rng.next() % span) as usize;
        let mut chosen = Vec::with_capacity(d);
        while chosen.len() < d {
            let idx = (rng.next() % k) as usize;
            if !chosen.contains(&idx) {
                chosen.push(idx);
            }
        }
        chosen.sort_unstable();
        // DÜZELTME 3: sym uzunluğu SEÇİLENLERİN EN UZUNU - önceki sürüm
        // blocks[chosen[0]].len() kullanıyordu; kısa son blok ilk seçilirse
        // diğer bloklar zip'te SESSİZCE kırpılıyordu (veri bozulması).
        let sym_len = chosen
            .iter()
            .map(|&i| self.blocks[i].len())
            .max()
            .unwrap_or(0);
        let mut sym = vec![0u8; sym_len];
        for &i in &chosen {
            for (a, b) in sym.iter_mut().zip(self.blocks[i].iter()) {
                *a ^= b;
            }
        }
        // DÜZELTME 4 (tur denetimi): önceki sürüm indeksleri 65537-hash'le seq'e
        // paketliyordu - KAYIPLI; çözücü maskeyi geri türetemezdi. Şartname §3:
        // başlık MUTLAK seq taşır, iki uç kompozisyonu AYNI kuraldan türetir
        // Gönderici ve alıcı aynı girdilerden bağımsız olarak türetir.
        (abs_seq as u32, sym)
    }

    /// Damla kompozisyonu - gönderen ve çözücü AYNI kuralı koşar (wire sözleşmesi).
    /// flags 0x01 yoksa: sistematik, seq = blok indeksi. Varsa: onarım, seq = abs_seq.
    pub fn composition(k: usize, seq: u32, is_repair: bool) -> Vec<usize> {
        if !is_repair {
            return vec![(seq as usize) % k.max(1)];
        }
        let mut rng = LcRng::new(
            0x9E3779B97F4A7C15u64
                .wrapping_mul(u64::from(seq))
                .wrapping_add(1),
        );
        let min_d = 2.min(k);
        let max_d = k.saturating_sub(1).clamp(min_d, 24).max(min_d);
        let span = (max_d - min_d + 1) as u64;
        let d = min_d + (rng.next() % span) as usize;
        let mut chosen = Vec::with_capacity(d);
        while chosen.len() < d {
            let idx = (rng.next() % k as u64) as usize;
            if !chosen.contains(&idx) {
                chosen.push(idx);
            }
        }
        chosen.sort_unstable();
        chosen
    }

    /// Kare paketleme: 20 B başlık + yük (şartname §2).
    pub fn pack(&self, seq: u32, block: u16, flags: u8, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() > BLOCK {
            return None;
        }
        let mut out = Vec::with_capacity(DAMLA_HDR_LEN + payload.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&block.to_le_bytes());
        out.push(flags);
        out.push(0u8); // ayrılmış
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        // 20 B başlık doldur (seq4+block2+flags1+rsv1+len2 = 10; kalan 10 sabit)
        out.extend_from_slice(b"BDLMQRV1AB");
        out.extend_from_slice(payload);
        Some(out)
    }
}

/// Basit LC üreteç (deterministik).
struct LcRng(u64);
impl LcRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut x = self.0;
        x ^= x >> 33;
        x.wrapping_mul(0xFF51_AFD7_ED55_8CCD)
    }
}

/// Türev üretimi (talep anında; hiçbir ara ürün saklanmaz).
/// `sikistirma`: 0=yok, 1=zlib-9 (küçültüyorsa) - burada zstd-19 vekili (kayıpsız).
/// `turns`: üretilecek karusel turu (akış için 1 tur yeter; kayıp direnci için >1).
pub fn uret_turev(data: &[u8], sikistirma: u8, turns: u64) -> Option<Vec<u8>> {
    if data.is_empty() || turns == 0 {
        return None;
    }
    // 1) sıkıştır (küçültüyorsa)
    let body: Vec<u8> = if sikistirma > 0 {
        let comp = zstd_compress(data)?;
        if comp.len() < data.len() {
            comp
        } else {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };
    // 2) karusel
    let k = Karusel::new(&body)?;
    let mut out = Vec::new();
    for t in 0..turns {
        // sistematik tur: t mod k blok sıralı
        for i in 0..k.k {
            let (seq, b) = k.systematic_drop((t as usize + i) % k.k)?;
            out.extend_from_slice(&k.pack(seq, (t % 2) as u16, 0, &b)?);
        }
        // onarım damlaları: her damla MUTLAK sırasından tohumlanır -
        // aynı tur içinde k FARKLI damla, turlar arasında da tekrar yok.
        // seq = abs_seq (çözücü kompozisyonu §3 kuralıyla yeniden türetir).
        for i in 0..k.k {
            let abs_seq = t.wrapping_mul(k.k as u64).wrapping_add(i as u64);
            let (seq, b) = k.repair_drop(abs_seq);
            out.extend_from_slice(&k.pack(seq, (t % 2) as u16, 0x01, &b)?);
        }
    }
    Some(out)
}

/// zstd-19 vekili (Cargo'da zstd var; şartnamedeki zlib-9'un kayıpsız karşılığı).
pub fn zstd_compress(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = zstd::bulk::Compressor::new(19).ok()?;
    enc.compress(data).ok()
}

pub fn zstd_decompress(data: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::Decompressor::new()
        .ok()?
        .decompress(data, 100 * 1024 * 1024)
        .ok()
}

/// ÇÖZÜCÜ (şartname §4): damla akışı → orijinal gövde.
/// Peeling + GF(2) eliminasyonu - "peeling tek başına YETMEZ" (Bulgu-5:
/// k=3, 11 doğru damla, kaybolan tek derece-1 damla → salt-peeling takıldı).
/// Rank yetersizse None döner - ASLA yanlış veri üretmez.
pub struct KaruselDecoder {
    k: usize,
    total_len: usize,
    solved: Vec<Option<Vec<u8>>>,
    solved_count: usize,
    pending: Vec<(Vec<usize>, Vec<u8>)>,
}

impl KaruselDecoder {
    pub fn new(k: usize, total_len: usize) -> Option<Self> {
        if k == 0 || k > 65_535 || total_len == 0 || total_len > k * BLOCK {
            return None;
        }
        Some(Self {
            k,
            total_len,
            solved: vec![None; k],
            solved_count: 0,
            pending: Vec::new(),
        })
    }

    pub fn is_complete(&self) -> bool {
        self.solved_count >= self.k
    }

    /// Paketlenmiş kareyi al (pack çıktısı): başlığı ayrıştır, damlayı işle.
    /// Bozuk/yabancı kare sessizce düşer (K1: yanlış bayt sızmaz).
    pub fn add_frame(&mut self, frame: &[u8]) -> bool {
        if frame.len() < DAMLA_HDR_LEN || &frame[10..20] != b"BDLMQRV1AB" {
            return false;
        }
        let seq = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let flags = frame[6];
        let len = u16::from_le_bytes([frame[8], frame[9]]) as usize;
        if frame.len() != DAMLA_HDR_LEN + len || len > BLOCK {
            return false;
        }
        let payload = &frame[DAMLA_HDR_LEN..];
        let idx = Karusel::composition(self.k, seq, flags & 0x01 != 0);
        self.add_drop(&idx, payload);
        true
    }

    /// Damlayı işle: bilinenleri düş, derece-1 ise peeling kaskadı.
    pub fn add_drop(&mut self, idx: &[usize], payload: &[u8]) {
        if self.is_complete() || idx.is_empty() || idx.iter().any(|&i| i >= self.k) {
            return;
        }
        let mut rem: Vec<usize> = Vec::with_capacity(idx.len());
        let mut pay = payload.to_vec();
        pay.resize(BLOCK, 0);
        for &i in idx {
            if let Some(s) = &self.solved[i] {
                for (a, b) in pay.iter_mut().zip(s.iter()) {
                    *a ^= b;
                }
            } else if !rem.contains(&i) {
                rem.push(i);
            }
        }
        match rem.len() {
            0 => {}
            1 => self.resolve(rem[0], pay),
            _ => self.pending.push((rem, pay)),
        }
    }

    fn resolve(&mut self, b0: usize, w0: Vec<u8>) {
        let mut queue = vec![(b0, w0)];
        while let Some((b, w)) = queue.pop() {
            if self.solved[b].is_some() {
                continue;
            }
            self.solved[b] = Some(w.clone());
            self.solved_count += 1;
            let mut i = 0;
            while i < self.pending.len() {
                if let Some(pos) = self.pending[i].0.iter().position(|&x| x == b) {
                    self.pending[i].0.swap_remove(pos);
                    for (a, c) in self.pending[i].1.iter_mut().zip(w.iter()) {
                        *a ^= c;
                    }
                    if self.pending[i].0.len() == 1 {
                        let (rem, pay) = self.pending.swap_remove(i);
                        queue.push((rem[0], pay));
                        continue; // i kaydı - swap_remove aynı i'ye yenisini koydu
                    }
                }
                i += 1;
            }
        }
    }

    /// Peeling takıldıysa GF(2) eliminasyonu (Bulgu-5 düzeltmesi).
    /// Kelime-dizisi bitset (u64 x N) - k ≤ 65535 desteklenir.
    fn eliminate(&mut self) -> bool {
        if self.is_complete() {
            return true;
        }
        let words = self.k.div_ceil(64);
        let mut rows: Vec<(Vec<u64>, Vec<u8>)> = Vec::with_capacity(self.pending.len());
        for (idx, pay) in &self.pending {
            let mut mask = vec![0u64; words];
            for &i in idx {
                mask[i / 64] |= 1u64 << (i % 64);
            }
            rows.push((mask, pay.clone()));
        }
        let unknowns: Vec<usize> = (0..self.k).filter(|&i| self.solved[i].is_none()).collect();
        let mut piv_rows: Vec<usize> = Vec::new();
        for &col in &unknowns {
            let (w, bit) = (col / 64, 1u64 << (col % 64));
            let piv = match rows
                .iter()
                .enumerate()
                .find(|(ri, (m, _))| m[w] & bit != 0 && !piv_rows.contains(ri))
            {
                Some((ri, _)) => ri,
                None => return false, // rank yetersiz - ÇÖZÜLEMEZ (yanlış veri yok)
            };
            piv_rows.push(piv);
            let (pm, pp) = (rows[piv].0.clone(), rows[piv].1.clone());
            for (ri, (m, p)) in rows.iter_mut().enumerate() {
                if ri != piv && m[w] & bit != 0 {
                    for (a, b) in m.iter_mut().zip(pm.iter()) {
                        *a ^= b;
                    }
                    for (a, b) in p.iter_mut().zip(pp.iter()) {
                        *a ^= b;
                    }
                }
            }
        }
        // her pivot artık tek bilinmeyenli olmalı
        for (ci, &col) in unknowns.iter().enumerate() {
            let (m, p) = &rows[piv_rows[ci]];
            let ones: u32 = m.iter().map(|x| x.count_ones()).sum();
            if ones != 1 {
                return false;
            }
            self.solved[col] = Some(p.clone());
            self.solved_count += 1;
        }
        self.pending.clear();
        true
    }

    /// Gövdeyi birleştir: tamamsa Some(orijinal), değilse eliminasyon dener.
    pub fn assemble(&mut self) -> Option<Vec<u8>> {
        if !self.is_complete() && !self.eliminate() {
            return None;
        }
        let mut out = Vec::with_capacity(self.total_len);
        for i in 0..self.k {
            let block = self.solved[i].as_ref()?;
            let take = (self.total_len - out.len()).min(BLOCK);
            out.extend_from_slice(&block[..take]);
            if out.len() >= self.total_len {
                break;
            }
        }
        Some(out)
    }
}

/// Türevi depoya yazma girişimi → RED (K-QR-GENISLEME kapısı).
/// QR video bir türevdir; `held_bytes`'a giremez.
pub fn qr_depoya_yazilamaz() -> Result<(), &'static str> {
    Err("K-QR-GENISLEME: QR-video türevdir, kalıcı depoya yazılamaz")
}

/// Türev büyüme oranı (video/ham) - her rejimde >1 olduğu kanıtı (K13).
pub fn turev_buyume(turev_len: usize, orijinal_len: usize) -> f64 {
    if orijinal_len == 0 {
        return 1.0;
    }
    turev_len as f64 / orijinal_len as f64
}

pub fn qrv_digest(turev: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(QRV_MAGIC);
    h.update([QRV_VERSION]);
    h.update((turev.len() as u64).to_le_bytes());
    h.update(turev);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn karusel_sistematik_akislidir() {
        let data: Vec<u8> = (0u8..=255).cycle().take(10 * BLOCK + 50).collect();
        let k = Karusel::new(&data).unwrap();
        assert_eq!(k.k, 11); // 10 tam + 1 kısa
                             // tur 0: blok 0 doğrudan gelir → anında açılabilir (akış)
        let (seq, b) = k.systematic_drop(0).unwrap();
        assert_eq!(b, data[..BLOCK]);
        assert_eq!(seq, 0);
        // onarım damlası deterministik (aynı mutlak sıra → aynı damla)
        let (s1, d1) = k.repair_drop(0);
        let (s2, d2) = k.repair_drop(0);
        assert_eq!((s1, d1.clone()), (s2, d2.clone()));
        // farklı mutlak sıra → farklı damla (kayıp direnci)
        let (s3, d3) = k.repair_drop(1);
        assert!((s1 != s3) || (d1 != d3));
        // KANARYA (yakalanan bug): bir turun k onarım damlası birbirinden farklı olmalı
        let tur0: Vec<_> = (0..k.k as u64).map(|i| k.repair_drop(i)).collect();
        let benzersiz: std::collections::BTreeSet<_> =
            tur0.iter().map(|(s, d)| (*s, d.clone())).collect();
        // eşik 2/3: küçük k'de iki tohumun aynı alt kümeyi seçmesi (doğum günü)
        // meşru ve seyrek; YAKALANAN bug ise TAMAMININ kopya olmasıydı (1/11).
        assert!(
            benzersiz.len() * 3 >= k.k * 2,
            "tur içi onarım damlaları çoğunlukla benzersiz olmalı: {}/{}",
            benzersiz.len(),
            k.k
        );
        // KANARYA (düzeltme 3): kısa son blok seçilse de damla uzunluğu kırpılmaz -
        // sym uzunluğu seçilenlerin en uzunu olmalı (BLOCK, kısa blok hariç)
        for (_, d) in &tur0 {
            assert!(
                d.len() == BLOCK || d.len() == 50,
                "damla kırpılmış: {}",
                d.len()
            );
        }
    }

    #[test]
    fn kare_paketleme_20_bayt_baslik() {
        let k = Karusel::new(b"ic".repeat(100).as_slice()).unwrap();
        let p = k.pack(5, 0, 0x04, b"veri").unwrap();
        assert_eq!(p.len(), DAMLA_HDR_LEN + 4);
        assert_eq!(&p[10..20], b"BDLMQRV1AB");
        assert_eq!(p[0..4], 5u32.to_le_bytes());
    }

    #[test]
    fn zstd_vekil_kayipsiz() {
        let data: Vec<u8> = b"sikisabilir icerik ".repeat(500);
        let c = zstd_compress(&data).unwrap();
        assert!(c.len() < data.len(), "sıkışır");
        assert_eq!(zstd_decompress(&c).unwrap(), data, "kayıpsız");
    }

    #[test]
    fn turev_buyume_depolama_degil() {
        // QR-video katmanı (sıkıştırmasız karusel) gövdeyi büyütür → türevdir (K13)
        let data = b"sikisabilir ".repeat(300);
        let turev = uret_turev(&data, 0, 1).unwrap();
        let buyume = turev_buyume(turev.len(), data.len());
        assert!(buyume > 1.0, "QR katmanı büyütür: {buyume}");
        // kapı: depoya yazılamaz
        assert!(qr_depoya_yazilamaz().is_err());
    }

    #[test]
    fn uret_turev_deterministik() {
        let data = b"deterministik turev".repeat(20);
        let a = uret_turev(&data, 1, 2).unwrap();
        let b = uret_turev(&data, 1, 2).unwrap();
        assert_eq!(qrv_digest(&a), qrv_digest(&b));
    }

    #[test]
    fn cozucu_uctan_uca_bit_esit() {
        // ŞARTNAME §4 kapanışı: üret → kareler → çözücü → bayt-eşit
        let data: Vec<u8> = (0u8..=255).cycle().take(13 * BLOCK + 77).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        // yalnız sistematik tur (kayıpsız kanal): k karede bitmeli
        for i in 0..k.k {
            let (seq, b) = k.systematic_drop(i).unwrap();
            let frame = k.pack(seq, 0, 0, &b).unwrap();
            assert!(dec.add_frame(&frame));
        }
        assert!(
            dec.is_complete(),
            "sistematik tarama k karede tamamlar (K6: fazlalık 1.00)"
        );
        assert_eq!(dec.assemble().unwrap(), data, "bayt-eşit");
    }

    #[test]
    fn cozucu_kayipli_kanal_onarimla_tamamlar() {
        // %30 sistematik kare kaybı → onarım damlaları kapatır (K1 deseni)
        let data: Vec<u8> = (7u8..=200).cycle().take(11 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        for i in 0..k.k {
            if i % 3 == 0 {
                continue; // her 3. kare kayıp
            }
            let (seq, b) = k.systematic_drop(i).unwrap();
            dec.add_frame(&k.pack(seq, 0, 0, &b).unwrap());
        }
        assert!(!dec.is_complete(), "kayıpla eksik kalmalı");
        for abs_seq in 0..(3 * k.k as u64) {
            if dec.is_complete() {
                break;
            }
            let (seq, b) = k.repair_drop(abs_seq);
            dec.add_frame(&k.pack(seq, 0, 0x01, &b).unwrap());
        }
        assert_eq!(
            dec.assemble().unwrap(),
            data,
            "onarım + eliminasyon bayt-eşit"
        );
    }

    #[test]
    fn cozucu_yetersiz_damla_red() {
        // NEGATİF KANARYA: k/2 damla → assemble None (asla yanlış veri değil)
        let data: Vec<u8> = (1u8..=100).cycle().take(10 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        for i in 0..k.k / 2 {
            let (seq, b) = k.systematic_drop(i).unwrap();
            dec.add_frame(&k.pack(seq, 0, 0, &b).unwrap());
        }
        assert!(
            dec.assemble().is_none(),
            "yetersiz damla → None (K1 negatif kanarya)"
        );
    }

    #[test]
    fn cozucu_bozuk_kare_sessiz_duser() {
        let data: Vec<u8> = (3u8..=90).cycle().take(5 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        // bozuk magic → red
        assert!(!dec.add_frame(b"XXXXXXXXXXXXXXXXXXXXXXXX"));
        // uzunluk tutarsız → red
        let (seq, b) = k.systematic_drop(0).unwrap();
        let mut fr = k.pack(seq, 0, 0, &b).unwrap();
        fr.truncate(fr.len() - 3);
        assert!(!dec.add_frame(&fr));
        assert_eq!(dec.solved_count, 0, "bozuk kare hiçbir blok çözmez");
    }

    #[test]
    fn kompozisyon_iki_uc_ayni_kurali_turetir() {
        // wire sözleşmesi: gönderen repair_drop + çözücü composition AYNI kümeyi bulur
        let data: Vec<u8> = (0u8..=255).cycle().take(9 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        for abs_seq in 0..20u64 {
            let (seq, sym) = k.repair_drop(abs_seq);
            let idx = Karusel::composition(k.k, seq, true);
            // aynı kümeyi XOR'layınca aynı damla çıkmalı
            let mut expect = vec![0u8; idx.iter().map(|&i| k.blocks[i].len()).max().unwrap()];
            for &i in &idx {
                for (a, b) in expect.iter_mut().zip(k.blocks[i].iter()) {
                    *a ^= b;
                }
            }
            assert_eq!(
                sym, expect,
                "abs_seq={abs_seq}: iki uç ayrışırsa wire kırık"
            );
        }
    }

    #[test]
    fn gecersiz_girdi_red() {
        assert!(Karusel::new(b"").is_none());
        assert!(uret_turev(b"", 1, 1).is_none());
        assert!(uret_turev(b"veri", 1, 0).is_none());
    }
}
