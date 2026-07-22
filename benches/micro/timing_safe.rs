//! benches/micro/timing_safe.rs — Task 8.6 dudect-tarzı istatistiksel zamanlama regresyon testi.
//!
//! RPC kimlik doğrulamasındaki `constant_time_eq_str` karşılaştırmasının
//! gerçekten sabit-zamanlı kaldığını istatistiksel olarak denetler:
//!
//!   1. Pozitif kontrol: erken-çıkışlı naif `==` benzeri karşılaştırmanın
//!      "ilk bayt farklı" vs "son bayt farklı" sınıfları arasında ÖLÇÜLEBİLİR
//!      zamanlama farkı ürettiği doğrulanır (harness duyarlılık testi).
//!      Kontrol farkı gösteremezse ortam/harness güvenilmezdir → exit 2.
//!   2. Asıl test: `constant_time_eq_str` aynı iki sınıf arasında fark
//!      ÜRETMEMELİDİR; |Welch-t| >= 4.5 ise sabit-zamanlılık bozulmuştur
//!      (veya ölçüm tekrarı gerekir — CI bu durumda fail olur) → exit 1.
//!
//! İstatistik: dudect'in kullandığı Welch'in t-testi; ham ölçümler yerine
//! batch-minimum değerleri kullanılır (kesintiler ancak süre EKLER; minimum
//! alarak outlier'lar elenir — side-channel literatüründe standart robust
//! yaklaşım). Eşik 4.5, dudect standardıdır.
//!
//! Çalıştırma:
//!   cargo bench --bench timing_safe          (CI bunu kullanır)
//! Ortam değişkenleri (yerel derinlemesine analiz için):
//!   TIMING_SAFE_BATCHES (vars. 64), TIMING_SAFE_ITERS (vars. 4096/batch/sınıf)

use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use budlum_core::rpc::server::constant_time_eq_str;

/// dudect standardı karar eşiği.
const T_THRESHOLD: f64 = 4.5;

/// Pozitif kontrol: kasten erken-çıkışlı, zamanlama sızıntısı olan
/// karşılaştırma. Bunu yakalayamayan harness sabit-zamanlılık ihlalini de
/// yakalayamaz.
fn naive_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Deterministik sahte-rastgele kaynak (xorshift64*): girdi sabit kalmasın diye
/// anahtar malzemesi bundan türetilir; seed sabit olduğundan koşular tekrar
/// üretilebilir.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// n batch × iters ölçüm; her batch'te iki sınıf dönüşümlü (interleaved)
/// ölçülür ve batch başına sınıf MINIMUMU döndürülür.
fn measure_min_per_batch<F: Fn(&[u8], &[u8]) -> bool>(
    f: F,
    first: &[u8],
    last: &[u8],
    valid: &[u8],
    batches: usize,
    iters: usize,
) -> (Vec<u64>, Vec<u64>) {
    let mut mins_first = Vec::with_capacity(batches);
    let mut mins_last = Vec::with_capacity(batches);
    for _ in 0..batches {
        let mut m_first = u64::MAX;
        let mut m_last = u64::MAX;
        for i in 0..iters {
            // Dönüşümlü ölçüm: sürüklenme (drift) her iki sınıfa eşit biner.
            let (cand, acc) = if i % 2 == 0 {
                (first, &mut m_first)
            } else {
                (last, &mut m_last)
            };
            let t0 = Instant::now();
            black_box(f(black_box(cand), black_box(valid)));
            let dt = t0.elapsed().as_nanos() as u64;
            *acc = (*acc).min(dt);
        }
        mins_first.push(m_first);
        mins_last.push(m_last);
    }
    (mins_first, mins_last)
}

fn mean(xs: &[u64]) -> f64 {
    xs.iter().sum::<u64>() as f64 / xs.len() as f64
}

fn variance(xs: &[u64]) -> f64 {
    let m = mean(xs);
    xs.iter().map(|x| (*x as f64 - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0)
}

/// Welch'in t-istatistiği (eşit olmayan varyans varsayımı).
fn welch_t(a: &[u64], b: &[u64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let num = mean(a) - mean(b);
    let den = (variance(a) / na + variance(b) / nb).sqrt();
    if den == 0.0 {
        // Ortam aşırı sessiz: iki dağılım da tek değere çökmüş. İstatistik
        // kurulamaz; fail-safe olarak f64::MAX döndür (çağıran karar verir).
        return if num == 0.0 { 0.0 } else { f64::MAX };
    }
    num / den
}

fn getenv_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() -> ExitCode {
    let batches = getenv_usize("TIMING_SAFE_BATCHES", 64);
    let iters = getenv_usize("TIMING_SAFE_ITERS", 4096);

    // 64-bayt'lık deterministik "API anahtarı" (x-api-key uzunluk sınıfında).
    let mut rng = XorShift(0xB0D1_0CA7_5EED_1234);
    let secret: String = (0..64)
        .map(|_| {
            let r = (rng.next() % 62) as u8;
            match r {
                0..=25 => (b'A' + r) as char,
                26..=51 => (b'a' + r - 26) as char,
                _ => (b'0' + r - 52) as char,
            }
        })
        .collect();

    // Sınıf A: ilk karakter farklı (naif karşılaştırma anında döner).
    // Sınıf B: son karakter farklı (naif karşılaştırma en uzun yolu yürür).
    let mut diff_first = secret.clone();
    let mut diff_last = secret.clone();
    let first_byte = secret.as_bytes()[0];
    let last_byte = secret.as_bytes()[63];
    diff_first.replace_range(0..1, if first_byte == b'A' { "B" } else { "A" });
    diff_last.replace_range(63..64, if last_byte == b'A' { "B" } else { "A" });

    // Isınma: I-cache/branch predictor dengelensin.
    for _ in 0..20_000 {
        black_box(constant_time_eq_str(
            black_box(&diff_first),
            black_box(&secret),
        ));
        black_box(naive_eq_bytes(
            black_box(diff_last.as_bytes()),
            black_box(secret.as_bytes()),
        ));
    }

    // 1) Pozitif kontrol (harness duyarlılığı)
    let (ctl_a, ctl_b) = measure_min_per_batch(
        naive_eq_bytes,
        diff_first.as_bytes(),
        diff_last.as_bytes(),
        secret.as_bytes(),
        batches,
        iters,
    );
    let t_control = welch_t(&ctl_a, &ctl_b);

    // 2) Asıl ölçüm (constant-time implementasyon)
    let ct = |a: &[u8], b: &[u8]| -> bool {
        constant_time_eq_str(
            std::str::from_utf8(a).expect("ascii anahtar"),
            std::str::from_utf8(b).expect("ascii anahtar"),
        )
    };
    let (ct_a, ct_b) = measure_min_per_batch(
        ct,
        diff_first.as_bytes(),
        diff_last.as_bytes(),
        secret.as_bytes(),
        batches,
        iters,
    );
    let t_ct = welch_t(&ct_a, &ct_b);

    println!("=== Task 8.6 timing-safe istatistiksel test (dudect-tarzı) ===");
    println!("batches={batches} iters/batch/sınıf={iters} eşik=|t|>={T_THRESHOLD}");
    println!(
        "kontrol (naif, SIZMALI): mean_first={:.2}ns mean_last={:.2}ns |t|={:.2}",
        mean(&ctl_a),
        mean(&ctl_b),
        t_control.abs()
    );
    println!(
        "constant_time_eq_str : mean_first={:.2}ns mean_last={:.2}ns |t|={:.2}",
        mean(&ct_a),
        mean(&ct_b),
        t_ct.abs()
    );

    if t_control.abs() < T_THRESHOLD {
        eprintln!(
            "FAIL(harness): pozitif kontrol zamanlama farkı üretemedi (|t|={:.2} < {T_THRESHOLD}). \
             Bu ortamda ölçüm güvenilmez; sabit-zamanlılık sonucu GEÇERSİZ.",
            t_control.abs()
        );
        return ExitCode::from(2);
    }
    if t_ct.abs() >= T_THRESHOLD {
        eprintln!(
            "FAIL(regresyon): constant_time_eq_str sınıflar arasında ölçülebilir fark üretti \
             (|t|={:.2} >= {T_THRESHOLD}). Sabit-zamanlılık bozulmuş olabilir!",
            t_ct.abs()
        );
        return ExitCode::from(1);
    }
    println!("PASS: kontrol duyarlı, constant_time_eq_str sınıflar arası fark üretmedi.");
    ExitCode::SUCCESS
}
