// B.U.D. 2.0 - the deterministic compression ratio measurement tool
// (K15/K2/K19). Rust port of the former scripts/measure_ratios.py.
//
// Purpose: to verify the claimed ratios (for example JSON at 17.19x) against a
// REAL measurement. This tool produces the deterministic corpus the
// measurement runner uses and measures the JSON/CSV/LOG ratios with zstd-19
// and xz-9. The output has to agree with FORMAT-V2.md section 7; if it does
// not, the claim is wrong (the K19 canary).
//
// Usage: cargo run --release --bin measure_ratios -- [--seed 7] [--rows 50000]
//        [--dump DIR]   (writes json.bin/csv.bin/log.bin for sha256sum checks)
//
// The corpus is bit-identical to the one the Python tool produced: this file
// implements CPython's Mersenne Twister exactly (random.seed(int) via
// init_by_array, getrandbits, and the _randbelow rejection loop behind
// randint/choice), so every recorded ratio stays reproducible.
//
// zstd-19 uses the `zstd` crate (a crate dependency). There is no xz crate in
// the lock, and none is added: xz-9 is measured by piping the corpus through
// the system `xz -9 -c` binary (xz-utils must be installed; it writes the same
// .xz stream, CRC64, as Python's lzma.compress(preset=9)). If `xz` is missing
// the xz columns are reported as unavailable.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const N: usize = 624;
const M: usize = 397;

/// CPython-compatible MT19937.
struct Mt {
    mt: [u32; N],
    idx: usize,
}

impl Mt {
    fn init_genrand(s: u32) -> Mt {
        let mut mt = [0u32; N];
        mt[0] = s;
        for i in 1..N {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Mt { mt, idx: N }
    }

    /// `random.seed(int)`: key = 32-bit little-endian chunks of abs(seed).
    fn seed(seed: u64) -> Mt {
        let mut key = vec![(seed & 0xffff_ffff) as u32];
        if seed >> 32 != 0 {
            key.push((seed >> 32) as u32);
        }
        let mut r = Mt::init_genrand(19650218);
        let (mut i, mut j) = (1usize, 0usize);
        for _ in 0..N.max(key.len()) {
            let prev = r.mt[i - 1];
            r.mt[i] = (r.mt[i] ^ (prev ^ (prev >> 30)).wrapping_mul(1664525))
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                r.mt[0] = r.mt[N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..N - 1 {
            let prev = r.mt[i - 1];
            r.mt[i] =
                (r.mt[i] ^ (prev ^ (prev >> 30)).wrapping_mul(1566083941)).wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                r.mt[0] = r.mt[N - 1];
                i = 1;
            }
        }
        r.mt[0] = 0x8000_0000;
        r
    }

    fn genrand(&mut self) -> u32 {
        if self.idx >= N {
            for k in 0..N {
                let y = (self.mt[k] & 0x8000_0000) | (self.mt[(k + 1) % N] & 0x7fff_ffff);
                let mut v = self.mt[(k + M) % N] ^ (y >> 1);
                if y & 1 != 0 {
                    v ^= 0x9908_b0df;
                }
                self.mt[k] = v;
            }
            self.idx = 0;
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// `random.getrandbits(k)` for 1 <= k <= 64.
    fn getrandbits(&mut self, k: u32) -> u64 {
        if k <= 32 {
            return (self.genrand() >> (32 - k)) as u64;
        }
        let mut out = 0u64;
        let mut left = k;
        let mut shift = 0;
        while left > 0 {
            let mut r = self.genrand() as u64;
            if left < 32 {
                r >>= 32 - left;
            }
            out |= r << shift;
            shift += 32;
            left = left.saturating_sub(32);
        }
        out
    }

    /// `random._randbelow` (getrandbits rejection loop).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let k = 64 - n.leading_zeros();
        loop {
            let r = self.getrandbits(k);
            if r < n {
                return r;
            }
        }
    }

    fn randint(&mut self, a: u64, b: u64) -> u64 {
        a + self.below(b - a + 1)
    }

    fn choice<'a, T>(&mut self, seq: &'a [T]) -> &'a T {
        let i = self.below(seq.len() as u64) as usize;
        &seq[i]
    }
}

fn gen_json(r: &mut Mt, rows: usize) -> Vec<u8> {
    let mut s = String::from("[");
    for i in 0..rows {
        if i > 0 {
            s.push(',');
        }
        let u = r.randint(1, 2000);
        let day = r.randint(1, 16);
        let hour = r.randint(0, 23);
        let a = *r.choice(&["l", "r", "w", "d"]);
        let v = r.randint(1, 10_000_000);
        let st = *r.choice(&[200, 200, 404, 500]);
        s.push_str(&format!(
            "{{\"u\":\"u{u}\",\"ts\":\"2026-08-{day:02}T{hour:02}:00Z\",\"a\":\"{a}\",\"v\":{v},\"s\":{st}}}"
        ));
    }
    s.push(']');
    s.into_bytes()
}

fn gen_csv(r: &mut Mt) -> Vec<u8> {
    let mut s = String::new();
    for _ in 0..60000 {
        let u = r.randint(1, 2000);
        let day = r.randint(1, 16);
        let c = *r.choice(&["a", "b", "c"]);
        let v = r.randint(1, 10_000_000);
        let st = r.randint(200, 500);
        s.push_str(&format!("u{u},2026-08-{day:02},{c},{v},{st}\n"));
    }
    s.into_bytes()
}

fn gen_log(r: &mut Mt) -> Vec<u8> {
    let mut s = String::new();
    for i in 0..80000usize {
        if i > 0 {
            s.push('\n');
        }
        let (min, lvl) = if r.below(2) == 0 {
            (10, "INFO")
        } else {
            (11, "WARN")
        };
        let m = i % 60;
        let req = r.randint(1_000_000_000, 10_000_000_000);
        let p = *r.choice(&["/a", "/b", "/c"]);
        let st = *r.choice(&[200, 200, 404, 500]);
        let b = r.randint(1, 1_000_000);
        let g = *r.choice(&["tr", "de", "us"]);
        s.push_str(&format!(
            "2026-08-16T10:{:02}:{m:02}Z {lvl} req={req} {p} s={st} b={b} reg={g}",
            min - 10
        ));
    }
    s.into_bytes()
}

fn zstd19(d: &[u8]) -> Result<usize, String> {
    zstd::bulk::compress(d, 19)
        .map(|v| v.len())
        .map_err(|e| e.to_string())
}

/// xz -9 via the system binary; None when xz is unavailable.
fn xz9(d: &[u8]) -> Option<usize> {
    let mut child = Command::new("xz")
        .args(["-9", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let mut stdout = child.stdout.take()?;
    let data = d.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).ok()?;
    let _ = writer.join();
    let status = child.wait().ok()?;
    status.success().then_some(out.len())
}

fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn report(name: &str, raw: &[u8]) -> Result<(), String> {
    let z = zstd19(raw)?;
    let rawl = raw.len();
    let zr = rawl as f64 / z as f64;
    match xz9(raw) {
        Some(x) => println!(
            "{name:<5} raw={rawl:>9}  zstd19={z:>9}  {zr:6.2}x | xz9={x:>9}  {:6.2}x",
            rawl as f64 / x as f64
        ),
        None => println!(
            "{name:<5} raw={rawl:>9}  zstd19={z:>9}  {zr:6.2}x | xz9=unavailable (no `xz` binary)"
        ),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed: u64 = 7;
    let mut rows: usize = 50000;
    let mut dump: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--seed" => seed = val()?.parse()?,
            "--rows" => rows = val()?.parse()?,
            "--dump" => dump = Some(val()?),
            _ => return Err(format!("unknown argument {a}").into()),
        }
    }
    let mut r = Mt::seed(seed);
    println!("=== B.U.D. 2.0 measurement ({}) seed={seed} ===", utc_now());
    let j = gen_json(&mut r, rows);
    let c = gen_csv(&mut r);
    let l = gen_log(&mut r);
    if let Some(dir) = &dump {
        std::fs::create_dir_all(dir)?;
        std::fs::write(format!("{dir}/json.bin"), &j)?;
        std::fs::write(format!("{dir}/csv.bin"), &c)?;
        std::fs::write(format!("{dir}/log.bin"), &l)?;
    }
    report("JSON", &j)?;
    report("CSV", &c)?;
    report("LOG", &l)?;

    // The canary (K19): is the claimed JSON 17.19x real?
    let jr = j.len() as f64 / zstd19(&j)? as f64;
    println!();
    if jr < 17.19 {
        println!("CANARY: JSON zstd19 is {jr:.2}x, below the claimed 17.19x - THE CLAIM DOES NOT HOLD AGAINST THE MEASUREMENT.");
        println!("  The $0.016/TB/month ceiling requires 18.76x for EVENODD(1.286) and 16.68x for plain 7+1(1.143).");
        println!("  At this measurement JSON only APPROACHES plain 7+1; it DOES NOT HOLD EVENODD (the K19 canary is active).");
    } else {
        println!("CANARY: JSON zstd19 is {jr:.2}x, at or above 17.19x - the claim holds against the measurement (not expected).");
    }
    Ok(())
}
