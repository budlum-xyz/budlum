#!/usr/bin/env python3
# B.U.D. 2.0 - Deterministik Sıkıştırma Oranı Ölçüm Aracı (K15/K2/K19)
#
# Amaç: iddia edilen oranların (ör. JSON 17.19x) GERÇEK ölçümle doğrulanması.
# Bu araç, skill-olcum runner'ının kullandığı deterministik korpusu üretir ve
# zstd-19 / xz-9 ile JSON/CSV/LOG oranlarını ölçer. Çıktı FORMAT-V2.md §7 ile
# tutarlı olmalıdır; tutmuyorsa iddia yanlıştır (K19 kanaryası).
#
# Kullanım: python3 scripts/measure_ratios.py [--seed 7] [--rows 50000]
# Bağımlılık: pip install zstandard (xz için stdlib lzma yeterli)

import argparse, json, lzma, random, sys, time

def measure(args):
    random.seed(args.seed)
    try:
        import zstandard as zstd
        def zs(d, l=19):
            return zstd.ZstdCompressor(level=l).compress(d)
    except ImportError:
        print("!! zstandard yok - zstd oranları atlanıyor (pip install zstandard)")
        def zs(d, l=19):
            return lzma.compress(d)
        print("!! yerine lzma kullanılıyor (yalnız referans)")
    def xz(d):
        return lzma.compress(d, preset=9)

    print(f"=== B.U.D. 2.0 ölçüm ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}) seed={args.seed} ===")

    # --- JSON: 50k kayıt (kullanıcı/ts/action/value/status) ---
    rows = []
    for i in range(args.rows):
        rows.append({
            "u": f"u{random.randint(1, 2000)}",
            "ts": f"2026-08-{random.randint(1,16):02d}T{random.randint(0,23):02d}:00Z",
            "a": random.choice(["l", "r", "w", "d"]),
            "v": random.randint(1, 10**7),
            "s": random.choice([200, 200, 404, 500]),
        })
    j = json.dumps(rows, separators=(",", ":")).encode()
    jz, jx = zs(j), xz(j)
    print(f"JSON  ham={len(j):>9}  zstd19={len(jz):>9}  {len(j)/len(jz):6.2f}x | xz9={len(jx):>9}  {len(j)/len(jx):6.2f}x")

    # --- CSV: 60k satır ---
    csv = "".join(
        f"u{random.randint(1,2000)},2026-08-{random.randint(1,16):02d},{random.choice(['a','b','c'])},{random.randint(1,10**7)},{random.randint(200,500)}\n"
        for _ in range(60000)).encode()
    cz, cx = zs(csv), xz(csv)
    print(f"CSV   ham={len(csv):>9}  zstd19={len(cz):>9}  {len(csv)/len(cz):6.2f}x | xz9={len(cx):>9}  {len(csv)/len(cx):6.2f}x")

    # --- LOG: 80k satır (şablon + tekrar) ---
    tmpl = [
        "2026-08-16T10:00:{m:02d}Z INFO req={r} {p} s={s} b={b} reg={g}",
        "2026-08-16T10:01:{m:02d}Z WARN req={r} {p} s={s} b={b} reg={g}",
    ]
    log = "\n".join(
        random.choice(tmpl).format(
            m=i % 60, r=random.randint(10**9, 10**10),
            p=random.choice(["/a", "/b", "/c"]),
            s=random.choice([200, 200, 404, 500]),
            b=random.randint(1, 10**6),
            g=random.choice(["tr", "de", "us"]))
        for i in range(80000)).encode()
    lz_, lx = zs(log), xz(log)
    print(f"LOG   ham={len(log):>9}  zstd19={len(lz_):>9}  {len(log)/len(lz_):6.2f}x | xz9={len(lx):>9}  {len(log)/len(lx):6.2f}x")

    # --- Kanarya (K19): iddia edilen 17.19x JSON gerçek mi? ---
    jr = len(j) / len(jz)
    print()
    if jr < 17.19:
        print(f"KANARYA: JSON zstd19 {jr:.2f}x < 17.19x (iddia) - İDDİA ÖLÇÜMLE TUTMUYOR.")
        print("  tavan $0.016/TB/ay EVENODD(1.286) için 18.76x, Düz 7+1(1.143) için 16.68x gerektirir.")
        print("  Bu ölçümle JSON Düz 7+1'e bile ANCAK yaklaşır; EVENODD'u TUTMAZ (K19 kanaryası aktif).")
    else:
        print(f"KANARYA: JSON zstd19 {jr:.2f}x >= 17.19x - iddia ölçümle tutuyor (beklenmiyor).")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rows", type=int, default=50000)
    measure(ap.parse_args())
