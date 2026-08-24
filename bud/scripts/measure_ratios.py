#!/usr/bin/env python3
# B.U.D. 2.0 - the deterministic compression ratio measurement tool
# (K15/K2/K19).
#
# Purpose: to verify the claimed ratios (for example JSON at 17.19x) against a
# REAL measurement. This tool produces the deterministic corpus the measurement
# runner uses and measures the JSON/CSV/LOG ratios with zstd-19 and xz-9. The
# output has to agree with FORMAT-V2.md section 7; if it does not, the claim is
# wrong (the K19 canary).
#
# Usage: python3 scripts/measure_ratios.py [--seed 7] [--rows 50000]
# Dependency: pip install zstandard (the stdlib lzma is enough for xz)
#
# DEBT: the repository rule says the code languages are Rust and Budl only.
# This file is the one remaining exception, and it is deliberate: the numbers
# recorded in FORMAT-V2.md section 7, bud_format_real.rs and
# bud_format_container.rs were produced by THIS corpus, which depends on
# Python's Mersenne Twister at seed 7. Porting it to Rust changes the corpus
# and therefore every recorded ratio. The port is a separate, measured piece of
# work: rewrite the generator, re-measure, and update all four places in the
# same commit.

import argparse, json, lzma, random, sys, time

def measure(args):
    random.seed(args.seed)
    try:
        import zstandard as zstd
        def zs(d, l=19):
            return zstd.ZstdCompressor(level=l).compress(d)
    except ImportError:
        print("!! no zstandard - the zstd ratios are skipped (pip install zstandard)")
        def zs(d, l=19):
            return lzma.compress(d)
        print("!! lzma is used instead (for reference only)")
    def xz(d):
        return lzma.compress(d, preset=9)

    print(f"=== B.U.D. 2.0 measurement ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}) seed={args.seed} ===")

    # --- JSON: 50k records (user/ts/action/value/status) ---
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
    print(f"JSON  raw={len(j):>9}  zstd19={len(jz):>9}  {len(j)/len(jz):6.2f}x | xz9={len(jx):>9}  {len(j)/len(jx):6.2f}x")

    # --- CSV: 60k lines ---
    csv = "".join(
        f"u{random.randint(1,2000)},2026-08-{random.randint(1,16):02d},{random.choice(['a','b','c'])},{random.randint(1,10**7)},{random.randint(200,500)}\n"
        for _ in range(60000)).encode()
    cz, cx = zs(csv), xz(csv)
    print(f"CSV   raw={len(csv):>9}  zstd19={len(cz):>9}  {len(csv)/len(cz):6.2f}x | xz9={len(cx):>9}  {len(csv)/len(cx):6.2f}x")

    # --- LOG: 80k lines (a template plus repetition) ---
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
    print(f"LOG   raw={len(log):>9}  zstd19={len(lz_):>9}  {len(log)/len(lz_):6.2f}x | xz9={len(lx):>9}  {len(log)/len(lx):6.2f}x")

    # --- The canary (K19): is the claimed JSON 17.19x real? ---
    jr = len(j) / len(jz)
    print()
    if jr < 17.19:
        print(f"CANARY: JSON zstd19 is {jr:.2f}x, below the claimed 17.19x - THE CLAIM DOES NOT HOLD AGAINST THE MEASUREMENT.")
        print("  The $0.016/TB/month ceiling requires 18.76x for EVENODD(1.286) and 16.68x for plain 7+1(1.143).")
        print("  At this measurement JSON only APPROACHES plain 7+1; it DOES NOT HOLD EVENODD (the K19 canary is active).")
    else:
        print(f"CANARY: JSON zstd19 is {jr:.2f}x, at or above 17.19x - the claim holds against the measurement (not expected).")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rows", type=int, default=50000)
    measure(ap.parse_args())
