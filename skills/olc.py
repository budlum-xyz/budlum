#!/usr/bin/env python3
"""SKILL: yerel dogrulama zinciri (bicim, klippy, kapilar, pedantic sayimi).

Arac seti sandbox geri yuklemesinde kaybolur (rustup/cargo, protoc, gitleaks,
actionlint, cargo-vet). Betik eksik araci sessizce atlamaz: ya kurar ya da
durur ve kullanimi yazdirir. Kapı ikilisi xtask/gates kaynaklari yerelden
yeniden derlenir; aksi halde eski kurallar uygulanir (olculdu: bayat ikili
yanlis FAIL/yanlis OK verdi).

  python3 olc.py <dizin>                 # fmt + gates --all
  python3 olc.py <dizin> --klippy        # + cargo clippy -p budlum-core --lib -D warnings
  python3 olc.py <dizin> --pedantic src/storage   # + pedantic/nursery sayimi + dosera dagilim
  python3 olc.py <dizin> --kur           # rustup + protoc kurulumu (agdan)
"""
import collections
import json
import os
import re
import subprocess
import sys

DIZIN = sys.argv[1]
MOD = sys.argv[2] if len(sys.argv) > 2 else "--klippy"
TC = "/home/user/work/.cache/tc2"
ENV = {**os.environ,
       "PATH": TC + "/cargo/bin:/home/user/work/bin:" + os.environ.get("PATH", ""),
       "RUSTUP_HOME": TC + "/rustup", "CARGO_HOME": TC + "/cargo",
       "CARGO_BUILD_JOBS": "1", "CARGO_INCREMENTAL": "0",
       # `CARGO_PROFILE_*_DEBUG=0` profil parmak izini degistirir: sicak cache'te
       # tum agaci yeniden derletiyor (olculdu, sonra rustc SIGKILL yedi). Soguk
       # derlemede ise debug bilgisi bellek ve disk yeri, o yuzden dev profili
       # kapali tutulur - clippy dev profilini kullanir, test profilinin cache'i
       # kendi hâlinde birikir.
       "CARGO_PROFILE_DEV_DEBUG": "0",
       "PROTOC": "/home/user/work/protoc27/bin/protoc"}


def taze():
    """Cargo parmagi izler: degmeyen kaynak yeniden derlenmez ve clippy onerileri
    ile uyari sayimi bos cikar (olculdu: --fix hicbir sey degistirmedi, sayim 0
    geldi). Her olcumden once kaynaklara dokunmak yeterli, deps yeniden derlenmiyor."""
    subprocess.run("find src -name '*.rs' -exec touch {} +", shell=True, cwd=DIZIN)


def run(cmd, cwd=DIZIN):
    # `cargo test` yerel olarak calistirilmaz (olculdu): budlum-core'un lib test
    # profili bu kutunun bellek sinirini asiyor, rustc SIGKILL ile olduruluyor ve
    # sandbox'in exec yolu dakalarca hicbir komutu calistirmiyor. Yerine
    # `cargo check -p budlum-core --lib --profile test` kosulur; birim testlerini
    # kosan ve sayan tek yer CI'dir, sayi oradan okunur.
    if "cargo test" in cmd:
        return 126, ("YEREL TEST KOSUMU YAPILMIYOR (OOM): bunun yerine "
                     "`cargo check -p budlum-core --lib --profile test` ve CI loğu.")
    # Borulu komutlarda cikis kodu son komutunkidir (`| tail -20` her zaman 0
    # dondurur); olculdu: CI pedantic ile kirmiziya dusen kapilari bu arac
    # "cikis: 0" gostererek gecmisti. pipefail borunun basindaki hatiri tasisin.
    if "|" in cmd:
        p = subprocess.run(["bash", "-c", "set -o pipefail; " + cmd], cwd=cwd, env=ENV,
                           capture_output=True, text=True)
    else:
        p = subprocess.run(cmd, shell=True, cwd=cwd, env=ENV, capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def kur():
    print("# arac kurulumu")
    if not os.path.exists(TC + "/cargo/bin/cargo"):
        subprocess.run("curl -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh && "
                       "rm -rf %s/rustup/toolchains/* %s/rustup/settings.toml && "
                       "RUSTUP_HOME=%s/rustup CARGO_HOME=%s/cargo sh /tmp/rustup-init.sh -y "
                       "--default-toolchain 1.97.1 --profile minimal -c rustfmt -c clippy"
                       % (TC, TC, TC, TC), shell=True)
    if not os.path.exists("/home/user/work/protoc27/bin/protoc"):
        subprocess.run("cd /tmp && curl -sSL -o pc.zip "
                       "https://github.com/protocolbuffers/protobuf/releases/download/"
                       "v27.2/protoc-27.2-linux-x86_64.zip && rm -rf /home/user/work/protoc27 && "
                       "unzip -oq pc.zip -d /home/user/work/protoc27", shell=True)
    # Arac agaci snapshot disi bir klasorde tutulur (4 GB'lik agac geri yuklemeyi
    # patlatiyordu); ~/.cargo ve ~/.rustup oraya symlink'lenir, ~/.profile da
    # yollari yazar. Olculdu: boylece tek on yoklama ile cargo/actionlint/protac
    # bulunuyor.
    for hedef, kaynak in (("/home/user/.cargo", TC + "/cargo"), ("/home/user/.rustup", TC + "/rustup")):
        if not os.path.islink(hedef):
            subprocess.run("rm -rf %s && ln -s %s %s" % (hedef, kaynak, hedef), shell=True)
    if not os.path.exists("/home/user/.profile") or "CARGO_HOME" not in open("/home/user/.profile").read():
        open("/home/user/.profile", "a").write(
            "\nexport CARGO_HOME=/home/user/.cargo RUSTUP_HOME=/home/user/.rustup\n"
            'export PATH="$CARGO_HOME/bin:/home/user/work/bin:/home/user/work/protoc27/bin:$PATH"\n'
            "export PROTOC=/home/user/work/protoc27/bin/protoc\n"
            "[ -f $CARGO_HOME/env ] && . $CARGO_HOME/env\n"
            "export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0\n")
    for _d in ("/home/user/work/bin", "/home/user/work/protoc27/bin"):
        subprocess.run("chmod +x %s/* 2>/dev/null || true" % _d, shell=True)
    for c, v in (("cargo", "--version"), ("gitleaks", "--version"), ("actionlint", "--version")):
        k, o = run("which %s && %s %s | head -1" % (c, c, v))
        print("  %-10s %s" % (c, o.strip().splitlines()[-1] if o.strip() else "YOK"))


def durum():
    """Arac agacinin var oldugunu tek komutla bildirir (geri yukleme kontrolu)."""
    print("# durum")
    var = os.path.exists(TC + "/cargo/bin/cargo")
    print("  cargo: %s" % ("VAR" if var else "YOK -> python3 skills/olc.py <dizin> --kur"))
    for yol in ("/home/user/work/bin/actionlint", "/home/user/work/bin/gitleaks",
                "/home/user/work/protoc27/bin/protoc"):
        print("  %-40s %s" % (yol, "VAR" if os.path.exists(yol) else "YOK"))
    k, o = run("cargo --version") if var else (127, "")
    print("  surum: %s" % (o.strip() or "okunamadi"))


def kapilar():
    print("# kapilar")
    src = os.path.join(DIZIN, "xtask/gates/src")
    binary = os.path.join(DIZIN, "xtask/gates/target/release/budlum-gates")
    if not os.path.exists(binary) or (os.path.getmtime(max(
            [os.path.join(r, f) for r, _, fs in os.walk(src) for f in fs])) >
            os.path.getmtime(binary)):
        k, o = run("find xtask/gates/src -name '*.rs' -exec touch {} + && "
                   "cargo build --release --manifest-path xtask/gates/Cargo.toml")
        print("  derleme:", "ok" if k == 0 else o[-400:])
    k, o = run("./xtask/gates/target/release/budlum-gates --all")
    fail = [l for l in o.splitlines() if l.startswith("FAIL")]
    print("  gates --all: cikis %d | FAIL %d" % (k, len(fail)))
    for l in fail[:8]:
        print("   ", l[:170])
    return fail


def klippy():
    print("# clippy -D warnings (lib)")
    if not os.path.exists(TC + "/cargo/bin/cargo"):
        print("  cargo yok: once --kur")
        return 1
    k, o = run("cargo fmt -p budlum-core -- --check")
    print("  fmt:", "temiz" if k == 0 else o[:400])
    kf, of_ = run("cargo fmt --manifest-path xtask/gates/Cargo.toml --all -- --check")
    print("  fmt (xtask/gates, CI Repo Lint adim 10):", "temiz" if kf == 0 else of_[:700])
    taze()
    k, o = run("cargo clippy -p budlum-core --lib -- -D warnings 2>&1 | tail -20")
    print("  clippy --lib cikis:", k)
    if k:
        print(o[-1200:])
    kg, og = run("cargo clippy --release --manifest-path xtask/gates/Cargo.toml --all-targets "
                 "2>&1 | tail -40")
    print("  clippy (gates --all-targets, CI'in tam komutu ve tam kapi: pipefail ile) cikis:", kg)
    if kg:
        print(og[-2500:])
    # fmt kirigi de kapis sayilir: CI'da ayri adim, yerelde sessiz gecmemeli.
    # Test kodu burada gorulmez; `#[test]` derlemesinin tek yetkili yeri CI'dir.
    return k or kf or kg


def pedantic(prefix):
    print("# pedantic/nursery sayimi (CI'deki ratchet'in lib kismi)")
    json_path = "/tmp/pedantic.json"
    taze()
    k, _ = run("cargo clippy -p budlum-core --lib --message-format=json -- "
               "-W clippy::pedantic -W clippy::nursery > %s 2>/tmp/pedantic.err" % json_path)
    if k:
        print("  clippy cikis %d; /tmp/pedantic.err son satirlari:" % k)
        print(open("/tmp/pedantic.err").read()[-400:])
    tot = 0
    perfile = collections.Counter()
    perlint = collections.Counter()
    for l in open(json_path):
        try:
            m = json.loads(l)
        except ValueError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        d = m.get("diagnostic", {})
        code = (d.get("code") or {}).get("code", "")
        if d.get("level") != "warning" or not code.startswith("clippy::"):
            continue
        tot += 1
        prim = [s for s in d.get("spans", []) if s.get("is_primary")]
        f = prim[0]["file_name"] if prim else "?"
        if f.startswith(prefix):
            perfile[f] += 1
            perlint[code] += 1
    print("  toplam uyar (tum crate lib): %d | %s altinda: %d" % (tot, prefix, sum(perfile.values())))
    for f, n in perfile.most_common(18):
        print("    %4d %s" % (n, f))
    print("  aileler:")
    for c, n in perlint.most_common(12):
        print("    %4d %s" % (n, c))
    return perfile


if __name__ == "__main__":
    if MOD == "--durum":
        durum()
    elif MOD == "--kur":
        kur()
    elif MOD == "--pedantic":
        pedantic(sys.argv[3] if len(sys.argv) > 3 else "src/")
    elif MOD == "--klippy":
        klippy()
        kapilar()
    else:
        kapilar()
