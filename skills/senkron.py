#!/usr/bin/env python3
"""SKILL: yerel agaci deponun branch basina bayt esit hale getir (kontrol / onarim).

Kum firtinasi geri yuklemesi yereldeki dosyalari sessizce bayat surume
dondurur (olculdu: `usl` head'i ile 17 yol farkliydi, 13'u onceki turun ittigi
dosyalardi ve uzaktaki surum yeniydi). Bu yuzden hicbir olcum ya da itme, agac
esitligi dogrulanmadan gecerli sayilmaz.

  python3 senkron.py <repo> <branch> <yerel_dizin>           # kontrol
  python3 senkron.py <repo> <branch> <yerel_dizin> --repair  # head tarball ile esitle

Onarim yalnizca uzaktan gelen icerigi yerelin ustune yazar; `target/` gibi
izlenmeyen dizinler korunur, silme yapilmaz. Onarımdan once yapilan yerel
degisiklikler kaybolur: yamalar sonra yeniden uygulanmali ve anchor sayisiyla
dogrulanmali olmalidir.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request


def tok():
    return (open(os.path.expanduser("~/.tokp1"), "rb").read().decode()
            + open(os.path.expanduser("~/.tokp2"), "rb").read().decode())


def api(repo, path):
    req = urllib.request.Request(
        "https://api.github.com/repos/" + repo + path,
        headers={"Authorization": "Bearer " + tok(),
                 "Accept": "application/vnd.github+json", "User-Agent": "ayaz-agent"})
    return json.loads(urllib.request.urlopen(req, timeout=240).read())


def blob_of(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def head_and_tree(repo, branch):
    head = api(repo, "/git/ref/heads/" + branch)["object"]["sha"]
    tr = api(repo, "/git/trees/" + head + "?recursive=1")
    if tr.get("truncated"):
        raise SystemExit("agac listesi kirpildi: tam karsilastirma yapilamaz")
    return head, {e["path"]: e["sha"] for e in tr["tree"] if e["type"] == "blob"}


def measure(repo, branch, dst):
    head, rem = head_and_tree(repo, branch)
    diff, eksik = [], []
    for p, sha in rem.items():
        f = os.path.join(dst, p)
        if not os.path.isfile(f):
            eksik.append(p)
            continue
        with open(f, "rb") as h:
            if blob_of(h.read()) != sha:
                diff.append(p)
    print("baslik: %s@%s head %s | izlenen %d yol | FARKLI %d | EKSIK %d"
          % (repo, branch, head[:9], len(rem), len(diff), len(eksik)))
    for p in (diff + eksik)[:24]:
        print("   ", p)
    return head, rem, diff, eksik


def main():
    repo, branch, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    repair = "--repair" in sys.argv[4:]
    head, _, diff, eksik = measure(repo, branch, dst)
    if not diff and not eksik:
        print("SONUC: yerel agac head ile bayt esit.")
        return 0
    if not repair:
        print("SONUC: bayat. --repair ile esitle, sonra yamalari yeniden uygulayin.")
        return 1
    tmp = os.path.join(os.path.dirname(dst.rstrip("/")), "fresh_" + head[:8])
    os.makedirs(tmp, exist_ok=True)
    req = urllib.request.Request(
        "https://api.github.com/repos/%s/tarball/%s" % (repo, head),
        headers={"Authorization": "Bearer " + tok(), "User-Agent": "ayaz-agent"})
    raw = urllib.request.urlopen(req, timeout=600).read()
    with open("/tmp/senkron.tar.gz", "wb") as h:
        h.write(raw)
    with tarfile.open("/tmp/senkron.tar.gz") as t:
        t.extractall(tmp, filter="data")
    # GitHub tarball'i tek bir ust dizin tasir (owner-repo-sha); onu asmaliyiz,
    # yoksa `cp -a tmp/.` o dizini yerel agacin icine koyar ve hicbir dosya
    # esitlenmez (olculdu: onarim sonrasi 14 FARKLI / 47 EKSIK kalmisti).
    # Uyarı: burada sabit "x" üreten bir comprehension kullanılıyordu, yani kaynak
    # dizin hiç var olmayan `tmp/x` oluyordu ve onarım sessizce hiçbir şey
    # eşlemeden hata veriyordu (ölçüldü: `cp -a .../fresh_b48bdfe2/x/.` 1).
    ic=[ad for ad in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, ad))]
    kaynak = os.path.join(tmp, ic[0]) if len(os.listdir(tmp)) == 1 and len(ic) == 1 else tmp
    subprocess.run(["cp", "-a", kaynak + "/.", dst + "/"], check=True)
    # Onarim ici klonu birakmayi veriyor: olculdu, `work/` altinda iki `fresh_*`
    # agaci 89 MB yer tutuyordu ve kalici izini snapshot tavanini asiyordu.
    try:
        shutil.rmtree(tmp)
    except OSError:
        pass
    _, _, diff2, eksik2 = measure(repo, branch, dst)
    print("SONUC: onarim sonrasi FARKLI %d, EKSIK %d (ikisi de 0 olmali)"
          % (len(diff2), len(eksik2)))
    return 0 if not diff2 and not eksik2 else 1


if __name__ == "__main__":
    raise SystemExit(main())
