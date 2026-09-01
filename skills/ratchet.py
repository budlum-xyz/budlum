#!/usr/bin/env python3
"""SKILL: ratchet'i olc: CI'nin olctugu clippy-extra sayisini logdan oku, tabani ona indir.

Kural: taban yalniz olculen sayi kadar inebilir; yukari cikarma yok, "surekli kirmizi"
da yok. Sayi iddia edilmez, `Budlum Core` isinin logundan okunur; adim yesil olsa bile
satir okunmadan "geriledi" denmez. Ayni logdan `no-idle-code` sayimi ve README test
rozetinin karsilastirdigi sayi da alinir (`badges-are-current` logdaki son ` passed`
satirini olcuyor).

  python3 ratchet.py <repo> <sha>                 # oku ve raporla
  python3 ratchet.py <repo> <sha> <dizin>         # + tabani <dizin>'e yaz (itme yok)
  python3 ratchet.py <repo> <sha> <dizin> --it    # + it.py ile `weed ratchet tabani` it
"""
import collections
import gzip
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


def tok():
    return (open(os.path.expanduser("~/.tokp1"), "rb").read().decode()
            + open(os.path.expanduser("~/.tokp2"), "rb").read().decode())


def gh(path):
    req = urllib.request.Request("https://api.github.com/repos/" + path,
                                 headers={"Authorization": "Bearer " + tok(),
                                          "Accept": "application/vnd.github+json",
                                          "User-Agent": "ayaz-agent"})
    # Sabit https api.github.com ucu, zaman asimi var; konak kullanicidan gelmez.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    return urllib.request.urlopen(req, timeout=300).read()


def job_log(repo, job):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request("https://api.github.com/repos/%s/actions/jobs/%s/logs" % (repo, job),
                                 headers={"Authorization": "Bearer " + tok(), "User-Agent": "a"})
    try:
        loc = opener.open(req, timeout=180).headers["Location"]
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location")
    if not loc:
        return ""
    # Kosu devam eden isin log yonlendirmesi blob store'da 404 donebiliyor
    # (olculdu: `Repo Lint` in_progress iken "The specified blob does not exist").
    # Log okunamazsa bos dizge dondurulur; cagiran taraf "sayim yok" der, sayi uydurmaz.
    try:
        # Log yonlendirmesi api.github.com'un verdigi sabit blob adresi; zaman asimi var.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        data = urllib.request.urlopen(urllib.request.Request(loc), timeout=600).read()
    except (urllib.error.HTTPError, urllib.error.URLError):
        return ""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf8", "replace")


REPO = sys.argv[1]
SHA = sys.argv[2]
DIZIN = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None
IT = "--it" in sys.argv

runs, page = [], 1
while True:
    d = json.loads(gh("%s/commits/%s/check-runs?per_page=100&page=%d" % (REPO, SHA, page)))
    runs += d["check_runs"]
    if len(d["check_runs"]) < 100:
        break
    page += 1
durum = collections.Counter(r["status"] for r in runs)
sonuc = collections.Counter(str(r["conclusion"]) for r in runs)
print("%s@%s | %d is | %s | %s" % (REPO, SHA[:9], len(runs), dict(durum), dict(sonuc)))
if any(s != "completed" for s in durum):
    print("UYARI: kosum hala suruyor; olcum eksik olabilir")

# `Wallet Core` da "Core" iceriyor ve logunda clippy-extra adimi yok; once tam ad,
# bulunursa iceren ad araniyor.
hedef = [r for r in runs if r["name"] == "Budlum Core"] or [r for r in runs if "Core" in r["name"]] or runs
N = B = K = rozet = None
adaylar = []
for r in hedef:
    # details_url bicimi `.../runs/<run>/job/<job>`: tekil "job". `/jobs/` arayan
    # desen hicbir sey bulamadi ve olcum "logda sayim yok" diye dustu (olculdu).
    m = re.search(r"/jobs?/(\d+)", r["details_url"] or "")
    if not m:
        continue
    txt = re.sub(r"\x1b\[[0-9;]*m", "", job_log(REPO, m.group(1)))
    for l in txt.splitlines():
        a = re.search(r"clippy-extra: (\d+) \| baseline: (\d+)", l)
        if a:
            N, B = int(a.group(1)), int(a.group(2))
        b = re.search(r"no-idle-code\]{:?}:? ?(\d+)", l)
        if b:
            K = int(b.group(1))
        # Filtreli alt kosumlar da `test result: ok. N passed` satiri üretiyor
        # (olculdu: 45 passed; 2559 filtered out). Rozetin olctugu tam kosum
        # "0 filtered out" ile bitiyor; son eslesme degil o satir alinir, yoksa
        # okuma 0'a ya da bir alt kumenin sayisina iniyor.
        c = re.search(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; (\d+) filtered out", l)
        if c:
            adaylar.append((int(c.group(2)) == 0, int(c.group(1))))
    if N is not None:
        break
# Rozet = tam kosenin en buyuk sayisi. "son eslesme" yanlis (olculdu: 22d7e2e99
# logunda `0 passed; ...; 0 filtered out` satiri daha sonra geliyor), "filtresiz
# satir" da tek basina yetmiyor; filtreli alt kumeler en buyuk olaniyla gecersiz.
if adaylar:
    tam = [n for filtreli, n in adaylar if filtreli]
    rozet = max(tam or [n for _, n in adaylar])
if N is None:
    print("SONUC: logda clippy-extra sayimi yok (adim calismadi ya da isim degisti)")
    raise SystemExit(2)

# `no-idle-code` sayimi `Repo Lint` isinin logundadir, `Budlum Core`da degil; yoksa
# okuma hep None donuyor (olculdu: tablo satiri bu sayiya dayanmak zorunda).
if K is None:
    for r in [x for x in runs if x["name"].startswith("Repo Lint")]:
        m = re.search(r"/jobs?/(\d+)", r["details_url"] or "")
        if not m:
            continue
        txt = re.sub(r"\x1b\[[0-9;]*m", "", job_log(REPO, m.group(1)))
        for l in txt.splitlines():
            b = re.search(r"no-idle-code\]:? ?(\d+)", l)
            if b:
                K = int(b.group(1))
                break
        if K is not None:
            break
print("clippy-extra %d | taban %d | no-idle-code %s | README rozet sayisi %d" % (N, B, K, rozet))
if N > B:
    print("SONUC: kapi kirmizi (%d > %d); tabana dokunulmaz, kod temizlenir" % (N, B))
    raise SystemExit(1)
if DIZIN is None:
    print("SONUC: taban %d'ye indirilebilir (%%5 pay ile %d); yazmak icin <dizin> verin"
          % (N, N + N * 5 // 100))
    raise SystemExit(0)

yol = os.path.join(DIZIN, ".github", "clippy-extra-baseline.txt")


def ilk_sayi(yol):
    # Taban dosyasinin kendi sozlesmesi: tek basina duran ILK sayi satiri tabandir.
    # Dosyanin tamamini okumak (olculdu) aciklama satirlari yuzinden ValueError
    # veriyordu: `int("7142\n# ---...")`.
    with open(yol) as f:
        for satir in f:
            t = satir.strip()
            if t.isdigit():
                return int(t)
    raise SystemExit("taban dosyasinda tek basina sayi satiri yok: " + yol)


onceki = ilk_sayi(yol)
# Yuzde bes pay: iki akis ayni anda uyari eklerse taban bir akisin olcumunde kati
# kalip digeri gereksiz kirmiziya dusuruyor. Kapi `base > n + n*10/100` ile bayat
# tabani ayrica reddediyor, yani pay 5-10 araliginda kaliyor.
hedef_sayi = min(onceki, N + N * 5 // 100)
if onceki == hedef_sayi:
    print("SONUC: taban zaten %d; yazilacak bir sey yok" % hedef_sayi)
    raise SystemExit(0)
open(yol, "w").write("%d\n" % hedef_sayi)
print("taban dosyasi %s: %d -> %d" % (yol, onceki, hedef_sayi))
if not IT:
    print("SONUC: yerel yazildi; itmek icin --it verin")
    raise SystemExit(0)
dal = "usl"
spec = [{"message": "weed ratchet tabani", "date": "2026-08-28T23:40:00Z",
         "paths": [".github/clippy-extra-baseline.txt"]}]
specyol = os.path.join(os.path.dirname(os.path.abspath(DIZIN)), "spec_ratchet.json")
open(specyol, "w").write(json.dumps(spec))
cikti = subprocess.run([sys.executable, os.path.join(os.path.expanduser("~"), "skills", "it.py"),
                        REPO, dal, specyol, DIZIN], capture_output=True, text=True)
print(cikti.stdout[-500:] or cikti.stderr[-400:])
