#!/usr/bin/env python3
"""SKILL: CI'yi OLDUGU gibi oku: is sayimi, kirmizi adim, adimin log satirlari.

Kural: yesillik/kirmizilik iddia edilmez, logdan okunur. `check-runs` tek basina
yaniltir - bir adim kirmizi oldugunda sonraki ~25 adim `skipped` olur ve hicbir
sey dogrulanmaz. Bu betik adim dizisini ve logu indirir.

  python3 ci.py <repo> <sha>                     # sayim + kirmizi isimler
  python3 ci.py <repo> <sha> --derin             # + kirmizi adimin log satirlari
  python3 ci.py <repo> <sha> --bekle             # kosu kumesi bitene kadar yoklar
  python3 ci.py <repo> <sha> --bekle --en-fazla 900
  python3 ci.py <repo> <sha> --derin --is "Budlum Core"
                                                 # + o isin logundan rozet satirlari

`--bekle` yoklama arasini 60 sn tutar ve her yoklamada tek satir ilerleme yazar;
tavan asilirsa "kirmizi gorunmeyen adim olculmemis olabilir" uyarisi basar, cunku
bir basligin yesil gorunmesi isi biterken o adimin hic kosmamasi demek olabilir.
`--is` verilen adla o isin logundan `test result:`, `FAIL [badges` ve rozet adimi
satirlarini yazdirir; rozet sayisi yalniz buradan okunur, README'den degil.
"""
import collections
import gzip
import json
import os
import re
import sys
import time
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


def tok():
    return (open(os.path.expanduser("~/.tokp1"), "rb").read().decode()
            + open(os.path.expanduser("~/.tokp2"), "rb").read().decode())


def gh(path, url=False):
    base = path if url else "https://api.github.com/repos/" + path
    req = urllib.request.Request(base, headers={"Authorization": "Bearer " + tok(),
                                                "Accept": "application/vnd.github+json",
                                                "User-Agent": "ayaz-agent"})
    return urllib.request.urlopen(req, timeout=240).read()


def job_log(job):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request("https://api.github.com/repos/%s/actions/jobs/%s/logs" % (REPO, job),
                                 headers={"Authorization": "Bearer " + tok(), "User-Agent": "a"})
    try:
        loc = opener.open(req, timeout=180).headers["Location"]
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location")
    if not loc:
        return ""
    data = urllib.request.urlopen(urllib.request.Request(loc), timeout=300).read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data.decode("utf8", "replace")


def strip(l):
    return re.sub(r"\x1b\[[0-9;]*m", "", re.sub(r"^\S+ ", "", l)).strip()


REPO = sys.argv[1]
SHA = sys.argv[2]


def runlar():
    runs, page = [], 1
    while True:
        d = json.loads(gh("%s/commits/%s/check-runs?per_page=100&page=%d" % (REPO, SHA, page)))
        runs += d["check_runs"]
        if len(runs) >= d.get("total_count", 0) or page > 6:
            break
        page += 1
    return runs


runs = runlar()
if "--bekle" in sys.argv:
    tavan = 1500
    if "--en-fazla" in sys.argv:
        tavan = int(sys.argv[sys.argv.index("--en-fazla") + 1])
    bas = time.time()
    while True:
        acik = sum(1 for r in runs if r.get("status") != "completed")
        kir = [r["name"] for r in runs if r.get("status") == "completed"
               and r.get("conclusion") not in ("success", "skipped", "neutral")]
        print("  yoklama %4ds | is %d | bitmeyen %d | kirmizi %d%s"
              % (int(time.time() - bas), len(runs), acik, len(kir),
                 (" (" + ", ".join(kir[:3]) + ")") if kir else ""), flush=True)
        if acik == 0 or time.time() - bas > tavan:
            if acik:
                print("  uyarı: %d is hala kosuyor, tavan %d sn asildi; kirmizi gorunmeyen "
                      "adim olculmemis olabilir" % (acik, tavan), flush=True)
            break
        time.sleep(60)
        runs = runlar()

say = collections.Counter(r["status"] for r in runs)
con = collections.Counter(str(r["conclusion"]) for r in runs)
print("%s@%s | %d is | %s | %s" % (REPO, SHA[:9], len(runs), dict(say), dict(con)))
red = [r for r in runs if r["conclusion"] == "failure"]
for r in red:
    print("  KIRMIZI:", r["name"])
if not red and say.get("in_progress"):
    print("  not: %d is henuz kosuyor, kirmizi gorunmuyor olabilir" % say["in_progress"])

if "--derin" in sys.argv:
    for r in red:
        m = re.search(r"actions/runs/(\d+)/job/(\d+)", r.get("html_url", ""))
        if not m:
            continue
        job = m.group(2)
        j = json.loads(gh("%s/actions/jobs/%s" % (REPO, job)))
        adimlar = [s for s in j["steps"] if (s["conclusion"] or "") not in ("success", "skipped", "")]
        print("job %s (%s) kirmizi adimlar: %s"
              % (job, j["name"], [(s["number"], s["name"]) for s in adimlar]))
        t = job_log(int(job))
        lines = [strip(l) for l in t.splitlines()]
        hits = [i for i, l in enumerate(lines)
                if re.search(r"error\[E|^error:|FAIL \[|panicked at|test result:|warning: unused", l)]
        print("  log satir %d, ilgili %d" % (len(lines), len(hits)))
        for i in hits[:14]:
            print("   >", lines[i][:200])
    if "--is" in sys.argv:
        ad = sys.argv[sys.argv.index("--is") + 1]
        hedef = next((r for r in runs if r["name"] == ad), None)
        m = re.search(r"actions/runs/(\d+)/job/(\d+)", (hedef or {}).get("html_url", ""))
        if not m:
            print("  uyari: %r isi bu baslikta bulunamadi" % ad)
        else:
            j = json.loads(gh("%s/actions/jobs/%s" % (REPO, m.group(2))))
            durum = [(s["number"], s["name"], s["conclusion"]) for s in j["steps"]
                     if (s["conclusion"] or "") not in ("success", "skipped")]
            print("%s | durum %s | adim %s | kirmizi/bekleyen adim: %s"
                  % (j["name"], j["status"], len(j["steps"]), durum if durum else "yok"))
            lines = [strip(l) for l in job_log(int(m.group(2))).splitlines()]
            for l in lines:
                if re.search(r"test result:|FAIL \[badges|badge says|Is the badge", l):
                    print("   >", l[:200])
