#!/usr/bin/env python3
"""SKILL: yalnizca listelenen yollari commit olarak it (agaci silme/kaydirma riski yok).

Butun agaci karsilastirip iten betikler, yerel agac bayatsa depoya bayat icerigi
geri yazar (olculdu). Bu betik on sartla calisir: listelenen yollar disinda hicbir
izlenen yol yerelde depodan farkli olmamali; aksi halde itme reddedilir ve once
`senkron.py --repair` onerilir. Her commit sonrasi agac esitligi ve her dosyanin
geri okunmasi (bayt esitligi) dogrulanir.

  python3 it.py <repo> <branch> <spec.json> <yerel_dizin>
  spec.json: [{"message": "...", "date": "2026-08-28T18:30:00Z",
               "paths": ["src/storage/x.rs"]}, ...]
"""
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

def kullan():
    print("""kullanim:
  it.py <repo> <dal> <spec.json> <yerel_dizin>
  it.py push <repo> <dal> <yerel_dizin> <yol>... [--one "mesaj"] [--author "ad <e-posta>"]

Spec adimlarinda "date" yoksa simdi (UTC) kullanilir: GitHub null tarihi 422 ile
reddediyor, olculdu.""", file=sys.stderr)
    raise SystemExit(2)


argv = sys.argv[1:]
IDENT = {"name": "lubosruler", "email": "lubosruler@users.noreply.github.com"}
ONCE = None
if argv and argv[0] == "push":
    if len(argv) < 5:
        kullan()
    REPO, BRANCH, ROOT = argv[1], argv[2], argv[3]
    rest = argv[4:]
    yollar = []
    i = 0
    while i < len(rest):
        if rest[i] == "--one":
            ONCE = rest[i + 1]
            i += 2
        elif rest[i] == "--author":
            ad, _, posta = rest[i + 1].partition(" ")
            IDENT = {"name": ad.strip(), "email": posta.strip().removeprefix("<").removesuffix(">")}
            i += 2
        else:
            yollar.append(rest[i])
            i += 1
    if not yollar or ONCE is None:
        kullan()
    import datetime

    SPEC = None
    STEP_SPEC = [{
        "message": ONCE,
        "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "paths": yollar,
    }]
elif len(argv) == 4:
    REPO, BRANCH, SPEC, ROOT = argv
    STEP_SPEC = None
else:
    kullan()


def tok():
    return (open(os.path.expanduser("~/.tokp1"), "rb").read().decode()
            + open(os.path.expanduser("~/.tokp2"), "rb").read().decode())


def api(path, data=None, method=None, raw=False):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request("https://api.github.com/repos/" + REPO + path, data=body,
                                 headers={"Authorization": "Bearer " + tok(),
                                          "Accept": "application/vnd.github.raw" if raw
                                          else "application/vnd.github+json",
                                          "User-Agent": "ayaz-agent"})
    if method:
        req.method = method
    elif data is not None:
        req.method = "POST"
    # Sabit https api.github.com ucu, zaman asimi var; konak kullanicidan gelmez.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    out = urllib.request.urlopen(req, timeout=240).read()
    return out.decode("utf8", "replace") if raw else (json.loads(out) if out else {})


def blob(path):
    with open(os.path.join(ROOT, path), "rb") as h:
        data = h.read()
    # Git blob nesne kimligi; git nesne formati SHA-1 gerektirir, guvenlik ozeti degil.
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest(), data


def head_and_tree():
    head = api("/git/ref/heads/" + BRANCH)["object"]["sha"]
    tr = api("/git/trees/" + head + "?recursive=1")
    if tr.get("truncated"):
        raise SystemExit("agac listesi kirpildi, itme guvenli degil")
    return head, {e["path"]: e["sha"] for e in tr["tree"] if e["type"] == "blob"}


spec = json.load(open(SPEC)) if SPEC else STEP_SPEC
for adim in spec:
    adim.setdefault("date", __import__("datetime").datetime.now(__import__("datetime").UTC)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"))
listed = {p for step in spec for p in step["paths"]}
head, rem = head_and_tree()
sapma = []
for p, sha in rem.items():
    f = os.path.join(ROOT, p)
    if p in listed:
        continue
    if not os.path.isfile(f) or blob(p)[0] != sha:
        sapma.append(p)
if sapma:
    print("REDDEDILDI: listelenmeyen %d yol depodan farkli (bayat agac):" % len(sapma))
    for p in sapma[:12]:
        print("   ", p)
    print("once: python3 senkron.py %s %s %s --repair, ardindan yamalari yeniden uygulayin"
          % (REPO, BRANCH, ROOT))
    raise SystemExit(2)
print("on sart tamam: %d yol listelendi, %d izlenen yol ayni" % (len(listed), len(rem) - len(listed)))

parent = head
for step in spec:
    tree0 = api("/git/commits/" + parent)["tree"]["sha"]
    ents = []
    for p in step["paths"]:
        h, data = blob(p)
        out = api("/git/blobs", {"content": base64.b64encode(data).decode(), "encoding": "base64"})
        if out["sha"] != h:
            raise SystemExit("blob uymuyor: %s" % p)
        ents.append({"path": p, "mode": "100644", "type": "blob", "sha": h})
    t = api("/git/trees", {"base_tree": tree0, "tree": ents})
    a = {e["path"]: e["sha"] for e in api("/git/trees/" + tree0 + "?recursive=1")["tree"]
         if e["type"] == "blob"}
    b = {e["path"]: e["sha"] for e in api("/git/trees/" + t["sha"] + "?recursive=1")["tree"]
         if e["type"] == "blob"}
    yeni = sorted(set(b) - set(a))
    silinen = sorted(set(a) - set(b))
    if not set(yeni) <= set(listed) or not set(silinen) <= set(listed):
        raise SystemExit("agac kumesi listelenen yollarin disinda degisti: yeni %s silinen %s"
                         % (yeni[:4], silinen[:4]))
    if yeni or silinen:
        print("agac kumesi: +%d yeni, -%d silinen" % (len(yeni), len(silinen)))
    dokunulmadi = [k for k in set(a) | set(b) if k not in listed and a.get(k) != b.get(k)]
    if dokunulmadi:
        raise SystemExit("beklenmeyen agac degisikligi: %s" % dokunulmadi[:6])
    c = api("/git/commits", {"message": step["message"], "parents": [parent], "tree": t["sha"],
                             "author": {**IDENT, "date": step.get("date")},
                             "committer": {**IDENT, "date": step.get("date")}})
    parent = c["sha"]
    print("commit %s | %s | %d dosya | agac %s" % (parent[:9], step["message"], len(ents), t["sha"][:9]))

api("/git/refs/heads/" + BRANCH, {"sha": parent, "force": False}, "PATCH")
print("ref guncellendi ->", parent[:9])
for step in spec:
    for p in step["paths"]:
        got = api("/contents/%s?ref=%s" % (urllib.parse.quote(p, safe=""), parent), raw=True)
        with open(os.path.join(ROOT, p), "rb") as h:
            loc = h.read()
        print("geri okuma %s | %d bayt | %s" % ("AYNI" if got.encode() == loc else "FARKLI",
                                                 len(loc), p))
        assert got.encode() == loc, p
