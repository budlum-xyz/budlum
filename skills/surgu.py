#!/usr/bin/env python3
"""Depolama alt agacinda pedantic/nursery uyarilarini azaltan mekanik surgu.

Clippy'nin `--message-format=json` cikisi tek gercek kaynaktir. Uc sinif islem
yapilir:

1. Tek parcali, `MachineApplicable` yeniden yazimlar (use_self, cast_lossless,
   single_char_pattern, ...) dogrudan yazilir. Cok parcali oneriler ATLANIR:
   `map_unwrap_or` gibi oneriler birbirine bagimli duzenleme ister ve sirali
   uygulama bozar (olculdu: `map_or(u64::to_le_bytesle_bytes(), /* f */)`).
2. `doc_markdown`: clippy'nin onerdigi ters tikla sarma kabul edilir; bir
   sozcugu ters tikla sarmak davranisi degistirmez.
3. `must_use_candidate` -> item'in belge blogunun ustune `#[must_use]`;
   `missing_const_for_fn` -> imzaya `const`; `missing_errors_doc` ->
   imzadan okulan hata turune isaret eden iki satirlik `# Errors` blogu.
   Hata turu okunamazsa o fonksiyona dokunulmaz.

Her adimdan sonra `cargo fmt` ve `cargo clippy --lib -- -D warnings` kosulur;
derlenmeyen dosya taze kopyasindan geri alinir. `--kuru` yazmadan sayar.
"""
import collections
import json
import pathlib
import re
import sys

KOK = pathlib.Path("/home/user/work/usl")
def kullan():
    print("""kullanim:
  surgu.py <taze-kopya> [pedantic.json] [--kuru]

<taze-kopya>: derlenmeyen dosyalarin geri alinacagi kaynak agac (taze klon).
[pedantic.json]: `olc.py --pedantic` ya da `cargo clippy --message-format=json` ciktilari;
verilmezse KOK'taki mevcut girdi taranir. --kuru yazmadan sayar, yazarsa uygular.

Girdi dosyasi yoksa trace basmak yerine kullanim yazilir ve cikis 2 olur
(olculdu: --argmansiz cagri `read_text()` trace'i veriyordu).""", file=sys.stderr)
    raise SystemExit(2)


if len(sys.argv) < 3 or "--help" in sys.argv or "-h" in sys.argv:
    kullan()

PRISTINE = pathlib.Path(sys.argv[1])   # geri alma kaynagi: taze klon
YAZ = "--kuru" not in sys.argv[2:]
ONCEK = "src/storage/"   # ameliyat alani: salt-okunur ada + bagimlilari
KABUL = {
    "clippy::use_self", "clippy::cast_lossless", "clippy::single_char_pattern",
    "clippy::bool_to_int_with_if", "clippy::unnecessary_cast", "clippy::zero_ptr",
    "clippy::needless_bool", "clippy::redundant_closure", "clippy::needless_lifetimes",
    "clippy::let_and_return", "clippy::clone_on_copy", "clippy::drop_ref",
    "clippy::redundant_clone", "clippy::needless_borrow", "clippy::single_match_else",
    "clippy::manual_unwrap_or", "clippy::unnecessary_to_owned",
}
kaynak = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") \
    else pathlib.Path("/tmp/ped.json")

tw = collections.defaultdict(list)
mustuse = collections.defaultdict(set)
consts = collections.defaultdict(set)
errdocs = collections.defaultdict(set)
gorev = collections.Counter()

for line in kaynak.read_text().splitlines():
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-message":
        continue
    d = m.get("message") or {}
    if d.get("level") != "warning":
        continue
    code = (d.get("code") or {}).get("code", "")
    if not code.startswith("clippy::"):
        continue
    prim = [s for s in d.get("spans", []) if s.get("is_primary")]
    if not prim or not prim[0].get("file_name", "").startswith(ONCEK):
        continue
    p = prim[0]
    f = p["file_name"]
    if code in KABUL or code == "clippy::doc_markdown":
        aday = []
        for ch in [d] + d.get("children", []):
            for cs in ch.get("spans", []):
                rep = cs.get("suggested_replacement")
                if rep is None or not cs.get("file_name", "").startswith(ONCEK):
                    continue
                if code == "clippy::doc_markdown":
                    if not (rep.startswith("`") and rep.endswith("`") and len(rep) > 2):
                        continue
                elif cs.get("suggestion_applicability") != "MachineApplicable":
                    continue
                aday.append((cs["file_name"], cs["byte_start"], cs["byte_end"], rep))
        if len(aday) == 1:
            fn, s, e, rep = aday[0]
            tw[fn].append((s, e, rep))
            gorev[code] += 1
    elif code == "clippy::must_use_candidate":
        # BILEREK ATLANIR: `#[must_use]` sonucu yok sayan cagriyi `unused_must_use`
        # ile kirmiziya cevirebilir ve o cagrilar baska crate'lerde ya da test
        # hedeflerinde oturuyor; yerel dogrulama `--lib` ile sinirli.
        gorev["atlanan: must_use (cagri yeri riski)"] += 1
    elif code == "clippy::missing_const_for_fn":
        consts[f].add(p["line_start"])
        gorev[code] += 1
    elif code == "clippy::missing_errors_doc":
        errdocs[f].add(p["line_start"])
        gorev[code] += 1


def hata_turu(cizgiler, i):
    """Imzadan hata turunu okur: `Result<T, E>` -> `E`; `x::Result<T>` -> `x::Error`."""
    metin = "".join(cizgiler[i:i + 14]).split("{", 1)[0]
    m = re.search(r"->\s*([\w:]*::)?Result\s*<", metin)
    if not m:
        return None
    on = metin[m.end() - 1:]
    derin = 0
    arg = ""
    for ch in on:
        if ch == "<":
            derin += 1
            if derin == 1:
                continue
        elif ch == ">":
            derin -= 1
            if derin == 0:
                break
        if derin >= 1:
            arg += ch
    parca, derin, out = "", 0, []
    for ch in arg:
        if ch == "<":
            derin += 1
        elif ch == ">":
            derin -= 1
        if ch == "," and derin == 0:
            out.append(parca.strip())
            parca = ""
        else:
            parca += ch
    out.append(parca.strip())
    out = [x for x in out if x]
    if len(out) >= 2:
        return out[-1].split("::")[-1].strip()
    if len(out) == 1 and (m.group(1) or "").strip(":"):
        return (m.group(1) + "Error").strip()
    return None


for f in sorted(set(list(tw) + list(mustuse) + list(consts) + list(errdocs))):
    yol = KOK / f
    if f in tw:
        b = yol.read_bytes()
        gor = []
        for s, e, rep in sorted(tw[f], key=lambda x: (x[0], x[1])):
            if any(not (e <= a or s >= c2) for a, c2, _ in gor):
                continue
            gor.append((s, e, rep))
        for s, e, rep in sorted(gor, key=lambda x: -x[0]):
            b = b[:s] + rep.encode() + b[e:]
        if YAZ:
            yol.write_bytes(b)
    satirlar = yol.read_text().splitlines(keepends=True)
    islemler = sorted(list([ln, "attr"] for ln in mustuse.get(f, set()))
                      + list([ln, "const"] for ln in consts.get(f, set()))
                      + list([ln, "err"] for ln in errdocs.get(f, set())), key=lambda x: -x[0])
    for ln, tur in islemler:
        i = ln - 1
        if i >= len(satirlar) or "fn" not in satirlar[i]:
            continue
        girinti = len(satirlar[i]) - len(satirlar[i].lstrip())
        if tur == "const":
            if "const fn" in satirlar[i]:
                continue
            satirlar[i] = re.sub(r"\bfn\b", "const fn", satirlar[i], count=1)
            gorev["uygulanan: const"] += 1
        elif tur == "attr":
            j = i
            while j > 0 and (satirlar[j - 1].lstrip().startswith("///")
                             or satirlar[j - 1].lstrip().startswith("#[")):
                j -= 1
            satirlar.insert(j, " " * girinti + "#[must_use]\n")
            gorev["uygulanan: must_use"] += 1
        else:
            if any("# Errors" in satirlar[k] for k in range(max(0, i - 14), i)):
                continue
            et = hata_turu(satirlar, i)
            if not et:
                gorev["atlanani: hata turu okunamadi"] += 1
                continue
            j = i
            while j > 0 and satirlar[j - 1].lstrip().startswith("#["):
                j -= 1
            blok = [" " * girinti + "/// # Errors\n", " " * girinti + "///\n",
                    " " * girinti + "/// Propagates `%s` from the step that failed; its variants name the "
                    "refused conditions.\n" % et]
            # belge blogunun sonuna, niteliklerden once ekle
            yer = i
            while yer > 0 and satirlar[yer - 1].lstrip().startswith("#["):
                yer -= 1
            while yer > 0 and satirlar[yer - 1].lstrip().startswith("///"):
                yer -= 1
            satirlar[yer:yer] = blok
            gorev["uygulanan: # Errors"] += 1
    if YAZ:
        yol.write_text("".join(satirlar))

print(("YAZILDI" if YAZ else "KURUSUN") + " | adim dagilimi:")
for k, n in gorev.most_common(20):
    print("   %5d %s" % (n, k))
print("etkilenen dosya:", len(set(list(tw) + list(mustuse) + list(consts) + list(errdocs))))
