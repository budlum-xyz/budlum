#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lisans tutarlilik kapisi: PolyForm Shield 1.0.0.

Neden bu dosya var: lisans degistirildiginde tek bir LICENSE dosyasini
degistirmek YETMIYOR. Bu repoda lisans BES ayri yerde beyan ediliyordu:
  LICENSE.md · budzero/LICENSE · 6 x Cargo.toml · README rozeti · NOTICE
ve degisiklikten ONCE bunlar birbiriyle CELISIYORDU: budzero/LICENSE "MIT
License" derken budzero/Cargo.toml "Apache-2.0" diyordu. Kimse fark etmemisti
cunku denetleyen bir program yoktu.

Ayrica: ucuncu taraf atiflari (Plonky3 MIT OR Apache-2.0, deny.toml
bagimlilik allow-listesi) DEGISTIRILMEMELIDIR. Bu kapi onlari da korur.
"""
import glob
import hashlib
import io
import re
import sys

SPDX = "LicenseRef-PolyForm-Shield-1.0.0"
KANONIK_UZUNLUK = 5747
KANONIK_SHA256 = "80ee7a573d585da44a6b993274071240470d2645922fff9f37910418b34fb836"

OK = F = 0

def k(ad, kosul, ek=""):
    global OK, F
    if kosul: OK += 1
    else: F += 1; print(f"  BASARISIZ: {ad} {ek}")

lic_bytes = io.open("LICENSE.md", "rb").read()
lic = lic_bytes.decode("utf-8")

# PolyForm'un 1.0.0 deposundaki kanonik Shield metninin agdan bagimsiz ozeti.
# Yerel LICENSE.md bunun ardindan projeye ozgu zorunlu bildirimleri tasir.
kanonik_ozet = hashlib.sha256(lic_bytes[:KANONIK_UZUNLUK]).hexdigest()
k(
    "LICENSE.md kanonik PolyForm metniyle basliyor",
    len(lic_bytes) >= KANONIK_UZUNLUK and kanonik_ozet == KANONIK_SHA256,
)

BOLUMLER = ["Acceptance", "Copyright License", "Distribution License", "Notices",
            "Changes and New Works License", "Patent License", "Noncompete",
            "Competition", "New Products", "Discontinued Products",
            "Sales of Business", "Fair Use", "No Other Rights", "Patent Defense",
            "Violations", "No Liability", "Definitions"]

for p in ("LICENSE.md", "budzero/LICENSE"):
    s = io.open(p, encoding="utf-8").read()
    k(f"{p}: Shield basligi", "PolyForm Shield License 1.0.0" in s)
    for b in BOLUMLER:
        k(f"{p}: '{b}' bolumu", f"## {b}" in s)
    k(f"{p}: Required Notice", "Required Notice:" in s)
    k(f"{p}: Licensor Line of Business", "Licensor Line of Business:" in s)
    # Eski lisanslarin GERI GELMEDIGI
    k(f"{p}: Apache metni yok", "Apache License" not in s)
    k(f"{p}: MIT metni yok", "MIT License" not in s)

# Her Cargo.toml ayni SPDX'i beyan etmeli
for c in sorted(glob.glob("**/Cargo.toml", recursive=True)):
    s = io.open(c, encoding="utf-8").read()
    m = re.search(r'^license\s*=\s*"(.+?)"', s, re.M)
    if m:
        k(f"{c}: SPDX = {SPDX}", m.group(1) == SPDX, m.group(1))
k("SPDX LicenseRef sozdizimi",
  re.fullmatch(r"LicenseRef-[A-Za-z0-9.\-]+", SPDX) is not None)

r = io.open("README.md", encoding="utf-8").read()
k("README rozeti Shield", "PolyForm%20Shield" in r)
k("README eski Apache rozeti YOK", "license-Apache" not in r)

n = io.open("docs/NOTICE", encoding="utf-8").read()
k("NOTICE Shield beyan ediyor", "PolyForm Shield License 1.0.0" in n)
# --- UCUNCU TARAF ATIFLARI KORUNMALI ---
k("NOTICE Plonky3 atfi korundu", "Plonky3" in n)
k("NOTICE Plonky3 lisansi korundu", "MIT OR Apache-2.0" in n)
d = io.open("budzero/deny.toml", encoding="utf-8").read()
k("deny.toml bagimlilik allow-listesi korundu",
  '"Apache-2.0"' in d and '"MIT"' in d)

print(f"\nSONUC: {OK} GECTI · {F} BASARISIZ")
sys.exit(1 if F else 0)
